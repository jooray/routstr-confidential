import * as peculiar from '@peculiar/x509';
import { SubjectAlternativeNameExtension } from '@peculiar/x509';
import { crypto } from "../crypto/index.js";
const AIA_EXT_TYPE = '1.3.6.1.5.5.7.1.1';
export function loadX509FromPem(pem) {
    let cert;
    try {
        cert = new peculiar.X509Certificate(pem);
    }
    catch (e) {
        throw new Error(`Unsupported certificate: ${e}`);
    }
    return {
        internal: cert,
        isWithinValidity() {
            const now = new Date();
            return now > cert.notBefore && now < cert.notAfter;
        },
        getAIAExtension() {
            const aiaExt = cert
                .getExtension(AIA_EXT_TYPE);
            return aiaExt?.caIssuers?.find(obj => obj.type === 'url')?.value;
        },
        getSubjectField(name) {
            return cert.subjectName.getField(name);
        },
        getAlternativeDNSNames() {
            // search for names in SubjectAlternativeNameExtension
            const ext = cert.extensions
                .find(e => e.type === '2.5.29.17'); //subjectAltName
            if (ext instanceof SubjectAlternativeNameExtension) {
                return ext.names.items
                    .filter(n => n.type === 'dns')
                    .map(n => n.value);
            }
            return [];
        },
        isIssuer({ internal: ofCert }) {
            const issuerName = normalizeDistinguishedName(ofCert.issuerName);
            const subjectName = normalizeDistinguishedName(cert.subjectName);
            if (issuerName !== subjectName) {
                return false;
            }
            const authorityKeyId = ofCert
                .getExtension(peculiar.AuthorityKeyIdentifierExtension)
                ?.keyId;
            const subjectKeyId = cert
                .getExtension(peculiar.SubjectKeyIdentifierExtension)
                ?.keyId;
            return !authorityKeyId
                || !subjectKeyId
                || authorityKeyId.toLowerCase() === subjectKeyId.toLowerCase();
        },
        getPublicKey() {
            return {
                buffer: new Uint8Array(cert.publicKey.rawData),
                algorithm: cert.publicKey.algorithm.name,
            };
        },
        async verifyIssued(otherCert) {
            const sigAlg = getSigAlgorithm(cert.publicKey, otherCert.internal);
            const impPublicKey = await crypto
                .importKey(sigAlg, new Uint8Array(cert.publicKey.rawData), 'public');
            const signature = new Uint8Array(otherCert.internal.signature);
            const verified = await crypto.verify(sigAlg, {
                publicKey: impPublicKey,
                signature,
                data: new Uint8Array(otherCert.internal['tbs'])
            });
            return verified;
        },
        serialiseToPem() {
            return cert.toString('pem');
        },
    };
}
function normalizeDistinguishedName(name) {
    return JSON.stringify(name.toJSON().map(rdn => (Object.entries(rdn)
        .flatMap(([type, values]) => values.map(value => [
        type.toLowerCase(),
        normalizeNameValue(value),
    ]))
        .sort(([typeA, valueA], [typeB, valueB]) => {
        if (typeA !== typeB) {
            return typeA < typeB ? -1 : 1;
        }
        return valueA === valueB ? 0 : valueA < valueB ? -1 : 1;
    }))));
}
function normalizeNameValue(value) {
    return value
        .normalize('NFKC')
        .toLowerCase()
        .trim()
        .replace(/\s+/gu, ' ');
}
function getSigAlgorithm(key, { signatureAlgorithm }) {
    if (!('name' in signatureAlgorithm)) {
        throw new Error('Missing signature algorithm name');
    }
    const { name, hash } = signatureAlgorithm;
    const { algorithm: keyAlg } = key;
    if (keyAlg.name !== name) {
        throw new Error(`Signature algorithm ${name} does not match`
            + ` public key algorithm ${keyAlg.name}`);
    }
    let hashName;
    switch (hash.name) {
        case 'SHA-256':
            hashName = 'SHA256';
            break;
        case 'SHA-384':
            hashName = 'SHA384';
            break;
        case 'SHA-512':
            hashName = 'SHA512';
            break;
        case 'SHA-1':
            hashName = 'SHA1';
            break;
        default:
            throw new Error(`Unsupported hash algorithm: ${hash.name}`);
    }
    switch (name) {
        case 'RSASSA-PKCS1-v1_5':
        case 'RSA-PKCS1-SHA1':
            return `RSA-PKCS1-${hashName}`;
        case 'ECDSA':
            if (hashName === 'SHA512' || hashName === 'SHA1') {
                throw new Error(`Unsupported hash algorithm for ECDSA: ${hashName}`);
            }
            switch (keyAlg.namedCurve) {
                case 'P-256':
                    return `ECDSA-SECP256R1-${hashName}`;
                case 'P-384':
                    return `ECDSA-SECP384R1-${hashName}`;
                default:
                    throw new Error(`Unsupported named curve: ${keyAlg.namedCurve}`);
            }
        default:
            throw new Error(`Unsupported signature algorithm: ${name}`);
    }
}
export function loadX509FromDer(der) {
    // peculiar handles both
    return loadX509FromPem(der);
}
export async function defaultFetchCertificateBytes(url) {
    const res = await fetch(url);
    if (!res.ok) {
        throw new Error(`Failed to fetch certificate from ${url}: ${res.statusText}`);
    }
    const buffer = await res.arrayBuffer();
    return new Uint8Array(buffer);
}
