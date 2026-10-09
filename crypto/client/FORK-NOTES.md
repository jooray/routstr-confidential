# Fork notes: `client/vendor/tls`

Vendored from `@reclaimprotocol/tls@0.1.4` (`npm pack @reclaimprotocol/tls@0.1.4`).
The published tarball ships compiled JS in `lib/`; the patches below are applied
directly to `lib/make-tls-client.js` and marked in-source with `// FORK PATCH`.

> **Licence.** The published package declares `"license": "See License in
> <https://github.com/reclaimprotocol/.github/blob/main/LICENSE>"` and ships no
> LICENSE file; the upstream repository licence governs. (The plan assumed MIT;
> the actual text is the Reclaim protocol licence.)

## Changes (six, all in `lib/make-tls-client.js`)

1. **Export the TLS 1.3 handshake traffic secrets.**
   `let handshakeSecrets` captures the `secretType: 'hs'` key set in
   `processServerPubKey`; a new `getHandshakeSecrets()` returns it (`masterSecret`
   = HS, `clientSecret` = client_hs, `serverSecret` = server_hs).

2. **Export the raw handshake messages.** New `getHandshakeMessages()` returns
   `handshakeMsgs.slice()`, so the driver can compute `th_SH = SHA256(CH‖SH)` and
   `th_SF = SHA256(CH‖SH‖EE‖Cert‖CV‖SFin)` itself.

3. **`skipSendSequence(n)`.** Advances `recordSendCount` (the node's credential
   record occupies epoch-1 sequence 0, so the client's KeyUpdate is seq 1).

4. **`updateTrafficKeysSilently()`.** `writeEncryptedPacket` is split into
   `sealEncryptedRecord(opts)` (returns `{header, content}` without writing) and
   `writeEncryptedPacket` (seals, writes, increments the counter). The new
   `updateTrafficKeysSilently` seals a KeyUpdate *without* sending it and rotates
   the traffic keys exactly as `updateTrafficKeys()` does.

5. **Transport injection, cipher suite, ALPN, key share, tickets.** No code change:
   the client is already driven by `write`/`onRead`/`handleReceivedBytes`. The
   driver passes `cipherSuites: ['TLS_AES_128_GCM_SHA256']`,
   `supportedProtocolVersions: ['TLS1_3']`, `namedCurves: ['X25519']`,
   `applicationLayerProtocols: ['http/1.1']`, and never requests a session ticket
   (the library throws on HelloRetryRequest, so a single key share is enforced).

6. **Native advice helpers.** Implemented in `client/src/advice.ts` (node:crypto),
   not in the fork: HKDF-Expand-Label, `traffic upd`, AES-128-ECB keystream,
   `H1 = AES_K1(0)`, `T0 = AES_K1(J0)`, GHASH key. The driver asserts
   `advice.c_ap_1 === fork.getKeys().clientSecret` on every run, cross-checking the
   fork against `cu-crypto` at runtime (and the fixtures cross-check it offline).

## Runtime dependencies

Installed via `client/package.json`: `@noble/{ciphers,curves,hashes}`,
`@peculiar/{asn1-cms,asn1-ecc,asn1-rsa,asn1-schema,x509}`, `micro-rsa-dsa-dh`.
The webcrypto provider is selected explicitly:

```ts
import { setCryptoImplementation } from '../vendor/tls/lib/crypto/index.js'
import { webcryptoCrypto } from '../vendor/tls/lib/crypto/webcrypto.js'
setCryptoImplementation(webcryptoCrypto)
```
