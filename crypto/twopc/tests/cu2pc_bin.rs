//! Drives the `cu-2pc` binary (C) over its stdin/stdout frame protocol
//! against an in-process N party, and checks the outputs against the
//! reference key schedule.

use cu_crypto::hkdf::{derive_secret, hkdf_extract};
use cu_crypto::keyschedule::KeySchedule;
use p256::elliptic_curve::PrimeField;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio_util::compat::TokioAsyncReadCompatExt;
use twopc::{ApOut, Party, Role};

async fn write_frame(w: &mut (impl AsyncWriteExt + Unpin), ch: u8, data: &[u8]) {
    let mut hdr = [0u8; 5];
    hdr[0] = ch;
    hdr[1..].copy_from_slice(&(data.len() as u32).to_be_bytes());
    w.write_all(&hdr).await.unwrap();
    w.write_all(data).await.unwrap();
    w.flush().await.unwrap();
}

fn hex32(v: &Value, k: &str) -> [u8; 32] {
    hex::decode(v[k].as_str().unwrap()).unwrap().try_into().unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn cu_2pc_binary_end_to_end() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_cu-2pc"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();

    // N side over an in-memory duplex bridged to channel 0.
    let (n_io, bridge) = tokio::io::duplex(4 << 20);
    let (mut br, mut bw) = tokio::io::split(bridge);
    let (ctl_tx, mut ctl_rx) = tokio::sync::mpsc::unbounded_channel::<Value>();
    let (in_tx, mut in_rx) = tokio::sync::mpsc::unbounded_channel::<(u8, Vec<u8>)>();

    // child stdout → bridge / control
    tokio::spawn(async move {
        loop {
            let mut hdr = [0u8; 5];
            if stdout.read_exact(&mut hdr).await.is_err() {
                break;
            }
            let len = u32::from_be_bytes(hdr[1..].try_into().unwrap()) as usize;
            let mut d = vec![0u8; len];
            stdout.read_exact(&mut d).await.unwrap();
            if hdr[0] == 0 {
                if bw.write_all(&d).await.is_err() {
                    break;
                }
            } else {
                ctl_tx.send(serde_json::from_slice(&d).unwrap()).unwrap();
            }
        }
    });
    // bridge → child stdin channel 0; control commands on channel 1
    let net_tx = in_tx.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match br.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if net_tx.send((0, buf[..n].to_vec())).is_err() {
                        break;
                    }
                }
            }
        }
    });
    tokio::spawn(async move {
        while let Some((ch, d)) = in_rx.recv().await {
            write_frame(&mut stdin, ch, &d).await;
        }
    });

    // Server key pair.
    let b = Scalar::from_repr([7u8; 32].into()).unwrap();
    let server_share: [u8; 65] = (ProjectivePoint::GENERATOR * b)
        .to_affine()
        .to_encoded_point(false)
        .as_bytes()
        .try_into()
        .unwrap();
    let th_sh = [0x11u8; 32];
    let th_sf = [0x22u8; 32];

    let n_task = tokio::spawn(async move {
        let mut p = Party::new(Role::N, n_io.compat()).await.unwrap();
        p.preprocess().await.unwrap();
        let joint = p.key_share().await.unwrap();
        let hs = p.handshake(&server_share, th_sh).await.unwrap();
        let ap = p.application(th_sf).await.unwrap();
        p.close().await;
        (joint, hs, ap)
    });

    let mut evs = Vec::new();
    let next_ev = |evs: &mut Vec<Value>, v: Value| {
        evs.push(v.clone());
        v
    };
    let key_share = loop {
        let v = next_ev(&mut evs, ctl_rx.recv().await.unwrap());
        assert_ne!(v["ev"], "error", "{v}");
        if v["ev"] == "key_share" {
            break v;
        }
    };
    in_tx
        .send((
            1,
            serde_json::to_vec(&json!({"cmd":"handshake","s":hex::encode(server_share),"th_sh":hex::encode(th_sh)}))
                .unwrap(),
        ))
        .unwrap();
    let hs = loop {
        let v = next_ev(&mut evs, ctl_rx.recv().await.unwrap());
        assert_ne!(v["ev"], "error", "{v}");
        if v["ev"] == "hs" {
            break v;
        }
    };
    in_tx
        .send((1, serde_json::to_vec(&json!({"cmd":"app","th_sf":hex::encode(th_sf)})).unwrap()))
        .unwrap();
    let ap = loop {
        let v = next_ev(&mut evs, ctl_rx.recv().await.unwrap());
        assert_ne!(v["ev"], "error", "{v}");
        if v["ev"] == "ap" {
            break v;
        }
    };
    let t0 = std::time::Instant::now();
    let status = child.wait().await.unwrap();
    assert!(t0.elapsed() < std::time::Duration::from_secs(2), "cu-2pc must exit promptly");
    assert!(status.success());
    let (joint, hs_n, ap_n) = n_task.await.unwrap();

    // Reference.
    let joint_hex = key_share["p"].as_str().unwrap();
    assert_eq!(hex::decode(joint_hex).unwrap(), joint.to_vec());
    let ep = EncodedPoint::from_bytes(joint).unwrap();
    let p = ProjectivePoint::from(AffinePoint::from_encoded_point(&ep).unwrap());
    let z = (p * b).to_affine().to_encoded_point(false);
    let x: [u8; 32] = z.x().unwrap().as_slice().try_into().unwrap();
    let early = hkdf_extract(&[0u8; 32], &[0u8; 32]);
    let derived = derive_secret(&early, "derived", b"");
    let ks = KeySchedule::from_handshake(hkdf_extract(&derived, &x), th_sh, th_sf);

    assert_eq!(&hex32(&hs, "c_hs"), ks.client_hs.as_bytes());
    assert_eq!(&hex32(&hs, "s_hs"), ks.server_hs.as_bytes());
    assert_eq!(hs_n.c_hs, hex32(&hs, "c_hs"));
    assert_eq!(&hex32(&ap, "s_ap_0"), ks.s_ap_0.as_bytes());
    assert_eq!(&hex32(&ap, "c_ap_1"), ks.c_ap_1.as_bytes());
    match ap_n {
        ApOut::N { k0, iv0, hk, .. } => {
            assert_eq!(k0, ks.c_ap_0.key());
            assert_eq!(iv0, ks.c_ap_0.iv());
            assert_eq!(hk, hex32(&ap, "hk"));
        }
        _ => panic!(),
    }
    let steps: Vec<&str> = evs
        .iter()
        .filter(|v| v["ev"] == "timing")
        .map(|v| v["step"].as_str().unwrap())
        .collect();
    assert_eq!(
        steps,
        ["preprocess", "key_share", "ectf", "phase_a", "phase_b"]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn cu_2pc_reports_error_when_peer_disappears() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_cu-2pc"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdin.take()); // EOF: no peer
    let mut stdout = child.stdout.take().unwrap();
    let mut evs = Vec::new();
    loop {
        let mut hdr = [0u8; 5];
        if stdout.read_exact(&mut hdr).await.is_err() {
            break;
        }
        let len = u32::from_be_bytes(hdr[1..].try_into().unwrap()) as usize;
        let mut d = vec![0u8; len];
        stdout.read_exact(&mut d).await.unwrap();
        if hdr[0] == 1 {
            evs.push(serde_json::from_slice::<Value>(&d).unwrap());
        }
    }
    let status = tokio::time::timeout(std::time::Duration::from_secs(10), child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(!status.success());
    assert!(evs.iter().any(|v| v["ev"] == "error"), "{evs:?}");
}
