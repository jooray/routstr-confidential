//! Protocol v2 statements (π_NK, π_C2S, π_C3S): completeness over the ideal
//! and the real-OT transport and through the `cu-prover` stdio job protocol,
//! soundness against wrong anchors / plaintexts, and one-bit disclosure.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use zkbench::fixtures;
use zkbench::proofs::{CheckResult, run_pair_ideal, run_pair_transport};
use zkbench::statements::{Params, Proof, Witness};

fn passed(res: &anyhow::Result<Vec<CheckResult>>) -> bool {
    matches!(res, Ok(rs) if rs.iter().all(|r| r.ok))
}

fn check<'a>(res: &'a [CheckResult], label: &str) -> &'a CheckResult {
    res.iter().find(|r| r.label == label).unwrap_or_else(|| panic!("no check {label}"))
}

fn only_bit(got: &str) -> bool {
    got == "01" || got == "00"
}

#[test]
fn names_and_roles() {
    for (name, p) in [("pi_nk", Proof::PiNK), ("pi_c2s", Proof::PiC2S), ("pi_c3s", Proof::PiC3S)] {
        assert_eq!(p.name(), name);
        assert_eq!(Proof::from_name(name), Some(p));
    }
    assert!(!Proof::PiNK.client_proves());
    assert!(Proof::PiC2S.client_proves() && Proof::PiC3S.client_proves());
    for (name, params, _) in fixtures::all() {
        assert_eq!(params.proof().name(), name);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn honest_v2_proofs_verify_ideal() {
    for (name, params, witness) in fixtures::all() {
        let res = run_pair_ideal(&params, &witness).await;
        assert!(passed(&res), "{name}: {res:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn honest_v2_proofs_verify_real_ot() {
    for (name, params, witness) in fixtures::all() {
        let out = run_pair_transport(Duration::ZERO, f64::INFINITY, &params, &witness)
            .await
            .unwrap_or_else(|e| panic!("{name}: {e:#}"));
        assert!(out.ok, "{name}: {:?}", out.checks);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn honest_bits_are_one() {
    for (params, witness) in [fixtures::pi_c2s(), fixtures::pi_c3s()] {
        let res = run_pair_ideal(&params, &witness).await.unwrap();
        assert_eq!(res.last().unwrap().got, "01");
    }
}

// --- wrong anchors -------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_anchor_fails() {
    for (name, mut params, witness) in fixtures::all() {
        let label = match &mut params {
            Params::PiC2S(p) => {
                p.h1[0] ^= 1;
                "h1"
            }
            Params::PiC3S(p) => {
                p.h2[31] ^= 0x80;
                "h2"
            }
            Params::PiNK(p) => {
                p.hk[5] ^= 4;
                "hk"
            }
            _ => unreachable!(),
        };
        let res = run_pair_ideal(&params, &witness).await;
        assert!(!passed(&res), "{name}: wrong {label} must fail");
        let res = res.unwrap();
        assert!(!check(&res, label).ok);
    }
}

/// A prover holding a different secret than the anchored one fails, even if
/// that secret decrypts the records (it does not hash to the anchor).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_secret_fails() {
    let v = fixtures::v2_secrets();
    // π_C2S with s_ap_0 instead of c_ap_1.
    let (params, _) = fixtures::pi_c2s();
    let res = run_pair_ideal(&params, &Witness::Secret(v.s_ap_0)).await;
    assert!(!passed(&res));
    // π_NK with a different IV.
    let (params, _) = fixtures::pi_nk();
    let parts = fixtures::pi_nk_parts();
    let mut iv0 = v.iv0;
    iv0[11] ^= 1;
    let res = run_pair_ideal(&params, &Witness::NodeKey { k0: v.k0, iv0, key: parts.key }).await;
    assert!(!passed(&res));
}

// --- one-bit disclosure ---------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn suffix_mismatch_gives_zero_bit() {
    let (params, witness) = fixtures::pi_c2s();
    let Params::PiC2S(mut p) = params else { unreachable!() };
    let n = p.expected.len();
    p.expected = vec![b'z'; n];
    let res = run_pair_ideal(&Params::PiC2S(p), &witness).await.unwrap();
    assert!(check(&res, "h1").ok);
    let last = res.last().unwrap();
    assert!(!last.ok);
    assert_eq!(last.got, "00");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c2s_verifier_moved_window_reveals_no_plaintext() {
    // 400 private 'x' bytes before the suffix; the verifier moves onto them.
    let (params, witness) = fixtures::pi_c2s_after(400);
    let Params::PiC2S(mut p) = params else { unreachable!() };
    p.sel_start = 0;
    let res = run_pair_ideal(&Params::PiC2S(p), &witness).await;
    if let Ok(res) = res {
        let last = res.last().unwrap();
        assert!(!last.ok);
        assert!(only_bit(&last.got), "leaked bytes: {}", last.got);
        assert!(!last.got.contains("78"), "plaintext 'x' bytes decoded");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c3s_verifier_moved_window_reveals_no_plaintext() {
    // Content is 500 × 'y' then R. Point the comparison at private bytes
    // (larger skip) and at a guess of them: the verifier learns one bit.
    let (params, witness) = fixtures::pi_c3s();
    let Params::PiC3S(mut p) = params else { unreachable!() };
    let r_len = p.expected.len();
    p.skip = r_len + 10;
    let res = run_pair_ideal(&Params::PiC3S(p.clone()), &witness).await.unwrap();
    let last = res.last().unwrap();
    assert!(!last.ok);
    assert!(only_bit(&last.got), "leaked bytes: {}", last.got);
    // A correct guess of private bytes is still only a bit.
    p.expected = vec![b'y'; r_len];
    let res = run_pair_ideal(&Params::PiC3S(p), &witness).await.unwrap();
    let last = res.last().unwrap();
    assert!(only_bit(&last.got));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c3s_usage_mismatch_and_error_head_skip() {
    let (params, witness) = fixtures::pi_c3s();
    let Params::PiC3S(mut p) = params else { unreachable!() };
    let r = p.expected.clone();
    let mut wrong = p.clone();
    wrong.expected = vec![b'y'; r.len()];
    let res = run_pair_ideal(&Params::PiC3S(wrong), &witness).await.unwrap();
    assert_eq!(res.last().unwrap().got, "00");
    p.expected = r[..40].to_vec();
    p.skip = r.len() - 40;
    let res = run_pair_ideal(&Params::PiC3S(p.clone()), &witness).await;
    assert!(passed(&res), "{res:?}");
    p.skip += 1;
    let res = run_pair_ideal(&Params::PiC3S(p), &witness).await.unwrap();
    assert!(!res.last().unwrap().ok);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c3s_after_server_key_updates() {
    // Records under s_ap_2 verify with key_updates = 2, and with nothing else.
    let (params, witness) = fixtures::pi_c3s_after_updates(2);
    let res = run_pair_ideal(&params, &witness).await;
    assert!(passed(&res), "{res:?}");
    let Params::PiC3S(mut p) = params else { unreachable!() };
    for wrong in [0, 1, 3] {
        p.key_updates = wrong;
        let res = run_pair_ideal(&Params::PiC3S(p.clone()), &witness).await.unwrap();
        assert!(!res.last().unwrap().ok, "key_updates {wrong} must not verify");
    }
    // Bounded, and omitted from the wire when 0 (older peers parse it).
    p.key_updates = zkbench::statements::MAX_SERVER_KEY_UPDATES + 1;
    assert!(run_pair_ideal(&Params::PiC3S(p.clone()), &witness).await.is_err());
    p.key_updates = 0;
    assert!(!serde_json::to_string(&p).unwrap().contains("key_updates"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c3s_first_record_from_an_offset() {
    // Only the record's tail is decrypted: from a block-aligned offset that
    // still covers R. Fewer AES blocks, same statement about the end.
    let (params, witness) = fixtures::pi_c3s_after_updates(0);
    let Params::PiC3S(full) = params else { unreachable!() };
    let r_len = full.expected.len();
    let content = full.records[0].ct.len() - 1;
    let off = (content - r_len) / 16 * 16;
    let mut p = full.clone();
    p.records[0].ct = full.records[0].ct[off..].to_vec();
    p.records[0].off = off;
    assert!(passed(&run_pair_ideal(&Params::PiC3S(p.clone()), &witness).await), "tail from {off}");
    // A wrong offset decrypts with the wrong counters: no equality.
    let mut wrong = p.clone();
    wrong.records[0].off = off - 16;
    assert!(!run_pair_ideal(&Params::PiC3S(wrong), &witness).await.unwrap().last().unwrap().ok);
    // Not block-aligned, or a later record with an offset: refused.
    let mut odd = p.clone();
    odd.records[0].off = off + 1;
    assert!(run_pair_ideal(&Params::PiC3S(odd), &witness).await.is_err());
    // Too far: the tail no longer covers R.
    let mut short = full.clone();
    let late = off + 16;
    short.records[0].ct = full.records[0].ct[late..].to_vec();
    short.records[0].off = late;
    assert!(run_pair_ideal(&Params::PiC3S(short), &witness).await.is_err());
}

// --- π_NK soundness -------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nk_key_outside_alphabet_fails() {
    let v = fixtures::v2_secrets();
    let mut parts = fixtures::pi_nk_parts();
    parts.key[7] = b'+';
    // N writes the record it claims, so the commitment matches; only the
    // alphabet check catches the stray byte.
    let c1 = fixtures::pi_nk_ciphertext(&v, &parts.template, &parts.key_offsets, &parts.key);
    let params = Params::PiNK(fixtures::pi_nk_params(&v, &parts, &c1));
    let witness = Witness::NodeKey { k0: v.k0, iv0: v.iv0, key: parts.key.clone() };
    let res = run_pair_ideal(&params, &witness).await.unwrap();
    assert!(check(&res, "c_commit").ok && check(&res, "hk").ok);
    assert!(!check(&res, "key_alphabet").ok);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nk_ciphertext_not_matching_template_fails() {
    let v = fixtures::v2_secrets();
    let parts = fixtures::pi_nk_parts();
    let witness = Witness::NodeKey { k0: v.k0, iv0: v.iv0, key: parts.key.clone() };

    // (a) the record N actually writes has a different head than the template
    // (an extra header injected in place of `identity`).
    let mut other = parts.template.clone();
    let pos = other.windows(8).position(|w| w == b"identity").unwrap();
    other[pos..pos + 8].copy_from_slice(b"gzip,br ");
    let c1 = fixtures::pi_nk_ciphertext(&v, &other, &parts.key_offsets, &parts.key);
    let params = Params::PiNK(fixtures::pi_nk_params(&v, &parts, &c1));
    let res = run_pair_ideal(&params, &witness).await.unwrap();
    assert!(!check(&res, "c_commit").ok);
    assert!(check(&res, "hk").ok);

    // (b) one flipped ciphertext bit.
    let mut c1 = fixtures::pi_nk_ciphertext(&v, &parts.template, &parts.key_offsets, &parts.key);
    c1[20] ^= 1;
    let params = Params::PiNK(fixtures::pi_nk_params(&v, &parts, &c1));
    let res = run_pair_ideal(&params, &witness).await;
    assert!(!passed(&res));

    // (c) the record is under another key (not the anchored K_0).
    let mut v2 = fixtures::v2_secrets();
    v2.k0[0] ^= 1;
    let c1 = fixtures::pi_nk_ciphertext(&v2, &parts.template, &parts.key_offsets, &parts.key);
    let params = Params::PiNK(fixtures::pi_nk_params(&v, &parts, &c1));
    let res = run_pair_ideal(&params, &witness).await;
    assert!(!passed(&res));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nk_rejects_unsupported_alphabet_and_bad_shapes() {
    let (params, witness) = fixtures::pi_nk();
    let Params::PiNK(p) = params else { unreachable!() };
    let mut a = p.clone();
    a.key_alphabet = "[A-Z]".into();
    assert!(run_pair_ideal(&Params::PiNK(a), &witness).await.is_err());
    let mut b = p.clone();
    b.key_offsets[1] = b.key_offsets[0];
    assert!(run_pair_ideal(&Params::PiNK(b), &witness).await.is_err());
    let mut c = p;
    c.template.pop();
    assert!(run_pair_ideal(&Params::PiNK(c), &witness).await.is_err());
}

#[test]
fn v2_stats() {
    for (name, params, _) in fixtures::all() {
        let s = zkbench::stats(&params);
        assert!(s.aes_blocks >= 2, "{name}");
        match params {
            Params::PiC2S(_) | Params::PiC3S(_) => assert_eq!(s.sha256_compressions, 7),
            Params::PiNK(p) => assert_eq!(s.sha256_compressions, 1 + (5 + p.head_len + 1 + 9).div_ceil(64)),
            _ => unreachable!(),
        }
    }
}

// --- the cu-prover job protocol ------------------------------------------

/// Run `cu-prover --job-stdin` twice (prover and verifier) with their stdio
/// cross-connected, exactly as the client and the sidecar do. Returns the
/// verifier's exit success.
fn run_cu_prover_pair(name: &str, params: &Params, witness: &Witness) -> bool {
    let bin = env!("CARGO_BIN_EXE_cu-prover");
    let job = |role_witness: Option<&Witness>| {
        let v = serde_json::json!({ "proof": name, "params": params, "witness": role_witness });
        let body = serde_json::to_vec(&v).unwrap();
        let mut frame = (body.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&body);
        frame
    };
    let spawn = |role: &str| {
        Command::new(bin)
            .args(["--job-stdin", "--role", role])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    };
    let mut prover = spawn("prover");
    let mut verifier = spawn("verifier");
    let mut p_in = prover.stdin.take().unwrap();
    let mut v_in = verifier.stdin.take().unwrap();
    p_in.write_all(&job(Some(witness))).unwrap();
    v_in.write_all(&job(None)).unwrap();
    let p_out = prover.stdout.take().unwrap();
    let v_out = verifier.stdout.take().unwrap();
    let pump = |mut r: std::process::ChildStdout, mut w: std::process::ChildStdin| {
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match r.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if w.write_all(&buf[..n]).is_err() {
                            break;
                        }
                        let _ = w.flush();
                    }
                }
            }
        })
    };
    let t1 = pump(p_out, v_in);
    let t2 = pump(v_out, p_in);
    let deadline = Instant::now() + Duration::from_secs(120);
    let v_status = loop {
        if let Some(s) = verifier.try_wait().unwrap() {
            break s;
        }
        if Instant::now() > deadline {
            let _ = verifier.kill();
            let _ = prover.kill();
            panic!("{name}: cu-prover pair timed out");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let p_deadline = Instant::now() + Duration::from_secs(30);
    while prover.try_wait().unwrap().is_none() {
        if Instant::now() > p_deadline {
            let _ = prover.kill();
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = (t1.join(), t2.join());
    v_status.success()
}

#[test]
fn cu_prover_job_stdin_runs_v2_proofs() {
    for (name, params, witness) in fixtures::all() {
        assert!(run_cu_prover_pair(name, &params, &witness), "{name}: honest job failed");
    }
    // A wrong anchor makes the verifier process fail.
    let (params, witness) = fixtures::pi_c2s();
    let Params::PiC2S(mut p) = params else { unreachable!() };
    p.h1[3] ^= 1;
    assert!(!run_cu_prover_pair("pi_c2s", &Params::PiC2S(p), &witness));
}

/// A job whose params are for another proof than the one it names is refused
/// before any protocol byte, on either role.
#[test]
fn cu_prover_job_refuses_params_for_another_proof() {
    let (params, witness) = fixtures::pi_c3s();
    for (role, w) in [("prover", Some(&witness)), ("verifier", None)] {
        let v = serde_json::json!({ "proof": "pi_c2s", "params": params, "witness": w });
        let body = serde_json::to_vec(&v).unwrap();
        let mut frame = (body.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&body);
        let mut child = Command::new(env!("CARGO_BIN_EXE_cu-prover"))
            .args(["--job-stdin", "--role", role])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // Keep stdin open: a refusal must not depend on the peer going away.
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(&frame).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(s) = child.try_wait().unwrap() {
                break s;
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                panic!("{role}: a mismatched job was not refused");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        drop(stdin);
        let mut out = Vec::new();
        child.stdout.take().unwrap().read_to_end(&mut out).unwrap();
        let mut err = String::new();
        child.stderr.take().unwrap().read_to_string(&mut err).unwrap();
        assert!(!status.success(), "{role}");
        assert!(out.is_empty(), "{role}: wrote protocol bytes");
        assert!(err.contains("its params are for pi_c3s"), "{role}: {err}");
    }
}
