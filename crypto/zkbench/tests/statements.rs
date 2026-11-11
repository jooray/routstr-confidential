//! Protocol v3 statements (π_NK, π_WIN, π_C3S): completeness over the ideal
//! and the real-OT transport and through the `cu-prover` stdio job protocol,
//! soundness against wrong anchors / plaintexts, and one-bit disclosure.
//! π_WIN is exercised here in the framing `"1.1"` shape (one window: the
//! whole final body record must equal the pinned suffix and the inner
//! content type); `tests/win.rs` has the framing `"2"` shape.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use zkbench::fixtures;
use zkbench::proofs::{CheckResult, run_pair_ideal, run_pair_transport};
use zkbench::statements::{Params, PiWin, Proof, WinWindow, Witness};

fn passed(res: &anyhow::Result<Vec<CheckResult>>) -> bool {
    matches!(res, Ok(rs) if rs.iter().all(|r| r.ok))
}

fn check<'a>(res: &'a [CheckResult], label: &str) -> &'a CheckResult {
    res.iter().find(|r| r.label == label).unwrap_or_else(|| panic!("no check {label}"))
}

fn only_bit(got: &str) -> bool {
    got == "01" || got == "00"
}

fn win(params: Params) -> PiWin {
    match params {
        Params::PiWin(p) => p,
        _ => unreachable!(),
    }
}

/// `n` private bytes ('x'), then the pinned suffix.
fn prefixed(n: usize) -> Vec<u8> {
    let mut content = vec![b'x'; n];
    content.extend_from_slice(fixtures::SUFFIX);
    content
}

#[test]
fn names_and_roles() {
    for (name, p) in [("pi_nk", Proof::PiNK), ("pi_win", Proof::PiWin), ("pi_c3s", Proof::PiC3S)] {
        assert_eq!(p.name(), name);
        assert_eq!(Proof::from_name(name), Some(p));
    }
    // π_C2S is gone (π_WIN does its job): the name is unknown.
    assert_eq!(Proof::from_name("pi_c2s"), None);
    assert!(serde_json::from_str::<Params>(r#"{"PiC2S":{}}"#).is_err());
    assert!(!Proof::PiNK.client_proves());
    assert!(Proof::PiWin.client_proves() && Proof::PiC3S.client_proves());
    for (name, params, _) in fixtures::all() {
        assert_eq!(params.proof().name(), name);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn honest_proofs_verify_ideal() {
    for (name, params, witness) in fixtures::all() {
        let res = run_pair_ideal(&params, &witness).await;
        assert!(passed(&res), "{name}: {res:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn honest_proofs_verify_real_ot() {
    for (name, params, witness) in fixtures::all() {
        let out = run_pair_transport(Duration::ZERO, f64::INFINITY, &params, &witness)
            .await
            .unwrap_or_else(|e| panic!("{name}: {e:#}"));
        assert!(out.ok, "{name}: {:?}", out.checks);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn honest_bits_are_one() {
    for (params, witness) in [fixtures::pi_win_suffix(), fixtures::pi_c3s()] {
        let res = run_pair_ideal(&params, &witness).await.unwrap();
        assert_eq!(res.last().unwrap().got, "01");
    }
}

// --- wrong anchors -------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_anchor_fails() {
    for (name, mut params, witness) in fixtures::all() {
        let label = match &mut params {
            Params::PiWin(p) => {
                p.anchor[0] ^= 1;
                "anchor"
            }
            Params::PiC3S(p) => {
                p.h2[31] ^= 0x80;
                "h2"
            }
            Params::PiNK(p) => {
                p.hk[5] ^= 4;
                "hk"
            }
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
    // π_WIN over the suffix record with s_ap_0 instead of c_ap_1.
    let (params, _) = fixtures::pi_win_suffix();
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
    let (params, witness) = fixtures::pi_win_suffix();
    let mut p = win(params);
    assert_eq!(p.windows.len(), 1);
    assert!(p.windows[0].is_whole_record());
    assert_eq!(p.windows[0].expected.len(), fixtures::SUFFIX.len() + 1);
    let n = p.windows[0].expected.len();
    p.windows[0].expected = vec![b'z'; n - 1];
    p.windows[0].expected.push(0x17);
    let res = run_pair_ideal(&Params::PiWin(p), &witness).await.unwrap();
    assert!(check(&res, "anchor").ok);
    let last = res.last().unwrap();
    assert!(!last.ok);
    assert_eq!(last.got, "00");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn suffix_record_must_be_application_data() {
    // The suffix inside a record whose inner content type is handshake (0x16)
    // or padding (0): the compared range ends with that byte, so no equality.
    let (params, witness) = fixtures::pi_win_suffix();
    let p = win(params);
    for flip in [0x17 ^ 0x16, 0x17] {
        let mut wrong = p.clone();
        *wrong.windows[0].ct.last_mut().unwrap() ^= flip;
        let res = run_pair_ideal(&Params::PiWin(wrong), &witness).await.unwrap();
        assert_eq!(res.last().unwrap().got, "00", "inner type {:#04x} must not verify", 0x17 ^ flip);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn suffix_record_with_other_bytes_is_refused() {
    // The final body record carries 64 private bytes before the suffix. The
    // sidecar's window is the whole record against `suffix ‖ 0x17`: the
    // lengths differ, so it never gets as far as a proof...
    let (params, witness) = fixtures::pi_win_suffix_record(fixtures::SUFFIX_SEQ, &prefixed(64), fixtures::SUFFIX);
    let p = win(params);
    let w = &p.windows[0];
    assert!(!w.is_whole_record());
    assert!(WinWindow::whole_record(w.seq, w.ct.clone(), w.expected.clone()).is_err());
    // ...and if it ran one anyway, the record's first bytes are not the suffix.
    let res = run_pair_ideal(&Params::PiWin(p.clone()), &witness).await.unwrap();
    assert!(check(&res, "anchor").ok);
    assert_eq!(res.last().unwrap().got, "00");
    // The honest record is exactly the window `whole_record` builds, and its
    // wire form omits the zero offsets.
    let honest = win(fixtures::pi_win_suffix().0);
    let h = &honest.windows[0];
    let built = WinWindow::whole_record(h.seq, h.ct.clone(), h.expected.clone()).unwrap();
    let json = serde_json::to_string(&built).unwrap();
    assert_eq!(json, serde_json::to_string(h).unwrap());
    assert!(!json.contains("off") && !json.contains("sel_start"), "{json}");
}

/// The length check is the verifier's, not the circuit's: π_WIN compares
/// `|expected|` bytes, so a record that continues after `suffix ‖ 0x17`
/// (more content, then the real type byte) satisfies the statement over its
/// first bytes. `is_whole_record` is what refuses it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_longer_record_is_caught_by_the_length_not_the_circuit() {
    let mut content = fixtures::SUFFIX.to_vec();
    content.push(0x17);
    content.extend_from_slice(b",\"x\":1}");
    let (params, witness) = fixtures::pi_win_suffix_record(fixtures::SUFFIX_SEQ, &content, fixtures::SUFFIX);
    let p = win(params);
    assert!(!p.windows[0].is_whole_record());
    assert!(WinWindow::whole_record(p.windows[0].seq, p.windows[0].ct.clone(), p.windows[0].expected.clone()).is_err());
    let res = run_pair_ideal(&Params::PiWin(p), &witness).await.unwrap();
    assert_eq!(res.last().unwrap().got, "01", "the statement alone does not see the record's end");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn suffix_window_geometry_is_bound_to_the_record() {
    let (params, witness) = fixtures::pi_win_suffix();
    let p = win(params);
    type Mutation = (&'static str, Box<dyn Fn(&mut WinWindow)>);
    // A wrong sequence number or offset gives a different keystream.
    let zero: Vec<Mutation> = vec![
        ("seq + 1", Box::new(|w| w.seq += 1)),
        ("seq - 1", Box::new(|w| w.seq -= 1)),
        ("off + 16", Box::new(|w| w.off += 16)),
    ];
    for (name, m) in zero {
        let mut q = p.clone();
        m(&mut q.windows[0]);
        let res = run_pair_ideal(&Params::PiWin(q), &witness).await.unwrap();
        assert_eq!(res.last().unwrap().got, "00", "{name} must not verify");
    }
    // Refused before any proof runs: an unaligned offset, a compared range
    // that leaves the ciphertext (moved, or the ciphertext cut short).
    let errors: Vec<Mutation> = vec![
        ("off + 1", Box::new(|w| w.off += 1)),
        ("sel_start + 1", Box::new(|w| w.sel_start += 1)),
        ("ct one byte short", Box::new(|w| { w.ct.pop(); })),
        ("empty ct", Box::new(|w| w.ct.clear())),
        ("off past a record", Box::new(|w| w.off = 1 << 15)),
    ];
    for (name, m) in errors {
        let mut q = p.clone();
        m(&mut q.windows[0]);
        assert!(run_pair_ideal(&Params::PiWin(q), &witness).await.is_err(), "{name} must be an error");
    }
    // A change of geometry that keeps the statement well-formed is no longer
    // the whole-record window, so a party checking `is_whole_record` (and the
    // ciphertext against its own record) refuses it.
    let not_whole: Vec<Mutation> = vec![
        ("ct one byte longer", Box::new(|w| w.ct.push(0))),
        ("expected without the content type", Box::new(|w| { w.expected.pop(); })),
        ("off + 16", Box::new(|w| w.off += 16)),
        ("a later start", Box::new(|w| { w.sel_start += 1; w.expected.remove(0); })),
    ];
    for (name, m) in not_whole {
        let mut q = p.clone();
        m(&mut q.windows[0]);
        assert!(!q.windows[0].is_whole_record(), "{name}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn win_verifier_moved_window_reveals_no_plaintext() {
    // 400 private 'x' bytes before the suffix; the verifier's window covers
    // them (from the record's first byte, and at a later block).
    let (params, witness) = fixtures::pi_win_suffix_record(fixtures::SUFFIX_SEQ, &prefixed(400), fixtures::SUFFIX);
    let base = win(params);
    let mut moved = base.clone();
    moved.windows[0].off = 64;
    moved.windows[0].ct.drain(..64);
    moved.windows[0].sel_start = 5;
    for p in [base.clone(), moved] {
        let res = run_pair_ideal(&Params::PiWin(p), &witness).await.unwrap();
        assert_eq!(res.len(), 2, "the anchor digest and one bit");
        let last = res.last().unwrap();
        assert!(!last.ok);
        assert!(only_bit(&last.got), "leaked bytes: {}", last.got);
        assert!(!last.got.contains("78"), "plaintext 'x' bytes decoded");
    }
    // A correct guess of private bytes is still only a bit (the client
    // refuses such parameters before proving: they are not its suffix).
    let mut guess = base;
    let n = guess.windows[0].expected.len();
    guess.windows[0].expected = vec![b'x'; n];
    let res = run_pair_ideal(&Params::PiWin(guess), &witness).await.unwrap();
    assert!(only_bit(&res.last().unwrap().got));
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
    for skip in [p.skip + 1, p.skip - 1] {
        let mut q = p.clone();
        q.skip = skip;
        let res = run_pair_ideal(&Params::PiC3S(q), &witness).await.unwrap();
        assert!(!res.last().unwrap().ok, "skip {skip} must not verify");
    }
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
async fn c3s_records_must_be_application_data() {
    // The same R inside a record whose inner content type is handshake (0x16)
    // or a padded record (last byte 0): no equality.
    let (params, witness) = fixtures::pi_c3s_after_updates(0);
    let Params::PiC3S(p) = params else { unreachable!() };
    for flip in [0x17 ^ 0x16, 0x17] {
        let mut wrong = p.clone();
        *wrong.records[0].ct.last_mut().unwrap() ^= flip;
        let res = run_pair_ideal(&Params::PiC3S(wrong), &witness).await.unwrap();
        assert!(!res.last().unwrap().ok, "inner type {:#04x} must not verify", 0x17 ^ flip);
    }
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
    // Not block-aligned: refused (a later record with an offset is refused
    // too, see tests/malformed.rs).
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c3s_minimal_tail_as_the_sidecar_builds_it() {
    // Usage (skip 0) and error head (body in skip), each over several records
    // with the first one decrypted from an offset.
    for (total, record_len, r_len, skip) in [(3000, 700, 300, 0), (3000, 700, 300, 900), (3001, 512, 40, 700)] {
        let (params, witness) = fixtures::pi_c3s_disclosure(total, record_len, r_len, skip);
        let res = run_pair_ideal(&params, &witness).await;
        assert!(passed(&res), "{total}/{record_len}/{r_len}/{skip}: {res:?}");
    }
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
fn statement_stats() {
    for (name, params, _) in fixtures::all() {
        let s = zkbench::stats(&params);
        assert!(s.aes_blocks >= 2, "{name}");
        match params {
            Params::PiWin(p) => {
                assert_eq!(s.sha256_compressions, 7);
                // The whole suffix record: one AES block per 16 bytes.
                assert_eq!(s.aes_blocks, p.windows[0].ct.len().div_ceil(16));
            }
            Params::PiC3S(_) => assert_eq!(s.sha256_compressions, 7),
            Params::PiNK(p) => assert_eq!(s.sha256_compressions, 1 + (5 + p.head_len + 1 + 9).div_ceil(64)),
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
fn cu_prover_job_stdin_runs_the_proofs() {
    for (name, params, witness) in fixtures::all() {
        assert!(run_cu_prover_pair(name, &params, &witness), "{name}: honest job failed");
    }
    // A wrong anchor makes the verifier process fail.
    let (params, witness) = fixtures::pi_win_suffix();
    let mut p = win(params);
    p.anchor[3] ^= 1;
    assert!(!run_cu_prover_pair("pi_win", &Params::PiWin(p), &witness));
    // So does a record that is not the suffix (one bit, zero).
    let (params, witness) = fixtures::pi_win_suffix_record(fixtures::SUFFIX_SEQ, &prefixed(64), fixtures::SUFFIX);
    assert!(!run_cu_prover_pair("pi_win", &params, &witness));
}

/// A job whose params are for another proof than the one it names is refused
/// before any protocol byte, on either role. The retired `pi_c2s` is refused
/// exactly as a name that never existed.
#[test]
fn cu_prover_job_refuses_params_for_another_proof() {
    let (params, witness) = fixtures::pi_c3s();
    for (name, role, w) in ["pi_win", "pi_c2s", "pi_bogus"]
        .into_iter()
        .flat_map(|n| [(n, "prover", Some(&witness)), (n, "verifier", None)])
    {
        let v = serde_json::json!({ "proof": name, "params": params, "witness": w });
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
                panic!("{name} {role}: a mismatched job was not refused");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        drop(stdin);
        let mut out = Vec::new();
        child.stdout.take().unwrap().read_to_end(&mut out).unwrap();
        let mut err = String::new();
        child.stderr.take().unwrap().read_to_string(&mut err).unwrap();
        assert!(!status.success(), "{name} {role}");
        assert!(out.is_empty(), "{name} {role}: wrote protocol bytes");
        assert!(err.contains(&format!("the job is for {name}, its params are for pi_c3s")), "{name} {role}: {err}");
    }
}

// --- image requests (docs/CONFIDENTIAL-IMAGES.md) ---------------------------
// The same statements with an images head and suffix: no circuit change.

/// The shared test vector (model z-image-turbo, 2 variants, WebP).
const IMAGES_SUFFIX: &[u8] = br#","model":"z-image-turbo","variants":2,"return_binary":false,"enhance_prompt":false,"enable_web_search":false,"style_references":[],"format":"webp"}"#;

/// π_WIN parameters as the sidecar builds them for an image request in
/// framing `"1.1"`: the final body record (the suffix the client sent) as one
/// whole-record window against the suffix the node rendered.
fn images_win(suffix_in_record: &[u8], expected_suffix: &[u8]) -> (Params, Witness) {
    fixtures::pi_win_suffix_record(1, suffix_in_record, expected_suffix)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn images_suffix_proves_and_a_swapped_count_does_not() {
    let (params, witness) = images_win(IMAGES_SUFFIX, IMAGES_SUFFIX);
    assert!(win(params.clone()).windows[0].is_whole_record());
    let res = run_pair_ideal(&params, &witness).await;
    assert!(passed(&res), "{res:?}");
    // The client sent 4 variants while the node pinned 2: one bit, zero.
    let sent = String::from_utf8(IMAGES_SUFFIX.to_vec()).unwrap().replace(r#""variants":2"#, r#""variants":4"#);
    let (params, witness) = images_win(sent.as_bytes(), IMAGES_SUFFIX);
    assert!(win(params.clone()).windows[0].is_whole_record(), "same length: only the proof can tell");
    let res = run_pair_ideal(&params, &witness).await.unwrap();
    assert_eq!(res.last().unwrap().got, "00");
    // Another variant's suffix of another length (a different format pin):
    // refused on the length, and zero if proven anyway.
    let sent = String::from_utf8(IMAGES_SUFFIX.to_vec()).unwrap().replace(r#""format":"webp""#, r#""format":"png","width":2048"#);
    let (params, witness) = images_win(sent.as_bytes(), IMAGES_SUFFIX);
    assert!(!win(params.clone()).windows[0].is_whole_record());
    let res = run_pair_ideal(&params, &witness).await.unwrap();
    assert_eq!(res.last().unwrap().got, "00");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn images_head_template_proves_under_pi_nk() {
    let v = fixtures::v2_secrets();
    let mut parts = fixtures::pi_nk_parts();
    let chat = b"POST /api/v1/chat/completions ".as_slice();
    let images = b"POST /api/v1/image/generate ".as_slice();
    assert!(parts.template.starts_with(chat));
    let shift = images.len() as isize - chat.len() as isize;
    let mut t = images.to_vec();
    t.extend_from_slice(&parts.template[chat.len()..]);
    parts.template = t;
    parts.key_offsets = parts.key_offsets.iter().map(|o| (*o as isize + shift) as usize).collect();
    let c1 = fixtures::pi_nk_ciphertext(&v, &parts.template, &parts.key_offsets, &parts.key);
    let params = Params::PiNK(fixtures::pi_nk_params(&v, &parts, &c1));
    let witness = Witness::NodeKey { k0: v.k0, iv0: v.iv0, key: parts.key.clone() };
    let res = run_pair_ideal(&params, &witness).await;
    assert!(passed(&res), "{res:?}");
}
