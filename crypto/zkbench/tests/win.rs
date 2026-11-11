//! π_WIN in the framing `"2"` shape: several record windows under one traffic
//! secret. Completeness, the one-bit result, and the attacks the sidecar's
//! windows are there to stop (a frame hidden in a DATA record, TLS padding
//! that moves the frame boundary, a wrong suffix, a wrong header block).

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use zkbench::channel::{Party, Prealloc, ZkChannel, ot_demand_with};
use zkbench::fixtures::{self, SUFFIX, h2_frame, pi_win_frames, v2_secrets, win_record, win_windows};
use zkbench::proofs::{CheckResult, run_pair_ideal, run_pair_transport, stats};
use zkbench::statements::{
    MAX_WIN_BYTES, MAX_WIN_WINDOWS, Params, PiWin, Proof, WinWindow, Witness, check_pi_win, pi_win_blocks,
};

fn passed(res: &anyhow::Result<Vec<CheckResult>>) -> bool {
    matches!(res, Ok(rs) if rs.iter().all(|r| r.ok))
}

fn win(params: Params) -> PiWin {
    match params {
        Params::PiWin(p) => p,
        _ => unreachable!(),
    }
}

/// The verifier's bit for `p` proven with `witness` (false when the anchor
/// check fails too).
async fn bit(p: &PiWin, witness: &Witness) -> Option<bool> {
    let res = run_pair_ideal(&Params::PiWin(p.clone()), witness).await.ok()?;
    let c = res.iter().find(|r| r.label == "windows")?;
    assert!(c.got == "01" || c.got == "00", "more than one bit decoded: {}", c.got);
    Some(c.ok)
}

/// What the sidecar expects for the fixture request, over the records a
/// (possibly dishonest) client actually sent: `records[i]` is
/// `(content, inner type, zero padding)`.
fn sidecar_view(records: &[(Vec<u8>, u8, usize)]) -> PiWin {
    let v = v2_secrets();
    let honest = pi_win_frames(4000);
    let mut windows = Vec::new();
    for (i, (content, ctype, pad)) in records.iter().enumerate() {
        let ct = win_record(&v.c_ap_1, i as u64, content, *ctype, *pad);
        // N derives the frame header from the record length it relays: the
        // length field is inner_len - 1 - 9, the rest is what the request
        // allows at this position.
        let inner = ct.len();
        let mut expect = honest[i].clone();
        let n = inner - 10;
        expect[0] = (n >> 16) as u8;
        expect[1] = (n >> 8) as u8;
        expect[2] = n as u8;
        expect.resize(9 + n, 0);
        if i == 0 {
            expect = honest[0].clone();
            expect.resize(inner - 1, 0);
        }
        if i == 2 {
            let at = expect.len() - SUFFIX.len();
            expect[at..].copy_from_slice(SUFFIX);
        }
        let (head, tail) = match i {
            0 => (expect.len(), 0),
            2 => (9, SUFFIX.len()),
            _ => (9, 0),
        };
        windows.extend(win_windows(i as u64, &ct, &expect, head, tail));
    }
    PiWin { anchor: v.h1(), key_updates: 0, windows }
}

fn honest_records() -> Vec<(Vec<u8>, u8, usize)> {
    pi_win_frames(4000).into_iter().map(|f| (f, 0x17, 0)).collect()
}

#[test]
fn name_and_role() {
    assert_eq!(Proof::PiWin.name(), "pi_win");
    assert_eq!(Proof::from_name("pi_win"), Some(Proof::PiWin));
    assert!(Proof::PiWin.client_proves());
    assert_eq!(fixtures::pi_win().0.proof(), Proof::PiWin);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn honest_request_verifies() {
    let (params, witness) = fixtures::pi_win();
    let res = run_pair_ideal(&params, &witness).await;
    assert!(passed(&res), "{res:?}");
    let res = res.unwrap();
    // The verifier decodes the anchor digest and one bit, nothing else.
    assert_eq!(res.len(), 2);
    assert_eq!(res[0].label, "anchor");
    assert_eq!(res[1].got, "01");
    let out = run_pair_transport(Duration::ZERO, f64::INFINITY, &params, &witness).await.unwrap();
    assert!(out.ok, "{:?}", out.checks);
    // The sidecar's own view of honest records is the same statement.
    assert_eq!(bit(&sidecar_view(&honest_records()), &witness).await, Some(true));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_anchor_or_secret_fails() {
    let (params, witness) = fixtures::pi_win();
    let mut p = win(params.clone());
    p.anchor[7] ^= 1;
    assert!(!passed(&run_pair_ideal(&Params::PiWin(p), &witness).await));
    // Another secret: the anchor check fails (and the bit is 0).
    let other = Witness::Secret(v2_secrets().s_ap_0);
    assert!(!passed(&run_pair_ideal(&params, &other).await));
    // The server-direction anchor with the server secret is a valid statement
    // only over server records: client records do not decrypt under it.
    let mut p = win(params);
    p.anchor = v2_secrets().h2();
    assert_eq!(bit(&p, &other).await, Some(false));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn any_wrong_window_byte_gives_zero() {
    let (params, witness) = fixtures::pi_win();
    let base = win(params);
    for wi in 0..base.windows.len() {
        for at in [0, base.windows[wi].expected.len() - 1] {
            let mut p = base.clone();
            p.windows[wi].expected[at] ^= 0x20;
            assert_eq!(bit(&p, &witness).await, Some(false), "window {wi} byte {at}");
        }
    }
    // A wrong sequence number or offset decrypts to noise.
    let mut p = base.clone();
    p.windows[1].seq += 1;
    assert_eq!(bit(&p, &witness).await, Some(false));
    let mut p = base.clone();
    let last = p.windows.len() - 1;
    p.windows[last].off += 16;
    assert_eq!(bit(&p, &witness).await, Some(false));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_frame_hidden_in_a_data_record_is_refused() {
    let witness = Witness::Secret(v2_secrets().c_ap_1);
    // (a) The second record is a HEADERS frame for another stream instead of
    // DATA on the request's stream: its frame header is not the expected one.
    let mut recs = honest_records();
    let n = recs[1].0.len() - 9;
    recs[1].0 = h2_frame(1, 4, 5, &vec![0x82; n]);
    assert_eq!(bit(&sidecar_view(&recs), &witness).await, Some(false));
    // The same with only the stream id, the type or a flag changed.
    for (ty, flags, stream) in [(0u8, 0u8, 5u32), (1, 0, 3), (0, 1, 3), (0, 8, 3)] {
        let mut recs = honest_records();
        let payload = recs[1].0[9..].to_vec();
        recs[1].0 = h2_frame(ty, flags, stream, &payload);
        assert_eq!(bit(&sidecar_view(&recs), &witness).await, Some(false), "{ty} {flags} {stream}");
    }
    // A DATA record whose length field is shorter than the record, with a
    // second frame in the rest: the length field is part of the header.
    let mut recs = honest_records();
    let whole = recs[1].0.len() - 9;
    let mut two = h2_frame(0, 0, 3, &vec![b'x'; whole - 100]);
    two.extend_from_slice(&h2_frame(1, 5, 5, &vec![0x82; 91]));
    assert_eq!(two.len(), recs[1].0.len());
    recs[1].0 = two;
    assert_eq!(bit(&sidecar_view(&recs), &witness).await, Some(false));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_padding_cannot_move_the_frame_boundary() {
    let witness = Witness::Secret(v2_secrets().c_ap_1);
    // (b) A record of the honest length whose inner plaintext is a shorter
    // DATA frame, a hidden HEADERS frame, the type byte and zero padding.
    // Its length field cannot equal inner_len - 10, and its last byte is not
    // the content type.
    for pad in [1usize, 16, 40] {
        let mut recs = honest_records();
        let full = recs[1].0.len();
        // The frame header claims exactly the length N derives from the
        // record size (so the header window matches); the payload then holds
        // a hidden frame, and TLS padding makes up the claimed length.
        let mut content = h2_frame(0, 0, 3, &vec![b'x'; full - 9]);
        content.truncate(full - pad);
        recs[1] = (content, 0x17, pad);
        let p = sidecar_view(&recs);
        assert_eq!(bit(&p, &witness).await, Some(false), "pad {pad}");
        // Without the last-byte window the same record would pass: this is
        // what rule A.4.3 is for.
        let mut weak = p.clone();
        weak.windows.remove(2);
        assert_eq!(bit(&weak, &witness).await, Some(true), "pad {pad} without the last-byte window");
    }
    // A handshake-typed record (a client KeyUpdate) in place of a frame.
    let mut recs = honest_records();
    recs[1].1 = 0x16;
    assert_eq!(bit(&sidecar_view(&recs), &witness).await, Some(false));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_suffix_or_header_block_is_refused() {
    let witness = Witness::Secret(v2_secrets().c_ap_1);
    // (c) The last DATA frame ends in another model's suffix of the same length.
    let mut recs = honest_records();
    let n = recs[2].0.len();
    let at = n - SUFFIX.len() + 10;
    recs[2].0[at] ^= 1;
    assert_eq!(bit(&sidecar_view(&recs), &witness).await, Some(false));
    // The suffix is not at the end (one more byte after it).
    let mut recs = honest_records();
    let mut payload = recs[2].0[9..].to_vec();
    payload.push(b' ');
    recs[2].0 = h2_frame(0, 1, 3, &payload);
    assert_eq!(bit(&sidecar_view(&recs), &witness).await, Some(false));
    // (e) A HEADERS block with another :path of the same length.
    let mut recs = honest_records();
    let pos = recs[0].0.windows(5).position(|w| w == b"/chat").unwrap();
    recs[0].0[pos + 1..pos + 5].copy_from_slice(b"keys");
    assert_eq!(bit(&sidecar_view(&recs), &witness).await, Some(false));
    // A longer block (an extra header) changes the record length: N compares
    // the whole record against the public block, which no longer fits.
    let mut recs = honest_records();
    let mut block = recs[0].0[9..].to_vec();
    block.extend_from_slice(b"\x00\x01x\x01y");
    recs[0].0 = h2_frame(1, 4, 3, &block);
    assert_eq!(bit(&sidecar_view(&recs), &witness).await, Some(false));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn key_updates_step_the_secret() {
    let v = v2_secrets();
    let next = cu_crypto::keyschedule::traffic_update(&cu_crypto::keyschedule::Secret::new(v.s_ap_0));
    let content = h2_frame(1, 4, 3, &[0x88, 0x5f, 0x03, b'a', b'/', b'b']);
    let ct = win_record(next.as_bytes(), 0, &content, 0x17, 0);
    let p = PiWin { anchor: v.h2(), key_updates: 1, windows: win_windows(0, &ct, &content, content.len(), 0) };
    let witness = Witness::Secret(v.s_ap_0);
    assert_eq!(bit(&p, &witness).await, Some(true));
    let mut q = p.clone();
    q.key_updates = 0;
    assert_eq!(bit(&q, &witness).await, Some(false));
    q.key_updates = 17;
    assert!(run_pair_ideal(&Params::PiWin(q), &witness).await.is_err());
}

#[test]
fn malformed_params_are_errors() {
    let base = win(fixtures::pi_win().0);
    assert!(check_pi_win(&base).is_ok());
    let cases: Vec<(&str, Box<dyn Fn(&mut PiWin)>)> = vec![
        ("no windows", Box::new(|p| p.windows.clear())),
        ("unaligned offset", Box::new(|p| p.windows[0].off = 8)),
        ("empty ciphertext", Box::new(|p| p.windows[0].ct.clear())),
        ("empty expected", Box::new(|p| p.windows[0].expected.clear())),
        ("selection past the ciphertext", Box::new(|p| p.windows[1].sel_start = p.windows[1].ct.len())),
        ("selection overflow", Box::new(|p| p.windows[1].sel_start = usize::MAX)),
        ("offset past a record", Box::new(|p| p.windows[1].off = 1 << 15)),
        ("offset overflow", Box::new(|p| p.windows[1].off = usize::MAX - 15)),
        ("too many windows", Box::new(|p| {
            let w = p.windows[1].clone();
            p.windows = vec![w; MAX_WIN_WINDOWS + 1];
        })),
        ("too many bytes", Box::new(|p| {
            let w = WinWindow { seq: 9, off: 0, ct: vec![0; 16384], sel_start: 0, expected: vec![0] };
            p.windows = vec![w; MAX_WIN_BYTES / 16384 + 1];
        })),
    ];
    for (name, f) in cases {
        let mut p = base.clone();
        f(&mut p);
        assert!(check_pi_win(&p).is_err(), "{name}");
    }
}

#[test]
fn shared_blocks_are_computed_once() {
    // A short record: the frame-header window and the last-byte window share
    // block 0.
    let v = v2_secrets();
    let content = h2_frame(6, 1, 0, &[7; 8]);
    let ct = win_record(&v.c_ap_1, 5, &content, 0x17, 0);
    let p = PiWin { anchor: v.h1(), key_updates: 0, windows: win_windows(5, &ct, &content, 9, 0) };
    assert_eq!(p.windows.len(), 2);
    assert_eq!(pi_win_blocks(&p), vec![(5, 0), (5, 1)]);
    let st = stats(&Params::PiWin(p));
    assert_eq!((st.sha256_compressions, st.aes_blocks), (7, 2));
    // The fixture: HEADERS in full, two blocks per DATA record plus the suffix.
    let p = win(fixtures::pi_win().0);
    let blocks = pi_win_blocks(&p);
    let mut uniq = blocks.clone();
    uniq.sort();
    uniq.dedup();
    assert_eq!(blocks.len(), uniq.len());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_short_control_record_proves_with_shared_blocks() {
    let v = v2_secrets();
    let witness = Witness::Secret(v.c_ap_1);
    for content in [h2_frame(4, 1, 0, &[]), h2_frame(6, 1, 0, &[7; 8]), h2_frame(8, 0, 0, &[0, 0, 1, 0])] {
        let ct = win_record(&v.c_ap_1, 2, &content, 0x17, 0);
        let p = PiWin { anchor: v.h1(), key_updates: 0, windows: win_windows(2, &ct, &content, 9, 0) };
        assert_eq!(bit(&p, &witness).await, Some(true));
    }
}

/// The cost table of the report: correlations (one per AND gate and per
/// committed input bit) for a small and a ~200 KB body in 16 KiB frames.
#[test]
fn demand_grows_with_records_not_bytes() {
    let (small, w) = fixtures::pi_win_body(300);
    let d_small = ot_demand_with(&small, &w).unwrap();
    let v = v2_secrets();
    let honest = pi_win_frames(16);
    let mut windows = Vec::new();
    let n = 200_000usize.div_ceil(16375);
    let mut frames = vec![honest[0].clone()];
    for i in 0..n {
        let len = if i + 1 == n { 200_000 - 16375 * (n - 1) } else { 16375 };
        let mut payload = vec![b'x'; len];
        if i + 1 == n {
            let at = len - SUFFIX.len();
            payload[at..].copy_from_slice(SUFFIX);
        }
        frames.push(h2_frame(0, (i + 1 == n) as u8, 3, &payload));
    }
    for (i, f) in frames.iter().enumerate() {
        let ct = win_record(&v.c_ap_1, i as u64, f, 0x17, 0);
        let (head, tail) = if i == 0 { (f.len(), 0) } else if i == frames.len() - 1 { (9, SUFFIX.len()) } else { (9, 0) };
        windows.extend(win_windows(i as u64, &ct, f, head, tail));
    }
    let big = Params::PiWin(PiWin { anchor: v.h1(), key_updates: 0, windows });
    let d_big = ot_demand_with(&big, &w).unwrap();
    let (sb, bb) = (stats(&small).aes_blocks, stats(&big).aes_blocks);
    eprintln!("pi_win small: {d_small} correlations, {sb} AES blocks; 200 kB: {d_big} correlations, {bb} AES blocks");
    assert!(d_big < d_small + 30 * 2 * 6000, "{d_small} -> {d_big}");
    assert!(d_big < 600_000);
}

// --- the proof channel: π_WIN and π_C3S repeat -------------------------------

async fn open_pair() -> (ZkChannel, ZkChannel) {
    let (a, b, _) = zkbench::transport::emulated_link(Duration::ZERO, f64::INFINITY, f64::INFINITY);
    let pre = Prealloc { nk: 0, cp: 300_000 };
    let c = tokio::spawn(async move { ZkChannel::open(a, Party::Client, pre).await });
    let n = tokio::spawn(async move { ZkChannel::open(b, Party::Node, pre).await });
    (c.await.unwrap().unwrap(), n.await.unwrap().unwrap())
}

fn serve(mut node: ZkChannel, params: Vec<Params>) -> tokio::task::JoinHandle<Vec<bool>> {
    tokio::spawn(async move {
        let mut out = Vec::new();
        for p in params {
            let Ok(Some(req)) = node.next_request().await else { break };
            let r = node.serve(&req.proof, &p, None).await;
            out.push(matches!(&r, Ok(c) if c.iter().all(|x| x.ok)));
            if r.is_err() {
                break;
            }
        }
        node.close().await;
        out
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_channel_repeats_win_and_c3s() {
    let (win_p, win_w) = fixtures::pi_win();
    let (c3_p, c3_w) = fixtures::pi_c3s();
    let seq = vec![win_p.clone(), win_p.clone(), c3_p.clone(), win_p.clone(), c3_p.clone()];
    let (mut client, node) = open_pair().await;
    let task = serve(node, seq.clone());
    for p in &seq {
        let w = if matches!(p, Params::PiWin(_)) { &win_w } else { &c3_w };
        client.request(p, Some(w)).await.unwrap();
    }
    client.close().await;
    assert_eq!(task.await.unwrap(), vec![true; 5]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_win_poisons_the_channel() {
    let (win_p, win_w) = fixtures::pi_win();
    let mut bad = win(win_p.clone());
    bad.windows[0].expected[3] ^= 1;
    let (mut client, node) = open_pair().await;
    // The node's own (honest) view differs from what the client's record holds.
    let task = serve(node, vec![Params::PiWin(bad.clone()), win_p.clone()]);
    let _ = client.request(&Params::PiWin(bad), Some(&win_w)).await;
    assert!(client.request(&win_p, Some(&win_w)).await.is_err(), "no proof after a failure");
    assert_eq!(task.await.unwrap(), vec![false]);
}

// --- cu-prover --job-stdin ---------------------------------------------------

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
fn cu_prover_job_stdin_runs_pi_win() {
    let (params, witness) = fixtures::pi_win();
    assert!(run_cu_prover_pair("pi_win", &params, &witness));
    let mut p = win(params);
    p.windows[1].expected[4] ^= 1;
    assert!(!run_cu_prover_pair("pi_win", &Params::PiWin(p), &witness));
}
