//! Writes the cross-language crypto fixtures as JSON.
//!
//! Usage: `cu-crypto-fixtures [path]` (defaults to stdout).

use std::io::Write;

fn main() {
    let doc = cu_crypto::fixtures::build();
    let text = serde_json::to_string_pretty(&doc).unwrap();
    match std::env::args().nth(1) {
        Some(path) => {
            std::fs::write(&path, text).expect("write fixtures");
            eprintln!("wrote {path}");
        }
        None => {
            let mut out = std::io::stdout();
            out.write_all(text.as_bytes()).unwrap();
            out.write_all(b"\n").unwrap();
        }
    }
}
