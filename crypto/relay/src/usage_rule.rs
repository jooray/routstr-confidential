//! The usage event rule (`PROTOCOL-V3.md` §5.4), shared by both framings.
//!
//! The last event before `data: [DONE]` is disclosed to the node. It is a
//! usage event when it carries the token counts and its `choices` carry no
//! response text: either `[]` (Venice, Numes, xKiro, NVIDIA), or one entry
//! whose fields are all on an allow-list and empty (OpenRouter: an empty
//! `content` with `role`, `finish_reason`, `native_finish_reason`;
//! Cloudflare: an empty `delta` with `finish_reason`). Anything else in a
//! choice (content, reasoning, tool calls, a refusal, audio, logprobs, a
//! field this rule does not know) refuses the event, so a disclosure never
//! carries model output. Google's usage, merged into the last content
//! chunk, is refused by design.
//!
//! The top level is an allow-list too: `choices`, `usage`, the labels `id`,
//! `object`, `model`, `provider`, `service_tier`, `system_fingerprint` (null or
//! at most 128 characters of `[A-Za-z0-9 ._:/@+-]`) and `created` (an unsigned
//! integer). `cost` (Venice) may be null, a number or a numeric object. `usage` may hold only numbers (of magnitude below 2^53), booleans, nulls and nested objects
//! of such (keys `[A-Za-z0-9_]{1,64}`, at most 3 levels counting `usage`). Any
//! other field could carry prompt- or output-derived data to the node.
//!
//! The vectors in `usage-event-vectors.json` are the conformance test for
//! every implementation (sidecar, reference driver, SDK, browser library).

use anyhow::{bail, Result};
use serde_json::Value;

/// The OpenAI `finish_reason` values: a fixed vocabulary.
pub const FINISH_REASONS: &[&str] = &["stop", "length", "tool_calls", "content_filter", "function_call"];
/// Delta fields that may be present when empty (`""` or `null`).
const EMPTY_TEXT_FIELDS: &[&str] = &["content", "reasoning", "reasoning_content", "refusal"];

fn is_identifier(s: &str) -> bool {
    (1..=32).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphabetic() || b == b'_')
}

const LABEL_FIELDS: &[&str] = &["id", "object", "model", "provider", "service_tier", "system_fingerprint"];

fn is_label(v: &Value) -> bool {
    v.is_null()
        || v.as_str().is_some_and(|s| {
            s.len() <= 128 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b" ._:/@+-".contains(&b))
        })
}

/// `depth` counts `usage` itself as 1; at most 3.
fn numeric_object(v: &Value, depth: u32) -> bool {
    let Some(o) = v.as_object() else { return false };
    depth <= 3
        && o.iter().all(|(k, x)| {
            (1..=64).contains(&k.len())
                && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                && match x {
                    Value::Null | Value::Bool(_) => true,
                    Value::Number(_) => plain_number(x),
                    Value::Object(_) => numeric_object(x, depth + 1),
                    _ => false,
                }
        })
}

/// A number every implementation reads the same: its magnitude is below
/// 2^53 (a nested count such as a cache-write count enters the price, and
/// the node's Python and a JavaScript client would read a larger one
/// differently).
fn plain_number(v: &Value) -> bool {
    v.as_f64().is_some_and(|f| f.abs() < (1u64 << 53) as f64)
}

/// An unsigned integer every implementation reads the same: at most 2^53 - 1
/// (a JavaScript client and the node's settlement hold larger ones inexactly).
fn uint(v: &Value) -> bool {
    v.as_u64().is_some_and(|n| n < (1 << 53))
}

fn empty_text(v: &Value) -> bool {
    v.is_null() || v.as_str() == Some("")
}

fn check_choice(c: &Value) -> Result<()> {
    let Some(obj) = c.as_object() else { bail!("R: a usage event's choice is not an object") };
    for (k, v) in obj {
        let ok = match k.as_str() {
            "index" => uint(v),
            "finish_reason" => v.is_null() || v.as_str().is_some_and(|s| FINISH_REASONS.contains(&s)),
            "native_finish_reason" => v.is_null() || v.as_str().is_some_and(is_identifier),
            "logprobs" => v.is_null(),
            "delta" => match v.as_object() {
                None => false,
                Some(d) => d.iter().all(|(dk, dv)| match dk.as_str() {
                    "role" => dv.is_null() || dv.as_str() == Some("assistant"),
                    "tool_calls" => dv.is_null() || dv.as_array().is_some_and(|a| a.is_empty()),
                    f if EMPTY_TEXT_FIELDS.contains(&f) => empty_text(dv),
                    _ => false,
                }),
            },
            _ => false,
        };
        if !ok {
            bail!("R: the usage event's choice carries {k:?} (only empty choices may sit next to usage)");
        }
    }
    Ok(())
}

/// Ok when `v` is a usage event as §5.4 defines it.
pub fn check_usage_event(v: &Value) -> Result<()> {
    if let Some(obj) = v.as_object() {
        for (k, x) in obj {
            let ok = match k.as_str() {
                "choices" | "usage" => true,
                "created" => uint(x),
                "cost" => x.is_null() || plain_number(x) || numeric_object(x, 1),
                f if LABEL_FIELDS.contains(&f) => is_label(x),
                _ => false,
            };
            if !ok {
                bail!("R: the usage event carries the top-level field {k:?} (not on the allow-list, or its value is not a plain label or number)");
            }
        }
    }
    let Some(choices) = v.get("choices").and_then(|c| c.as_array()) else {
        bail!("R: usage event has no choices array");
    };
    if choices.len() > 1 {
        bail!("R: usage event has more than one choice");
    }
    for c in choices {
        check_choice(c)?;
    }
    if !v.pointer("/usage/prompt_tokens").is_some_and(uint) || !v.pointer("/usage/completion_tokens").is_some_and(uint) {
        bail!("R: usage event missing token counts");
    }
    if !numeric_object(&v["usage"], 1) {
        bail!("R: the usage object carries something other than numbers");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_vectors() {
        let all: Value = serde_json::from_str(include_str!("../usage-event-vectors.json")).unwrap();
        let vectors = all["vectors"].as_array().unwrap();
        assert!(vectors.len() >= 20);
        for t in vectors {
            let got = check_usage_event(&t["event"]).is_ok();
            assert_eq!(got, t["ok"].as_bool().unwrap(), "vector {}", t["name"]);
        }
    }

    /// Counts above 2^53 - 1 are refused, as the clients refuse them
    /// (`Number.isSafeInteger`): one rule in every implementation.
    #[test]
    fn integers_above_the_safe_range_are_refused() {
        let event = |prompt: u64, created: u64, index: u64| {
            serde_json::json!({"choices":[{"index":index,"delta":{}}],"created":created,"usage":{"prompt_tokens":prompt,"completion_tokens":1}})
        };
        let max = (1u64 << 53) - 1;
        assert!(check_usage_event(&event(max, max, max)).is_ok());
        assert!(check_usage_event(&event(max + 1, 0, 0)).is_err());
        assert!(check_usage_event(&event(1, max + 1, 0)).is_err());
        assert!(check_usage_event(&event(1, 0, max + 1)).is_err());
        let mut e = event(1, 0, 0);
        e["usage"]["completion_tokens"] = serde_json::json!(u64::MAX);
        assert!(check_usage_event(&e).is_err());
    }
}
