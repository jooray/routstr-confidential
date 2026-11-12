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

fn empty_text(v: &Value) -> bool {
    v.is_null() || v.as_str() == Some("")
}

fn check_choice(c: &Value) -> Result<()> {
    let Some(obj) = c.as_object() else { bail!("R: a usage event's choice is not an object") };
    for (k, v) in obj {
        let ok = match k.as_str() {
            "index" => v.as_u64().is_some(),
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
    let Some(choices) = v.get("choices").and_then(|c| c.as_array()) else {
        bail!("R: usage event has no choices array");
    };
    if choices.len() > 1 {
        bail!("R: usage event has more than one choice");
    }
    for c in choices {
        check_choice(c)?;
    }
    if v.pointer("/usage/prompt_tokens").and_then(|t| t.as_u64()).is_none()
        || v.pointer("/usage/completion_tokens").and_then(|t| t.as_u64()).is_none()
    {
        bail!("R: usage event missing token counts");
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
}
