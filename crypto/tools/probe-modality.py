#!/usr/bin/env python3
"""GAP-3 probe: does a multimodal content part amplify prompt tokens beyond the
body-length (LEN) bound escrow is priced on?

Escrow prices the prompt as ``prompt_tokens <= LEN`` (SPEC §5.1), where ``LEN``
is the request body byte length. An ``image_url`` content part is ~50–100 body
bytes but is billed as hundreds to thousands of *image tokens* server-side, so
a vision-capable model breaks the `LEN`→token bound and `cost > E`.

For each (model, case) this sends a tiny streaming request with
``stream_options.include_usage`` and reports ``prompt_tokens`` from the final
usage event:

  * ``text``      — short text prompt (baseline: bytes -> tokens)
  * ``image_url`` — same body plus one ``image_url`` part pointing at a small
                    public JPEG (the URL itself is ~50 bytes; the image tokens
                    are what the upstream counts)
  * ``data_uri``  — same but inline ``data:image/png;base64,...`` (Venice
                    currently rejects data URIs with 400 — a safe outcome)

Per-case classification:
  * ``safe``      — the part is rejected (4xx): cannot be amplified
  * ``accepted``  — served; token cost is image-dependent (unsafe for escrow)
  * ``amplified`` — served AND this sample already exceeded the body-byte bound
  * ``unknown``   — network/auth/overload error

Per-model verdict: ``safe`` only if every image form is rejected; otherwise
``unsafe`` (accepts an image => the attacker picks the image size).

Usage:
    VENICE_API_KEY=... python3 probe-modality.py [--model M]... [--json out.json]

Spend is negligible: max_tokens 4, at most two tiny requests per model.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

API = "https://api.venice.ai/api/v1/chat/completions"

# Candidate set: every model the local node advertises confidentially, plus the
# upstream test model and its decoy (both confirmed vision-capable).
DEFAULT_MODELS = [
    "mistral-small-3-2-24b-instruct",
    "google-gemma-3-27b-it",
    "gemini-3-flash-preview",
    "claude-opus-5",
    "claude-sonnet-5",
    "claude-fable-5",
    "qwen3-235b-a22b-thinking-2507",
    "hermes-3-llama-3.1-405b",
    "kimi-k3",
    "inkling",
    "deepseek-v4-pro",
    "deepseek-v4-flash",
    "deepseek-v4-flash-0731",
    "deepseek-v3.2",
    "seed-2-1-turbo",
    "deepseek-v4-pro-0813",
    "mercury-2",
]

# Two public JPEGs on a stable host, both referenced by a ~50-byte URL. The
# *small* one (~550x368) and the *large* one (~1200x800) show that the token
# count depends on the image, not on the body bytes: the attacker picks the
# image, so a model that accepts any image is not bounded by LEN.
IMAGE_URL = "https://www.gstatic.com/webp/gallery/1.jpg"
IMAGE_URL_BIG = "https://www.gstatic.com/webp/gallery/4.jpg"
# Inline 1x1 PNG; Venice rejects data URIs, recorded as a safe outcome.
DATA_URI = (
    "data:image/png;base64,"
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR4nGNgAAIAAAUAAen63NgAAAAASUVORK5CYII="
)

SUFFIX_KEYS = {
    "max_tokens": 4,
    "max_completion_tokens": 4,
    "n": 1,
    "stream": True,
    "stream_options": {"include_usage": True},
    "venice_parameters": {
        "include_venice_system_prompt": False,
        "enable_web_search": "off",
    },
}


def body_for(model: str, case: str) -> dict:
    content: list[dict] = [{"type": "text", "text": "Reply with one word."}]
    if case == "image_url":
        content.append({"type": "image_url", "image_url": {"url": IMAGE_URL}})
    elif case == "image_big":
        content.append({"type": "image_url", "image_url": {"url": IMAGE_URL_BIG}})
    elif case == "data_uri":
        content.append({"type": "image_url", "image_url": {"url": DATA_URI}})
    body: dict = {"messages": [{"role": "user", "content": content}]}
    body.update(SUFFIX_KEYS)
    body["model"] = model
    return body


def post_stream(body: dict, key: str, timeout: float = 60.0) -> dict:
    """POST as SSE; return status, usage, error."""
    raw = json.dumps(body).encode()
    req = urllib.request.Request(
        API,
        data=raw,
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "Accept-Encoding": "identity",
            "Connection": "close",
        },
        method="POST",
    )
    out = {
        "body_bytes": len(raw),
        "status": None,
        "prompt_tokens": None,
        "completion_tokens": None,
        "model": None,
        "error": None,
    }
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            out["status"] = resp.status
            data = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        out["status"] = e.code
        try:
            out["error"] = json.loads(e.read().decode("utf-8", "replace")).get("error", "")
        except Exception:  # noqa: BLE001
            out["error"] = f"HTTP {e.code}"
        return out
    except Exception as e:  # noqa: BLE001
        out["status"] = -1
        out["error"] = f"{type(e).__name__}: {e}"
        return out

    for line in reversed(data.splitlines()):
        line = line.strip()
        if not line.startswith("data: "):
            continue
        payload = line[6:]
        if payload == "[DONE]":
            continue
        try:
            ev = json.loads(payload)
        except json.JSONDecodeError:
            continue
        usage = ev.get("usage")
        if usage and usage.get("prompt_tokens") is not None:
            out["prompt_tokens"] = usage.get("prompt_tokens")
            out["completion_tokens"] = usage.get("completion_tokens")
            out["model"] = ev.get("model")
            return out
    out["error"] = "no usage event in stream"
    return out


def classify(base: dict, case: str, r: dict) -> str:
    """safe/unsafe/unknown for a non-text case.

    The escrow bound is attacker-defeated the moment the model *accepts* an
    image part: the attacker chooses the image, so its token cost is not a
    function of the body bytes. Only a rejection proves the part cannot be
    amplified. "amplified" further flags that this sample alone already
    exceeded the priced body-byte bound.
    """
    if case == "text":
        return "baseline"
    if r["status"] in (400, 422):
        return "safe"  # rejected: the part cannot be amplified on this model
    if r["prompt_tokens"] is not None:
        if r["prompt_tokens"] > r["body_bytes"]:
            return "amplified"
        return "accepted"  # accepted; token cost is image-dependent
    return "unknown"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", action="append", default=None)
    ap.add_argument("--json", default=None)
    args = ap.parse_args()

    key = os.environ.get("VENICE_API_KEY", "")
    if not key:
        print("VENICE_API_KEY is not set", file=sys.stderr)
        return 2
    models = args.model or DEFAULT_MODELS

    rows = []
    verdicts: dict[str, str] = {}
    for model in models:
        base = post_stream(body_for(model, "text"), key)
        model_verdict = "safe" if base["status"] == 200 else "unknown"
        for case in ("text", "image_url", "image_big", "data_uri"):
            r = base if case == "text" else post_stream(body_for(model, case), key)
            verdict = classify(base, case, r)
            if case != "text":
                # Text-only-safe requires every image form to be rejected.
                if verdict in ("accepted", "amplified"):
                    model_verdict = "unsafe"
                elif verdict == "unknown" and model_verdict != "unsafe":
                    model_verdict = "unknown"
            rows.append({"model": model, "case": case, "verdict": verdict, **r})
            print(
                f"{model:36s} {case:9s} {verdict:8s} status={r['status']:<4} "
                f"prompt_tokens={r['prompt_tokens']} body_bytes={r['body_bytes']}"
                + (f"  err={r['error'][:60]!r}" if r["error"] else ""),
                flush=True,
            )
        verdicts[model] = model_verdict
        print(f"  -> {model}: {model_verdict}", flush=True)

    safe = [m for m, v in verdicts.items() if v == "safe"]
    unsafe = [m for m, v in verdicts.items() if v == "unsafe"]
    unknown = [m for m, v in verdicts.items() if v == "unknown"]
    print("\nSUMMARY")
    print(f"  text-only (safe for model_allowlist): {safe}")
    print(f"  unsafe (amplification): {unsafe}")
    print(f"  unknown: {unknown}")

    if args.json:
        with open(args.json, "w") as f:
            json.dump(
                {"verdicts": verdicts, "safe": safe, "unsafe": unsafe, "unknown": unknown, "rows": rows},
                f,
                indent=2,
            )
        print(f"wrote {args.json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
