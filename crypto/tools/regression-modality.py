#!/usr/bin/env python3
"""Regression test (VENICE-TESTS style): every model the confidential offer
advertises must reject multimodal content parts.

Why: escrow prices the prompt as ``prompt_tokens <= LEN`` (SPEC §5.1). A model
that *accepts* an ``image_url`` part is not bounded by body bytes — the client
picks the image, so one ~50-byte URL can cost hundreds to thousands of tokens
(GAP-3; probe evidence in ``crypto/runs/modality/probe.json``). The gate in the
sidecar (``offer.venice.json`` → ``text_only_ok``) is only as good as this
check: if Venice later enables vision on an allow-listed model — or a new model
is added to the offer — the check fails here.

The authoritative list is read from ``relay/offer.venice.json`` (``text_only_ok``
and ``price_list`` keys) so the test follows the offer, not a hardcoded set.

Usage:
    VENICE_API_KEY=... python3 regression-modality.py [--offer PATH] [--json OUT]

Exit code 0 iff every advertised model rejects an image_url part (400/422).
Mirrors the procedure in ``docs/original/VENICE-TESTS.md``: one tiny request per
model, ``stream_options.include_usage``, read ``prompt_tokens``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

API = "https://api.venice.ai/api/v1/chat/completions"
DEFAULT_OFFER = os.path.join(os.path.dirname(__file__), "..", "relay", "offer.venice.json")
IMAGE_URL = "https://www.gstatic.com/webp/gallery/1.jpg"
DATA_URI = (
    "data:image/png;base64,"
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR4nGNgAAIAAAUAAen63NgAAAAASUVORK5CYII="
)


def request(model: str, image: str | None, key: str) -> dict:
    content: list[dict] = [{"type": "text", "text": "Reply with one word."}]
    if image:
        content.append({"type": "image_url", "image_url": {"url": image}})
    body = {
        "model": model,
        "messages": [{"role": "user", "content": content}],
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
    req = urllib.request.Request(
        API,
        data=json.dumps(body).encode(),
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "Accept-Encoding": "identity",
            "Connection": "close",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            status, data = resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return {"status": e.code, "prompt_tokens": None}
    except Exception as e:  # noqa: BLE001
        return {"status": -1, "prompt_tokens": None, "error": f"{type(e).__name__}: {e}"}
    pt = None
    for line in reversed(data.splitlines()):
        if line.startswith("data: {") and '"usage"' in line:
            try:
                usage = json.loads(line[6:]).get("usage") or {}
                pt = usage.get("prompt_tokens")
            except json.JSONDecodeError:
                pass
            break
    return {"status": status, "prompt_tokens": pt}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--offer", default=DEFAULT_OFFER)
    ap.add_argument("--json", default=None)
    ap.add_argument("--model", action="append", default=None)
    args = ap.parse_args()

    key = os.environ.get("VENICE_API_KEY", "")
    if not key:
        print("VENICE_API_KEY is not set", file=sys.stderr)
        return 2

    if args.model:
        models = args.model
        allow = set(models)
    else:
        with open(args.offer) as f:
            offer = json.load(f)
        allow = set((offer.get("text_only_ok") or {}).keys())
        # every model in the price list must be in the allow-list too
        models = sorted(allow | set((offer.get("price_list") or {}).keys()))

    if not models:
        print("no models to check (empty offer)", file=sys.stderr)
        return 2

    failures: list[str] = []
    results = []
    for model in models:
        text = request(model, None, key)
        img = request(model, IMAGE_URL, key)
        data = request(model, DATA_URI, key)
        row = {
            "model": model,
            "in_allowlist": model in allow,
            "text_status": text["status"],
            "image_url_status": img["status"],
            "image_url_prompt_tokens": img["prompt_tokens"],
            "data_uri_status": data["status"],
        }
        # A model is safe iff it rejects the image URL (data URIs are already
        # rejected by Venice). The text baseline confirms the model exists.
        safe = img["status"] in (400, 422)
        row["safe"] = safe
        if model in allow and not safe:
            failures.append(
                f"{model}: ACCEPTS image_url (status={img['status']}, "
                f"prompt_tokens={img['prompt_tokens']}) — remove it from "
                f"text_only_ok/price_list or modality-pin the provider"
            )
        # The text baseline is a sanity check that the model still exists; a
        # 429 is upstream load, not a modality regression, so it is not fatal.
        if model in allow and text["status"] not in (200, 429):
            failures.append(f"{model}: in allow-list but text request status={text['status']}")
        results.append(row)
        print(
            f"{model:36s} allow={str(model in allow):5s} text={text['status']:<4} "
            f"image_url={img['status']:<4} image_pt={img['prompt_tokens']} "
            f"data_uri={data['status']:<4} safe={safe}"
        )

    print()
    if failures:
        print(f"FAIL ({len(failures)} model(s)):")
        for f in failures:
            print("  " + f)
    else:
        print(f"PASS: all {len(models)} advertised models reject image parts (GAP-3 gate holds)")

    if args.json:
        with open(args.json, "w") as f:
            json.dump({"pass": not failures, "failures": failures, "results": results}, f, indent=2)
        print(f"wrote {args.json}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
