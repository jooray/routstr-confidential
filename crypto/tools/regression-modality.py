#!/usr/bin/env python3
"""Modality check (VENICE-TESTS style): do the given models reject multimodal
content parts, by URL *and* by data URI?

Since 2026-10-10 this is no longer a gate: the node reserves a full-context
prompt, which bounds image parts too, and the sidecar offer's optional
``model_allowlist`` is empty by default. Kept for operators who want to
restrict confidential mode to text-only models. The history:

Why: a model that *accepts* an ``image_url`` part is not bounded by body bytes:
the client picks the image, so one ~50-byte URL (or a small inline data URI)
can cost hundreds to thousands of tokens (GAP-3; probe evidence in
``crypto/runs/modality/probe.json``). The gate in the sidecar
(``offer.venice.json`` -> ``text_only_ok``) is only as good as this check: if
Venice later enables vision on an allow-listed model, or a new model is added
to the offer, the check fails here.

Models: ``--model`` (repeatable), else the offer file's ``model_allowlist`` (or
the legacy ``text_only_ok`` map).

Usage:
    VENICE_API_KEY=... python3 -I regression-modality.py [--offer PATH] [--json OUT] [--model M]...
    python3 -I regression-modality.py --self-test      # offline, mocked transport

Per model, three tiny requests (max_tokens 4):
  * text      positive control: must be 200 (the model exists, the key works)
  * image_url must be rejected with a client error (400/422)
  * data_uri  must be rejected with a client error (400/422)

429, 5xx, timeouts and connection errors are *inconclusive*: retried with
backoff; if still inconclusive the model is INCONCLUSIVE and the gate fails.

Exit status: 0 iff every advertised model PASSes; 1 if any model FAILs; 2 if
none fail but at least one is INCONCLUSIVE (or on a usage error). The key is
never printed.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Callable

API = "https://api.venice.ai/api/v1/chat/completions"
DEFAULT_OFFER = os.path.join(os.path.dirname(__file__), "..", "relay", "offer.venice.json")
IMAGE_URL = "https://www.gstatic.com/webp/gallery/1.jpg"
DATA_URI = (
    "data:image/png;base64,"
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR4nGNgAAIAAAUAAen63NgAAAAASUVORK5CYII="
)
REJECT = (400, 422)
RETRIES = int(os.environ.get("CU_RETRIES", "2"))
BACKOFF = [2.0, 6.0, 15.0]


def _post_real(model: str, image: str | None, key: str) -> dict:
    """One request. Returns {"status", "prompt_tokens", "error"}; status -1 on
    a transport error (timeout, connection reset, DNS)."""
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
        try:
            err = e.read().decode("utf-8", "replace")[:160]
        except Exception:  # noqa: BLE001
            err = ""
        return {"status": e.code, "prompt_tokens": None, "error": err}
    except Exception as e:  # noqa: BLE001  (URLError, timeout, reset)
        return {"status": -1, "prompt_tokens": None, "error": f"{type(e).__name__}: {e}"}
    pt, done = None, "data: [DONE]" in data
    for line in reversed(data.splitlines()):
        if line.startswith("data: {") and '"usage"' in line:
            try:
                usage = json.loads(line[6:]).get("usage") or {}
                pt = usage.get("prompt_tokens")
            except json.JSONDecodeError:
                pass
            break
    if status == 200 and not done:
        # A truncated stream is a transport problem, not a verdict.
        return {"status": -1, "prompt_tokens": pt, "error": "stream ended without [DONE]"}
    return {"status": status, "prompt_tokens": pt, "error": None}


TRANSPORT: dict[str, Callable] = {"post": _post_real}


def transient(status: int) -> bool:
    return status == -1 or status == 429 or status >= 500


def request(model: str, image: str | None, key: str) -> dict:
    """Request with retries on inconclusive outcomes; ``inconclusive`` is set
    if every attempt was transient."""
    r: dict = {}
    for attempt in range(RETRIES + 1):
        if attempt:
            time.sleep(BACKOFF[min(attempt - 1, len(BACKOFF) - 1)])
        r = TRANSPORT["post"](model, image, key)
        if not transient(r["status"]):
            r["inconclusive"] = False
            return r
    r["inconclusive"] = True
    return r


def evaluate(model: str, key: str) -> dict:
    text = request(model, None, key)
    img = request(model, IMAGE_URL, key)
    data = request(model, DATA_URI, key)
    row = {
        "model": model,
        "text_status": text["status"],
        "image_url_status": img["status"],
        "image_url_prompt_tokens": img["prompt_tokens"],
        "data_uri_status": data["status"],
        "data_uri_prompt_tokens": data["prompt_tokens"],
    }
    reasons = []
    if not text["inconclusive"] and text["status"] != 200:
        reasons.append(f"text control status={text['status']} (model missing or key rejected)")
    for name, r in (("image_url", img), ("data_uri", data)):
        if not r["inconclusive"] and r["status"] not in REJECT:
            reasons.append(
                f"{name} not rejected (status={r['status']}, prompt_tokens={r['prompt_tokens']})"
                + (" - ACCEPTS images: remove it from text_only_ok/price_list or modality-pin the provider"
                   if r["status"] == 200 else "")
            )
    inconclusive = [n for n, r in (("text", text), ("image_url", img), ("data_uri", data)) if r["inconclusive"]]
    if reasons:
        verdict = "FAIL"
    elif inconclusive:
        verdict = "INCONCLUSIVE"
        reasons.append("still 429/5xx/timeout after retries: " + ", ".join(inconclusive))
    else:
        verdict = "PASS"
    row["verdict"] = verdict
    row["reasons"] = reasons
    return row


def run(models: list[str], key: str, quiet: bool = False) -> tuple[int, list[dict]]:
    rows = []
    for model in models:
        row = evaluate(model, key)
        rows.append(row)
        if not quiet:
            print(
                f"{row['verdict']:12s} {model:34s} text={row['text_status']:<4} "
                f"image_url={row['image_url_status']:<4} data_uri={row['data_uri_status']:<4}"
                + (("  " + "; ".join(row["reasons"])) if row["reasons"] else ""),
                flush=True,
            )
    fails = sum(r["verdict"] == "FAIL" for r in rows)
    inc = sum(r["verdict"] == "INCONCLUSIVE" for r in rows)
    if not quiet:
        print()
        print(f"summary: {len(rows) - fails - inc} PASS, {fails} FAIL, {inc} INCONCLUSIVE of {len(rows)} models")
        if fails or inc:
            print("GATE CLOSED: not every advertised model was shown to reject image_url and data URI parts")
        else:
            print(f"PASS: all {len(rows)} advertised models reject image_url and data URI parts (GAP-3 gate holds)")
    return (1 if fails else 2 if inc else 0), rows


def self_test() -> int:
    """Mocked transport: the negative controls must not pass."""
    global RETRIES, BACKOFF
    RETRIES, BACKOFF = 1, [0.0]

    def mock(text: int, url: int, data: int) -> Callable:
        def post(model: str, image: str | None, key: str) -> dict:
            st = text if image is None else url if image == IMAGE_URL else data
            return {"status": st, "prompt_tokens": 3000 if (image and st == 200) else 7, "error": None}
        return post

    scenarios = [
        ("text-only model (text 200, url 400, data 400) passes", mock(200, 400, 400), 0),
        ("422 is also a client-error rejection", mock(200, 422, 422), 0),
        ("data URI accepted (url 400, data 200) fails", mock(200, 400, 200), 1),
        ("image URL accepted (url 200, data 400) fails", mock(200, 200, 400), 1),
        ("vision model (both 200) fails", mock(200, 200, 200), 1),
        ("outage: 503 everywhere is inconclusive, gate closed", mock(503, 503, 503), 2),
        ("rate limit on the image probes is inconclusive", mock(200, 429, 429), 2),
        ("timeouts (status -1) are inconclusive", mock(-1, -1, -1), 2),
        ("bad key: 401 everywhere fails the text control", mock(401, 401, 401), 1),
        ("model gone: text 404 fails even though images 404", mock(404, 404, 404), 1),
    ]
    bad = 0
    saved = TRANSPORT["post"]
    try:
        for label, fn, want in scenarios:
            TRANSPORT["post"] = fn
            rc, rows = run(["selftest-model"], "sk-selftest", quiet=True)
            ok = rc == want
            bad += not ok
            print(f"{'ok  ' if ok else 'BAD '} {label}: exit={rc} (want {want}) verdict={rows[0]['verdict']}")
    finally:
        TRANSPORT["post"] = saved
    print(f"self-test: {len(scenarios) - bad}/{len(scenarios)} scenarios behave as required")
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--offer", default=DEFAULT_OFFER)
    ap.add_argument("--json", default=None)
    ap.add_argument("--model", action="append", default=None)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()

    key = os.environ.get("VENICE_API_KEY", "")
    if not key:
        print("VENICE_API_KEY is not set", file=sys.stderr)
        return 2

    if args.model:
        models = args.model
    else:
        with open(args.offer) as f:
            offer = json.load(f)
        allow = offer.get("model_allowlist")
        if allow is None:
            allow = [m for m, ok in (offer.get("text_only_ok") or {}).items() if ok is True]
        models = sorted(set(allow))
    if not models:
        print("no models to check (the offer has no model_allowlist; pass --model)", file=sys.stderr)
        return 2

    now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"modality regression  {now}  provider={API}  models={len(models)}  retries={RETRIES}")
    rc, rows = run(models, key)
    if args.json:
        with open(args.json, "w") as f:
            json.dump({"time": now, "provider": API, "exit": rc, "results": rows}, f, indent=2)
        print(f"wrote {args.json}", file=sys.stderr)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
