---
title: "Confidential mode: what a Routstr node can and cannot see"
geometry: "margin=0.5in"
fontsize: 9pt
documentclass: extarticle
---

**The short version.** In confidential mode, your routstrd talks to the AI provider (for example
Venice) through the Routstr node. The node only relays encrypted traffic and adds its own API key.
It cannot read your prompts or the answers, and it cannot change them. Billing is based on the
usage figures the provider itself reports. You do not need new apps, accounts or special hardware
(no enclaves, nothing to re-attest): it is a software upgrade of routstrd and of the node, switched on
per request.

## What you trust, and for what

| Party | You trust it for | You no longer trust it for |
|---|---|---|
| **The provider** (e.g. Venice) | Running the model you asked for, and handling your data per its policy. It sees your prompt, as it always has. | |
| **The Routstr node** | Business honesty: taking your payment, relaying traffic, refunding unused money. Reputation covers this, as it does today. | Reading your prompts and answers, changing them, swapping the model, inflating the bill. |
| **Your routstrd** | Everything: it holds the encryption keys. It runs on your machine. | |

The assumption behind this design: **nodes resell reputable providers, and you should not have to
trust the node much.** Cryptography replaces most of that trust; the rest (refunds, uptime) is
business trust that node reputation already handles.

## The three common objections

**1. "Can the node change my tool calls, system prompt or messages?"** No. Your request body
(messages, system prompt, tools, tool results) is encrypted with keys only your routstrd has. If the
node changed even one byte, the provider would reject it as tampered. The same holds for the answer,
including tool calls the model makes: your routstrd checks every piece against the provider's
encryption, so a modified answer is detected and discarded. The node writes exactly one thing, the
request header with its API key. A zero-knowledge proof shows your routstrd that this header matches a
published template. (It could still write a different header of the same length, such as another
account, but it cannot touch your content with it.)

**2. "Can the node change the model, say to a cheaper one, or bill me for a dearer one?"** No. The
model name and the token limits sit at the end of your encrypted request, where they override
anything earlier, and the node cannot alter encrypted bytes. The node holds back that last piece of the
request until your routstrd has proven it names the agreed model and limits. Until then the provider
has an incomplete request and does nothing. Your routstrd also checks that it is really talking to
the provider: the certificate must be valid and the hostname must be on your
trusted list (wildcards allowed). The bill is computed from the provider's own usage report, which
your routstrd proves to the node and checks against its own copy, at the rates the node signed before
the request; you receive a signed receipt, and routstrd rejects one that does not match. What
weights the provider actually runs is the provider's honesty, which is why you pick reputable ones.

**3. "Can the Routstr node read my prompts and responses?"** No. It only ever handles ciphertext;
the keys never leave your machine. What it can still see: which provider and model you use, when,
how long your request is, and the size of each streamed chunk. Chunk sizes can leak some
information about an answer (research has partially reconstructed responses from them), but this
is far less than today, where the node sees everything in plain text. On a provider error the node
sees only the status and headers, not the error text.

## What it costs, and the limits

- **Speed:** about +1 s to the first token in our tests (+0.3 s with pre-warmed sessions, not yet in
  routstrd); streaming a 60-token answer then takes 1.0 to 1.4 s instead of about 0.75 s direct.
- **Money:** paid like your other requests to that node, from the same balance. The node holds back
  the maximum (a full-context prompt plus your token limit) and charges only the usage the provider
  reported. Nothing is charged if the provider never got your complete request or rejected it (4xx,
  503); other 5xx errors are charged like an abandoned request.
- **Providers and models:** chat completions with text models, on providers with the standard TLS 1.3
  behaviour Venice has today; others need checking. A confidential request is refused, never sent
  the normal way, if this mode is unavailable.
- **Not covered:** the provider still sees your prompt; the node can still refuse service or keep
  money after a failed session (reputation is your protection there, as today).
