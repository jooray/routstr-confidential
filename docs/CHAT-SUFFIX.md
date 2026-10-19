# The offer-driven chat suffix

A confidential chat request ends with a public JSON suffix that pins every
cost-relevant parameter (paper §4.4). Until 2026-10-19 its keys and values
were hard-coded, identically, in the sidecar, the SDK, the browser library
and the reference client, and one of them was Venice's `venice_parameters`.
A second provider needed code changes in all of them.

The suffix is now described by the offer. The operator writes it in the
sidecar's offer file, the node copies it into the offer it signs, and every
party renders it from there. The clients hold the offer to a narrow policy
(below), because the node chooses every pinned value.

## Offer

Sidecar offer file (operator config):

```json
"chat": {
  "cap_keys": ["max_tokens", "max_completion_tokens"],
  "fixed_pins": [
    ["n", 1],
    ["stream", true],
    ["stream_options", {"include_usage": true}],
    ["venice_parameters", {"include_venice_system_prompt": false, "enable_web_search": "off"}]
  ]
}
```

Without a `chat` block the sidecar uses a provider-neutral default: the two
cap keys above and the first three pins. The Venice offer file
(`crypto/relay/offer.venice.json`) adds `venice_parameters`, because Venice
otherwise adds its own system prompt (billed as prompt tokens).

The node copies the block into its signed offer as `chat`, and keeps
`suffix_keys` (now derived: `model`, the cap keys, the fixed pin keys, in
order). Clients refuse an offer without a `chat` block.

## Rendering

For model `M` and token cap `T`:

```
suffix = "," + join(",", ["\"model\":" + J(M)]
                         ++ [J(k) + ":" + T          for k in cap_keys]
                         ++ [J(k) + ":" + J(v)       for (k, v) in fixed_pins]) + "}"
```

`J` is compact JSON with **object keys sorted** (bytewise; keys are ASCII).
The node signs the offer as sorted-key JSON, so the order of an object pin's
members does not survive the signature; sorting is the one order every party
can reconstruct. `serde_json::to_string` (without `preserve_order`),
Python's `json.dumps(sort_keys=True, separators=(",", ":"))` and the
clients' `canonicalJson` agree on the values the grammar allows.

With the Venice block above, `M = "m"`, `T = 5`:

```
,"model":"m","max_tokens":5,"max_completion_tokens":5,"n":1,"stream":true,"stream_options":{"include_usage":true},"venice_parameters":{"enable_web_search":"off","include_venice_system_prompt":false}}
```

(Before this change `venice_parameters` rendered in the other member order,
so clients older than this change refuse sessions with a sidecar that has
it: their suffix differs from the one in `ready`. That costs nothing but a
refused session.)

## Policy (sidecar at startup, every client on every offer)

1. `cap_keys`: non-empty, no repeats, each one of `max_tokens`,
   `max_completion_tokens`, `max_output_tokens`. Any other key would let the
   offer name a cap the provider ignores.
2. `fixed_pins`: a list of `[key, value]`. Keys match
   `^[A-Za-z_][A-Za-z0-9_]*$`, are unique, and are none of `model` and the
   three cap names.
3. Values: `true`/`false`, integers with `|n| < 2^53`, strings of printable
   ASCII without `"` or `\`, arrays of values, objects whose keys match the
   key pattern and whose values are values. No `null`, no fractions.
4. Required: `stream` pinned to `true`, and `stream_options` pinned to an
   object with `include_usage: true` (the usage proof reads the final SSE
   usage event); its other members must be off (rule 6).
5. `n`, when pinned, is `1`.
6. Every other pin switches something off: `false`, `"off"`, `[]`, or an
   object whose members are all off.
7. The fixed part (everything after the caps) renders to at most 1024 bytes.
8. `suffix_keys` equals `["model", ...cap_keys, ...fixed pin keys]`.

## The caller's request

The protocol keys (`model`, the three cap names, `n`, `stream`,
`stream_options`) never come from the caller and are dropped from the
private part, as before. Any other key the offer pins is dropped when the
caller's value equals the pinned value; when it differs, the client refuses
the request (`pinned_parameter`, HTTP 400 in routstrd) rather than send it
with the caller's choice silently replaced.
