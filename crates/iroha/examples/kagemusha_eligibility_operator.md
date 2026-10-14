# Disposable enrollment eligibility operator

`kagemusha_eligibility_operator.rs` supplies current eligibility for a disposable
KAGEMUSHA physical-device campaign. It uses the SDK's canonical request decoder,
asset/policy binding, live clock checks, freeze precedence and verified Ed25519
response signing. It represents an explicitly selected `SchemeOperator`; it
refuses a `Bank` template. It neither authenticates a phone nor issues a wallet
credential. Native issuer startup, platform evidence verification and committed
Scheme/manifest authority remain required.

Build and test the example from the same source candidate as the issuer:

```sh
cargo iroha-fast -- test -p iroha --example kagemusha_eligibility_operator
cargo iroha-fast -- build -p iroha --example kagemusha_eligibility_operator
python3 -m pytest scripts/tests/kagemusha_eligibility_https_test.py
```

The binary takes one absolute private directory argument and reads one canonical
Norito observation, at most 2,048 bytes, from stdin. Success writes only the exact
signed response to stdout. Every error returns failure without request bodies,
signatures or private paths. The caller must authenticate transport before
dispatching; use the Linux supervisor below for the local campaign.

The directory contains three owner-private, single-link regular files:

- `template.norito`: the canonical, independently selected
  `KagemushaEligibilityPolicyTemplateV1` with `SchemeOperator` authority.
- `signer.key`: exactly 32 raw Ed25519 private-key bytes matching that template.
- `current.json`: one complete current-state image, atomically replaced by its
  operator. Never update records in place while serving.

The current-state image has exactly `version` (integer 1), `templateHex` (the
lowercase hex of the exact template original) and `records`. Each record has
exactly `assetDigest`, `accountDigest`, `actorDigest`, `approved`, `frozen` and
`revision`. Digests are nonzero, lowercase, 64-character hex; the flags are
booleans and revision is a positive integer. Bind the canonical account, actor
and asset incarnation independently before publishing a row. The selected
operator owns approval and freeze decisions. No missing row implies approval.

Every request rereads and validates the entire image, including uniqueness of
the three-digest identity tuple, before selecting its row. The image is bounded
to 1 MiB and 4,096 records. A current freeze overrides approval. Unknown subjects,
foreign assets/templates, malformed or unavailable state and stale requests
produce no signed response. Whole-image replacement supplies atomic observations;
it does not supply a database transaction across other operator systems.

## Local HTTPS transport

[`scripts/kagemusha_eligibility_https.py`](../../../scripts/kagemusha_eligibility_https.py)
requires Linux, Python 3.12+, a native ELF build of this adapter, a TLS certificate
valid for `127.0.0.1`, its private key and a private bearer-token original. Its
configuration is a private JSON file with exactly these fields:

| Field | Selection |
| --- | --- |
| `port` | Integer 1024–65535; listener binds only `127.0.0.1`. |
| `certificate`, `tls_key` | Absolute private PEM paths. |
| `transport_token` | Absolute private bearer-token path, without a newline. |
| `adapter`, `adapter_sha256` | Absolute native executable path and its lowercase SHA-256. |
| `operator_directory` | Absolute directory containing the three operator files. |
| `timeout_seconds` | Integer 1–60 bounding each transport/child operation. |

Run `python3 scripts/kagemusha_eligibility_https.py --config ABSOLUTE_PRIVATE_JSON`.
Use `https://127.0.0.1:PORT/eligibility` for the issuer's observation endpoint.
Configure the issuer's authenticated TLS trust for the actual local certificate;
never disable certificate verification. Both HTTP MIME fields are
`application/x-norito`. The supervisor verifies the bearer token before reading
or dispatching the request body, accepts only the exact route and bounded
framing, and does not retry a child invocation.

Retained descriptors authenticate selected files and their ancestry. The
supervisor copies the admitted executable and TLS originals into kernel-sealed
memory files and executes the original ELF through its descriptor with an empty
environment. Changed custody, timeout, oversized output and child failure return
an empty refusal. The operating-system loader and its system libraries remain
trusted dependencies; this service does not establish a reproducible loader
closure. Operator configuration, secrets and current customer records stay
outside the repository. The component tests are not enrollment or release
qualification.
