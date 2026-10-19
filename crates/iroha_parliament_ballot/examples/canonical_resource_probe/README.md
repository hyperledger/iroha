# Canonical candidate resource probe

This one-shot engineering diagnostic measures the actual candidate vote-validity
entry: complete canonical envelope and authenticated-context decoding, checked
`ScopedBallotContextV1` construction, actual stamp and proof verification, and
destruction of the owned inputs and verifier values. It calls
`check_block_ballot_v1`; it does not decide casting-window/nullifier execution,
append a corpus, authenticate chain history or create a protocol effect.
Registration is outside this diagnostic's scope.

```
canonical_resource_probe ENVELOPE CONTEXT \
  --network 'hash:<UPPERCASE_HEX>#<CHECKSUM>' \
  --body <64-lowercase-hex-digits> --fatal-fd FD \
  [--heap-limit N] [--units N] [--input-bytes N]
```

`ENVELOPE` is `AnonymousBallotEnvelopeV1::encode_canonical_bounded()`.
`CONTEXT` is `anonymous_ballot::framing::enc(&AuthenticatedBallotContextV1)`.
The caller supplies the trusted network and sealed body identity separately.
The context's derived values and scope are recomputed; that computation does
not itself authenticate the context's chain provenance.

Each file is retrieved as a bounded regular file and closed before invocation.
Its immutable staging owner remains live through worker join, outside the
verifier workspace. The worker independently checks actual envelope length at
most 262,144 and context length at most 163,840. It atomically debits one unit
and their actual combined length before either arena copy. A linear token
rechecks both lengths individually, even if their total is unchanged. Success,
rejection, invalid context and local resource failure retain the whole debit.
Defaults are one unit, 425,984 input bytes and a 32 MiB heap limit.

Either positional argument can be `--borrowed-oversize`: the supervisor then
creates a genuine caller buffer one byte beyond that input's cap, and the
worker refuses it before copying either input. A file literally named that
string is addressed as `./--borrowed-oversize`. File retrieval and caller
capacity are outside the charged interval; their timing is not bounded.

The example directly reuses the existing `resource_contract/arena.rs` and
`native.rs`, and `memory_entry/fatal.rs`, without changing those sources or
transferring their old binary evidence. Its new budget supplies the fatal
protocol's same combined cap and one-unit semantics. The fixed mapping contains
32 MiB heap, 1 MiB allocator metadata, 8 MiB supplied native stack, 64 KiB
control and two native-page guards; the separate shared fatal page is also
counted. No default arena allocation falls back to System. All owned input,
context, proof/error and result values end before routing is disabled.
Surviving allocations after thread join are a child error, never a successful
cleanup claim. The published mapping remains allocated until process exit.

Use a fresh process with no concurrent application work. This process-global
allocator switch is not an embeddable node service. Runtime/TLS allocations
can bypass the default allocator; loader, thread infrastructure and the
supervisor are separate. A bounded mapping or a successful finite observation
does not establish all-input completion, complete native coverage or a 64 MiB
qualification certificate. `complete_workspace_certificate` and
`profile_qualified` remain false. Acceleration identity is recorded by the
external build command/features; the example cannot infer a dependency's Cargo
feature state and does not mislabel it with a local `cfg`.

The supervisor passes a fresh zeroed page through inherited descriptor `FD`
(at least 3): regular, unlinked, owner-only 0600, writable, exactly one native
page. It must neither mutate/truncate nor inspect the page until child death.
The four native-endian u64 words remain magic `0x5041524c46415431`, state,
units and bytes. State is 1 at setup, 2 after admission, 3 on arena exhaustion.
Every remaining page byte stays zero. Exhaustion performs only atomic
publication and `_exit(73)`, with no stdout, formatting or unwinding.

Exit meanings:

| Code | Meaning and control state |
| --- | --- |
| 0 | `accepted`, stage `complete`: full stamp/proof validity; state 2 |
| 1 | `rejected`: invalid envelope/stamp/proof; state 2 |
| 2 | `admission_rejected`: component size or available budget; state 1, zero debit |
| 3 | CLI or staging input error before reservation; state 1 if installed |
| 4 | Local setup/context/verifier error; inspect stage and control/debit |
| 73 | Resource exhaustion, state 3 and full debit; no child JSON required |
| 74 | Unclassified internal/ownership/control failure; never proof rejection |

Panic, signal, timeout, missing marker or contradictory debit is incomplete
observation. Neither abnormal termination nor `_exit` promises Rust destructor
cleanup. Normal reports have `validity_only=true` and `protocol_effect=false`;
`accepted` names this validity request, not a committed ballot.

## Reproduction

Use a 64-bit Linux or macOS host and Python 3.11 or later. From a retained source
checkout, build both examples into a dedicated target directory:

```sh
CARGO_TARGET_DIR="$PWD/target/parliament-canonical-portable" cargo build --release \
  -p iroha_parliament_ballot \
  --example canonical_resource_fixtures --example canonical_resource_probe
```

Record the actual build command, compiler/target, dependency features and build
log. A `portable` label requires verifying that the backend's `accel` feature
was absent; an accelerated build must be identified as `accel`. Capture the
exact source inputs, manifests, lockfile and patched dependencies in a retained
source manifest, with its digest. Pin both example binaries by SHA-256. Do not
reuse a build record from an earlier binary or source snapshot.

The campaign requires a JSON `--build-record` with `worker_sha256` equal to the
probe executable's SHA-256 and `mode` equal to `portable` or `accel`. Include the
source-manifest identity and actual build details in that record or bind their
retained records by digest. The script checks the executable digest and mode
label; it does not independently authenticate those source/build assertions.
A minimal digest-and-mode record alone is not proof of source correspondence.

The generator's CLI is
`canonical_resource_fixtures OUTPUT_DIR SEATS THREADS [valid|late-invalid]`.
It accepts seats 3, 500 and 1000, defaults to `valid`, and refuses an existing
output directory. Its secrets and proving tape are deterministic public test
material, unsuitable for real credentials. Each fixture proves and verifies an
honest candidate ballot. The late-invalid variant then changes the first
coefficient byte, requires backend `ChallengeMismatch`, and mines a new stamp
over that exact changed authorization. Every stamp uses the unchanged standard
28-bit difficulty. Mining can take time; parallel scheduling can change the
winning nonce and attempt count. Failures retain partial output for inspection.

Create the required four-fixture set, with an appropriate explicit thread count
(4 below), under a fresh parent directory:

```sh
fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/parliament-canonical.XXXXXX")"
example_dir="$PWD/target/parliament-canonical-portable/release/examples"
"$example_dir/canonical_resource_fixtures" "$fixture_root/valid-3" 3 4 valid
"$example_dir/canonical_resource_fixtures" "$fixture_root/valid-500" 500 4 valid
"$example_dir/canonical_resource_fixtures" "$fixture_root/valid-1000" 1000 4 valid
"$example_dir/canonical_resource_fixtures" "$fixture_root/late-invalid-1000" 1000 4 late-invalid
```

Each completed directory contains canonical `context.norito`,
`authorization.norito`, `envelope.norito` and a Norito JSON `manifest.json` with
the trusted network/body literals, public roster recipe, lengths and actual
cryptographic results. Run the campaign from the same retained source checkout:

```sh
python3 scripts/check_parliament_ballot_canonical_resources.py \
  --worker "$example_dir/canonical_resource_probe" \
  --build-record /absolute/path/to/build-record.json \
  --fixture "$fixture_root/valid-3" \
  --fixture "$fixture_root/valid-500" \
  --fixture "$fixture_root/valid-1000" \
  --fixture "$fixture_root/late-invalid-1000" \
  --output "$fixture_root/campaign" --timeout 120
```

The campaign owns the fatal descriptor and launches a fresh worker per case;
do not supply `--fatal-fd` yourself. Its timeout is per worker invocation and
does not limit preceding fixture mining. It retains copied executable/scripts,
inputs, raw stdout/stderr, fatal-page evidence, per-case results, `summary.json`
and `SHA256SUMS`. It checks the four originals plus malformed input, separate
caps, budget, trusted-identity and fatal-allocation controls. Overall `pass`
requires all four fixture identities and all supplied cases to pass. A timeout
or missing/contradictory evidence is operational failure, never a proof result.

Current validation: 18 probe unit tests and 52 campaign/supervisor Python tests
passed. The generator and full canonical fixture campaign have not yet run.
The focused tests cover parser bounds, independent reservations, staging,
outcome classification, fatal control, arena behavior and native stack
placement; they do not activate process-wide routing concurrently with the
Rust test harness. Reproduce the focused checks with:

```sh
cargo test -p iroha_parliament_ballot --example canonical_resource_probe
python3 -m pytest -q scripts/tests/check_parliament_ballot_canonical_resources_test.py \
  scripts/tests/parliament_ballot_memory_supervisor_test.py
```

Even a successful campaign leaves chain-history authentication, all-input and
all-native-allocation coverage, complete workspace certification, profile and
production qualification false. These are finite validity/resource
observations; independent review and required hardware evidence remain open.

TODO: establish fresh current-source fixture results, complete native-memory
coverage and all-input sufficiency, independent unsafe review and required
target measurements. Production qualification remains unchanged.
