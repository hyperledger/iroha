# Resource observations

`qualify` records experimental observations; all profile, hardware and production
integration qualification gates remain false. `measure.rs` and its earlier B5
results remain unchanged. No production Norito record schema is defined here.

Build from the repository root with the normal revision metadata, then run the
resulting binary. Use a stable target slot for repeated builds; do not use
`--stable-local-metadata` for an identified qualification artifact.

```sh
scripts/cargo_fast.sh --target-slot parliament-ballot --incremental -- build --release -p iroha_parliament_ballot_proof --example qualify --features accel
# Locate target directory from the wrapper output; record binary SHA-256.
<target-directory>/release/examples/qualify --row candidate --samples 31 --source-id <source-manifest-sha256> --run-id <machine-build-label> > observations.jsonl
<target-directory>/release/examples/qualify --row comparator --samples 3 --source-id <source-manifest-sha256> --run-id <machine-build-label> > comparator-observations.jsonl
```

Omit `--features accel` for a portable build and record its separate binary hash.
`--case registration|vote3|vote500|vote1000` restricts work; `all` is the default
for both case and row. `--samples` accepts 1 through 1001 and defaults to 31.
Every sample uses a distinct reproducible test tape. Deterministic tapes must
never be reused for production proofs. The same row, case and sample index use
identical tape bytes across builds, enabling proof byte-digest parity checks.
The JSON `proof_shake256_32` is SHAKE256(proof, 32 bytes), encoded as lowercase hex.

Output uses `norito::json`, with a run header, one flushed sample record per proof,
a summary after each case and a final `run_complete` record. An interrupted run
has only its completed observations. Errors emit a contextual `sample_error`
record and return failure; failed runs must never be treated as complete.
Each sample records seven phases:

1. `input_setup`: create the profile, secret, maximum-size registration fields or
   the sealed list and complete vote statement. Registration uses a 4096-byte
   body context and all six 256-byte opaque fields. Votes use 3, 500 or 1000 entries.
2. `prove`: derive the sample's deterministic 112-byte tape, prove and return the
   proof. The actual challenge retry counter and attempts are reported.
3. `test_record_encode`: encode the statement and copy the proof into the existing
   **test-only** record codec. This codec is not a production Norito envelope.
4. `cold_input_valid`: after dropping prover inputs and the separate proof buffer,
   start from the single encoded record; construct a fresh profile, decode the
   statement/list, check public digests and run ordinary public verification.
5. `decode_only`: separately measure fresh profile and statement/list decoding.
6. `warm_valid`: retain that decoded statement and the encoded record, then run
   ordinary verification again (digests, context and transcript are recomputed).
7. `cold_input_late_invalid`: drop the decoded statement, flip the first proof
   coefficient byte in place, and run fresh decode and public verification. Every
   sample must return `VerifyError::Rejected`; sample 0 also runs an untimed backend
   diagnostic requiring the precise `ProofError::ChallengeMismatch` outcome.

All timings are integer nanoseconds. Summary median and p95 use nearest rank
`ceil(p*n)`; maximum and exact sample count are also present. With three samples,
p95 equals maximum and does not estimate a population tail. Successful proof
samples are the observed retry distribution, not a proof of the grinding tail.

The counting allocator records requested live Rust heap bytes: entry, exit,
absolute peak, growth above entry, allocated-byte traffic and successful allocation
calls. Absolute peaks include encoded inputs, decoded inputs when retained,
allocator-backed proof intermediates and the runner's buffers. Prior sample
metrics are retained until a case summary, so the report includes that bounded
bookkeeping. JSON formatting and output occur outside measured phases. The wrapper
uses `GlobalAlloc`'s default allocate-copy-free `realloc`, whose transient requested
allocation is counted. Stack, allocator metadata/fragmentation, other native heaps,
GPU allocation and RSS are excluded. Any unrelated concurrent Rust allocation can
contaminate these process-wide counters. These observations cannot establish a
64 MiB verifier ceiling for a production adapter or a whole process.

## Malformed encoding observations

`qualify malformed` accepts the same options and measures malformed encodings
through `cold_verify`. For each row/case it first constructs and accepts one
fixed public-test-tape proof outside timing. It then constructs 16 registration
or 22 vote mutations outside timing: outer lengths/tag/field framing, descriptor,
body or vote/list bounds and digests, plus proof counter, grinding bits,
opening padding and opening capacity. Untimed preflight requires the expected
decode rejection or the specific backend codec error; all timed samples must
reject at the same public boundary. No mutation construction/search is timed.

```sh
<target-directory>/release/examples/qualify malformed --samples 31 --source-id <source-manifest-sha256> --run-id <machine-build-label> > malformed-observations.jsonl
```

Each fixed mutant is repeated in a warm process. These observations report
timing/allocation distributions and maxima, not fresh-proof trials, exhaustive
malformed-input coverage or an adversarial worst-case bound. The canonical
record, one mutant and bounded diagnostic/metric bookkeeping remain live and
are included in requested-heap totals. Output has `malformed_sample` and
`malformed_summary` records with exact mutation names, sample indices,
SHAKE256-32 input digests, rejection outcomes and the same metric units and
nearest-rank summaries. An unexpected result emits `malformed_case_error` and
fails. Qualification flags stay false. The ordinary seven-phase campaign and
its historical results are unchanged.

## Temporary device host

The module is reusable by a temporary device test host:

```rust,ignore
#[path = "/absolute/repository/path/crates/iroha_parliament_ballot_proof/examples/qualification/mod.rs"]
mod qualification;
// On a serialized background worker, with an explicit file/writer:
qualification::run(&arguments_without_argv0, &mut output)?;
```

It installs a global Rust counting allocator; the host must not install a second
one. The host needs the ballot/backend dependencies and workspace Norito with its
`json` feature. Its own `accel` feature must forward acceleration consistently so
the report label agrees with its build. The entry point does not access arguments,
environment variables or files itself. Device thermals, battery, resident footprint
and operating-system state require separate host instrumentation. The caller must
serialize runs and flush its writer when requested.

Validation:

```sh
scripts/cargo_fast.sh --target-slot parliament-ballot --incremental -- test --release -p iroha_parliament_ballot_proof --example qualify -- --test-threads=1
scripts/cargo_fast.sh --target-slot parliament-ballot --incremental -- clippy -p iroha_parliament_ballot_proof --example qualify --features accel -- -D warnings
```

Retain raw JSON lines, the exact command, compiler and OS versions, hardware
identity, binary SHA-256 and a manifest of the source contents actually built.
A Git commit alone cannot identify a dirty shared checkout. Record input/phase
order, build features, other machine workloads and sampling limitations. These
runs are not cold process/cache tests, isolated baselines, production mappings,
validator/phone baseline qualification or independent cryptographic audit.
