# Direct reference-mode cross-verification

This diagnostic addresses the bidirectional upstream-interoperability item in
`specs/parliament_ballot_proof_profile.md` §11.3. It exercises ordinary FAEST
reference mode only. The Parliament extension has a different transcript and
leaf commitment and is outside this evidence. Neither interoperability nor this
finite negative corpus establishes cryptographic security qualification.

## Method

`cross_verify_upstream.py` downloads the complete official
[FAEST v3.0.2 source](https://github.com/faest-sign/faest-ref/tree/4fb6b71143b37764546b7c7729440d9cd8898a5e),
requires archive SHA-256
`3caa4ee6f915edda17f8800be3ab77c69c12766651e320a8a8f453fa015d5cbd`,
and compiles its shared library without modifying upstream source. Meson selects
portable AES, bundled `opt64` SHA3, release optimization, and disables optional
OpenSSL, benchmarks, test-vector generators, docs, and Valgrind integrations.
`ctypes` declarations match the public
[`faest_param.h.in` API](https://github.com/faest-sign/faest-ref/blob/4fb6b71143b37764546b7c7729440d9cd8898a5e/faest_param.h.in).
Its `faest_*_verify` receives the actual signature length, including malformed
lengths; the upstream
[API implementation](https://github.com/faest-sign/faest-ref/blob/4fb6b71143b37764546b7c7729440d9cd8898a5e/faest_param.c.in)
performs the length check. A nonzero return is required for every negative case.

The separate `examples/faest_cross_verify.rs` executable dispatches only to the
twelve existing reference `FaestParams`. A verification rejection exits 1;
file, dispatch, or signing errors exit 2. The driver therefore cannot count a
missing input file or a crashed process as a successful rejection. Portable and
`accel` executables are copied separately before either build can replace the
other. Their `identity` operation checks which Cargo feature was compiled.

For each of all twelve parameter sets:

1. SHAKE256 of the documented public seed and set label produces a new test key;
   one key bit is cleared to meet the reference key rule. Rust derives the
   public key, and upstream `validate_keypair` independently validates it.
2. C signs a fresh 137-byte message using fixed public test randomness. The
   actual C signature is verified by both Rust executables and C.
3. Portable Rust signs a different fresh 273-byte message. The actual Rust
   signature is verified by C and both Rust executables. Accelerated Rust also
   signs that message; C verifies its output directly, and its bytes must equal
   the portable output.
4. Each of the two distinct signatures supplies 16 negative inputs: one changed
   message, one changed public key, a single-bit change at the start of each of
   the nine reference signature fields, truncation to 0, 1, half, and one fewer
   byte, and one trailing byte. Every input goes through C and both Rust
   verification APIs. Field locations are obtained from the Rust reference
   codec; they select corruption locations, not expected valid signatures.

The success condition is direct verifier acceptance, independently of signature
byte comparisons. No official signature fixture is supplied to either signer.
All recorded keys, randomness, and messages are **public test material**.

## Reproduction

Python 3.11+, Clang/C++17, Rust 1.93.1, Meson 1.9.2, and Ninja 1.13.0 were used.
The build tools are installed in an isolated temporary virtual environment;
there are no repository dependency, lockfile, or production API changes.

Run from the repository root (the initial upstream download needs network):

```sh
python3.11 -m venv /tmp/parliament-faest-cross/tools
/tmp/parliament-faest-cross/tools/bin/pip install meson==1.9.2 ninja==1.13.0
scripts/cargo_fast.sh --target-slot parliament-backend --incremental -- build --release --locked -p iroha_zkp_vole --example faest_cross_verify
cp target/cargo-fast/parliament-backend/release/examples/faest_cross_verify /tmp/parliament-faest-cross/rust-portable
scripts/cargo_fast.sh --target-slot parliament-backend --incremental -- build --release --locked -p iroha_zkp_vole --example faest_cross_verify --features accel
cp target/cargo-fast/parliament-backend/release/examples/faest_cross_verify /tmp/parliament-faest-cross/rust-accel
python3.11 crates/iroha_zkp_vole/tests/fixtures/faest_v3_0_2/cross_verify_upstream.py \
  --work-dir /tmp/parliament-faest-cross \
  --meson /tmp/parliament-faest-cross/tools/bin/meson \
  --ninja /tmp/parliament-faest-cross/tools/bin/ninja \
  --rust-portable /tmp/parliament-faest-cross/rust-portable \
  --rust-accel /tmp/parliament-faest-cross/rust-accel \
  --output /tmp/parliament-faest-cross/cross_verification.json
```

These are diagnostic builds using ordinary metadata, without
`--stable-local-metadata`. The report records binary hashes, Rust/Clang/tool
versions, the upstream archive and API-source hashes, Rust source/manifest/lock
hashes, compiler-command digest, and the full fresh signature corpus. Binary
hashes are evidence of the actual run, not a promise of bit-reproducible binaries
across hosts or checkout paths. The current build's CPU, compiler, allocator, and
provider behavior are not a target-independent security certificate.

The driver accepts prebuilt Rust executables. Its source inventory and binary
hashes alone are not build attestation: their association is supplied by the
controlled build-and-copy commands and saved build receipts under
`cross_verification_evidence/`. `build_receipt.json` additionally pins the
vendored AES manifest and Cargo configuration; neither is part of the driver's
Rust-source glob. Reproduction requires the matching reviewed source/lock
snapshot. The task-owned copied binaries must remain unchanged during the run.

The current driver flushes and fsyncs each completed case to
`case_results.jsonl` before proceeding. It always retains an unqualified final
report on source drift, marks `publication_status=rejected_source_drift`, and
exits nonzero. A completed functional case does not override that source guard.

The campaign has a fixed case count. Each subprocess invoked by the Python
driver (the Rust bridge, Meson, or Ninja) has a 1,200-second timeout; the upstream
C calls execute inside the Python process without a separate wall-clock timeout.
Portable upstream C verification
on the `s` sets dominates this diagnostic's runtime. Its elapsed time is not a
ballot verifier performance measurement.

Focused harness checks:

```sh
python3.11 -m unittest discover -s crates/iroha_zkp_vole/tests/fixtures/faest_v3_0_2 -p test_cross_verify_upstream.py -v
scripts/cargo_fast.sh --target-slot parliament-backend --incremental -- test --release --locked -p iroha_zkp_vole --example faest_cross_verify
scripts/cargo_fast.sh --target-slot parliament-backend --incremental -- clippy --release --locked -p iroha_zkp_vole --example faest_cross_verify -- -D warnings
scripts/cargo_fast.sh --target-slot parliament-backend --incremental -- clippy --release --locked -p iroha_zkp_vole --example faest_cross_verify --features accel -- -D warnings
```

## Recorded result

The original run completed every functional case on all twelve sets, then
**rejected final publication** because the shared `Cargo.lock` changed during
execution. The `iroha_sccp` dependency list gained one `iroha_allocation` edge.
Removing only that edge in memory recovers the exact build lock SHA-256
`dc55d38cf752be174f1e270b0c3ff7d292bdaed5f7d8297daf2225d4249c1c48`;
the live lock was not restored or modified. The copied Rust executables still
match their original build receipt.

The original driver is preserved as
`cross_verification_evidence/rejected_publication/driver_used.py` (SHA-256
`f75da4a204a3bc6b6da1bcdd2c6689c9f0e953e6ae77601ac7e909c61537517a`).
Its completed-case output and full command log retain 24 successful functional
case summaries, 48 successful Rust verification calls, and 768 Rust rejection
results. Its control flow checks all C returns before printing each successful
case. That establishes 36 successful C verification calls and 384 C rejection
predicates in that run, but **the individual raw C nonzero return values were
lost**. The 12 Rust signature files and their identical accelerated outputs
survived. The 12 C-origin signature byte arrays were only in memory and were
lost when the guard raised; no original C signature hashes were retained.

This evidence-loss defect was fixed in the current diagnostic driver, with
focused tests of flushed case retention and rejected-report preservation. The
full negative campaign was not rerun. The original publication failure remains
recorded in `rejected_publication/rejection.json`.

`recover_cross_verification.py` performs a separate positive recovery run using
the retained binaries and exact frozen build lock. It retains the original 12
Rust signatures, regenerates 12 deterministic C signatures from the same public
input recipe, and actually verifies both directions again. The regenerated C
bytes are explicitly labelled; they are not claimed as retained original bytes.
The live lock discrepancy is recorded separately because these already-built
executables do not read it. Frozen executable/library/lock hashes and diagnostic
source inputs are checked before and after recovery. Recovery executes no
negative verification calls and invents no lost return values.

```sh
python3.11 crates/iroha_zkp_vole/tests/fixtures/faest_v3_0_2/recover_cross_verification.py \
  --work-dir /tmp/parliament-faest-cross \
  --output /tmp/parliament-faest-cross/recovery_report.json
```

This recovery command requires the original retained `/tmp` artifacts identified
by the build receipts. A fresh checkout should use the full reproduction command
above.

Recovery completed on 2026-10-13 with an unchanged frozen-input guard and exit
0. All twelve sets (`faest_{128,192,256}{s,f}` and
`faest_em_{128,192,256}{s,f}`) passed both directions with both Rust modes.
The retained full corpus is in
[`recovery_report.json`](cross_verification_evidence/recovery_report.json).
Its 24 records contain the actual signature bytes, inputs, field layouts,
provenance, and successful verifier results; the 48 flushed input/completion
checkpoints are in `recovery_cases.jsonl.txt`.

| Run | Positive verifier calls | Direct cross-implementation calls | Negative verifier calls | Publication |
|---|---:|---:|---:|---|
| Original campaign | 84: C 36, portable Rust 24, accelerated Rust 24 | 48 | 1,152: 384 per verifier | Rejected after live lock drift; raw C rejection codes lost |
| Separate recovery | 84: C 36, portable Rust 24, accelerated Rust 24 | 48 | 0 | Complete diagnostic against frozen inputs |

These are separate executions, not additional distinct-signature counts. Each
uses 24 distinct signatures. The original run established identical portable
and accelerated Rust signing bytes for every set; recovery checked all 12
retained pairs again and verified the accelerated output directly with C.
The original 384 negative inputs cover both signature origins on every set.
Their retained Rust command logs and C rejection predicates are described above;
recovery does not upgrade them to retained raw C return-code evidence.

[`summary.json`](cross_verification_evidence/summary.json) separates the two runs
and lists each corpus digest. [`manifest.json`](cross_verification_evidence/manifest.json)
pins the diagnostic sources, build receipts, original rejected run, recovery
corpus, checkpoints, and logs. The harness checks passed six Python unit tests,
one Rust example test, and strict Clippy in portable and accelerated modes.
No claim is made that the changing live workspace passed this frozen diagnostic,
or that reference interoperability qualifies the Parliament extension.
