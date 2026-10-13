# Parliament standalone ballot validation

The experimental implementation now follows the frozen construction in
[the profile](../../specs/parliament_ballot_proof_profile.md) section 6:
registration and `R_vote+`, the 128-byte nullifier, vote authorization, final
descriptor, 112-byte random tape, salted challenge 1 and H5, bounded counter,
and affine 112-byte leaf commitments. This record supports engineering goals
B2–B5 in [the goals record](../../specs/parliament_ballot_implementation_goals.md).
Later adversarial, security-accounting and physical-device work is recorded in
[the B6 qualification evidence](parliament_ballot_b6.md); the measurements below
remain the historical B5 run.
No profile is selected or qualified, and neither experimental crate is wired
into Core. The binding-ballot gate remains false and qualified attempt latency
remains unavailable.

## Source and reproduction

Measured on 2026-10-13 in the shared working tree. The
[source manifest](parliament_ballot_standalone/source.sha256) identifies the
two crates' production sources, measurement program, Cargo manifests and lock,
Rust toolchain, build wrapper and vendored AES provider. Its SHA-256 is
`0035c93f484a955850fa8c6e39b97e1182ee7c7674b83ca1d73c9abee79525f7`.
It was checked unchanged after both measurement runs. A Git commit alone does
not identify this uncommitted candidate. Verify the manifest from the repository
root with `shasum -a 256 -c docs/validation/parliament_ballot_standalone/source.sha256`.
The later B6 runner adds a Norito JSON development dependency, changing the
manifest/lock entries in that historical snapshot. A mismatch in the current
tree does not reidentify the earlier run; use the separate B6 source manifest
for the newer evidence.

Hardware/software: Apple M2 Ultra, 24 cores, 192 GiB RAM; macOS 27.0.1
(26A434); `rustc 1.93.1 (01f6ddf75 2026-02-11)`, LLVM 21.1.8,
`aarch64-apple-darwin`. These are developer-machine observations, not the
named Intel validator or phone baselines. Independent Python vector generation
was running concurrently; no CPU isolation or idle-host guarantee is claimed.

Run the two modes sequentially from the repository root:

```sh
scripts/cargo_fast.sh --target-slot parliament-ballot --stable-local-metadata --incremental -- \
  run --release -p iroha_parliament_ballot_proof --example measure
scripts/cargo_fast.sh --target-slot parliament-ballot --stable-local-metadata --incremental -- \
  run --release -p iroha_parliament_ballot_proof --features accel --example measure
```

The [measurement program](../../crates/iroha_parliament_ballot_proof/examples/measure.rs)
uses seven distinct reproducible test tapes per case and one thread. Real proofs
require fresh randomness. It proves and verifies every sample, reporting minimum
and median wall times and the largest incremental requested-heap allocation.
The heap number is measured above allocation at entry, excluding retained
statements, lists and proof buffers, stack, allocator overhead and process RSS;
displayed MiB are truncated to two decimal places. Verification starts from
decoded statements. Cold-process/list decoding, late-invalid proofs, p95 and
retry distributions are outside these measurements.

## Local measurements

Raw output: [portable](parliament_ballot_standalone/portable.txt) and
[accelerated](parliament_ballot_standalone/accel.txt). Times below are median
milliseconds; heap values are prove/verify MiB and identical in both modes.

| Row | Relation | Seats | Proof bytes | Portable prove / verify | Accelerated prove / verify | Incremental heap |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Candidate | Registration | — | 160,148 | 482.1 / 337.1 | 226.7 / 110.4 | 2.95 / 2.21 |
| Candidate | Vote | 3 | 233,012 | 585.6 / 408.3 | 330.1 / 158.5 | 4.10 / 3.29 |
| Candidate | Vote | 500 | 233,012 | 592.5 / 409.8 | 345.7 / 164.1 | 4.16 / 3.35 |
| Candidate | Vote | 1,000 | 233,012 | 606.8 / 415.1 | 357.8 / 168.7 | 4.22 / 3.41 |
| Comparator | Registration | — | 109,498 | 2,036.3 / 1,920.9 | 422.1 / 303.4 | 7.94 / 5.74 |
| Comparator | Vote | 3 | 158,074 | 2,951.5 / 2,762.9 | 569.4 / 393.9 | 9.07 / 5.74 |
| Comparator | Vote | 500 | 158,074 | 2,959.0 / 2,767.0 | 580.7 / 397.6 | 9.13 / 5.80 |
| Comparator | Vote | 1,000 | 158,074 | 2,963.4 / 2,764.4 | 594.8 / 403.5 | 9.19 / 5.86 |

Proof bytes exclude production envelope fields and shared seal/list context.
These values establish neither the complete 256 KiB envelope cap nor the
64 MiB verifier bound. No baseline verification or phone performance limit is
qualified by this table.

## Testing

The backend's pinned official FAEST v3.0.2 component vectors and all twelve
official signatures reproduce byte for byte in reference mode. The extended
mode has a separate independently generated Python leaf/transcript known-answer
vector. The ballot fixtures retain complete proofs and intermediates from the
[independent Python reference](../../crates/iroha_parliament_ballot_proof/tests/reference/README.md);
[fixture provenance](../../crates/iroha_parliament_ballot_proof/tests/fixtures/README.md)
distinguishes these project-generated vectors from official FAEST evidence.

Scoped validation commands (from the repository root):

```sh
scripts/cargo_fast.sh --target-slot parliament-ballot --stable-local-metadata --incremental -- \
  test --release -p iroha_parliament_ballot_proof -- --test-threads=4
scripts/cargo_fast.sh --target-slot parliament-ballot --stable-local-metadata --incremental -- \
  test --release -p iroha_parliament_ballot_proof --features accel -- --test-threads=4
scripts/cargo_fast.sh --target-slot parliament-backend --stable-local-metadata --incremental -- \
  test --release -p iroha_zkp_vole
scripts/cargo_fast.sh --target-slot parliament-backend --stable-local-metadata --incremental -- \
  test --release -p iroha_zkp_vole --features accel
scripts/cargo_fast.sh --target-slot parliament-backend --stable-local-metadata --incremental -- \
  test --release -p iroha_zkp_vole --test conformance_crt -- --ignored
cargo fmt -p iroha_zkp_vole -p iroha_parliament_ballot_proof -- --check
scripts/check_no_legacy_codec.sh
python3.11 -I crates/iroha_parliament_ballot_proof/tests/reference/test_reference.py
python3.11 scripts/formal/check_sora_parliament_source_contract.py
python3.11 -m pytest -q \
  scripts/tests/check_sora_parliament_source_contract_test.py \
  scripts/tests/check_sora_parliament_crypto_bench_test.py \
  scripts/tests/check_sora_parliament_broker_source_contract_test.py
```

Strict all-target Clippy passes for both crates in both feature modes; strict
Rustdoc passes with `accel`. The Python suites pass 1,187 tests on Python 3.11,
and the independent reference has four fast layout/hash/parser/generator tests.
The backend passed 389 tests per mode, with its normally ignored full CRT
table-regeneration check also run separately. After the final borrow-only
secret-copy cleanup, the affine unit test and independent extended-mode
known-answer vectors passed again in the relevant modes, with strict Clippy.
The ballot suite passes all 149 tests in each mode: 63 unit, two independent
evaluators, 57 proof, 19 relation and eight complete cross-implementation vector
cases. All eight final independent proofs match Rust byte for byte.

The complete workspace test suite was not run for this scoped work.
Workspace-wide formatting still reports differences in unrelated concurrent
SCCP changes in Core, the data model and `iroha_sccp`; the two proof crates'
format checks pass. Those concurrent files were left untouched.

## Remaining qualification

Independent cryptographic review, quantified primitive premises, the complete
deployment-wide security ledger and independent attack-cost assessment remain
open. The owner must record both weakenings: extraction to adaptive relation
soundness, and the former `2^128`-query floor to a proven bound below 1/2 at
`2^64` queries plus an independently assessed `2^128`-gate attack cost.

At the end of B5, implementation obligations still included bounded-parser fuzzing, cross-machine
x86/ARM parity, independent constant-time/erasure review, complete envelope and
allocation/work accounting, cold/late-invalid measurements and the named
validator/phone baselines. Later production authentication, lifecycle, SDK,
network and release qualification remain gated by profile selection. Agreement
between two implementations and arithmetic checks establish no missing
cryptographic premise.
The [B6 record](parliament_ballot_b6.md) tracks subsequent coverage and the
remaining obligations without converting these earlier measurements into
qualification evidence for changed source.
