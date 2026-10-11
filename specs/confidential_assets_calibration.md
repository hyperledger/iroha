# Confidential Gas Calibration Baselines

This ledger tracks the validated outputs of the confidential gas calibration
benchmarks. Each row documents a release-quality measurement set captured with
the procedure described in `specs/confidential_assets.md#calibration-baselines--acceptance-gates`.

| Date (UTC) | Commit | Profile | `ns/op` | `gas/op` | `ns/gas` | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| 2025-10-18 | 3c70a7d3 | baseline-neon | 2.93e5 | 1.57e2 | 1.87e3 | Darwin 25.0.0 arm64e (hostinfo); `cargo bench -p iroha_core --features bench --bench isi_gas_calibration -- --sample-size=200 --warm-up-time=5 --save-baseline neon-20251018`; `cargo test -p iroha_core bench_repro -- --ignored`; `cargo bench -p ivm --bench gas_calibration -- --sample-size=200 --warm-up-time=5`; `rustc 1.88.0 (6b00bc3)` |
| 2026-04-28 | 8ea9b2a7 | baseline-neon-20260428 | 4.29e6 | 1.57e2 | 2.73e4 | Darwin 25.0.0 arm64 (`rustc 1.91.0`). Command: `cargo bench -p iroha_core --features bench --bench isi_gas_calibration -- --sample-size=10 --warm-up-time=2 --noplot --save-baseline baseline-neon-20260428`; log at `specs/confidential_assets_calibration_neon_20260428.log`. x86_64 parity runs (SIMD-neutral + AVX2) are scheduled for the 2026-03-19 Zurich lab slot; artefacts will land under `artifacts/confidential_assets_calibration/2026-03-x86/` with matching commands and will be merged into the baseline table once captured. |
| 2026-04-28 | — | baseline-simd-neutral | — | — | — | **Waived** on Apple Silicon—`ring` enforces NEON for the platform ABI, so `RUSTFLAGS="-C target-feature=-neon"` fails before the bench can run (`specs/confidential_assets_calibration_simd_neutral_attempt_20260428.log`). Neutral data stays gated on CI host `bench-x86-neon0`. |
| 2026-04-28 | — | baseline-avx2 | — | — | — | **Deferred** until an x86_64 runner is available. `arch -x86_64` cannot spawn binaries on this machine (“Bad CPU type in executable”; see `specs/confidential_assets_calibration_avx2_attempt_20260428.log`). CI host `bench-x86-avx2a` remains the source of record. |

`ns/op` aggregates the median wall-clock per instruction measured by Criterion;
`gas/op` is the arithmetic mean of the corresponding schedule costs from
`iroha_core::gas::meter_instruction`; `ns/gas` divides the summed nanoseconds by
the summed gas across the nine-instruction sample set.

*Note.* The current arm64 host does not emit Criterion `raw.csv` summaries out of
the box; rerun with `CRITERION_OUTPUT_TO=csv` or an upstream fix before tagging a
release so the artefacts required by the acceptance checklist are attached.
If `target/criterion/` is still missing after `--save-baseline`, collect the run
on a Linux host or serialize the console output into the release bundle as a
temporary stop-gap. For reference, the arm64 console log from the latest run
lives at `specs/confidential_assets_calibration_neon_20251018.log`.

Per-instruction medians from the same run (`cargo bench -p iroha_core --features bench --bench isi_gas_calibration`):

| Instruction | median `ns/op` | schedule `gas` | `ns/gas` |
| --- | --- | --- | --- |
| RegisterDomain | 3.46e5 | 200 | 1.73e3 |
| RegisterAccount | 3.15e5 | 200 | 1.58e3 |
| RegisterAssetDef | 3.41e5 | 200 | 1.71e3 |
| SetAccountKV_small | 3.28e5 | 67 | 4.90e3 |
| GrantAccountRole | 3.33e5 | 96 | 3.47e3 |
| RevokeAccountRole | 3.12e5 | 96 | 3.25e3 |
| ExecuteTrigger_empty_args | 1.42e5 | 224 | 6.33e2 |
| MintAsset | 1.56e5 | 150 | 1.04e3 |
| TransferAsset | 3.68e5 | 180 | 2.04e3 |

### 2026-04-28 (Apple Silicon, NEON enabled)

Median latencies for the 2026-04-28 refresh (`cargo bench -p iroha_core --features bench --bench isi_gas_calibration -- --sample-size=10 --warm-up-time=2 --noplot --save-baseline baseline-neon-20260428`):

| Instruction | median `ns/op` | schedule `gas` | `ns/gas` |
| --- | --- | --- | --- |
| RegisterDomain | 8.58e6 | 200 | 4.29e4 |
| RegisterAccount | 4.40e6 | 200 | 2.20e4 |
| RegisterAssetDef | 4.23e6 | 200 | 2.12e4 |
| SetAccountKV_small | 3.79e6 | 67 | 5.66e4 |
| GrantAccountRole | 3.60e6 | 96 | 3.75e4 |
| RevokeAccountRole | 3.76e6 | 96 | 3.92e4 |
| ExecuteTrigger_empty_args | 2.71e6 | 224 | 1.21e4 |
| MintAsset | 3.92e6 | 150 | 2.61e4 |
| TransferAsset | 3.59e6 | 180 | 1.99e4 |

`ns/op` and `ns/gas` aggregates in the table above are derived from the sum of
these medians (total `3.85717e7` ns across the nine-instruction set and 1,413
gas units).

The schedule column is enforced by `gas::tests::calibration_bench_gas_snapshot`
(total 1,413 gas across the nine-instruction set) and will trip if future patches
change metering without updating the calibration fixtures.

## Commitment Tree Telemetry Evidence (M2.2)

Per roadmap task **M2.2**, every calibration run must capture the new
commitment-tree gauges and eviction counters to prove the Merkle frontier stays
within configured bounds:

- `iroha_confidential_tree_commitments{asset_id}`
- `iroha_confidential_tree_depth{asset_id}`
- `iroha_confidential_root_history_entries{asset_id}`
- `iroha_confidential_frontier_checkpoints{asset_id}`
- `iroha_confidential_frontier_last_checkpoint_height{asset_id}`
- `iroha_confidential_frontier_last_checkpoint_commitments{asset_id}`
- `iroha_confidential_root_evictions_total{asset_id}`
- `iroha_confidential_frontier_evictions_total{asset_id}`

Record the values immediately before and after the calibration workload. A
single command per asset is sufficient; example for `4cuvDVPuLBKJyN6dPbRQhmLh68sU`:

```bash
curl -s http://127.0.0.1:8180/metrics \
  | rg 'iroha_confidential_(tree_(commitments|depth)|root_history_entries|frontier_(checkpoints|last_checkpoint_height|last_checkpoint_commitments)|root_evictions_total|frontier_evictions_total){asset_id="4cuvDVPuLBKJyN6dPbRQhmLh68sU"}'
```

Attach the raw output (or Prometheus snapshot) to the calibration ticket so the
governance reviewer can confirm root-history caps and checkpoint intervals are
honoured. The telemetry guide in `specs/telemetry.md#confidential-tree-telemetry-m22`
expands on alerting expectations and the associated Grafana panels.

## Neutral & AVX2 Waiver

SDK Council granted a temporary waiver for the Phase C gate requiring
`baseline-simd-neutral` and `baseline-avx2` measurements:

- **SIMD-neutral:** On Apple Silicon the `ring` crypto backend enforces NEON for
  ABI correctness. Disabling the feature (`RUSTFLAGS="-C target-feature=-neon"`)
  aborts the build before the bench binary is produced (`specs/confidential_assets_calibration_simd_neutral_attempt_20260428.log`).
- **AVX2:** The local toolchain cannot spawn x86_64 binaries (`arch -x86_64 rustc -V`
  → “Bad CPU type in executable”; see
  `specs/confidential_assets_calibration_avx2_attempt_20260428.log`).

Until CI hosts `bench-x86-neon0` and `bench-x86-avx2a` are online, the NEON run
above plus the telemetry evidence satisfy the Phase C acceptance criteria.
The waiver is recorded in `status.md` and will be revisited once x86 hardware is
available.
