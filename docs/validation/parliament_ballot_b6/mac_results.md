# Mac B6 resource observations

All 272 fresh proofs completed: 31 candidate proofs and 3 comparator proofs per case, on both portable and accelerated builds. Every honest proof accepted; every coefficient-mutated proof returned `VerifyError::Rejected`. For the first sample of every mode/row/case, an additional untimed backend check required `ProofError::ChallengeMismatch`.

All 136 paired portable/accelerated proof digests and retry counters matched (candidate 124, comparator 12). These are SHAKE256-32 digest comparisons; the B5 vector suite separately checks full proof bytes. No row, production adapter or hardware baseline is qualified.

## Identity and method

- Machine: Apple M2 Ultra, 24 physical/logical cores, 192 GiB memory; macOS 27.0.1 (26A434), aarch64-apple-darwin.
- Toolchain: rustc 1.93.1, commit `01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf`, LLVM 21.1.8. Full metadata: [mac-machine.json](mac-machine.json).
- Source: [223-file manifest](mac-source.sha256), SHA-256 `044ecda041aefe175861344d821d019d88d38004b9c2297e68d6dafb8b8e65cb`. All entries rechecked after all four runs. The manifest, not the concurrent dirty Git HEAD, identifies source contents.
- Portable binary SHA-256: `70916ec8896ebe94560a8a968e6e69ce031b4494d94957e1c81af780ca4fa894`.
- Accelerated binary SHA-256: `d87bf0aef83005fb18857d865dd551d1b5e7ae268be63382ce6cb9e81ba22830`.
- Exact commands and build identities: [receipt](mac-receipt.json). Builds used `scripts/cargo_fast.sh --target-slot parliament-ballot --incremental --`; stable local revision metadata was not enabled.
- Each sample creates fresh inputs and a distinct deterministic test tape, proves once, and measures setup, encoding, cold input verification, decode alone, warm verification and cold late-invalid verification. Registration uses all maximum opaque bounds; votes use 3/500/1000 entries. [Runner method](../../../crates/iroha_parliament_ballot_proof/examples/QUALIFICATION.md).

## Timing and requested live heap

Timing cells are **median / p95 / maximum milliseconds**, using nearest rank. Candidate n=31; comparator n=3 is exploration only and its p95 equals maximum. Exact integer nanoseconds, allocation traffic, entry/exit/peak requested live bytes and all per-sample counters remain in the raw records and [machine-readable summary](mac-summary.json).

| Mode | Row | Case | n | Prove ms | Cold valid ms | Warm valid ms | Cold late-invalid ms | Maximum cold heap B | Maximum retry counter |
|---|---|---|---:|---|---|---|---|---:|---:|
| accel | candidate | registration | 31 | 285.555/379.690/528.873 | 136.056/367.247/384.600 | 137.832/248.804/252.037 | 135.869/173.828/174.459 | 2519539 | 931 |
| accel | candidate | vote3 | 31 | 375.212/458.615/506.288 | 175.680/220.080/276.453 | 175.414/219.099/223.823 | 179.314/201.142/227.708 | 3713035 | 997 |
| accel | candidate | vote500 | 31 | 405.622/577.210/651.648 | 204.964/278.848/306.822 | 194.996/279.700/288.646 | 200.708/287.062/342.029 | 3903883 | 1576 |
| accel | candidate | vote1000 | 31 | 366.661/755.493/1199.533 | 173.714/399.695/545.806 | 172.106/327.066/382.839 | 172.409/438.921/676.452 | 4095883 | 1549 |
| accel | comparator | registration | 3 | 439.594/440.190/440.190 | 310.445/402.238/402.238 | 309.574/321.089/321.089 | 307.908/338.523/338.523 | 6148730 | 518 |
| accel | comparator | vote3 | 3 | 583.378/605.357/605.357 | 399.329/432.868/432.868 | 398.784/402.028/402.028 | 399.214/399.550/399.550 | 6187442 | 269 |
| accel | comparator | vote500 | 3 | 598.841/602.325/602.325 | 403.869/406.118/406.118 | 404.236/406.283/406.283 | 403.722/415.396/415.396 | 6378290 | 638 |
| accel | comparator | vote1000 | 3 | 602.340/604.659/604.659 | 410.500/410.865/410.865 | 407.708/408.221/408.221 | 407.883/410.623/410.623 | 6570290 | 760 |
| portable | candidate | registration | 31 | 396.943/405.606/426.108 | 278.895/293.744/313.521 | 278.459/284.946/289.296 | 279.010/283.373/285.652 | 2519545 | 931 |
| portable | candidate | vote3 | 31 | 581.758/592.898/603.875 | 406.431/423.070/509.253 | 405.445/425.830/431.990 | 405.470/419.241/446.706 | 3713041 | 997 |
| portable | candidate | vote500 | 31 | 595.230/600.699/623.414 | 411.677/416.532/419.408 | 412.138/431.320/453.021 | 412.831/420.004/439.977 | 3903889 | 1576 |
| portable | candidate | vote1000 | 31 | 617.381/666.424/667.892 | 421.767/440.930/473.215 | 420.018/462.810/497.673 | 422.355/449.593/455.623 | 4095889 | 1549 |
| portable | comparator | registration | 3 | 2131.788/2154.259/2154.259 | 1993.375/2016.847/2016.847 | 2016.029/2044.559/2044.559 | 1989.991/2152.870/2152.870 | 6148736 | 518 |
| portable | comparator | vote3 | 3 | 2947.224/3282.073/3282.073 | 2796.610/2904.773/2904.773 | 2761.243/2887.605/2887.605 | 2763.651/2928.453/2928.453 | 6187448 | 269 |
| portable | comparator | vote500 | 3 | 2991.340/4736.605/4736.605 | 2994.822/3504.087/3504.087 | 2809.149/3850.367/3850.367 | 2821.500/3199.167/3199.167 | 6378296 | 638 |
| portable | comparator | vote1000 | 3 | 3010.700/5089.878/5089.878 | 2790.874/2829.300/2829.300 | 2785.240/2798.232/2798.232 | 2784.924/2875.191/2875.191 | 6570296 | 760 |

Counter means unsuccessful challenge candidates; attempts are counter + 1. Observed counters are not an estimate or proof of the full grinding tail. All three verification modes have the same maximum requested live peak for a given row/case/build in these runs. Portable absolute peaks are six bytes larger than accelerated peaks because the retained run labels differ; these totals deliberately include harness state.

| Role/case | Statement B | Candidate proof B | Candidate test record B | Comparator proof B | Comparator test record B |
|---|---:|---:|---:|---:|---:|
| registration | 6016 | 160148 | 166172 | 109498 | 115522 |
| vote3 | 960 | 233012 | 233980 | 158074 | 159042 |
| vote500 | 64576 | 233012 | 297596 | 158074 | 222658 |
| vote1000 | 128576 | 233012 | 361596 | 158074 | 286658 |

These are the existing test-only statement/record encodings; no production Norito envelope size is asserted.

## Evidence and checks

- [Accelerated candidate raw records](mac-accel-candidate31.jsonl) and [comparator raw records](mac-accel-comparator3.jsonl).
- [Portable candidate raw records](mac-portable-candidate31.jsonl) and [comparator raw records](mac-portable-comparator3.jsonl).
- Eight deterministic runner helper tests passed in each mode: [accelerated log](mac-qualify-tests.txt), [portable log](mac-qualify-tests-portable.txt).
- Strict all-target ballot clippy passed [accelerated](mac-clippy-all-accel.txt) and [portable](mac-clippy-all-portable.txt); [legacy codec guard](mac-no-legacy-codec.txt) passed. Scoped Rust formatting and diff whitespace checks passed.
- A separate automated read-only runner review found no correctness/mislabeling blocker; it did not constitute a new hardware run or the required independent implementation/cryptographic review.
- B5 measurement source and evidence were preserved. B6 adds a separate runner plus a Norito dev dependency and its corresponding lockfile dependency entry.

## Limits

The machine was not isolated. Other development tasks and device build preparation ran concurrently; this agent also ran portable helper compilation/clippy during some early accelerated candidate samples and built the portable example during early accelerated comparator samples. The reported outliers are retained. This data cannot attribute a timing difference solely to acceleration or serve as a controlled hardware baseline.

Heap counts requested live Rust allocations, including inputs and retained metrics, rather than only growth above entry. Counts exclude stack, allocator metadata/fragmentation, Objective-C/native or GPU allocation and RSS. Default instrumented realloc uses allocate-copy-free, including its transient allocation. Global counters can include unrelated Rust thread allocation. Prior sample metrics remain until the case summary, and JSON output is outside measured phases. These are neither whole-process memory bounds nor proof of a production 64 MiB budget.

Cold means fresh statement/list decode from retained test-codec bytes, with fresh public digest/context/transcript work. It does not mean a cold process or CPU cache. Phase order is fixed, thermals/caches carry over and no cool-down protocol was imposed. No production Norito mapping, wallet/node integration, energy result or hardware qualification follows from these observations.

The [source-only iOS host template](ios_host_template/README.md) is separate from these Mac runs. Its release profile and OS footprint sampling need their own evidence and interpretation.

A later unrelated root lockfile change occurred after the measured runs. The [exact measured lock](measured-root-Cargo.lock.template) and [recovery provenance](post-measurement-lock-change.json) retain the original graph; the live checkout was not reverted. The source manifest describes the measurement snapshot, not the later checkout.
