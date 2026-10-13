# Samsung Android B6 resource observations

All 272 fresh proofs completed: 31 candidate proofs and 3 comparator proofs per case on both portable and accelerated builds. Every honest proof accepted; every coefficient-mutated proof returned `VerifyError::Rejected`. The first sample of each mode/row/case also required an untimed backend `ProofError::ChallengeMismatch` (16 checks).

All 136 paired Android portable/accelerated proof digests and retry counters matched. All 272 Android/Mac pairs also matched, including proof, statement and test-record lengths. These are SHAKE256-32 digest comparisons, not byte-for-byte comparisons of retained proof files; the B5 vector suite separately checks full proof bytes. No profile, production adapter or named hardware baseline is qualified.

## Identity and method

- Device: Samsung SM-S942B, SoC model reported as `s5e9965`, Android 16/API 36, `arm64-v8a` / `aarch64`, `MemTotal` 11,916,624 KiB. This is not the named Pixel baseline.
- Execution: native release executable under `adb shell`; this does not exercise an Android application, wallet lifecycle, JVM/JNI bridge, or Kotlin SDK. USB charging remained connected.
- Toolchain: rustc 1.93.1 (`01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf`, LLVM 21.1.8); Android NDK 28.2.13676358, Clang 19.0.1, `aarch64-linux-android` Rust target and API 23 linker. Full bounded [machine metadata](android-machine.json).
- Source: [223-file manifest](android-source.sha256), SHA-256 `044ecda041aefe175861344d821d019d88d38004b9c2297e68d6dafb8b8e65cb`. All entries matched at all eight [source checks](android-source-checks.jsonl), including after each run and before/after the portable build.
- The last successful execution source check was at `2026-10-13T03:00:48.463801+00:00`. A separate [post-run checkout check](android-postrun-source-check.json) at `2026-10-13T03:02:07.948081+00:00` observed a changed `Cargo.lock`. The exact [measured root lockfile](measured-root-Cargo.lock.template) was recovered in memory and verified against the frozen hash; [provenance](post-measurement-lock-change.json) identifies the later unrelated dependency edge. The live lockfile was preserved. The execution checks and manifest identify these binaries, not the later mutable checkout.
- Accelerated binary SHA-256: `1235d160e38b2c72dd6febafc7680eb594dbd8906a5af5b690fc4ca093432cbd`.
- Portable binary SHA-256: `3e1e1ffd854b3ab728517f9d2f3d92bce186254fc43ba7596cfe77a1e0b15e5c`.
- Both pushed binary hashes were checked on the device. Builds use normal revision metadata without `--stable-local-metadata`. Exact [commands and collection method](android_commands.md), [run receipt](android-receipt.json), [accelerated build log](android-build-accel.txt) and [portable build log](android-build-portable.txt).
- Each sample creates fresh inputs and a deterministic test tape distinct within its run, then measures setup, proving, encoding, cold input verification, decode alone, warm verification and cold late-invalid verification in that order. Mode/platform reruns intentionally reuse corresponding test tapes for parity. Registration uses the maximum opaque bounds; votes use 3/500/1000 entries. [Runner method](../../../crates/iroha_parliament_ballot_proof/examples/QUALIFICATION.md).

## Timing and requested live heap

Timing cells are **median / p95 / maximum milliseconds**, using nearest rank. Candidate n=31; comparator n=3 is exploratory and its p95 equals maximum. Integer nanoseconds, every sample, allocation traffic and heap metrics remain in the raw records and [machine-readable summary](android-summary.json). All case summaries were recomputed from the raw samples and matched.

| Mode | Row | Case | n | Prove ms | Cold valid ms | Warm valid ms | Cold late-invalid ms | Maximum cold heap B | Maximum retry counter |
|---|---|---|---:|---|---|---|---|---:|---:|
| accel | candidate | registration | 31 | 310.248/338.582/339.270 | 147.549/161.186/163.472 | 146.411/160.777/163.272 | 146.512/161.010/161.384 | 2518871 | 931 |
| accel | candidate | vote3 | 31 | 516.938/553.376/580.872 | 242.730/268.896/269.708 | 242.351/256.270/268.182 | 242.415/255.341/270.390 | 3712367 | 997 |
| accel | candidate | vote500 | 31 | 603.814/675.657/676.706 | 277.290/309.766/311.837 | 276.995/309.871/310.664 | 276.731/311.097/312.010 | 3903215 | 1576 |
| accel | candidate | vote1000 | 31 | 675.943/702.640/702.646 | 303.629/322.005/322.621 | 303.368/320.121/320.399 | 302.617/321.035/321.256 | 4095215 | 1549 |
| accel | comparator | registration | 3 | 752.171/876.405/876.405 | 516.588/518.891/518.891 | 516.315/516.452/516.452 | 518.558/519.519/519.519 | 6148062 | 518 |
| accel | comparator | vote3 | 3 | 1016.666/1017.784/1017.784 | 662.736/663.109/663.109 | 660.828/661.802/661.802 | 664.399/664.411/664.411 | 6186774 | 269 |
| accel | comparator | vote500 | 3 | 1041.910/1041.924/1041.924 | 670.815/671.965/671.965 | 670.950/671.924/671.924 | 671.073/672.390/672.390 | 6377622 | 638 |
| accel | comparator | vote1000 | 3 | 1067.295/1067.694/1067.694 | 680.268/681.429/681.429 | 678.937/679.791/679.791 | 680.313/680.467/680.467 | 6569622 | 760 |
| portable | candidate | registration | 31 | 708.291/710.696/712.251 | 478.603/481.212/481.303 | 477.985/481.020/482.030 | 478.703/481.737/481.886 | 2518877 | 931 |
| portable | candidate | vote3 | 31 | 1039.935/1043.051/1043.507 | 692.548/694.797/694.934 | 691.833/694.165/694.398 | 692.380/694.719/695.396 | 3712373 | 997 |
| portable | candidate | vote500 | 31 | 1067.852/1069.498/1069.977 | 702.150/708.068/764.304 | 701.486/705.830/706.704 | 701.996/703.663/703.724 | 3903221 | 1576 |
| portable | candidate | vote1000 | 31 | 1093.868/1098.480/1099.847 | 711.538/714.167/714.636 | 709.764/713.387/713.584 | 711.560/713.601/713.715 | 4095221 | 1549 |
| portable | comparator | registration | 3 | 3364.400/3378.267/3378.267 | 3103.264/3116.767/3116.767 | 3102.950/3108.111/3108.111 | 3102.974/3108.864/3108.864 | 6148068 | 518 |
| portable | comparator | vote3 | 3 | 4800.984/4802.494/4802.494 | 4449.220/4458.317/4458.317 | 4453.088/4454.308/4454.308 | 4452.708/4456.671/4456.671 | 6186780 | 269 |
| portable | comparator | vote500 | 3 | 4822.835/4827.916/4827.916 | 4453.017/4460.956/4460.956 | 4452.955/4459.030/4459.030 | 4457.923/4461.455/4461.455 | 6377628 | 638 |
| portable | comparator | vote1000 | 3 | 4848.070/4851.568/4851.568 | 4470.316/4611.838/4611.838 | 4462.833/4463.746/4463.746 | 4453.550/4469.917/4469.917 | 6569628 | 760 |

Counter means unsuccessful challenge candidates; attempts are counter + 1. Observed counters do not estimate or establish the full grinding tail. All three verification modes have the same maximum requested live peak for a given row/case/build in these runs. Absolute peaks include retained harness bookkeeping and labels; comparisons of small differences must account for those inputs.

| Role/case | Statement B | Candidate proof B | Candidate test record B | Comparator proof B | Comparator test record B |
|---|---:|---:|---:|---:|---:|
| registration | 6016 | 160148 | 166172 | 109498 | 115522 |
| vote3 | 960 | 233012 | 233980 | 158074 | 159042 |
| vote500 | 64576 | 233012 | 297596 | 158074 | 222658 |
| vote1000 | 128576 | 233012 | 361596 | 158074 | 286658 |

These are test-only statement/record encodings; no production Norito envelope size is asserted.

## Sampled device observations

Only bounded technical fields were retained in [telemetry records](android-telemetry.jsonl): battery/charging, numerical thermal readings, and this task’s process memory/thread fields. Sampling ran approximately every ten seconds, plus a final attempt per run. The completed process can disappear before that final attempt.

| Run | Telemetry / process samples | Battery level first → last | Battery temperature range °C | Thermal status values | Maximum observed RSS KiB | Maximum observed HWM KiB |
|---|---:|---:|---:|---|---:|---:|
| accel-candidate31 | 17 / 16 | 94 → 95 | 34.9–36.3 | [0] | 8104 | 8360 |
| accel-comparator3 | 5 / 4 | 95 → 95 | 36.3–36.4 | [0] | 9508 | 13348 |
| portable-candidate31 | 37 / 36 | 96 → 99 | 36.4–37.4 | [0] | 8012 | 8524 |
| portable-comparator3 | 23 / 22 | 99 → 100 | 37.4–37.6 | [0] | 13116 | 13628 |

RSS is sampled resident memory for the entire executable. HWM is the process high-water mark as of a sampled instant and includes setup/proving; a later peak can be missed. Neither is a per-verification bound. Thermal service readings can include cached values. Battery temperature and reported thermal status do not prove absence of CPU throttling, and battery level during charging does not measure energy consumption.

## Evidence and limits

- [Accelerated candidate raw records](android-accel-candidate31.jsonl) and [comparator raw records](android-accel-comparator3.jsonl).
- [Portable candidate raw records](android-portable-candidate31.jsonl) and [comparator raw records](android-portable-comparator3.jsonl).
- All four `adb` processes exited zero and stderr files are empty. Headers, row/case/sample coverage, seven-phase order, every honest/invalid outcome, retry arithmetic, record-length arithmetic, summary statistics and cross-build/platform fields were checked. [Validation result](android-validation.txt).
- [Mac evidence](mac_results.md) supplies the matching source-bound comparison records. No device serial, UDID, account data, app inventory or network identifiers are archived.

The device was not isolated. Runs occurred in the order accelerated candidate, accelerated comparator, portable candidate, portable comparator, with no cooling protocol; compilation of the portable binary occurred between modes. USB charging, polling, other device activity, and cache/thermal carry-over can affect timings. These observations do not attribute differences solely to acceleration or establish a controlled baseline.

Cold means fresh statement/list decode from retained test-codec bytes, with fresh public digest/context/transcript work; it does not mean a cold process or CPU cache. Heap counts requested live Rust allocation including input and retained metrics, not only growth above entry. It excludes stack, allocator metadata/fragmentation and foreign heaps; default instrumented realloc includes allocate-copy-free transient allocation. Global counters can include unrelated Rust-thread allocation. Prior sample metrics are retained until case summary, while JSON output is outside measured phases.

No production Norito mapping, node/wallet integration, whole-process memory bound, full grinding-tail/work bound, constant-time claim, energy result, named hardware qualification or independent cryptographic review follows from this experiment. The Samsung native-shell observations are additional B6 evidence; production remains gated.
