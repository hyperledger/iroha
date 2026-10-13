# Android B6 evidence commands

These commands describe an authorized finite experiment on Samsung SM-S942B,
Android 16/API 36, arm64-v8a. Execution is a native executable under `adb shell`,
not an Android application or the named Pixel baseline. All qualification and
production-availability gates remain false. No SDK or production source changes
are part of this run.

The source manifest is [android-source.sha256](android-source.sha256), SHA-256
`044ecda041aefe175861344d821d019d88d38004b9c2297e68d6dafb8b8e65cb`.
It was checked before the accelerated run, after each run, before and after the
portable build, and after completion. [Check records](android-source-checks.jsonl)
retain the outcomes. The manifest identifies the dirty shared checkout more
precisely than Git HEAD.

A [later checkout observation](android-postrun-source-check.json) found a changed
root lockfile after all runs completed. To reproduce these measured binaries,
use the exact [measured root lockfile](measured-root-Cargo.lock.template) in a
separate checkout matching the manifest; do not overwrite a shared live
checkout. Its SHA-256 is
`ecfb0f0635527e68e3e329bfbde338e051912e10986839d66d8e384011e9e303`.
[Recovery provenance](post-measurement-lock-change.json) records the distinction.

## Build

From the repository root, with the installed Android NDK 28.2.13676358:

```sh
android_ndk_bin="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/darwin-x86_64/bin"
env \
  CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$android_ndk_bin/aarch64-linux-android23-clang" \
  CC_aarch64_linux_android="$android_ndk_bin/aarch64-linux-android23-clang" \
  AR_aarch64_linux_android="$android_ndk_bin/llvm-ar" \
  scripts/cargo_fast.sh --target-slot parliament-android --incremental -- \
  build --release --target aarch64-linux-android \
  -p iroha_parliament_ballot_proof --features accel --example qualify
```

The portable command is identical with `--features accel` omitted. Both use
normal revision metadata, without `--stable-local-metadata`. Each binary is
copied aside before a later build can overwrite the target-slot output.
The accelerated build was supplied by the parent task and its exact binary
identity checked locally and on the device. The Android evidence runner built
the portable configuration after both accelerated runs.

## Push and run

The actual newly created task directory is
`/data/local/tmp/parliament-b6-20261013-bbea7df9`. No unrelated files or processes
were modified. Its directory and binaries have mode 700.

```sh
adb shell mkdir -m 700 /data/local/tmp/parliament-b6-20261013-bbea7df9
adb push <saved-accel-binary> /data/local/tmp/parliament-b6-20261013-bbea7df9/qualify-accel
adb shell chmod 700 /data/local/tmp/parliament-b6-20261013-bbea7df9/qualify-accel
adb shell sha256sum /data/local/tmp/parliament-b6-20261013-bbea7df9/qualify-accel
```

For each configuration, first `candidate` with 31 samples per case, then
`comparator` with 3 samples per case:

```sh
adb shell 'echo $$ > /data/local/tmp/parliament-b6-20261013-bbea7df9/accel-candidate31.pid; exec /data/local/tmp/parliament-b6-20261013-bbea7df9/qualify-accel --row candidate --samples 31 --source-id 044ecda041aefe175861344d821d019d88d38004b9c2297e68d6dafb8b8e65cb --run-id samsung-sm-s942b-accel-candidate31' > android-accel-candidate31.jsonl
```

The other runs substitute the matching binary, row, sample count and label.
Default cases are registration and vote lists of 3, 500 and 1000 entries.
Device standard output is retained as NDJSON without rewriting; standard error
and the host-observed `adb` exit status are recorded separately. The process
identifier file concerns only this task's executable and is used for RSS
sampling. No device serial or UDID is passed into the evidence.

## Bounded metadata and telemetry

Metadata reads are restricted to manufacturer, model, SoC model, Android
release/API, ABI, machine architecture and `MemTotal`. During each finite run,
roughly every ten seconds, the host reads:

- `dumpsys battery`, retaining only power/charging flags, status, health,
  level/scale, voltage and temperature;
- `dumpsys thermalservice`, retaining thermal status and numerical temperature,
  sensor-type and status values; sensor names and unrelated output are omitted;
- the task-owned `/proc/<pid>/status`, retaining only `VmRSS`, `VmHWM`,
  `VmSize` and thread count.

The raw service dumps are not archived. No account data, app inventory, network
identifiers, serial, UDID or broad personal device data was collected. Build-log
paths are replaced by `<repository>` and `<android-sdk>` before archiving.

Telemetry is a separate sampled observation, not a per-phase RSS measurement
or proof of peak memory. `VmHWM` is the process high-water mark at the sampled
instant and includes proving and setup; samples can miss a later peak. Thermal
output can include cached readings. Polling, USB charging, preceding samples,
other device activity and thermal/cache carry-over can affect timings. No
cool-down, process/cache reset, power measurement or controlled baseline is
claimed. Compare proof digests and retry counters across builds/platforms;
do not interpret matching digests as a byte-by-byte comparison of retained
proof files.
