# Bounded standalone parser fuzzing

This isolated Cargo workspace contains test tooling only. It adds no fuzzer
dependency to the node or ballot library. `parsers` exercises the standalone
test statement/record decoders and the extended raw-proof parser for both rows
and roles; accepted encodings must round-trip byte for byte. The harness-only
selector chooses row, role and decoder. Profiles are cached; this is not a
resource measurement of the full verifier. No production Norito envelope or
full proof verification is exercised here.

On 2026-10-13, two coverage-guided libFuzzer campaigns with AddressSanitizer
completed without a crash or failed invariant:

| Build | Executed inputs | libFuzzer cov / ft | New units | Reported peak RSS |
|---|---:|---:|---:|---:|
| Portable | 1,038,579 | 717 / 927 | 338 | 492 MB |
| Accel | 958,154 | 725 / 935 | 368 | 495 MB |

Each used `-max_total_time=60` and terminated itself after 61 seconds. These
coverage counters are local instrumentation counters, not coverage percentages.
RSS includes the fuzzer, sanitizer, mutation corpus and runtime; it is not ballot
verification memory. This finite initial campaign does not establish full fuzz,
cryptographic, constant-time, denial-of-service or production qualification.

Toolchain: `cargo-fuzz 0.13.1`, `rustc 1.96.0-nightly (80381278a 2026-03-01)`,
`aarch64-apple-darwin`, libfuzzer-sys 0.4.10. The isolated lock keeps every shared
dependency at a version in the root lock; `arbitrary` and `libfuzzer-sys` are
test-only additions. The binary links `librustc-nightly_rt.asan.dylib`.
These ASan campaigns used ordinary cargo-fuzz build metadata, without
`--stable-local-metadata`. The exact isolated lock is retained as
`Cargo.lock.template` because repository ignore rules exclude nested
`Cargo.lock` files. Restore it before building this workspace:

```sh
cp crates/iroha_parliament_ballot_proof/fuzz/Cargo.lock.template crates/iroha_parliament_ballot_proof/fuzz/Cargo.lock
```

The manifest hashes the template, which is byte-identical to the lock used by
the recorded campaigns and replay runs.

## Run

The seed builder reads archived fixture bytes and checks their statement/record
digests. It reproduces the S=1000 public list from fixture labels using Python's
SHAKE256, without proving. Its 31 inputs cover both rows and roles, S=3/S=1000,
valid statements/proofs/records, out-of-range counters, and coefficient changes
that remain syntactically valid. All fixture secrets are already public test
inputs. Never use them for real credentials.

From the repository root:

```sh
python3 crates/iroha_parliament_ballot_proof/fuzz/seed_corpus.py --output-dir /tmp/parliament-parser-fuzz-final-portable
cargo +nightly fuzz run parsers --fuzz-dir crates/iroha_parliament_ballot_proof/fuzz --target-dir target/cargo-fast/parliament-backend/fuzz /tmp/parliament-parser-fuzz-final-portable -- -seed=1346458188 -max_total_time=60 -max_len=400000 -timeout=10 -rss_limit_mb=2048 -print_final_stats=1
python3 crates/iroha_parliament_ballot_proof/fuzz/seed_corpus.py --output-dir /tmp/parliament-parser-fuzz-final-accel
cargo +nightly fuzz run parsers --fuzz-dir crates/iroha_parliament_ballot_proof/fuzz --target-dir target/cargo-fast/parliament-backend/fuzz --features accel /tmp/parliament-parser-fuzz-final-accel -- -seed=1346458188 -max_total_time=60 -max_len=400000 -timeout=10 -rss_limit_mb=2048 -print_final_stats=1
```

Use fresh corpus directories to reproduce the starting corpus. Time-bounded
fuzzing does not promise identical execution counts. The first trial used the
default newly resolved dependencies; its results are excluded from the retained
evidence. The two table rows above are the reruns after aligning the lock.

The direct cargo-fuzz invocation is intentional: `cargo_fast.sh` refuses
external Cargo subcommands because it cannot resolve their target selectors.
For the separate replay workspace, its ownership guard also refuses a target
under the parent checkout's warm target, so replay and clippy use the dedicated
external lane `/tmp/parliament-backend-fuzz-replay-target` through cargo_fast.

## Retained corpus and deterministic replay

`evidence/corpus.tar.xz` retains the 124 unique inputs from both final corpus
directories (9,773,121 uncompressed input bytes), named by SHA-256. The manifest
records each size/hash, archive hash, source hashes and final statistics;
`evidence/portable.txt` and `evidence/accel.txt` preserve the actual run logs.
Their `.txt` extension avoids repository ignore rules for `.log` files. The
archive was checked by reading every entry back and comparing it with the
manifest.

Extract into a fresh directory and replay with both feature modes:

```sh
cp crates/iroha_parliament_ballot_proof/fuzz/Cargo.lock.template crates/iroha_parliament_ballot_proof/fuzz/Cargo.lock
mkdir -p /tmp/parliament-parser-fuzz-retained
tar -xJf crates/iroha_parliament_ballot_proof/fuzz/evidence/corpus.tar.xz -C /tmp/parliament-parser-fuzz-retained
scripts/cargo_fast.sh --stable-local-metadata --target-dir /tmp/parliament-backend-fuzz-replay-target --incremental -- run --manifest-path crates/iroha_parliament_ballot_proof/fuzz/Cargo.toml --release --bin replay -- /tmp/parliament-parser-fuzz-retained/corpus
scripts/cargo_fast.sh --stable-local-metadata --target-dir /tmp/parliament-backend-fuzz-replay-target --incremental -- run --manifest-path crates/iroha_parliament_ballot_proof/fuzz/Cargo.toml --release --features accel --bin replay -- /tmp/parliament-parser-fuzz-retained/corpus
```

These are the flags used for the local regression replays. Their executables
use `--stable-local-metadata`; they are local regression tools, not identified
qualification artifacts or the binaries used by the recorded ASan campaigns.

Both modes must print `evidence/replay_expected.txt`. Inputs are processed in
filename order; the SHA3-512 digest binds their lengths, individual SHA3-512
digests and decoder outcomes. Outcome 0 means rejection (or empty harness input),
and 1 means syntactic statement/proof acceptance. For record mode, bit 0 is the
record parser, bit 1 its statement parser, and bit 2 its proof parser. Therefore
the histogram is **not a count of verified proofs**. The replayer repeats the
round-trip invariants and runs outside libFuzzer/ASan; the retained fuzz logs are
the sanitizer evidence.
