# Receive-credit measurements

```sh
scripts/cargo_fast.sh --target-slot perf-agents --stable-local-metadata -- \
  bench -p iroha_p2p --features bench --bench receive_credit
```

The target reports absolute Criterion measurements of the first-release record
path. It does not retain a retired implementation or an A/B baseline.

- `receive_credit_record/seal/B`: canonical header encoding, allocation of the
  single wire buffer, one plaintext copy and ChaCha20-Poly1305 sealing. Plaintext
  sizes are 256 B, 4 KiB, 64 KiB and 1 MiB. Keys and plaintext are prepared once.
- `receive_credit_record/write_contiguous/B` and `write_4k/B`: advance the
  production partial-write/flush loop over a pre-sealed record, with a sink that
  accepts either the complete remaining buffer or at most 4 KiB per call. This
  isolates writer overhead and includes entering the current-thread executor.
  The sink counts accepted bytes and calls; it performs no socket syscalls, TLS
  encryption or memory copying. Sealing and sink setup are outside timing.
- `receive_credit_release/waiters/N`: drop a real count/byte reservation and
  observe N registered Tokio notifications, for N = 0, 1, 8 or 64. A saturated
  Lane count partition makes each reservation retry fail before release. Timed
  work includes lease refunds, the production conditional `notify_waiters`, wake
  callbacks, readiness polls and waiter cleanup. Registration, initial polls and
  allocation happen before timing. This measures notification work, not scheduler
  latency across OS threads.

The byte-throughput figures describe plaintext bytes, not complete wire bytes.
The writer fixture verifies canonical decryption and the exact write/flush counts;
the release fixture verifies that every registered waiter is woken once and that
the next sample can reserve the same capacity:

```sh
scripts/cargo_fast.sh --target-slot perf --stable-local-metadata --incremental -- \
  test -p iroha_p2p --lib --features bench benchmark::tests
```

Use `-- --test` for an untimed smoke run. Defaults are 30 samples, one-second
warm-up and two-second measurement. Retain Criterion confidence intervals and
record machine/compiler/profile and competing workloads with any published
numbers. These component timings do not establish whole-node or network release
readiness.
