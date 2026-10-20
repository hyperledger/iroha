# Queue and gossip measurements

`read_path_hotpaths` reports absolute Criterion timings for the production
transaction queue and inbound admission worker. Run an optimized benchmark:

```sh
scripts/cargo_fast.sh --target-slot perf-agents --stable-local-metadata -- \
  bench -p iroha_core --features bench,iroha-core-tests --bench read_path_hotpaths
```

- `queue_committed_cleanup/resident_N/K`: remove K identified committed inputs
  from a queue containing N distinct signed inputs. N is 64, 1,024 or 16,384;
  K is 1, 8 or 64. Every iteration restores the removed inputs before timing,
  preserving the resident cardinality. The measured call includes index removal,
  metadata and capacity refunds, and backpressure publication. It excludes block
  execution and certification; this is the cleanup callback after those steps.
- `inbound_gossip/known/K`: K canonical peer frames already retained in the queue.
  The worker checks routing and skips byte-identical known frames before decoding
  the transaction graph.
- `inbound_gossip/unknown_cold_signature_cache/K`: remove those identities and
  empty the stateless signature cache before each sample. The measured worker
  decodes canonical frames, verifies signatures and admits the signed inputs.
  K is 1, 16, 128 or 512. Frame cloning and cache/queue reset are outside timing.

Fixtures register a domainless account with an Ed25519 key, explicit global-root
metadata, one active public lane, and zero test fees. Transactions execute a `Log`
instruction. Admission itself uses the production handler; no queue insertion or
signature-validation substitute is timed. The same lazy frames are reused without
populating a shared decoded-entrypoint cache. Construction/signing, fixture State
startup and outgoing gossip draining are outside timing. These are single-worker
component measurements, not network throughput or settlement qualification.

Use `-- --test` to smoke-test every case. Fixture invariants are covered by:

```sh
scripts/cargo_fast.sh --target-slot perf --stable-local-metadata --incremental -- \
  test -p iroha_core --lib --features bench,iroha-core-tests gossiper::benchmark::tests
```

Criterion's default for this target is 30 samples, a one-second warm-up and a
two-second measurement. Override those on the command line when appropriate.
Record the machine, profile, compiler, competing workload and Criterion confidence
intervals with results. Re-run on an idle machine before setting a regression gate.
There is no reconstructed A/B baseline.

The matching [P2P benchmark](../../iroha_p2p/benches/README.md) covers record
sealing/writing and receive-credit release notifications.
