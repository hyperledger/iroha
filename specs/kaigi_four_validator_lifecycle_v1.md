# Final Kaigi four-validator lifecycle gate

The opt-in `network_functional` gate exercises the production final Kaigi authorization and
usage circuits against four real permissioned validators. Its implementation is pending
compilation and real execution; this document does not assert deployment qualification.

`iroha_core::privacy_release_evidence::kaigi` owns pure fixture construction under the
nonshipping `privacy-release-evidence` feature. It uses the migrated native PIPA-R
`kaigi_zk` owner and entropy dependencies. The helper returns
ordinary configuration references, `RegisterVerifyingKey` instructions and real canonical
proof carriers. It never reads or mutates `StateTransaction`, installs a key or grants
permission. Fixed fixture openings are unsuitable for production; proof generation uses
real PIPA-R proofs and the canonical circuit-owned authorization/usage context.

The existing `crates/iroha_core/tests/kaigi_privacy.rs` assertions remain intact. Their
pure key-generation, proof framing and circuit helpers supply the fixture implementation;
the network gate installs the returned keys with signed governed instructions. The
network builder projects both ordinary Kaigi key references and enabled native PIPA-R state
into signed genesis through its existing policy-hash owner. Daemon policy equality
must remain enforced: a stale daemon failure cannot be repaired by altering genesis.

## State and authority assertions

The single ignored network leaf is
`kaigi_privacy_network::four_validator_kaigi_private_lifecycle_replay_and_restart`.

- Seed the universal host/participant identities through ordinary genesis, and fund the
  independently signing participant with an Applied transfer of the default fee asset.
  Install both governed keys with the host's normal verifier-management permission.
- Sign Create, Join, Usage, Leave, Rejoin and End as their actual host or participant.
  Every positive submission must converge as the exact successful external transaction
  on all four peers, with identical complete call records and expected private counters,
  commitments, roots, nullifiers, original identity and sequence.
- Reject forbidden envelope metadata, an actual native proof-byte mutation, host
  impersonation, altered usage billing, repeated Join/Usage, the old Join after departure
  and restart, repeated End and recreation. Require the exact typed native rejection;
  transport, timeout and unrelated failures cannot count. After each rejection, an
  independently Applied barrier must converge before comparing the unchanged record.
- Cold-restart one validator after Leave and after End. Commit a new barrier with the
  remaining three; restart the fourth with its persisted configuration and storage,
  require a changed process ID, catch up that exact transaction, and compare records.
  The original Create must remain visible after both restarts.
- Validate structural revision-4 status on all peers, exact four-validator/three-vote
  summaries and a common committed subject. This is not an independent certificate
  signature verifier; the normal daemon owns authenticated QCs and signed RS16 data
  availability. No consensus bypass or observer padding is introduced.

The shared test helper owns a 32-MiB parent thread and four 32-MiB Tokio worker stacks.
Each validator receives one GiB of ordinary local storage. Fee checks, proof byte limits,
verification timeout, RS16 admission and exact quorum rules keep their production values.
Do not set `RUST_MIN_STACK` globally, since daemon children would inherit it.

## Focused compile and execution inventory

Only the coordinated build owner should execute these commands:

```sh
cargo test --locked -p iroha_core --lib --features privacy-release-evidence --no-run --message-format=json-render-diagnostics
cargo test --locked -p integration_tests --test network_functional --features privacy-release-evidence,zk-stark --no-run --message-format=json-render-diagnostics
```

First run these exact non-network leaves from the captured binaries with `--exact`:

- Core: `privacy_release_evidence::kaigi::tests::real_kaigi_release_builders_preserve_governed_keys_and_final_carriers`
- Network harness: `kaigi_privacy_network::kaigi_rejection_control_requires_exact_native_reason`
- Network harness: `kaigi_privacy_network::kaigi_proof_corruption_preserves_framing_and_public_instances`

The real leaf needs `--ignored --exact --nocapture --test-threads=1` and explicitly
`IROHA_TEST_REQUIRE_NETWORK=1`; a skipped network fails the gate. For a local diagnostic,
use an absolute newly built `TEST_NETWORK_BIN_IROHAD`, `TEST_NETWORK_IROHAD_FEATURES=zk-stark`
and `IROHA_TEST_SKIP_BUILD=1`, preserving source, binary and invocation hashes. This is
separate from official release evidence, which also requires the clean signed source
identity, release-profile daemon/tools/harness and authenticated same-candidate program
bundle consumed by `iroha_test_network`'s release runner.

Retain the source seal, exact Cargo artifact/features, raw test log, four process logs,
signed genesis, effective configuration, Kura/state stores, restart observations and
pre/post binary hashes. Keep raw disposable signing configuration private. Successful
execution covers this lifecycle only: relay transport, independent audits, physical
hardware and complete product qualification remain separate gates.
