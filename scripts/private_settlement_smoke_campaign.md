# N=3 positive smoke gate

`private_settlement_smoke_campaign.py` runs the required ten fresh correctness
runs before a release measurement campaign. Each invocation starts four global
validators and three disjoint four-validator participant committees, using the
feature-isolated Rust entrypoint
`nexus::atomic_private_settlement_localnet::atomic_private_settlement_n3_real_process_smoke`.
The source-coupled protocol lives in
`integration_tests/tests/nexus/atomic_private_settlement_localnet.rs` and
`atomic_private_settlement_real_process_harness.rs` in the same directory.

The source checkout must be clean at the exact signed commit. The driver checks
`git verify-commit` and reuses `compute_workspace_source_manifest.py`'s canonical
`release_source_identity`, including actual tracked bytes hidden by Git index
flags and the mandatory `Cargo.lock`. The recorded source hash is the canonical
workspace source manifest. Gitlinks must be existing empty directories: their
commit pins remain bound by the signed parent tree. Populated documentation
submodules are separate unsealed checkouts and fail qualification; the driver
never changes or deinitializes them. Untracked ignore policies are rejected
unless their parent directory is already excluded by a tracked ignore rule.
Those nested policies cannot affect source discovery; tracked inputs beneath
an ignored directory remain part of the manifest. Ignoring only `.gitignore`
filenames, local Git excludes, and untracked rules cannot authorize that exception.
Cargo home must be absolute and canonical, and Cargo
configuration cannot traverse symlinks. Unsigned Cargo configuration in the checkout, ancestor
directories, or Cargo home is rejected. Use a new absolute target directory and
a new absolute evidence directory outside the repository. Both release builds
use locked offline dependencies, four build jobs, no incremental artifacts and
no sccache reuse. The installed compiler, dependency cache, linker and system
libraries remain trusted build-environment prerequisites; retained compiler and
Cargo version logs do not constitute hermetic toolchain qualification.

```sh
python3 scripts/private_settlement_smoke_campaign.py run \
  --repo /absolute/path/to/signed-checkout \
  --commit FULL_SIGNED_COMMIT \
  --target-dir /absolute/path/to/new-smoke-target \
  --output /absolute/path/outside-the-repo/new-smoke-evidence

python3 scripts/private_settlement_smoke_campaign.py validate \
  /absolute/path/outside-the-repo/new-smoke-evidence --commit FULL_SIGNED_COMMIT
```

The driver builds `iroha3d` with `test-network-private-settlement-route-control` and the grouped
integration test with `atomic-private-settlement-smoke` once. This explicit
capability enables the common release harness and its CPU SHA3-384 privacy proof.
The driver discovers the exact ignored smoke test,
then executes ten serial fresh requests. It requires
one executed passing test, zero failures and zero ignored tests from every
invocation. `IROHA_TEST_REQUIRE_NETWORK=1` and
`IROHA_TEST_NETWORK_START_ATTEMPTS=1` are set explicitly. The driver does not
retry or count skipped networks as success. A failed command, state invariant,
source/binary check, or evidence check ends the campaign; the failed directory
is retained and cannot validate as a passing campaign.

After scrubbing inherited test settings, each proving child receives
`RAYON_NUM_THREADS=8` and the exact smoke invocation retains
`--test-threads=1`. Every command receipt records the effective
`RAYON_NUM_THREADS`, `RUST_TEST_THREADS`, `CARGO_BUILD_JOBS`, and
`CARGO_INCREMENTAL` values; absent values are `null`. Validation requires these
values to match the pinned invocation. Each validator keeps the test harness
configuration of four Rayon, scheduler, and pipeline workers. The sixteen
validators and proving process can exceed sixteen runnable workers; these
settings do not impose a host-wide CPU cap.

The experimental result field `activation_height` records the committed height
of the first successful exact Active-genesis capability observation; it is not
a scheduled activation height. The Rust fixture authenticates the compiled Active
genesis record before that observation.

Each request has exactly `version`, `protocol`, `kind`, `request_id`,
`invocation_nonce`, `commit`, `seed`, and `run`. The version is 1, protocol is
`AtomicPrivateSettlementV1`, kind is `smoke`, and run is in `0..9`. The request ID
is SHA-256 of canonical compact JSON of the other seven fields. Request IDs,
256-bit invocation nonces and 64-bit seeds must be distinct across the campaign;
network, bundle, and all validator identities must also be fresh in every run.

Each owner-only `run-NN` directory contains the request, raw command log,
terminal command receipt, Rust result, source/binary seals before and after
execution, and an initially empty owner-only `evidence` directory. The Rust
result binds an exact 114-file inventory with lengths and SHA-256 digests:

- The bound request, before/after process inventories and all 16 restart records.
- Three participant authorities, the all-Prepare barrier, Commit certificates,
  and the three-leg finalized receipt.
- All 16 raw financial responses at `before`, `collecting`, `audited`, `prepared`,
  `registered`, `commit-certified`, `finalized`, and `replay` stages, plus an
  all-16 state snapshot after each of the 16 sequential restarts.
- `prepared-artifact-sizes.json` records all three ordered leg ordinals and their
  proof, canonical base64, capsule, canonical material/upload and JSON request
  byte lengths. The genuine finite APZ1 profile is exactly 2,527,280 proof bytes
  (3,369,708 base64 bytes), below the independent 8 MiB proof ceiling.
- `verified-carrier-sizes.json` records the original verified signed carrier's
  Norito and JSON lengths and its public receipt's Norito length. The carrier
  and receipt ceiling is 4 MiB; the default HTTP body ceiling is 64,000,000 bytes.
  Capsules use the separate default 1 MiB bound. Recorded bounds must match the
  source contract, not merely exceed the recorded measurements. These Rust
  measurements do not establish maximum-size carrier qualification; Python does
  not reconstruct private artifacts or remeasure omitted proof bytes.
- Sixteen continuous raw observation streams, bound to their exact phase
  attempts, classifications, counts, checkpoint coverage and hash chains.
- Sixteen canonical `SumeragiFinalityProof` files before restart and sixteen afterward.
- Sixteen before-restart transport summaries and their sixteen complete raw
  log prefixes. Each summary binds its process PID, canonical peer identity,
  current run, proof bytes, certified source and exact ordered audit lines.
  Each raw prefix is capped at 64 MiB; JSON retains its 16 MiB bound.

Validation checks a nonzero genesis-readiness observation, a strictly later
authority-context observation, finalized-height ordering, disjoint four-member
committees, all 16 distinct process IDs and configuration commitments, changed
process IDs for every restart, and the final atomic financial deltas (three
roots, six nullifiers, nine commitments/encrypted outputs, one replay marker and
one receipt). It rejects intermediate partial application and rollback,
including a mismatch between retained responses and continuous observer
summaries. Replay and every restart must retain the exact finalized financial
state and signed finality decision. Observation/file bounds are strict;
exceeding them fails and retains the run instead of truncating observations.

The Rust harness verifies contiguous native finality through `CertifiedPrefix`
from the configured signed genesis, including exact-quorum BLS and original
signed RS16 availability. Python validates the current proof schema, exact
global committee and PoPs, retained proof digest, certified-source bindings,
and every selected row/custody/application observation against the complete raw
prefix. It rejects omitted lines, changed offsets, duplicate rows, wrong PID or
sender, insufficient stripe coverage, and mismatched payload/context/result.
Restart recovery must retain the same certified decision; it does not claim
fresh network transport because restoration emits no network custody evidence. Protocol hashes must retain Iroha's low marker bit;
the reserved empty Prepare digest is `00…01`, and Commit must bind a nonempty
Prepare barrier. It does not independently verify BLS or recompute
Norito protocol hashes. The log observations are source-bound local process
evidence, not Byzantine remote-transport attestations. Independent cryptographic
review remains a separate release requirement.

The read-only `validate_campaign(path, expected_commit=...)` API rechecks every
artifact plus the retained signed checkout and executable bytes. Keep those
files available and unchanged while using the gate as a release prerequisite.
Synthetic unit tests are in
`scripts/tests/private_settlement_smoke_campaign_test.py`; they never start a
network or create measured release evidence.

The subsequent canonical release campaign keeps its Python execution session
alive through physical worker, economic-verifier, capture and adapter shutdown.
An owner-directed SIGINT/SIGTERM requests draining after the current registered
job or retained network; it never signals a native child or starts a later job.
Publication errors and expired qualification deadlines retain the original
failure while waiting for actual children/process groups. A late natural exit
is not a successful measurement, accepted ACK, or evidence closure. Packet
capture keeps its existing exact tcpdump shutdown operation. Execute this
canonical campaign entrypoint on the main Python thread so its lifetime scope
can own signal handling; do not terminate the enclosing app/session to drain it.

## Happy-day payment observation

`private_settlement_happy_day_campaign.py` validates the distinct native entrypoint
`nexus::atomic_private_settlement_localnet::atomic_private_settlement_n3_happy_day`.
The request and completion marker explicitly bind `happy_day`. Its 81 retained
artifacts prove the same three-leg financial state checks, all sixteen signed
finality observations, sixteen transport summaries plus their complete raw log
prefixes, replay idempotence, and continuous terminal cleanup. All
sixteen validator PIDs remain unchanged; no restart artifact is accepted. Every
terminal observation must match the finalized financial state with zero local
and replicated staging. Earlier finalization observations may show monotonic
local cleanup after the atomic financial transition.

This read-only validator does not establish source, build, runtime closure, or
ten-run release qualification. The invoking experiment controller must retain
and authenticate those records separately. Run `--help` for the required
owner-only run directory, bound request, and validator image SHA-256 inputs.
