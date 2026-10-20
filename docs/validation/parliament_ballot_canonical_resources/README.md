# Canonical ballot resource observations

Both portable and accelerated workers pass the same 55 cases, including genuine
3-, 500- and 1,000-seat votes and a separately stamped late-invalid 1,000-seat
proof. All 55 input pairs, exits and complete worker reports match. These are
finite vote-validity and resource observations, with no committed ledger effect.
Production qualification remains false.

The current typed decoder and local-refusal correction is covered by a fresh
[regression receipt](envelope-refusal-receipt.json): 107 anonymous-ballot model
tests, 79 protocol tests and 25 example tests pass, followed by 55 worker cases
per mode with exact input/report parity. Original local decode refusals now
remain unavailable through binary/JSON carriers, admission, block validation
and sealed-list replay. They cannot serve as malformed ballot or seal evidence.
Schema-limit violations remain invalid input, even when their numeric ceilings
match an enclosing budget. No wire representation or proof rule changes.

The [probe and reproduction instructions](../../../crates/iroha_parliament_ballot/examples/canonical_resource_probe/README.md)
define the entry boundary. Canonical envelope/context decoding, checked context
construction, actual stamp/proof verification and owned-value destruction run
inside the charged interval. The caller's file retrieval and immutable input
storage are outside it. Fixture authority and block anchors do not authenticate
chain history. Registration and casting-window/nullifier execution are outside
this probe.

## Results

The host was an Apple M2 Ultra, arm64, macOS 27.0.1, with 16 KiB pages;
Rust/Cargo 1.93.1 built the `local-release` profile. Each invocation reserves
43,106,304 bytes (41.109375 MiB), including arena metadata, the supplied native
stack, control storage, guard pages and the shared fatal page. This reserved
mapping is not a bound on every runtime/native allocation.

Every original envelope is 233,455 bytes and consumes one work unit. The byte
debit includes the complete envelope plus context. Both modes report:

| Fixture | Context bytes | Charged bytes | Peak requested bytes | Peak arena block bytes | Result |
| --- | ---: | ---: | ---: | ---: | --- |
| 3 seats | 1,352 | 234,807 | 3,924,851 | 4,765,632 | Accepted |
| 500 seats | 65,963 | 299,418 | 4,309,766 | 5,281,728 | Accepted |
| 1,000 seats | 130,963 | 364,418 | 4,698,862 | 5,674,944 | Accepted |
| 1,000 seats, late-invalid | 130,963 | 364,418 | 4,698,862 | 5,674,944 | Proof rejection |

The 1,000-seat fixture uses the default policy. The maximal structurally valid
context is **130,995 bytes**, including all ten required bodies and the largest
permitted bond, so the maximal valid pair is **364,450 bytes**. The
[source-derived formula and typed tests](../../../specs/parliament_ballot_resource_contract.md#verification-and-debit-boundary)
establish the wire bound. The context decoder's 327,680-byte nominal codec charge
cap is separate from physical heap/workspace. The envelope decoder permits zero
sequence elements and exactly 233,012 bytes for its sole proof copy. The fresh
worker runs reproduce the table's peaks; they use the retained genuine default-policy fixtures rather
than a newly mined maximal-policy proof.

Per mode, the 55 cases comprise three accepted, 16 rejected, 12 admission
refusals, six staging errors, 15 context/worker errors and three forced arena
exhaustions. All 46 normal arena exits report zero live requested and block
bytes. Staging errors allocate nothing in the arena. Forced exhaustion exits
with code 73, retains the full debit and publishes only the fatal control page;
it does not establish destructor cleanup.

The current example tests pass: six generator tests and 19 worker tests, including
an isolated three-case hook-restoration regression. The typed protocol
library passes 79 tests; two on-demand fixture-generation helpers
remain ignored. That suite includes registration, wallet admission/execution,
corpus closure and independent replay. It is runnable with
`scripts/test_parliament_ballot_local.sh --full`, without a qualification record.

## Source and retention

The fresh regression root is `.codex/parliament-envelope-refusal-20261020`.
Its receipt pins all five successful test/build captures, 114 scoped input hashes
before and after each phase, feature trees, both campaign manifests and a complete
raw-record/parity recheck. Each phase's scoped inputs stayed unchanged. These
are ordinary live-checkout engineering results; the scope is not a complete
frozen compiler-input inventory. Documentation was updated after validation.
The portable campaign overlapped the accelerated build in separate processes;
no isolated timing or named-hardware result is claimed. The initial model run
is retained separately: 103 tests passed and four assertions failed. Corrected
tests account for raw byte-vector specialization and the source order of protocol
ceilings; runtime checks were not relaxed. The preceding
[context-boundary receipt](context-boundary-receipt.json) retains its original scope.

The earlier [receipt](receipt.json) retains local source manifests, build records,
feature trees, fixture generation, test logs and both earlier campaigns under
`.codex/parliament-canonical-resource-revision3-20261019`;
each campaign's `SHA256SUMS` covers 388 files, including its copied executable,
scripts, raw child output, exact inputs, fatal pages and results. These retained
local artifacts are not distributed release evidence.

Those earlier workers use source manifest
`948ce1a0cda0f0b876995235878f6223807355d40bc646bdb2c58426bc7f7a9d`.
Those earlier fixtures and protocol-suite results use the separately identified
revision2 snapshot. Revision3 changes only two pointer assertions in an example's
test module; generator and library source bytes are unchanged. Portable and
accelerated feature trees separately establish the absence/presence of the
backend AES hardware feature. Build source checks are unchanged before/after
compilation, but external dependency sources are not fully captured and the
working-tree capture is not an atomic checkout snapshot.

Earlier failures remain retained: the first genuine input exited 74 because a
first-use Norito panic hook retained an arena owner; the corrected one-shot
worker restores the original hook before routing ends. The first 1,000-seat
generator incorrectly used a default Policy Jury with target 500; it now uses
the default Confirmation Jury with target 1,000. Neither correction relaxes the
standard policy or 28-bit stamp requirement. A subsequent test-only lint failure
is also preserved separately from the passing final build.

TODO: complete all-input sufficiency, native/System/TLS and exceptional-path
coverage, physical cost calibration, independent unsafe/cryptographic review,
named hardware measurements and production integration. The reserved mapping,
finite parity and local protocol suite do not establish a complete 64 MiB
certificate, node/network readiness or any production activation condition.
