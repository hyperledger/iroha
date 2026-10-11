# KAGEMUSHA V1 physical-evidence closure

> **Superseded design authority (2026-10-03).** The
> [single implementation draft](kagemusha_single_design_proposal.md) supersedes
> this document's monetary protocol, provider assumptions and release prerequisites.
> This file records existing interfaces or evidence during migration; it defines
> no additional payment protocol or integration/use gate. Update retained contracts
> with their implementing patches; preserve the observations below as evidence.

This records the implementation-coupled contract enforced by
`scripts/verify_kagemusha_v1_release_evidence.py`,
`scripts/verify_kagemusha_v1_physical_device.py`, and
`scripts/run_kagemusha_v1_release_evidence.py`, plus the explicitly outstanding
sender-validity qualification requirements below. Synthetic unit-test
transcripts are not OEM evidence or hardware qualification.

## Non-circular identities

The small `hardware_profile_qualification_report` remains the hardware-profile
preimage: provider, policy epoch, run-derived verification identifier and exact
physical-check list. Its SHA-256 enters `HardwareProfileV1`, whose identity
enters the release candidate context. The signed raw physical transcript then
binds that context in `run.candidate_context_digest`, plus the exact release
artifact-set digest. Existing `run.candidate_digest` retains its separate meaning
as the candidate artifact recovered in the physical state-transition test.

The profile's manifest row MUST also contain `physical_evidence` with exactly:

| Field | Evidence kind | Meaning |
| --- | --- | --- |
| `transcript` | `physical_transcript` | Complete canonical, observer-approved physical transcript, including event chain. |
| `attestation` | `oem_attestation` | Complete raw OEM enrollment/service attestation bytes. |
| `trust_roots` | `oem_trust_roots` | Exact governed OEM verifier trust-root/policy bundle. |
| `observer_policy` | `observer_policy` | Byte-identical copy of the independently supplied, hash-pinned observer policy. |
| `oem_report` | `report` | Independent native OEM attestation verification result. |

The manifest's closed file inventory and verification observations commit all
five files and the small qualification report. The final release receipt binds
the manifest, observer policy and signed verification records. No transcript or
OEM report digest is inserted back into the hardware-profile preimage. This
ordering avoids a transcript/profile/report hash cycle.

## Independent trust and native OEM validation

The separately pinned observer policy MUST admit `physical-device-verifier`
with the exact SHA-256 of the fixed operator-local physical verifier and the
hardware qualification report schema. The release projector loads those
already authenticated source bytes using its own authenticated release module;
it never imports or executes candidate-provided source. It reruns the complete
transcript checker and observer-signature verification and requires the exact
derived qualification report. The collection runner binds this physical source
in its tooling closure and rechecks it before publication. The release projector
also rechecks the source before returning its projection.

The transcript must match the governed profile identity, provider, policy epoch,
capability mask, platform, qualification report, validity interval, release
candidate context and artifact inventory. Its attestation digest must match the
retained raw OEM bytes.

Each restart and power-loss cycle must end on a fresh hardware boot identifier
that has not appeared earlier in the run, including the initial boot. Matching
the immediately preceding boot and control pair is insufficient: returning to
an older boot is rejected even when the event chain and observer approvals are
valid. Sender recovery retains this same freshness requirement across the
complete prefix and its subsequent recovery cycles.

Inbox and outbox recovery must preserve every durable record field: the exact
operation or credit identity, canonical bytes, certificate or receipt, revision
and durable result. Per-attempt `latency_ms` and `rss_bytes` may differ after a
restart. Each original and recovery measurement still undergoes integer/schema
validation and contributes independently to the existing overall operation p95
limit of 30,000 ms and whole-process RSS maximum of 128 MiB. Thermal folds also
retain their separate 10,000 ms p95 limit. These are quantile limits, not a new
per-attempt latency timeout or separate original/recovery populations;
measurement changes do not permit any durable record substitution.
See [release-runner software validation](kagemusha_v1_release_runner_validation.md)
for the scoped regression evidence and remaining qualification limits.

`iroha.kagemusha_v1.oem_attestation_verification_report` is a closed V1 JSON
report. Besides standard schema/version/verification identifier fields, it binds:

- The exact hardware profile, provider, epoch, capability mask and hardware policy.
- The exact public provider commitment and registry index. The enclosing provider
  row also contains a canonical low-S P-256 signature that Rust and the release
  projector verify directly under the profile's governed issuer key; neither
  this OEM report nor fresh observer approvals can replace that authorization.
- The device, product, firmware, OS build and platform seen in the transcript,
  and the governed product-class and firmware-policy digests.
- `attestation_verifier_sha256`, equal to the hardware profile's
  `enrollment_attestation_verifier_digest` and the actual threshold-observed
  verifier executable identity admitted by the independent observer policy.
- `{sha256, byte_len}` bindings for raw `attestation`, `trust_roots`, `transcript`
  and `observer_policy`. Root bytes must independently hash to the profile's
  `attestation_trust_roots_digest`. Both governed implementation/root fields
  use the SHA-256 of the exact retained implementation/root-bundle bytes for
  this release-evidence corridor.
- `challenge_sha256`, the SHA-256 of the domain
  `iroha:kagemusha:v1:physical-oem-challenge\0` followed by canonical JSON of
  `hardware_profile_id`, `device_id`, `firmware_digest`, `os_build_digest`,
  `candidate_context_digest`, `artifact_set_digest` and `run_id`. The native OEM
  verifier must require the raw attestation to authenticate this challenge.
  These are pre-attestation inputs, avoiding another hash cycle.
- Release candidate context, artifact inventory, run identifier, start/end times,
  and exact hardware-backed/production-build/no-software-fallback assertions.

The native OEM verifier invocation consumes exactly this report and those four
raw files. The separate physical qualification invocation consumes its small
report and all five sidecar files. Both invocations require independent
threshold-signed observations over the exact input bytes and current candidate
context; a command cannot be reused for both reports. A generic positive report,
a changed candidate, or self-reported hardware booleans cannot replace this
chain.

Actual OEM chain parsing, revocation, freshness/challenge verification and the
binding from native attestation claims to product/firmware policy are the
responsibility of the authorized, independently admitted OEM verifier. There
is no generic parser that establishes those properties for arbitrary iPhone,
Samsung, Huawei, Google or Meizu attestations. An OEM/laboratory must provide
and qualify that verifier, its controlled trust-root bundle and complete raw
physical evidence for each enabled profile. Without them the release gate
remains closed; this implementation supplies no qualified profile or attestation.

## Sender admission and historical recovery evidence

The [operation-7 admission contract](kagemusha_device_bridge_v1.md#outgoing-lifecycle-operations-5--10-and-12)
requires the qualified service to authenticate the exact sender compact
credential and governed profile, then check the actual trusted commit instant
and any entire positive, nonempty half-open lease against both validity
intervals before consuming the predecessor. Public frame validation, host
wall-clock time, or a later terminal-proof failure cannot grant this authority.

The closed raw transcript now requires one `sender_validity_context` followed
by paired `sender_admission_attempt` / `sender_admission_result` events for each
of these cases, in this order, for both `send_split` and `redeem_split`:

| Case | Required observed outcome |
| --- | --- |
| `before_issuance` | Reject at actual hardware time before the signed credential activates. |
| `trusted_valid` | Commit once at actual hardware time inside both intervals. |
| `lease_credential_straddle` | Reject a lease ending beyond the credential while actual time remains inside it. |
| `lease_empty` | Reject an empty lease. |
| `lease_zero` | Reject a lease with zero start. |
| `lease_before_credential` | Reject a nonempty lease starting before the credential activates. |
| `lease_end` | Commit once with a full lease ending exactly at credential expiry. |
| `trusted_before_expiry` | Commit once later in the valid credential interval. |
| `credential_expiry` | Reject at actual hardware time greater than or equal to credential expiry. |
| `credential_after` | Reject at actual hardware time strictly after credential expiry. |

The context opens the exact governed profile and one early-expiring compact
credential. The checker reconstructs the existing canonical Norito credential
ID and verifies its low-S P-256 issuer signature under the profile's exact
governance key, including network, lane, device key, suite and hardware epoch.
The release projector also checks the sender VK digest and suite against its
independently derived candidate VK set and enabled profile. The entire run
remains inside the unchanged governed profile interval. Physical observations
use monotonically advancing actual clock intervals; exact millisecond equality
at both credential endpoints belongs to unit/circuit tests, not a simulated
physical clock. The actual admission-decision time must follow the retained
sample, continue prior authenticated clock evidence, and be freshly observed.

Each attempt must retain active native-valid request and reservation windows.
Send requests retain the existing 300,000 ms maximum TTL. For nonempty lease
boundary cases, both unrelated windows must contain the entire lease so their
failure cannot explain the expected rejection. Rejection must leave state,
epoch, monetary/authorization/lease/release counters, journal and outbox
revision/digest unchanged. Positive controls advance exactly one successor
and the applicable commit counters, with a new recoverable terminal outbox.

Six `sender_historical_recovery` events then recover those successful commits
on fresh hardware boots after credential expiry but before profile expiry.
Operations 7--10 retain the original certificate and terminal envelope;
operation 7 replays the exact cached original command and response. Operation
12 consumes its separate release authorization and releases the retained
outbox entry, without advancing monetary state or the original commit/lease
counters. Prior boots, controls, operation identities and authority observations
cannot be reused as fresh evidence.

Each result and recovery contains a device signature over the closed event
subject, its kind and the context event hash; results also bind the exact
attempt event hash. This is a **service-produced observation of actual admitted
or rejected operations**. A provider must never expose it as a signing oracle
for caller-supplied JSON. Observer signatures, a public frame codec, or a host
clock cannot replace the service's authenticated decision and state evidence.

## Native operation-12 structural evidence

The current `connect_norito_bridge` manifest declares only the development
binaries `soracloud_request_signer` and `swift_parity_regen`, both gated by
`dev-tools`. The bridge has no declared operation-12 sender parser executable or
`src/kagemusha_sender_release_evidence.rs` projection module. This procedure's
native parser executable/source provenance pins therefore remain unavailable in
the current candidate. A reviewed structural-evidence producer and its physical
qualification remain outstanding. Observer signatures, a frame codec, or a host
clock cannot replace actual native command validation and service-produced
operation evidence.

The nested signed projection binds the exact command, retained operation,
preparation/candidate, certificate/envelope, underlying terminal receipt,
Release-purpose authorization, sender profile/credential/policy/VK and public
commit evidence. For a send it also binds the exact signed request windows and
public committed time. A protocol hiding commitment is kept distinct from the
SHA-256 of a service observation. The service-signed release record separately
attests actual acknowledgement verification or consumption of Core's opaque
finalized-redemption capability for those exact parsed identities.

The projection is always `structural_only=true`. It cannot establish loaded
release-catalog membership, execute a recursive proof, consume a nonce, or
construct a finalized redemption capability. In particular a voucher's
`artifact_manifest_digest` is a loaded release manifest selector, **not** the
candidate artifact-set digest; V1 sends carry no such public manifest field.
Actual qualified-service evidence binding operation 1 and its loaded release,
manifest and Core authorization key to the candidate remains outstanding.
The parser report is accepted only nested inside physical evidence; it cannot
replace a required qualification, OEM or release report or contribute required
verification counts.

## Outstanding physical profile procedure

Direct physical preactivation/expiry and recovery after profile expiry remain
unresolved pending an authorized provider/laboratory procedure. Requiring those
events while simultaneously requiring the same enabled profile to contain the
entire run would be contradictory. Isolating a lease beyond a long-lived sender
profile while a five-minute receiver request contains that entire lease can
also be impossible. This patch neither shortens production profile lifetimes
nor accepts expired runs, detached diagnostic profiles or simulated clocks to
make those scenarios pass. Profile containment remains mandatory in credential
validation and the terminal circuit; its software boundary tests do not supply
physical admission evidence.

The native parser and controlled synthetic fixtures establish software
structure and negative checks only. They supply no qualified OEM service,
physical device run or production authority. Native release gates remain closed
until the complete implementation and genuine independently authenticated
qualification evidence are available.

## Focused checks

Run `python3 -m pytest pytests/scripts/kagemusha_v1_physical_device_test.py
pytests/scripts/kagemusha_v1_release_evidence_test.py
pytests/scripts/kagemusha_v1_physical_provenance_test.py
pytests/scripts/kagemusha_v1_provider_policy_test.py
scripts/tests/run_kagemusha_v1_release_evidence_test.py`. The tests cover raw-byte
substitution, independently pinned policy and roots, OEM report subject
substitution even after generic observer reapproval, missing transcript
signatures, rechecked event-chain semantics and candidate replay.
