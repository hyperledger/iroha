# ZK Audit Matrix

This matrix began as a record of the 2026-04-02 and 2026-05-16 ZK hardening
passes. Historical risk labels are not current release qualification. The
standalone-election, Parliament and IVM entries below reflect their current source
owners; this correction does not constitute a new independent audit or
revalidate the other entries. Release completion is tracked in the
[first-release closure](privacy_first_release_closure.md) and the
[ZK remediation goals](zk_first_release_goals.md). The 2026-09-26 source review
replaces the affected rows below with actual relation and resource limitations;
it does not assign a blanket low-risk rating to cryptographic implementations.

## Matrix

| Surface | Backend family | Runtime criticality | Outer binding checks | Backend verifier used | Residual risk after patch |
| --- | --- | --- | --- | --- | --- |
| Standalone ZK election ballot / tally | Closed semantic native PIPA-R registry; no admitted ballot or tally circuit | Separate consensus-critical election product, implementation incomplete | Active VK, exact circuit role, VK/schema/envelope and contextual host checks remain mandatory; they cannot supply the missing semantic statement | `world::voting_circuit_matches` and the closed `native_pipa_r::NativeRelationV1` registry reject the current unsupported vote roles before an accepting proof path | Unqualified. No production ballot/tally relation or canonical key owner; toy vote-bool and generic STARK Binding AIR are rejected. See the required bindings below. |
| Parliament private body ballots / tally | Fixed timed-OVN over BLS12-381 with threshold-BLS release; separate from the native PIPA-R registry | Consensus-critical Parliament lifecycle | Exact session, registered participant, frozen survivor corpus, release identity, phase/deadline and finalized-release bindings; complete ordered ballot corpus and aggregate count checks | `iroha_crypto::timed_ovn`; Core `governance::timed_ovn`, `tle_release` and `parliament::reducer_ballot` | Real protocol and lifecycle owners exist, but the [ballot decision](parliament_private_ballot_design.md) retires timed-OVN and its threshold-BLS release, so they are not review targets. The replacement credential-membership/nullifier PQ proof has no qualified profile, implementation or audit yet; implementation presence is not an audit result. |
| Confidential transfer / unshield | Fixed native PIPA-R relations | Typed wallet owner and explicit-relation verification | Canonical key, public instances, ownership, membership, range and conservation | `iroha_core_zk::verify_for_relation` over the guarded verifier | Note commitments remain public and linkable. Optional inputs require no dummy empty-leaf membership; regenerated keys, full-capacity and adversarial Core controls pass. Real SDK change/redemption proofs also verify against current Core with negative key/relation/format controls. Final native distribution and source-bound release qualification remain open in the [ZK goals](zk_first_release_goals.md). A local proof does not restore retired monetary instructions or authorize ledger effects. |
| `IvmProved` admission | Closed until one complete native STARK execution relation is qualified | Consensus-critical | Core rejects proof-backed execution and trigger registration; reserved IVM identities are rejected by generic proof surfaces | No production IVM execution-proof verifier is admitted | Unqualified. A canonical public statement exists, but complete finalized-State ownership, the constrained execution relation, local proving and transactional dependency checks remain open. |
| Kaigi privacy authorization / usage | Fixed native PIPA-R relations | Consensus-critical for Kaigi privacy-mode flows | Active VK, canonical circuit/schema, exact public call/subject/role/sequence or host/segment/billing context | `verify_for_relation(KaigiAuthorization/KaigiUsage, ...)` after contextual checks | Dedicated circuits and context binding exist; independent relation, privacy and implementation qualification remain required. A generic binding proof cannot authorize these roles. |
| RAM-LFE execution receipts | Resolver signature; proof mode unavailable | Non-consensus helper / application-facing | Signed policy/payload/clock checks; direct proof helper refuses before decoding | Signature verification; proof mode unavailable | Signature mode has an explicit signer trust model. Policy registration/activation, stateless receipts and the shared proof helper reject the unavailable relation. The former generic payload-hash verifier is removed, so direct identifier callers cannot promote an unrelated proof to execution correctness. The [execution-proof contract](ram_lfe_execution_proof.md) requires policy-hash binding, bounded secret-derived initialization and the complete interpreter relation; no binding-only adapter can complete it. |
| Identifier receipts | RAM-LFE attestation plus signed output opening | Consensus-critical claim admission / application-facing verification | Policy/program linkage, opening signature, opaque identifier/receipt hash | Signature verification or the shared RAM-LFE verifier | Shared checks avoid verifier-policy drift but do not supply RAM-LFE's missing semantic proof relation. Qualify signature and proof modes separately. |
| Lane relay / FASTPQ | Fixed masked DEEP/STARK relation | Safety-critical for lane proof checking | Complete canonical statement digest, all public inputs, ordered batch identity and AIR/FRI checks; relay authority separately requires finalized QC-bound roots | `offline_compact::verify_quantity_ordinary_artifact` and the canonical AXT envelope verifier | Complete required-Metal fixed-SMT child (482,978 bytes), ordinary one-child artifact (485,600 bytes) and AXT one-child artifact (484,750 bytes) production and independent verification pass; the cached child preserves the seeded proof bytes and has a retained public artifact with separate verification/mutation checks. Ordinary roots cover the touched-balance tree, not the complete ledger. AXT consistency does not establish source finality or spend authority; remote-spend and relay business-effect promotion remain rejected. Complete same-seed CPU/Metal proof-byte parity and separate retained-artifact replay pass on the same unoptimized test executable; optimized facade measurements, maximum application shapes, multi-child resource behavior, source-bound network qualification and independent hiding/soundness review remain open. |
| BFV full bootstrap | Reserved native STARK relation with full execution material | Governed Soracloud artifact verification | Exact statement/artifact binding and reconstructed trace/composition commitments | `verify_stark_fri_bfv_full_bootstrap_air_envelope_for_artifacts_with_limits` | Public-padding-only verification always rejects because hidden trace columns lack their own low-degree argument. Full-material replay is the supported correctness path; a bounded private relation remains outstanding. |
| Vega private commitments | T256 Hyrax / Figure 9 | Candidate private proving; engine unavailable for ledger activation | Public row dimensions, independently derived bases and transcript/statement checks | Shared fixed-window secret MSM with clearing owners | Secret-dependent row trimming and raw private MSM vectors are removed. Twenty-five native arithmetic, erasure and worker controls pass; current-source review confirms public work dimensions and clearing private owners. Target-specific side-channel review, compiler-created copy analysis, independent protocol review and complete resource qualification remain open. |
| ZK-X509 | Complete typed certificate/CRL/disclosure relation | Candidate credential protocol; engine unavailable | Fixed full relation/profile and unchanged 9,437,184-byte ceiling | Dedicated typed verifier | Joined MAIN columns, full current/next Fp4 DEEP checks, paired FRI leaves and the repaired RFC temporal relation give a codec bound of 9,420,938 bytes. The first maximum producer attempt failed before producing a proof; the corrected ordinary/maximum RFC source preflights pass in isolation. Fresh integrated profile pins, actual maximum-shape proofs, independent soundness/hiding review and resource measurements remain required; codec bounds do not establish deployability. |
| Torii `POST /v1/zk/verify-batch` | Standalone native IPA poly-open helper | Diagnostic only, not ledger-equivalent | Configured total-body cap before decode; finite batch/envelope/curve-`k`/label caps; the wire selects only curve/`n` and the verifier derives the deterministic V1 generators; transcript-bound statement (`transcript_label`, complete derived parameter fingerprint, curve/`n`, `z`, `t`, `p_g`, optional metadata); proof-round shape checks | `iroha_zkp_halo2::batch::verify_open_batch_with_limits` | Deterministic unblinded polynomial openings provide no standalone zero knowledge. Callers cannot encode alternate generator relations, and resource use is bounded, but the diagnostic endpoint lacks ledger VK registry / circuit/schema policy enforcement. |
| IVM batch syscall (`SYSCALL_ZK_VERIFY_BATCH`) | Registry-backed native PIPA-R and exact STARK profile verifier on `CoreHost`; disabled on `DefaultHost` | Runtime helper with ledger-grade binding on the node host | Outer `OpenVerifyEnvelope` header checks, VK registry lookup, circuit/schema/manifest/curve/`max_k` or STARK profile enforcement, then backend verification with guardrails | `iroha_core::smartcontracts::ivm::host::CoreHost` -> `iroha_core_zk::verify_backend_with_timing_guardrails` | Low on the runtime host. `DefaultHost` intentionally returns `ERR_DISABLED`, so the remaining risk is misuse of a non-runtime host rather than a standalone verifier bypass. |

## Election statement completion

[Standalone referenda](governance_pipeline.md#standalone-referendum-boundary)
remain a separate product with PLAIN and proof-backed ZK ballots. They cannot
produce Parliament body results or authorize `GovernanceCertificateV1`.
The missing ZK implementation does not withdraw that product requirement.
The [retired vote fixture](governance_vote_tally.md) supplies neither an
approved semantic circuit nor a production key; changing its label cannot
satisfy the closed registry.

Public PLAIN arithmetic now uses an explicit pre-vote frozen smallest-unit
context, funded escrow even at a zero minimum, immutable-choice monotonic
updates, and a durable closed result independent of released locks. Core and
Torii share the checked public tally. The exact integer-square-root and capped
conviction multiplier live in `conviction_weight_from_units_v1`, a pure checked
reference taking the asset's smallest units. A future private ballot relation
must prove that same equation against its confidential bond. This is a
public-account correctness repair;
it supplies neither anonymous credentials nor a confidential position/ballot or
sound private tally proof, and does not open any registry admission gate.

Core's retained standalone ZK election state now has one bounded, ordered
sequence of fixed 32-byte `(nullifier, commitment)` pairs. Snapshot and restore
validation preserve the exact pair and admission order, reject duplicate
nullifiers, and refuse the retired split-field layout. This is only durable
corpus structure: the current nullifier is still derived from a public
commitment, and no credential, confidential bond, choice-preserving update, or
dropout-resilient closed-corpus tally relation has been qualified. Ballot and
tally production admission remain closed. Both ballot routes still clone the
retained election before the bounded append; whole-owner allocation admission
for that clone and its publication remains a separate resource gate.
Create, Submit and Finalize now declare the same whole-election scheduler key
because each replaces the entire retained record; field-suffixed election hint
keys are rejected rather than treated as independent writes.

Core's current `ballot_inputs_from_columns` reads only commitment and eligible
root. `SubmitBallot` requires the supplied ciphertext to equal those commitment
bytes, and `derive_ballot_nullifier` hashes that public commitment with domain,
network and election selector. `tally_from_columns` reads only one `u64` count
per option. These shapes do not define ballot encryption, credential-based
uniqueness or a tally relation over the actual accepted corpus.

The standalone ZK ballot and final-tally execution routes now retain an explicit
fail-closed semantic admission guard after verifying-key role resolution and
before proof verification or accepted-state mutation. A future key-registration
change alone cannot open these routes. The guard must remain until reviewed
relations prove credential-linked anonymous authority, a confidential bond
weighted in the asset's frozen smallest units, choice-preserving conviction
updates, and the exact closed accepted corpus. Public PLAIN ballots continue to
use their separate frozen-scale arithmetic and funded escrow protocol. The
current closed key registry still rejects vote roles before this guard can be
reached by an instruction; the guard is independent defense against a later
registry or role change and does not qualify standalone ZK elections.

The [standalone protocol contract](standalone_election_protocol_contract.md)
requires anonymous, aggregate-only, committee-free, non-reconstructing dropout
completion. Its construction remains unresolved. The retained standalone
contract therefore needs a reviewed semantic design
that specifies and enforces the following bindings at the circuit and host
boundaries before any production registry/key admission:

- Exact network, election selector, nullifier domain, eligibility snapshot,
  option count and ballot policy. Eligibility membership and the
  election-scoped nullifier must follow one authenticated credential relation;
  a hash of a freely changed public commitment is not that relation.
- A valid choice and its authorized weight, with the actual conviction-lock
  owner, amount and duration where applicable. Duplicate, replacement and
  lock-extension rules must agree with the retained state transition;
  caller-provided hints alone do not prove them.
- The exact admitted ciphertext/commitment and its well-formed relation to the
  choice and confidential bond. Specify any public parameters and tally-opening
  relation required by the construction without a decryption committee, master
  decryption key, voter-secret reconstruction, omitted accepted ballots or
  additional subset tallies. No encryption scheme or recovery construction is
  selected by this matrix.
- The exact closed accepted ballot corpus, its order/root/count, election and
  eligibility/key/policy context, including replacement and duplicate handling.
  Tally counts must be derived from that corpus and respect option, weight and
  arithmetic bounds. Comparing public counts to submitted counts does not
  prove tally correctness or bind another election's result.

Dynamic context may be bound through a precisely specified canonical statement;
its representation, circuit relation and proof/key parameters still require
review. Parliament's three-choice, linkable-participation timed-OVN statement
is not a substitute for this standalone relation. Dedicated election snapshot
reads validate stored shape, not ballot proofs, finality or Parliament
certificate authority. No accepting alias, fallback or new qualification is
introduced by this documentation correction.

## Notes

- The strongest OtterSec-style risk in this repo was the standalone native IPA
  helper, because it previously derived Fiat-Shamir challenges without binding
  the full public statement. That helper now binds `transcript_label`,
  backend/domain size, the exact deterministic parameter fingerprint, `z`,
  `t`, `p_g`, and any optional metadata carried in `OpenVerifyEnvelope`.
- FASTPQ already seeded Fiat-Shamir with `public_io`, so its issue was not the
  same bug class. The hardening here closes the verifier-side claim-validation
  gap by requiring field-for-field `PublicIO` equality before accepting the
  proof.
- Generic arithmetic verification uses the guarded backend implementation.
  Application callers require an explicit `ProofRelation` through
  `verify_for_relation`, then enforce their authenticated public context and
  replay state. Typed privacy protocols retain their dedicated verifiers.
- The former IVM binding AIR and Halo2 registration are retired. Generic AIR
  verification still rejects reserved IVM identities, while Core rejects
  `IvmProved` before effects. Deterministic replay or matching supplied
  commitments cannot establish the missing private execution relation.
- The pre-release decode-only `/v1/zk/verify` and `/v1/zk/submit-proof`
  routes were removed instead of retaining success responses that could be
  confused with cryptographic or ledger acceptance.
- Block headers and peer handshakes now include a `zk_policy_hash` in the
  confidential feature digest, so peers commit to the consensus-relevant ZK
  verifier policy instead of trusting node-local timeout or worker settings.
- Generic `VerifyProof` is registry-only: it requires `vk_ref`, rejects inline
  VKs, and enforces active VK record, circuit/version, schema, namespace, gas
  schedule, and commitment binding before calling the backend verifier.
- Local verifier elapsed time is reported for telemetry but is no longer a
  consensus rejection condition. Runtime limits that can change block validity
  are sourced from the committed ZK policy.
- The standalone Halo2 helper's wire carries only `(version, curve, n)` and the
  verifier derives the one deterministic V1 parameter set for that selector.
  Canonical sets live in a bounded process-local cache and Fiat-Shamir
  challenges come from a running transcript state. This removes the
  caller-chosen generator surface entirely, as well as the previously noted
  unbounded-cache and quadratic-history rough edges, without changing its
  non-ledger status.
