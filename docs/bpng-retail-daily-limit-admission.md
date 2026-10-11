# BPNG retail daily-limit admission

This is a source-level release finding, not a Taira allocation, owner approval,
installed policy, or live acceptance receipt. BPNG retail activation must remain
closed while the signed runtime advertises a `singleSignerDailyLimitKina` that
the admitted ledger cannot enforce for every applicable payment.

## Current first-release source slice

The candidate source adds an identity-wide retail DAY usage bucket and a one-shot
native `ActivateRetailDailyLimitV1` instruction. Activation registers a currently
absent dataspace-restricted definition and installs its exact policy atomically
under the definition-domain owner's authority. An immutable activation marker
binds the canonical policy digest and closes governed debits until the following
UTC day. `BindRetailIdentityV1` accepts an exact issuer-signed account binding;
it does not permit rebinding. Native account, definition, domain and rekey
preflights retain the policy, identity and usage state. Five reserved consensus
state roots are inaccessible to generic IVM state syscalls. No `WorldData` field
or decoder migration is added.

This is still **not release-qualified**. The target definition, asset owner,
issuer key, cap, exception roster, signed BPNG allocation, finalized activation
transaction and live direct-Torii evidence have not been supplied. A currently
absent definition may have existed in an earlier incarnation; the owner release
gate must review finalized history for that exact ID. The next-day marker closes
the same-day accounting gap, but does not itself prove lifetime novelty.

The owner-installed policy now selects exact monetary issuer and reserve
accounts. `RetailMonetaryMovementV1` admits only issuer mint into the reserve,
reserve-authorized credit to a bound retail account, retail-authorized defund
to the reserve, and issuer burn from the reserve. Every operation carries a
nonzero one-use digest retained in a fifth reserved consensus-state root.
Generic mint, burn and transfers touching the monetary reserve stay closed.
Activation and snapshot admission require an exact two-decimal PGK asset
definition, matching the MiBank adapter's integer minor-unit scale.
Retail defund consumes the same identity-wide DAY bucket; reserve credit
requires a signed retail receiver binding. The activation-day debit hold also
applies to reserve credit, retail defund and reserve burn. A nonempty generic
institutional exception roster and SCCP inbound release remain closed.

The one-use digest is only transaction linkage. It cannot authenticate a
MiBank debit receipt, prove bank account settlement, or prove final Iroha
execution. Core must verify and retain the exact signed MiBank receipt before
signing/submitting reserve credit, and must authenticate the exact protocol-4
transaction tuple and finalized execution before marking top-up applied or
starting a bank defund credit. The current bank-credit verifier is source-only
and has no independent production anchor or evidence custody. KAGEMUSHA
load/unload (not yet implemented) and other protocol custody need separate
owner-approved typed treatment; their generic paths remain closed. No live top-up, defund,
protocol-4 or physical-device acceptance follows from this source slice.

## Finalized activation evidence boundary

`verify_finalized_retail_activation_v1` accepts only a `VerifiedSumeragiBlock`.
The portable `SumeragiFinalityVerifier` constructs one after admitting the
contiguous `SumeragiFinalityProof` prefix from an independently selected
signed genesis or trusted checkpoint. Each proof, as served by
`GET /v1/bridge/finality/{height}`, is the Kura-certified frame of its height:
the result-bearing block with its exact-quorum `CommitQC` over the core header
and certified result `R` (`specs/sumeragi.md` §12.7). The node builds it from
its own certified read; the client re-verifies every certificate, parent link
and epoch authority itself. The activation verifier then binds that frame's
exact executed block wire, one direct owner-signed activation instruction,
and its successful typed Network output. Callers must supply the
owner-approved full policy, definition, domain, dataspace and entry hash
independently. The verifier compares the complete policy, including the cap,
reserve, monetary issuer, identity issuer and key. It derives the canonical
policy digest and following UTC-day activation marker from the finalized
block timestamp.

The activation executes in the `bpng` physical dataspace lane and is merged
into the global block that the proof certifies. Retail instructions carry no
concrete dataspace routing target, so the governed lane policy needs an
explicit `SumeragiLaneRoute` for `ActivateRetailDailyLimitV1` to that fixed
lane; without it the activation routes to the universal lane and fails closed.
The `iroha_core` test module `smartcontracts::isi::retail_daily_limit::finality_tests`
executes this path on the certified test chain: a real lane block with an
exact-quorum lane certificate, the global merge, contiguous portable
verification from the signed genesis, an activation marker equal to the one
native execution stored, and the same entry anchor from the node's certified
read. Substituted coordinates, entries and carriers are refused.

The portable proof embeds the complete executed block wire, so the verifier
needs no separate block read. `GET /v1/ledger/block/{height}` requires a
canonical signed read and `CanReadAllLedgerData`, but the `/v1/bridge/finality`
proof, bundle and attestation routes currently serve the same complete wire,
including merged restricted-dataspace entries, without that grant.
TODO(retail-finality-disclosure): reconcile the finality routes with the
ledger privacy boundary (enforce the full-ledger grant or serve a reviewed
selective carrier) before BPNG Core relies on them for restricted activation
blocks.

This is evidence of the historical activation event at that height. It does
not authenticate a later read of the `retail_day_policy_v1` and
`retail_day_activation_v1` state-map entries. `ContractStateMapV1` has a
Core-local cold-capture path, but Core does not maintain and publish its
accumulated root in a finalized consensus field, and Torii has no corresponding
value-inclusion proof route. The certified execution result `R` commits the
complete World state only as a homomorphic multiset root without per-entry
membership proofs, and a block's own writes through its ordinary-write root
(`specs/sumeragi.md` Appendix E, E51); neither authenticates a later value of
that accumulated map. The existing ledger `state_proof` route returns a finalized block
envelope without membership proofs for those entries. Production admission
therefore remains closed until the current-state binding or an independently
reviewed immutable-state theorem and proof chain is implemented and qualified.

The data model now shares the exact physical policy and activation key
constructors with native execution. Its
`verify_retail_policy_activation_against_supplied_root_v1` checks both canonical
values, their digest/next-day relation, exact physical keys and two Merkle map
inclusions against **one caller-supplied accumulated root**. The API names the
root as supplied because no finalized root of that map with membership proofs
is published.
Core can now cold-capture every current physical contract-state key/value from
one generation-bound `StateView`, associate that local map with the same view's
committed height and block hash, and generate only the exact retail policy and
activation inclusion proofs. The capture rechecks both values against the
independently expected policy. Its result remains private to Core and is
explicitly a **local, unauthenticated root**; there is no Torii proof route and
no restricted-dataspace disclosure on this source path.
This check cannot authorize activation from its own output, from Torii's
per-block execution-witness `post_state_root`, or from an operator-selected
root. A qualified release still needs a consensus-committed root with
membership proofs for these entries, an independently verified quorum
attestation over the exact root and current
finalized height, or the separately reviewed immutable-state proof path below.
The future selective proof route must authenticate
the exact caller and `CanReadRestrictedDataspace` for the installed physical
dataspace before returning values; the local Core capture cannot stand in for
that route or release admission.

### Immutable-state proof path

The source now checks policy and activation immutability at final World commit
preparation. `retail_daily_limit_state::validate_immutable_policy_transition`
visits the actual storage journal after deterministic DA and lifecycle writes.
Every existing policy or activation entry must retain its exact bytes; removal
and replacement fail before publication, including a self-consistent replacement
policy and activation digest. A new entry must use its canonical physical key,
match its exact counterpart, satisfy first-release policy validation, and have
both counterpart keys absent in the actual predecessor. This check observes
only touched entries and does not construct another accumulated root.

The native mutation audit supporting this invariant is scoped as follows:

| Mutation surface | Enforcement |
| --- | --- |
| `isi/retail_daily_limit.rs::ActivateRetailDailyLimitV1` | Sole native writer of policy and activation; checks owner through fresh definition registration, exact dataspace, and absence of all retained definition records; inserts the pair in one transaction. |
| `isi/asset.rs`, `isi/domain.rs`, `isi/world.rs`, `isi/multisig.rs` | Definition/domain/account removal and account rekey preflights retain policy, identities, usage and governed balances. |
| `ivm/host.rs` and `host/contract_state_namespace.rs` | All five retail roots are opaque to generic contract state reads, writes and enumeration; contract state is physically scoped. |
| `state/world_commit.rs::PreparedWorldCommit::prepare_overlay` | Rechecks immutable policy/activation bytes against the actual predecessor journal after all late World writes and before State publication. |
| `state/deserialize_world.rs` | Validates current snapshot pair shape, digest and references, plus the retained undo image used by replacement-block execution. Existing predecessor bytes must be identical and first insertion must be atomic. This validates internal consistency, without authenticating snapshot history. |

These source checks support an induction over admitted successor transitions:
given an authentic predecessor containing the finalized activation pair, every
successor running this exact qualified implementation preserves that pair.
The tests exercise fresh pairs, unchanged bytes, deletion, malformed/orphan
additions, predecessor repair, and self-consistent replacement through the
actual commit-preparation owner. They do not establish those induction premises
for Taira or for a process restart.

Focused source verification on 2026-09-25:
`cargo iroha-fast --target-slot retail-fees -- test -p iroha_core --lib retail_policy_commit_`
passed all three tests, including the coherent cap-and-digest replacement case.

### Restart and retained-lineage boundary

Snapshot admission also checks the retail policy and activation entries in the
actual `smart_contract_state` undo journal. An existing predecessor entry must
have exactly the current bytes; a new pair must have both keys absent in the
predecessor. The read-only history borrow preserves the journal for replacement
block execution. A coherent current cap-and-digest replacement, deleted pair,
or repaired half-pair therefore cannot conceal an invalid predecessor in an
otherwise well-shaped snapshot. This does not establish where the snapshot
or its internally consistent predecessor originated.

Focused source verification on 2026-09-25:
`cargo iroha-fast --target-slot retail-fees -- test -p iroha_core --lib state::retail_daily_limit_state::tests`
passed all three tests: coherent replacement/deletion rejection, atomic-birth
and exact-history preservation, and current activation-marker validation.

The existing snapshot/checkpoint machinery has these distinct guarantees:

| Source path | Guarantee and remaining dependency |
| --- | --- |
| `snapshot.rs::try_read_snapshot_bundle` | The ordinary signed-bundle path verifies the configured snapshot signing key, exact payload digest, Merkle bytes, canonical WSV hash and signed fast manifest, with exact network and snapshot binding. The local snapshot signature authenticates cache bytes under that separately trusted key, not execution of the snapshot's World. |
| `snapshot.rs::verify_snapshot_restore_preflight` | Refuses to restore any snapshot above height zero (`NativeExecutionReplayRequired`), as does the emergency Fast manifest path. Strict startup then re-executes the signed genesis and every certified Kura block and requires the World state accumulator to equal a cold capture (`specs/sumeragi.md` Appendix E, E56); emergency Fast startup cannot opt into that replay. Accelerated recovery against the certified parent World state root is `TODO(S9)` in that function. |

The execution-policy digest in
`state.rs::execution_policy_digest_with_runtime_policies_v1` binds configured
runtime policies; it does not hash retail state-map entries and is not a
membership-provable commitment to them.

Complete deterministic replay from an independently trusted origin, with the
original result-bearing activation block and every required successor body,
can reconstruct the pair and check admitted execution commitments. Strict
restart performs that replay from the signed genesis over the node's own
certified Kura blocks, so a restarted node holds the pair only through
re-executed certified history. That is local evidence: retained header and
hash lineage alone cannot upgrade the historical activation receipt to an
independently authenticated current policy for a remote reader. An immutable
proof path must additionally authenticate the exact current pair and the
qualified implementation's continuity over the activation-to-checkpoint
interval; a local World root, local signing key or caller-supplied expectation
does not establish those premises by itself.

TODO: qualify the invariant against the exact immutable node release and bind a
fresh finalized checkpoint to the verified activation's chain. Admission must
authenticate release/runtime continuity over that interval; it cannot infer it
from a finality certificate or from local snapshot custody. The current
historical activation result stays historical and the local map root stays
unauthenticated until that complete proof path is reviewed, implemented and
independently admitted. No Core readiness gate opens here.

The new first-release wire IDs are
`iroha.asset.retail_day.activate.v1`,
`iroha.asset.retail_day.identity.bind.v1`, and
`iroha.asset.retail_day.monetary_movement.v1`. A source-matched qualified SDK
or native owner CLI must encode and submit these before provisioning. Current
application SDKs and admin helpers are not assumed to support them.

## Earlier account-scoped native control

`SetAssetTransferControl` installs a DAY cap for one `(AccountId,
AssetDefinitionId)` pair. The executing asset path adds each outbound transfer
to that account's UTC calendar-day usage and rejects an over-cap transfer.
Atomic batch transfers aggregate repeated sources before this check. The
native record is held in reserved account metadata, and
`POST /v1/controls/asset-transfer/query` can return its limit, usage, and a
block checkpoint. Only the asset-definition owner or a delegate holding
`CanSetAssetTransferDailyLimit` for the exact asset, active account-alias
domain, and dataspace can set the cap. Existing tests cover exact-cap success,
over-cap rejection, unchanged usage after rejection, and batch aggregation.

This control is **opt-in per account**. An account without a record has no DAY
limit, and a direct Torii transaction is not required to pass through BPNG
Core. A signed application environment value or Core counter therefore cannot
establish a universal retail limit. The native limit also counts an account,
not the application `actor_id` used by the previous Core counter. The chain
has no authenticated mapping from every possible signing key and rekey lineage
to that application actor. Native transfer-control exceptions for protocol
movements must be assessed against the approved payment policy separately.

`AssetIssuerUsagePolicyV1` offers one useful on-chain admission primitive:
`require_subject_binding: true` rejects ordinary transfers involving an
unbound source or destination. For a newly registered retail account, the
asset owner could set the account DAY cap first and add its issuer subject
binding second. That ordering prevents an unbound account from receiving or
sending this asset through the ordinary transfer path during registration.
It does not make the limit mandatory for every bound account: the asset owner
can add a binding without a cap or remove the issuer policy, and a limit setter
can clear an installed cap. The issuer policy also has no signer-wide usage
field. The source now restricts issuer-policy metadata set/removal to the asset
definition owner in both executor admission and native execution, while leaving
ordinary metadata delegation intact. This closes a delegated-policy-mutation
path, but its deployment is only a possible component of a qualified protocol,
not an activation receipt by itself.

## First-release consensus design boundary

The needed control is an asset-and-physical-dataspace policy with a positive
whole-Kina DAY cap, an issuer-authorized opaque retail identity for every
participating retail account, and a closed list of institutional source
identities and typed protocol movement exceptions. The exact cap, identity
issuer, and exception roster must come from the owner-signed BPNG policy; no
fixture value or application configuration can supply them. A new account must
not receive or debit Digital Kina until its binding is committed under that
policy. The ledger must reject removal or weakening of an active policy while
the asset has a nonzero governed balance, except through a separately specified
owner-governed transition that preserves usage and finality. An ordinary asset
metadata permission must never be able to modify this control.

Debit usage belongs in dedicated consensus state keyed by `(asset definition,
physical dataspace, retail identity, UTC day)`, rather than in account metadata
or a portal/Kasumi counter. Every admitted numeric debit, including direct Torii,
contract and batch legs, must update that state in the same state transaction as
the balance change. Multiple accounts bound to one identity spend from the same
bucket. A controller rekey or alias reassignment must either carry the exact
identity binding atomically or be rejected before moving a governed balance;
historical usage never resets. Multisig and delegated transfers debit the
source account's retail identity, not the submitting authority's account.
Unbound sources and alternate balance scopes fail closed. A typed protocol
movement may bypass the cap only if the installed owner-signed policy names
that exact source class and purpose; an arbitrary transaction cannot self-label
an exception. Mint, burn, transparent/private bridge, reserve and KAGEMUSHA
movements each need an explicit owner decision before their treatment is coded.

Consensus can prove that two accounts share a committed opaque identity. It
cannot infer that two independently issued identities belong to one human.
Retail enrollment must therefore provide an owner-authorized uniqueness
attestation and rekey lineage for the identity commitment. If an offline
KAGEMUSHA payment itself is intended to consume this daily ceiling, an
on-chain debit-only counter cannot enforce that payment at spend time; the
owner must specify the offline accounting and reconciliation rule. These are
economic and identity-authority inputs, not values a node or application can
choose from available source code.

This is a coordinated consensus change, not a new flag on the existing account
cap. The current source has these distinct mutation surfaces:

| Source path | Required first-release treatment |
| --- | --- |
| `asset.rs::PreparedNumericTransferPlan::prepare/apply` and `PreparedNumericAssetMovementBatch` | Resolve each source to the owner-attested identity, aggregate all same-identity legs before applying a batch, and persist one conditional DAY usage update with the balance transcript. Direct Torii and IVM `Transfer` share this native path. |
| `asset.rs::NumericAssetMovementAuthorization` | Replace implicit cap bypass with a closed typed-purpose decision against the owner-signed institutional exception list. A direct transaction must never request an exception by metadata. |
| `asset.rs` burn, SCCP release, privacy bridge and the future KAGEMUSHA load/unload | Specify whether each debit consumes a retail bucket or is an exact institutional exception; reject any uncovered path for a governed asset. |
| `multisig.rs::rekey_account_id` and account recovery | Preserve the same retail identity and its prior usage when the controller changes, or reject before moving the account and balances. Alias reassignment alone never establishes identity continuity. |
| Asset-definition policy mutation and state snapshot/query | Require the owner-authorized policy revision and preserve dedicated usage across policy changes, restart and signed query. Generic account-control metadata must not become a second usage ledger. |

The current `AssetIssuerUsagePolicyV1` cannot be interpreted as that identity
contract: its binding has only allowed domains and dataspaces, and
`AccountId` is derived from a single-key or multisig controller. The policy
does not carry an opaque person commitment, signed uniqueness attestation,
cap, exception roster or usage. Adding a cap field there alone would still
permit alternate-account and rekey resets. A first-release implementation
must introduce the complete policy/permission instruction, consensus usage
state and movement/rekey transitions together, with Norito roundtrip and
four-peer restart tests. There is no safe partially enabled decoder or
account-metadata fallback for the missing pieces.

## Registration and activation boundary

The current MiBank registration plan commits `Register<Account>` before it
binds the account's `mibank.bpng` alias. A scoped daily-limit delegate needs a
strictly active alias, so it cannot add `SetAssetTransferControl` to that first
registration transaction with its existing permission. The asset-definition
owner could atomically register and cap an account, but that is a different
authority and still would not constrain direct Torii transfers from other
uncapped accounts that acquire Digital Kina.

A release gate may advertise a positive retail daily ceiling only after an
owner-approved, signed on-chain policy supplies all of these properties:

1. The policy binds the exact Digital Kina asset definition, BPNG physical
   dataspace, retail identity scope, approved whole-Kina cap, and exact
   institutional exceptions. No matching retail debit may use an uncapped
   account, alternate balance route, other account controlled by the same
   applicable signer, or uncapped native/contract/batch path.
2. The policy states how single-key, multisig, alias rotation/rekey, account
   replacement, and approved KAGEMUSHA/protocol movements contribute to the
   same daily total. It must define the signer or retail identity from
   consensus-verifiable state, not a mutable application claim.
3. A current qualified Iroha release enforces that policy in its shared
   movement path. Positive and negative tests cover direct client-signed
   Torii transactions, new uncapped accounts, same-signer alternate accounts,
   batch and contract calls, UTC day rollover, cap change, and every permitted
   exception. There is no decoder, shim, or old counter fallback.
4. The BPNG signed runtime and provisioning receipt identify the exact policy
   revision and activation transaction. A signed finalized read at an exact
   block proves the installed ledger policy, cap, scope and exceptions equal
   the signed claim before `/readyz` or retail money routes open. Live
   direct-Torii rejection and exact-cap success are captured as original
   finality evidence.

The current Iroha asset-definition metadata policy controls subject domain
and dataspace bindings, not a mandatory signer-wide daily total. Extending it
only with a per-account default DAY cap would still fail item 1 if one signer
can control another account, and would not establish item 2's application
actor mapping. It would also need a complete review of institutional
exceptions and protocol movements. No safe narrow source change to the
current account control alone can satisfy this gate.
