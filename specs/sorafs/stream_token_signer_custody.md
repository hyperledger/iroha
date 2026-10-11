# SoraFS V1 stream-token signer custody contract

The stream-token role has one provider-scoped signing contract. Operators choose
software custody or an optional hardware adapter; both use the same authenticated
Ed25519 protocol. Configuration, opaque key operations and independently signed
state evidence have separate owners. Public handles and signatures alone do not
establish current authorization or deployment readiness. The protocol makes no
claim about a participant's server hardware or private-key exportability.

## Configuration and runtime ownership

The complete [public-pin template](snippets/stream_token_signer_binding.toml)
contains the required table hierarchy. Its placeholders and zero generations or
intervals are deliberately invalid: replace every reviewed public pin before
admission. Key bytes and environment enablement are never configuration. Explicit
native custody tables name owner-only runtime credential paths; external adapters
retain their credentials and any optional device sessions or PINs. Public configuration identifies the authorized key
and its scope without prescribing the operator's key-storage implementation.

- `sorafs.storage.stream_tokens.enabled` defaults to false. Disabled issuance
  rejects configured signer pins and injected signer, observer or approved
  anchor dependencies. Enabled issuance also requires storage, its nonzero
  `provider_id_hex`, operator-signature authentication and native governed gateway
  admission.
- `admission_native` is required whenever issuance is enabled and forbidden when
  disabled. It names independent direct Ed25519 `operator`, `observer` and
  `reputation_recorder` accounts with distinct absolute owner-only credential paths
  (`operator_credential`, `observer_credential`, `reputation_recorder_credential`),
  an explicit valid Norito `fee_payment_json` for operator/observer actions, and explicit
  `clock_uncertainty_ms` within 0–5,000. The daemon authenticates the configured
  gateway policy and current permissions from its own finalized State; injected
  or broker-provided gateway admission adapters are rejected. These account and
  credential references are separate from the signer custody configuration below.
- Native reputation delivery signs only the complete payload retained by the original
  governed admission intent. The source-time recorder policy fixes its fee payer and
  finite lifetime. Delivery proves the original Append or another permanent terminal
  disposition before native acknowledgement; an Accepted serving attempt additionally
  requires Delivered. Recorder key rotation must retain custody and permission for
  pending originals, or governance must explicitly cancel them. Recovery never changes
  their payloads. This callback is independent of general reputation publication and PoR.
- `admission_reconcile_interval_ms` defaults to 1,000 and accepts 1–60,000. It
  schedules bounded native callback recovery without enabling unrelated services. Each background
  tick completes native finality, policy, permission and pending-prefix preparation. An empty
  prefix leaves that tick unsigned and reports only an idle scheduling outcome, never an
  authenticated empty result or readiness. Pending work still requires its original signed Check
  and complete delivery/acknowledgement proofs; startup qualification and reconciliation always
  perform their signed Checks. No empty result is cached between ticks or across restart.
- `admission_operation_timeout_ms` defaults to 30,000 and accepts 1–60,000. One
  absolute monotonic deadline begins before the admission worker queue and covers
  native transactions, callbacks, acknowledgements and final serving confirmation.
  A later phase cannot renew it; token and lease expiry remain independent limits.
- `signer` is all-or-nothing: runtime/key handles, signer service/administrator,
  strong Ed25519 key, key/policy revisions and policy digest, plus independently
  configured `attester` and `observer` tables. All six service/administrator
  identities and all three public keys must be distinct. Signer `key_revision`
  is the sole generation and must fit `1..=u32::MAX`; the token's
  `token_pk_version` is its checked conversion, not another configuration value.
- Provider identity comes from storage; chain and genesis-derived network identity
  come from the enclosing authenticated node context. They are not response-selected
  or duplicated inside `signer`. Handles are credential-free identifiers;
  `software`, `signer`, `hsm`, `kms` and `pkcs11` schemes use the same binding
  checks. A provider label is never authorization. Observer routing is independent
  and permits software implementations under the same public trust checks.
- Custody lifetime and anchor-age limits are positive and at most 86,400,000 ms.
  Observer age/lifetime is positive and at most 300,000 ms. Eligibility intervals
  have exclusive ends and are evaluated against a caller-owned clock at runtime.

`iroha_config::parameters::{user,actual}` own configuration. Torii's
`StreamTokenSignerPinsV1::from_config` derives the full immutable configuration
digest and canonical Manifest binding. `ToriiRuntimeDeps` receives
`with_sorafs_stream_token_signer_client`,
`with_sorafs_stream_token_state_observer` and
`with_sorafs_stream_token_approved_anchor`. The approved full custody anchor is an
independent deployment input bound to that complete digest; neither client may
bootstrap it from its own response. Registry slot 11 carries the one capability
and its two separately injected transports.

## Native custody authority

`MutateSorafsStreamTokenCustody` owns the provider's governed public signer binding,
independent attester trust, enrollment sequence and predecessor, active signed
enrollment digest, and terminal signer/attester revocation flags. Its dedicated
provider-scoped `CanManageSorafsStreamTokenCustody` permission governs configuration,
enrollment and revocation. Expected revision and digest bind each atomic mutation;
immutable history retains the executing height, deterministic ordinal and authority.
This history excludes token bodies, signatures, reservations and the operation
journal. Those remain with their existing durable owners.

The action uses one tagged JSON form, `{"action":"revoke","value":{"signer":true,
"attester":false}}`, and a typed revocation payload carrying both flags. Configure
and enroll carry their exact Manifest-owned frames; the native DTO does not
redefine those signed payloads.
The shared `signer::custody_control::SignerCustodyPolicyV1` and
`SignerCustodyControlStateV1` own the common binding, attester trust and enrollment
shape. StreamToken native admission and historical readers additionally require
role 11 and the exact provider purpose; a valid deployment-approval policy cannot
enter this provider-scoped authority.

Enrollment verifies the complete canonical signer attestation against the
previous committed control snapshot and that block's actual identity and time.
A policy change in the current block cannot be presented as already committed
under its predecessor's block hash. Genuine policy changes clear the active head
and require enrollment; the enrollment sequence and predecessor never reset.
Revocation cannot be cleared by relabelling a retired key or changing policy within
the same key generation. Same-key renewal uses a new attested enrollment.

Each provider has a total limit of 8,194 control-history records. Ordinary changes
may consume the first 8,192; the last two records are reserved for monotonic
revocation. Earlier revocations count against the same total. History is not pruned
to admit more changes. This bound limits lifetime control changes and must be
considered during deployment planning.

Core's `read_stream_token_custody_control_at_v1` reads the exact provider control
snapshot at a requested committed height from one `StateReadOnly` view. It checks
the canonical binding, chain and genesis-derived network, bounded history/index
coherence, and derives the custody anchor from native state and the same view's
block identity. Torii requires this anchor to match the signed observer claim and
compares the complete active head, both revocation flags, and independently pinned
attester trust. The independent approved anchor remains a required deployment input.
Neither observer signatures nor a nonzero state digest substitute for this native
association.

The SDK's `get_stream_token_custody_state` reads the bounded native
`/v1/sorafs/providers/{provider_id}/custody/{height}` projection before provider
admission or advertisement exists. Its independently selected owner, complete
signer binding, qualified World schema and certified Global decision authenticate
one exact native record, or absence of both the current head and first revision.
An HTTP error never means unconfigured custody. The authenticated native instance
must match the selected network and chain under the existing Global-root derivation;
a valid private-root certificate cannot satisfy this read. The publisher borrows
original pre-tail World values and uses one finite source/decode allowance for
signed genesis plus the current execution-anchored certificate, without walking
the full genesis prefix. Finality freshness belongs to the caller. This public
record supports wallet Configure/Enroll preparation and grants no enrollment or
current-use eligibility. Provider discovery reuses the same custody projection
checks while retaining its separate admission and signed-advert requirements.

Historical control records remain readable when a provider is removed from the
current registry. They do not confer current serving authority. Torii separately
requires the pinned provider to remain registered in the same State view used for
each capture and validation; native mutations and exact retries also require
current provider registration and permission.

## One-body issuance and recovery

The Manifest owner authenticates independent signer attestation and signed,
challenge-bound current/completed observations. Torii retains its exact prepared
body, original custody and authenticated-operator quota across the operation.

1. Startup requires a fresh `CurrentCustody` observation with phase `Startup`.
   It contains no invented token or completed row and grants no signing or serving
   authority. If unrelated committed work advances the local tip while the signed
   reply is in flight, Torii certifies that newer tip in the same fresh State view
   and requires identical complete custody control and revision digest. The signed
   candidate remains the observed anchor; the original floor, minimum and historical
   anchors still apply. Changed custody, missing certificates or a removed provider
   refuse startup. All live operation and admission phases retain the exact-tip rule.
2. Each issuance has a separate fresh `BeforeProvider` observation. The service
   derives the same operation from its own pinned provider binding and exact
   canonical body before reading state or calling the signer.
3. Torii makes one `Sign`. An ambiguous result permits at most one read-only
   recovery of that same operation, with no new reservation, commit or signing.
   Consumed issuance quota is not refunded. The echoed HTTP nonce does not create
   idempotency across separate HTTP requests.
4. The bounded receipt contains exactly four ordered signatures for role payload,
   audit record, provenance and response. Fresh `AfterCommit` and then separate
   `BeforeRelease` observations authenticate the original custody and exact durable
   completion. Each phase also prepares a fresh native `Check`, asks the separately
   configured observer to sign and submit that exact instruction, then consumes
   successful execution and the original Reserve/Complete history against one
   State/Kura/QC view. The resulting completion must equal the private receipt and
   signed observation, including its original journal digest and terminal block.
   Startup or pre-sign evidence cannot replace either observation.
5. Before publication, Torii checks approved, current and historical signing custody
   anchors against the native control reader and Kura's certified frames
   using one immutable Core State view. Completion keeps its separate finalized
   operation-block identity; it is not interpreted as custody control state. Larger
   heights alone prove no ancestry. Torii resamples time after finality reads and
  rejects expiry, rollback, revocation or custody drift.

`query::stream_token_authority::observation` owns the native Check capability.
Its challenge is generated before signing and its monotonic deadline never
renews. The consumer checks current provider ownership, separate Check/Operate
permissions, custody revision and phase at both endpoints of the caller's UTC
uncertainty interval. Decoded transaction or row claims cannot construct this
capability. The broker's Check operation only transports the exact bounded signed
transaction; Torii independently verifies its finalized execution.

The signer client and broker return only bounded untrusted receipt bytes.
`SignerStreamTokenServiceV1` owns durable production and read-only recovery over
`SignerOperationCoordinatorV1` and the StreamToken-purpose `SignerReceiptJournalV1`.
Private files, exclusive reservation/CAS, staged receipt checks and pre/post-I/O
state fencing precede release; the transport never creates a verified authority.
The coordinator rejects a generic role-11 Sign reservation. Its stream-token
entry point checks the exact canonical body against the borrowed domain-prefixed
signing bytes and passes a sealed body, time-window and request-digest review to
the source's purpose-specific Reserve. The source must independently rederive
that review and perform the finalized CAS. The daemon native source performs
this CAS through the actual signed transaction queue and authenticates the resulting
Reserve, Complete and independent phase-specific Checks against its State and
durable Kura finality. It compares each mutation to its original signed transaction
hash, so a competing identical request cannot borrow another operation's success.

The token signature covers `sorafs.stream-token.signature.v1\0` followed by the
canonical body frame. The token transport is canonical padded base64 over one
canonical Norito V1 frame, capped at 2048 decoded bytes and 4096 header bytes.
Same-value alternate layouts and compression are rejected; finite decoder limits
also intersect any stricter caller budget.

## Native software runtime construction

The optional `sorafs.storage.stream_tokens.signer.native` configuration selects the
local State-backed runtime. It requires absolute owner-only `signer_credential`,
`operator_credential`, `observer_credential`, `custody_record` and `receipt_journal`
paths, the current governed provider `operator`, an explicit canonical
`fee_payment_json`, and bounded `timeout_ms` (default 30,000; 100–60,000). The three
software key identities are distinct. The attester remains independently trusted;
its private key is not a daemon input. The custody file is signed material that
must match current finalized native state, never an alternative authority.

The common signer `clock_uncertainty_ms` setting (default 250; maximum 5,000)
bounds both UTC endpoints for native and external runtimes. Each native transaction
has one monotonic deadline beginning before signing; ambiguous submission or
finality failure never generates a replacement mutation. Recovery reads the
original immutable operation and performs fresh Check observations.

Daemon startup assembles the selected runtime after State and queue construction
and rejects conflicting injected signer dependencies. Startup current-custody
observation reads actual finalized State without waiting for a new block. Once
serving, signing and completed observations submit the native phase-specific
transactions and require their finalized execution. Explicit external broker
adapters remain a separate configuration choice under the same consumer protocol;
failed native construction cannot select one automatically.
Emergency Fast recovery disables storage and skips native credential loading and custody
construction on every platform, matching the other storage runtime dependencies.

Source-adjacent fixtures exercise the production constructor, signed software
custody, queue submission, native executor outcomes and durable three-of-four QCs.
The daemon issuer test calls `StreamTokenIssuer::from_config` and the real issue path,
checks its native Current/BeforeProvider/AfterCommit/BeforeRelease transactions and
exactly one Reserve/Complete, then verifies the returned canonical CID token's transport,
signature and policy fields. A subsequently finalized revocation denies existing-token
custody admission and a new issuance. These are source assertions pending the coordinated
test run. Public gateway serving additionally requires the configured deployment-owned
admission quota/sequencer and committed reputation callback; this fixture supplies neither
and cannot establish their cross-replica behavior.
These fixture assertions require focused test execution; they do not establish
live consensus, ordinary fee settlement or a four-process deployment qualification.

## Current custody before serving admission

Every new CAR-range or chunk admission authenticates a separately challenged
`CurrentCustody` observation with the current-only `BeforeAdmission` phase. Static
canonical token, signature, key generation, provider, manifest, profile and initial
issue/expiry checks precede observer I/O. The driver authenticates current custody
and repeats local finalized-history checks, then resamples its monotonic trusted
time and checks token issue/expiry again before any accepted quota transaction.
The exact final millisecond becomes the accepted quota and reputation-callback
timestamp; that qualification is never cached for another request.

Revoked, stale, unavailable or substituted authority evidence fails closed with
HTTP `503`. The typed `Excluded(SignerAuthorityUnavailable)` callback retains the
decoded body digest and key generation without counting a provider observation or
violation or obtaining an accepted quota lease. Its failure timestamp is the initial
request observation, since a failed or rolled-back clock cannot establish a trusted
final admission time. If the durable audit provider also fails, no terminal outcome
is fabricated. An already-expired token is rejected before observer I/O; expiry while
waiting on observer/finality work is an infrastructure exclusion.

This is a logical cutoff for new admissions using freshly authenticated evidence
and the node's known finalized history. It neither proves globally latest custody
state nor cancels packets from a previously admitted stream. Same-key custody
renewal does not revoke existing token signatures. Governed revocation must be
terminal for the revoked key generation; reactivation with the same key/version
would otherwise revive earlier tokens. Native control transitions enforce terminal
generation revocation, and every current observation must agree with that state.

## Cutover and qualification

Generate a replacement key with the configured provider, obtain independent
attestation and governed activation, and atomically update the reviewed signer
pins, approved full custody anchor and authenticated provider inventory. A
provider descriptor pins one key; switch its `gateway-key` and token together.
An in-flight operation cannot be retried or relabelled under renewed custody.
Finalize the old custody's terminal audit/revocation transition before revocation
takes effect; no post-revocation signing or silent multi-key fallback is allowed.
Retain public fingerprints, generations, policy/record/completion digests and
approval evidence, never credentials or key material.

TODO: complete coherent native caller/broker/producer validation and qualify the
configured signer provider, attester, current finalized-state observer and
authoritative durable operation source. Validate the native custody transitions and
Torii reader together against durable certified history and four voting
validators. The present source contracts and signed simulations do not complete
those qualification outcomes.


Custody enrollment may reference an earlier committed approval block while unrelated
blocks finalize. The reducer reconstructs the exact native custody at that block and
requires it to equal the current control digest and state; an intervening custody
mutation or revocation rejects the enrollment. Consensus execution uses replicated
committed lineage. Independent attesters and runtime consumers authenticate their
observations against exact durable State/Kura/QC evidence. Public canonical request
and control-record digest helpers derive material only and grant no execution authority.
