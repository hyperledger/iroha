# KAGEMUSHA — final implementation draft

Status: **canonical implementation target, revision 2026-10-05**. This revision
applies the owner answers of 2026-10-05: the hash families, `credit_id` and
`proof_digest` (§§3, 4.1, 5.1), the state core and head commitment (§3), the
credit-digest tree (§3), receiver matching and credential continuity (§§3.2,
5.1, 5.2), verifying-key selection (§3.2) and proof caps (§8). It also applies
the second set of owner answers of 2026-10-05: Poseidon signing messages (§§3,
8), depth-32 indexed map trees and the further Poseidon digests (§3), and the
blacklist entry order and two-sided blacklist enforcement (§§1.1, 3.2, 5, 7).
It amends the 2026-10-04 revision, which adopted the owner-approved split-lineage
architecture: a step proof on the payment path and a local background lineage
fold (§§1.1, 3). That revision replaced the 2026-10-03 revision, which replaced
revision 6 and its decision menu.
Implement and integrate this design for the
POC and production. The [verification checklist](kagemusha_evidence_gate.md) records
results; it does not authorize, prohibit or delay use or deployment.

This is a specification, not a claim that the implementation is complete.
The [source inventory](kagemusha_single_design_evidence.md) records what exists
and what changes. This document takes precedence over older KAGEMUSHA monetary
and phone-provider designs. Existing lower-level specifications describe their
current implementations until their contracts are replaced in the same patches.

## 1. Decisions and requirements

There is one protocol: a proof-carrying offline wallet, hardware-backed signing
keys, and a durable software state provider running in the released app on a
stock, uncompromised phone. The user explicitly selected this trust model for
the POC. Phones must run the vendor OS without rooting, jailbreak or a rootkit;
bootloaders must remain locked where the platform exposes that condition.
The same protocol is the production integration target. A stronger hardware
state provider may be researched later; it is not a prerequisite or a second
payment protocol.

There is no per-payment issuer call, Reserve/Commit service approval, deferred
settlement, signature-only payment alternative, or release sign-off gate.
The local lineage fold (§3.1) is not deferred settlement. It runs on the
holder's phone, needs no network, counterparty, issuer or ledger, and cannot
change ownership or reverse a commit, except by the §3.2 burn branch (P4).
Signatures, proof validity, replay protection and durable state commits are
ordinary runtime requirements. A failed check rejects that operation; a missing
implementation returns an explicit error rather than reporting a payment complete.

### 1.1 Required behavior

| ID | Requirement | Design rule |
|---|---|---|
| R1 | Offline payments | After enrollment and loading, peers need only each other (§5). |
| R2 | Mainstream phones | Stock Android/vendor equivalents and iPhone, hardware-backed keys, no custom applet (§2). Actual platform evidence and measurements are recorded separately. Activation, loading and receiving require a device class whose published lineage budget is met (§5.3). |
| R3 | Load from the ledger | A finalized reserve debit creates one wallet-bound load voucher (§6). |
| R4 | Final device-to-device value, unbounded hops | Send irreversibly transfers value to the bound receiver. Receive makes it immediately and durably owned by the receiver, subject only to the P4 burn exception (§3.2). The value becomes onward-spendable offline once the receiver's local lineage fold reaches its current head, which covers the crediting head; the fold needs no network, counterparty or approval. Only exact Payment replay can finish delivery; no refund or hop ceiling (§§3–5). |
| R5 | Optional return online | Unload is the holder's choice, available from any folded head (§3.1). Remaining offline has no deadline unless an enabled regulatory control supplies one (§§6–7). |
| R6 | Account blacklist | With the control enabled, a payment does not take place if the payer's own committed list contains the receiver or the receiver's own committed list contains the payer. Lists are best effort and may differ between phones (§7). |
| R7 | Optional daily/monthly limits | Disabled by default; enforced through signed quotas and persistent counters when enabled (§7). |
| R8 | Optional attestation expiry | Disabled by default; an enabled lease can require renewal before future sending (§7). |
| R9 | Compact payment | Canonical binary Payment is at most 10,000 bytes, independent of history (§8). |
| R10 | Stock OS in the proof | Every transition's issuer-signed credential, recording the platform evidence verified at enrollment or the last renewal, is verified natively by every party that consumes the package, and in-circuit by the lineage proof covering that transition. The step proof binds the credential digest (§§2.2, 3.2). Android: hardware key, locked bootloader, verified vendor boot, patch levels and app signing identity, as the attestation records them. iPhone: an App Attest key of this app on genuine Apple hardware, bound to the payment key; no boot, patch or jailbreak field exists. This proves recorded evidence, not live absence of compromise. |

For a payment from A to B, the following define completion:

- **P1a:** At completion, B durably owns the value, subject only to the P4
  exception.
- **P1b:** Once B's local lineage fold reaches B's current head, which covers
  the crediting head, B can spend the value onward offline or unload it. The
  fold needs no network, counterparty or approval.
- **P2:** A cannot spend the same value again under the stated trust assumptions.
- **P3:** B needs no later reconciliation, approval or settlement.
- **P4:** Later discovery of misconduct by A cannot invalidate B's accepted value.
  Sole exception (§3.2 containment): an incoming Payment that passed every
  native check at Receive but fails in-circuit verification in B's lineage
  proof is burned. Its `credit_id` stays consumed, its amount leaves B's
  spendable balance through the lineage's `burned_total` counter (§3.2), and
  B's other value is unaffected. Under §2.1 this arises only from a verifier
  defect or an outside-model payer.
- **P5:** Only explicitly enabled regulatory controls require an otherwise
  functioning offline wallet to reconnect.
- **PC:** Before completion is shown, all native verification, the receiver's
  step proof, the durable commit, recovery data and fold witnesses (§4.1) are
  finished. The only later work is the deterministic local lineage proof
  required by P1b. It needs no external input and cannot change ownership
  except by the P4 burn branch.

A committed Send permanently removes `amount + fee` from the payer. There is
no refund, cancellation, timeout reversal or retargeting after that commit.
The payer can only present the exact same Payment bytes again to the bound
receiver. Delivery evidence never authorizes restoring the payer's balance.

The receiving wallet reports **complete** (P1a) only after its own step proof,
state, commit receipt, recovery data and fold witnesses (§4.1) are durable.
Until its current head is folded, the completed credit is labelled
**spendable after local proof**, with the fold backlog. A wallet's next Send,
Unload or device move, including after its own previous Send, waits until its
current head is folded; the UI shows this as the fold backlog. At Send commit
the payer reports **sent — irreversible, delivery unconfirmed**; valid
`Credited` evidence changes that to **delivered**, or to **delivered, burned**
when it reports the P4 burn. This distinction reports delivery, not provisional
value. A lost receipt changes neither party's monetary rights.

Defaults, for the POC and production, are: blacklist enforcement off, spending
limits off, attestation
expiry off and transfer fees zero. An operator can enable the defined controls
through signed scheme policy. Enabling these controls needs no additional design
decision.

### 1.2 Scope of durability

Normal restart, process death, interrupted I/O, power loss and supported app/OS
updates preserve the committed state and its private recovery data. Restoring
older app files must never restore spending authority. Temporary locked or
unavailable storage means **retry**, never wallet deletion or a zero balance.

A phone is the custody device. Destruction of its key or all current private
recovery data is permanent custody loss; a commitment cannot recreate missing
bytes. Factory reset, destructive uninstall/clear-data paths and loss of the
phone are not balance recovery mechanisms. Do not restore an older checkpoint,
automatically mint compensation, or promise survival of deliberate erasure.
Show destructive custody consequences before wallet-controlled reset actions.

## 2. Trust, enrollment and keys

### 2.1 Explicit assumptions

The safety argument assumes: correct released wallet code; a stock vendor OS
that enforces app isolation, key access and the storage contract in §4; a
hardware-backed non-exportable signing key; sound cryptography; correctly
operating issuer keys and ledger consensus; and retention of the custody data
in §1.2. An ordinary user may interrupt operations, restore app backups, change
the wall clock or replay messages. Those actions must not create another spend.
A compromised OS or modified wallet executable is outside this selected model.

The lineage proof (Ω, §3) establishes conserved, authorized lineage. It cannot establish the
absence of a rootkit, or discover another valid fork by itself. The state
provider prevents forks under the assumptions above. Insurance or later fraud
detection is not part of that argument.

### 2.2 Enrollment

Enrollment is online once per wallet incarnation. Bind a fresh issuer challenge
to the canonical domainless `AccountId`, network, scheme, asset incarnation,
wallet key, app identity and enrollment policy. A new incarnation always begins
at zero; reenrollment never imports an old balance or resets its replay state.

The issuer verifies platform evidence and issues a compact signed credential:

`(scheme, asset_incarnation, wallet_id, account_id, payment_key,
provider_contract, platform_evidence_kind, evidence_digest, app_policy,
regulatory_policy,
enrollment_id)`.

`wallet_id` binds the public key and unique incarnation. `provider_contract`
names the §4 Advance contract and receipt format of the scheme. It is fixed for
the scheme's lifetime, so app and adapter updates never require reenrollment.
The credential conveys exactly the evidence verified, including its time and
platform limitations. Its issuer signature and policy binding are consumed by
the lineage relation and verified natively by every consumer. Raw attestation chains stay in enrollment records, outside
peer messages.

- **Android and compatible vendor APIs:** validate the attestation chain
  to a pinned Google root or adapter-named vendor root, with no certificate on
  the attestation revocation status list at the time of the check (a leaked key
  passes until Google lists it; the list is not instantaneous), and the
  challenge, hardware security level, generated key properties, expected app
  signing identity, locked device, verified vendor boot and enrollment patch
  policy. Reject software keys, unlocked/custom boot evidence and identity
  mismatches. Keep TEE and StrongBox evidence distinct. These fields describe
  the attested event, not a live runtime examination of every payment.
  See the [AOSP attestation contract](https://source.android.com/docs/security/features/keystore/attestation).
- **iPhone:** create the payment key in the Secure Enclave. Verify App Attest
  and bind its fresh assertion transcript to that payment public key and the
  enrollment challenge. Reject when App Attest is unsupported, the attestation
  does not chain to Apple's App Attestation root, the App ID differs, the
  environment is development for a production scheme, or the nonce, key
  identifier or counter does not match. The binding authenticates the app's
  supplied key; it is not independent Apple attestation of that separate key or
  a measurement proving the running OS has no exploit. Stock iOS and correct
  local key creation remain assumptions. See [Apple's validation
  API](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server).
- **Other vendor ecosystems:** use an adapter with an explicit equivalent
  evidence contract. A brand name is not an attestation format. Do not invent
  Android fields for a platform that lacks them or silently enroll a software
  key. Such adapter work can proceed alongside the POC.

Play Integrity, where used, is an enrollment-time signal recorded in
`evidence_digest`. Delete the periodic Play Integrity refresh lease and its
Guard slot; periodic renewal exists only as the optional §7 attestation lease.
Local root/jailbreak checks supplement these checks; they are not a proof that
compromise is absent. A positive local check rejects enrollment. After
enrollment, run the checks before issuing each Request and before Send; a
positive result rejects that operation and says why. It never deletes state,
changes the balance or alters committed payments. Preserve custody, delivery
bytes and recovery access; a detected compromise is outside the security
assumption, not authority to reverse a Send.

Renewal, where the attestation lease is enabled, is not a repeat of enrollment:
platforms attest a key only when it is generated. A renewal carries three
things. (1) Possession: the payment key signs the issuer's fresh renewal
challenge. (2) Fresh platform evidence where the platform offers it: on
Android, a newly generated attested key whose attestation challenge is the
renewal challenge, whose public key the payment key also signs, and whose
attestation records the current boot state and patch levels; on iPhone, an App
Attest assertion by the enrolled App Attest key over the challenge (an App
Attest key cannot be attested twice, and nothing about the OS is attested).
(3) The enrollment evidence, identified as historical facts about the payment
key's generation. The issuer applies the scheme's current enrollment policy to
the fresh evidence and records in the renewed credential which facts are fresh
and which are historical. Without expiry enabled, enrollment does not create a
periodic reattestation or app-store-update requirement. Normal vendor OS updates
retain the custody contract; record regressions and repair them, without
silently redefining old completed payments as provisional.

### 2.3 Key roles and user authentication

Separate the scheme root, enrollment signer, finalized-load authorization,
regulatory-policy signer and artifact signer by role and domain. Ledger finality
must authenticate every load; an enrollment or artifact signature cannot mint.
A wallet key signs provider receipts, Request quotes, peer session
and ledger-control authentication, and the §2.2 renewal challenge and
renewal-key binding, each under its own signing domain (§3). These signatures
confer only the authority of their named operation. All verifiers enforce the role,
scheme and network.

PIN/biometric authorization is local UX, verified by the phone's secure
hardware: Send and Unload confirmation uses the platform's hardware-backed user
authentication (Android BiometricPrompt with strong biometric or device
credential; iPhone LocalAuthentication backed by the Secure Enclave). Do not
bind the payment key itself to user authentication: on Android removing the
screen lock invalidates such keys, which would destroy the balance. If a
confirmation key bound to user authentication is used, it is a separate key
that can be regenerated without affecting custody. Never use an app-only PIN
screen. Keep payment
identity stable across biometric enrollment changes. Do not select a key policy
that silently destroys money when a fingerprint changes. Where a storage class
requires a device passcode, explain that removing the passcode may destroy its
custody material; test that lifecycle on each adapter. Apple's storage classes
have distinct [backup and passcode behavior](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web).

## 3. One state, step and lineage relations

The existing Rust state and recursive-proof owners remain canonical (§9).
Swift and Kotlin own platform I/O, not independent balance algorithms.
All amounts are checked `u128` integer asset units; zero-value Send is rejected.
Sequences are checked `u128`, never wrapping or resetting within an incarnation.

**Notation.** σ is a *step proof*: the proof of one transition's step relation,
proved before Advance on the payment path. Λ is the *lineage relation*, and
also its proof for a head: the recursive proof, made after Advance in the
background, that the head extends a valid lineage from the zero state. Ω is
Λ's proof in single-parity transport form (§3.2), the form that peers and the
ledger verify. τ is the provider's commit receipt (§4.1). A subscript names the
operation tag: σ_send is the step relation or proof of a Send, and Λ_recv is
the part of Λ that covers a Receive step. Ω(h) covers head `h`; Ω(pred) is Ω of
a package's predecessor head. A head is **folded** once its Ω is durable and
self-verified (§3.1 step 5). *Fold witnesses* are the inputs that Λ needs for
steps no Ω covers yet (§4.1). To *decide* an Ω is to run the PIPA-v1
accumulator acceptance check `decide` ([PIPA-v1 §11](plonk_ipa_v1.md)) on the
accumulator that Ω carries. Its *deferred values* are the cross-field
values that the wrap leaves for its consumer to constrain (PIPA-v1 §12 S6, §13).
`send_chain` and `recv_chain` are running hash chains over the descriptors of
sent and received credits (`credit_id`, counterparty wallet and amount; for a
send also its ordinal, fee and Request digest). Neither contains a Payment
digest.

**Hash families.** `H` is the role-separated SHA-256 hash of the [wallet wire
record](kagemusha_wallet_wire_v1.md). `P(d, x)` is the RP57 Poseidon
`iroha_pasta::poseidon::hash_with_domain` with domain word `d` over the Pasta
field Fp, the Vesta scalar field in which σ is proved; its value is one
canonical Fp element. `P_bytes(d, b)` is `P` over the byte length of `b`
followed by `b` split into 31-byte little-endian chunks, the last one
zero-filled. Two hash families apply:

- **Poseidon.** `P` for every value a step relation computes or opens:
  `credit_id` (§5.1), the state commitment and rest digest, the chains, σ's
  public-input encoding of its statement, and the roots, leaves and openings of
  every wallet map, of the blacklist and quota-window trees (§7) and of the
  credit-digest tree. `P_bytes` for the large-input digests: `proof_digest` in
  both its domains (§4.1), the Payment digest, the lineage digest over Ω, the
  credit-opening, credit-status and credited digests (§5.1), and every signed
  message (below).
- **SHA-256.** `H` only for small fixed bodies that no relation recomputes over
  a large input, and at ledger, HTTP, platform-attestation and artifact
  boundaries: the identities (scheme, relation, asset scope, wallet, enrollment,
  account), the object digest of each signed object over its signed message and
  signature, the statement, package, operation and nullifier digests, the
  enrollment and renewal challenges given to platform attestation, the
  evidence, certificate-set and verifying-key-set digests, and local custody
  records. The wire record lists each one and why it stays SHA-256.

**Signatures.** Every P-256 signature in the protocol (hardware receipts τ,
issuer credentials, certificates, Requests and every other signed wallet,
policy, ledger or artifact body) signs, as its message, the 32-byte canonical
encoding of `P_bytes(d, body)` under that body's own signing domain `d`, with
standard ECDSA over SHA-256: the Secure Enclave
`kSecKeyAlgorithmECDSASignatureMessageX962SHA256` and Android KeyMint
`DIGEST_SHA256` (`SHA256withECDSA`) over those 32 bytes, never a no-digest mode.
Native verifiers compute the Poseidon digest, then verify ECDSA normally;
in-circuit each signature costs one SHA-256 block over the 32-byte message.
Platform attestation statements (KeyMint attestation chains, App Attest
attestations and assertions) keep their platform formats.

A SHA-256 value enters a `P` preimage as two 128-bit limbs, a `P` value as one
element. Native code, the data model included, computes `P` values with
`iroha_pasta`; the packing rule, every `P` domain and every element list are
pinned with shared native and in-circuit vectors (§3.2).

Each `wallet_id` is enrolled for one scheme and asset incarnation (§2.2) and
owns one private state:

```text
lifecycle: Active | Retiring
scheme_id, asset_digest, wallet_id, credential digest
balance, burned_total
sequence, next_send, next_load, next_redeem
send_chain, recv_chain
consumed_credit_root
pending_outgoing_root, load/redeem recovery root, fee-claim recovery root
regulatory_policy, enabled_controls, quota share/windows, quota_usage_root,
blacklist version/root/issue time, lease expiry, accepted time/epoch information
state nonce, state commitment
```

The state commitment (the head commitment) is one canonical Fp value with two
levels: `P(core ‖ P(rest))`, under distinct core and rest domains. The core
holds every field that a step proof reads, changes or carries:
lifecycle, `scheme_id`, `asset_digest`, `wallet_id`, credential digest,
balance, burned_total, sequence, next_send, next_load, next_redeem, send_chain,
recv_chain; the consumed-credit, pending-outgoing, load/redeem-recovery,
fee-claim-recovery and quota-usage roots; the enabled-controls mask, quota
share/windows root, blacklist version, root and issue time, the regulatory
policy's maximum blacklist age, lease expiry, policy epoch and accepted-time
floor; and the state nonce. Load and redeem recovery share one map and root,
keyed by `(kind, ordinal)`. The rest digest commits the remaining fields
(including the rest of the regulatory policy body and the time anchor). No σ
opens the rest digest; Λ opens it. A σ constrains a map root
only where an enabled control reads or updates it (§7). It carries the other
successor roots as witnesses. Advance requires each of them to equal the root
recomputed from the authenticated store (§4.2), and Λ constrains every root
transition. Every natively maintained map or store is authenticated against
the root committed in the selected head, except where §3.2 substitutes a
lineage-adjusted root.

Authenticated local maps hold the openings and retained objects behind their
roots. The root is not a backup of the map. The consumed-credit map permanently
binds each received `credit_id` to `(amount, receive sequence)`. That leaf, the
`recv_chain` append and every root of a Receive are computable from the Request
and the predecessor head, so no state commitment contains a Payment digest.
The full canonical Payment digest is bound by the Receive receipt (§4.1). Λ_recv
inserts `credit_id → (Payment digest, burned flag)` into the lineage-level
*credit-digest root*, which Ω exposes and CreditStatus opens (§§3.2, 5.1); that
root is not part of the state commitment.

Every wallet map (consumed-credit, pending-outgoing, load/redeem recovery keyed
by `(kind, ordinal)`, fee-claim recovery, quota-usage) and the credit-digest
tree is a depth-32 Poseidon indexed Merkle tree. Its leaves `(key, value,
next_key)` are sorted and linked by key from a zero sentinel leaf, which alone
forms the empty tree. Membership opens the key's leaf by its path;
non-membership opens the low leaf whose `key` and `next_key` bracket the absent
key; insertion updates the low leaf's `next_key` and writes the new leaf at the
next free index. Every opening carries exactly 32 siblings. The wire record
fixes the leaf, node and value encodings, their domains, the empty tree, the
removal step that ArchiveSent uses and the opening layout. The wallet retains
each credit's Payment digest with its Receive record. The consumed-credit map is
never pruned or reset within an incarnation. There is no exclusive
receive slot; multiple incoming and committed outgoing payments are allowed.
An absent recipient must not freeze all other spending. The same key cannot
pay itself; different wallets of the same account can transfer value and
remain subject to their quotas.

Map leaves contain stable credit/operation identifiers and effect descriptors,
not the current proof, receipt or complete output package. Exact output bytes
live in an authenticated auxiliary archive. This keeps the successor state
commitment independent of the proof and receipt that will certify it.

### 3.1 State packages

A public package is `(statement, σ, τ)`, plus Ω(pred) when its operation
consumes it. The statement binds scheme, the scheme's relation identity (§3.2),
wallet credential digest, asset, operation, sequence, predecessor and successor state
commitments, and the operation's public effect. Sensitive openings and private
history are witnesses. `τ` is the provider's durable commit receipt bound to the
exact statement and proof digest.

The operation tag fixes the package shape and the receipt's `proof_digest`
domain (§4.1):

- **Send, Unload and Retiring** commit only from a folded head. Their σ
  consumes Ω(pred) (§3.2), their package carries it, and τ uses the Ω‖σ
  domain. Only these packages serve as a Payment, an Unload claim, a fee claim
  or a retirement closure.
- **Bootstrap, Load, Receive, ArchiveSent and RefreshPolicy** may commit from
  an unfolded head. Their package carries no Ω, and τ uses the σ-only domain.
  The ledger verifies a Bootstrap package for activation (§3.2), and a payer
  verifies a Receive package as Credited evidence (§5.1).
- **CreditStatus** is a read-only proof about a folded head `h`, not a
  transition package: `{statement(h), proof_digest(h), τ(h), Ω(h), membership
  opening}` (§5.1).

To make a transition:

1. Natively verify every input package and object (an incoming Payment,
   Credited evidence, a load voucher, a policy update). For Send, Unload and
   Retiring the predecessor must be folded. The wallet uses the Ω recorded as
   self-verified at fold time (step 5) and does not re-verify it on the payment
   path.
2. Construct the next state, prove its step relation to produce `σ_next`, and
   natively verify `σ_next`.
3. Call `Advance(expected_head, new_head, proof_digest, operation_id,
   recovery_capsule)` (`proof_digest`: §4.1) and obtain `τ_next` (§4). The
   provider natively verifies `τ_next` before it persists the completion
   record (§4.2 step 4).
4. Release the new complete package only after durable completion.
5. In the background, prove Λ over the steps no Ω covers yet, in order, wrap
   it as Ω (§3.2), natively verify Ω including the decide, and record it
   durably. One Λ may cover a contiguous run of steps where the artifact set has
   a relation for that run length. It verifies each step's σ and τ, and only
   the last head of the run receives Ω and becomes folded. Each head has at most
   one recorded Ω. Every Lineage message, Payment and ledger package from that
   head carries those exact bytes.

A head whose Ω is durable and self-verified is **folded**. Verifiers reject a
Send, Unload or Retiring package, and a fee claim, that lacks Ω(pred).

The current receipt is verified natively whenever a package is consumed. The
lineage proof covering that step verifies the same receipt inside the recursive
relation.
Every incoming package is also fully verified, including its receipt. Thus an
ancestor's authorization cannot disappear inside a later proof. A proof alone
is not a transferable credit. This ordering avoids requiring the current proof
to contain a signature over its own digest.

### 3.2 Transition relations

The lineage relation Λ retains the semantics of the paired-Pasta recursive
construction and its P-256 gadgets on the Iroha-native PLONK/IPA stack
([PIPA-v1](plonk_ipa_v1.md)), keeping Pasta IPA recursion; replace obsolete
online Guard bindings. Ω is Λ in single-parity transport form: one PIPA-v1
proof on a single Pasta curve, Pallas (Ep), whose transport wrap carries Λ's
cross-field checks as deferred values (PIPA-v1 §12 S6, §13); §8 bounds its
size. Step relations are single-parity on Vesta (Eq) and non-recursive. They
use only checked integer arithmetic and Poseidon, with each permutation in a
native lane that an equality bus binds to the main circuit. Each operation tag
has its own step relation.
Pin all hash domains, curve encodings, transcript parameters and verifier
material in one authenticated artifact set. Native and in-circuit encodings
must have shared vectors. No server receives wallet private state or acts as
its monetary prover; proving runs in the native wallet core. Enrollment
evidence verification is an issuer task.

Every transition enforces the following. The tag says where and when each
check runs.

- *[σ, before Advance]:* checked balance arithmetic against
  `balance − burned_total`, where `burned_total` is Ω(pred)'s when σ consumes
  Ω(pred); positive amounts; one-time ordinals; one sequence advance;
  lifecycle; the scheme, asset, `wallet_id` and credential-digest binding and
  their continuity; Request/credit identity, with the Request's receiver
  matched by `wallet_id`, not by credential digest; counterparty and exact
  amount/fee binding; distinct payer and receiver wallets; the policy epoch and
  accepted-time window; the enabled-controls mask; the chain append.
- *[σ_send, before Advance, only while the control is enabled]:* nonmembership
  of the Request's receiver account digest in the payer's committed blacklist
  and the maximum blacklist age; the touched quota windows and usage update;
  lease expiry and time-window arithmetic, all against head-committed roots and
  fields (§7).
- *[σ_recv, before Advance, only while the receiver's blacklist control is
  enabled]:* nonmembership of the Request's payer account digest in the
  receiver's committed blacklist, against the head-committed root (§7).
- *[native, inside the serialized Advance section]:* consumed-credit
  nonmembership and insertion, and every root update, against stores
  authenticated by the expected head, with each successor root equal to the one
  in σ's successor commitment (§4.2).
- *[Λ, after Advance, in the background; required before Send, Unload or
  Retiring commits from that head (§3.1)]:*
  - credential, scope, relation identity, operation tag and provider contract
    (R10);
  - the predecessor Ω and receipt, or the unique zero-state enrollment base
    case;
  - this step's σ and τ, and every input package's Ω, σ and τ;
  - every signature it owns: the Request and receiver credential only in
    Λ_recv; load vouchers in Λ_load; certificates, credentials, and policy,
    list, time and credential updates in the step that consumes them;
  - the Request's account digests against the credential each belongs to:
    Λ_send checks the payer account digest against the payer's own
    credential, and Λ_recv checks the receiver account digest against the
    receiver credential it verifies; each counterparty's digest is bound only
    through `credit_id`;
  - credential continuity: a renewal's replacement credential, and the
    receiver credential of a Request that Λ_recv verifies, bind the wallet's
    `wallet_id` and `payment_key`, so a Request quoted before a renewal stays
    receivable after it (§5.1);
  - exact map membership and nonmembership updates and every root transition,
    unchanged unrelated fields (opening the rest digest) and exact operation
    effects from §§5–7;
  - fee terms, against the fee-schedule digest that the payer's own
    head-committed policy permits (Λ_send verifies no receiver-supplied
    signature), and quota/time transitions;
  - receipt bindings to the statement, proof digest, operation identifier,
    sequence and predecessor/successor, and for Receive the Payment digest;
  - the lineage-adjusted values (below).

Λ_send binds only the payer's own lineage. A receiver verifies the payer's
Ω(pred), σ_send and τ_send, never the payer's Λ_send. A Send permanently
consumes its gross sending quota. Delivery, replay and outbox cleanup cannot
increase the payer's balance or restore that quota. No substituted app approval
or arbitrary hardware signature satisfies the receipt interface.

Ω publicly exposes: the head commitment; `wallet_id`, credential digest and
`payment_key`; scheme and relation identity; the policy facts (lifecycle,
policy epoch and enabled-controls mask); and the lineage-adjusted
`burned_total`, pending-outgoing root and credit-digest root. Every consumer of
a package carrying Ω(pred), natively and in Λ, checks before mutation:

- `σ.predecessor = Ω.head` and `statement.credential_digest = Ω.credential`;
- τ verifies under `Ω.payment_key`;
- σ's `burned_total` and pending-outgoing inputs equal Ω's;
- for a Payment: the Request's payer wallet equals `Ω.wallet_id`; its send
  ordinal is the one σ_send consumes; and the Payment's carried credential
  digest and `payment_key` equal Ω's.

A mismatch is rejected before mutation. Statements and Ω carry one
scheme-level relation identity, not one per relation. Each consumer selects σ's
verifying key from the verifying-key allowlist by operation tag, for Send also
by `Ω.enabled_controls`, and for Receive also by the blacklist bit of the
statement's enabled-controls mask; Λ uses the same allowlist. G1 defines the
allowlist, with one entry per selector; its digest is the
`verifying_key_set_digest` that the relation identity binds. The statements of
σ_send and σ_recv bind the enabled-controls mask, and their relations check
that mask against the core; a σ_send or σ_recv whose relation omits a check
for an enabled control that it enforces is rejected. Every Λ
that consumes an Ω constrains every deferred value of that Ω. Native verifiers
decide every incoming Ω before they accept or fold it.

**Lineage-adjusted values.** Λ cannot change a committed head, but a burn or an
ArchiveSent no-op changes values that the head already fixed. Λ therefore
carries its own `burned_total`, pending-outgoing root and credit-digest root,
and Ω exposes them. At step `h`, Λ adds the amounts burned at `h` to
`burned_total`; it applies the step's descriptor insertion, or its archive
removal unless the no-op branch is taken, to the pending-outgoing root; and it
inserts the step's credits into the credit-digest root. A σ that consumes
Ω(pred) (Send, Unload and Retiring) takes `burned_total` and the pending-outgoing
root from Ω(pred) as public inputs. Its successor core carries that
`burned_total` and the pending-outgoing root derived from that input root, which
resynchronizes the core. A σ proved from an unfolded head (Load, Receive,
ArchiveSent, RefreshPolicy) carries the core values forward; none of these
operations releases value. The native pending-outgoing store authenticates
against Ω(pred)'s root for an operation that consumes Ω(pred), and against the
core root otherwise.

Post-commit failure is contained:

- Λ_recv has a deterministic burn branch. It is taken when the in-circuit check
  of an incoming Payment that passed native checks evaluates false: its Ω
  including deferred values, σ_send, τ_send, the Request, the consumer checks
  above, or `credit_id` nonmembership in the predecessor's consumed-credit root
  (on a duplicate, the committed leaf update is accepted as is). On that branch
  the `credit_id` stays consumed and its amount is added to Λ's `burned_total`.
  The credit-digest root records the credit with its burned flag, unless that
  `credit_id` is already recorded there. No accumulator or deferred value of
  the burned Payment enters Ω. Only that Payment is burned.
- Λ_archive has a no-op branch, taken when the in-circuit check of the Credited
  evidence evaluates false. Λ's pending-outgoing root keeps the descriptor, and
  there is no balance effect. The wallet keeps that descriptor and its Payment
  bytes. It can archive the descriptor again after a later Send, Unload or
  Retiring writes it back into the core.
- Λ_send contains no check on counterparty-only data that can fail after
  commit. The Request signature and receiver credential are checked natively
  before Advance, and in-circuit only in the receiver's own Λ_recv. Fee terms
  are checked against the payer's own policy.
- Load vouchers, certificates, fee schedules, credentials, and policy, list,
  time and credential updates have no failure branch. The issuer and ledger
  roles of §2.3 sign them. A peer can relay them but cannot forge or re-encode
  them (§8), so only a verifier defect can make them fail in-circuit. The next
  two rules target that defect.
- Native and in-circuit verifiers accept exactly the same set for every object
  that Λ verifies after a native check: Ω including its deferred values, σ, τ,
  the Request, Credited evidence, load vouchers, fee schedules, certificates,
  credentials, and policy, list, time and credential updates.
- Every signature that Λ verifies uses a P-256 gadget that is complete for every
  input the native verifier accepts.

The zero-state proof binds its unique enrolled incarnation, zero balance and
`burned_total`, empty maps and chains, and zero ordinals. The provider installs
this base state once, by
Advance from an enrollment marker made durable with the payment key before the
credential request. From then until custody is deleted, the key is always
covered by one durable current marker, or by a terminal marker once the
incarnation's custody is deliberately deleted or its unused enrollment abandoned.
Older generations are retired as §4.2 says; coverage is continuous, not
preservation of every generation. A key or
credential without its uninstalled enrollment marker is a used incarnation and
is never initialized again.
The ledger enables load issuance only after verifying and recording the complete
Bootstrap package for that incarnation. A credential alone cannot receive a
load voucher. This activation is idempotent and occurs during enrollment.
An interrupted enrollment resumes the same installation; it never creates two
initialized heads. Abandonment is allowed only while the enrollment marker is
still selected and Bootstrap has never committed. It commits a terminal marker
and records its receipt in a ledger instruction that atomically rejects prior
activation and permanently disables activation and loads. No voucher or monetary
balance exists to return. Once Bootstrap commits, including an uncertain
activation response, recover that incarnation and use §6.3; do not abandon funded
obligations. Releasing an unused quota allocation requires that terminal evidence
and does not erase historical quota usage.

### 3.3 Stable offline verification

Freeze the step relations, the lineage relation, the transport wrap, their
verifying-key allowlist (§3.2) and their verification interface for the
lifetime of a scheme. Existing offline wallets verify future payments in that
scheme using the same material. Implementation optimizations preserve that
interface and semantics. A breaking relation is a different scheme. Moving value to it uses a voluntary
unload and new load; there is no cross-scheme offline decoder or conversion.
Existing wallets can keep their original scheme without reconnecting.

Certificates for planned signing-key rotation are signed directly by the
existing scheme root and travel within authenticated packages or peer policy
data. Delegation depth is fixed, independent of rotation count. Historical
loads remain valid. New issuance can stop after issuer compromise; old completed
value is not retroactively tainted. An emergency online reconnection rule is
not implied by key rotation: it exists only if a previously enabled regulatory
control authorizes it. No unavailable online revocation lookup is hidden in
native or in-circuit verification.

## 4. Durable state provider

### 4.1 Contract

`Advance` is a local operation, serialized per wallet. It either leaves the
old head usable without releasing a new receipt, or durably selects the exact
new head and retains everything needed to finish and return its package.
Only one successor of a given head may be released. Competing precomputed
proofs do not debit value; only the winning commit can become a package.

The signed receipt binds the scheme, wallet, provider-contract identity,
sequence, operation ID, old/new commitments, statement digest, proof digest
and recovery capsule digest. The operation tag fixes the `proof_digest` domain
(§3.1). For Send, Unload and Retiring,
`proof_digest = P_bytes(proof domain, LE32 len(Ω) ‖ Ω ‖ LE32 len(σ) ‖ σ)` over
Ω(pred) and σ. Bootstrap, Load, Receive, ArchiveSent and RefreshPolicy use
`P_bytes` under a distinct σ-only domain over `LE32 len(σ) ‖ σ`. Either value is
one canonical Fp element (§3). A Receive receipt also binds the full canonical
Payment digest (§5.1). σ_recv's statement and successor commitment never
contain that digest or any value derived from it (§3), so σ_recv can be
precomputed at Request signing. Λ_recv constrains the receipt's Payment digest
in-circuit against the Payment it verifies and inserts it into the credit-digest
root (§3.2). τ is never signed over a declined or unconfirmed speculative σ
(§5.1). Before first release, persist the assembled canonical output,
including its proof and receipt, in redundant authenticated local completion
records.
Retries return those exact bytes; they never create a new Payment, proof or
receipt for a released result. If every copy of released Payment bytes is lost,
report delivery-data loss; neither a regenerated package nor a restored payer
balance is recovery. Reusing an operation ID with changed inputs fails
only after the ID has a selected head; a discarded staging attempt frees it.
A crash after head selection but before signing finishes resumes that same
operation offline.
When a write error leaves the outcome unknown, report the operation pending
until reconciliation. Show a resumed operation's released result, and show an
operation whose staging was discarded as not performed.

Freeze the private recovery capsule body before signing: actual next state
openings, proof, required map nodes, retained input bytes, output descriptors
and operation recovery data. The receipt signs this immutable body's digest.
Append the receipt and assembled output bytes in a separate durable completion
record excluded from that digest. Neither the body nor a monetary map leaf
contains its own final receipt/package. Persist both records before returning;
a hash or a key-store marker alone is insufficient for onward spending.

Until a durable Ω covers a step, the capsule and completion records of that
step retain every input that Λ verifies for it: σ, τ, every consumed input (the
incoming Payment with the payer's Ω, σ and τ; the Request; Credited evidence
and the matching Payment; the load voucher; policy, list, time and credential
updates with their certificates and fee schedules) and the map openings. These
fold witnesses are outside backup sets and marker-bound. A missing witness is
custody loss under §1.2, shown as such, never a silent wait.

### 4.2 Stock-phone adapter

Implement the contract with the released native core, a durable journal, a
non-backup platform marker and the credential's hardware-backed `payment_key`,
the wallet key that alone signs receipts. The OS is trusted
to enforce storage and key access. A reusable hardware key does not itself
implement compare-and-swap or make the marker safe against a compromised OS.

The adapter performs this recoverable sequence:

1. On startup and before every operation, reconcile all marker generations and
   journal records. Finish any interrupted commit and retirement of **all**
   older markers before permitting another receipt. Do not infer absence from
   a read error or locked storage.
2. Return the retained result for an operation ID that already has a selected
   head. Otherwise:
   - check the expected head;
   - authenticate every native store the operation uses (consumed-credit,
     pending-outgoing, load/redeem and fee-claim recovery, quota-usage,
     blacklist) against the roots committed in that head, or for the
     pending-outgoing store of Send, Unload and Retiring against Ω(pred)'s
     root (§3.2), and stop on any mismatch;
   - for Receive, check consumed-credit nonmembership and stage the insertion
     inside this serialized section, including when σ_recv was re-proved
     because the head changed;
   - recompute each successor root from the authenticated store and the staged
     update, and require it to equal the root in σ's successor commitment;
     otherwise discard the staging;
   - reserve the storage of §5.3.

   Persist the complete staged capsule with authenticated links to the
   predecessor and operation ID. Flush its data and directory metadata using
   the platform's durability contract.
3. Install the new marker, binding that capsule and its predecessor. Make it
   durable before retiring old markers. On restart, a complete successor marker
   selects that successor; a staging record without its marker, complete or
   not, selects nothing and is discarded before any other operation; the head
   bound by the current marker stays selected. Never select an arbitrary older
   valid-looking marker.
   A payment key or journal found with no marker at all is lost custody: never
   install a base state or select a journal head under it. Enrollment writes
   its first marker before requesting the credential, and a new incarnation
   generates a new key.
4. Durably retire older markers, finish the selected operation and sign its
   receipt. Natively verify the receipt under the credential's `payment_key`;
   discard a failing signature and sign again, so that no receipt is released
   before it verifies. Retain the exact released package. Only then return or
   display/send it.

A complete marker with missing or mismatched capsule means unavailable custody
data: recover its authenticated local copy or stop the operation. Never fall
back to the old balance. No backup, restore or
device-transfer path may carry keys or markers. Restored app files are compared
with the surviving current marker. Store redundant local
recovery copies for interrupted writes; do not claim they survive total erasure.
Keep current capsules, completion records and these copies outside backup and
device-transfer sets, where an app-data restore cannot replace them. Native
authenticated stores are custody data too: keep them, with redundant local
copies, outside backup and device-transfer sets. A store that fails
authentication is rebuilt from those copies or from retained capsules;
otherwise the wallet reports custody loss. If a
platform restore still removes them, that is custody loss under §1.2 and the
wallet shows it as such; it never waits silently for missing bytes.

Android and Apple storage adapters must implement these semantics with their
actual APIs and record durability assumptions. This document does not assert
that a successful API return has already demonstrated power-loss durability.
That is implementation and verification work, not an administrative prerequisite
to use or integration. A failed durable commit cannot truthfully return success.

## 5. Offline exchange and recovery

### 5.1 Messages

Every message binds the scheme, asset, wallet identities and canonical format.
`credit_id = P(kgwcrdt1, Request body)` is one canonical Fp value (§3). The
*Request body* is the canonical signed Request fields as 28 elements in
request-body order, with their dependencies (receiver credential, fee schedule,
certificates) bound by digest.
Request fields bind both wallet IDs, the payer's and the receiver's account
digests (each the `account_digest` of that party's credential), payer send
ordinal `s`, receiver credential,
amount, signed fee schedule and exact fee, regulatory policy references, the
receiver's authenticated accepted time (§7) and a fresh 256-bit nonce. The
receiver signs these fields in the Request domain. No free-form field changes
the monetary interpretation.

| Step | Message and state effect |
|---|---|
| Offer | Payer advertises its next `s`, amount and supported scheme, and carries its `CredentialV1` (at most 1,024 bytes); its payment key signs the Offer. It is an authenticated session hint, with no debit or credit authority. The receiver verifies the credential natively and authenticates the Offer with it. A delivery retry also opens with an Offer, so the receiver always holds the payer's credential. After the Offer, the payer may send a Lineage message (§8) carrying Ω of its folded head. The receiver verifies it only after an authenticated Offer, rate-limits it, and checks Ω's `wallet_id`, credential digest and `payment_key` against the Offer's credential. |
| Request | Receiver signs a nonmonetary setup quote containing the exact fields above, with the payer account digest taken from the Offer's credential. With its blacklist control enabled, it issues no Request when its committed list contains that account (§7). It creates no state transition, receiver ordinal or reserved receive slot. The payer verifies its signature and the receiver credential natively before proving Send (below). |
| Payment | From a folded head, the payer verifies the Request and the applicable Send policy and checks `s == next_send`. The Request's payer account digest must be the payer credential's and its receiver account digest the Request receiver credential's; with the payer's blacklist control enabled, its committed list must not contain the receiver's account (§7). It may prove σ_send *speculatively*, after verifying the Request and before the payer confirms; a declined speculative σ_send is discarded and never signed. It natively verifies σ_send and uses the Ω(pred) recorded as self-verified at fold time (§3.1), which is not re-verified on the payment path. It then permanently subtracts `amount + fee`, increments `next_send`, appends to `send_chain` and inserts the credit descriptor in its pending outbox. It commits and retains the full canonical Payment before first release. Payment contains the signed Request body, the payer's `payment_key` and credential digest (both equal to Ω(pred)'s), and the Send package {statement, Ω(pred), σ_send, τ_send}. The receiver's credential, fee schedule and certificates are bound by digest in the Request body, which the receiver holds. |
| Receive | On a device class whose published lineage budget is met (§5.3), the receiver natively verifies before mutation: the payer credential from the session's Offer, whose digest equals Payment's credential digest, σ_send's statement and `Ω(pred).credential`; Ω(pred), including the decide; the §3.2 consumer checks; σ_send and τ_send; its own bound identity, matched by the Request's receiver `wallet_id` and the `payment_key` of the Request's receiver credential, never by credential-digest equality, so that credential may be an earlier one of this incarnation; the Request it signed, whose payer account digest equals the Offer credential's; and, with its blacklist control enabled, that its committed list does not contain that payer account, which σ_recv also proves (§7). If Payment's Ω(pred) is byte-identical to a Lineage Ω that the receiver already verified in this session, that verification is reused; otherwise it verifies Ω(pred) in full. It proves σ_recv (precomputed at Request signing, re-proved if its head changed), whose statement and successor commitment exclude the Payment digest (§3), and adds exactly `amount`. In the serialized Advance (§4.2) it checks nonmembership and inserts `credit_id → (amount, receive sequence)` into the permanent consumed-credit map; the Receive receipt also binds the full canonical Payment digest. Show complete only after durable completion. Λ_recv later proves the incoming objects, the map update and the receipt's Payment digest in-circuit and records the digest in the credit-digest root, or takes the burn branch (§3.2). |
| Credited | Optional delivery evidence, in one of two forms. (i) The receiver's Receive package {statement, σ_recv, τ_recv}, whose receipt binds the exact Payment digest; its status is *credited, unfolded*. (ii) A read-only `CreditStatus` against a folded receiver head `h` that covers the credit: {statement(h), proof_digest(h), τ(h), Ω(h), 32-sibling membership opening of `credit_id → (Payment digest, burned flag)` in Ω(h)'s credit-digest root}, with no σ and no Ω(pred); its status is *credited* or *burned*. Credited advances no state. The receiver need not retain it. A payer keeps Credited evidence it consumed as a fold witness until its ArchiveSent step is folded (§4.1). |
| ArchiveSent | Payer verifies matching Credited evidence (credited or burned) and proves removal of the matching pending outgoing descriptor. It may delete the delivered Payment bytes only after a durable Ω covers the ArchiveSent step on its archive branch (§3.2), and never the copies a fee claim still needs (§6.2). Balance, quotas and consumed-credit entries stay unchanged. |

A Request has no cancellation or expiry that can invalidate an already
committed Payment. Its validity for Send is scoped to the payer's still-unused
`s`; consuming that ordinal prevents another Send under the same quote.
Quote creation authenticates setup, not receiver spending authority. The payer
verifies the Request signature and receiver credential natively before proving
Send.
σ_send binds the quote's exact fields. The receiver re-verifies its own quote
natively at Receive, and its Λ_recv verifies the signature and credential
in-circuit.

The Receive receipt and CreditStatus bind the digest of the **entire canonical
Payment**, including its proofs and provider receipt. This Payment digest is
`P_bytes`, under its own domain, of the Payment transcript ([wire
record](kagemusha_wallet_wire_v1.md)), which binds every part of the canonical
Payment and binds Ω(pred) and σ_send through `proof_digest`. Conflicting bytes
for a consumed credit are rejected. A proof of absence or a generic signed
acknowledgement is not evidence of credit. A CreditStatus verifier decides
Ω(h), checks τ(h) under `Ω(h).payment_key` over the carried statement and
`proof_digest`, checks that the statement's successor is `Ω(h).head` and that
`Ω(h).wallet_id` and `Ω(h).payment_key` equal the Request's receiver wallet and
the `payment_key` of the Request's receiver credential (credential digests are
not compared), and checks the opening. CreditStatus therefore cannot invent an accepted credit. Its
budget is the 10,000-byte Credited bound (§8). It carries no σ, so it is
expected to be smaller than Payment. ArchiveSent verifies all that evidence
natively before Advance and in-circuit in Λ_archive. If the in-circuit check
fails, Λ_archive takes the no-op branch: the descriptor stays pending (§3.2),
and there is no balance effect.
No receiver acknowledgement archive or subsequent pruning exchange is needed.
The permanent replay map permits delivery evidence to be regenerated after
unrelated sends, receives and cleanup.

### 5.2 Retry and race rules

- A Send becomes irreversible at its durable commit. Cancellation before that
  commit changes no balance. An uncertain commit is resolved from the selected
  local head and journal; a transport error never implies that Send did not occur.
- Every delivery retry presents the exact committed Payment bytes to the same
  receiver. Framing and carrier may change; the canonical transaction bytes may
  not. No new Send or proof is generated for a delivery retry.
- The first valid Receive credits once. A duplicate with identical bytes returns
  optional Credited evidence without another credit. Permanent consumed-credit
  membership prevents replay after cleanup, restart or unrelated transactions.
- A stale Offer or an unacceptable quote detected before Send can start a new
  setup without debit. After Send, a newer Request, policy, fee schedule or
  retirement state cannot cancel the recipient's existing claim. Verify the
  historical policy and fee terms proved by Send, not a new quote's terms.
- The receiver may be absent or temporarily unable to store or process Payment.
  Declining a screen or disconnecting does not produce a monetary refusal.
  Preserve the payer's outbox for later delivery. No timeout or negative reply
  permits refund, retargeting or any restoration of the debit.
- A receiver whose committed blacklist contains the payer's account does not
  accept the Payment (§7). This is not a monetary refusal: the debit stands and
  the Payment stays deliverable to that receiver, which can receive it once its
  committed list no longer contains that account.
- Receive does not depend on a still-open Request, the receiver's old head or
  the receiver credential that was current when the Request was signed. A
  Request quoted before a renewal stays receivable after it (§3.2). Delayed
  valid Payments remain receivable after other payments. Malformed,
  unauthenticated or wrong-recipient objects are rejected without mutation;
  rejection is not a value-return authorization.
- Lost Credited evidence only leaves delivery unconfirmed at the payer.
  The receiver can spend onward once its lineage fold reaches its current head,
  which covers the crediting head. Lost evidence never delays that. The receiver can later prove the
  original credit through its permanent replay map, even after spending that
  value.
- If every retained copy of a not-yet-delivered Payment is destroyed, delivery
  cannot be reconstructed from a digest. The in-flight value is stranded under
  §1.2; it is never returned to the payer. Explicit regulatory controls can
  restrict use only as §7 defines and cannot reverse Send.

### 5.3 Storage and user experience

Keep exact unresolved outgoing Payment bytes until verified Credited evidence
allows ArchiveSent and a durable Ω covers that ArchiveSent step on its archive
branch. Keep consumed-credit IDs, Payment digests, private map
openings and recovery data for the lifetime of the wallet incarnation. Do not
prune these by age, peer absence or an arbitrary history limit. Local storage
grows with received credits and unresolved operations; constant-size proofs do
not imply constant total wallet storage.

Before Send or Receive, reserve actual disk capacity for the full
commit/recovery/output path. Include replay-map growth, redundant output copies,
fee claims and eventual outbox cleanup. A Request alone promises no reserved
capacity. Temporary capacity pressure postpones Receive while the immutable
Payment remains deliverable; it does not cancel that credit. Do not strand an
already accepted balance because its ancestry is long. Derive proving workspace
bounds from the fixed relations. Publish in artifact metadata the measured
memory, storage, and background lineage time, peak memory and energy per
operation and device class, where a *device class* is a phone model and memory
tier. A class's lineage
budget is met when its published Λ peak memory and fold-witness storage for
the operation's relation fit the device's available app memory and reserved
storage. A class with no published budget does not meet it. A wallet activates,
Loads, Receives or commits RefreshPolicy only on a device class whose published
lineage budget is met; otherwise it refuses before commit, and the voucher or
Payment stays deliverable. Never rely on platform background-execution time
for multi-minute proving: folds resume whenever the app runs. Fold-witness
storage counts toward the reserved capacity. Existing measurements do not yet
provide those budgets for this design.

A receiver may apply a Request-issuance policy (minimum amount, rate limit,
maximum unfolded backlog). It may fold a contiguous run of unfolded steps in one
Λ where the artifact set has a relation for that run length (§3.1 step 5), and
may hold several incarnations ("pockets"). These policies affect only the
issuance of new quotes, never a committed Payment.

Show amount, recipient, fee and irreversibility before payer confirmation.
After Send commit show **sent — irreversible, delivery unconfirmed**, then
**delivered** if valid delivery evidence arrives (**delivered, burned** if it
reports the P4 burn). A wallet's next Send, Unload or device move, including
after its own previous Send, waits until its current head is folded; the UI
shows this as the fold backlog. Reconnecting the same phones
resumes delivery of the existing Payment; it does not create another payment.

## 6. Ledger boundary, fees and wallet replacement

### 6.1 Load and unload

After completed Bootstrap activation (§3.2), a finalized online transaction
debits the payer's ledger account into the scheme reserve and creates a unique
load voucher bound to `(wallet_id, next_load, asset, amount)`. The ledger assigns
successive ordinals per incarnation. `Load` consumes exactly the next voucher,
verifies its finalized issuance, adds its amount and increments `next_load`.
Out-of-order vouchers wait; duplicates cannot load twice. Retrieving the
original voucher after a connection failure is idempotent. Unabsorbed vouchers
remain reserve liabilities; failed delivery does not refund their issuance.
Retirement closes future loads atomically (§6.3).

`Unload` subtracts a chosen positive amount, increments `next_redeem` and creates
a ledger-directed claim with a domain-separated nullifier derived from scheme,
wallet and redemption ordinal. The ledger verifies the complete committed
package, including Ω of its predecessor and the §3.2 consumer checks, and pays
its bound account exactly once at face value. Unload is possible only from a
folded head, and its amount is bounded by `balance − burned_total` with
Ω(pred)'s `burned_total`. Retry returns
the original result. No timeout restores an uncertain redemption to the wallet.
Retain the claim until finalized payout. The remaining wallet balance continues
to work offline. Unload spends the holder's current balance; it cannot reclaim
an earlier Send.

Reserve accounting conserves the sum of spendable wallet balances
(`balance − burned_total`, with the lineage-adjusted `burned_total`), burned
credits (§3.2), unabsorbed loads, in-flight recipient credits, earned but unpaid
fees and unpaid redemption claims. Burned value stays in the reserve and cannot
be redeemed. Send moves `amount` to an in-flight recipient credit and `fee` to an
earned fee; Receive moves only that amount into the receiver's balance. Each
transition moves value between these categories; it does not create it.
Distinguish proven accounting from a monetary backstop. No first-redeemer
preference, pro-rata haircut or later payer-misconduct finding changes an
honest recipient's claim. Ledger unavailability delays a requested unload but
is not an offline settlement dependency.

### 6.2 Optional fees

Fees are zero by default. A signed immutable schedule fixes the fee calculation,
rounding rule and online beneficiary. Bind the schedule and exact fee into
Request and Send; Receive verifies those historical terms. The payer's
head-committed policy names the schedule digests it may pay under, and Λ_send
checks the fee against that policy, not against a receiver-supplied signature
(§3.2). Send permanently
debits `amount + fee`, and the fee is earned at that commit even if delivery is
delayed or never finishes. Receive gives the recipient `amount`.

The complete committed Payment authorizes one fee payout keyed by `credit_id`,
only to the fixed beneficiary. Anyone may relay it online, including before
Receive; the ledger verifies Ω(pred), σ_send, τ_send and the fee terms, with
the schedule and credentials taken from its own records by the digests the
Payment binds, and rejects duplicate claims. Later delivery evidence and
schedule changes cannot alter or cancel the entitlement. Use checked integer
arithmetic and explicit rounding.
For a nonzero fee, the payer retains a separate fee-claim object containing the
Payment until finalized payout. ArchiveSent cannot delete the last copy needed
by that claim. It does not block spending or require the holder to reconnect;
another party may relay it, or the claim remains unpaid in the reserve.

Load/unload fees are also possible under a displayed signed quote: the exact
net offline value and online charge must be separate fields. They never deduct
an undisclosed fee from a previously accepted offline balance.

### 6.3 Replacement and custody loss

Move value to another enrolled phone using an ordinary offline payment,
including full-balance transfer. This uses the same proof and message format
and requires a folded head (§3.1). A wallet that cannot complete its fold
cannot move or unload value; no online path unloads an unfolded lineage. The
§5.3 device gate keeps value from arriving on a device class that cannot fold.
Keep the old wallet's key, private state, replay map and unresolved Payment and
claim bytes. Zero spendable balance does not mean its custody data is disposable.

Retirement closes new setup and funding, while preserving existing claims:

1. Commit a proven `Retiring` transition from a folded head (§3.1). It issues
   no new Request quotes, but
   continues to Receive valid Payments under previously signed quotes, including
   Sends that commit later. It may Load vouchers already issued, Send or Unload
   remaining value and finish delivery, fee and redemption claims. The lifecycle
   never reverts to Active.
2. Submit a ledger-control instruction carrying the complete Retiring package,
   or a later complete Send or Unload package proving that lifecycle and its
   `next_load`. Each of these commits only from a folded head and carries its
   predecessor Ω (§3.1). In one transaction, the ledger
   checks that no voucher at or above that ordinal exists and permanently
   disables further loads. If a voucher exists, the instruction fails and the
   wallet loads it first. A load submitted after
   closure is refused and debits nothing. Repeating closure is idempotent;
   later activation attempts cannot reopen it.
3. Keep the retiring incarnation's receiving custody available for late
   Payments. An empty balance, empty outbox or a delivery receipt cannot prove
   the absence of unseen incoming Payments. An old signed quote cannot be
   revoked to invalidate a Payment. Normal retirement therefore does not delete
   that key, replay map or recovery data, even after known obligations finish.

The wallet can remain Retiring offline indefinitely. Deliberate permanent
custody deletion writes a terminal marker before deleting key material and
warns that late incoming Payments and any retained claims will be lost. It is
a destructive custody action under §1.2, not a lossless monetary drain or a
way to refund the payer. Unused enrollment abandonment has the separate
unactivated/no-voucher condition in §3.2.

There is no seed restore that recreates spent offline value on another phone
or automatic issuer reissue. The issuer cannot reclaim or reissue a committed
Payment on timeout or reported delivery failure. Replacement does not renew
regulatory quotas.

## 7. Explicit regulatory controls

Only the following signed controls may restrict future use. The credential
binds the scheme's permitted controls and their activation semantics. A wallet
can accept a newer authenticated scheme policy, fee schedule or certificate via
a peer; learning it does not require an online call unless an enabled rule
below explicitly requires freshness. Blacklists are downloaded only while
online, from the issuer or ledger, and are never relayed between peers.
Policies cannot retroactively undo completed credit or impose an unannounced
new connectivity control on an existing credential.

`RefreshPolicy` is a proven, locally committed transition for authenticated
policy/list updates, time reanchoring and lease renewal. It preserves wallet
identity, balance, ordinals, consumed-credit entries and pending obligations;
advances policy/list epochs
monotonically; and cannot reset consumed quota or backdate accepted time. Any
replacement credential binds the same incarnation. Verify the appropriate
policy/enrollment signer and the existing credential's permitted controls.
Obtaining a renewal online is necessary only for an enabled control that needs
it. Cached or peer-carried policy updates and downloaded lists use this same
transition; they never reanchor time (below).

| Control | Behavior when enabled | Connectivity consequence |
|---|---|---|
| Account blacklist | Each wallet enforces only its own committed list, the latest authenticated list it downloaded and committed; list versions are monotone. If the sender or the receiver is listed, the payment fails and does not take place: the payer's list must not contain the receiver's account (natively before Send and in σ_send), and the receiver's list must not contain the payer's account (natively before it issues a Request and before it accepts a Payment, and in σ_recv). A Payment that the receiver refuses after the payer's commit stays deliverable (§5.2). With no list held (version 0), no account is refused. Lists are best effort: different phones can and will hold different lists, there is no cross-device consistency requirement, and a later list never invalidates a completed payment. | None from list age alone. A separately explicit maximum-list-age rule can require refresh before Send. |
| Daily/monthly sending quotas | Debit gross `amount + fee` permanently against both configured windows at Send. Delivery and cleanup do not replenish quota. Issuer allocates wallet shares so their sum cannot exceed the account allowance in any window. | No routine sync while the signed quota and trusted time remain usable; loss of the time anchor may require renewal. |
| Attestation lease | Require renewal before a future Send after the signed expiry. Accepted balance and already committed exchanges remain owned and recoverable. | Renewal is the configured online requirement. |

While a control is enabled, σ_send enforces it against the head-committed
blacklist root, issue time and maximum list age, quota-usage root and quota
share/windows, accepted-time floor and lease fields; σ_recv enforces the
receiver's blacklist against its head-committed blacklist root. Every receiver
therefore verifies the payer's controls before completion: it selects σ_send's
verifying key by Ω(pred)'s enabled-controls mask (§3.2). The blacklist gap tree,
ordered by the integer value of each account digest's two limbs, and the quota
share's window tree are `P` trees (§3) whose roots the regulatory-policy signer
signs; the quota-usage tree is the wallet's own indexed `P` tree. Native checks
against authenticated stores also run inside the serialized Advance section (§4.2 step
2). Controls are off by default and then add nothing to σ beyond the check that
the enabled-controls mask is empty.

Blacklisting a former payer does not taint downstream value. No ancestor lookup
can become an implicit blacklist. A restriction on the current holder must be
an explicit control on that holder, never a reassignment or confiscation of the
accepted amount by the payment protocol.

Time-dependent controls use an issuer-signed time anchor and OS monotonic
elapsed time, never the editable wall clock. An anchor is created only by a
direct issuer exchange in the current boot: the wallet sends a fresh nonce
generated in this boot, the issuer's signed response covers that nonce and
its own time, and the wallet accepts it only if it arrives within a fixed
response-age bound of the request on the monotonic clock. The anchor records
the boot identity, the issuer's signed time `T`, and the monotonic readings
when the request was sent (`m_req`) and when the response arrived (`m_rcv`).
Real time at a later reading `m` in the same boot lies between
`T + (m - m_rcv)` and `T + (m - m_req)`; the width `m_rcv - m_req` is the
anchor's uncertainty and never exceeds the response-age bound. Checks are
conservative: an expiry, lease end or other deadline counts as passed once the
upper end has passed, and a window start or not-before counts as reached only
once the lower end has. A Send whose interval touches two day or month windows
is counted in every window it touches. The monotonic clock must keep running
while the device sleeps (Android `elapsedRealtime`, Apple
`mach_continuous_time`); a clock that stops in sleep is not used. Elapsed time
runs only within the anchor's boot. A signed time that arrives in any
other way (cached, in a policy update, or carried by a peer) can raise the
accepted time floor but never creates an anchor or restarts elapsed time. Use
one effective accepted time for all applicable windows and checks: at least
the prior accepted time, anchored local time and authenticated Request time. A
reboot that loses the elapsed-time basis needs reanchoring only while such a
control is enabled; until then that control refuses Send, because the accepted
time floor alone can lag real time. With controls off, no clock condition
blocks payment.

Policy renewal, reenrollment and device replacement preserve consumed allowance.
While an old wallet can still spend under its allocation, its share stays
reserved; another device cannot be issued the same share. Quotas bind explicit
windows and expiry, and unused expired shares are not retrospectively spendable.
Additional per-counterparty caps, receive-age rules and arbitrary version-based
sync requirements are outside this design.

## 8. Wire format, carriers and performance

Use one canonical Norito V1 envelope and explicit layout flags. Unknown mandatory
fields, noncanonical encodings, overflow and mismatched scheme/relation IDs are
rejected before mutation. Do not guess codecs or accept a retired format as a
fallback. Bind hashes and signatures to canonical bytes with length-delimited,
role-separated transcripts. Every protocol P-256 signature signs the 32-byte
Poseidon message of its body under the body's signing domain (§3), and uses
fixed 64-byte big-endian `r || s`, with `1 <= r < n` and `1 <= s <= floor(n/2)`
for the P-256 group order `n`. Normalize signing output before freezing the canonical
object; native and in-circuit verifiers reject high-S or alternate encodings
rather than rewriting received bytes. Raw platform attestation records remain
unchanged in enrollment evidence. The Send statement binds the exact signed
Request body, which binds the verification dependencies by digest; its receipt
binds that statement and the §4.1 `proof_digest` over Ω(pred) and σ_send. The
payer fields that Payment carries must equal Ω(pred)'s (§3.2). No
unauthenticated extension can change the canonical Payment digest while
preserving its authorization.

The [wallet wire record](kagemusha_wallet_wire_v1.md) records the G1 field
layouts, transcripts, bounds and vectors of this design. Where it marks an
item TODO(G1), this document governs.

Text transport is `kgm1:` plus unpadded base64url; text/framing expansion is
additional carrier overhead, not hidden in the binary budget.

| Object | Maximum canonical binary bytes |
|---|---:|
| Offer (with the payer's `CredentialV1`) and simple session-control frame | 2,048 |
| Request, Payment or Credited (a Receive package, or CreditStatus {statement, `proof_digest`, τ, Ω, opening} of a folded head), with required dependencies | 10,000 each |
| Lineage (Ω of the payer's folded head) | 10,000 |

Payment uses the compact §5.1 layout: the signed Request body, the payer's
`payment_key` and credential digest, and {statement, Ω(pred), σ_send, τ_send},
with Ω in single-parity transport form. The σ and Ω byte caps are the exact
proof lengths that the frozen artifact allowlist (§3.2) records. Under R9 they
satisfy `|Ω| + |σ_send| ≤ 10,000 − F_payment`, where `|Ω|` is the Ω
transport-proof length, `|σ_send|` the largest σ_send length in the allowlist,
and `F_payment` every other byte of the largest valid Payment (about 1,681
bytes, so about 8,319 bytes for both proofs; the wire record pins it). Until
the artifacts freeze, G1 enforces only the frame bound. If the measured Ω
cannot keep Payment within 10,000 bytes, any fallback layout or bound requires
a new owner decision.
The same applies if CreditStatus cannot keep Credited within 10,000 bytes, for
example a fallback in which Credited carries only the Receive package. Its
opening has exactly 32 siblings, so a CreditStatus is a fixed number of bytes
plus `|Ω|` (the wire record pins it). A Lineage message is smaller than the
Payment that carries the same Ω.

Proofs summarize lineage; do not ship a certificate or transaction chain whose
size grows with hops. Payment includes the signed Request body. σ_send binds
its exact fields; both wallets verify the signature natively, and the
receiver's Λ_recv verifies it in-circuit. Credited binds the full Payment
digest. ArchiveSent consumes that evidence locally and creates no additional
peer-message round trip.
An unknown scheme can be declined during Offer. Malformed unauthenticated
traffic is dropped. A setup error before Send carries no monetary authority;
a decode, version, policy or capacity error after Send cannot reverse the debit.
Valid committed Payments retain their recipient binding and historical terms.
Each package contains the certificates and authenticated terms its verifier
needs beyond the preinstalled scheme roots and the fixed artifact set. For a
Payment, the receiver's own credential, fee schedule and certificates are bound
by digest in the Request body, and the payer's credential and certificates
travel in the session's Offer. A missing dependency cannot trigger an
implicit online fetch during payment.

Keep NFC, supported local radio transports, QR and Petal Stream as carriers of
the same envelope. Carrier negotiation selects transport, never monetary rules.
Petal is an opaque optical carrier; its documented per-payload size must be
handled by framing/reassembly when a whole message is larger. Do not carry over
QR frame-rate arithmetic as a measured result for Swift or Petal. Each carrier
reassembles and validates a complete bounded message before monetary parsing.

The UX target is **2 seconds p95** from payer confirmation after Request to
receiver durable completion (P1a). It includes the payer's remaining step-proof
time, transfer, receiver verification, the receiver step proof and both
durable commits. Report separately, per device class: the time until the value
is ready to spend onward (fold), and tap-to-done including setup and the
confirmation dwell. Measure Offer/Request setup, cold startup and payer
receipt-confirmation latency separately. Schemes with enabled controls report
latency separately; enabled quotas are expected to miss the 2 s target (about
13–15 CPU-s for σ_send, an estimate). Record failures and slow trials as
well as successes. The 10,000-byte bound is a format requirement;
2 seconds is an optimization target. Neither is a claim about today's code.
Work on integration and optimization can proceed together; missing a latency
target does not authorize skipping proof or durability work.

## 9. Implementation ownership and retirement

Implement in the existing owners. The detailed capability inventory and deletion
checks are in [the evidence appendix](kagemusha_single_design_evidence.md).

| Owner | Work to retain and change |
|---|---|
| `crates/iroha_core_zk/src/kagemusha_v1_state/` | Single state machine, pending maps, transition validation and recovery projections. Replace old operation ordering with: native verification and step proof, then Advance, then the background lineage fold. Add the fold scheduler, witness custody, the lineage-adjusted values and credit-digest root, and the burn/no-op branches. |
| `crates/iroha_core_zk/src/kagemusha_v1_recursion/` | One artifact set on PIPA-v1 (`crates/iroha_plonk`, `iroha_plonk_gadgets`, `iroha_pasta`): step relations, the lineage relation and the transport wrap. Port the retained P-256 and recursion gadgets off vendored halo2, which remains only the `iroha_plonk_oracle` test oracle. Replace per-operation online and hardware-only authority assumptions. |
| `crates/iroha_plonk`, `crates/iroha_plonk_gadgets`, `crates/iroha_pasta` | The PIPA-v1 proof system: arithmetization, transcripts, prover, verifier, accumulation and `decide`, gadget chips, Pasta fields, curves, MSM and Poseidon ([PIPA-v1](plonk_ipa_v1.md)). |
| `crates/iroha_crypto/src/kagemusha.rs` | Retain encryption and recovery primitives; update caller contracts and domain bindings. |
| `crates/connect_norito_bridge/src/kagemusha_core_coordinator_v1/` | Opaque state/proof handles, platform dispatch and durable retry coordination. Remove per-payment service phases. |
| Swift; Kotlin `core-jvm`, `client-android`, `kagemusha-wallet-android` | Thin shared-core clients; platform evidence/key/storage adapters and carriers remain in their appropriate modules. Kotlin owns JVM behavior; preserve Java consumer assertions. |
| `iroha_data_model`, `iroha_core`, `iroha_torii`, `iroha_config` | One model and service family for enrollment, load, unload and policy; reserve/finality/replay enforcement; configuration through user → actual → defaults. |
| Formal models, fixtures and package tools | Update the selected trust boundary, messages and crash transitions; preserve useful assertions and regenerate one canonical set of vectors. |

Remove per-payment ordinary Reserve/Commit/FI-control service requirements and
its duplicate wire/API family. Remove monetary Refuse/Refund, cancellable receive
Requests, acknowledgement/pruning chains and their obsolete recovery APIs from
the target state machine, proof relations, model, codecs and SDKs. Move useful attestation, storage and equation
code first. Remove the independent signature-only suite and empty
`iroha_kagemusha_attested` / `iroha_kagemusha_issuer` stubs after migrating
actual consumers. Preserve generic Petal/NFC/QR components. Artifact
authentication is the artifact signer's signature over the frozen artifact set:
remove the review, fuzz, reproducible-build and profile-qualification evidence
of `KagemushaInternalValidationReceiptV1`, threshold release approvals and the
Production/TestnetExperiment split from `KagemushaAuthenticatedReleaseV1`, its
governance install path and the compact-key and native-profile specs. Keep every
runtime binding that receipt carries: move `native_profile_digest`, the Eq and
Ep protocol digests, the relation identities and the artifact inventory digest
into the signed artifact manifest, and keep every verifier comparison against
them. Removing sign-offs must not remove a binding a verifier checks. Retire
unused secure-element wrappers and separate monetary-provider profiles; the
local Advance interface is the one adapter boundary.

Deletion is part of implementation, with no separate owner permission step.
For each replacement, identify all callers, move retained behavior/assertions,
connect the canonical owner, remove obsolete exports/layouts/fixtures and run
the affected checks in the same change. Keep no compatibility shim, second
production engine or decoder fallback. Do not delete by filename prefix: the
ordinary modules contain useful shared capabilities as well as retired protocol.
This draft does not establish that live issued state is absent; the review
found no evidence of a funded deployment outside testnets. Old-format value
under a TestnetExperiment release is testnet value; a testnet reset is its
cutover. Before an old release is removed from a network, establish whether
funded old-format value exists there. If it does, that release's verifier
stays until its holders have unloaded or paid it into the new scheme by their
own choice; nobody is required to go online for the cutover. Keep no decoder
fallback beyond that.

## 10. Goals and execution order

These are concrete implementation goals, not permission gates. Start the POC
integration now; work streams may overlap. Mark a goal complete when its stated
result exists and record observations in the checklist. Failed experiments
produce fixes or accurately stated limitations, not a release approval ceremony.

| ID | Goal and owner | Completion result |
|---|---|---|
| G0 | Consolidate design — specs | One target, explicit stock-OS assumption, informational checklist and current migration inventory; superseded authority clearly marked. **Completed by this draft.** |
| G1 | Define canonical objects — model/core | Norito state/message/credential/receipt fields, bounded envelopes, domain-separated transcripts and cross-language vectors encode §§3–8 exactly. |
| G2 | Implement Advance — native/platform adapters | Journal, marker cleanup and retained capsule implement §4; retry, backup restore and interruption cases exercise the real platform boundaries. |
| G3 | Complete proofs — core ZK | Real step proofs for every operation (Bootstrap, Load, Send, Receive, ArchiveSent, Unload, RefreshPolicy, Retiring), Λ covering every step and Ω for every folded head, and CreditStatus against folded heads. Λ_recv verifies the signed Request; Λ verifies every ancestor receipt, irreversible debit, exact arithmetic, policy and permanent replay membership, and carries the lineage-adjusted values. Each consumer constrains every Ω deferred value. Native-versus-circuit differential and fuzz tests over each §3.2 equivalence object run in the relation owners' CI. |
| G4 | Integrate the phone exchange — bridge/Swift/Kotlin | A → B → C remains offline, including restart, interrupted delivery and exact-byte replay; Send never reverses; receiver completion has its step proof and durable commit, and onward payment (offline) and Unload succeed after the local fold. Record size, critical-path latency and fold time, RAM and energy. |
| G5 | Connect ledger and controls — node/Torii/config | Finalized load and exact-once unload/fee claims preserve reserve liabilities; optional controls default off and operate as §7 specifies. |
| G6 | Delete superseded implementations — component owners | Old payment authority, profiles, APIs, duplicate engines, stub crates and obsolete vectors removed with their consumers migrated; one packaged implementation remains. |
| G7 | Verify and maintain — component owners | Checklist records genuine proofs, device results, formal assumptions and known deviations on the candidate; repairs update code and vectors together. This work continues during use. |

Suggested first vertical slice: one asset, Android → Android, controls/fees off,
real enrollment and load, shared Rust transition/proof path, durable offline
receive, background lineage fold and onward payment. Integrate iPhone storage/keys and alternate carriers
in parallel. Stand-in payloads are useful for carrier work but cannot satisfy a
completed-payment claim. Neither the POC nor production integration introduces
a flag that bypasses monetary validation.

## 11. Verification and present implementation truth

The checklist covers conservation, competing successors, receipt substitution,
permanent replay protection, irreversible Send, exact-byte redelivery, lost
delivery evidence, crashes, storage errors, clock rollback, stale policies,
genuine multi-hop proofs and physical carriers. It also covers:

- native-vs-circuit acceptance equivalence (differential and fuzz tests over
  every §3.2 equivalence object);
- the poison-pill burn branch, including a duplicate `credit_id`, and the
  ArchiveSent no-op branch with a later re-archive;
- a σ whose `burned_total` or pending-outgoing input is the stale core value
  instead of Ω(pred)'s;
- a Request whose payer differs from Ω's wallet, and a relay-rewritten payment
  key or credential digest in Payment;
- a tampered deferred value, a mixed history, a wrong relation identity, and a
  wrong VK for the operation tag or enabled-controls mask;
- shared native and in-circuit vectors for `P`, the `P_bytes` packing
  (including empty input and 31-byte chunk boundaries) and every element list
  (§3), and a σ_send whose held blacklist exceeds the maximum list age;
- a signature over anything other than the 32-byte Poseidon message of its
  body and domain, or made in a no-digest mode, which is rejected;
- indexed-tree vectors: the empty tree, successive insertions at the next free
  index, membership, non-membership through the sentinel and an interior low
  leaf, an update and the ArchiveSent removal, and a forged low leaf or an
  occupied target slot, which is rejected;
- blacklist entries whose byte order and limb order differ; a payment refused
  because the payer's list contains the receiver or the receiver's list
  contains the payer, at Request, at Send and at Receive; two phones with
  different lists; and a payment with no list held;
- a Request quoted before the receiver's credential renewal and received after
  it, with CreditStatus matched by `wallet_id` and `payment_key`, and a
  receiver credential with another `payment_key`, which is rejected;
- a σ successor root that differs from the authenticated store, a stale native
  store against the head roots, and a receipt that fails self-verification;
- crash and restore between commit and fold, and fold-witness loss;
- duplicate delivery during a σ_recv re-prove.

Update the finite-state model to match this exchange; a model's provider
assumption is not proof that a phone API implements it. Each result identifies
its code, artifacts, devices and trust assumptions.

At this rewrite's inspected working-tree baseline, substantial state, crypto,
attestation, recursive gadget, ledger and carrier code exists. The ordinary
outgoing path still depends on Reserve/Commit and FI-control responses; complete
production State proving still has rejection paths. A Receive consumer now
exists and must be reused where applicable. There is no demonstrated complete
phone implementation of this consolidated design, or measured end-to-end
2-second proof exchange. The single-parity wrap Ω is unbuilt and unmeasured.
σ_send and σ_recv have been measured with the §3 core (3,296 bytes each), but
σ_send does not yet carry the blacklist non-membership, quota and lease checks, so
σ_send with those controls, σ_recv with the blacklist control, Ω, Payment and
CreditStatus sizes and the 2 s target remain to be measured. The Poseidon
signing messages, the indexed map trees, the further `P_bytes` digests, the
blacklist limb order and the Request account digests (revision 2026-10-05,
second set) are not yet implemented. The
source inventory identifies those exact boundaries.

No build, device experiment, live payment, deployment or implementation-code
deletion was performed for this documentation rewrite. These facts distinguish
the target from its implementation; they add no approval gate.
