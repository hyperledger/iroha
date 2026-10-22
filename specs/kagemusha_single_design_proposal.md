# KAGEMUSHA — final implementation draft

Status: **canonical implementation target, revision 2026-10-10**. This revision
applies the owner directive of 2026-10-10 that every phone whose payment key lives
in a TEE, StrongBox or Secure Enclave can pay offline: one hardware-attestation
admission rule for Android and iPhone, with a pinned root set, a named revocation
source per root and an operator denylist, and no Play Integrity, vendor user
account, GMS/HMS or store-install dependency (§2.2); closed E1 refusal
reasons (§2.4); the two abandonment forms of an unused enrollment (§3.2); and a
pre-commit runtime capacity check in place of per-device-class lineage budgets
(§§1.1, 5.3). The revision lands as one
coordinated cutover (§9.1); until then the contract that the code of the
validator baseline, Iroha `ff7ec9457c`, implements stays in force.
It amends revision 2026-10-05, which applied the owner answers of 2026-10-05:
the hash families, `credit_id` and
`proof_digest` (§§3, 4.1, 5.1), the state core and head commitment (§3), the
credit-digest tree (§3), receiver matching and credential continuity (§§3.2,
5.1, 5.2), verifying-key selection (§3.2) and proof caps (§8). It also applies
the second set of owner answers of 2026-10-05: Poseidon signing messages (§§3,
8), depth-32 indexed map trees and the further Poseidon digests (§3), and the
blacklist entry order and two-sided blacklist enforcement (§§1.1, 5, 7).
It also applies the third set of owner answers of 2026-10-05 (B1–B8): Poseidon for
every digest the lineage relation recomputes (§3); the burn branch's corrected claim
and its duplicate-credit root rule (§3.2); the fixed quota-usage array, its refresh rule
and the quota share expiry in the step proof (§§3, 7); and the Send time span bound (§7).
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
| R2 | Mainstream phones | Every stock Android phone (with or without Google services, including Huawei, Honor, Meizu, Xiaomi and Samsung) and every iPhone whose payment key is generated in its TEE, StrongBox or Secure Enclave and passes the one §2.2 admission rule; no custom applet, model list, vendor user account, GMS/HMS or store-install dependency; enrollment and issuer-side vendor-service inputs are described in §2.2. This is the design target, not a qualified claim: a vendor's own attestation root is admitted only after its adapter profile is implemented and qualified with genuine device chains (§2.2), and a phone whose attestation carries no application identity is refused for that evidence (§2.4). Actual platform evidence and measurements are recorded separately. Every operation runs a pre-commit runtime capacity check on the phone itself (§5.3). |
| R3 | Load from the ledger | A finalized reserve debit creates one wallet-bound ordinary Load receipt (§6). |
| R4 | Final device-to-device value, unbounded hops | Send irreversibly transfers value to the bound receiver. Receive makes it immediately and durably owned by the receiver, subject only to the P4 burn exception (§3.2). The value becomes onward-spendable offline once the receiver's local lineage fold reaches its current head, which covers the crediting head; the fold needs no network, counterparty or approval. Only exact Payment replay can finish delivery; no refund or hop ceiling (§§3–5). |
| R5 | Optional return online | Unload is the holder's choice, available from any folded head (§3.1). Remaining offline has no deadline unless an enabled regulatory control supplies one (§§6–7). |
| R6 | Account blacklist | Each wallet may hold one authenticated list, signed by the RegulatoryPolicy role, installed locally only when its `list_version` strictly increases and never sent to peers (owner decision 2026-10-17, blacklist local-only). While a list is held, the payer refuses to Send to a listed receiver account before the irreversible debit, and the receiver refuses to accept a Payment from a listed payer account (an open Request names no payer). Nothing about the list is committed in wallet state, proved by any σ, Λ or Ω, or carried in a Request, Payment, PayerCompanion, Credited or PolicyData. Lists are best effort and may differ between phones; no list distribution path exists (§7). |
| R7 | Optional daily/monthly limits | Disabled by default; enforced through signed quotas and persistent counters when enabled (§7). |
| R8 | Optional attestation expiry | Disabled by default; an enabled lease can require renewal before future sending (§7). |
| R9 | Compact payment | Canonical binary Payment is at most 10,034 bytes, independent of history (§8). |
| R10 | Stock OS in the proof | Every transition's issuer-signed credential, recording the platform evidence verified at enrollment or the last renewal, is verified natively by every party that consumes the package. In-circuit, the lineage proof verifies the credential and its certificate in the step that introduces the credential (Bootstrap and RefreshCredential), and Λ_recv verifies the quoted receiver credential of a Request issued before a renewal; every other step binds the credential digest and payment key by continuity from that verification (owner decision 2026-10-17, lean lineage). The step proof binds the credential digest (§§2.2, 3.2). Android: hardware key, locked bootloader, verified vendor boot, patch levels and app signing identity, as the attestation records them. iPhone: an App Attest key of this app on genuine Apple hardware, bound to the payment key; no boot, patch or jailbreak field exists. This proves recorded evidence, not live absence of compromise. Load finality has the explicit §6.1 native-verification carve-out: the released app on a stock uncompromised vendor OS verifies CommitQC and receipt inclusion before its hardware-backed payment key signs Advance; the lineage proof does not independently prove BLS finality. Other R10 credential and attestation obligations remain unchanged. |

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
when it reports the P4 burn. Native verifies that evidence read-only when it
arrives, so the status changes at once; the ArchiveSent step that consumes it
is deferred (§5.3). Receipt arrival therefore does not itself start another fold.
This distinction reports delivery, not provisional value. A lost receipt
changes neither party's monetary rights.

Defaults, for the POC and production, are: spending limits off, attestation
expiry off and transfer fees zero; a wallet holds no account blacklist until one
is installed (§7). An operator can enable the defined controls
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

The first release retains Pasta/Poseidon recursive proofs and explicitly assumes
that the concrete RP57 Fiat–Shamir instantiation preserves the argument and
accumulation security required by recursive composition. This additional
heuristic is specified in the [recursive soundness memo](kagemusha_recursion_soundness_v1.md#selected-recursive-fiatshamir-assumption);
it is not a proved consequence of the single-proof random-oracle results. The
joint privacy-composition argument and candidate acceptance tests remain
required, and unbounded lineage depth remains heuristic.

The lineage proof (Ω, §3) establishes conserved, authorized lineage. It cannot establish the
absence of a rootkit, or discover another valid fork by itself. The state
provider prevents forks under the assumptions above. Insurance or later fraud
detection is not part of that argument.

### 2.2 Enrollment

Enrollment is online once per wallet incarnation. Bind a fresh issuer challenge
to the canonical domainless `AccountId`, network, scheme, asset incarnation,
wallet key, app identity and enrollment policy. A new incarnation always begins
at zero; reenrollment never imports an old balance or resets its replay state.

Native keeps a surviving platform-only key whose slot directory and enrollment
binding are absent visible as lost custody. It never initializes that key or
imports its value. A separately authorized fresh enrollment, or an exact retained
`Phase`/`Slot` retry, may use its own distinct slot. Opening an independently
issuer-authenticated credential may exclude that orphan only after a positive
protected-key lookup proves a different payment key; an already selected source
is never excluded. Missing or ambiguous owned records and unknown storage/key
answers still refuse. In particular, retained `Accepted` without `Phase`/`Slot`
cannot infer a fresh grant from a surviving key: the pre-effect crash and erased
post-effect custody are ambiguous, so that recovery remains fail-closed.

Every token on the universal dataspace is eligible for KAGEMUSHA offline payments. There
is no Parliament approval, named-token allowlist or regulated/non-regulated asset-class gate.
The canonical universal balance scope is `AssetBalanceScope::Global`, routed to
`DataSpaceId::UNIVERSAL`. Its ordinary asset authorization, exact incarnation and scale,
reserve backing, enrollment and proof requirements still apply. These setup requirements
must be available to every universal asset through the shared registration and SDK paths;
no special governance authority is required merely because a token is non-regulated.
Current enrollment eligibility and freeze status use the
[eligibility SDK contract](kagemusha_enrollment_eligibility_v1.md). Bank-required enrollment
uses the user's bank middleware for KYC approval and freeze status. Other schemes select
their own authorized provider, including an issuer, community operator or SORA Parliament
for assets it governs. Parliament approval is not a protocol prerequisite. A scheme may
explicitly admit public enrollment; missing bank data never selects that policy implicitly.
The issuer rechecks authenticated authority, account routing and fresh eligibility at the
online enrollment boundaries. These observations do not replace platform evidence or confer
monetary authority, and add no per-payment call. Regulatory classification is an issuer policy
concern, not a cryptographic limitation or a legal classification made by the codec.

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

**Admission rule.** One rule admits phones on both platforms. A phone may enroll
at E1, and then Activate, Load, Send, Receive and Unload, if and only if the
issuer verifies at E1 a vendor hardware attestation proving four things:

1. A fresh, nonexportable P-256 SIGN/SHA-256 payment key was generated inside
   the phone's isolated secure hardware: on Android StrongBox or the TEE (equal
   attestation and KeyMint security levels of 1 or 2, origin GENERATED, no
   USAGE_COUNT_LIMIT or ALL_APPLICATIONS); on iPhone and iPad the Secure
   Enclave, whose key App Attest binds but does not independently attest (below).
2. The key is bound to the E1 challenge and to this app. Android: the
   attested application identity names the app package, a version at or above
   the policy minimum and only signers in the policy's signer set (1–4 entries,
   so every released distribution channel can enroll). Apple: production App
   Attest for the App ID plus a fresh, counter-checked assertion over the
   payment-key binding digest.
3. Android only: the hardware-enforced RootOfTrust records a locked
   bootloader, Verified boot and a nonzero verified-boot key; the boot hash is
   required only from KeyMint (attestation version 100) on.
4. The chain ends at a root of the policy's pinned root set, matched by SPKI,
   whose manufacturer ownership was authenticated independently of any device
   chain; the root's implemented and qualified adapter profile validates the
   chain; and no certificate is listed by that root's named revocation source or
   by the operator denylist.

The [enrollment policy](kagemusha_wallet_enrollment_policy_v1.md) fixes the
exact checks, root families, adapter profiles, revocation sources and denylist
format. Each failure has one closed refusal reason (§2.4). An attestation that
carries no application identity, such as attestation version 1 (Keymaster 2),
is refused for that evidence, never by model.

The only on-device preconditions are conditions the holder can fix; they are
not admission rules: a screen lock or passcode (custody class and Send/Unload
confirmation, §2.3), unlocked credential storage (retry), custody excluded from
backup, and enough free storage and memory, checked before each commit (§5.3).

Nothing else gates enrollment or offline payment: no Play Integrity or other
vendor online verdict, vendor user account (Google, Huawei or other), Google
Mobile Services, Huawei Mobile Services, app-store installation, exact app
version, StrongBox-only selection, patch-level refusal, model or device
allowlist, per-model budget, second attested key or periodic online check.
StrongBox versus TEE and patch levels are recorded credential facts; they never
refuse a phone. Registration, enrollment and payment have no vendor user
account, GMS/HMS or store-install dependency. They are not free of every vendor
service: Apple enrollment uses Apple's App Attest service, and the issuer reads
Google's attestation status list as the revocation source of the Google root
families ([policy](kagemusha_wallet_enrollment_policy_v1.md) Android admission
step 3). Those are enrollment attestation and issuer-side revocation inputs;
offline payment uses neither.

- **Android and compatible vendor APIs:** validate the KeyMint attestation
  chain against the policy's root set, under the reviewed adapter profile of
  the matched root. The reviewer authenticates the manufacturer's ownership of
  every pinned root independently of any device; a self-signed root that a
  device supplies proves nothing about who owns it. Under Google's RSA root key,
  certificate validity periods are not evaluated only for the documented
  factory-provisioned profile, per Google's guidance that expired factory keys
  stay trustworthy unless revoked; remotely provisioned chains, including those
  that chain to the RSA root, keep their validity checks, and so do chains under
  Google's Key Attestation CA1 root. Revocation is mandatory for every chain. A
  vendor's own root, such as Huawei's, is admitted by a reviewed `Vendor`
  root-set row naming that vendor's adapter profile. The profile is code: it is
  implemented, reviewed and qualified with genuine device chains and enrollment
  tests before its first row is admitted, and the `huawei` profile is
  implemented in the cutover (§9.1). After that, adding or changing the row is
  data only, with no code change. An unknown adapter identifier fails issuer
  configuration; it never reaches E1. A Vendor root that names no published
  revocation service uses the operator denylist as its revocation source. Every
  source is read at the time of the check: a leaked key passes until it is
  listed, lists are not instantaneous, and the denylist proves only that this
  operator had not listed the chain, not comprehensive vendor revocation or a
  bounded detection window. Check the challenge, hardware security level,
  generated key properties, app identity, locked device and verified
  vendor boot; record the patch levels against the policy floor. Reject software
  keys, unlocked or unverified boot evidence, identity mismatches and roots
  outside the set. Keep TEE and StrongBox evidence distinct; the attested level
  chooses the kind. The adapter generates the key in StrongBox where the phone
  declares it and in the TEE otherwise, falling back to the TEE only when
  StrongBox definitively fails before creating a key; there is no policy-driven
  selector or refusal plan. The fallback never reuses the failed slot's
  generation grant, alias or challenge: that slot is abandoned locally (§3.2),
  and a fresh enrollment with a new challenge and slot carries forward only the
  hardware-choice hint to generate in the TEE. These fields describe the
  attested event, not a live runtime examination of every payment. See the
  [AOSP attestation
  contract](https://source.android.com/docs/security/features/keystore/attestation)
  and [Google's verification
  procedure](https://developer.android.com/privacy-and-security/security-key-attestation).
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
- **Other vendor ecosystems:** a platform that does not run Android apps (for
  example HarmonyOS NEXT with HUKS key attestation) uses an adapter with an
  explicit equivalent evidence contract under the same four-part rule. A brand
  name is not an attestation format. Do not invent Android fields for a platform
  that lacks them or silently enroll a software key. Such adapter work can
  proceed alongside the POC.

Enrollment evidence is the platform attestation alone; it records no vendor
online verdict, and periodic renewal exists only as the optional §7 attestation
lease. Local root/jailbreak heuristics are not admission or payment rules: the
attested boot state (Android) and App Attest (iPhone) are the enrollment
evidence, and a heuristic would refuse genuine phones without proving that
compromise is absent. A detected compromise is outside the security assumption
(§2.1); it is never authority to delete state, change the balance, alter
committed payments or reverse a Send. Preserve custody, delivery bytes and
recovery access.

Residual risk, stated plainly. Hardware custody holds only while the
attestation authority, the secure hardware and the OS are trustworthy.
Nonexportability keeps the payment key inside the phone; it does not prevent
forks. Anti-forking still rests on the released wallet, its exclusive ownership
of the wallet state, the durable markers and stock-OS storage isolation (§§2.1,
4). On iPhone, App Attest binds the payment key the app supplies but does not
independently attest that key's Secure Enclave provenance.

Dropping Play Integrity gives up a fresh Google device-integrity verdict bound
to E1 and the payment key, with its root, hook and emulator detection and,
where configured, its recognized-distribution, licensing and STRONG-integrity
patch signals. This revision also removes the earlier enrollment refusal on a
positive local root or jailbreak check. The rule therefore admits cases the
earlier rule rejected whenever the Google verdict or the local check caught
them: hardware evidence forged with a leaked attestation key that neither its
revocation source nor the operator denylist yet lists, and a runtime compromise
on a phone whose recorded boot evidence is Verified. Whoever holds a cloned
payment key and wallet state can spend the same balance on several forks, so the
aggregate loss can exceed that wallet's balance. Listing a key or chain stops
later E1 admission and, at the operator service, later Activate and Load; it
does not end offline spending of value already issued. Remotely provisioned
attestation keys are not exposed to factory key leaks. KYC, quotas and caps
(§7) limit exposure where they are enabled; they are off by default and do not
restore cryptographic anti-forking.

The operator's online service must refuse new Activate and Load requests for a
wallet whose retained E1 chain contains a certificate that its root's
revocation source or the operator denylist later lists. It never refuses Unload
and never affects offline acceptance or committed payments. This refusal is
enforced only at the operator service, which holds the retained chain: the
ledger's activation and load instructions do not consult retained attestation
chains, revocation sources or the denylist, and this revision adds no such
validator-facing check (§9.1). The refusal is ledger-wide only where an
existing mandatory authorization gate makes the operator service unavoidable
for that operation.

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

### 2.4 E1 outcomes and refusal reasons

An E5 exchange has exactly two terminal outcomes, Issued and Refused. Only they
are immutable: the issuer retains the terminal outcome with the exchange, and no
retry, later observation or outage changes it. The immutable outcome is distinct
from current delivery authorization (Delivery of an Issued outcome, below): a
Refused outcome is returned unchanged on every retry, while an Issued outcome's
exact E6 is returned only when a fresh eligibility observation currently
authorizes its delivery. Unavailable and Unknown are recovery states, never
terminal outcomes; neither is retained as the exchange's answer.

- **Issued:** the E6 result with the signed credential (§2.2). The outcome is
  fixed once the signed credential is retained; a later eligibility denial or
  outage withholds its delivery but never turns it into Refused.
- **Refused(reason):** exactly one reason from the closed table below, decided
  before any credential is signed: at E5 verification or at the signing
  boundary. The E1 challenge is consumed. Because the attestation binds that
  challenge, another attempt needs a new challenge, slot and key, after
  abandoning this one (§3.2).
- **Unavailable (retryable, before any effect):** a revocation source, the
  operator denylist, the eligibility provider or issuer storage could not be
  read before the issuer decided, and no effect has taken place: no Apple
  counter advance, credential signature, quota allocation or E6 retention.
  Nothing is decided or consumed. When the exchange is already claimed, the
  issuer records the typed outage on that claim, and a retry of the exact
  retained E5 while E1 is live resumes verification of the same claim, whose
  first dispatch time stays the time checked against the challenge lifetime;
  otherwise the retry is the first dispatch.
- **Unknown (uncertain, after a possible effect):** the issuer claimed the
  exchange and an effect may have taken place, but it holds no terminal outcome.
  Recovery never repeats an effect: it does not verify again as a new first
  attempt, consume the Apple counter again or sign a second credential. It
  returns a terminal outcome that retained effect records establish (a retained
  signed credential completes as Issued), and otherwise follows the
  [eligibility contract](kagemusha_enrollment_eligibility_v1.md) Inspect rules.
  The issuer treats an Unknown exchange as possibly issued: if the wallet
  abandons it, the wallet uses the marker form (§3.2), and the exchange's quota
  share stays reserved until that Abandonment's successful execution is
  finalized.

Each effect is recorded durably, atomically with the claim state that names it,
before it can become visible. The Apple counter value that a claim consumes is
stored with that claim when the counter advances, so a retry of the same claim
reuses that record and never fails the counter check against its own earlier
advance.

**Delivery of an Issued outcome.** Every E6 delivery, the first, a repeat and
recovery alike, needs its own fresh eligibility observation at the delivery
boundary, as the [eligibility contract](kagemusha_enrollment_eligibility_v1.md)
requires; the E1 challenge lifetime does not apply to it. That observation
decides only whether the retained E6 is delivered now. When the provider reports
`NotApproved` or `Frozen`, the issuer withholds delivery and reports code 11 or
12 as a withheld delivery, not as a Refused outcome. When the provider, issuer
storage or current authority routing cannot be read, delivery is `Unavailable`.
In either case the issuer keeps the Issued outcome, the exact retained E6 bytes
and the exchange's quota share. It does not consume or abandon the exchange,
sign again or restart E1, and the wallet keeps its slot, enrollment marker and
retained E5 and retries delivery later. Once a fresh observation approves, the
issuer returns the same E6 byte for byte, never a newly signed credential. A
withheld delivery never forces abandonment; the holder may still choose the
marker form (§3.2), and the quota share then stays reserved until that
Abandonment's successful execution is finalized.

| Code | Reason | Platform | Class | Cause |
|---:|---|---|---|---|
| 1 | KeyNotInSecureHardware | Android | Phone | The attestation or KeyMint security level is Software, the two levels differ, or attestation version 2 is not TEE. |
| 2 | AttestationWithoutAppIdentity | Android | Phone | The attestation carries no application identity: attestation version 1 (Keymaster 2), or a later attestation without `attestationApplicationId`. |
| 3 | BootloaderUnlocked | Android | Phone | The RootOfTrust records an unlocked bootloader. |
| 4 | BootNotVerified | Android | Phone | Boot state is not Verified, the verified-boot key is zero, or a KeyMint boot hash is not 32 nonzero bytes. |
| 5 | UntrustedAttestationRoot | Both | Phone | The chain does not validate under its root's adapter profile to a root of the policy's root set (Android), including signature, order, constraint, critical-extension and validity failures, or does not validate to Apple's App Attestation root (Apple). |
| 6 | AttestationRevoked | Android | Phone | A chain certificate is listed by its root's revocation source or by the operator denylist. |
| 7 | AppIdentityMismatch | Both | App | The package, a signer, the App ID or the App Attest environment differs from the app policy. |
| 8 | AppVersionBelowMinimum | Android | App | The attested package version is below the app policy minimum. |
| 9 | EvidenceInvalid | Both | Attempt | The evidence is malformed or does not match this attempt: shape, challenge, attested key (the trusted attestation certificate's subject key is not the payment key), attestation extension placement, an undocumented version pair, a RootOfTrust whose DER shape differs from its version's schema, key properties, authorization tags (including 405 or 600), App Attest nonce, key identifier, counter or key-binding assertion. |
| 10 | ChallengeExpired | Both | Attempt | E5 verification began after the E1 challenge lifetime. |
| 11 | AccountNotApproved | Both | Account | The eligibility provider reports `NotApproved`. |
| 12 | AccountFrozen | Both | Account | The eligibility provider reports `Frozen`. |

The class tells the wallet what the holder can do; the app owns the wording:

- **Phone:** this phone cannot hold offline value. Abandon the attempt and do
  not start again on this phone. Online payments are unaffected.
- **App:** install the released app from an official channel, or update it,
  then start again.
- **Attempt:** abandon and start again with a new challenge. A repeat is a
  defect report, not a device verdict.
- **Account:** the account's status, not the phone, blocks enrollment. An
  eligibility denial uses codes 11 and 12 at every online enrollment boundary,
  with two meanings. At the pre-key permit, E5 verification or signing
  boundary, before any credential exists, it refuses (at E5 or signing, the
  terminal Refused outcome); start again after the status changes. At E6
  delivery, after issuance, it only withholds delivery of the Issued outcome
  (above); keep the slot and retry delivery after the status changes, without
  abandoning or starting again.

Codes are a closed `u16` set. Zero and unknown codes are protocol errors, never
admission. Native exports the set; the issuer worker reports exactly one code
with each refusal; Core and the SDKs relay it unchanged and never substitute
free text. Right after key generation, the Android adapter may apply the
Phone and App checks to its own fresh attestation and report the same codes
before E5, then abandon (§3.2). The issuer stays authoritative; the adapter
reports the first failure it finds, which may differ from the issuer's first.

Conditions found on the phone before E5 are not E1 refusals: no screen lock or
passcode, locked credential storage (retry), no secure hardware or App Attest
support (Phone class, reported by the platform adapter), and too little storage
or memory (§5.3).

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
accumulator acceptance check `decide` ([PIPA-v1 §11](plonk_ipa_v1.md)) on each
accumulator that Ω carries: the Pallas accumulator bound in its public digest,
batched with Ω's own opening, and the Vesta accumulator ([Λ/Ω
record](kagemusha_lambda_omega_v1.md) §3). These accumulators are Ω's *deferred
values*: the cross-field values that the wrap leaves for its consumer to
constrain (PIPA-v1 §12 S6, §13).
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
zero-filled. Two hash families apply, and every digest that the lineage relation
recomputes is Poseidon:

- **Poseidon.** `P` for every value a step relation computes or opens and every
  digest Λ recomputes: `credit_id` (§5.1), the state commitment and rest digest,
  the chains, the statement digest (σ's public-input encoding of its statement,
  which the receipt also binds), `operation_id`, the unload nullifier, the object
  digest of each signed object that a relation verifies or names (requests,
  receipts, credentials, certificates, ordinary Load receipts, fee schedules, scheme
  policies, quota shares, time anchors and charge quotes, over the
  signed message and the signature), the certificate-set and package digests, and
  the roots, leaves and openings of every wallet map, of the quota-window and
  quota-usage trees (§7) and of the credit-digest tree. The entries root of the
  local account blacklist (§7) is also `P`; only native code computes it.
  `P_bytes` for the large-input digests: `proof_digest` in
  both its domains (§4.1), the Payment digest, the lineage digest over Ω, the
  credit-opening, credit-status and credited digests (§5.1), and every signed
  message (below), and the public recovery `capsule_commitment` (§4.1).
- **SHA-256.** `H` only where no relation recomputes the value: `scheme_id` and
  the identities fixed at enrollment (asset scope, wallet, enrollment), the
  enrollment and renewal transcripts given to platform attestation, `account`,
  the artifact digests (relation, verifying-key set, artifact manifest), the
  evidence digest, the output descriptor and local custody records (marker,
  capsule-body, capsule, completion, fold). The wire record lists each one and why it stays
  SHA-256.

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
regulatory_policy, enabled_controls, quota share/windows/expiry, quota_usage_root,
lease expiry, accepted time/epoch information
state nonce, state commitment
```

The state commitment (the head commitment) is one canonical Fp value with two
levels: `P(core ‖ P(rest))`, under distinct core and rest domains. The core
holds every field that a step proof reads, changes or carries:
lifecycle, `scheme_id`, `asset_digest`, `wallet_id`, credential digest,
balance, burned_total, sequence, next_send, next_load, next_redeem, send_chain,
recv_chain; the consumed-credit, pending-outgoing, load/redeem-recovery,
fee-claim-recovery and quota-usage roots; the enabled-controls mask, quota
windows root and quota share expiry, the regulatory policy's maximum anchor
response time, lease expiry, policy epoch and accepted-time floor; and the state
nonce. Load and redeem
recovery share one map and root, keyed by `(kind, ordinal)`. The rest digest
commits the remaining fields (including the rest of the regulatory policy body,
the held policy objects and the time anchor). No σ
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
by `(kind, ordinal)`, fee-claim recovery) and the credit-digest tree is a
depth-32 Poseidon indexed Merkle tree.
Its leaves `(key, value, next_key)` are sorted and linked by key from a zero
sentinel leaf, which alone forms the empty tree. Membership opens the key's leaf
by its path; non-membership opens the low leaf whose `key` and `next_key`
bracket the absent key; insertion updates the low leaf's `next_key` and writes
the new leaf at the next free index. Every opening carries exactly 32 siblings.
Relations prove only that the written slot was empty: allocation position and
lifetime exhaustion are native-store policy, not proved map semantics. The wire
record fixes the leaf, node and value encodings, their domains, the empty tree,
the removal step that ArchiveSent uses and the opening layout. The one exception
is the quota-usage map: a depth-6 fixed array (a Poseidon Merkle tree of 64
slots) aligned one to one with the 64 slots of the quota share's window tree.
A Send charges its touched windows in place at their own slots, with no
insertion, and a QuotaShare refresh rebuilds the array for the new windows (§7).
The wallet retains
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
   Credited evidence, an ordinary Load receipt, a policy update). For Send, Unload and
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
   durably. For a lean step (Load, Send, Unload and Retiring today; owner decision
   2026-10-17, with the other own steps to follow), Λ proves the transition relation directly
   instead of verifying the step's own σ, which the payment path already
   verified natively; every other step's own σ is verified. Λ verifies each
   step's τ and every incoming package's Ω, σ and τ. The fold owner verifies each new Ω exactly once, through the
   installed verifier, before any credit, pending-map, archive or manifest
   effect; the recorded bytes reuse that verification only on exact canonical
   byte identity, and an adopted interrupted publication reuses the full
   verification of its exact record bytes. One Λ may cover a contiguous run
   of steps where the artifact set has a relation for that run length. It
   verifies each step's σ, or proves a lean step's transition directly, and
   each step's τ, and only the last head of the run receives Ω
   and becomes folded. Each head has at most one recorded Ω. Every Lineage message, Payment and ledger package from that
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

The wallet artifact bundle carries every exact descriptor, verifying key and
proving key used by its sigma, Q, A, W and Ω source owners. Load finality uses
native BLS verification against the independently authenticated signed genesis
and certified epoch transitions; it has no circuit, proving key, verifier-key
catalog or server proof service. Missing or changed monetary proving artifacts
prevent complete source qualification; reinstallable artifact unavailability is
not custody loss. Directory contents cannot substitute for the compiler's closed
original list. Signed-genesis trust is selected independently of those artifacts.

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
- *[σ_send, before Advance, only while the control is enabled]:* the touched
  quota windows, their in-place usage update, the quota share expiry and the
  Send time span; lease expiry and time-window arithmetic, all against
  head-committed roots and fields (§7).
- *[native, inside the serialized Advance section]:* consumed-credit
  nonmembership and insertion, and every root update, against stores
  authenticated by the expected head, with each successor root equal to the one
  in σ's successor commitment (§4.2).
- *[Λ, after Advance, in the background; required before Send, Unload or
  Retiring commits from that head (§3.1)]:*
  - scope, relation identity, operation tag and provider contract, and the
    credential (R10): in-circuit at least at Bootstrap, RefreshCredential and
    a Request's renewed receiver credential, and in every step whose route
    still re-verifies it; a lean step (Load, Send, Unload and Retiring today) carries the credential
    digest and payment key by continuity;
  - the predecessor Ω and receipt, or the unique zero-state enrollment base
    case;
  - this step's σ, or for a lean step its transition relation proved directly
    in place of its own σ; its τ; and every input package's Ω, σ and τ;
  - every signature it owns: the Request and receiver credential only in
    Λ_recv; certificates and credentials in the step that introduces them and
    in each step whose route still re-verifies them; and policy, time and
    credential updates in the step that consumes them;
  - in Λ_load, the exact ordinary receipt terms and replay insertion bound to
    the credential-authorized Advance. Native BLS finality and receipt-event
    inclusion are checked before that signature under §6.1, not in Λ_load;
  - the Request's account digests against the credential each belongs to:
    Λ_send checks the payer account digest against the payer's own
    credential, and Λ_recv checks the receiver account digest against the
    receiver credential it verifies; each counterparty's digest is bound only
    through `credit_id`;
  - for RefreshPolicy(QuotaShare), the quota-usage array rebuild (§7);
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
`burned_total`, pending-outgoing root and credit-digest root. Ω's public digest
also binds the lineage verifying-key digest, which every native verifier
recomputes with the artifact-set constant. Every consumer of
a package carrying Ω(pred), natively and in Λ, checks before mutation:

- `σ.predecessor = Ω.head` and `statement.credential_digest = Ω.credential`;
- τ verifies under `Ω.payment_key`;
- σ's `burned_total` and pending-outgoing inputs equal Ω's;
- for a Payment: the Request's payer wallet equals `Ω.wallet_id`; its send
  ordinal is the one σ_send consumes; and the payer credential digest and `payment_key` are taken from Ω.
  Assembly compares the reconstructed signed Request with the original in full.

A mismatch is rejected before mutation. Statements and Ω carry one
scheme-level relation identity, not one per relation. Each consumer selects σ's
verifying key from the verifying-key allowlist by operation tag and, for Send,
also by `Ω.enabled_controls`. Λ uses the same allowlist. G1 defines
the allowlist, with one entry per selector; its digest is the
`verifying_key_set_digest` that the relation identity binds. The statements of
σ_send and σ_recv bind the enabled-controls mask, and their relations check
that mask against the core; a σ_send whose relation omits a check for an
enabled control is rejected. Every Λ
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
  including deferred values, σ_send, τ_send, the Request's signature, the
  consumer checks above, or `credit_id`
  nonmembership in the predecessor's consumed-credit root (on a duplicate, the
  committed consumed-credit root equals the predecessor's root or is a
  structurally valid indexed-tree insert of a fresh key). On that branch
  the `credit_id` stays consumed and its amount is added to Λ's `burned_total`.
  The credit-digest root records the credit with its burned flag, unless that
  `credit_id` is already recorded there, in which case the recorded leaf, its
  Payment digest and its burned flag stay as they are. No accumulator or
  deferred value of the burned Payment enters Ω, except a corrected claim
  (G*, u) with G* = ⟨s(u), g⟩ ≠ G that Λ_recv computes itself to show that the
  Payment's accumulator (G, u) fails to decide; such a claim decides by
  construction. Only that Payment is burned.
- Λ_archive has a no-op branch, taken when the in-circuit check of the Credited
  evidence evaluates false; it may likewise fold a self-computed corrected
  claim of the evidence's failing accumulator, and nothing else of that
  evidence enters Ω. Λ's pending-outgoing root keeps the descriptor, and
  there is no balance effect. The wallet keeps that descriptor and its Payment
  bytes. It can archive the descriptor again after a later Send, Unload or
  Retiring writes it back into the core. A CreditStatus for a duplicate
  `credit_id` shows the first recorded Payment digest, so it does not match a
  second Payment under that `credit_id`, and archiving that Payment takes the
  native rejection or the no-op branch.
- Λ_send contains no check on counterparty-only data that can fail after
  commit. The Request signature and receiver credential are checked natively
  before Advance, and in-circuit only in the receiver's own Λ_recv. Fee terms
  are checked against the payer's own policy.
- Ordinary Load receipts, certificates, fee schedules, credentials, and policy,
  time and credential updates have no failure branch. The issuer roles of §2.3
  sign their objects; native BLS finality authenticates ledger Load receipts as
  specified in §6.1. A peer can relay them but cannot forge or re-encode
  them (§8), so only a verifier defect can make them fail in-circuit. The next
  two rules target that defect.
- Native and in-circuit verifiers accept exactly the same set for every object
  that Λ verifies after a native check: Ω including its deferred values, σ, τ,
  the Request, Credited evidence, ordinary Load receipts, fee schedules, certificates,
  credentials, and policy, time and credential updates.
  For ordinary Load receipts this equivalence covers canonical transcript and
  monetary-term binding. Native BLS finality and event inclusion remain the
  explicit pre-Advance trust boundary of §6.1; Λ does not repeat those checks.
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
ordinary Load receipt. This activation is idempotent and occurs during enrollment.
The ordinary account-signed transaction carrying Activate may have several
submission attempts, each retaining its exact signed envelope. A new envelope
must carry the identical retained Activation, with the same account, network,
asset and incarnation; it does not repeat Bootstrap or initialize another head.
Each candidate remains subject to ordinary transaction admission and fees.
Expiry, an HTTP status or an absent lookup is not evidence of non-inclusion or
rejection. For each retained attempt Native requests one direct finality original
by the attempt's exact entrypoint hash: the inclusion block's original consensus
header, BLS CommitQC and execution-result preimage, with Merkle membership of the
exact entrypoint in the certified network-input root and of its joined Network
output, at the output position equal to the entry's input index, in the certified
output root. Native verifies it under the epoch authority selected by its
protected manifest (§6.1), without walking or replaying earlier blocks, and
retains the first authenticated outcome of each attempt immutably with its exact
original. Successful execution of one retained attempt confirms the wallet;
authenticated rejected execution closes only that attempt. Confirmation proves
activation of the wallet, not successful execution of every envelope.
An interrupted enrollment resumes the same installation; it never creates two
initialized heads. The holder may abandon an unused enrollment, for example
after an E1 refusal (§2.4) or an interruption that cannot resume, only while
Bootstrap has never been selected. Once Bootstrap is selected or commits,
including an uncertain activation response, recover that incarnation and use
§6.3; do not abandon funded obligations. Before any permit or slot has been
accepted, Native may also cancel the authenticated retained Client. Under the
same exclusive provider ownership used for permit admission and authorization,
it authenticates that exact Client, definitively establishes the absence of
Accepted, Slot and Phase originals, and durably publishes an immutable Cancelled
record bound to the Client digest. Missing, corrupt or uncertain custody is
Unavailable and never authorizes a fresh attempt. Every later permit admission
and authorization rechecks Cancelled before any side effect, including after
restart or a delayed issuer reply. Successful cancellation returns
`LocalAbandoned`; it has no ledger instruction or slot/key effects. A different
request identity may then start while the old Client and cancellation remain
retained. If an Accepted original already exists, this pre-permit form refuses.

An Accepted E1 whose account authorization never selected a Slot or Phase has a
separate terminal expiry path. The Enrollment-role issuer signs a canonical
`KagemushaEnrollmentExpiryProofV1` under the distinct
`iroha:kagemusha:pre-key-expired:v1\0` domain. It binds the exact current Resume
dispatch and retained Accepted permit SHA-256 digests, request and attempt
identities, challenge digest, immutable expiry, and issuer observation at or
after that expiry. Native verifies the rooted signer and every binding, retains
Client and Accepted unchanged, requires Slot, Phase and Cancelled absence and
refuses any matching intent or unavailable custody. Only then does it durably
publish the immutable Expired proof. This has no ledger or hardware-key effect.
Begin authenticates a retained Expired proof as terminal recovery DATA; permit
acceptance and account authorization always refuse it. Generic abandonment or
the expiry action may adopt that authenticated terminal outcome after restart
without matching the new dispatch nonce to the old proof. This recovers a crash
between Native publication and app completion DATA without replacing the proof,
creating a key or allowing the expired identity to resume. A new request may
start after `LocalAbandoned`; the old originals and proof remain retained.

For selected slots, abandonment has two forms, chosen by the slot's durable
state. The names below are Native's slot statuses
(`KagemushaWalletSlotStatusV1`). Two different Native names say Pending. The
enrollment progress `EnrollmentProgressV1::Pending`, which Native reports for
slot status `Empty` or `IntentOnly`, is the no-marker form below; "abandon from
Pending" means that form. The same form covers a selected slot whose key lookup
is unknown, which Native reports as `Unavailable` rather than as a progress
value. The slot status `Pending(marker)` is a selected head
waiting for its receipt, and Native reports it as progress `BootstrapSelected`:
Bootstrap is selected, so it is never abandoned.

- **No marker (Native `Empty` or `IntentOnly`, or a selected slot whose key
  lookup is unknown).** No enrollment marker exists. Either the slot was
  selected but no key was generated under it (`Empty`, or `IntentOnly` with the
  key definitively absent), or the platform cannot establish whether a key
  exists. The unknown case has no slot status of its own: on Android API 26–30 a
  missing lookup result is unknown, so Native reconciliation of that slot
  reports `Unavailable`. It arises in two windows. A selected pre-E2 slot has a
  durable Slot original but no intent yet, because slot selection is durable
  before E2 and before intent creation; reconciliation reaches `Empty` only
  through a key probe, which on API 26–30 cannot report absence. An interrupted
  generation after the intent has spent its one-shot generation grant, so that
  slot can neither continue nor adopt a key.
  Abandonment is local: the provider durably writes the abandoned-slot record
  with a holder-abandoned reason. The slot then reconciles to `SlotAbandoned`
  without a key probe, and no key is ever generated, adopted or initialized
  under it again. No E5 can name this slot, because E5 carries the durable
  generation-zero marker, so no credential or ledger record names it and there
  is nothing to submit. `abandon()` reports this local form and returns no
  ledger-control bytes. Before writing the record, local abandonment must:
  1. authenticate the slot's retained pre-key Client, Accepted permit and Slot
     originals and their selected enrollment scope. Authenticate the intent
     when it is present or required (`IntentOnly`, and an intent whose key is
     unknown after generation began): it must match the selected scope. A slot
     selected before E2 has no intent. Its absent intent is legitimate when
     authenticated durable pre-E2 phase and custody evidence establishes it:
     the authenticated retained originals select the slot and place the attempt
     before E2 and intent creation, and readable custody shows no intent,
     generation-attempt record, enrollment marker, retained E5 or E6, or
     initialized state. This evidence does not require a key-probe-derived
     `Empty`, so it also covers the API 26–30 pre-E2 slot whose lookup is
     unknown. A missing required original (the Client, Accepted permit or Slot,
     or the intent of a slot whose retained originals or generation-attempt
     record place it at or after intent creation) is a lost original, never
     legitimate absence: abandonment reports `Unavailable` and writes nothing;
  2. establish, from durable custody it can read, that the slot has no
     enrollment marker, retained E5, E6 or credential record, or initialized
     state. Unavailable or uncertain storage, an unreadable record or a lost
     marker never counts as "no marker": abandonment then reports
     `Unavailable` and writes nothing;
  3. hold exclusive ownership of the slot across the check and the write, so that
     generation recovery, marker installation, E5 retention and Bootstrap
     selection cannot run concurrently with it or after it;
  4. leave the slot terminal: once the record is durable, every later
     recovery path, including reconciliation, recovery of a generation reply
     and a delayed platform generation result, returns `SlotAbandoned` before
     any key probe and never adopts that key.

  On Android API 26–30 local abandonment, in either unknown window, never
  turns a missing lookup result into absence: it stays unknown, a spent
  one-shot generation grant stays spent, no generation grant is ever issued
  for the abandoned slot, and the abandoned alias is never regenerated or
  reused. Native authenticates the retained pre-key originals before committing
  this local form and checks the abandoned-slot record before generation
  recovery. `abandon()` returns `LocalAbandoned` without ledger bytes; it does
  not require a key-probe-derived `Empty` on API 26–30.
- **Marker (Native `Enrollment`: the generation-zero marker is still
  current).** This includes an issuer refusal and an issued credential whose
  Bootstrap was never selected. Abandonment commits the terminal marker with
  reason Abandoned (Native `Terminal`) and returns the exact Abandonment frame
  signed by the payment key, as `abandon()` does today. The holder's account
  submits it in an ordinary transaction; the ledger instruction atomically
  rejects prior activation and permanently disables activation and loads for
  that `wallet_id`. No receipt or monetary balance exists to return. Native
  retains the frame, and the wallet resubmits the exact bytes until finalized
  inclusion is authenticated.

A fresh enrollment always uses a new issuer challenge, a new slot and a newly
generated key, so it has a new `wallet_id`. It starts as soon as the abandonment
is durable on the phone and never waits for ledger acceptance: the ledger keys
activation by `wallet_id`, and the abandoned incarnation can no longer select
Bootstrap from this custody. Ledger acceptance of an Abandonment matters only
for the old `wallet_id`: it permanently disables activation and loads even
against a restored or compromised copy, and it is the terminal evidence that
releasing an unused quota allocation requires; that release does not erase
historical quota usage. Only the marker form can hold such an allocation: an
issued credential, or a claimed E5 whose outcome is Unknown and so may have
been issued (§2.4). The issuer keeps every issued or potentially issued
allocation reserved (§7) until it authenticates finalized successful execution
of that `wallet_id`'s Abandonment; inclusion of a failed execution releases
nothing. With quota controls enabled, the issuer allocates the new wallet's
share atomically from the remaining allowance, in the same durable step that
records the allocation, so two enrollments can never both receive the last
share. Starting an enrollment promises no available quota. The new enrollment
itself still starts at once; the no-marker form holds no allocation and has
nothing to wait for.

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
and recovery capsule commitment. The operation tag fixes the `proof_digest` domain
(§3.1). For Send, Unload and Retiring,
`proof_digest = P_bytes(proof domain, LE32 len(Ω) ‖ Ω ‖ LE32 len(σ) ‖ σ)` over
Ω(pred) and σ. Bootstrap, Load, Receive, ArchiveSent and RefreshPolicy use
`P_bytes` under a distinct σ-only domain over `LE32 len(σ) ‖ σ`. Either value is
one canonical Fp element (§3). A Receive receipt also binds the full canonical
Payment digest (§5.1). σ_recv's statement and successor commitment never
contain that digest or any value derived from it (§3). The open Request has no
payer or send ordinal, so σ_recv is prepared after the Payment completes those
fields and determines the credit identifier and consumed-credit update.
Λ_recv constrains the receipt's Payment digest
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

Freeze the exact canonical private recovery body B before sampling its opening:
actual next state openings, proof, required map nodes, retained input bytes,
output descriptors and operation recovery data. Let `b = H("capsule-body", B)`
and split all 32 bytes injectively into `m0 = LE128(b[0..16])` and
`m1 = LE128(b[16..32])`, represented in Fp without reduction. Independently sample
uniform canonical `r ∈ Fp`, including zero, and compute the Vesta commitment
`C = m0 g[0] + m1 g[1] + r w` under the installed IPA generator tuple. The receipt
binds the nonzero 32-byte value `capsule_commitment = P_bytes(kgwcapc1, enc(C))`.
Identity C is valid and has its canonical encoding. SHA collision resistance,
Poseidon collision resistance and the existing IPA generator-relation premise
bind this value to every B byte; no SHA hiding assumption is used.

Sample r from at most 128 independent 32-byte OS entropy fills. Clear only bit
255 of each candidate, then accept its first canonical little-endian Fp encoding.
This gives each accepted scalar exactly two raw preimages, retaining a uniform
opening including zero; under ideal independent fills the exhaustion probability
is `(1 - p/2^255)^128`, at most `2^-128`. An entropy error fails immediately; exhaustion or
a zero public commitment refuses this attempt before selection. Do not reduce
arbitrary bytes, derive r from the state nonce or proof coins, reseal internally,
or regenerate the body/proof to avoid refusal. Construction consumes the frozen
body, and verification reconstructs it deterministically without sampling.

The selected private recovery capsule is the exact canonical wrapper W=(B,r).
Its private custody identity is `H("capsule", W)`. Markers, manifests, predecessor
links, plans, fold records and completion records authenticate this identity;
public receipts carry only `capsule_commitment`. Every join between a receipt
and local custody verifies the authenticated wrapper's commitment and exact
retained output. A caller-supplied association between these identifiers is not
authentication. After W is collected, retained output is returned only after its
exact completion frame and both identifiers match the authenticated permanent
step entry; a sequence parsed from its explicit canonical output schema is only
a bounded lookup locator. Neither the body hash, wrapper hash nor opening is exported in
a receipt. The opening is required to open the commitment and remains in the
same redundant non-backup custody as the body for its entire retention lifetime.
Once W is durable, retries reuse its exact B, r and commitment. A missing opening
is reconciled from an authenticated copy or reported as custody loss, never
replaced by fresh randomness.

Append the receipt and assembled output bytes in a separate durable completion
record excluded from W. Neither B nor a monetary map leaf contains its own final
receipt/package. Persist both records before returning; a commitment or a
key-store marker alone is insufficient for onward spending. Capacity checks
count the complete wrapper, including its opening and framing, for both retained
copies within the unchanged 524,288-byte capsule cap. The sole first-release
provider-contract identity binds these semantics; regenerated credentials,
fixtures and authenticated artifacts use that identity without a fallback.

Until a durable Ω covers a step, the capsule and completion records of that
step retain every input that Λ verifies for it: σ, τ, every consumed input (the
incoming Payment with the payer's Ω, σ and τ; the Request; Credited evidence
and the matching Payment; the ordinary Load receipt; policy, time and credential
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
     pending-outgoing, load/redeem and fee-claim recovery, quota-usage) against
     the roots committed in that head, or for the
     pending-outgoing store of Send, Unload and Retiring against Ω(pred)'s
     root (§3.2), and stop on any mismatch;
   - for Receive, check consumed-credit nonmembership and stage the insertion
     inside this serialized section, including when σ_recv was re-proved
     because the head changed;
   - recompute each successor root from the authenticated store and the staged
     update, and require it to equal the root in σ's successor commitment;
     otherwise discard the staging;
   - reserve the storage of §5.3 and run its runtime capacity check.

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
*Request body* is the canonical signed Request fields as 24 elements in
request-body order, with their dependencies (receiver credential, fee schedule,
certificates) bound by their `P` digests.
Request fields bind both wallet IDs, the payer's and the receiver's account
digests (each the `account_digest` of that party's credential), payer send
ordinal `s`, receiver credential,
amount, signed fee schedule and exact fee, regulatory policy references, the
receiver's authenticated accepted time (§7) and a fresh 256-bit nonce. The
receiver signs the terms, every field except the payer wallet, the payer account
digest and `s`, in the Request domain, and issues the Request open (those three
fields zero). The payer completes them for its own wallet, account and next `s`;
the signature and the Request digest do not change, and `credit_id` over the
completed fields is unique per payer and ordinal (owner, 2026-10-18: three codes,
receiver first). No free-form field changes the monetary interpretation.

| Step | Message and state effect |
|---|---|
| Request | Receiver signs a nonmonetary open setup quote containing its terms (the fields above except the payer wallet, payer account digest and `s`, which are zero). It is issued before any payer message, so it consults no blacklist; the receiver's list applies at Receive. Any payer completes it for its own wallet, account and next `s`. |
| Payment | From a folded head, the payer verifies the Request and the applicable Send policy in one native pre-check, which applies every enabled control (§7) and returns σ_send's control witnesses, and checks `s == next_send`. The Request's payer account digest must be the payer credential's and its receiver account digest the Request receiver credential's; while the payer holds a local blacklist, that list must not contain the receiver's account, checked natively at Send preparation and again at commit, before the irreversible debit (§7). It may prove σ_send *speculatively*, after verifying the Request and before the payer confirms; a declined speculative σ_send is discarded and never signed. It natively verifies σ_send and uses the Ω(pred) recorded as self-verified at fold time (§3.1), which is not re-verified on the payment path. It then permanently subtracts `amount + fee`, increments `next_send`, appends to `send_chain` and inserts the credit descriptor in its pending outbox. It commits and retains the full canonical Payment before first release. Payment contains the unique signed Request fields and signature, and the Send package {statement, Ω(pred), σ_send, τ_send}. It reconstructs the exact signed Request from those single owners; the payer key and credential digest come from Ω(pred). Assembly rejects any mismatch with the original full signed Request before compaction. The receiver's credential, fee schedule and certificates are bound by digest in the Request body, which the receiver holds. |
| Receive | After the §5.3 runtime capacity check passes on the receiving phone, the receiver natively verifies before mutation: the payer credential from the PayerCompanion carried beside the Payment, whose digest equals Payment's credential digest, σ_send's statement and `Ω(pred).credential`; Ω(pred), including the decide; the §3.2 consumer checks; σ_send and τ_send; its own bound identity, matched by the Request's receiver `wallet_id` and the `payment_key` of the Request's receiver credential, never by credential-digest equality, so that credential may be an earlier one of this incarnation; the open Request it signed, completed by the Payment, whose payer account digest equals the PayerCompanion credential's; and, while it holds a local blacklist, that the list does not contain that payer account (§7). If Payment's Ω(pred) is byte-identical to a Lineage Ω that the receiver already verified in this session, that verification is reused; otherwise it verifies Ω(pred) in full. Using the completed Request and selected receiver head, it proves σ_recv, whose statement and successor commitment exclude the Payment digest (§3), and adds exactly `amount`. In the serialized Advance (§4.2) it checks nonmembership and inserts `credit_id → (amount, receive sequence)` into the permanent consumed-credit map; the Receive receipt also binds the full canonical Payment digest. Show complete only after durable completion. Λ_recv later proves the incoming objects, the map update and the receipt's Payment digest in-circuit and records the digest in the credit-digest root, or takes the burn branch (§3.2). |
| Credited | Optional delivery evidence, in one of two forms. (i) The receiver's Receive package {statement, σ_recv, τ_recv}, whose receipt binds the exact Payment digest; its status is *credited, unfolded*. (ii) A read-only `CreditStatus` against a folded receiver head `h` that covers the credit: {statement(h), proof_digest(h), τ(h), Ω(h), 32-sibling membership opening of `credit_id → (Payment digest, burned flag)` in Ω(h)'s credit-digest root}, with no σ and no Ω(pred); its status is *credited* or *burned*. Credited advances no state. The receiver need not retain it. A payer keeps Credited evidence it consumed as a fold witness until its ArchiveSent step is folded (§4.1). |
| ArchiveSent | Payer verifies matching Credited evidence (credited or burned) and proves removal of the matching pending outgoing descriptor. It may delete the delivered Payment bytes only after a durable Ω covers the ArchiveSent step on its archive branch (§3.2), and never the copies a fee claim still needs (§6.2). Balance, quotas and consumed-credit entries stay unchanged. The delivery verdict comes first: the payer verifies the evidence read-only when it arrives and defers ArchiveSent to an idle drain (§5.3). An ArchiveSent that Advance never selected, planned from an older head, is planned again on the current head under the same request and Credited original; one archive per Send capsule, wallet and Credited original still holds. Replacement requires both custody nonselection and authenticated absence from the permanent operation index. The selected stale entry and plan retain the retired capsule identity until idempotent draft and capsule cleanup succeeds; only then may a replacement plan be published. A batch-only original is retained under the authenticated entry before its immutable draft key is retired. Interrupted cleanup repeats after restart; selected, uncertain or delivery-data-loss operations never replan. |

A Request has no cancellation or expiry that can invalidate an already
committed Payment. A payer's completion is scoped to its still-unused `s`;
the payer's Send retry identity is derived from the Request digest, so paying
the same Request again replays the same Send. Different payers of one open
Request make distinct credits.
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
Payment transitively, through the recomputed Request and package digests, and
binds Ω(pred) and σ_send through `proof_digest`. Conflicting bytes
for a consumed credit are rejected. A proof of absence or a generic signed
acknowledgement is not evidence of credit. A CreditStatus verifier decides
Ω(h), checks τ(h) under `Ω(h).payment_key` over the carried statement and
`proof_digest`, checks that the statement's successor is `Ω(h).head` and that
`Ω(h).wallet_id` and `Ω(h).payment_key` equal the Request's receiver wallet and
the `payment_key` of the Request's receiver credential (credential digests are
not compared), and checks the opening. CreditStatus therefore cannot invent an accepted credit. Its
budget is the 10,034-byte Credited bound (§8). It carries no σ, so it is
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
- An unacceptable quote detected before Send can start a new setup without
  debit. After Send, a newer Request, policy, fee schedule or
  retirement state cannot cancel the recipient's existing claim. Verify the
  historical policy and fee terms proved by Send, not a new quote's terms.
- The receiver may be absent or temporarily unable to store or process Payment.
  Declining a screen or disconnecting does not produce a monetary refusal.
  Preserve the payer's outbox for later delivery. No timeout or negative reply
  permits refund, retargeting or any restoration of the debit.
- The receiver checks its local blacklist when it issues a Request and again
  before it accepts the Payment (§7), so a list it installs after the Request
  can refuse a Payment under that Request. A refused Payment changes no state;
  it is not a monetary refusal, the debit stands, and the payer keeps the exact
  Payment bytes for later delivery.
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
branch; deferring ArchiveSent only holds them longer. Keep consumed-credit IDs, Payment digests, private map
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
bounds from the fixed relations.

**Transactional preparation.** A new request first acknowledges a fixed binding
of its wallet, scheme, request ID, operation kind and exact original digest.
Changed bytes under that ID conflict, including after a refused preparation or
restart. A bound request without a validated plan is Preparing; it does not owe
an unvalidated original and does not authorize a proof, signature or monetary
transition.

Planning constructs map objects in a
bounded, clearing memory workspace. A staged content address is not a durability
acknowledgment. A new preparation that fails native planning before batch
retention leaves neither those variable originals nor unpublished map objects.
After planning, an immutable request-ID recovery batch retains the exact
inputs, source, native choices, plan and objects.
Only after every object and original is durably acknowledged may one manifest
publication select the plan. Uncertain publication reopens the selected manifest
and adopts any present exact batch. Fresh planning is allowed only after definitive batch absence
before plan selection. Recovery never replaces retained choices, rebases a
stale source or deletes possibly shared objects. Every materialized object is
read back from durable storage after the plan publication and before cleanup.
Cleanup removes only the acknowledged staging record. Subsequent validation can
confirm retained objects and proving takes no custody; neither can create new
preparation objects.

The native derivation made by planning is reused through proving within the
same exclusive call. It is never stored, persisted or shared, and it is used only
while the request bytes, source capsule, archive checkpoint, plan choices and
draft it was made from are unchanged; a changed archive checkpoint before proving
is custody loss. A held plan after restart or retry, a recovered batch and a
speculative entry instead replay native validation on fresh custody, and that one
derivation is reused through proving. Before the capsule is published, the
retained draft is checked against the proven successor state on durable custody.
Commit derives the operation again, independently, from the durable plan.
A review's speculative σ_send (§5.1) is proved from its own throwaway derivation, off the
wallet owner, while no payment holds priority; payments wait for it rather than cancel it.
Execution after confirmation plans with its nonce (a Send whose controls need a clock
reading is not speculated), and freezes its σ only for an identical derived statement and
relation; otherwise it proves. A declined or stale speculation is dropped unsigned.

The runtime capacity owner checks the bounded intake workspace before fresh
allocation, and checks memory before reading a retained batch. Fresh admission
includes simultaneous redundant recovery and materialization, archive envelopes,
and index publication growth. This is an admission bound, not an exclusive
filesystem reservation; subsequent provider failures retain their error meaning.
An existing selected monetary outcome still follows exact recovery rather than
a new capacity verdict. These rules remove unvalidated retention; they do not
claim constant storage use or identical physical failure outcomes for all valid
private originals.

**Runtime capacity check.** Before an operation proves its step, and again in
§4.2 step 2 before it commits, the wallet checks the phone it is running on, at
that moment:

- storage: free bytes in its no-backup custody storage cover the reservation
  above plus the fold witnesses the operation adds until a durable Ω covers it;
- memory: memory currently available to the app covers the peak proving memory
  of the operation's step relation and of the lineage relation that folds it.

Both bounds come from the installed relations, never from a phone model. The
proof owner computes each relation's peak proving memory and fold-witness bytes
from that relation's fixed, authenticated descriptor (its domain size and its
column and lookup counts) with one conservative formula. The check adds no field
to the artifact manifest, verifier pack or producer inventory, and needs no
artifact-producer change. Measured peaks and fold times are recorded as evidence
(§8); a measurement above the computed bound is a defect in the formula, which
is fixed in code. A failed check
refuses the operation before commit with a typed `NotEnoughStorage` or
`NotEnoughMemory` result, never a device verdict: nothing is debited or
credited, the receipt or Payment stays deliverable, and the holder retries after
freeing storage or memory. Proving that runs out of memory before commit is
reported the same way and leaves the head unchanged. A phone cannot always
return that typed result: the OS may kill the app for memory (the Android
low-memory killer, iOS jetsam) during proving or commit. That is ordinary
process death (§1.2) and is recovered at the next app start: an operation
whose Advance did not commit leaves the head unchanged and is reported as
interrupted, with its receipt or Payment still deliverable; an operation whose
Advance committed completes from its retained outcome. An OS kill is never a
device verdict, a refusal or a reason to discard a selected outcome. The
capacity bounds stay derived from the installed relation descriptors, with no
artifact change. There is no phone-model
list, device class, roster or published per-model budget; per-phone latency,
memory and energy measurements are recorded as evidence (§8), never as an
admission list. Never rely on platform background-execution time for
multi-minute proving: folds resume whenever the app runs. Fold-witness storage
counts toward the reserved capacity.

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

The payer shows **delivered** as soon as Native verifies the evidence read-only,
before any ArchiveSent. It first persists the exact Credited original. An
ArchiveSent commits a head that needs its own fold before the next Send, so the
wallet defers it. A selected (pending) ArchiveSent always finishes at once. An
unselected one runs in an idle drain, one at a time and never inside a payment
step. The drain runs only when no exchange is open or requested and the fold backlog is
empty, and then only while the phone charges, once 16 ArchiveSent steps are
deferred, or once the oldest is 24 hours old. The wallet re-checks these gates
immediately before every ArchiveSent dispatch. An already dispatched ArchiveSent
may finish; a concurrently opened exchange can wait for its completion and fold.
These admission gates never defer a selected or pending ArchiveSent recovery.

## 6. Ledger boundary, fees and wallet replacement

### 6.1 Load and unload

After completed Bootstrap activation (§3.2), the payer submits an ordinary signed
block transaction containing `KagemushaWalletLedgerActionV1::IssueLoad` inside
`KagemushaWalletLedgerV1`. It fixes the
scheme, wallet, asset digest, expected next ordinal, nonzero request ID, net
amount and any canonical charge quote and beneficiary. Ledger execution compares
the exact asset and ordinal, debits the payer into the scheme reserve, applies
any displayed charge and advances the ordinal atomically. A stale ordinal or
changed retry terms fail. No separate Load signer, publisher service or receipt
publication transaction participates in this operation.

The immutable `KagemushaWalletLoadReceiptV1` records those terms, the payer account digest,
original transaction hash and block height. An exact replay within the original
transaction and height can recover its original result; another transaction or
height cannot reuse that request ID successfully. After a lost response, the
payer queries the original receipt instead of signing another successful Load.
Receipt retrieval reads bounded recovery data from committed State without
reconstructing historical certificates; its result grants no independent
finality or offline balance authority. Retrieval is idempotent; failed delivery
does not refund the deposit or remove its reserve liability. Retirement closes future loads atomically (§6.3).

Native finality verification is implemented in
`iroha_data_model::isi::kagemusha_wallet::load_finality`:
`verify_finalized_kagemusha_wallet_load_v1` returns the opaque
`VerifiedKagemushaWalletLoadV1` only after authenticating the selected global
network and chain, successful external transaction, exact direct instruction
index, payer and complete approved terms. Its receipt is bound to the original
transaction and height. The query's serialized receipt alone is not finality
proof. `Load` must absorb only its exact next ordinal and cannot credit a
duplicate.

The native wallet verifies the receipt block's ordinary BLS CommitQC and counted
successful-Load event inclusion before signing its Load Advance. The selected
signed genesis fixes the first ordered validator roster and proofs of possession.
Each outgoing committee's boundary certificate authorizes the next epoch and its
exact height interval. A certificate outside that interval, a missing transition,
a foreign network or substituted receipt fails. Ordinary intermediate blocks
need no recursive proof or full-history replay.

Activate and Unload use the same direct reader. Each signed attempt is confirmed
by one bounded `KagemushaWalletLedgerFinalityV1` (entrypoint hash, receipt-free
CommitQC certificate, the joined Network output row, and entrypoint and output
Merkle paths) read through the account-authenticated
`/v1/kagemusha/{scheme}/wallets/{wallet}/ledger/{entrypoint}/finality` route.
Activate and Unload emit no ledger event; the certified transaction result is
their outcome. Epoch transitions it needs are read through
`…/ledger/{entrypoint}/epochs/{boundary}` and advance the same wallet-wide epoch
index as Load. Native never walks blocks from genesis, imports a checkpoint, or
treats a missing response as non-inclusion.

Epoch synchronization requests one bounded original boundary certificate at a
time. Only native BLS verification under the already selected incumbent can
authorize its successor; the wallet durably publishes that authority through its
protected manifest before advancing the cursor. Restart restores the locally
selected checkpoint against the independently installed genesis. Older epoch
records remain in the authenticated archive for delayed receipts and folding.
A peer-supplied checkpoint or roster cannot replace this process. Receipt evidence
contains only its own certificate and counted event path, independently of the
chain's age; transport and durable-custody qualification are tracked in NF6.

The offline Load relation binds the exact receipt transcript, monetary effect,
ordinal, recovery-map insertion and credential-bound own Advance signature.
Its two A stages and one W continuation, with one own-receipt signature leaf and
no own σ leaf, retain monetary proof obligations without a finality proof or
carried finality accumulators. The existing selected
trust model (§2.1) requires the released app on a stock uncompromised OS to perform
native verification before requesting that signature. Consequently, offline
funding lineage relies on that application/provider assumption; PLONK does not
independently prove the BLS finality check. A caller verdict never substitutes for
the mandatory native pre-signing check.

The native certificate reader authenticates consensus execution under at most
`f` faulty committee members. Honest validators validate normal block execution
and the lag-two schedule before signing. Light verification does not reexecute
the VM, establish possession of the full block, or replace native storage custody.
Fresh Load preparation authenticates its exact retained receipt evidence before
Advance selection. An unsigned Selected restart may sign only that already
authenticated capsule; it does not accept new evidence or credit another Load.
A completed retry returns the exact retained output. Receipt evidence is not part
of the 10,034-byte offline Payment envelope.

TODO(G3/G5): complete the [native finality goals](kagemusha_native_finality_goals.md),
rebuild affected A/W/Omega keys, and qualify Load, subsequent Receive/Unload and
the common terminal catalog. Measure real complete Payment envelopes against
10,034 bytes and native verification on physical phones. Historical recursive
finality runs and structural fixtures do not establish those gates.

`Unload` subtracts a chosen positive amount, increments `next_redeem` and creates
a ledger-directed claim with a domain-separated nullifier derived from scheme,
wallet and redemption ordinal. The ledger verifies the complete committed
package, including Ω of its predecessor and the §3.2 consumer checks, and pays
the face amount exactly once: the bound account receives it in full when the
online charge is zero; otherwise the displayed quote's charge is withheld for
its fixed beneficiary and the account receives the remainder. Unload is possible only from a
folded head, and its amount is bounded by `balance − burned_total` with
Ω(pred)'s `burned_total`. Retry returns
the original result. No timeout restores an uncertain redemption to the wallet.
Retain the claim until finalized payout. Native records a payout only from
authenticated successful execution of a signed transaction whose explicit
instruction carries the exact claim bytes, verified by the direct finality rule of
§6.1. Any account may submit that transaction: the claim's own validation binds
the paid account to its credential, and relaying never changes or retargets it.
An authenticated rejected execution of one envelope is retained for that envelope
only. It never restores offline value, releases, replaces or retargets the claim;
a new envelope carries the identical claim and the ledger's nullifier pays it at
most once. The remaining wallet balance continues
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
§5.3 runtime capacity check keeps value from arriving on a phone that lacks the
memory or storage to fold it.
Keep the old wallet's key, private state, replay map and unresolved Payment and
claim bytes. Zero spendable balance does not mean its custody data is disposable.

Retirement closes new Request quotes and funding, while preserving existing claims:

1. Commit a proven `Retiring` transition from a folded head (§3.1). It issues
   no new Request quotes, but
   continues to Receive valid Payments under previously signed quotes, including
   Sends that commit later. It may Ordinary Load receipts already issued, Send or Unload
   remaining value and finish delivery, fee and redemption claims; it pays other
   receivers' open Requests as usual. The lifecycle
   never reverts to Active.
2. Submit a ledger-control instruction carrying the complete Retiring package,
   or a later complete Send or Unload package proving that lifecycle and its
   `next_load`. Each of these commits only from a folded head and carries its
   predecessor Ω (§3.1). In one transaction, the ledger
   checks that no receipt at or above that ordinal exists and permanently
   disables further loads. If a receipt exists, the instruction fails and the
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
unactivated/no-receipt condition in §3.2.

There is no seed restore that recreates spent offline value on another phone
or automatic issuer reissue. The issuer cannot reclaim or reissue a committed
Payment on timeout or reported delivery failure. Replacement does not renew
regulatory quotas.

## 7. Explicit regulatory controls

Only the following signed controls and the local account blacklist (below) may
restrict future use. The credential
binds the scheme's permitted controls and their activation semantics. A wallet
can accept a newer authenticated scheme policy, fee schedule or certificate via
a peer; learning it does not require an online call unless an enabled rule
below explicitly requires freshness.
Policies cannot retroactively undo completed credit or impose an unannounced
new connectivity control on an existing credential.

`RefreshPolicy` is a proven, locally committed transition for authenticated
policy updates, time reanchoring and lease renewal. It preserves wallet
identity, balance, ordinals, consumed-credit entries and pending obligations;
advances policy epochs
monotonically; and cannot reset consumed quota or backdate accepted time. A
QuotaShare refresh requires every new window to be longer
than the credential's maximum anchor response time and rebuilds the quota-usage
array for the new windows, checking only the 64 slots of the old array and of the
new share: a key held before keeps its window end and carries its usage; a newly
introduced key starts at zero and is admitted only if its window starts no earlier
than the new accepted-time floor, except at the wallet's first quota allocation;
and a charged key may be dropped only once its window has ended by that floor
(wire record §3.3). Any
replacement credential binds the same incarnation. Verify the appropriate
policy/enrollment signer and the existing credential's permitted controls.
Obtaining a renewal online is necessary only for an enabled control that needs
it. Cached or peer-carried policy updates use this same transition; they never
reanchor time (below).

| Control | Behavior when enabled | Connectivity consequence |
|---|---|---|
| Daily/monthly sending quotas | Debit gross `amount + fee` permanently against both configured windows at Send. Delivery and cleanup do not replenish quota. Issuer allocates wallet shares so their sum cannot exceed the account allowance in any window. | No routine sync while the signed quota and trusted time remain usable; loss of the time anchor may require renewal. |
| Attestation lease | Require renewal before a future Send after the signed expiry. Accepted balance and already committed exchanges remain owned and recoverable. | Renewal is the configured online requirement. |

While a control is enabled, σ_send enforces it against the head-committed
quota-usage root, quota windows root and share expiry, maximum anchor response
time, accepted-time floor and lease fields. Every receiver
therefore verifies the payer's controls before completion: it selects σ_send's
verifying key by Ω(pred)'s enabled-controls mask (§3.2). The quota share's
window tree is a `P` tree (§3) whose root the regulatory-policy signer signs;
the quota-usage array is the wallet's own depth-6 `P` tree, aligned with the
window tree's slots. Native checks
against authenticated stores also run inside the serialized Advance section (§4.2 step
2). Controls are off by default and then add nothing to σ beyond the check that
the enabled-controls mask is empty.

**Local account blacklist.** Each wallet may hold one list of account digests,
signed by a RegulatoryPolicy-role key ([wire record](kagemusha_wallet_wire_v1.md)
§3.3). Its entries are ordered by the integer value of each account digest's two
limbs, and its signed entries root is a `P` tree (§3). The app obtains a list
online and installs it locally; peers never relay it. The native wallet
authenticates the certificate set, role, signature, scheme, entry order, count
and entries root, and replaces a held list only when the new `list_version`
strictly increases. Installing a list is not a wallet operation: it has no
Advance, receipt, state change, fold or lineage proof. While a list is held, the
payer refuses a Send to a listed receiver account at Send preparation and again
at commit, before the irreversible debit; the receiver refuses a Payment from a
listed payer account before any mutation (an open Request names no payer, so
issuing one consults no list). With no list held, no account is refused.
Nothing about the list is committed in wallet state, proved by any σ, Λ or Ω, or
carried in a Request, Payment, PayerCompanion, Credited, PolicyData or other peer
message. Lists are best effort: different phones can and will hold different
lists, there is no cross-device consistency requirement, and a later list never
invalidates a completed payment. A list has no age rule and never requires
reconnection. No list distribution path exists.

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
is counted in every window it touches. While quotas are enabled, every window of
an installed quota share is longer than the credential's maximum anchor response
time (checked when the share is installed), and a Send's accepted interval is no
wider than that bound, natively and in σ_send, so it touches at most two windows
of each kind. The monotonic clock must keep running
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
windows and expiry, and unused expired shares are not retrospectively spendable:
the share's expiry is a core field, and σ_send refuses a Send whose accepted
upper time has reached it.
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
| PayerCompanion (the payer's `CredentialV1` and its issuer certificate) and simple session-control frame | 2,048 |
| Request, Payment or Credited (a Receive package, or CreditStatus {statement, `proof_digest`, τ, Ω, opening} of a folded head), with required dependencies | 10,034 each |

Payment uses the compact §5.1 layout: the unique signed Request fields and
signature, and {statement, Ω(pred), σ_send, τ_send},
with Ω in single-parity transport form. The σ and Ω byte caps are the exact
proof lengths that the frozen artifact allowlist (§3.2) records. Under R9 they
satisfy `|Ω| + |σ_send| ≤ 10,034 − F_payment`, where `|Ω|` is the Ω
transport-proof length, `|σ_send|` the largest σ_send length in the allowlist,
and `F_payment` every other byte of the largest valid Payment (1,394
bytes with the single-owner Request representation, leaving 8,640 bytes for
both proofs; the wire record pins it). The current source catalog admits at most
3,520 bytes for each σ and 5,120 bytes for the Ω transport. Payment admission
checks these individual capacities as well as the independent joint and complete
frame bounds before a consuming operation can Advance. Unused capacity in one
role cannot enlarge the other role. Frozen keys still require their exact lengths.
Artifact generation and measurement must establish that every admitted source
fits these capacities and the complete 10,034-byte envelope.
The same applies if CreditStatus cannot keep Credited within 10,034 bytes, for
example a fallback in which Credited carries only the Receive package. Its
opening has exactly 32 siblings, so a CreditStatus is a fixed number of bytes
plus `|Ω|` (the wire record pins it). A Lineage message is smaller than the
Payment that carries the same Ω.

Proofs summarize lineage; do not ship a certificate or transaction chain whose
size grows with hops. Payment reconstructs the exact signed Request body. σ_send binds
its exact fields; both wallets verify the signature natively, and the
receiver's Λ_recv verifies it in-circuit. Credited binds the full Payment
digest. ArchiveSent consumes that evidence locally and creates no additional
peer-message round trip.
A payer refuses a Request for a scheme it does not hold. Malformed unauthenticated
traffic is dropped. A setup error before Send carries no monetary authority;
a decode, version, policy or capacity error after Send cannot reverse the debit.
Valid committed Payments retain their recipient binding and historical terms.
Each package contains the certificates and authenticated terms its verifier
needs beyond the preinstalled scheme roots and the fixed artifact set. For a
Payment, the receiver's own credential, fee schedule and certificates are bound
by digest in the Request body, and the payer's credential and its issuer
certificate travel beside the Payment in the PayerCompanion. A missing dependency cannot trigger an
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
durable commits. Report separately, per measured phone: the time until the value
is ready to spend onward (fold), and tap-to-done including setup and the
confirmation dwell. Measure Request issuance, cold startup and payer
receipt-confirmation latency separately. Schemes with enabled controls report
latency separately. With the fixed quota-usage array (§3), the quota σ_send is
estimated at about 350 permutations, a single-lane shape near 3.4 KB; its
proving time, targeted well under 1 s, is to be measured. Record failures and slow trials as
well as successes. The 10,034-byte bound is a format requirement;
2 seconds is an optimization target. Neither is a claim about today's code.
Work on integration and optimization can proceed together; missing a latency
target does not authorize skipping proof or durability work.

## 9. Implementation ownership and retirement

Use the current owners below; build missing integration against the canonical objects. The detailed capability inventory and deletion
checks are in [the evidence appendix](kagemusha_single_design_evidence.md).

| Owner | Current responsibility and remaining work |
|---|---|
| `crates/iroha_core_zk/src/kagemusha_wallet_advance_v1/` and `kagemusha_wallet_state_v1/` | The shared state machine retains native operation originals, permanent replay indexes, source-selected fold witnesses and checkpoints around the existing Advance provider. Its background worker performs ordered native folding with cooperative payment preemption. Qualify the complete installed proof catalog, funded exchange and custody/recovery lifetime on stock phones; component fixtures do not establish these outcomes. |
| `crates/iroha_kagemusha_proof/` | Native step, lineage and transport relations use PIPA-v1 with the P-256 and recursion gadget owners. Qualify the complete authenticated artifact set and real operation compositions, including Load receipts admitted through native BLS verification before Advance. The superseded vendor trees and temporary differential oracle are deleted; independent vectors and mutation coverage remain under the [native prover migration inventory](native_prover_migration_inventory.md). |
| `crates/iroha_plonk`, `crates/iroha_plonk_gadgets`, `crates/iroha_pasta` | The PIPA-v1 proof system: arithmetization, transcripts, prover, verifier, accumulation and `decide`, gadget chips, Pasta fields, curves, MSM and Poseidon ([PIPA-v1](plonk_ipa_v1.md)). |
| `iroha_crypto`; canonical wallet custody types | Use the current encryption and recovery primitives with canonical caller contracts and domain bindings. The retired KAGEMUSHA crypto module is deleted. |
| `crates/connect_norito_bridge/` | C/JNI adapters expose opaque native state/proof handles, Advance platform dispatch and retained retry originals to thin SDKs. Qualify the current rebuilt native artifacts and complete installed wallet flow; the superseded coordinator and per-payment service phases are deleted. |
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
This first release ships one current implementation and authenticated artifact
format. Retired testnet releases do not justify retaining an old verifier,
decoder, key fallback or monetary engine. Regenerate disposable testnet state
from the current signed genesis and catalog when its protocol inputs change;
historical test artifacts remain evidence only.

### 9.1 Cutover sequencing

The first release uses chain-only Android E1 attestation, the closed E5/E6
exchange, the signed client runtime and bridge ABI 31. No first-device
Google authentication or Play Integrity input remains. Fact bit 9 is reserved
zero for every credential evidence record, including retained enrollment
evidence and renewal fresh evidence. Native record validation and the
credential proof relation both reject it; there is no historical-credential
exception or compatibility decoder.

The credential, 56-byte evidence record, enrollment challenge and Abandonment
frame retain their field layouts. The accepted evidence predicate changes the
monetary circuit, so its proving originals and all dependent recursive keys
must come from current source. Candidate originals may be reused only when
complete current-source admission succeeds; changed source fingerprints must
regenerate. The completed key set and inventory determine a fresh relation,
scheme and signed artifact manifest. The release binds that complete carrier,
its genesis and signed runtime, and builds validators and all mobile Native
slices from the resulting current source.

The mobile artifact carrier stores each `wallet-originals/<raw-sha256>` file as
exactly one lossless zstd frame. The signed catalog continues to bind the actual
decoded original; compression does not change a proof, key, relation or scheme.
The sole proving-key original is compact: `PIPACPK1 || descriptor_digest32 ||
LE32(vk_bytes) || canonical_vk || copy_digest32 || source_fingerprint32`. Fixed
and permutation evaluation tables are reconstructed from the installed native
witnessless circuit. Import checks descriptor, selectors, copy mapping and the
complete source fingerprint, then checks every original VK commitment before
returning admitted metadata or constructing a proving key. Metadata admission
does not construct proving FFTs, masks or coset caches. The fingerprint is untrusted lookup data; it cannot
grant source admission or replace commitment checks. Existing opaque admission
seals remain nonserializable and are minted only after complete native source
and commitment admission. A bounded private memo on each immutable pinned
parameter owner may reuse previously computed commitments for identical public
columns; original VK points and declared fingerprints cannot populate it.
Every source and VK commitment is still checked, and the complete operation
graph is admitted before granting the wallet capability.
Each pinned parameter owner also keeps two bounded, process-local
verification memos (least recently used first out), filled only after
acceptance and never from rejected, undecidable or cancelled work, prover-side
MSMs, batch decisions or caller-supplied points, digests or flags. The first
holds `<s(u), g>` keyed by the exact canonical challenge bytes, inserted only
by an accepted generator-claim or accumulator decide or production full
verification; every decide still compares its claimed `G` on every call, so a
false claim with the same challenges is rejected and a correction still obtains
the true point. The second holds full SHA-256 keys over the curve, `k`, the
descriptor profile and digest, the key's `transcript_repr` and SHA-256 of its
bytes, every length-framed instance and the exact proof bytes; production full
verification of byte-identical inputs on the same owner returns that earlier
acceptance after the structural checks and a cancellation checkpoint. Oracle,
filtered, succinct and batch paths never use either memo. Neither memo is
serialized, persisted, exposed over FFI or shared by independently admitted
parameters, and neither changes a verdict: every wallet, custody, binding and
allowlist check above the proof system still runs on every call.
One process-local admitted-graph memo in the Native bridge may reuse the
complete admission of the last fully successful installation for byte-identical
originals: SHA-256 over the eight exact runtime originals, each length-framed,
plus the kernel identity of the carrier root, with the whole framed key
compared on lookup. Every attempt still authenticates its signed base,
selection and genesis and checks every carrier metadata, layout and
transport-selection original first. A hit then requires the stored pack's
exact bytes and installation identity (an exact equivalent of loading it
again), repeats the other installed-pack checks of a load, re-authenticates
the producer inventory, requires the same transport rows and root object, closes
custody over the reader's observed originals and re-hashes every stored frame
against its transport identity, and only then builds a fresh provider, custody
root and owner. It shares the same installed pack, pinned parameter owners,
qualified sources and carrier reader; it holds no provider, custody, key or
enrollment state, and the sources' verify-once memos are reused by a later
installation in the same process for mathematical validity only. It mints no
seal, grants nothing and is never serialized,
persisted or exposed over FFI. It is stored only after complete success, is
never reused once a live read through its reader has failed, and is evicted on
a key mismatch, a refused revalidation or an INVALID or custody-loss result. It
shortens in-process retries only; a restart qualifies again.
This representation changes original hashes and therefore requires a newly
authenticated catalogue and scheme; it does not change the monetary circuits
or proof verification. Dense proving-key originals have no production fallback.
The [compact artifact goals](kagemusha_compact_artifact_goals.md) track measured
size, adversarial checks, offline operation validation and delivery.
The closed `iroha.kagemusha.wallet-artifact-original-transport.v1` JSON has, in
order, `schema`, mandatory `encoding: "zstd"`, and `walletOriginals`. Each row has
`bytes`, `sha256`, `storedBytes`, `storedSha256` in that order. Rows are nonempty,
unique and ascending by lowercase raw SHA-256; canonical JSON ends with one LF.
There are at most 12,288 rows and 32 MiB of JSON. Each raw original is bounded by
1 GiB, each stored frame by 1 GiB plus 4 MiB, and the decoder window by 8 MiB.

Delivery and resume use the stored extent/hash and preserve the raw-address
filename. Native retains no-follow private ancestry and sealed file custody,
verifies the exact stored identity, rejects extra/skippable/concatenated frames
and trailing bytes, and checks exact decoded length/hash before returning the
final declared byte. It also refuses changed or missing previously observed
originals on reopening. Decoding streams in bounded memory without a decoded
disk cache. There is no raw mobile fallback. Raw directories remain the distinct
offline compiler and authenticated candidate input format. Repackaging verifies
the pinned signed pack/catalog and every original, preserves those originals,
and recomputes transport and financial metadata; the signed runtime must select
those exact recomputed metadata bytes before publication. Source reconstruction
and wallet installation remain mandatory after lossless decoding.

Nothing in this revision is deployed piecemeal. The cutover is one coordinated
change, and the release driver builds and releases it:

1. **Bridge ABI 31.** `connect_norito_bridge` deletes the first-device
   authentication-key C/JNI exports (`first_device_auth_key_v1.rs` and its JNI
   adapter), its enrollment `prepare_request` takes the Android chain only, and
   the runtime capacity results of §5.3 become typed. Abandonment returns an
   explicit result, `LocalAbandoned` for the §3.2 no-marker form or
   `Abandonment(frame)` with the exact retained frame for the marker form.
   Refusals carry the closed §2.4
   codes. The first-device authentication and Play Integrity token inputs leave
   every startup consumer together (step 2). The export inventory changes
   accordingly. The current ABI also carries open-Request setup, Payment-companion
   setup 55 and verified-delivery setup 54. ABI 31 artifacts refuse older callers;
   there is no compatibility export.
2. **`firstDeviceAuthentication` is removed everywhere at once.** That selection
   carries a Google OAuth client, a Play Integrity cloud project and a second
   attested sign-up key. It goes from the signed v7 runtime the release driver
   composes; from Native installed selection (`installed/selection.rs` and
   `selection/bpng.rs`); from BPNG Core's runtime projection, together with its
   Play Integrity secret; from the Android app's first-device bootstrap and
   schema; and from the iOS runtime decode. Removing one alone breaks startup,
   because all current consumers require the same closed runtime field roster.
3. **E1 policy and issuer.** These land together: the Model's Android app and
   enrollment arms of the [enrollment policy](kagemusha_wallet_enrollment_policy_v1.md)
   and the regenerated `fixtures/kagemusha/wallet_enrollment_policy_v1_vectors.json`; the
   issuer worker, its configuration and the Python verifier admitting under §2.2
   with no Play Integrity token or hardware selector; the E5 `PlatformEvidenceV1`
   and E6 `IssuerEvidenceV1` Android arms carrying the chain only; the closed
   §2.4 refusal codes, exported by Native and relayed unchanged by BPNG Core and
   the Kotlin and Swift SDKs, which also keep a withheld E6 delivery distinct
   from a terminal Refused outcome (§2.4); and an issuer that never sets fact
   bit 9; native evidence validation and credential circuits reject that reserved bit.
   - Native core replaces the old Model policy arms, the E5/E6 carriers, the
     issuer worker configuration, the worker's Play Integrity fact requirement
     and the hardware-selector coupling in the credential and pre-key owners,
     and implements the §3.2 local abandonment safeguards and atomic quota
     accounting.
   - The Python verifier implements root and adapter-profile dispatch (the
     `google` and `huawei` profiles), the rollback-protected operator denylist,
     the revised chain checks of the enrollment policy, the exact chain-only
     evidence digest, persisted typed refusals and the §2.4 recovery states.
     Retryable pre-decision outages resume the exact retained claim; uncertain
     effects remain Unknown and never authorize another issuance.
   - The Kotlin SDK replaces the token-taking `prepareRequest` and the
     byte-only `abandon` with the chain-only request and the explicit
     abandonment result. Its StrongBox fallback carries only the
     hardware-choice hint into a freshly authorized slot under a new challenge
     and never reuses the old generation grant (§2.2).

   The issuer owner selects the reviewed policy originals (the Google RSA and
   CA1 SPKI pins, signer set, minimum version and patch floor; the Apple root and
   App ID) and the operator denylist in this step. The `huawei` root row follows
   as a data-only policy change once genuine chains qualify it (§2.2). The Iroha
   READMEs that still describe Play Integrity change with their code.
4. **Mobile Native rebuild.** The release driver rebuilds Native for the three
   Android ABIs and the Apple xcframework from the cutover source, and the
   Android and iOS apps bind ABI 31. No other work package builds, promotes or
   deploys mobile natives.

**Cutover acceptance.** Each case below passes against the cutover source and
is recorded in the [checklist](kagemusha_evidence_gate.md) with its chain or
device provenance. These are acceptance tests of the cutover, not a release
approval ceremony (§10):

- Huawei: the `huawei` profile is qualified, and its root row admitted, only
  when a genuine chain from a post-2019 Huawei phone without Google Mobile
  Services enrolls under it. Until then no Huawei root is pinned, and a chain
  to an unpinned root, Huawei's included, is refused with code 5.
- Reserved evidence: bit 9 is refused for every platform, in both records of
  initial credentials and either record of renewed credentials. The native
  validator and actual credential circuit both exercise this rejection.
- Validity: an expired certificate in a remotely provisioned chain is refused,
  including one that chains to the Google RSA root; an expired certificate in a
  documented factory-provisioned chain under that root is accepted.
- Injected extensions: a key description outside the trusted attestation
  certificate or duplicated, a provisioning information extension that is not
  immediately above the key description, and an unknown critical extension are
  refused.
- Denylist: a listed serial or SPKI is refused with code 6. Two cases are
  tested separately, as the [enrollment
  policy](kagemusha_wallet_enrollment_policy_v1.md) update rules state. A
  candidate update that fails authentication or is stale or altered (a lower
  sequence, or the current sequence with other bytes) is rejected, and the
  intact authenticated current denylist stays in force and keeps deciding
  verifications. A missing, unreadable, malformed or inconsistent active
  denylist custody or retained sequence record makes verification
  `Unavailable`, never an empty list.
- Signer and version boundaries: one and four signers, a signer outside the
  set, the minimum package version and one below it, every documented
  attestation and KeyMint version pair, an undocumented pair and attestation
  version 1.
- Outcomes: an outage before any effect resumes the same claim; an uncertain
  effect is Unknown and never yields a second credential or a second Apple
  counter consumption.
- Delivery after issuance: an account freeze or `NotApproved` observed at E6
  delivery, and an eligibility-provider or issuer-storage outage there, each
  withhold delivery (code 11 or 12, or `Unavailable`) while the Issued outcome,
  the exact retained E6 and the quota share stay retained. Neither forces
  abandonment, restarts E1 or signs again, and the wallet keeps its slot and
  marker. A later approving observation, including one after the E1 challenge
  lifetime, returns the same E6 bytes.
- Abandonment: a delayed generation result after local abandonment; unavailable
  or uncertain storage and a lost marker, which write no record; races between
  local abandonment and Bootstrap selection, marker installation or generation
  recovery; the API 26–30 spent grant and unknown lookup; an API 26–30 crash
  after Slot publication and before intent creation, which local abandonment
  accepts from its authenticated pre-E2 evidence while the null lookup stays
  unknown: the slot reconciles to `SlotAbandoned`, no grant is issued and the
  alias is never regenerated, and the same window with a missing Client,
  Accepted permit or Slot original, or an unreadable generation-attempt,
  marker, E5, E6 or initialized-state record, reports `Unavailable` and writes
  nothing; concurrent enrollments against the last quota share; and quota
  release only on finalized successful Abandonment.
- Capacity: `NotEnoughStorage` and `NotEnoughMemory` before commit, and an OS
  kill during proving and during commit, each recovered at the next app start
  as §5.3 states.
- Frame cap: the maximal app and enrollment policies, encoded with the actual
  Norito encoder, fit the 1,024-byte frame cap of the enrollment policy.

Native implements the §3.2 no-marker abandonment from
progress `EnrollmentProgressV1::Pending` or from a no-marker slot whose key
lookup is unknown (local, no ledger bytes, a holder-abandoned reason), with its
four safeguards, including authenticated pre-E2 evidence in place of a
key-probe-derived `Empty`, and a reconciliation order
that checks the abandoned-slot record before any generation recovery; the rule
that a fresh slot does not wait for ledger acceptance of an Abandonment; and the
reservation of every issued or potentially issued quota share until finalized
successful Abandonment. The enrollment-owner and issuer-worker tests exercise
these rules, including restart, uncertain storage, delayed generation and
exact retained outcomes. Device qualification remains separate from these
component tests.

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

### 10.1 First-release completion sequence

The remaining work is executed in the following order, with independent proof,
ledger and measurement work continuing while a platform dependency is resolved.
The [first-release execution goals](kagemusha_first_release_goals.md) map these
requirements to the current source, harnesses and external dependencies.
This is the first release: replace defective layouts, APIs and constructions
directly, regenerate their artifacts and consumers, and remove superseded paths.
Do not preserve compatibility decoders, old-key fallbacks or a second monetary
implementation. The stock-phone, hardware-key, shared-native-core, irreversible
offline payment, exact-byte recovery and offline onward-spending requirements
remain unchanged.

| Priority | Existing goals / owner | Required completion evidence |
| --- | --- | --- |
| 1. iOS rollback and release | G2 / native provider and Swift storage | Trace Selected marker, journal, signature, anchor and externally available Payment bytes. Reproduce interrupted/ambiguous writes, restart, concurrency and replay. Determine which backup/restore schedules supported stock-device operations actually permit. Establish the platform persistence guarantee before claiming that a released Payment precludes a competing successor from restored state; Keychain readback alone is insufficient. Preserve any residual counterexample and identify the smallest unavailable primitive or required design decision. |
| 2. Complete monetary lifecycle | G4/G5, NF1–NF6 / wallet, node and SDK | From one source/artifact candidate, perform enrollment → activation → funded Load → A pays B → B pays C offline → Unload → ledger payout. Cover supported selectors, Receive folding, ArchiveReceive, ArchiveStatus, fees and enabled controls; crashes, lost acknowledgements, exact retries, duplicate credits, conflicting inputs, invalid proofs, stale state and restart must preserve conservation, committed payments and once-only payout. Retain actual four-validator and physical Android/iPhone results separately from software fixtures. |
| 3. Proof correctness and privacy | G3 / proof owners and independent reviewer | Run genuine-proof native/circuit binding mutations for every consuming operation, including Ω opening and both exposed accumulator decisions at acceptance boundaries. Complete [C12](kagemusha_recursion_soundness_v1.md) for the actual recursive setup, three-Q prefix, RP57 interfaces, exposed challenges, adaptive histories, checkpoints, retries and joint folding/publication, with explicit assumptions and independent review. Regenerate affected artifacts after a construction change. |
| 4. Size and performance | G1/G4/G7 / native, SDK and carrier owners | Retain each genuine bounded message's exact canonical envelope and demonstrate ≤10,034 bytes across supported variants. Measure cold opening, peak memory, retained storage, durable payment completion and the separate time until received value is spendable. Evaluate the two-second p95 requirement on a declared physical-device/OS/carrier population; preserve failed, cancelled and slow trials. Stand-in proofs and host timings do not qualify phone payments. |
| 5. One verified delivery | G6/G7 / native and managed consumer owners | Record source closure, lock/build inputs, catalog/key/native-library/SDK hashes and exact test commands. Rebuild matching consumers, run focused regressions followed by complete required suites and release checks, and update current specifications/status/public documentation. A changed source candidate requires affected evidence to be repeated; compilation or another candidate's results do not close a requirement. |

The completion report names concrete defects and their regressions, exact source
and artifact identities, network/device results, size/resource/timing measurements,
completed cryptographic arguments and their assumptions. Every remaining item
names its precise external dependency and smallest necessary decision. A
component passing its tests is evidence for that component's recorded scope,
not completion of this sequence.

## 11. Verification and present implementation truth

The checklist covers conservation, competing successors, receipt substitution,
permanent replay protection, irreversible Send, exact-byte redelivery, lost
delivery evidence, crashes, storage errors, clock rollback, stale policies,
genuine multi-hop proofs and physical carriers. It also covers:

- native-vs-circuit acceptance equivalence (differential and fuzz tests over
  every §3.2 equivalence object);
- the poison-pill burn branch, including a duplicate `credit_id` with the same
  and with another Payment digest (the first credit-digest leaf stays, and
  archiving the second Payment is rejected natively or takes the no-op branch),
  a corrected claim of a failing accumulator, and the ArchiveSent no-op branch
  with a later re-archive;
- a σ whose `burned_total` or pending-outgoing input is the stale core value
  instead of Ω(pred)'s;
- a Request whose payer differs from Ω's wallet, and a relay-rewritten payment
  key or credential digest in Payment;
- a tampered deferred value, a mixed history, a wrong relation identity, and a
  wrong VK for the operation tag or the enabled-controls mask;
- shared native and in-circuit vectors for `P`, the `P_bytes` packing
  (including empty input and 31-byte chunk boundaries) and every element list
  (§3);
- a signature over anything other than the 32-byte Poseidon message of its
  body and domain, or made in a no-digest mode, which is rejected;
- indexed-tree vectors: the empty tree, successive insertions at the next free
  index, membership, non-membership through the sentinel and an interior low
  leaf, the ArchiveSent removal, and a forged low leaf or an occupied target
  slot, which is rejected;
- the local account blacklist: entries whose byte order and limb order differ;
  a Send refused before the debit because the payer's list contains the
  receiver; a Request refused, and a Payment refused before any mutation,
  because the receiver's list contains the payer, including a list installed
  after the Request; a list install whose `list_version` does not increase or
  whose certificate set, role, signature, scheme, entry order, count or root
  fails; two phones with different lists; and a payment with no list held;
- the quota-usage array: in-place charges at the touched windows' slots, a
  repeated or misaligned slot, the refresh rebuild with its end, drop and
  introduction rules and the first-allocation exception, a Send at or after the
  quota share expiry, a share whose shortest window is not longer than the
  maximum anchor response time, and a Send interval wider than that bound;
- a Request quoted before the receiver's credential renewal and received after
  it, with CreditStatus matched by `wallet_id` and `payment_key`, and a
  receiver credential with another `payment_key`, which is rejected;
- a σ successor root that differs from the authenticated store, a stale native
  store against the head roots, and a receipt that fails self-verification;
- crash and restore between commit and fold, and fold-witness loss;
- duplicate delivery during a σ_recv re-prove;
- the §9.1 cutover acceptance cases: E1 admission under each adapter profile,
  rejected stale or altered denylist updates and unavailable active denylist
  custody, the §2.4 recovery states, withheld delivery after issuance, local
  abandonment races and storage uncertainty, the API 26–30 crash between Slot
  publication and intent creation, quota reservation, and capacity
  refusals with OS-kill recovery.

Update the finite-state model to match this exchange; a model's provider
assumption is not proof that a phone API implements it. Each result identifies
its code, artifacts, devices and trust assumptions.

The candidate implements the G1 objects, Poseidon transcripts, fixed 64-slot
quota usage, share expiry and Send time-span
bounds. Shared Rust/SDK vectors and
native σ relations cover all four Send masks and the Receive selector. The
codec budget reserves 3,520 bytes for every σ; the fixed Payment overhead is 1,394
bytes, leaving at most 5,120 bytes for the complete transported Ω. Final admitted
proof lengths must be measured together after descriptor regeneration. The retired
Reserve/Commit monetary engines and mint-finality authority are deleted.

Native PIPA-R/PIPA-AS, total soft circuit verification and authenticated indexed
map components, per-operation relations and Q → A → Ω composition are
implemented. Load authenticates ordinary Sumeragi BLS finality before Advance;
retired recursive-finality proofs supply no authority. The current complete
catalog test expects 22 routes and 16 programs, including ordinary and renewed
Receive routes over the single Receive sigma selector. The complete current
catalog still needs matching strict profiles, regenerated registry DATA and
genuine capacity/size qualification against the 5,120-byte Omega transport cap.
Changes to proof constraints and fixed input capacities require regenerated
descriptors and genuine proofs before artifact freeze; earlier component
geometry and the historical 52-route catalog do not establish this result.

The shared Rust wallet coordinator now retains exact outputs, fold witnesses,
checkpoints and permanent replay indexes around the existing durable `Advance`
provider. Its component tests exercise interruption, recovery and missing or
rolled-back archives. Native storage uses retained directory descriptors and
identity-checked publication. The coordinator requires a real authenticated
proof provider. C/JNI and managed SDK lifecycle paths and the seven-stage host
journey are implemented. The recorded captured journey completes
Bootstrap/Activate/Load, A → B → C → Unload, archive restart/replay and local
certified settlement/confirmation with an engineering issuer, simulated payment
hardware and a local committee. That result does not qualify the changed source,
four running validators or physical phones. Current harnesses also assert a
fresh-ID duplicate Receive after receiver restart and reverse spending of
received value through the renewal continuation; their matching execution
remains required. The iOS multiple-anchor-write-loss counterexample remains
explicitly unqualified until the supported platform persistence/key boundary
excludes it. Component tests do not demonstrate a complete phone payment, the
two-second p95 requirement or physical-device latency, energy, durability or
memory compliance. The [current evidence checklist](kagemusha_evidence_gate.md#8-recorded-results)
distinguishes executed component checks, diagnostic hard failures and outstanding
qualification.
