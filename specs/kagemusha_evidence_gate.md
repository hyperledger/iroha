# KAGEMUSHA verification checklist

Status: working checklist, 2026-10-16, for the split-lineage proposal and its
accepted native BLS Load-finality amendment. This document records useful checks for
[the single protocol](kagemusha_single_design_proposal.md). It is not an
approval process and does not block use, production integration or deployment.
The filename is retained for existing links. Section 8 distinguishes current
requirements from historical component checks; complete protocol and physical-device qualification remain open.

The selected conditional source arguments cover reachable valid preparation, the
integer, hash, tree, signature and recursive-verifier kernels, complete group
arithmetic (GROUP), finite Strict checking (K-check), and common-template causal
transfer. The [logical composition](kagemusha_c12_composition_v1.md) includes
setup before pins and causal private-byte materialization under one ideal raw
setup oracle, with matching valid source witnesses and exact retained originals.
Applying that model to deterministic BLAKE2b is an explicit instantiation
assumption, not a theorem conditioned on literal release pins or a requirement
for a new simulator executable against a chosen installed key.

Each source candidate, its admitted catalog and matching native/managed
artifacts require a coherent join and their own qualification. The 16 October
captured candidate has passing strict profiles, compiled registry inspections,
native builds and host JNI tests. The earlier catalog and build-storage failures
recorded in section 8 retain their historical scope.
Genuine four-validator monetary execution, matching SDK artifacts, physical
carrier measurements and physical-to-logical storage/refusal refinement remain
required. Mathematical source arguments do not establish machine-code or
physical failure behavior. The initial phones are Pixel 6 and the connected
iPhone 16 Pro Max. Current-candidate iPhone enrollment must retain its actual
App Attest evidence. Payment release still requires a retained nonrollback
anchor excluding the old wallet head, or a guarantee that losing that anchor
makes the same payment key unusable. If both anchors are lost while old wallet
files and the same payment key remain usable, Keychain readback alone does not
establish that boundary.

Runtime signature, proof, authorization, replay and durability checks remain
part of the protocol. Removing a release gate does not make an invalid
payment valid or make an unimplemented security property an established fact.

## 1. What the evidence should distinguish

A state package contains its step proof `σ` and provider receipt `τ`. Send,
Unload and Retiring commit only from a folded head and their packages also
carry the lineage wrap `Ω` of that predecessor; Bootstrap, Load, Receive,
ArchiveSent and RefreshPolicy may commit from an unfolded head and carry no
`Ω`. The operation tag fixes the receipt's `proof_digest` domain. Before
`Advance`, the wallet natively verifies the incoming packages, proves `σ` and
natively verifies it. The provider then executes atomic, durable
`Advance(expected_head, new_head, proof_digest, operation_id, recovery_capsule)`
and produces `τ`, which it natively verifies before release. In the background
the wallet proves the lineage proof `Λ` and its wrap `Ω` and natively verifies
`Ω`; verifiers reject a Send, Unload or Retiring package, or a fee claim, that
lacks its predecessor `Ω`. The current receipt is checked natively; the lineage
proof covering a step verifies its own and incoming receipts recursively. Tests
should follow that order and bind the receipt to the exact proof digest and
state transition.

Load funding finality is a separate native check: the wallet verifies the exact
Sumeragi BLS certificate and receipt event under its authenticated genesis and
epoch authority before selecting a fresh Load for Advance signing. Its monetary
proof binds the receipt and signed transition; it does not independently prove
the BLS verification. An unsigned restart may sign only the exact previously
authenticated, durably selected capsule. A completed retry returns its retained
output without signing or crediting again. Record the released-app and
uncompromised-OS assumption with this funding assurance.

A committed Send irreversibly debits `amount + fee`. Recovery delivers the
same exact Payment bytes to the bound receiver, which credits them once.
Timeout, interruption, rejection, missing delivery evidence or sender regret
never restores the debit. No step or lineage relation has a reversal operation.

The single target uses a software provider and marker in the released wallet
on a stock vendor OS. The phone must be unrooted, not jailbroken and free of
rootkits or other OS compromise. Enrollment verifies available platform
evidence, including locked verified boot where attested. Continued absence of
runtime compromise is a security assumption, not a fact proven by enrollment.
Record that assumption with every result. Stronger hardware enforcement
against a hostile OS is optional research, not a prerequisite for this design.

Platform attestation records particular signed facts about a key, app or boot.
It does not establish that the running OS is uncompromised at payment time.
A valid transition proof does not, by itself, establish that its predecessor
was never used elsewhere. Record the component that enforces that property.

The checklist follows the completed-payment properties in the proposal:

| Property | What to check |
|---|---|
| P1a | Accepted value is durably owned at completion, subject only to the P4 exception. |
| P1b | Once the receiver's local fold reaches its current head, which covers the crediting head, with no network, counterparty or approval, the value is spendable onward offline and can be unloaded. |
| P2 | The payer cannot spend it again under the provider's stated security assumptions. |
| P3 | Completion needs no later reconciliation, approval or settlement. |
| P4 | Later discovery of payer misconduct does not revoke an honest recipient's accepted value. The sole exception burns only an incoming Payment that passed native checks but fails in the receiver's lineage proof. |
| P5 | Only an explicitly enabled regulatory control requires connectivity. |
| PC | Native verification, the receiver's step proof, the durable commit, recovery data and fold witnesses finish before the receiver reports completion; only the local lineage fold follows, and it changes ownership only by the P4 burn branch. |

## 2. Records and independently runnable work

Use a record per check: **not run**, **observed as expected**, **deviation**,
**source reading**, or **not accessible**. Include the steps, expected result,
actual result and limits of the conclusion. None of these labels grants or
withholds permission to use or integrate the implementation.

Identify the protocol revision, source commit, dependency lock, build hashes,
step and lineage relations and wrap, provider and firmware, attestation policy,
device model, OS build, security patch and carrier. Keep the raw signed bytes,
proofs, key hashes, logs, timings and fault traces alongside the reproducible
procedure.
Where raw evidence contains identifying data, retain it in controlled storage
and record its digest and access location. Pin external source code by commit;
record vendor-document retrieval dates and content hashes.

The work below can start independently. Primitive discovery and relation
design can proceed together. Storage probes and carrier measurements need no
prover; label their stand-in payloads explicitly. Complete proof and device
checks naturally need the corresponding implementation, but are not
prerequisites for other integration work. Long-duration experiments can run
beside development; there is no mandatory 90-day wait.

## 3. Provider behavior and platform claims

- Capture actual Android TEE and StrongBox attestations independently. Record
  the chain, origin, security levels, hardware/software-enforced fields,
  use-limit tags, app identity, boot and patch claims, and evidence freshness.
  A feature flag or another vendor's result does not describe this device.
- Capture Apple evidence separately. App Attest authenticates its own key and
  supplied transcript; it does not independently attest a separate payment
  key or report payment-time OS integrity.
- Record each [proposal §9.1 cutover acceptance](kagemusha_single_design_proposal.md#91-cutover-sequencing)
  case for E1 admission with its chain provenance: the adapter profile, root,
  provisioning kind and, for a device chain, the phone, OS build and whether
  Google Mobile Services are present. A Huawei case counts only with a genuine
  chain from a post-2019 Huawei phone without Google Mobile Services; an
  emulator chain ends at a software root and qualifies no profile. Record what
  each pinned root's independent ownership evidence is.
- Identify which trusted component owns the current head, enforces
  `expected_head`, commits the successor and retains the recovery outcome.
  Document how a verifier authenticates the provider and its contract.
- Interrupt signing before its result returns. If the successor was selected,
  retry or recovery must yield that same committed package offline. A selected
  head with no recoverable outcome is a durability defect, not merely latency.

The following hostile-OS experiments are optional research beyond the target
assumption. They do not gate integration or production use. Their results
must not be reported as guarantees of the software provider:

- Bypass the app and OS key-store service where research access permits.
  Begin concurrent operations from one head, varying messages, cancellation
  and completion order. Look for two different receipts accepted for the same
  predecessor. Record whether the interface itself serialized the attempts.
- Save and replay key blobs and host database rows after use. Upgrade the same
  old blob twice and exercise every returned copy. Record which component
  prevents a second authorized successor.
- For a counter candidate, attempt chosen and repeated counters, concurrent
  assertions and assertions after rollback. A failed hook shows only that
  the attempted attack failed; it does not prove counter unforgeability.
- Record how a rooted, unlocked or research device differs from the ordinary
  device. Do not transfer results across changed enforcement without an
  explicit supporting argument. Inaccessible privileged tests remain
  inaccessible, rather than evidence of security.

## 4. State machine, proof storage and crash recovery

Check the written authority contract and the implemented transition relations
against the same fields: scheme, asset, predecessor, operation, counterparty,
amounts, successor, proof digest and recovery capsule. Trace the durable
linearization point before release of a usable Payment.

Exercise sends, receives, loads, unloads, delivery retries and phone replacement
under message loss, duplication, reordering, concurrency, process death,
power loss and restoration of older host files.

Here, migration means phone replacement through an ordinary offline payment,
not a separate monetary operation. A change of scheme uses voluntary unload
and load through the ledger, with no required change to an existing wallet.

Expected invariants:

- Loads and transfers conserve value. Arithmetic cannot overflow, underflow
  or cross assets or schemes. The proof and native verifier agree.
- A Request is a signed setup quote bound to both wallets, the payer's next
  send ordinal, amount, fee terms and nonce. It creates no monetary state,
  exclusive receive slot or receiver ordinal. A stale or declined quote can
  prevent a new Send; cancellation, replacement or later expiry of the quote
  cannot invalidate an already committed Payment.
- Each Send consumes its send ordinal and debits `amount + fee` exactly once.
  After its commit, every timeout, crash, transport error, receiver decline and
  lost delivery evidence leaves that debit unchanged. No step or lineage
  relation has an operation that restores it on those grounds; reject retired
  refund/refusal monetary objects and attempts to recredit the sender through
  other operations.
- Receive checks nonmembership of the exact `credit_id` against the
  consumed-credit store authenticated by the head's `consumed_credit_root`,
  inside the serialized `Advance` section, credits once and inserts
  `credit_id → (amount, receive sequence)` in the same committed transition.
  Its receipt binds the complete Payment digest, which no state commitment or
  `σ_recv` statement contains; `Λ_recv` later proves the update and the digest
  in-circuit and records the digest in the credit-digest root. Entries are
  permanent. Deliver a delayed Payment after unrelated receives and then replay
  it repeatedly, including after restart and delivery evidence cleanup: only
  the first valid Receive changes the balance. Repeat with a restored stale
  native store, which fails authentication against the head roots, and with
  duplicate delivery on two carriers during a `σ_recv` re-prove, which credits
  once. A `σ` whose successor root differs from the root recomputed from the
  authenticated store is discarded before commit.
- An incoming Payment that passes every native check but fails in `Λ_recv`,
  including a duplicate `credit_id`, takes the burn branch: its `credit_id`
  stays consumed, `Λ`'s `burned_total` grows by its amount, the credit-digest
  root records it as burned, no accumulator of the burned Payment enters `Ω`,
  the receiver's other value stays spendable and reserve accounting counts the
  burned credit. Only that Payment is burned. Every later Send, Unload and
  Retiring `σ` takes `burned_total` from `Ω(pred)`; a `σ` that uses the stale
  core value is rejected natively and in `Λ`.
- Send, Unload and Retiring packages carry their predecessor `Ω`; Send,
  Unload, fee claims, retirement and device moves from an unfolded head are
  rejected. A wallet's next Send waits until its current head is folded, also
  after its own previous Send. Crash and restore between commit and fold
  resume the fold from retained witnesses; loss of a fold witness or of a
  native authenticated store without a recoverable copy is reported as custody
  loss, never a silent wait.
- A Payment whose Request names a different payer wallet than `Ω(pred)`, or
  whose carried payment key or credential digest differs from `Ω(pred)`'s, is
  rejected before mutation, and so is a payer credential from the Offer whose
  digest differs.
- With each regulatory control enabled, the receiver's verification of
  `σ_send` rejects a Send that violates it, and a `σ_send` proved under the
  verifying key for a different enabled-controls mask than `Ω(pred)`'s.
- Each ordinary load receipt and redemption is consumed at most once. Funding and
  retirement cannot recreate a consumed receipt or reverse a committed Send.
- A nonzero fee is earned at Send. Its exact retained Payment authorizes one
  fee payout, keyed by `credit_id`, only to its fixed beneficiary. Claim the fee
  before Receive and retry after Receive: there is one payout total. Failed
  delivery or decline neither cancels the fee entitlement nor restores its
  debit. Map leaves and immutable capsule bodies do not contain the very
  receipt or final package that authenticates them.
- Optional Credited evidence is the committed Receive package or a read-only
  `CreditStatus` {statement, `proof_digest`, receipt, `Ω`, opening} against a
  folded receiver head. Verify the Receive package's step proof and provider
  receipt, which binds the exact Payment digest, or decide the folded head's
  `Ω`, check its receipt and the opening of `credit_id → (Payment digest,
  burned flag)` in `Ω`'s credit-digest root, recipient and scope. Another
  Payment, an unconsumed credit or an invalid receipt fails; a burned credit
  reports **delivered, burned**. `ArchiveSent` verifies this evidence natively
  before `Advance` and in `Λ_archive`, and removes only the corresponding
  retained outbox entry, without a monetary effect. If the in-circuit check
  fails, `Λ_archive` takes the no-op branch: the entry stays pending in `Ω`'s
  pending-outgoing root, its Payment bytes are kept, and it can be archived
  again after a later Send, Unload or Retiring. The payer deletes the delivered
  Payment bytes only after a durable `Ω` covers the ArchiveSent step on its
  archive branch.
  Evidence loss cannot change either balance or remove a permanent
  consumed-credit entry. The flow creates no acknowledgement chain,
  receiver pruning obligation or prerequisite for onward spending.
- `Advance` retries recover the same committed outcome. Once a Payment is
  assembled and released, every retry returns its exact original bytes,
  including proof and receipt. Crash before release must finish the selected
  Send, retain its complete Payment and deliver that Payment; it cannot select
  another successor, regenerate a different released Payment or restore value.
  Loss of every retained copy of released bytes reports delivery-data loss;
  generating a new receipt or proof is not recovery. Inject a faulty receipt
  signature before first release: it fails native self-verification and is
  signed again, and no failing receipt is released.
- Phone replacement uses the ordinary payment path. Interruptions preserve
  its exact outcome; the old phone retains unresolved obligations, with no
  copied balance or separate migration authority.
- Crashes preserve authenticated recovery bytes sufficient to reconstruct
  the complete package and prove its next transition offline. Temporary host
  unavailability permits retry. Deliberate total erasure of the private
  recovery bytes is custody loss: a digest cannot reconstruct those bytes.
- Every message, per-operation buffer and recovery object respects the
  proposal's bounds. Exercise zero, the limit and one over it. Preflight
  available storage before accepting an operation. Unresolved operations can
  accumulate indefinitely. Permanent consumed-credit entries and their map
  openings also consume storage; do not prune them by age or claim globally
  bounded wallet storage.
- Capacity pressure is handled before acceptance. Preserve already committed
  Payments and distinguish a capacity wait from loss of accepted value. Test
  repeated, cyclic and branching histories and migrations, including growth
  of unresolved operations, rather than only a short acyclic payment chain.
- An older wallet can verify and spend its admitted packages after another
  wallet upgrades. Exercise the unchanged step relations, lineage relation,
  wrap, verifying-key allowlist and verification interface within the scheme
  without an unconfigured requirement to reconnect.
- Retirement: race load issuance with the atomic ledger instruction that closes
  new loads. Previously committed receipts stay recoverable and new loads after
  closure debit nothing. Deliver an already committed Payment while the receiver
  is retiring; it remains receivable once. Also issue a quote before Retiring,
  commit its Send afterwards and deliver it: retiring cannot cancel that credit.
  Retirement stops issuing new quotes and preserves old receive custody.
  Neither a zero balance nor a receipt proves
  that no delayed incoming Payment exists. Intentional custody deletion reports
  the loss of late incoming value; it is not a safe monetary drain certificate.
- Interrupted enrollment: try funding a load before the ledger records the
  completed Bootstrap receipt; the transaction fails without debit. Abandon is
  permitted only while Bootstrap has never been selected, in the proposal §3.2
  form the slot's durable state selects: local with no ledger bytes when no
  marker exists, or the signed Abandonment frame while the generation-zero
  marker is current. Once Bootstrap is selected or commits, including an
  uncertain activation response, resume that incarnation and use Retiring; do
  not select Abandon. If a load is funded, consume its original receipt once
  without cancelling its obligation, refunding its mint, resetting ordinals or
  initializing a second authority. Abandoning an unused enrollment changes no
  monetary balance.
- Local abandonment: deliver a delayed platform generation result after the
  abandoned-slot record is durable, and restart into every recovery path; each
  returns `SlotAbandoned` without a key probe and adopts no key. Make storage
  unavailable or uncertain, or lose the marker: abandonment writes no record and
  reports `Unavailable`. Race local abandonment against Bootstrap selection,
  marker installation and generation recovery; exactly one wins. On Android API
  26–30 the spent grant and an unknown lookup never regenerate the alias. Also
  on API 26–30, crash after Slot publication and before intent creation, then
  abandon locally: the authenticated pre-E2 evidence and readable absence of
  intent, generation-attempt, marker, E5, E6 and initialized-state records
  admit abandonment while the null lookup stays unknown; the slot reconciles to
  `SlotAbandoned`, no grant is issued and the alias is never regenerated. Lose
  a required Client, Accepted permit or Slot original, or make one of those
  records unreadable: abandonment reports `Unavailable` and writes nothing. With
  quota controls enabled, race two enrollments for the last share; one fails,
  and the old share is released only on finalized successful Abandonment.
- Time anchors: delay the issuer's response to near the response-age bound and
  sign it just before a lease end; the wallet must treat the lease as ended.
  Sleep the device for hours while anchored; elapsed time must include the
  sleep. A Send whose time interval touches two windows is counted in both.
- Marker coverage: at every step of enrollment, a normal transition,
  retirement and abandonment, the key is covered by exactly one durable current
  marker or a terminal marker.

Use a finite-state model for adversarial schedules and an inductive argument
for unbounded executions. State the bounds of each model check; a bounded
search does not prove unbounded-hop safety. Review the provider contract and
proof relations together, identifying which component discharges each
obligation instead of having each assume the other enforces it.

## 5. Real proofs and protocol interoperability

Generate real zero-state and load proofs, step proofs, lineage proofs and wraps
for a complete load → A → B → C → unload lineage. Include split/change, delayed
and duplicate delivery, receive-then-send, phone replacement and cyclic
transfers. Retain witness fixtures, proofs, verification keys and component
resource measurements, including lineage fold time, peak memory and energy.

Try forked predecessors, changed amounts, duplicate and reordered credits,
forged or substituted provider receipts, altered proof digests, missing
ancestor authorization, mixed schemes, wrong assets, malformed encodings and
mismatched relation identifiers. Record the trust boundary rejecting each
case. Mutation tests should show a named failure when a monetary invariant
is removed; ordinary valid fixtures alone do not exercise that invariant.
Include mutations that restore a committed Send after timeout or decline,
omit consumed-credit insertion, permit its later removal, or replace the
retained Payment bytes during recovery. Each must be rejected or violate a
named invariant in the test. Replace a Payment's P-256 signature `s` with
`n - s`, and vary signature encodings or verification dependencies. Native
and recursive checks must reject altered bytes; they must not normalize an
incoming Payment into a different digest or insert an alternate consumed entry.
Signing normalizes before freezing the original canonical object.

Compare native and recursive verification of the same package. Native and
in-circuit verifiers must accept exactly the same set for every object that
`Λ` verifies after a native check: run differential and fuzz tests, in the
relation owners' CI, over `Ω` including its deferred values, `σ`, `τ`, the
Request, Credited evidence, ordinary Load receipt bindings, fee schedules,
certificates, credentials, and policy, time and credential updates. Load's
BLS certificate and counted event inclusion are verified natively before Advance
signing under the accepted [design §6.1](kagemusha_single_design_proposal.md#61-load-and-unload)
trust boundary; exercise their native mutation and pre-signing refusal cases
separately, without requiring an in-circuit BLS verifier. Exercise the
poison-pill burn branch of `Λ_recv` and the no-op branch of `Λ_archive`; a
tampered deferred value; a mixed history; a wrong relation identity; a `σ`
under the wrong verifying key for its operation tag or enabled-controls mask;
an `Ω` whose head, credential digest or payment key does not match the `σ`
statement or `τ`; a `σ` whose `burned_total` or pending-outgoing input differs
from `Ω(pred)`'s; and a receipt whose `proof_digest` omits or swaps `Ω`, or
uses the domain of another operation tag. Check that current receipts are verified before credit and that
successor lineage proofs bind those receipts to the exact predecessor and
incoming packages. Check that an invalid package cannot become valid merely by
wrapping it in another proof.

The scheme keeps its fixed step relations, lineage relation, wrap,
verifying-key allowlist and verification interface for its lifetime. Test
voluntary transfers to a different scheme separately; breaking changes cannot
require old wallets to update or reconnect to keep using their existing value.

## 6. Complete device exchanges

The user-selected initial measurement population is Pixel 6 and the connected
iPhone 16 Pro Max. These are measurement subjects, not a runtime device allowlist. Record
fresh OS/build and app/native/catalog identities for each run; expansion to other
phones remains separate work. Report Android → iPhone and iPhone → Android
individually for every actually supported carrier. Do not pool different
directions, carriers, cold starts or enabled-control profiles into one percentile.

For each qualified timing cell, retain 200 ordered attempts and use the
nearest-rank empirical p95 (the 190th ordered duration). Retain failed,
cancelled and interrupted attempts in their original positions; report their
counts and reasons rather than silently replacing them with successes. A cell
with failures does not establish the completion target from successful timings
alone. Preliminary diagnostic runs may use fewer attempts, clearly labeled,
to identify bottlenecks before the full evaluation. Durable-completion time and
the later local-fold time until received value is spendable remain separate
measurements. No timing or durability success is established by selecting this
population or procedure.

Use a continuous local clock that includes device sleep for every timestamp in
an attempt; do not subtract timestamps across phones or reboots. The nearby
harness uses Darwin `CLOCK_MONOTONIC_RAW` and Android `elapsedRealtimeNanos`.
After native admission authenticates the exact Credited response, its earlier
arrival on the payer's clock bounds receiver durable completion from above;
the later payer admission time measures delivery confirmation separately. An
arrival upper bound within the target can establish the timing bound, but an
upper bound above it alone does not prove the receiver missed the target.
Recovery without the original clock anchor supplies no timing sample. Neither
clock selection nor an authenticated acknowledgement proves power-loss durability.

Run real proofs and the software provider on stock phones for each claimed
device and ordered sender/receiver/carrier combination. Label runs with
padded proofs so their timings are not attributed to a real prover. Record
untested combinations without claiming platform or vendor universality.

- A pays B; after B reports complete and its local fold reaches its current
  head, B pays all received value to C with radios off. Before that fold, B
  shows the completed credit as **spendable after local proof** with its fold
  backlog, and Send and Unload wait for the fold. Repeat after restart, temporary
  storage unavailability and recoverable faults. Record total
  private-recovery-byte erasure as custody loss, not successful recovery from
  a digest. Inspect both endpoints: the payer reports its durable Send
  independently and reports **delivered** only from valid receiver completion
  evidence.
- After A commits Send, interrupt delivery before B receives it; also exercise
  a decline, capacity failure and a lost Credited message. A's amount and fee
  never return. B can receive other payments before the original exact Payment
  is retried, and can then credit that Payment once. Withhold optional Credited
  evidence and confirm that B's accepted value becomes onward-spendable after
  its fold without that evidence. Recover that evidence later through
  `CreditStatus` without changing B's state.
- Cut power at authority, proof-store, journal and release boundaries,
  including inside `Advance` and after commit but before return. Distinguish
  forced restart from actual loss of power to storage. Test locked,
  unavailable and full storage without treating transient errors as absence.
- Exercise platform backup, vendor transfer, reinstall and update paths.
  Repeat rollback attempts against the actual provider boundary, and record
  precisely which destructive events are outside its durability assumptions.
- After B accepts value from A, give B and C authenticated misconduct evidence
  about A. B's credit remains usable, and C accepts B's otherwise valid
  package. Check native and recursive verification.
- With regulatory controls off, pay, recover and spend onward offline after
  reboots, clock changes and long idle periods. Run each enabled control
  separately. Record the longest tested interval and any network dependency.
- When the proposal §5.3 runtime capacity check fails on the phone (too
  little free custody storage or available memory for the operation's
  relations), activation, Load, Send, Receive and RefreshPolicy refuse before
  commit with `NotEnoughStorage` or `NotEnoughMemory`, and the load receipt or
  Payment stays deliverable. Kill the app for memory during proving and during
  commit (the Android low-memory killer, iOS jetsam): at the next start an
  uncommitted operation leaves the head unchanged and stays deliverable, and a
  committed one completes from its retained outcome. No device class, model
  list or published budget gates any phone. On each measured phone, record fold
  time, peak memory and energy per operation as evidence, including folds
  interrupted by app suspension and resumed at the next app run. With a
  receiver's Request-issuance policy (minimum amount, rate limit, maximum
  unfolded backlog), new quotes stop at the configured limit and committed
  Payments stay receivable.
- Measure every package-carrying message against the **10,000-byte** bound,
  including the Lineage message, the single-parity `Ω` inside Payment and a
  CreditStatus, and each Offer with the payer credential against **2,048
  bytes**. If `Ω` cannot keep Payment, or CreditStatus cannot keep Credited,
  within 10,000 bytes, record a deviation; a fallback is a new owner decision.
  Report schemes with enabled controls separately. Measure
  the **2-second p95** target from payer confirmation after the Request to the
  receiver's durable completion (P1a). Include intervening framing, retries,
  carrier setup, the payer's remaining step-proof time, receiver verification,
  the receiver step proof and both durable commits. Report separately, per
  measured phone and never as an enablement gate, the fold time until the
  value is ready to spend onward and tap-to-done including setup and the
  confirmation dwell. Measure the payer's
  later delivery confirmation separately. State sample counts and the
  percentile estimator before measurement; retain raw samples, failures, cold/warm
  results, peak memory, energy and thermal effects. These are requirements
  and targets, not measured results.

Zero observed failures does not establish zero failure probability. Under
independent, identically distributed Bernoulli trials, n clean trials give an
approximate 95% upper failure-rate bound of 3/n. Adaptive attacks, correlated
storage faults and different devices do not acquire that model merely by
repetition. An empirically successful delay is not a storage durability
contract. Record counterexamples and repair the underlying mechanism.

## 7. Integration and existing material

Compare node, issuer, wallet core, Swift and Kotlin implementations using the
same canonical vectors and real packages. Exercise ledger loads, unloads,
fees and migrations on a valid multi-peer network. Check reserve accounting,
replay indexes, finality and issuer/provider key separation. State the stock-OS
assumption with the deployed software provider; do not describe its marker
as hardware enforcement against an OS takeover.

Re-run affected checks after changes to provider, firmware, OS, step or
lineage relations, wrap or storage behavior. Record what results still apply
and how existing offline packages interoperate. Use the proposal's retirement map and actual caller
inventory when consolidating implementations; verification work does not
create a separate approval condition for integration or production use.

Starting points, not evidence that this protocol has passed:

- Android: `kotlin/kagemusha-wallet-android/src/main/java/org/hyperledger/iroha/sdk/offline/wallet/` (the Android `Advance` adapter, payment-key and backup rules) and `kotlin/core-jvm/src/main/java/org/hyperledger/iroha/sdk/offline/KagemushaP256Codec.kt`. Generate and inspect keys even when feature flags are negative. The old KeyMint single-use probes of the retired protocol were deleted.
- Apple: `IrohaSwift/Sources/IrohaSwift/KagemushaWalletApplePlatformV1.swift` and `KagemushaWalletAppleAppAttestV1.swift` in the same directory (Secure Enclave payment key and App Attest enrollment evidence of step E5). The old `examples/ios/KagemushaAppAttestProbe/` app of the retired protocol was deleted.
- Attestation: `kotlin/core-jvm/src/main/java/org/hyperledger/iroha/sdk/crypto/keystore/attestation/` and `python/iroha_app_attestation/src/iroha_app_attestation/`.
- Arithmetic certificates: [Pasta prime, auxiliary-curve and SWU cover checks](../formal/kagemusha_pasta/README.md) verify the native constants; the checker and sixteen controls pass. The [regularity argument](../formal/kagemusha_pasta/REGULARITY.md) applies cited geometric theorems to those hypotheses. The [focused workflow](../.github/workflows/pasta_certificates.yml), local commands and action-pin guard pass; hosted CI remains unobserved. These checks do not establish the protocol or its privacy argument. The retired `formal/kagemusha_v1/` model is deleted.
- The [provider publication model](../formal/kagemusha_protocol/README.md) exhausts484 states and2,792 transitions, with14 controls and seven unsafe-rule counterexamples. It covers irreversible selection, redundant completion, exact original replay and unavailable/absent/lost distinctions. The [conditional accounting model](../formal/kagemusha_protocol/ACCOUNTING.md) tracks disjoint reserve liabilities, core versus folded balance, authentic burned backing, unbacked rejection, fees, Archive and retirement races. The corrected model permits Archive and collection of a burned first credit while retaining unpaid fee originals. Ordinary Receive remains exact replay; a separate post-commit defensive duplicate operation adds equal optimistic balance and deferred burn, retaining the first credit's digest and flag. Original identity is the opaque pair `(credit key, digest)`, not an implemented hash. Repeated use of any such original, including an alternate digest, must retain its amount. A negative mutation changes amount, balance and burn together and is rejected despite preserving aggregate value; a maximal-value case reaches the core overflow guard.
- All 65 current provider/accounting/schedule/composition controls pass, along with the provider and one-Send product commands (`accounting-original-amendments-application-1/result.json`, SHA `c42745714671d86c0b3ab37eb1e374692c421c484d823d8826f0739201dbe98c`). Final-source finite graphs complete with 6,789 single-unit states, 68,190 fee states and 289 unbacked states. The three-wallet/two-payment graph exhausts 4,649,058 states and 63,751,915 permitted transitions without a violation, under the unchanged 5,000,000-state cap (`accounting-final-originals-graph-validation-1/result.json`, SHA `947c26f4ccdef1edba14f9a6d1eafe16c8f25792742d32c432e6442be63c11ca`). This run includes the final amount invariant, completes in 591.577 s and retains unchanged model/interpreter pins. Independent review confirms that the alternate-original amount and overflow-coverage gaps are closed (`accounting-containment-final-independent-review-1/review.json`, SHA `6148ea68dcae341491651fddeb7991acd6e053e515bd8f06cb3d40e3863789d9`). Four unsafe transition rules have reachable shortest counterexamples. Earlier cutoffs and superseded results remain retained. This is conditional model evidence; a complete independent protocol proof remains open.
- The one-Send provider/accounting product exhausts3,076 states and25,836 transitions and rejects four composition mutations. It covers competing capsules, uncertain selection, signing/storage interruption, retained-original delivery, payer/carrier loss, first credit and both fold outcomes. The explicit defensive duplicate operation is excluded from the ordinary finite graph inventory and the one-Send product; its focused schedules and mutations are separate. Authentic prior funding, receiver durable commit and successful fold verification remain premises. All-operation/multi-head composition, concrete native/circuit refinement, unrestricted monetary histories, hosted CI and the complete protocol argument remain open.
- Evidence records: §8 below. The old physical-evidence record of the retired hardware protocol and its verifier script were deleted; record new device results here with their provider assumptions.
- [Pinned AOSP characteristics](https://android.googlesource.com/platform/system/keymint/+/fda4e68d32f8dfc103e0283b4bfc41503ecfb19f/common/src/tag.rs), [operations](https://android.googlesource.com/platform/system/keymint/+/fda4e68d32f8dfc103e0283b4bfc41503ecfb19f/ta/src/operation.rs) and [upgrades](https://android.googlesource.com/platform/system/keymint/+/fda4e68d32f8dfc103e0283b4bfc41503ecfb19f/ta/src/keys.rs): reference behavior, not vendor-firmware evidence.
- [Android attestation](https://developer.android.com/privacy-and-security/security-key-attestation), [Apple validation](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server) and [Apple fraud-risk guidance](https://developer.apple.com/documentation/devicecheck/assessing-fraud-risk): capture the exact statements and their limits in each evidence record.

## 8. Recorded results

### Current first-release completion requirements

The selected [logical C12 composition](kagemusha_c12_composition_v1.md) retains
its named setup, masking, valid-source, concrete-coin and causal-custody
premises. It includes all three Q stages, both exposed accumulators,
checkpoints, retries and stopped outcomes. Its conditional logical result does
not qualify a compiled catalog or physical device. The 16 October captured
candidate has matching strict engineering/production profiles, installed registry
DATA, native builds and host JNI tests. Genuine monetary execution across all
supported variants, four-validator execution and physical carrier measurements
remain open. Later source changes need matching validation; historical source
and execution records below do not qualify a successor.

The [first-release execution goals](kagemusha_first_release_goals.md) identify
the current source and required evidence. The current complete-catalog test
expects 22 routes / 16 programs, four Send sigma masks and one Receive sigma
selector with ordinary/renewed recursive variants. The current compact Payment
has 1,394 B fixed overhead, a 3,520 B sigma capacity and a 5,086 B Omega
transport capacity. These source bounds do not constitute a genuine envelope
measurement. Older 52-route / 32-program catalogs and 1,723 B Payment-overhead
measurements below remain scoped to their captures. Fresh-ID duplicate Receive
after receiver restart and reverse-direction received-value spending are present
in the host harnesses; current-candidate execution is still required.

The initial phones are Pixel 6 and the connected iPhone 16 Pro Max. Current
candidate enrollment must carry actual platform evidence, including App Attest
on iPhone. Release across power loss or restoration must exclude replay of an
old head under a still-usable payment key through the retained authority/key
boundary described above. These are implementation requirements, not an
additional approval or deployment process.

### Historical complete catalog capture (source9696, 2026-10-15)

The earlier captured source identity was
`9696be0d5573d45534cc7d18f9785df2a69aded4160643d6ac476aacb11f1755`;
its strict exported registry DATA was
`1ae7a48772cd342e0176f583a321f58596ed32c6178b17ba3c4b757f43eb139a`.
That catalog covered 52 routes, 32 programs, 32 terminal keys and 505 originals.
Its native strict reconstruction/export passed, including all 488 private mask
checks, 16 active sigma imports and 89 active Q imports. The initial export's
private-file mode refusal remains a failed attempt; the continuation copied the
same originals to exclusive immutable files and reran strict native admission.
The terminal export receipt SHA was
`d214cf379b22bbfea86c1bb0faf017ee8f7c47591b6cc165a4bf26b3f01d1287`.
These are catalog observations at that source, not genuine monetary or phone
qualification and not evidence for the current source proposal.

The corresponding final macOS and Linux captures stopped on exhausted build
storage. Those failed attempts retain their logs and candidate identities;
this historical result is not a claim that the current build storage is
exhausted. Matching final artifacts and execution were not established by
that capture.

The reviewed source arguments accompanying the capture covered reached
operation relations, their integer/hash/tree/signature/recursive dependencies,
complete group arithmetic and finite Strict checking at their recorded source
scope. Finite controls supported the derivations but did not prove universal
correctness or physical privacy. The current conditional logical argument and
its bounded source transfers are stated in the linked composition and
recursion documents.

### Earlier captured implementation observations (through 2026-10-12)

The following records describe only their named captured candidates. Their
pending-work statements are historical; the current requirements above do not
transfer qualification from those candidates.

The measured lookup-mask candidate reuses two dead quotient-workspace columns for
public lookup-mask weights, without changing proof bytes, random draws or the
MSM ceiling. Current native Pasta/PLONK validation passes 427 tests with nine
explicit ignores, and strict library/test lint passes. The compiled x86 library
run under Rosetta passes 389 tests with seven explicit ignores. These are
correctness checks, not physical-x86 or performance qualification; checked source
pins remain unchanged (`m3-preweight-current-engine-validation-1` and
`m3-preweight-current-parity-harness-validation-1`). The preceding current-source
baseline diagnostic verifies two 7,936-byte real-Q proofs, with slower CPU
26.8131 seconds and kernel peak RSS 661,602,304 bytes
(`m3-lookup-mask-preweight-baseline-real-q-diagnostic-1`). It precedes this
optimization and is neither its measurement nor a full M3 verdict. The new
captured candidate changes only the three reviewed prover files in its consumed
source set; all four workload descriptors, compiler flags and feature sets match
the baseline. Its separate same-seed diagnostic verifies both proofs with slower
CPU 26.37372 seconds and kernel peak RSS 601,030,656 bytes; source/binary and all
probes remain valid (`m3-lookup-mask-preweight-real-q-diagnostic-1/result.json`,
SHA `ffd51919a5ba70c1678adbf5f9a9ca88713516dbb61a2a70bac56d18b2246c06`).
These two single-process observations do not establish a causal speedup or gate
verdict. All eight ordinary M3 harness controls and strict lint pass. The full
unchanged eight-configuration schedule completes against the immutable
captured executable in `m3-lookup-mask-preweight-current-1`: 76 attempts,
72 valid measured processes and 144 verified measured proofs. All valid
measurements meet their hard limits; seven configurations pass. The one-thread
real-Q configuration is **borderline**, with block CPU medians 26.151054,
27.588369 and 26.425610 seconds. The second block exceeds the required
27-second margin despite meeting the 30-second hard limit. All four invalid
attempts remain retained. Terminal review independently reconstructs the
schedule, thresholds, source and binary joins (`m3-lookup-mask-preweight-terminal-review-1/review.json`,
SHA `d8e8b8dcc82d084f13470c284eb7290d75cbd489ae475e3cd371d30a1ccc5e3f`).
No full M3 pass follows.

The subsequent reviewed selector-factor candidate is applied. It factors only
consecutive gate-only products within the original eight-root chunks, preserves
lookup and shared consumers, and compacts the remaining public expression DAG.
The real-Q descriptor removes 38 field multiplications per row; this arithmetic
count is not a measured speedup. Five new controls compare both fields, filter
order, chunk boundaries and the complete quotient against the unchanged oracle.
Current native engine validation passes all 432 non-ignored tests, with nine
explicit experimental ignores, and strict library/test lint. The five new tests,
both curves' fixed proof vectors, worker-count parity, workspace reuse and
cancellation controls all pass. The initial lint failure and its narrow repair
remain recorded. Checked owned sources do not drift during the successful run
(`m3-gate-selector-factor-engine-validation-2/verification.json`,
SHA `426610ef9b166966989dd3ce120282f7f792268002dbf20e7210b523d9ad581a`).
The emulated-x86 library run passes 394 tests with seven explicit ignores;
all nine ordinary measurement-harness controls and strict harness lint also pass
(`m3-gate-selector-factor-parity-harness-validation-1/verification.json`,
SHA `5337c040f30e92b747c6231e262bb544d48f7dd1b46295c2d8b5e4f4c4750f9c`).
The fresh candidate capture pins the actual compiler-input closure and an
immutable executable. Its separate diagnostic verifies both 7,936-byte real-Q
proofs; the slower sample uses 26.478967 seconds of process CPU and kernel peak
RSS is 667,451,392 bytes. Independent review confirms the source, binary and probe
records (`m3-gate-selector-factor-real-q-independent-review-1/terminal-review.json`,
SHA `ceb0dbc39a90cae92bf5adac21a00e6641010349bda819b864281dd9e4d52981`).
This is a diagnostic, not a qualification or causal speedup result. The
unchanged eight-configuration campaign in
`m3-gate-selector-factor-current-capture-1` stopped naturally when its provenance
check detected a changed `irohad` development-dependency manifest. The executable
remained unchanged, but the source identity did not. Its partial samples and
invalid attempts remain retained; every configuration is incomplete and
inconclusive. The fresh capture in `m3-gate-selector-factor-current-capture-2`
has the same executable, workload descriptors and consumed-file closure; its
updated Cargo metadata was captured without source drift. Its fresh campaign
inherited no samples from the interrupted run. The first four-thread synthetic-Q
block contains a valid 11.276027125-second sample, exceeding the 10-second hard
limit. The campaign subsequently stopped naturally at sequence 30 when its
source identity changed; its executable remained unchanged. The valid hard
failure, partial configurations and invalid attempts remain retained. This
incomplete campaign cannot qualify the candidate. Independent raw-record review confirms
four workers, passing calibration and host probes, and unchanged selected source
and executable identities (`m3-gate-selector-factor-capture2-hard-failure-review-1`,
manifest SHA `b65b942228bf18ae14f7345a609a76b8b80307d00f096e19d7d1f8477e755ae5`).
The preceding campaign cannot qualify these changed sources.

The next candidate adds a nonrecursive streaming MSM fallback when concurrent
reservations leave insufficient scratch for a full-input Pippenger plan. It
preserves the existing arithmetic kernel, full-width secret-scalar policy,
checked public bounds and process-wide 64 MiB scratch ceiling. Six new controls
exercise both curves, exceptional points, finite admission, saturation,
cancellation/retry and unwind. The pre-retirement
`m3-streaming-msm-correctness-1` run admits 131 ordinary Pasta cases, three
PLONK proof-byte/scheduling goldens, 367 gadget cases and six recursion cases.
It stops after three shared-allocation source files change during the compact
component tests. Both component tests return success, but their changed-source
boundary refuses admission; later recursion, fold-golden and lint stages do not
run. All emitted executables remain unchanged. The terminal failure and
independent review remain in `m3-streaming-msm-correctness-release-review-1`;
the run does not qualify the later source.

The unused recursive BLS, BLAKE2b and ordinary-ledger Merkle circuits are now
removed: 30 files, 53 obsolete ordinary test functions and five Gadgets
development-dependency edges. Native finality and retained payment circuits
remain. Locked offline Cargo metadata, all 15 retirement controls and scoped
format checks pass. The fresh `kagemusha-post-retirement-correctness-1` run
ended with all 362 selected tests passing: three rebuilt PLONK goldens,
314 ordinary gadget cases, 43 ordinary recursion cases and both explicitly
selected k16 fold adversarial cases. Each test's source and executable checks
passed. Of 34 initial ignores, the two explicit folds were subsequently run;
25 gadget and seven recursion cases remain unexecuted. Strict lint then failed
on `clippy::option_if_let_else` in the MSM fallback, so the overall result remains
unsuccessful. The equivalent lazy `map_or_else` repair is applied. The reviewed seven-row inventory correction is
also applied; the maintained full primitive inventory checker passes. The subsequent
`kagemusha-engine-focused-continuation-1` stopped at strict lint after 13.78 seconds
with an orphaned `cells::low_word` helper; no tests ran. The unused helper and
its obsolete helper-only test are now removed; the other cell tests and the
separate, used ECC helper remain. Scoped formatting and diff checks pass.
The second focused continuation stopped at strict lint on two redundant trait
imports in the streaming MSM tests, after 3.32 seconds and before any test ran.
Those imports are removed without changing test logic. The third lint command
exited successfully, but its wrapper refused Clippy's derived argument value;
that refusal is retained. The fourth continuation explicitly binds the exact
strict-lint arguments to emitted artifact and depfile bytes, preserves the
other source/environment checks, and passes strict lint with source admission.
That continuation then passed 439 tests: four retained cell tests, 131 ordinary
Pasta cases, 302 ordinary PLONK cases and both k16 fold adversarial cases. Its
first remaining ignored recursion case, the malformed-accumulator matrix,
failed after 136.15 seconds at its exact layout assertion: Pallas synthesized
1,058 rows and 3,529 cells against the expected 1,378 rows and 3,849 cells.
The current run remains unsuccessful. The failure occurs after its Pallas
malformed-input and known/unknown-shape checks, before column tampering and the
Vesta matrix. Its failed-child source and executable checks passed; the six
later ignored recursion cases did not run. Independent source accounting now
confirms the current shapes: Pallas uses 1,058 rows and 3,529 advice cells;
Vesta uses 1,058 rows and 3,625 advice cells. The canonical scalar decoder
retains already-bounded limbs and adds the modulus comparison; the ordinary
range lane and existing binding constraints remain intact. Vesta adds 96
native scalar-recomposition cells. Only the three stale expected counts and
an explanatory comment are corrected; malformed-input, forged-verdict,
known/unknown and column-tampering assertions are unchanged. The original
failed run remains failed. The corrected matrix now passes both curves in
272.74 seconds, including every retained tampering assertion. The fifth focused
continuation also passes both foreign-codec cases, all three accumulation-circuit
cases and the source-choice case: seven executed passes, no failures or ignores.
Fresh strict lint and every before/after source, executable, metadata and tool
check pass. Its 1,703 selected source entries remain current at independent
review. The earlier 439 passes are separately joined through the exact test-only
overlay; the failed fourth run is not relabelled as successful. The fifth result
is retained at `kagemusha-engine-focused-continuation-5/result.json` (SHA256
`33da1c89f49700dd15701d4f5857ac0d8e86adc19c836cb54882e3df75ef6301`).
Heavy gadget and M3 gates remain separate. The derivation, independent
review and exact application/formatting receipts are retained under
`target/qualification/kagemusha-accumulator-decode-shape-reconciliation-draft-1`,
`kagemusha-accumulator-decode-shape-independent-review-1` and
`kagemusha-accumulator-shape-root-application-1`.

The fresh heavy-gadget run now passes all thirteen selected cases, including
exhaustive foreign-field cell checks, fixed/variable-key and full-leaf P-256
tampering, statement binding, both-curve digest proofs and real SHA-256 proofs.
Independent review reconciles all 68 child exits and raw logs, 136 source and
136 executable boundary records, 1,656 current selected source entries, 28
retained depfiles and 14 binaries (`m3-streaming-msm-heavy-gadgets-3/result.json`,
SHA256 `61fc20bdd2a3da6a38e39bd3a5ae0687eff28b224e510c0be28df4a9fa6931cd`).
The complete ignored inventory contains these thirteen executed cases and twelve
deferred M3/diagnostic cases. The 313 surviving ordinary gadget cases were listed,
not rerun; their earlier evidence retains the explicit source reconciliation and
retired-helper disposition. The fresh M3 candidate also passes all three strict
shape checks. Its complete performance campaign finishes with **72 valid
processes across all eight configurations**, nine per configuration in three
blocks. All eighteen invalid attempts remain retained, for ninety attempts
overall. Seven configurations pass; real Q with four workers fails. These are
host component measurements, not phone or complete-payment qualification.

| Configuration | Metric | Three block medians (seconds) | Maximum valid kernel RSS (MiB) | Verdict |
| --- | --- | --- | --- | --- |
| `q_exact-1` | process CPU | 21.705, 21.407, 21.434 | 622.016 | pass |
| `q_exact-4` | observed elapsed | 6.495, 6.022, 6.114 | 634.766 | pass |
| `q_chips-1` | process CPU | 26.626, 26.686, 26.701 | 719.359 | pass |
| `q_chips-4` | observed elapsed | 9.482, 8.139, 8.133 | 698.016 | fail |
| `a_exact-1` | process CPU | 27.841, 27.632, 27.753 | 785.047 | pass |
| `a_exact-4` | observed elapsed | 7.884, 7.662, 7.799 | 828.156 | pass |
| `a_chips-1` | process CPU | 31.246, 31.710, 30.746 | 825.641 | pass |
| `a_chips-4` | observed elapsed | 8.843, 8.711, 8.639 | 776.703 | pass |

The first real-Q/four-thread block has three valid slower-proof times of
9.481868959, 10.218662958 and 8.914890459 seconds. The second exceeds the unchanged
10-second hard limit; its block median also exceeds the nine-second time-margin
threshold. Later faster blocks do not reverse either observation. All valid
process memory readings meet their hard caps. Original proof samples, probes,
invalid attempts and the first failure snapshot remain retained under
`m3-streaming-msm-current-capture-1`; calibration never adjusts the failed time.
Its natural exit is 1. The final ledger SHA256 is
`e38c3b51db7fd21d554c140a331afeddf8b714011d33aa1f117dadef07112d8f`
and terminal summary SHA256 is
`0c3f513adae01026f11c50227b6b5b82fd6ad68a0bbda0016d3e418309ecf01c`.
The executable, build inputs and complete selected local source bytes are
preserved in `m3-real-q-fft-baseline-preserved-1` before any rebuild.
The subsequent baseline diagnostic completes six observations and verifies all
36 proofs, with no host or calibration invalidity, but its final source check
fails after a new merge changes selected inputs. Its natural exit is 1 and the
whole diagnostic is source-inconclusive; it cannot authorize an FFT-only
comparison (`m3-real-q-fft-baseline-diagnostic-1/result.json`, SHA256
`a986e12b0ac7c43c0c2a0299c3b3d421a3493faaa31dc768f966bab89055712f`).
The 32 preserved artifacts and 1,622 source copies remain intact. Fresh captures
must use the reconciled candidate; none of these observations grants a gate pass.
Independent terminal review reconciles all 810 raw files and 270 successful
child tests: 540 proofs verify, comprising 180 measured and 360 calibration
proofs; 144 measured proofs enter valid gate decisions. All memory hard limits
and block margins pass. Sixteen invalid attempts fail calibration stability and
two fail the quiet-memory checks. The review is retained at
`m3-streaming-msm-terminal-resource-review-1/review.json` (SHA256
`4b6892111e47703b567a7181259b832726ec9d2a0b0f3dda72255d46b815a038`).

The reviewed lookup-FFT change is applied after merge reconciliation. It batches
up to four lookup triples in already-owned dead gate columns, preserving field
workspace bounds and the process-wide MSM budget. The actual three-file
application joins the frozen patch and observed before/after images
(`m3-lookup-fft-root-application-1/receipt.json`, SHA256
`52585a42aa111c8be13c41bd70aa87dff7ce025dcd30782c5680fc210cedb04c`).
Scoped formatting passes. The first rebuilt validation stops at strict Clippy
on five missing error-documentation sections in the merged allocation API;
no Rust tests execute. The subsequent repair adds only Rustdoc to those five
methods and three analogous verifier APIs; all non-documentation bytes match
(`m3-merged-api-doc-repair-1/receipt.json`, SHA256
`1d65664c3c460799fb50a7411d6caf6fade94881a233eb60818fbef0c656db98`).
The next strict-lint attempt stops on four style diagnostics in the merged
verification API: two identical match-arm pairs and two implicit raw-pointer
borrows in the existing ownership test. The exact repair combines only those
arms and makes the borrows explicit; branch bodies and assertions remain
unchanged (`m3-verification-attempt-style-repair-1/receipt.json`, SHA256
`2f33a3ea3354d987e7b96138a1c433cfda40680341d5574feb6d4688f51fd62a`).
Both failed attempts ran zero Rust tests and remain retained. The fresh
`m3-lookup-fft-engine-validation-4` run passes strict all-target Pasta/PLONK/
Gadgets/Recursion lint and **317 ordinary tests**, with six declared ignores.
Both new FFT tests and all three proof-byte golden selectors pass, including
both native curves and owned/borrowed PIPA-R parity. Independent review checks
14 child results, four exact compiled inventories, 130 retained depfile
bindings, four test executable identities and all 16 source boundaries, with
no current selected-source drift. The result SHA256 is
`971f894bf94a09e7961a259c62ff21de887eedb2c46c6d50a2997a97b1c4a716`;
review `m3-engine4-terminal-independent-review-1/review.json`, SHA256
`cb548933d4092429cb535213e7985a436f8e01ffd8408a413d8d4c5e8e882398`.
This qualifies the selected component correctness checks.

The subsequent maintained campaign (`m3-real-q-fft-current-capture-1`) stops
naturally when concurrent `Cargo.lock` changes invalidate its final observed
source boundary. It retains 75 attempts: 62 valid and 13 invalid, with all
450 measured/calibration proof samples verified. Three configurations finish
with passing timing/memory decisions: both four-worker A shapes and the
four-worker synthetic Q shape. Real Q on one worker is borderline: its block
CPU medians are 26.713744, 26.808307 and 27.181077 s, so the third exceeds the
27 s margin target while remaining within the 30 s hard cap. Four configurations
remain incomplete. No valid process in this campaign exceeds its hard limits;
that does not qualify an incomplete or source-changed candidate or erase earlier
failures. Independent replay matches every retained verdict
(`m3-lookup-fft-terminal-independent-review-1/review.json`, SHA256
`836548d97da5883123605718053d929907d10d20eaae2d9df7ce708dbb907794`).
The old executable and lock original are preserved. A fresh captured successor
(`m3-real-q-fft-current-capture-2`) retains the same executable and starts the
unchanged schedule. Its first real-Q four-worker block has three valid processes
and a 7.9762655 s elapsed median, then four consumed Norito codec/derive files
change during the next configuration. The normal boundary guard stops this
second campaign with exit one after four attempts; no configuration completes
all three blocks. Fresh current-source M3 qualification remains required.

A separate four-process forced-contention diagnostic verifies eight sums with
identical inputs and canonical outputs within each curve's pair. With
64,678,720 bytes artificially reserved, the earlier scalar fallback takes
5.414–5.603 seconds per MSM and streaming takes 0.348–0.360 seconds. Streaming
peaks at 66,853,760 reserved bytes, below 67,108,864. The held reservation is
accounting, not a physical allocation. Direct child CPU, kernel peak RSS, host
probes and all source/binary boundaries are retained in
`target/qualification/m3-streaming-msm-forced-diagnostic-1`. This is a forced
arithmetic-path comparison, not a repeated-block benchmark, an explanation of
the earlier proof outlier, or a fresh M3 qualification. The previous executable
and source records remain in `m3-pre-streaming-preserved-1`; its valid hard
failure is unchanged. The heavy adversarial result above and the completed M3
campaign supersede no earlier failed or invalid attempt.

The earlier ordinary gadget and recursion run passes 286 gadget and 27 recursion
unit tests, with eight and two explicit ignores respectively. Its compact
component test fails on an obsolete Glue row-count expectation (19 versus the
implemented 16), and that failure remains recorded. The reviewed test-only repair
is applied; both component tests now pass with zero failures or ignores and an
unchanged source interval (`recursion-compact-current-terminal-review-1/review.json`,
SHA `ed3c9c751d015c32190f513e8963efa73053bbd89e7510dd6bab87dac50f9031`).
A separate continuation passes the eight
remaining ordinary integration tests, with three explicit expensive ignores,
and both explicitly selected k16 native full-fold adversarial tests. These are
component checks, not complete circuit, catalog or timing qualification
(`m3-preweight-current-gadgets-recursion-1`,
`m3-current-recursion-remainder-1`).

Twelve wallet files now preserve original resource-refusal errors through
retained choices, policy/blacklist custody and activation/unload recovery;
the subsequent reviewed repair preserves these origins in all 36 remaining
model-decoder calls in the state module, four nested mappings and native Unload
decision verification. The next reviewed repair covers 33 preparation readers,
two intake readers, the retained proof Request reader and nested quota checks.
One opaque original resource refusal now survives state, proof, intake and native
error conversion through the bridge's RESOURCE result. Invalid-input verdicts
and source-read order are retained. The earlier seven new controls and the
successor's eleven new controls are applied; runtime validation remains pending
(`kagemusha-wallet-model-read-family-application-1` and
`kagemusha-preparation-intake-read-family-applied-1/application.json`,
SHA `f0e747a7a4a7e5b86f3415d3c556382e8ef269ff222bc6f342565dfcb3eff303`).
The native checkpoint readers now retain the same original refusal at all eight
A-operation decoder sites and the Q reader. Seven native error families own
the refusal through the wallet mapping to RESOURCE. Exact-length, malformed
input, source/key binding and cancellation checks retain their order. Independent
review found no blocker, and formatting checks pass. Ten new tests cover actual
enclosing sequence/allocation limits, identical-byte retry, observer identity
and unchanged invalid-input verdicts; compilation and execution remain pending
(`kagemusha-native-checkpoint-resource-applied-1/application.json`,
SHA `d085342ae8ad9619e3ff620df9faaf05de47463984817ceed14b3d4f15c40d43`).
The reviewed test-only mask checker now covers Omega, all sixteen sigma roles
and every distinct private Q/A/W original after strict import. Its boundary
closure includes arbitrary advice rotations and the actual rotated fixed-table
cells. Thirteen unit controls and current strict-key import remain unexecuted.
An independent-data scan of 488 retained historical private keys passes 711,481
symbolic checks and the opening-rank checks for their eleven descriptor shapes;
this does not grant current-key authority or close C12
(`c12-private-mask-checker-application-1`). The soundness memo links the
[independently reviewed local ZK derivation](kagemusha_local_zk_v1.md), including
the joint final-response and residual-oracle law, explicit 255-bit bounded
sampling and unconditioned failure bounds. A coherent local Omega-H proof over
a genuine fixed-Poseidon witness needs no all-H private ancestry. C12 remains
open: erasing Omega leaves the exported F-derived P/V and target public sigma
law to be compared, or an alternative coherent source/valid-cut argument to be
supplied. The total public-only proof simulator, actual current-key M(K) reports
and concrete randomness bounds remain required. Reverse dependency order alone
does not supply that comparison; the
[current blocker record](kagemusha_recursion_soundness_v1.md) distinguishes this
privacy obligation from the accepted recursive soundness heuristic.
Retirement source guards pass. The reviewed streaming Core restart
restoration is applied. Its inventory writer and 31 readback controls pass.
After repairing the typed-array and obsolete snapshot-restoration fixtures, all
48 tests in the first consumer group pass. The original broad source gate still
rejected that attempt for nine concurrent, unconsumed Deploy edits; that verdict
is retained. A fresh combined run now holds conservative dependency namespaces
from their first use, checks emitted input containment, and includes Deploy
before its consuming groups. That run passes the 48 recovery, four signed-network
and nine payload-forgery controls, then stops at four resource-contract fixtures:
their genesis block budgets violate current transaction/privacy coherence.
The failure and unchanged consumed-source evidence are retained in
`sccp-forgery-streaming-scoped-validation-1`. The reviewed fixture repair now
uses coherent signed-genesis limits, individual cap+1 rejection, aggregate
packing-window acceptance and residual-capacity rescue. All four repaired tests
pass in the next run, alongside 83 other tests. That run stops before the next
group at an exact-inventory check because merged tests changed the selection.
Review of the complete current Core inventory adds 18 tests and removes one
test of retired GenerationStorage code; every command and count guard remains
unchanged. The next run records 212 passes and nine failures through group17:
network fixtures changed node-local limits after genesis although execution
reads committed policy. The reviewed four-file repair installs these limits
through signed genesis and preserves all original assertions. The subsequent
run records 220 passes and one failure, including 75 of 76 network tests passing.
Its sealed-reveal fixture advanced height without publishing the preceding
commitments. The reviewed correction now publishes a genuine certified height-2
block before executing the height-3 reveal, preserving the quota, hash-ranking,
pending-count and effect assertions. Targeted and complete validation remain
required (`sccp-forgery-streaming-scoped-validation-4`,
`network-sealed-reveal-certified-fixture-application-1`). The reviewed clone-only catalog transport and
fresh-write limit are applied; their Rust controls and current catalog execution
remain pending. The guarded native bridge and complete Swift host suite pass
2,242 tests with no skips (`swift-current-preweight-terminal-review-1`). The
Kotlin/JVM and Java consumer run records 1,897 fresh test cases with two failures:
an obsolete lane-proof encoding expectation and two missing canonical instruction
IDs. It also refuses a retained stale report from a deleted test class; that
report contributes no current coverage. The reviewed codec/fixture repairs are applied; the rebuilt Rust generator
round-trips all sixteen optional-tail/length-layout vectors. The fresh full
Kotlin/JVM and Java consumer suite now passes 1,899 tests in 214 suites, with no
failures, errors or skips. Source, rebuilt generator and admitted native bridge
checks pass before and after execution; terminal review reconciles every raw
XML case (`kotlin-current-core-jvm-terminal-review-4/review.json`, SHA
`cd3291693fbaf0ecbb7324c1de9f06a766f4ea6676dee148d306f57409252c38`).
The failed run and stale report remain retained. Current full-catalog,
native-finality network, Android and physical-device qualification remain open. Results retained
below apply only to their named captured candidates and do not transfer across
the merge or these edits.

The approved first-release Load design verifies Sumeragi BLS evidence natively
before signing Advance under the released-app/uncompromised-OS profile. The
monetary proof binds the receipt and credential-bound signature; it does not
supply an independent BLS funding proof to the receiver. Current Load has four A
stages and three W continuations. Rebuilt A/W/Omega keys, source profiles, signed
inventories and current-candidate integration are required by
[NF1–NF6](kagemusha_native_finality_goals.md); historical recursive-finality
qualification does not transfer. Full protocol, M3 and phone gates remain open.
Fresh Load selection verifies native finality; an unsigned restart may sign only
the exact authenticated durable Selected capsule, and completed retry returns
retained output without a new signature or credit. This is custody-based reuse
of the same selected operation, not repeated BLS verification on every resume.
Torii serves one exact original epoch-boundary certificate per bounded request;
it does not traverse ordinary intervening heights. Native manifest custody
authenticates and durably retains each successor epoch, including older receipt
epochs. SDK synchronization resumes its bounded work across calls and restarts;
terminal receipt evidence contains one certificate and counted event proof.

The earlier 20-seed Sumeragi component run passes 495 tests in total: 493 library
tests and both specification integration tests. The heavy 100,000-interval idle
case and report-only case remain explicitly ignored; there are no doc tests.
All 497 registered names reconcile with the results. Original/final source,
tools, emitted dependency inputs and test executable checks pass in
`sumeragi-current-component-1`. Its separate strict 152-mutation run reaches a
failure in the unmodified 200-seed baseline: F28 key rotation fails seed 177,
while its other 199 seeds pass. At 85,000 simulated milliseconds, honest replica
3 has committed no heights after healing, against the required five; its trace
remains at height 14/CommitQC 13 while peers reach height 75. The actual failing
child's source and executable checks pass. Its original log and exit 101 remain
in `sumeragi-current-mutations-1/cargo-0339`; this is a baseline liveness failure,
not a mutation kill. The gate later stopped without a terminal receipt; no matching process remains.
Its incomplete later mutation attempts remain retained. The applied repair lets
validated Sync responses enrich the download sources of an existing body request
restored without local rows. Certificate, parent, epoch and custody checks remain
unchanged. Two regressions cover source enrichment after durable restart and the
exact F28 seed; ML32 restores the old source-suppression guard. Fresh strict
validation passes both regressions and all 200 F28 seeds. ML32 is killed by both
regressions: the source-enrichment assertion fails, and seed 177 reproduces the
original post-heal stall. The full mutated F28 sweep fails only that seed. All ten
child invocations pass their source, executable and feature checks
(`sumeragi-f28-ml32-current-1`); there are no build errors or timeout kills.
The fresh 20-seed component run includes the repair and passes 497 tests with
zero failures and the same two explicit ignores. All 499 registered names
reconcile with its raw results; both new regressions pass. Independent review
checks all four child records, 1,534 current source entries, 72 retained depfiles
and both executable identities (`sumeragi-current-component-2/result.json`, SHA
`66b31ef8f95e17438d29991ff3a99bd28c17aa7994a24fa2797db6a11c4968a6`).
A separate source-saturation recovery repair is now applied: a bounded list
filled with stale sources retains the verified live Sync responder, preserving
committee peers and retry fanout. An invalid deferred certificate triggers a
bounded refresh at the missing height. Initial admission reserves the complete
896-byte donor slot; replacement needs no additional capacity. Independent
static review passes; the focused runtime result is recorded below
(`sumeragi-sync-donor-root-application-1/receipt.json`, SHA
`284000e8e133466f57ed677d7a586335617913cc14fdf48a9cde95753cdc534d`).
The predecessor 153-mutation run finishes naturally with a reported passing
baseline and source-custody refusals for all mutations after this edit; it records
zero kills and no qualification (`sumeragi-current-mutations-2/result.json`, SHA
`5496fdd87aede1f76cf43741774b2e10fa9ce8d5b0bc7111416ecb6f1896e952`).
The first fresh targeted ML32/33/34 run stops before tests on ten incorrect
`CoreStatus` field accesses in the new regressions. The test-only repair reads
the existing `footprint` fields without changing assertions; scoped formatting
and diff checks pass (`sumeragi-sync-donor-footprint-repair-1/receipt.json`, SHA
`b260672f044aaa0b17dd05d8053f77d8b6f4cb94fb1ea27e83a2515dc1c609d5`).
The corrected targeted run passes all four named baseline controls and the full
200-seed F28 sweep; ML32, ML33 and ML34 are each killed by their required tests.
ML32 also reproduces the seed-177 stall. Independent review checks all 20 child
records, 320 retained depfile hashes, four mutation-specific image chains and
the final 1,534-source union (`sumeragi-sync-donor-regressions-current-2/result.json`,
SHA `f70be91a792d9e03d4418ab705ea1b7aeee33b2aa58f9215bcd9ee36c317bf10`).
Strict lint separately fails on six adjacent style diagnostics; its original
failure remains retained. The reviewed five-file repair preserves membership
checks, lazy fallback, helper bodies and all eight moved tests. It is applied
with passing scoped formatting checks (`sumeragi-adjacent-strict-lint-repair-application-1/receipt.json`,
SHA `090d486e9c0bfbe5452c195d8a7e4a343adb56d5a5c44e6b49e762f84e814206`).
Fresh strict all-target Clippy passes with `-D warnings`, including the custom
build target, library, test library and spec test. Independent review confirms
all 1,540 selected entries, 193 artifact identities, 18 retained depfiles and
11 tool executable hashes (`sumeragi-current-strict-lint-3/result.json`, SHA
`566f46304529dc688f158547a610c1d1781884729af7d6f7e162e110ae3d6fa5`).
The fresh 20-seed component suite passes **500 tests**, with zero failures and
two explicit ignores. Its 502 selectors reconcile exactly with raw library and
spec-test outcomes; the donor controls and all 13 signing tests pass. Independent
review checks four child intervals, the 1,534-source union, 72 retained depfiles
and both executable identities (`sumeragi-current-component-5/result.json`, SHA
`77f574baf212bcc6ef43bb86b2fdcd45d3a23227f786c8a5345ed60bfd2778cb`).
The subsequent full 155-mutation attempt ends naturally with exit 1. Its
baseline passes 166 named tests and all 36 scenarios at 200 seeds, then MS64,
MS65, MS66 and MS1 are killed by their required tests. The next mutation compiles
but its admission refuses a changed `Cargo.lock`; all 151 remaining mutation
errors follow that source refusal, rather than establishing survived mutations
or additional protocol failures. Independent review checks all 375 admitted
children's original logs, source intervals and executable identities. The final
boundary contains 30 changed or added paths, including 22 emitted Rust inputs,
so this is historical partial evidence, not current-candidate qualification
(`sumeragi-current-mutations-5/result.json`, SHA
`5496fdd87aede1f76cf43741774b2e10fa9ce8d5b0bc7111416ecb6f1896e952`).
The resolved source passes fresh strict all-target lint in
`sumeragi-current-strict-lint-4`. The next component launch refuses during
preflight after concurrent work adds Core mutation HC343 and its specification
row; no component child starts. After that exact source join, strict all-target
lint passes again in `sumeragi-current-strict-lint-5`, and the 20-seed component
suite passes **513 tests**, with zero failures and two explicit ignores
(`sumeragi-current-component-6/result.json`, SHA
`8b8006e07f09e23749920a0a27b02abd63b929137076df1d79ea423a821ce215`).
Independent review reconciles all 515 selectors, four Cargo exits, 72 retained
depfile bindings, both executable identities and the 1,536-source interval
(`sumeragi-component6-independent-review-1/review.json`, SHA
`0bcdfa7318780bc8dd53d1a472c8b0be5131653858a1e0f8b69f459728877242`).
Later additions HC344–HC352 affect only the unselected Core mutation table and
its specification rows; the retained review confirms identical remaining script
AST and specification bytes. The fresh full 162-mutation gate must bind that
update; the four earlier kills cannot be reused as current passes. The
10,000-seed suite and F22 idle stress remain unqualified. These component results
do not establish current Core recovery, native Load, real-network or phone
acceptance.

The stock-profile native network harness compiles in
`native-finality-harness-capture-8`, but its strict source closure fails. Three
consumed SDK inputs changed during compilation: `client/payment_return.rs`,
`client/native_payment.rs` and `client/native_payment/carrier.rs` in `iroha`.
The preserved inventory contains 85 local packages, 98 depfiles and 4,233
compiler inputs. It is source-inconclusive and supplies no runtime acceptance.
The original build result and failed closure remain retained; the root
disposition is `native-finality-harness-capture-8/root-terminal-disposition.json`
(SHA `e350cafa9b9aea82e1e34001d7de489916b9ff9c479dfffd88127344dca4b2f1`).
Fresh capture must include the settled SDK edits and the applied reviewed
donor-retention repair before network qualification.
The corresponding node/CLI capture, `native-finality-stock-capture-12`, also
compiles and passes its stock-feature audit, but fails source closure on the
same three SDK files. Its inventory preserves 89 local packages, 103 depfiles
and 4,580 compiler inputs; the source-inconclusive disposition is retained at
`native-finality-stock-capture-12/root-terminal-disposition.json` (SHA
`b2de788ba7c7632d3bd377f50c1033d0c50dc52bf60989d95fc10074ad56ed2d`).
The subsequent `native-finality-stock-capture-13` exits 101 after 3,076.72 seconds:
the SCCP flow expects authenticated receipt evidence, while its compiled EVM
transport still exposes the earlier receipt signature. This is a compiler
failure, not a source-qualified build. The original diagnostics and result
(SHA `f8936cea2d4e5ff99fa750e224b037f94903caa07ae36ba27cb69e012f4889c7`)
remain retained. Concurrent SCCP repairs require a fresh build and validation;
this failed capture supplies no network acceptance.
The paired `native-finality-harness-capture-9` compiles successfully in
3,319.93 seconds, but its wrapper reports source-inconclusive and strict closure
rejects the changed HEAD. Preservation inventories 85 local packages, 98 depfiles
and 4,275 compiler inputs; 4,269 input files are retained and six are missing.
Its copied binary is
`410530ff22298877a0df1fe09671184b9362bf8a42dae910df998ab47584293f`;
the root disposition is `root-terminal-disposition.json` in that capture
(SHA `948f7becc310566d3fbd3629ed19de128855273192482d19ec67a8e6eff2e321`).
No runtime or current-candidate acceptance follows from the compiler result.
The subsequently integrated SCCP receipt path also receives an independently
reviewed deadline correction: all three authenticated Torii reads use the
existing absolute-deadline client, preserving authority and the shared runtime.
Three new tests cover stalled reads, sequential budget consumption and missing
or expired budgets. Formatting passes; the complete 15-test receipt module is
awaiting execution results. The source application is retained in
`sccp-receipt-torii-deadline-application-1/receipt.json` (SHA
`8fa644b63a8bb5c97ed1ee13e4c43eb42868d6736d62e9157f548ff64df353ed`).

Linux worker capture2 also compiles, then refuses the changed
`iroha/src/client/native_payment.rs` compiler input before executing its worker
test. Retrieval preserves all 629 inventoried files with equal before/after
inventories. It separately refuses a changed `/usr/bin/bash` file identity,
despite unchanged bytes. Neither mismatch is waived. The failed worker result
and retrieval disposition remain in `kagemusha-linux-worker-retrieval-2`
(`root-retrieval-disposition.json`, SHA
`97e7d2a0fa98872303e41e23b3f899ca927dd524b38e0bebcc1efd94dd0e6d75`).
The guest shuts down normally; both original disk hashes, sizes and mtimes
remain unchanged, and recovery overlay hashes are retained in
`kagemusha-linux-issuer-recovery-1/disks-after-poweroff.json` (SHA
`c4ee6f00c5a2e870e2bac9b3a62c882c3a886048109f85f4d46c0c7dc4d08f29`).

Thirteen funded ancestry/Send/Receive cases are now registered in the proof crate's
`receive_omega::native_load_tests`, using the same verified native-BLS first-Load
fixture as Load/Omega. They cover accepted and corrected-burn outer closure,
accepted/renewed owner chains, both corrected-burn insertion branches,
nondeciding carried claims, compact catalog re-keying/identity and funded Send
authorization and installed-native replay, preserving the existing genuine
source and mutation assertions. The oversized generic-Ω/Send joint-bound
negative also has an explicit native-BLS entry point in `a_receive_native_bounds`.
All five affected integration targets now compile in the release profile. The
local-input review preserves 46 emitted artifacts, 37 packages and 1,303 inputs,
with no missing or changed compiler input. One changed data-model test file is
excluded by its unchanged `cfg(test)` parent and normal library artifact; the
original broad source-drift verdict is retained. The review is
`native-funded-proof-build-1/consumed-input-review/receipt.json`, SHA
`42e6d0840d146f517ea77ed7e139ac8f00102372c9939da4ec684a1a6d2c8a46`.
The Receive, Archive, consuming and bounds harnesses pass 19 ordinary cases
in total. The Load harness contains only ignored proof cases, so its ordinary
invocation exercised no tests and is not a pass. The first genuine native
Load-to-Omega run failed after building the four A-stage artifacts: the source-substitution
assertion detected that native preparation accepted changed receipt bytes.
The A3 circuit already binds the receipt digest; this failure exposed a missing
matching native input check, not a demonstrated circuit bypass. The original
failure is retained in `native-funded-load-outer-1` with natural exit101.
Native preparation now checks the exact receipt digest before predecessor/Q
verification, with a new regression covering every receipt byte, a foreign
domain and a changed statement digest. The fixed library and all five test
targets compile, and all seven native Load unit tests pass. Capture2 preserves
47 emitted local artifacts, 37 packages and 1,344 inputs without missing or
changed compiler inputs; only the evidence/status records changed during the
build. Its local-input review SHA is
`66d499efeb13aae96600cfb37f1c7c6d91f03286cbc1f299f147158d1ade74e5`.
The fresh genuine native Load-to-Omega regression passes, preserving all six
source-substitution assertions, all four A/three W stages and complete outer
verification. Its result SHA is
`4beb0f904011086859c547d4a9924d38724476cf235c798c663f3770db1c89fd`.
The diagnostic generic wrapper has 9,856 proof bytes and 10,944 transport bytes,
so it does not pass the production size gate. A separate compact diagnostic
produces 3,712 proof bytes/4,800 transport bytes but does not establish the
complete catalog or carried-key continuity. The separate genuine two-terminal
Bootstrap/Load rekey case also passes, including actual source-key equality,
descriptor equality and outer-key binding. Its result SHA is
`cc75701bc448f470a602292000bad5b5ec86710f4704e046f6b9451703115c23`.
That generic partial catalog still does not pass the production size gate.
The separate compact Bootstrap/Load case also passes with both genuine proofs,
native original import and transport restoration, equal source keys, and the
common outer key bound before signing. Both partial-catalog transports are
4,800 bytes. Its result SHA is
`53de9b0afdacc84c3e05e1c96ebab9525a2f1ae25c655d4ed74e2658fe6686a5`.
The three-terminal Bootstrap/Load/Send-mask0 rekey case also passes with actual
native proofs, unchanged common source keys, complete Send stage/context/map
checks and 4,800-byte transports for each terminal. Its result SHA is
`0a2da2eaa511087a7e14d6edc3fdea86b56301c221400757b2d7f315d98d854b`.
The fifth case also passes: native-funded common-key Send executes the complete
five-A/four-W authorization, map and opening schedule, preserving mandatory own2V1F,
the exact 320-byte predecessor transcript and all final-state assertions. Its result
SHA is `b13ea630ce02d9dabef824e4f560df52804b890fb6c4d473bf7531f106f5a8a8`.
The sixth case passes for two distinct wallet identities sharing byte-exact
binding and verifier-key originals: Bootstrap, funded Load and receiver Bootstrap
all verify with 3,712-byte proofs and 4,800-byte transports. Native original
import, restoration and both terminal decisions pass. Its result SHA is
`74411d91631d213e74871396359f9cce033752fed472c62aabc7f4719e03b625`.
The seventh case also passes: native-funded Load retains its exact predecessor
catalog, and its lineage key digest equals the retained key/binding digest.
Both compact Bootstrap and Load transports verify at 4,800 bytes. Its result
SHA is `74fc1d84d285232e8d9ee0ea6e27591d029eb8034ca46abd395cb19f6a1c54f5`.
A five-second stack sample instrumented this correctness process; its elapsed
time is excluded from performance qualification. Case8 stops the campaign with
natural exit101 after its five-A/four-W native Send stages and exact checkpoint
replay complete: native preparation accepts a changed Credential tape
(`original mutation4`). The circuit still binds the object; native preparation
checks its length but does not join it to the authenticated object/Q exports.
The failed result is retained in `native-funded-campaign-two-case08-1`, SHA
`ede5f8b3cbb04a633f67d6eb433b8952ca265dc098ffa07ed80cffcd51ce7c7d`.
Seven cases pass, one fails, and thirteen remain unrun. Native Send preparation
now joins the five exact signed tapes to their existing state/statement digests
and the fixed three-slot signature-Q exports, including authorized keys and the
derived receipt. The absent-fee fixed dummy policy is preserved. Four new unit
cases cover byte mutations, Q exports/shapes, receipt projections and zero-fee
behavior. Isolated capture3 compiles all six selected targets; its retained
compiler-input review binds 47 local artifacts, 37 packages and 1,344 source
inputs, with exact Cargo environment/configuration/link-output joins. All fifteen
native Send unit tests pass (zero failed or ignored), result SHA
`803828a6ce69f088ef2ce96373c0448e412eb07fadb3509d50bf3166ca3c872c`.
The unchanged genuine failed case now passes against the captured executable
in `native-funded-send-retry-1`, result SHA
`09c5c90a6cbcf439c2196769db4c574e2462bdf20b24c2e43ffb646f7d6e7ce8`.
All five A/four W stages, exact original/checkpoint replay and the original
mutation assertions complete. The failed case remains retained. This repairs
case8. The retained remaining-component campaign passes cases9–14: nondeciding
incoming Omega correction, four-obligation acceptance, exact payer/receiver
heads, and corrected burn/credit/consumed-root checks. Case15 (ReceiveRenewed)
fails with `RowOutOfRange` after955.202 s: its copied ordinary-Receive partition
requires65,675 A1 rows against65,529 usable rows. The production renewed schedule
already places the credit-effects task in A8. The fixture now binds the shared
`OperationSchedule::for_variant`, preserving every assertion and all hard caps
(`receive-renewed-stale-fixture-correction-1/result.json`, SHA
`3edaca55ca0a46df4cbde776daa910918abbcd6dfcfd50b277625532656dd0c8`).
All six requested proof targets rebuild successfully in915.557 s, with no compiler
diagnostics or source/tool/metadata drift (`load-q-public-inverse-proof-capture-4/result.json`,
SHA `b97c3a63dcd25554e9d44c6b5997f539d8abc739bcdbc6c213c3d8bdf8f7960d`).
The capture preserves339 artifacts,38 generators and14,825 compiler inputs;
its3,311 inherited external inputs lack prior compile-time byte pins, a retained
limitation. Independent compiler-input closure review admits the captured component
execution. Corrected case15 passes with all original assertions intact
(`native-funded-remaining-components-2/case-15/result.json`, SHA
`d7c17ed07ebc3fea2a5e90a313752b2d985911edb32557b057280887d7e7e5ea`);
its executable SHA is `12cac9c1078633bd199c43ed98698b5e44683181937b5d1a0dbe10578cf52139`.
The original failure stays retained. Case16 Archive acceptance now passes all ten A and
nine W stages, including nineteen restored canonical checkpoints and retained-owner
checks (`native-funded-remaining-components-2/case-16/result.json`, SHA
`c18808a7bd0537a7bff409c0317794f9ee96ebc34d8478afcb4d92a3655477b1`).
Its executable SHA is `d31045854f9efc0c78251cbdcb660971a03c074034455072a5d0f39d82326f19`.
Case17 full-envelope-tail no-op also passes all ten A and nine W stages, restoring
all nineteen canonical checkpoints and preserving the adjusted pending state with
`valid=false` (`native-funded-remaining-components-2/case-17/result.json`, SHA
`25874944071dfbe5da781d723088e6b925ab2dd67d8f8d4476f9f572c9f29376`).
Its source/binary custody checks pass before and after execution. Case18
invalid-proof no-op also passes all ten A and nine W stages and restores all
nineteen checkpoints, preserving the adjusted pending state with `valid=false`
(`native-funded-remaining-components-2/case-18/result.json`, SHA
`5c5b6199533a42b6007946d3e973211f73efd5c13102ca2213df2234747ed73d`).
The same executable and source custody pass before and after its natural exit0.
Case19 stopped with exit101 at the fixture predecessor-root assertion before consuming
stages: the Unload helper rebuilt a different synthetic receipt instead of the
authenticated Load original. The failed result and passing source/binary checks
are retained (`native-funded-remaining-components-2/case-19/result.json`, SHA
`23daefa2ce932cef4741fe11660feee7eccf0b17fe338060bc34fe9fda739953`).
The fixture correction is in progress; cases20–21 remain unrun. These are genuine
component checks, not final Omega admission or complete payment-envelope measurements.
The fifteen unit fixtures alone test bindings, not signature authenticity or
complete proof admission.
The analogous hard-own-tape checks are applied to Receive, Archive and consuming
preparation after independent source review (`native-own-original-q-binding-independent-review-1`,
SHA `dd1ca8fea61ea1435988b82da4b476ed12e2d8c38479fbc6edbb197e134157e8`).
Receive/Archive also join their own sigma and statement to Q0. The current native A namespace passes all95 ordinary tests, including the five
new DATA controls, with four heavy cases explicitly ignored
(`native-own-original-q-controls-1/result.json`, SHA
`bd90f95970735f57bc2442e7e1f9627bf0f8f691e8307987a1e2420a2c1ebf3b`).
The original remaining campaign stopped at the case15 failure. Its source-bound
successor passes that corrected case, Archive acceptance and both invalid-proof
and full-envelope-tail no-ops, then stops on the case19 fixture failure; no terminal
pass is inferred for the failed or unrun consuming cases. Incoming soft tapes are excluded from these hard checks; circuit
owners and native Q verification retain their existing responsibilities. The
21-case component campaign has no ArchiveStatus case, but the ignored complete
wallet A→B→C test already contains its positive genuine CreditStatus route;
neither source coverage nor these reviews establish a runtime pass.
These partial catalogs do not establish full52 size, other control
masks or complete key continuity. Circuit layout
and the native BLS authority boundary are unchanged.
The new funded entries still require genuine proof execution. Their synthetic executed receipt
and partial catalogs cannot qualify the real network or complete52 artifact set.
Five additional funded cases are registered under `a_archive_recursive` and
`a_consuming_recursive`: Archive acceptance, invalid-proof and full-envelope-tail
no-ops, plus Unload/Retiring all-owner composition and installed-native checkpoint
replay. They use the same verified receipt and fresh predecessor originals.
The five existing composition/mutation function bodies are unchanged. These
registrations compile in the same capture. Archive acceptance and both no-op
branches pass; the consuming replay case fails during fixture construction and the
all-owner case remains unrun. Neither compilation nor these component passes grant
complete catalog, network or performance acceptance.
Pre-migration local release-profile checks pass all14 compact certificate/checkpoint
tests and258 ordinary KAGEMUSHA model tests, with five explicit tests ignored.
The four vector checks are a subset of those258 and match the current shared
fixture without regeneration. The codec retirement guard also passes all five
checks. Logs, commands, numeric exits and the model executable hash are retained
in `native-compact-validation-1/model-results.json`, SHA
`53ca638376618d1c9852f768cbd92571521e3e153f2b7bc6eb2bea55a1a274a5`.
These are ordinary component checks, not a complete release compiler-provenance
capture. The coherent recovery-body/opening and bounded-retry migration is now
applied across119 paths with every prepared after-hash matched
(`capsule-coherent-aggregate-application-2/result.json`, SHA
`cb3546a4f3b887a311d73d1c72de55eb04c9d9aa50adeb4271da55755bd9999c`).
The first integrated compile exposed a missing DTO slice-decoder implementation;
the owner now delegates to Norito's canonical prefix decoder, retaining nested
validation and exact consumption, with an added trailer/truncation control.
The failed build is retained. The maintained Rust vector writer then passes its
one exact test (`capsule-coherent-model-fixture-write-2/step-01/result.json`, SHA
`9a218bebe713f4c5b3689837f7e998359c7b24f7a377c65cbf2a464b3ef17475`).
The regenerated fixture SHA is
`85a03f75943c6b6f6796dc8e2c4ca8ae23958808ac667e71b4bac42b3308708d`:
29 frame contracts,21 digest roles and60 Poseidon domains. A fresh recompilation
then inventories229 wallet model tests, zero ignored, and passes all229 with the
fixture unchanged (`capsule-coherent-model-validation-1/step-04/result.json`, SHA
`275180ce7ba72eefe407b6c0ca7b8bf05ea2152c0d9ea6a50365cf185677f626`).
Before the subsequent integration merge, the first native bridge build passed
compilation but failed provenance admission
because `manifest.rs` changed during compilation; that refusal is retained.
After preserving its required generic type annotation and removing two unused
preparation wrappers, the fresh native build passes compilation and guarded
source/ABI28 admission with345 exports and no source drift
(`kotlin-current-native-abi28-2/capture/pins.json`). The first current CoreZK
test build exposed 16 test-only migration errors. The reviewed nine-file repair
updates fixture ownership/accessors and retained Request decoding. Its compiled
inventory then exposed the incorrectly selected freeze test module. An explicit
`freeze/tests.rs` path now selects all six intended tests instead of seven
parent duplicates. Those six controls, the six Omega mask-boundary controls and
the complete-route descriptor-capacity control pass in the subsequent suites.
The preceding Kotlin run reports 1,906 tests and two stale-expectation failures;
its source, generator and native postchecks pass. Those failures remain retained.

After the integration merge, the fresh ABI 29 capture passes guarded admission
with 345 exports, 499 artifacts and 499 depfiles, with no source/identity/tool
errors (`kotlin-current-native-abi29-2/admitted-review.json`). The earlier ABI 29
attempt correctly refused a concurrent test-source edit despite successful
compilation. The current generator capture and 31 focused Kotlin tests pass,
then the unfiltered JVM suite passes 1,882 tests in 211 fresh XML suites, with
zero failures, errors or skips and clean provenance postchecks
(`kotlin-current-core-jvm-2/result.json`). Its 1,906→1,882 selector change is
reconciled against the incoming enrollment migration; this execution does not
claim retirement completeness. This SDK receipt predates the three test/vector
corrections below. Current Swift uses a fresh guarded rebuild after them. The
first run passes 2,240 of 2,241 tests and fails one stale negative selector
assertion: selector 20 is now the valid AbandonLedgerInstruction. The correction
moves only that negative assertion to unsupported selector 21 and retains the
positive selector-20 assertion. The maintained rerun passes all 2,241 tests
(4 + 2,165 + 72), with zero failures or skips and successful native verification
after the suite; source and fixture postchecks remain unchanged
(`swift-current-abi29-launch-2/result.json`, elapsed 1,693.741 s). The failed
first run and exact correction remain in `swift-current-abi29-launch-1` and
`swift-enrollment-selector-test-repair-1`. This is host/simulator evidence,
not physical-phone qualification.

The merged main fixture
`fb58fa5336515cb18f804c732feb6aa413455c8b6524e44cabff3159969a413b`
passes all 233 current wallet model tests, with zero ignored and unchanged bytes
(`capsule-coherent-model-validation-2/step-04/result.json`). The first ordinary
wallet run reports 794 passes, three failures and 25 explicit ignores. Two
private enrollment-worker vectors retained the prior provider-bound scheme;
the maintained Rust writers regenerate both from the current scheme. Their
readbacks and the actual Rust-to-Python exchange pass; all 67 selected Python
policy/worker tests pass. The recovery regression now separates loss of private
W from loss of the authenticated StepEntry index: the former preserves exact
Complete bytes, while the latter returns WitnessLost; neither path re-signs.
This is a test correction to the existing bounded retry implementation.
The rebuilt follow-up inventories 822 tests and passes all 797 ordinary cases,
with 25 explicit ignores and zero failures in 339.545 s
(`capsule-coherent-corezk-validation-4/step-07/result.json`, SHA
`f25dc44956f622c53154c81662521febb4881fe1b55313e246eace8997a0b3ef`).
The failed run and correction receipts remain in
`capsule-coherent-corezk-validation-3` and
`capsule-corezk-three-failures-repair-1`. Ordinary component tests do not supply
release compiler closure, proof performance or physical-phone qualification.

The current two-target proof capture compiles and passes independent emitted-
input custody review (`c12-load-q-capture6-independent-review-1/closure-review.json`).
All three actual-original consuming controls and genuine cases 19–21 pass.
Case 21 verifies oversized-envelope rejection with real proof inputs in
842.45 s; the complete serial component job exits naturally with zero failures
(`native-funded-remaining-components-4/result.json`, SHA
`4d67bae8d1c64b876fe5086b269179e68ef5f7ca36e9c1f5726d301b149c2374`).
Case 19 retains the Unload/Retiring differential,
checkpoint replay and hard-owner rejection controls; case 20 retains both
all-owner circuit chains. Receipts are in
`native-funded-remaining-components-4/case-{19,20,21}/result.json`. Historical
external-input provenance limits remain explicit. Core replaces retired
attestation/roster state with native committee generations, liability time and
original anchors. The storage, hook and consumer migration compiles and passes
223 SCCP tests plus all three public-boundary tests
(`sccp-native-core-validation-5/result.json`, natural exit 0, unchanged captured
Core sources). These include snapshot, fee, routing and block callers. The prior
incoming 206-error build, repair attempts and earlier 176-test component pass
remain retained. The first inventory selector matched zero tests and provides
no coverage. The corrected selector ran 29 cases: 26 passed, two stale expected
source/classification assertions failed, and the explicit regeneration case was
ignored (`sccp-native-consumer-validation-6`). The repaired suite passes all
28 ordinary cases with the explicit regeneration case ignored, unchanged captured
sources and natural exit 0 (`sccp-native-consumer-validation-7/inventory/result.json`).
Codec and retired-prover source guards also pass
(`kagemusha-retirement-guards-20261012-1/result.json`). The five retired Torii
proof/roster routes are removed while all 14 current routes remain. The first Torii
consumer build stopped on 12 Rust SDK references to the removed API; that failed
attempt is retained (`sccp-native-consumer-validation-7`). After removing the obsolete
SDK methods, the next source-stable run passes all 3 focused SDK tests, 15 Torii
SCCP tests and 101 route-catalog tests, with natural exit 0
(`sccp-native-consumer-validation-8/result.json`). This does not qualify the pending
native proof/committee API or its CLI and wallet consumers. The coordinated
153-file certified-result producer/reader switch is applied
(`sccp-certified-result-coherent-candidate-1/application.json`). After repairing
its missed model projection and Core consumers, 26 certified-result tests,
10 private-dataspace model tests and 231 Core SCCP tests pass. The three ordinary
Load fixtures are regenerated by their Rust writers and all three readbacks
pass (`sccp-ordinary-load-fixtures-regeneration-1`). The captured matching model
binary subsequently passes all 275 KAGEMUSHA tests with five explicit ignores;
its source, binary and fixtures remain unchanged
(`kagemusha-model-after-certified-result-1/result.json`). The new terminal-scope
coverage first exposed a private fixture missing its signed SNS fee policy;
that failed attempt and the following test-only enum-name compile failure are
retained. The corrected terminal-scope and genuine private-export selections
pass all 12 tests (`sccp-certified-result-current-validation-5`). The publication
suite first reports 46 passes and one pool-accounting failure; the unchanged
single test passes in isolation. A test-only epoch pin prevents unrelated
reclamation during its exact refund assertions. The current rerun passes all
47 publication tests with unchanged sources
(`sccp-certified-result-current-validation-6/result.json`). This does not
qualify eventual epoch reclamation. The same binary exports an actual H1/H2
ledger setup (`kagemusha-executed-setup-after-certified-result-2`); its signed
genesis, network identity and asset incarnation differ from the prior catalog,
so that catalog cannot yet supply the current monetary acceptance inputs.

The separate native consumer candidate passes 179 isolated library cases,
including all 15 TON cell cases and the complete committee DATA decoding
controls, plus 17 wallet EVM integration cases
(`sccp-native-committee-ton-isolated-validation-2`). The initial committee
missing-field test failure is retained; required optional fields are now explicit. Authenticated
EVM artifacts pass all 297 candidate fixture runtime tests on Prague and Osaka
(`sccp-native-evm-runtime-validation-2/result.json`). The first runtime attempt's
reporter-count refusal and earlier isolated compilation failures remain retained.
The combined 120-file Core, Torii, SDK, CLI and evidence consumer migration is
applied with its original index preserved
(`sccp-native-consumers-coherent-candidate-1/application.json`). Its model fixture readback passes 336 tests with six explicit ignores, the
consensus schema controls pass two with one explicit ignore, and the SCCP model
selection passes 149 with two explicit ignores
(`sccp-native-consumers-model-validation-4`). The grouped evidence codec and
consensus roundtrip selections pass eight and nine tests respectively. A later
standalone test exposed a misplaced native import; that failure is retained and
the import is corrected. The subsequent focused run passes all 487 tests:
28 standalone roundtrip, 43 governance, three event-filter, 344 native SCCP
library, 52 wallet-library and 17 EVM signing cases, with zero failures or
ignores and unchanged captured sources
(`sccp-native-retirement-runtime-validation-1`). Combined Core/Torii/SDK/CLI
consumer validation remains in progress.

The retired SCCP modules and fixtures are removed while ordinary Ethereum
signing remains. The maintained Rust writer, both Rust readbacks, TON renderer
and drift check, and two independent Python tree/history tests pass
(`sccp-native-retirement-fixture-generation-3`). The tree uses native 199-byte
controls; payload and native EVM calldata bytes remain exact. The two prior
compile failures are retained: missing new-event filter arms and a missing
scalar `Copy` derive. The filter repair includes a regression for global
evidence versus route-specific holds. No contract or network qualification
follows from fixture generation.

The combined Core selection now compiles and executes: 277 of 284 tests pass
(`sccp-native-core-integration-validation-3`). Its seven retained failures
include two genuine-certificate signature failures: production Core/model
consensus used the w3f transcript while the native SCCP verifier requires
the accepted allowlisted `ConsensusDigest`/`DST_SIG` path. The signature check
is not relaxed. The other failures cover missing forgery Execute registration,
canonical-time fixture assumptions, an invariant-error assertion and a malformed
control fixture. Original World journal/publication checks pass 21 tests in the
separate continuing tail selection; no failed group is counted as passed.
The subsequent source-stable tail passes 77 checks before the public-boundary
test fails compilation on its missing root-scope argument; that call is repaired.
Permanent forgery custody and exact current/undo snapshot joins are applied.
Their first compile exposes seven type, fixture and refusal-classification
errors; the reviewed repair preserves original resource categories. Native
consensus production and genuine fixture consumers are now migrated to the
unchanged allowlisted suite, with explicit old-suite rejection controls.
The first combined native run passes 397 tests in its first eight groups,
including all 117 certified-chain cases. Its next custody group passes seven
and fails one test whose predecessor-cell fixture encodes the undo value as a
scalar instead of the required object; that test-only repair preserves both
mixed-cut rejection assertions (`sumeragi-native-consensus-current-validation-1`).
The subsequent explicit-feature model selection passes 188 with one failure
and one explicit fixture-writer ignore: a test compares Debug strings containing
distinct per-attempt resource-owner identities. The repaired test compares exact
refusal fields and origin classification and rejects reuse under a later owner;
the current explicit-feature rerun passes all 189 ordinary cases with its one
fixture-writer ignore. That fresh attempt passes 324 tests across six groups,
then Core test compilation exposes 14 fixture API errors (MV cell/storage writers
and a nonexistent JSON macro), with unchanged sampled sources
(`sccp-native-consumer-combined-validation-3`). The two-file repair uses actual
block writers and supported Norito value construction, retaining all assertions;
the first focused compile retains one missed MV type namespace error. After its
single-path correction, the fresh focused run passes all 21 cases: custody 8,
shared hold predicate 2, liability 6 and staking 5, with unchanged sampled sources
(`sccp-hold-liability-custody-focused-validation-2`). No failed group is counted
as passed. The shared forgery/quarantine value-path predicate, closed Held
status and original-registration liability guards are applied with consumer and
adversarial tests. A second unchanged-source selection passes all 26 outbound,
settlement and self-claim cases (6/17/3), including held proof/fee/value, pending
refund and bounce guards (`sccp-held-value-flow-focused-validation-1`). These
47 focused checks do not replace the incomplete combined consumer qualification.
The coherent submission, current-parent selection, direct signed-source execution
and delayed-penalty paths are now applied across 45 files. The candidate preserves
the original Queue rows when skipping stale claims, checks forgery validity before
spending block quota, and refuses late execution-output failures before publication.
Independent source reviews found no remaining scoped blocker. The first 77-group
combined attempt passes the six model/crypto groups (324 checks, two fixture-writer
ignores), then exposes nine Core compile errors in imports and one migrated Queue
test helper (`sccp-forgery-focused-validation-1`). Those errors are repaired; a
subsequent compile catches the unsupported anonymous lifetime in a generic control
argument. The verifier now takes its actual control enum directly. The repaired
Core test binary compiles and lists all 28 expected forgery cases; runtime passes
19 and fails nine (`sccp-forgery-archive-validation-3`). The failing fixtures repeat
the SCCP clock transition already owned by `State::block`; the missing-clock
negative also mistakenly assumes that block creation omits it. Production checks
remain unchanged; the fixture repair removes the duplicate transitions and
explicitly removes only the local child-clock effect in the missing-S0 negative.
The mandatory sixth archive
field now retains the exact SCCP delta, joins its sole synthetic write and original
certified root, and rejects the retired layout. Its separate diagnostics pass all
45 archive checks and the original Queue owner check, then fail all four signed
Network cases (`sccp-archive-network-diagnostics-1`). Source inspection identifies
BLS consensus keys incorrectly used for ordinary transaction envelopes and a
missing global-trigger permission in the callback's signed genesis. The repaired
fixtures retain the original ordinary account key and grant the exact trigger
capability; they preserve BLS committee verification and all rollback assertions.
The fresh combined rerun passes all 28 direct forgery cases and three of the four
Network cases, including original-pool retry and the exact callback output boundary
(`sccp-forgery-archive-validation-4`). Its duplicate case stops at the new diagnostic
assertion: the outer rejection displays only "Validation failed", hiding its
instruction cause. The terminal-cause diagnostic repair retains the exact duplicate
assertion; the next combined rerun is pending. Later groups are not counted as run.
The committed-view verifier supplies no reusable execution grant,
and authenticated historical record/lifecycle restoration remains incomplete. SCCP
and current node/network readiness remain open.

The ten native TON unit suites and the first-release committee journal label
are migrated. The original 141/145 run and full diagnostics remain in
`sccp-native-ton-validation-2` and `sccp-native-ton-emulator-diagnostics-1`.
Three failed trace assertions now check the exact typed raw out-messages;
compiler placement annotations resolve the measured storage overrun without
changing function bodies, ABIs or limits. Minter code is 140 cells/72,824 bits;
the n31/three-checkpoint/four-retry state is 204 cells/101,322 bits against
205/102,000. This sampled case does not bound arbitrary retry history.
The maintained current-source `--offline all` run passes 145 tests, vector and
wrapper freshness, and independently agrees on StateInit in Tolk and Python
(`sccp-native-ton-validation-3`). Its 34 measured gas rows form the initial
baseline; the subsequent fresh full run passes the 1.1× comparison and all hard
limits with unchanged sources (`sccp-native-ton-validation-4`). A fresh full run
after correcting stale fee comments also passes all 145 cases, the unchanged
34-row baseline and independent StateInit check (`sccp-native-ton-validation-5`).
The builder now
refuses a missing baseline while retaining measurements; all 49 builder tests
pass. Deployment and current node/network qualification remain open.

The complete 52-route catalog passes its exact engineering test with zero
failures in 9,661.205 s (`corezk-native-full52-current-reuse-1/result.json`).
It performs 4,798 strict original reads, 16 active sigma imports, 89 active Q
imports and three active seal-acquisition cases; cancelled imports open no
source and the unavailable-source retry succeeds. The source and executable
remain unchanged through completion. Independent terminal review verifies the
retained outputs, original source closure and authorized raw-source hard links
(`corezk-native-full52-terminal-independent-review-1/review.json`, SHA
`e3b9502a3e49726ce9bbf48b50a416b6c9d8302dde93d769f25bbd74648a4539`).
This is engineering catalog construction and strict source qualification for
the captured pre-migration source. It supplies no deployment authority, genuine
receipt, native wallet-open result or C12 closure. Current node/network, actual
Payment envelopes, real-proof monetary exchange and phone qualification remain
open.

A later optimized wallet component capture passes strict emitted-input review
(`corezk-native-network-capture16-independent-review-1/review.json`) and all
14 source-locator, output-separation and native storage tests
(`kagemusha-sealed-originals-current-validation-1/result.json`). The test
harness can reopen the same sealed originals while repeating authentication
and qualification; it does not copy retained wallet authority or skip proof
checks. This evidence covers its recorded source boundary before the combined
120-file migration, and does not establish an actual catalog requalification
or monetary exchange.

The owner has explicitly accepted the current Pasta/Poseidon recursive
Fiat–Shamir security-preservation assumption for the first release, as recorded
in the [soundness memo](kagemusha_recursion_soundness_v1.md#selected-recursive-fiatshamir-assumption).
This resolves the design choice to retain the construction. It does not supply
a privacy premise or close C12's shared-oracle source/composition argument.
C12 does not require a simulator executable against the unmodified fixed hash;
the remaining argument and candidate acceptance tests are still required.

The preceding CoreZK14 shared-wallet capture passes all739 ordinary tests,
with zero failures and25 explicit ignored cases, in188.357 s. It includes the
current own-original proof bindings, native BLS Load admission, durable epoch
publication/restart, exact retries and custody failures. The copied executable
SHA is `811d9f220e4528bd96b4687005828c722874d14024084299ce1dd7e8ab3bce74`.
Strict current component closure and before/after source/copy custody pass;
result `corezk-native14-wallet-ordinary-1/result.json` has SHA
`5e67a9499ea76e38ef44ed5c6ac29c34021196ed19729aedd689f731314018dd`.
The ignored genuine/full52/network tests are excluded explicitly. Prior wallet
captures and their failures remain retained, with no transfer to current release,
performance or phone qualification. Server and SDK checks remain separate.
The fresh stock4 node/client build exits zero and emits625 artifacts. Its source
capture and supplemental compiler-input closure reject qualification: eight
consumed production inputs in `iroha_deploy` changed during compilation, along
with four package test files. The original failure, copied binaries,102 local
compiler-artifact inventories and13 build-output records are retained under
`native-finality-stock-capture-4`. Tools and Cargo metadata remain unchanged.
No source closure or current monetary-network admission follows. The successor
stock5 and harness4 builds also exit zero, but their captures both refuse
current-candidate qualification: `native_genesis_policy.rs` changed during
compilation, and the daemon startup refactor adds further consumed-input drift.
Their binaries and original capture/preservation/closure exits (1/0/1) remain
in `native-finality-stock-capture-5` and `native-finality-harness-capture-4`.
The next coherent candidate must include the resolved startup changes and the
pending recovery-capsule migration before network admission; no four-validator
monetary result is inferred from either build.
The typed Kotlin enrollment transport now covers PreKey, Evidence, Issue and
Deliver with fresh direct-account authentication, exact original recovery, typed
Pending and action-bound responses. Its focused 42-test run passes, including
all nine Rust canonical frames, six inclusive-bound hashes, owner/deadline and
cancellation failures, malformed/authentication cases, and existing Load
transport regressions. The receipt is
`enrollment-service-sdk-kotlin-1/result.json`, SHA
`29496717ab8b93833c7ed3cb93d0a98b4413ddc35e7d7e7649beaa1c11569cb4`.
The shared fixture `fixtures/kagemusha/enrollment_service_v1_vectors.json` is
emitted by the Rust service types; its standalone generator snapshot test passes
against the retained canonical Rust libraries. These are synthetic envelope DATA,
not signed enrollment originals. Swift's corresponding client passes all 21 new
enrollment cases, including monotonic callback/response deadlines and strict HTTP
authentication/encoding checks. The maintained authenticated native rebuild and
complete Swift workflow passes **2,236 tests**, zero failures or skips: 2,160 core,
72 mobile-transport and four transfer-UI cases. Pre-test and post-test artifact
custody verification pass, with unchanged sources during the run. Evidence is
`swift-local-l795mb74`; its raw test-log SHA is
`311d49030f41f33ce9fe88dae7b7f427dcb35e3545016b19f201f1913913355a`,
and `swift-enrollment-sdk-run-1/result.json` SHA is
`a2ee6957c13894bca7b71567f464b0d708030ba915c7f51f62bbed1e1fdf7724`.
The current Kotlin run covers **1,907 distinct JVM cases**, including 222
Java-consumer cases and 17 new enrollment cases, against the same authenticated
ABI27 bridge. Its full attempt passes 1,900 cases and fails seven before fixture
comparison because the generator environment setting was omitted. With the
fresh Rust generator selected, all 13 cases in the four affected classes pass,
covering all seven original failures without source or assertion changes. The
original failed attempt is retained. Native artifact and generator custody
checks pass before and after; all 1,890 previous JVM case identities remain.
The combined record is `kotlin-enrollment-sdk-run-1/summary.json`, SHA
`30bcec2718342b06140de01abfb83eda2fb8bc08799818274c17d631ad913e6c`.
These are host SDK checks, not a monetary-network or physical-device result.
No bank or Parliament authority is introduced by these clients.

The genuine ABC test now includes forged Load inputs, signer-unavailable Selected
restart and exact retry. It also checks changed receipt, certificate and event
bytes across retry states, and completed exact replay after a second restart
with signing unavailable and zero new signer calls. These additional assertions
compile in capture12 but remain unrun. The Load-to-Omega component helpers also have explicit
ignored test entry points. In the earlier capture, both Load integration targets
compiled in the release profile, and three ordinary receipt/identity/original-custody checks passed
with zero failures. Their three explicit proof-construction cases remain ignored;
the new ABC proof-dependent case has not run. The raw command and zero exit are
retained in `native-compact-validation-1/proof-native-load-components-1.json`,
with log SHA `607796eeb260271f2a800ae59ff13682a212588811ad70ddb540b48828025a18`.
The Swift/Kotlin Load transport comments now describe native BLS admission and
retained Selected/completed retries. Three new tests per language exercise the
public C/JNI Load-original decoder using the unchanged Rust-generated 342-byte
receipt and 215-byte shape-only certificate envelope. They cover canonical kana
payers, exact retained bytes, foreign selectors/payers and trailing-byte refusal.
The current guarded host bridge rebuild passes ABI27 admission with unchanged
compiler inputs; its dylib SHA is
`6bf3bb7d57d5ddab2cc8f81defbcf286a3adb535c24dc6116e9a196878214944`.
The complete maintained Swift suite passes 2,215 tests across its three XCTest
bundles, including all three new C decoder cases, and passes the final artifact
custody check. Its result SHA is
`ee635dd5e8148dba5572f31e8854f6bc3e54015f340a3b23bb8fa22a0f79ed99`.
The first Kotlin attempt compiles
both Android modules and passes 101 client and 196 wallet managed tests; its
1,890 JVM cases have 15 failures, and neither host-JNI task executed. Pre-existing
host-JNI XML copied by that attempt is excluded from its outcome review.
The failed result is retained in `native-finality-kotlin-execution-1`. Corrections
to the source inventory, manifest fixtures and generic receipt hex verifier pass
all 100 cases in the three focused JVM suites, with unchanged source and matching
native-library admission before and after; result SHA is
`9290be6707b04eb08f8567829a05b6ea31d563865f5d30f4d74342d449548b97`.
The full Kotlin retry uses the separately captured Rust parity generator missing
from the first attempt. All five requested tasks execute: 1,890 JVM tests, 101
client and 196 wallet managed tests, and 33 client and 15 wallet host-JNI tests.
All 2,235 executions pass with no skips, including all four native Load-original
decoder cases (the three new cases and the existing argument check). The
original four parity suites pass against the captured Rust executable. Source
and tool pins remain unchanged and native admission succeeds before and after.
The exact result and task-count review are retained in
`native-finality-kotlin-execution-2`. These Swift/Kotlin results qualify the
current host component suites; Android release artifacts, successful monetary
operations and physical-device qualification remain separate.
Android toolchain preparation installs and verifies all three Rust 1.93.1 Android
targets and cargo-ndk 4.1.2. The pinned NDK r28-beta2 remains absent because its
Google SDK Preview License is unaccepted; authorization is pending. SDK manager
returns zero while skipping that package, so its exit is not installation evidence
(`android-toolchain-preparation-1/outcome-review.json`, SHA `afaea5750e44dfc3a25afc702ad1b56b17ee20a8946c8672c794a4ad998cb9f7`).
The maintained Cargo configuration check accepts the current default configuration;
no Android native library or AAR has been built by this preparation.
These explicit stand-in envelopes test DATA decoding only and supply no BLS or
monetary-admission evidence.
The real-network controller's 27 controls and the release-capture adapter's six
controls pass with natural zero exits and unchanged source/tool pins. Independent
review checks every named test and the retained raw logs in
`native-network-control-execution-1/integration-independent-outcome-review.json`,
SHA `a2b0cc7c0ca8ddc7b19ff061c929628c0f9f93e1f2046679f0a42a54e73ad9a9`.
These bounded filesystem/DATA and read-only Git controls do not execute a
validator network, native proof, SDK or measurement workload. The stock release node/CLI build completes successfully with its default-feature
audit passing, but capture1 remains source-inconclusive: three actual compiled
inputs changed during the build, including the native receipt-binding fix.
The original binaries, 102 artifact records, 88 package owners and 4,454 inputs
are retained; five generated inputs still require reproduction. Capture2 also
builds successfully and preserves its originals, but four actual deployment
source inputs changed during compilation (`runtime/owned.rs`,
`runtime/activation.rs`, `store.rs` and `workspace.rs`). Its original refusal
remains retained; the outcome review SHA is
`8e9be2e4b7e6c0f96eb7145c7f277bc55c1aa65b2ec8ed3eff2fd3480970b4f0`
in `native-finality-stock-capture-2`. Capture3's compilation succeeds, but its
subsequent source-closure acceptance is withdrawn. Independent review finds
that both recorded Cargo bin generators emit `VERGEN_GIT_SHA=local-fast-build`,
while the retained output files contain the Git commit. The shared Cargo output
directory was overwritten after compilation and before preservation; current
hashed executable observations also identify a mixed copied binary pair.
The exact other writer is unidentified. Original results and the erroneous
closure remain unchanged, with an explicit withdrawal SHA
`d995344e673ce42388afa67a9b7c390fb8f06433ab3ae28d3d189c4442f61eab`.
The independent forensic record is
`native-finality-stock-capture-3-overwrite-review-1/review.json`, SHA
`6c1a37090336de66cfe14c3a52a2239e4dff68b32cdaa00a74138fced7aa812c`.
Six later deployment-package changes separately prevent current-checkout
admission. Preparation6 uses separate fresh stock4/harness4 output directories
and joins retained compiler env/cfg/link directives to captured Cargo records.
Its 21 controls pass; controller6's 50 controls pass, including refusal of the
actual contradictory capture and later review withdrawals. Independent source
review accepts these helper changes with no remaining finding in scope
(`native-finality-capture6-review-1/review.json`, SHA
`d788ec76818a06817dcd52e111e1958e7d89793ac20236dfc0bdca4d732e5585`). These are helper controls, not build or network
acceptance. Harness3 has now compiled successfully and preserved its executable
(`cbdc39a0750cae8b1ee63f09accde165ea78978d804c88e65f0ec3e91d16d92d`).
Its supervisor rejects source acceptance because the checkout changed during
the build; the withdrawn launch prerequisite also establishes no network
admission. Fresh compatible captures remain required before the four-validator
monetary run.
The network test now retries the exact Unload transaction after restarting all
four stores, then submits the same instruction in a fresh certified transaction
and requires unchanged balances and total supply. Source review accepts the
added assertions; they remain uncompiled and unrun. This test-source change
requires a fresh integration-harness capture before execution.
Controller revision3 also binds the post-restart completion fields to the exact
bounded signed retry original and includes it in the final artifact recheck.
All 30 revision3 DATA controls pass, including its three new original-custody
and malformed-completion cases. Root reviewed correspondence with the current
Rust restart owner; the two retained Rust sources still match after the merge.
`target/qualification/native-network-control-execution-3/result.json` has SHA
`71ce92af35a62a3bdc485e3f01ebbb9cbc4680b29c133f94b2548201bb07ebb6`.
A second independent review did not complete because the delegated reviewers
hit their usage limits. This establishes controller behavior only; fresh source
captures and the actual network campaign remain required.
The current ABC test additionally verifies and fully folds A's ArchiveReceive
and B's ArchiveStatus, reopens both payer custody trees, and requires exact
acknowledgement replay without another signature or monetary change. B's folded
CreditStatus must expose an empty pending-outgoing root. It retains both
acknowledgements and both Archive packages, each bounded by 10,000 bytes. These
new Rust assertions compile in capture12 but remain unrun. Controller revision4 joins
all four exact originals into its existing final artifact recheck, requires
literal completion flags for both folds and restart replay, and enforces the
same bound on Payment/Receive originals. All 36 DATA controls pass with natural
exit0 and unchanged pins; the prior30 test bodies are preserved. The receipt
`target/qualification/native-network-control-execution-4/result.json` has SHA
`da01b220c3cbb6a1c399b07b1be4fa21e4d5e179862dd594fef3aacada4470be`.
Root reviewed the source correspondence; no second independent review completed.
These controls supply no native proof, network or phone qualification.
The previously draft-only native Ω differential producer is now registered as
a private CoreZk test. Its eight real-proof/malformed-input cases emit the 117
native field words consumed by the maintained incoming-circuit differential.
Independent source review accepts the bindings; capture12 compiles the test,
while execution with a current genuine fixture remains pending. A component
fixture and successful hard verification do
not establish complete-catalog admission or the C12 privacy argument.
The unused final Ω checkpoint codec, context hash and associated layout metadata
are removed. Production recovery continues through A/W checkpoints and durable
RecordedFold; exact Ω transport restoration and its full native decisions are
unchanged. Fixture assertions now use that transport path, including cancellation,
length, proof and foreign-claim refusals. Independent source review and scoped
formatting checks pass; compilation, the seven remaining native unit tests and
genuine proof replay remain pending. The six-file change is retained in
`unused-omega-checkpoint-cleanup-1/result.json`, SHA
`eb822ca535fd9d7921b1265e909b74843dd933260c4db17113fce79c89c4f132`.
It requires fresh consumed-source capture; the native-profile encoder and circuit
layout are unchanged, which is not a newly measured fingerprint or proof result.
The soundness memo now gives the conditional composition for the current eight
fresh Load suffix calls, retaining failed attempts, exact replay and correlated
checkpoint state. Current local simulation errors, arbitrary-history endpoint
privacy and the concrete shared-oracle realization remain unproved; C12 is open.
Full delivery, monetary-network and physical-phone qualification remain open,
and server cost is unqualified.

The historical `optimizations` checkout advanced from `ad75acfe2a` through
`7f14c2389c`, `505a5bd87d` and `28499f4150` to `99f7ebf0bc` while checks were
running. Merge conflicts were resolved, but consumed CoreZk, bridge, data-model
and filesystem sources changed.
SDK and component results below belong to their captured pre-merge inputs;
the merged candidate requires rebuilt checks. A commit hash alone does not
reproduce the continuing edits.
Earlier component results belong to their captured source and binary, not
retroactively to this checkout. No authenticated artifact
set, full-protocol qualification, phone result or completed offline payment is
claimed. Earlier measurements of deleted implementations below do not qualify
this candidate. The [Λ/Ω construction](kagemusha_lambda_omega_v1.md#10-milestones-named-tests-and-thresholds)
defines the unchanged engineering limits and current shared-host method.

**Evidence availability.** The resumed filesystem no longer contains the
four-row M3 campaign, canonical finality metadata snapshot 2, Linux enrollment
guest receipt, later JS/Python supplements or fresh consensus mutation review.
Those results cannot be independently rechecked from this checkout and do not
qualify the current candidate. The interrupted canonical source and full52 jobs
have no terminal receipts or signed complete wallet grant. Independent recovery
rereads all 1,043 surviving content-addressed originals (65,074,847,520 bytes),
with unchanged custody and no surviving producer or terminal output. A fresh
full52 run has reconstructed all 2,495 descriptor/key records, reread all 4,990
originals and rejected missing, unused or duplicate records without reading a
proving key. It has indexed 512 reusable sources and completed the source
inventory for all 52 routes, 32 programs and 32 terminal keys, referencing 507
originals. The original store now holds 1,045 blobs (65,112,597,504 bytes).
That run now completes in 15,716.63 seconds with `accepted_component=true`,
9,753 strict original reads, 16 active sigma imports and 89 active Q imports.
It retains the signed engineering pack, 291-byte source acceptance and complete
source membership. The result SHA is
`4da806a067f5fb3fc004d2513f00fb14b9348862247f9996d71de035abe00ed9`.
This acceptance uses the preserved historical compiler; it does not qualify the
current source, actual receipt proof or native wallet-open. The subsequent genuine
runner passes signed-pack selection and the actual Core H3/H4 refusals, H5
Register and H6 Log execution. Its recursive proof/admission step fails after
6,269.74 seconds on the H1 raw block-wire equality assertion, after native H1
verification. It produces no completed history or differential originals.
The exact log SHA is
`3e3e6e7f2d478065ca0a028573174a7d2e6aee995b7e8608a558deb8e6c6af29`.
The metadata-only Torii resumption is inapplicable because its genuine-proof
success prerequisite is absent. The H1 mismatch must be resolved and all cheap
capture/continuity checks must precede expensive proving on retry.
Source tracing identifies the invalid test assumption: native H1 admission binds
the header hash and exact resultless proposal to the independently selected
signed genesis, then validates execution results. Full executed H1 wire need
not equal the pre-execution signed-genesis wire. The installed three-file repair
uses that exact resultless identity in both Register and Load, and checks the
complete six-height native history before initializing the Register prover.
The rebuilt native7 executable passes the ordinary malformed/reordered/foreign-
history regression. Its copied binary SHA is
`3fcee772457dcb1045ad7f2feea182f37b59ddd1352249716364aa10e38bf0e5`;
the actual compiler closure retains 1,726 inputs, 42 depfiles and four generators
without consumed-source or tool drift during that capture. Existing-journal
proof recovery subsequently lost both its process and wrapper without a terminal
result; no successful history completion is established. The port
receipt SHA is `1ef68a999d401a9881fb6c7c44e99eac70ea74bc5cef8b3fe143f820a03a14cf`
under `genuine-genesis-preflight-repair-draft`. The independently reviewed
recovery runner passes all 14 tiny synthetic custody/failure controls. It requires
current native preflight, copies only authenticated artifact DATA into fresh
custody and runs existing-only recovery plus the full mutation differential.
Three additional tiny parser controls cover the required H1–H6 completion
sequence before and after reopening. Their possible overlap with the start of
worker4 is recorded in `four-thread-context-1.json`; the measurement policy is
unchanged. Completion markers and unchanged copied originals support the
source-inferred restore path, not a measured zero-entropy or zero-key-import claim.
The real donor DATA snapshot passes under custody locks; the rebuilt-native
six-height preflight passes after3,038.33s, including signed source-graph
admission. Its receipt explicitly records that proof production had not started.
The runner then copies eight custody files (365,160,126B) and starts existing-only
proof recovery. At15:41UTC on2026-10-08, neither wrapper83992 nor child87280
exists and session88019 is unavailable. The step log is empty and no terminal
result exists. A retained preflight marker is not a completed proof. The exit
cause is unknown. Subsequent checkpoint inspection preserved the original DATA;
rebuilt native8 passes its own signed H1–H6 and terminal Register preflight
after3,118.36s. Its fresh marker is
`genuine-register-h6-recovery-2/compact/native-preflight.json`, SHA
`726a45d766ce3b34fea2e15ade360bb8827c21d9eb20029ef086037ee4d428a0`.
The subsequent `GENUINE_REGISTER_HISTORY height=1 native_preflight=true` marker
shows that the existing-only server open and restored-genesis call returned.
At 00:56UTC on 2026-10-09, both execution handles (main90406 and observer32060)
are missing, and neither wrapper247 nor native361 remains in the process table.
The retained log is still 201B with height1 only; no step3 exit-observed result,
step4 result or final result exists. This is an interrupted attempt of unknown
cause, not a successful or naturally failing protocol run. H2–H6, the complete
differential and terminal source admission remain unproved. Neither marker grants
completed history, recursive Register-proof completion or wallet authority;
measured zero entropy or key-generation calls are not inferred from this
source-supported restore.
The captured historical native9 passes the H1 regression and ten focused staging/custody
controls as well as the twenty source-admission controls recorded below. Its
fresh recovery copies 793 authenticated files, including all 788 retained
journal records, into new custody. That Resume invocation passes its
own signed H1–H6 native preflight, including contiguous history, signed-genesis
identity and the Register event. Its new marker is
`genuine-register-h6-recovery-3/compact/native-preflight.json`, SHA
`726a45d766ce3b34fea2e15ade360bb8827c21d9eb20029ef086037ee4d428a0`;
the marker explicitly records that proof production had not started. The
continuation is interrupted, with no observed exit or terminal result. The
interruption audit (`native9-recovery3-interruption-audit-1/result.json`, SHA
`bb1614f46f626464b53fcfce2e194a95b95ac4e0af80cb63d3323f6f34fe0a36`)
finds both execution handles and recorded processes absent, retains 1,648 journal
nodes as DATA, and releases the source/resource hold. It records H1 only, no
complete H2–H6 proof traversal, differential or terminal source admission. The
cause is unknown. An earlier
three-second read-only stack sample located server graph/VK reconstruction before
`producer.genesis()` (`genuine-register-h6-recovery-3-hot-stack-1/result.json`, SHA
`47581ba8b50c17185f7940fd81b4404f176f6f02e68b3fa1f8e0264847a85c6a`).
The run subsequently emitted `GENUINE_REGISTER_HISTORY height=1 native_preflight=true`.
Its immutable 201-byte log prefix and process/selection bindings are retained in
`native9-h1-progress-1/receipt.json`, SHA
`c998d3e8bd71da148a9bbcbf3be12999a011709d5506e5d91236de4b9197e667`.
This establishes an accepted H1 prefix after graph admission, not measured
checkpoint-restoration counts, complete H1–H6 traversal, terminal differential
success or timing qualification. The interrupted attempt is
`genuine-register-h6-recovery-3`; its copied-custody receipt is
`b212741128252e0ef21f79121d58d65ad8d4fec28678f120d8fcb4af5f1861fb`.
All interrupted attempts remain unchanged; none grants a history-success gate
or qualifies the approved native-finality replacement.
A bounded three-second diagnostic of the earlier native8 recovery observed strict
source/wrapper key import in179 of183 main-thread samples during H2 preparation
(`native8-recovery-hot-stack-1`). That captured program repeats imports
for uncheckpointed leaves sharing a class. The reviewed call-local reuse is now
installed: it retains one pair, reloads and binds all six originals per use,
and preserves full witness checks. The current proof library compiles and
all eight mechanism controls pass with unchanged source inputs. Its separate
genuine Result1 regression also passes: eight real k16 source/wrapper proofs
compare fresh/cached returned evidence and exact proof bytes across distinct
AbsorbPair witnesses and two-, four- and six-interval checkpoints. Wrong
layouts, changed originals and incorrect checkpoints reject; exact replay
passes. The four retained wrapper proofs are each 9,856 B. The result is
`result1-genuine-parity-1/result.json`, SHA
`ceefa6249ea495a28712c511979156e6c98405d8f51453659fd663fa7c65072f`;
independent review accepts the proof and source evidence. Its 146.87 s duration
is diagnostic, not a performance qualification or a measured speedup.
Complete-history evidence remains open. BLS/Aggregation use distinct classes
and do not benefit from this reuse. The stack sample does not identify the
active program or establish whole-job cost.
The separate bounded extraction helper passes all eleven tiny filesystem/CLI
controls with unchanged inputs (`finality-result1-extractor-controls-1`, result
SHA `94b84802c871d7e18b3aa12d105b7455aa9e4522a395b8c46e1253bb2724ec8a`).
The synthetic six-role cases exercise exact copy/rehash, missing-input refusal
before output, occupied/unsafe output and partial failure without success. No
actual PK was read by those synthetic controls. Separate actual fixture
preparation now passes using the existing compiler for one exact Result1
source/wrapper pair and zero proofs, followed by strict reimport. The six
originals total 283,689,426 B, including 283,357,580 B of proving keys. Its receipt
is `result1-selective-fixture-1/result.json`, SHA
`ea7e8dd28ded8c9b29848d74d2de7a781b2f04d2ea727a5fe30760dd7c60a5d3`.
The actual parity test consumes those authenticated originals without in-test
regeneration. Fixture metadata alone supplies no proof or complete-catalog
acceptance.
The original failed result remains unchanged. The new preflight result and exact copy receipt are in
`genuine-register-h6-recovery-1`; the runner records are under
`genuine-genesis-recovery-runner`. Selection
alone is authenticated DATA, not source-graph qualification. Originals
and phase receipts are under `genuine-register-h6-native6-core1-1`.
Current-owner installation and genuine proof qualification remain required.
Catalog records are retained in
`canonical-complete52-interruption-review-2` and
`canonical-complete52-after-interruption-1` under `target/qualification`.
The retained four-row engine and
oracle executables still match their recorded hashes; fresh M3 qualification is
required after the implementation and harness are fixed. The availability
inventory is `target/qualification/resume-20261008/retention.json`; it records
filesystem observations, not replacement test evidence.

**Recursive privacy argument.** C12 remains open. The ideal-mask local lemma
supports a coherent endpoint-H Omega proof over a genuine fixed-Poseidon witness;
all-H private ancestry is unnecessary for that local comparison. After Omega is
simulated, the exported P/V and original public sigma proofs retain their
F-derived joint law. The fresh-H fold lemma and reverse dependency order do not
supply the comparison of that surviving law under the common query interface.
Existing domain tags preserve address separation; they do not authorize changing
answers on publication or replay. The independently agreeing source reviews are
`c12-endpoint-outer-first-quotient-review-1` and
`c12-endpoint-only-rom-boundary-1` under `target/qualification`.

The [local memo's equal-opening translation](kagemusha_local_zk_v1.md#appendix-b-equal-opening-translation-under-a-fixed-transcript-function)
also couples the complete IPA response under fixed RP57 when the commitment,
actual evaluation and full entry prefix agree and xi is nonzero. This algebraic
result neither supplies an efficient public sampler nor erases private Direct
frames; the xi=0 path and the surviving joint-law comparison remain open.

Native-H producers with genuine fixed-Pow5 Q consumers still fail the
no-incoming Load/Send round-cell binding; forcing H to F answers changes the
fresh-oracle law and later public sigma prefixes expose those addresses. These
are gaps in those proof adapters, not a production attack or impossibility
result. The retained `c12-logical-source-game-boundary-1` and
`c12-primary-theorem-intake-1` records identify those failures and the limits of
the primary theorems reviewed. The selected recursive-FS soundness heuristic
adds no privacy premise.

Closure requires the surviving-carrier comparison or an alternative coherent
source/valid-cut argument and the total public-only simulator specified in the
[soundness memo](kagemusha_recursion_soundness_v1.md), including observable
outcomes, durable order and exact replay, plus current-key M(K) and concrete
randomness justification. Any chosen revision of the recursive relation needs
implementation, re-keying and its own proof. No review above executes proofs or
grants C12 qualification.

The applied coefficient-MSM change uses the existing full-width secret path in
both halves of `create_fold`, because its transcript may remain private inside
an outer proof. It retains the process-wide 64 MiB scratch cap and adds secret
scratch wiping; bucket operations and other fold branches remain variable-time.
The fresh source-bound run passes both-curve k16 full-fold goldens, 27 ordinary
recursion cases, three transcript cases and eight Pasta regressions, plus strict
recursion lint. The two ignored ordinary cases are the separately executed k16
goldens. Independent review reconstructs all 40 passing selections and checks
13 source/executable boundaries, including unchanged proof bytes and rejection
of false claims. The earlier attempt remains invalidated by source drift and
contributes no result to this run. These are component correctness checks, with
no whole-fold constant-time, performance or privacy claim
(`c12-fold-secret-msm-validation-2` and
`c12-fold-secret-msm-validation2-resource-review-1` under `target/qualification`).

Earlier diagnostic evidence follows. Independent source review accepts the final-salt
trace for all wallet owner families and the conditional honest-fold abort bound
in the [soundness memo](kagemusha_recursion_soundness_v1.md). The bound's
small-field falsification checks pass; its relation-finding and fresh-oracle
premises remain explicit. A complete bounded k6 outer-transcript model passes
eight controls on both curves, including lookup/permutation, multiopen, the full
IPA, mutations, bounded sampling and a shared oracle table. It uses a programmable full-prefix
oracle; the unchanged fixed-Poseidon verifier rejects those model proofs as
expected. A structural audit of the accepted historical full52 Omega descriptor
finds four masked opening sets, no public-only set, and all S7 rank counts within
the required bound. This advances the argument but does not execute an actual
Omega simulator or close C12. A separately reviewed bounded-view lemma gives
explicit salt-guess, collision and abort terms in the ideal full-prefix model,
with a total public-instance outer simulator assumed. The generalized public-table
reader and simulator pass eight independently executed small controls; five more
controls cover an exact-pinned, target-only k16 reference adapter. No k16 proof
has run, and repository verifier limits remain unchanged. An independently
reviewed local hiding-IPA refinement supplies conditional finite-point, final-G
and rank-collapse bounds, with three small-field controls passing. The actual
Omega interface theorem and concrete sponge model remain required. Source review
also identifies an exact padding alias between two logical absorb/squeeze
histories. The revised cumulative padded-block model passes eight small controls
on both fields, including complete k6 verification and shared-table aliases.
Ten further controls pass for the selected deferred actual-Omega runner's source,
artifact and phase-boundary checks. Neither set executes a k16 proof or qualifies
the production sponge. A conditional source argument transferring the earlier
freshness and salt-guess bounds to normalized addresses passes independent
source/mathematical review within its stated ideal experiment. The concrete
sponge and inner-circuit bridge remain open; the alias is
a model limitation, not an established proof-system forgery. A new target-only
ideal-permutation adapter passes 15 controls, including six complete k6
curve/layout cases, proof mutations and shared forward/inverse queries. It
programs only unoccupied final primitive inputs and retains a bijection; frozen
verification replays existing edges. Independent source review precedes execution
and all source hashes remain unchanged. This establishes finite model consistency,
not inherited prefix-oracle probability bounds or recursive privacy. The result
is `c12-ideal-permutation-controls-1/result.json`, SHA
`48fcc556b0c68d0586f60afd4cf8a4791decbe6b5eff4521db0716e08564e535`.
Independent mathematical/source review also accepts a bounded hidden-`as1`-path
coupling under that shared ideal permutation, with explicit public-interface,
operational and entropy assumptions. It accounts for adaptive forward/inverse
queries, programmed output fibers, early address-cache replies and retained
retries (`c12-hidden-as1-permutation-path-1`). This is a conditional argument,
not an executed proof or complete privacy qualification.
Two further arguments pass independent mathematical/source review: a bounded
outer-path coupling under atomic proof publication and a stopped PLONK prefix
through S/xi/zeta, including the dependent quotient/R opening group and the IPA's
required conditional coefficient distribution. Their records are
`c12-atomic-outer-path-freshness-1` and `c12-outer-prefix-coupling-1`.
The exact historical Omega artifact subsequently passes a symbolic masking-boundary
audit and10 small controls (`c12-omega-mask-boundary-audit-1`). All156 gate
expressions, boundary lookup tuples and six sigma tails satisfy the required
mask-independence predicates; independent source review accepts the conditional
quotient-degree argument. A satisfying original witness, nonzero denominators
and the joint observation boundary remain explicit premises. No actual Omega
proof ran for these reviews; the concrete sponge and recursive-circuit bridge
remain open.
Source-pinned records are in
`c12-exported-salt-source-trace-1`, `fold-abort-bound-1` and
`c12-outer-simulator-reference-1`, `c12-hidden-fold-ro-lemma-1`,
`c12-actual-omega-model-draft`, `c12-padded-prefix-model-1`,
`c12-normalized-prefix-lemma-1` and `c12-hiding-ipa-abort-refinement-1` under
`target/qualification`.

An alternative synthetic setup experiment passes eight controls, including four
k6 cases with unchanged fixed-Poseidon verifier arithmetic and complete generator
decisions. Only isolated test parameter-authority data changes; current release
pins reject the synthetic setup. Six separate curve-map controls pass, including
all132 retained generator encodings and a complete single-SWU inverse. Original
logs and unchanged source/tool pins are retained in
`target/qualification/c12-small-controls-execution-20261009-1`. The subsequent
fresh-target construction has an exact uniform-field-pair argument with
explicit finite failure and raw-query collision bounds in its ideal raw-XMD
experiment. Six small source-map setup controls and nine setup-to-proof
controls pass. The latter verifies four complete k6 fixed-RP57 proofs, exact
shared parameter families, current-authority refusal and f/c/G/instance
mutations; all source/tool pins remain unchanged. Its40.05s execution receipt is
`c12-raw-setup-proof-execution-1/result.json`, SHA
`16be203eaa8c7d129dc7425ddcb02641a4d9c29bbf56288f34583938dc1db5ac`.
Common diagnostic coins across relation examples establish no multi-request
privacy claim. A separately reviewed conditional IPA joint-law argument uses
unchanged RP57 and known setup logs, removing challenge programming from that
continuation. It retains prefix-failure, entropy and recursive-obligation
premises. Actual Omega integration, concrete hash assumptions, current setup
pins and complete recursive composition remain open; these results do not
qualify C12 or the release.

The maintained [setup controls](../formal/kagemusha_setup/README.md) now pass
all77 cases, preserving every prior60 method and assertion and adding seventeen
generic public-table/rebinding controls. Its single generic fixed-RP57 simulator
handles public-only groups and multiple products/lookups. It requires explicit
coins and retains exact outcomes at capacity without reseeding. Exact public
preprocessing bytes now bind retries alongside descriptor/key/parameters and
instances. Provider errors,128 rejected legal bit draws, storage failures and
interrupts retain failed attempts; a late hash failure cannot publish success.
All fourteen actual k6 proofs fully verify, including four adaptive-input and
six generic cases; the original proof goldens remain exact. After the engine
reconstruction port, the source guard correctly refused two stale source pins.
The reviewed repair updates those pins, includes reconstruction/export/source-
fingerprint dependencies and tests missing or changed new source roles.
All77 current cases and fourteen diagnostic k6 proofs pass in156.55s with
unchanged source/tool pins (`setup-current-source-controls-1/subject/result.json`,
SHA `70375b8067d5d453cafb08d0c2926da93691df49895cd3c3215f28f4f9d976aa`).
Original manifests, the initial refusal and the earlier157.94s result remain
preserved. This source-custody repair does not establish native16 or C12.
Review fixes reject large authority inputs before private-reference I/O and
require canonical digest text before source interpolation. Mocked failure
fixtures are explicitly excluded from proof counts.

The bounded producer retains both-curve k0/k2/k6 parity, shared-context replay,
terminal resource failures and final output size/hash/namespace checks. Its
traced-allocation checks are not an OS/RSS cap. The separately retained29.01s
k0/k2 CLI passes; all17 files match their hashes and all four parameter outputs
match the earlier implementation. No large parameters or native proofs were
produced. CI selects the maintained controls and retains partial failures;
hosted execution remains unobserved. These controls do not establish a privacy
theorem, current setup authority or C12 qualification.

Eight separate pointwise mask-rank controls pass for the inspected historical
Omega descriptor, admitting zero grouping challenge and five common blinded
domain rows algebraically while rejecting an unmasked product boundary.
No generic simulator was relaxed. The new non-hiding L/R polynomial derivation
bounds encoding/zero events without a relation-finding assumption under
independent mapped tapes, including known generator logs. The maintained
[fold controls](../formal/kagemusha_fold/README.md) pass all 29 tests with
unchanged source/tool pins. The ten algebra cases retain bounded coefficients
and degrees, dependent logs, two essential-hypothesis negatives and14,739
exhaustive F17 tapes. Ten additional transcript cases reproduce both native
PIPA-AS prelude KATs with the independent RP57 reference, compare its constants
with the native tables and check all19 squeeze calls against a separate block
schedule. They cover scalar encodings/maps, padding aliases, the unsqueezed
final scalar/unabsorbed generator, mutations and source refusal. The current
capture is `c12-ideal-fold-maintained-execution-1` (29/29, 1.498s), with 32
unchanged source/tool pins and result SHA
`79f581777c5bd2ce71213ccfd679cff4221208f224a0f48d746bbee7e84ecbef`.
Nine additional finite ideal-permutation controls check both-direction replay,
refused candidates, exact retry, carried capacity and malformed endpoints. They
exhaust all 83,521 single-edge tapes (13,889 bad, 69,632 no-bad) and 2,187
two-edge tapes. Explicit negatives demonstrate failure when public operations
inspect hidden data or initial capacity is chosen after the private tape.
The conditional union bound requires independent uniform private salts and
capacities given disclosed words, an independent initial capacity, and an
outside interface that cannot inspect hidden state. The tests do not infer
these premises for the real protocol. No native proof or key is generated.
These bounded algebra, transcript and model checks establish neither the IPA
equation on those synthetic traces nor concrete challenge independence,
adaptive privacy, performance compliance or C12.

A source audit covers
all fourteen operation roles and six successor native owners: fresh source
inputs can be constructed from the accepted replacement proof and its actual
opening without the discarded Omega witness. A separately pinned and reviewed
native-to-hard-verifier source argument traces the exact public/key digests,
typed instances, transcript and opening equation. Under a coherent admitted
plan, native acceptance supplies the hard verifier's assignment without the old
Omega witness. Gadget/layout completeness, actual installed k16 execution and
the later operation/fold/prover remain open; no proof was generated for this
argument (`c12-native-omega-hard-predecessor-1`). The held seven-file test
revision (`c12-native-omega-hard-predecessor-test-draft-2`) prepares one current
Bootstrap export and a shared canonical Norito fixture codec with explicit
schema identities and independently selected manifest/descriptor/key hashes.
It removes the Retiring test's old two-file export and retains native full
verification, all three claim decisions, fixed-k16 hard checks and five negative
cases. Source review, formatting and patch checks pass; the source is not yet
installed or compiled, and no current fixture or hard-circuit result is claimed.
The prior draft's missing schema declarations and JSON macro errors remain
recorded as source defects. Total failure bounds and fixed-RP57 joint fold
hiding also remain open. Substitution
requires the first fold publication boundary and no already selected dependent
operation; signed or retained Payments cannot be patched. The source reviews and exact limitations
are recorded in the [soundness memo](kagemusha_recursion_soundness_v1.md).
The generic prefix algorithm is now part of the maintained package above. Its
historical rebind preserves public tables/copy digests/selectors but leaves
embedded recursive constants unchanged. No k16 simulation or coherently
re-keyed recursive catalog ran for these results.

The historical complete52 Load A1 artifact passes14 bounded-reader/symbolic
controls and one exact-table mask audit
(`target/qualification/c12-load-a1-mask-boundary-draft-1`). Its -1,0,1,2 advice
rotations require three usable boundary rows and seven tail rows. All1,210 gate
expression checks and 42 lookup expression checks pass, with zero fixed tails
and self-mapping sigma tails in all16 equality columns. The audit hashes the
exact140,511,414-byte PK once, checks2,230 framing bytes and reads19,904 sparse
scalar bytes; source/tool pins and held file/parent identities are unchanged.
Under separately admitted full copy mapping, valid pre-mask advice and nonzero
denominators, the degree8 relation fits seven quotient pieces. This is historical
artifact evidence, not current-source key admission, proof production, a memory
or time gate, or C12 completion. The result and raw numeric exits are retained.
The remaining eight selected Load keys, A2–A5 and W0–W3, now pass eight new
controls and one finite audit of their distinct originals
(`target/qualification/c12-load-remaining-mask-boundary-preparation-1`). All
11,028 gate and 784 lookup checks pass, with zero fixed tails and self-mapping
sigma tails. The W profile has 11 lookups and requires its own +6 rotated fixed
row closure; its degree 6 relation fits five quotient pieces under the stated
valid-relation premises. The audit hashes 1,032,765,488 PK bytes once, checks
966,704 framing bytes and reads 182,528 sparse scalar bytes. Both child exits
are zero; source/tool and held file/parent identities remain unchanged. The
independent review accepts the raw results without rereading the PKs (result
SHA `3d2a5f9f8dce2549e4e50c16a46d1449ca5b801582074cd62016e152f1a64a5e`,
review SHA `ed222ea8d47389bce81486e41953439c242d5f9321a6798b08b5fbcbdc1b8ba2`).
With A1 and the exact matching previously audited Omega triple, the selected
historical fresh-Load suffix's mask-table checks are covered. Valid original
witness/full-copy admission, current-source transfer and complete joint
composition are still required. No proof, keygen, parameter, FFT or MSM
work ran; the 5.515-second audit is not a performance gate.
The diagnostic request owner admits at most 256 columns and 256 total values,
then checks the descriptor's exact shape and canonical scalar types. This covers
Load A's 69-word statement and Q0's five-column [124,2,1,1,1] frame. The former
four-column guard rejected Q0 despite its 129 values. Two new regression methods
reproduce that refusal against the isolated original code; all nine maintained
request-shape methods pass after the repair, with child exit zero and unchanged
source/tool pins (`target/qualification/formal-owner-column-cap-execution-1`,
result SHA `0e682db8b80bc0eef61338071b3ef03715a2b393736411e5a6ffa2aa5b7bd623`,
independent review SHA
`a59de5a32838dc35af919bdbdebfa7ccbc021529dee98b9fc39c7cc8ffc93582`).
Column/value budgets still reject before scalar inspection or entropy; exact
failure replay, changed bindings and explicit large-mode opt-in remain covered.
The simulator is a failing sentinel: these checks execute no proof or entropy.
The preceding maintained suite passes all 100 controls and 14 small k6 reference
proofs, with no failures, errors or skips and unchanged source/interpreter pins
(142.45 s; `setup-current-source-controls-2/result.json`, SHA
`3a1d68c6ea2f92aabce9a109ab3812c58171e6da27bc2e74bffbdacfb6845efd`).
The stale commitment source pin first refused execution. Exact old/current
review then refreshed that pin for the bounded-prefix helper, its test module
and test-only observation changes, with every existing non-probe body unchanged
(`setup-bounded-commit-source-refresh-2/review.json`, SHA
`6a4e1c9adda7a1afe8e1f054464331a087368806d6e22e02ac9d404a12daac49`).
The original refusal and both source originals remain retained. The current
zero-grouping successor passes all 101 controls with no failures, errors or
skips in 148.60 s. It retains fourteen ordinary fixed-RP57 k6 proofs and records
two test-adapted x1=0 proofs separately; both curves exercise public-last,
masked-last and R-last groups through the actual simulator. Source pins remain
unchanged (`c12-x1-zero-maintained-validation-1/result.json`, SHA
`aa3d3efb56768593b08080257b52180a76668e48adc67ab188749268f90a3e6c`).
No native or large proof ran; actual A1 chosen-setup construction, coherent
recursive setup, adaptive privacy and C12 remain open.
The independently reviewed A1 local law additionally gives an explicit total
response/residual-oracle bound in the normalized-prefix ROM, conditional on the
audited tables, valid source/witness, coherent known-log setup and fresh coins
(`target/qualification/c12-load-a1-joint-sampler-law-1`). It retains identity and
rank-collapse failures and charges scalar sampling, prior-query collisions and
bad algebraic challenges. Both prover algorithms and the verifier use the same
mathematical oracle in this statement. Its first primitive sponge block contains
only x(C0); full primitive-table/concrete-RP57 coupling is still unproved. The
[soundness memo](kagemusha_recursion_soundness_v1.md) records the exact bound and
remaining operational, setup and composition premises. No new proof or C12
qualification follows from this source/math result.
The reviewed local law also covers all selected A/W roles
(`target/qualification/c12-load-aw-joint-sampler-laws-1`). W has seven opening
groups but only six masked values; fixed columns 10/11 form a public-only group
whose exact polynomial evaluation is retained. The sharp W base-to-scalar atom,
slot ranks, denominator bounds and total failure coupling are explicit. Its 247
simulator samples and 9,856 proof bytes are source arithmetic only. Composing all
nine A/W replacements requires coherent setup and the complete future-evaluation
interface. The independently reviewed Omega local law supplies the tenth suffix
term (`target/qualification/c12-omega-joint-sampler-law-1`): all four opening
groups are masked, with 96 simulator samples and 3,712 bytes by source arithmetic.
It preserves total failure and the complete residual normalized-oracle state
under the stated premises. The ten-role sum requires at least ten explicitly
budgeted requests; the default owner cap is eight. No concrete RP57 privacy,
actual proof, current recursive authority or full C12 qualification follows.

The three Load Q witnesses are also reconstructible from their exact internal
stage-public columns and admitted catalog. The reviewed source argument at
`target/qualification/c12-load-q-public-reconstruction-1` gives pointwise
equality at the native proof-entry boundary when replay uses the same typed
witness, prover and actual provider/event tapes. It includes failed responses
and residual oracle state, without a new ideal-randomness or RP57 assumption
for these identical Q calls. Load Q0 has no incoming slot or local fold; the
earlier capsule-derived nonce computation still belongs to the retained prior
state. These internal columns contain the original sigma and signature data;
the argument does not generate or hide them from the final wallet public view.
A separate four-file native inverse/parity test implementation is applied after
independent review of the current six compatibility joins
(`target/qualification/c12-load-q-public-inverse-draft2-independent-review-1`,
review SHA `deaec55eacd3919dc9d82fd657c274180fcf68f7c46ca42832bc0b297ca4d3ec`).
The implementation is recorded in `c12-load-q-application-1`; capture3 compiles
all six selected targets after the explicit Fq test type correction. All11
ordinary decoding/refusal controls pass. Both genuine parity tests complete:
Q0 verifies three proofs and the signature cases verify four, with four total
key generations and three strict original imports. Exact native proof bytes,
provider-event tapes and source/copy custody match. Results are retained in
`load-q-public-inverse-controls-3`, `load-q-public-inverse-q0-parity-3` and
`load-q-public-inverse-signature-parity-3`. Independent compiler-input review
admits this component capture; inherited external-input provenance limitations
remain explicit. These identical-input checks do not prove different-history
privacy, actual OS entropy, current complete catalog authority or full C12.

Strict proof lib/tests Clippy now passes with `--release --locked --keep-going
--no-deps -- -D warnings`, natural exit0 in184.012 s and no diagnostics
(`native-proof-strict-lint-after-reviewed-repairs-2/result.json`, SHA
`f43f9eae14e994c4e73ccb927f51d14d0da385f25d10ef0c44bd39f65d35b73a`).
The reviewed 21-file repair retains every assertion and source-admission call,
including deliberately malformed ranges, and adds no lint suppression. All20,193
sampled source files, tools and helpers remain unchanged across the run. This
establishes lint only; it executes no tests. The original keep-going failure
with93 locations and its raw logs remain retained.

The exact outer Eq16 A1 constructor draft passes 14 bounded controls with
unchanged source/tool pins and numeric child exit zero
(`target/qualification/c12-load-a1-chosen-eq-constructor-draft-2`, result SHA
`762524b6d42b193d1e1e811bb150fb964545181fa12e57b5510cc73b813ca010`).
Independent outcome review `33188a4e…15e36` accepts only the small DATA/parser,
custody, allocation-accounting, publication and replay checks. The code retains
one setup owner and partial read observations, checks allocations throughout
parameter reconstruction, and excludes import-created bytecode from its bounded
output tree. No actual Eq16 setup, full original intake, A1 construction or proof
ran in that draft check. The eight-file migration is now installed in
`formal/kagemusha_setup`, with a checked-in DATA descriptor and an explicit
originals-directory argument whose location cannot change the pinned profile.
The maintained 14 constructor controls and two source-integrity tests pass once,
with exact selected names, child exit zero and unchanged source/tool pins
(`target/qualification/c12-load-a1-constructor-maintained-controls-1`, result SHA
`79b9a6b247d0a67a80b447c47c63f3e0783fc6869789d0de44f23951b4265431`).
After the request-limit change, a fresh combined run of all 25 affected
constructor, custody and request-shape controls also passes against the same
current source manifest, with child exit zero and unchanged source/tool pins
(`target/qualification/formal-current-intake-controls-1`, result SHA
`6777bafe66404bcd196276e15fa86f1bf8d93cc607d451afc7266cdb11719ffc`).
Independent outcome review `58dfdc62…ea1fb` confirms the exact 25 results and
all 68 execution pins. No proofs, parameter derivation, PK reads or live entropy
draws ran in those 25 intake checks; mocked responses exercise the ownership
checks. The later complete 100-control regression above passes, including its
14 small reference proofs. Actual large construction remains unrun.
The 2 GiB checkpointed Python allocation ceiling is not a memory qualification
or a change to the 64 MiB process-wide MSM limit.

The target-only shared recursive setup constructor now passes independent source
review and all 15 bounded DATA controls once
(`target/qualification/c12-shared-recursive-setup-bundle-draft-3`, result SHA
`0d896caa5ce0d90c4c238e672b0655949918604d64c73c3bf0dae1d63a03a39d`,
independent outcome review SHA
`881d7b4f5cb135741c202572723bbb0583984558339e6703ad320ce19b73a9c0`).
The raw child exits zero and all 97 source/tool pins remain unchanged. Its closed
schedule uses one live setup owner for both Pasta curves at k=6 through k=16,
with a separate inverse FFT for each domain. The planned authority replacement
covers all 22 parameter digests, closed parameter loading and both recursion
generators; production sources remain unchanged. The successful-publication
control exercises the real file ledger, all member/output hash joins, the three
source overlays, terminal Outcome and exact replay, while replacing parameter
generation with structurally sized DATA tapes. Those tapes are not accepted
parameters, and no actual setup, inverse FFT, MSM, keygen or proof ran. The live
successful Outcome and complete checked output inventory must both be bound by
any later admission; a parsed prepared manifest alone grants no authority.
Actual construction, the isolated Cargo dependency graph, recursive re-keying,
production rejection of foreign authority and full C12 remain open. The graph
helper separately passes nine synthetic metadata controls. Materializer revision3
passes eleven DATA/source/ledger controls with exact raw results and checked
source pins; its single-read plan hash/parse binding is reviewed. The latter run
has no fresh before/after Python hash or separately saved outer wrapper, as
recorded in `c12-private-cargo-materializer-controls-1/integration-independent-outcome-review.json`
(SHA `3940dc5b156f97bc28e043473cce9059479366f4834423968a2c139d48a7588e`).
No actual setup, package materialization, Cargo, parameter decoding or native
proof ran. The historical source plan remains provisional and refuses admission;
it must be reconciled with the approved native-finality source before use.

A fixed-parameter outer IPA simulation now has an independently reviewed
conditional argument for `k >= 1`: solve the final R point from the verifier
equation, retain `c = 0` on rank collapse, and preserve point/zero-challenge
failures without a retry or setup-log assumption. An exact finite-group check
matches the complete joint outcomes and oracle-table effects in 152 cases
(839,112 samples), including nonuniform challenge maps. This is a local lemma;
the mask/prefix and operational premises remain conditional. The recursive
model, composition and instantiation boundary remains open: ordinary transcript
ROM simulation does not alone supply the next honest Send's constrained Pow5
witness. Reverse-order erasure could avoid that witness demand, but its contextual
comparison must preserve Receive outcomes, newly signed originals, failures and
exact retries. This is neither an impossibility result nor a demand for an
unconditional security proof of fixed Poseidon. The concrete continuation and
primary-source model review are retained in
`c12-total-erasure-continuation-cut-1` and
`c12-recursive-transcript-oracle-primary-research-1`; no additional oracle or
recursive-security assumption has been adopted.
The root review is `c12-fixed-parameter-oracle-root-review-1/review.json`, SHA
`71bfa1d8100f6663f02c3a3c25642acb4a7d155bb60547c55c9aeba3219b58e2`;
the frozen argument and controls are in
`c12-fixed-parameter-oracle-continuation-1` and
`c12-final-ipa-one-shot-finite-controls-1`. No Pasta runtime or full C12
qualification follows from the finite model.

**Resumed component validation.** The retained engine capture passes 94 Pasta
units, 266 Plonk units and the separately selected large GLV differential case.
Its independently reviewed compiler inputs and copied binaries remain bound to
that capture. After keygen cleanup and lint repairs, the fresh copied oracle
passes all 42 ordinary and eight explicit large correctness cases, including
complete proof-byte parity and mutation checks. Its binary remains unchanged;
the broad source-drift result remains retained separately from the consumed-input
review in `target/qualification/keygen-cancellation-oracle-current`.
Current Pasta/Plonk library and test targets pass strict Clippy.
The combined proof/CoreZk/Torii/configuration test-target check and artifact CLI
check pass; concurrent engine edits during that check restrict it to compilation
evidence. The last gadget strict lint failed on 570 library diagnostics; the
separate warning-only diagnostic is not a strict pass. Reviewed source fixes are
now applied, together with lookup compression simplification and earlier wiping
and release of the dead denominator allocation. Both-field regression tests are
added. All six optimized engine test targets now compile. Independent review
checks 73 actual compiler depfiles, 1,461 source inputs, 4,135 package files and
five cfg-only generators; the 22 concurrent Deploy/Wallet edits are outside
that compiled graph. The copied executable passes all 94 Pasta and 268 Plonk
cases, including the new both-field regressions. Its gadget selection finishes
with 284 passing cases, one stale fixture-count failure and eight explicit
ignores. Subsequent test-only lint fixes and removal of an unused
private wiping helper are recorded as source changes, so these results remain
bound to the copied executable. Strict lint exposed 45 gadget test diagnostics,
then a feature-subset unused X25519 wrapper and three Torii-shared diagnostics.
Those repairs are applied. Plonk, Gadgets and KagemushaProof library/test targets
pass strict Clippy with `--no-deps`; the dependency-inclusive command still
fails on eight unrelated configuration diagnostics. The gadget run also exposes
a stale 18-signature assertion after the standalone Load-voucher signature was
removed. Its repair checks the exact 17 current signed objects against the
canonical generator, retaining the native/circuit and swapped-message checks.
The rebuilt oracle independently passes all 42 ordinary and eight explicit
correctness cases, including exact proof-byte comparisons. Actual component
inputs and tools are unchanged; the original HEAD-only drift refusal remains
in `target/qualification/engine23-oracle-capture-1/correctness`.
The matching current x86_64 Mach-O executable also passes all 50 correctness
cases under Rosetta, including all eight explicit large cases and exact
native/vendored proof bytes. All 1,864 package files, 400 ordinary compiler
inputs, the independently reproduced generated include, tools, retained
originals and binary stay unchanged. The receipt is
`engine23-oracle-x86-capture-1/correctness/result.json`, SHA
`1b275b1a0bd0bce6375f98601efbc3aa50ae7bde88097c3dd093eca7bb93784a`.
This is x86 instruction-path correctness, not physical x86 performance.
The second engine capture passes the repaired 17-object P-256 fixture, twelve
targeted lookup/allocation/owned-witness controls, four ordinary BLS controls
and eight M3 harness correctness cases. Its three explicit BLS cases also pass,
including a complete 1,084-leaf proof/verification trace. Source, binary,
tools and retained inputs stay unchanged
(`engine23-capture-2/correctness/result.json`). Strict gadget library/test lint
passes. The remaining 308 ordinary proof cases finish with zero failures;
together with the four earlier BLS cases, all 312 ordinary cases of that
captured proof executable pass. The exact-source wrapper retains its refusal
because later test and runtime edits postdate that capture; these are historical
component results (`engine23-capture-2/remaining-proof-correctness`). They do not
qualify the subsequent runtime fixes or M3 performance. Captured binaries and
the original broad source-drift verdict are retained in
`target/qualification/engine23-capture-1`. The source port is recorded in
`target/qualification/engine23-production-port-1`. Earlier records are under
`target/qualification/keygen-advice-capture-20261008`,
`keygen-cancellation-strict-2`, `keygen-m3-gadgets-strict-1` and
`finality-server-import-check-3` within the same qualification directory.

The maintained engine now implements source-bound VK-to-PK reconstruction
without commitment MSMs and an opaque 96-byte source-admission record. The
current copied engine binary passes 14 focused tests, including eight small
genuine proofs across both curves, exact proof-byte comparison, full
verification, source/parameter mutations, malformed imports and cancellation.
Strict library lint passes after replacing manual Copy/Clone with derives; the
first lint failure is retained. Actual compiler inputs, generated outputs and
tools remain unchanged for these checks. Results are under
`target/qualification/engine-source-seal-capture-2` and
`engine-source-seal-validation-1/{tests-2,lint-2}`; the test receipt is
`cb3658bfcef981f4f1942ab40eaa8650e4aa25f50fa9aab92f62771c371f5f15`.
The 53 dependent proof/wallet source files are installed, with the same
derived Copy/Clone correction for Omega. They retain private admission records
and borrow installed verifier metadata while rebuilding proving buffers for
the active stage. The final current proof-library capture passes all 51
selected ordinary controls, including four genuine k8 direct/rebuilt proofs
with exact byte comparison and full verification. The selection includes
eight finality import-reuse mechanism controls and the selected-original
comparison control. Strict proof-library lint also passes. The first build
syntax failure and first lint failure are retained with their scoped repairs.
Current proof results are in `source-seal-consumer-validation-1/proof-tests-2`
(receipt `ce80b5fb2e270c625fe1652ef54649f4003ca0c40127621288d206eea9598268`)
and `proof-lint-2`. The copied proof binary is
`fa9efed7e43fd3b428c2edaf573b1f4f36b08a29a9f03629798e503582ca7264`;
its actual 41 depfiles, 1,392 compiler inputs and three generators are retained
under `source-seal-proof-capture-3/consumed-input-review`, with unchanged
source/tool inputs and no generated Rust. The shared-wallet native9 build also
succeeds. Its broad source check remains inconclusive because of concurrent
Deploy edits; a separate strict review admits all 37 actual packages,
42 depfiles, 1,732 compiler inputs and four configuration-only generators with
zero changed consumed/package inputs, exclusions or source-equivalence
supplements. All eleven changed Deploy paths are outside that closure.
The current binary
`e7c75d02aa809ffc38ee80ffc8e0df527894d2184344b8b037b6d4c2be6d2b12`
passes all 20 selected scanner, private-binding and source-dispatch controls
with unchanged inputs (`native9-ordinary-controls-1/result.json`, SHA
`54c6bd771a81bc1859d2c4c15d21f3091ce431405e5c1b9dcf419b095c2d6af0`).
These 20 cases produce no completed proofs. The same binary subsequently passes
all289 ordinary Advance and214 wallet-state cases, including crash/restart,
exact replay, permanent receive deduplication, unavailable custody, maps,
preemption and one genuine k8 checkpoint proof. Seven ignored monetary/history
cases are explicitly excluded. Both native processes exit0; the original
wrapper retains its failed/inconclusive501 count because two fee-claim tests
printed between their test names and terminal statuses. Independent review
accounts for all503 exact names and unchanged current source inputs without
rerunning or rewriting that result (`native9-wallet-controls-independent-review-1/review.json`,
SHA `49e1862599fd81e324711c6e8a302714881b8c704d3d0cd02e0635c19c211a1f`).
The corrected runner reuses the maintained serial-libtest parser;13 small parser
controls pass, including read-only replay of both original logs. A subsequent
153-case batch passes preparation74, enrollment21, registration21, finality28
and intake9, including both-curve k6 key reimports and two small genuine proofs
(`native9-admission-controls-1`). The final batch passes all77 ordinary artifact
and23 proof-boundary cases (`native9-artifact-controls-1`); selected k6/k8 key
generation/import and k16 parameter work generate no completed proof in that
batch. Each new process exits0, each exact selected name passes, and all current
source inputs remain unchanged. Independent reviews are retained in
`native9-admission-controls-independent-review-1` and
`native9-artifact-controls-independent-review-1` (the latter SHA
`e95f499edddd6ac3727fd4d6a3e574b9cb76375c906f550784daae12b634ab17`).
The three disjoint batches cover all756 ordinary tests across the nine wallet
namespaces. The earlier20 artifact and11 H1/staging controls are subsets and
are not added to that total. Ignored complete-catalog, monetary-history and
maintenance cases remain outside this result. These are component results,
not full monetary or physical-device evidence.
The strict closure is retained at
`corezk-native-network-capture-9/consumed-input-review/generated-closure/receipt.json`,
SHA `f78bb97bf5936e0a691831ec75a7b6860e4d75f020f0305f0684207d310d0cab`.
Its genuine complete-catalog harness adds 33 Q0/Q1/Omega acquisition attempts
for caps, cancellation, changed or missing D/V/PK originals and retry; these
additions remain unexecuted. Current complete-history qualification also
remains open.
This component result does not qualify M3, complete catalogs, wallet memory,
phone performance or recursive privacy.

The Rust account SDK's bounded Load event-path API and existing Load receipt
transport pass all 13 focused cases (seven existing and six event-path cases),
with zero failures or ignored tests. They cover exact account/network signing,
canonical Norito, malformed or oversized paths, deadline cancellation and
blocking-runtime entry. All compiled inputs, generated samples, tools and the
copied executable remain unchanged. Unrelated uncompiled Deploy/Wallet Rust
edits are recorded separately; the original broad build verdict and first
overbroad runtime refusal are preserved. These are transport component results,
not finality proof or monetary-network results
(`rust-sdk-kagemusha-capture-1/runtime-2`). The same-network controller passes
23 local orchestration controls, including exact typed rejection evidence;
its helper selector separately passes three local controls. Neither selection
is a live-network result. The continuation's missing module paths and five API
compile errors are repaired; the first native settlement test build's three
Norito JSON mutation errors are also repaired. Each failed build is preserved.
The corrected native owner builds and its copied inventory test passes; two
consumed data-model files changed during compilation, so its original
current-source refusal remains. The next harness build identifies a missing
iterator conversion and two unparenthesized Norito JSON expressions; those
errors are repaired and the failed build is retained.
Source tracing then found that both proposed malformed Unload cases fail
canonical decoding during routing, before certified execution. They cannot
establish the intended native-proof rejection check. The native fixture now
increments the canonical final IPA blinding scalar, re-signs its receipt with
the retained simulated C key and requires model acceptance plus an installed
native `Proof` rejection. It checks that the genuine claim, wallet snapshot and
provider signing count remain unchanged. The ledger continuation independently
checks that fixture and requires the exact certified proof failure even after
the successful claim's nullifier was paid. Account fee-quote/routing refusals
remain separately inconclusive and cannot invent a signed transaction or
certified failure. The corrected native binary builds and passes all three
ordinary controls, including canonical scalar mutation and malformed-tail
rejection. All actual compiler inputs, generated inputs, tools and the copied
binary remain unchanged through execution
(`corezk-native-network-capture-3/runtime-controls-1`). The sixth network harness
also builds; its 97 compiler depfiles bind 4,127 inputs across 84 local packages,
and all five missing generated inputs are reproduced exactly. Its broad drift
record covers unrelated developer-profile and documentation edits, while its
actual package and compiler inputs remain unchanged. All seven ordinary helper
controls pass with unchanged source, tools and retained originals
(`real-network-monetary-harness-capture-6/helpers-runtime-1`). The revised
controller passes 26 local controls and keeps account-specific network rejection
separate from the certified proof rejection gate. Its engine-closure extension
passes 30 controls and admits the actual six-role engine receipt without
inventing a network-style receipt or changing the retained broad verdict.
The sixth stock node/CLI capture builds with no source drift and passes the
stock-feature audit; all five generated compiler inputs are reproduced exactly
(`real-network-monetary-stock-capture-6`). A subsequent change to a compiled
Deploy transport input requires a fresh stock capture; the stable historical
capture is retained. The seventh stock build also compiles, but that input
changes again during compilation; its explicit source refusal is preserved.
Further stock rebuilding waits for the coordinated compact cutover. The optimized Core test build finishes naturally, and all55 selected ordinary
ledger tests pass from its preserved executable. Its 4,348 actual inputs,
76 depfiles and nine generators are retained; all five generated inputs are
reproduced exactly. The concurrent merge and later retirement/runtime edits
prevent a current-source verdict. The retained historical closure and exact
route-specific supplements govern Register/H6 diagnostics; they do not establish
whole-source equivalence. No live monetary campaign has run. Workspace format,
retired-codec guards and patch whitespace checks pass on the resumed checkout.

The current October 10 checkout again passes the legacy-codec guard, all 14
dependency/source retirement controls and the locked, offline, all-feature Cargo
dependency graph check. Selected sources remained unchanged during these checks;
the receipt is `target/qualification/native-finality-retirement-current-20261010-1/result.json`
(SHA `6490935a2c54e9e6c5ee96ee008386c61f2af0f57777410a9074de21cd891fe2`).
This validates retirement guards, not native wallet or network operation.

The M7 source retirement is installed: 30 reviewed source/manifest changes and
378 exact deleted files, with every original preserved in a verified archive.
Cargo regenerates the lockfile, pruning 14 packages with no additions or retained
identity/checksum changes. The earlier dependency/source-seal draft controls pass;
current dependency graph, nine dependency controls, five retirement controls,
47 source-seal tests, Rust-lane inventory and legacy-codec checks pass. All three
negative production-API doctests and the enabled captured-transcript key test
pass after deletion, and strict Plonk library/test lint passes. The Norito,
environment and FHE inventories are regenerated and checked against current
source; no retired oracle path remains in them. The initial IVM-only guard reports
`vendor/bytes/src/lib.rs:6` (`#![no_std]`); the preserved pre-retirement guard
produces the identical failure. The reviewed 15-file repair makes this maintained
fork native/std-only, with the custom owner/reclaim implementation unchanged.
All 1,007 post-port tests pass, including eight owner/reclaim cases; disabling std
fails with the intended compile error. The unchanged IVM-only guard now passes,
with no exemption. Cargo removes only the unused bytes-to-portable-atomic lock
edge, with no package identity or resolved node/edge/feature changes. The original
failure remains alongside the repair evidence in `bytes-native-only-port-1`
(result SHA `dec13bd6cd8079abb3cb0342ec53a1bc0065816248c051261815b8a1742a512e`).
The consolidated retirement receipt is `m7-retirement-port-1/validation.json`
with the subsequent strict-lint receipt beside it. All 42 independent Sigma/Wide
cases now regenerate native proofs at 1/2/4/7 workers on ARM and compiled x86
under Rosetta. Both targets pass exact descriptor/key/proof comparisons and
proof/public-input mutations; focused strict Plonk lint passes. This is
instruction-path correctness, not physical x86 performance. The four remaining
RP56 parameter-generator consumers have 17 reviewed test/fixture files installed;
their four dev-dependencies are now removed in the same lockfile transaction. All 822 constant fields and
102 Kaigi frames are captured from the original generator and independently
rederived with Python integer arithmetic. Three corruption controls and the
strict Rust fixture-reader test pass. The rebuilt Poseidon crate passes all
20 tests; selected Kaigi, SoraFS and IVM unit cases pass 5, 3 and 4 respectively.
The first consumer wrapper stops on a duplicate output-directory name before
its last target. A subsequent standalone target selection is refused because
IVM uses grouped test targets. Both failures are retained. The corrected
`ivm_group_07` selection passes all11 SIMD cases. Exact source/lock deletion is
recorded in `m7-retirement-port-1`; a separate whitespace receipt removes only
the trailing blank line from Kaigi's manifest. Post-retirement checks remain
open, and these results do not establish protocol qualification (`m7-retirement-draft`,
`m7-native-goldens-draft` and `m7-parameter-migration-draft` under
`target/qualification`).

Native fold preparation now samples a canonical Fq salt with fallible OS entropy
and bounded rejection sampling, replacing arbitrary 256-bit values that could
fail field decoding. Entropy failure remains unavailable and retryable. Omega's
terminal fold and Bootstrap checkpoint restoration also retain the shared
cancellation token through actual recursive folding. The two deterministic
recursive-boundary regressions pass on a copied proof executable with all
1,384 consumed source inputs and four generator closures preserved and unchanged
(`native-fold-cancellation-capture-1/fold-regressions`). All three Fq sampler
regressions also pass on native5, covering zero, the modulus boundary, exhausted
rejection, entropy failure and cancellation. The combined five-case receipt is
`native-fold-salt-cancellation-fix-1/focused-validation.json`. A subsequent audit
finds seven intermediate wallet stages and two server-finality draws still using
infallible OS entropy. They now share a crate-private sampler for both Pasta
fields. The finality callback retains entropy unavailability distinctly even if
a consumer swallows its provisional error. All eleven focused regressions pass
on native6, with unchanged actual compiler, package, generator and tool inputs
(`corezk-native-network-capture-6/entropy-regressions/component-result.json`,
SHA `0a254e7bfaf73056a75a53d46d94075657a4d31424b129b1ae8b494f088eb07a`).
The original broad source-drift refusal remains; its narrower closure excludes
only uncompiled Core Rustdoc and evidence changes. The deterministic Q nonce and
all proof layouts remain unchanged. The genuine runner's four compiled-selector
and provenance checks pass using native6 and the explicitly historical Core
capture. Its later post-bytes preflight preserves both executables as historical
diagnostics with exact reviewed source differences and 28 passing runner controls.
This preflight is separate from the subsequent Core execution passes and active
recursive proving. Neither establishes a monetary acceptance claim.
These component checks do not establish a genuine wallet exchange, payment
latency or release qualification.

A further source audit finds an infallible thread-RNG call in durable-store
staging-name generation: OS seeding/reseeding failure can panic before file
creation. The reviewed six-file fallible API repair is now installed, including
all native/simulated filesystem implementations and callers. Native7 passes all
seven new store/archive tests plus three existing custody/archive checks and the
H1 regression, with exact current-source admission. The 11-case result is
`corezk-native-network-capture-7/repairs-runtime-1/result.json`, SHA
`ebf446f2d580400a66f8a90a98ac1ba32e1bd1294fd716e6c0742f2b98ac16c1`.
This is component correctness, not proof-recovery or phone qualification. The port
receipt in `staging-name-entropy-draft` is
`f8b4205c9671b021141a3c2cbc0e6ff96b886272fae52f570ba147a9d25a49bd`.
The repair preserves exclusive creation, descriptor custody, collision limits,
exact-byte retries and existing fault-step numbering. No selected M3 source file
or root overlaps this change; no build or test ran during the port. This fix is
independent of compact-registration retirement. The remaining 185-file migration
is reconciled separately in `compact-coordinated-cutover-3` and remains held for
the genuine proof/differential gate.

The broader current-source native wallet selection completes with 723 passing
cases, two failing fixtures and zero ignored tests; all source, binary, tool and
retained-input checks pass (`corezk-native-network-capture-3/runtime-wallet-ordinary-2`).
The session-renewal fixture now permits the conservative one-millisecond ceiling
at acceptance and still expires on the next monotonic tick. The unsafe-file-mode
fixture explicitly sets mode 0644 instead of relying on the process umask.
Production deadline/custody checks and every rejection assertion are unchanged.
The fresh native capture compiles and both corrected cases pass with unchanged
inputs and binary. The exact combined inventory covers all 728 ordinary wallet
cases: 723 broad-run passes, three earlier controls and these two repairs. Its
compiler-input comparison changes only the two reviewed test fixtures; metadata,
tools and all 1,031 compiled case names remain equal. The coverage record is
`corezk-ordinary-wallet-fixture-repairs-1/ordinary-coverage-receipt.json`.
All 27 artifact-dependent or heavy ignored wallet cases remain separate and unqualified.

The copied six-executable component capture passes server cache 13, artifact CLI
11, verifier recipes 10, catalog intake 10, continuity cancellation 2, Torii
lifecycle 6 and parent queue 2, configuration 9, registration 2, compact intake 3 and fold-preemption
2 selected cases. These selections are not a count of unique workspace tests.
The cache cases include real proofs on both curves after eviction and exact
deterministic regeneration. The scheduler cases use production coordination with
explicitly mocked proof work. Full-graph and genuine compact-proof cases remain
ignored pending artifacts. Independent review checks 91 actual compiler depfiles,
5,234 ordinary inputs and five generated inputs, including 13 exactly reproduced
generated files. The original broad build-drift verdict and server-runtime merge
drift remain retained in
`target/qualification/finality-server-component-capture-1`; this evidence belongs
to the preserved binaries, not the subsequent merged source.

The latest completed host Swift run passes **2,242 tests** across three XCTest
bundles (4, 2,166 and 72), with zero failures. The canonical local runner built
and packaged its selected ABI29 native bridge and completed both source/artifact
admission checks, including verification after execution. Admission binds the
native compiler dep-info and original selected input identities, plus manifest,
runtime and native build inputs; unrelated broad source changes remain
diagnostics. Logs and producer records are retained in
`target/qualification/swift-local-dcqlwsh2`; its natural exit is zero and all
2,242 cases have zero skips. The root terminal receipt has SHA
`dfb13f28b224f2d7aaa35d5ac69deac79c4d0c0e0145f5fd4e1ac60410fb0c8d`.
The runner does not independently capture the complete prospective Swift
compiler-input closure. Earlier successful runs and refused source captures
remain historical records. This host suite does not establish physical-device
or complete monetary-protocol qualification.

The latest completed Kotlin/JVM and Java consumer run passes **1,902 tests in
215 suites**, with zero failures, errors or skips, in 550.62 seconds. The full
`:core-jvm:test --rerun-tasks` run retains JDK 21 and the JDK 8 API compile guard.
Fresh generator10 admission binds 303 compiler artifacts and 14,393 unchanged
selected inputs. The newly captured ABI29 bridge passes source, identity and
artifact admission before and after execution; its dylib bytes match the last
successful Swift run. All prior JVM test cases remain, with one new registry
regression. Records are retained in `target/qualification/kotlin-current-core-jvm-8`
(`result.json`, SHA `b927c33e0eb917976de31b87595ef19da58114bb4b2b48457132eec57649d2e6`),
`kotlin-fixture-generator-capture-10` and `native-sdk-current-capture-1/capture`.
This establishes current host consumer coverage, not Android, physical-device,
complete monetary-protocol or C12 qualification.

Before the registry repair, the complete Kotlin/JVM and Java consumer run executed **1,901 fresh
tests in 215 suites**, with one failure and zero errors or skips. It runs the
full `:core-jvm:test` task with `--rerun-tasks`, JDK 21 and the retained JDK 8
API compile guard. The fresh Rust fixture generator and ABI29 native library
pass admission before and after the 584.45-second Gradle run. Original logs,
fresh XML and input identities remain in
`target/qualification/kotlin-current-core-jvm-7`. The failure finds four missing
Kotlin registry entries already present in Rust: three SCCP actions and AMX
expiry. Adding those four exact wire IDs makes the 328 `iroha.`-prefixed entries
match. Its seven signed-attachment regression cases pass with zero failures, errors or
skips in 46.71 seconds, with selected inputs and native binaries unchanged
(`kotlin-native-registry-current-focused-1/result.json`). Independent review then
finds that the parity test's prefix filter omits 69 other valid canonical IDs,
which the Kotlin transaction encoder incorrectly rejects. The repaired registry
now contains all 397 canonical IDs. Its parity check covers every registration
macro, checks the parsed count and rejects duplicate IDs. All eight focused
signed-attachment tests pass with zero failures, errors or skips in 30.89 seconds;
they include roundtrips for five non-`iroha.` namespaces and rejection of ten
invented aliases or unknown IDs. Selected source, fixture-generator and native
inputs remain unchanged (`kotlin-native-registry-current-focused-2/result.json`).
This is codec/admission evidence, not native proof execution. The current complete
host suite reported above also covers the repair.
Rust's corresponding inventory expectations and golden hashes now cover 397
registrations with governance and 379 without it. Independent derivation
reproduces both earlier hashes by removing exactly the four added registrations.
Both existing inventory tests pass separately with default features and with
`--no-default-features`: four focused passes, zero failures or ignores, and
unchanged selected inputs (`rust-native-registry-focused-1/result.json`, SHA
`28a4303171077df4f3f40105e1532cd10fa160a98efbf4d9a33910fbba7e7cde`).
The earlier 1,901-case pass in
`kotlin-current-core-jvm-6` and the intervening generator source refusal remain
historical evidence. Android and physical-device qualification remain separate.

The fresh complete C# host assembly executes **5,797 passing cases**, including
all six actual native confidential-prover cases, with zero failures, skips or
errors (`csharp-current-abi29-2`). Independent source/discovery review accounts
for all 1,233 methods, with every Fact exactly once and all 17 deferred theory
providers expanded to their exact source-defined counts. The actual loader
observes the rebuilt ABI29 dylib `5514e2ea…cad5`. The compiler and test process
both finish with exit zero, but the wrapper retains exit one: native
`iroha_torii_shared` source and the shared workflow fixture change during the
run. These passing cases do not qualify the new source interval. The refreshed
native bridge capture2 subsequently compiles and passes ABI29/346-export
admission with dylib `42215c38…28fc`; another consumed private-settlement source
change makes C# attempt3 refuse before compilation. Current native delivery
and consumer qualification remain open, including refresh of the earlier
Swift/Kotlin captured-source qualifications. The first C# build failure from
loader diagnostics on compiler stderr remains retained; disabling that trace
only for build/version probes allows the successful fresh build.

The earlier C# native-consumer selection passes 543 cases, including six actual
confidential-prover cases, with zero failures or skips and the exact rebuilt
ABI27 dylib observed by the loader. Source and compiled artifacts remain
unchanged. The wrapper initially refused its 518-case discovery count: one
selected theory expands into 26 data rows at execution. Independent review
matches those 26 rows to the source and confirms every other method's count and
filter membership. The original refusal and separate reconciliation are retained
under `target/qualification/csharp-current-abi27-1`. This establishes the
selected host consumers, not installed release-package or network readiness.
After the observation surface changed, the six actual C# native cases also pass
against the preserved `37d3b93c…554dd9` library with its actual loader path
observed. Managed inputs and compiled outputs remain unchanged. This separate
receipt, `target/qualification/csharp-native-captured-abi27-3/runtime-result.json`,
explicitly does not qualify current native sources; their admission refusal is
retained separately.

The collection and custody-deletion SDK changes pass 16 focused
managed Kotlin tests with JDK 21 and the JDK 8 API compile guard retained. The
run binds unchanged SDK inputs, compiled classes and XML results under
`target/qualification/native-terminal-sdk-kotlin-managed-2`. This covers typed
status parsing, immutable collection values, owner-bound one-use deletion
reviews and uncertain-outcome recovery; it excludes host JNI execution and
physical custody. ABI/header parity and the no-legacy-codec guard also pass for
the coordinated source changes. The rebuilt ABI27 host `b968de18…fda800` also
passes 62 fresh Kotlin/Java JNI cases: nine wallet/deletion/collection probes,
18 privacy cases, 25 SoraFS cases and ten signer cases, with zero failures or
skips. SDK/fixture sources and the selected artifact are unchanged before and
after execution. The loader receives the sole explicit library directory;
independent mapped-library path observation was unavailable. The retained
receipt is `target/qualification/native-terminal-sdk-kotlin-native-current-2`;
its initial test-probe compile failure is retained separately. These host
boundary checks do not open a genuine funded wallet or qualify a phone. The
current captured Rust collection/deletion selection passes 47 of 48 cases,
including all 26 bridge cases. Its one failure is a test expecting empty-map
warnings from a fixture whose three map roots are nonempty. The narrowly
corrected expectation awaits a rebuilt run; the original failure and unchanged
runtime sources, tools and binaries are retained in
`finality-per-use-compiler-capture-1/collection-terminal-runtime-1`.

The merged wallet observation surface now shares one native C/JNI dispatcher
for metadata, retained peer output and prepared Load data. Kotlin and Java
consumers pass eight managed tests with the JDK 8 API guard retained
(`target/qualification/kotlin-observation-managed-current-1`). The canonical
Kotlin account codec remains the single owner. Mandatory ABI27 inventory now
contains 88 C/JNI exports; header parity, 60 mismatch controls and 69 artifact
tests with 347 subtests pass. Originals are retained under
`observation-jni-inventory-check-3`, including earlier tooling failures.
The previous ABI27 artifact lacks the newly required exports and is correctly
refused. The rebuilt ABI27 host `37d3b93c…554dd9` passes 65 fresh Kotlin/Java
JNI cases, including the new observation probe and both canonical account
codec tests. Sources, fixtures and artifact bytes remain unchanged; the receipt
is `target/qualification/kotlin-observation-jni-current-1`. The loader used the
sole explicit artifact directory; an independent mapped-library observation
was unavailable. This covers the host boundary, not a funded wallet or phone.
The complete rebuilt Swift suite also passes 2,203 unique tests across three
XCTest bundles (4, 2,127 and 72), with zero failures or skips. The canonical
runner completes its post-execution artifact check against the same current
ABI27 dylib. The receipt is
`target/qualification/kotlin-observation-swift-current-1/completion-review.json`;
the earlier 2,180-case capture remains evidence for its own preserved candidate.

The fresh Python installed-wheel selection passes all five native consumer
tests with zero failures or skips. The emitted native module, wheel payload
and installed module have the same SHA `2117d3e4…63d14e`; source, actual Cargo
inputs, tools and installed files remain unchanged through final verification.
The retained result is
`target/qualification/python-native-local-unit-current-abi27-3/artifact/result.json`.
The two earlier producer refusals remain recorded. This is a local component
result; the clean-source release packaging guard remains unchanged and no
release, wallet exchange or phone qualification follows.

The next JavaScript capture executes all six original native cases successfully,
but post-run admission rejects a data-model finality source change. Its original
`passed: false` result remains in
`target/qualification/js-native-current-abi27-2/runtime/result.json`.
The subsequent attempt refuses a changed Node executable before compilation.
After selecting the actual Node executable, another build succeeds but artifact
admission refuses a consumed `iroha_torii_shared` source change, before runtime.
Both refusals remain under `js-native-current-abi27-{3,4}`; neither is a native
test pass for the current candidate.
The new Core/CoreZk capture passes 24 explicitly selected setup, registration and
finality diagnostics (14 Core and ten CoreZk). Its binaries and original
mixed-source verdict remain unchanged in
`target/qualification/monetary-pipeline-capture-1/diagnostic-runtime-1`.
These checks do not qualify the merged source or complete monetary exchange.

The first real-network daemon/CLI capture passes its stock-feature audit and
independent compiler-input review, including exact reproduction of generated
tables. The companion harness builds successfully but its consumed data-model
source changes during compilation, so source admission refuses it before
network execution. Both original verdicts remain under
`target/qualification/real-network-monetary-{stock,harness}-capture-1`.
The second stock daemon/CLI capture also passes exact consumed-input review and
independent generated-table reproduction. Its original broad drift verdict is
retained: only uncompiled harness/documentation paths changed during that build.
A later merge changed 24 consumed inputs, so these binaries cannot be paired
with a harness compiled from the current checkout. The exact comparison is
retained in `post-merge-current-source-refusal.json`; no network runtime was
started. A matching daemon/harness rebuild remains required. Originals are
under `target/qualification/real-network-monetary-stock-capture-2`.
The second harness also builds, but admission observes two consumed Torii
telemetry source files changing during compilation and refuses it. Its original
binary, input inventory and refusal remain under the corresponding
`real-network-monetary-harness-capture-2`; no network test is counted as passed.

All eight native Send control masks and both Receive variants complete their
measurement and separate one-key footprint processes: 20 processes pass, with
all 304 timed proofs independently verified. Locally generated step descriptors
encode 3,296-byte proofs without quotas and 3,456-byte proofs with quotas.
Four-worker observed proof p95 ranges from 391.7 to 1,378.1 ms; separate one-key
kernel peak RSS ranges from 46.50 to 169.16 MiB. These are captured-binary step
diagnostics, not durable-payment latency, complete-catalog or phone results.
The broad wrapper retains its source-drift failure from the concurrent merge;
the binary and measurement tools remained unchanged. Original samples and
descriptor/key digests are under
`target/qualification/monetary-selectors-capture-1/runtime-1`; its
`selector-summary.json` pins each process result. Three measurement helper tests
pass, and selected-package strict Clippy with `--no-deps` passes. The ordinary
strict command still fails on the 570 gadget dependency diagnostics; fixes are
staged separately from the active measurement sources.

The revised measurement harness passes 114 focused tests. It binds the complete
local package inputs, actual compiler depfiles, selected Rust tools, and both
present and absent Cargo configuration files in checkout ancestors and
`CARGO_HOME`. Unqualified compiler/wrapper overrides, configuration includes,
injected configuration environment, unavailable inputs and probe failures refuse
qualification. This is a local input and tool policy, not a hermetic operating
system claim. Fresh preparation succeeds with 2,022 bound inputs across 20 local
package roots and 23 actual compiler depfiles. Independent preflight confirms
unchanged before/after inputs and the selected executable. The nine-process,
three-block campaign under seed 20261008 stopped on a hard failure.
All four A configurations (synthetic and real chips, with one and four workers)
have completed nine valid processes with passing verdicts. The real A
one-worker block medians are 31.107561, 30.902561 and 31.939405 seconds of CPU
time; its six invalid attempts remain recorded. The real Q four-worker
configuration failed on its seventh valid process: 10.630025916 seconds of
observed elapsed time exceeded the 10-second hard limit, with no invalidity
reasons. The other three Q configurations are incomplete. No retry or
replacement sample changes that failure. Memory
compression invalidates an attempt even when its two proofs verify. The first
real-chip Q one-worker block has a 27.049123-second CPU median: all three runs
meet the 30-second hard limit, but the median misses the required 27-second
margin. The second real-chip Q four-worker block has a 9.420910083-second
elapsed median, inside the 10-second hard limit but outside the required
9-second margin. These block failures remain even if later blocks are faster.
Candidate,
preflight, raw attempts and the terminal failure are retained in
`target/qualification/m3-current-source-closure-candidate-20261008`. The source
closure and configuration repair records are retained in
`target/qualification/qualifier-source-closure` and
`qualifier-cargo-config-draft`.

After native engine retirement and the bytes repair, a new M3 preparation
retains all four k16/PIPA-R descriptors with unchanged captured inputs and tools.
Its candidate is `m3-engine23-final-20261008-2/candidate.json` (SHA
`a9f3e0e619710b6565672793d3118bedebbbda6666815f0765584d9f3e16735d`),
and its executable is `624707b2c650067a784efe8eaf07755fc0996094b8ebbd6be321b1616ae52840`.
The first post-retirement preparation is preserved separately. Preparation
establishes no timing or memory pass, and neither preparation replaces the
earlier hard failure.
Its separate one-thread campaign stops on source-boundary drift: three synthetic
Q processes are valid, while the first A attempt is retained as invalid. The
only changed selected input is Cargo.lock, adding Torii's optional bytes edge;
Torii is outside the compiled M3 graph. Exact dependency, compiler-input and tool
review establishes no change to the measured executable or its consumed source.
The original partial campaign remains unchanged and cannot be sealed as a
completed phase. A prospective metadata-only candidate3 refresh uses the same
binary, without a build (`m3-engine23-final-20261008-3/candidate.json`, SHA
`6faf96419c4eb3c1fb24dd6b5c499a86c5bf62a5d77adcfe2fcd31d60c75de9d`).

Candidate3's fresh one-thread phase completes under a separately pinned plan,
with 36 valid processes, one retained invalid attempt and no imported samples.
It preserves the seeded eight-configuration order while leaving worker4 entries
unmeasured in that original phase summary. The process, calibration, probe and verdict
functions are unchanged; each selected configuration requires three blocks of
three valid fresh processes. Fifteen mutation controls cover a separate raw-evidence
combiner for disjoint worker phases. It preserves each original partial summary
and cannot claim the original fully interleaved campaign, full release or phone
qualification. The sealed combined assessment fails; raw invalid attempts and
hard failures remain retained.
The terminal phase seal is
`m3-phase-combiner-candidate3/one-thread-seal.json`, SHA
`57c40f73849c19d7f7f3160259861866b9ac772771c30168ead9a045483e7673`.
Its two passing and two borderline selected configurations meet every hard limit;
the original summary remains inconclusive for the unmeasured worker4 rows. The
separate four-worker phase stops on a valid hard failure with unchanged
source/binary/tool pins and no phase overlap. The first real-Q one-worker block has three valid CPU samples:
27.344776, 27.234224 and 27.220971 seconds. All meet the 30-second hard limit,
but the 27.234224-second median exceeds the required 27-second time margin.
Its second median also misses at 27.019909 seconds; the final 25.618863-second
median does not change its borderline verdict.
The first synthetic-A one-worker block also misses its memory margin: median
kernel peak RSS is 868,139,008 bytes, above the 867,046,522.88-byte margin
(`0.85 GiB × 0.95`), while every sample remains below the 912,680,550.4-byte
hard cap. Later lower samples cannot erase either first-block result.
Real A completes all nine valid one-worker processes with CPU block medians
32.028733, 31.432403 and 29.935427 seconds, and RSS medians 778,502,144,
770,310,144 and 707,969,024 bytes, meeting its hard limits and margins. Synthetic
A completes as borderline because its first-block memory margin remains missed.
A synthetic-Q attempt is invalid because pre/post calibration drift exceeds
5%; its favorable 19.628857-second CPU sample is excluded and retained. The
synthetic-Q configuration then completes nine valid processes in ten attempts
and passes.

The four-worker phase retains 18 valid processes and no invalid attempts before
its declared stop. Real Q's sixth process, in block two, produces verified proofs
at 13.284632334 and 8.163979958 seconds observed elapsed. The slower proof fails
the unchanged 10-second hard limit; kernel peak RSS is 628,260,864 bytes and all
calibration and environmental probes are valid. Passing block medians cannot
erase this individual failure. The other three four-worker configurations remain
inconclusive, with only three, six and three valid processes for real A,
synthetic A and synthetic Q respectively. The four-worker seal is
`m3-phase-combiner-candidate3/four-thread-seal.json`, SHA
`c0c0ed64eb9c003f7f05c417103ac8f4065be098553345f5b6912474d8d1e0e7`.
The combined assessment is `m3-phase-combiner-candidate3/combined-result.json`,
SHA `074eeeb57425b544b15382deb6fd0330171485e45080ef609e75222d8f7fed26`:
two configurations pass, two are borderline, one fails and three are incomplete.
It establishes no M3 qualification.

The maintained qualification harness now rejects unrecognized or ambiguous
power-probe output and checks low-power mode in the active AC profile. Hosts
whose recognized profile does not expose that optional setting remain supported.
Summary validation also replays the declared RNG draws for every attempt,
including invalid attempts; changing a seed and its matching raw report cannot
substitute a different run. Eleven new regressions fail before these fixes;
the complete focused suite passes126 cases after them. Source and execution
records are retained in `m3-qualification-power-seed-fix-1`. These are harness
correctness results, with no new native measurement or change to the sealed
candidate3 verdicts. The next measurement campaign requires a fresh candidate
bound to the corrected harness.

A subsequent bounded one-worker real-Q stack diagnostic completes with both
proofs verified and unchanged source, helpers and binary. Its result is retained
at `m3-candidate3-q1-profile-1/result.json`, SHA
`75332cd389bc29cd32fbbd452a56ce3320256e1f318bcde7b4be2b3c8e045f2f`.
All diagnostic timings are excluded from qualification; sampling cannot repair
or replace any sealed result.

The independently installed coset-first-pass FFT change passes all 14 focused
ARM correctness cases in `coset-first-pass-arm-validation-1`; the captured
compiler-input review accepts component source custody. That run
preserves its original strict-owner Clippy failure. Four test-helper lints were
subsequently repaired without changing production commitment logic; strict owner
Clippy and all eight `rebuild::tests` then pass. The captured x86 executable
passes all14 selected correctness cases, including unchanged golden proof bytes
for both curves. `coset-first-pass-x86-validation-1/result.json` has SHA
`be5270f67e1c792fdbb41bc23f4108524fc31d9fb2769939de479907588c9f5b`;
its actual compiler-input receipt has SHA
`23e1c2296a1406b903c0051abbc9c1bcbcb97fc41a2b08a3e952ac306c4dd1ce`.
These are component correctness/lint results. Repair source and assertions
are retained in `plonk-rebuild-probe-lints-1`. Its `root-validation.json`
records the two successful follow-up invocations from the tool transcript; it
is not a full compiler/tool provenance receipt.

The subsequent `m3-post-fft3-20261009-1` four-worker campaign completes with
all four configurations passing. It retains 36 valid fresh processes across
three blocks per configuration, two verified proofs per process, and 11 invalid
attempts out of 47 total attempts. All invalid calibration or memory-pressure
attempts remain in the record. Q uses the slower proof's observed elapsed time;
A's four-worker requirement is memory only. All valid runs satisfy their hard
limits and every block median satisfies the applicable 10% time and 5% memory
margins. No timing adjustment was applied.

| Four-worker workload | Slower-proof elapsed block medians (seconds) | Maximum valid elapsed (seconds) | Maximum kernel RSS (bytes) | Verdict |
| --- | --- | --- | --- | --- |
| Synthetic Q | 6.271861417 / 6.379341667 / 6.350869875 | 6.659121 | 664,305,664 | pass |
| Real Q chips | 8.516209625 / 8.641103541 / 8.528893833 | 8.677744459 | 693,485,568 | pass |
| Synthetic A | 8.043878083 / 7.946488458 / 7.841625417 | 10.382043417 (informational) | 805,847,040 | pass |
| Real A chips | 8.934245166 / 9.011196541 / 8.899934 | 12.979032125 (informational) | 838,959,104 | pass |

The supervisor completed with exit0 and unchanged source, binary, helper and
tool pins. Root independently recomputed the summary from every retained raw
measured/calibration record: `root-four-worker-review.json` SHA
`aa9724b41b276e37336315476340e3310b73aaaedef86915f667e8685bc13abb`.
The frozen candidate SHA is
`6719f2bd974599cf80ba76f69997e74671b6274314f9998171806effc3cef0a2`;
`four-thread-campaign/summary.json` SHA is
`9441660548ffad1f01c08972e48caa230628dbd4d2946c3595d9547ba00fb37e`.
The same candidate's one-worker campaign completed naturally with exit1:
36 valid measured processes and four retained invalid attempts, all due to both
CPU and elapsed calibration drift. Each configuration has three valid processes
in each of three blocks. All hard limits pass, but real Q's second block misses
the 27-second CPU margin. Its faster third block does not erase that result.

| One-worker workload | Slower-proof CPU block medians (seconds) | Maximum valid CPU (seconds) | Maximum kernel RSS (bytes) | Verdict |
| --- | --- | --- | --- | --- |
| Synthetic Q | 20.695443 / 21.199168 / 19.818511 | 21.353318 | 533,381,120 | pass |
| Real Q chips | 25.950183 / 27.788199 / 25.258789 | 28.338087 | 671,006,720 | borderline |
| Synthetic A | 25.546674 / 27.655707 / 27.562523 | 27.747699 | 787,136,512 | pass |
| Real A chips | 31.192419 / 31.919000 / 30.547737 | 32.610504 | 785,268,736 | pass |

Root's terminal audit reopens every original process/log and recomputes exact
invalid reasons, both calibration clocks, schedule/seeds, worker/layout/memory
policies and limits. It joins both supervisor exits and immutable helper pins.
The phases remain separate schedules: their disjoint verdicts give seven passes
and one **borderline**, never a whole-M3 pass. All 261 process reports contain
two verified proofs (522 including calibration and invalid attempts).
`terminal-joint-outcome-review.json` has SHA
`676f299ced71b5d3e912ab962714194d100e95e929b02a454b09239d4eae5924`.
The later merge changes nine captured source-scope files, so this is historical
candidate evidence; it cannot qualify the current checkout. No monetary catalog,
full-wallet, two-second durable-completion or physical-phone gate follows.

The next candidate uses validated public fixed-table bounds for the usable
prefixes of singleton, unrotated lookup commitments. Random padding retains the
full-width secret path and the same blind; scalar validation precedes small-input,
optional-table and scratch fallbacks. It shares the existing secret MSM kernel
and process-wide 64 MiB budget. This changes no constraint, descriptor or intended
proof byte. Bucket access remains variable-time; no constant-time MSM claim is
made. The candidate passes 101 ordinary Pasta and 283 ordinary Plonk library
tests, the explicitly selected large GLV comparison, and strict release library/
test Clippy. Seven new tests check all public bound/carry bit edges, prefix/tail
commitment equality, malformed bounds and exact full proof bytes against the
unchanged full-width commitment route. Both curves, 1/4 workers and every tested
transcript profile including PIPA-R are covered. Compiled x86 under Rosetta passes
the eight selected tests (seven new plus one existing) and both independent
native golden families. This is instruction-path correctness, not physical-x86
or phone performance. The first test compilation and lint failures are retained.
`target/qualification/bounded-lookup-secret-msm-draft-1/correctness-result.json`
has SHA `2285e06d5729f9d940fe334f6f90fad24926782e0f5de83adee6c7dd78ecc9ea`.
Root's algebra review is retained separately; a second independent review did
not complete. The fresh source-bound M3 capture under
`target/qualification/m3-bounded-lookup-20261010-1` completes with all 2,033
selected inputs unchanged and the same four workload descriptors. Candidate SHA
is `775e45418f7a0c7beee472913275112626954c04e2c10d0b65d8634449403cad`;
retained binary SHA is
`439ebdbc8f13eb7e759244fe292e90089593ea567ba35e119dcef0aa697057ba`.
A separate uncalibrated real-Q diagnostic verifies both proofs, with slower CPU
26.764711 s, observed elapsed 26.815414292 s and kernel peak RSS 607,911,936 B.
It is excluded from qualification. This narrow margin does not establish an
improvement or a gate pass. The full eight-configuration schedule used seed
20261010 and stopped with natural exit 1 after 4,411.69 s when the measured
source closure changed. Its retained-record audit verifies all 108 fresh-process
records and 216 proofs: 35 valid attempts and one invalid changed-source attempt.
All valid runs meet hard limits and every completed block meets the margins,
but none of the eight configurations has all three required blocks. The changed
selected files are `crates/iroha_primitives/Cargo.toml` and `src/bigint.rs` in that
crate; the binary and supervisor pins remained unchanged. The original source
refusal and invalid attempt are preserved, without treating a verified proof as
a valid measurement. `terminal-outcome-review.json` has SHA
`a595a7210a01f684c73ce98af4ee9bf4ce1da08f3a0ebed26fb438d062ec5743`
in the same campaign directory. This root audit has no second independent
review. A fresh capture in `m3-bounded-lookup-20261010-2` preserves all 2,033
selected inputs and the same four actual workload descriptors. Its candidate
SHA is `13c6cbf956992bd9abab66111d15af8b99a90d459a1cf344910e93b28ebc5170`;
the retained executable is byte-identical to the preceding candidate. The new
schedule stopped with natural exit1 after 9,119.75 seconds. Seven configurations
pass; real-Q one-worker remains incomplete at eight valid processes. The final
attempt was invalidated because root added the canonical enrollment fixture
generator as a Cargo example, changing the pinned whole-workspace metadata.
No selected Rust input or retained executable changed; the metadata refusal
remains invalid without a waiver. Its second completed real-Q one-worker block
also has a 27.242100-second CPU median, above the required 27-second margin.
The root retained-record audit verifies 450 proofs across 225 fresh processes:
71 valid and four invalid attempts. All valid runs meet hard limits. Its
`terminal-outcome-review.json` SHA is
`9bbaefc9a5e2f4f753f0fd912160ac43a2d12b0eb2ee36f939eace8014a88f81`.
No prior attempts are imported into the next candidate.

The reviewed eight-gate Horner grouping and the carry/shared-table coverage
additions are now applied (`quotient-carry-application-1`, result SHA
`bd5c8c4d2708affd444ed3a164268ef37992e542b5eeb60ab75b5c402b49caa5`).
The grouping changes evaluation order while preserving field polynomials,
filtered gate positions and intended proof bytes. The added independent serial
quotient oracle covers both curves, group boundaries, lookup/permutation tails,
filters, cache policies and worker counts. Focused validation passes 425 native
unit/integration/doc cases, 387 compiled-x86 library cases, all five Q-leaf
controls and the final-usable-row regression. Both native proof-byte golden
families pass. Broad strict Clippy stops on two unrelated primitives warnings;
the new Q-leaf test file also has an unused import. The failed lint and unchanged
source pins remain retained in `quotient-carry-focused-validation-1/result.json`,
SHA `ddcd7411db62fdeb68f27d8c3210c488f164a5fdd34c778136228cb56febbbf2`.
After successful SDK custody verification, the unused import is removed and
all five Q-leaf tests pass again. Selected Pasta/Plonk/Gadgets release lib/tests
strict Clippy with `--no-deps` passes after replacing a bounded unchecked cast
in the new gate-fold test with a checked conversion. The initial selected lint
failure is retained in `quotient-carry-selected-validation-2`; the successful
exit is in `quotient-carry-selected-validation-3`. Neither fix changes production
code. No performance improvement is inferred from correctness tests. The fresh
prepared M3 candidate retains the same four workload descriptors. Its first
real-Q one-worker diagnostic verifies both 7,936-byte proofs. The slower proof
uses 27.084290 seconds of process CPU and 27.188487125 seconds of elapsed time;
kernel peak RSS is 666,812,416 bytes. Probe and source checks pass. This meets the
30-second and 768-MiB hard limits but exceeds the 27-second time margin. It is a
borderline single-process diagnostic, not a qualification or improvement claim.
Evidence is `m3-quotient-real-q-diagnostic-1/result.json`, SHA
`7dd79121d0d2514f4010f5ed2a46a983361ebef3c84a169c3e3005a9c84a24e8`.
The full campaign `m3-quotient-gate-fold-1` completes all three blocks for all
eight configurations, retaining72 valid processes and one calibration-invalid
Q-exact/four-worker attempt. All valid runs meet hard time and peak-RSS limits;
all memory margins pass. Seven configurations pass. Real-Q/one-worker remains
**borderline** because its first block exceeds the required27 s margin; later
blocks do not erase that miss. The unchanged independent summarizer exits1,
matching the retained verdict (`m3-quotient-gate-fold-independent-terminal-review-1/review.json`,
SHA `5f6814cfc45fa98b39ceef871f8bd95b031305a4c3730d23eb9081034dcff852`).

| Workload | Workers / time metric | Three block medians (seconds) | Verdict |
| --- | --- | --- | --- |
| Real Q | 1 / process CPU | 27.490747,26.771704,26.309914 | Borderline |
| Real Q | 4 / observed elapsed | 8.239941,8.158571,8.130607 | Pass |
| Synthetic Q | 1 / process CPU | 22.270702,20.702939,20.675619 | Pass |
| Synthetic Q | 4 / observed elapsed | 6.136633,6.087077,6.009022 | Pass |
| Real A | 1 / process CPU | 31.042974,30.599958,30.116041 | Pass |
| Real A | 4 / observed elapsed | 8.730354,8.602614,8.605501 | Pass |
| Synthetic A | 1 / process CPU | 27.751751,27.172252,26.526616 | Pass |
| Synthetic A | 4 / observed elapsed | 7.956877,7.760658,7.633341 | Pass |

The retained219 measurement/calibration processes verify438 proof samples,
including144 measured samples. Source/binary seals and all original invalid
records remain intact. This is a historical component result:30 selected paths
have since changed, including dependency sources and the new quotient edits.
No result transfers to the current checkout. A separate excluded profile of the
same retained binary identifies FFT and expression evaluation as major quotient
costs. Reviewed lookup-mask factoring and fixed-width tile evaluation are now
applied, with both-field serial-oracle coverage extended to challenge0 and1.
Selected engine/gadget strict lint and refreshed correctness/proof-byte checks
pass:425 native and387 compiled-x86 cases, with9 and7 explicit ignores. All380
selected source pins remain unchanged through those runs
(`quotient-tile-focused-validation-1/result.json`, SHA
`371dc273b8246df258385ab5ff4c23553f23a94939dc433c3fbf0b4a45a168ac`).
The retained native binary emits four straight-line field operations for the
fixed-width arithmetic; this is code-generation evidence, not a measured speedup.
Subsequent formatter changes only line wrapping and one optional trailing comma;
all24 owned Rust files pass formatting checks. A workspace check also finds an
unrelated `kaigi.rs` formatting difference, which is retained without editing it.
The new candidate retains the same four workload descriptors and hard limits.
Its separate real-Q one-worker diagnostic verifies both 7,936-byte proofs, with
26.599858/26.588303 s process CPU and kernel peak RSS 661,340,160 B. All probe
and source checks pass (`m3-quotient-tile-real-q-diagnostic-1/result.json`, SHA
`39045afbae3a6b0cb5154fe5361980badd6d71850b98665c5a3aaada83512ddc`).
This single process is diagnostic. The fresh eight-configuration, three-block
campaign finishes naturally with exit1 and a **borderline** verdict under the
unchanged method in `m3-quotient-tile-lookup-1`, with binary SHA
`7d6f33271e3b8ced1e5e112441331052916aa9be61b7ea0daa570d61311827ed`.
Independent review joins all raw logs and the ledger, recomputes the exact
schedule/seeds and confirms72 valid processes across24 three-process blocks,
144 verified measured proofs and three retained invalid attempts. Including
calibration and invalid-attempt processes,225 processes exit0 and450 proof
samples verify. All150 per-attempt source/binary checks and the final component
recheck match; this is component custody, not whole-workspace qualification.
The review is `m3-quotient-tile-lookup-terminal-review-1/review.json`, SHA
`fa96688941310d76d79c80cce058e3d1f6628752d8afbf1b6ffe7423dee98c3d`.

Seven configurations pass. All valid processes meet their hard time and memory
limits, but real-Q one-worker block CPU medians are26.584335/27.124422/26.236431 s:
the second exceeds the unchanged27 s margin below the30 s hard cap. Its peak
RSS is708,624,384 B. The three invalid attempts retain their original calibration
drift or compression/pageout reasons; none becomes a valid sample. No prior or
diagnostic attempts count toward this schedule, and the better final block does
not erase the miss. Complete M3, full-wallet and phone qualification remain open.

A separate current-binary stack diagnostic then completes with both7,936-byte
proofs verified, one worker, unchanged source/helper/binary and unchanged cached
parameters. Its result is `m3-quotient-tile-q1-profile-1/result.json`, SHA
`81bf91f27cb62c7e594f82d10a7689e230ccd11d4c41771c714bb3e73e6e44d5`.
Sampling covers the whole process; there are no exact live phase timestamps.
All sampled timings remain outside gate qualification.

A bounded reconstruction-loop comparison rejects the proposed serial block
reordering: all 192 algebra controls, 48 pre-cancellation pairs and three timing
equality checks pass, but paired CPU medians regress by 3.073%, 2.583% and 2.641%
at synthetic widths 1, 4 and 16. The benchmark's kernel peak RSS is 81,412,096 B;
all source/artifact pins remain unchanged. No production change follows from
this experiment. Its 36 timing rows describe isolated synthetic kernels, not
the real Q opening plan or a gate result. The raw execution is retained in
`m3-multiopen-serial-block-micro-preparation-1/execution-1`; root review is
`m3-multiopen-serial-block-micro-result-review-1/review.json`, SHA
`a5820cadcffc79271cf3cdc01217c7082bf9a4559c86d3f06d8c4b66c77f5da7`.

The earlier installed quotient scratch change reuses three dead gate-stage coset
buffers for streamed lookup transforms. Eight focused ARM correctness cases
and strict Plonk lib/tests lint pass. Both native golden families also pass in
the captured x86_64 executable under Rosetta, covering both curves and worker
counts 1/2/4/7. The first ARM capture's test-fixture compile error is retained;
the corrected fixture uses the required `Value::known` assignment. The exact
source captures and results are under `quotient-scratch-{arm,x86}-validation-*`.

A predeclared four-process diagnostic then verifies two proofs per process for
old/new real Q and new/old synthetic A. Both workload pairs use exactly
6,291,456 fewer quotient-workspace bytes. Real-Q slower CPU changes from
27.171014 to 26.922422 seconds; synthetic-A from 27.465919 to 27.407090 seconds.
Kernel peak RSS changes from 612,450,304 to 597,098,496 bytes for Q and from
715,325,440 to 671,481,856 bytes for synthetic A. All probe records are valid
for this diagnostic. These single-process comparisons cannot establish block
margins, attribute all RSS differences to the allocation change, or replace
candidate3's failures. No proof-byte equality is inferred from equal lengths.
The records and independent review are retained in
`target/qualification/quotient-scratch-fixed-seed-diagnostic-1`.

The retirement/oracle/codec script selection passes 50 tests and 72 subtests.
The shipping oracle source check accepts rustfmt line wrapping while rejecting
conditional, commented-out and macro-contained assertions; actual oracle-enabled
compilation remains the semantic shipping gate. Initial false refusals and all
repair attempts are retained under `target/qualification/resume-20261008`.

The actual-workload advice scheduling diagnostic completes four correctness
processes and 24 timed processes with equal ordered commitments across both
schedules and worker counts. All three block pairs have valid environmental
observations. Serial submission regresses four-worker elapsed time by a median
factor of 3.07 for Q and 1.12 for A, so production keeps the existing schedule.
The exact binary, source review and every observation are retained in
`target/qualification/advice-current-capture-20261008`. These are commitment
diagnostics, not full-proof or M3 gate results.

The fresh recovered finality snapshot independently rehashes all 5,004 retained
originals, including 4,990 descriptor/verifying-key files totalling 406,815,883
bytes. Its explicit recovered-DATA record preserves the stopped producer and
missing original compiler binary. It supplies no proving-key qualification,
completed graph or wallet admission. The snapshot and independent review are in
`target/qualification/canonical-finality-recovered-metadata-1` and
`canonical-finality-recovered-metadata-review-1`.

The optimized per-use artifact capture completes successfully. Independent
review binds its three retained test executables to 78 emitted compiler
depfiles, 3,651 ordinary source inputs, 67 local packages and 9,383 unchanged
package files. All three generated inputs are reproduced exactly from the
captured IVM and bridge generators; the bridge selects no installed runtime
authority. The 20 changing files are outside the compiled packages and declared
generator inputs. The original broad source-drift classification is preserved,
with the narrower review retained separately under
`target/qualification/finality-per-use-compiler-capture-1`.
Its focused catalog/server/import selection passes 41 cases, including genuine
both-curve cache proofs, exact regeneration after eviction, a real k16 original
key import comparison, and recovered descriptor/key intake without reading or
generating proving keys. Thirteen artifact-dependent cases remain ignored in
those ordinary selections. The new complete52 run uses the independently
reviewed binary and recovered originals, with its attempts retained at
`target/qualification/canonical-complete52-per-use-1`. It has not produced a
completed authenticated wallet catalog or a monetary acceptance result.

**Artifact build-order correction.** `OwnPolicy` and `BootstrapPolicy` now fix
only the independently selected provider and root key. They bind scheme identity
from the constrained state/statement/lineage and signed objects, as required by
the [acyclic build order](kagemusha_lambda_omega_v1.md#24-verifying-keys-without-a-cycle-pipa-s14).
The former scheme constants created a key→relation→scheme→key cycle. Captures
below that used those constants remain scoped to their recorded source; fresh
affected A/W/Ω keys, a complete authenticated catalog and proof qualification
are required. No older-key compatibility path is installed.
The corrected Bootstrap regression passes 1/1 in 289.24 s: two genuine
sigma/Q/A1/W/A2 chains with distinct carried SchemeIDs have identical six
source VK byte strings, descriptors and known/unknown layouts. A third chain
uses genuinely signed foreign-scheme certificate originals and rejects at A2
after actual sigma/Q/A1/W proofs. The administrative sigma suite passes 8/8
in 19.01 s; own-scope constraints and fixed-layout mutations pass 2/2 in 12.13 s.
Exact binaries, source snapshots and logs are retained under
`target/qualification/bootstrap-carried-scheme`; the only build-source drift
was an `OwnPolicy` comment change. These component checks do not qualify the
corrected Omega catalog, installed wallet or performance gates.

| Milestone | Current evidence | Remaining boundary |
|---|---|---|
| G1 revision-4 σ and controls | Native proof crate release suite: 90 passed, 41 intentionally ignored; statement gadget 5 unit and 8 integration cases passed. Shared Rust vectors, all 8 Send masks and both Receive selectors are pinned. Fixed64 usage, recorded blacklist, share expiry and time-span checks have negative tests. Real k14 proofs for masks 2 and 7 verify at 3,456 B; other descriptor lengths are 3,296 B at k12. | The same suite and real k12/k14 cases pass after PIPA-R migration. Authenticated artifacts, cross-language rebuilt consumers and exhaustive ignored sweeps remain open. Native wallet preparation, verification and folding consume σ through the installed source owners. Acceptance under the complete authenticated 52-route catalog remains open; the component results do not establish that release boundary. |
| Envelope arithmetic | Canonical fixed Payment overhead is 1,723 B. The recorded 3,456 B maximum Send sigma leaves 4,821 B for Ω. The guarded compact k16 construction is implemented in the native compiler and prover; captured genuine component proofs verify at 3,712 B plus two 544 B claims, giving 4,800 B transport. Structural Norito encoding with those sample lengths is 9,979 B. The 11,392 B and 10,944 B generic descriptors are superseded size failures. | Current complete authenticated 52-route catalog, frozen descriptor/key identities and actual proof-carrying Payment/Status encodings remain unqualified against the 10,000 B cap. Recheck every enabled Send mask and both Receive variants with genuine current proofs. Historical compact proofs, earlier full52 engineering construction and stand-in size tests do not establish this release gate; the sample Payment has only 21 B of headroom. |
| M3b carry/range binding | [Carry memo](kagemusha_ff_carry_v1.md#current-fused-leaf-review-2026-10-09) retains the independent fused arithmetic/range/shared-table reviews and eight explicit clarifications; the original four-item wording checklist remains unrecovered. The unchanged production construction now has 22 FF and five Q-leaf ordinary passes in the completed post-retirement Gadgets library component, with the exact source/executable interval recorded in memo item 8. Both-field malformed-table checks and all 12 supported final-row combinations pass. | The original post-retirement runner remains unsuccessful after 362 selected passes and its strict MSM style-lint failure. Later focused checks and `m3-lookup-fft-engine-validation-4` pass strict four-package all-target lint; engine4 also passes 317 ordinary PLONK cases with six declared ignores. Both every-cell `+1` sweeps (Fq-in-Fp and P-256 p-in-Fq) and the actual 9,000-product proof subsequently pass in the thirteen-case `m3-streaming-msm-heavy-gadgets-3` component run. These tests remain opt-in via `#[ignore]`, but are no longer unexecuted. The FF/Q-leaf files match that captured run; its transitive engine source interval predates the current lookup-FFT/merged changes. Fp-in-Fq and P-256 n still have no dedicated exhaustive FF sweep, and the full field/table cross-product was not swept. Scoped engineering review and component passes do not establish all-moduli exhaustive coverage, current whole-engine qualification or an external cryptographic audit. |
| M3 consuming witness / MSM budget | The prover consumes witnesses, releases lookup/quotient evaluations after their last use, and shares nonblocking process-wide MSM reservations across both Pasta kernels and complete-MSM callers. The 64 MiB MSM ceiling is unchanged. Its caller-owned quotient workspace reuses field columns and wipes every retained row on success, error and unwind. The current prepared-coset implementation fills one shared powers column per coset only when at least one owned FFT is needed; that column is charged to the same explicit workspace ceiling. Cached fixed-only keys retain zero field scratch. MSM reduction uses exact complete-curve gap weighting for sparse windows and linear summation at density at least one occupied position per 32. Affine and overflow occupancy both count; every lower position keeps its original weight. Independent review accepted the algebra, existing variable-time scope and unchanged scratch reservation. Full-width secret planning, constant-time secret inversion and buffer clearing are preserved. The integrated cancellation engine with shared public parameter tables passes **92 Pasta units**, **250 Plonk units** (one explicit ignored case and three timing/working-set cases excluded), and **45 independent native/vendored non-measurement oracle tests**, including proof-byte parity and mutation cases. The latter includes 37 ordinary cases and all eight intentionally ignored non-timing golden cases; its sole timing case remains excluded. The same 45 cases also pass in a captured x86_64 Mach-O executable under Rosetta (37 ordinary and eight non-timing ignored cases). Actual Cargo dep-info binds 2,762 consumed inputs, with no source/tool drift through execution; binary SHA `770b6200da9ca901877fde7bbd60880b79ead7e57a376eb6c0dbbc74ab742789` and the earlier missing-spec-input refusal are retained in `target/qualification/oracle-x86-rosetta`. This is emulated x86 instruction-path parity, not physical x86 timing or device qualification. Both instruction targets additionally pass all **73 companion oracle tests**: library 18, curve/parameter/FFT/MSM parity 37, KATs 13 and constraint systems 5, including every ignored large correctness case and k15/k16 parameter vector. Actual compiler and runtime inputs and tools remain unchanged; the x86 companion receipt separately records the non-consumed README update during execution. Records are retained at `target/qualification/oracle-m1a-current/{arm,x86}/summary.json`. A further independently reviewed succinct corpus passes four live-original oracle tests and two native-only replay tests on both ARM and compiled x86 under Rosetta, covering eight Sigma/Wide cases, all challenges, exact G/xi, final decisions and 40 mutations. Both captures have zero consumed source/tool/runtime drift (`target/qualification/snark-succinct-parity/{arm-tape,x86-tape}`); strict lint passes. The frozen native replay remains usable after oracle deletion. The original invalid-equation panic and trailing-prefix acceptance remain explicit observations, while native mutations reject normally. This does not claim parity of the distinct PIPA-AS fold transcript or the current full KAGEMUSHA catalog. The new path-filtered CI job requires all five actual compiled harnesses, active oracle-mode cases, complete nonempty pass counts and zero ignored correctness tests; the named timing measurement and maintenance-only reference-fixture printer are excluded, and hosted CI execution remains unobserved. Private IPA generator tables now use immutable shared ownership, so cloning parameters retains their public points without duplicating either table. Independent decoding still validates every point and allocates separate tables; no global cache, mutable table access or interning of untrusted inputs is introduced. Independent review and both-curve tests cover clone lifetime, exact serialized bytes, and malformed points at every encoded position. Initial Vec-to-Arc conversion may allocate; this change alone establishes no peak-RSS or timing improvement. All-target Pasta/Plonk strict Clippy passes. Explicit operation tokens now reach synthesis, original-key loading, commitment kernels, quotient construction, IPA, complete verification and native recursive decisions. Rayon work joins before cancellation returns; secret polynomials, blind arrays, canonical lookup-key buffers and leased quotient columns are guarded across early returns. Cancellation remains a typed hard result and cannot authorize a burn or correction. Actual cancellation/retry tests cover both curves, 1/4-worker proving, scratch release, witness assignment that flattens inner errors, fresh transcript/randomness and exact retry bytes. Both-curve tests cover empty/neighboring windows, sparse overflow-only cancellation, identity running sums, both sides of the exact density cutoff, positional weighting, negative centered carries and the randomized GLV/unsigned verifier-MSM comparison. Large polynomial evaluation uses fixed Horner subtrees, multiopen reconstructs disjoint coefficient blocks in unchanged slot order, and grand-product inversions use constant-time worker-sized batches with total scratch no larger than the original column. New tests compare both fields on 1/4 workers across empty, threshold and odd-sized inputs, zeros and negative challenges. Focused all-target Pasta/Plonk strict Clippy also passes for this engine. Actual fixed-only proofs cover eager zero-buffer and OnDemand two-column storage, exact one-byte-short refusal, both curves, and 1/4/1 worker reuse. Independent k13 comparisons exercise the parallel branches inside complete proofs on both curves and 1/4 workers: all 4,064 bytes match the vendored prover and both complete verifiers accept them. Existing owned/borrowed, row-wise quotient and transcript/RNG parity cases also pass. The subsequent four-row evaluator candidate preserves node/constraint order and reserves at most16MiB extra scratch through the same64MiB process budget, with immediate scalar fallback. Its normal binary passes261 ordinary tests plus the explicit large GLV case; strict Plonk lib/tests Clippy passes. Its independently captured oracle binary passes42 ordinary and eight explicit large correctness cases, including complete proof-byte equality, verification and mutations. Consumed build sources/tools and runtime sources/binary are unchanged. The retained wrapper initially rejected its stale expected counts and included one maintenance printer; `target/qualification/quotient-tiles-oracle-capture-1/oracle-runtime/count-scope-review.json` records the actual compiled inventory and excludes that extra maintenance case from the50 correctness passes. The interrupted eight-configuration M3 campaign is no longer running and its directory is unavailable; no completed qualification is established. The corrected harness prospectively binds the specified memory-activity policy, requires a fresh candidate/schedule and preserves recorded invalidity and hard failures. Its114 script tests pass after the local source-closure and Cargo-configuration repairs. Microkernel speedups and correctness passes do not qualify the M3 gate. Current original-checkout shared-table commands, results, retained binary hashes and source observations are in `target/qualification/params-arc-sharing/correctness-observed.json` (1,623 selected engine/oracle source and Cargo inputs unchanged); the earlier cancellation integration evidence remains in `target/qualification/prover-cancellation-integration/correctness-observed.json`; earlier immutable pre-cancellation captures remain separately retained under `m3-msm-gap-production`. Earlier captured independent-caller and complete-MSM contention tests establish the existing shared budget mechanism; these component correctness results do not establish a timing or phone pass. | All eight synthetic/real Q/A worker configurations require nine valid fresh processes in three blocks. The sparse-window candidate is **superseded/incomplete/inconclusive**, with binary SHA `57bb694fa697493201bd6bda82acfc7c2556f695a4651cabcc1ca3d16f251aaa` and source SHA `b1db82c35b1e392795b20724ef0ce0d3057363b6684e18152a90ffd64624c831`. Completed first-block real Q4/A1 medians are **9.664976959 s elapsed / 33.664216 s CPU**, above the required 9/32.4 s margins despite meeting hard limits. Historical real A4 records three valid processes from ten attempts: diagnostic elapsed median **10.167093875 s**, maximum **11.784894917 s**, and peak **834,682,880 B**. G3.7 specifies no A4 elapsed-time limit; its four-worker time is diagnostic and its RSS cap still applies. Synthetic A4 has three valid processes with median **8.761906417 s**. Real Q1 has one valid **29.300507 s CPU** process, above the 27 s margin but below 30 s; subsequent memory-pressure/compression/pageout brackets are invalid and remain retained. That campaign recorded its ledger, candidate, two proofs per process, calibrations and terminal summary under `target/qualification/m3-component-20261007-msm-gaps-current-lock`. The directory is unavailable in the current checkout, so those historical figures cannot supply newly verified evidence; no partial configuration is a qualification pass. Its predecessor gap capture was invalidated by recorded lockfile drift. Earlier completed candidates retain hard failures: parallel polynomials Q1 **30.013863 s CPU** against 30 s; prepared cosets Q4 **12.266209583 s** against 10 s; empty-prefix Q4 **10.107276125 s** against 10 s. Their raw valid/invalid samples, exact binaries and terminal verdicts remain under the corresponding `m3-component-20261007-*` directories. The batched-FFT capture is separately **interrupted/inconclusive**, with no surviving runner and an incomplete final calibration bracket. Hard limits, the 10% time margin and 5% memory margin remain unchanged. The runner stopped naturally at Q1 attempt15 when its post-attempt provenance check observed the genuine cancellation integration; that attempt also retained invalid host-pressure readings. `superseded-capture.json` records the refusal without turning it into a valid hard failure or a pass. The newly integrated cancellation engine has the scoped correctness evidence in this row; all eight performance configurations still require qualification under the unchanged accepted method. Source-bound VK-to-PK reconstruction without commitment MSMs and its staged wallet consumers are implemented, with the focused proof-byte and admission checks recorded above. Current complete-catalog per-stage execution and proving-buffer release still require qualification. Physical-phone results remain separate. |
| Independent full-proof reference | The standard-library Python verifier derives complete PLONK, multiopen and IPA equations from the specification and independently decides the generator. All **46 genuine proofs** pass across both Pasta curves, three transcript profiles and ten pinned parameter sets at k6–k10. The final adversarial suite passes **169/169** in 114.22 s with unchanged verifier/test/fixture hashes, including exact parser and instance shapes, parameter/descriptor identities, typed-instance boundaries, metadata aliases and six constructive false claims that preserve the soft IPA equation but fail generator decision. Independent read-only mathematical/parser review accepted the final scoped implementation. A fresh original-checkout Rust oracle recomputes the complete frozen fixture exactly: **1/1** in 9.99 s, executable `ecc02d13…894b9a`, 2,743 actual compiler inputs and zero source/tool/runtime drift (`target/qualification/python-reference/current2/runtime-observed.json`). Strict oracle fixture lint and all ten CI admission/shipping-source tests pass. The frozen fixture SHA is `6a3e07aeec1c7bdaef42ca3cd72771fee90cbe38e681ac48cd3b38e7e4384e55`. CI requires the genuine fixture comparison, isolated standard-library replay and adversarial suite. | Individual proofs and canonical generator claims only: no batch-weight, encoded-accumulator, k16, recursive PIPA-AS, full-catalog or physical-phone qualification. No production fallback decoder is added. The temporary oracle and retired vendor trees are deleted; hosted CI execution and current retained-consumer/release qualification remain separate. |
| Retained native consumers | SoraFS PoP uses native PIPA-R with consuming witnesses, full opening verification and new pinned circuit/key identities. All 38 proof and 25 Node PoP consumer tests pass; canonical fixtures, signed inventory and strict lint pass. Native Kaigi passes 23 library tests, seven Core_zk Kaigi tests, two descriptor/key-carrier tests and 48 verifier/admission/guardrail tests. Both libraries now generate unchanged RP56 parameters with native Grain and compare all 201 field elements against dev-only independent oracles. Their normal dependency graphs contain no `poseidon-primitives`; the immutable 23/38-case capture has no source/binary drift (`target/qualification/retained-rp56-native-20261007`). Focused all-target strict Clippy passes; the dependency-inclusive run retains 570 existing gadget diagnostics. The rebuilt JavaScript host passes all 22 Kaigi tests. All three rebuilt Core Kaigi lifecycle/admission integration tests pass. The rebuilt Core real-proof release builder and native policy/gas/guardrail components pass; current Torii native-policy, exact-identity, allowlist and KAGEMUSHA route/finality tests pass. The key carrier binds the complete compiled descriptor and processed Vesta key; old keys and labels reject. The native development vote fixture passes reproducibility and adversarial checks; the native confidential host hash passes 35 regression tests. The confidential production implementation now uses consuming native PIPA-R with three new exact circuit/key identities and one native public column. Its activated Rust confidential suite passes 50 tests, including all three production-depth real proofs at 3,680 B each; the independent relation corpus passes ten host/adversarial cases. The first-release engine retirement is now installed: only Native PIPA-R=0 and STARK=1 remain, with seven exact registry profiles; the generic Halo2 parser, dispatch, key reader, runtime configuration selectors and obsolete fixtures are deleted. Current Core_zk/IVM test targets compile. Focused current SDK checks pass: Kotlin registry/model/Java consumers 53, C# registry 96, Python confidential/client/registry 262, isolated Swift registry 10 and JavaScript OpenVerify codec 4. The retained RAM-LFE circuit corpus is ported to the native engine. All ten native Poseidon tests pass, including genuine proofs at ordinary and maximum inputs plus round/S-box/copy/padding attacks. The complete first run passed 26 cases and found a stale degree11/20 key expectation; the corrected byte suite proves degrees5/8/9 and rejects the larger degrees under the unchanged cap. The old test adapter and its vendored dev-dependencies are deleted; the complete rebuilt 27-case corpus passes. Two unused production receipt helpers are also removed; their consumers use the retained signed-HKDF receipt validators. The rebuilt Core selections pass all 38 tests (15 RAM-LFE, four identifier proof-refusal and 19 ordinary identifier cases), with zero failed or ignored and all three edited source hashes unchanged (`ram-lfe-retirement-focused-validation-1` and `ram-lfe-retirement-identifier-validation-1`). This is focused component evidence, without a whole-dependency provenance claim. The original 218-case both-field Poseidon oracle corpus is captured and passes native replay plus independent Python rederivation and six mutation controls. All eleven shared-backend inventory checks and the three retirement source guards pass. The actual rebuilt JavaScript confidential addon passes six original nonskipping tests; the installed sealed Python wheels pass all five original nonskipping native wallet tests (150.88 s), including full-65,536-tree proofs, change redemption, adversarial rejection and GIL progress. Python installed admission passes before and after execution. The source-admitted ABI-26 CloseLoads host passes the combined C# suite **536/536**, zero failed/skipped/not-run (592.36 s): 482 registry/query/event/receipt cases, seven managed owner cases, six native confidential cases and 41 Kaigi cases. Real native cases cover both full-tree evidence formats, retained change redemption, owner disposal and invalid inputs. The matching original-source Swift package passes 133/133 cases (19 confidential, 114 wallet/load/platform/vectors), with unchanged SDK sources and producer pins; actual JNI and managed wallet suites pass 4/4 and 86/86. Runtime observation confirms the exact `3b51ff55…` dylib; selected source and binary pins have zero drift. Original logs, wheel and host receipts, source manifests and earlier natural failures remain under `target/qualification/native-sdk/{python-current-source,csharp-native-migration}`. These are captured local native component results; subsequent source edits, installed release-package admission and physical devices remain outside their scope. | Packaged SDK and network qualification and final consumer execution remain open. Shared retired vendor dependencies and the temporary oracle are now deleted after the migrated consumers' replacement reference checks; current post-retirement validation remains open. The rebuilt full Core_zk library baseline finished with 489 passing tests and two stale negative expectations; both expectations are repaired and all seven focused verifier tests pass. JavaScript registry tests reject the stale native artifact source fingerprint. Kotlin client baseline tests passed 33/93; native address validation requires a rebuilt source-admitted ABI-26 artifact; earlier ABI-25 captures are historical. The registry fixture has now been regenerated by Rust: its canonical 182-byte native instruction matches Kotlin byte for byte. Its status field is the canonical u32 enum payload; the inconsistent one-byte Rust slice decoder and SDK encoder are removed. These are not qualification passes. The reviewed dependency-budget baseline includes the promoted native confidential dependencies and passes; the release source seal predates substantial concurrent work and still fails, so release packaging is not qualified. An attempted broad C# run (the MTP runner ignored its filter) failed 1,518 of 3,595 tests; inspected failures include the unavailable rebuilt native address validator. The correctly filtered source-level tests above do not establish native SDK qualification. |
| Measurement controls | Fallible direct CPU/kernel RSS probes; verified 1/4-worker pools; two separately verified owned-witness proofs; source/binary and actual descriptor binding. All 75 Python runner tests pass with Python 3.12 and the pinned script dependencies. The candidate binds the prospective memory-activity policy; changed policy requires a fresh schedule and preserves previously recorded invalid attempts. The ledger retains and rechecks raw output, process exits, environmental probes, both calibrations, candidate boundaries and declared execution order, including the 18-attempt ceiling. Descriptor inventory must retain the completed build's executable hash. Component preparation derives local dependency roots and cross-crate inputs from actual Cargo artifacts and depfiles, binds Cargo/toolchain/build inputs, and rejects in-scope source drift while separately recording whole-checkout changes. Missing probes, launch failures, altered calibration and scoped source drift invalidate retained attempts. RSS headroom uses each block median while every valid process must meet the hard cap. CLI run/summary returns failure for failed, borderline or inconclusive qualification. The current driver retains a caller-owned quotient workspace with a 256 MiB field-buffer ceiling across both proofs; reports must show empty initial storage and exact reuse on the second proof. Its allocation is included in kernel RSS, with no adjustment to the hard RSS or MSM limits. | All eight synthetic/chip-filled Q/A worker configurations still require the complete nine-process, three-block qualification. The DAG-release component retained three invalid Q four-worker attempts, then a valid calibrated hard failure: slower proof 35.1231 s observed elapsed against 10 s, kernel peak 722,059,264 B, both 7,936 B proofs verified (`target/qualification/m3-component-20261007-dag-release`). The canonical-key candidate has unchanged workload descriptors and a stable 1,998-file compiled dependency scope. Under the same predeclared seed 20261007 it retains four invalid calibration brackets, followed by a valid Q four-worker hard failure: slower observed elapsed 21.1679 s against 10 s, kernel peak 728,170,496 B, both 7,936 B proofs verified. Its binary SHA is `362e2ca429ead3253d7945b3d11c8203528b7ea4c95c275487dbc7f6988f09fb`; source/build/raw-attempt/summary evidence is retained in `target/qualification/m3-component-20261007-canonical-lookup`. The configured early stop preserves this failed partial schedule; it cannot produce a pass for any incomplete configuration. The workspace candidate has the same four workload descriptors and stable 1,999-file dependency scope. Its Q four-worker configuration exhausted the declared 18-attempt ceiling with no valid calibration bracket and is inconclusive. The next scheduled A real-chip one-worker process had valid calibration but failed its CPU hard cap: 36.203590 s against 36 s, kernel peak 830,881,792 B within the 0.85 GiB cap, both 7,584 B proofs verified. The partial schedule stopped as declared; binary SHA `f7f6947efb876fa7709037c15f97ee8ab90d69abda0ca8e3a8ade8d353d37c70` and all evidence remain in `target/qualification/m3-component-20261007-workspace`. The per-column workspace candidate retains the same four descriptors and stable 1,999-file scope. Its five invalid Q four-worker brackets were followed by a valid hard failure: slower observed elapsed 19.701137292 s against 10 s and kernel peak 814,596,096 B against 805,306,368 B, with both 7,936 B proofs verified. The declared early stop preserves this failed partial schedule; binary SHA `8926d09d25c6460c7cf42700e8850827949be4bd3b367716889319b2a853189d` and raw/source/summary evidence are in `target/qualification/m3-component-20261007-columns`. The streamed lookup candidate has unchanged descriptor digests and layout records, with binary SHA `a5d2e1577d7212bc441f9152523343a7864497f44b52540c1b8d20ca554f24ac`. Its five invalid brackets and three valid processes are retained in `target/qualification/m3-component-20261007-streamed-lookups`. Valid slower times are 9.721029833/9.651365542/14.434622416 s; the last fails 10 s and ends the partial schedule. Valid kernel peaks are 785,907,712/667,402,240/725,827,584 B, all within 805,306,368 B. The first block RSS median 725,827,584 B meets its headroom target; its time median 9.721029833 s misses the 9 s target. Every valid-process proof verifies at 7,936 B. Neither the nine-process Q configuration nor the other seven configurations is qualified. Invalid attempts remain recorded; elapsed-time failures are never normalized. Component results do not qualify a frozen whole-release candidate or a phone. |
| PIPA-R / recursion | Native PIPA-R typed transcripts/proofs and PIPA-AS folds pass both-curve tests. The complete succinct circuit interpreter matches real source proofs. Total soft accumulator decoding, malformed-claim → burn → Trivial replacement → hard fold, and exceptional identity-correction rejection pass on both curves. Obligation tests cover the branch truth table and all 14 unsplit schedules, with four fixed Vesta fold slots including explicit trivial fillers. The [soundness argument](kagemusha_recursion_soundness_v1.md) records assumptions and outstanding review. | The Q → A → Ω composition and operation relations are implemented, with captured genuine component proofs. Complete current catalog, key-continuity and recursive-mutation qualification remain open. Component proofs do not establish unbounded-PCD soundness or a joint simulator. |
| Q signature relation | Five integration tests pass for exact ten-word slot binding, fixed/variable keys, malformed raw256 inputs, low-S and verdict rules, and witness-independent layout. The 5V/1F shape reaches 64,238 rows / 747,364 cells. A real one-slot native proof is 8,576 B and its opening decides. Raw256 bridge cell tampering and shared-table audits pass. | Signed-object semantics, issuer-role authorization and complete operation composition remain required. Q proofs are local, not the transported Ω. |
| Q sigma relation | Real Receive-k12 and incoming Send-k14 proofs are verified in Q with a hard three-slot local accumulation. The shared byte/ECC layout has 29 advice, 42 fixed, 22 equality columns and 12 lookups; largest row span 50,799 at k16. Its actual native Q proof is 10,496 B and verifies, with altered public chunks rejected. Native preparation binds exact proof lengths, class keys, selected claims and exported frames. | One four-worker synthesis/prove/self-verify diagnostic took 12.8297 s; this is neither an isolated proof timing nor qualification. Q is local, not the transported Omega proof. |
| Historical recursive-finality producer inventory | One captured canonical signed identity commits all16 sigma plus Omega verifier originals and the complete producer catalog. Its profile binds the compiled14-variant schedules, all52 logical selector routes, six finality source-class schedules, all16 fixed sigma recipes and the162-byte compiled compact Omega recipe. The captured14,513-byte profile matches an independently framed preimage; its finality dependency is retired and must not be reused as current authority. Bounded content-addressed readers check exact lengths/hashes before source import; verifier-only reads never request PKs. Public sigma qualification passes actual16-source original imports and foreign-selector/changed-PK cases (23.32 s, `target/qualification/native-sigma-source-qualification`); Q qualification passes actual signed Bootstrap Q0/Q1 plus root, hard/soft, manifest and truncated-original mutations (60.50 s, `native-q-source-qualification`). Shared source factories pass seven captured cases (`native-q-source-factories/results.json`). The current immutable Core capture passes17 artifact namespace cases with6explicit expensive ignores (3.44 s), actual signed Bootstrap Q/A1/W0/A2 public-route qualification (267.84 s), and actual Retiring2Q/4A/3W public-route qualification (309.06 s), including signed context mutations, old-manifest refusal before storage and incomplete final-Omega rejection (`target/qualification/native-route-omega-qualification`, zero recorded source drift). Retiring deliberately uses an unqualified candidate Omega. The implemented all-route qualifier reconstructs complete native context and imports each original in sequence; final Omega qualification requires every logical route, exact common predecessor identity and full terminal D+VK deduplication in signed program order before canonical source import. The offline compiler shares raw source recipes without qualified markers or placeholder signatures. The prior-anchor engineering run completes all52 operation walks and retains1,033 originals, then fails final Omega with `Source(OmegaLayout)` after10,972.91s; no complete grant is produced. Diagnosis finds a catalog-wide linear sum passed to a three-term primitive. The local catalog selector now chains bounded sums while preserving the one-to-three-key layout. Four focused recursion cases and strict lint pass. The separate canonical-anchor finality-source job stopped without a terminal receipt; its surviving partial artifacts require exact source reconciliation before reuse. Earlier failed profile expectation and all previous captures remain retained at their linked qualification paths. | Signatures or individual source owners grant no complete wallet capability. The complete source-qualified route/catalog closure, actual transport/latency/memory gates and NativeProofs orchestration remain open. The independently selected global genesis and exact receipt wrapper must bind the Load dependency. No wallet-open capability is granted by these component checks. |
| A / Ω recursive frames | All 14 A variants share the tested 69-field frame. Same-tape statement/message mutations and isolated source k12/k14/k16 Ω frames pass. The captured witnessed-key Tagged3 Bootstrap/Load/Send-mask0 component catalog was rebuilt under its actual common Ω digest with exact source-descriptor and key equality; all three genuine outer proofs verify and their complete claims decide in that captured source. Source A proofs are 7,744 B. The complete Send chain binds current Credential, direct Enrollment certificate and Receipt, full 320-byte predecessor public transcript plus proof/P/V/σ digest, pending/fee/unchanged maps and every opening. Stage/task omission, receipt substitution and internal-key misuse reject. | The complete source-qualified release terminal catalog over every required selector route, enabled Send masks, remaining operation composition and final authenticated rooted artifacts remain open; its distinct key count is not assumed from the 14 semantic variants. The historical witnessed-key three-terminal result below is 4,800 B per transport under the unchanged 4,821 B cap. The canonical native source pins its installed catalog into the circuit. The captured native-pinned Receive-catalog test passes1/1 in7,069.43 s: rebuilt Bootstrap, Load and Receive share one immutable three-terminal key, each3,712 B raw/4,800 B transport. It checks exact planned/actual terminal VK, all four real fold inputs and their decisions, dropped-fourth rejection, retained-credit membership, strict original import and canonical checkpoint replay (`target/qualification/kagemusha-receive/pinned-omega-accept/run.log`). This remains a captured pre-O(1) component result with superseded voucher-Load ancestry; the current source rekey, ordinary-finality fixture and full release catalog remain open. Descriptor equality does not establish source equality or transfer the old size result. Installed native Bootstrap/Load/Send component differential results are scoped to their captured Tagged3 sources. Current Bootstrap replaces eager PK retention with shared verifier metadata, strict per-role original imports and one borrowed PK per proof; Bootstrap/Refresh consumer compilation passes, and captured Bootstrap exact-proof/checkpoint replay passes1/1 in1,359.45 s (`native-bootstrap-borrowed*`), including all three exact proof byte strings, foreign borrowed keys, source/table/VK/profile mutations and canonical restoration. Metadata construction is not catalog authority and does not establish a memory gate. The historical five-A/four-W Load retained nine descriptor/VK identities and strictly imported one borrowed PK per stage. Its six unit cases and actual five-A/four-W source import regression pass (117.29 s), including changed genesis, foreign-stage originals and the fifth-terminal checkpoint boundary; captured A rows are 53,354/61,436/60,868/55,352/56,016 (`target/qualification/native-load-borrowed`). This is witnessless source/import evidence, not a finalized funding proof. Send now uses the same metadata-only/per-stage borrowed-key ownership without changing its fixed schedules or controls; the current proof library and consuming integration targets compile; current genuine proof replay requires the rebuilt native-finality Load fixture. Descriptor `4c9ed1f762bbad39623dd865a5c72876d5482d1ddf20bf15f6facf3259d9233b` is a source candidate, not a frozen catalog or qualified timing result. Frame fixtures alone do not authorize operations. |
| Fixed-stage continuation context | All staged producers now commit the complete immutable operation context once as C, then bind C, the fixed internal ordinal and current full-k16 Pallas claim under kgwlink1. The immediately preceding exact W key and unchanged P/V folds preserve all prior obligations; historical hash replay, its helper and private trace copies are removed. Independent local review found no context or obligation gap. The current proof library and every integration target compile. A strict native/circuit mutation test passes (86.93s): all nine internal Archive ordinals match the independent formula, have identical assignment extents, preserve known/unknown layout and reject changed context, point, every challenge limb, variant, stage, short source and terminal/overflow ordinals. The captured executable and source subset are retained in `target/qualification/archive-constant-context`. The subsequent native namespace passes77 tests and its independent stage-link framing check passes. Explicit incoming message projections use two exact128-bit halves; the72.24s strict encoding regression and independent review preserve all original bits, including malformed encodings (`archive-two-half-context`). | Every staged source key changes. Earlier actual-proof results below remain tied to their captured pre-change executables. Fresh actual proofs, strict original imports, final catalog closure and performance qualification remain required. |
| Native ordinary finality | The recursive BLS/history circuits, finality artifact compiler, proof service and unused compact Register path are deleted. Load uses native exact-quorum BLS verification, authenticated epoch transitions and counted event inclusion before its signed Advance. The four-A/three-W monetary relation binds the receipt and credential-bound signature under the selected released-app/uncompromised-OS profile. Historical recursive-finality captures below are retired-component evidence and impose no proving-service or disk prerequisite. | Complete [NF1–NF5](kagemusha_native_finality_goals.md): current native mutation tests, pre-signing refusal/recovery, rebuilt monetary artifacts and real Load/exchange/Unload. Physical-phone latency, memory and complete-wallet release qualification remain open. |
| Compact Ω layout | The captured guarded secondary-range candidate produces and natively verifies an actual **3,712 B PIPA-R proof / 4,800 B transport** at k16, degree 9, exactly one lookup, 11 advice columns, 25 advice queries, 12 fixed queries and six equality columns. The authentic full-C4 Q2/tagged-A3 Bootstrap source is used. Witnessed-key and pinned-one-key cases pass complete predicates, known/unknown fixed/permutation/assignment equality and native opening decisions. The rooted single-terminal construction then rebuilds every signed object, sigma, Q and A/W proof under the actual compact Ω digest; exact source and outer VK bytes remain unchanged and both accumulators decide. The standalone rooted test passed 1/1 (`target/qualification/rooted-compact-bootstrap.log`, 384.49 s busy-host component run). The captured witnessed-key catalog run reproduces this rooted construction with 65,458 primary range rows, then completes **common two-terminal Bootstrap/Load and three-terminal Bootstrap/Load/Send-mask0 catalogs**: each signed source chain is rebuilt under its shared key before proving; exact terminal VK bytes and the common outer VK remain unchanged; all three 3,712-byte outer proofs verify and every modified public-column case rejects. The common schedules use 64,991 and 64,996 primary range rows respectively. The complete three-terminal run passes 1/1 in 2,754.43 s on this busy host; this is a component run, not a timing qualification. `target/qualification/compact-three-terminal-catalog-merged2.log` records `COMPACT_TWO_TERMINAL_CLOSURE` and `COMPACT_THREE_TERMINAL_CLOSURE`; its source and binary provenance are retained in `target/qualification/compact-three-terminal-catalog-merged2-source.json`. The replay suite passes 5/5, including both native curves, exact source/cached-clone bindings, every meaningful cell mutation, missing/extra events and boundary/collision controls. The corrected 81/93-bit top gates reject coordinated overflow; the continuing duplex offset regression passes both fields. Source-coupled details and hashes are in the carry/compact record §28. The current compiled factory derives guarded k16 placement from unknown source metadata and pins its exact 162-byte policy preimage in the native profile. The merged native binary passes83 cases with three source-import sweeps explicitly ignored (`target/qualification/native-producer-merge-reconcile/captured-native`). The freshly rebuilt genuine rooted Bootstrap regression passes in289.54 s, reproducing exact descriptor/VK identity and strict original-PK import, then verifying3,712 B raw/4,800 B transport, both claims and public mutations. All recorded proof-source and copied-binary hashes remain unchanged (`target/qualification/merge-reconcile-root/fixture-capture`); executable SHA is `4947f8d9643fa8841d9a38631ec579bf3a4d4527e7775028dc7dbff1fd48f447`. Seven default Load/recovery/claim cases pass, with one expensive case ignored; the initial all-ignored Bootstrap invocation is retained separately and is not proof evidence. The seven reconciled fixture files retain all114 top-level builders/types/tests and20 direct test registrations, while shared fixture modules register none. All proof test targets compile and pass scoped strict lint. This is captured single-terminal evidence, not complete-catalog qualification. | **Historical component size/capacity and three-terminal key-continuity evidence only.** The current compact helper uses the canonical native pinned-catalog source, original-PK importer and canonical checkpoint replay. The captured native-source test completes the Bootstrap/Load/Receive three-terminal catalog and passes1/1 in7,069.43 s, each3,712 B raw/4,800 B transport, with actual common-key rebuilding, exact original import, canonical checkpoint replay, exact terminal VK, all four actual fold inputs and claim decisions, dropped-fourth rejection and retained-credit membership (`target/qualification/kagemusha-receive/pinned-omega-accept/run.log`). This captured pre-O(1) result does not qualify the subsequently changed staged sources or the complete release catalog. The earlier witnessed-key multi-terminal source is no longer the producer; matching descriptors alone cannot carry qualification across that change. These Load-derived chains use the superseded dedicated-publisher voucher trust model. Current Load verifies native BLS evidence before Advance and binds the receipt in the four-A/three-W monetary source; the older compact-finality ancestry is retired. The integration helpers require genuine finality and original proving artifacts; the retired issuer fixture is removed. Installing the current fixture and rebuilding this catalog remain prerequisites for current-release qualification. The other seven Send masks and full allowed terminal catalog, every operation shape, adversarial recursive composition and loaded-host qualification remain open. No transport admission or release artifact is frozen. Superseded profiles remain failed diagnostics: generic common Bootstrap/Load Ω transports 11,360 B; the prior 4,768 B compact descriptor failed range capacity at k16. Captured wire encoding tests pass 2/2. The regenerated-vector KAGEMUSHA data-model namespace passes 224 tests (two explicit maintenance captures ignored), including fixed frame-padding contracts, codecs, ordinary Load event inclusion, the native-captured receipt fixture and exact CreditedReceive overhead679/proof budget9,321 (`target/qualification/credited-receive-bounds/captured-kagemusha-namespace.log` and `captured-namespace-provenance.json`). The actual Rust generator emits fixture SHA `a584169008fb9ef1a41af50d4e523857acb2ff8f8999947386f74c8ee266fdf6`; its metadata delta also passes37 Kotlin tests and34 unchanged Swift wire/vector tests in an isolated pure component target. The earlier ABI25/21 mismatch and interrupted ordinary-Load rename build remain invalid historical attempts. The subsequent source-bound ABI25 host capture passes 123 Kotlin and 88 Swift cases, and the expanded data-model namespace passes 228 cases with two explicit maintenance ignores, each within its recorded component scope. Neither result requalifies these older recursive catalogs or establishes full SDK/phone acceptance. Fixed Payment overhead remains 1,723 B, and explicitly structural 3,456 B sigma / 4,800 B Omega bytes encode to 9,979 B. The current 4,821 B Omega allowance leaves 21 B for the captured 4,800 B component (`target/qualification/payment-current-encoding-size.log`). After the catalog selector repair, metadata synthesis for32 genuine retained same-descriptor terminal keys fits65,060 of65,530 usable k16 rows, and compiled secondary-range replay passes. Counts1/8/16/24/32 preserve the exact outer descriptor under the actual compiler configuration while their source fingerprints differ. Receipts, exact library/executable pins and root-manifest drift are retained in `target/qualification/omega-catalog-layout-diagnostic`. This is source-fit evidence, not authoritative terminal membership, a regenerated Omega key or a final proof. Actual complete-catalog proof acceptance and the complete10,000B release gate remain open. |
| Signed-object constraints | The captured 14-case object suite and three additional delivery-evidence cases pass for all 11 exact signed-body schemas against Rust vectors, same-tape message/object digests and Request credit ID; malformed fields/version/key framing; total credential evidence/policy and exact renewal continuity; Send/Receive receipt substitutions; policy/voucher body bounds; Request overflow/pair checks; exact basis-point rounding, clamps and overflow before clamping; exact Load voucher/wallet binding; Send payer ownership and head-held fees (including zero-fee defaults); original 163-byte Payment transcript and transitive package binding, with every byte and nested component substitution rejected; total credit-opening parsing and root/credit/Payment binding reject sentinel, alias, next-key, sibling and burn-flag substitutions. Total incoming statements match hard semantics across all 14 variants and every field, and malformed statements remain false even when the receipt digest is recomputed to match. Dynamic CreditStatus heads and receipts use one fixed layout across all operation tags. Both Credited transcript forms match Rust vectors; CreditStatus and Receive evidence bind the original Request, receiver wallet/key, pinned relation, credit/amount and retained Payment, with renewal preserved and coherent foreign-relation/root/Payment substitutions rejected. These tests hash the original malformed transcripts and reject forged true verdicts. Four current delivery-object tests additionally hard-bind canonical Status component addresses and Credited Payment/evidence preimages before soft semantics; substituted preimages reject under both proposed verdicts, while noncanonical original references remain false. Proof/signature decisions remain separate required obligations. The corrected Archive receiver binding uses Request credential field8 rather than certificate-set field17; canonical fixtures preserve distinct digests. Six focused status/delivery checks pass (61.79 s), including original-preimage rejection under both proposed verdicts. | Component tests. The Receive Objects producer additionally passes exact raw-tape, selector, owner/context/Q-export and joint-size tests at and one byte above the limit, including active-length aliases and known/unknown shape parity. Incoming σ digest/index/proof chunks are hard equalities; only the original statement and actual proof verdict remain soft. Other Receive producers and terminal closure remain in progress; a standalone parsed object is not authenticated. |
| Receive source provenance / authorization | The original Payment transcript now hard-binds Request, carried payer credential and package content addresses; Request hard-binds its quoted credential and certificate. Ordinary versus renewed is determined by that exact quoted/current digest equality. Six Receive component tests and three Payment differential/substitution tests pass: fixed-Payment auxiliary substitutions fail for either proposed verdict, while rebound invalid object versions remain total. The actual renewed incoming 3V1F signature-Q proof verifies at 7,936 B and 51,177 maximum rows; the real Receive/incoming-Send two-slot Q is 7,008 B with both 3,296-byte σ proofs and passes Accept/Trivial cases. A genuine k16 soft signature-Q proof, hard recursive extraction and exact receipt binding pass for both honest and r=0 signatures, with Accept/Trivial mode and message/key/signature/verdict/proof substitution controls. Earlier constant-size-context Bootstrap-only malformed-sigma Receive passes its complete10A/9W chain, all19 strict original imports, borrowed-key exact proof parity and canonical exact-byte checkpoint replays in a fresh session in2,045.12 s (`target/qualification/kagemusha-receive/o1-current/receive-run.log`): actual incoming Q soft-false, exact re-signed originals, allTrivial, unchanged consumed root and zero adjusted spendable value, with no Load dependency. All ten source layouts fit k16 with maximum65,305 rows under65,529; original/Q/context/current-P/W, foreign-session and malformed-custody substitutions reject. A separate pre-policy-correction Bootstrap-only malformed-sigma burn closes actual Ω in1,949.62 s (`target/qualification/kagemusha-receive/bootstrap-burn-omega-o1/run.log`): fresh immutable Bootstrap/Receive catalog rebuild, exact planned terminal VK, all19 original imports and native exact-byte replays,3,712 B proof/4,800 B transport, allfour canonical obligations deciding, droppedfourth rejection and retained burned-credit membership, with no Load ancestry. The corrected carried-scheme Bootstrap-only malformed-sigma Receive→Ω now passes1/1 in1,614.99 s (`target/qualification/kagemusha-receive/bootstrap-burn-omega-carried-scheme`, binary `eeff209e…44c32`): all10A/9W, all19 strict original imports, borrowed-key proof-byte parity, exact canonical checkpoints in a fresh session, maximum65,305 source rows, actual Trivial burn with zero adjusted spendable value and no Load ancestry. Its fresh immutable two-terminal native catalog preserves the exact terminal VK; Ω is3,712 B/4,800 B transport, allfour obligations decide and dropping the fourth rejects. The only build drift is unrelated finality metadata, retained with both source snapshots. Captured accepted Receive also closes actual Ω under an immutable common Bootstrap/Load/Receive key:3,712 B proof/4,800 B transport, exact planned terminal VK, allfour selected inputs decided, droppedfourth rejection and retained credit membership;1/1 passes in7,069.43 s (`target/qualification/kagemusha-receive/pinned-omega-accept/run.log`). The later native-predicate capture passes its genuine malformed-sigma Receive chain in1,395.16 s: all10A/9W, all19 strict original imports and checkpoints, native four-predicate proposals, A1 fixed/permutation/advice parity, and W/signature-owner mutation checks. Proof sources and copied executable remain unchanged (`target/qualification/native-worker-predicate-terminal/receive-predicates.log`, binary `993ec675…0866d`). This is captured burn-branch component evidence; it does not install the full52-source wallet grant. | The corrected Bootstrap-only malformed-sigma chain qualifies its captured carried-scope keys. Accepted/renewed/corrected-value captures still predate the policy correction and require fresh A/W/catalog qualification. The accepted outer capture uses the prior history-hash continuation source and superseded Load ancestry. Current accepted/renewed/corrected proof and outer closure, ordinary-finality Load, the full catalog and durable wallet integration remain open. Component timings are not performance gates. |
| Administrative leaves | Fixed k12 Unload, Retiring and Archive leaves produce genuine3,296B proofs with opening decisions; consuming leaf/schema/mutation checks preserve unrelated state, exact balance/nullifier/ordinal/charge bounds and irreversible retirement. Archive own authorization, original evidence addresses, signature Q ownership, result bits and opening commitments pass focused component checks. Its retained proof owner rejects coherently re-signed oversized Payments and covers raw retained Omega/sigma capacities8,597/8,277 under the shared joint bound; incoming Receive/Status carriers cover9,321/8,132 bytes. Missing/duplicate tasks and misplaced Q owners reject. The fixed native producer has10A/9W owners, exact source-key imports, borrowed PK use and canonical checkpoints. Core and adjusted pending owners each fit16,983 rows and pass mutation/layout tests; both adjusted removal and terminal closure enforce Corrected no-op. Earlier seven/nine/eleven/ten-stage source failures are retained in their qualification directories and do not qualify current sources. The fixed-stage-context constructor-predecessor capture passes both actual-Q19-key original import sweeps (Status559.49s, Receive616.15s), including truncation/wrong-stage rejection, plus77 native tests (`archive-constant-context-imports`). Genuine current Bootstrap Omega metadata then exposed Status retained-proof stage1 at66,341>65,529 rows; an extra range bus did not help and was removed. Exact two128-bit message halves preserve all256 bits and existing raw-tape/claim/owner bindings; strict all-byte/half/malformed/layout mutation regression passes72.24s, with independent review. Both actual-Q/k12-incoming source sweeps now fit every10A/9W source using that proved predecessor descriptor/VK: Status maximum64,195 rows (71.16s), Receive63,048 (66.62s), under unchanged65,529 (`archive-two-half-context`, binary0f49a8e6…ba85). Fresh exact-key imports pass all19A/W original keys for each variant (Status403.25s, Receive294.50s), with wrong-stage/truncation rejection; the complete Omega catalog is a separate gate. A further actual-k14 incoming sigma/Q source sweep fits all ten stages (maximum63,344 rows,55.16s; `archive-k14-source`). Its strict original-import sweep passes all19A/W keys, including truncation/wrong-stage rejection (447.25s; `archive-k14-import`, binaryd7819bd4…3c2f); the immutable executable and predecessor originals stayed unchanged, with unrelated finality/Receive source drift recorded. Complete Archive proofs and catalog admission remain pending. Current Bootstrap-to-Retiring passes1/1 in1,315.82s using the new fixed-stage context: all4A/3W genuine proofs, seven strict original imports, metadata-only/borrowed-key exact proof-byte parity, fresh canonical checkpoint replay and all opening decisions; no Load ancestry. Its A maxima34,484/38,591/61,340/56,575 and7,744B proofs are captured in `kagemusha-receive/o1-current/retiring-*` (binary66652c55…d5a0). Earlier consuming and Archive component captures remain scoped to their superseded sources. | Final Retiring Omega, complete full-domain Archive accept/no-op chains, native proof-byte parity and final shared catalog/provider admission remain unqualified. Funded Unload and Archive composition use the native-BLS first-Load fixture; their captured component results do not qualify the current complete installed catalog. Source layouts and busy-host suite durations do not establish memory/latency or phone gates. |
| Refresh shared leaf / recursive owners | One fixed k12 tag7 sigma key proves all five update kinds with genuine 3,296 B proofs and a 2,538-row maximum. All five proofs verify under that key, and genuine Q-sigma composition passes all five kinds under one shared Q key (7,008 B local proofs), with every opening decided. Leaf/schema tests cover exact kind selection, unchanged fields, counters/floor, intersections, expiry, five original signed tapes, hard3V/2F slots, direct certificates and mandatory map owners. Actual compact Bootstrap-rooted Credential, SchemePolicy and TimeAnchor Q/A/W compositions pass together (1,935.63 s); Blacklist's four A/three W closure also passes inside the retained map-capacity attempt. Every A proof is7,744 B; maximum source rows are61,725/61,671/61,659/61,665 respectively. Original sigma/Q0/Q1/Q2 proofs, native opening decisions, retained context history and adversarial omission/changed-original tests are exercised. Source/binary manifests and logs are retained under `target/qualification/refresh-recursive*` and `refresh-map-recursive*`; these capture the compiled candidate rather than later source edits. Quota's complete stage failed the fixed k16 gate at91,131 rows, before oversized proof generation. The replacement keeps all 64 slots and all 578 semantics, using mandatory old/window/usage root tasks plus exact matching and a shared typed subhash/issue/count context. Isolated typed owners pass (maximum 28,638 rows), but the first eight-stage composition failed at PreviousRoot with 68,931 rows after four valid 7,744 B A proofs; its source/binary/log remain in `target/qualification/quota-split-recursive*`. The revised root-only path retains object proposals while mandatory original and merge owners recompute every signed tape and issue/count. Two proposal binding/schema/layout tests pass (69.26 s); independent code review found no binding gap, conditional on complete source-bound closure (`target/qualification/quota-root-proposals*`). The following eight-stage preflight stopped before Refresh proofs: PreviousRoot fit at 65,490 rows, but later WindowRoot/UsageRoot reached 67,303/70,411 (`target/qualification/quota-root-proposal-preflight*`). The current seven-stage schedule moves roots before longer continuation histories without dropping any owner. All seven unknown-witness layouts and actual proofs pass, with maxima53,206/60,014/63,122/62,715/61,679/62,974/61,420 under the unchanged65,529 ceiling (`target/qualification/quota-seven-native*`). The representative-W preflights remain sizing diagnostics, not later-stage key-identity evidence. Their replacement sequentially derives every A/W verifier and requires exact binding/VK equality before actual proofs. All seven captured sequential unknown-source preflights reproduce those fitting bounds; the same captured candidate also passes actual proof and borrowed-key replay below. Unknown-source planning alone is not proof evidence. The captured actual chain independently derives each successive key and reproduces the fitting bounds. That captured candidate reaches complete seven-A/six-W closure: every A proof is7,744 B, all five signed originals and hard3V/2F remain bound, and every opening decides. The complete captured test passes1/1 in3,884.48 s, including exact native A/W proof-byte parity, every checkpoint restoration and canonical Norito payload replay. It uses the earlier typed-key mount and does not qualify the subsequent strict original-PK importer or a latency gate. Installed native Credential Refresh passes exact original-key/proof parity for all four A and three W stages, full checkpoint restoration and changed-proof/Q/stage rejection (1,111.59 s, `target/qualification/native-refresh-credential*`); the retained-candidate SchemePolicy/TimeAnchor/Blacklist run also passes all three kinds (3,983.89 s, `target/qualification/native-refresh-policy-anchor-blacklist*`), reproducing every original A/W proof byte and raw checkpoint. Captured preparation and canonical checkpoint codec tests pass10/10, and the earlier native component batch passes61/61 (`target/qualification/native-refresh-original-unit*`). The current metadata-only Bootstrap/Send/Refresh native batch passes70 tests, with one explicit ordinary-Load capacity test ignored, including both-curve foreign-key rejection, bounds, checkpoints and source-profile guards; the exact same binary passes all five Archive constructor cases (`target/qualification/native-metadata-checks/`). The subsequent fresh Archive source-profile assertion also passes1/1, requiring its exact Tagged3 layout to equal the shared terminal descriptor. These unit tests do not qualify current-source genuine proof replay; the captured Quota native run separately passes canonical payload restoration. The captured strict original-PK Credential run passes1/1 in2,985.22 s (`target/qualification/native-refresh-original-credential2*`): all4A/3W exact source imports, changed stage/VK/table/truncation rejection, exact proof-byte replay and canonical checkpoints pass. That source retained all PKs. The current producer replaces eager retention with shared descriptor/VK metadata and one per-stage original import returning a borrowed PK; no original bytes or proving buffers remain in the producer. Exact full descriptor/VK checks precede folds, and source imports reconstruct the installed stage without accepted claims or key generation. Metadata creation is not catalog authority. Independent review found no local binding gap; shared-metadata/Receive units pass15/15. Current borrowed Refresh integration checks pass. Captured Credential Refresh now passes1/1 in3,725.63 s (`native-refresh-borrowed-credential*`): all4A/3W strict original source imports, foreign borrowed-key rejection, exact original proof bytes, and raw/canonical checkpoint replay. Captured Quota now passes1/1 in4,990.54 s (`target/qualification/native-refresh-borrowed-quota*`): all7A/6W actual proofs use exact sequential verifier identities, strict original-PK source imports and borrowed stage keys; every original proof byte matches and all raw/canonical checkpoints restore. Every opening decides. Its captured binary SHA is `2e1cb9d349cabca85aef4782b5c9a85e3788816632d16b2966edab4c0528881a`; source drift during compilation is retained in its manifest, so this qualifies that executable component rather than later concurrent edits. No RSS or phone-memory gate follows from the ownership change. CoreZK now converts exact retained Credential/SchemePolicy/Blacklist/TimeAnchor originals into native Refresh inputs. Renewal keeps predecessor Credential/Enrollment custody for C4 and authenticates the released capsule under its successor Credential. Native policy evaluation derives the exact effect and complete successor; unrelated state changes, forged/replayed updates and changed history paths reject. All22 preparation component tests pass, including5new signed Refresh cases (`target/qualification/corezk-refresh-preparation/results.json`). The new Quota conversion retains a canonical 64-slot predecessor-usage frame under explicit capsule role 10 (exactly one iff QuotaShare), authenticates its root against the actual predecessor, and derives every successor slot from the exact signed share. Independent source review found no local binding gap. The actual Rust generator and three canonical witness/role cases pass; complete Kotlin/Swift vector classes pass 39/36 cases with unchanged generated fixture inputs. Full/empty usage frames are 2,805/181 bytes under the 8,192-byte cap; the quota capsule is 7,591 bytes. The corrected initial Rust fixture-field and Swift frame-count failures are retained. The fresh complete data-model namespace passes 228 cases with two explicit maintenance captures ignored (34.60 s), including the regenerated fixture and Archive retained-role requirements. The expanded CoreZK preparation namespace passes 33 cases, including Quota, complete Load/Archive conversion and unfolded sigma preparation; all 12 capsule tests pass, including power-loss replica repair and exact quota-witness replay. CoreZK source remained unchanged throughout build and execution; the exact pre-acyclic-scheme proof dependency is retained separately. These are captured component results (`target/qualification/quota-refresh-custody/results.json`), with later proof-policy and transitive M3 source changes excluded. These tests do not establish genuine released-receipt or installed-producer acceptance. | Final Ω wrappers under the full shared terminal catalog and the installed wallet producer remain open. No release terminal admission, performance gate or physical-phone compliance follows from these component runs. |
| Pre-Advance administrative preparation | All five Refresh kinds derive exact sigma witnesses from verified released heads, including unfolded heads, retaining signed original frames, map openings and source capsule identity. Six typed administrative proving adapters bind the complete26-field statement and exact installed D/VK before proving and full verification. Load preparation now binds an opaque qualified receipt source to the exact installation, verifies receipt finality and both claims, authenticates the recovery insertion, and derives checked net balance/ordinal/sequence while retaining original receipt/finality bytes. Two independent source reviews found no local binding gap. Native consuming preparation now derives Unload/Retiring from the opaque verified fold, authenticates exact charge originals and both insertion paths, preserves adjusted lineage values and all unrelated fields, and removes the public caller-derived consuming witness API. The captured preparation namespace passes 49 ordinary cases (1.11 s), including seven consuming signature/strict-sigma/adversarial tests; the explicit public Refresh case passes 1/1 (11.13 s) with actual 3,296 B sigma proofs for all five updates and re-signed corrupt predecessor rejection. `target/qualification/prepare-consuming/current/results.json` retains executable `a41f8067517254c065cb97c1f911284e6fd0890c29a71d355b87d1e189af73bc`, unchanged preparation sources and separate lifecycle status failures. Earlier Load captures remain scoped to their records. | Genuine public Load preparation still requires the complete ordinary receipt proof and qualified installation; the full public consuming path requires the actual verified fold and installed producer. Arithmetic fixtures do not confer either capability. The Refresh test uses two actual sigma keys in a signed engineering inventory and a synthetic retained marker; it does not qualify recursive admission, complete producer authority or actual Advance custody. Native must recheck source identity under its commit lock. No wallet-open, performance or phone qualification follows. |
| Indexed maps / state openings | Eight IMT tests pass, covering both fields, full-depth G1 vectors, authenticated empty insertion, removed-slot clearing, full integer key order, immutable first records and every-cell small-circuit tampering. The 25-case state/statement and operation-map suite passes (including Bootstrap, Load, Unload, Retiring and all five refresh state effects) for core33/rest8/statement26, all operation tags, recomputed-hash forgeries, exact control masks, identity/head continuity, OQ-3 and Archive no-op. Production-depth map components fit k16 (Send 31,746, Receive 35,446 Archive 31,524 and Unload recovery 17,094 maximum assigned rows). The obsolete indexed quota upsert/update/dummy-witness API is removed; native tree tests pass with duplicate/zero rejection and final-slot exhaustion. Three focused indexed tests additionally pass after native removal was added: both fields authenticate the predecessor relink and cleared leaf, absent/sentinel removal leaves state unchanged, and cleared slots are never reused, including after u32::MAX allocation. Shared digest parity passes 17 tests (one long case ignored). Blacklist refresh insertion and Request-recorded history lookup pass, including hard route authentication with a soft pair verdict. The fixed64 quota rebuild passes at 51,652 sponge / 36,008 range / 17,670 glue rows, including full64 matching, first-share, expired/unused drops, exact signed window count in 1..=64, and recomputed-root reset/end/drop attacks; the same component passes on the recursive duplex. Independent source review found no local merge/state-effect gap. Shared hash framing passes both-field tests and all eight IMT tests after generic lane composition. | The constraints are bound into the operation relations; qualification of those bindings under the complete current authenticated catalog remains open. They do not authorize a payment by themselves. |
| Node enrollment journal | The private prepared-worker protocol binds the journal incarnation, exact preparation and durable acknowledgement before E1. Complete/Recover claim once; Inspect reads only an exact retained result, including after expiry. Fresh eligibility is required before live recovery, signing and E6 delivery. The captured private Python package passes **212/212** with unchanged source/runtime pins (`target/qualification/enrollment-inspect/full-suite-5-installer`); the separate initializer and installed wheel entry point also pass, preserving occupied/partial-store refusal. The earlier Rust protocol suite passes17 cases with two maintenance generators ignored. Generic Bank/SchemeOperator policy and 24 actual Rust vectors pass11 Model, eight middleware, eight Kotlin and one Java component cases. The captured Rust HTTP/middleware/pool suite passes **29/29** (`sdk-enrollment-http-current`); its independent45-depfile/five-build-output audit retains the original broad prose-drift refusal. The copied Core executable passes13 issuer and38 journal cases. The corrected supervised Torii copy passes **28/28**: five signer, nine actual local HTTPS, two account-authentication, five supervised lifetime and seven worker/process cases (`target/qualification/enrollment-service-torii-supervised-2`). Its exact executable and owned runtime inputs remain unchanged; independent audit of86 actual local compiler artifacts and nine build outputs establishes that its two recorded broad-drift paths were not consumed. Earlier fixture/build failures remain retained. | Every universal-dataspace token is eligible without Parliament, a named-token allowlist or legal-class gate. The new asset-independent templates, exact asset-bearing middleware observation and native finality-backed Global registration path are implemented; fixed-asset CBSI/BPNG profiles remain deployment adapters. Model/SDK strict lint passes. Actual Rust regeneration supplies24 new template/observation vectors; all24 old and24 new vectors match Kotlin/JVM (nine Kotlin and one Java case). The copied Model passes15 eligibility and nine enrollment-policy cases; two maintenance generators are explicitly ignored. Its four registration cases initially fail on compressed public-key fixtures; all four pass after correction in the refreshed Model copy (`universal-asset-model-sdk-2`), with genuine native certificates and explicitly synthetic execution rows. The generated observation is344B within2048B. The same copied Rust SDK passes **32/32**, including11 middleware cases, with zero runtime source drift. Independent48-depfile/five-script audit excludes22 unrelated build-drift paths without changing the original broad classification (`target/qualification/universal-asset-model-sdk`). Actual WSV registration passes for three arbitrary asset identities and scales0/2/28 without Parliament. Both current Core tests now pass, including genuine StateExecutor success/rejection and exact finalized Register extraction; all eight CLI publication cases also pass (`enrollment-universal-corrected/registration-cli-runtime`). The latter preserves exact package reopening, changed-input refusal and foreign-instance rejection at the first non-genesis certificate. Runtime sources and copied binaries remain unchanged; actual external consumed changes during compilation retain the original `component_only_source_inconclusive` classification. Earlier compressed-key and wrong-chain fixture failures remain separately retained. The copied native bridge passes **66/66** installed-selection/custody/layout cases, including four generic release/session tests, with unchanged runtime sources (`universal-asset-bridge-runtime/installed-runtime`). The copied universal-template Torii namespace passes **31/31** with unchanged executable; its broad source/runtime drift from coordinated subsequent repairs is retained (`enrollment-universal-torii-cli-current/issuer-runtime`). The corrected same-build copies additionally pass14 issuer,38 journal,18 worker protocol,11 native registration and8 shared production ledger cases, with two explicit worker-maintenance ignores (`enrollment-universal-corrected`). Exact binaries and Python interpreter/tool pins remain unchanged; broader runtime source drift is retained where observed. The shared ledger tests exercise the actual paired publication/restart transition with an explicitly substituted recursive test workload; they are not real monetary proof evidence. Standalone CoreZk and bridge lib/tests strict lint pass; broader Core/CLI strict lint fails in unrelated existing code and the workspace formatting check retains14 findings before owned formatting repairs. The guarded ABI27 host has341 exports including all84 required symbols; current captured Swift246, Kotlin/JNI60 and C#536 cases pass against its exact dylib SHA `ae5589d06b41027f1ccbd4924255c92164e3e2ee49b5a15a62b7852e58606090`. Swift's unrelated source drift and the initial JNI runner's wrong-ABI artifact refusal remain retained. Full release packaging and actual service deployment remain pending. With regenerated Rust worker originals, the full Python suite passes **214/214** in37.691s with unchanged interpreter and source pins (`enrollment-inspect/full-suite-6-universal-template`). Its two added cases exercise synthetic AppAttest A→B→A under one retained store generation and reject the retired preparation schema. This is component evidence using synthetic platform evidence and test keys. The earlier Linux guest's 206 Python passes and six additional process/clock cases are historical; its guest receipt is no longer retained. The current package is re-executed in a fresh Debian 12 ARM64 guest on the read-only original checkout with private ext4 target storage: **144/144 pytest cases pass**, zero skips, in20.76s (`target/qualification/kagemusha-linux-python-suite-2`). Exact collected names, all three test-phase outcomes, source/fixture hashes, Python/OpenSSL identities and Debian package versions are retained and unchanged before/after. Independent inventory review reconciles the historical214 names to the current144:96 retained,118 retired/changed and48 added. All144 current source definitions were collected; this is not the same historical214-test suite (`kagemusha-linux-python-suite-inventory-review-1`). The prior unittest attempt's missing package path in the installer subprocess is retained; supplying the package path to subprocesses resolves it without a source change. This run covers the Python package and synthetic evidence, not the newly implemented compiled Rust descriptor-worker test, genuine provider admission or power-loss durability. Complete serving deployment, monetary exchange and phone qualification remain open. Exact asset authorization, reserve consent/backing and applicable controls remain required. Bank-required policies keep KYC/freeze checks and never fall back after bank failure. The journal retains complete exchanges and one-time consumption under its existing3MiB record cap. OS/interpreter dependency trust and privileged whole-filesystem rollback remain outside the local journal guarantee. |
| Wallet / integration | Source-stable Core executable `5e1c41f9…50c355` passes **147 state/recovery**, **214 Advance/provider**, **18 enrollment-owner** and **1 elapsed-boundary** cases, zero ignored (`target/qualification/core-complete-source-metadata-2`); all20,878 source/package/vendor/tool inputs and runtime source remained unchanged. Native permits bind retained client/attempt/slot and same-boot generation elapsed; exact E6 issuer selection, durable Abandon replay/loss refusal and tri-state original reads are exercised. Maximal E6 is **260,907 bytes**, below262,144. The later source-stable Core copy `18f21a5f…5e8c8b` passes **233 Advance cases**; its state run passes147 and fails three new CloseLoads fixtures because they omitted authoritative source custody. Those fixtures now retain the exact verified source snapshot; all three pass from later diagnostic executable `c6cc502b…eb3da6`, alongside six native-ledger continuity/publication/payout cases. Shared coordination retains source-selected originals/maps, Request-recorded blacklist gaps, replay indexes and durable folds. Native Credited conversion and the background worker preserve exact outputs, cooperative payment cancellation, parked errors and join-before-release; **38 C boundary cases pass**. The guarded CloseLoads ABI26 host `3b51ff55…5b0ee5` passes **4 actual JNI** and **86 managed Kotlin** cases. Its admitted original Swift package passes **133 cases** (114 wallet/load/platform/vectors and19 confidential), with unchanged SDK sources and producer pins; six additional confidential keyset cases and one current-source retirement guard pass from the same retained executable. Original logs and receipts are under `target/qualification/native-enrollment/{close-loads-swift,kotlin-closeloads-current-results}` and `native-sdk/{host-abi26-close-loads-current,swift-abi26-close-loads-current}`. | Captured local component evidence only; explicit simulated provider boundaries do not establish physical custody or genuine52-route operation. Subsequent source adds retained FeeClaim retrieval and canonical online claim construction, bounded sequential native finality rooted in installed genesis, durable checkpoint selection and authenticated payout acknowledgement. Current merged managed Kotlin **147 cases pass**; current Swift source parses. Current native C/registry/installation/setup executable `b713cf2f…ac429f` passes **85 cases**, zero ignored, with private checkout-local build/runtime scratch (`target/qualification/native-enrollment/fee-ledger-c-current`). Strict CoreZk and bridge lib/tests Clippy passes, including normal-mode compilation of all five shipping oracle-build guards. Retained diagnostic executable `59c9f12b…e92ccd` passes **six fee, six ledger and three CloseLoads cases**; the earlier two stale Request fixture failures remain retained. Actual encoding measures a20,060-byte pair carrier and a16,348-byte online claim containing a10,000-byte Payment plus a6,381-byte canonical multisig beneficiary; the next larger claim is rejected by the16KiB aggregate cap. Build-source drift and unpinned system temporary build scratch prevent a candidate-qualified label for that executable. CloseLoads preserves request-id replay while allowing a later authenticated source to close newly issued loads. The installed loader now allows a512MiB cumulative engineering finality D/V extent, covering the observed406,815,883 bytes while preserving per-original bounds and the64MiB process MSM cap; phone memory is unqualified. These newer components require a coherent source capture and rebuilt SDK runtime; the canonical FeeClaim retains its existing16KiB aggregate cap without a separate4KiB beneficiary exclusion. The later captured ABI26 host `46f10abf…212222` passes five C and six JNI probes plus158 managed Kotlin cases. Its source-admitted Swift package passes211 selected cases with zero skipped in654.971s, including five actual native confidential tests, four PeerWallet request cases and five application-auth cases (`target/qualification/native-enrollment/eligibility-merged-swift-tests-current`). The receipt pins34 XCTest bundle files and records six SDK source changes from the subsequent merge. This is captured pre-merge component evidence; it does not qualify the newly resolved selectors or current complete candidate. The merged installed-runtime/review surface requires another reconciliation after that merge. The native Unload DATA projection now selects the exact retained request/plan/receipt and credential originals, survives historical capsule collection and restart without signing, and requires the admitted account plus exact quoted beneficiary. Diagnostic Core `30256198…f0b3e8` passes all three projection/recovery cases; latest managed Kotlin144 cases pass and Swift parses (`target/qualification/unload-projection`). The rebuilt, source-admitted host `5b73dc39…3eef46` passes five actual C and six actual JNI probes, alongside 144 managed Kotlin cases. The initial JNI Review-fixture failure is retained; the corrected request includes its required destination original and tests the empty-destination refusal. The Swift response parser and public result type enforce the same closed status range. Its source-admitted test invocation retained a compile failure in the incoming Request transport range expression; that syntax is repaired and parses, while full Swift runtime awaits the next matching native package. The ignored native acceptance harness requires a separately pinned actually executed ledger setup: distinct registered A/B/C accounts41/42/43, actual asset incarnation, matching canonical genesis, and ordered H1/H2 finality originals. Its ordinary account-binding test passes from the same copied binary; the independent native host-enrollment/restart case also passed from `5c0fe857…90e51c4`. The exporter then proves A's Bootstrap/Activate and retains its exact IssueLoad target; the consumer reopens the same custody/payment key and requires an independently pinned matching finalized receipt. Its consumer covers actual A → B → C proofs, pending Send recovery, exact replay, duplicate refusal, fold/restart, conservation and verified Unload-claim export. The earlier strict CoreZk lib/tests Clippy passed; the latest combined bridge lint is retained as a failure on five unrelated CBSI selection findings. Both artifact-dependent tests remain unexecuted. The actual executed setup is now exported and independently reviewed: canonical genesis registers distinct A/B/C/reserve accounts and the actual asset, mints 1,000 atomic units only to A, then certifies H2 through the actual StateExecutor. Core setup tests pass three cases (two artifact-dependent cases ignored), and its explicit exporter passes separately. The exact ordered H1/H2 originals, setup pin `407c7593…fa880`, runtime receipt and preserved broad-source inconclusive record are retained in `target/qualification/executed-ledger-setup-build-2`; a supplemental review verifies all76 actual depfiles and nine build outputs, without qualifying the whole checkout. Independent proof-source intake passes all seven semantic mutations, and the interrupted canonical finality-source construction has no terminal receipt. The corresponding complete signed source graph and matching A receipt remain required; the older genesis/asset/receipt fixture cannot substitute for them. No substitute grant or proof is accepted. This harness does not execute node settlement; genuine catalog/provisioning, real-proof exchange/unload, four-validator and physical-phone gates remain open. Enrollment, Abandon and load closure return originals, never ledger acknowledgement. Earlier Swift guard refusals and ABI25/pre-permit captures remain historical diagnostics. |
| Ledger services | The dedicated Load publisher and its configuration are deleted. The captured generator-produced KAGEMUSHA data-model executable passes 224 cases (99.18 s), including ordinary transaction and certified Load-event verification, the exact native capture fixture, and the measured 679-byte Credited::Receive framing plus 9,321-byte proof budget. Both Receive selectors preserve exact frozen lengths; inclusive-envelope and cap+1 checks pass. Two maintenance captures remain explicitly ignored. The actual Rust generator emitted only the two new bounds keys and their explanatory metadata; the fresh-source follow-up encountered the active ordinary-Load type migration and is retained as failed, without transferring captured results to that newer source. Configuration passes all 1,035 cases (732 library and 303 integration), including rejection of the retired publisher role. The actual Rust inventory generator passes and regenerates the canonical JSON with 972 classified domains and 47 construction users, including the ordinary-Load event-path lookup key and its seven counted-Merkle uses. The expanded Core selection passes 109 cases with zero failures and two explicit ignores (231.98 s). It covers both new event-path tests, all five native finality-cursor tests, historical receipt recovery after chain growth and local QC loss, private-root refusal before debit/receipt creation, exact Load/retry/rollback, journal custody, payload refunds, all seven exact native/STARK admission cases and native P2P ingress. Source and executable provenance are retained in `target/qualification/kagemusha-integration-current`; concurrent proof/dependency changes make these captured results, not a frozen current-candidate qualification. Two actual Kagami exports are byte-identical and match both canonical schemas, including the certified Load event and removal of retired publisher types. | Component evidence only. Test-only epoch guards retain original fixture generations while exact payload-refund assertions run. The current captured Sumeragi protocol/simulator executable passes 441 cases with zero failures and two explicit heavy cases ignored, using five fixed seeds per randomized scenario (2,026.18 s; `target/qualification/consensus-after-enrollment/run-1`). Its sampled sources and copied executable remain unchanged; this component run does not establish a complete candidate dependency closure. The earlier actual strict 133-mutation execution completes with its full baseline passed, all 133 mutants killed by named tests, and zero survivors, errors or scenario-only kills, using the complete non-fast 200-seed mode (24,572.36 s). Fifty scenario subsets do not independently kill their mutants; their required named tests do. The gate itself exits zero, but its source-bound wrapper refuses current-candidate qualification because `Cargo.lock` is the sole changed path among 1,524 captured inputs. The complete report and this boundary are retained in `target/qualification/kagemusha-sumeragi-current/captured-gate-result.json`. A separate exact-hash lock recovery and dependency-impact review finds only the incoming `iroha_core_zk` → `iroha_sumeragi` edge: CoreZK is absent from all 254 resolved Sumeragi dependency packages and the declared source closure, every reachable package lock record is equal, and all 1,523 non-lock captured inputs matched at that review. This substantiates unchanged Sumeragi inputs without altering the original whole-file provenance rejection; it does not qualify the whole checkout or monetary network (`lock-impact-review.json`). The fresh full strict 200-seed mutation execution also passes: baseline plus **133 named-test kills**, zero survivors, errors or scenario-only kills, in11,027.18s (`target/qualification/consensus-after-enrollment/mutations-1`, report SHA `6c4ed3bdfa68de87472686a2a1d78caae3620285222f1d7f7a49a2dca4064eb1`). Its50 scenario misses are still killed by the required named tests. Independent review verifies948 retained logs, all201 actual local compiler inputs from282 depfiles,36 build outputs and254 reachable packages. The changed lock edge and dev/test profile are outside this release dependency closure; the runner change only adds unselected Core mutations, with its selected Sumeragi table and algorithms unchanged. The original399-path/HEAD drift refusal remains. The supplement (`mutations-1/independent-review/receipt.json`) accepts component execution only: registry archives were reconstructed after execution, per-mutant binaries were overwritten by the two build lanes, and the SDK/stdlib/OS closure was not fully pinned. These limits prevent a whole-checkout or release qualification claim. Preparation passes 10/10 and the expanded wallet state/recovery suite passes 42/42 (57.36 s), including the required complete ordered checkpoint-chain restart case. Both retain dependency source-drift records and are captured component evidence. The refreshed stock default-feature daemon/client and separate source-stable harness pass all three required real four-validator cases: commit36.22s, individual plus whole-cluster restart106.95s, and stopped-leader replacement36.29s (`target/qualification/sumeragi-network-current-run-1/summary.json`). Every case uses exactly four peers, unchanged copied binaries and no ignored tests; no peers remain after teardown. Independent stock-build review of100 local compiler artifacts and11 build outputs identifies its two broad-drift paths as unconsumed; the original source-scope classification is retained. Source edits resumed after the immutable copies and are recorded during the last two runtime cases. These are exact-binary consensus component results, not current post-capture checkout or KAGEMUSHA monetary-network qualification. The genuine complete signed native-inventory WSV case remains explicitly ignored in the debug selection; the separately executed inventory generator passed. Committed receipts are recovery data: monetary Load requires independently verified normal block finality and exact receipt binding. Complete genuine ordinary-finality Load proof qualification, real-proof wallet exchange/unload on at least four validators, and current release artifacts remain required. |

The earlier repaired-harness **diagnostic**, binary SHA-256
`58b0368064ce8ab590d4e0a6bafce17e73d3aea9115b23ec41826db92903217b`, produced
two valid PIPA-R proofs in each configuration below on the shared Mac. It
includes shared A round selectors, reused quotient coset buffers and exact
DAG normalization. The worktree was not frozen for these runs; there was no
calibration/repetition qualification. Raw records are retained in
`target/qualification/m3-pilot-20261006-normalized-dag/`; earlier raw attempts
remain under the adjacent `m3-pilot-*` directories. RSS is the kernel lifetime
peak, including key generation, and is not phase-subtracted. Time is the slower
of the two proofs. Q is the 5-variable-key/1-fixed-key signature chip workload;
A is the IMT-like load, not a complete operation relation.

| Real workload | Workers | Judged diagnostic time | Peak RSS bytes | Gate observation |
|---|---:|---:|---:|---|
| Q chips | 1 | 29.9847 s CPU | 750,321,664 | Inside hard limits; lacks 10% time margin |
| Q chips | 4 | 10.1756 s elapsed | 674,955,264 | Exceeds 10 s; RSS below 0.75 GiB |
| A IMT load | 1 | 33.0941 s CPU | 764,788,736 | Inside hard limits; lacks 10% time margin |
| A IMT load | 4 | 10.0960 s elapsed (diagnostic) | 728,449,024 | RSS below 0.85 GiB; no A4 time gate is invented |

Q proofs are 7,936 bytes; the shared-selector A workload proofs are 7,584 bytes.
Those are local chip workload proofs, not transported Omega artifacts.

No synthetic-shape or phone result is inferred from these chip diagnostics.
Streaming/allocation changes or narrower/split workloads must meet the existing
limits before M3 is marked qualified.

### Earlier observations (retired layouts; not current qualification)

Records below follow §2. Source: `optimizations` at `df9c70cdb3` plus the
uncommitted working tree of 2026-10-03; host: Apple-silicon Mac, 20 CPUs, 128 GiB,
shared with other build jobs (timings ±25%). No phone, live network or payment was used.

| Check | Record | Result and limits |
|---|---|---|
| G1 canonical objects and transcripts | observed as expected | `iroha_data_model::kagemusha::kagemusha_wallet_v1` ([wire record](kagemusha_wallet_wire_v1.md)): 129 unit tests pass (`scripts/cargo_fast.sh --stable-local-metadata --incremental --target-slot kagemusha-wallet -- test -p iroha_data_model --lib kagemusha_wallet_v1`), including every-byte-flip, decode-order, bound (limit, limit+1) and Norito-tag tests. Not yet consumed by the proof relation, provider, bridge, node or Torii. |
| Low-S signature rule (§8) | observed as expected | Native codec accepts `s = floor(n/2)` and rejects `floor(n/2)+1`, `n - s`, `r = 0`, `s = 0`, `r = n`, `s = n`; signer DER and raw high-S output is normalized and verified before freezing. In-circuit enforcement used the old halo2 P-256 gadget `assert_p256_ecdsa_digest::<F, 256, true>`, deleted with the old recursion code; the PIPA-v1 relation must re-implement it, and no relation consumes the new objects yet. |
| Cross-language vectors | partial current evidence | `fixtures/kagemusha/wallet_v1_vectors.json` matches the maintained Rust generator, SHA `58852dd2d7300b123f1923fc9fa50157bd497a8eccc87451865cb4b6bd67b1ad`. All four Rust vector checks and all41 Kotlin vector cases pass. Twelve additional pure-JVM transport/pre-signing refusal cases bring the focused Kotlin run to53/53, with no failures or skips and unchanged source/fixture hashes (`kotlin-native-finality-focused-1/result.json`, SHA `8cd9fedc25057dfddc2e0c368c8a06f9a2b0f0cc169388c466ea8e6b6d95b31c`). Actual tests reran; Gradle compilation was up to date. An explicitly empty native-library directory prevents treating this as native bridge evidence. The rebuilt ABI27 full suites now pass all41 Kotlin and36 Swift vector cases against the unchanged fixture, plus the17 Kotlin ledger/Load/epoch cases, three Swift C decoder cases and four Kotlin JNI decoder cases. Their complete suite and custody results are recorded above; these are host checks, not monetary-network or physical-device qualification. Prior Kotlin39/Swift36 results under ABI25 and the retained ABI21/refusal attempts remain historical records in `target/qualification/kagemusha-sdk-current`; they do not qualify the new fixture or current bridge. Other language consumers remain unqualified here. |
| Payment, Credited and Offer size bounds | observed as expected (stand-in proofs) | Size tests assert the worst cases with stand-in proofs of the provisional caps (transition 6,016 B, CreditStatus 2,000 B). Stand-in proofs are structural only and are not completed payments. |
| In-circuit P-256 cost | measured | One full-width low-S verification: 1,466,624 advice cells = 23 advice + 4 lookup columns at k=16 in each Pasta field. A k=16 proof of that circuit alone: 10,112 B per parity; prove 12.5–13.0 s (20 threads), 20.7–24.2 s (4), 31.9–32.8 s (1); verify 0.26 s; peak RSS 0.79–0.95 GiB. |
| IPA proof scaling | measured | Test-only harness `crates/iroha_core_zk/src/g3_proof_scaling_measurement_tests.rs` (ignored tests, release; deleted with the old recursion code and recoverable from Git history). k=16 proof bytes = 1,976 + 358·(advice columns); prove ≈ 7.2 s + 0.54 s per column at 20 threads; peak RSS ≈ 257 MiB + 27 MiB per column; proving key ≈ 25.5 MB + 9.1 MB per column. Narrow no-lookup proofs: bytes = 768 + 352·W + 64·k (k=18–20, W=1–3: 2,272–3,104 B), prove 21–80 s, verify 1.0–3.2 s. One thread is only 2.5–3.3× slower than 20. |
| Recursive-verifier building blocks | measured | ≈ 2,170 advice cells per MSM source (`reciprocal_compact_batch_allocation_diagnostic_in_both_parities`, a deleted old-recursion diagnostic: 1,008 sources = 34 advice + 6 lookup columns at k=16); dense rows for 1,008 sources: 131,046 rows in 9.3 s. |
| R9 and 2 s p95 with the current construction | deviation (estimate from the measured models) | A Send transition needs ≥ 6 in-circuit P-256 verifications plus transcripts, maps and recursion (≈ 150–230 columns): ≈ 55–85 KB per parity at k=16, so Payment ≤ 10,000 B needs a narrow large-k outer layer, whose proving alone is ≈ 21–80 s per parity on this host. End-to-end 2 s p95 is not reachable on this path; proposal revision 2026-10-04 moves recursion off the payment path (split lineage). |
| Android Keystore absence semantics | source reading | AOSP `AndroidKeyStoreSpi` (android14-release): `containsAlias` returns false on any Keystore error, `aliases`/`size`/`getCertificate*` swallow errors, only `getKey` distinguishes `KEY_NOT_FOUND`; keystore2 `rebind_alias` replaces an existing alias on generation. Device confirmation: not run. |
| Android lock-screen removal | source reading | keystore2 android12–14 `reset_user(.., keep_non_super_encrypted_keys=true)` deletes certificate-only and super-encrypted entries and keeps plain non-auth keys; Android 15 depends on build flag `fix_unlocked_device_required_keys_v2`. Device confirmation: not run. |
| Android backup/restore | source reading | `BackupAgent` never backs up `getNoBackupFilesDir()`, but a full-data restore of an app without its own agent first clears all app data and its Keystore namespace (`FullRestoreEngine` → `clearApplicationUserDataLIF`, android14). The wallet's backup set must therefore be empty. Device confirmation: not run. |
| iPhone keychain passcode class | source reading | Apple Platform Security: `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` items are never backed up, synced or escrowed and become unusable when the passcode is removed or reset. Restart and power-loss durability after a write: not run. |
