# Native exchange acceptance inputs

`native_exchange.rs` contains **ignored, artifact-dependent** host acceptance tests for the complete software pipeline.
Each result belongs to its independently admitted source/receipt dependencies; retained
historical executions do not qualify a changed candidate. The ordinary host-custody test
covers only persistence of the explicit software hardware fixture.

The export test first authenticates the complete signed producer catalog and independent
native genesis through `open_pinned_engineering_wallet_sources`. Its seven source
pins and path inputs are mandatory. `KAGEMUSHA_NATIVE_SOURCE_SHA256` records the independently
captured test candidate. All new paths must be absolute, inside this checkout's
`target/qualification`; output directories must not exist.

The A-target stage imports the proving DATA once into
`<A-target>/source-admission/originals`. Its hash-pinned `public-target/target.json`
exports a `sealed_originals` locator for that exact absolute directory. Exchange
and either C-confirmation stage read this same pinned target and check its seven
source pins before reopening the directory through strict `DirectoryOriginalsV1`
admission. They independently reload the signed pack/inventory/genesis and repeat
complete source reconstruction, active imports and all cancellation/corruption
controls. Each writes fresh membership/acceptance evidence and
`reopened-originals.norito` into its own fresh `source-admission` directory; no
second `originals` copy or `sealed-transport.norito` is produced there. A missing,
unsafe or corrupt selected source fails with no fallback. Keep the first sealed
DATA directory intact for the entire chain. Wallet A/B/C journals and software
keys remain in their own custody trees; no grant is serialized or reused between
processes. This is a host test orchestration change, not a new source trust rule.

The separately ignored
`requalify_signed_wallet_catalog_from_retained_originals` helper test takes
`KAGEMUSHA_WALLET_RETAINED_ORIGINALS` and a fresh
`KAGEMUSHA_WALLET_ACCEPTANCE_OUTPUT`, plus the same independently pinned catalog
and genesis inputs. The six-stage pipeline needs no new environment variable:
its later stages obtain the locator from the already required pinned A target.

Both tests also require `KAGEMUSHA_NATIVE_LEDGER_SETUP` (the executed setup's
`setup.json`) and `KAGEMUSHA_NATIVE_LEDGER_SETUP_SHA256`. The fixed nine originals
come from `iroha_core::sumeragi::test_chain::kagemusha_setup`: the separately
registered accounts A/B/C (engineering signer seeds 41/42/43), reserve, actual
registered asset incarnation, original signed genesis, genesis manifest,
`registration-proof.norito` (the fixed `[H1, H2]` finality-proof array), and
`capture.json`. Every original's length and hash are checked. The capture must
match the independently pinned finality source fixture; the signed genesis,
network, instance and initial epoch must match the admitted native owner. The
ordered proofs are verified from that owner. The independently pinned executed
setup producer owns the registration and supply assertions; finality alone is
not an asset-row membership proof. There is no fallback to the old component
asset incarnation or old genesis fixture.

1. Run `export_actual_a_load_target_with_retained_native_custody` with
   `KAGEMUSHA_NATIVE_LOAD_TARGET_OUTPUT`. It enrolls A using the explicit simulated hardware,
   admits the actual account signature, proves/releases Bootstrap, signs Activate, and folds.
   The real host custody tree and private software-key fixture remain in `wallet-a`.
2. Give the finality producer only `public-target/target.json` and its seven SHA-256/length
   bound originals. Pin the manifest independently. `issue-load.norito` is the existing
   `KagemushaWalletLedgerV1::IssueLoad`: A's actual scheme/wallet/asset, ordinal 0, request
   `[201;32]`, net amount 100, no online charge. The exact account, credential, certificate
   set, asset, Bootstrap and Activate originals accompany it. The manifest also binds all
   seven source pins, executed-setup manifest pin, native chain/instance/initial epoch and
   candidate binary/source hashes.
   This is **target DATA**, with no receipt, proof or settlement verdict. A missing valid
   Activate or foreign genesis must be refused by the producer.
3. The actual producer must execute/finalize that exact target, then export the canonical
   `KagemushaWalletLoadReceiptV1` (maximum 512 bytes) and
   `KagemushaWalletLoadFinalityV1` (maximum 262,144 bytes, one receipt certificate and event path).
   The historical ordinary firstLoad
   fixture targets a different wallet/asset and is not a substitute.
4. Run `actual_native_a_to_b_to_c_then_unload_with_restart_and_replay` with a fresh
   `KAGEMUSHA_NATIVE_EXCHANGE_OUTPUT`, the existing `KAGEMUSHA_NATIVE_LOAD_TARGET` manifest
   path and `_SHA256`, and exact `KAGEMUSHA_NATIVE_LOAD_RECEIPT` / `_SHA256` and
   `KAGEMUSHA_NATIVE_LOAD_FINALITY` / `_SHA256`. Also provide the existing
   `KAGEMUSHA_EXECUTED_LOAD_CAPTURE` / `_SHA256` and
   `KAGEMUSHA_EXECUTED_LOAD_RECEIPT_SHA256`. It requalifies sources and reopens the SAME
   persisted A custody and original key. It never reenrolls A or reconstructs its Bootstrap.
   Before Load, it confirms the already committed Activate through the native activation
   cursor using the exact signed transaction and complete H1-through-activation finality originals. A complete host
   owner restart must retain this confirmation without another payment signature. The fixture
   first asserts the unconfirmed activation refusal, then retains the strict proof-rejection
   checks for changed receipt, QC and event evidence after confirmation.
   B and C enroll against their own registered accounts and native account challenges;
   the final Unload claim must pay C's account, distinct from A and B.

The consumer tests actual Load verification, duplicate refusal, pending irreversible Send
recovery, lost delivery/exact-byte replay, invalid incoming proof refusal, local Receive
fold checkpoints/restart, onward Send only after folding, unavailable storage, A→B→C
conservation, Archive, and an actual verified Unload package. A second positive Unload must
first report `FoldRequired`, then fail native preparation after the depleted head is fully
folded; neither refusal nor folding may sign another payment or alter the original claim.
It exports the exact canonical
Unload claim for separate node execution. Its result explicitly does **not** claim ledger
settlement, four-validator network qualification, physical attestation or phone gates.

The pending-Send continuation requires B and C's original saved keys, all four
public frames and selected E5/E6 enrollment custody. It uses the same strict
reopening path as the completed-Send and Archive continuations. Missing custody
refuses before enrollment continuation, and reopening must reproduce the exact
recorded keys, frames and selected enrollment bytes. No deterministic key
reconstruction or replacement enrollment is available.

The Archive checks use both delivery forms: A accepts B's exact Receive package;
B accepts C's folded CreditStatus. Each payer verifies the produced Archive
package, folds the complete outgoing backlog, reopens the same custody, and
replays the acknowledgement without another signature or monetary change. B's
final CreditStatus must expose an empty pending-outgoing root. The four exact
acknowledgement/Archive originals are retained with their lengths and hashes in
`archive_originals`; every original must fit 10,000 bytes. Exact current-candidate
execution, rather than registration of the checks, establishes acceptance.

For retained A Send/Archive custody, the ignored
`archive_recovery::checkpoint::retain_current_send_checkpoint_once_without_monetary_replay`
test attempts exactly one checkpoint at the current authenticated cursor with
payment signing disabled. `KAGEMUSHA_NATIVE_SEND_CHECKPOINT_OUTPUT` receives
`selection.json`, the actual `fold-outcome.json`, and a structured `receipt.json`
binding the source, target, session, exact completed Payment and Archive originals,
native snapshots and reopened cursor. Errors and non-checkpoint outcomes cannot
admit continuation. The Archive consumer requires this receipt through
`KAGEMUSHA_NATIVE_SEND_CHECKPOINT_RECEIPT` and `_SHA256`, then independently
reopens and verifies the same native custody. No historical failure string or
fixed checkpoint ordinal authorizes recovery.

B's later folded-head status is additionally retained as
`b-final-credit-status.envelope.norito`, with exact A→B Request/Payment bindings,
canonical Credited model verification and separate installed lineage verification.
Its `b_final_credit_status` result is distinct from the ten-frame census below.
The capture checks unchanged wallet snapshots and signature counts; this case
has an unburned opening and does not qualify burned-status execution.

The exchange additionally retains the **complete canonical envelopes** for both
Offers, Requests and Payments, their predecessor Lineage messages, the Receive
acknowledgement and the CreditStatus acknowledgement. The Offers and Requests
are the exact producer originals; the census neither reconstructs nor signs them.
`message_envelopes` records each full frame's
role, byte count, SHA-256 and bound. Each frame and its measurement are synced
before checking the bound, so an oversized failure remains inspectable. A naked
Payment or Credited object's byte count does not establish the carrying frame's
size. All measured frames are retained before Sigma proofs and the Omega
opening/accumulator decisions are verified against the admitted catalog. The
separate `proof-checks.json` retains each proof decision, including failures.
It also records Offer signature/credential/certificate verification and Payment
model verification against that payer credential and the exact signed Request,
including the receiver credential, certificates and fee schedule. This does not
assert that Payment commits to the Offer's session nonce or proposed amount.
The census separately runs canonical `Credited::verify_for` against the exact
held Request and retained Payment. It checks the Receive receipt and monetary
bindings, or the CreditStatus receipt, credit-membership opening and receiver,
credit and Payment bindings. The separately recorded Sigma/Omega proof decisions
remain mandatory; model verification cannot substitute for them. The parent
exchange's Archive owner performs native operation admission separately. These ten
observed messages cover the zero-fee, controls-off ABC exchange only; they do not
qualify every fee/control variant, all message types, or physical carriers.

The separate controls producer retains all five carrying-frame roles for every
executed Send mask 0–3 and its after-expiry exchange: actual Offer, Request,
Payment, Receive Credited and the Payment's exact predecessor Lineage. The fee
producer retains those same five roles for its fee-3, amount-97 exchange, plus
the original Offer in `producer_originals`. Their `complete_exchange_roles`
inventory requires each named role exactly once, checks its tag and successful
frame-bound measurement, and keeps the proof/operation verdicts separate. These
are capture paths; fresh genuine execution is still required to establish each
variant's measured bounds. They do not qualify CreditStatus for every
control/fee case or physical carriers.

The renewal continuation retains the same five roles for each of its five
existing reverse payments, including the daily and monthly boundary cases and
the renewed-receiver case. Its inventory uses one consistent label per session;
it also retains the already-signed Offer from the retiring receiver's refused
Request. No extra payment or signature is created for measurement.

The online-charge producer retains its root-verified certificate set in a
`PolicyData::Certificates` carrying envelope and preserves the exact certificate
and five charge quotes before attempting Unload. Quotes, ledger receipts,
finality and claims retain their own bounded original formats; they are not
additional peer-message variants. This capture establishes neither carrier
delivery nor physical issuer enrollment.

The existing charged Unload and later charged Load also stop at Selected with
the signer unavailable, drop both wallet and host device owners, and restore the
exact saved key and capsule. Exact Pending retries and conflicting same-ID inputs
must not sign or derive another operation. Resume must release the selected
generation and output with one successful signature and no new derivation; a
second full restart with the signer unavailable must replay those exact bytes.
Load checks its retained receipt/finality roles; Unload checks its signed quote
and certificate through the permanent payout custody and reconstructed claim.
These host checks preserve the existing payout and conservation assertions;
their registration does not establish genuine execution or physical power-loss
behavior.

`message_census::remeasure_retained_genuine_exchange_envelopes_without_wallet_mutation`
rechecks existing public originals without opening wallet custody, reenrolling,
signing or repeating a monetary operation. In addition to the catalog inputs it
requires `KAGEMUSHA_NATIVE_MESSAGE_ORIGINALS` and `_SHA256`, a privately retained
JSON manifest with schema `iroha.kagemusha.message-originals.v1`, the exact seven
`source_pins`, and exactly eight `originals` entries (`name`, `bytes`, `sha256`):
`a-b-payment.norito`, `b-c-payment.norito`, `a-credited-receive.norito` and
`b-credited-status.norito`, plus `a-b-offer.norito`, `a-b-request.norito`,
`b-c-offer.norito` and `b-c-request.norito`. Those files are siblings of the
manifest; a four-original manifest is rejected. Use a fresh
`KAGEMUSHA_NATIVE_MESSAGE_CENSUS_OUTPUT`. The result binds its observer binary
and source snapshot separately. The snapshot is diagnostic and is not a guarded
compiler consumed-input attestation. It cannot promote historical producer
evidence into a current-candidate lifecycle result. Its proof verification is
not a new native message/operation-admission verdict. Both archive-recovery
continuations require this same pinned manifest at entry. They check roles,
bounds, hashes and source pins before opening custody. Both also compare the
exact A→B Offer and Request hashes against `retained_offer_sha256` and
`retained_request_sha256` in the pinned selected-Send continuation. The
interrupted archive continuation requires the exact manifest hash recorded as
`message_originals_manifest_sha256` by its preceding archive continuation;
missing or changed pins are refused before custody opens. These producer pins
prevent substituting a different valid same-payer Offer whose nonce is not bound
by Payment. The continuations then require equality
with the retained monetary originals and authenticate the session bindings
before resuming archives, folds or Unload. A missing original is not replaced
by another wallet operation.

The ordinary `message_census` regressions use clearly labelled structural
vectors, never genuine-proof qualification. They check exact signed-Request
linkage (including a different valid Request signed by the same receiver),
valid same-payer Offer substitution against the producer pin, missing or changed
predecessor manifest pins, manifest substitution, Offer/Request frame bounds, and retention of oversized
Offer and Payment frames. A payload that fits while its complete carrying
envelope exceeds the bound is still rejected.
Additional structural regressions check both Credited forms against a distinct
valid same-receiver Request and altered Payment linkage, exact extraction of
the Payment's predecessor Lineage, and rejection of missing, duplicated,
mislabeled or failed-bound roles in each exchange inventory.

No host-census result supplies a physical latency measurement. Device campaigns
must retain separate monotonic events for payer confirmation, receiver durable
completion, and the receiver's fold reaching its current head. Report durable
completion and additional time to onward spendability separately; a fold retry
or restart cannot reset the original interval. Keep failed and slow trials.

The software-key file is test-only private custody, not a portable wallet format or runtime
API. Never distribute it with the public target. Consumer execution changes A's selected
state; retrying a failed acceptance run must reconcile its retained state, never overwrite
that tree or create another A to reuse the same finalized deposit.


The complete component chain has six stages. Keep each stage's exact binaries,
source capture, originals, log and completion record; a JSON progress record is
never a substitute for the native verifier's source capability.

| Stage | Exact test suffix | Required new inputs and outputs |
| --- | --- | --- |
| A target | `export_actual_a_load_target_with_retained_native_custody` | Fresh target output, as above. Keep `wallet-a` private. |
| Fund A | Core `funding::execute_actual_a_registration_activation_and_load` | Exact target path/pin and `KAGEMUSHA_NATIVE_VERIFIER_PACK`/`_SHA256`. `KAGEMUSHA_EXECUTED_LOAD_OUTPUT` is fresh; it receives `capture.json`, H1–H5 canonical blocks/native proofs and exact `receipt.norito`. The test executes Register/install, Activate and IssueLoad against real StateExecutor, then checks duplicate debit refusal. |
| Certify Load | `load::export_native_load_finality_from_executed_history` | Seven source pins, catalog/setup/target inputs above, `KAGEMUSHA_EXECUTED_LOAD_CAPTURE`/`_SHA256`, and `KAGEMUSHA_EXECUTED_LOAD_RECEIPT_SHA256`. Fresh `KAGEMUSHA_NATIVE_LOAD_EVIDENCE_OUTPUT` and a separate fresh `KAGEMUSHA_NATIVE_LOAD_ADMISSION_OUTPUT`. |
| Exchange | `actual_native_a_to_b_to_c_then_unload_with_restart_and_replay` | Exact funded receipt plus native BLS certificate and event inclusion; reopen the same A. Outputs include the claim and retained C custody; no ledger settlement is claimed. |
| Settle C | Core `funding::settlement::execute_actual_c_unload_with_conservation_and_permanent_replay` | Same target/pack/receipt, `KAGEMUSHA_NATIVE_UNLOAD_CLAIM`/`_SHA256` and `KAGEMUSHA_NATIVE_EXCHANGE_RESULT`/`_SHA256`. Fresh `KAGEMUSHA_EXECUTED_UNLOAD_OUTPUT` receives `settlement.json` and 13 originals, including H6 canonical SignedBlockWire, its exact signed transaction, instruction and claim. |
| Confirm C | `settlement::actual_c_confirms_executed_unload_after_process_restart` | Same catalog/setup/target/receipt pins; `KAGEMUSHA_NATIVE_EXCHANGE_RESULT`/`_SHA256` and `KAGEMUSHA_EXECUTED_UNLOAD_SETTLEMENT`/`_SHA256`. Fresh `KAGEMUSHA_NATIVE_SETTLEMENT_CONFIRMATION_OUTPUT`; reopen the retained C key and four public originals in place. |

The Load evidence exporter authenticates the installed wallet identity, independently
pinned signed genesis and the complete certified prefix from H1 through the receipt
height (H5 in the component fixture), including the counted event opening.
It retains only the receipt-block certificate and counted event path in
`load-finality.norito`, alongside `receipt.norito` and `generated.json`. Certified
epoch boundaries are synchronized separately into the native wallet's authenticated
epoch index. The native verifier restores the receipt's selected epoch and rechecks
the envelope directly with BLS. There is no finality circuit,
proving-key cache, proof journal or finality source catalog. The seven source pins
include `KAGEMUSHA_SIGNED_GENESIS_FIXTURE_SHA256` and the six wallet catalog/identity
pins; they do not include a finality producer or inventory.
Use `load::resume_native_load_finality_from_executed_history` only with the same
selected output and all exact input pins. It requires the existing selection and
a new admission-output directory. Missing selected state is refused; it never
initializes a replacement on resume.

The settlement test requires a separately captured **Core lib-test executable**;
compiling Core as a bridge dependency does not produce this test harness. It
executes C's genuine Unload at H6, replays original certified frames into a new
StateExecutor/Kura instance, and accepts the exact retry without a second payout.
Foreign-account/proof mutations fail. It checks A/B/C/reserve balances, total
registered supply and every asset bucket. This is fresh in-memory State recovery,
not a disk or power-loss test. The same-C continuation consumes exact successful
H6 evidence, retains its confirmation while advancing to H9, reopens before and
after confirmation, and asserts zero new payment signatures. Its confirmation
original is a test result projection, not a new public protocol.

Engineering orchestration may reuse only completed stages whose inputs, binary,
log and output originals still match. An interrupted native evidence export can use the
explicit existing-store resume action; deterministic funding/settlement tests can
be repeated in a fresh State and fresh output directory. Interrupted A creation,
A→B→C exchange or C confirmation requires explicit native custody reconciliation;
never reset these directories, reenroll another A against the same deposit, or
infer completion from a file's presence. Completed-stage reuse does not itself
satisfy the protocol's crash-recovery acceptance requirements.

This component chain uses real proofs and ledger execution with engineering
issuer/platform fixtures and exactly three signed votes from a four-seat fixture.
It is not the later four-validator monetary network gate. A real network harness
must use its actual emitted genesis/provisioning bundle and assert exact identity
(or build a new matching catalog); network setup may normalize genesis inputs.

The shared native Load producer derives the consecutive registration, activation
and Load heights from the canonical receipt, within the existing 64-block history
bound. It independently verifies the complete native prefix, unique successful
Register membership and funded Load event. The exchange then authenticates the
exact target Activate transaction and its successful execution at the derived
activation height before admitting Load to the retained wallet. Both the local
StateExecutor fixture (H3/H4/H5) and a four-validator campaign with a later live
predecessor use this same verifier and original capture format.

The separate network controller additionally requires pinned `registered.json`
and `funded.json` originals from its retained four-validator owner and joins
their heights to `setup.live_height`. Those network observations are not inputs
to the shared native verifier and do not turn a local fixture into network
evidence. The native target still uses engineering enrollment and simulated
payment hardware; neither it nor issuer startup qualifies actual issuer-service
enrollment or a physical device.
