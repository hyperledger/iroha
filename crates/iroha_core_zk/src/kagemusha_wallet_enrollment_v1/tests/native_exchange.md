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
   Before Load, it confirms the already committed H4 Activate through the native activation
   cursor using the exact signed transaction and H1–H4 finality originals. A complete host
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

The Archive checks use both delivery forms: A accepts B's exact Receive package;
B accepts C's folded CreditStatus. Each payer verifies the produced Archive
package, folds the complete outgoing backlog, reopens the same custody, and
replays the acknowledgement without another signature or monetary change. B's
final CreditStatus must expose an empty pending-outgoing root. The four exact
acknowledgement/Archive originals are retained with their lengths and hashes in
`archive_originals`; every original must fit 10,000 bytes. Exact current-candidate
execution, rather than registration of the checks, establishes acceptance.

The exchange additionally retains the **complete canonical envelopes** for both
Payments, their predecessor Lineage messages, the Receive acknowledgement and
the CreditStatus acknowledgement. `message_envelopes` records each full frame's
role, byte count, SHA-256 and bound. Each frame and its measurement are synced
before checking the bound, so an oversized failure remains inspectable. A naked
Payment or Credited object's byte count does not establish the carrying frame's
size. All measured frames are retained before Sigma proofs and the Omega
opening/accumulator decisions are verified against the admitted catalog. The
separate `proof-checks.json` retains each proof decision, including failures.
This helper checks CreditStatus's Omega only: it does not independently recheck
its credit-membership opening, receipt or Request/Payment linkage. The parent
exchange's Archive owner performs full native admission separately. These six observed
messages cover the zero-fee, controls-off ABC exchange only; they do not qualify
Offer, every fee/control variant, all message types, or physical carriers.

`message_census::remeasure_retained_genuine_exchange_envelopes_without_wallet_mutation`
rechecks existing public originals without opening wallet custody, reenrolling,
signing or repeating a monetary operation. In addition to the catalog inputs it
requires `KAGEMUSHA_NATIVE_MESSAGE_ORIGINALS` and `_SHA256`, a privately retained
JSON manifest with schema `iroha.kagemusha.message-originals.v1`, the exact seven
`source_pins`, and exactly four `originals` entries (`name`, `bytes`, `sha256`):
`a-b-payment.norito`, `b-c-payment.norito`, `a-credited-receive.norito` and
`b-credited-status.norito`. Those files are siblings of the manifest. Use a fresh
`KAGEMUSHA_NATIVE_MESSAGE_CENSUS_OUTPUT`. The result binds its observer binary
and source snapshot separately. The snapshot is diagnostic and is not a guarded
compiler consumed-input attestation. It cannot promote historical producer
evidence into a current-candidate lifecycle result. Its proof verification is
not a new native message/operation-admission verdict. The focused ordinary regression
`message_census_records_complete_frame_and_retains_oversize_failure` uses clearly
labelled structural vectors solely to reject a payload that fits while its
carrying envelope exceeds 10,000 bytes.

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
| Settle C | Core `funding::settlement::execute_actual_c_unload_with_conservation_and_permanent_replay` | Same target/pack/receipt and `KAGEMUSHA_NATIVE_UNLOAD_CLAIM`/`_SHA256`. Fresh `KAGEMUSHA_EXECUTED_UNLOAD_OUTPUT` receives `settlement.json` and 13 originals, including H6 canonical SignedBlockWire, its exact signed transaction, instruction and claim. |
| Confirm C | `settlement::actual_c_confirms_executed_unload_after_process_restart` | Same catalog/setup/target/receipt pins; `KAGEMUSHA_NATIVE_EXCHANGE_RESULT`/`_SHA256` and `KAGEMUSHA_EXECUTED_UNLOAD_SETTLEMENT`/`_SHA256`. Fresh `KAGEMUSHA_NATIVE_SETTLEMENT_CONFIRMATION_OUTPUT`; reopen the retained C key and four public originals in place. |

The Load evidence exporter authenticates the installed wallet identity, independently
pinned signed genesis and every ordinary H1–H5 certificate and counted event opening.
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
