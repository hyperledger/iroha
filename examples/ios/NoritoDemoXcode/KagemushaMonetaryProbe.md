# Disposable native monetary stage contract

This extends the physical enrollment XCTest mailbox. Every command calls the
current Swift SDK on the actor's actual Native owner and real Apple platform.
It is test glue; full-SDK arm64 iOS typechecking and host harness tests do not
replace matching-source Native linking or physical monetary execution.
It supplies no account key, FI issuer, ledger signer, ledger execution, transport
implementation or qualification verdict. Only exact externally produced originals
can complete those boundaries. Native refusals remain refusals.

A/B/C use distinct canonical accounts, UUID roots and Native custody slots in one
explicitly isolated disposable app. Slots on the same phone share the app and its
actual Keychain access group; this does not simulate independently signed apps.
The selected iOS device is iPhone17 Pro Max (`iPhone18,2`), iOS26.7 build23H24.
Pixel6 is the other selected device; its corresponding driver is maintained in
`kotlin/kagemusha-wallet-android`. Running all three actors on iOS does not qualify
Android or a cross-OS population. Monetary qualification requires a matching
authenticated package cohort and actual execution on each selected device.

## Mailbox originals

Use the enrollment interface's private root, pins, independently pinned catalog,
configuration and sequential ready-file protocol. `command.plist` contains exactly
`action` and `inputs`, with each input a `{path,size,sha256}` file pin. Each input
must lie below the current invocation inbox. The harness retains all exact input
bytes privately before Native execution and never replaces an existing original.
No input named `success`, `verified`, `balance` or `proof-override` is accepted.
The full wire frames are Norito originals. Plists below are harness metadata only.

IDs are exactly32 nonzero bytes; distinct intents need distinct IDs. `amount` is
exactly16 bytes, unsigned little-endian low64 then high64, nonzero. `epoch` is
exactly8 unsigned little-endian bytes. These scalar inputs are forwarded as typed
SDK values; the harness does not encode ledger or wallet protocol frames. All
fees, account identity, scale and proof authority come from Native verification.

The closed commands and exact sets of input names are:

| Action | Inputs | Meaning |
|---|---|---|
| `open` | `result` | Exact canonical E6; Native account admission through a live callback |
| `release-wallet` | none | Close/join this owner, keep all custody and originals |
| `bootstrap` | none | Native restart-safe Bootstrap; retain actual completion status |
| `activation` | none | Export Native Activate original and ledger instruction |
| `retain-activation` | `signed-wire` | Retain actual outer signed transaction **before** external dispatch |
| `activation-status` | `signed-wire` | Observe that exact retained attempt |
| `activation-finality` | `signed-wire`, `finality` | Ingest one next actual finalized block |
| `confirm-activation` | `signed-wire` | Native successful inclusion confirmation |
| `prepare-load` | `request-id`, `amount` | Persist/export the exact Native Load instruction |
| `prepared-load` | `request-id` | Observe the retained plan, without selecting another ordinal |
| `load` | `request-id`, `receipt`, `finality` | Admit actual matching ordinary-ledger receipt and finality |
| `ledger-finality` | `finality` | Advance Native's verified Global-chain prefix |
| `ledger-status` | none | Observe retained prefix, including absence |
| `epoch-boundary` | `epoch`, `boundary` | Verify the exact incumbent epoch boundary |
| `epoch-status` | none | Observe Native epoch authority |
| `offer` | `setup-id`, `amount` | Export actual signed Offer and envelope |
| `request` | `setup-id`, `offer`; optionally both `fee-schedule`, `fee-certificate` | Export native Request from received signed Offer |
| `decode-offer`, `decode-request`, `decode-payment`, `decode-credited` | `envelope` | Native extract of expected peer type; no monetary admission |
| `review-send` | `request-id`, `request`, `destination` | Retain live native review and exact projection |
| `review-unload` | `request-id`, `amount`; optionally all `quote`, `certificates`, `beneficiary` | Review actual native Unload terms |
| `decide-review` | `decision` | Explicit exact-review confirm/cancel; confirmation also invokes iOS authentication |
| `receive` | `request-id`, `payment`, `offer` | `receiveFromOffer` using the originally retained signed Offer |
| `credit` | `request-id` | Native credit projection and original Credited evidence |
| `accept-credited`, `credited-status` | `request-id`, `credited` | Native handling/status for the original payer Send ID |
| `fold-once`, `fold-status`, `snapshot` | none | Native local fold or exact current-head observations |
| `request-status`, `released-request` | `request-id` | Recover/observe actual native request mapping |
| `retry`, `released-operation` | `operation-id` | Retry/observe the exact Native operation |
| `resume` | none | Reconcile/finish the selected Native operation |
| `unload-claim` | `request-id`; optionally `beneficiary` | Export actual retained claim and ledger instruction |
| `unload-finality` | `transaction-hash`, `claim`, `finality` | Verify next block for the exact submitted claim |
| `unload-status`, `confirm-unload` | `transaction-hash`, `claim` | Observe history or confirm exact successful settlement |
| `begin-time`, `cancel-time` | none | Actual owner-local direct issuer time exchange |
| `finish-time` | `anchor`, `certificate` | Consume native exchange with actual issuer response |
| `refresh-time` | `request-id`, `anchor`, `certificates` | Native TimeAnchor refresh after direct exchange retention |

Receipt/anchor/certificate bounds are512 bytes; fee schedule/quote1024;
canonical account/beneficiary4096; peer originals/envelopes/certificate bundle10000;
signed transaction/claim65536; epoch boundary256KiB. Finality intake is capped at
36MiB overall; `load` itself has the SDK's stricter256KiB finality bound. E6 uses the
SDK's exact `RESULT_MAX_BYTES`. Native retains every canonicality and protocol
bound check. An external file's hash or a signed transaction's existence proves
neither admission nor ledger execution.

For initial activation, the network controller first prepares one exact versioned
signed transaction without submitting it. After the real `retain-activation` call
returns Native's not-started result (no confirmation, rejection, verified height
or block hash), the driver exports `<SEQ>-activation-retained.json`. It has exactly
these string fields: `schema` (`iroha.kagemusha.wallet-activation-retained.v1`),
`action` (`retain-activation`), `signedWireSHA256`, `signedWireBytes` (decimal),
`nativeResult` (`not_started`), `nativeReturnedTicks` (decimal), `invocation` and
`sequence` (decimal). Progress, rejection or confirmation cannot produce this
initial-retention receipt. The controller pins its exact bytes and joins the
retained command, started event and successful finished event before acknowledging
retention and permitting submission of the unchanged transaction. This JSON is
test-controller DATA, not a cryptographic attestation or confirmation of finality.

## Open and review callbacks

After successful enrollment, stage the exact exported E6 as `open.result`. The
actor transfers `loadInstalledRuntime()` from its live enrollment owner. After a
restart use `install` then `open` with the same E6 and account; no expired FI
session is necessary (`session` is an empty dictionary in this case).

`open` exports `<SEQ>-open-account-challenge.bin`. While that command awaits the
external account signer, provide:

```text
inbox/<INVOCATION>/<SEQ>-open-signature.plist
  challengeSHA256 = SHA256(exact exported challenge)
  signature = {path, size:64, sha256}
inbox/<INVOCATION>/<SEQ>-open-signature.ready
  exactly64 ASCII bytes: SHA256(the plist), no newline
```

Stage the exact64-byte externally generated account signature first and publish
the ready marker last. This callback waits at most120 seconds; Native deadlines
remain authoritative. The harness checks cancellation and its continuous-clock
bound before and after selecting readiness and again after retaining the signature,
before returning it to Native. Command intake also checks its bound immediately
before dispatch; readiness or suspension during publication cannot bypass expiry.
An expired started record needs explicit recovery, and no harness deadline cancels
an already dispatched Native operation. An ordinary timeout retains the SDK's exact pending owner.
Retry `open` in a new command in the same process; the SDK may already retain a
signature and then does not invoke the callback again. Actual Task cancellation
has the SDK's custody-retirement semantics and is not manufactured as a timeout.
A new process gets a new invocation and live challenge; never transplant a stale
callback or permit. No private account key enters this harness.

`review-send`/`review-unload` export `<SEQ>-native-review.bin` plus native amounts,
fees, debit, destination digest, current head and source commitment. The live
`KagemushaWalletReviewV1` remains in the same actor. A decision plist has exactly:

```text
decision = "confirm" or "cancel"
invocation = exact current invocation UUID
reviewSequence = exact sequence that produced the retained review
reviewSHA256 = SHA256(exact native-review.bin)
```

A cancelled review is passed to Native `discardReview`. A confirmed review first
invokes real `LAContext.deviceOwnerAuthentication` with reuse disabled and a prompt
identifying its review hash and native gross atomic amount. The app Info.plist
contains the required Face ID usage description. Authentication failure is
retained as a failed attempt; no debit call occurs. This diagnostic UI combines an
external display of the full native projection with actual iOS authentication;
it makes no claim of a hardware-authenticated display or NFC tap confirmation.
Native `executeReviewed` still consumes the real owner-local token and rechecks
its complete source. An exported projection can never recreate that capability.

## Recovery and timing

Before every Load/Receive/reviewed operation, the harness freezes the action and
exact input hashes under the stable request ID. Setup and Load-plan identities
are similarly frozen. New inbox paths with identical bytes are valid retries;
changed intent under the same ID is rejected. The harness cannot replace Native's
journal or infer success after uncertain delivery.

Before dispatching a confirmed review, an immutable execution marker is retained.
A failure/crash then requires `request-status`, `resume`, `retry` or `released-*`
on the same custody and exact IDs. This increment refuses another review for a
marked ID even if the process died just before Native selected it. That narrow
conservative case remains a harness recovery limitation: do not erase the marker
or invent a replacement debit. Reviews and direct-time tokens cannot survive
process reopening; Native monetary outcomes do. `release-wallet`, `install`,
`open` provide a non-destructive same-process reopen sequence. `stop` closes all
owners. Neither command abandons enrollment, deletes keys, replaces custody,
erases apps, restores arbitrary developer files or claims power-loss testing.

Every command preserves actual status, detail, sequence and original output.
Pending, preparing, not-performed, archived and delivery-loss statuses remain
visible; they are not labelled completed. Completion exports use the SDK's actual
`releasedOutput` projection; peer frames use the native `envelope` operation.
Mailbox publications synchronize private sibling staging before an atomic rename
that refuses an existing destination. Interrupted staging cannot occupy a final
name. An identical final output is synchronized again on retry; different bytes
are always refused. This helper never repairs or deletes Native journal state.
A fresh invocation can inspect Native custody and publish into a new output root.
Every failed command remains in the results and causes the XCTest summary to fail
even if a subsequent explicit retry succeeds.

`mach_continuous_time` timestamps and the invocation's timebase are retained for:
command start/end, Native returned completion, observed retained completion,
actual iOS confirmation, current-head fold observation and the next successful
native Send review. Values are comparable only within the same invocation/phone;
never subtract A's clock from B's clock. The first complete Receive observation
is not retroactively relabelled as its historical commit time. Fold-ready means
only exact-current-head Ω observed; the next successful Send review separately
establishes that specific operation's readiness under current Native checks.
Monetary completion and fold completion remain separate. Confirmation-to-complete
includes this test driver's own retention overhead and is not an optimized UI
latency measurement. Hardware/OS interrupts and all unsuccessful attempts remain
in the evidence population.

For A→B→C, the external controller must carry original Offer/Request/Payment/
Credited bytes through the selected actual carrier and preserve independent
physical ingress/egress evidence. The mailbox's file copy is not carrier success.
Real cross-phone P1a timing needs an externally observed common boundary, or the
specified one-device request/ack round trip; these local clocks alone cannot
produce a cross-device duration. After B's fold and successful onward review,
execute the reviewed onward payment to C. Source balances and destination net
amounts come from native projections; do not assume all-value send is fee-free.
Each Unload uses real signed ledger submission and exact finalized history before
native confirmation. HTTP status, proof generation, claim export and any single
component result are insufficient to declare settlement or release readiness.
