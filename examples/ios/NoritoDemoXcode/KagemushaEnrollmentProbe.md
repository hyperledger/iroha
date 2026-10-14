# Native enrollment device probe interface

`KagemushaEnrollmentPhysicalDeviceTests/testDisposableNativeEnrollmentActor` is an
explicit physical-iOS test. It installs the authenticated native runtime, handles
E1/E5/E6 through the production Apple adapter, then drives the actual SDK's open,
activation, Load, payment, fold and Unload APIs as separate retained commands.
It contains no account private key, issuer, replacement proof or carrier verdict.
A closed mailbox does not establish enrollment or monetary qualification; inspect
exact outcomes and originals. See [the monetary stage contract](KagemushaMonetaryProbe.md).

Build only with the matching authenticated arm64-iOS bridge, `ENABLE_TESTABILITY=YES`,
and a separately provisioned app ID under
`org.hyperledger.iroha.kagemusha.enrollment-probe.*`. Its actual App Attest environment
and signed entitlements must match the installed application/issuer policy. Current
genuine enrollment requires production App Attest; the ordinary demo has no such
entitlement. Independently provision and inspect the disposable App ID, embedded
profile and signed entitlements before running it. Do not
substitute arbitrary entitlements or the storage-only probe's evidence. Ordinary
demo CI excludes this class. `KagemushaEnrollmentProbeFilesTests` covers the mailbox
path/pin/publication/clock guards, without native or device qualification.

## Private inputs

Stage inputs inside the disposable app's **Application Support** directory:

```text
kagemusha-enrollment-probes/<RUN-UUID>/
  catalog/
    app-manifest.bin
    envelope.bin
    wallet-runtime.bin
    verifier-pack.bin
    producer-inventory.bin
    signed-genesis.bin
    registration-source.bin
    originals/                       # exact complete source files, original relative names
    registration/                    # exact generic registration sources, when applicable
  accounts/{A,B,C}.bin                # three distinct canonical account originals
  inbox/<INVOCATION-UUID>/
    configuration.plist
    access-token.bin
    dpop-proof.bin
    attestation-root.der
    0000.plist
    0000.ready
```

Use fresh canonical uppercase UUIDs for the run, each of the three actors, and every
invocation. All staged directories must be owned by the app UID and exact mode 0700;
files must be owned by that UID, exact mode 0600, without extra hard links or special permission bits, protected while
locked and excluded from backup. The latter two properties are controller staging
obligations, not observed qualification facts: input validation checks ownership,
mode, path and hash. The trusted controller must have exclusive mailbox access;
path checks do not resist concurrent intermediate-directory replacement by another
same-UID writer. No symbolic links, path traversal, directory
aliases or incomplete writes are allowed. Stage runtime FI tokens/DPoP and account
signature files through an owner-only channel. Never add them to the repository,
command-line arguments, logs, XCTest attachments or the public export directory.
The harness never sends HTTP, so external issuer transport authentication stays
with the external controller.

`configuration.plist` is harness metadata, not a protocol codec. It has exactly:

- `version`: integer1.
- `requiredStage`: exactly `installed`, `dispatch`, `e5`, `e6`, `opened`, `activated`,
  `loaded`, `sent`, `received` or `unloaded`. The selected stage must be observed in
  this invocation; unrelated later stages do not satisfy it. `unloaded` requires
  actual native ledger confirmation, not claim export.
- `actors`: keys `A`, `B`, `C`; each contains exactly `id` (its UUID) and `account`
  (a file pin). UUIDs and the three account-original hashes must be distinct.
- `catalog`: an array of file pins for **every** regular file below `catalog/`,
  including the seven entry points and every originals/registration source file.
  Extra/unlisted or missing files fail. Verifier pack and producer inventory must
  be nonempty; Native authenticates completeness and its compiled trust contract.
- `session`: either an empty dictionary for an open-only invocation, or exactly
  `access-token`, `dpop-proof`, `attestation-root`, each a file pin beneath this
  invocation's inbox. `begin` requires this session only if no enrollment owner
  was already obtained with `start-enrollment`. An empty DPoP file is
  allowed only to the extent the actual native signed session permits it.

A file pin has exactly `path` (relative to the run root), `size` (byte count), and
`sha256` (64 lowercase hex characters). The configuration is independently pinned
by a Test action environment digest. `signed-genesis.bin` additionally must match
the independently obtained genesis pin; it is not inferred from the catalog.
Registration-source bytes are relocated through Native's existing
`relocateRegistrationSource` API to the copied registration directory. An empty
registration-source is accepted only if Native authenticates the fixed-adapter
case. Never fill a missing generic source with empty bytes to proceed.

Configure the XCTest target's `.xctestrun` environment:

```text
KAGEMUSHA_ENROLLMENT_RUN_ID                 canonical run UUID
KAGEMUSHA_ENROLLMENT_INVOCATION_ID          fresh canonical invocation UUID
KAGEMUSHA_ENROLLMENT_ACTOR                  A, B, or C
KAGEMUSHA_ENROLLMENT_CONFIG_SHA256          exact configuration.plist SHA256
KAGEMUSHA_ENROLLMENT_GENESIS_SHA256         independent signed genesis SHA256
KAGEMUSHA_ENROLLMENT_APP_ID_PREFIX          actual 10-character signed App ID prefix
KAGEMUSHA_ENROLLMENT_EXPECTED_MACHINE       iPhone18,2 for the selected iPhone17 Pro Max
KAGEMUSHA_ENROLLMENT_TIMEOUT_SECONDS        integer1..1800
```

The timeout bounds mailbox waits. Native/vendor calls retain their real SDK
lifecycle and deadlines; the probe does not forcibly interrupt uncertain effects.
Build/app/framework/test/config/catalog hashes and actual OS identity must still
be pinned by the external run controller. A config hash is not an attestation of
which native framework the app loaded.

## Ordered commands and retained outputs

The live test process consumes `0000`, `0001`, etc. up to10000 commands. Each command
plist has exactly `action` and `inputs` (dictionary of pins). Publish its referenced
files and plist first, then create a fresh `<sequence>.ready` containing the
exact64 lowercase ASCII SHA256 characters of the plist, with no newline. Pins for
command data must remain under this invocation's inbox. Wait for the matching
finished record before issuing a dependent command. The actual native owner is
retained between commands, including ordinary provider/refusal failures.

The trusted controller never replaces or rewrites a command, input or ready file.
A transfer can expose a short ready file: the driver waits for its complete
64-byte frame within the invocation deadline before comparing the plist digest.
Oversized or malformed complete frames and unsafe file ownership, modes or links
fail. The same framing applies to the open-signature callback. This bounded
intake does not infer atomic publication or power-loss durability from a successful
`devicectl` copy; Native calls follow the driver's own retained-input publication.

| Action | Input pins | Effect/public output |
|---|---|---|
| `install` | none | Verify source pins; actual install/registration. Retry keeps the same installation attempt. |
| `start-enrollment`, `renew-session` | `access-token`, `dpop-proof`, `attestation-root` | Authenticate a freshly supplied private session; `begin` is required next. |
| `begin` | none | Transfer the installed owner to enrollment once; begin this actor's stable request; export exact dispatch and canonical `service-prekey.norito`. |
| `permit` | `response` | Consume original canonical `ToriiKagemushaEnrollmentResponseV1` with Permit; Native authenticates it against the current live dispatch; export verified permit and exact account challenge. |
| `authorize` | `signature` | External existing-account Ed25519 signature, exactly64 bytes over that exact challenge; Native controls actual key generation/reconciliation. No account signer exists in the app test. |
| `collect-evidence` | none | Recover retained E5 first. Otherwise collect actual App Attest through the native evidence journal and prepare E5; export the exact E5 account challenge or already-retained request. |
| `retain-request` | `signature` | External64-byte signature over E5's native challenge; Native durably retains E5 before exporting it and the canonical Evidence service request. |
| `accept-result` | `response` | Original canonical service response with Credential; Native verifies/retains exact E6. Exporting E6 is not activation. |
| `inspect` | none | Recover exact native-retained E5/E6 after a selected begin; thrown storage errors are never absence. |
| `stop` | none | Explicitly close/join the retained owner. No abandonment, key deletion, replacement, or native custody cleanup. |

Canonical service envelopes are produced/decoded by the maintained SDK transport
owners. Pending, Refused or HTTP errors must remain exact external-controller
observations; do not invent a Permit/Credential or feed a decoded host verdict into
Native. The enrollment dispatch accepts only actual Permit/Credential responses and
does not yet automate the issuer's Evidence/Issue/Deliver HTTP state machine.

Outputs live under `actors/<ACTOR-UUID>/public/<INVOCATION-UUID>/` inside the app.
Only known public protocol originals, native account challenges, and nonsecret
outcome metadata go there. Exact incoming bytes/config/command originals stay in
`actors/<ACTOR-UUID>/private/<INVOCATION-UUID>/`; never export that directory or the
adjacent `custody/` directory. Every action gets a started/finished record with
continuous monotonic ticks and duration; native failures include numeric status,
reason and platform code without error descriptions. Local monotonic ticks cannot
be compared across devices. A failure is retained even if later retried, and any
failed command makes the final XCTest fail; `closed.plist` records aggregate counts
and the requested/achieved stage. Closing before the configured stage also fails.
Missing finished/closed records represent interruption, never success.

## Restart and actor boundaries

Each actor has a separate UUID file container and native custody root. The only
system-seam change is `applicationSupportDirectory`; actual Keychain/Secure Enclave,
passcode, storage-protection and clock operations remain production code. Actors
share the app's entitled Keychain access group, while Native independently selects
and binds their slots/payment keys. No caller-selected key alias or fake group
is introduced. The actor identity freezes account, request, catalog and bundle
binding; changing them refuses the existing container. An exclusive actor lock
prevents two driver processes from using the same container.

A new enrollment process must use a new invocation UUID, then `install`,
`start-enrollment` with a fresh valid session, and `begin`. Native preserves the same request/client/custody selection but
samples a **new live dispatch nonce**. A permit from the previous process is not
replayed as live authority: send the fresh Resume dispatch to the actual issuer
and authorize its new account challenge. E5/E6 that Native has durably retained
can be inspected/exported exactly. Incomplete harness output files remain retained
and are not overwritten; reconciliation uses Native custody in the new invocation.

The monetary stage extension transfers `loadInstalledRuntime()` and invokes
`openEnrolledResult(..., signExistingAccount:, requireCurrent:)` with a separate
same-owner live signature callback. An open-only restart uses the retained E6 and
account without a live enrollment session. It does not establish power-loss or
stock-restore durability. No cleanup deletes enrollment state: later explicit
retirement must use the canonical enrollment/ledger lifecycle.

The immutable actor identity also binds the derived actual Keychain access group.
Changing App ID prefix or bundle ID cannot silently reuse a prior actor namespace.
A/B/C have distinct UUID roots and native custody slots in the disposable app;
they share that signed app's access-group trust boundary. Neither private actor
files nor public protocol exports should be copied wholesale into the repository.
Only deliberately selected nonsecret evidence belongs in public attachments.

Use `start-enrollment` immediately after installation to supply a freshly obtained
private session; its inputs are exactly `access-token`, `dpop-proof`, and
`attestation-root` pins (limits16384/4096/16384). This avoids expiring short-lived
DPoP while a large catalog is verified. `begin` then emits the live dispatch.
`renew-session` accepts the same three exact private pins on the existing owner
and calls native `renewSession`. It discards only the obsolete exported dispatch
reference; a subsequent `begin` with the same request ID must obtain a fresh
permit. Native retains attempt/permit dates and returned evidence. Universal
ApplicationRelease sessions require actual P-256 DPoP; an unrelated FI-specific
empty-DPoP fixture does not authorize this enrollment. Neither command exports
session material. The optional config session is useful only when it is still
fresh at the first `begin`; an empty dictionary and explicit `start-enrollment`
are the preferred device procedure.

The mailbox accepts sequences0000–9999 within one owner invocation. The elapsed
wait bound remains explicit; Native proving/vendor calls are never converted into
successful timeout outcomes. This accommodates at least200 warm-cell attempts
without requiring owner closure solely because of the earlier enrollment-only
command ceiling. Actual cold/warm classification still requires recorded process
and owner lifetimes. The120-second signature mailbox deadline uses the same
continuous Mach clock available at the Xcode target's iOS15 deployment minimum.
