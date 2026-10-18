# Native SDK bridge

`connect_norito_bridge` exposes the current ABI-30 C and JNI bridge to the SDKs.
The ordinary Rust target emits `cdylib`, `staticlib`, and `rlib` outputs; Rust
consumers and tests retain the `rlib` interface.

The Apple owner is `scripts/build_norito_xcframework.sh`. It builds five
`staticlib` slices using the source-sealed `apple-release` Cargo profile and
whole-graph ThinLTO. Its final bridge optimization level is O1 so the ThinLTO
pass does not reapply O3 to the broad data-model modules. Dependencies retain
the release profile's crypto O3 and data-model O1 settings. The build preserves
symbols and the existing unwind behavior.

Every slice retains authenticated PQClean normalization and complete-archive C
link checks. The native host check exercises ABI identity, SHA3/SHAKE, ML-DSA,
and ML-KEM. Static XCFramework layout, headers, exports, and authenticated ZIP
limits remain enforced by their existing owners. SwiftPM is the sole supported
Swift delivery path; qualify the packaged archive and an ordinary Release SDK
consumer. Profile selection alone is
not evidence that a candidate passes resource, SDK, or device qualification.

`connect_norito_domain_id_validate_v1` admits only exact canonical ASCII
`domain.dataspace` identities through the native pinned UTS-46 owner. Its 127-byte
input bound is checked before reading or allocating. SDK callers must retain the
provided spelling and reject missing native admission; this API does not normalize
Unicode input or provide a managed fallback.

KAGEMUSHA canonical wallet objects are owned by
`iroha_data_model::kagemusha::kagemusha_wallet_v1`. The bridge retains one native
runtime or admitted wallet per opaque handle. Trusted embedding-app initialization
calls `kagemusha_wallet_ffi::start_native_wallet` with independently deployed
`NativeInstallationConfigV1`, an authenticated native genesis owner, the signed
verifier pack/inventory, the exclusive Advance provider and its sole original-key
source. The loader qualifies the complete 22-route graph before registering a
runtime; no default trust root or environment-selected installation exists.

C/JNI `open_begin` accepts only bounded credential, Enrollment CertificateSet,
AccountId and asset-scope originals. Native reconciles the actual enrolled slot and
returns a fresh 32-byte account challenge. `open_finish` consumes that challenge
and the existing Ed25519 account signature; errors retain unadmitted custody for a
fresh begin. `open_cancel` abandons the challenge. Repeating finish after lost
output returns the same still-live admitted handle; closing never resurrects it. Internal registration failure
retains an initialized owner until promotion succeeds. No foreign digest, proof
verdict or replacement payment key can open a wallet.

Typed setup and lifecycle calls cover Bootstrap, Offer/Request, Credited archival,
direct time exchanges, Load, Send, Receive, policy refresh, Unload and Retiring.
Offer/Request setup outputs are canonical object frames; peer transports carry
`KagemushaWalletEnvelopeV1` frames. Typed native `envelope`/`original` helpers wrap or
extract Offer, Request, Payment and Credited with exact scheme/kind and full-frame
bounds; they return no monetary verdict. Direct-time cancel only discards an opaque token.
Exact retained Payment bytes and durable completion remain native responsibilities.
Exact-byte output retries, credit-status reads, Send/Unload reviews and discarded review
tokens leave local lineage folding running. A review authenticates its current source
under the wallet owner lock; execution after hardware approval takes payment priority and rechecks that source before
proving or committing. Polling an unavailable credit opening returns `FoldRequired` without
cancelling the proof that makes the value onward-spendable.
The embedding app must provision signed complete artifacts/configuration; the
unprovisioned runtime fails unavailable. Full real-wallet and physical-device
qualification remain open.


For initial enrollment, trusted native startup constructs CoreZK `EnrollmentOwnerV1`
from the approved scheme and exact policy originals; on Apple it also selects the pinned
App Attestation root DER. Android selects no root original: its leaf-first `KeyMint` chain
carries its own root, which the issuer matches by SPKI against the policy's root set. A
policy naming an unimplemented or unqualified vendor adapter fails installation. Native
then registers `NativeEnrollmentRuntime` through `retain_native_enrollment`. The typed
C/JNI enrollment begin accepts a retry ID and account/asset originals, returning native-selected
issuer dispatch DATA. The signed pre-key permit must pass native scope, signature and elapsed-time
checks before the existing-account challenge can authorize hardware generation. Android E5
evidence is the `KeyMint` chain only (2–8 DER certificates, at most 65,536 bytes in all): no
Play Integrity token, Google account, vendor online verdict or second attested key. Native
retains the exact account-authorized E5 and issuer-signed E6 before returning them. Complete-source loader handoff preserves the same opaque handle
and exclusive provider on failures. `beginEnrolled` still requires a fresh existing-account
signature through ordinary original admission. No foreign liveness or hardware verdict
can substitute for issuer checks. The E6 transport bound is separate from Payment10KB.

The enrollment handle's explicit `abandon` action permanently closes an unused enrollment
before runtime handoff and returns an explicit result: result 58 (`LocalAbandoned`) for a slot
that never had an enrollment marker, which has nothing to submit, or result 28 with the exact
retained signed Abandonment frame (`Abandonment(frame)`) for the holder's account to submit
until its finalized inclusion is authenticated. Native refuses once Bootstrap commits.

Every operation runs the design §5.3 runtime capacity check on the phone before it proves its
step and again before it commits. The bounds come from the installed relations: free custody
storage must cover the operation's reservation plus the largest fold-witness schedule, and
memory available to the app (`MemAvailable` on Android, `os_proc_available_memory` on iOS) must
cover the largest installed relation's peak proving memory. A shortfall is the typed failure
`-12` (`CONNECT_NORITO_KAGEMUSHA_WALLET_NOT_ENOUGH_STORAGE`) or `-14`
(`CONNECT_NORITO_KAGEMUSHA_WALLET_NOT_ENOUGH_MEMORY`): nothing is debited or credited, the
receipt or Payment stays deliverable, and the holder retries after freeing space. It is never a
device verdict. An unanswered memory probe evaluates storage only. Retained outcomes and resumed
selections never depend on current capacity.

Issuer refusals carry the closed `u16` codes 1–12 of the design's refusal table. Core and the
SDKs relay a code unchanged; `connect_norito_kagemusha_wallet_enrollment_refusal_v1` (JNI
`KagemushaWalletNativeV1.enrollmentRefusal`) returns its holder class (1 Phone, 2 App,
3 Attempt, 4 Account) for the evidence platform, and refuses zero, unknown and
platform-inapplicable codes as protocol errors. Closing the handle only releases ownership. Abandon output is published
before an immutable digest selection, and nothing is returned until both are durable; a missing
selected original is refused. Recovery may complete a missing selection for a present valid
original. This local mechanism does not establish protection against complete filesystem rollback.
