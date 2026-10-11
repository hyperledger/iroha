# Enrollment eligibility authority and middleware contract

Every token on the universal dataspace is eligible for KAGEMUSHA offline payments through
its authorized asset/scheme setup. Universal balances use `AssetBalanceScope::Global`, routed
to `DataSpaceId::UNIVERSAL`; no named-token allowlist, Parliament approval or legal asset-class
arm may restrict that path. Exact asset identity, scale, reserve backing and applicable
transfer controls remain enforced. Bank-required enrollment uses the user's bank middleware for current KYC approval
and freeze status. Other schemes may use their issuer or another authorized operator. SORA
Parliament is one optional provider for tokens it governs, not a protocol prerequisite.
Explicit public-enrollment policy is permitted; missing or unavailable bank data never selects
it as a fallback. This authority selection does not change payment proofs, hardware enrollment,
irreversible Send, reserve accounting or controls.

`iroha_data_model::kagemusha::enrollment_eligibility_v1` defines one canonical Norito protocol.
`iroha::kagemusha_enrollment` and Kotlin/JVM's
`org.hyperledger.iroha.sdk.offline.KagemushaEnrollmentEligibilityV1` provide middleware adapters,
including Java-callable lookup, clock and signer interfaces. The bank supplies its existing
current-state lookup and signing callback. It can use authenticated software signing custody;
the optional convenience signer accepts an existing Ed25519 key pair. The adapter generates
no keys and neither stores nor logs secrets or KYC documents.

## Current authority selection

The issuer independently selects an asset-independent eligibility template and platform
enrollment template from authenticated configuration, then checks current ledger registration
and the rooted Enrollment-role certificate. The eligibility template binds genesis network,
scheme, positive revision, bank FI or scheme operator identity, one strong Ed25519 middleware
key and a positive response-time bound. Deriving the concrete policy adds the registered
asset's exact identity, incarnation and scale. No wildcard enters a credential, proof or
response digest; no new provider configuration is required for each token. Both authority
kinds must match the exact selected enrollment route.
Bank middleware must additionally check the subject's actual bank/account relationship.
Neither token classification nor Parliament membership is a wire-format authority arm.
There is no public caller-selected key or fallback to a different provider after a failure.

The policy type is DATA: construction, validation, self-consistent hashing and a matching
signature do not authenticate operator authorization, account routing or current
revocation status. This policy is separate from the platform enrollment policy, so it changes
neither E1 nor credential/circuit bytes. Its Ed25519 key authenticates a middleware observation;
only the existing scheme-rooted Enrollment-role P-256 signer can issue a credential.

Configuration names the canonical template originals as `eligibility_template_hex` and
`enrollment_template_hex`; retired per-asset configuration fields have no decoder fallback.
The private verifier keeps one exclusive store generation and the same attestation counters
across token selections. It joins the old child before switching to the exact retained
asset-specific configuration. Returning to an earlier token reopens that same configuration
and attempt; it cannot reset counters, reuse another token's result or restart a consumed E1.

## Fresh requests and exact responses

Before every pre-key permit (including Resume), E5 verification selection, credential-body
signing selection and E6 delivery (including recovery), the issuer retains a new CSPRNG nonce
and the exact request. The request binds the complete authority-policy digest, canonical
domainless account digest, authenticated actor digest, unchanged enrollment attempt, exact
operation-original digest, closed purpose and trusted creation/exclusive expiry times.
The lifetime cannot exceed the policy's response-time bound. Pre-key and new E5-verification
requests must also remain within the original E1 deadline. Already verified evidence and
exact retained E6 recovery use a new current eligibility interval without restarting E1 or
pretending to perform fresh platform verification; E1 expiry cannot erase a retained result.
The service enforces this phase-dependent deadline; the wire verifier checks the response-time
bound. Exact operation-original selection belongs to the service, not the SDK
caller or mobile app. An eligibility check cannot reset E1 or replace a retained E6.

A retained E5 in the `Verifying` phase may still name an unclaimed worker preparation.
Live recovery that can claim it therefore consumes its own fresh `VerifyEvidence` observation
within E1, bound to the exact retained request. After E1 expiry, the issuer may only use the
private worker's passive `Inspect` action: return the exact retained result, report an unknown
claimed outcome or report unavailable without starting verification. Inspect creates no
credential authority; signing and E6 delivery keep their separate current eligibility checks.

The sole middleware HTTP body is `KagemushaEligibilityObservationV1`: version, exact asset
scope and the retained inner request. It carries no selected policy, key or authority. The
middleware SDK decodes this bounded canonical envelope under its independently configured
template, derives the asset policy and checks the inner policy digest before calling the
clock or lookup. A different asset ID, incarnation, scale or policy revision refuses before
lookup. The Rust callback receives the exact asset, derived policy and request; the shared
inner request and signed-response protocol still provides nonce and operation binding. Bare
inner requests are not a second middleware transport layout.

Middleware authenticates the calling issuer and resolves actor/account/provider binding using
its current authority records (the bank's customer directory for the bank route). It reads
approval and freeze status atomically from current source records. An operator's explicitly
public-enrollment policy still binds the authenticated account, scheme and current policy;
it is not permission to issue arbitrary monetary value.
Unknown subjects, missing records, failed authentication and unavailable stores produce an
error. A source observation carries a positive audit revision; revision alone permits no cache
hit. Frozen takes precedence over approved. The SDK reads once per request, checks genuine
time before and after the lookup and after signing, and rejects rollback or expiry. The
callback supplies the actual current-read time (not a record's last-update time), bounded by
the before/after samples. A slow callback cannot relabel an earlier observation as later.

The signed response binds the full request digest, one definitive decision (`ApprovedUnfrozen`,
`NotApproved`, `Frozen`), positive source revision, observation time and exclusive validity
deadline. Observation must be at or after request creation and not in the future; validity may
not extend the request. The SDK verifies the actual signer output under the selected key
before returning canonical bytes. Errors and denials cannot become approval.

The issuer rechecks current authority/routing after the response, verifies its exact retained
request and current time, retains the original response and consumes the nonce at the named
durable boundary. Repeated delivery requires a fresh observation, while returning the original
E6 byte for byte. A delivery-time `NotApproved`, `Frozen` or unavailable observation only
withholds that delivery: the issued result, its exact E6 and its quota share stay retained, the
attempt is neither refused nor abandoned, E1 is not restarted and nothing is signed again, and
a later approving observation delivers the same E6 (design §2.4). Eligibility cannot promise
that a bank will never freeze an account after an observation; it is checked at each named
online enrollment boundary. It adds no online call to offline Send/Receive.

## Encoding

Every template, observation envelope, policy, request, response body and response has a unique
first-release Norito schema. Complete frames are capped at 2,048 bytes before decoding under
payload-derived resource limits. Enum discriminants are explicit positive indices; unknown
arms and noncanonical frames reject. There are no extension maps, old-layout decoders or
signature algorithm negotiation. The eight-field provider policy has explicit Bank and
SchemeOperator discriminants 1 and 2; it contains no legal classification field. Actual Rust
measurements are 231-byte policy, 264-byte request and 174-byte signed response frames for
both authorities and every purpose.

Identities and the signing message are SHA-256 over `domain || LE64(frame length) || frame`,
where `frame` is the complete canonical Norito frame and the domains are respectively:

- Policy: `iroha:kagemusha:eligibility:policy:v1\0`.
- Request: `iroha:kagemusha:eligibility:request:v1\0`.
- Response signing message: `iroha:kagemusha:eligibility:response:v1\0` over the response body.

The response signature is canonical Ed25519 over its 32-byte signing message. No payment
Poseidon domain, signer certificate role, proof descriptor or proof bytes change.

## Account-authenticated issuer transport

The optional node issuer accepts `POST /v1/kagemusha/enrollment`. Its sole canonical Norito
request binds the action (`PreKey`, `Evidence`, `Issue` or `Deliver`), exact native dispatch
and, only for Evidence, the exact account-signed E5. Native Torii account authentication covers
the complete envelope, method, route and network. Configuration selects the provider; this
endpoint accepts no caller-selected signer, worker, private path or platform verdict.

Rust callers use `AccountClient::kagemusha().enrollment(&request)`; the explicit blocking
facade exposes the same operation. Both use one bounded asynchronous transport request,
preserve the original bytes and reject a response for another action. A pending response or
transport failure never starts a replacement platform attempt. Recovery reuses the native
originals with fresh HTTP authentication. Permit and E6 response bytes remain transport data
until the native wallet owner verifies and durably admits them. Online enrollment envelopes
have separate fixed bounds (544 KiB request, 264 KiB response); the offline Payment limit
remains 10,000 bytes.

## Component evidence and remaining integration

The generic installed selector now uses one independently signed application release and
asset-independent enrollment templates. A separate bounded registration source must prove a
successful direct Global Register under the installed genesis before it can select the exact
asset, incarnation, scale and consenting reserve. The original CBSI/BPNG selections remain
specific deployment authentication adapters. Neither the generic selector nor the operator
`iroha offline registration-package` command contains a token allowlist or grants enrollment
from caller-supplied metadata. The package command publishes a fresh immutable source only
after native verification; importing it cannot change the installed trust root. TODO: qualify
this new path through actual ledger execution, rebuilt ABI28 C/JNI/Swift/Kotlin artifacts and
wallet reopening. The constructor layout change refuses older native ABI versions.

The actual Rust generator covers both authorities, four purposes and three decisions in
[`enrollment_eligibility_v1_vectors.json`](../fixtures/kagemusha/enrollment_eligibility_v1_vectors.json)
and the new template/observation forms in
[`enrollment_eligibility_template_v1_vectors.json`](../fixtures/kagemusha/enrollment_eligibility_template_v1_vectors.json).
All24 original and24 template cases match Kotlin/JVM frames, digests and signatures; nine
Kotlin tests and one Java consumer pass. The captured Model passes15 eligibility cases
(two explicit maintenance generators ignored) and nine enrollment-policy cases. The initial
four registration tests fail at a compressed public-key fixture; after correction to the
required uncompressed original, all four pass from the refreshed Model executable
(`target/qualification/universal-asset-model-sdk-2`). Their native quorum certificates cover
synthetic execution rows; the actual Core execution tests remain distinct. All original
failures are retained. The generated template is198B, concrete policy231B, inner request264B,
asset-bearing observation344B and signed response174B; each fits the2048B frame cap.

The Rust middleware and HTTP components pass32 cases with zero ignored from the same copied
SDK executable:11 middleware, seven enrollment HTTP, seven Load HTTP and seven pool-lifecycle
cases. They include three distinct assets under one Bank or SchemeOperator template, exact
same-attempt cross-asset refusal, changed template/asset originals, stale or unavailable
observations, freeze priority and clock rollback. Runtime sources and binary remain unchanged.
Independent review of48 actual local compiler depfiles and five build-script outputs excludes
22 concurrent CLI/bridge/mobile changes from this build's inputs, preserving its original
broad source-inconclusive classification. These are executable-bound component results, not
actual provider installation or a complete release candidate. The copied native bridge also
passes66 installed-selection, custody and layout cases with unchanged runtime sources, including
the generic application release and asset-independent session configuration. Rebuilt ABI28
Swift/JNI delivery remains separate.

The regenerated worker originals pass the full214-case Python suite in37.691s with unchanged
source and interpreter pins (`target/qualification/enrollment-inspect/full-suite-6-universal-template`).
This includes A→B→A under one retained generation and refusal of the retired preparation schema.
The platform signatures are synthetic and transport is scripted; real Linux launch and service
deployment remain open.

The node enrollment journal retains each complete request, selected Scheme/policy, signed
response and consumption timestamp in its single atomic attempt record. The index is append-only
under the existing 3 MiB record bound: there is no separate nonce file to lose and recreate, no
eviction and no arbitrary retry-count cap. A consumed nonce cannot succeed again after reopening.
Attempt phase changes invalidate earlier observations; current policy/routing must still be
selected independently at consumption. A crash after consumption requires a fresh observation.
The refreshed copied Core executable passes 13 issuer-service cases and 38 enrollment-journal
cases with no failures or ignores (`target/qualification/enrollment-service-core-current`).
They include the configured SchemeOperator path without a bank or Parliament gate, current
account/actor binding, selection races, freeze/expiry refusal, live recovery versus passive
Inspect and fresh-authorized exact E6 recovery. The build retains its broad source-drift record;
these are executable-bound component results, not whole-checkout qualification. The corrected
universal-template Torii copy passes31 signer, local HTTPS, authentication and process/lifetime
cases (`target/qualification/enrollment-universal-torii-cli-current/issuer-runtime`). Its exact
executable remains unchanged; broad source/runtime drift from the following coordinated
repairs is retained. Actual Linux worker launch and service deployment still require qualification. Local atomicity
does not establish protection against arbitrary rollback of the entire issuer store.

The wire verifier and middleware adapter do not establish a serving issuer. TODO: qualify the
configured provider's transport and authority selection through the journal's durable
eligibility operations and the node enrollment owner. Qualify revocation during lookup,
unavailable provider state, replay/restart, freeze between enrollment steps and exact E6
recovery. A configured operator claiming to represent Parliament must have that authorization;
the claim itself grants no privilege and is not required for other token operators.
No real bank or Parliament authority is bundled in fixtures or selected by default.
