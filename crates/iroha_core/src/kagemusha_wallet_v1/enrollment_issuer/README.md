# Native enrollment issuer boundary

`EnrollmentIssuerV1` owns an existing private attempt journal and the committed
`State`. It accepts a mandatory `EnrollmentIssuerRuntimeV1`; it provides no
permissive implementation or decoder that constructs a session from DATA.

`authenticate` requires actual Torii envelope authentication over the exact
closed action envelope, including the dispatch and any E5 original. Each operation provisionally matches the dispatch routing scope against an
configured provider/app route and compares the exact selected Scheme/app/certificate/manifest/release/origin with the
dispatch. The selected enrollment template derives its concrete policy from the exact asset;
the dispatch policy must equal that derivation. A consistent State view must also contain the account and matching
scheme registration, asset incarnation, scale and balance scope. Aliases and FX
corridor routes do not select enrollment authority. The selected provider independently checks
the account, actor and customer relationship; routing DATA cannot authorize an action.

Pre-key permit, new E5 or live E5 recovery, credential signing, and E6 delivery
each use a new signed provider observation. Its exact operation digest, request,
response and consumed nonce live in the single attempt record. Current routing
and configuration are read again after the response and immediately before
signer or active verifier invocation. The selected runtime must revalidate its
actual custody and generation at use. Missing/unknown results are not denial or
permission to retry a fresh verification.

The first E1, selected E5, captured verification time and retained E6 remain
unchanged. Live recovery can claim only the original prepared request after a
fresh provider check. After E1 expiry, `Inspect` can read a previously retained worker
result but cannot claim a row or verify evidence. Previously verified evidence
may still be signed and exact E6 delivered under fresh current eligibility.
Revoking an old app, certificate or route refuses recovery rather than replacing
its originals.

`[torii.kagemusha_enrollment]` is absent by default. Presence requires explicit
public policy/certificate originals, route pins, an existing journal and trusted
program originals, protected worker store, HTTPS credential and private P-256 signer file. Enrollment and eligibility templates are unsigned DATA selected by current
authenticated operator configuration (`enrollment_template_hex` and
`eligibility_template_hex`). One provider/app configuration can serve independently registered
assets; it is not a token allowlist or registration permission. The bounded middleware
observation envelope carries the exact asset and inner request. Middleware derives its
concrete policy from an independently selected template before any eligibility lookup. A bank provider supplies current bank eligibility;
a Scheme operator supplies its explicitly selected issuer/community/governance policy.
Neither a token classification nor Parliament approval is universally required.

The concrete Torii adapter mounts `POST /v1/kagemusha/enrollment` with a bounded
Norito envelope and existing exact-network account authentication. Its dedicated
service thread owns the journal, blocking HTTPS client, signer and private worker
through destruction. Accepted commands finish before custody is released; a lost
HTTP response does not reset a consumed E5. Configuration is the authenticated
startup selection until node restart, with exact custody checks on every boundary.
Emergency Fast recovery does not open this optional service.

The private worker currently supports Linux only. It selects exact configured
Python/zipapp/OpenSSL originals and inherits retained descriptors and an existing
exclusive worker generation; no missing counter store is initialized by serving
startup. Asset-specific verifier configurations are derived from the selected template,
retained by exact digest, and selected serially. The old child fully joins before a switch;
the same exclusive generation lock and counter store remain held. Retained preparations,
E5 and results remain bound to their original configuration. These pins do not attest the interpreter/system dependency closure.
The OS, standard library, dynamic loader and TLS roots remain trusted deployment
components. Signer custody uses only the canonical 32-byte P-256 scalar original,
with rooted Enrollment-certificate binding and revalidation around actual signing.

TODO: qualify the complete Linux launch and real platform evidence through this
serving path, together with node shutdown and network integration. Component
unit runtimes use explicit DATA and real test-key signatures for ordering and
refusal; they establish no device or deployed-service qualification.
