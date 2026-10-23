---
title: Account Curve Registry
description: Canonical account-controller identities, committed admission policy, and local implementation capabilities.
---

# Account Curve Registry

`iroha_crypto::Algorithm::ALL` and `account::curve::CurveId` define the same
11 first-release signing identities in every build. Algorithm wire tags and
account curve IDs are different mappings; `CurveId::from_algorithm` is total.
Optional backends do not remove identities from binary decoding, JSON names,
address tags, or schema metadata. Unknown curve IDs still fail with
`ERR_UNKNOWN_CURVE`.

| Curve ID | Algorithm | Optional implementation | Public-key bytes | Signature bytes |
|----------|-----------|-------------------------|------------------|-----------------|
| `0x01` | `ed25519` | none | 32 | 64 |
| `0x02` | `ml-dsa` | `pqc` for private-key operations and verification | 1952 | 3309 |
| `0x03` | `bls_normal` | `bls` | 48 | 96 |
| `0x04` | `secp256k1` | none | 33 | 64 |
| `0x05` | `bls_small` | `bls` | 96 | 48 |
| `0x0A` | `gost3410-2012-256-paramset-a` | `gost` | 64 | 64 |
| `0x0B` | `gost3410-2012-256-paramset-b` | `gost` | 64 | 64 |
| `0x0C` | `gost3410-2012-256-paramset-c` | `gost` | 64 | 64 |
| `0x0D` | `gost3410-2012-512-paramset-a` | `gost` | 128 | 128 |
| `0x0E` | `gost3410-2012-512-paramset-b` | `gost` | 128 | 128 |
| `0x0F` | `sm2` | `sm` | 2 + DistID bytes + 65 | 64 |

The [JSON registry](address_curve_registry.json) records the same geometry.
Its `feature` field describes an implementation dependency, not whether the
identity exists or an account is permitted. Geometry is necessary but does not
establish a valid key or signature; callers must use the canonical parser and
actual verifier. ML-DSA public-key framing validation remains available without
`pqc`; its signature verifier does not.

## Committed admission and local capability

Ordinary account and multisignature admission uses the single
`CryptoAdmissionPolicyV1.allowed_algorithms` set from committed State parameters.
Permitted curves are derived through `CurveId::from_algorithm`; there is no
separate mutable curve allowlist and no node-local configuration fallback.
BLS account controllers follow this policy without a blanket exemption.
Consensus key requirements are a separate protocol constraint.

The signed genesis source supplies the initial policy before State is
initialized. The bootstrap owner must authenticate that exact source and retain
its policy through execution; absence is not permission to use local defaults.
This ownership belongs to the committed-policy implementation, rather than the
identity registry or address decoder.

A known identity may lack a local implementation. Native constructors and
verifiers retain `UnsupportedImplementation { algorithm, operation }`;
`Algorithm::require_implementation` provides the same explicit capability check.
This is distinct from malformed encoding, an invalid signature relation, and an
original local resource refusal. Immediate Norito binary/JSON adapters preserve
`UnsupportedFeature`; address decoding uses `ERR_UNSUPPORTED_IMPLEMENTATION`
for that category. It must not become `ERR_UNKNOWN_CURVE` or a false signature.
Backend availability does not filter or invalidate the committed policy.

## Validation and qualification

- Resolve the canonical identity without consulting local build features.
- Apply the committed policy at its authoritative admission owner.
- Validate the canonical key/signature envelope and run the required actual
  cryptographic relation; an absent implementation cannot authorize acceptance.
- Preserve typed local resource refusals without relabeling them as protocol
  invalidity or missing implementation.

The model tests require every registry entry to round-trip in every feature
configuration. Crypto tests separately cover fixed unsupported diagnostics,
unchanged valid/invalid verification, and original decoder resource refusals.
TODO: qualify all outer SDK/FFI and service error adapters on the final composed
source; these component checks do not establish their end-to-end classification.


### SDK address error categories

Canonical algorithm names and numeric curve IDs are recognized independently of
compiled crypto backends. Swift, Kotlin and JavaScript accept the exact canonical
names above; aliases and case folding are not protocol identities. An unknown
text name is `ERR_UNKNOWN_ALGORITHM`; an unknown numeric ID is
`ERR_UNKNOWN_CURVE`. A recognized identity whose requested native operation is
absent is `ERR_UNSUPPORTED_IMPLEMENTATION`, with the native algorithm and operation
retained at typed boundaries. Invalid key material remains `ERR_INVALID_PUBLIC_KEY`.
The authenticated native controller validator remains mandatory.

The address JNI boundary throws a structured Kotlin-owned exception before error
text is rendered into a public SDK diagnostic. This preserves the fixed category
and original capability fields; it does not close the separate native input/output
allocation and retry-custody gaps. Java duplicate implementation retirement remains
tracked by the JVM consolidation inventory; this change adds no Java implementation.
