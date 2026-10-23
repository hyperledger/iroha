<!--
  SPDX-License-Identifier: Apache-2.0
-->

# Multisignature Controller Schema v1 (ADDR‑1c)

This note is the canonical reference for the multisignature controller payload
used by the Sora Name Service. It formalises the CTAP2 CBOR map and documents
the validation rules enforced by
`MultisigPolicy::validate()`, and records the golden fixtures that SDKs and
operations teams rely on when reproducing controller hashes.

## Deterministic CTAP2 map

`AccountController::Multisig` policies are serialised as a CTAP2-style CBOR map
with integer keys. The layout mirrors the on‑chain payload; the CBOR form is
used solely for hashing/signing and never appears inside the address envelope.

- Maps are definite-length (`0xA3`) and omit optional fields entirely.
- Integer fields are encoded big-endian using the smallest width that fits
  (`cbor_write_unsigned` in `crates/iroha_data_model/src/account/controller.rs`).
- Member maps are emitted in canonical order; duplicate keys are rejected
  during validation prior to serialisation.

The structure can be expressed in CDDL as:

```text
ms-policy = {
  1: ms-version,   ; always 1 until a new policy version rolls out
  2: ms-threshold, ; approval weight required (uint16)
  3: [* ms-member] ; definite-length array
}
ms-version = 1
ms-threshold = uint .size 2

ms-member = {
  1: curve-id,          ; matches specs/references/address_curve_registry.md
  2: member-weight,     ; uint16 > 0
  3: bytes ; canonical raw PublicKey payload for the registered algorithm
}
curve-id = uint .size 1
member-weight = uint .size 2
```

`MultisigPolicy::encode_ctap2()` is the only supported encoder and is the source
of truth for the map layout.

## Validation invariants

Policies are normalised and validated before they can be embedded into an
account address:

| Rule | Notes / source | Failure mode |
|------|----------------|--------------|
| `version == MultisigPolicy::CURRENT_VERSION (1)` | Ensures all nodes agree on semantics before accepting a policy. | `MultisigPolicyError::UnsupportedVersion` |
| `1 <= threshold <= Σ member.weight` | Enforcement happens after deduplication so callers cannot bypass the check by repeating members. | `ZeroThreshold` or `ThresholdExceedsTotal` |
| `1 <= members.len() <= CONTROLLER_MULTISIG_MEMBER_MAX (65,535)` | `CONTROLLER_MULTISIG_MEMBER_MAX` is the `u16` member-count limit shared with the binary controller encoding documented in `specs/account_structure.md`. | `EmptyMembers` or `AccountAddressError::MultisigMemberOverflow` |
| Member weight ≥ 1 | Enforced inside `MultisigMember::new`. | `MemberWeightZero` |
| Every member uses a canonical `Algorithm` / `CurveId` identity | The total registry is feature-independent; address decoding rejects only unassigned curve IDs as unknown. | `AccountAddressError::UnknownCurve` for an unassigned ID |
| Members are deduplicated after canonical sorting by `(algorithm_string || 0x00 || key_bytes)` | Prevents equivalent public keys from inflating total weight; the canonical order feeds directly into CTAP2 encoding. | `DuplicateMember` |

These are structural controller invariants. Ordinary account admission separately
requires every member algorithm in the committed
`CryptoAdmissionPolicyV1.allowed_algorithms` set. Curve permissions are derived
from that one set; BLS members have no blanket exemption. `MultisigPolicy::validate`
does not consult node-local configuration or claim that a local backend exists.

A known algorithm with an absent parser or verifier produces a typed
`UnsupportedImplementation { algorithm, operation }` at the native boundary.
Immediate Norito adapters retain `UnsupportedFeature`; this is distinct from an
unknown curve, a failed signature relation, and an original local resource
refusal. Complete service/SDK propagation requires separate qualification.

These invariants ensure every controller hash is deterministic regardless of the
host language. SDKs must surface the same validation errors so users receive
early feedback before Torii admission rejects the payload.

## Controller registration

`MultisigRegister` still requires callers to supply the `account` field, but the
on-chain controller id is derived from the multisig spec. Registration rekeys
the supplied account to the canonical `AccountController::Multisig` identifier
computed from the spec once validation succeeds.

- Tooling may still mint a fresh keypair for the `account` field and discard the
  private key, because multisig controllers never sign transactions directly.
- Newly registered controllers persist `multisig/spec` metadata and are rekeyed
  to the canonical multisig account id.
- Signatories do not have to be pre-registered. Missing signatory accounts are
  materialized during successful `MultisigRegister`/`AddSignatory` execution and
  tagged with `iroha:created_via = "multisig"` metadata.
- JSON decoding errors when the `account` field is omitted, so clients must send
  it even though the final account id is deterministic.
- Signatories must be single-key accounts; nested multisig controllers are
  rejected.

## Deterministic digest

To sign or compare policies, hosts compute a Blake2b‑256 MAC over the CTAP2
payload with an empty key/salt and the personalisation string
`"iroha-ms-policy"`. The implementation in
`MultisigPolicy::digest_blake2b256()` is:

```rust
pub fn digest_blake2b256(&self) -> [u8; 32] {
    let encoded = self.encode_ctap2();
    let mut mac = Blake2bMac::<U32>::new_with_salt_and_personal(
        &[],
        &[],
        b"iroha-ms-policy",
    )
    .expect("personalised Blake2b parameters must be valid");
    Mac::update(&mut mac, &encoded);
    mac.finalize().into_bytes().into()
}
```

The digest is stable across languages as long as the CBOR encoder and
validation invariants above are respected. Empty-personalisation Blake2b
hashes are rejected explicitly to avoid accidental data drift.

## Golden policies

Three deterministic policies ship with the address compliance vectors and offer
fixture coverage for both the CTAP2 payloads and the digests. The canonical JSON
lives in `fixtures/account/address_vectors.json`.

| Case ID | Threshold | Members (curve, weight) | `ctap2_cbor_hex` | `digest_blake2b256_hex` |
|---------|-----------|-------------------------|------------------|-------------------------|
| `addr-multisig-council-threshold3` | 3 | `(1,1) · (1,1) · (1,2)` | `0xA3010102030383A30101020103582068F4B6017D0F876A55C80A82B8388A54AAD264D367269E2DE8BE079C935B5F96A3010102010358207EA0E3BD52E207C9D3B0EBA65C0704E66FCA2D8E165A175218B174FC4160E413A301010202035820884B8857F4EAA1613C61504DB34D4BEAF346517A0E31DE3CDDD4D9B4201D9D0B` | `0x3CA0D464D52713DD60DDAA55B3B3F49A6EF114574864E2AADE63114C4DB06B9F` |
| `addr-multisig-wonderland-threshold2` | 2 | `(1,1) · (1,2)` | `0xA3010102020382A3010102010358205C9C6DF261C9CB840475776AAEFCD944B405328FAB28F9B3A95EF40490D3DE84A301010202035820D04AB232742BB4AB3A1368BD4615E4E6D0224AB71A016BAF8520A332C9778737` | `0xCDEFCDA0C30A91D0B2F2E4A9885A86A990D285B4E200AA0131E545C865C2E563` |
| `addr-multisig-default-quorum3` | 3 | `(1,1) · (1,1) · (1,1) · (1,1)` | `0xA3010102030384A30101020103582065E8F9B0BC6EAE124169F0576F97362D295A8CF5F770B45E14357CE647D33EECA301010201035820ACF12B4ACC1C660A8326AED34039EFB728A5E496488240F50A932AB7ABA51751A301010201035820B533D8AD9FCFBDDE0B481C1B334DDC3C53412FD614564E7E5AFD020368D382C3A301010201035820BC7CBCB5636375FA1D82434D466724D92377F53B980695DD49D26D0CE12205A5` | `0xB32B7CEA6AE24A0E6746B5450392814A6E0A00CF645CD2FB9D2ECF03D88C0C1D` |

Consumers should assert both strings when verifying their own encoders; the
fixtures back the Rust, JS, Swift, and Android SDK tests as well as the Torii
admission suites.

## Verification workflow

| Step | Command | Purpose |
|------|---------|---------|
| Generate/verify fixtures | `cargo xtask address-vectors --out fixtures/account/address_vectors.json` or `cargo xtask address-vectors --verify` | Regenerates the canonical JSON, including the multisig CTAP2 payloads and digests, or checks that the committed file matches the generator. |
| Inspect payloads ad hoc | `cargo run -p iroha_data_model --example account_address_vectors | jq '.cases.positive[] | select(.category == "multisig")'` | Dumps the same JSON without writing to disk for quick experiments. |
| Host validation tests | `crates/iroha_data_model/tests/account_address_vectors.rs` | Ensures `AccountController` parsing + multisig hashing match the fixtures. |

## References

- Binary controller encoding: [`specs/account_structure.md`](../account_structure.md#23-controller-payload-encodings-addr-1a)
- Canonical curve registry: [`specs/references/address_curve_registry.md`](address_curve_registry.md)
- Implementation: [`crates/iroha_data_model/src/account/controller.rs`](../../crates/iroha_data_model/src/account/controller.rs)
- Compliance fixtures: [`fixtures/account/address_vectors.json`](../../fixtures/account/address_vectors.json)
