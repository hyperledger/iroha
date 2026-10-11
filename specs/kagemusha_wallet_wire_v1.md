# KAGEMUSHA wallet wire record V1

**Status.** This record describes the canonical G1 wire objects of the single
KAGEMUSHA split-lineage design ([proposal](kagemusha_single_design_proposal.md)
§§3, 3.1, 3.2, 4.1, 5.1, 7 and 8; §10, G1). They are implemented in
`iroha_data_model::kagemusha::kagemusha_wallet_v1`
(`crates/iroha_data_model/src/kagemusha/kagemusha_wallet_v1.rs` and its child
files). Their cross-language vectors are `fixtures/kagemusha/wallet_v1_vectors.json`.
Kotlin `org.hyperledger.iroha.sdk.offline.KagemushaWalletWireV1` (`kotlin/core-jvm`)
and Swift `KagemushaWalletWireV1` (`IrohaSwift`) consume the vectors, and the Swift and
Kotlin peer carriers move envelope frames, the Lineage message included (§6). The Durable
State Provider binds the operation-dependent `proof_digest` (§3.2); the protocol
relations, the bridge, the ledger instructions and the Torii routes do not use these
objects yet. The owner answers of 2026-10-05 (proposal revision 2026-10-05) are
implemented: the data model depends on `iroha_pasta` and computes every Poseidon value
natively (`credit_id`, the state commitment, chains, map, blacklist, quota-window and
credit-digest trees and openings, and the packed-byte `proof_digest` and Payment
digest). Proof bytes, relation bindings, verifying keys and the lineage roots of the
Payment's Ω(pred) in the vectors are labelled stand-ins; map roots, credit-digest roots
and openings are computed.

The second set of owner answers of 2026-10-05 is specified here and not yet
implemented (TODO(G1)): the Poseidon signing message and the remaining SHA-256 roles
(§1), the `P_bytes` lineage, credit-opening, credit-status and credited digests (§§1,
3.2, 3.4), the depth-32 indexed map trees and their openings (§3.2), the limb-ordered
blacklist and two-sided blacklist enforcement (§§3.3, 3.4), the Request account
digests (§3.4), the Receive verifying-key selector (§3.1) and the vector consistency
rules (§5). For these items this record governs, and the code and vectors change
together to match it. Elsewhere the code is authoritative; a change to it updates this
record and the vectors together.

Notation: `‖` is concatenation; `LE16`…`LE128` are little-endian unsigned
integers; every name without a width is a raw 32-byte digest, identifier, nonce or
σ-field value, and all-zero means "none"; `key` is a 65-byte uncompressed SEC1 P-256
key (`0x04 ‖ X ‖ Y`, on the curve); `sig` is a 64-byte big-endian `r ‖ s`; `tag` is
one byte. Numbers in parentheses are exact transcript lengths, pinned by tests.
"Design only" marks a rule these objects do not enforce or test.

## 1. Digests, transcripts and signatures

```text
H(role, body) = SHA-256("iroha:kagemusha:wallet:v1:" ‖ role ‖ 0x00 ‖ LE64(len(body)) ‖ body)
```

The 26-byte prefix is `69726f68613a6b6167656d757368613a77616c6c65743a76313a` and
`role` is an ASCII label below. Check value: `H("scheme", empty)` =
`90882608a8e8892521a2661be1e81c3fbfca0f8773e621000daed362a37485a5`.

**Poseidon** (proposal §3). `P(domain, items)` is the RP57 Poseidon
`iroha_pasta::poseidon::hash_with_domain::<Fp>(domain, items)` over the σ field of §3.2:
a fresh sponge absorbs `[domain, len(items), items…]` and its value is one canonical
σ-field element. `P_bytes(domain, b) = P(domain, [len(b)] ‖ c_0 ‖ … ‖ c_(m−1))`, where
`len(b)` is the byte length as one element, `m = ⌈len(b) / 31⌉` and `c_i` is bytes
`31i … 31i + 30` of `b` read as a little-endian integer, the last chunk zero-filled; every
chunk is below `2^248`, and the length element separates inputs whose chunks agree. `P`
covers `credit_id` (§3.4), the state commitment, rest digest, chains, σ statement digest,
the indexed map trees and the credit-digest tree (§3.2), and the blacklist and
quota-window trees (§3.3); `P_bytes` covers `proof_digest` in both domains (§3.2), the
Payment digest, the lineage, credit-opening, credit-status and credited digests (§3.4),
and every signed message (below). The vectors pin every domain, the packing at the empty
input and the 31-byte chunk boundaries, and every value (§5).

- **Transcripts.** A body is a fixed-layout transcript of the object's fields in
  declaration order: fixed-width integers, raw digests, keys and signatures, and
  enums as a one-byte tag equal to the Norito tag. Where variants differ, the tag
  is followed by the variant's fields and zero fill to a pinned union width. Nested
  fixed records are inlined. A reference to a signer certificate is its 32-byte
  certificate digest. Only the `account`, `certificate-set`, `evidence`,
  `verifying-key-set`, `marker`, `capsule`, `completion` and `fold` roles and the
  lineage digest have variable-length bodies.
- **Signing** (TODO(G1)). Every P-256 signature of the protocol signs, as its message,
  the 32-byte canonical encoding `m` of `P_bytes(d, transcript)`, where `d` is the
  body's signing domain in the table below, with standard ECDSA-P256 over SHA-256: the
  ECDSA message hash is `SHA-256(m)`, one SHA-256 block in circuit. The Secure Enclave
  signs `m` with `kSecKeyAlgorithmECDSASignatureMessageX962SHA256`, Android KeyMint with
  a `DIGEST_SHA256` key through `SHA256withECDSA`, and issuer, policy, ledger and
  artifact signers with the same ECDSA-P256-SHA256; no-digest modes (`NONEwithECDSA`,
  `kSecKeyAlgorithmECDSASignatureDigestX962*`) are never used. The core computes `m`
  and hands exactly those 32 bytes to a platform signer. A fresh output, strict DER or
  raw `r ‖ s`, is normalized to low S and verified under the expected key before it is
  frozen into an object; an output that does not verify is rejected.
- **Verifying.** A verifier recomputes `m` from the transcript, then verifies ECDSA
  over `m`. Only the fixed 64-byte `r ‖ s` with `1 ≤ r < n` and
  `1 ≤ s ≤ floor(n/2)` is accepted. High S, out-of-range scalars and other
  encodings are rejected; received bytes are never rewritten. JCA and CryptoKit
  accept high S, so SDKs apply the raw low-S check first.
- **Object digest.** `H(<x>, m ‖ sig)` (96-byte body). A signature confers only its
  signer role's authority; decoding or validating grants no monetary authority.

Signed bodies (17; the transcript of each is in the section named, and the `-body`
SHA-256 roles do not exist):

| Signed body | Signing domain `d` | Transcript bytes | Signer | Object-digest role |
|---|---|---:|---|---|
| certificate (§3.1) | `kgwcert1` | 108 | scheme root | `certificate` |
| credential (§3.1) | `kgwcred1` | 476 | Enrollment | `credential` |
| renewal challenge (§3.1) | `kgwrnch1` | 130 | payment key | none |
| renewal key binding (§3.1) | `kgwrnkb1` | 163 | payment key | none |
| artifact manifest (§3.1) | `kgwartf1` | 290 | Artifact | `artifact-manifest` |
| receipt τ (§3.2, derived, never transmitted) | `kgwrcpt1` | 338 | payment key | `receipt` |
| scheme policy (§3.3) | `kgwspol1` | 142 | RegulatoryPolicy | `scheme-policy` |
| fee schedule (§3.3) | `kgwfsch1` | 191 | RegulatoryPolicy | `fee-schedule` |
| blacklist (§3.3) | `kgwblst1` | 118 | RegulatoryPolicy | `blacklist` |
| quota share (§3.3) | `kgwqshr1` | 190 | RegulatoryPolicy | `quota-share` |
| time anchor (§3.3) | `kgwtanc1` | 138 | TimeAnchor | `time-anchor` |
| charge quote (§3.3) | `kgwchgq1` | 219 | RegulatoryPolicy | `charge-quote` |
| offer (§3.4) | `kgwoffr1` | 194 | payer payment key | none |
| session control (§3.4, when signed) | `kgwsctl1` | 197 | session payment key | none |
| request (§3.4) | `kgwrqst1` | 418 | receiver payment key | `request` |
| load voucher (§3.6) | `kgwvchr1` | 250 | LoadAuthorization | `voucher` |
| ledger control (§3.6) | `kgwlctl1` | 211 | payment key | none |

SHA-256 role table (all 34 labels of `KagemushaWalletDigestRoleV1`). `H` remains only
for small fixed bodies that no relation recomputes over a large input, and at ledger,
HTTP, platform-attestation and artifact boundaries:

| Role | Body | Bytes | Why SHA-256 |
|---|---|---:|---|
| `scheme` | scheme transcript (§3.1) | 163 | fixed identity; ledger and artifact boundary |
| `relation` | relation transcript (§3.1) | 162 | fixed identity; artifact boundary |
| `provider-contract` | `LE16 1 ‖ "kagemusha-advance-journal-marker-v1"` zero-padded to 64 | 66 | constant |
| `asset-scope` | asset scope transcript (§3.1) | 54 | fixed identity; ledger boundary |
| `account` | complete canonical Norito frame of the domainless `AccountId` | var | ledger boundary; the ledger derives it from the `AccountId` |
| `enrollment-challenge` | §3.1 | 194 | platform-attestation challenge, used only by the issuer |
| `enrollment-id`, `enrollment-key-binding` | `challenge_digest ‖ payment_key` | 97 | fixed identity; App Attest client data |
| `wallet-id` | `scheme_id ‖ asset_digest ‖ payment_key ‖ enrollment_id` | 161 | fixed identity |
| `certificate`, `credential`, `artifact-manifest`, `receipt`, `scheme-policy`, `fee-schedule`, `blacklist`, `quota-share`, `time-anchor`, `charge-quote`, `request`, `voucher` | `m ‖ sig` of the signed body above | 96 | fixed object digest |
| `certificate-set` | `LE32 count ‖ certificate digests in set order` | 4+32n | at most 100 bytes |
| `evidence` | `tag kind ‖ LE32 count ‖ (LE32 len ‖ original bytes)…` | var | raw platform attestation, used only by the issuer |
| `renewal-assertion` | renewal transcript (§3.1) | 130 | App Attest client data |
| `verifying-key-set` | verifying-key allowlist (§3.1) | 42+41n | artifact boundary, bound through the relation identity |
| `statement` | §3.2 | 440 | fixed transcript |
| `package` | `statement_digest ‖ proof_digest ‖ receipt_digest` | 96 | fixed transcript |
| `operation-id` | `wallet_id ‖ tag operation_kind ‖ input` | 65 | fixed transcript |
| `unload-nullifier` | `scheme_id ‖ wallet_id ‖ LE128 redeem_ordinal` | 80 | fixed transcript; ledger boundary |
| `output` | `tag operation_kind ‖ statement_digest ‖ proof_digest ‖ payment_digest or zero` | 97 | local; no relation recomputes it |
| `marker`, `capsule`, `completion`, `fold` | complete canonical Norito frame of the local object (§3.5) | var | local custody record; no relation recomputes it |

`credit_id`, `proof_digest`, the Payment digest, the lineage, credit-opening,
credit-status and credited digests, every signed message, map values, leaves and roots,
chains, the state commitment, the σ statement digest and the blacklist, quota-window and
credit-digest trees are not SHA roles: they are `P` or `P_bytes` values under the domains
of this section and §3.2.

## 2. Canonical frames and bounds

Canonical bytes are one complete `norito::encode_canonical` frame ([Norito](../norito.md)):

| Offset | Bytes | Content |
|---:|---:|---|
| 0 | 4 | magic `NRT0` (`4e525430`) |
| 4 | 2 | major `0`, minor `0` |
| 6 | 16 | schema hash: first 16 bytes of `SHA-256("norito:v1:type-name" ‖ 0x00 ‖ frame name)` |
| 22 | 1 | compression `0` |
| 23 | 8 | payload length, `LE64` |
| 31 | 8 | CRC-64/XZ of the payload, little-endian |
| 39 | 1 | flags `0x02` (`COMPACT_LEN`) |
| 40 | p | zero alignment padding |
| 40+p | len | payload |

- The frame name is `iroha_data_model::kagemusha::kagemusha_wallet_v1::<Type>`; the
  vectors pin the name and schema hash of all 26 framed types (envelope:
  `f03a9dc47142299cad9ffe0b2115fd42`).
- `p` is a property of the type, never inferred from the bytes. It is 8 when a
  `u128` is reachable without passing through a sequence (archived alignment 16;
  the envelope payload starts at byte 48), and 0 otherwise. The table below lists
  it per type. `armv7` is not an admitted native target: its `u128` alignment would
  change the padding.
- Payload (Norito derived layout under `COMPACT_LEN`): a record is its fields in
  declaration order, each `varint len ‖ payload`; integers are little-endian fixed
  width; a `bool` is one byte; a digest field is `0x20 ‖ 32 bytes`, a key
  `0x41 ‖ 65 bytes`, a signature `0x40 ‖ 64 bytes`; an enum is an `LE32` tag (equal
  to the transcript tag) followed by its variant's fields, each length-prefixed;
  `Vec<u8>` is `LE64 count ‖ bytes`; any other sequence is
  `LE64 count ‖ (varint len ‖ element)…`. `AccountId` and `AssetDefinitionId` use
  their own canonical encodings.
- **Decode order** for every framed type: (1) the complete-frame byte cap, before
  any parsing (10,000 for any envelope); (2) canonical decode under
  payload-derived limits (header, schema, flags, padding, CRC, exact length and
  canonical re-encoding); (3) every version
  field equals 1, outer value first, so a nested foreign body reports a version
  error, not a scheme mismatch; (4) envelopes only: the per-kind bound; (5) the
  expected scheme (expected wallet for a completion record); (6) structural
  validation. Decoding verifies the signatures whose keys the frame carries;
  certificate root, issuer and policy-signer signatures are checked by
  `verify(scheme, …)`, except that a certificate frame decodes against its scheme
  root. Payment, Credited and Lineage are validated structurally at decode; their
  full verification takes the session's inputs (§3.4).
- Flipping any byte of a vector Credential, Certificate, Offer, Request, Payment,
  Credited (both forms), Lineage, FoldRecord, Package, LoadVoucher, SchemePolicy,
  FeeSchedule, Blacklist, QuotaShare, TimeAnchor, ChargeQuote, LedgerControl or
  ArtifactManifest frame fails decoding or validation, or changes the object digest
  (tested). The quota share and blacklist digests cover only body and signature;
  the body's root and count bind the carried windows and entries. State,
  commitments, anchored time, unsigned session controls and renewal evidence bytes
  have no such binding.

| Bound | Value |
|---|---:|
| Envelope, Offer and SessionControl (complete frame) | 2,048 |
| Envelope, Request, Payment, Credited, PolicyData and Lineage | 10,000 |
| `kgm1:` text, session / message | 2,736 / 13,339 |
| Nested payer credential of an Offer (complete frame) | ≤ 1,024 |
| σ bytes and Ω transport-proof bytes | ≥ 1; the exact lengths of the frozen verifying-key allowlist (§3.1), with Ω + the largest σ_send ≤ 8,319 = 10,000 − F_payment (F_payment = 1,681, §4) and Ω ≤ 7,812 = 10,000 − F_status (F_status = 2,188, §4); until it freezes only the carrying frame |
| Map and credit-digest opening siblings | exactly 32 (§3.2) |
| Verifying-key allowlist entries | 8..=16 (one per operation; Send also per enabled-controls mask; Receive also with the blacklist bit) |
| Certificates per set | ≤ 3 |
| Blacklist entries | ≤ 65,535 |
| Quota windows per share | 1..=64 |
| Android renewal chain: certificates; each DER; total DER | 2..=8; 1..=16,384; ≤ 65,536 |
| App Attest renewal assertion | 1..=4,096 |
| Completion record output bytes | 1..=10,000 |
| Asset scale; fee basis points | ≤ 28; ≤ 10,000 |

Standalone frame caps (complete frame, checked before decoding) and padding:

| Type | Cap | p | Type | Cap | p |
|---|---:|---:|---|---:|---:|
| `SchemeV1` | 512 | 0 | `PaymentV1` | 10,000 | 8 |
| `SignerCertificateV1` | 512 | 0 | `PackageV1` | 10,000 | 8 |
| `CredentialV1` | 1,024 | 0 | `MarkerV1` | 1,024 | 8 |
| `RenewalRequestV1` | 73,728 | 0 | `RecoveryCapsuleV1` | 262,144 | 8 |
| `ArtifactManifestV1` | 1,024 | 0 | `CompletionRecordV1` | 65,536 | 0 |
| `VerifyingKeyAllowlistV1` | 2,048 | 0 | | | |
| `SchemePolicyV1` | 1,024 | 0 | `FoldRecordV1` | 10,000 | 8 |
| `FeeScheduleV1` | 1,024 | 8 | `LoadVoucherV1` | 1,024 | 8 |
| `BlacklistV1` | 2,228,736 | 0 | `UnloadClaimV1` | 16,384 | 8 |
| `QuotaShareV1` | 8,192 | 0 | `FeeClaimV1` | 16,384 | 8 |
| `TimeAnchorV1` | 512 | 0 | `LedgerControlV1` | 1,024 | 8 |
| `ChargeQuoteV1` | 1,024 | 8 | `ActivationV1` | 16,384 | 8 |
| `EnvelopeV1` | per kind | 8 | `CloseLoadsV1` | 16,384 | 8 |
| | | | `AbandonmentV1` | 1,024 | 8 |

Type names omit the `KagemushaWallet` prefix. The blacklist cap is
`65,536 × 34 + 512`: each canonical entry takes 34 bytes. The blacklist is not a
peer message: a wallet downloads it only while online, from the issuer or ledger,
as this standalone frame, and peers never relay it, so its size does not bear on
the envelope bounds. The package cap applies where a completion record's output is
decoded as a package. The fold record carries one Ω, so it takes the Lineage
message bound.

**Text.** `kgm1:` followed by unpadded base64url of one canonical envelope frame.
Decoding rejects text above 13,339 bytes, a missing prefix, an empty body,
characters outside `A–Z a–z 0–9 - _` (so padding and whitespace), a body length of
`1 mod 4`, and text that does not re-encode to itself; the frame then follows the
decode order above.

## 3. Objects

Unless stated, a signed object's frame is `{body, signature}`, and its transcript
is the body's fields in the order shown.

### 3.1 Identity, certificates, credential, enrollment, renewal, artifact manifest

| Object | Fields in transcript order | Interoperability rules |
|---|---|---|
| Scheme (`scheme`) | `LE16 version ‖ network_id ‖ scheme_root_key(key) ‖ relation_id ‖ provider_contract` | `scheme_id = H("scheme", ·)`. `network_id` is the raw genesis `NetworkId`, carries the Iroha hash marker (last byte odd) and is not the marked zero `00…01`; `relation_id` nonzero; `provider_contract` is the V1 constant. Decoding requires the recomputed `scheme_id`. The root key signs certificates only. |
| Relation (`relation`) | `LE16 1 ‖ eq_protocol_digest ‖ ep_protocol_digest ‖ native_profile_digest ‖ verifying_key_set_digest ‖ artifact_inventory_digest` | Gives `relation_id`, fixed for the scheme's lifetime: one scheme-level identity that every statement and Ω carries. `verifying_key_set_digest` is the `verifying-key-set` digest of the verifying-key allowlist (below). |
| Verifying-key allowlist (`verifying-key-set`) | `LE16 version ‖ LE32 n ‖ n × (tag kind ‖ LE32 enabled_controls ‖ verifying_key_digest ‖ LE32 proof_bytes) ‖ lineage_verifying_key_digest ‖ LE32 lineage_proof_bytes` | Frame `{version, steps: [{kind, enabled_controls, verifying_key_digest, proof_bytes}], lineage_verifying_key_digest, lineage_proof_bytes}`. One σ entry per selector, strictly ascending by `(tag, mask)`, at most 16: every operation with mask 0, Send also once per supported enabled-controls mask (defined bits only), and Receive also once with mask 1 (BLACKLIST) exactly when some Send mask has bit 0; digests nonzero; lengths at least 1, σ at most 10,000. `lineage_proof_bytes` plus the largest Send `proof_bytes` is at most 8,319 (R9), and `lineage_proof_bytes` is at most 7,812 (the Credited bound with the fixed opening; §2, §4). A consumer selects σ's entry by the package's operation tag; for Send also by its mask (`Ω.enabled_controls`), and for Receive also by bit 0 of the statement's `enabled_controls` (selector `(Receive, enabled_controls & 1)`). It requires σ and Ω(pred) to have exactly the listed lengths. The Receive entry, the 8,319 budget and the 7,812 cap are TODO(G1). The frame decodes only against a manifest body whose `verifying_key_set_digest` it recomputes. |
| Provider contract | see §1 | Constant `52b501e3344547c36579684aafb2b15eb0caf3393e77aebdfbaa14ac57d0cc8d`. |
| Asset scope (`asset-scope`) | `LE16 version ‖ asset UUID (16) ‖ asset_incarnation ‖ LE32 scale` | Frame `{version, asset: AssetDefinitionId, asset_incarnation, scale}`. UUIDv4 asset, valid `AxtAssetIncarnationV1`, `scale ≤ 28`. Gives `asset_digest`. |
| Signer certificate (signed under `kgwcert1`) | `LE16 version ‖ scheme_id ‖ tag role ‖ key ‖ LE64 serial` | Signed by the scheme root. Roles: Enrollment 1, LoadAuthorization 2, RegulatoryPolicy 3, TimeAnchor 4, Artifact 5. Fixed depth one; no validity period or revocation is evaluated offline; the consumer requires the role it needs. |
| Certificate set (`certificate-set`) | `LE32 count ‖ certificate digests` | Frame `{certificates}`: at most 3, unique, strictly ascending by certificate digest (unsigned byte order). Each carrier holds exactly the certificates it needs, with the required roles and scheme. |
| Enrollment challenge (`enrollment-challenge`) | `LE16 version ‖ scheme_id ‖ asset_digest ‖ account_digest ‖ app_policy ‖ enrollment_policy ‖ issuer_nonce` | All nonzero. `challenge_digest` is the KeyMint attestation challenge and the App Attest attestation `clientDataHash`. The App Attest enrollment assertion `clientDataHash` is `H("enrollment-key-binding", challenge_digest ‖ payment_key)`. H values go to App Attest unchanged. |
| Evidence digest (`evidence`) | `tag kind ‖ LE32 count ‖ (LE32 len ‖ bytes)…` | Kinds: AndroidKeyMintTee 1, AndroidKeyMintStrongBox 2, AppleAppAttest 3. Non-empty original items, never rewritten: Android attestation DER chain leaf first; Apple attestation object, then assertion. |
| Evidence record (inline, 56) | `digest ‖ LE64 time_ms ‖ LE32 facts ‖ LE32 os_patch_level ‖ LE32 vendor_patch_level ‖ LE32 boot_patch_level` | Fact bits below; `digest` nonzero. |
| Regulatory policy (inline, 20) | `LE32 permitted_controls ‖ LE64 blacklist_max_age_ms ‖ LE64 time_anchor_max_response_ms` | Controls: bit 0 BLACKLIST, 1 QUOTAS, 2 ATTESTATION_LEASE; others zero. `blacklist_max_age_ms > 0` requires bit 0. `time_anchor_max_response_ms > 0` iff bit 1, bit 2 or `blacklist_max_age_ms > 0`. |
| Credential (signed under `kgwcred1`) | `LE16 version ‖ scheme_id ‖ asset_digest ‖ wallet_id ‖ account_digest ‖ payment_key(key) ‖ provider_contract ‖ tag evidence_kind ‖ enrollment_evidence(56) ‖ fresh_evidence(56) ‖ app_policy ‖ regulatory_policy(20) ‖ enrollment_id ‖ LE64 issued_at_ms ‖ LE32 renewal_sequence ‖ LE64 lease_expires_at_ms ‖ issuer_certificate` | Enrollment-role signer. Nonzero bindings; V1 provider contract even without a scheme; `wallet_id` recomputes. Renewal 0 requires `fresh_evidence = enrollment_evidence`; later renewals require `fresh.time_ms ≥ enrollment.time_ms`. `lease_expires_at_ms ≠ 0` iff the lease is permitted. A replacement changes only `fresh_evidence`, `issued_at_ms`, `lease_expires_at_ms` and `issuer_certificate`, and `renewal_sequence` is the predecessor's plus one. |
| Renewal transcripts | renewal challenge and `renewal-assertion`: `LE16 1 ‖ scheme_id ‖ wallet_id ‖ credential_digest ‖ challenge`; renewal key binding: `LE16 1 ‖ scheme_id ‖ wallet_id ‖ challenge ‖ new_attested_key` | The payment key signs the renewal challenge under `kgwrnch1` (possession) and, on Android, the key binding under `kgwrnkb1` (§1). The App Attest renewal assertion's client data is `H("renewal-assertion", ·)`. |
| Renewal request (frame only) | `{version, scheme_id, wallet_id, credential_digest, challenge, possession_signature, evidence}` | Evidence: Android 1 `{new_attested_key, key_binding_signature, chain: [{der}]}` or Apple 2 `{assertion}` within the §2 bounds, on the credential's platform. Issuer verification of the chain or assertion is TODO(G5). |
| Artifact manifest (signed under `kgwartf1`) | `LE16 version ‖ network_id ‖ relation_id ‖ eq_protocol_digest ‖ ep_protocol_digest ‖ native_profile_digest ‖ verifying_key_set_digest ‖ artifact_inventory_digest ‖ provider_contract ‖ signer_certificate` | Artifact-role signer. Bindings nonzero; `relation_id` recomputes from the five bindings; network, relation and provider contract equal the scheme's. |

Fact bits: 0 HARDWARE_BACKED_KEY, 1 STRONGBOX, 2 BOOTLOADER_LOCKED, 3 VERIFIED_BOOT,
4 PATCH_POLICY_MET, 5 APP_SIGNING_IDENTITY, 6 APP_ATTEST_GENUINE_DEVICE,
7 APP_ATTEST_KEY_BINDING, 8 APP_ATTEST_PRODUCTION, 9 PLAY_INTEGRITY_SIGNAL,
10 REVOCATION_LIST_CLEAR, 11 LOCAL_COMPROMISE_CHECKS_CLEAR; 12–31 are zero.
Android records never carry 6–8; Apple records never carry 0–5 or 9 and have zero
patch levels. Enrollment evidence requires bits 0, 2, 3 and 5 on Android (plus 1
for StrongBox; TEE forbids 1) and bits 6 and 7 on Apple.

### 3.2 State, field encoding, statement, proofs, receipt, package

**σ field and element rule.** The step proofs σ are single-parity proofs over the
Pasta `Fp` (Vesta scalar field),
`p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001`. A σ-field
value is its canonical 32-byte little-endian encoding (`< p`); decoding rejects a
noncanonical value wherever a field value is required. Element lists use one rule:
an integer, tag or mask is one element; a 32-byte SHA-256 digest or identifier is
two `u128` limbs, low 16 bytes first (each little-endian); a `P` value (commitment,
chain, root, nonce, `credit_id`, `proof_digest`, Payment, lineage, credit-opening,
credit-status or credited digest, signed message) is one element. The domain of `P`
(§1) is the `u64` of 8 little-endian ASCII bytes; the signing domains are in §1, and
the others are:

| Domain | Use | Domain | Use |
|---|---|---|---|
| `kgwcore1` | state commitment | `kgwcdig1` | credit-digest value |
| `kgwrest1` | rest digest | `kgwimlf1` | indexed-tree leaf |
| `kgwstmt1` | σ statement digest | `kgwimnd1` | indexed-tree node |
| `kgwcrdt1` | `credit_id` | `kgwblkl1`, `kgwblkn1` | blacklist leaf, node (§3.3) |
| `kgwschn1` | `send_chain` append | `kgwqwin1`, `kgwqwnd1` | quota-window leaf, node (§3.3) |
| `kgwrchn1` | `recv_chain` append | `kgwprf_1` | `proof_digest`, Ω‖σ (`P_bytes`) |
| `kgwccrd1` | consumed-credit value | `kgwstep1` | `proof_digest`, σ only (`P_bytes`) |
| `kgwpout1` | pending-outgoing value | `kgwpay_1` | Payment digest (`P_bytes`) |
| `kgwload1` | load value (load/redeem map) | `kgwlin_1` | lineage digest over the Ω bytes (`P_bytes`) |
| `kgwrdm_1` | redeem value (load/redeem map) | `kgwcopn1` | credit-opening digest (`P_bytes`) |
| `kgwfee_1` | fee-claim value | `kgwcsts1` | credit-status digest (`P_bytes`) |
| `kgwquse1` | quota-usage value | `kgwcrdd1` | credited digest (`P_bytes`) |

**Indexed map trees** (TODO(G1)). The consumed-credit, pending-outgoing, load/redeem
recovery, fee-claim and quota-usage maps and the lineage-level credit-digest tree are
each a depth-32 Poseidon indexed Merkle tree:

- *Slots and nodes.* Slots `0 … 2^32 − 1` are the leaves at height 0. The node at
  height `h + 1` and index `j` has the children `2j` (left) and `2j + 1` (right) at
  height `h`, so bit `h` of the slot index selects the child at height `h`; the root is
  the node at height 32. A node is `P(kgwimnd1, [left, right])`. An empty slot is the
  element `0`, and an empty subtree of height `h + 1` is the node over two empty
  subtrees of height `h`.
- *Leaves.* An occupied slot holds `(key, value, next_key)`, hashed
  `P(kgwimlf1, [key, value, next_key])`. `key` is the map key below, a nonzero
  canonical value compared as an integer in `[0, p)`; `value` is
  `P(value domain, elements)` of the table below; `next_key` is the next larger key
  present, or `0` for the largest. Keys are unique, and the leaves form one list
  sorted by key.
- *Empty tree.* The zero sentinel leaf `(0, 0, 0)` in slot 0, every other slot empty.
  The sentinel is never removed, and slot 0 holds no other leaf. The vectors pin its
  root.
- *Membership* of `k` opens the leaf whose `key = k` at its slot. *Non-membership* of
  `x ≠ 0` opens the low leaf with `key < x` and (`next_key = 0` or `x < next_key`) at
  its slot; the sentinel is the low leaf of every key below the smallest present key.
  An empty slot never opens as a leaf.
- *Insert* `(x, v)`, `x` absent: open the low leaf `(k, w, n)` and replace it with
  `(k, w, x)`; then open slot `f`, the next free index, as empty in the resulting root
  and write `(x, v, n)` there. *Update* a present key: open its leaf and replace only
  `value`. *Remove* `k`: open the leaf `(k', w', k)` whose `next_key` is `k` and replace
  it with `(k', w', n)`, where `n` is the `next_key` of `k`'s leaf; then open `k`'s leaf
  in the resulting root and clear its slot to empty. Each opening is against the root
  that the previous step produced.
- *Next free index.* `f` is one more than the highest slot ever written, `1` for the
  empty tree. A removal frees no slot, so slots are never reused, and an insertion
  with `f = 2^32` is rejected. Relations check that the written slot is empty; this
  native rule fixes which slot, and the vectors pin it.
- *Openings* (transcripts): a leaf opening is `key ‖ value ‖ next_key ‖ LE32 slot ‖
  siblings` (1,124 bytes) and an empty-slot opening `LE32 slot ‖ siblings` (1,028
  bytes), where `siblings` is exactly 32 canonical 32-byte values in increasing height
  (height 0 first). The CreditStatus opening (§3.4) is a leaf opening that carries the
  value's elements instead of `value`.

Map keys and operations: `credit_id` keys the consumed-credit, pending-outgoing and
fee-claim maps and the credit-digest tree; `kind · 2^128 + ordinal` (Load 1, Redeem 2)
keys the one load/redeem recovery map; `window kind · 2^128 + window_start_ms` keys the
quota-usage map. Pending-outgoing entries are inserted by Send and removed by
ArchiveSent, quota-usage entries are inserted or updated by Send, and every other map
and the credit-digest tree are insert-only. The data model builds roots and openings
natively.

**State.** The private state is not transmitted; it travels only inside a recovery
capsule. Its frame is `{version, core, rest}`.

- The *core* holds every field a step proof reads, changes or carries. Frame and
  element order (32 elements): `lifecycle` (Active 1, Retiring 2), `scheme_id` (2),
  `asset_digest` (2), `wallet_id` (2), `credential_digest` (2), `balance`,
  `burned_total`, `sequence`, `next_send`, `next_load`, `next_redeem` (`u128` each),
  `send_chain`, `recv_chain`, `consumed_credit_root`, `pending_outgoing_root`,
  `load_redeem_recovery_root`, `fee_claim_root`, `quota_usage_root`, `LE32
  enabled_controls`, `quota_windows_root`, `LE64 blacklist_version`, `blacklist_root`,
  `LE64 blacklist_issued_at_ms`, `LE64 blacklist_max_age_ms`, `LE64
  lease_expires_at_ms`, `LE64 policy_epoch`, `LE64 accepted_time_floor_ms`,
  `state_nonce`. `blacklist_max_age_ms` is the credential regulatory policy's, held in
  the core so that σ_send enforces the list-age rule.
- The *rest* is opened only by the lineage relation. Frame and element order (13
  elements): `LE32 permitted_controls`, `LE64 time_anchor_max_response_ms` (the rest of
  the regulatory policy), `scheme_policy` (2), `fee_schedule` (2), `blacklist` (2),
  `quota_share` (2), `LE64 quota_share_id`, `time_anchor` (2).
- The commitment is one σ-field value:
  `P(kgwcore1, core elements ‖ P(kgwrest1, rest elements))`. Its transcript is the
  32-byte encoding; all-zero is only the Bootstrap predecessor.
- Rules: nonzero identities; the five map roots and `state_nonce` are nonzero
  canonical values; chains and the blacklist and quota-windows roots are canonical
  (zero is the empty chain or "none held"); the regulatory policy reassembled from the
  core and rest is valid and `enabled_controls` ⊆ its permitted controls. A scheme
  policy, blacklist or quota share is held exactly when its digest, its epoch, version
  or share id, and its root (if any) are all nonzero; without a scheme policy,
  `enabled_controls` and `fee_schedule` are zero; an unheld blacklist has a zero issue
  time; `lease_expires_at_ms ≠ 0` iff the lease is permitted. Bootstrap state has zero
  balance, `burned_total`, ordinals, sequence and chains, the empty-tree root for every map,
  and zero policy fields except the credential's regulatory policy and lease.
- The spendable value is `balance − burned_total` with the lineage-adjusted
  `burned_total` of the Ω recorded for the head, whose `head` must equal the state's
  computed commitment (§§3.2, 6.1 of the proposal); Send and Unload pre-checks use it.

**Map values and chains** (element lists after the domain; a map leaf is
`(key, P(value domain, elements), next_key)`; no state commitment or chain contains a
Payment digest):

| Object | Value domain | Key | Elements |
|---|---|---|---|
| consumed credit (permanent map) | `kgwccrd1` | `credit_id` | `credit_id`, `amount`, `receive_sequence` (3) |
| pending outgoing | `kgwpout1` | `credit_id` | `credit_id`, `receiver_wallet_id` (2), `send_ordinal`, `amount`, `fee`, `request_digest` (2) (8) |
| load (load/redeem map) | `kgwload1` | `1 · 2^128 + ordinal` | `ordinal`, `voucher_digest` (2), `amount` (4) |
| redeem (load/redeem map) | `kgwrdm_1` | `2 · 2^128 + ordinal` | `ordinal`, `nullifier` (2), `amount`, `online_charge` (5) |
| fee claim | `kgwfee_1` | `credit_id` | `credit_id`, `fee`, `fee_schedule_digest` (2) (4) |
| quota usage | `kgwquse1` | `kind · 2^128 + start` | `window_kind` tag, `window_start_ms`, `window_end_ms`, `used` (4) |
| `send_chain` append | `kgwschn1` | — | `[send_chain]` ‖ the pending-outgoing elements (9) |
| `recv_chain` append | `kgwrchn1` | — | `[recv_chain]` ‖ `credit_id`, `payer_wallet_id` (2), `amount` (5) |
| credit digest (lineage level, not in the state) | `kgwcdig1` | `credit_id` | `credit_id`, `payment_digest`, `burned` 0 or 1 (3) |

**Operation kinds and effects** (effect transcript (161) = `tag ‖ fields ‖ zero fill
to 160`; the effect tag equals the operation kind; Ω(pred) marks the kinds that
consume the predecessor's lineage proof):

| Tag | Kind | Effect fields (width) | Elements | `operation-id` input | Ω(pred) |
|---:|---|---|---:|---|---|
| 1 | Bootstrap | `enrollment_id ‖ enrollment_marker` (64) | 4 | `enrollment_id` | no |
| 2 | Load | `voucher ‖ LE128 load_ordinal ‖ LE128 amount ‖ LE128 online_charge` (80) | 5 | `voucher` | no |
| 3 | Send | `credit_id ‖ receiver_wallet_id ‖ LE128 send_ordinal ‖ LE128 amount ‖ LE128 fee ‖ request ‖ LE64 accepted_lower_ms ‖ LE64 accepted_upper_ms` (160) | 10 | `credit_id` | yes |
| 4 | Receive | `credit_id ‖ payer_wallet_id ‖ LE128 amount` (80) | 4 | `credit_id` | no |
| 5 | ArchiveSent | `credit_id ‖ credited` (64) | 2 | `credited` | no |
| 6 | Unload | `nullifier ‖ LE128 redeem_ordinal ‖ LE128 amount ‖ LE128 online_charge ‖ charge_quote` (112) | 7 | `nullifier` | yes |
| 7 | RefreshPolicy | `tag update_kind ‖ update ‖ LE64 accepted_time_floor_ms` (41) | 4 | `update` | no |
| 8 | Retiring | none (0) | 0 | 32 zero bytes | yes |

Update kinds: Credential 1, SchemePolicy 2, Blacklist 3, QuotaShare 4, TimeAnchor 5;
`update` is the applied object's digest. Effect rules: nonzero digests; `credit_id` a
nonzero canonical σ-field value; Send, Receive and Unload amounts positive; Send
`amount + fee` fits `u128` and `accepted_lower_ms ≤ accepted_upper_ms`; Unload
`online_charge ≤ amount` and `charge_quote` nonzero iff `online_charge > 0`. The Send
`request` is the digest of the signed Request, which binds the receiver credential, fee
schedule and certificates by digest; the Receive effect carries no Payment digest.
`ArchiveSent` uses the Credited digest, a `P_bytes` value (§3.4), as its operation input,
so archiving again with new evidence is a new operation.

- **Statement** (`statement`, 440): `LE16 version ‖ scheme_id ‖ relation_id ‖
  credential_digest ‖ asset_digest ‖ tag lifecycle ‖ LE128 sequence ‖ LE128
  next_load ‖ LE32 enabled_controls ‖ LE128 lineage_burned_total ‖
  lineage_pending_outgoing_root ‖ predecessor ‖ successor ‖ effect(161)`. Lifecycle,
  sequence and `next_load` are the successor's; `enabled_controls` is the
  predecessor's mask that σ enforced. For Send, Unload and Retiring the lineage
  fields are Ω(pred)'s `burned_total` and pending-outgoing root (the root nonzero);
  every other kind has zero lineage fields. Bootstrap alone has sequence 0, a zero
  predecessor, Active, `next_load` 0 and an empty mask; every other statement has a
  nonzero predecessor. Commitments are canonical and the successor is nonzero.
  Retiring yields lifecycle Retiring; Load yields `next_load = load_ordinal + 1`; a
  Credential refresh has `update = credential_digest`. A successor chains on the
  predecessor's successor commitment with sequence plus one; lifecycle changes only
  by Retiring from Active; `next_load` changes only by Load at the predecessor's
  `next_load`; `credential_digest` changes only by a Credential refresh. Against its
  credential: Bootstrap names the credential's `enrollment_id`, Send and Receive
  never name the wallet itself, and an Unload nullifier recomputes.
- **σ public input** (28 elements, digest `P(kgwstmt1, ·)`): `version`,
  `relation_id` (2), `scheme_id` (2), `asset_digest` (2), `credential_digest` (2),
  lifecycle, sequence, `next_load`, `enabled_controls`, `lineage_burned_total`,
  `lineage_pending_outgoing_root`, `predecessor`, `successor`, effect tag, then the
  effect's elements in field order zero-filled to 10. The `iroha_kagemusha_proof`
  step relations and `iroha_plonk_gadgets::statement::StatementV1` encode this
  layout, with the relation identity as witness limbs bound by the digest, and
  reproduce the statement vectors natively and in circuit.
- **Consumer checks** (proposal §3.2) of a statement carrying Ω(pred), before
  mutation: scheme and relation equal Ω's; `predecessor = Ω.head`;
  `credential_digest = Ω.credential_digest`; the lineage fields equal Ω's
  `burned_total` and pending-outgoing root; `enabled_controls = Ω.enabled_controls`
  (which selects σ_send's verifying key); the predecessor lifecycle (Active for
  Retiring, else the statement's) equals Ω's; and the wallet-bound effect rules for
  `Ω.wallet_id`.
- **Operation and nullifier.** `operation_id = H("operation-id", wallet_id ‖ tag kind ‖ input)`;
  `nullifier = H("unload-nullifier", scheme_id ‖ wallet_id ‖ LE128 redeem_ordinal)`.
- **Step proof σ.** Frame `{bytes}`, non-empty. The PIPA-v1 layout comes from the
  artifact set (TODO(G3)); its exact length is the verifying-key allowlist entry of its
  selector (§3.1).
- **Lineage proof Ω.** Frame `{public, proof}`; `proof` is the non-empty single-parity
  transport proof of the allowlist's exact transport length. The public transcript (320)
  is `LE16 version ‖ scheme_id ‖ relation_id ‖ head ‖ wallet_id ‖ credential_digest ‖
  payment_key(key) ‖ tag lifecycle ‖ LE64 policy_epoch ‖ LE32 enabled_controls ‖
  LE128 burned_total ‖ pending_outgoing_root ‖ credit_digest_root`; identities
  nonzero, the head and both roots nonzero canonical values, defined control bits only.
  The Ω bytes are that transcript followed by the proof, so `proof_digest` and the
  Payment digest bind every exposed value; `lineage_digest = P_bytes(kgwlin_1, Ω bytes)`
  identifies byte-identical reuse. A head has at most one recorded Ω, carried unchanged
  by every Lineage message, Payment and ledger package from it.
- **`proof_digest`.** One canonical σ-field value: Send, Unload and Retiring
  `P_bytes(kgwprf_1, LE32 len(Ω) ‖ Ω ‖ LE32 len(σ) ‖ σ)`; every other operation
  `P_bytes(kgwstep1, LE32 len(σ) ‖ σ)`. It is recomputed on every use; the Durable
  State Provider binds it in Advance.
- **Receipt τ.** Frame `{version, operation_id, capsule_digest, payment_digest,
  signature}`. Its signed body is derived by every verifier and never transmitted; the
  signature covers `P_bytes(kgwrcpt1, body)` (§1). The body (338) is `LE16 version ‖
  scheme_id ‖ wallet_id ‖ provider_contract` (from the signer) `‖ LE128 sequence ‖
  operation_id ‖ predecessor ‖ successor` (from the statement) `‖ statement_digest ‖
  proof_digest ‖ capsule_digest ‖ payment_digest`. `proof_digest` is a nonzero
  canonical σ-field value;
  `payment_digest` is the full canonical Payment digest (a canonical σ-field value) for
  Receive and zero otherwise. The signer is the wallet's credential, or, for a consumer
  of a package carrying Ω(pred), Ω's scheme, wallet and payment key under the V1
  provider contract. The carried `operation_id` must equal the recomputed one.
- **Package.** Frame `{version, statement, lineage, step_proof, receipt}`; `lineage`
  is None 0 or Present 1 `{lineage: Ω(pred)}`, present exactly for Send, Unload and
  Retiring, and a present Ω passes the consumer checks.
  `package_digest = H("package", statement_digest ‖ proof_digest ‖ receipt_digest)`,
  defined only after the receipt verifies (under the credential, which must also
  carry Ω's wallet and payment key, or under Ω for a consumer without the
  credential). σ's verifying key is selected from the verifying-key allowlist by the
  operation tag, for Send also by the mask and for Receive also by the mask's blacklist
  bit (§3.1); the allowlist also checks σ's and Ω's exact lengths.

### 3.3 Policy objects

All are signed, under the signing domain in parentheses (§1), by a
RegulatoryPolicy-role key except the time anchor (TimeAnchor role). Each body's
`signer_certificate` names the signer.

| Object | Body fields in transcript order | Interoperability rules |
|---|---|---|
| Scheme policy (`kgwspol1`) | `LE16 version ‖ scheme_id ‖ asset_digest ‖ LE64 policy_epoch ‖ LE32 enabled_controls ‖ fee_schedule ‖ signer_certificate` | `policy_epoch ≥ 1` (0 is the implicit default); defined control bits only; zero `fee_schedule` means no fee. |
| Fee schedule (`kgwfsch1`) | `LE16 version ‖ scheme_id ‖ asset_digest ‖ LE64 schedule_id ‖ beneficiary_account_digest ‖ LE32 basis_points ‖ LE128 fixed ‖ LE128 minimum ‖ LE128 maximum ‖ tag rounding ‖ signer_certificate` | Rounding Down 1, Up 2; `basis_points ≤ 10,000`; `maximum ≥ minimum`. For `a = 10,000·q + r`, `fee(a) = clamp(fixed + q·bp + ⌊r·bp / 10,000⌋ (+1 if Up and r·bp mod 10,000 ≠ 0), minimum, maximum)`; an unclamped `u128` overflow rejects. |
| Blacklist (`kgwblst1`) | `LE16 version ‖ scheme_id ‖ LE64 list_version ‖ LE64 issued_at_ms ‖ LE32 entry_count ‖ entries_root ‖ signer_certificate` | Frame `{body, signature, entries: [{account_digest}]}`. `list_version ≥ 1`; `entries_root` a nonzero canonical σ-field value; entries strictly ascending in limb order (below), never `00…00` or `FF…FF`; count and root recompute. Downloaded only online, from the issuer or ledger, as one standalone frame; never a peer message. |
| Quota share (`kgwqshr1`) | `LE16 version ‖ scheme_id ‖ asset_digest ‖ wallet_id ‖ LE64 share_id ‖ LE64 issued_at_ms ‖ LE64 expires_at_ms ‖ windows_root ‖ LE32 window_count ‖ signer_certificate` | Frame `{body, windows, signature}` (windows before the signature). `share_id ≥ 1`; `windows_root` a nonzero canonical σ-field value; `issued < expires`; each window has `start < end` within `[issued, expires]`; windows strictly sorted by `(kind, start)`, never overlapping within a kind; count and root recompute. |
| Time anchor (`kgwtanc1`) | `LE16 version ‖ scheme_id ‖ wallet_id ‖ nonce ‖ LE64 issuer_time_ms ‖ signer_certificate` | Answers one wallet nonce. |
| Charge quote (`kgwchgq1`) | `LE16 version ‖ scheme_id ‖ asset_digest ‖ wallet_id ‖ tag kind ‖ LE128 ordinal ‖ LE128 net_amount ‖ LE128 online_charge ‖ beneficiary_account_digest ‖ LE64 issued_at_ms ‖ signer_certificate` | Kinds Load 1, Unload 2. `online_charge > 0`. Load: the ledger debit `net_amount + online_charge` fits `u128`. Unload: `net_amount > 0` and the payout `net_amount − online_charge` does not underflow. |

- **Blacklist order** (TODO(G1)). An account digest `a` orders by its limb integer
  `int(a) = hi · 2^128 + lo`, where `lo` and `hi` are its two σ limbs (bytes 0–15 and
  16–31, each little-endian), so `int(a)` is the 32 bytes read as one little-endian
  integer. Entries, sentinels, gap leaves and openings follow this order: `x < y` iff
  `hi(x) < hi(y)`, or `hi(x) = hi(y)` and `lo(x) < lo(y)`. `00…00` and `FF…FF` are the
  least and greatest values.
- **Blacklist tree.** A Poseidon tree of fixed depth 16 over 65,536 gap leaves. With
  sentinels `s_0 = 00…00`, entries `s_1…s_n` in limb order and `s_{n+1} = FF…FF`,
  leaf `i ≤ n` is `P(kgwblkl1, limbs(s_i) ‖ limbs(s_{i+1}))` (four elements); unused
  leaves are the leaf of `FF…FF ‖ FF…FF`; a node is `P(kgwblkn1, [left, right])`; the
  root is one σ-field value. Non-membership of `x` is one gap leaf with
  `lower < x < upper` in limb order and its 16 siblings, a local witness that is never
  transmitted.
- **Blacklist enforcement** (TODO(G1)). A wallet enforces only its own committed list,
  and only while its BLACKLIST control is enabled and it holds a list
  (`blacklist_version ≥ 1`); with version 0 it refuses no account and applies no age
  rule. The payer's list must not contain the Request's `receiver_account_digest` (Send
  rule, §3.4; σ_send). The receiver's list must not contain the Request's
  `payer_account_digest` (Request and Receive rules, §3.4; σ_recv). The maximum-age rule
  (Time, below) applies to Send only. Lists are best effort: phones hold different
  lists, nothing requires them to agree, and a later list never invalidates a completed
  payment.
- **Quota tree.** A window is `kind` (Daily 1, Monthly 2), `start_ms`, `end_ms` and
  `limit` (half-open `[start, end)`); its leaf is `P(kgwqwin1, [tag kind, start_ms,
  end_ms, limit])`, an empty slot is the leaf of four zero elements, and the root is a
  depth-6 Poseidon tree over 64 slots, windows first, with nodes `P(kgwqwnd1, [left,
  right])`; the root is one σ-field value.
- **Time.** The local anchored time `{anchor, boot_id, LE64 request_monotonic_ms,
  LE64 receive_monotonic_ms}` gives, at monotonic reading `m` in the same boot,
  `[T + (m − m_rcv), T + (m − m_req)]`, valid when `m ≥ m_rcv` and
  `m_rcv − m_req ≤ time_anchor_max_response_ms`. A Send binds `L = max(floor,
  anchor lower, receiver_accepted_time_ms)` and `U = max(anchor upper, L)` (`U = L`
  without an anchor). An active time-dependent control without the committed
  same-boot anchor refuses Send. A deadline (lease expiry, quota share expiry) has
  passed iff `U ≥ deadline`. Blacklist age is `U − blacklist_issued_at_ms`; both it and
  the maximum age are core fields, so σ_send enforces the maximum-age rule (§3.2). A quota
  window is touched iff `start ≤ U` and `L < end`; every touched window needs
  `used + amount + fee ≤ limit`, and each window kind the share defines must be
  touched.
- **RefreshPolicy.** One signed update per transition. Epochs, list versions and
  share ids strictly increase; a time anchor must differ from the held one; a
  quota share keeps the end of every existing usage key; `quota_usage_root` never
  changes. The new floor is `max(old floor, t)`, where `t` is the credential's
  `issued_at_ms`, the old floor for a scheme policy, the list's or share's
  `issued_at_ms`, or the anchor's `issuer_time_ms`.

### 3.4 Messages and envelope

The envelope frame is `{version, message}`; message tags are Offer 1, Request 2,
Payment 3, Credited 4, SessionControl 5, PolicyData 6 and Lineage 7. The scheme
checked at decode is the body scheme (Offer, Request), the carried Request's scheme
(Payment), Ω's scheme (Lineage) or the message's own field.

| Message | Frame and transcript | Interoperability rules |
|---|---|---|
| Offer | `{body, payer_credential, certificates, signature}`; offer body (signed under `kgwoffr1`) = `LE16 version ‖ scheme_id ‖ asset_digest ‖ payer_wallet_id ‖ payer_credential_digest ‖ LE128 next_send ‖ LE128 amount ‖ session_nonce` | Payer payment key signs. Body matches the credential's scheme, asset, wallet and digest; the credential frame is at most 1,024 bytes; `amount > 0`; certificates exactly the payer issuer. No debit or credit authority; a delivery retry also opens with an Offer, so the receiver holds the payer credential. |
| Lineage | `{version, lineage: Ω}` | Unsigned and sent only after an authenticated Offer. The receiver rate-limits it and checks Ω's scheme, `wallet_id`, credential digest and `payment_key` against the Offer's credential; a Payment whose Ω(pred) has the same `lineage_digest` reuses that verification. |
| Request | `{body, receiver_credential, fee_schedule, certificates, signature}`; request body (signed under `kgwrqst1`, 418) = `LE16 version ‖ scheme_id ‖ asset_digest ‖ payer_wallet_id ‖ payer_account_digest ‖ receiver_wallet_id ‖ receiver_account_digest ‖ LE128 send_ordinal ‖ receiver_credential_digest ‖ LE128 amount ‖ fee_schedule ‖ LE128 fee ‖ LE64 policy_epoch ‖ scheme_policy ‖ LE64 receiver_accepted_time_ms ‖ certificates ‖ nonce` | Receiver payment key signs. Slot None 0 or Present 1 `{schedule}`. `amount > 0`; payer ≠ receiver wallet; `amount + fee` fits; `policy_epoch = 0` iff `scheme_policy` zero. Both account digests are nonzero (TODO(G1)): `receiver_account_digest` equals the carried receiver credential's `account_digest`, and `payer_account_digest` equals the payer credential's (checked by the receiver against the Offer's credential before it signs, and by the payer against its own before Send). None requires zero `fee_schedule` and `fee`; Present requires the digest, the Request's scheme and asset, and `fee = fee(amount)`. Certificates exactly the receiver issuer (Enrollment) plus the fee signer (RegulatoryPolicy) when present; their set digest is `body.certificates`. `credit_id = P(kgwcrdt1, ·)` over the 28 request-body elements in transcript order (version; scheme, asset, payer wallet, payer account, receiver wallet, receiver account (2 each); `send_ordinal`; receiver credential (2); `amount`; fee schedule (2); `fee`; `policy_epoch`; scheme policy (2); `receiver_accepted_time_ms`; certificates (2); nonce (2)), one canonical σ-field value. `request_digest = H("request", m ‖ sig)`. |
| Payment | `{version, request: {body, signature}, payer_payment_key, payer_credential_digest, send: Package}`; `payment` (163) = `LE16 version ‖ request_digest ‖ payer_payment_key(key) ‖ payer_credential_digest ‖ package_digest`; the Payment digest is `P_bytes(kgwpay_1, payment)`, one canonical σ-field value, binding Ω(pred), σ_send and τ_send through the package digest and its `proof_digest` | The compact layout: the receiver's credential, fee schedule and certificates are bound by digest in the Request body, and the payer's credential and certificates travel in the Offer. Structurally (no `payment_digest` without it): `send` is a Send package carrying Ω(pred) that passes the consumer checks with τ verified under `Ω.payment_key`; the Request payer is `Ω.wallet_id`; the carried key and credential digest are Ω's; the effect's credit, receiver, ordinal, amount, fee and `request` equal the Request's, `accepted_lower_ms ≥ receiver_accepted_time_ms`, the statement's scheme and asset are the Request's; `Ω.policy_epoch ≥` the Request's. At Receive: the carried Request is the receiver's held one, which verifies in full; the receiver's current credential is matched by the Request's receiver wallet and its receiver credential's payment key, never by credential digest, so a Request signed before a renewal stays receivable; the Offer's payer credential verifies under the scheme, is the Request's payer with a key other than the receiver's, matches the carried digest and key, and has the Request's `payer_account_digest`; the receiver's blacklist rule holds (Receive rule, below); the statement's relation is the scheme's. σ_send and Ω(pred) with its decide are the proof owner's. |
| Credited | `{version, scheme_id, evidence}`; the credited transcript (99) is `LE16 version ‖ tag evidence ‖ credit_id ‖ payment_digest ‖ evidence digest`, and the Credited digest is `P_bytes(kgwcrdd1, ·)` (TODO(G1)) | Evidence Receive 1 `{package}` (status *credited, unfolded*; evidence digest = its package digest) or Status 2 `{status: CreditStatus}` (status *credited* or *burned*; evidence digest = its credit-status digest). `scheme_id` is the evidence statement's scheme. The payer verifies it against its scheme, held Request and retained Payment: in both forms the evidence statement names the payer's scheme and relation identity (rejected before the `ArchiveSent` mutation, as `Λ_archive` rejects it); Receive form, a Receive package (no Ω) whose effect credit, payer wallet and amount match, whose receipt binds the Payment digest, whose scheme and asset are the Request's, and whose τ verifies under the Request's receiver credential; Status form, Ω(h)'s `wallet_id` and `payment_key` equal the Request's receiver wallet and its receiver credential's key (credential digests are not compared, so a receiver that renewed after the Request still matches) and the opening names this credit and Payment digest. `ArchiveSent` also requires the retained Payment's pending-outgoing leaf. |
| CreditStatus (inside Credited) | `{version, statement, proof_digest, receipt, lineage: Ω(h), opening}`; the credit-status transcript (162) is `LE16 version ‖ statement_digest ‖ proof_digest ‖ receipt_digest ‖ lineage_digest ‖ opening_digest`, and its digest is `P_bytes(kgwcsts1, ·)` (TODO(G1)) | Read-only evidence from a folded receiver head `h`, carrying no σ and no Ω(pred): the statement's successor is `Ω(h).head`; scheme, relation, credential digest and lifecycle equal Ω's; τ(h) verifies under Ω(h)'s key over the carried statement and nonzero `proof_digest`, with its own capsule and Payment digests. The opening recomputes `Ω(h).credit_digest_root` natively. The decide of Ω(h) is the proof owner's (TODO(G3)). Only a membership opening is evidence; a non-membership (low-leaf) opening is not. |
| Credit opening (inside CreditStatus) | `{credit_id, payment_digest, burned: bool, next_key, slot: u32, siblings: bytes}`; the credit-opening transcript (1,125) is `credit_id ‖ payment_digest ‖ u8 burned ‖ next_key ‖ LE32 slot ‖ siblings`, and the opening digest is `P_bytes(kgwcopn1, ·)` (TODO(G1)) | The leaf opening (§3.2) of `credit_id` in the credit-digest tree: the leaf `P(kgwimlf1, [credit_id, P(kgwcdig1, [credit_id, payment_digest, burned]), next_key])` at `slot`, with exactly 32 siblings as 1,024 concatenated canonical bytes in increasing height. `credit_id` and `payment_digest` are nonzero canonical σ-field values; `next_key` is zero or a canonical value above `credit_id`; `slot ≥ 1`. |
| SessionControl | `{version, scheme_id, asset_digest, sender_wallet_id, peer_wallet_id, session_nonce, kind, LE16 reason, credit_id, auth}`; session-control body (signed under `kgwsctl1`) = all fields except `auth`, kind as a tag | Kinds SetupDeclined 1, UnsupportedScheme 2, ReceiveDeferred 3, Close 4; auth Unsigned 0 or Signed 1 `{signature}`. Scheme, asset and nonce nonzero; sender nonzero except UnsupportedScheme; peer zero (unknown) or not the sender; opaque `reason` only for SetupDeclined and ReceiveDeferred; `credit_id` nonzero iff ReceiveDeferred. `credit_id` is a canonical σ-field value. Unsigned only for UnsupportedScheme and for SetupDeclined before the sender's own Offer or Request; otherwise signed by the payment key of that session's Offer or Request credential. Invalid controls are dropped. |
| PolicyData | `{version, scheme_id, asset_digest, item}` | Items SchemePolicy 1, FeeSchedule 2, Certificates 3 (non-empty); tag 4 is unused, because the blacklist is never peer-carried (§3.3). Item scheme equals `scheme_id`; scheme policy and fee schedule asset equal `asset_digest`. Signers are selected by certificate digest. |

- **Unknown scheme.** A receiver may decode an Offer envelope through the per-kind
  bound without the scheme check, validate only its body, and reply with an
  unsigned UnsupportedScheme naming the Offer's scheme, asset and session nonce,
  zero sender and the payer as peer.
- **Send rule** (native pre-check; relation enforcement is design only, G3): the
  Request names the payer's wallet and `next_send`; the Ω is the one recorded for the
  payer's head (its `head` is the payer state's computed commitment, and wallet,
  credential and key are the payer's); payer `policy_epoch ≥` the Request's, with an
  equal `scheme_policy` at equal epochs; `fee_schedule` equals the payer's held
  schedule; payer and receiver keys differ; `balance − Ω.burned_total ≥ amount + fee`;
  `payer_account_digest` is the payer credential's and `receiver_account_digest` the
  Request receiver credential's (TODO(G1)); with the payer's blacklist enforced (§3.3),
  `receiver_account_digest` has a gap opening in the payer's committed list and the
  list-age rule holds.
- **Request rule** (receiver, native, before it signs a Request; TODO(G1)): the Offer
  is authenticated; `payer_account_digest` is the Offer credential's and
  `receiver_account_digest` the receiver's own credential's; with the receiver's
  blacklist enforced (§3.3), `payer_account_digest` has a gap opening in its committed
  list. Otherwise the receiver issues no Request (it may send SetupDeclined).
- **Receive rule** (receiver, native, before mutation; TODO(G1)): with the receiver's
  blacklist enforced at the head it receives on, `payer_account_digest` has a gap
  opening in that committed list; σ_recv proves the same against the head's
  `blacklist_root`. A Payment refused by this rule stays deliverable and changes no
  state.

### 3.5 Custody objects (local, never transmitted)

Their enums are Norito enums: frames carry 4-byte tags; the `output` transcript
carries one byte.

| Object | Frame | Interoperability rules |
|---|---|---|
| Marker (`marker` over the frame) | `{version, scheme_id, asset_digest, wallet_id, payment_key, LE128 generation, state}`; state Enrollment 1 `{challenge_digest, enrollment_id}`, Head 2 `{LE128 sequence, operation_id, head, capsule_digest, predecessor_capsule_digest}`, Terminal 3 `{reason, last_capsule_digest}` | Reasons Abandoned 1, CustodyDeleted 2. Generation 0 iff Enrollment, whose `enrollment_id` and `wallet_id` recompute. Head: complete `head`; zero predecessor capsule iff sequence 0. Terminal: zero last capsule iff Abandoned. Successors raise the generation by one: Enrollment → Head (sequence 0) or Terminal Abandoned; Head → Head (sequence + 1, linked capsule) or Terminal CustodyDeleted (last = capsule). The Bootstrap `enrollment_marker` is the generation-0 marker digest. |
| Output descriptor | `{kind, digest}` | `digest = H("output", ·)` over the statement digest, `proof_digest` (a nonzero canonical σ-field value) and, for Receive, the Payment digest the receipt binds (a canonical σ-field value): receipt-free, so the capsule freezes before the receipt. Every other kind input is bound by the statement. |
| Recovery capsule (`capsule` over the frame) | `{version, scheme_id, wallet_id, operation_id, kind, predecessor_capsule_digest, successor_state, statement, predecessor_lineage, step_proof, payment_digest, map_openings: [bytes], retained_inputs: [{role, bytes}], output}` | Retained roles: Request 1, Payment 2, Credited 3, LoadVoucher 4, ChargeQuote 5, PolicyUpdate 6, CertificateSet 7, Credential 8. State and statement agree on scheme, wallet, credential, asset, lifecycle, sequence and `next_load`; kind, effect kind and output kind agree; `operation_id` recomputes; zero predecessor capsule iff sequence 0; `predecessor_lineage` (the Ω recorded at fold time) is present exactly for Send, Unload and Retiring, passes the consumer checks for this wallet, and the successor's `burned_total` is its `burned_total`; the successor state's computed commitment is the statement's successor; `payment_digest` is a canonical σ-field value, nonzero exactly for Receive; the output rebuilds for every kind. Openings and retained inputs are non-empty, and the fold witnesses (every consumed input `Λ` verifies for the step, proposal §4.1) are retained: Receive needs Request, Payment, CertificateSet and Credential; ArchiveSent Request, Payment and Credited; Send the Request (the Payment binds its fee schedule only by digest); Load LoadVoucher and CertificateSet (the voucher's LoadAuthorization certificate); RefreshPolicy PolicyUpdate and CertificateSet. The receipt signs `capsule_digest`. Each map opening uses a §3.2 opening layout; which openings each kind retains is TODO(G3). |
| Completion record (`completion` over the frame) | `{version, wallet_id, operation_id, capsule_digest, receipt, output: bytes}` | Decoded against the expected wallet. `output` is the canonical compact Payment for Send, whose payer key and credential digest are the wallet's, and the canonical Package frame otherwise. Its receipt equals the record's; its statement, Ω(pred), σ and receipt Payment digest are the capsule's; its receipt-free parts rebuild the capsule's output descriptor; the receipt verifies over `capsule_digest`. |
| Fold record (`fold` over the frame) | `{version, scheme_id, wallet_id, LE128 first_sequence, LE128 sequence, head, capsule_digest, lineage: Ω}` | The self-verified Ω of one folded head covering the run `first_sequence..=sequence`. Nonzero identities and capsule digest; complete `head`; Ω valid with this scheme, wallet and head; `first_sequence ≤ sequence`. |

### 3.6 Ledger objects

| Object | Frame and transcript | Interoperability rules |
|---|---|---|
| Load voucher (signed under `kgwvchr1`) | `LE16 version ‖ scheme_id ‖ asset_digest ‖ wallet_id ‖ LE128 ordinal ‖ LE128 amount ‖ LE128 online_charge ‖ charge_quote ‖ transaction_hash ‖ LE64 block_height ‖ authorizer_certificate` | LoadAuthorization-role signer. `block_height ≥ 1`; `amount > 0`; `charge_quote` nonzero iff `online_charge > 0`, and then a Load quote with the same scheme, asset, wallet, ordinal, net amount and charge; `amount + online_charge` fits. A state absorbs it only at its `next_load`. |
| Unload claim | `{version, credential, package, account: AccountId, charge, certificates}`; charge None 0 or Quoted 1 `{quote, beneficiary: AccountId}` | Certificates exactly the issuer plus the quote signer when quoted. `H("account", account)` equals the credential's account digest. The package is a verified Unload carrying Ω(pred), which names the credential's wallet and payment key and passes the consumer checks; `charge` is Quoted iff the effect names a quote, which must be an Unload quote for the effect's exact terms, with `H("account", beneficiary)` as its beneficiary. Payout `amount − online_charge`. |
| Fee claim | `{version, payment, beneficiary: AccountId}` | Structurally a valid Payment naming a fee schedule with `fee > 0`. The payout is checked against the historical schedule the Payment names (digest, scheme, asset, `fee = fee(amount)`), and `H("account", beneficiary)` equals its beneficiary. Full verification takes the schedule, the receiver's Request and the payer's credential and certificates from the ledger's records by the digests the Payment binds, and verifies the Payment as at Receive. |
| Ledger control (signed under `kgwlctl1`) | `LE16 version ‖ scheme_id ‖ asset_digest ‖ wallet_id ‖ tag action ‖ fields zero-filled to 80 ‖ nonce` | Actions Activate 1 `{package_digest}`, CloseLoads 2 `{package_digest, LE128 next_load}`, Abandon 3 `{enrollment_id, LE128 marker_generation, terminal_marker_digest}`. Signed by the wallet payment key; nonzero digests; `marker_generation ≥ 1`. |
| Activation | `{version, control, credential, bootstrap: Package, asset: AssetScope, certificates}` | Certificates exactly the issuer; asset digest equals the credential's; an Activate control by the credential's key naming the digest of the verified Bootstrap package. |
| Close loads | `{version, control, credential, package, certificates}` | A CloseLoads control naming the digest and `next_load` of a verified Retiring, Send or Unload package (so carrying Ω(pred) and passing the consumer checks) whose lifecycle is Retiring. |
| Abandonment | `{version, control, payment_key, challenge_digest}` | An Abandon control whose `enrollment_id` and `wallet_id` recompute from `payment_key` and `challenge_digest`, naming the generation and digest of the Terminal Abandoned marker. Signing only after that marker is durable is design only (G2). |

Exactly-once payouts per nullifier and per `credit_id`, recording activation and
closure, and rejecting Abandon after Activate (and Activate or loads after
Abandon) are ledger state: design only, TODO(G6).

## 4. Measured sizes

Worst-case valid envelopes, printed by `size_tests.rs`. The Payment and Request carry
a fee schedule and two Request certificates. σ_send is the 3,296-byte proof of
`sigma_send` (`iroha_kagemusha_proof`, the §3.2 layout, `k = 12`, one lane; the
exact descriptor length, also with the blacklist list-age control) and σ_recv the
3,296-byte `sigma_recv` at that shape; neither yet carries the blacklist non-membership,
quota or lease checks (§7, TODO(G3)). Ω is unmeasured: the rows use the named
placeholder Ω transport proof of 4,000 bytes (TODO(G3)). The Request account digests
add 66 bytes to every Request and Payment, and the fixed 32-sibling credit opening fixes
the Credited::Status overhead; values marked † are computed from the frame layout until
`size_tests.rs` re-measures them (TODO(G1)). `F_payment` = 1,681† bytes with the joint
budget 8,319† bytes (`KAGEMUSHA_WALLET_PAYMENT_FIXED_BYTES_V1`,
`KAGEMUSHA_WALLET_PAYMENT_PROOF_BUDGET_V1`), and `F_status` = 2,188† bytes with the Ω cap
7,812†, are pinned constants that the size test and the verifying-key allowlist check;
they hold for Ω and σ lengths of 128 to 9,999 bytes each.

| Envelope | Bytes / bound | Fixed overhead | Largest fitting proof |
|---|---:|---|---|
| Offer (credential frame 618 / 1,024) | 1,104 / 2,048 | — | — |
| SessionControl (signed ReceiveDeferred) | 338 / 2,048 | — | — |
| Request (fee schedule, 2 certificates) | 1,801† / 10,000 | — | — |
| Payment (σ_send 3,296; Ω proof 4,000) | 8,977† / 10,000 | 1,681† + Ω proof + σ_send | Ω proof 5,023† with the measured σ_send; Ω proof + σ_send 8,319† |
| Credited::Receive (σ_recv 3,296) | 3,975 / 10,000 | 679 + σ_recv | — |
| Credited::Status (Ω(h) proof 4,000; CreditStatus frame 6,133†) | 6,188† / 10,000 | 2,188† + Ω(h) proof | Ω(h) proof 7,812† |
| Lineage (Ω proof 4,000) | 4,413 / 10,000 | 413 + Ω proof | — |
| PolicyData certificates (3) | 698 / 10,000 | — | — |

A Send package alone is 5,358 bytes with a 1,000-byte Ω proof and 8,358 with a
4,000-byte one (1,062 bytes beyond the two proofs). Other measured frames: the
largest Android renewal request (8 certificates totalling 65,536 DER bytes) is
66,021 of 73,728 bytes; a 64-window quota share is 2,941 bytes; the full
65,535-entry blacklist, an online download rather than an envelope, is 2,228,433 of
2,228,736 bytes. Vector frames with 48-byte stand-in σ and Ω proofs: envelopes
Credited::Receive 725 and Lineage 460; standalone scheme 208, certificate 222,
credential 618 and fold record 616. The Payment, Credited::Status, Receive recovery
capsule and verifying-key allowlist vector frames change with the TODO(G1) items and
are re-measured with them.

## 5. Vectors

`fixtures/kagemusha/wallet_v1_vectors.json` holds the prefix and digest rule, one
digest vector per SHA-256 role (34: body, preimage, digest), 18 signature vectors, each
with its transcript, signing domain and 32-byte message `m`, and their high-S twins
(`codec_ok` false, `verify_ok` true), the low-S boundary scalars (`s = floor(n/2)`
accepted; `floor(n/2) + 1`, `r` or `s` zero or `n` rejected), nine envelope vectors
(header fields, padding, CRC, canonical bytes, `kgm1:` text and bound), the 26 frame
identities and caps, 30 pinned object frames, the enum tag table, and:

- `field_encodings`: the modulus, the element, Poseidon and packing rules, the 43
  Poseidon domains (the 26 of §3.2 and the 17 signing domains of §1), the element lists
  of every map value and the credit-digest value, a `send_chain` append from the empty
  chain and a `recv_chain` append with their chain values, a Send and a Receive
  statement with their σ digests, a Receive successor state's core and rest elements,
  rest digest and commitment, and the same for a `controlled_state` (Retiring, every
  control enabled, every policy object held) whose 32 core and 13 rest elements are
  pairwise distinct, with every field's value by name, so that each consumer binds every
  element position to its field;
- `poseidon`: one `P` known-answer vector per domain (over `[1, 2, 3]`), the `P_bytes`
  packing at lengths 0, 1, 30, 31, 32, 62 and 63, `credit_id` with its 28 elements, both
  `proof_digest` domains, the Payment, lineage, credit-opening, credit-status and
  credited digests and the signed message of each signed body (bodies, element counts,
  digests), every map value with its key, the indexed tree (the empty slot, the sentinel
  leaf, the empty-tree root, successive insertions at slots 1, 2, … with every
  intermediate root, a membership opening, non-membership openings through the
  sentinel and through an interior low leaf, a quota-usage update and a
  pending-outgoing removal), the `CreditStatus` credit-digest opening, the blacklist
  leaf, node, root and a gap opening over entries whose unsigned byte order differs
  from their limb order, the quota-window leaf, empty slot, node and root, and the
  verifying-key allowlist transcript and digest.

The vectors are self-consistent (TODO(G1)): the vectored relation identity and artifact
manifest bind the computed `verifying_key_set_digest` of the vectored allowlist, so that
allowlist decodes against the vectored manifest, and no separate stand-in digest
exists; every σ stand-in has exactly its selector's `proof_bytes`, and every Ω stand-in
(Payment, Lineage, CreditStatus, fold record and capsule) exactly the allowlist's
`lineage_proof_bytes`.

The `P` values reproduce `fixtures/native_prover/kats_v1.json` (`kagemusha_v1_poseidon`),
which the Rust tests check. Keys come from fixed scalars; signatures are RFC 6979, frozen
to low S; stand-ins follow the labelled rules in `stand_ins`. The Rust test
`kagemusha_wallet_v1_vectors_file_matches_the_generated_vectors` compares the file
byte for byte; `IROHA_UPDATE_KAGEMUSHA_WALLET_VECTORS=1` rewrites it (test-only).
The Kotlin (`KagemushaWalletVectorsV1Test`) and Swift (`KagemushaWalletVectorsV1Tests`)
consumers recompute the SHA-256 digests, verify each signature vector over its pinned
message `m` after the low-S rule, validate envelope headers and per-kind bounds, and
round-trip `kgm1:` text; typed SDK decoding of message bodies is TODO(G4). Their role
tables (34 roles; the retired roles, including every `-body` role and `lineage`,
`credit-opening`, `credit-status` and `credited`, rejected) and element-list checks
follow this revision: element counts, the state and statement elements re-derived from
their frames and transcripts, the named `controlled_state` positions, the `P_bytes`
packing and the indexed-tree openings' structure. Neither SDK recomputes `P` values;
`iroha_kagemusha_proof` reproduces them natively and in circuit
(`tests/digest_parity.rs`).

## 6. Carriers

Every peer message travels as one complete canonical envelope frame (§2). A carrier
moves that frame unchanged; its framing is outside every digest and signature and
grants no authority. Before handing a frame to the wallet, a carrier checks it
structurally (`KagemushaWalletWireV1.inspectEnvelope`): the byte cap, the Norito header,
schema hash, flags, padding, CRC and exact field spans, the envelope version, a known
message tag and the per-kind bound, without the expected-scheme check. Swift also checks
the message's top-level version and that its decode-time scheme field is 32 bytes; Kotlin
does not yet (TODO(G4), §7). Nested version fields, the scheme check, typed decoding and
signature verification stay with the wallet (TODO(G4)). The implementations are
Swift `IrohaPeerWireV1`, `IrohaPeerQRV1`, `IrohaPeerNfcV1` and `IrohaPeerNearbyV1`
(`IrohaSwift`, with the platform adapters in `IrohaSwiftMobileTransports`) and the
Kotlin `org.hyperledger.iroha.sdk.offline.IrohaPeer*` types (`kotlin/core-jvm`, with
the Android NFC and Nearby adapters in `client-android`). Their tests carry the
envelope vectors of §5 and structural envelopes of every kind.

**IPM1 message.** An 84-byte header, then the encoded body:

| Offset | Bytes | Content |
|---:|---:|---|
| 0 | 4 | magic `IPM1` |
| 4 | 1 | wire version `1` |
| 5 | 1 | encoding: `0` none, `1` zlib |
| 6 | 2 | profile, big-endian: `1` KAGEMUSHA wallet V1 (`0` is reserved and rejected) |
| 8 | 1 | kind: the envelope message tag (Offer 1, Request 2, Payment 3, Credited 4, SessionControl 5, PolicyData 6, Lineage 7) |
| 9 | 1 | flags `0` |
| 10 | 2 | schema version, big-endian: `1` |
| 12 | 4 | canonical (frame) length, big-endian |
| 16 | 4 | encoded body length, big-endian |
| 20 | 32 | canonical hash: BLAKE2b-256 of `"IROHA-PEER-PAYLOAD-V1" ‖ 0x00 ‖ BE16 profile ‖ kind ‖ BE16 schema ‖ frame` |
| 52 | 32 | wire hash: BLAKE2b-256 of `"IROHA-PEER-MESSAGE-V1" ‖ 0x00 ‖ header bytes 0..52 ‖ body` |

- The canonical payload is exactly one envelope frame whose message tag equals the
  IPM1 kind, within that kind's bound (2,048 bytes for Offer and SessionControl,
  10,000 otherwise). Both lengths are positive and at most 10,000.
- zlib is the RFC 1950 form (`78 9C`, DEFLATE, Adler-32 of the frame). A sender uses it
  only when it saves at least 32 bytes and at least one 256-byte QR shard; a decoder
  rejects any other zlib header or length pair.
- Decoding checks the header and both bounds before allocating, then the total length,
  the wire hash, decompression to exactly the declared length, the envelope, and the
  canonical hash. The stream identifier is the first 16 bytes of the wire hash.

**QR.** A QR text is `IQR1:` ‖ Base45 (RFC 9285, canonical) of one `IRQR` frame ‖ `:`,
at most 700 bytes. An `IRQR` frame is `"IRQR" ‖ 1 ‖ frame kind ‖ BE16 profile ‖ IPM1
kind ‖ 0 ‖ stream identifier (16) ‖ BE16 index ‖ BE16 total ‖ BE16 payload length ‖
payload ‖ BE32 CRC-32C` of everything before the checksum; frame kinds are complete 0,
header 1, data 2 and parity 3. A message whose complete frame fits one text may be shown
as that single static text. Otherwise the sequence is the header frame (the 84-byte IPM1
header), then
256-byte data shards (the last zero-filled) with one XOR parity shard per pair, in the
order D0, D1, P0, D2, D3, P1, …, and the identical header again after every 12
non-header frames; `total` counts data shards (40 for a 10,000-byte body). A receiver
accepts frames in any order, ignores identical duplicates, recovers one missing shard
per pair from parity, quarantines a stream on a conflicting duplicate or an invalid
message, bounds active streams (3) and frames before the header (12 frames, 3,072 bytes
per stream), and decodes only a complete message.

**NFC.** ISO/IEC 7816 application `F0504B45504B524E464301`, proprietary class `0x80`,
chunks of at most 4,096 bytes and messages of at most 10,084 bytes (header plus 10,000).
One session carries the receiver-hosted Request, the payer's Payment (begun, written in
contiguous chunks and committed) and the receiver's durable acknowledgement, which is
the Credited envelope. The receiver exposes Credited only after the Payment is durably
admitted; a resumed or retried session must present the byte-identical Payment. The
Kotlin carrier also requires the Payment to carry exactly the hosted Request's signed
body and signature, and Credited to name that Request's scheme
(`KagemushaWalletWireV1.requireExchangeBinding`); the Credited evidence itself is checked
by the wallet's typed decoder (TODO(G4)). TODO(G4): Offer and SessionControl
over NFC; until then the receiver obtains the Offer over another carrier before it
builds the Request.

**Nearby and Petal.** A Nearby session (service `org.hyperledger.iroha.kagemusha.transfer.v1`)
authenticates both devices and then carries complete IPM1 messages of at most 32,704
bytes in encrypted, per-direction sequenced records; the Kotlin session opens a record
only to a verified IPM1 message of its profile. Petal Stream ([petal_stream.md](petal_stream.md))
carries the encoded IPM1 message with the IPM1 kind as its `kind` byte. Transport
encryption and checksums never replace the wallet's verification.

## 7. Open items

- TODO(G4): Offer and SessionControl over the NFC carrier (§6).
- TODO(G4): the Kotlin `inspectEnvelope` accepts a message whose own top-level version
  is not 1 or whose decode-time scheme field is malformed, which the Swift carrier
  and the Rust decoder reject (§6); no carrier checks nested version fields yet.
- TODO(G1): the second-set items listed in the status paragraph: the signing message
  and the 34-role SHA table (§1), the `P_bytes` lineage, credit-opening, credit-status
  and credited digests, the indexed map trees and openings (§3.2), the blacklist limb
  order and enforcement (§3.3), the Request account digests and the Request, Send and
  Receive rules (§3.4), the Receive allowlist entry with the 8,319 and 7,812 budgets
  (§3.1), the re-measured sizes (§4) and the vector consistency rules (§5), in the data
  model, the vectors, the Advance provider, the platform signers and both SDKs.
- TODO(G3): the PIPA-v1 σ layout, the Ω transport-proof layout, their exact lengths
  and the frozen verifying keys. Once the artifacts freeze, the verifying-key allowlist
  (§3.1) carries them; its validation requires Ω proof + largest σ_send ≤ 8,319 bytes
  (R9) and Ω proof ≤ 7,812 bytes. Until then σ and Ω are bounded only by their frames,
  and the vectors' allowlist is a labelled stand-in.
- TODO(G3): σ_send's blacklist control enforces only the maximum list age; the
  receiver non-membership opening, the quota windows and usage update and the lease
  check are not in `iroha_kagemusha_proof` yet, and σ_recv has no blacklist variant.
  The 28-element `credit_id`, the in-circuit signature check over the 32-byte Poseidon
  message, the indexed map trees in circuit (Λ), the capsule's retained openings and
  the `artifact_inventory_digest` preimage are also open. The step relations already
  follow §3.2 (the 28-element statement, the 32-element core and 13-element rest and
  the chain domains) and reproduce its vectors.
- Open owner questions: the Payment digest is `P_bytes` over the 163-byte `payment`
  transcript, not over the whole Norito Payment frame (a G1 reading of the proposal's
  "Payment transcript", §5.1). Choices this record makes for the second set: relations
  check only that an inserted slot was empty, and the next free index is a native rule
  that no root commits (§3.2); removal unlinks and clears a slot without reuse (§3.2);
  the Receive verifying key is selected by the blacklist bit alone (§3.1); the
  allowlist caps Ω at 7,812 bytes so that Credited::Status fits (§3.1); the receiver's
  blacklist is checked at Receive against the list committed at that head, so a list
  committed between Request and Receive can refuse an already committed Payment, which
  stays deliverable (§3.4); and the statement and 96-byte object digests stay `H`
  although `Λ` recomputes them for every receipt, credential and Request it verifies
  (§1).
- TODO(owner), kept as is: a Send capsule retains the Request message (§8);
  `Λ_load` and `Λ_unload` do not verify ChargeQuote signatures; a Retiring wallet's
  refusal to issue Requests is wallet behaviour (TODO(G4)).
- TODO(G5): `app_policy` and `enrollment_policy` preimages with the Torii
  enrollment family; issuer verification of renewal evidence.
- TODO(G4/G6): JavaScript, Python and C# consumers when their wire copies migrate.
- TODO(G6): the ledger instruction family; TODO(G3/G6): the release install path
  carrying the artifact manifest.

## 8. Differences from the implementation design

- The full blacklist cap is 2,228,736 bytes, not the design's 2,228,224, which
  would reject a maximum list (2,228,433 bytes). SDKs take the cap from the vectors.
- The marker terminal reason, output descriptor kind and retained-input role are
  Norito enums, not `u8` fields: their frames carry 4-byte tags, and the `marker`,
  `capsule` and `completion` digests cover those frames.
- Frame padding follows the type's archived alignment, not every contained `u128`:
  a `u128` reached only through a sequence (quota share windows) adds no padding.
  Use the per-type table of §2.
- The credit-opening siblings are one flat byte string of 32-byte values, not a
  sequence of 32-byte arrays: Norito would spend 65 bytes per array element inside
  the 10,000-byte Credited bound.
- The ArchiveSent capsule also retains the Request, which the Payment binds only
  by digest. A Send capsule retains the Request it consumed (its fee schedule) and a
  Load capsule the voucher's certificate set, which the design's fold-witness list
  omits although `Λ` verifies them (proposal §§3.2, 4.1).
- Credited is verified against the payer's scheme as well as its Request and
  Payment, so a relation identity other than the scheme's is rejected natively.
