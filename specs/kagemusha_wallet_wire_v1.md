# KAGEMUSHA wallet wire record V1

**Status.** This record describes the canonical G1 wire objects of the single KAGEMUSHA
split-lineage design ([proposal](kagemusha_single_design_proposal.md) §§3, 3.1, 3.2,
4.1, 5.1, 7 and 8; §10, G1). They are implemented in
`iroha_data_model::kagemusha::kagemusha_wallet_v1`
(`crates/iroha_data_model/src/kagemusha/kagemusha_wallet_v1.rs` and its child files).
Their cross-language vectors are `fixtures/kagemusha/wallet_v1_vectors.json`. The NEW
first-release typed E1 policy pair additionally uses the unadmitted DATA
`fixtures/kagemusha/wallet_enrollment_policy_v1_vectors.json`; that pair
adds two SHA roles to the coordinated Model/Kotlin/Swift digest inventory; typed
foreign policy carriers and issuer ownership still require migration. Its
revision 2026-10-10 (Android signer set and minimum version, SPKI root set with a
revocation source per root, no Play Integrity field) regenerates those vectors, and
E5 Android evidence is the KeyMint chain only (§3.1). Both are app-attestation and
issuer-policy changes that land in the coordinated cutover of
[proposal §9.1](kagemusha_single_design_proposal.md#91-cutover-sequencing); they
change no layout in this record that a validator checks. Kotlin
`org.hyperledger.iroha.sdk.offline.KagemushaWalletWireV1` (`kotlin/core-jvm`) and Swift
`KagemushaWalletWireV1` (`IrohaSwift`) consume the vectors (§5), the Swift and Kotlin
peer carriers move envelope frames, the Lineage message included (§6), and the iPhone
and Android payment-key adapters sign exactly the 32-byte message of §1. The Durable
State Provider binds the operation-dependent `proof_digest` (§3.2) and signs the 32-byte
Poseidon message of §1. The shared Rust state owner assembles these objects and retains
their custody through the provider; native step relations consume the corresponding G1
layout. The native bridge opens a wallet only after authenticating its installation,
verifier pack, producer inventory and exact original source graph. The closed ledger
instruction family and account-authenticated Torii receipt/finality routes are
implemented. Qualification of their combined monetary flow on four validators and
the selected physical phones remains open; the
[verification checklist](kagemusha_evidence_gate.md) records that distinction.
The owner answers of 2026-10-05 (proposal
revision 2026-10-05) are implemented: the data model depends on `iroha_pasta` and
computes every Poseidon value natively (`credit_id`, the state commitment, chains, map,
blacklist, quota-window and credit-digest trees and openings, and the packed-byte
`proof_digest` and Payment digest). Proof bytes, relation bindings, verifying keys and
the lineage roots of the Payment's Ω(pred) in the vectors are labelled stand-ins; map
roots, credit-digest roots and openings are computed.

**Third set (2026-10-05, B1–B8; proposal revision 2026-10-05).** This record now fixes
the third set as the canonical G1 layout: every digest a relation recomputes is `P`, so the
object digests, the certificate-set, package, statement, operation and nullifier digests
leave the SHA-256 role table (B1, §§1, 3.2); the Request records the receiver blacklist
version and root used at issuance, Receive checks only that recorded list, and the
wallet keeps a blacklist history in the rest (B6, §§3.2, 3.4); the quota-usage map is a
depth-6 array aligned with the window slots and charged in place (B5, §3.3); the quota
share expiry and the maximum anchor response time are core fields, and σ_send enforces
the expiry and the Send time span (B7, B8, §3.3). The data model, shared vectors and Kotlin/Swift consumers implement this layout.
Proof-relation integration and qualification remain separate G3 work; §7 records open items.

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
chunk is below `2^248`, and the length element separates inputs whose chunks agree. Every
digest a relation recomputes is `P` or `P_bytes` (B1). `P` covers `credit_id` (§3.4), the
state commitment, rest digest, chains, the statement digest (the σ statement digest),
the object digests of the signed objects (below), the certificate-set (§3.1), package,
operation and nullifier digests (§3.2), the indexed map trees and the credit-digest tree
(§3.2), and the blacklist and quota-window trees and the quota-usage array (§3.3);
`P_bytes` covers `proof_digest` in both domains (§3.2), the Payment digest, the lineage,
credit-opening, credit-status and credited digests (§3.4), and every signed message
(below). The vectors pin every domain, the packing at the empty input and the 31-byte
chunk boundaries, and every value (§5).

- **Transcripts.** A body is a fixed-layout transcript of the object's fields in
  declaration order: fixed-width integers, raw digests, keys and signatures, and
  enums as a one-byte tag equal to the Norito tag. Existing fixed-union transcripts
  zero fill to a pinned union width. The NEW policy preimages use their exact selected
  arm and LE32-length-prefixed exact UTF8; see their separate contract. Nested
  fixed records are inlined. A reference to a signer certificate is its 32-byte
  certificate digest, a `P` value. Only the `account`, `evidence`,
  `verifying-key-set`, NEW `app-policy` and `enrollment-policy`, `marker`, `capsule-body`, `capsule`, `completion` and `fold` roles, the
  certificate-set digest and the lineage digest have variable-length inputs.
- **Signing.** Every P-256 signature of the protocol signs, as its message,
  the 32-byte canonical (little-endian, §3.2) encoding `m` of `P_bytes(d, transcript)`, where `d` is the
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
- **Object digest.** `P(d_obj, [m, r_lo, r_hi, s_lo, s_hi])` (5 elements) under the
  body's object-digest domain in the table below, where `m` is the signing message (one
  element) and `r_lo = r mod 2^128`, `r_hi = ⌊r / 2^128⌋` and likewise `s_lo`, `s_hi` are
  the numeric 128-bit halves of the big-endian `r` and `s` of `sig`; no P-256 scalar is
  reduced modulo `p` (in circuit the limbs are range-checked and linked to the raw
  big-endian `sig` bytes). The artifact manifest alone keeps `H("artifact-manifest", m ‖ sig)`
  (96-byte body), an artifact digest that no relation recomputes. A signature confers only
  its signer role's authority; decoding or validating grants no monetary authority.

Signed bodies (16; the transcript of each is in the section named, and the `-body`
SHA-256 roles do not exist):

| Signed body | Signing domain `d` | Transcript bytes | Signer | Object digest |
|---|---|---:|---|---|
| certificate (§3.1) | `kgwcert1` | 108 | scheme root | `P(kgwocrt1, ·)` |
| credential (§3.1) | `kgwcred1` | 476 | Enrollment | `P(kgwocrd1, ·)` |
| renewal challenge (§3.1) | `kgwrnch1` | 130 | payment key | none |
| renewal key binding (§3.1) | `kgwrnkb1` | 163 | payment key | none |
| artifact manifest (§3.1) | `kgwartf1` | 290 | Artifact | `H("artifact-manifest", m ‖ sig)` |
| receipt τ (§3.2, derived, never transmitted) | `kgwrcpt1` | 338 | payment key | `P(kgworcp1, ·)` |
| scheme policy (§3.3) | `kgwspol1` | 142 | RegulatoryPolicy | `P(kgwopol1, ·)` |
| fee schedule (§3.3) | `kgwfsch1` | 191 | RegulatoryPolicy | `P(kgwofee1, ·)` |
| blacklist (§3.3) | `kgwblst1` | 118 | RegulatoryPolicy | `P(kgwoblk1, ·)` |
| quota share (§3.3) | `kgwqshr1` | 190 | RegulatoryPolicy | `P(kgwoqsh1, ·)` |
| time anchor (§3.3) | `kgwtanc1` | 138 | TimeAnchor | `P(kgwotim1, ·)` |
| charge quote (§3.3) | `kgwchgq1` | 219 | RegulatoryPolicy | `P(kgwochg1, ·)` |
| offer (§3.4) | `kgwoffr1` | 194 | payer payment key | none |
| session control (§3.4, when signed) | `kgwsctl1` | 197 | session payment key | none |
| request (§3.4) | `kgwrqst1` | 458 | receiver payment key | `P(kgworeq1, ·)` |
| ledger control (§3.6) | `kgwlctl1` | 211 | payment key | none |

SHA-256 role table (all 21 labels of `KagemushaWalletDigestRoleV1`). `H` remains only for
`scheme_id`, the identities fixed at enrollment that no relation recomputes (asset scope,
wallet, enrollment), the enrollment and renewal transcripts given to platform
attestation, `account`, the artifact digests, the evidence digest, the output descriptor
and the local custody records (B1):

| Role | Body | Bytes | Why SHA-256 |
|---|---|---:|---|
| `scheme` | scheme transcript (§3.1) | 163 | fixed identity; ledger and artifact boundary |
| `relation` | relation transcript (§3.1) | 162 | artifact digest; carried, never recomputed in a relation |
| `provider-contract` | `LE16 1 ‖ "kagemusha-advance-pedersen-capsule-v1"` zero-padded to 64 | 66 | constant |
| `asset-scope` | asset scope transcript (§3.1) | 54 | fixed identity; ledger boundary |
| `account` | complete canonical Norito frame of the domainless `AccountId` | var | ledger boundary; the ledger derives it from the `AccountId` |
| `enrollment-challenge` | §3.1 | 194 | platform-attestation challenge, used only by the issuer |
| `app-policy` | NEW [typed app identity](kagemusha_wallet_enrollment_policy_v1.md) | ≤431 Android, ≤294 Apple | fixed initial selection; no approval implied; the Android arm changes at the proposal §9.1 cutover |
| `enrollment-policy` | NEW [typed platform/regulator/lifetime policy](kagemusha_wallet_enrollment_policy_v1.md) | 174–572 Android, 167 Apple | selected issuer inputs; no approval implied; the Android arm changes at the proposal §9.1 cutover |
| `enrollment-id`, `enrollment-key-binding` | `challenge_digest ‖ payment_key` | 97 | enrollment transcript; App Attest client data |
| `wallet-id` | `scheme_id ‖ asset_digest ‖ payment_key ‖ enrollment_id` | 161 | fixed identity; carried, never recomputed in a relation |
| `artifact-manifest` | `m ‖ sig` of the signed artifact manifest | 96 | artifact digest |
| `evidence` | `tag kind ‖ LE32 count ‖ (LE32 len ‖ original bytes)…` | var | raw platform attestation, used only by the issuer |
| `renewal-assertion` | renewal transcript (§3.1) | 130 | App Attest client data |
| `verifying-key-set` | verifying-key allowlist (§3.1) | 42+41n | artifact digest, bound through the relation identity |
| `output` | `tag operation_kind ‖ statement_digest ‖ proof_digest ‖ payment_digest or zero` | 97 | local; no relation recomputes it |
| `capsule-body` | exact canonical `RecoveryBodyV1` frame B (§3.5) | var | private input to the binding commitment; no relation recomputes it |
| `marker`, `capsule`, `completion`, `fold` | complete canonical Norito frame of the local object (§3.5); `capsule` hashes the entire body-and-opening wrapper W | var | private custody record; no relation recomputes it |

`credit_id`, `proof_digest`, the Payment digest, the lineage, credit-opening,
credit-status and credited digests, every signed message, the object digests (except the
artifact manifest's), the certificate-set, package, statement, operation and nullifier
digests, map values, leaves and roots, chains, the state commitment and the blacklist,
quota-window, quota-usage and credit-digest trees are not SHA roles: they are `P` or
`P_bytes` values under the domains of this section and §3.2.

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
  vectors pin the name and schema hash of all 29 framed types (envelope:
  `f03a9dc47142299cad9ffe0b2115fd42`).
- `p` is a property of the type, never inferred from the bytes. It is 8 when a
  `u128` is reachable without passing through indirect Vec-backed storage (archived
  alignment 16;
  the envelope payload starts at byte 48), and 0 otherwise. The wallet model pins
  every record or enum with a direct `u128` field to `repr(align(16))`; enclosing
  records, enums and inline fixed arrays inherit that alignment, while indirect
  Vec-backed storage does not inherit its elements' alignment. All 29 frame padding values below are compile-time
  assertions. `armv7`, `aarch64` and `x86_64` use this one layout and the existing
  canonical bytes, schemas, flags and payload encodings. There is no target-specific
  decoder or alternate-padding acceptance. Native runtime and physical-device
  qualification remain separate from the frame contract.
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
  Credited (both forms), Lineage, FoldRecord, Package, LoadReceipt, LoadFinality, SchemePolicy,
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
| σ bytes and Ω transport-proof bytes | ≥ 1, with exact source-specific lengths in the verifying-key allowlist (§3.1); every σ ≤ 3,520 and Ω ≤ 5,044. The independent Payment joint bound is Ω + σ_send ≤ 8,564 = 10,000 − F_payment (F_payment = 1,436, §4). The Receive 9,321-byte and Status 7,812-byte envelope budgets do not relax these role caps. |
| Map and credit-digest opening siblings | exactly 32 (§3.2) |
| Quota-usage array and quota-window openings | exactly 6 siblings (§3.3) |
| Verifying-key allowlist entries | 8..=16 (one per operation; Send also per enabled-controls mask; Receive also for a Request-recorded blacklist decision) |
| Certificates per set | ≤ 3 |
| Blacklist entries | ≤ 65,535 |
| Quota windows per share | 1..=64 |
| Android enrollment (E5) and renewal chain: certificates; each DER; total DER | 2..=8; 1..=16,384; ≤ 65,536 |
| App Attest enrollment attestation; enrollment and renewal assertion | 1..=65,536; 1..=4,096 |
| Completion record output bytes | 1..=10,000 |
| Asset scale; fee basis points | ≤ 28; ≤ 10,000 |

Standalone frame caps (complete frame, checked before decoding) and padding:

| Type | Cap | p | Type | Cap | p |
|---|---:|---:|---|---:|---:|
| `SchemeV1` | 512 | 0 | `PaymentV1` | 10,000 | 8 |
| `SignerCertificateV1` | 512 | 0 | `PackageV1` | 10,000 | 8 |
| `CredentialV1` | 1,024 | 0 | `MarkerV1` | 1,024 | 8 |
| `RenewalRequestV1` | 73,728 | 0 | `RecoveryCapsuleV1` | 524,288 | 0 |
| `ArtifactManifestV1` | 1,024 | 0 | `CompletionRecordV1` | 65,536 | 0 |
| `VerifyingKeyAllowlistV1` | 2,048 | 0 | `LoadFinalityV1` | 262,144 | 0 |
| `SchemePolicyV1` | 1,024 | 0 | `FoldRecordV1` | 10,000 | 8 |
| `FeeScheduleV1` | 1,024 | 8 | `LoadReceiptV1` | 512 | 8 |
| `BlacklistV1` | 2,228,736 | 0 | `UnloadClaimV1` | 16,384 | 8 |
| `QuotaShareV1` | 8,192 | 0 | `FeeClaimV1` | 16,384 | 8 |
| `TimeAnchorV1` | 512 | 0 | `LedgerControlV1` | 1,024 | 8 |
| `ChargeQuoteV1` | 1,024 | 8 | `ActivationV1` | 16,384 | 8 |
| `EnvelopeV1` | per kind | 8 | `CloseLoadsV1` | 16,384 | 8 |
| `QuotaRefreshWitnessV1` | 8,192 | 8 | `AbandonmentV1` | 1,024 | 8 |
| `RecoveryBodyV1` | 524,288, also subject to its complete wrapper cap | 8 | | | |

Type names omit the `KagemushaWallet` prefix. `LoadReceiptV1` has the canonical
`iroha_data_model::isi::kagemusha_wallet` namespace; the other wallet frames use
`iroha_data_model::kagemusha::kagemusha_wallet_v1`. The blacklist cap is
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
| Verifying-key allowlist (`verifying-key-set`) | `LE16 version ‖ LE32 n ‖ n × (tag kind ‖ LE32 enabled_controls ‖ verifying_key_digest ‖ LE32 proof_bytes) ‖ lineage_verifying_key_digest ‖ LE32 lineage_proof_bytes` | Frame `{version, steps: [{kind, enabled_controls, verifying_key_digest, proof_bytes}], lineage_verifying_key_digest, lineage_proof_bytes}`. One σ entry per selector, strictly ascending by `(tag, mask)`, at most 16: every operation with mask 0, Send also once per supported enabled-controls mask (defined bits only), and Receive also once with mask 1 (BLACKLIST) exactly when some Send mask has bit 0; digests nonzero; lengths at least 1 and σ at most 3,520, including both Receive selectors. The complete Credited::Receive envelope budget is independently 9,321 (`10,000 − F_receive`; §4). `lineage_proof_bytes` plus the largest Send `proof_bytes` is at most `10,000 − F_payment` (R9; 8,564 with the single-owner Payment frame, §4), and `lineage_proof_bytes` is at most 5,044. The Credited::Status envelope separately permits at most 7,812 bytes with its fixed opening (§2, §4); that spare capacity cannot enlarge the Ω role cap. A consumer selects σ's entry by the package's operation tag; for Send also by its mask (`Ω.enabled_controls`), and for Receive by the decision its Request records: selector `(Receive, 1)` iff `receiver_blacklist_version ≠ 0` (§3.4), whatever the receiver's current enabled-controls bits, so verifying a Receive package takes its Request. It requires σ and Ω(pred) to have exactly the listed lengths. The frame decodes only against a manifest body whose `verifying_key_set_digest` it recomputes. |
| Provider contract | see §1 | Constant `ac0c9bdca39a5a00385214934f0299da60d5ff1425aa270c535a462247a9fa1e`. |
| Asset scope (`asset-scope`) | `LE16 version ‖ asset UUID (16) ‖ asset_incarnation ‖ LE32 scale` | Frame `{version, asset: AssetDefinitionId, asset_incarnation, scale}`. UUIDv4 asset, valid `AxtAssetIncarnationV1`, `scale ≤ 28`. Gives `asset_digest`. |
| Signer certificate (signed under `kgwcert1`) | `LE16 version ‖ scheme_id ‖ tag role ‖ key ‖ LE64 serial` | Signed by the scheme root. Roles: Enrollment 1, RegulatoryPolicy 3, TimeAnchor 4, Artifact 5. Tag 2 is invalid. Fixed depth one; no validity period or revocation is evaluated offline; the consumer requires the role it needs. Its digest `P(kgwocrt1, ·)` (§1) is what every `*_certificate` field names, a canonical σ-field value. |
| Certificate set (`kgwcset1`) | `count`, then the certificate digests in set order (one element each) | Frame `{certificates}`: at most 3, unique, strictly ascending by certificate digest (unsigned byte order). Each carrier holds exactly the certificates it needs, with the required roles and scheme. Its digest is `P(kgwcset1, [count, digests…])`, one canonical σ-field value. |
| Enrollment challenge (`enrollment-challenge`) | `LE16 version ‖ scheme_id ‖ asset_digest ‖ account_digest ‖ app_policy ‖ enrollment_policy ‖ issuer_nonce` | All nonzero. `challenge_digest` is the KeyMint attestation challenge and the App Attest attestation `clientDataHash`. The App Attest enrollment assertion `clientDataHash` is `H("enrollment-key-binding", challenge_digest ‖ payment_key)`. H values go to App Attest unchanged. |
| Evidence digest (`evidence`) | `tag kind ‖ LE32 count ‖ (LE32 len ‖ bytes)…` | Kinds: AndroidKeyMintTee 1, AndroidKeyMintStrongBox 2, AppleAppAttest 3. Non-empty original items, never rewritten: Android, exactly the KeyMint attestation DER chain, leaf first; Apple, the attestation object, then the fresh key-binding assertion. The attested security level selects the Android kind. No vendor online verdict, decoded token or signing input is an evidence item. The issuer computes this digest and the wallet recomputes it at E6; a validator sees only the nonzero 32-byte value in the evidence record, whose layout is unchanged. This Android preimage applies from the proposal §9.1 cutover. Renewal follows its separate evidence contract. |
| Enrollment platform evidence (E5, frame only) | `PlatformEvidenceV1`: Android `{certificates: [der]}`; Apple `{key_id, attestation, key_binding_assertion}` | Wallet-to-issuer exchange only; no ledger instruction, validation rule or state decodes it. The exact originals the phone sends in E5, carried as canonical bytes inside the account-signed request, within the §2 bounds. Android carries the KeyMint chain only: no token or other field. Apple `key_id` is nonzero. The arm must match the selected enrollment policy's platform. The issuer admits the evidence under the [enrollment policy](kagemusha_wallet_enrollment_policy_v1.md) rules. The Android arm changes at the proposal §9.1 cutover. |
| Issuer-retained evidence (E6, frame only) | `IssuerEvidenceV1`: Android `{certificates: [der]}`; Apple `{attestation, key_binding_assertion}` | Issuer-to-wallet exchange only. The issuer returns, byte for byte, the E5 originals it verified; the credential's evidence digest is recomputed from them before delivery and again at the wallet's E6 intake. It adds no issuer-acquired item. The Android arm changes at the proposal §9.1 cutover. |
| Evidence record (inline, 56) | `digest ‖ LE64 time_ms ‖ LE32 facts ‖ LE32 os_patch_level ‖ LE32 vendor_patch_level ‖ LE32 boot_patch_level` | Fact bits below; `digest` nonzero. |
| Regulatory policy (inline, 20) | `LE32 permitted_controls ‖ LE64 blacklist_max_age_ms ‖ LE64 time_anchor_max_response_ms` | Controls: bit 0 BLACKLIST, 1 QUOTAS, 2 ATTESTATION_LEASE; others zero. `blacklist_max_age_ms > 0` requires bit 0. `time_anchor_max_response_ms > 0` iff bit 1, bit 2 or `blacklist_max_age_ms > 0`. The policy is fixed for the incarnation; with bit 1 every quota window a wallet installs is longer than `time_anchor_max_response_ms` (B8, §3.3). |
| Credential (signed under `kgwcred1`) | `LE16 version ‖ scheme_id ‖ asset_digest ‖ wallet_id ‖ account_digest ‖ payment_key(key) ‖ provider_contract ‖ tag evidence_kind ‖ enrollment_evidence(56) ‖ fresh_evidence(56) ‖ app_policy ‖ regulatory_policy(20) ‖ enrollment_id ‖ LE64 issued_at_ms ‖ LE32 renewal_sequence ‖ LE64 lease_expires_at_ms ‖ issuer_certificate` | Enrollment-role signer. Nonzero bindings; V1 provider contract even without a scheme; `wallet_id` recomputes. Renewal 0 requires `fresh_evidence = enrollment_evidence`; later renewals require `fresh.time_ms ≥ enrollment.time_ms`. `lease_expires_at_ms ≠ 0` iff the lease is permitted. A replacement changes only `fresh_evidence`, `issued_at_ms`, `lease_expires_at_ms` and `issuer_certificate`, and `renewal_sequence` is the predecessor's plus one. |
| Renewal transcripts | renewal challenge and `renewal-assertion`: `LE16 1 ‖ scheme_id ‖ wallet_id ‖ credential_digest ‖ challenge`; renewal key binding: `LE16 1 ‖ scheme_id ‖ wallet_id ‖ challenge ‖ new_attested_key` | The payment key signs the renewal challenge under `kgwrnch1` (possession) and, on Android, the key binding under `kgwrnkb1` (§1). The App Attest renewal assertion's client data is `H("renewal-assertion", ·)`. |
| Renewal request (frame only) | `{version, scheme_id, wallet_id, credential_digest, challenge, possession_signature, evidence}` | Evidence: Android 1 `{new_attested_key, key_binding_signature, chain: [{der}]}` or Apple 2 `{assertion}` within the §2 bounds, on the credential's platform. Issuer verification of the chain or assertion is TODO(G5). |
| Artifact manifest (signed under `kgwartf1`) | `LE16 version ‖ network_id ‖ relation_id ‖ eq_protocol_digest ‖ ep_protocol_digest ‖ native_profile_digest ‖ verifying_key_set_digest ‖ artifact_inventory_digest ‖ provider_contract ‖ signer_certificate` | Artifact-role signer. Bindings nonzero; `relation_id` recomputes from the five bindings; network, relation and provider contract equal the scheme's. |

Fact bits: 0 HARDWARE_BACKED_KEY, 1 STRONGBOX, 2 BOOTLOADER_LOCKED, 3 VERIFIED_BOOT,
4 PATCH_POLICY_MET, 5 APP_SIGNING_IDENTITY, 6 APP_ATTEST_GENUINE_DEVICE,
7 APP_ATTEST_KEY_BINDING, 8 APP_ATTEST_PRODUCTION, 10 REVOCATION_LIST_CLEAR,
11 LOCAL_COMPROMISE_CHECKS_CLEAR; bit 9 and bits 12–31 are reserved zero.
Android records never carry 6–8; Apple records never carry 0–5 and have zero
patch levels. Enrollment evidence requires bits 0, 2, 3 and 5 on Android (plus 1 for StrongBox; TEE forbids 1) and bits 6 and 7 on Apple. These are
the record-validity rules every consumer, validators included, checks natively;
bit 9 is rejected in enrollment evidence and renewal fresh evidence alike.

Issuer policy (enrollment policy revision 2026-10-10, from the proposal §9.1
cutover) decides which valid bits an issued record carries. The E1 issuer sets
exactly the facts it verified: on Android bits 0, 2, 3, 5 and 10, plus 1 for
StrongBox and 4 when the patch floor is met; on Apple bits 6, 7 and 8. It requires
bit 10 on Android and bit 8 on Apple, and it never sets bit 9 or bit 11.
REVOCATION_LIST_CLEAR means no chain certificate was listed by its root's
revocation source or by the operator denylist at the check. There is no Play
Integrity fact or historical-credential exception. The native Model and the
credential proof relation both require bit 9 to be zero, including the retained
enrollment record and fresh record of every renewed credential.

### 3.1.0 Ledger native verifier installation

`KagemushaWalletLedgerActionV1::InstallVerifierPack` carries, in order,
`asset: [u8;32]`, `manifest_digest: [u8;32]`, and `pack: Vec<u8>` under the
instruction's exact `scheme`. The asset selects an existing immutable
registration. Its real reserve account must submit consent and hold the exact
`CanManageKagemushaWallet` permission for that registered asset definition.
The current World network, asset incarnation, scale and balance partition must
still equal the registration. The manifest digest is an explicit governance
installation pin; a received Payment does not select it.

Core authenticates the complete pack of §3.1.1 against that pin, requires its
actual Scheme to equal the registered Scheme, and retains one immutable row
`(kind=14, scheme, owner=scheme, entry=0)`. Its canonical value schema is
`iroha_core::kagemusha_wallet_v1::VerifierInstallation`, with ordered fields
`version: u16=1`, `scheme: [u8;32]`, `authorizing_asset: [u8;32]`,
`manifest: [u8;32]`, and `original: Vec<u8>`. The complete row is at most the
verifier-pack cap plus 1,024 bytes. Missing, noncanonical, unbounded or
unauthenticated material cannot create that row. Only exact original retries
are accepted; replacing or deleting an installed relation is unsupported.
Restored snapshots check the exact authorizing registration and signed
original authority frames; execution reauthenticates the actual native keys.

Each proof-consuming instruction captures this original from its same WSV
transaction overlay, checks the current credential and receipt bindings,
verifies the exact selected σ and required Ω, and decides Ω's own opening and
both transported claims. One bounded package-verification reservation charges
its total σ and Ω transport bytes against the existing transaction/block proof
quotas before native verification and ledger mutation. Missing installation
retains the `VerifierArtifactsUnavailable` local deferral. Invalid installed
material or proof cannot become a success verdict. Installing verifier
material grants no producer, foreign wallet-open or device readiness.

### 3.1.1 Installed native verifier inventory

The first-release native verifier pack has the canonical Norito schema
`iroha.core_zk.kagemusha.wallet.verifier_pack.v1`. Its ordered fields are
`version: u16`, the original canonical Scheme, Artifact signer certificate,
ArtifactManifest and verifying-key allowlist frames (each `Vec<u8>`),
`steps: Vec<StepOriginalV1>`, and `lineage: ArtifactOriginalV1`.
`StepOriginalV1` is `{kind: OperationKindV1, enabled_controls: u32,
artifact: ArtifactOriginalV1}`; `ArtifactOriginalV1` is
`{descriptor: Vec<u8>, verifying_key: Vec<u8>}`. These are mounted originals,
never rewritten to obtain a matching hash. The decoder admits exactly one
uncompressed canonical frame under payload-derived allocation limits; it
never retries another schema or profile.

The installed pack requires the complete sixteen-selector catalog, in this
order: `(1,0), (2,0), (3,0), (3,1), (3,2), (3,3), (3,4), (3,5), (3,6),
(3,7), (4,0), (4,1), (5,0), (6,0), (7,0), (8,0)`, followed by one Ω artifact.
The general model allowlist permits a supported control subset; this complete
native installation rejects such a subset. Each selector must also occupy
the same position in the manifest-bound allowlist. A descriptor is at most
1,048,576 bytes and a VK at most 262,144 bytes; aggregate descriptor/VK
originals are at most 16,777,216 bytes. The complete pack is at most
16,842,752 bytes. Authority frames keep their existing §2 caps. These are
finite loader limits, not phone memory qualification.

Use the existing `H` framing for the additional artifact roles
`eq-protocol`, `ep-protocol`, `native-profile`, `artifact-inventory` and
`producer-catalog`:
`SHA256("iroha:kagemusha:wallet:v1:" ‖ ASCII role ‖ 00 ‖ LE64 len(body) ‖ body)`.
The native owner constructs the protocol/profile bodies from compiled native
constructors and constants; the pack has no fields that choose those bodies.
For the following bodies, `frame(x) = LE32 len(x) ‖ x`, curve tags are Pallas 0
and Vesta 1, and every byte/length below is exact.

The Eq/Ep protocol body is, in order:

- `LE16 wallet_version=1 ‖ LE16 native_protocol_version=1 ‖ curve_tag`, then
  the native curve's 32-byte little-endian base and scalar moduli.
- `frame(ASCII "iroha.plonk.pipa.circuit_descriptor.v2")`, the exact 16-byte
  descriptor persona `"PIPA-v2-CircDesc"`, native `VK_VERSION` (02), exact
  16-byte VK persona `"Iroha-PlonkVK-v2"`, key-digest domain `"kgwvkey1"`,
  native proof domain `"pipa-rb1"`, native fold domain `"pipa-as1"`, and native
  typed instance-frame domain `"pipainst"` (each domain eight bytes).
- `LE32 width=3 ‖ LE32 rate=2 ‖ LE32 full_rounds=8 ‖ LE32 partial_rounds=57 ‖
  LE32 secure_mds=0`, then `LE32 native_table_bytes ‖ SHA256(native_table)`.
  The table is the exact `PoseidonField::rp57().to_table()` output in the
  native proof curve's base field, Fq for Eq and Fp for Ep.
- `frame(ASCII "Halo2-Parameters") ‖ LE32 5`, then ascending k12 through k16,
  each `u8 k ‖ pinned_params_digest(curve,k)` from the compiled native table.
- Two final codes: scalar encoding/challenge map. Eq is `01 01` (one exact
  Fp integer in Fq; one subtraction Fq→Fp); Ep is `02 00` (low128/high127
  Fq scalar pair in Fp; identity Fp→Fq).

The sole native artifact-profile body starts `LE16 1 ‖ LE32 16`,
then the sixteen `(u8 operation_tag ‖ LE32 mask)` selectors above. It then
carries `frame(sigma_policy) ‖ frame(omega_policy)`, where each policy is a
canonical Norito `iroha.core_zk.kagemusha.wallet.descriptor_policy.v1` frame
with ordered fields `{version: u16, curve: CurveV1, min_k: u8, max_k: u8,
transcript: TranscriptV2, instance_mode: InstanceModeV1,
proof_suffix: ProofSuffixV1, instance_lengths: Vec<u32>,
instance_types: Vec<InstanceType>}`. Both use version1,
`KagemushaPoseidonRp57Base`, `Direct`, `FoldedGenerator`. Sigma uses Vesta,
k12..16, lengths `[1]`, types `[Bounded]`; Omega uses Pallas, k16 only,
lengths `[1,2,16]`, types `[Bounded,Field,Bounded]`. The body continues with
`LE32 33 ‖ LE32 8 ‖ LE32 26 ‖ LE32 18 ‖ LE32 52 ‖ LE32 16 ‖ LE32 544 ‖
LE32 1120 ‖ "kgwomg_1" ‖ 01 02 03 04`. These bind current core/rest/statement,
lineage public and D_A element counts, accumulator rounds, claim and fold-body
sizes, D_A domain, and the mandatory sigma opening, Omega opening, Pallas
claim decision and Vesta claim decision. The decision codes are fixed native
requirements; no caller supplies verdict bits. The fold-body count is 1,120
bytes: commitment `D`, sixteen masked `L`/`R` pairs, `c` and the unabsorbed
`G` suffix. The corresponding local private witness additionally retains 33
canonical scalars (1,056 bytes), for 2,176 bytes under its clearing private owner.
Those private coins are not Payment, public lineage or FoldRecord fields.
The profile ends with
`frame(compiled_operation_schedules) ‖ frame(compiled_sigma_sources) ‖ frame(compiled_omega_layout)`.
The sigma source frame is `LE16(1) ‖ LE32(16)` followed, in selector order,
by `kind:u8 ‖ mask:LE32 ‖ family:u8 ‖ k:u8 ‖ lanes:u8 ‖ limb_bits:u8 ‖ prefix:u8`.
Monetary sources use family1, one lane, folded prefix1 and `k - 1` range limbs;
quota-enabled Send uses k14, other Send masks and both Receive selectors use k12.
The six typed administrative sources use family0/k12 with zero lane/limb/prefix fields.
The Omega layout frame is emitted by `omega::native::compiled_policy_transcript`:
`ASCII "iroha-kagemusha-omega-layout-v1\0"`, followed by the LE32 words
`[16,18,37,65530,32768,131072,262138,11,12,16,15,252,6,0,1,2,4,5,9,6,4,5,6,7,8,9,3]`,
then `ASCII "SecondaryPlan::new/v1\0"`. These pin the proof/trace domains, reserved
prefix, fixed spans, column/range limits, counted spare-port lists and direct-public
columns. The k18 assignment measures only unknown-source occupancy; exact guarded
replay and the final proof stay at k16. Failure never selects a larger domain.
These fixed recipes are reconstructed by strict original imports, either in the
independent complete-profile generator or during ordinary strict installation.
Signed metadata alone cannot select another layout or confer producer readiness.
The canonical Norito operation policy is generated by
`a_relation::schedule::compiled` from the same fourteen fixed Q/task partitions
used by native producers, plus all 52 logical own/incoming-selector routes.
No finality leaf policy or finality proving graph is part of the profile.
Concrete operation graph/child-key and complete context-schema reconstruction
remain mandatory at source installation. There is no retired profile fallback.

The inventory body is `LE16 1 ‖ eq_protocol_digest ‖ ep_protocol_digest ‖
native_profile_digest ‖ LE32 len(allowlist_original) ‖
SHA256(allowlist_original) ‖ LE32 17`, then each artifact in catalog order.
A sigma entry starts `u8 role=1 ‖ u8 operation_tag ‖ LE32 mask`; the final
Omega entry starts `u8 role=2 ‖ u8 operation_tag=0 ‖ LE32 mask=0`.
Each entry continues `u8 curve_tag ‖ u8 k ‖ LE32 descriptor_bytes ‖
SHA256(descriptor_original) ‖ LE32 vk_bytes ‖ SHA256(vk_original) ‖
native_descriptor_digest ‖ complete_native_vk_digest ‖ LE32 proof_bytes`.
The descriptor digest is its native V2-domain BLAKE2b value; the VK digest is
its complete native base-field `P_B(kgwvkey1; …)` value. Proof bytes come from
the actual descriptor; Omega includes both 544-byte transported claims.
Each actual key digest and length must equal its signed allowlist entry.
After the seventeenth entry, the body appends the mandatory nonzero
`H(producer-catalog, canonical_producer_inventory)` commitment. Both the
verifier-only view and full producer inventory use this same signed identity.
Scheme/certificate/manifest originals are excluded from the inventory body:
including them would create a cycle through relation_id. Their canonical
frames, exact scheme identity, Artifact-role certificate/signature and exact
manifest digest are checked separately against installation authority that
is provisioned independently of received wallet objects.

The producer preimage is the canonical
`iroha.core_zk.kagemusha.wallet.producer_inventory.v1` object implemented in
`kagemusha_wallet_artifacts_v1::producer_inventory`. It binds the compiled native
profile, exact descriptor/VK/PK lengths and SHA-256 references, all sixteen sigma
entries, every required logical route, ordered Q/A/W source identities and full
context words, deduplicated terminal descriptor/VK identities, the sole Omega
original. The installed scheme and native genesis bind the network separately. Its
metadata cap is 16 MiB; it contains no proving tables. Reads enforce an explicit
local PK cap before opening storage and exact length/hash equality for each
original. Descriptor/VK-only reads require no PK custody.

The authenticated inventory view checks the signed preimage and structural
coverage. It cannot authorize monetary operations. Every wallet source requires
exact compiled-source qualification; declared context words, classes or task
metadata are not a proof of that relation. The ordinary strict constructor
reconstructs source tables and checks every original VK commitment. The explicit
finite built-in constructor accepts only immutable entries emitted after that
same strict qualification and complete graph closure. Wallet
installation also binds native finality to its independently authenticated signed
global genesis. `AuthenticatedProducerInventoryV1::qualify_finality` checks the
installed network and retains the native verifier with the scheme/manifest
identity. No finality descriptor, proving key, verifier key, server inventory or
metadata snapshot is required. The offline compiler reconstructs only monetary
proof sources. Complete native wallet execution remains a validation requirement.
The native artifact owner is `iroha_core_zk::kagemusha_wallet_artifacts_v1`.

**Finite built-in source authority.** The native proof engine owns a closed
compiled registry, with no runtime registration, raw-digest seal constructor or
serialized capability. Its profile transcript is canonical Norito over the
owner-contract tag `iroha.kagemusha.complete-builtin-source-profile.v1`, complete
canonical producer inventory, independently authenticated network, provider
contract, canonical scheme-root key and the ordered Vesta k12/k14/k16 and Pallas
k16 parameter identities. Each member is bound to an exact role path: sigma
`[1, selector]`, Q `[2, program, stage]`, A `[3, logical_route, stage]`, W
`[4, logical_route, stage]`, or Omega `[5]`. It pins the curve/domain, descriptor,
VK and compact-PK lengths and full hashes, descriptor digest, copy identity and
source fingerprint. Artifact-declared fingerprints remain untrusted DATA.

The phone checks the complete profile, current typed source plans, every original,
canonical decoding and current resource bounds before granting a complete wallet
source owner. It preserves all route masks, child/context checks and eager Omega
closure. Missing, altered, unknown or stale material fails closed. The built-in
constructor does not silently select the expensive strict path. Proving still
reconstructs and checks its exact source before producing the same proof bytes;
hardware authorization, ledger finality and durable monetary state are unchanged.

Only a complete owner constructed through the unconditional strict path can emit
registry data. The generator cannot consult the registry it is generating. The
native build independently computes the current source/dependency-input identity;
stale or incomplete input coverage disables built-in admission while leaving the
strict generator buildable. Target support requires deterministic canonical
arithmetic and source layout; a target/toolchain label alone proves no equivalence.
Generated entries change native source admission, not the circuit relation or
signed inventory transcript. This requires no server at payment time and creates
no expanded-table disk cache or second monetary engine.

### 3.2 State, field encoding, statement, proofs, receipt, package

**σ field and element rule.** The step proofs σ are single-parity proofs over the
Pasta `Fp` (Vesta scalar field),
`p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001`. A σ-field
value is its canonical 32-byte little-endian encoding (`< p`); decoding rejects a
noncanonical value wherever a field value is required. Element lists use one rule:
an integer, tag or mask is one element; a 32-byte SHA-256 digest or identifier is
two `u128` limbs, low 16 bytes first (each little-endian); a `P` value (commitment,
chain, root, nonce, `credit_id`, `proof_digest`, statement, object, certificate-set,
package, operation, nullifier, Payment, lineage, credit-opening, credit-status or
credited digest, signed message) is one element. Every field that holds a `P` value is a
canonical σ-field value; decoding rejects a noncanonical one. The domain of `P`
(§1) is the `u64` of 8 little-endian ASCII bytes; the signing domains and the
object-digest domains are in §1, and the others are:

| Domain | Use | Domain | Use |
|---|---|---|---|
| `kgwcore1` | state commitment | `kgwcdig1` | credit-digest value |
| `kgwrest1` | rest digest | `kgwimlf1` | indexed-tree leaf |
| `kgwstmt1` | statement digest (σ public input) | `kgwimnd1` | indexed-tree node |
| `kgwcrdt1` | `credit_id` | `kgwblkl1`, `kgwblkn1` | blacklist leaf, node (§3.3) |
| `kgwschn1` | `send_chain` append | `kgwqwin1`, `kgwqwnd1` | quota-window leaf, node (§3.3) |
| `kgwrchn1` | `recv_chain` append | `kgwquse1`, `kgwqusn1` | quota-usage leaf, node (§3.3) |
| `kgwccrd1` | consumed-credit value | `kgwprf_1` | `proof_digest`, Ω‖σ (`P_bytes`) |
| `kgwpout1` | pending-outgoing value | `kgwstep1` | `proof_digest`, σ only (`P_bytes`) |
| `kgwload1` | load value (load/redeem map) | `kgwpay_1` | Payment digest (`P_bytes`) |
| `kgwrdm_1` | redeem value (load/redeem map) | `kgwlin_1` | lineage digest over the Ω bytes (`P_bytes`) |
| `kgwfee_1` | fee-claim value | `kgwcopn1` | credit-opening digest (`P_bytes`) |
| `kgwbhst1` | blacklist-history value | `kgwcsts1` | credit-status digest (`P_bytes`) |
| `kgwcset1` | certificate-set digest (§3.1) | `kgwcrdd1` | credited digest (`P_bytes`) |
| `kgwpkg_1` | package digest | `kgwopid1` | `operation_id` |
| `kgwnull1` | unload nullifier | | |

**Indexed map trees.** The consumed-credit, pending-outgoing, load/redeem
recovery, fee-claim and blacklist-history maps and the lineage-level credit-digest tree
are each a depth-32 Poseidon indexed Merkle tree (the quota-usage map is the one
exception, a fixed array, §3.3):

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
  and write `(x, v, n)` there. No map updates a value in place (the quota-usage array,
  §3.3, is not an indexed map). *Remove* `k`: open the leaf `(k', w', k)` whose `next_key` is `k` and replace
  it with `(k', w', n)`, where `n` is the `next_key` of `k`'s leaf; then open `k`'s leaf
  in the resulting root and clear its slot to empty. Each opening is against the root
  that the previous step produced.
- *Next free index.* `f` is one more than the highest slot ever written, `1` for the
  empty tree. A removal frees no slot, so slots are never reused; slot `2^32 − 1` is a
  valid slot, and only an insertion with `f = 2^32` is rejected. Relations check only
  that the low leaf brackets the new key and that the written slot opens empty in the
  intermediate root; no root commits `f`. This native rule fixes which slot, and the
  vectors pin it: allocation position and lifetime exhaustion are native-store policy,
  not proved map semantics. Unique keys, the sorted links and reachability do not
  depend on slot positions, and external consumers (CreditStatus) rely on the certified
  map invariant through membership alone. A prover slot that differs from the native
  store only breaks its own successor commitment, which Advance rejects.
- *Openings* (transcripts): a leaf opening is `key ‖ value ‖ next_key ‖ LE32 slot ‖
  siblings` (1,124 bytes) and an empty-slot opening `LE32 slot ‖ siblings` (1,028
  bytes), where `siblings` is exactly 32 canonical 32-byte values in increasing height
  (height 0 first). The CreditStatus opening (§3.4) is a leaf opening that carries the
  value's elements instead of `value`.

Map keys and operations: `credit_id` keys the consumed-credit, pending-outgoing and
fee-claim maps and the credit-digest tree; `kind · 2^128 + ordinal` (Load 1, Redeem 2)
keys the one load/redeem recovery map; the blacklist `list_version` keys the
blacklist-history map. Pending-outgoing entries are inserted by Send and removed by
ArchiveSent (relink the predecessor, then clear the slot; never reuse a slot);
blacklist-history entries are inserted by RefreshPolicy(Blacklist); every other map and
the credit-digest tree are insert-only. The credit-digest tree is membership-or-insert:
`burned` is fixed at the first insertion of a `credit_id`, and an existing key keeps its
`(payment_digest, burned)` even when they differ from a later Receive's proposed
insertion. A duplicate `credit_id` carrying another Payment digest therefore shows the
original leaf, which does not match the second Payment, so native ArchiveSent rejects it
and `Λ_archive` takes its no-op branch. The data model builds roots and openings
natively.

**State.** The private state is not transmitted; it travels only inside a recovery
capsule. Its frame is `{version, core, rest}`.

- The *core* holds every field a step proof reads, changes or carries. Frame and
  element order (33 elements): `lifecycle` (Active 1, Retiring 2), `scheme_id` (2),
  `asset_digest` (2), `wallet_id` (2), `credential_digest`, `balance`,
  `burned_total`, `sequence`, `next_send`, `next_load`, `next_redeem` (`u128` each),
  `send_chain`, `recv_chain`, `consumed_credit_root`, `pending_outgoing_root`,
  `load_redeem_recovery_root`, `fee_claim_root`, `quota_usage_root`, `LE32
  enabled_controls`, `quota_windows_root`, `LE64 quota_share_expires_at_ms`, `LE64
  blacklist_version`, `blacklist_root`, `LE64 blacklist_issued_at_ms`, `LE64
  blacklist_max_age_ms`, `LE64 time_anchor_max_response_ms`, `LE64
  lease_expires_at_ms`, `LE64 policy_epoch`, `LE64 accepted_time_floor_ms`,
  `state_nonce`. `blacklist_max_age_ms` and `time_anchor_max_response_ms` are the
  credential regulatory policy's, held in the core so that σ_send enforces the list-age
  rule and the Send time span (B8); `quota_share_expires_at_ms` is the held quota share's
  `expires_at_ms`, held in the core so that σ_send enforces the share expiry (B7).
  `time_anchor_max_response_ms` and `quota_share_expires_at_ms` are bound to their
  authenticated source (the credential at Bootstrap, the installed
  share at RefreshPolicy(QuotaShare)) and no other transition changes them.
- The *rest* is opened only by the lineage relation. Frame and element order (8
  elements): `LE32 permitted_controls` (the rest of the regulatory policy),
  `scheme_policy`, `fee_schedule`, `blacklist`, `quota_share`, `LE64 quota_share_id`,
  `time_anchor` (the object digests of the held policy objects, one element each) and
  `blacklist_history_root` (§3.3, B6).
- The commitment is one σ-field value:
  `P(kgwcore1, core elements ‖ P(kgwrest1, rest elements))`. Its transcript is the
  32-byte encoding; all-zero is only the Bootstrap predecessor.
- Rules: nonzero identities; the four indexed map roots of the core, the quota-usage
  array root, `blacklist_history_root` and `state_nonce` are nonzero canonical values;
  chains and the blacklist and quota-windows roots are canonical (zero is the empty chain
  or "none held"); the regulatory policy reassembled from the core and rest is valid and
  `enabled_controls` ⊆ its permitted controls. A scheme policy, blacklist or quota share
  is held exactly when its digest, its epoch, version or share id, and its root (if any)
  are all nonzero; without a scheme policy, `enabled_controls` and `fee_schedule` are
  zero; an unheld blacklist has a zero issue time; `quota_share_expires_at_ms` is nonzero
  iff a quota share is held, and the quota-usage root is the array aligned with the held
  windows (§3.3); `lease_expires_at_ms ≠ 0` iff the lease is permitted. Bootstrap state
  has zero balance, `burned_total`, ordinals, sequence and chains, the empty-tree root for
  every indexed map (the blacklist history included), the all-padding quota-usage array
  root, and zero policy fields except the credential's regulatory policy and lease.
- The spendable value is `balance − burned_total` with the lineage-adjusted
  `burned_total` of the Ω recorded for the head, whose `head` must equal the state's
  computed commitment (§§3.2, 6.1 of the proposal); Send and Unload pre-checks use it.

**Map values and chains** (element lists after the domain; a map leaf is
`(key, P(value domain, elements), next_key)`; no state commitment or chain contains a
Payment digest):

| Object | Value domain | Key | Elements |
|---|---|---|---|
| consumed credit (permanent map) | `kgwccrd1` | `credit_id` | `credit_id`, `amount`, `receive_sequence` (3) |
| pending outgoing | `kgwpout1` | `credit_id` | `credit_id`, `receiver_wallet_id` (2), `send_ordinal`, `amount`, `fee`, `request_digest` (7) |
| load (load/redeem map) | `kgwload1` | `1 · 2^128 + ordinal` | `ordinal`, `receipt_digest`, `amount` (3) |
| redeem (load/redeem map) | `kgwrdm_1` | `2 · 2^128 + ordinal` | `ordinal`, `nullifier`, `amount`, `online_charge` (4) |
| fee claim | `kgwfee_1` | `credit_id` | `credit_id`, `fee`, `fee_schedule_digest` (3) |
| blacklist history (rest) | `kgwbhst1` | `list_version` | `list_version`, `entries_root` (2) |
| quota usage (array leaf, not an indexed map, §3.3) | `kgwquse1` | window slot | `window_kind` tag, `window_start_ms`, `window_end_ms`, `used` (4) |
| `send_chain` append | `kgwschn1` | — | `[send_chain]` ‖ the pending-outgoing elements (8) |
| `recv_chain` append | `kgwrchn1` | — | `[recv_chain]` ‖ `credit_id`, `payer_wallet_id` (2), `amount` (5) |
| credit digest (lineage level, not in the state) | `kgwcdig1` | `credit_id` | `credit_id`, `payment_digest`, `burned` 0 or 1 (3) |

**Operation kinds and effects** (field widths of the Norito effect; the effect tag
equals the operation kind; the effect enters the statement digest as its element list,
and there is no effect byte transcript; Ω(pred) marks the kinds that consume the
predecessor's lineage proof):

| Tag | Kind | Effect fields (width) | Elements | `operation_id` input | Ω(pred) |
|---:|---|---|---:|---|---|
| 1 | Bootstrap | `enrollment_id ‖ enrollment_marker` (64) | 4 | `enrollment_id` (2 limbs) | no |
| 2 | Load | `receipt_digest ‖ LE128 load_ordinal ‖ LE128 amount ‖ LE128 online_charge` (80) | 4 | `receipt_digest` | no |
| 3 | Send | `credit_id ‖ receiver_wallet_id ‖ LE128 send_ordinal ‖ LE128 amount ‖ LE128 fee ‖ request ‖ LE64 accepted_lower_ms ‖ LE64 accepted_upper_ms` (160) | 9 | `credit_id` | yes |
| 4 | Receive | `credit_id ‖ payer_wallet_id ‖ LE128 amount` (80) | 4 | `credit_id` | no |
| 5 | ArchiveSent | `credit_id ‖ credited` (64) | 2 | `credited` | no |
| 6 | Unload | `nullifier ‖ LE128 redeem_ordinal ‖ LE128 amount ‖ LE128 online_charge ‖ charge_quote` (112) | 5 | `nullifier` | yes |
| 7 | RefreshPolicy | `tag update_kind ‖ update ‖ LE64 accepted_time_floor_ms` (41) | 3 | `update` | no |
| 8 | Retiring | none (0) | 0 | the element 0 | yes |

Update kinds: Credential 1, SchemePolicy 2, Blacklist 3, QuotaShare 4, TimeAnchor 5;
`update` is the applied object's digest (a `P` value). Effect rules: nonzero digests;
`credit_id`, `receipt_digest`, `request`, `credited`, `nullifier`, `charge_quote` and `update`
nonzero canonical σ-field values (`charge_quote` zero when absent); Send, Receive and
Unload amounts positive; Send `amount + fee` fits `u128` and `accepted_lower_ms ≤
accepted_upper_ms`; Unload `online_charge ≤ amount` and `charge_quote` nonzero iff
`online_charge > 0`. The Send `request` is the object digest of the signed Request, which
binds the receiver credential, fee schedule and certificates by digest; the Receive effect
carries no Payment digest. `ArchiveSent` uses the Credited digest, a `P_bytes` value
(§3.4), as its operation input, so archiving again with new evidence is a new operation.

- **Statement** (frame fields in this order; no byte transcript): `LE16 version ‖
  scheme_id ‖ relation_id ‖ credential_digest ‖ asset_digest ‖ tag lifecycle ‖ LE128
  sequence ‖ LE128 next_load ‖ LE32 enabled_controls ‖ LE128 lineage_burned_total ‖
  lineage_pending_outgoing_root ‖ predecessor ‖ successor ‖ effect`. Its digest
  `statement_digest` is the σ statement digest below, which the receipt, the package,
  the output descriptor and CreditStatus bind. Lifecycle, sequence and `next_load` are
  the successor's; `enabled_controls` is the predecessor's mask (σ_send enforces it; a
  σ_recv's blacklist check follows its Request's recorded decision, §3.4). For Send,
  Unload and Retiring the lineage fields are Ω(pred)'s `burned_total` and
  pending-outgoing root (the root nonzero);
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
- **σ public input** (26 elements, digest `statement_digest = P(kgwstmt1, ·)`):
  `version`, `relation_id` (2), `scheme_id` (2), `asset_digest` (2),
  `credential_digest`, lifecycle, sequence, `next_load`, `enabled_controls`,
  `lineage_burned_total`, `lineage_pending_outgoing_root`, `predecessor`, `successor`,
  effect tag, then the effect's elements in field order zero-filled to 9. The
  `iroha_kagemusha_proof` step relations and `iroha_plonk_gadgets::statement::StatementV1`
  encode this layout, with the relation identity as witness limbs bound by the digest,
  and must reproduce the statement vectors natively and in circuit; final artifact
  qualification remains G3 work.
- **Consumer checks** (proposal §3.2) of a statement carrying Ω(pred), before
  mutation: scheme and relation equal Ω's; `predecessor = Ω.head`;
  `credential_digest = Ω.credential_digest`; the lineage fields equal Ω's
  `burned_total` and pending-outgoing root; `enabled_controls = Ω.enabled_controls`
  (which selects σ_send's verifying key); the predecessor lifecycle (Active for
  Retiring, else the statement's) equals Ω's; and the wallet-bound effect rules for
  `Ω.wallet_id`.
- **Operation and nullifier.** `operation_id = P(kgwopid1, [wallet_id (2), kind] ‖
  input)`, where `input` is per kind (table above): `enrollment_id` as two limbs for
  Bootstrap, the element 0 for Retiring, and one canonical `P` element otherwise (4
  elements, 5 for Bootstrap; kind and arity make it injective). `nullifier =
  P(kgwnull1, [scheme_id (2), wallet_id (2), redeem_ordinal])`. Both are canonical
  σ-field values.
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
- **Receipt τ.** Frame `{version, operation_id, capsule_commitment, payment_digest,
  signature}`. Its signed body is derived by every verifier and never transmitted; the
  signature covers `P_bytes(kgwrcpt1, body)` (§1). The body (338) is `LE16 version ‖
  scheme_id ‖ wallet_id ‖ provider_contract` (from the signer) `‖ LE128 sequence ‖
  operation_id ‖ predecessor ‖ successor` (from the statement) `‖ statement_digest ‖
  proof_digest ‖ capsule_commitment ‖ payment_digest`. `proof_digest` is a nonzero
  canonical σ-field value. `capsule_commitment` is the nonzero opaque 32-byte
  identifier `P_bytes(kgwcapc1, enc(C))` of the private capsule commitment (§3.5),
  not a private custody hash; the receipt field's encoding and transcript position
  are fixed-width, and native custody authenticates its full opening before signing;
  `payment_digest` is the full canonical Payment digest (a canonical σ-field value) for
  Receive and zero otherwise. The signer is the wallet's credential, or, for a consumer
  of a package carrying Ω(pred), Ω's scheme, wallet and payment key under the V1
  provider contract. The carried `operation_id` must equal the recomputed one.
- **Package.** Frame `{version, statement, lineage, step_proof, receipt}`; `lineage`
  is None 0 or Present 1 `{lineage: Ω(pred)}`, present exactly for Send, Unload and
  Retiring, and a present Ω passes the consumer checks.
  `package_digest = P(kgwpkg_1, [statement_digest, proof_digest, receipt_digest])`,
  defined only after the receipt verifies (under the credential, which must also
  carry Ω's wallet and payment key, or under Ω for a consumer without the
  credential); `receipt_digest` is the receipt's object digest `P(kgworcp1, ·)` (§1).
  σ's verifying key is selected from the verifying-key allowlist by the operation tag,
  for Send also by the mask and for Receive also by its Request's recorded blacklist
  version (§3.1), so a Receive package is checked together with its Request; the
  allowlist also checks σ's and Ω's exact lengths.

### 3.3 Policy objects

All are signed, under the signing domain in parentheses (§1), by a
RegulatoryPolicy-role key except the time anchor (TimeAnchor role). Each body's
`signer_certificate` names the signer.

| Object | Body fields in transcript order | Interoperability rules |
|---|---|---|
| Scheme policy (`kgwspol1`) | `LE16 version ‖ scheme_id ‖ asset_digest ‖ LE64 policy_epoch ‖ LE32 enabled_controls ‖ fee_schedule ‖ signer_certificate` | `policy_epoch ≥ 1` (0 is the implicit default); defined control bits only; zero `fee_schedule` means no fee. |
| Fee schedule (`kgwfsch1`) | `LE16 version ‖ scheme_id ‖ asset_digest ‖ LE64 schedule_id ‖ beneficiary_account_digest ‖ LE32 basis_points ‖ LE128 fixed ‖ LE128 minimum ‖ LE128 maximum ‖ tag rounding ‖ signer_certificate` | Rounding Down 1, Up 2; `basis_points ≤ 10,000`; `maximum ≥ minimum`. For `a = 10,000·q + r`, `fee(a) = clamp(fixed + q·bp + ⌊r·bp / 10,000⌋ (+1 if Up and r·bp mod 10,000 ≠ 0), minimum, maximum)`; an unclamped `u128` overflow rejects. |
| Blacklist (`kgwblst1`) | `LE16 version ‖ scheme_id ‖ LE64 list_version ‖ LE64 issued_at_ms ‖ LE32 entry_count ‖ entries_root ‖ signer_certificate` | Frame `{body, signature, entries: [{account_digest}]}`. `list_version ≥ 1`; `entries_root` a nonzero canonical σ-field value; entries strictly ascending in limb order (below), never `00…00` or `FF…FF`; count and root recompute. Downloaded only online, from the issuer or ledger, as one standalone frame; never a peer message. |
| Quota share (`kgwqshr1`) | `LE16 version ‖ scheme_id ‖ asset_digest ‖ wallet_id ‖ LE64 share_id ‖ LE64 issued_at_ms ‖ LE64 expires_at_ms ‖ windows_root ‖ LE32 window_count ‖ signer_certificate` | Frame `{body, windows, signature}` (windows before the signature). `share_id ≥ 1`; `windows_root` a nonzero canonical σ-field value; `issued < expires`; each window has `start < end` within `[issued, expires]`; windows strictly sorted by `(kind, start)`, never overlapping within a kind; count and root recompute. Installing it (RefreshPolicy, below) also requires every window to be longer than the wallet's `time_anchor_max_response_ms` (B8). |
| Time anchor (`kgwtanc1`) | `LE16 version ‖ scheme_id ‖ wallet_id ‖ nonce ‖ LE64 issuer_time_ms ‖ signer_certificate` | Answers one wallet nonce. |
| Charge quote (`kgwchgq1`) | `LE16 version ‖ scheme_id ‖ asset_digest ‖ wallet_id ‖ tag kind ‖ LE128 ordinal ‖ LE128 net_amount ‖ LE128 online_charge ‖ beneficiary_account_digest ‖ LE64 issued_at_ms ‖ signer_certificate` | Kinds Load 1, Unload 2. `online_charge > 0`. Load: the ledger debit `net_amount + online_charge` fits `u128`. Unload: `net_amount > 0` and the payout `net_amount − online_charge` does not underflow. |

- **Blacklist order.** An account digest `a` orders by its limb integer
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
- **Blacklist enforcement.** A wallet enforces only its own committed list,
  and only while its BLACKLIST control is enabled and it holds a list
  (`blacklist_version ≥ 1`); with version 0 it refuses no account and applies no age
  rule. The payer's list must not contain the Request's `receiver_account_digest` (Send
  rule, §3.4; σ_send). The receiver's list is judged only when it issues a Request (B6):
  the Request records the version and root of the list it enforced, `(0, 0)` when it
  enforced none, and its list must not contain the Request's `payer_account_digest`
  (Request rule, §3.4). Receive checks the payer against that recorded list only (Receive
  rule, §3.4; σ_recv), so a list the receiver commits later neither refuses nor admits a
  Payment under an earlier Request. The maximum-age rule (Time, below) applies to Send
  only. Lists are best effort: phones hold different lists, nothing requires them to
  agree, and a later list never invalidates a completed payment.
- **Blacklist history** (B6). The rest's `blacklist_history_root` is a depth-32 indexed
  map (§3.2) from `list_version` to `P(kgwbhst1, [list_version, entries_root])`, the
  empty tree at Bootstrap; every RefreshPolicy(Blacklist) inserts the new list's pair,
  and no other transition changes it. For a Request's nonzero recorded pair, the head
  that receives the Payment looks up the recorded version in its history (natively at
  Receive and in `Λ_recv`): an authenticated opening against that head's history root,
  either the version's leaf or its low-leaf non-membership opening, is always required;
  the recorded decision holds iff the leaf is present with the recorded root, and fails
  only on proven absence or an authenticated different root. This proves that this
  wallet committed that list before the Receive; it does not prove that the list was the
  latest one held when the Request was signed, and a recorded `(0, 0)` carries no proof
  (an open owner question, §7).
- **Quota tree.** A window is `kind` (Daily 1, Monthly 2), `start_ms`, `end_ms` and
  `limit` (half-open `[start, end)`); its leaf is `P(kgwqwin1, [tag kind, start_ms,
  end_ms, limit])`, an empty slot is the leaf of four zero elements, and the root is a
  depth-6 Poseidon tree over 64 slots, windows first, with nodes `P(kgwqwnd1, [left,
  right])`; the root is one σ-field value.
- **Quota-usage array** (B5; the one exception to the depth-32 indexed maps). A depth-6
  Poseidon tree over 64 slots aligned one to one with the held share's window slots:
  slot `i` holds `P(kgwquse1, [tag kind, start_ms, end_ms, used])` with the kind, start
  and end of window slot `i` and its consumed gross amount `used` (a refreshed window may
  carry `used` above a lowered limit, which only refuses further charges), and an empty
  window slot (or every slot, without a share) holds the padding leaf `P(kgwquse1, [0,
  0, 0, 0])`; nodes are `P(kgwqusn1, [left, right])`, and the root is the core's
  `quota_usage_root`. A charge rewrites only its own slot's `used`; every other slot is
  unchanged. An opening is the leaf's four elements, its slot and exactly 6
  siblings, height 0 first. The vectors pin the padding leaf and the all-padding root.
- **Time.** The local anchored time `{anchor, boot_id, LE64 request_monotonic_ms,
  LE64 receive_monotonic_ms}` gives, at monotonic reading `m` in the same boot,
  `[T + (m − m_rcv), T + (m − m_req)]`, valid when `m ≥ m_rcv` and
  `m_rcv − m_req ≤ time_anchor_max_response_ms`. A Send binds `L = max(floor,
  anchor lower, receiver_accepted_time_ms)` and `U = max(anchor upper, L)` (`U = L`
  without an anchor). An active time-dependent control without the committed
  same-boot anchor refuses Send. A deadline (lease expiry, quota share expiry) has
  passed iff `U ≥ deadline`; both deadlines are core fields, so σ_send enforces them:
  `U < lease_expires_at_ms` while the lease control is enabled, and `U <
  quota_share_expires_at_ms` while the quota control is enabled (B7). Blacklist age is
  `U − blacklist_issued_at_ms`; both it and the maximum age are core fields, so σ_send
  enforces the maximum-age rule (§3.2). *Send time span* (B8): while the quota control
  is enabled, `U − L ≤ time_anchor_max_response_ms`, natively (a valid same-boot anchor
  implies it) and in σ_send; because every installed window is longer than that bound,
  an accepted interval touches at most two windows of each kind, which are σ_send's two
  charge candidates per kind. A quota window is touched iff `start ≤ U` and `L < end`;
  every touched window needs `used + amount + fee ≤ limit`, each window kind the share
  defines must be touched, and σ_send's window segments show that no touched window lies
  outside its candidates. Each touched window is charged exactly once, in place at its
  own slot of the quota-usage array: its window leaf and usage leaf open at the same slot
  with the same kind, start and end, and no active charge repeats a slot. The canonical
  witness order is Daily then Monthly, each by ascending slot; each usage opening is
  against the root produced by the preceding active charge, and an inactive charge
  preserves the root. Distinct in-place updates commute, so the successor
  `quota_usage_root` does not depend on that order, and σ_send's successor root and the
  native store agree.
- **RefreshPolicy.** One signed update per transition. Epochs, list versions and
  share ids strictly increase; a time anchor must differ from the held one. The new
  floor is `F = max(old floor, t)`, where `t` is the credential's `issued_at_ms`, the
  old floor for a scheme policy, the list's or share's `issued_at_ms`, or the anchor's
  `issuer_time_ms`. A Blacklist update also inserts `(list_version, entries_root)` into
  the blacklist history (B6). A QuotaShare update requires every new window to be longer
  than `time_anchor_max_response_ms` (B8), sets `quota_share_expires_at_ms` to the
  share's `expires_at_ms` (B7) and rebuilds the quota-usage array for the new windows,
  checking only the 64 slots of the old array and the 64 of the new share (B4, B5),
  by a constrained sorted merge of the two key-sorted arrays with canonical padding:
  - a new window whose key `(kind, start)` is in the old array keeps that key's `end`
    (otherwise the share is refused) and carries its `used`;
  - a new window whose key is absent from the old array starts at `used = 0` and is
    admitted only if `start ≥ F`, unless the predecessor never held a share
    (`quota_share_id = 0`, whose usage root is the all-padding root);
  - an old key that the new share omits may be dropped only if its `used = 0` or its
    `end ≤ F`; otherwise the share is refused.

  The last two rules keep consumed quota from being reset: a charged key that may be
  dropped has `start < end ≤ F`, floors never decrease, so that key can never be
  re-added at zero, and a live charged key cannot be dropped. Every other update kind
  keeps `quota_usage_root`. The issuer contract behind these refusal rules is an open
  owner question (§7).

### 3.4 Messages and envelope

The envelope frame is `{version, message}`; message tags are Offer 1, Request 2,
Payment 3, Credited 4, SessionControl 5, PolicyData 6 and Lineage 7. The scheme
checked at decode is the body scheme (Offer, Request), the Send statement's scheme
(Payment), Ω's scheme (Lineage) or the message's own field.

| Message | Frame and transcript | Interoperability rules |
|---|---|---|
| Offer | `{body, payer_credential, certificates, signature}`; offer body (signed under `kgwoffr1`) = `LE16 version ‖ scheme_id ‖ asset_digest ‖ payer_wallet_id ‖ payer_credential_digest ‖ LE128 next_send ‖ LE128 amount ‖ session_nonce` | Payer payment key signs. Body matches the credential's scheme, asset, wallet and digest; the credential frame is at most 1,024 bytes; `amount > 0`; certificates exactly the payer issuer. No debit or credit authority; a delivery retry also opens with an Offer, so the receiver holds the payer credential. |
| Lineage | `{version, lineage: Ω}` | Unsigned and sent only after an authenticated Offer. The receiver rate-limits it and checks Ω's scheme, `wallet_id`, credential digest and `payment_key` against the Offer's credential; a Payment whose Ω(pred) has the same `lineage_digest` reuses that verification. |
| Request | `{body, receiver_credential, fee_schedule, certificates, signature}`; request body (signed under `kgwrqst1`, 458) = `LE16 version ‖ scheme_id ‖ asset_digest ‖ payer_wallet_id ‖ payer_account_digest ‖ receiver_wallet_id ‖ receiver_account_digest ‖ LE128 send_ordinal ‖ receiver_credential_digest ‖ LE128 amount ‖ fee_schedule ‖ LE128 fee ‖ LE64 policy_epoch ‖ scheme_policy ‖ LE64 receiver_accepted_time_ms ‖ LE64 receiver_blacklist_version ‖ receiver_blacklist_root ‖ certificates ‖ nonce` | Receiver payment key signs. Slot None 0 or Present 1 `{schedule}`. `amount > 0`; payer ≠ receiver wallet; `amount + fee` fits; `policy_epoch = 0` iff `scheme_policy` zero. `receiver_credential_digest`, `fee_schedule`, `scheme_policy` and `certificates` are canonical σ-field values (`P` digests, zero where absent). `receiver_blacklist_version` and `receiver_blacklist_root` record the receiver's blacklist decision for this Request (B6, Request rule below): `(0, 0)` means no enforcement for this Request (control off or no list held); version 0 iff root 0, and a nonzero root is a canonical σ-field value. Both account digests are nonzero: `receiver_account_digest` equals the carried receiver credential's `account_digest`, and `payer_account_digest` equals the payer credential's (checked by the receiver against the Offer's credential before it signs, and by the payer against its own before Send). None requires zero `fee_schedule` and `fee`; Present requires the digest, the Request's scheme and asset, and `fee = fee(amount)`. Certificates exactly the receiver issuer (Enrollment) plus the fee signer (RegulatoryPolicy) when present; their set digest is `body.certificates`. `credit_id = P(kgwcrdt1, ·)` over the 26 request-body elements in transcript order (version; scheme, asset, payer wallet, payer account, receiver wallet, receiver account (2 each); `send_ordinal`; receiver credential; `amount`; fee schedule; `fee`; `policy_epoch`; scheme policy; `receiver_accepted_time_ms`; `receiver_blacklist_version`; `receiver_blacklist_root`; certificates; nonce (2)), one canonical σ-field value, so the recorded blacklist decision is bound wherever `credit_id` is. `request_digest = P(kgworeq1, [m, r_lo, r_hi, s_lo, s_hi])` (§1). |
| Payment | `{version, request: PaymentRequest, send: Package}`; `PaymentRequest` carries only the unique Request fields and its signature (below); `payment` (163) = `LE16 version ‖ request_digest ‖ payer_payment_key(key) ‖ payer_credential_digest ‖ package_digest`; the Payment digest is `P_bytes(kgwpay_1, payment)`, one canonical σ-field value. `request_digest` and `package_digest` are `P` values in the same 32-byte slots. Given canonical decoding and recomputed subordinate digests, this transcript binds every field of the Payment frame transitively: the Request body and signature through `request_digest`, and the statement, Ω(pred), σ_send and τ_send through `package_digest` and its `proof_digest` | The compact layout: the receiver's credential, fee schedule and certificates are bound by digest in the Request body, and the payer's credential and certificates travel in the Offer. Structurally (no `payment_digest` without it): `send` is a Send package carrying Ω(pred) that passes the consumer checks with τ verified under `Ω.payment_key`; the reconstructed Request payer is `Ω.wallet_id`; the payer key and credential digest are read from Ω; the effect's credit, receiver, ordinal, amount, fee and `request` equal the Request's, `accepted_lower_ms ≥ receiver_accepted_time_ms`, the statement's scheme and asset are the Request's; `Ω.policy_epoch ≥` the Request's. At Receive: the carried Request is the receiver's held one, which verifies in full; the receiver's current credential is matched by the Request's receiver wallet and its receiver credential's payment key, never by credential digest, so a Request signed before a renewal stays receivable; the Offer's payer credential verifies under the scheme, is the Request's payer with a key other than the receiver's, matches Ω's credential digest and key, and has the Request's `payer_account_digest`; the Request's recorded blacklist decision holds (Receive rule, below), whatever the receiver's current list and controls; the statement's relation is the scheme's. σ_send and Ω(pred) with its decide are the proof owner's. |
| Credited | `{version, scheme_id, evidence}`; the credited transcript (99) is `LE16 version ‖ tag evidence ‖ credit_id ‖ payment_digest ‖ evidence digest`, and the Credited digest is `P_bytes(kgwcrdd1, ·)` | Evidence Receive 1 `{package}` (status *credited, unfolded*; evidence digest = its package digest) or Status 2 `{status: CreditStatus}` (status *credited* or *burned*; evidence digest = its credit-status digest). `scheme_id` is the evidence statement's scheme. The payer verifies it against its scheme, held Request and retained Payment: in both forms the evidence statement names the payer's scheme and relation identity (rejected before the `ArchiveSent` mutation, as `Λ_archive` rejects it); Receive form, a Receive package (no Ω) whose effect credit, payer wallet and amount match, whose receipt binds the Payment digest, whose scheme and asset are the Request's, whose σ_recv verifies under the key selected by the Request's recorded blacklist version (§3.1), and whose τ verifies under the Request's receiver credential; Status form, Ω(h)'s `wallet_id` and `payment_key` equal the Request's receiver wallet and its receiver credential's key (credential digests are not compared, so a receiver that renewed after the Request still matches) and the opening names this credit and Payment digest. `ArchiveSent` also requires the retained Payment's pending-outgoing leaf. |
| CreditStatus (inside Credited) | `{version, statement, proof_digest, receipt, lineage: Ω(h), opening}`; the credit-status transcript (162) is `LE16 version ‖ statement_digest ‖ proof_digest ‖ receipt_digest ‖ lineage_digest ‖ opening_digest`, and its digest is `P_bytes(kgwcsts1, ·)` | Read-only evidence from a folded receiver head `h`, carrying no σ and no Ω(pred): the statement's successor is `Ω(h).head`; scheme, relation, credential digest and lifecycle equal Ω's; τ(h) verifies under Ω(h)'s key over the carried statement and nonzero `proof_digest`, with its own capsule commitment and Payment digest. The opening recomputes `Ω(h).credit_digest_root` natively. The decide of Ω(h) is the proof owner's (TODO(G3)). Only a membership opening is evidence; a non-membership (low-leaf) opening is not. |
| Credit opening (inside CreditStatus) | `{credit_id, payment_digest, burned: bool, next_key, slot: u32, siblings: bytes}`; the credit-opening transcript (1,125) is `credit_id ‖ payment_digest ‖ u8 burned ‖ next_key ‖ LE32 slot ‖ siblings`, and the opening digest is `P_bytes(kgwcopn1, ·)` | The leaf opening (§3.2) of `credit_id` in the credit-digest tree: the leaf `P(kgwimlf1, [credit_id, P(kgwcdig1, [credit_id, payment_digest, burned]), next_key])` at `slot`, with exactly 32 siblings as 1,024 concatenated canonical bytes in increasing height. `credit_id` and `payment_digest` are nonzero canonical σ-field values; `next_key` is zero or a canonical value above `credit_id`; `slot ≥ 1`. |
| SessionControl | `{version, scheme_id, asset_digest, sender_wallet_id, peer_wallet_id, session_nonce, kind, LE16 reason, credit_id, auth}`; session-control body (signed under `kgwsctl1`) = all fields except `auth`, kind as a tag | Kinds SetupDeclined 1, UnsupportedScheme 2, ReceiveDeferred 3, Close 4; auth Unsigned 0 or Signed 1 `{signature}`. Scheme, asset and nonce nonzero; sender nonzero except UnsupportedScheme; peer zero (unknown) or not the sender; opaque `reason` only for SetupDeclined and ReceiveDeferred; `credit_id` nonzero iff ReceiveDeferred. `credit_id` is a canonical σ-field value. Unsigned only for UnsupportedScheme and for SetupDeclined before the sender's own Offer or Request; otherwise signed by the payment key of that session's Offer or Request credential. Invalid controls are dropped. |
| PolicyData | `{version, scheme_id, asset_digest, item}` | Items SchemePolicy 1, FeeSchedule 2, Certificates 3 (non-empty); tag 4 is unused, because the blacklist is never peer-carried (§3.3). Item scheme equals `scheme_id`; scheme policy and fee schedule asset equal `asset_digest`. Signers are selected by certificate digest. |


The `PaymentRequest` frame has these twelve fields in order:
`payer_account_digest`, `receiver_account_digest`, `receiver_credential_digest`,
`fee_schedule`, `policy_epoch`, `scheme_policy`, `receiver_accepted_time_ms`,
`receiver_blacklist_version`, `receiver_blacklist_root`, `certificates`, `nonce`,
`signature`. The other eight signed Request body fields have a single wire owner:

| Reconstructed Request field | Payment field |
|---|---|
| `version` | `version` |
| `scheme_id`, `asset_digest` | `send.statement.scheme_id`, `send.statement.asset_digest` |
| `payer_wallet_id` | `send.lineage.public.wallet_id` |
| `receiver_wallet_id`, `send_ordinal`, `amount`, `fee` | The corresponding fields of `send.statement.effect.Send` |

This projection preserves the exact Request signing transcript, credit identifier,
Request digest and Payment digest transcript. The payer key and credential digest in
the Payment digest come from Ω(pred). Assembly validates the full signed Request and
payer credential, requires that the reconstructed signed Request equals that full
input, and verifies the Send package. A changed input is rejected before compaction.
The structural `signed_request()` reconstruction does not verify proof authority or
repair malformed represented values: native and circuit consumers still verify the
reconstructed Request, package, receipt and incoming proofs at their existing
acceptance boundaries. Only this single-owner V1 frame is decoded.

- **Unknown scheme.** A receiver may decode an Offer envelope through the per-kind
  bound without the scheme check, validate only its body, and reply with an
  unsigned UnsupportedScheme naming the Offer's scheme, asset and session nonce,
  zero sender and the payer as peer.
- **Send rule** (one complete native pre-check; `σ_send` also proves its ordinal,
  spendable, epoch, time and enabled-control parts, see the σ status in §7). It
  authenticates its inputs against the payer's head, derives one accepted interval
  `[L, U]` (§3.3, Time), applies every part below and returns σ_send's control
  witnesses (gap opening, window segments and quota-usage openings against the
  head-committed roots); the partial checks are not separate entry points. The
  Request names the payer's wallet and `next_send`; the Ω is the one recorded for the
  payer's head (its `head` is the payer state's computed commitment, and wallet,
  credential and key are the payer's); payer `policy_epoch ≥` the Request's, with an
  equal `scheme_policy` at equal epochs; `fee_schedule` equals the payer's held
  schedule; payer and receiver keys differ; `balance − Ω.burned_total ≥ amount + fee`;
  `payer_account_digest` is the payer credential's and `receiver_account_digest` the
  Request receiver credential's; with the payer's blacklist enforced (§3.3),
  `receiver_account_digest` has a gap opening in the payer's committed list and the
  list-age rule holds; with the lease enabled, `U < lease_expires_at_ms`; with the quota
  control enabled, `U < quota_share_expires_at_ms`, the Send time span and the quota
  charges (§3.3, Time).
- **Request rule** (receiver, native, before it signs a Request): the Offer
  is authenticated; `payer_account_digest` is the Offer credential's and
  `receiver_account_digest` the receiver's own credential's. With the receiver's
  blacklist enforced (§3.3), the body records the committed `(blacklist_version,
  blacklist_root)`, `payer_account_digest` must have a gap opening in that list, and the
  receiver retains that gap opening (580 raw bytes: the two limb-ordered bounds, `LE32`
  leaf index and 16 siblings) with the issued Request for its Receive and any σ_recv
  re-proof; otherwise the body records `(0, 0)`. A listed payer gets no Request (the
  receiver may send SetupDeclined).
- **Receive rule** (receiver, native, before mutation; one Receive preparation path
  with the full Payment verification): when the Request records a nonzero
  `(receiver_blacklist_version, receiver_blacklist_root)`, the history lookup of the head
  it receives on finds that pair (§3.3, Blacklist history) and the gap opening retained
  with the Request shows `payer_account_digest` absent from the recorded root; σ_recv,
  selected by that nonzero version, proves the same absence against the recorded root.
  A recorded `(0, 0)` needs no check, and σ_recv's mask-0 relation constrains the recorded
  pair to `(0, 0)`. The receiver's list and controls at Receive neither excuse a
  recorded check nor add one, so a newer receiver list never strands a committed
  Payment. A Payment that fails this rule changes no state.

### 3.5 Custody objects (local, never transmitted)

The private recovery body B is frozen before drawing its opening. Set
`b = H("capsule-body", B)`, `m0 = LE128(b[0..16])`, `m1 = LE128(b[16..32])`
and use both limbs as Fp elements without reduction. Under the installed Vesta
IPA generators compute `C = m0 g[0] + m1 g[1] + r w` with an independent uniform
canonical Fp opening r. `capsule_commitment = P_bytes(kgwcapc1, enc(C))`, where
the eight ASCII bytes define the little-endian u64 domain and enc(C) is the
canonical 32-byte Vesta encoding. Identity C is permitted. A zero public
commitment refuses the attempt before selection. Its probability is not assumed
to be 1/p. The selected wrapper W contains exactly B's canonical frame bytes and
r; its private identity is `H("capsule", W)`.

The admitted g[0], g[1], w are the existing `Halo2-Parameters` Eq points derived
from `[0,0,0,0,0]`, `[0,1,0,0,0]`, `[1]` respectively. Their canonical encodings
are `45065ed079bf389758f591131095ef419310e8c708a805852b9b77bed8c7ecbd`,
`e0c0802686d3ed571f7f3399526b24460b16ace461ebda9dcfe6e5b7b298c18c`, and
`7520d96f3e5cd41760367151608b54821883c10c4b9a4ff2beae227bef94bcab`.
Use the existing secret-scalar kernel and fixed tuple, never caller-selected
points or public-input variable-time MSM. Binding requires the same admitted
IPA generator-relation premise plus SHA/Poseidon collision resistance.

Opening sampling uses at most 128 independent 32-byte OS entropy fills. Clear
only bit 255 of each candidate (`candidate[31] &= 0x7f`), then accept the first
canonical little-endian Fp encoding, including zero. Each 255-bit candidate has
exactly two raw preimages, so accepted r is uniform. Under ideal independent
fills, exhaustion is `(1 - p/2^255)^128 < 2^-128`. Entropy error or exhaustion
fails without selection. No reduction, body-derived opening, internal zero-d
reseal or body/proof regeneration is permitted. Exact retries after durable W
reuse all its bytes; missing r follows the same authenticated-copy reconciliation
and custody-loss rules as missing B. Neither r, the body hash nor the wrapper
hash is carried in the public receipt. After capsule collection, an existing
authenticated retained entry may bind its private identity and public commitment
only if both were derived from the same validated W before collection; a
caller-supplied association or operation-ID match is insufficient.

Their enums are Norito enums: frames carry 4-byte tags; the `output` transcript
carries one byte.

| Object | Frame | Interoperability rules |
|---|---|---|
| Marker (`marker` over the frame) | `{version, scheme_id, asset_digest, wallet_id, payment_key, LE128 generation, state}`; state Enrollment 1 `{challenge_digest, enrollment_id}`, Head 2 `{LE128 sequence, operation_id, head, capsule_digest, predecessor_capsule_digest}`, Terminal 3 `{reason, last_capsule_digest}` | Reasons Abandoned 1, CustodyDeleted 2. Generation 0 iff Enrollment, whose `enrollment_id` and `wallet_id` recompute. Head: complete `head`; zero predecessor capsule iff sequence 0. Terminal: zero last capsule iff Abandoned. Successors raise the generation by one: Enrollment → Head (sequence 0) or Terminal Abandoned; Head → Head (sequence + 1, linked capsule) or Terminal CustodyDeleted (last = capsule). The Bootstrap `enrollment_marker` is the generation-0 marker digest. |
| Output descriptor | `{kind, digest}` | `digest = H("output", ·)` over the statement digest, `proof_digest` (a nonzero canonical σ-field value) and, for Receive, the Payment digest the receipt binds (a canonical σ-field value): receipt-free, so the capsule freezes before the receipt. Every other kind input is bound by the statement. |
| Recovery body (`capsule-body` over the frame) | `{version, scheme_id, wallet_id, operation_id, kind, predecessor_capsule_digest, successor_state, statement, predecessor_lineage, step_proof, payment_digest, map_openings: [bytes], retained_inputs: [{role, bytes}], output}` | Retained roles: Request 1, Payment 2, Credited 3, LoadReceipt 4, ChargeQuote 5, PolicyUpdate 6, CertificateSet 7, Credential 8, LoadFinality 9, QuotaRefreshWitness 10. State and statement agree on scheme, wallet, credential, asset, lifecycle, sequence and `next_load`; kind, effect kind and output kind agree; `operation_id` recomputes; zero predecessor capsule iff sequence 0; `predecessor_lineage` (the Ω recorded at fold time) is present exactly for Send, Unload and Retiring, passes the consumer checks for this wallet, and the successor's `burned_total` is its `burned_total`; the successor state's computed commitment is the statement's successor; `payment_digest` is a canonical σ-field value, nonzero exactly for Receive; the output rebuilds for every kind. Retained inputs are non-empty, and the fold witnesses (every consumed input `Λ` verifies for the step, proposal §4.1) are retained: Receive needs Request, Payment, CertificateSet and Credential; ArchiveSent Request, Payment, Credited, the historical payer Credential and its CertificateSet; Send the Request (the Payment binds its fee schedule only by digest); Load LoadReceipt and LoadFinality (the ordinary receipt, native BLS certificate and counted event path; epoch authority is retained separately in Native custody); RefreshPolicy PolicyUpdate and CertificateSet, plus exactly one QuotaRefreshWitness for QuotaShare and none for the other update kinds. The body freezes before an independent opening is sampled; the receipt signs the resulting `capsule_commitment`, as defined below. Each map opening is one §3.2 opening transcript, a leaf opening (1,124 bytes) or an empty-slot opening (1,028 bytes) with exactly 32 canonical siblings and a valid leaf; any other bytes are rejected. Which openings each kind retains is TODO(G3); the vectored Receive capsule retains its consumed-credit insertion witness (the low leaf's opening and the written slot's empty-slot opening). Third set: blacklist-history openings (a Receive's membership of a nonzero recorded pair, a Blacklist refresh's insertion) are ordinary depth-32 openings of this kind. A QuotaShare refresh retains the complete typed predecessor usage array below; its actual predecessor authenticates the array root before the native transition derives every successor slot. Remaining σ witnesses (depth-6 quota openings, depth-16 gap openings) are not indexed-map openings; the coordinator reconstructs them from its authenticated source snapshot, issued Request custody, and retained native intent/choices. The source snapshot retains all 64 quota slots and exact complete policy originals; it is rechecked before Advance and during folding. |
| Recovery capsule (`capsule` over W) | `{body_frame: bytes, opening: [u8;32]}` | `body_frame` is the exact complete canonical RecoveryBodyV1 frame B; `opening` is canonical little-endian Fp r, including zero. This sole first-release wrapper has no duplicate point or cached commitment and no body-only decoder. W is bounded as a whole before sampling/signing; its body also passes its own bound and all rules above. Validate B and r, recompute the public commitment below, and authenticate all private links with `H("capsule", W)`. |
| Monetary restart witness (local retained input, Native required for Send and Receive) | `{version, predecessor_capsule_digest, manifest_digest, statement_digest, enrollment, send: Option<SendSources>, receive: Option<ReceiveSources>}` | Exactly one role11 frame ≤65,536 bytes, version1. Exactly one typed branch agrees with Send or Receive. The exact certificate, installation, predecessor capsule and statement are reauthenticated before restore. SendSources retains the optional original anchored-time frame and optional same-boot monotonic observation, the complete signed quota share, all64 original predecessor usage slots, and an opaque exact full-Blacklist archive reference when held. Complete lists are published and read back in the coordinator's actual immutable archive; the reference alone grants no issuer or current-state authority. ReceiveSources retains the original recorded-history/gap pair and actual source-selected history lookup opening. Permanent credit insertion paths are obtained only from the actual credit tree after predecessor Ω full verification; no future credit value or root is retained at preparation. The Native restore reruns the existing hard Send/Receive checks and compares the exact successor state and statement; the capsule/receipt bind every retained byte. |
| Quota refresh witness (local retained input) | `{version, predecessor_usage: [Option<QuotaUsageLeaf>; 64]}` | Complete frame ≤8,192 bytes; version 1. Every occupied leaf is `{window_kind, window_start_ms, window_end_ms, used}`. Occupied slots form a strictly ordered prefix by `(kind, start)` with valid nonoverlapping windows per kind; every remaining slot is `None`. The named role selects this type, never its byte length. The private capsule hash and signed capsule commitment bind the exact frame; canonical decoding alone grants no predecessor-root or policy authority. |
| Completion record (`completion` over the frame) | `{version, wallet_id, operation_id, capsule_digest, receipt, output: bytes}` | Decoded against the expected wallet. `output` is the canonical compact Payment for Send, whose payer key and credential digest are the wallet's, and the canonical Package frame otherwise. Its receipt equals the record's; its statement, Ω(pred), σ and receipt Payment digest are the capsule's; its receipt-free parts rebuild the capsule's output descriptor; the private `capsule_digest` equals the authenticated wrapper hash, while the receipt verifies over that same wrapper's recomputed `capsule_commitment`. Exact output bytes and all other joins remain required. After W is collected, an operation retry reads the canonical Payment or Package selected by its explicit frame schema, treats the embedded sequence only as a locator, and authenticates the exact completion frame and its private/public capsule identifiers against the permanent StepEntry selected by the protected manifest. It neither scans history nor trusts the decoded sequence as authority. |
| Fold record (`fold` over the frame) | `{version, scheme_id, wallet_id, LE128 first_sequence, LE128 sequence, head, capsule_digest, lineage: Ω}` | The self-verified Ω of one folded head covering the run `first_sequence..=sequence`. Nonzero identities and capsule digest; complete `head`; Ω valid with this scheme, wallet and head; `first_sequence ≤ sequence`. |

### 3.6 Ledger objects

| Object | Frame and transcript | Interoperability rules |
|---|---|---|
| Ordinary Load receipt (unsigned) | `LE16 version ‖ scheme_id ‖ asset_digest ‖ wallet_id ‖ request_id ‖ LE128 ordinal ‖ LE128 amount ‖ LE128 online_charge ‖ charge_quote ‖ transaction_hash ‖ LE64 block_height ‖ payer_account_digest` (282 bytes) | Digest `P_bytes(kgwolod1, transcript)`. Ordinary successful `IssueLoad` execution, authenticated by the installed genesis-rooted native certificate verifier. `block_height ≥ 2`; `amount > 0`; nonzero request identity; `charge_quote` nonzero iff `online_charge > 0`, and then a Load quote with the same scheme, asset, wallet, ordinal, amount and charge; `amount + online_charge` and `ordinal + 1` fit. A state absorbs only its `next_load`. Decoding or recomputing the digest grants no authority. |
| Load finality (local custody frame) | `{version, receipt_digest, certificate: SumeragiCommitCertificateV1, event_proof: MerkleProof<EventBox>}` | Complete frame at most 262,144 bytes, containing only the receipt certificate and counted event path. The certificate carries the canonical consensus header, ordinary BLS CommitQC and execution-result preimage. Native selects its epoch authority from independently authenticated signed global genesis or its protected local epoch archive, then verifies the exact receipt before Advance signing. No finality prover, history-vector layout, accumulator or caller verdict is accepted. This local frame is not carried in each Payment; the 10,000-byte peer bound is unchanged. |
| Epoch boundary (online DATA frame) | `SumeragiCommitCertificateV1 {consensus_header, commit_qc, result_preimage}` | At most 262,144 bytes. Request one exact incumbent boundary through the payer-authenticated `/v1/kagemusha/{scheme}/wallets/{wallet}/loads/{request}/epochs/{boundary}` route. The boundary must precede the retained receipt. Native verifies the incumbent's exact-quorum certificate before atomically selecting the successor under its rollback-sensitive manifest; it never imports a peer checkpoint. Older selected epochs remain available for delayed receipts. Each read and checkpoint is bounded independently of chain lifetime, with no ordinary-block replay. |
| Unload claim | `{version, credential, package, account: AccountId, charge, certificates}`; charge None 0 or Quoted 1 `{quote, beneficiary: AccountId}` | Certificates exactly the issuer plus the quote signer when quoted. `H("account", account)` equals the credential's account digest. The package is a verified Unload carrying Ω(pred), which names the credential's wallet and payment key and passes the consumer checks; `charge` is Quoted iff the effect names a quote, which must be an Unload quote for the effect's exact terms, with `H("account", beneficiary)` as its beneficiary. Payout `amount − online_charge`. |
| Fee claim | `{version, payment, beneficiary: AccountId}` | Structurally a valid Payment naming a fee schedule with `fee > 0`. The payout is checked against the historical schedule the Payment names (digest, scheme, asset, `fee = fee(amount)`), and `H("account", beneficiary)` equals its beneficiary. Full verification takes the schedule, the receiver's Request and the payer's credential and certificates from the ledger's records by the digests the Payment binds, and verifies the Payment as at Receive. |
| Ledger control (signed under `kgwlctl1`) | `LE16 version ‖ scheme_id ‖ asset_digest ‖ wallet_id ‖ tag action ‖ fields zero-filled to 80 ‖ nonce` | Actions Activate 1 `{package_digest}`, CloseLoads 2 `{package_digest, LE128 next_load}`, Abandon 3 `{enrollment_id, LE128 marker_generation, terminal_marker_digest}`. Signed by the wallet payment key; nonzero digests; `marker_generation ≥ 1`. |
| Activation | `{version, control, credential, bootstrap: Package, asset: AssetScope, certificates}` | Certificates exactly the issuer; asset digest equals the credential's; an Activate control by the credential's key naming the digest of the verified Bootstrap package. |
| Close loads | `{version, control, credential, package, certificates}` | A CloseLoads control naming the digest and `next_load` of a verified Retiring, Send or Unload package (so carrying Ω(pred) and passing the consumer checks) whose lifecycle is Retiring. |
| Abandonment | `{version, control, payment_key, challenge_digest}` | An Abandon control whose `enrollment_id` and `wallet_id` recompute from `payment_key` and `challenge_digest`, naming the generation and digest of the Terminal Abandoned marker. Signing only after that marker is durable is design only (G2). |

Exactly-once payouts per nullifier and per `credit_id`, recording activation and
closure, and rejecting Abandon after Activate (and Activate or loads after
Abandon) are ledger state. The current ledger implements idempotent activation
for the same asset and Bootstrap digest and rejects conflicting or abandoned
incarnations; complete G6 qualification remains open.

Activation recovery may retain additional ordinary account-signed transaction
envelopes containing the exact same Activation frame. This does not alter the
Activation wire, payment key, account identity or Bootstrap proof. Each envelope
has its own exact transaction identity, admission and fee checks, transport DATA
and Native finality cursor. App time can schedule a retry but cannot prove that
an earlier attempt did not commit. Successful authenticated inclusion of any
retained attempt confirms the same wallet; it does not imply that other attempts
succeeded. Preserve all signed attempts, each selected verification checkpoint
and the winning finality original. Superseded checkpoints may be retired only
after durable replacement within the same attempt. Native/app/Core integration
and installed execution of this recovery path remain under qualification.
An attempt may be marked rejected only after Native authenticates its exact
transaction and rejected execution output in a verified finalized block. A proof,
storage or transport error never supplies that verdict. Rejection does not enable
Load and does not prevent another retained same-Activation attempt from proving
successful inclusion.

## 4. Measured sizes

Structurally valid complete envelopes are printed by `size_tests.rs`. The Request
carries a fee schedule and two certificates; Payment binds these dependencies by
digest. The codec samples use 3,520-byte σ_send, 4,800-byte Ω and 3,456-byte σ_recv
stand-ins. These establish encoding overhead and exact bounds, not cryptographic
acceptance or a completed Payment. The source fixes the 1,436-byte overhead;
size tests must be rerun on the final composed candidate. Cryptographic and
physical-device qualification remain open. The accepted ordinary
transaction/finality Load relation and complete proof catalog still require qualification (G3).
`F_payment` = 1,436 bytes and the joint proof budget is 8,564 bytes
(`KAGEMUSHA_WALLET_PAYMENT_FIXED_BYTES_V1`, `KAGEMUSHA_WALLET_PAYMENT_PROOF_BUDGET_V1`).
`F_receive` = 679 bytes and the `σ_recv` budget is 9,321 bytes
(`KAGEMUSHA_WALLET_CREDITED_RECEIVE_FIXED_BYTES_V1`,
`KAGEMUSHA_WALLET_CREDITED_RECEIVE_PROOF_BUDGET_V1`). Both Receive selectors must fit
this complete-envelope budget; their frozen keys still select exact proof lengths.
`F_status` = 2,188 bytes and its envelope-derived Ω budget is 7,812 bytes
(`KAGEMUSHA_WALLET_CREDITED_STATUS_FIXED_BYTES_V1`, `KAGEMUSHA_WALLET_LINEAGE_PROOF_CAP_V1`).
The size tests pin complete-frame arithmetic over proof lengths from 128 to
9,999 bytes; that arithmetic does not grant proof authority. The source catalog
separately caps every σ at 3,520 bytes and the Ω transport at 5,044 bytes
(`KAGEMUSHA_WALLET_SIGMA_PROOF_CAP_V1`, `KAGEMUSHA_WALLET_OMEGA_PROOF_CAP_V1`).
The allowlist requires both role bounds and its exact source-specific lengths.
Payment structural admission checks each role and the independent 8,564-byte
joint bound before native verification; neither role can borrow unused capacity.
The internal Ω input tape adds its 320-byte public prefix, giving a 5,364-byte
individual raw cap and an independent 8,884-byte joint raw budget. These input
limits do not enlarge the wire envelope or replace the complete proof decisions.

| Envelope | Bytes / bound | Fixed overhead | Envelope-derived proof budget |
|---|---:|---|---|
| Offer (credential frame 618 / 1,024) | 1,104 / 2,048 | — | — |
| SessionControl (signed ReceiveDeferred) | 338 / 2,048 | — | — |
| Request (fee schedule, 2 certificates) | 1,843 / 10,000 | — | — |
| Payment (σ_send 3,520; Ω proof 4,800) | 9,756 / 10,000 | 1,436 + Ω proof + σ_send | Ω proof 5,044 with the selected σ_send; Ω proof + σ_send 8,564 |
| Credited::Receive (σ_recv 3,456 sample) | 4,135 / 10,000 | 679 + σ_recv | σ_recv 9,321 |
| Credited::Status (Ω(h) proof 4,800, 32 siblings; CreditStatus frame 6,933) | 6,988 / 10,000 | 2,188 + Ω(h) proof | Ω(h) proof 7,812 |
| Lineage (Ω proof 4,800) | 5,213 / 10,000 | 413 + Ω proof | — |
| PolicyData certificates (3) | 698 / 10,000 | — | — |

Other measured frames: the largest Android renewal request (8 certificates totalling 65,536 DER bytes) is
66,021 of 73,728 bytes; a 64-window quota share is 2,941 bytes; the full
65,535-entry blacklist, an online download rather than an envelope, is 2,228,433 of
2,228,736 bytes. Vector frames with 48-byte stand-in σ and Ω proofs: envelopes
Payment 1,529, Credited::Receive 725, Credited::Status 2,235 and Lineage 460;
standalone scheme 208, certificate 222, credential 618, verifying-key allowlist (10
entries) 581, Payment 1,518 and fold record 616. Recovery bodies retain their
complete consumed-credit insertion openings inside the selected wrapper. The canonical quota-refresh witness
is 2,805 bytes with all 64 usage slots occupied and 181 bytes with all slots empty,
under its 8,192-byte cap. The maintained Rust generator emits a Receive recovery
body of 8,326 bytes and its selected wrapper of 8,409 bytes, including the retained
opening and wrapper framing. The quota-refresh wrapper with all 64 retained
predecessor slots is 7,674 bytes. These native64 codec samples contain labelled
stand-in step proofs and fit the unchanged 524,288-byte cap. Consumer readback,
negative cap checks and native32/SDK qualification remain pending. These private
frame measurements do not qualify a native proof or a payment envelope.

**Canonical framing.** The B6 Request transcript is 458 bytes, including the blacklist
version and root. Tests measure Request 1,843 bytes, `F_payment` 1,436 bytes and the
joint budget `|Ω| + |σ_send| ≤ 8,564` bytes. B1 changes no field width,
and B5, B7 and B8 change only private state, so `F_status` (2,188 bytes) and
its 7,812-byte envelope budget stay. The source caps remain 3,520 bytes for σ and
5,044 bytes for Ω even when a particular envelope has spare room. The 4,800-byte Ω
and 3,520-byte σ stand-ins leave 244 bytes in the complete envelope. Every admitted Send mask, both
Receive variants and the complete uniform Ω catalog must retain their exact measured
descriptors before artifact freeze. The ordinary-transaction/finality Load migration does
not add a Payment evidence trail or relax the 10,000-byte bound.

## 5. Vectors

`fixtures/kagemusha/wallet_v1_vectors.json` holds the prefix and digest rule, one
digest vector per SHA-256 role (21: body, preimage, digest), 17 signature vectors, each
with its transcript, signing domain and 32-byte message `m`, and their high-S twins
(`codec_ok` false, `verify_ok` true), the low-S boundary scalars (`s = floor(n/2)`
accepted; `floor(n/2) + 1`, `r` or `s` zero or `n` rejected), nine envelope vectors
(header fields, padding, CRC, canonical bytes, `kgm1:` text and bound), the frame
identities and caps, pinned object frames, the enum tag table, and:

- `field_encodings`: the modulus, the element, Poseidon and packing rules, the 60
  Poseidon domains (34 general domains, 16 signing domains and 10 object-digest domains), the element lists
  of every map value and the credit-digest value, a `send_chain` append from the empty
  chain and a `recv_chain` append with their chain values, a Send and a Receive
  statement with their σ digests, a Receive successor state's core and rest elements,
  rest digest and commitment, and the same for a `controlled_state` (Retiring, every
  control enabled, every policy object held) whose 33 core and 8 rest elements are
  pairwise distinct, with every field's value by name, so that each consumer binds every
  element position to its field;
- `poseidon`: one `P` known-answer vector per domain (over `[1, 2, 3]`), the `P_bytes`
  packing at lengths 0, 1, 30, 31, 32, 62 and 63, `credit_id` with its 26 elements, both
  `proof_digest` domains, the Payment, lineage, credit-opening, credit-status and
  credited digests and the signed message of each signed body (bodies, element counts,
  digests), every map value with its key, the indexed tree (the empty slot, the sentinel
  leaf, the empty-tree root, successive insertions at slots 1, 2, … with every
  intermediate root, the empty subtree of height 1, a membership opening,
  non-membership openings through the sentinel, through an interior low leaf and above
  the largest key, a pending-outgoing removal with the next
  free slot), the `CreditStatus` credit-digest opening, the blacklist
  leaf, node, root and a gap opening over entries whose unsigned byte order differs
  from their limb order, the quota-window leaf, empty slot, node and root, and the
  verifying-key allowlist transcript and digest.

The vectors are self-consistent: the vectored relation identity and artifact
manifest bind the computed `verifying_key_set_digest` of the vectored allowlist, so that
allowlist decodes against the vectored manifest, and no separate stand-in digest
exists; every σ stand-in has exactly its selector's `proof_bytes`, and every Ω stand-in
(Payment, Lineage, CreditStatus, fold record, capsule, and the Unload claim and Retiring
close-loads packages) exactly the allowlist's `lineage_proof_bytes`.

The `P` values reproduce `fixtures/native_prover/kats_v1.json` (`kagemusha_v1_poseidon`),
which the Rust tests check. Keys come from fixed scalars; signatures are RFC 6979, frozen
to low S; stand-ins follow the labelled rules in `stand_ins`. The Rust test
`kagemusha_wallet_v1_vectors_file_matches_the_generated_vectors` compares the file
byte for byte; `IROHA_UPDATE_KAGEMUSHA_WALLET_VECTORS=1` rewrites it (test-only).
The Kotlin (`KagemushaWalletVectorsV1Test`) and Swift (`KagemushaWalletVectorsV1Tests`)
consumers recompute all 21 SHA-256 role digests, including the NEW policy identities,
with every retired role rejected, and mirror
the 16 signing domains with their transcript lengths, verify every signature vector over
its pinned 32-byte message `m` after the low-S rule (and reject it over the transcript),
validate envelope headers and per-kind bounds, and round-trip `kgm1:` text. They
re-derive the element lists (statements, state core and rest with the named
`controlled_state` positions, chains, map values and the 26-element `credit_id` with
both Request account digests and the recorded blacklist pair), the `P_bytes` packing and element counts of every
large-input digest and signing message, the depth-32 indexed-tree openings (sorted
links, low-leaf brackets, fixed 32 siblings, empty subtrees and transcripts), the
CreditStatus opening, the limb-ordered blacklist and the verifying-key allowlist with
its manifest binding and every vectored σ and Ω length. Typed SDK decoding of message
bodies is TODO(G4). Neither SDK recomputes `P` values; `iroha_kagemusha_proof`
(`tests/digest_parity.rs`: statements, state, chains, `credit_id`, the indexed, blacklist
and quota-window trees) and `iroha_plonk_gadgets` (`tests/statement_digest.rs`, and the
byte-linking tests of `src/bytes` for the packing, every large-input digest and every
signing message) reproduce them natively and in circuit.

**Canonical third-set coverage.** The vectors carry 21 SHA-256 role
vectors (the consumers reject retired roles), 60 Poseidon domains (34 general,
16 signing and 10 signed-object domains), every object, certificate-set, package, operation and
nullifier digest as a `P` vector, the 26-element statement and `credit_id` (with the
recorded blacklist pair), the 33-element core and 8-element rest with their named
positions, the new map-value element counts, the quota-usage padding leaf and
all-padding root with an in-place charge and a refresh rebuild, and a blacklist-history
insertion and membership opening.

## 6. Carriers

Every peer message travels as one complete canonical envelope frame (§2). A carrier
moves that frame unchanged; Request additionally carries its destination-account
original. Carrier framing is outside wallet object digests and signatures and
grants no authority. Before handing a frame to the wallet, a carrier checks it
structurally (`KagemushaWalletWireV1.inspectEnvelope`): the byte cap, the Norito header,
schema hash, flags, padding, CRC and envelope field spans, the envelope and message's
top-level versions, a known message tag, the per-kind bound and a 32-byte decode-time
scheme field, without the expected-scheme check. Both Swift and Kotlin apply these
structural checks. Nested version fields, the expected-scheme check, typed decoding and
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
| 12 | 4 | canonical payload length, big-endian |
| 16 | 4 | encoded body length, big-endian |
| 20 | 32 | canonical hash: BLAKE2b-256 of `"IROHA-PEER-PAYLOAD-V1" ‖ 0x00 ‖ BE16 profile ‖ kind ‖ BE16 schema ‖ canonical payload` |
| 52 | 32 | wire hash: BLAKE2b-256 of `"IROHA-PEER-MESSAGE-V1" ‖ 0x00 ‖ header bytes 0..52 ‖ body` |

- For Request, the canonical payload is `"KWRQAC1" ‖ 0x00 ‖ BE32 envelope_length ‖
  BE32 account_length ‖ envelope_original ‖ destination_account_original`. The
  unchanged Request envelope is 1..=10,000 bytes and the mandatory canonical
  AccountId companion is 1..=4,096 bytes; the complete carrier is at most 14,112
  bytes. Both hashes bind both originals; structural transport decoding grants no
  account authentication or financial authority.
- Every other kind carries exactly one envelope frame whose message tag equals
  the IPM1 kind, within that kind's bound: 2,048 bytes for Offer and SessionControl,
  10,000 for Payment, Credited, PolicyData and Lineage. Canonical and encoded lengths
  are positive and bounded by the selected kind. The Request companion does not
  increase the 10,000-byte complete Payment bound.
- zlib is the RFC 1950 form (`78 9C`, DEFLATE, Adler-32 of the canonical payload). A sender uses it
  only when it saves at least 32 bytes and at least one 256-byte QR shard; a decoder
  rejects any other zlib header or length pair.
- Decoding checks the header and both bounds before allocating, then the total length,
  the wire hash, decompression to exactly the declared length, the kind-specific
  payload structure, and the canonical hash. The stream identifier is the first
  16 bytes of the wire hash.

**QR.** A QR text is `IQR1:` ‖ Base45 (RFC 9285, canonical) of one `IRQR` frame ‖ `:`,
at most 700 bytes. An `IRQR` frame is `"IRQR" ‖ 1 ‖ frame kind ‖ BE16 profile ‖ IPM1
kind ‖ 0 ‖ stream identifier (16) ‖ BE16 index ‖ BE16 total ‖ BE16 payload length ‖
payload ‖ BE32 CRC-32C` of everything before the checksum; frame kinds are complete 0,
header 1, data 2 and parity 3. A message whose complete frame fits one text may be shown
as that single static text. Otherwise the sequence is the header frame (the 84-byte IPM1
header), then
256-byte data shards (the last zero-filled) with one XOR parity shard per pair, in the
order D0, D1, P0, D2, D3, P1, …, and the identical header again after every 12
non-header frames; `total` counts data shards (40 for a maximum 10,000-byte Payment,
56 for a maximum 14,112-byte Request carrier). A receiver
accepts frames in any order, ignores identical duplicates, recovers one missing shard
per pair from parity, quarantines a stream on a conflicting duplicate or an invalid
message, bounds active streams (3) and frames before the header (12 frames, 3,072 bytes
per stream), and decodes only a complete message.

**NFC.** The receiver's phone is the card (host card emulation) and the payer's phone is
the reader. Commands use the proprietary class `0x80`, chunks of at most 4,096 bytes and
messages of at most 14,196 bytes (84-byte header plus the maximum Request carrier). Payment
and Credited retain their 10,084-byte transport bound (84-byte header plus their
10,000-byte envelope); an Offer is at most 2,132 bytes.

- *Application identifier.* An application selects its card by the ISO/IEC 7816-4
  application identifier (5–16 bytes) it registered with the platform: on iOS the HCE
  entitlement `com.apple.developer.nfc.hce.iso7816.select-identifier-prefixes` and the
  reader's `com.apple.developer.nfc.readersession.iso7816.select-identifiers`, on Android
  the `HostApduService` aid-filter. Both phones of an exchange use the same identifier.
  An application without its own registration uses the protocol identifier
  `F0504B45504B524E464301`. The identifier only routes the card; it grants no authority.
- *Framing.* Commands are ISO/IEC 7816-4 APDUs in canonical form: the short case whenever
  Lc ≤ 255 and Le ≤ 256, the extended case otherwise; other encodings are rejected. SELECT
  is `00 A4 04 00 ‖ Lc ‖ AID ‖ 00`; a card answers its own identifier with `9000` and any
  other with `6A82`. Every other command is `80 ‖ INS ‖ 00 00` with the data and Le below.
- *Commands.* `s` is the 16-byte session identifier chosen by the card, `h_r` the
  Request's canonical hash and `w_r`, `w_o`, `w_p`, `w_a` the wire hashes of the Request,
  Offer, Payment and acknowledgement; offsets are BE32.

  | INS | Command | Data | Le | Response |
  |---|---|---|---|---|
  | `30` | GET_INTAKE | — | 68 | `IOI1` |
  | `31` | BEGIN_OFFER | `s ‖` Offer IPM1 header (84) | — | — |
  | `32` | WRITE_OFFER | `s ‖ w_o ‖ offset ‖` 1..4,096 bytes | — | — |
  | `33` | SUBMIT_OFFER | `s ‖ w_o` | — | — |
  | `10` | GET_INFO | — | 98 | `INF1` |
  | `11` | READ_REQUEST | `s ‖ h_r ‖ offset` | 1..4,096 | Request bytes |
  | `20` | BEGIN_PAYMENT | `s ‖ h_r ‖` Payment IPM1 header (84) | — | — |
  | `21` | WRITE | `s ‖ w_p ‖ offset ‖` 1..4,096 bytes | — | — |
  | `22` | COMMIT | `s ‖ h_r ‖ w_p` | — | — |
  | `23` | READ_ACK | `s ‖ w_p ‖ offset` | 1..4,096 | acknowledgement bytes |
  | `24` | CONFIRM_ACK | `s ‖ w_p ‖ w_a` | — | — |
  | `25` | GET_STATUS | `s ‖ h_r` | 174 | `NST1` |

- *Records* (fixed length, big-endian, absent values zero-filled):
  - `IOI1` (68): `"IOI1" ‖ 1 ‖ state ‖ BE16 profile ‖ s ‖ BE32 offer_length ‖
    BE32 received_offer_bytes ‖ w_o ‖ BE16 max_write_chunk ‖ BE16 reason`. States:
    awaiting-offer 1, receiving-offer 2, preparing-request 3, request-ready 4, declined 5.
    The Offer fields are zero while awaiting an Offer and when the card hosts a Request
    built from an Offer that arrived over another carrier; `reason` is nonzero exactly
    when declined.
  - `INF1` (98): `"INF1" ‖ 1 ‖ phase ‖ BE16 profile ‖ flags ‖ 0 ‖ s ‖ BE32 request_length ‖
    h_r ‖ w_r ‖ BE16 max_read_chunk ‖ BE16 max_write_chunk`.
  - `NST1` (174): `"NST1" ‖ 1 ‖ phase ‖ BE16 profile ‖ flags ‖ 0 ‖ s ‖ h_r ‖ w_r ‖
    BE16 payment_profile ‖ BE32 payment_length ‖ BE32 received_payment_bytes ‖ w_p ‖
    BE16 ack_profile ‖ BE32 ack_length ‖ w_a ‖ BE16 max_read_chunk ‖ BE16 max_write_chunk`.
  - Phases: request-ready 1, payment-receiving 2, acknowledgement-ready 3, complete 4.
    Flags: idempotent writes `0x01` (always set) and durable acknowledgement `0x02` (set
    exactly in phases 3 and 4).
- *Status words.* `9000` success; `6A82` another identifier; `6985` wrong state, a
  conflicting replay or a Request that is not ready; `6982` a continuity, hash, profile or
  IPM1 failure; `6581` the receiver could not persist; `6700` length; `6A80` malformed
  data; `6D00` and `6E00` an unknown instruction or class.
- *Tap 1: Offer to Request.* A card started without a Request awaits the payer's Offer.
  The reader reads `IOI1`, sends BEGIN_OFFER, writes contiguous chunks (an overlapping
  replay must be byte-identical) and submits. Before SUBMIT_OFFER a different header
  replaces an unfinished Offer; afterwards the intake is bound to that Offer, the same
  Offer's commands are idempotent and any other answers `6985`. The card decodes the
  complete Offer, enters preparing-request and hands the Offer to the receiver's wallet,
  which signs a Request bound to it under the Request rule or declines with a reason. The
  reader polls GET_INTAKE until request-ready, then reads `INF1` and the Request. Request
  commands before request-ready answer `6985`.
- *Tap 2: Payment to Credited.* The payer reviews the Request and approves the Payment away
  from the card, retains the exact Payment with the Request identity, then taps again:
  BEGIN_PAYMENT, contiguous WRITEs, COMMIT, READ_ACK and CONFIRM_ACK, resumed from
  GET_STATUS after any loss. The receiver durably admits the Payment header at
  BEGIN_PAYMENT and answers COMMIT only after it has ingested the Payment and persisted
  the Credited acknowledgement, which it exposes only then. A resumed or retried session
  presents the byte-identical Payment. The Payment must carry exactly the hosted Request's
  signed body and signature, and Credited must name that Request's scheme
  (`KagemushaWalletWireV1.requireExchangeBinding`); the Credited evidence itself is
  checked by the wallet's typed decoder (TODO(G4)). TODO(G4): SessionControl and Lineage
  over NFC.

**Nearby and Petal.** A Nearby session (service `org.hyperledger.iroha.kagemusha.transfer.v1`)
authenticates both devices and then carries complete IPM1 messages of at most 32,704
bytes in encrypted, per-direction sequenced records; the Kotlin session opens a record
only to a verified IPM1 message of its profile. Petal Stream ([petal_stream.md](petal_stream.md))
carries the encoded IPM1 message with the IPM1 kind as its `kind` byte. A receiver that
advertises before it holds a Request binds its discovery context and session to a fresh
random 32-byte value in place of the Request hash; the Offer, Request, Payment and Credited
then all travel inside the authenticated session. Transport encryption and checksums never
replace the wallet's verification.

**Account check code.** Before approving a Send, the payer compares the receiving account's
check code with the receiver, aloud or on both screens. The payer's wallet derives it from
the reviewed `receiver_account_digest`; the receiver's wallet derives it from its own account
original, so both read `H("account", original)` of the same canonical AccountId frame. The
code is that digest's first four bytes as a big-endian unsigned 32-bit integer, reduced
modulo 10^8 and written as eight zero-padded decimal digits in two groups of four separated
by one space (U+0020): a digest beginning `00 01 02 03` gives `0006 6051`. Every wallet
renders exactly this text, and decimal digits read aloud the same way in every language. The
code is display DATA: it authenticates nothing, and the wallet still binds the Payment to the
full reviewed account. Kotlin and Swift `KagemushaWalletAccountCheckCodeV1` implement it
against `fixtures/kagemusha/wallet_account_check_code_v1.json`.

## 7. Open items

- TODO(G4): SessionControl and Lineage over the NFC carrier (§6).
- TODO(G4): nested version fields remain with the typed wallet decoder; carriers check
  only the message's own top-level version and the decode-time scheme field's length (§6).
- TODO(G3): qualify the complete admitted PIPA-v1 σ and Ω transport artifact set,
  its exact proof lengths and the selected verifying keys. The verifying-key allowlist
  (§3.1) carries their identities; its validation requires Ω proof + largest σ_send ≤ 10,000 −
  F_payment (8,564 bytes with the single-owner Payment frame; R9), each σ ≤ 3,520 bytes
  and Ω transport ≤ 5,044 bytes. These source capacities are stricter than the
  9,321-byte Receive and 7,812-byte Status envelope budgets. The vectors' allowlist
  remains a labelled stand-in until exact artifacts are admitted. Every admitted Send mask and the complete Ω construction must be measured
  together against this joint budget after the final descriptor and capacity changes.
  A stand-in byte sample or an earlier descriptor does not qualify the candidate.
- The P-256 Q signature relation verifies the SHA-256 hash of the 32-byte
  Poseidon signing message. The operation relations implement indexed-map
  predicates and effects; recovery capsules retain their selected openings.
  The native producer inventory commits all σ originals, compiled operation
  routes, terminal A identities and the sole Ω original. These implementations
  do not replace qualification of the admitted keys, genuine operation
  compositions and adversarial mutations on one coherent candidate.
- TODO(G3): qualify the canonical B1/B5–B8 proof relations and frozen artifacts against
  the current native objects: 26-element statements and credit IDs, 33-element core,
  8-element rest, quota-usage array, Request blacklist history and quota/time checks.
  The data model, vectors, size constants and Kotlin/Swift structural consumers use
  this layout and reject superseded roles and Request encodings.
- Closed by the third set (2026-10-05): the quota share expiry in σ (B7), two charge
  candidates per kind (B8), the quota charge order (B5; §3.3, Time), the Payment
  transcript digest (kept: it binds the frame transitively, §3.4), the indexed-tree
  slot rule and removal (kept, §3.2), the Receive selector (now the Request's recorded
  decision, §3.1), the Ω cap of 7,812 bytes (kept as a derived envelope bound, §2), the
  receiver list at Receive (B6, §3.4), the `H` statement and object digests (B1, §1),
  the Λ/Ω OQ-1 to OQ-4 text deltas (applied here and in the proposal) and the one-byte
  R9 overrun of the pre-B5 quota σ_send (superseded by the B5 shape and the B6 budget,
  above).
- Open owner question (B6, receiver-list semantics): `Λ_recv` proves only that a
  nonzero recorded `(version, root)` was committed by this wallet before the Receive
  (blacklist-history membership, §3.3); it cannot prove that the list was the latest
  one held when the Request was signed, and a recorded `(0, 0)` carries no proof.
  Under proposal §2.1 the released wallet records its current decision, but a modified
  receiver wallet holding the payment key could cite an older committed list or `(0,
  0)`. May `Λ` accept any historically committed Request-list snapshot, including a
  no-enforcement decision (this record's construction), or must it prove the latest
  decision at issuance, which needs a Request state transition or a trusted
  latest-state signer?
- Open owner question (B4/B5, quota renewal contract): a QuotaShare refresh refuses a
  share that drops a charged key whose window has not ended by the new floor, or that
  introduces an absent key starting before the new floor, except at the first
  allocation (§3.3, RefreshPolicy). Confirm these wallet-side refusals, or instead bind
  the issuer to never change the end of a `(kind, start)` key, so that only the drop
  rule is needed? Both keep consumed quota from being reset.
- Open owner question (B1 scope): B1's list of remaining `H` uses names `scheme_id`, the
  enrollment and renewal transcripts, `account`, the marker, the output descriptor, the
  artifact digests and the platform attestation formats. This record also keeps
  `wallet-id` and `asset-scope` (identities that relations carry but never recompute,
  as Λ/Ω OQ-1 states) and the `capsule`, `completion` and `fold` custody digests (local
  records, like the marker) as `H` (§1). Codex (B9) reads the list as exhaustive and
  notes that native credential validation recomputes `wallet_id`, so exact native and
  in-circuit credential parity would need `Λ` to recompute it; with `H`, the in-circuit
  credential check relies on the issuer signature for that binding. Keep these `H`, or
  move them to `P` (a `P` `wallet_id` is one element and changes the Request,
  `credit_id`, chain, map-value, effect, operation and core element lists)?
- A Send capsule retains the Request message (§8); `Λ_load` and `Λ_unload` do not
  verify ChargeQuote signatures. The native setup owner refuses new Requests
  from a Retiring wallet and retains exact prior setup retries. These are
  wallet behavior, separate from the lineage relation.
- NEW first-release G5 preimages: [typed app/enrollment policy contract](kagemusha_wallet_enrollment_policy_v1.md). These domains and lifetime rules are new decisions, not owner-answer evidence or a mapping of existing opaque digests. Native policy approval/issuer admission and foreign policy carriers remain coordinated G5 work; issuer verification of renewal evidence remains TODO(G5).
- TODO(G4/G6): JavaScript, Python and C# consumers when their wire copies migrate.
- TODO(G3/G6): qualify the implemented ledger instruction family and native
  installation path with matching manifest, catalog, keys and SDK artifacts
  through four-validator monetary execution and physical-device flows.

## Native Load epoch synchronization bridge

Setup **52** reads protected native epoch progress with no inputs. Setup **53** takes
the expected u64 incumbent epoch in `amount` (high half zero; epoch 0 is valid) and one
canonical `SumeragiCommitCertificateV1` in `first`, at most 262,144 bytes. All other
inputs are zero or empty. It verifies exactly that incumbent's boundary and atomically
publishes the successor checkpoint. Both return kind **57**: `sequence_low` is the epoch,
`sequence_high` and `detail` are zero, and the exact 16-byte payload is
`LE64 first_height || LE64 boundary_height`. Progress is protected custody, not HTTP DATA.
An exact original retry reconciles uncertain publication without regressing the tip.
All older epoch checkpoints remain indexed for delayed receipts and retained Load folding.

The Load-original DATA validator binds the exact payer/read selectors and receipt digest,
returns status zero only after canonical decoding, and writes the receipt's untrusted u64
height to its required output pointer (zero on failure). JNI uses one output `long` slot
with the same unsigned bits. This locator grants no finality or monetary authority. SDK
synchronization requests at most 64 boundaries per call, selected from native progress,
checking current ownership and cancellation between requests. A complete batch returns
partial progress; callers repeat until its boundary covers the receipt. Retries resume durable
progress. The subsequent native Load independently restores its receipt epoch from the
protected index and verifies its BLS certificate and counted event before signing Advance.

## Native retained-history collection boundary

The installed wallet setup selector **47** performs one bounded collection turn for the
historical u128 sequence carried in `amount`; zero names Bootstrap. `setup_id`, `token`
and all three originals are zero/empty. The caller supplies no fold verdict, map root or
nonmembership path. Native selects the latest fully verified covering Ω and its retained
pending-map descriptor, checks that exact root and derives Send nonmembership itself.
Collection writes its source-bound durable intent before removing any object and resumes
that same intent after interruption. The current head and undelivered Sends cannot be
collected; required fee, activation and Unload originals and permanent replay records remain.

Results **50 Idle**, **51 Progress**, **52 Collected** contain no bytes and `detail=0`.
Idle has sequence zero; Progress/Collected return the exact requested sequence. Collection
runs under ordinary background eligibility while real payment work can cancel and join it;
the collection call itself does not reserve payment priority. It never deletes payment keys
or terminal custody. The prior public caller-supplied `OutgoingAbsent`/`collect_step` surface
is removed. Existing selector46/result49 keep their activation-attempt semantics.

## Native explicit terminal custody deletion boundary

Terminal deletion is separate from Retiring and retained-history collection. Setup48 reads
actual provider-selected Pending/Released custody and returns result53 with an owner-local,
one-use token in the low sequence word (positive and at most `i64::MAX`; high/detail zero)
and exactly254 bytes of display DATA. The fixed frame is `KWCDV1\0\0` (8 bytes), phase
(1 Pending/2 Released), lifecycle (1 Active/2 Retiring), selected operation kind (1..8), three
boolean bytes for nonempty pending-outgoing/fee-claim/Load-Unload-recovery maps, then six
nonzero bytes32 values (slot, marker original digest, scheme, asset scope, wallet, head),
then LE128 sequence, gross retained balance and core burned total. Core burns must not exceed
gross balance. These retained amounts are **not a fully folded spendable balance**; unfinished
proof work may reveal additional burns. Copying the projection grants no capability.

Before setup49 consumes the token, the client must display the exact state and obtain fresh
explicit confirmation of permanent payment-key loss, loss of retained offline-value recovery,
pending delivery recovery and unpaid or late fee/Unload/activation claims. Native accepts no
caller-supplied marker, path, balance, generic approval flag or projection as authority. The
actual non-Clone review binds the admitted owner and exact current marker. Capability tokens
are process-wide, bounded, positive and never reused across wallet owners or token purposes.

Setup49 freezes money operations before entering a possibly irreversible provider call. The
existing provider publishes and anchors the terminal marker before deleting the key and
custody. Result54 returns the exact nonzero32-byte terminal marker with all scalar fields zero;
ordinary operations remain terminal. On error, only setup50 reconciliation or close may
continue. Setup50 never newly publishes a terminal marker: it resumes already committed
cleanup, or returns result56 (empty bytes/all scalar fields zero) after definite noncommit.
A further deletion then requires a fresh review and explicit confirmation. Terminal recovery
is idempotent and never recreates a key or wallet. Existing provider restart reconciliation
owns cleanup if the process was lost; a terminal wallet cannot reopen for money operations.

Setup51 discards only an unused review, returning result55 with empty bytes/all scalar fields
zero; it cannot undo an attempted deletion. All four selectors use zero setup identity/amount
and no originals; only49/51 carry a token. Discarding a warning or entering Retiring never
publishes deletion. No hardware, phone or deployment qualification follows from host or
simulated-provider tests of this boundary.

## 8. Differences from the implementation design

- The full blacklist cap is 2,228,736 bytes, not the design's 2,228,224, which
  would reject a maximum list (2,228,433 bytes). SDKs take the cap from the vectors.
- A Blacklist Refresh uses retained PolicyUpdate role 6 for one native local
  `BlacklistOriginalReferenceV1` frame, bounded at 512 bytes: `{version: u16 = 1,
  scheme_id: bytes32, original_digest: bytes32, original_bytes: u32}`. The fixed
  Blacklist update kind selects this exact codec; other update kinds retain their
  exact inline originals. There is no inline-list fallback, header substitute or
  length-based dispatch. `original_digest` is the existing domain-separated
  immutable archive-object digest of every byte of the complete standalone list.
  The actual coordinator archive publishes and checks exact readback before
  proving/Advance, and Native resolves the original again before the existing
  issuer-role signature, entry/root and state-effect checks. Missing/corrupt
  selected objects are custody loss; unavailable storage remains retryable. This
  local reference changes neither the full list cap nor any financial relation.
  The source-selected manifest keeps a bounded immutable index keyed by the signed
  blacklist object digest, retaining the full original reference and the exact
  CertificateSet original in archive objects across old Refresh-capsule collection.
  Current lookup derives its selector from the released current state and rechecks
  the entire custody marker and manifest selection after reading both originals;
  it authenticates the RegulatoryPolicy issuer and the current version/root/time
  joins without scanning permanent history or accepting a foreign caller selector.
- The marker terminal reason, output descriptor kind and retained-input role are
  Norito enums, not `u8` fields: their frames carry 4-byte tags, and the `marker`,
  `capsule` and `completion` digests cover those frames.
- Frame padding follows the type's archived alignment, not every contained `u128`:
  a `u128` reached only through a sequence (quota share windows) adds no padding.
  Use the per-type table of §2.
- The credit-opening siblings are one flat byte string of 32-byte values, not a
  sequence of 32-byte arrays: Norito would spend 65 bytes per array element inside
  the 10,000-byte Credited bound.
- The ArchiveSent capsule also retains the Request and historical payer Credential
  with its CertificateSet, which the Payment binds only by digest. A later payer
  renewal cannot substitute its successor credential for those Send originals. A Send capsule retains the Request it consumed (its fee schedule) and a
  Load capsule retains its ordinary receipt and complete finality evidence. Those
  originals are required to rebuild the Load fold (proposal §§3.2, 4.1).
- A QuotaShare refresh retains all 64 predecessor usage slots as one canonical
  `QuotaRefreshWitnessV1` under retained role 10. The native conversion authenticates
  the root against the predecessor and derives the successor usage from the exact
  signed share; no supplied successor array or untyped length dispatch exists.
- Credited is verified against the payer's scheme as well as its Request and
  Payment, so a relation identity other than the scheme's is rejected natively.
