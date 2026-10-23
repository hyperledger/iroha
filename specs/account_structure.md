# Account Structure RFC

**Status:** Accepted (ADDR-1)  
**Audience:** Data model, Torii, Nexus, Wallet, Governance teams

## Summary

This document describes the shipping account-addressing stack implemented in
`AccountAddress` (`crates/iroha_data_model/src/account/address.rs`) and the
companion tooling. It provides:

- A checksummed, human-facing **I105 account address** produced by
  `AccountAddress::to_i105` that binds a chain discriminant to the account
  controller and offers deterministic interop-friendly textual forms.
- A domainless canonical account payload keyed only by the controller.
  Alias routing and domain ownership now live outside the payload through
  dataspace-aware `AccountAlias` bindings and domain-owned entities.

## Motivation

Wallets and off-chain tooling rely on raw `name@dataspace` or `name@domain.dataspace` on-chain account aliases today. This
has two major drawbacks:

1. **No network binding.** The string has no checksum or chain prefix, so users
   can paste an address from the wrong network without immediate feedback. The
   transaction will eventually be rejected (chain mismatch) or, worse, succeed
   against an unintended account if the destination exists locally.
2. **Domain collision.** Domains are namespace-only and can be reused on each
   chain. Federation of services (custodians, bridges, cross-chain workflows)
   becomes brittle because `finance` on chain A is unrelated to `finance` on
   chain B.

We need a human-friendly address format that guards against copy/paste errors
and a deterministic mapping from an on-chain alias to the authoritative chain/account binding.

## Goals

- Describe the I105 envelope implemented in the data model and the
  canonical parsing/alias rules that `AccountId` and `AccountAddress` follow.
- Encode the configured chain discriminant directly into each address and
  document the configuration and validation contract shared by nodes and SDKs.
- Describe the domainless canonical account payload and the separate alias
  binding layer.

## Non-goals

- Implementing cross-chain asset transfers. The routing layer only returns the
  target chain.
- Finalising governance for global domain issuance. This RFC focuses on the data
  model and transport primitives.

## Background

### Current on-chain account alias

```
AccountId {
    controller: AccountController // single PublicKey or multisig policy
}

Display / JSON text: canonical I105 literal only
Parse accepts:
- Canonical I105 account literals only.
- Runtime parsers reject noncanonical/dotted I105 literals, `norito:<hex>`,
  canonical hex (`0x...`), any `@...` suffix, and account-alias literals such as
  `name@dataspace` or `name@domain.dataspace`.

Account aliases are parsed separately through `AccountAlias`, not through
`AccountId`. There is no public `AccountSubjectId`; subject identity is
`AccountId`.
```

`ChainId` lives outside of `AccountId`. Nodes check the transaction’s `ChainId`
against configuration during admission (`AcceptTransactionFail::ChainIdMismatch`)
and reject foreign transactions, but the account string itself carries no
network hint.

### Domain identifiers

`DomainId` wraps a `Name` whose input already uses exact NFC spelling and is
scoped to the local chain.
Every chain can register `wonderland`, `finance`, etc. independently.

### Nexus context

Nexus is responsible for cross-component coordination (lanes/data-spaces). It
currently has no concept of cross-chain domain routing.

## Implemented Design

### 1. Deterministic chain discriminant

`iroha_config::parameters::actual::Common` now exposes:

```rust
pub struct Common {
    pub chain: ChainId,
    pub chain_discriminant: u16, // globally coordinated
    // ... existing fields
}
```

- **Constraints:** Every peer and client in a deployment must use the same
  configured `u16` value. Changing it is a coordinated network configuration
  change because the expected I105 prefix changes.
- **Registry scope:** No public discriminant or CAIP registry participates in
  V1 parsing or admission. Operators coordinate allocations outside the
  runtime; the configured value is authoritative.
- **Usage:** Threaded through state admission, Torii, SDKs, and wallet APIs so
  every component can embed or validate it.

### 2. Canonical address codecs

The Rust data model now distinguishes the public `AccountId` surface from the
lower-level `AccountAddress` helper.

- `AccountId` text/JSON parsing is hard-cut to canonical I105 only.
- `AccountAddress` remains the canonical binary envelope and can still be
  rendered as I105. Canonical hex remains an internal envelope/debug view and
  is not a public account identifier.

- **I105** – the canonical account-address envelope that embeds the chain
  discriminant. Decoders validate the prefix before promoting the payload to
  the canonical form.
- **Canonical hex** – an internal `0x…` view of the canonical byte envelope for
  debugging, fixtures, and low-level tooling only.

`AccountAddress::parse_encoded` accepts i105 forms for
the raw address envelope. `AccountId::parse_encoded`, `FromStr`, and JSON
deserialization accept only canonical I105 and reject noncanonical I105 forms,
canonical hex, `norito:`, alias, and `@domain` forms.

#### 2.1 Header byte layout (ADDR-1a)

Every canonical payload is laid out as `header · controller`. The
`header` is a single byte that communicates which parser rules apply to the bytes that
follow:

```
bit index:   7        5 4      3 2      1 0
             ┌─────────┬────────┬────────┬────┐
payload bit: │version  │ class  │  norm  │ext │
             └─────────┴────────┴────────┴────┘
```

The first byte therefore packs the schema metadata for downstream decoders:

| Bits | Field | Allowed values | Error on violation |
|------|-------|----------------|--------------------|
| 7-5  | `addr_version` | `0` (v1). Values `1-7` are reserved for future revisions. | Values outside `0-7` trigger `AccountAddressError::InvalidHeaderVersion`; implementations MUST treat non-zero versions as unsupported today. |
| 4-3  | `addr_class` | `0` = single key, `1` = multisig. | Other values raise `AccountAddressError::UnknownAddressClass`. |
| 2-1  | `norm_version` | `1` (Norm v1). Values `0`, `2`, `3` are reserved. | Values outside `0-3` raise `AccountAddressError::InvalidNormVersion`. |
| 0    | `ext_flag` | MUST be `0`. | Set bit raises `AccountAddressError::UnexpectedExtensionFlag`. |

The Rust encoder writes `0x02` for single-key controllers (version 0, class 0,
norm v1, extension flag cleared) and `0x0A` for multisig controllers (version 0,
class 1, norm v1, extension flag cleared).

#### 2.2 Domainless payload semantics

Canonical payload bytes are domainless: the wire layout is `header · controller`
with no selector segment, no implicit default-domain reconstruction, and no
decode fallback that reinterprets alias or domain-qualified literals as
canonical accounts.

Alias routing and domain ownership are modeled separately from the canonical
account payload. `AccountAddress` decodes only into `AccountId`; callers that
need alias context must carry an `AccountAlias` literal or an explicit
domain-owned resource identifier alongside the account. The public
subject-identity surface is just `AccountId`; `AccountSubjectId` is not part of
the public API.

Account aliases are a separate binding layer on top of that canonical subject:

- `merchant@banka.paynet` means the alias binding carries both `domain = banka` and
  `dataspace = paynet`, while the bound account is still the same canonical
  domainless `AccountId`.
- `merchant@paynet` is a dataspace-root alias with no domain segment at all; it
  still resolves to a canonical `AccountId` and should not force a synthetic
  alias-derived account identity.
- Stored account values keep only account metadata, an optional primary alias,
  an optional UAID, and opaque identifiers. Alias leases/bindings and
  domain-owned resources live in dedicated state instead of on the account.

Implementation rule for tests and fixtures: seed the universal `AccountId`
first, then add alias leases, alias permissions, and any domain-owned state as
separate records. Account registration is always domainless; tests that need
alias context should bind the alias after registering the canonical account.

#### 2.3 Controller payload encodings (ADDR-1a)

The controller payload is a tagged union appended immediately after the header in
canonical payloads:

| Tag | Controller | Layout | Notes |
|-----|------------|--------|-------|
| `0x00` | Compact single key | `curve_id:u8` · `key_len:u8` · `key_bytes` | Canonical for key payloads up to 255 bytes. |
| `0x01` | Multisig | `version:u8` · `threshold:u16` · `member_count:u16` · (`curve_id:u8` · `weight:u16` · `key_len:u16` · `key_bytes`)\* | The encoded member count is 16-bit; the old 255-member hard cap is gone. Unknown curves raise `AccountAddressError::UnknownCurve`; malformed policies bubble up as `AccountAddressError::InvalidMultisigPolicy`. |
| `0x02` | Extended single key | `curve_id:u8` · `key_len:u16` · `key_bytes` | Canonical only for payloads longer than 255 bytes. The length is big-endian; shorter payloads encoded with this tag are rejected. |

Multisig policies also expose a CTAP2-style CBOR map and canonical digest so
hosts and SDKs can verify the controller deterministically. See
`specs/references/multisig_policy_schema.md` (ADDR-1c) for the schema,
validation rules, hashing procedure, and golden fixtures.

All key bytes are encoded exactly as returned by `PublicKey::to_bytes`; decoders reconstruct `PublicKey` instances and raise `AccountAddressError::InvalidPublicKey` if the bytes do not match the declared curve.

> **Ed25519 canonical enforcement (ADDR-3a):** curve `0x01` keys must decode to the exact byte string emitted by the signer and must not lie in the small-order subgroup. Nodes now reject non-canonical encodings (e.g., values reduced modulo `2^255-19`) and weak points such as the identity element, so SDKs should surface matching validation errors before submitting addresses.

##### 2.3.1 Curve identifier registry (ADDR-1d)

| ID (`curve_id`) | Algorithm | Implementation feature | Notes |
|-----------------|-----------|--------------|-------|
| `0x00` | Reserved | — | MUST NOT be emitted; decoders surface `ERR_UNKNOWN_CURVE`. |
| `0x01` | Ed25519 | — | Canonical v1 identity (`Algorithm::Ed25519`); ordinary admission follows the committed policy. |
| `0x02` | ML‑DSA-65 | `pqc` | Canonical identity and the protocol-fixed 1,952-byte, nonzero public-key geometry exist in every build; cryptographic operations require the PQC implementation. Single-key addresses use extended controller tag `0x02`; multisig members use their existing `u16` lengths. |
| `0x03` | BLS12‑381 (normal) | `bls` | Public keys in G1 (48 bytes), signatures in G2 (96 bytes). |
| `0x04` | secp256k1 | — | Deterministic ECDSA over SHA‑256; public keys use the 33‑byte SEC1 compressed form and signatures use the canonical 64‑byte `r∥s` layout. |
| `0x05` | BLS12‑381 (small) | `bls` | Public keys in G2 (96 bytes), signatures in G1 (48 bytes). |
| `0x0A` | GOST R 34.10‑2012 (256, set A) | `gost` | Canonical identity exists in every build; cryptographic operations require the GOST implementation. |
| `0x0B` | GOST R 34.10‑2012 (256, set B) | `gost` | Canonical identity exists in every build; cryptographic operations require the GOST implementation. |
| `0x0C` | GOST R 34.10‑2012 (256, set C) | `gost` | Canonical identity exists in every build; cryptographic operations require the GOST implementation. |
| `0x0D` | GOST R 34.10‑2012 (512, set A) | `gost` | Canonical identity exists in every build; cryptographic operations require the GOST implementation. |
| `0x0E` | GOST R 34.10‑2012 (512, set B) | `gost` | Canonical identity exists in every build; cryptographic operations require the GOST implementation. |
| `0x0F` | SM2 | `sm` | DistID length (u16 BE) + DistID bytes + 65‑byte SEC1 uncompressed SM2 key; canonical identity exists in every build; cryptographic operations require the SM implementation. |

Slots `0x06–0x09` remain unassigned for additional curves; introducing a new
algorithm requires matching data-model, SDK, host, fixture, and test coverage
in the same change. Algorithm and curve identity are independent of implementation
features: every assigned identifier is known in every Rust build. Unknown identifiers
remain invalid. A known algorithm whose required cryptographic implementation is
unavailable returns the typed `UnsupportedImplementation` cause; it must not be
reported as an unknown curve, invalid signature, or completed protocol rejection.

The canonical registry (including a machine-readable JSON export) lives under
[`references/address_curve_registry.md`](references/address_curve_registry.md).
Tooling SHOULD consume that dataset directly so curve identifiers remain
consistent across SDKs and operator workflows.

- **SDK gating:** SDKs default to Ed25519-only validation/encoding. Swift exposes
  compile-time flags (`IROHASWIFT_ENABLE_MLDSA`, `IROHASWIFT_ENABLE_GOST`,
  `IROHASWIFT_ENABLE_SM`); the Java/Android SDK requires
  `AccountAddress.configureCurveSupport(...)`; the JavaScript SDK uses
  `configureCurveSupport({ allowMlDsa: true, allowGost: true, allowSm2: true })`.
  secp256k1 support is available but not enabled by default in the JS/Android
  SDKs; callers must opt in explicitly when emitting non‑Ed25519 controllers.
- **Host admission:** `Register<Account>` and other ordinary controller consumers
  require every signatory algorithm to belong to the original committed
  `CryptoAdmissionPolicyV1`. Permitted curves follow the canonical algorithm-to-curve
  mapping; there is no independently authored curve list or BLS account exemption.
  Genesis authenticates the initial policy, and updates become effective for the
  next block. A missing local implementation is a separate capability failure and
  cannot change this protocol policy. See [ordinary crypto admission](crypto_admission_policy.md).

##### 2.3.2 Multisig controller guidance

`AccountController::Multisig` serialises policies via
`crates/iroha_data_model/src/account/controller.rs` and enforces the schema
documented in [`references/multisig_policy_schema.md`](references/multisig_policy_schema.md).
Key implementation details:

- Policies are normalised and validated by `MultisigPolicy::validate()` before
  being embedded. Thresholds must be ≥ 1 and ≤ Σ weight; duplicate members are
  removed deterministically after sorting by `(algorithm || 0x00 || key_bytes)`.
- The binary controller payload (`ControllerPayload::Multisig`) encodes
  `version:u8`, `threshold:u16`, `member_count:u16`, then each member’s
  `(curve_id, weight:u16, key_len:u16, key_bytes)`. This is exactly what
  `AccountAddress::canonical_bytes()` writes to I105 payloads.
- The binary member-count field is `u16`, so the encodable limit is 65,535
  members.
- Hashing (`MultisigPolicy::digest_blake2b256()`) uses Blake2b-256 with the
  `iroha-ms-policy` personalization string so governance manifests can bind to a
  deterministic policy ID that matches the controller bytes embedded in I105.
- Fixture coverage lives in `fixtures/account/address_vectors.json` (cases
  `addr-multisig-*`). Wallets and SDKs should assert the generated fixture
  bundle directly rather than copying inline literals into code or docs. The
  canonical renderer now emits mixed Base58 + Iroha-poem I105 payload symbols after the
  chain sentinel.

#### 2.4 Failure rules (ADDR-1a)

- Payloads shorter than the required canonical header+controller size emit
  `AccountAddressError::InvalidLength` or
  `AccountAddressError::UnexpectedTrailingBytes`.
- Headers that set the reserved `ext_flag` or advertise unsupported versions/classes MUST be rejected using `UnexpectedExtensionFlag`, `InvalidHeaderVersion`, or `UnknownAddressClass`.
- Unknown controller tags raise `UnknownControllerTag`.
- Oversized or malformed key material raises `KeyPayloadTooLong` or `InvalidPublicKey`.
- Multisig controllers that exceed the encodable `u16` member count raise
  `MultisigMemberOverflow`; there is no 255-member limit.
- Canonical rendering uses mixed Base58 + Iroha-poem I105 payload symbols after
  the chain sentinel. Public renderers, JSON, and documentation emit this
  canonical form.
- `AccountId` text/JSON parsing does not attempt alias or domain fallback:
  noncanonical I105 literals, `norito:<hex>`, canonical hex, `@domain`, and alias
  forms are rejected up front in favor of canonical I105 only.

#### 2.5 Normative binary vectors

- **Selector-free canonical single-key payload (`seed byte 0x00`)**  
  Canonical hex: `0x020001203b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29`.  
  Breakdown: `0x02` header, `0x00` controller tag, `0x01` curve id (Ed25519),
  `0x20` key length, followed by the 32-byte key payload.
- **Canonical multisig payload layout**  
  `0x0A | 0x01 | version:u8 | threshold:u16 | member_count:u16 | ...members`
  where each member is encoded as `(curve_id:u8, weight:u16, key_len:u16,
  key_bytes)`.
- **Canonical ML-DSA-65 single-key layout**
  `0x02 | 0x02 | 0x02 | 0x07A0 | key_bytes`, where the first `0x02` is the
  single-key header, the second is the extended controller tag, the third is
  the ML-DSA curve id, and `0x07A0` is the big-endian 1,952-byte key length.

The fixture bundle in `fixtures/account/address_vectors.json` publishes I105
outputs plus non-canonical vectors used to assert rejection on public
`AccountId` parser paths.

Reviewed-by: Data Model WG, Cryptography WG — scope approved for ADDR-1a.

##### Sora Nexus reference aliases

Sora Nexus networks default to `chain_discriminant = 0x02F1`
(`iroha_config::parameters::defaults::common::CHAIN_DISCRIMINANT`). The
`AccountAddress::to_i105` helpers therefore emit
consistent textual forms for every canonical payload. The authoritative sample
literals now live only in `fixtures/account/address_vectors.json` so the CLI,
Torii responses, and SDK helpers all consume one canonical I105 source
of truth instead of duplicating stale inline strings.

#### 2.6 Public textual forms

- **Canonical account id:** a I105 literal only.
- **On-chain account aliases:** `name@dataspace` or `name@domain.dataspace`.
  These aliases resolve on-chain to canonical I105 account ids and are not a
  second account-id codec.
- **Out-of-band wrappers:** transport wrappers such as CAIP-style URIs or other
  integration envelopes may exist in downstream systems, but they are not
  canonical account ids. Any such wrapper must resolve to a canonical I105 account id or an
  on-chain alias before it reaches strict parser paths.
- **Machine helpers:** Rust, TypeScript/JavaScript, Python, Swift, Kotlin, and
  Java SDKs expose canonical I105 codecs
  (`AccountAddress::to_i105`, `AccountAddress::parse_encoded`, and equivalents).

#### 2.7 Deterministic i105 encoding

- **Prefix mapping:** Reuse the `chain_discriminant` inside the same canonical
  i105 codec. Well-known discriminants use sentinels such as `sora`, `test`,
  or `dev` as part of the canonical i105 literal; there is no separate ASCII
  account-id codec. The authoritative assignments live in
  [`address_prefix_registry.md`](references/address_prefix_registry.md);
  SDKs MUST keep the matching JSON registry in sync to avoid collisions.
- **Account material:** I105 encodes the canonical payload built by
  `AccountAddress::canonical_bytes()`—header byte and controller payload.
  Domain-selector bytes are not emitted in canonical payloads. There is no additional hashing step; I105 embeds the
  binary controller payload (single key or multisig) as produced by the Rust
  encoder, not the CTAP2 map used for multisig policy digests.
- **Encoding:** `encode_i105()` renders the canonical payload with the
  105-symbol I105 alphabet: 58 Base58 symbols plus the 47 katakana from the
  Iroha poem (including `ヰ` and `ヱ`). It appends a six-symbol Bech32m-style checksum
  over the canonical bytes. CLI/SDK helpers expose the same procedure, and
  `AccountAddress::parse_encoded` reverses it via `decode_i105`.

#### 2.8 Normative textual test vectors

`fixtures/account/address_vectors.json` contains canonical i105 literals plus
negative fixtures that exercise non-canonical and malformed inputs.
Highlights:

- **`addr-single-default-ed25519` (Sora Nexus, prefix `0x02F1`).**  
  Torii emits the generated I105 literal from `AccountId`’s `Display`
  implementation (canonical I105).
- **Multisig controller payloads.**  
  Canonical controller bytes encode `member_count:u16`, so address encoding
  supports the full `u16` member-count range.
- **Failure case (`i105-prefix-mismatch`).**  
  Parsing an i105 literal encoded with prefix `NETWORK_PREFIX + 1` on a node
  expecting the default prefix yields
  `AccountAddressError::UnexpectedNetworkPrefix { expected: 753, found: 754 }`
  before domain routing is attempted. Negative-path `AccountId` tests also cover
  rejected `norito:...`, `0x...`, alias, and `@domain` inputs. The
  `i105-checksum-mismatch` fixture exercises tampering detection over the
  I105 checksum.

#### 2.9 Compliance fixtures

ADDR‑2 ships a replayable fixture bundle covering positive and negative
scenarios across canonical I105, noncanonical negative-vector output, canonical
`AccountAddress` hex renderings, selector-free payloads, multisignature
controllers, and rejected noncanonical `AccountId` literal forms. The canonical JSON
lives in `fixtures/account/address_vectors.json` and can be regenerated with:

```
cargo xtask address-vectors --out fixtures/account/address_vectors.json
# verify without writing:
cargo xtask address-vectors --verify
```

For ad-hoc experiments (different paths/formats) the example binary is still
available:

```
cargo run -p iroha_data_model --example account_address_vectors > fixtures/account/address_vectors.json
```

The canonical Rust host verifier in
`crates/iroha_data_model/tests/account_address_vectors.rs`, together with the JS,
Swift, and Android harnesses (`javascript/iroha_js/test/address.test.js`,
`IrohaSwift/Tests/IrohaSwiftTests/AccountAddressTests.swift`,
`java/iroha_android/src/test/java/org/hyperledger/iroha/android/address/AccountAddressTests.java`),
consumes the same fixture to guarantee codec parity across SDKs. Actual Torii
route admission remains covered separately by
`crates/iroha_torii/tests/address_parsing.rs`.

### 3. Globally unique domains & normalization

See also: [`references/address_norm_v1.md`](references/address_norm_v1.md)
for the canonical boundary between universal accounts and explicit domain
records. `AccountId` and `AccountAddress` are domainless. A complete `DomainId`
is stored anywhere routing, alias ownership, or domain ownership requires
domain context; no account-address selector or configured default-domain value
participates in World state.

#### 3.1 Normalization & spoofing defenses

Norm v1 defines the canonical pipeline every component must use before an
explicit domain or alias label is persisted. The full walkthrough
lives in [`references/address_norm_v1.md`](references/address_norm_v1.md);
the summary below captures the steps that wallets, Torii, SDKs, and governance
tools must implement.

1. **Input validation.** Reject empty strings, UTF-8 inputs longer than 255
   bytes, whitespace, Unicode control characters (including NUL), Unicode
   bidirectional controls, and the reserved delimiters `@`, `#`, `$`. These
   are protocol-level `Name` invariants, enforced identically by constructors
   and Norito/JSON decoders before an identifier or metadata key is returned.
2. **Unicode NFC spelling gate.** Compute NFC only to verify the input spelling.
   Reject any input whose bytes would change (for example, reject
   `e\u{0301}` rather than rewriting it to `é`). Protocol-level `Name`
   constructors and decoders never collapse alternate spellings.
3. **UTS-46 routing canonicalisation.** For explicit domain and alias routing,
   run the already admitted exact-NFC label through UTS‑46 with
   `use_std3_ascii_rules = true`, `transitional_processing = false`, and
   DNS-length enforcement enabled. The result is a lower-case A-label sequence;
   inputs that violate STD3 rules fail here.
4. **Length limits.** Enforce the DNS-style bounds: each label MUST be 1–63
   bytes and the full domain MUST NOT exceed 255 bytes after step 3. SDKs
   should apply the same UTF-8 byte bound and character exclusions before
   signing; node-side decoding remains authoritative.
5. **Optional confusable policy.** UTS‑39 script checks are tracked for
   Norm v2; operators can enable them early, but failing the check must abort
   processing.

If every stage succeeds, the lower-case A-label string is stored as part of the
explicit domain or alias record. It is never embedded into an account address
or compressed through a process-local default. Invalid input is rejected with
structured `ParseError`s at the boundary where the name was supplied.

Canonical fixtures demonstrating these rules — including punycode round-trips
and invalid STD3 sequences — are listed in
`specs/references/address_norm_v1.md` and are mirrored in the SDK CI
vector suites tracked under ADDR‑2.

### 4. Nexus domain registry & routing

- **Registry schema:** Nexus maintains a signed map `DomainName -> ChainRecord`
  where `ChainRecord` includes the chain discriminant, optional metadata (RPC
  endpoints), and a proof of authority (e.g., governance multi-signature).
- **Sync mechanism:**
  - Chains submit signed domain claims to Nexus (either during genesis or via
    governance instruction).
  - Nexus publishes periodic manifests (signed JSON plus optional Merkle root)
    over HTTPS and content-addressed storage (e.g., IPFS). Clients pin the
    latest manifest and verify signatures.
- **Lookup flow:**
  - Torii receives a transaction referencing `DomainId`.
  - If the domain is unknown locally, Torii queries the cached Nexus manifest.
  - If the manifest indicates a foreign chain, the transaction is rejected with
    a deterministic `ForeignDomain` error and the remote chain info.
  - If the domain is missing from Nexus, Torii returns `UnknownDomain`.
- **Trust anchors & rotation:** Governance keys sign manifests; rotation or
  revocation is published as a new manifest entry. Clients enforce manifest
  TTLs (e.g., 24h) and refuse to consult stale data beyond that window.
- **Failure modes:** If manifest retrieval fails, Torii falls back to cached
  data within TTL; past TTL it emits `RegistryUnavailable` and refuses
  cross-domain routing to avoid inconsistent state.

### 5. Wallet & API ergonomics

- **Display defaults:** Wallets show the I105 address plus a resolved account
  alias when one is available. Aliases are descriptive bindings that may
  change, while I105 is the stable account identity.
- **Input canonicalization:** Torii and SDKs accept canonical I105 account IDs only and reject `@domain` suffixes, alias forms, noncanonical I105 literals, and canonical-hex account literals in runtime parser paths. There is no
  strict-mode toggle; raw phone/email identifiers must be kept off-ledger
  via UAID/opaque mappings.
- **Error prevention:** Wallets parse I105 prefixes and enforce chain-discriminant
  expectations. Chain mismatches trigger hard failures with actionable diagnostics.
- **Codec libraries:** Official Rust, TypeScript/JavaScript, Python, and Kotlin
  libraries provide I105 encoding/decoding against the shared vectors.

#### Accessibility & Safe Sharing Guidance

- Keep repository-local implementation requirements in this section. Public,
  in-depth wallet and explorer UX guidance belongs in the sibling
  `iroha-docs` repository and is published at <https://docs.iroha.tech/>.
- **Safe sharing flows:** Surfaces that copy or display addresses default to the i105 form and expose an adjacent “share” action that presents both the full string and a QR code derived from the same payload so users can verify the checksum visually or by scanning. When truncation is unavoidable (e.g., small screens), retain the start and end of the string, add clear ellipses, and keep the full address accessible via copy-to-clipboard to prevent accidental clipping.
- **IME safeguards:** Address inputs MUST reject composition artefacts from IME/IME-style keyboards. Enforce ASCII-only entry, present an inline warning when full-width or Kana characters are detected, and offer a plain-text paste zone that strips combining marks before validation so Japanese and Chinese users can disable their IME without losing progress.
- **Screen-reader support:** Provide visually hidden labels (`aria-label`/`aria-describedby`) that describe the leading i105 digits and chunk the i105 payload into 4- or 8-character groups, so assistive technology reads grouped characters instead of a run-on string. Announce copy/share success via polite live regions and ensure QR previews include descriptive alt text (“i105 address for <alias> on chain 0x02F1”).
- **Single-format usage:** Keep address sharing on canonical I105 only and avoid secondary account-literal formats in wallet/explorer copy flows.

## Implementation Checklist

- **I105 envelope:** The sentinel is `sora`, `test`, or `dev` for the built-in
  discriminants and `n<discriminant>` otherwise. The body is
  `AccountAddress::canonical_bytes()` encoded in base 105, followed by six
  Bech32m checksum limbs derived from HRP `snx` and the canonical bytes.
- **Discriminant configuration:** The configured `u16` value is authoritative;
  no external registry lookup is part of V1 parsing or admission.
- **Domain policy:** Runtime `Name` parsing validates that input already uses exact NFC spelling; domain-label routing separately applies its defined UTS-46 canonicalization.
  Explicit domain and alias constructors additionally use
  `name::canonicalize_domain_label` for UTS-46 and lowercase ASCII output.
- **Textual helpers:** Rust, TypeScript/JavaScript, Python, and Kotlin codecs use
  the shared I105 test vectors.
- **CLI tooling:** Provide a deterministic operator workflow via `iroha tools address convert`
  (see `crates/iroha_cli/src/address.rs`), which accepts canonical I105 literals,
  defaults to i105 output using the Sora Nexus prefix (`753`), enforces prefix
  expectations on parse, and rejects `@domain` suffixes so operator pipelines
  stay on canonical address literals only.
- **Wallet/explorer UX:** Follow the [address display guidelines](sns/address_display_guidelines.md)
  shipped with ADDR-6—keep canonical I105 as the single copy/QR payload and
  apply IME-safe input/output handling.
- **Torii integration:** Strict account-literal parsing accepts canonical I105
  only, rejects noncanonical forms and any `@domain` suffix, and emits canonical
  I105 account identifiers.

### Torii response formats

- `GET /v1/accounts` and `POST /v1/accounts/query` emit canonical I105 account
  literals in responses.
- Asset holder listings (`GET /v1/assets/{definition_id}/holders`) and their JSON
  envelope counterpart (`POST …/holders/query`) also emit canonical I105 account
  identifiers in `items[*].account_id`.
- **Testing:** Unit and integration coverage exercises encoder/decoder
  round-trips, wrong-chain failures, manifest lookups, Torii responses, and SDK
  I105 flows.

## Error Code Registry

Address encoders and decoders expose failures through
`AccountAddressError::code_str()`. The following tables provide the stable codes
that SDKs, wallets, and Torii surfaces should surface alongside human-readable
messages, plus recommended remediation guidance.

### Canonical Construction

| Code | Failure | Recommended Remediation |
|------|---------|-------------------------|
| `ERR_UNSUPPORTED_ALGORITHM` | Encoder received a signing algorithm not supported by the registry or build features. | Restrict account construction to curves enabled in the registry and configuration. |
| `ERR_KEY_PAYLOAD_TOO_LONG` | Signing key payload length exceeds the supported limit. | Single-key controllers support canonical `u16` lengths through extended tag `0x02`; reject payloads larger than 65,535 bytes. |
| `ERR_INVALID_HEADER_VERSION` | Address header version is outside the supported range. | Emit header version `0` for V1 addresses. |
| `ERR_INVALID_NORM_VERSION` | Normalisation version flag is not recognised. | Use normalisation version `1` and avoid toggling reserved bits. |

### Format Decoding and Auto Detection

| Code | Failure | Recommended Remediation |
|------|---------|-------------------------|
| `ERR_INVALID_LENGTH` | Payload length does not match the expected canonical header/controller size. | Supply the full canonical payload emitted by the official encoder. |
| `ERR_CHECKSUM_MISMATCH` | Canonical I105 checksum validation failed. | Regenerate the canonical I105 address from a trusted source; this typically indicates a copy/paste error. |
| `ERR_INVALID_HEX_ADDRESS` | Canonical hexadecimal form failed to decode. | Provide a `0x`-prefixed, even-length hex string produced by the official encoder. |
| `ERR_MISSING_I105_SENTINEL` | I105 form does not start with a recognized chain-discriminant sentinel. | Use the canonical output for the configured chain. |
| `ERR_I105_TOO_SHORT` | I105 string is too short to contain payload and checksum. | Use the full canonical I105 string emitted by the encoder. |
| `ERR_INVALID_I105_CHAR` | I105 payload includes a glyph outside the I105 alphabet. | Replace it with canonical I105 output generated by an official codec. |
| `ERR_INVALID_I105_BASE` | A low-level encoder requested an unsupported alphabet base. | File a bug against the caller; V1 uses base 105. |
| `ERR_INVALID_I105_DIGIT` | A digit exceeds the I105 alphabet bound. | Regenerate canonical I105 and avoid manual digit manipulation. |
| `ERR_UNSUPPORTED_ADDRESS_FORMAT` | Auto-detection could not recognise the input format. | Provide canonical I105 on strict account-id parser paths; use canonical `0x` hex only in low-level/debug tooling that explicitly accepts it. |

### Domain and Network Validation

| Code | Failure | Recommended Remediation |
|------|---------|-------------------------|
| `ERR_UNEXPECTED_NETWORK_PREFIX` | Decoded I105 network prefix differs from the configured value. | Switch to an address from the target chain or adjust the expected discriminant/prefix. |
| `ERR_UNKNOWN_ADDRESS_CLASS` | Address class bits are not recognised. | Use V1 class `0` (single key) or `1` (multisig). |
| `ERR_UNEXPECTED_EXTENSION_FLAG` | Reserved extension bit was set. | Clear reserved bits; extensions are unsupported in V1. |
| `ERR_UNKNOWN_CONTROLLER_TAG` | Controller payload tag not recognised. | Use a V1 single-key or multisig controller payload. |
| `ERR_UNEXPECTED_TRAILING_BYTES` | Canonical payload contained trailing bytes after decoding. | Regenerate the canonical payload; only the documented length should be present. |

### Controller Payload Validation

| Code | Failure | Recommended Remediation |
|------|---------|-------------------------|
| `ERR_INVALID_PUBLIC_KEY` | Key bytes do not match the declared curve. | Ensure the key bytes are encoded exactly as required for the selected curve (e.g., 32-byte Ed25519). |
| `ERR_UNKNOWN_CURVE` | Curve identifier is not registered. | Use a curve ID in `references/address_curve_registry.md` that is enabled by the node configuration. |
| `ERR_MULTISIG_MEMBER_OVERFLOW` | Multisig controller declares more members than supported. | Reduce the multisig membership to the documented limit before encoding. |
| `ERR_INVALID_MULTISIG_POLICY` | Multisig policy payload failed validation (threshold/weights/schema). | Rebuild the policy so that it satisfies the CTAP2 schema, weight bounds, and threshold constraints. |

## Alternatives Considered

- **Embedding chain name in the domain string (e.g., `finance@chain`).** This
  conflates an alias label with network identity and is not the implemented
  encoding.
- **Rely solely on Nexus routing without changing addresses.** Users would still
  copy/paste ambiguous strings; we want the address itself to carry context.
- **Bech32m textual envelope.** V1 uses the I105 base-105 alphabet and network
  sentinel while reusing Bech32m only for its six-limb checksum. A full Bech32m
  text format is not supported.
