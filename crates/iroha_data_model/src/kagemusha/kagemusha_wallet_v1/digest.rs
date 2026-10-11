//! Domain-separated SHA-256 digests, Poseidon signing messages, object digests and signature
//! freezing (§§3, 8, design §1; owner answers A1 and A3, and B1 of the third set, 2026-10-05).

use p256::ecdsa::Signature as P256Signature;
use sha2::{Digest as _, Sha256};

use super::{
    KagemushaWalletValidationErrorV1, WalletResult,
    keys::{KagemushaDevicePublicKeyV1, KagemushaDeviceSignatureV1},
    poseidon::{kagemusha_wallet_poseidon_bytes_v1, poseidon_items_v1},
};

#[cfg(test)]
#[path = "digest_tests.rs"]
mod digest_tests;

/// Prefix of every KAGEMUSHA wallet V1 digest preimage.
pub const KAGEMUSHA_WALLET_DIGEST_PREFIX_V1: &[u8] = b"iroha:kagemusha:wallet:v1:";
/// Exact body bytes hashed by the artifact-manifest digest: `m (32) || signature (64)`.
pub const KAGEMUSHA_WALLET_SIGNED_OBJECT_TRANSCRIPT_BYTES_V1: usize = 96;

/// Exact role label of one domain-separated SHA-256 KAGEMUSHA wallet V1 digest.
///
/// `H` remains only where no relation recomputes the value (wire record §1, owner answer B1 of
/// the third set): `scheme_id`, the identities fixed at enrollment (asset scope, wallet,
/// enrollment), the enrollment and renewal transcripts given to platform attestation, the
/// `account` digest, the artifact digests, the evidence digest, the output descriptor and the
/// local custody records. Every digest a relation recomputes is a Poseidon value of the σ field
/// instead (§3): `credit_id`, map leaves and roots, chains, the state commitment, the statement,
/// object, certificate-set, package, operation and nullifier digests, the blacklist,
/// quota-window, quota-usage and credit-digest trees, every signing message, and the
/// large-input digests (`P_bytes`, [`super::poseidon`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KagemushaWalletDigestRoleV1 {
    /// `scheme`: scheme identity (§§2.2, 3.3).
    Scheme,
    /// `relation`: frozen relation identity (§§3.2, 3.3).
    Relation,
    /// `provider-contract`: Advance contract and receipt format identity (§2.2).
    ProviderContract,
    /// `asset-scope`: asset incarnation and scale (§2.2).
    AssetScope,
    /// `account`: canonical domainless `AccountId` frame.
    Account,
    /// `enrollment-challenge`: issuer enrollment challenge (§2.2).
    EnrollmentChallenge,
    /// NEW first-release `app-policy`: explicit app identity selection.
    AppPolicy,
    /// NEW first-release `enrollment-policy`: exact verifier/regulatory selection.
    EnrollmentPolicy,
    /// `enrollment-id`: enrollment incarnation identity (§2.2).
    EnrollmentId,
    /// `enrollment-key-binding`: App Attest enrollment assertion client data (§2.2).
    EnrollmentKeyBinding,
    /// `wallet-id`: wallet incarnation identity (§2.2).
    WalletId,
    /// `artifact-manifest`: artifact manifest digest `H(m || signature)`.
    ArtifactManifest,
    /// `evidence`: original platform evidence bytes (design C3).
    Evidence,
    /// `renewal-assertion`: App Attest renewal assertion client data (design C3).
    RenewalAssertion,
    /// `verifying-key-set`: the σ verifying-key allowlist whose digest is the manifest's
    /// `verifying_key_set_digest` (§3.2, owner answer Q11).
    VerifyingKeySet,
    /// `output`: receipt-free output descriptor (§4.1).
    Output,
    /// `marker`: local provider marker frame (§4.2).
    Marker,
    /// `capsule`: local recovery capsule frame (§4.1).
    Capsule,
    /// `completion`: local completion record frame (§4.1).
    Completion,
    /// `fold`: durable fold record of one self-verified Ω (§3.1 step 5).
    Fold,
}

impl KagemushaWalletDigestRoleV1 {
    /// Every role, in declaration order.
    pub const ALL: [Self; 20] = [
        Self::Scheme,
        Self::Relation,
        Self::ProviderContract,
        Self::AssetScope,
        Self::Account,
        Self::EnrollmentChallenge,
        Self::AppPolicy,
        Self::EnrollmentPolicy,
        Self::EnrollmentId,
        Self::EnrollmentKeyBinding,
        Self::WalletId,
        Self::ArtifactManifest,
        Self::Evidence,
        Self::RenewalAssertion,
        Self::VerifyingKeySet,
        Self::Output,
        Self::Marker,
        Self::Capsule,
        Self::Completion,
        Self::Fold,
    ];

    /// Exact ASCII role label hashed after [`KAGEMUSHA_WALLET_DIGEST_PREFIX_V1`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Scheme => "scheme",
            Self::Relation => "relation",
            Self::ProviderContract => "provider-contract",
            Self::AssetScope => "asset-scope",
            Self::Account => "account",
            Self::EnrollmentChallenge => "enrollment-challenge",
            Self::AppPolicy => "app-policy",
            Self::EnrollmentPolicy => "enrollment-policy",
            Self::EnrollmentId => "enrollment-id",
            Self::EnrollmentKeyBinding => "enrollment-key-binding",
            Self::WalletId => "wallet-id",
            Self::ArtifactManifest => "artifact-manifest",
            Self::Evidence => "evidence",
            Self::RenewalAssertion => "renewal-assertion",
            Self::VerifyingKeySet => "verifying-key-set",
            Self::Output => "output",
            Self::Marker => "marker",
            Self::Capsule => "capsule",
            Self::Completion => "completion",
            Self::Fold => "fold",
        }
    }
}

/// Domain-separated digest `H(role, body)` (§8).
#[must_use]
pub fn kagemusha_wallet_digest_v1(role: KagemushaWalletDigestRoleV1, body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(KAGEMUSHA_WALLET_DIGEST_PREFIX_V1);
    hasher.update(role.as_str().as_bytes());
    hasher.update([0]);
    hasher.update(body_length_le64(body));
    hasher.update(body);
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------------------
// Signing messages, signatures and signed-object digests (§§3, 8; owner answer A1)
// ---------------------------------------------------------------------------------------

/// Signing domain of one signed wallet body: the Poseidon domain of its 32-byte signing
/// message `m = P_bytes(d, transcript)` (§§3, 8; owner answer A1 of 2026-10-05).
///
/// Every P-256 signature of the protocol signs `m` as its message with standard
/// ECDSA-P256-SHA256: the ECDSA hash is `SHA-256(m)`, one SHA-256 block in circuit. The Secure
/// Enclave signs `m` with `kSecKeyAlgorithmECDSASignatureMessageX962SHA256`, Android `KeyMint`
/// with a `DIGEST_SHA256` key through `SHA256withECDSA`, and issuer, policy, ledger and artifact
/// signers with the same ECDSA-P256-SHA256; no-digest modes are never used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KagemushaWalletSigningDomainV1 {
    /// `kgwcert1`: signer certificate body, signed by the scheme root.
    Certificate,
    /// `kgwcred1`: credential body, signed by an Enrollment-role key.
    Credential,
    /// `kgwrnch1`: renewal challenge, signed by the payment key (possession).
    RenewalChallenge,
    /// `kgwrnkb1`: renewal key binding of a newly attested Android key, signed by the payment
    /// key.
    RenewalKeyBinding,
    /// `kgwartf1`: artifact manifest body, signed by an Artifact-role key.
    ArtifactManifest,
    /// `kgwrcpt1`: provider receipt body, signed by the payment key.
    Receipt,
    /// `kgwspol1`: scheme policy body, signed by a RegulatoryPolicy-role key.
    SchemePolicy,
    /// `kgwfsch1`: fee schedule body, signed by a RegulatoryPolicy-role key.
    FeeSchedule,
    /// `kgwblst1`: blacklist body, signed by a RegulatoryPolicy-role key.
    Blacklist,
    /// `kgwqshr1`: quota share body, signed by a RegulatoryPolicy-role key.
    QuotaShare,
    /// `kgwtanc1`: time anchor body, signed by a TimeAnchor-role key.
    TimeAnchor,
    /// `kgwchgq1`: charge quote body, signed by a RegulatoryPolicy-role key.
    ChargeQuote,
    /// `kgwoffr1`: Offer body, signed by the payer payment key.
    Offer,
    /// `kgwsctl1`: session control body, signed by the session payment key.
    SessionControl,
    /// `kgwrqst1`: Request body, signed by the receiver payment key.
    Request,
    /// `kgwlctl1`: ledger control body, signed by the payment key.
    LedgerControl,
}

impl KagemushaWalletSigningDomainV1 {
    /// Every signing domain, in declaration order.
    pub const ALL: [Self; 16] = [
        Self::Certificate,
        Self::Credential,
        Self::RenewalChallenge,
        Self::RenewalKeyBinding,
        Self::ArtifactManifest,
        Self::Receipt,
        Self::SchemePolicy,
        Self::FeeSchedule,
        Self::Blacklist,
        Self::QuotaShare,
        Self::TimeAnchor,
        Self::ChargeQuote,
        Self::Offer,
        Self::SessionControl,
        Self::Request,
        Self::LedgerControl,
    ];

    /// The 8 ASCII bytes of the domain word.
    #[must_use]
    pub const fn ascii(self) -> [u8; 8] {
        match self {
            Self::Certificate => *b"kgwcert1",
            Self::Credential => *b"kgwcred1",
            Self::RenewalChallenge => *b"kgwrnch1",
            Self::RenewalKeyBinding => *b"kgwrnkb1",
            Self::ArtifactManifest => *b"kgwartf1",
            Self::Receipt => *b"kgwrcpt1",
            Self::SchemePolicy => *b"kgwspol1",
            Self::FeeSchedule => *b"kgwfsch1",
            Self::Blacklist => *b"kgwblst1",
            Self::QuotaShare => *b"kgwqshr1",
            Self::TimeAnchor => *b"kgwtanc1",
            Self::ChargeQuote => *b"kgwchgq1",
            Self::Offer => *b"kgwoffr1",
            Self::SessionControl => *b"kgwsctl1",
            Self::Request => *b"kgwrqst1",
            Self::LedgerControl => *b"kgwlctl1",
        }
    }

    /// Domain label as text, for example `kgwcert1`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Certificate => "kgwcert1",
            Self::Credential => "kgwcred1",
            Self::RenewalChallenge => "kgwrnch1",
            Self::RenewalKeyBinding => "kgwrnkb1",
            Self::ArtifactManifest => "kgwartf1",
            Self::Receipt => "kgwrcpt1",
            Self::SchemePolicy => "kgwspol1",
            Self::FeeSchedule => "kgwfsch1",
            Self::Blacklist => "kgwblst1",
            Self::QuotaShare => "kgwqshr1",
            Self::TimeAnchor => "kgwtanc1",
            Self::ChargeQuote => "kgwchgq1",
            Self::Offer => "kgwoffr1",
            Self::SessionControl => "kgwsctl1",
            Self::Request => "kgwrqst1",
            Self::LedgerControl => "kgwlctl1",
        }
    }

    /// Poseidon domain word: the `u64` of the 8 little-endian ASCII bytes.
    #[must_use]
    pub const fn domain(self) -> u64 {
        u64::from_le_bytes(self.ascii())
    }

    /// Exact transcript bytes of the signed body (wire record §1).
    #[must_use]
    pub const fn transcript_bytes(self) -> usize {
        match self {
            Self::Certificate => 108,
            Self::Credential => 476,
            Self::RenewalChallenge => 130,
            Self::RenewalKeyBinding => 163,
            Self::ArtifactManifest => 290,
            Self::Receipt => 338,
            Self::SchemePolicy => 142,
            Self::FeeSchedule => 191,
            Self::Blacklist => 118,
            Self::QuotaShare => 190,
            Self::TimeAnchor => 138,
            Self::ChargeQuote => 219,
            Self::Offer => 194,
            Self::SessionControl => 197,
            Self::Request => 458,
            Self::LedgerControl => 211,
        }
    }
}

/// Signing message `m`: the 32-byte canonical encoding of `P_bytes(domain, transcript)` (§§3,
/// 8; owner answer A1). Every P-256 signature of the protocol signs exactly these 32 bytes with
/// ECDSA-P256-SHA256.
#[must_use]
pub fn kagemusha_wallet_signing_message_v1(
    domain: KagemushaWalletSigningDomainV1,
    transcript: &[u8],
) -> [u8; 32] {
    debug_assert_eq!(transcript.len(), domain.transcript_bytes());
    kagemusha_wallet_poseidon_bytes_v1(domain.domain(), transcript)
}

/// Object-digest domain of one signed body whose digest a relation recomputes (wire record §1,
/// owner answer B1 of the third set).
///
/// The object digest is `P(d_obj, [m, r_lo, r_hi, s_lo, s_hi])`
/// ([`kagemusha_wallet_signed_object_digest_v1`]). The artifact manifest alone keeps the SHA-256
/// digest `H("artifact-manifest", m || signature)`, an artifact digest no relation recomputes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KagemushaWalletObjectDigestDomainV1 {
    /// `kgwocrt1`: signer certificate.
    Certificate,
    /// `kgwocrd1`: credential.
    Credential,
    /// `kgworcp1`: provider receipt τ.
    Receipt,
    /// `kgwopol1`: scheme policy.
    SchemePolicy,
    /// `kgwofee1`: fee schedule.
    FeeSchedule,
    /// `kgwoblk1`: blacklist.
    Blacklist,
    /// `kgwoqsh1`: quota share.
    QuotaShare,
    /// `kgwotim1`: time anchor.
    TimeAnchor,
    /// `kgwochg1`: charge quote.
    ChargeQuote,
    /// `kgworeq1`: Request.
    Request,
}

impl KagemushaWalletObjectDigestDomainV1 {
    /// Every object-digest domain, in declaration order.
    pub const ALL: [Self; 10] = [
        Self::Certificate,
        Self::Credential,
        Self::Receipt,
        Self::SchemePolicy,
        Self::FeeSchedule,
        Self::Blacklist,
        Self::QuotaShare,
        Self::TimeAnchor,
        Self::ChargeQuote,
        Self::Request,
    ];

    /// Domain label as text, for example `kgwocrt1`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Certificate => "kgwocrt1",
            Self::Credential => "kgwocrd1",
            Self::Receipt => "kgworcp1",
            Self::SchemePolicy => "kgwopol1",
            Self::FeeSchedule => "kgwofee1",
            Self::Blacklist => "kgwoblk1",
            Self::QuotaShare => "kgwoqsh1",
            Self::TimeAnchor => "kgwotim1",
            Self::ChargeQuote => "kgwochg1",
            Self::Request => "kgworeq1",
        }
    }

    /// Poseidon domain word: the `u64` of the 8 little-endian ASCII bytes.
    #[must_use]
    pub const fn domain(self) -> u64 {
        let bytes = self.as_str().as_bytes();
        u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])
    }

    /// Signing domain of the body this object digest names.
    #[must_use]
    pub const fn signing_domain(self) -> KagemushaWalletSigningDomainV1 {
        match self {
            Self::Certificate => KagemushaWalletSigningDomainV1::Certificate,
            Self::Credential => KagemushaWalletSigningDomainV1::Credential,
            Self::Receipt => KagemushaWalletSigningDomainV1::Receipt,
            Self::SchemePolicy => KagemushaWalletSigningDomainV1::SchemePolicy,
            Self::FeeSchedule => KagemushaWalletSigningDomainV1::FeeSchedule,
            Self::Blacklist => KagemushaWalletSigningDomainV1::Blacklist,
            Self::QuotaShare => KagemushaWalletSigningDomainV1::QuotaShare,
            Self::TimeAnchor => KagemushaWalletSigningDomainV1::TimeAnchor,
            Self::ChargeQuote => KagemushaWalletSigningDomainV1::ChargeQuote,
            Self::Request => KagemushaWalletSigningDomainV1::Request,
        }
    }
}

/// The 5 σ-field elements of one object digest: `[m, r_lo, r_hi, s_lo, s_hi]`.
///
/// `m` is the signing message (one canonical element) and `r_lo = r mod 2^128`,
/// `r_hi = floor(r / 2^128)` and likewise `s_lo`, `s_hi` are the numeric 128-bit halves of the
/// big-endian `r` and `s` of the 64-byte signature. No P-256 scalar is reduced modulo `p`; in
/// circuit the limbs are range-checked and linked to the raw big-endian signature bytes.
#[must_use]
pub fn kagemusha_wallet_signed_object_items_v1(
    message: &[u8; 32],
    signature: &KagemushaDeviceSignatureV1,
) -> Vec<[u8; 32]> {
    let raw = signature.as_raw_bytes();
    let half = |offset: usize| {
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&raw[offset..offset + 16]);
        u128::from_be_bytes(bytes)
    };
    WalletFieldItemsV1::with_capacity(5)
        .field(message)
        .integer(half(16))
        .integer(half(0))
        .integer(half(48))
        .integer(half(32))
        .finish()
}

/// Object digest of one signed object: `P(d_obj, [m, r_lo, r_hi, s_lo, s_hi])` (wire record §1,
/// owner answer B1), one canonical σ-field value.
///
/// `message` is the body's signing message, a canonical σ-field value by construction.
#[must_use]
pub fn kagemusha_wallet_signed_object_digest_v1(
    domain: KagemushaWalletObjectDigestDomainV1,
    message: &[u8; 32],
    signature: &KagemushaDeviceSignatureV1,
) -> [u8; 32] {
    poseidon_items_v1(
        domain.domain(),
        &kagemusha_wallet_signed_object_items_v1(message, signature),
    )
}

/// SHA-256 digest of the signed artifact manifest: `H("artifact-manifest", m || signature)`,
/// an artifact digest no relation recomputes (wire record §1).
#[must_use]
pub fn kagemusha_wallet_artifact_manifest_digest_v1(
    message: &[u8; 32],
    signature: &KagemushaDeviceSignatureV1,
) -> [u8; 32] {
    let body =
        WalletTranscriptV1::with_capacity(KAGEMUSHA_WALLET_SIGNED_OBJECT_TRANSCRIPT_BYTES_V1)
            .digest(message)
            .signature(signature)
            .finish();
    kagemusha_wallet_digest_v1(KagemushaWalletDigestRoleV1::ArtifactManifest, &body)
}

/// Raw output of a platform P-256 signer, before it is frozen into a canonical object.
///
/// The variant is explicit: there is no length-based dispatch between encodings.
// The fixed 64-byte raw form stays inline; equalizing the variants would only add an
// allocation or an indirection to a short-lived signer handoff value.
#[allow(variant_size_differences)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KagemushaWalletSignerOutputV1<'a> {
    /// Strict DER, as returned by Android Keystore `SHA256withECDSA` or `CryptoKit`
    /// `derRepresentation`.
    Der(&'a [u8]),
    /// Fixed-width big-endian `r || s`, as returned by `CryptoKit` `rawRepresentation`.
    Raw([u8; 64]),
}

/// Normalize a fresh signer output over the signing message `message` of `domain` to low S and
/// verify it under `key`.
///
/// Every constructor that embeds a fresh signature goes through this function, so a frozen
/// object never carries a high-S, malformed or non-verifying signature. The signer signed the
/// 32 bytes of `message` with ECDSA-P256-SHA256. Verifiers use
/// [`kagemusha_wallet_verify_signature_v1`], which rejects high S instead of rewriting it.
///
/// # Errors
///
/// Returns [`KagemushaWalletValidationErrorV1::InvalidSignature`] for non-canonical DER,
/// out-of-range scalars, or a signature that does not verify.
pub fn kagemusha_wallet_freeze_signature_v1(
    key: &KagemushaDevicePublicKeyV1,
    domain: KagemushaWalletSigningDomainV1,
    message: &[u8; 32],
    signer_output: KagemushaWalletSignerOutputV1<'_>,
) -> WalletResult<KagemushaDeviceSignatureV1> {
    let rejected = || KagemushaWalletValidationErrorV1::InvalidSignature { domain };
    let signature = match signer_output {
        KagemushaWalletSignerOutputV1::Der(der) => {
            KagemushaDeviceSignatureV1::from_der_normalizing_low_s(der).map_err(|_| rejected())?
        }
        KagemushaWalletSignerOutputV1::Raw(raw) => {
            let parsed = P256Signature::from_slice(&raw).map_err(|_| rejected())?;
            let low_s = parsed.normalize_s().unwrap_or(parsed);
            KagemushaDeviceSignatureV1::from_raw_bytes(low_s.to_bytes().as_slice())
                .map_err(|_| rejected())?
        }
    };
    kagemusha_wallet_verify_signature_v1(key, domain, message, &signature)?;
    Ok(signature)
}

/// Verify a received low-S ECDSA-P256-SHA256 signature over the 32-byte signing message
/// `message` of `domain` under `key`.
///
/// # Errors
///
/// Returns [`KagemushaWalletValidationErrorV1::InvalidSignature`] when the key or signature
/// is not canonical or the signature does not verify.
pub fn kagemusha_wallet_verify_signature_v1(
    key: &KagemushaDevicePublicKeyV1,
    domain: KagemushaWalletSigningDomainV1,
    message: &[u8; 32],
    signature: &KagemushaDeviceSignatureV1,
) -> WalletResult<()> {
    signature
        .verify(key, message)
        .map_err(|_| KagemushaWalletValidationErrorV1::InvalidSignature { domain })
}

// ---------------------------------------------------------------------------------------
// σ-field encodings (§§3, 3.2, 8; design §1.2 and §1.3)
// ---------------------------------------------------------------------------------------

/// Canonical little-endian encoding of the σ-field modulus
/// `p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001`.
///
/// The step relations σ are single-parity on Vesta `Eq` (§3.2), so every value they compute
/// or open (state commitment, chains, map roots, the statement digest) is an element of the
/// Vesta scalar field, Pasta `Fp`. A field value travels as its 32-byte little-endian
/// encoding, which must be `< p`; a noncanonical encoding is rejected before mutation (§8).
pub const KAGEMUSHA_WALLET_FIELD_MODULUS_V1: [u8; 32] = [
    0x01, 0x00, 0x00, 0x00, 0xed, 0x30, 0x2d, 0x99, 0x1b, 0xf9, 0x4c, 0x09, 0xfc, 0x98, 0x46, 0x22,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
];

/// Whether `value` is a canonical little-endian σ-field encoding, `value < p` (design §1.2).
///
/// This is a pure byte comparison against [`KAGEMUSHA_WALLET_FIELD_MODULUS_V1`], from the
/// most significant byte down; no field arithmetic is involved.
#[must_use]
pub fn kagemusha_wallet_is_canonical_field_v1(value: &[u8; 32]) -> bool {
    for (byte, modulus) in value
        .iter()
        .rev()
        .zip(KAGEMUSHA_WALLET_FIELD_MODULUS_V1.iter().rev())
    {
        match byte.cmp(modulus) {
            core::cmp::Ordering::Less => return true,
            core::cmp::Ordering::Greater => return false,
            core::cmp::Ordering::Equal => {}
        }
    }
    false
}

/// Canonical σ-field encoding of one integer element: `value` little-endian in the low 16
/// bytes, zero in the high 16 bytes (design §1.3). Every `u128` is below `p`.
#[must_use]
pub fn kagemusha_wallet_field_from_u128_v1(value: u128) -> [u8; 32] {
    let mut encoding = [0_u8; 32];
    encoding[..16].copy_from_slice(&value.to_le_bytes());
    encoding
}

/// Builder of one ordered σ-field element list (design §1.3 limb rule).
///
/// An integer (`u8` to `u128`, an enum tag or a mask) is one element; a 32-byte SHA-256
/// digest or identifier is two elements, its little-endian 128-bit limbs, low half first; a
/// field value (commitment, chain, Poseidon root, nonce) is one element, its canonical
/// encoding. The callers validate field values before they are appended.
#[derive(Debug)]
pub(super) struct WalletFieldItemsV1 {
    items: Vec<[u8; 32]>,
}

impl WalletFieldItemsV1 {
    /// Start an empty list with the exact expected capacity.
    pub(super) fn with_capacity(capacity: usize) -> Self {
        Self {
            items: Vec::with_capacity(capacity),
        }
    }

    /// Append one integer element.
    pub(super) fn integer(mut self, value: u128) -> Self {
        self.items.push(kagemusha_wallet_field_from_u128_v1(value));
        self
    }

    /// Append a 32-byte digest as its two little-endian 128-bit limbs, low half first.
    pub(super) fn digest(self, value: &[u8; 32]) -> Self {
        let mut low = [0_u8; 16];
        let mut high = [0_u8; 16];
        low.copy_from_slice(&value[..16]);
        high.copy_from_slice(&value[16..]);
        self.integer(u128::from_le_bytes(low))
            .integer(u128::from_le_bytes(high))
    }

    /// Append one canonical field value.
    pub(super) fn field(mut self, value: &[u8; 32]) -> Self {
        self.items.push(*value);
        self
    }

    /// Append `count` zero elements, used to fill a fixed-width effect union.
    pub(super) fn zeros(mut self, count: usize) -> Self {
        self.items
            .resize(self.items.len().saturating_add(count), [0; 32]);
        self
    }

    /// Number of elements appended so far.
    pub(super) fn len(&self) -> usize {
        self.items.len()
    }

    /// Return the completed element list.
    pub(super) fn finish(self) -> Vec<[u8; 32]> {
        self.items
    }
}

fn body_length_le64(body: &[u8]) -> [u8; 8] {
    // `usize` is at most 64 bits on every admitted target, so the conversion is exact.
    u64::try_from(body.len()).unwrap_or(u64::MAX).to_le_bytes()
}

/// Fixed-layout transcript builder shared by the wallet object owners (design §1).
#[derive(Debug)]
pub(super) struct WalletTranscriptV1 {
    bytes: Vec<u8>,
}

impl WalletTranscriptV1 {
    /// Start an empty transcript with the exact expected capacity.
    pub(super) fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    /// Append one byte, used for enum tags.
    pub(super) fn u8(mut self, value: u8) -> Self {
        self.bytes.push(value);
        self
    }

    /// Append a little-endian `u16`.
    pub(super) fn u16(mut self, value: u16) -> Self {
        self.bytes.extend_from_slice(&value.to_le_bytes());
        self
    }

    /// Append a little-endian `u32`.
    pub(super) fn u32(mut self, value: u32) -> Self {
        self.bytes.extend_from_slice(&value.to_le_bytes());
        self
    }

    /// Append a little-endian `u64`.
    pub(super) fn u64(mut self, value: u64) -> Self {
        self.bytes.extend_from_slice(&value.to_le_bytes());
        self
    }

    /// Append a little-endian `u128`.
    pub(super) fn u128(mut self, value: u128) -> Self {
        self.bytes.extend_from_slice(&value.to_le_bytes());
        self
    }

    /// Append `count` zero bytes, used to fill a fixed-width enum union.
    pub(super) fn zeros(mut self, count: usize) -> Self {
        self.bytes.resize(self.bytes.len().saturating_add(count), 0);
        self
    }

    /// Append one raw 32-byte digest or nonce.
    pub(super) fn digest(mut self, value: &[u8; 32]) -> Self {
        self.bytes.extend_from_slice(value);
        self
    }

    /// Append one 65-byte uncompressed SEC1 P-256 key.
    pub(super) fn key(self, key: &KagemushaDevicePublicKeyV1) -> Self {
        self.bytes(key.as_sec1_bytes())
    }

    /// Append one 64-byte `r || s` signature.
    pub(super) fn signature(self, signature: &KagemushaDeviceSignatureV1) -> Self {
        self.bytes(signature.as_raw_bytes())
    }

    /// Append raw bytes whose length is fixed by the caller's layout.
    pub(super) fn bytes(mut self, value: &[u8]) -> Self {
        self.bytes.extend_from_slice(value);
        self
    }

    /// Return the completed transcript.
    pub(super) fn finish(self) -> Vec<u8> {
        self.bytes
    }
}
