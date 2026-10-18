//! Figure 9 mDL witness parsing and native preflight validation.
use super::{
    VEGA_MDL_DOCUMENT_TYPE_V1, VEGA_MDL_NAMESPACE_V1, VegaMdlConsensusBindingV1, VegaMdlError,
    VegaMdlPublicInputsV1, VegaSignatureRoleV1, cbor::CborNode,
    derive_device_authentication_digest_v1, validate_date, validate_trusted_presentation_date_v1,
};
use core::fmt;
use iroha_data_model::privacy::{
    PrivacyP256PointV1, PrivacyVegaMdlDateV1, VEGA_MDL_BIRTH_DATE_ISSUER_SIGNED_ITEM_BYTES_V1,
    VEGA_MDL_BIRTH_RANDOM_BYTES_V1, VEGA_MDL_ISSUER_AUTHENTICATION_SIG_STRUCTURE_BYTES_V1,
    VEGA_MDL_MSO_PAYLOAD_BYTES_V1, VegaExistingCredentialStatementV1,
};
use iroha_zkp_halo2::vega::{VegaMdlFigure9WitnessV1, validate_vega_mdl_figure9_encoding_v1};
use p256::{
    EncodedPoint, PublicKey, Scalar,
    ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier},
    elliptic_curve::{PrimeField, sec1::ToEncodedPoint},
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
const COSE_ES256_PROTECTED_HEADER_V1: &[u8] = &[0xa1, 0x01, 0x26];
const DEVICE_KEY_PREFIX_V1: &[u8] = b"\x69deviceKey";
const VALID_UNTIL_PREFIX_V1: &[u8] = b"\x6avalidUntil";
const DEVICE_KEY_FIELD_BYTES_V1: usize = 85;
const VALID_UNTIL_FIELD_BYTES_V1: usize = 33;
const BIRTH_DATE_DIGEST_ENTRY_BYTES_V1: usize = 35;
const MDL_LOOKUP_ENTRY_COUNT_V1: usize =
    DEVICE_KEY_FIELD_BYTES_V1 + VALID_UNTIL_FIELD_BYTES_V1 + BIRTH_DATE_DIGEST_ENTRY_BYTES_V1;
/// Raw private inputs needed by the Figure 9 mDL relation.
///
/// All variable-length byte buffers are zeroized on drop. Lookup addresses and
/// values are intentionally not accepted from callers; validation derives them
/// from the canonical document structure.
pub struct VegaMdlWitnessV1 {
    issuer_authentication_sig_structure: Zeroizing<Vec<u8>>,
    mobile_security_object_payload: Zeroizing<Vec<u8>>,
    birth_date_issuer_signed_item: Zeroizing<Vec<u8>>,
    issuer_signature: Zeroizing<[u8; 64]>,
    device_signature: Zeroizing<[u8; 64]>,
}
impl VegaMdlWitnessV1 {
    /// Construct one exact-shape raw witness.
    ///
    /// `issuer_authentication_sig_structure` is the exact COSE `Sig_structure` signed by the
    /// issuer. It is deliberately distinct from `mobile_security_object_payload`, which is the
    /// exact payload byte string embedded in that structure.
    ///
    /// # Errors
    ///
    /// Returns [`VegaMdlError`] unless every document fragment and raw `r || s`
    /// signature has its one released canonical width.
    pub fn new(
        issuer_authentication_sig_structure: Vec<u8>,
        mobile_security_object_payload: Vec<u8>,
        birth_date_issuer_signed_item: Vec<u8>,
        issuer_signature: &[u8],
        device_signature: &[u8],
    ) -> Result<Self, VegaMdlError> {
        // Take ownership of private document material behind zeroizing guards
        // before the first fallible shape check. Every early return below then
        // scrubs all moved witness buffers, including fields validated later.
        let issuer_authentication_sig_structure =
            Zeroizing::new(issuer_authentication_sig_structure);
        let mobile_security_object_payload = Zeroizing::new(mobile_security_object_payload);
        let birth_date_issuer_signed_item = Zeroizing::new(birth_date_issuer_signed_item);
        validate_exact_input_length(
            "issuer_authentication_sig_structure",
            issuer_authentication_sig_structure.len(),
            VEGA_MDL_ISSUER_AUTHENTICATION_SIG_STRUCTURE_BYTES_V1,
        )?;
        validate_exact_input_length(
            "mobile_security_object_payload",
            mobile_security_object_payload.len(),
            VEGA_MDL_MSO_PAYLOAD_BYTES_V1,
        )?;
        validate_exact_input_length(
            "birth_date_issuer_signed_item",
            birth_date_issuer_signed_item.len(),
            VEGA_MDL_BIRTH_DATE_ISSUER_SIGNED_ITEM_BYTES_V1,
        )?;
        validate_exact_input_length("issuer_signature", issuer_signature.len(), 64)?;
        validate_exact_input_length("device_signature", device_signature.len(), 64)?;
        let mut issuer_signature_bytes = Zeroizing::new([0_u8; 64]);
        issuer_signature_bytes.copy_from_slice(issuer_signature);
        let mut device_signature_bytes = Zeroizing::new([0_u8; 64]);
        device_signature_bytes.copy_from_slice(device_signature);
        Self::from_zeroizing_parts(
            issuer_authentication_sig_structure,
            mobile_security_object_payload,
            birth_date_issuer_signed_item,
            issuer_signature_bytes,
            device_signature_bytes,
        )
    }
    /// Assemble guarded private inputs already represented at fixed signature
    /// width, revalidating all variable-width document fragments.
    pub(super) fn from_zeroizing_parts(
        issuer_authentication_sig_structure: Zeroizing<Vec<u8>>,
        mobile_security_object_payload: Zeroizing<Vec<u8>>,
        birth_date_issuer_signed_item: Zeroizing<Vec<u8>>,
        issuer_signature: Zeroizing<[u8; 64]>,
        device_signature: Zeroizing<[u8; 64]>,
    ) -> Result<Self, VegaMdlError> {
        validate_exact_input_length(
            "issuer_authentication_sig_structure",
            issuer_authentication_sig_structure.len(),
            VEGA_MDL_ISSUER_AUTHENTICATION_SIG_STRUCTURE_BYTES_V1,
        )?;
        validate_exact_input_length(
            "mobile_security_object_payload",
            mobile_security_object_payload.len(),
            VEGA_MDL_MSO_PAYLOAD_BYTES_V1,
        )?;
        validate_exact_input_length(
            "birth_date_issuer_signed_item",
            birth_date_issuer_signed_item.len(),
            VEGA_MDL_BIRTH_DATE_ISSUER_SIGNED_ITEM_BYTES_V1,
        )?;
        Ok(Self {
            issuer_authentication_sig_structure,
            mobile_security_object_payload,
            birth_date_issuer_signed_item,
            issuer_signature,
            device_signature,
        })
    }
}
impl fmt::Debug for VegaMdlWitnessV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VegaMdlWitnessV1")
            .field(
                "issuer_authentication_sig_structure_bytes",
                &self.issuer_authentication_sig_structure.len(),
            )
            .field(
                "mobile_security_object_payload_bytes",
                &self.mobile_security_object_payload.len(),
            )
            .field(
                "birth_date_issuer_signed_item_bytes",
                &self.birth_date_issuer_signed_item.len(),
            )
            .field("private_values", &"[REDACTED]")
            .finish()
    }
}
/// Canonical Figure 9 ECDSA witness `(r, s^-1 mod n)`.
pub struct VegaEcdsaWitnessV1 {
    r: Zeroizing<[u8; 32]>,
    s_inverse: Zeroizing<[u8; 32]>,
}
impl VegaEcdsaWitnessV1 {
    /// Borrow canonical big-endian `r`.
    #[must_use]
    pub fn r(&self) -> &[u8; 32] {
        &self.r
    }
    /// Borrow canonical big-endian `s^-1 mod n`.
    #[must_use]
    pub fn s_inverse(&self) -> &[u8; 32] {
        &self.s_inverse
    }
}
impl fmt::Debug for VegaEcdsaWitnessV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VegaEcdsaWitnessV1([REDACTED])")
    }
}
/// Derived lookup relation over authenticated MSO payload bytes.
#[derive(Default)]
pub struct VegaMdlLookupTableV1 {
    addresses: Vec<u32>,
    values: Zeroizing<Vec<u8>>,
}
impl VegaMdlLookupTableV1 {
    /// Borrow the ordered MSO byte addresses.
    #[must_use]
    pub fn addresses(&self) -> &[u32] {
        &self.addresses
    }
    /// Borrow the bytes at [`Self::addresses`].
    #[must_use]
    pub fn values(&self) -> &[u8] {
        &self.values
    }
}
impl fmt::Debug for VegaMdlLookupTableV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VegaMdlLookupTableV1")
            .field("entries", &self.addresses.len())
            .field("values", &"[REDACTED]")
            .finish()
    }
}
/// Fully parsed, preflighted private witness ready for circuit assignment.
pub struct VegaMdlValidatedWitnessV1 {
    raw: VegaMdlWitnessV1,
    public_inputs: VegaMdlPublicInputsV1,
    lookup: VegaMdlLookupTableV1,
    issuer_authentication_digest: [u8; 32],
    birth_date_digest: [u8; 32],
    device_public_key: PrivacyP256PointV1,
    device_public_key_x: [u8; 32],
    device_public_key_y: [u8; 32],
    birth_date: PrivacyVegaMdlDateV1,
    valid_until: PrivacyVegaMdlDateV1,
    issuer_ecdsa: VegaEcdsaWitnessV1,
    device_ecdsa: VegaEcdsaWitnessV1,
}
impl VegaMdlValidatedWitnessV1 {
    /// Borrow the exact Figure 9 public-input vector.
    #[must_use]
    pub const fn public_inputs(&self) -> &VegaMdlPublicInputsV1 {
        &self.public_inputs
    }
    /// Borrow the deterministically derived lookup table.
    #[must_use]
    pub const fn lookup(&self) -> &VegaMdlLookupTableV1 {
        &self.lookup
    }
    /// Borrow the exact issuer-authenticated COSE `Sig_structure`.
    #[must_use]
    pub fn issuer_authentication_sig_structure(&self) -> &[u8] {
        &self.raw.issuer_authentication_sig_structure
    }
    /// Borrow the exact Tag-24 MSO payload.
    #[must_use]
    pub fn mobile_security_object_payload(&self) -> &[u8] {
        &self.raw.mobile_security_object_payload
    }
    /// Borrow the exact Tag-24 birth-date `IssuerSignedItemBytes`.
    #[must_use]
    pub fn birth_date_issuer_signed_item(&self) -> &[u8] {
        &self.raw.birth_date_issuer_signed_item
    }
    /// Return SHA-256 of the exact issuer COSE `Sig_structure`.
    #[must_use]
    pub const fn issuer_authentication_digest(&self) -> [u8; 32] {
        self.issuer_authentication_digest
    }
    /// Return SHA-256 of the exact birth-date signed item.
    #[must_use]
    pub const fn birth_date_digest(&self) -> [u8; 32] {
        self.birth_date_digest
    }
    /// Return the canonical compressed device P-256 key.
    #[must_use]
    pub const fn device_public_key(&self) -> PrivacyP256PointV1 {
        self.device_public_key
    }
    /// Return the private device-key x-coordinate.
    #[must_use]
    pub const fn device_public_key_x(&self) -> [u8; 32] {
        self.device_public_key_x
    }
    /// Return the private device-key y-coordinate.
    #[must_use]
    pub const fn device_public_key_y(&self) -> [u8; 32] {
        self.device_public_key_y
    }
    /// Return the private Gregorian date of birth.
    #[must_use]
    pub const fn birth_date(&self) -> PrivacyVegaMdlDateV1 {
        self.birth_date
    }
    /// Return the private credential-expiry date.
    #[must_use]
    pub const fn valid_until(&self) -> PrivacyVegaMdlDateV1 {
        self.valid_until
    }
    /// Borrow the canonical issuer `(r, s^-1)` witness.
    #[must_use]
    pub const fn issuer_ecdsa(&self) -> &VegaEcdsaWitnessV1 {
        &self.issuer_ecdsa
    }
    /// Borrow the canonical device `(r, s^-1)` witness.
    #[must_use]
    pub const fn device_ecdsa(&self) -> &VegaEcdsaWitnessV1 {
        &self.device_ecdsa
    }
    /// Borrow the exact private assignment accepted by the native Figure 9 proof circuit.
    ///
    /// # Errors
    ///
    /// Returns [`VegaMdlError`] only if this value's closed-profile invariant
    /// was violated internally.
    pub fn circuit_witness(&self) -> Result<VegaMdlFigure9WitnessV1<'_>, VegaMdlError> {
        VegaMdlFigure9WitnessV1::new(
            self.issuer_authentication_sig_structure(),
            self.birth_date_issuer_signed_item(),
            self.issuer_ecdsa().r(),
            self.issuer_ecdsa().s_inverse(),
            self.device_ecdsa().r(),
            self.device_ecdsa().s_inverse(),
        )
        .map_err(VegaMdlError::from)
    }
}
impl fmt::Debug for VegaMdlValidatedWitnessV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VegaMdlValidatedWitnessV1")
            .field("lookup_entries", &self.lookup.addresses.len())
            .field("private_values", &"[REDACTED]")
            .finish()
    }
}
/// Parse and preflight the complete Figure 9 witness.
///
/// This validates strict deterministic CBOR, exact COSE payload binding, Figure 8
/// unique-prefix/contiguity requirements, the signed birth digest, Gregorian validity and age
/// semantics, and both ES256 signatures. These checks reject malformed witnesses cheaply; the proof
/// circuit independently constrains the same relation.
///
/// # Errors
///
/// Returns [`VegaMdlError`] for any malformed, unbound, expired, under-age, or
/// cryptographically invalid witness.
pub fn validate_mdl_witness(
    statement: &VegaExistingCredentialStatementV1,
    binding: &VegaMdlConsensusBindingV1<'_>,
    trusted_block_timestamp_ms: u64,
    witness: VegaMdlWitnessV1,
) -> Result<VegaMdlValidatedWitnessV1, VegaMdlError> {
    validate_trusted_presentation_date_v1(statement, trusted_block_timestamp_ms)?;
    let expected_device_digest = derive_device_authentication_digest_v1(statement, binding)?;
    if expected_device_digest != statement.device_authentication_digest {
        return Err(VegaMdlError::DeviceAuthenticationDigestMismatch);
    }
    let public_inputs = VegaMdlPublicInputsV1::from_statement(statement)?;
    validate_vega_mdl_figure9_encoding_v1(
        &witness.issuer_authentication_sig_structure,
        &witness.birth_date_issuer_signed_item,
    )?;
    validate_issuer_signature_structure(
        &witness.issuer_authentication_sig_structure,
        &witness.mobile_security_object_payload,
    )?;
    let birth = parse_birth_item(&witness.birth_date_issuer_signed_item)?;
    let parsed_mso = parse_mso_payload(&witness.mobile_security_object_payload, birth.digest_id)?;
    if parsed_mso.birth_date_digest != birth.digest {
        return Err(VegaMdlError::BirthDateDigestMismatch);
    }
    if parsed_mso.signed > parsed_mso.valid_from {
        return Err(VegaMdlError::CredentialSignedAfterValidFrom);
    }
    if parsed_mso.valid_from.date > statement.presentation_date {
        return Err(VegaMdlError::CredentialNotYetValid);
    }
    if parsed_mso.valid_until <= statement.presentation_date {
        return Err(VegaMdlError::CredentialExpired);
    }
    validate_age(
        birth.date,
        statement.presentation_date,
        statement.minimum_age_years,
    )?;
    let issuer_key = VerifyingKey::from_sec1_bytes(statement.issuer_public_key.as_bytes())
        .map_err(|_| VegaMdlError::InvalidP256PublicKey {
            field: "issuer_public_key",
        })?;
    let issuer_authentication_digest: [u8; 32] =
        Sha256::digest(&witness.issuer_authentication_sig_structure).into();
    let issuer_ecdsa = validate_signature(
        &witness.issuer_signature,
        issuer_authentication_digest,
        &issuer_key,
        VegaSignatureRoleV1::Issuer,
    )?;
    let device_key = VerifyingKey::from_sec1_bytes(parsed_mso.device_public_key.as_bytes())
        .map_err(|_| VegaMdlError::InvalidP256PublicKey { field: "deviceKey" })?;
    let device_ecdsa = validate_signature(
        &witness.device_signature,
        *statement.device_authentication_digest.as_bytes(),
        &device_key,
        VegaSignatureRoleV1::Device,
    )?;
    Ok(VegaMdlValidatedWitnessV1 {
        raw: witness,
        public_inputs,
        lookup: parsed_mso.lookup,
        issuer_authentication_digest,
        birth_date_digest: birth.digest,
        device_public_key: parsed_mso.device_public_key,
        device_public_key_x: parsed_mso.device_public_key_x,
        device_public_key_y: parsed_mso.device_public_key_y,
        birth_date: birth.date,
        valid_until: parsed_mso.valid_until,
        issuer_ecdsa,
        device_ecdsa,
    })
}
struct ParsedBirthItem {
    digest_id: u64,
    date: PrivacyVegaMdlDateV1,
    digest: [u8; 32],
}
struct ParsedMso {
    birth_date_digest: [u8; 32],
    device_public_key: PrivacyP256PointV1,
    device_public_key_x: [u8; 32],
    device_public_key_y: [u8; 32],
    signed: ParsedRfc3339UtcSeconds,
    valid_from: ParsedRfc3339UtcSeconds,
    valid_until: PrivacyVegaMdlDateV1,
    lookup: VegaMdlLookupTableV1,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ParsedRfc3339UtcSeconds {
    date: PrivacyVegaMdlDateV1,
    seconds_since_midnight: u32,
}
fn validate_issuer_signature_structure(
    sig_structure: &[u8],
    expected_payload: &[u8],
) -> Result<(), VegaMdlError> {
    let root = CborNode::parse_exact(sig_structure)?;
    let values = root
        .as_array()
        .filter(|values| values.len() == 4)
        .ok_or(VegaMdlError::InvalidIssuerSignatureStructure)?;
    if values[0].as_text() != Some("Signature1") {
        return Err(VegaMdlError::InvalidIssuerSignatureStructure);
    }
    let protected = values[1]
        .as_bytes()
        .ok_or(VegaMdlError::InvalidIssuerSignatureStructure)?;
    if protected != COSE_ES256_PROTECTED_HEADER_V1 {
        return Err(VegaMdlError::InvalidProtectedHeader);
    }
    let protected_map = CborNode::parse_exact(protected)?;
    let entries = protected_map
        .as_map()
        .filter(|entries| entries.len() == 1)
        .ok_or(VegaMdlError::InvalidProtectedHeader)?;
    if !entries[0].0.integer_equals(1) || !entries[0].1.integer_equals(-7) {
        return Err(VegaMdlError::InvalidProtectedHeader);
    }
    if values[2].as_bytes() != Some(&[][..]) {
        return Err(VegaMdlError::InvalidIssuerSignatureStructure);
    }
    let payload = values[3]
        .as_bytes()
        .ok_or(VegaMdlError::InvalidIssuerSignatureStructure)?;
    if payload != expected_payload {
        return Err(VegaMdlError::IssuerPayloadMismatch);
    }
    Ok(())
}
fn parse_birth_item(bytes: &[u8]) -> Result<ParsedBirthItem, VegaMdlError> {
    let wrapper = CborNode::parse_exact(bytes)?;
    let inner_bytes = wrapper.tagged(24).and_then(CborNode::as_bytes).ok_or(
        VegaMdlError::InvalidTag24Wrapper {
            field: "birth_date_issuer_signed_item",
        },
    )?;
    let item = CborNode::parse_exact(inner_bytes)?;
    let entries = item.as_map().filter(|entries| entries.len() == 4).ok_or(
        VegaMdlError::InvalidDocumentFieldShape {
            field: "birth_date_issuer_signed_item",
        },
    )?;
    let _ = entries;
    let digest_id = required_unsigned(&item, "digestID")?;
    let random = required_bytes(&item, "random")?;
    validate_exact_input_length(
        "birth_date_random",
        random.len(),
        VEGA_MDL_BIRTH_RANDOM_BYTES_V1,
    )?;
    if required_text(&item, "elementIdentifier")? != "birth_date" {
        return Err(VegaMdlError::InvalidDocumentFieldValue {
            field: "elementIdentifier",
        });
    }
    let date = parse_full_date(required_text(&item, "elementValue")?, "birth_date")?;
    Ok(ParsedBirthItem {
        digest_id,
        date,
        digest: Sha256::digest(bytes).into(),
    })
}
fn parse_mso_payload(bytes: &[u8], birth_digest_id: u64) -> Result<ParsedMso, VegaMdlError> {
    let wrapper = CborNode::parse_exact(bytes)?;
    let tagged = wrapper
        .tagged(24)
        .ok_or(VegaMdlError::InvalidTag24Wrapper {
            field: "mobile_security_object_payload",
        })?;
    let (inner_bytes, inner_range) =
        tagged
            .as_bytes_with_range()
            .ok_or(VegaMdlError::InvalidTag24Wrapper {
                field: "mobile_security_object_payload",
            })?;
    let mso = CborNode::parse_exact(inner_bytes)?;
    if mso.as_map().is_none() {
        return Err(VegaMdlError::InvalidDocumentFieldShape {
            field: "mobile_security_object",
        });
    }
    if required_text(&mso, "version")? != "1.0" {
        return Err(VegaMdlError::InvalidDocumentFieldValue { field: "version" });
    }
    if required_text(&mso, "digestAlgorithm")? != "SHA-256" {
        return Err(VegaMdlError::InvalidDocumentFieldValue {
            field: "digestAlgorithm",
        });
    }
    if required_text(&mso, "docType")?.as_bytes() != VEGA_MDL_DOCUMENT_TYPE_V1 {
        return Err(VegaMdlError::InvalidDocumentFieldValue { field: "docType" });
    }
    let value_digests = required_map(&mso, "valueDigests")?;
    let namespace = value_digests
        .map_get_text(
            core::str::from_utf8(VEGA_MDL_NAMESPACE_V1).expect("Vega namespace is constant ASCII"),
        )
        .ok_or(VegaMdlError::MissingDocumentField {
            field: "valueDigests/org.iso.18013.5.1",
        })?;
    if namespace.as_map().is_none() {
        return Err(VegaMdlError::InvalidDocumentFieldShape {
            field: "valueDigests/org.iso.18013.5.1",
        });
    }
    let (digest_key, digest_value) = namespace.map_entry_unsigned(birth_digest_id).ok_or(
        VegaMdlError::MissingDocumentField {
            field: "birth_date_digest",
        },
    )?;
    let digest = digest_value
        .as_bytes()
        .filter(|digest| digest.len() == 32)
        .ok_or(VegaMdlError::InvalidDocumentFieldShape {
            field: "birth_date_digest",
        })?;
    let mut birth_date_digest = [0_u8; 32];
    birth_date_digest.copy_from_slice(digest);
    let device_key_info = required_map(&mso, "deviceKeyInfo")?;
    let (device_key_name, device_key) = device_key_info
        .map_entry_text("deviceKey")
        .ok_or(VegaMdlError::MissingDocumentField { field: "deviceKey" })?;
    let device_key_range = device_key_name.range().start..device_key.range().end;
    let device_key_field = inner_bytes
        .get(device_key_range.clone())
        .ok_or(VegaMdlError::InvalidDocumentFieldShape { field: "deviceKey" })?;
    if device_key_field.len() != DEVICE_KEY_FIELD_BYTES_V1
        || !device_key_field.starts_with(DEVICE_KEY_PREFIX_V1)
    {
        return Err(VegaMdlError::InvalidDocumentFieldShape { field: "deviceKey" });
    }
    let (device_public_key, device_public_key_x, device_public_key_y) =
        parse_device_key(device_key)?;
    let validity_info = required_map(&mso, "validityInfo")?;
    let signed = required_tagged_rfc3339_seconds(validity_info, "signed")?;
    let valid_from = required_tagged_rfc3339_seconds(validity_info, "validFrom")?;
    let (valid_until_name, valid_until_value) =
        validity_info
            .map_entry_text("validUntil")
            .ok_or(VegaMdlError::MissingDocumentField {
                field: "validUntil",
            })?;
    let valid_until_range = valid_until_name.range().start..valid_until_value.range().end;
    let valid_until_field = inner_bytes.get(valid_until_range.clone()).ok_or(
        VegaMdlError::InvalidDocumentFieldShape {
            field: "validUntil",
        },
    )?;
    if valid_until_field.len() != VALID_UNTIL_FIELD_BYTES_V1
        || !valid_until_field.starts_with(VALID_UNTIL_PREFIX_V1)
    {
        return Err(VegaMdlError::InvalidDocumentFieldShape {
            field: "validUntil",
        });
    }
    let valid_until_text = valid_until_value
        .tagged(0)
        .and_then(CborNode::as_text)
        .ok_or(VegaMdlError::InvalidDocumentFieldShape {
            field: "validUntil",
        })?;
    let valid_until = parse_rfc3339_utc_seconds(valid_until_text, "validUntil")?.date;
    let digest_entry_range = digest_key.range().start..digest_value.range().end;
    if digest_entry_range.len() != BIRTH_DATE_DIGEST_ENTRY_BYTES_V1 {
        return Err(VegaMdlError::InvalidDocumentFieldShape {
            field: "birth_date_digest",
        });
    }
    let mut lookup = VegaMdlLookupTableV1::default();
    for range in [device_key_range, valid_until_range, digest_entry_range] {
        append_lookup_range(
            &mut lookup,
            bytes,
            (inner_range.start + range.start)..(inner_range.start + range.end),
        )?;
    }
    if lookup.addresses.len() != MDL_LOOKUP_ENTRY_COUNT_V1
        || lookup.values.len() != MDL_LOOKUP_ENTRY_COUNT_V1
    {
        return Err(VegaMdlError::InvalidDocumentFieldShape {
            field: "mobile_security_object_lookup",
        });
    }
    Ok(ParsedMso {
        birth_date_digest,
        device_public_key,
        device_public_key_x,
        device_public_key_y,
        signed,
        valid_from,
        valid_until,
        lookup,
    })
}
fn parse_device_key(
    node: &CborNode<'_>,
) -> Result<(PrivacyP256PointV1, [u8; 32], [u8; 32]), VegaMdlError> {
    let entries = node
        .as_map()
        .filter(|entries| entries.len() == 4)
        .ok_or(VegaMdlError::InvalidDocumentFieldShape { field: "deviceKey" })?;
    let _ = entries;
    if node
        .map_get_integer(1)
        .is_none_or(|value| !value.integer_equals(2))
        || node
            .map_get_integer(-1)
            .is_none_or(|value| !value.integer_equals(1))
    {
        return Err(VegaMdlError::InvalidDocumentFieldValue { field: "deviceKey" });
    }
    let x = node
        .map_get_integer(-2)
        .and_then(CborNode::as_bytes)
        .filter(|coordinate| coordinate.len() == 32)
        .ok_or(VegaMdlError::InvalidDocumentFieldShape { field: "deviceKey" })?;
    let y = node
        .map_get_integer(-3)
        .and_then(CborNode::as_bytes)
        .filter(|coordinate| coordinate.len() == 32)
        .ok_or(VegaMdlError::InvalidDocumentFieldShape { field: "deviceKey" })?;
    let mut x_bytes = [0_u8; 32];
    let mut y_bytes = [0_u8; 32];
    x_bytes.copy_from_slice(x);
    y_bytes.copy_from_slice(y);
    let encoded =
        EncodedPoint::from_affine_coordinates((&x_bytes).into(), (&y_bytes).into(), false);
    let public_key = PublicKey::from_sec1_bytes(encoded.as_bytes())
        .map_err(|_| VegaMdlError::InvalidP256PublicKey { field: "deviceKey" })?;
    let compressed = public_key.to_encoded_point(true);
    let mut compressed_bytes = [0_u8; 33];
    compressed_bytes.copy_from_slice(compressed.as_bytes());
    Ok((PrivacyP256PointV1::new(compressed_bytes), x_bytes, y_bytes))
}
fn validate_signature(
    signature_bytes: &[u8; 64],
    message_digest: [u8; 32],
    verifying_key: &VerifyingKey,
    role: VegaSignatureRoleV1,
) -> Result<VegaEcdsaWitnessV1, VegaMdlError> {
    let signature = Signature::from_slice(signature_bytes)
        .map_err(|_| VegaMdlError::InvalidSignatureEncoding { role })?;
    if signature.normalize_s().is_some() {
        return Err(VegaMdlError::NonCanonicalHighSSignature { role });
    }
    verifying_key
        .verify_prehash(&message_digest, &signature)
        .map_err(|_| VegaMdlError::SignatureVerificationFailed { role })?;
    let (r, s) = signature.split_scalars();
    let inverse = Option::<Scalar>::from(s.as_ref().invert())
        .ok_or(VegaMdlError::InvalidSignatureEncoding { role })?;
    Ok(VegaEcdsaWitnessV1 {
        r: Zeroizing::new(r.to_repr().into()),
        s_inverse: Zeroizing::new(inverse.to_repr().into()),
    })
}
fn required_map<'a>(
    map: &'a CborNode<'a>,
    field: &'static str,
) -> Result<&'a CborNode<'a>, VegaMdlError> {
    let value = map
        .map_get_text(field)
        .ok_or(VegaMdlError::MissingDocumentField { field })?;
    value
        .as_map()
        .map(|_| value)
        .ok_or(VegaMdlError::InvalidDocumentFieldShape { field })
}
fn required_text<'a>(map: &'a CborNode<'a>, field: &'static str) -> Result<&'a str, VegaMdlError> {
    map.map_get_text(field)
        .ok_or(VegaMdlError::MissingDocumentField { field })?
        .as_text()
        .ok_or(VegaMdlError::InvalidDocumentFieldShape { field })
}
fn required_bytes<'a>(
    map: &'a CborNode<'a>,
    field: &'static str,
) -> Result<&'a [u8], VegaMdlError> {
    map.map_get_text(field)
        .ok_or(VegaMdlError::MissingDocumentField { field })?
        .as_bytes()
        .ok_or(VegaMdlError::InvalidDocumentFieldShape { field })
}
fn required_unsigned(map: &CborNode<'_>, field: &'static str) -> Result<u64, VegaMdlError> {
    map.map_get_text(field)
        .ok_or(VegaMdlError::MissingDocumentField { field })?
        .as_unsigned()
        .ok_or(VegaMdlError::InvalidDocumentFieldShape { field })
}
fn required_tagged_rfc3339_seconds(
    map: &CborNode<'_>,
    field: &'static str,
) -> Result<ParsedRfc3339UtcSeconds, VegaMdlError> {
    let text = map
        .map_get_text(field)
        .ok_or(VegaMdlError::MissingDocumentField { field })?
        .tagged(0)
        .and_then(CborNode::as_text)
        .ok_or(VegaMdlError::InvalidDocumentFieldShape { field })?;
    parse_rfc3339_utc_seconds(text, field)
}
fn parse_full_date(text: &str, field: &'static str) -> Result<PrivacyVegaMdlDateV1, VegaMdlError> {
    let bytes = text.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return Err(VegaMdlError::InvalidDate { field });
    }
    let date = PrivacyVegaMdlDateV1 {
        year: parse_decimal_u16(&bytes[0..4], field)?,
        month: parse_decimal_u8(&bytes[5..7], field)?,
        day: parse_decimal_u8(&bytes[8..10], field)?,
    };
    if date.year == 0 {
        return Err(VegaMdlError::InvalidDate { field });
    }
    let _ = validate_date(date, field)?;
    Ok(date)
}
fn parse_rfc3339_utc_seconds(
    text: &str,
    field: &'static str,
) -> Result<ParsedRfc3339UtcSeconds, VegaMdlError> {
    let bytes = text.as_bytes();
    if bytes.len() != 20
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return Err(VegaMdlError::InvalidDate { field });
    }
    let date = parse_full_date(&text[..10], field)?;
    let hour = parse_decimal_u8(&bytes[11..13], field)?;
    let minute = parse_decimal_u8(&bytes[14..16], field)?;
    let second = parse_decimal_u8(&bytes[17..19], field)?;
    if hour > 23 || minute > 59 || second > 59 {
        return Err(VegaMdlError::InvalidDate { field });
    }
    Ok(ParsedRfc3339UtcSeconds {
        date,
        seconds_since_midnight: u32::from(hour) * 3_600
            + u32::from(minute) * 60
            + u32::from(second),
    })
}
fn parse_decimal_u8(bytes: &[u8], field: &'static str) -> Result<u8, VegaMdlError> {
    bytes.iter().try_fold(0_u8, |value, byte| {
        let digit = byte
            .checked_sub(b'0')
            .filter(|digit| *digit <= 9)
            .ok_or(VegaMdlError::InvalidDate { field })?;
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(digit))
            .ok_or(VegaMdlError::InvalidDate { field })
    })
}
fn parse_decimal_u16(bytes: &[u8], field: &'static str) -> Result<u16, VegaMdlError> {
    bytes.iter().try_fold(0_u16, |value, byte| {
        let digit = byte
            .checked_sub(b'0')
            .filter(|digit| *digit <= 9)
            .ok_or(VegaMdlError::InvalidDate { field })?;
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u16::from(digit)))
            .ok_or(VegaMdlError::InvalidDate { field })
    })
}
fn validate_age(
    birth: PrivacyVegaMdlDateV1,
    presentation: PrivacyVegaMdlDateV1,
    threshold: u8,
) -> Result<(), VegaMdlError> {
    let _ = validate_date(birth, "birth_date")?;
    let _ = validate_date(presentation, "presentation_date")?;
    if birth > presentation {
        return Err(VegaMdlError::BirthDateAfterPresentation);
    }
    let mut age = presentation.year - birth.year;
    if (presentation.month, presentation.day) < (birth.month, birth.day) {
        age = age
            .checked_sub(1)
            .ok_or(VegaMdlError::BirthDateAfterPresentation)?;
    }
    if age < u16::from(threshold) {
        return Err(VegaMdlError::AgeThresholdNotMet);
    }
    Ok(())
}
fn append_lookup_range(
    lookup: &mut VegaMdlLookupTableV1,
    source: &[u8],
    range: core::ops::Range<usize>,
) -> Result<(), VegaMdlError> {
    let bytes = source
        .get(range.clone())
        .ok_or(VegaMdlError::InvalidCanonicalCbor)?;
    lookup.addresses.reserve(bytes.len());
    lookup.values.reserve(bytes.len());
    for (address, value) in range.zip(bytes.iter().copied()) {
        lookup
            .addresses
            .push(u32::try_from(address).map_err(|_| VegaMdlError::LookupAddressOverflow)?);
        lookup.values.push(value);
    }
    Ok(())
}
fn validate_exact_input_length(
    field: &'static str,
    actual: usize,
    expected: usize,
) -> Result<(), VegaMdlError> {
    if actual != expected {
        return Err(VegaMdlError::InvalidInputLength {
            field,
            actual,
            expected,
        });
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_engines::vega::{
        VEGA_MDL_PUBLIC_INPUT_COUNT_V1, VEGA_PRIVACY_ACTION_INDEX_V1, VegaBindingFieldV1,
        verify_mdl_figure9_v1,
    };
    use iroha_data_model::privacy::{
        PrivacyChallengeV1, PrivacyCredentialDocumentTypeV1, PrivacyEngineManifestDigestV1,
        PrivacyIssuerIdV1, PrivacyParameterDigestV1, PrivacyParameterIdV1,
        PrivacySessionTranscriptDigestV1, PrivacyStatementContextV1,
        PrivacyStatementSchemaDigestV1, PrivacyTransactionIntentDigestV1,
        PrivacyVegaDeviceAuthenticationDigestV1, PrivacyVegaIssuerRecordDigestV1,
        PrivacyVegaMdlDigestAlgorithmV1, PrivacyVegaMdlNamespaceV1,
        PrivacyVegaMdlSignatureAlgorithmV1, PrivacyVerifierDigestV1,
    };
    use iroha_zkp_halo2::vega::VegaT256ScalarV1;
    use p256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner};
    const TRUSTED_TIMESTAMP_MS: u64 = 1_785_024_000_000;
    struct Fixture {
        statement: VegaExistingCredentialStatementV1,
        witness: VegaMdlWitnessV1,
    }
    fn cbor_head(major: u8, argument: u64) -> Vec<u8> {
        let mut encoded = Vec::new();
        match argument {
            0..=23 => encoded.push((major << 5) | u8::try_from(argument).expect("small argument")),
            24..=0xff => {
                encoded.push((major << 5) | 24);
                encoded.push(u8::try_from(argument).expect("u8 argument"));
            }
            0x100..=0xffff => {
                encoded.push((major << 5) | 25);
                encoded.extend_from_slice(
                    &u16::try_from(argument).expect("u16 argument").to_be_bytes(),
                );
            }
            0x1_0000..=0xffff_ffff => {
                encoded.push((major << 5) | 26);
                encoded.extend_from_slice(
                    &u32::try_from(argument).expect("u32 argument").to_be_bytes(),
                );
            }
            _ => {
                encoded.push((major << 5) | 27);
                encoded.extend_from_slice(&argument.to_be_bytes());
            }
        }
        encoded
    }
    fn cbor_unsigned(value: u64) -> Vec<u8> {
        cbor_head(0, value)
    }
    fn cbor_negative(value: i64) -> Vec<u8> {
        assert!(value < 0);
        cbor_head(
            1,
            u64::try_from(-(i128::from(value)) - 1).expect("negative CBOR argument"),
        )
    }
    fn cbor_bytes(value: &[u8]) -> Vec<u8> {
        let mut encoded = cbor_head(2, u64::try_from(value.len()).expect("test length fits u64"));
        encoded.extend_from_slice(value);
        encoded
    }
    fn cbor_text(value: &str) -> Vec<u8> {
        let mut encoded = cbor_head(3, u64::try_from(value.len()).expect("test length fits u64"));
        encoded.extend_from_slice(value.as_bytes());
        encoded
    }
    fn cbor_array(values: Vec<Vec<u8>>) -> Vec<u8> {
        let mut encoded = cbor_head(
            4,
            u64::try_from(values.len()).expect("test length fits u64"),
        );
        for value in values {
            encoded.extend_from_slice(&value);
        }
        encoded
    }
    fn cbor_map(mut entries: Vec<(Vec<u8>, Vec<u8>)>) -> Vec<u8> {
        entries.sort_by(|left, right| {
            left.0
                .len()
                .cmp(&right.0.len())
                .then_with(|| left.0.cmp(&right.0))
        });
        let mut encoded = cbor_head(
            5,
            u64::try_from(entries.len()).expect("test length fits u64"),
        );
        for (key, value) in entries {
            encoded.extend_from_slice(&key);
            encoded.extend_from_slice(&value);
        }
        encoded
    }
    fn cbor_tag(tag: u64, value: Vec<u8>) -> Vec<u8> {
        let mut encoded = cbor_head(6, tag);
        encoded.extend_from_slice(&value);
        encoded
    }
    fn signing_key(seed: u8) -> SigningKey {
        let bytes = [seed; 32];
        SigningKey::from_bytes((&bytes).into()).expect("fixed non-zero test signing key")
    }
    fn compressed_key(signing_key: &SigningKey) -> PrivacyP256PointV1 {
        let encoded = signing_key.verifying_key().to_encoded_point(true);
        let mut bytes = [0_u8; 33];
        bytes.copy_from_slice(encoded.as_bytes());
        PrivacyP256PointV1::new(bytes)
    }
    fn context() -> PrivacyStatementContextV1 {
        PrivacyStatementContextV1 {
            network_id: super::super::network_id_from_genesis_hash_bytes([0xA7; 32]),
            action_index: VEGA_PRIVACY_ACTION_INDEX_V1,
            transaction_intent_digest: PrivacyTransactionIntentDigestV1::new([0x26; 32]),
            parameter_id: PrivacyParameterIdV1::new([0x21; 32]),
            parameter_digest: PrivacyParameterDigestV1::new([0x22; 32]),
            verifier_digest: PrivacyVerifierDigestV1::new([0x23; 32]),
            statement_schema_digest: PrivacyStatementSchemaDigestV1::new([0x24; 32]),
            engine_manifest_digest: PrivacyEngineManifestDigestV1::new([0x25; 32]),
        }
    }
    fn binding(statement: &VegaExistingCredentialStatementV1) -> VegaMdlConsensusBindingV1<'_> {
        VegaMdlConsensusBindingV1::from_context(&statement.context, [0xa7; 32])
    }
    fn fixture_with_dates(
        birth_date: &str,
        signed: &str,
        valid_from: &str,
        valid_until: &str,
        presentation_date: PrivacyVegaMdlDateV1,
        minimum_age_years: u8,
    ) -> Fixture {
        let issuer_signing_key = signing_key(1);
        let device_signing_key = signing_key(2);
        let device_uncompressed = device_signing_key.verifying_key().to_encoded_point(false);
        let device_x = device_uncompressed.x().expect("uncompressed x");
        let device_y = device_uncompressed.y().expect("uncompressed y");
        let birth_inner = cbor_map(vec![
            (cbor_text("digestID"), cbor_unsigned(1)),
            (cbor_text("random"), cbor_bytes(&[0x42; 16])),
            (cbor_text("elementIdentifier"), cbor_text("birth_date")),
            (cbor_text("elementValue"), cbor_text(birth_date)),
        ]);
        let birth_item = cbor_tag(24, cbor_bytes(&birth_inner));
        let birth_digest: [u8; 32] = Sha256::digest(&birth_item).into();
        let device_key = cbor_map(vec![
            (cbor_unsigned(1), cbor_unsigned(2)),
            (cbor_negative(-1), cbor_unsigned(1)),
            (cbor_negative(-2), cbor_bytes(device_x)),
            (cbor_negative(-3), cbor_bytes(device_y)),
        ]);
        assert_eq!(
            [cbor_text("deviceKey"), device_key.clone()].concat().len(),
            DEVICE_KEY_FIELD_BYTES_V1
        );
        let validity_info = cbor_map(vec![
            (cbor_text("signed"), cbor_tag(0, cbor_text(signed))),
            (cbor_text("validFrom"), cbor_tag(0, cbor_text(valid_from))),
            (cbor_text("validUntil"), cbor_tag(0, cbor_text(valid_until))),
        ]);
        let value_digests = cbor_map(vec![(
            cbor_text("org.iso.18013.5.1"),
            cbor_map(vec![(cbor_unsigned(1), cbor_bytes(&birth_digest))]),
        )]);
        let mso_entries = vec![
            (cbor_text("version"), cbor_text("1.0")),
            (cbor_text("digestAlgorithm"), cbor_text("SHA-256")),
            (cbor_text("valueDigests"), value_digests),
            (
                cbor_text("deviceKeyInfo"),
                cbor_map(vec![(cbor_text("deviceKey"), device_key)]),
            ),
            (cbor_text("docType"), cbor_text("org.iso.18013.5.1.mDL")),
            (cbor_text("validityInfo"), validity_info),
        ];
        let mso_inner = cbor_map(mso_entries);
        let mso_payload = cbor_tag(24, cbor_bytes(&mso_inner));
        let sig_structure = cbor_array(vec![
            cbor_text("Signature1"),
            cbor_bytes(COSE_ES256_PROTECTED_HEADER_V1),
            cbor_bytes(&[]),
            cbor_bytes(&mso_payload),
        ]);
        assert_eq!(
            sig_structure.len(),
            VEGA_MDL_ISSUER_AUTHENTICATION_SIG_STRUCTURE_BYTES_V1
        );
        assert_eq!(mso_payload.len(), VEGA_MDL_MSO_PAYLOAD_BYTES_V1);
        assert_eq!(
            birth_item.len(),
            VEGA_MDL_BIRTH_DATE_ISSUER_SIGNED_ITEM_BYTES_V1
        );
        let mut statement = VegaExistingCredentialStatementV1 {
            context: context(),
            issuer_id: PrivacyIssuerIdV1::new([0x40; 32]),
            issuer_record_epoch: 1,
            issuer_record_digest: PrivacyVegaIssuerRecordDigestV1::new([0x41; 32]),
            document_type: PrivacyCredentialDocumentTypeV1::Iso18013_5Mdl,
            namespace: PrivacyVegaMdlNamespaceV1::OrgIso18013_5_1,
            digest_algorithm: PrivacyVegaMdlDigestAlgorithmV1::Sha256,
            issuer_authentication_algorithm: PrivacyVegaMdlSignatureAlgorithmV1::CoseSign1Es256,
            device_authentication_algorithm: PrivacyVegaMdlSignatureAlgorithmV1::CoseSign1Es256,
            issuer_public_key: compressed_key(&issuer_signing_key),
            device_authentication_digest: PrivacyVegaDeviceAuthenticationDigestV1::new([0x11; 32]),
            presentation_date,
            minimum_age_years,
            reader_challenge: PrivacyChallengeV1::new([0x31; 32]),
            session_transcript_digest: PrivacySessionTranscriptDigestV1::new([0x32; 32]),
        };
        statement.device_authentication_digest =
            derive_device_authentication_digest_v1(&statement, &binding(&statement))
                .expect("valid Hdev binding");
        let issuer_digest: [u8; 32] = Sha256::digest(&sig_structure).into();
        let issuer_signature: Signature = issuer_signing_key
            .sign_prehash(&issuer_digest)
            .expect("issuer signature");
        let issuer_signature = issuer_signature.normalize_s().unwrap_or(issuer_signature);
        let device_signature: Signature = device_signing_key
            .sign_prehash(statement.device_authentication_digest.as_bytes())
            .expect("device signature");
        let device_signature = device_signature.normalize_s().unwrap_or(device_signature);
        let witness = VegaMdlWitnessV1::new(
            sig_structure,
            mso_payload,
            birth_item,
            &issuer_signature.to_bytes(),
            &device_signature.to_bytes(),
        )
        .expect("bounded witness");
        Fixture { statement, witness }
    }
    fn fixture(birth_date: &str, valid_until: &str) -> Fixture {
        fixture_with_dates(
            birth_date,
            "2025-01-01T00:00:00Z",
            "2025-01-01T00:00:00Z",
            valid_until,
            PrivacyVegaMdlDateV1 {
                year: 2026,
                month: 7,
                day: 26,
            },
            18,
        )
    }
    fn valid_fixture() -> Fixture {
        fixture("1980-06-15", "2035-08-17T12:34:56Z")
    }
    #[test]
    fn canonical_figure9_witness_validates_end_to_end() {
        let Fixture { statement, witness } = valid_fixture();
        let validated = validate_mdl_witness(
            &statement,
            &binding(&statement),
            TRUSTED_TIMESTAMP_MS,
            witness,
        )
        .expect("valid Figure 9 witness");
        assert_eq!(
            validated.birth_date(),
            PrivacyVegaMdlDateV1 {
                year: 1980,
                month: 6,
                day: 15
            }
        );
        assert_eq!(
            validated.valid_until(),
            PrivacyVegaMdlDateV1 {
                year: 2035,
                month: 8,
                day: 17
            }
        );
        assert_eq!(
            validated.lookup().addresses().len(),
            MDL_LOOKUP_ENTRY_COUNT_V1
        );
        assert_eq!(
            validated.lookup().addresses().len(),
            validated.lookup().values().len()
        );
        for (&address, &value) in validated
            .lookup()
            .addresses()
            .iter()
            .zip(validated.lookup().values())
        {
            assert_eq!(
                validated.mobile_security_object_payload()[address as usize],
                value
            );
        }
        let inputs = validated.public_inputs().as_array();
        assert_eq!(inputs.len(), VEGA_MDL_PUBLIC_INPUT_COUNT_V1);
        assert_eq!(
            inputs[2].to_be_bytes()[28..],
            statement.device_authentication_digest.as_bytes()[..4]
        );
        assert_eq!(
            inputs[10],
            VegaT256ScalarV1::from_u64(u64::from(statement.presentation_date.year))
        );
        assert_eq!(
            inputs[13],
            VegaT256ScalarV1::from_u64(u64::from(statement.minimum_age_years))
        );
        assert_ne!(validated.issuer_ecdsa().s_inverse(), &[0; 32]);
        assert_ne!(validated.device_ecdsa().s_inverse(), &[0; 32]);
    }
    #[test]
    fn achievable_date_and_age_maxima_validate_with_a_later_four_digit_expiry() {
        const MAXIMUM_PRESENTATION_TIMESTAMP_MS: u64 = 253_370_678_400_000;
        let Fixture { statement, witness } = fixture_with_dates(
            "9848-12-31",
            "9998-01-01T00:00:00Z",
            "9998-01-01T00:00:00Z",
            "9999-12-31T00:00:00Z",
            PrivacyVegaMdlDateV1 {
                year: 9_998,
                month: 12,
                day: 31,
            },
            150,
        );
        let validated = validate_mdl_witness(
            &statement,
            &binding(&statement),
            MAXIMUM_PRESENTATION_TIMESTAMP_MS,
            witness,
        )
        .expect("maximum satisfiable Vega witness");
        assert_eq!(validated.birth_date().year, 9_848);
        assert_eq!(validated.valid_until().year, 9_999);
        assert_eq!(
            validated.public_inputs().as_array()[13],
            VegaT256ScalarV1::from_u64(150)
        );
    }
    #[test]
    fn hdev_frame_has_a_pinned_kat_and_binds_every_consensus_class() {
        let Fixture { statement, .. } = valid_fixture();
        let baseline = derive_device_authentication_digest_v1(&statement, &binding(&statement))
            .expect("baseline digest");
        assert_eq!(
            hex::encode(baseline.as_bytes()),
            "ff11698510952036300c5969711c688a5fd41a4e54e6fd9abb89fbf0e846e40c"
        );
        let mut challenge = statement.clone();
        challenge.reader_challenge = PrivacyChallengeV1::new([0x41; 32]);
        assert_ne!(
            derive_device_authentication_digest_v1(&challenge, &binding(&challenge))
                .expect("challenge digest"),
            baseline
        );
        let mut session = statement.clone();
        session.session_transcript_digest = PrivacySessionTranscriptDigestV1::new([0x42; 32]);
        assert_ne!(
            derive_device_authentication_digest_v1(&session, &binding(&session))
                .expect("session digest"),
            baseline
        );
        let mut threshold = statement.clone();
        threshold.minimum_age_years = 21;
        assert_ne!(
            derive_device_authentication_digest_v1(&threshold, &binding(&threshold))
                .expect("threshold digest"),
            baseline
        );
        let mut noncanonical_action = statement.clone();
        noncanonical_action.context.action_index += 1;
        assert_eq!(
            derive_device_authentication_digest_v1(
                &noncanonical_action,
                &binding(&noncanonical_action)
            )
            .expect_err("first-release Vega admits only action index zero"),
            VegaMdlError::BindingMismatch {
                field: VegaBindingFieldV1::ActionIndex,
            }
        );
        let mut intent = statement.clone();
        intent.context.transaction_intent_digest =
            PrivacyTransactionIntentDigestV1::new([0x51; 32]);
        assert_ne!(
            derive_device_authentication_digest_v1(&intent, &binding(&intent))
                .expect("transaction-intent digest"),
            baseline
        );
        let mut issuer = statement.clone();
        issuer.issuer_id = PrivacyIssuerIdV1::new([0x53; 32]);
        assert_ne!(
            derive_device_authentication_digest_v1(&issuer, &binding(&issuer))
                .expect("issuer-id digest"),
            baseline
        );
        let mut issuer_epoch = statement.clone();
        issuer_epoch.issuer_record_epoch += 1;
        assert_ne!(
            derive_device_authentication_digest_v1(&issuer_epoch, &binding(&issuer_epoch))
                .expect("issuer-record epoch digest"),
            baseline
        );
        let mut issuer_revision = statement.clone();
        issuer_revision.issuer_record_digest = PrivacyVegaIssuerRecordDigestV1::new([0x54; 32]);
        assert_ne!(
            derive_device_authentication_digest_v1(&issuer_revision, &binding(&issuer_revision),)
                .expect("issuer-record digest"),
            baseline
        );
        let mut parameters = statement.clone();
        parameters.context.parameter_digest = PrivacyParameterDigestV1::new([0x52; 32]);
        assert_ne!(
            derive_device_authentication_digest_v1(&parameters, &binding(&parameters))
                .expect("parameter digest"),
            baseline
        );
        assert_eq!(
            verify_mdl_figure9_v1(&intent, &binding(&intent), TRUSTED_TIMESTAMP_MS, &[0x51],)
                .expect_err("a Vega proof cannot replay under another transaction intent"),
            VegaMdlError::DeviceAuthenticationDigestMismatch
        );
        let mut zero_intent = statement.clone();
        zero_intent.context.transaction_intent_digest =
            PrivacyTransactionIntentDigestV1::new([0; 32]);
        assert_eq!(
            derive_device_authentication_digest_v1(&zero_intent, &binding(&zero_intent))
                .expect_err("zero transaction intent"),
            VegaMdlError::ZeroConsensusDigest {
                field: "transaction_intent_digest",
            }
        );
        let mut zero_epoch = statement.clone();
        zero_epoch.issuer_record_epoch = 0;
        assert_eq!(
            derive_device_authentication_digest_v1(&zero_epoch, &binding(&zero_epoch))
                .expect_err("zero issuer epoch"),
            VegaMdlError::ZeroIssuerRecordEpoch
        );
        let mut alternate_genesis = binding(&statement);
        alternate_genesis.genesis_hash[0] ^= 1;
        assert_eq!(
            derive_device_authentication_digest_v1(&statement, &alternate_genesis)
                .expect_err("genesis must identify the statement network"),
            VegaMdlError::NetworkGenesisMismatch
        );
        let mut alternate_network = statement.clone();
        alternate_network.context.network_id =
            super::super::network_id_from_genesis_hash_bytes(alternate_genesis.genesis_hash);
        assert_ne!(
            derive_device_authentication_digest_v1(
                &alternate_network,
                &VegaMdlConsensusBindingV1::from_context(
                    &alternate_network.context,
                    alternate_genesis.genesis_hash,
                ),
            )
            .expect("another valid network produces its own genesis-bound digest"),
            baseline
        );
    }
    #[test]
    fn cheap_prechecks_reject_binding_signature_digest_age_and_expiry_attacks() {
        let Fixture {
            statement,
            mut witness,
        } = valid_fixture();
        witness.issuer_signature[0] ^= 1;
        assert!(matches!(
            validate_mdl_witness(
                &statement,
                &binding(&statement),
                TRUSTED_TIMESTAMP_MS,
                witness
            ),
            Err(VegaMdlError::SignatureVerificationFailed {
                role: VegaSignatureRoleV1::Issuer
            } | VegaMdlError::InvalidSignatureEncoding {
                role: VegaSignatureRoleV1::Issuer
            })
        ));
        for role in [VegaSignatureRoleV1::Issuer, VegaSignatureRoleV1::Device] {
            let Fixture {
                statement,
                mut witness,
            } = valid_fixture();
            let signature_bytes = match role {
                VegaSignatureRoleV1::Issuer => &mut witness.issuer_signature,
                VegaSignatureRoleV1::Device => &mut witness.device_signature,
            };
            let low_s =
                Signature::from_slice(&signature_bytes[..]).expect("canonical fixture signature");
            assert!(
                low_s.normalize_s().is_none(),
                "fixture must use the sole canonical low-s representative"
            );
            let (r, s) = low_s.split_scalars();
            let high_s = Signature::from_scalars(r.to_repr(), (-*s).to_repr())
                .expect("high-s counterpart remains a valid scalar pair");
            assert!(high_s.normalize_s().is_some());
            **signature_bytes = high_s.to_bytes().into();
            assert_eq!(
                validate_mdl_witness(
                    &statement,
                    &binding(&statement),
                    TRUSTED_TIMESTAMP_MS,
                    witness,
                )
                .expect_err("malleable high-s representative"),
                VegaMdlError::NonCanonicalHighSSignature { role }
            );
        }
        let Fixture {
            statement,
            mut witness,
        } = valid_fixture();
        let random_byte = witness
            .birth_date_issuer_signed_item
            .iter()
            .position(|byte| *byte == 0x42)
            .expect("fixture random byte");
        witness.birth_date_issuer_signed_item[random_byte] ^= 1;
        assert_eq!(
            validate_mdl_witness(
                &statement,
                &binding(&statement),
                TRUSTED_TIMESTAMP_MS,
                witness
            )
            .expect_err("birth digest attack"),
            VegaMdlError::BirthDateDigestMismatch
        );
        let Fixture { statement, witness } = fixture("2010-06-15", "2035-08-17T12:34:56Z");
        assert_eq!(
            validate_mdl_witness(
                &statement,
                &binding(&statement),
                TRUSTED_TIMESTAMP_MS,
                witness
            )
            .expect_err("under-age attack"),
            VegaMdlError::AgeThresholdNotMet
        );
        let Fixture { statement, witness } = fixture("1980-06-15", "2026-07-26T23:59:59Z");
        assert_eq!(
            validate_mdl_witness(
                &statement,
                &binding(&statement),
                TRUSTED_TIMESTAMP_MS,
                witness
            )
            .expect_err("same-day expiry"),
            VegaMdlError::CredentialExpired
        );
        let Fixture { statement, witness } = valid_fixture();
        assert_eq!(
            validate_mdl_witness(
                &statement,
                &binding(&statement),
                TRUSTED_TIMESTAMP_MS + 86_400_000,
                witness
            )
            .expect_err("untrusted public date"),
            VegaMdlError::TrustedPresentationDateMismatch
        );
    }
    #[test]
    fn validity_preflight_rejects_malformed_signed_and_valid_from_dates() {
        for (field, signed, valid_from) in [
            ("signed", "2025-01-01t00:00:00Z", "2025-01-01T00:00:00Z"),
            ("validFrom", "2025-01-01T00:00:00Z", "2025-01-01T00:00:60Z"),
        ] {
            let Fixture { statement, witness } = fixture_with_dates(
                "1980-06-15",
                signed,
                valid_from,
                "2035-08-17T12:34:56Z",
                PrivacyVegaMdlDateV1 {
                    year: 2026,
                    month: 7,
                    day: 26,
                },
                18,
            );
            assert_eq!(
                validate_mdl_witness(
                    &statement,
                    &binding(&statement),
                    TRUSTED_TIMESTAMP_MS,
                    witness,
                )
                .expect_err("malformed validity timestamp"),
                VegaMdlError::InvalidDate { field }
            );
        }
    }
    #[test]
    fn validity_preflight_enforces_the_circuit_date_ordering() {
        let Fixture { statement, witness } = fixture_with_dates(
            "1980-06-15",
            "2026-08-01T03:04:05Z",
            "2026-07-01T04:05:06Z",
            "2035-08-17T12:34:56Z",
            PrivacyVegaMdlDateV1 {
                year: 2026,
                month: 7,
                day: 26,
            },
            18,
        );
        assert_eq!(
            validate_mdl_witness(
                &statement,
                &binding(&statement),
                TRUSTED_TIMESTAMP_MS,
                witness,
            )
            .expect_err("signed after validFrom"),
            VegaMdlError::CredentialSignedAfterValidFrom
        );
        let Fixture { statement, witness } = fixture_with_dates(
            "1980-06-15",
            "2025-01-01T03:04:05Z",
            "2026-07-27T04:05:06Z",
            "2035-08-17T12:34:56Z",
            PrivacyVegaMdlDateV1 {
                year: 2026,
                month: 7,
                day: 26,
            },
            18,
        );
        assert_eq!(
            validate_mdl_witness(
                &statement,
                &binding(&statement),
                TRUSTED_TIMESTAMP_MS,
                witness,
            )
            .expect_err("presentation before validFrom"),
            VegaMdlError::CredentialNotYetValid
        );
        let Fixture { statement, witness } = fixture_with_dates(
            "1980-06-15",
            "2026-07-26T23:59:59Z",
            "2026-07-26T00:00:00Z",
            "2026-07-27T00:00:00Z",
            PrivacyVegaMdlDateV1 {
                year: 2026,
                month: 7,
                day: 26,
            },
            18,
        );
        assert_eq!(
            validate_mdl_witness(
                &statement,
                &binding(&statement),
                TRUSTED_TIMESTAMP_MS,
                witness,
            )
            .expect_err("signed timestamp follows validFrom within one date"),
            VegaMdlError::CredentialSignedAfterValidFrom
        );
        for (signed, valid_from) in [
            ("2026-07-26T00:00:00Z", "2026-07-26T00:00:00Z"),
            ("2026-07-26T00:00:00Z", "2026-07-26T23:59:59Z"),
        ] {
            let Fixture { statement, witness } = fixture_with_dates(
                "1980-06-15",
                signed,
                valid_from,
                "2026-07-27T00:00:00Z",
                PrivacyVegaMdlDateV1 {
                    year: 2026,
                    month: 7,
                    day: 26,
                },
                18,
            );
            validate_mdl_witness(
                &statement,
                &binding(&statement),
                TRUSTED_TIMESTAMP_MS,
                witness,
            )
            .expect("equal and forward-ordered private timestamps are valid");
        }
    }
    #[test]
    fn strict_structure_rejects_payload_swap_fixed_key_mutation_and_noncanonical_cbor() {
        let Fixture {
            statement,
            mut witness,
        } = valid_fixture();
        *witness
            .mobile_security_object_payload
            .last_mut()
            .expect("non-empty payload") ^= 1;
        assert_eq!(
            validate_mdl_witness(
                &statement,
                &binding(&statement),
                TRUSTED_TIMESTAMP_MS,
                witness
            )
            .expect_err("payload swap"),
            VegaMdlError::IssuerPayloadMismatch
        );
        let Fixture {
            statement,
            mut witness,
        } = valid_fixture();
        let payload_offset = witness
            .issuer_authentication_sig_structure
            .windows(witness.mobile_security_object_payload.len())
            .position(|candidate| candidate == witness.mobile_security_object_payload.as_slice())
            .expect("embedded MSO payload");
        let key_offset = witness
            .mobile_security_object_payload
            .windows(DEVICE_KEY_PREFIX_V1.len())
            .position(|candidate| candidate == DEVICE_KEY_PREFIX_V1)
            .expect("deviceKey field");
        witness.mobile_security_object_payload[key_offset] ^= 1;
        witness.issuer_authentication_sig_structure[payload_offset + key_offset] ^= 1;
        assert_eq!(
            validate_mdl_witness(
                &statement,
                &binding(&statement),
                TRUSTED_TIMESTAMP_MS,
                witness
            )
            .expect_err("fixed deviceKey mutation"),
            VegaMdlError::InvalidClosedProfileEncoding
        );
        let Fixture {
            statement,
            mut witness,
        } = valid_fixture();
        let array_length = witness.issuer_authentication_sig_structure[0];
        assert_eq!(array_length, 0x84);
        witness.issuer_authentication_sig_structure[0] = 0x98;
        witness.issuer_authentication_sig_structure.insert(1, 0x04);
        assert_eq!(
            validate_mdl_witness(
                &statement,
                &binding(&statement),
                TRUSTED_TIMESTAMP_MS,
                witness
            )
            .expect_err("non-minimal array length"),
            VegaMdlError::InvalidClosedProfileEncoding
        );
    }
    #[test]
    fn every_issuer_structure_truncation_is_rejected_without_panic() {
        let Fixture { witness, .. } = valid_fixture();
        for length in 0..witness.issuer_authentication_sig_structure.len() {
            let truncated = &witness.issuer_authentication_sig_structure[..length];
            let result = std::panic::catch_unwind(|| {
                validate_issuer_signature_structure(
                    truncated,
                    &witness.mobile_security_object_payload,
                )
            });
            assert!(result.is_ok(), "panic at truncation {length}");
            assert!(
                result.expect("no panic").is_err(),
                "accepted truncation {length}"
            );
        }
    }
    #[test]
    fn fixed_date_parser_rejects_invalid_calendar_and_time_forms() {
        assert_eq!(
            parse_full_date("2024-02-29", "date"),
            Ok(PrivacyVegaMdlDateV1 {
                year: 2024,
                month: 2,
                day: 29
            })
        );
        for malformed in [
            "2023-02-29",
            "2024-2-29",
            "0000-01-01",
            "2024-13-01",
            "2024-01-32",
        ] {
            assert!(parse_full_date(malformed, "date").is_err(), "{malformed}");
        }
        for malformed in [
            "2030-01-02t03:04:05Z",
            "2030-01-02T24:04:05Z",
            "2030-01-02T03:60:05Z",
            "2030-01-02T03:04:60Z",
            "2030-01-02T03:04:05+00:00",
        ] {
            assert!(
                parse_rfc3339_utc_seconds(malformed, "datetime").is_err(),
                "{malformed}"
            );
        }
    }
    #[test]
    fn completed_gregorian_age_observes_birthday_boundary() {
        let birth = PrivacyVegaMdlDateV1 {
            year: 2008,
            month: 7,
            day: 27,
        };
        assert_eq!(
            validate_age(
                birth,
                PrivacyVegaMdlDateV1 {
                    year: 2026,
                    month: 7,
                    day: 26
                },
                18
            ),
            Err(VegaMdlError::AgeThresholdNotMet)
        );
        validate_age(
            birth,
            PrivacyVegaMdlDateV1 {
                year: 2026,
                month: 7,
                day: 27,
            },
            18,
        )
        .expect("birthday completes the threshold age");
    }
    #[test]
    fn witness_constructor_enforces_every_exact_bound() {
        let exact = || {
            (
                vec![1; VEGA_MDL_ISSUER_AUTHENTICATION_SIG_STRUCTURE_BYTES_V1],
                vec![1; VEGA_MDL_MSO_PAYLOAD_BYTES_V1],
                vec![1; VEGA_MDL_BIRTH_DATE_ISSUER_SIGNED_ITEM_BYTES_V1],
            )
        };
        let (issuer, mso, birth) = exact();
        assert!(VegaMdlWitnessV1::new(issuer, mso, birth, &[1; 64], &[2; 64]).is_ok());
        for issuer_len in [
            VEGA_MDL_ISSUER_AUTHENTICATION_SIG_STRUCTURE_BYTES_V1 - 1,
            VEGA_MDL_ISSUER_AUTHENTICATION_SIG_STRUCTURE_BYTES_V1 + 1,
        ] {
            let (_, mso, birth) = exact();
            assert!(
                VegaMdlWitnessV1::new(vec![1; issuer_len], mso, birth, &[1; 64], &[2; 64]).is_err()
            );
        }
        for mso_len in [
            VEGA_MDL_MSO_PAYLOAD_BYTES_V1 - 1,
            VEGA_MDL_MSO_PAYLOAD_BYTES_V1 + 1,
        ] {
            let (issuer, _, birth) = exact();
            assert!(
                VegaMdlWitnessV1::new(issuer, vec![1; mso_len], birth, &[1; 64], &[2; 64]).is_err()
            );
        }
        for birth_len in [
            VEGA_MDL_BIRTH_DATE_ISSUER_SIGNED_ITEM_BYTES_V1 - 1,
            VEGA_MDL_BIRTH_DATE_ISSUER_SIGNED_ITEM_BYTES_V1 + 1,
        ] {
            let (issuer, mso, _) = exact();
            assert!(
                VegaMdlWitnessV1::new(issuer, mso, vec![1; birth_len], &[1; 64], &[2; 64]).is_err()
            );
        }
        let (issuer, mso, birth) = exact();
        assert!(VegaMdlWitnessV1::new(issuer, mso, birth, &[1; 63], &[2; 64]).is_err());
        let (issuer, mso, birth) = exact();
        assert!(VegaMdlWitnessV1::new(issuer, mso, birth, &[1; 64], &[2; 65]).is_err());
    }
    #[test]
    fn birth_randomizer_rejects_both_adjacent_noncanonical_widths() {
        for random_len in [
            VEGA_MDL_BIRTH_RANDOM_BYTES_V1 - 1,
            VEGA_MDL_BIRTH_RANDOM_BYTES_V1 + 1,
        ] {
            let inner = cbor_map(vec![
                (cbor_text("digestID"), cbor_unsigned(1)),
                (cbor_text("random"), cbor_bytes(&vec![0x42; random_len])),
                (cbor_text("elementIdentifier"), cbor_text("birth_date")),
                (cbor_text("elementValue"), cbor_text("1980-06-15")),
            ]);
            let item = cbor_tag(24, cbor_bytes(&inner));
            assert!(matches!(
                parse_birth_item(&item),
                Err(VegaMdlError::InvalidInputLength {
                    field: "birth_date_random",
                    actual,
                    expected: VEGA_MDL_BIRTH_RANDOM_BYTES_V1,
                }) if actual == random_len
            ));
        }
    }
    #[test]
    fn arbitrary_short_cbor_inputs_never_panic() {
        for length in 0..=96 {
            for fill in [0_u8, 0x18, 0x5f, 0x7f, 0x9f, 0xbf, 0xff] {
                let bytes = vec![fill; length];
                let outcome = std::panic::catch_unwind(|| CborNode::parse_exact(&bytes).map(drop));
                assert!(outcome.is_ok(), "length={length}, fill={fill:#x}");
            }
        }
    }
    #[test]
    fn public_scalar_type_remains_non_reducing_at_application_boundary() {
        assert!(VegaT256ScalarV1::from_be_bytes_exact([0xff; 32]).is_err());
    }
}
