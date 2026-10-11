//! Confidential parameter registries and lifecycle helpers.
//!
//! The confidential asset roadmap introduces on-ledger registries that track zero-knowledge
//! verifier metadata together with Pedersen and Poseidon parameter sets. These structures model the
//! governance state transitions (publish → activate → deprecate → withdraw) and advertise the
//! hashes that wallets and validators must verify before accepting an upgrade.

use crate::{
    DeriveFastJson as DeriveFast, DeriveJsonDeserialize as DeriveJsonDe,
    DeriveJsonSerialize as DeriveJsonSer, json_helpers::fixed_bytes,
};
use core::{
    fmt::{self, Display, Formatter},
    ops::{Index, IndexMut},
};
use iroha_schema::IntoSchema;
use norito::{
    codec::{Decode, Encode},
    core::{self as norito_core, DecodeFromSlice, Error as NoritoError},
};

/// Permanent point-query spentness checkpoints for confidential assets.
pub mod spentness;
/// Exact magic prefix for the first-release confidential memo wire.
pub const CONFIDENTIAL_MEMO_WIRE_MAGIC_V1: [u8; 8] = *b"IRHCM1\xA5\x5A";
/// Exact number of padded recipient slots carried by every confidential memo.
pub const CONFIDENTIAL_MEMO_RECIPIENT_SLOTS_V1: usize = 8;
/// Exact ML-KEM-768 encapsulation length.
pub const CONFIDENTIAL_MEMO_ML_KEM_768_CIPHERTEXT_BYTES_V1: usize = 1_088;
/// Exact ML-KEM-1024 encapsulation length.
pub const CONFIDENTIAL_MEMO_ML_KEM_1024_CIPHERTEXT_BYTES_V1: usize = 1_568;
/// Exact XChaCha20-Poly1305 nonce length.
pub const CONFIDENTIAL_MEMO_XCHACHA_NONCE_BYTES_V1: usize = 24;
/// Exact Poly1305 authentication-tag length appended to `XChaCha` ciphertexts.
pub const CONFIDENTIAL_MEMO_XCHACHA_TAG_BYTES_V1: usize = 16;
/// Exact wrapped 32-byte memo-key plus Poly1305-tag length.
pub const CONFIDENTIAL_MEMO_WRAPPED_KEY_BYTES_V1: usize = 48;
/// Maximum encrypted memo body accepted by confidential instructions.
pub const CONFIDENTIAL_MEMO_MAX_CIPHERTEXT_BYTES_V1: usize = 64 * 1024;
/// Maximum bare V1 memo wire size when all slots select ML-KEM-1024.
pub const CONFIDENTIAL_MEMO_MAX_WIRE_BYTES_V1: usize = CONFIDENTIAL_MEMO_WIRE_MAGIC_V1.len()
    + CONFIDENTIAL_MEMO_RECIPIENT_SLOTS_V1
        * (1 + CONFIDENTIAL_MEMO_ML_KEM_1024_CIPHERTEXT_BYTES_V1
            + CONFIDENTIAL_MEMO_XCHACHA_NONCE_BYTES_V1
            + CONFIDENTIAL_MEMO_WRAPPED_KEY_BYTES_V1)
    + CONFIDENTIAL_MEMO_XCHACHA_NONCE_BYTES_V1
    + 3
    + CONFIDENTIAL_MEMO_MAX_CIPHERTEXT_BYTES_V1;

#[cfg(feature = "pqc")]
const _: () = {
    use iroha_crypto::confidential_memo;
    assert!(
        CONFIDENTIAL_MEMO_RECIPIENT_SLOTS_V1
            == confidential_memo::CONFIDENTIAL_MEMO_RECIPIENT_SLOTS_V1
    );
    assert!(
        CONFIDENTIAL_MEMO_XCHACHA_NONCE_BYTES_V1
            == confidential_memo::CONFIDENTIAL_MEMO_NONCE_BYTES_V1
    );
    assert!(
        CONFIDENTIAL_MEMO_WRAPPED_KEY_BYTES_V1
            == confidential_memo::CONFIDENTIAL_MEMO_WRAPPED_KEY_BYTES_V1
    );
    assert!(
        CONFIDENTIAL_MEMO_XCHACHA_TAG_BYTES_V1 == confidential_memo::CONFIDENTIAL_MEMO_TAG_BYTES_V1
    );
    assert!(
        CONFIDENTIAL_MEMO_MAX_CIPHERTEXT_BYTES_V1
            == confidential_memo::CONFIDENTIAL_MEMO_MAX_CIPHERTEXT_BYTES_V1
    );
};

/// Closed KEM/DEM suite used by one padded confidential-memo recipient slot.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(tag = "suite", content = "value", deny_unknown_fields)]
pub enum ConfidentialMemoSuiteV1 {
    /// ML-KEM-768 key encapsulation with XChaCha20-Poly1305 key wrapping.
    #[norito(rename = "ml-kem-768-xchacha20-poly1305-v1")]
    MlKem768XChaCha20Poly1305,
    /// ML-KEM-1024 key encapsulation with XChaCha20-Poly1305 key wrapping.
    #[norito(rename = "ml-kem-1024-xchacha20-poly1305-v1")]
    MlKem1024XChaCha20Poly1305,
}

#[cfg(feature = "pqc")]
impl From<ConfidentialMemoSuiteV1> for iroha_crypto::confidential_memo::ConfidentialMemoKemSuiteV1 {
    fn from(value: ConfidentialMemoSuiteV1) -> Self {
        match value {
            ConfidentialMemoSuiteV1::MlKem768XChaCha20Poly1305 => Self::MlKem768,
            ConfidentialMemoSuiteV1::MlKem1024XChaCha20Poly1305 => Self::MlKem1024,
        }
    }
}

#[cfg(feature = "pqc")]
impl From<iroha_crypto::confidential_memo::ConfidentialMemoKemSuiteV1> for ConfidentialMemoSuiteV1 {
    fn from(value: iroha_crypto::confidential_memo::ConfidentialMemoKemSuiteV1) -> Self {
        match value {
            iroha_crypto::confidential_memo::ConfidentialMemoKemSuiteV1::MlKem768 => {
                Self::MlKem768XChaCha20Poly1305
            }
            iroha_crypto::confidential_memo::ConfidentialMemoKemSuiteV1::MlKem1024 => {
                Self::MlKem1024XChaCha20Poly1305
            }
        }
    }
}

/// Failure while sealing or opening a typed confidential memo.
#[cfg(feature = "pqc")]
#[derive(Debug, thiserror::Error)]
pub enum ConfidentialMemoOperationErrorV1 {
    /// The ML-KEM/XChaCha operation failed.
    #[error(transparent)]
    Crypto(#[from] iroha_crypto::confidential_memo::ConfidentialMemoErrorV1),
    /// Cryptographic output or input did not satisfy the canonical wire shape.
    #[error("invalid confidential memo wire shape: {0}")]
    WireShape(String),
}

impl ConfidentialMemoSuiteV1 {
    const fn wire_tag(self) -> u8 {
        match self {
            Self::MlKem768XChaCha20Poly1305 => 0,
            Self::MlKem1024XChaCha20Poly1305 => 1,
        }
    }

    fn from_wire_tag(tag: u8) -> Result<Self, NoritoError> {
        match tag {
            0 => Ok(Self::MlKem768XChaCha20Poly1305),
            1 => Ok(Self::MlKem1024XChaCha20Poly1305),
            _ => Err(NoritoError::Message(format!(
                "unknown confidential memo suite tag {tag}"
            ))),
        }
    }

    /// Return the exact ML-KEM encapsulation length selected by this suite.
    #[must_use]
    pub const fn encapsulation_bytes(self) -> usize {
        match self {
            Self::MlKem768XChaCha20Poly1305 => CONFIDENTIAL_MEMO_ML_KEM_768_CIPHERTEXT_BYTES_V1,
            Self::MlKem1024XChaCha20Poly1305 => CONFIDENTIAL_MEMO_ML_KEM_1024_CIPHERTEXT_BYTES_V1,
        }
    }
}

/// One indistinguishable real-or-padding recipient slot in a confidential memo.
///
/// Every slot has a syntactically complete ML-KEM encapsulation and a 48-byte
/// XChaCha20-Poly1305 wrap of the memo key. Wallets try their local secret keys
/// against every slot; the wire carries no recipient identifier or real-slot
/// count.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
pub struct ConfidentialMemoRecipientSlotV1 {
    suite: ConfidentialMemoSuiteV1,
    /// Exact suite-sized ML-KEM encapsulation.
    #[norito(json = "crate::json_helpers::base64_vec")]
    encapsulation: Vec<u8>,
    /// XChaCha20-Poly1305 nonce for this slot's memo-key wrap.
    #[norito(json = "fixed_bytes")]
    wrap_nonce: [u8; CONFIDENTIAL_MEMO_XCHACHA_NONCE_BYTES_V1],
    /// Encrypted 32-byte memo key followed by its Poly1305 tag.
    #[norito(json = "fixed_bytes")]
    wrapped_memo_key: [u8; CONFIDENTIAL_MEMO_WRAPPED_KEY_BYTES_V1],
}

impl ConfidentialMemoRecipientSlotV1 {
    /// Construct one complete real or padding recipient slot.
    ///
    /// # Errors
    ///
    /// Rejects a non-canonical encapsulation length or an all-zero placeholder
    /// in any cryptographic field.
    pub fn new(
        suite: ConfidentialMemoSuiteV1,
        encapsulation: Vec<u8>,
        wrap_nonce: [u8; CONFIDENTIAL_MEMO_XCHACHA_NONCE_BYTES_V1],
        wrapped_memo_key: [u8; CONFIDENTIAL_MEMO_WRAPPED_KEY_BYTES_V1],
    ) -> Result<Self, NoritoError> {
        let slot = Self {
            suite,
            encapsulation,
            wrap_nonce,
            wrapped_memo_key,
        };
        slot.validate()?;
        Ok(slot)
    }

    /// Return the suite selected by this slot.
    #[must_use]
    pub const fn suite(&self) -> ConfidentialMemoSuiteV1 {
        self.suite
    }

    /// Borrow the exact ML-KEM encapsulation.
    #[must_use]
    pub fn encapsulation(&self) -> &[u8] {
        &self.encapsulation
    }

    /// Borrow the per-slot `XChaCha` nonce.
    #[must_use]
    pub const fn wrap_nonce(&self) -> &[u8; CONFIDENTIAL_MEMO_XCHACHA_NONCE_BYTES_V1] {
        &self.wrap_nonce
    }

    /// Borrow the wrapped memo key and authentication tag.
    #[must_use]
    pub const fn wrapped_memo_key(&self) -> &[u8; CONFIDENTIAL_MEMO_WRAPPED_KEY_BYTES_V1] {
        &self.wrapped_memo_key
    }

    fn validate(&self) -> Result<(), NoritoError> {
        if self.encapsulation.len() != self.suite.encapsulation_bytes() {
            return Err(NoritoError::Message(format!(
                "confidential memo {:?} encapsulation is {} bytes; expected {}",
                self.suite,
                self.encapsulation.len(),
                self.suite.encapsulation_bytes()
            )));
        }
        if self.encapsulation.iter().all(|byte| *byte == 0) {
            return Err(NoritoError::Message(
                "confidential memo ML-KEM encapsulation must not be all zero".to_owned(),
            ));
        }
        if self.wrap_nonce.iter().all(|byte| *byte == 0) {
            return Err(NoritoError::Message(
                "confidential memo wrap nonce must not be all zero".to_owned(),
            ));
        }
        if self.wrapped_memo_key.iter().all(|byte| *byte == 0) {
            return Err(NoritoError::Message(
                "confidential memo wrapped key must not be all zero".to_owned(),
            ));
        }
        Ok(())
    }
}

impl Default for ConfidentialMemoRecipientSlotV1 {
    fn default() -> Self {
        Self {
            suite: ConfidentialMemoSuiteV1::MlKem768XChaCha20Poly1305,
            encapsulation: vec![0; CONFIDENTIAL_MEMO_ML_KEM_768_CIPHERTEXT_BYTES_V1],
            wrap_nonce: [0; CONFIDENTIAL_MEMO_XCHACHA_NONCE_BYTES_V1],
            wrapped_memo_key: [0; CONFIDENTIAL_MEMO_WRAPPED_KEY_BYTES_V1],
        }
    }
}

/// The exact eight ordered recipient slots carried by a V1 confidential memo.
///
/// Storage is a fixed array. JSON and schema expose the closed object `slot_0`
/// through `slot_7`; missing, additional and duplicate keys are rejected.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, iroha_schema::TypeId)]
pub struct ConfidentialMemoRecipientSlotsV1 {
    slots: [ConfidentialMemoRecipientSlotV1; CONFIDENTIAL_MEMO_RECIPIENT_SLOTS_V1],
}

const MEMO_SLOT_KEYS: [&str; CONFIDENTIAL_MEMO_RECIPIENT_SLOTS_V1] = [
    "slot_0", "slot_1", "slot_2", "slot_3", "slot_4", "slot_5", "slot_6", "slot_7",
];

impl ConfidentialMemoRecipientSlotsV1 {
    /// Return the fixed V1 cardinality.
    #[must_use]
    pub const fn len(&self) -> usize {
        CONFIDENTIAL_MEMO_RECIPIENT_SLOTS_V1
    }

    /// Return `false`; a V1 memo always carries all eight slots.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Borrow the slot at `index`, if it is one of the exact eight positions.
    #[must_use]
    pub const fn get(&self, index: usize) -> Option<&ConfidentialMemoRecipientSlotV1> {
        if index < self.slots.len() {
            Some(&self.slots[index])
        } else {
            None
        }
    }

    /// Iterate over the slots in canonical wire order.
    pub fn iter(
        &self,
    ) -> impl ExactSizeIterator<Item = &ConfidentialMemoRecipientSlotV1> + DoubleEndedIterator {
        self.slots.iter()
    }

    /// Consume the wrapper and recover the exact canonical slot array.
    #[must_use]
    pub fn into_array(
        self,
    ) -> [ConfidentialMemoRecipientSlotV1; CONFIDENTIAL_MEMO_RECIPIENT_SLOTS_V1] {
        self.slots
    }

    fn get_mut(&mut self, index: usize) -> Option<&mut ConfidentialMemoRecipientSlotV1> {
        self.slots.get_mut(index)
    }
}

impl From<[ConfidentialMemoRecipientSlotV1; CONFIDENTIAL_MEMO_RECIPIENT_SLOTS_V1]>
    for ConfidentialMemoRecipientSlotsV1
{
    fn from(
        slots: [ConfidentialMemoRecipientSlotV1; CONFIDENTIAL_MEMO_RECIPIENT_SLOTS_V1],
    ) -> Self {
        Self { slots }
    }
}

impl IntoSchema for ConfidentialMemoRecipientSlotsV1 {
    fn type_name() -> String {
        "ConfidentialMemoRecipientSlotsV1".to_owned()
    }

    fn update_schema_map(map: &mut iroha_schema::MetaMap) {
        if !map.contains_key::<Self>() {
            map.insert::<Self>(iroha_schema::Metadata::Struct(
                iroha_schema::NamedFieldsMeta {
                    declarations: MEMO_SLOT_KEYS
                        .into_iter()
                        .map(|name| iroha_schema::Declaration {
                            name: name.to_owned(),
                            ty: core::any::TypeId::of::<ConfidentialMemoRecipientSlotV1>(),
                        })
                        .collect(),
                },
            ));
            ConfidentialMemoRecipientSlotV1::update_schema_map(map);
        }
    }
}

impl norito::json::FastJsonWrite for ConfidentialMemoRecipientSlotsV1 {
    fn write_json(&self, output: &mut String) {
        norito::json::write_json_unbounded(self, output);
    }

    fn write_json_to(
        &self,
        output: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        output.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            output.push('{')?;
            for (index, (key, slot)) in MEMO_SLOT_KEYS.iter().zip(&self.slots).enumerate() {
                if index != 0 {
                    output.push(',')?;
                }
                output.push('"')?;
                output.push_str(key)?;
                output.push_str("\":")?;
                slot.write_json_to(output)?;
            }
            output.push('}')?;
            Ok(())
        })();
        output.end_container();
        result?;
        Ok(())
    }
}

impl norito::json::JsonDeserialize for ConfidentialMemoRecipientSlotsV1 {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        parser.skip_ws();
        parser.preflight_object_entries()?;
        parser.expect(b'{')?;
        parser.skip_ws();
        let mut slots: [Option<ConfidentialMemoRecipientSlotV1>;
            CONFIDENTIAL_MEMO_RECIPIENT_SLOTS_V1] = core::array::from_fn(|_| None);
        if !parser.try_consume_char(b'}')? {
            loop {
                parser.skip_ws();
                let key = parser.parse_key()?;
                let Some(index) = MEMO_SLOT_KEYS.iter().position(|name| *name == key.as_str())
                else {
                    return Err(norito::json::Error::unknown_field(key.as_str()));
                };
                if slots[index].is_some() {
                    return Err(norito::json::Error::duplicate_field(MEMO_SLOT_KEYS[index]));
                }
                slots[index] = Some(ConfidentialMemoRecipientSlotV1::json_deserialize(parser)?);
                parser.skip_ws();
                if parser.try_consume_char(b',')? {
                    continue;
                }
                parser.expect(b'}')?;
                break;
            }
        }
        for (key, slot) in MEMO_SLOT_KEYS.into_iter().zip(&slots) {
            if slot.is_none() {
                return Err(norito::json::Error::missing_field(key));
            }
        }
        Ok(Self {
            slots: slots.map(|slot| slot.expect("all eight memo slots were checked")),
        })
    }
}

impl Index<usize> for ConfidentialMemoRecipientSlotsV1 {
    type Output = ConfidentialMemoRecipientSlotV1;

    fn index(&self, index: usize) -> &Self::Output {
        self.get(index)
            .unwrap_or_else(|| panic!("confidential memo slot index {index} is outside 0..8"))
    }
}

impl IndexMut<usize> for ConfidentialMemoRecipientSlotsV1 {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        self.get_mut(index)
            .unwrap_or_else(|| panic!("confidential memo slot index {index} is outside 0..8"))
    }
}

impl Default for ConfidentialMemoRecipientSlotsV1 {
    fn default() -> Self {
        core::array::from_fn(|_| ConfidentialMemoRecipientSlotV1::default()).into()
    }
}

/// Exact eight-slot confidential memo envelope.
///
/// The independent body key is wrapped into all eight slots. Unused slots are
/// populated with fresh dummy ML-KEM keys and otherwise indistinguishable
/// ciphertexts; a sender never transmits a recipient count or empty slot.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::confidential::ConfidentialMemoEnvelopeV1")]
pub struct ConfidentialMemoEnvelopeV1 {
    slots: ConfidentialMemoRecipientSlotsV1,
    /// XChaCha20-Poly1305 nonce for the encrypted memo body.
    #[norito(json = "fixed_bytes")]
    payload_nonce: [u8; CONFIDENTIAL_MEMO_XCHACHA_NONCE_BYTES_V1],
    /// Encrypted memo body followed by its Poly1305 tag.
    #[norito(json = "crate::json_helpers::base64_vec")]
    ciphertext: Vec<u8>,
}
fn varint_len(len: usize) -> usize {
    let mut value = len;
    let mut bytes = 0;
    loop {
        bytes += 1;
        if value < 0x80 {
            return bytes;
        }
        value >>= 7;
    }
}
fn write_varint<W: std::io::Write>(writer: &mut W, len: usize) -> Result<(), NoritoError> {
    let mut value = len;
    loop {
        let byte = u8::try_from(value & 0x7F).expect("masked varint chunk must fit within 7 bits");
        value >>= 7;
        if value == 0 {
            writer.write_all(&[byte])?;
            break;
        }
        writer.write_all(&[byte | 0x80])?;
    }
    Ok(())
}
fn read_varint(bytes: &[u8]) -> Result<(usize, usize), NoritoError> {
    let mut value: usize = 0;
    let mut shift = 0usize;
    for (idx, byte) in bytes.iter().enumerate() {
        let chunk = (byte & 0x7F) as usize;
        let shift_u32 = u32::try_from(shift)
            .map_err(|_| NoritoError::Message("ciphertext length overflow".to_owned()))?;
        value |= chunk
            .checked_shl(shift_u32)
            .ok_or_else(|| NoritoError::Message("ciphertext length overflow".to_owned()))?;
        if byte & 0x80 == 0 {
            let encoded_len = idx + 1;
            if encoded_len > 1 {
                let min_shift = 7usize
                    .checked_mul(encoded_len - 1)
                    .ok_or_else(|| NoritoError::Message("ciphertext length overflow".into()))?;
                let min_value = 1usize
                    .checked_shl(u32::try_from(min_shift).map_err(|_| {
                        NoritoError::Message("ciphertext length overflow".to_owned())
                    })?)
                    .ok_or_else(|| NoritoError::Message("ciphertext length overflow".into()))?;
                if value < min_value {
                    return Err(NoritoError::Message(
                        "non-canonical ciphertext length".into(),
                    ));
                }
            }
            return Ok((value, encoded_len));
        }
        shift += 7;
        if shift >= usize::BITS as usize {
            return Err(NoritoError::Message("ciphertext length overflow".into()));
        }
    }
    Err(NoritoError::LengthMismatch)
}
impl ConfidentialMemoEnvelopeV1 {
    /// Construct a canonical exact-eight-slot confidential memo envelope.
    ///
    /// # Errors
    ///
    /// Rejects malformed or duplicate slots, an all-zero body nonce, and a
    /// body that cannot contain exactly one XChaCha20-Poly1305 tag or exceeds
    /// the consensus allocation cap.
    pub fn new(
        slots: impl Into<ConfidentialMemoRecipientSlotsV1>,
        payload_nonce: [u8; CONFIDENTIAL_MEMO_XCHACHA_NONCE_BYTES_V1],
        ciphertext: Vec<u8>,
    ) -> Result<Self, NoritoError> {
        let envelope = Self {
            slots: slots.into(),
            payload_nonce,
            ciphertext,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    /// Borrow all eight real-or-padding recipient slots.
    #[must_use]
    pub const fn slots(&self) -> &ConfidentialMemoRecipientSlotsV1 {
        &self.slots
    }

    /// Borrow the encrypted memo body's XChaCha20-Poly1305 nonce.
    #[must_use]
    pub const fn payload_nonce(&self) -> &[u8; CONFIDENTIAL_MEMO_XCHACHA_NONCE_BYTES_V1] {
        &self.payload_nonce
    }

    /// Borrow the encrypted memo body and its authentication tag.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Consume the envelope and return the encrypted memo body.
    #[must_use]
    pub fn into_ciphertext(self) -> Vec<u8> {
        self.ciphertext
    }

    /// Validate the complete first-release envelope invariant.
    ///
    /// # Errors
    ///
    /// Returns [`NoritoError`] when any slot is malformed, two slots are
    /// identical, the body nonce is all zero, or the body violates its exact
    /// authentication-tag minimum or allocation cap.
    pub fn validate(&self) -> Result<(), NoritoError> {
        for (index, slot) in self.slots.iter().enumerate() {
            slot.validate().map_err(|error| {
                NoritoError::Message(format!(
                    "invalid confidential memo recipient slot {index}: {error}"
                ))
            })?;
            if self.slots.iter().take(index).any(|earlier| earlier == slot) {
                return Err(NoritoError::Message(format!(
                    "confidential memo recipient slot {index} duplicates an earlier slot"
                )));
            }
        }
        if self.payload_nonce.iter().all(|byte| *byte == 0) {
            return Err(NoritoError::Message(
                "confidential memo payload nonce must not be all zero".to_owned(),
            ));
        }
        if self.ciphertext.len() < CONFIDENTIAL_MEMO_XCHACHA_TAG_BYTES_V1 {
            return Err(NoritoError::Message(format!(
                "confidential memo ciphertext must contain a {CONFIDENTIAL_MEMO_XCHACHA_TAG_BYTES_V1}-byte authentication tag"
            )));
        }
        if self.ciphertext.len() > CONFIDENTIAL_MEMO_MAX_CIPHERTEXT_BYTES_V1 {
            return Err(NoritoError::Message(format!(
                "confidential memo ciphertext must not exceed {CONFIDENTIAL_MEMO_MAX_CIPHERTEXT_BYTES_V1} bytes"
            )));
        }
        Ok(())
    }

    /// Encode the bare canonical confidential-memo wire.
    ///
    /// # Errors
    ///
    /// Returns [`NoritoError`] when the envelope violates any V1 invariant.
    pub fn encode_wire(&self) -> Result<Vec<u8>, NoritoError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(self.encoded_len());
        bytes.extend_from_slice(&CONFIDENTIAL_MEMO_WIRE_MAGIC_V1);
        for slot in self.slots.iter() {
            bytes.push(slot.suite.wire_tag());
            bytes.extend_from_slice(&slot.encapsulation);
            bytes.extend_from_slice(&slot.wrap_nonce);
            bytes.extend_from_slice(&slot.wrapped_memo_key);
        }
        bytes.extend_from_slice(&self.payload_nonce);
        write_varint(&mut bytes, self.ciphertext.len())?;
        bytes.extend_from_slice(&self.ciphertext);
        Ok(bytes)
    }

    /// Decode exactly one bare canonical confidential-memo wire.
    ///
    /// # Errors
    ///
    /// Rejects malformed, non-canonical, truncated, or trailing bytes. There
    /// is no legacy candidate decoder.
    pub fn decode_wire(bytes: &[u8]) -> Result<Self, NoritoError> {
        let (envelope, consumed) = <Self as DecodeFromSlice>::decode_from_slice(bytes)?;
        if consumed != bytes.len() {
            return Err(NoritoError::Message(format!(
                "confidential memo wire has {} trailing bytes",
                bytes.len() - consumed
            )));
        }
        Ok(envelope)
    }

    /// Encrypt a memo for one to eight ML-KEM recipients and pad it to exactly
    /// eight shuffled slots.
    ///
    /// # Errors
    ///
    /// Returns [`ConfidentialMemoOperationErrorV1`] on malformed recipient
    /// keys, entropy failure, oversized plaintext, or any wire-shape failure.
    #[cfg(feature = "pqc")]
    pub fn seal(
        suite: ConfidentialMemoSuiteV1,
        recipient_public_keys: &[Vec<u8>],
        plaintext: &[u8],
    ) -> Result<Self, ConfidentialMemoOperationErrorV1> {
        let encrypted = iroha_crypto::confidential_memo::seal_confidential_memo_v1(
            suite.into(),
            recipient_public_keys,
            plaintext,
        )?;
        Self::from_crypto(encrypted)
    }

    /// Open this memo with one ML-KEM recipient secret key.
    ///
    /// # Errors
    ///
    /// Fails unless exactly one slot and the body authenticate for the supplied
    /// suite/key pair.
    #[cfg(feature = "pqc")]
    pub fn open(
        &self,
        suite: ConfidentialMemoSuiteV1,
        recipient_secret_key: &[u8],
    ) -> Result<Vec<u8>, ConfidentialMemoOperationErrorV1> {
        let encrypted = self.to_crypto()?;
        iroha_crypto::confidential_memo::open_confidential_memo_v1(
            &encrypted,
            suite.into(),
            recipient_secret_key,
        )
        .map_err(Into::into)
    }

    #[cfg(feature = "pqc")]
    fn from_crypto(
        encrypted: iroha_crypto::confidential_memo::ConfidentialMemoCiphertextV1,
    ) -> Result<Self, ConfidentialMemoOperationErrorV1> {
        let slots = encrypted.slots.map(|slot| ConfidentialMemoRecipientSlotV1 {
            suite: slot.suite.into(),
            encapsulation: slot.encapsulation,
            wrap_nonce: slot.wrap_nonce,
            wrapped_memo_key: slot.wrapped_body_key,
        });
        Self::new(slots, encrypted.payload_nonce, encrypted.ciphertext)
            .map_err(|error| ConfidentialMemoOperationErrorV1::WireShape(error.to_string()))
    }

    #[cfg(feature = "pqc")]
    fn to_crypto(
        &self,
    ) -> Result<
        iroha_crypto::confidential_memo::ConfidentialMemoCiphertextV1,
        ConfidentialMemoOperationErrorV1,
    > {
        self.validate()
            .map_err(|error| ConfidentialMemoOperationErrorV1::WireShape(error.to_string()))?;
        Ok(
            iroha_crypto::confidential_memo::ConfidentialMemoCiphertextV1 {
                slots: self.slots.clone().into_array().map(|slot| {
                    iroha_crypto::confidential_memo::ConfidentialMemoCiphertextSlotV1 {
                        suite: slot.suite.into(),
                        encapsulation: slot.encapsulation,
                        wrap_nonce: slot.wrap_nonce,
                        wrapped_body_key: slot.wrapped_memo_key,
                    }
                }),
                payload_nonce: self.payload_nonce,
                ciphertext: self.ciphertext.clone(),
            },
        )
    }

    fn encoded_len(&self) -> usize {
        CONFIDENTIAL_MEMO_WIRE_MAGIC_V1.len()
            + self
                .slots
                .iter()
                .map(|slot| {
                    1 + slot.suite.encapsulation_bytes()
                        + CONFIDENTIAL_MEMO_XCHACHA_NONCE_BYTES_V1
                        + CONFIDENTIAL_MEMO_WRAPPED_KEY_BYTES_V1
                })
                .sum::<usize>()
            + CONFIDENTIAL_MEMO_XCHACHA_NONCE_BYTES_V1
            + varint_len(self.ciphertext.len())
            + self.ciphertext.len()
    }
}

impl Default for ConfidentialMemoEnvelopeV1 {
    fn default() -> Self {
        Self {
            slots: ConfidentialMemoRecipientSlotsV1::default(),
            payload_nonce: [0; CONFIDENTIAL_MEMO_XCHACHA_NONCE_BYTES_V1],
            ciphertext: Vec::new(),
        }
    }
}

impl norito::SerializePayload for ConfidentialMemoEnvelopeV1 {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), NoritoError> {
        writer.write_all(&self.encode_wire()?)?;
        Ok(())
    }

    fn encoded_len_hint(&self) -> Option<usize> {
        Some(self.encoded_len())
    }

    fn encoded_len_exact(&self) -> Option<usize> {
        self.encoded_len_hint()
    }
}

impl<'de> norito::DeserializePayload<'de> for ConfidentialMemoEnvelopeV1 {
    fn deserialize(archived: &'de norito_core::Archived<Self>) -> Self {
        Self::try_deserialize(archived)
            .expect("ConfidentialMemoEnvelopeV1 deserialization must succeed for valid archives")
    }

    fn try_deserialize(archived: &'de norito_core::Archived<Self>) -> Result<Self, NoritoError> {
        let ptr = core::ptr::from_ref(archived).cast::<u8>();
        let payload = norito_core::payload_slice_from_ptr(ptr)?;
        let (value, _) = <Self as DecodeFromSlice>::decode_from_slice(payload)?;
        Ok(value)
    }
}

impl<'a> norito_core::DecodeFromSlice<'a> for ConfidentialMemoEnvelopeV1 {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), NoritoError> {
        if !bytes.starts_with(&CONFIDENTIAL_MEMO_WIRE_MAGIC_V1) {
            return Err(NoritoError::Message(
                "invalid confidential memo V1 wire magic".to_owned(),
            ));
        }

        let mut cursor = CONFIDENTIAL_MEMO_WIRE_MAGIC_V1.len();
        let mut slots = Vec::with_capacity(CONFIDENTIAL_MEMO_RECIPIENT_SLOTS_V1);
        for index in 0..CONFIDENTIAL_MEMO_RECIPIENT_SLOTS_V1 {
            let tag = *bytes.get(cursor).ok_or(NoritoError::LengthMismatch)?;
            cursor += 1;
            let suite = ConfidentialMemoSuiteV1::from_wire_tag(tag)?;
            let encapsulation_end = cursor
                .checked_add(suite.encapsulation_bytes())
                .ok_or_else(|| NoritoError::Message("memo slot length overflow".to_owned()))?;
            let nonce_end = encapsulation_end
                .checked_add(CONFIDENTIAL_MEMO_XCHACHA_NONCE_BYTES_V1)
                .ok_or_else(|| NoritoError::Message("memo slot length overflow".to_owned()))?;
            let wrapped_key_end = nonce_end
                .checked_add(CONFIDENTIAL_MEMO_WRAPPED_KEY_BYTES_V1)
                .ok_or_else(|| NoritoError::Message("memo slot length overflow".to_owned()))?;
            if wrapped_key_end > bytes.len() {
                return Err(NoritoError::LengthMismatch);
            }

            let encapsulation = bytes[cursor..encapsulation_end].to_vec();
            let mut wrap_nonce = [0; CONFIDENTIAL_MEMO_XCHACHA_NONCE_BYTES_V1];
            wrap_nonce.copy_from_slice(&bytes[encapsulation_end..nonce_end]);
            let mut wrapped_memo_key = [0; CONFIDENTIAL_MEMO_WRAPPED_KEY_BYTES_V1];
            wrapped_memo_key.copy_from_slice(&bytes[nonce_end..wrapped_key_end]);
            slots.push(
                ConfidentialMemoRecipientSlotV1::new(
                    suite,
                    encapsulation,
                    wrap_nonce,
                    wrapped_memo_key,
                )
                .map_err(|error| {
                    NoritoError::Message(format!(
                        "invalid confidential memo recipient slot {index}: {error}"
                    ))
                })?,
            );
            cursor = wrapped_key_end;
        }

        let payload_nonce_end = cursor
            .checked_add(CONFIDENTIAL_MEMO_XCHACHA_NONCE_BYTES_V1)
            .ok_or_else(|| NoritoError::Message("memo payload length overflow".to_owned()))?;
        if payload_nonce_end > bytes.len() {
            return Err(NoritoError::LengthMismatch);
        }
        let mut payload_nonce = [0; CONFIDENTIAL_MEMO_XCHACHA_NONCE_BYTES_V1];
        payload_nonce.copy_from_slice(&bytes[cursor..payload_nonce_end]);
        cursor = payload_nonce_end;

        let (cipher_len, encoded_varint_len) = read_varint(&bytes[cursor..])?;
        if cipher_len > CONFIDENTIAL_MEMO_MAX_CIPHERTEXT_BYTES_V1 {
            return Err(NoritoError::Message(format!(
                "confidential memo ciphertext must not exceed {CONFIDENTIAL_MEMO_MAX_CIPHERTEXT_BYTES_V1} bytes"
            )));
        }
        let cipher_start = cursor
            .checked_add(encoded_varint_len)
            .ok_or_else(|| NoritoError::Message("memo payload length overflow".to_owned()))?;
        let cipher_end = cipher_start
            .checked_add(cipher_len)
            .ok_or_else(|| NoritoError::Message("memo payload length overflow".to_owned()))?;
        if cipher_end > bytes.len() {
            return Err(NoritoError::LengthMismatch);
        }

        let slots: [ConfidentialMemoRecipientSlotV1; CONFIDENTIAL_MEMO_RECIPIENT_SLOTS_V1] =
            slots.try_into().map_err(|_| {
                NoritoError::Message(
                    "confidential memo must contain exactly eight slots".to_owned(),
                )
            })?;
        let ciphertext = bytes[cipher_start..cipher_end].to_vec();
        let envelope = Self::new(slots, payload_nonce, ciphertext)?;
        Ok((envelope, cipher_end))
    }
}
/// Status of a confidential registry entry.
///
/// Entries begin in the `Proposed` state once governance publishes new metadata. They become
/// `Active` at the scheduled height and transition to `Withdrawn` once retired, at which point they
/// must not be used by validators or wallets. The lifecycle applies uniformly to verifier keys and
/// parameter sets.
/// Norito encodes the enum discriminant as a four-byte little-endian integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema)]
#[repr(u8)]
#[norito(reuse_archived)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::confidential::ConfidentialStatus")]
pub enum ConfidentialStatus {
    /// Entry has been published but is not yet active.
    Proposed,
    /// Entry is active and may be used for verification.
    Active,
    /// Entry has been withdrawn and must reject verification attempts.
    Withdrawn,
}
impl ConfidentialStatus {
    /// Returns true if the status permits active use.
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(self, ConfidentialStatus::Active)
    }
    fn from_discriminant(value: u32) -> Result<Self, NoritoError> {
        match value {
            0 => Ok(Self::Proposed),
            1 => Ok(Self::Active),
            2 => Ok(Self::Withdrawn),
            other => Err(NoritoError::Message(format!(
                "invalid ConfidentialStatus discriminant {other}"
            ))),
        }
    }
}
impl From<ConfidentialStatus> for u8 {
    fn from(status: ConfidentialStatus) -> Self {
        match status {
            ConfidentialStatus::Proposed => 0,
            ConfidentialStatus::Active => 1,
            ConfidentialStatus::Withdrawn => 2,
        }
    }
}
impl<'a> DecodeFromSlice<'a> for ConfidentialStatus {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), NoritoError> {
        let (raw, used) = u32::decode_from_slice(bytes)?;
        ConfidentialStatus::from_discriminant(raw).map(|status| (status, used))
    }
}

impl norito::json::JsonSerialize for ConfidentialStatus {
    fn json_serialize(&self, out: &mut String) {
        let label = match self {
            ConfidentialStatus::Proposed => "Proposed",
            ConfidentialStatus::Active => "Active",
            ConfidentialStatus::Withdrawn => "Withdrawn",
        };
        norito::json::write_json_string(label, out);
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        let label = match self {
            ConfidentialStatus::Proposed => "Proposed",
            ConfidentialStatus::Active => "Active",
            ConfidentialStatus::Withdrawn => "Withdrawn",
        };
        norito::json::write_json_string_to(label, out)
    }
}

impl norito::json::JsonDeserialize for ConfidentialStatus {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let value = parser.parse_string()?;
        match value.as_str() {
            "Proposed" => Ok(ConfidentialStatus::Proposed),
            "Active" => Ok(ConfidentialStatus::Active),
            "Withdrawn" => Ok(ConfidentialStatus::Withdrawn),
            other => Err(norito::json::Error::unknown_field(other.to_owned())),
        }
    }
}
/// Digest advertising the active confidential feature set (verifier keys, parameters, and policy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema)]
#[norito(reuse_archived)]
#[derive(DeriveJsonSer, DeriveJsonDe, DeriveFast)]
#[norito(no_fast_from_json)]
#[norito(deny_unknown_fields, decode_fields)]
pub struct ConfidentialFeatureDigest {
    /// Optional hash summarizing the set of active verifying keys.
    #[norito(json = "crate::json_helpers::fixed_bytes::option")]
    pub vk_set_hash: Option<[u8; 32]>,
    /// Poseidon parameter set identifier expected by the node.
    pub poseidon_params_id: Option<u32>,
    /// Pedersen parameter set identifier expected by the node.
    pub pedersen_params_id: Option<u32>,
    /// Version of the confidential ruleset encoded in manifests and policies.
    pub conf_rules_version: Option<u32>,
    /// Hash of the ZK consensus policy that affects proof admission and verification.
    #[norito(json = "crate::json_helpers::fixed_bytes::option")]
    pub zk_policy_hash: Option<[u8; 32]>,
}
impl ConfidentialFeatureDigest {
    /// Construct a new digest from individual components.
    #[must_use]
    pub const fn new(
        vk_set_hash: Option<[u8; 32]>,
        poseidon_params_id: Option<u32>,
        pedersen_params_id: Option<u32>,
        conf_rules_version: Option<u32>,
        zk_policy_hash: Option<[u8; 32]>,
    ) -> Self {
        Self {
            vk_set_hash,
            poseidon_params_id,
            pedersen_params_id,
            conf_rules_version,
            zk_policy_hash,
        }
    }
    /// Returns `true` if all fields are `None`.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.vk_set_hash.is_none()
            && self.poseidon_params_id.is_none()
            && self.pedersen_params_id.is_none()
            && self.conf_rules_version.is_none()
            && self.zk_policy_hash.is_none()
    }
}
/// Ruleset version embedded into [`ConfidentialFeatureDigest::conf_rules_version`] for v1 networks.
pub const CONFIDENTIAL_RULES_VERSION: u32 = 1;
/// Default genesis confidential-policy hash for bundled ZK defaults and the version-1 (genesis)
/// SCCP light-client profiles.
///
/// Core's `default_genesis_confidential_policy_hash_uses_default_zk_and_sccp_v1_policy` test
/// requires this pin to match the current consensus inputs; regenerate it when those change.
/// Appending a light-client profile version that is not yet activated leaves it unchanged.
pub const DEFAULT_GENESIS_CONFIDENTIAL_POLICY_HASH: [u8; 32] = [
    0x91, 0xd3, 0xb1, 0xb1, 0x08, 0x63, 0x40, 0x51, 0x90, 0xa4, 0xab, 0x2d, 0x78, 0x38, 0xbc, 0xa2,
    0x2b, 0xd9, 0x84, 0x08, 0xa0, 0x3f, 0xe0, 0xf8, 0xde, 0xff, 0xdc, 0x35, 0xc2, 0x4d, 0xdf, 0x7a,
];
/// Default digest advertising the v1 ruleset and canonical genesis confidential policy.
pub const DEFAULT_CONFIDENTIAL_FEATURE_DIGEST: ConfidentialFeatureDigest =
    ConfidentialFeatureDigest::new(
        None,
        None,
        None,
        Some(CONFIDENTIAL_RULES_VERSION),
        Some(DEFAULT_GENESIS_CONFIDENTIAL_POLICY_HASH),
    );
/// Identifier for confidential parameter registries (Pedersen/Poseidon).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSer,
    DeriveJsonDe,
    DeriveFast,
)]
#[norito(no_fast_from_json)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::confidential::ConfidentialParamsId")]
pub struct ConfidentialParamsId {
    value: u32,
}
impl ConfidentialParamsId {
    /// Construct a new identifier from a raw integer value.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self { value }
    }
    /// Access the underlying integer value.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.value
    }
}
impl From<u32> for ConfidentialParamsId {
    fn from(value: u32) -> Self {
        Self { value }
    }
}
impl From<ConfidentialParamsId> for u32 {
    fn from(value: ConfidentialParamsId) -> Self {
        value.value
    }
}
impl Display for ConfidentialParamsId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}
/// Descriptor for a Pedersen parameter set tracked on-ledger.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema)]
#[norito(reuse_archived)]
#[derive(DeriveJsonSer, DeriveJsonDe, DeriveFast)]
#[norito(no_fast_from_json)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::confidential::PedersenParams")]
pub struct PedersenParams {
    /// Identifier referenced by shielded assets and proofs.
    pub params_id: ConfidentialParamsId,
    /// Hash of the curve generators used by the Pedersen commitment scheme.
    #[norito(json = "fixed_bytes")]
    pub generators_hash: [u8; 32],
    /// Hash of auxiliary constants (domain separators, blinding hints, etc.).
    #[norito(json = "fixed_bytes")]
    pub constants_hash: [u8; 32],
    /// Optional URI (CID) pointing to the canonical parameter bundle documentation.
    pub metadata_uri_cid: Option<String>,
    /// Optional URI (CID) pointing to the binary parameter bundle.
    pub params_cid: Option<String>,
    /// Block height when the parameter set becomes active.
    pub activation_height: Option<u64>,
    /// Block height when the parameter set must be withdrawn.
    pub withdraw_height: Option<u64>,
    /// Lifecycle status of the parameter entry.
    pub status: ConfidentialStatus,
}
impl PedersenParams {
    /// Returns `true` if the parameter set is usable for verification at `height`.
    #[must_use]
    pub fn is_effective_at(&self, height: u64) -> bool {
        match self.status {
            ConfidentialStatus::Active => {
                let activation_ok = self.activation_height.is_none_or(|h| height >= h);
                let withdraw_ok = self.withdraw_height.is_none_or(|limit| height < limit);
                activation_ok && withdraw_ok
            }
            ConfidentialStatus::Proposed | ConfidentialStatus::Withdrawn => false,
        }
    }
}
/// Descriptor for a Poseidon parameter set tracked on-ledger.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema)]
#[norito(reuse_archived)]
#[derive(DeriveJsonSer, DeriveJsonDe, DeriveFast)]
#[norito(no_fast_from_json)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::confidential::PoseidonParams")]
pub struct PoseidonParams {
    /// Identifier referenced by shielded assets and proofs.
    pub params_id: ConfidentialParamsId,
    /// Hash of the Poseidon round constants.
    #[norito(json = "fixed_bytes")]
    pub round_constants_hash: [u8; 32],
    /// Hash of the Poseidon MDS matrix.
    #[norito(json = "fixed_bytes")]
    pub mds_matrix_hash: [u8; 32],
    /// Optional URI (CID) pointing to the canonical parameter bundle documentation.
    pub metadata_uri_cid: Option<String>,
    /// Optional URI (CID) pointing to the binary parameter bundle.
    pub params_cid: Option<String>,
    /// Block height when the parameter set becomes active.
    pub activation_height: Option<u64>,
    /// Block height when the parameter set must be withdrawn.
    pub withdraw_height: Option<u64>,
    /// Lifecycle status of the parameter entry.
    pub status: ConfidentialStatus,
}
impl PoseidonParams {
    /// Returns `true` if the parameter set is usable for verification at `height`.
    #[must_use]
    pub fn is_effective_at(&self, height: u64) -> bool {
        match self.status {
            ConfidentialStatus::Active => {
                let activation_ok = self.activation_height.is_none_or(|h| height >= h);
                let withdraw_ok = self.withdraw_height.is_none_or(|limit| height < limit);
                activation_ok && withdraw_ok
            }
            ConfidentialStatus::Proposed | ConfidentialStatus::Withdrawn => false,
        }
    }
}
/// Frequently used confidential registry types.
pub mod prelude {
    #[cfg(feature = "pqc")]
    pub use super::ConfidentialMemoOperationErrorV1;
    pub use super::spentness::{
        ConfidentialSpentnessCheckpointDigestV1, ConfidentialSpentnessCheckpointV1,
        ConfidentialSpentnessErrorV1, ConfidentialSpentnessPathV1, ConfidentialSpentnessProofV1,
        ConfidentialSpentnessRootV1, ConfidentialSpentnessStateKindV1,
        ConfidentialSpentnessStateV1,
    };
    pub use super::{
        ConfidentialMemoEnvelopeV1, ConfidentialMemoRecipientSlotV1,
        ConfidentialMemoRecipientSlotsV1, ConfidentialMemoSuiteV1, ConfidentialParamsId,
        ConfidentialStatus, PedersenParams, PoseidonParams,
    };
}
#[cfg(test)]
mod tests {
    #[test]
    fn confidential_status_slice_matches_canonical_enum_discriminant() {
        for (tag, status) in [
            (0_u32, ConfidentialStatus::Proposed),
            (1, ConfidentialStatus::Active),
            (2, ConfidentialStatus::Withdrawn),
        ] {
            let bytes = tag.to_le_bytes();
            let frame = norito::to_bytes(&status).expect("canonical status frame");
            assert_eq!(&frame[norito::core::Header::SIZE..], &bytes);
            assert_eq!(
                ConfidentialStatus::decode_from_slice(&bytes).expect("status slice"),
                (status, bytes.len())
            );
            assert_eq!(
                norito::decode_from_bytes::<ConfidentialStatus>(&frame)
                    .expect("canonical status roundtrip"),
                status
            );
            for end in 0..bytes.len() {
                assert!(ConfidentialStatus::decode_from_slice(&bytes[..end]).is_err());
            }
        }
        for tag in [3_u32, 255, 256, u32::MAX] {
            assert!(ConfidentialStatus::decode_from_slice(&tag.to_le_bytes()).is_err());
        }
    }

    #[test]
    fn canonical_registry_schema_identity_roundtrips() {
        let value = ConfidentialParamsId::new(17);
        assert_eq!(
            <ConfidentialParamsId as norito::NoritoSchema>::nominal_name(),
            "iroha_data_model::confidential::ConfidentialParamsId"
        );
        let encoded = norito::encode_canonical(&value).expect("canonical owner frame");
        assert_eq!(
            encoded[6..22],
            norito::schema::identity::frame_hash::<ConfidentialParamsId>()
        );
        assert_eq!(
            norito::decode_canonical::<ConfidentialParamsId>(&encoded)
                .expect("canonical owner roundtrip"),
            value
        );
        let mut wrong_owner = encoded;
        wrong_owner[6] ^= 1;
        assert!(matches!(
            norito::decode_canonical::<ConfidentialParamsId>(&wrong_owner),
            Err(norito::Error::SchemaMismatch)
        ));
    }

    mod memo_slots;
    use super::*;
    use norito::codec::{decode_adaptive, encode_adaptive};
    #[test]
    fn pedersen_roundtrip() {
        let params = PedersenParams {
            params_id: ConfidentialParamsId::new(7),
            generators_hash: [0xA5; 32],
            constants_hash: [0x5A; 32],
            metadata_uri_cid: Some("ipfs://pedersen-docs".into()),
            params_cid: Some("ipfs://pedersen-raw".into()),
            activation_height: Some(10),
            withdraw_height: Some(30),
            status: ConfidentialStatus::Active,
        };
        let bytes = norito::to_bytes(&params).expect("encode pedersen params");
        let decoded: PedersenParams =
            norito::decode_from_bytes(&bytes).expect("decode pedersen params");
        assert_eq!(params, decoded);
        assert!(decoded.is_effective_at(15));
        assert!(!decoded.is_effective_at(35));
    }
    #[test]
    fn poseidon_roundtrip() {
        let params = PoseidonParams {
            params_id: ConfidentialParamsId::new(5),
            round_constants_hash: [0x11; 32],
            mds_matrix_hash: [0x22; 32],
            metadata_uri_cid: None,
            params_cid: Some("ipfs://poseidon".into()),
            activation_height: Some(5),
            withdraw_height: Some(25),
            status: ConfidentialStatus::Active,
        };
        let bytes = norito::to_bytes(&params).expect("encode poseidon params");
        let decoded: PoseidonParams =
            norito::decode_from_bytes(&bytes).expect("decode poseidon params");
        assert_eq!(params, decoded);
        assert!(decoded.is_effective_at(10));
        assert!(!decoded.is_effective_at(30));
    }
    fn memo_slot(index: u8, suite: ConfidentialMemoSuiteV1) -> ConfidentialMemoRecipientSlotV1 {
        ConfidentialMemoRecipientSlotV1::new(
            suite,
            vec![index.wrapping_add(1); suite.encapsulation_bytes()],
            [index.wrapping_add(17); CONFIDENTIAL_MEMO_XCHACHA_NONCE_BYTES_V1],
            [index.wrapping_add(33); CONFIDENTIAL_MEMO_WRAPPED_KEY_BYTES_V1],
        )
        .expect("construct canonical confidential memo slot")
    }

    fn memo_envelope() -> ConfidentialMemoEnvelopeV1 {
        ConfidentialMemoEnvelopeV1::new(
            core::array::from_fn(|index| {
                let suite = if index % 2 == 0 {
                    ConfidentialMemoSuiteV1::MlKem768XChaCha20Poly1305
                } else {
                    ConfidentialMemoSuiteV1::MlKem1024XChaCha20Poly1305
                };
                memo_slot(u8::try_from(index).expect("eight slots fit u8"), suite)
            }),
            [0xA5; CONFIDENTIAL_MEMO_XCHACHA_NONCE_BYTES_V1],
            vec![0x5A; CONFIDENTIAL_MEMO_XCHACHA_TAG_BYTES_V1 + 9],
        )
        .expect("construct canonical confidential memo envelope")
    }

    fn memo_wire(envelope: &ConfidentialMemoEnvelopeV1) -> Vec<u8> {
        envelope.encode_wire().expect("encode canonical memo wire")
    }

    #[test]
    fn confidential_memo_roundtrips_with_exactly_eight_slots() {
        let payload = memo_envelope();

        {
            let ordinary = norito::json::to_json(&payload).expect("serialize payload JSON");
            assert_eq!(
                norito::json::to_json_bounded(&payload, ordinary.len())
                    .expect("serialize payload at exact JSON limit"),
                ordinary
            );
            assert_eq!(
                norito::json::to_json_bounded(&payload, ordinary.len() - 1),
                Err(norito::json::BoundedJsonError::BodyTooLarge)
            );
        }
        let encoded = encode_adaptive(&payload);
        let decoded: ConfidentialMemoEnvelopeV1 =
            decode_adaptive(&encoded).expect("decode encrypted payload");
        assert_eq!(decoded, payload);
        assert_eq!(decoded.slots().len(), CONFIDENTIAL_MEMO_RECIPIENT_SLOTS_V1);
        assert_eq!(memo_wire(&decoded), memo_wire(&payload));
    }

    #[test]
    fn confidential_memo_wire_has_no_recipient_count() {
        let envelope = memo_envelope();
        let wire = memo_wire(&envelope);
        assert!(wire.starts_with(&CONFIDENTIAL_MEMO_WIRE_MAGIC_V1));
        assert_eq!(wire[CONFIDENTIAL_MEMO_WIRE_MAGIC_V1.len()], 0);
        let (decoded, consumed) = ConfidentialMemoEnvelopeV1::decode_from_slice(&wire)
            .expect("decode canonical confidential memo wire");
        assert_eq!(consumed, wire.len());
        assert_eq!(decoded, envelope);
    }

    #[test]
    fn confidential_memo_rejects_body_without_authentication_tag() {
        let mut envelope = memo_envelope();
        envelope.ciphertext = vec![0x5A; CONFIDENTIAL_MEMO_XCHACHA_TAG_BYTES_V1 - 1];
        let err = envelope
            .validate()
            .expect_err("tagless memo body must fail");
        assert!(
            err.to_string().contains("authentication tag"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn confidential_memo_rejects_oversized_ciphertext() {
        let mut envelope = memo_envelope();
        envelope.ciphertext = vec![3; CONFIDENTIAL_MEMO_MAX_CIPHERTEXT_BYTES_V1 + 1];
        let err = envelope
            .validate()
            .expect_err("oversized confidential ciphertext must fail validation");
        assert!(
            err.to_string().contains("ciphertext must not exceed"),
            "unexpected error: {err}"
        );
        let err = norito::to_bytes(&envelope)
            .expect_err("oversized confidential ciphertext must fail serialization");
        assert!(
            err.to_string().contains("ciphertext must not exceed"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn confidential_memo_decode_rejects_noncanonical_ciphertext_length() {
        let envelope = memo_envelope();
        let mut wire = memo_wire(&envelope);
        let body_len = envelope.ciphertext().len();
        let length_offset = wire.len() - body_len - varint_len(body_len);
        wire.splice(length_offset..=length_offset, [0x99, 0x00]);
        let err = ConfidentialMemoEnvelopeV1::decode_from_slice(&wire)
            .expect_err("non-canonical memo body length must fail");
        assert!(
            err.to_string().contains("non-canonical ciphertext length"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn confidential_memo_decode_rejects_oversized_ciphertext_length_before_allocation() {
        let envelope = memo_envelope();
        let mut wire = memo_wire(&envelope);
        let body_len = envelope.ciphertext().len();
        let length_offset = wire.len() - body_len - varint_len(body_len);
        wire.truncate(length_offset);
        write_varint(&mut wire, CONFIDENTIAL_MEMO_MAX_CIPHERTEXT_BYTES_V1 + 1)
            .expect("write oversized body length");
        let err = ConfidentialMemoEnvelopeV1::decode_from_slice(&wire)
            .expect_err("oversized memo body length must fail before allocation");
        assert!(
            err.to_string().contains("ciphertext must not exceed"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn confidential_memo_rejects_legacy_x25519_wire() {
        let mut legacy = vec![1];
        legacy.extend_from_slice(&[7; 32]);
        legacy.extend_from_slice(&[2; 24]);
        legacy.push(
            u8::try_from(CONFIDENTIAL_MEMO_XCHACHA_TAG_BYTES_V1).expect("fixture value fits u8"),
        );
        legacy.extend_from_slice(&[3; CONFIDENTIAL_MEMO_XCHACHA_TAG_BYTES_V1]);
        let err = ConfidentialMemoEnvelopeV1::decode_from_slice(&legacy)
            .expect_err("legacy X25519 memo wire must fail the V1 magic");
        assert!(
            err.to_string().contains("wire magic"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn confidential_memo_rejects_unknown_suite_and_truncation() {
        let mut unknown_suite = CONFIDENTIAL_MEMO_WIRE_MAGIC_V1.to_vec();
        unknown_suite.push(0xFF);
        let err = ConfidentialMemoEnvelopeV1::decode_from_slice(&unknown_suite)
            .expect_err("unknown memo suite must fail");
        assert!(
            err.to_string().contains("suite tag"),
            "unexpected error: {err}"
        );

        let mut truncated = memo_wire(&memo_envelope());
        truncated.truncate(truncated.len() - 1);
        assert!(ConfidentialMemoEnvelopeV1::decode_from_slice(&truncated).is_err());

        let mut trailing = memo_wire(&memo_envelope());
        trailing.push(0);
        let err = ConfidentialMemoEnvelopeV1::decode_wire(&trailing)
            .expect_err("canonical memo decoder must reject trailing bytes");
        assert!(err.to_string().contains("trailing bytes"));
    }

    #[test]
    fn confidential_memo_rejects_zero_or_duplicate_slots() {
        let err = ConfidentialMemoRecipientSlotV1::new(
            ConfidentialMemoSuiteV1::MlKem768XChaCha20Poly1305,
            vec![0; CONFIDENTIAL_MEMO_ML_KEM_768_CIPHERTEXT_BYTES_V1],
            [1; CONFIDENTIAL_MEMO_XCHACHA_NONCE_BYTES_V1],
            [2; CONFIDENTIAL_MEMO_WRAPPED_KEY_BYTES_V1],
        )
        .expect_err("zero ML-KEM encapsulation must fail");
        assert!(
            err.to_string().contains("all zero"),
            "unexpected error: {err}"
        );

        let mut slots = memo_envelope().slots().clone();
        slots[7] = slots[0].clone();
        let err = ConfidentialMemoEnvelopeV1::new(
            slots,
            [0xA5; CONFIDENTIAL_MEMO_XCHACHA_NONCE_BYTES_V1],
            vec![0x5A; CONFIDENTIAL_MEMO_XCHACHA_TAG_BYTES_V1],
        )
        .expect_err("duplicate real-or-padding slot must fail");
        assert!(
            err.to_string().contains("duplicates"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn confidential_memo_default_is_an_invalid_non_wire_placeholder() {
        let envelope = ConfidentialMemoEnvelopeV1::default();
        assert!(envelope.validate().is_err());
        assert!(norito::to_bytes(&envelope).is_err());
    }
}

#[cfg(test)]
mod captured_confidential_schema_tests;

#[cfg(test)]
mod additional_frame_owner_identity_tests {
    //! Typed frame contracts observed with the original codec.

    #[test]
    fn captured_additional_frame_owner_identities() {
        crate::frame_owner_identity_tests::assert_bidirectional::<
            crate::confidential::PedersenParams,
        >("iroha_data_model::confidential::PedersenParams");
        crate::frame_owner_identity_tests::assert_bidirectional::<
            crate::confidential::PoseidonParams,
        >("iroha_data_model::confidential::PoseidonParams");
    }
}

#[cfg(test)]
mod checked_container_cleanup_tests {
    //! Original owning writer refusal and nested-depth controls.
    use super::*;
    use crate::checked_container_refusal_controls::audit;

    #[test]
    fn original_memo_slots_checked_container_retains_original_backing_and_depth() {
        let slots = core::array::from_fn(|_| {
            ConfidentialMemoRecipientSlotV1::new(
                ConfidentialMemoSuiteV1::MlKem768XChaCha20Poly1305,
                vec![7; CONFIDENTIAL_MEMO_ML_KEM_768_CIPHERTEXT_BYTES_V1],
                [7; CONFIDENTIAL_MEMO_XCHACHA_NONCE_BYTES_V1],
                [7; CONFIDENTIAL_MEMO_WRAPPED_KEY_BYTES_V1],
            )
            .unwrap()
        });
        let value = ConfidentialMemoRecipientSlotsV1::from(slots);
        let source = value
            .slots
            .each_ref()
            .map(|slot| slot.encapsulation().as_ptr());
        audit(&value);
        assert_eq!(
            value
                .slots
                .each_ref()
                .map(|slot| slot.encapsulation().as_ptr()),
            source
        );
    }
}
