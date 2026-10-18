//! Types representing executable parts of a transaction.
pub use self::model::*;
#[cfg(test)]
use crate::isi::Instruction;
use crate::{
    isi::InstructionBox, smart_contract::ContractAddress, transaction::signed::FeePaymentIntent,
};
use ::base64::{Engine as _, engine::general_purpose::STANDARD};
use iroha_data_model_derive::model;
use iroha_primitives::const_vec::ConstVec;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};
use norito::{DeserializePayload, core as ncore};
use std::{fmt, iter::IntoIterator, ops::Deref, vec::Vec};
#[model]
mod model {
    use super::*;
    use iroha_crypto::Hash;
    use iroha_primitives::const_vec::ConstVec;
    /// An executable transaction or trigger payload.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::transaction::executable::model::Executable")]
    #[derive(
        derive_more::Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema,
    )]
    pub enum Executable {
        /// Ordered set of instructions.
        #[debug("Instructions(..)")]
        Instructions(ConstVec<InstructionBox>),
        /// Invoke a deployed contract instance by reference.
        ContractCall(ContractInvocation),
        /// IVM smart contract bytecode (.to)
        Ivm(IvmBytecode),
        /// IVM smart contract bytecode accompanied by a precomputed instruction overlay.
        ///
        /// This executable is intended for proof-carrying flows where the transaction
        /// supplies a deterministic overlay (ISIs) together with a binding proof (via
        /// [`SignedTransaction`](crate::transaction::SignedTransaction) attachments) that
        /// binds the declared code, overlay, event and gas commitments.
        ///
        /// Nodes must deterministically replay the IVM execution and compare all
        /// outputs. The binding proof alone does not establish execution correctness
        /// or hide execution from validators.
        IvmProved(IvmProved),
        /// Ordered, atomic mix of native instructions and deployed-contract calls.
        ///
        /// Raw IVM bytecode and nested batches are intentionally excluded from
        /// [`ExecutableBatchItem`], keeping the mixed form explicit and bounded.
        Batch(ConstVec<ExecutableBatchItem>),
    }
    /// One ordered item in [`Executable::Batch`].
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::transaction::executable::model::ExecutableBatchItem")]
    #[derive(
        derive_more::Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema,
    )]
    pub enum ExecutableBatchItem {
        /// Execute one native Iroha Special Instruction.
        Instruction(InstructionBox),
        /// Invoke one deployed contract instance by reference.
        ContractCall(ContractInvocation),
    }
    /// Wrapper for IVM bytecode used by [`Executable::Ivm`].
    ///
    /// Uses **base64** (de-)serialization format.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::transaction::executable::model::IvmBytecode")]
    #[derive(
        derive_more::Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema,
    )]
    #[debug("IVM bytecode(len = {})", self.0.len())]
    #[repr(transparent)]
    // SAFETY: `IvmBytecode` has no trap representation in `Vec<u8>`
    pub struct IvmBytecode(
        /// Raw Kotodama bytecode blob.
        pub(super) Vec<u8>,
    );
    /// Claimed IVM outputs checked by a binding proof and mandatory execution replay.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::transaction::executable::model::IvmProved")]
    #[derive(
        derive_more::Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema,
    )]
    pub struct IvmProved {
        /// Raw Kotodama bytecode blob.
        pub bytecode: IvmBytecode,
        /// Precomputed ordered overlay to apply only after proof verification and replay agree.
        pub overlay: ConstVec<InstructionBox>,
        /// Commitment to deterministic execution-side events materialized for this proved run.
        pub events_commitment: Hash,
        /// Commitment to the gas policy and usage recomputed during validator replay.
        pub gas_policy_commitment: Hash,
    }
    /// Bounded canonical bytes for one schema-bound Kotodama argument record.
    #[derive(derive_more::Debug, Clone, PartialEq, Eq, PartialOrd, Ord, IntoSchema)]
    #[norito(reuse_archived)]
    #[repr(transparent)]
    #[derive(norito::NoritoSchema)]
    #[norito_schema(
        name = "iroha_data_model::transaction::executable::model::ContractArgumentRecord"
    )]
    pub struct ContractArgumentRecord(pub(super) Vec<u8>);
    /// By-reference invocation of a deployed contract instance.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::transaction::executable::model::ContractInvocation")]
    #[derive(
        derive_more::Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        IntoSchema,
        crate :: DeriveFastJson,
        crate :: DeriveJsonSerialize,
        crate :: DeriveJsonDeserialize,
    )]
    #[norito(no_fast_from_json)]
    #[derive(derive_more::Constructor)]
    pub struct ContractInvocation {
        /// Canonical deployed contract address.
        pub contract_address: ContractAddress,
        /// Exact code hash that the signer authorizes at this address.
        ///
        /// Validators reject the invocation if the live instance binding has changed, preventing an
        /// in-flight signed call from crossing a governance `kaizen`/`改善` rebind boundary.
        pub expected_code_hash: Hash,
        /// Public or view entrypoint selector.
        pub entrypoint: String,
        /// Canonical schema-bound `EntrypointArgumentRecordV1` bytes.
        ///
        /// JSON is converted by Torii/CLI/SDK tooling before the invocation is
        /// signed; validators and the VM never interpret JSON as argument transport.
        pub arguments: Option<ContractArgumentRecord>,
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for ExecutableBatchItem {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        norito::core::decode_field_canonical::<Self>(bytes)
    }
}
/// Maximum signed argument-record bytes accepted by transaction decoding.
///
/// This wire limit is independent from compiler source-size limits. It is
/// enforced before allocating the record payload.
pub const MAX_CONTRACT_ARGUMENT_RECORD_BYTES: usize = 1024 * 1024;
/// Error returned when a signed contract argument record exceeds its wire cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("contract argument record is {actual} bytes; maximum is {max}")]
pub struct ContractArgumentRecordTooLarge {
    /// Supplied record length.
    pub actual: usize,
    /// Maximum accepted record length.
    pub max: usize,
}
impl ContractArgumentRecord {
    /// Construct a bounded signed argument record.
    ///
    /// # Errors
    ///
    /// Returns [`ContractArgumentRecordTooLarge`] when `bytes` exceeds
    /// [`MAX_CONTRACT_ARGUMENT_RECORD_BYTES`].
    pub fn try_new(bytes: Vec<u8>) -> Result<Self, ContractArgumentRecordTooLarge> {
        if bytes.len() > MAX_CONTRACT_ARGUMENT_RECORD_BYTES {
            return Err(ContractArgumentRecordTooLarge {
                actual: bytes.len(),
                max: MAX_CONTRACT_ARGUMENT_RECORD_BYTES,
            });
        }
        Ok(Self(bytes))
    }
    /// Borrow the canonical record bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Mutably borrow the fixed-length record bytes.
    ///
    /// This cannot violate the allocation bound because the slice length is
    /// immutable; it is primarily useful for signature-tampering tests.
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.0
    }
    /// Consume the wrapper and return its canonical bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}
impl AsRef<[u8]> for ContractArgumentRecord {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}
impl Deref for ContractArgumentRecord {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.as_bytes()
    }
}
impl TryFrom<Vec<u8>> for ContractArgumentRecord {
    type Error = ContractArgumentRecordTooLarge;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_new(bytes)
    }
}

impl ncore::SerializePayload for ContractArgumentRecord {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), ncore::Error> {
        ncore::SerializePayload::serialize(&self.0, writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        ncore::SerializePayload::encoded_len_hint(&self.0)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        ncore::SerializePayload::encoded_len_exact(&self.0)
    }
}

impl<'de> DeserializePayload<'de> for ContractArgumentRecord {
    fn deserialize(archived: &'de ncore::Archived<Self>) -> Self {
        // Norito's public decode functions, Option decoder, and generated
        // containing-struct decoder all call `try_deserialize`; hostile wire
        // bytes therefore take the fallible path below. This infallible trait
        // entrypoint is retained only for the trait contract.
        Self::try_deserialize(archived)
            .expect("ContractArgumentRecord deserialization must enforce its wire bound")
    }
    fn try_deserialize(archived: &'de ncore::Archived<Self>) -> Result<Self, ncore::Error> {
        let ptr = core::ptr::from_ref(archived).cast::<u8>();
        let bytes = ncore::payload_slice_from_ptr(ptr)?;
        let (value, used) = <Self as ncore::DecodeFromSlice>::decode_from_slice(bytes)?;
        if used > bytes.len() {
            return Err(ncore::Error::LengthMismatch);
        }
        Ok(value)
    }
}
impl<'de> ncore::DecodeFromSlice<'de> for ContractArgumentRecord {
    fn decode_from_slice(bytes: &'de [u8]) -> Result<(Self, usize), ncore::Error> {
        let (len, offset) = ncore::read_seq_len_slice(bytes)?;
        if len > MAX_CONTRACT_ARGUMENT_RECORD_BYTES {
            return Err(ncore::Error::LengthMismatch);
        }
        let end = offset
            .checked_add(len)
            .ok_or(ncore::Error::LengthMismatch)?;
        let payload = bytes.get(offset..end).ok_or(ncore::Error::LengthMismatch)?;
        Ok((Self(payload.to_vec()), end))
    }
}

impl norito::json::FastJsonWrite for ContractArgumentRecord {
    fn write_json(&self, out: &mut String) {
        norito::json::JsonSerialize::json_serialize(&self.0, out);
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        norito::json::JsonSerialize::json_serialize_to(&self.0, out)
    }
}

impl norito::json::JsonDeserialize for ContractArgumentRecord {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let mut sequence = norito::json::SeqVisitor::new(parser)?;
        let mut bytes = Vec::new();
        while let Some(byte) = sequence.next_element::<u8>()? {
            if bytes.len() == MAX_CONTRACT_ARGUMENT_RECORD_BYTES {
                return Err(norito::json::Error::Message(format!(
                    "contract argument record exceeds {MAX_CONTRACT_ARGUMENT_RECORD_BYTES} bytes"
                )));
            }
            if bytes.len() == bytes.capacity() {
                let additional = MAX_CONTRACT_ARGUMENT_RECORD_BYTES
                    .saturating_sub(bytes.len())
                    .min(4096);
                bytes.try_reserve_exact(additional).map_err(|_| {
                    norito::json::Error::Message(
                        "contract argument record allocation failed".to_owned(),
                    )
                })?;
            }
            bytes.push(byte);
        }
        sequence.finish()?;
        Ok(Self(bytes))
    }
    fn json_from_value(value: &norito::json::Value) -> Result<Self, norito::json::Error> {
        let items = value.as_array().ok_or_else(|| {
            norito::json::Error::Message("contract arguments must be a byte array".to_owned())
        })?;
        if items.len() > MAX_CONTRACT_ARGUMENT_RECORD_BYTES {
            return Err(norito::json::Error::Message(format!(
                "contract argument record exceeds {MAX_CONTRACT_ARGUMENT_RECORD_BYTES} bytes"
            )));
        }
        let mut bytes = Vec::with_capacity(items.len());
        for item in items {
            bytes.push(<u8 as norito::json::JsonDeserialize>::json_from_value(
                item,
            )?);
        }
        Ok(Self(bytes))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for Executable {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        const INSTRUCTIONS_TAG: u32 = 0;
        let flags = norito::core::effective_decode_flags()
            .unwrap_or_else(norito::core::default_encode_flags);
        let tag_bytes = bytes
            .get(..core::mem::size_of::<u32>())
            .ok_or(norito::core::Error::LengthMismatch)?;
        let tag = u32::from_le_bytes(
            tag_bytes
                .try_into()
                .expect("slice length checked for executable tag"),
        );
        if tag != INSTRUCTIONS_TAG {
            let _guard = norito::core::PayloadCtxGuard::enter(bytes);
            let mut cursor = std::io::Cursor::new(bytes);
            let decoded = <Self as norito::codec::Decode>::decode(&mut cursor)?;
            let used = usize::try_from(cursor.position())
                .map_err(|_| norito::core::Error::LengthMismatch)?;
            return Ok((decoded, used));
        }
        let mut offset = core::mem::size_of::<u32>();
        let remaining = bytes
            .get(offset..)
            .ok_or(norito::core::Error::LengthMismatch)?;
        let (field_len, hdr) = norito::core::read_len_from_slice_with_flags(remaining, flags)?;
        let field_start = offset
            .checked_add(hdr)
            .ok_or(norito::core::Error::LengthMismatch)?;
        let field_end = field_start
            .checked_add(field_len)
            .ok_or(norito::core::Error::LengthMismatch)?;
        let field = bytes
            .get(field_start..field_end)
            .ok_or(norito::core::Error::LengthMismatch)?;
        let (instructions, used) =
            norito::core::decode_field_canonical_from_slice::<ConstVec<InstructionBox>>(field)?;
        if used != field.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        offset = field_end;
        norito::core::note_payload_access(bytes, offset);
        Ok((Self::Instructions(instructions), offset))
    }
}
// Collect any iterator of instructions into an executable. The identity
// `Into` implementation keeps existing `InstructionBox` items unchanged.
impl<A> FromIterator<A> for Executable
where
    A: Into<InstructionBox>,
{
    fn from_iter<T: IntoIterator<Item = A>>(iter: T) -> Self {
        let items: Vec<InstructionBox> = iter.into_iter().map(Into::into).collect();
        Self::Instructions(items.into())
    }
}
impl<T, A> From<T> for Executable
where
    T: IntoIterator<Item = A>,
    A: Into<InstructionBox>,
{
    fn from(collection: T) -> Self {
        Executable::from_iter(collection)
    }
}
impl From<IvmBytecode> for Executable {
    fn from(source: IvmBytecode) -> Self {
        Self::Ivm(source)
    }
}
impl From<ContractInvocation> for Executable {
    fn from(source: ContractInvocation) -> Self {
        Self::ContractCall(source)
    }
}
impl From<InstructionBox> for ExecutableBatchItem {
    fn from(source: InstructionBox) -> Self {
        Self::Instruction(source)
    }
}
impl From<ContractInvocation> for ExecutableBatchItem {
    fn from(source: ContractInvocation) -> Self {
        Self::ContractCall(source)
    }
}
/// Errors raised while requiring a signature-bound transaction gas limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionGasLimitError {
    /// The signed fee intent does not declare an executable gas limit.
    Missing,
}
impl fmt::Display for TransactionGasLimitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => f.write_str("missing gas limit in fee payment intent"),
        }
    }
}
impl std::error::Error for TransactionGasLimitError {}
/// Return the optional nonzero executable gas limit bound by the signed fee intent.
#[must_use]
pub const fn parse_transaction_gas_limit(fee_payment: &FeePaymentIntent) -> Option<u64> {
    match fee_payment.gas_limit() {
        Some(limit) => Some(limit.get()),
        None => None,
    }
}
/// Return the executable gas limit bound by the signed fee intent.
///
/// # Errors
///
/// Returns [`TransactionGasLimitError::Missing`] when the signed intent omits the limit.
pub const fn require_transaction_gas_limit(
    fee_payment: &FeePaymentIntent,
) -> Result<u64, TransactionGasLimitError> {
    match parse_transaction_gas_limit(fee_payment) {
        Some(limit) => Ok(limit),
        None => Err(TransactionGasLimitError::Missing),
    }
}
impl AsRef<[u8]> for IvmBytecode {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
impl IvmBytecode {
    /// Create [`Self`] from raw IVM bytecode
    #[inline]
    pub const fn from_compiled(blob: Vec<u8>) -> Self {
        Self(blob)
    }
    /// Size of the smart contract in bytes
    pub fn size_bytes(&self) -> usize {
        self.0.len()
    }
}
impl Executable {
    /// Returns `true` if the executable kind requires a signature-bound gas limit.
    pub fn requires_transaction_gas_limit(&self) -> bool {
        match self {
            Self::Instructions(_) => false,
            Self::Batch(items) => items
                .iter()
                .any(|item| matches!(item, ExecutableBatchItem::ContractCall(_))),
            Self::ContractCall(_) | Self::Ivm(_) | Self::IvmProved(_) => true,
        }
    }
    /// Return the ordered mixed-batch items, if this is a batch executable.
    #[must_use]
    pub fn batch_items(&self) -> Option<&ConstVec<ExecutableBatchItem>> {
        match self {
            Self::Batch(items) => Some(items),
            _ => None,
        }
    }
    /// Iterate native instructions explicitly supplied by the transaction author.
    ///
    /// This includes the legacy instruction executable and instruction items in
    /// a mixed batch. Contract calls, raw IVM bytecode, and proved-VM overlays
    /// are excluded because their native effects are not direct batch items.
    pub fn explicit_instructions(&self) -> impl Iterator<Item = &InstructionBox> {
        let instructions = match self {
            Self::Instructions(instructions) => Some(instructions.as_ref()),
            _ => None,
        };
        let batch = match self {
            Self::Batch(items) => Some(items.as_ref()),
            _ => None,
        };
        instructions
            .into_iter()
            .flatten()
            .chain(batch.into_iter().flatten().filter_map(|item| match item {
                ExecutableBatchItem::Instruction(instruction) => Some(instruction),
                ExecutableBatchItem::ContractCall(_) => None,
            }))
    }
}

impl norito::json::JsonDeserialize for ExecutableBatchItem {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        parser.skip_ws();
        parser.consume_char(b'{')?;
        parser.skip_ws();
        let key = parser.parse_key()?;
        let item = match key.as_str() {
            "Instruction" => Self::Instruction(InstructionBox::json_deserialize(parser)?),
            "ContractCall" => Self::ContractCall(ContractInvocation::json_deserialize(parser)?),
            other => return Err(norito::json::Error::unknown_field(other.to_owned())),
        };
        parser.skip_ws();
        parser.consume_char(b'}')?;
        Ok(item)
    }
}

impl norito::json::FastJsonWrite for ExecutableBatchItem {
    fn write_json(&self, out: &mut String) {
        out.push('{');
        match self {
            Self::Instruction(instruction) => {
                norito::json::write_json_string("Instruction", out);
                out.push(':');
                norito::json::JsonSerialize::json_serialize(instruction, out);
            }
            Self::ContractCall(invocation) => {
                norito::json::write_json_string("ContractCall", out);
                out.push(':');
                norito::json::JsonSerialize::json_serialize(invocation, out);
            }
        }
        out.push('}');
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push('{')?;
            match self {
                Self::Instruction(instruction) => {
                    out.push_str("\"Instruction\":")?;
                    norito::json::JsonSerialize::json_serialize_to(instruction, out)?;
                }
                Self::ContractCall(invocation) => {
                    out.push_str("\"ContractCall\":")?;
                    norito::json::JsonSerialize::json_serialize_to(invocation, out)?;
                }
            }
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result?;
        Ok(())
    }
}

impl norito::json::FastJsonWrite for IvmBytecode {
    fn write_json(&self, out: &mut String) {
        norito::json::write_base64_json(&self.0, out);
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        norito::json::write_base64_json_to(&self.0, out)
    }
}

impl norito::json::JsonDeserialize for IvmBytecode {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let encoded = parser.parse_string()?;
        let bytes = STANDARD
            .decode(encoded.as_str())
            .map_err(|err| norito::json::Error::Message(err.to_string()))?;
        Ok(Self(bytes))
    }
}

impl norito::json::FastJsonWrite for IvmProved {
    fn write_json(&self, out: &mut String) {
        out.push('{');
        norito::json::write_json_string("bytecode", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.bytecode, out);
        out.push(',');
        norito::json::write_json_string("overlay", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.overlay, out);
        out.push(',');
        norito::json::write_json_string("events_commitment", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.events_commitment, out);
        out.push(',');
        norito::json::write_json_string("gas_policy_commitment", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.gas_policy_commitment, out);
        out.push('}');
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push_str("{\"bytecode\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.bytecode, out)?;
            out.push_str(",\"overlay\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.overlay, out)?;
            out.push_str(",\"events_commitment\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.events_commitment, out)?;
            out.push_str(",\"gas_policy_commitment\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.gas_policy_commitment, out)?;
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result?;
        Ok(())
    }
}

impl norito::json::JsonDeserialize for IvmProved {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        parser.skip_ws();
        parser.consume_char(b'{')?;
        let mut bytecode: Option<IvmBytecode> = None;
        let mut overlay: Option<iroha_primitives::const_vec::ConstVec<InstructionBox>> = None;
        let mut events_commitment: Option<iroha_crypto::Hash> = None;
        let mut gas_policy_commitment: Option<iroha_crypto::Hash> = None;
        loop {
            parser.skip_ws();
            if parser.try_consume_char(b'}')? {
                break;
            }
            let field = parser.parse_key()?;
            match field.as_str() {
                "bytecode" => {
                    bytecode = Some(IvmBytecode::json_deserialize(parser)?);
                }
                "overlay" => {
                    overlay = Some(
                        iroha_primitives::const_vec::ConstVec::<InstructionBox>::json_deserialize(
                            parser,
                        )?,
                    );
                }
                "events_commitment" => {
                    events_commitment = Some(iroha_crypto::Hash::json_deserialize(parser)?);
                }
                "gas_policy_commitment" => {
                    gas_policy_commitment = Some(iroha_crypto::Hash::json_deserialize(parser)?);
                }
                other => return Err(norito::json::Error::unknown_field(other.to_owned())),
            }
            if !parser.consume_comma_if_present()? {
                parser.skip_ws();
                parser.consume_char(b'}')?;
                break;
            }
        }
        let bytecode = bytecode
            .ok_or_else(|| norito::json::Error::Message("missing field `bytecode`".to_owned()))?;
        let overlay = overlay
            .ok_or_else(|| norito::json::Error::Message("missing field `overlay`".to_owned()))?;
        let events_commitment = events_commitment.ok_or_else(|| {
            norito::json::Error::Message("missing field `events_commitment`".to_owned())
        })?;
        let gas_policy_commitment = gas_policy_commitment.ok_or_else(|| {
            norito::json::Error::Message("missing field `gas_policy_commitment`".to_owned())
        })?;
        Ok(Self {
            bytecode,
            overlay,
            events_commitment,
            gas_policy_commitment,
        })
    }
}
impl Executable {
    /// Number of explicit native instructions carried by this executable.
    ///
    /// Contract calls and raw IVM bytecode contribute zero; proved overlays and
    /// native items inside a mixed batch are counted.
    pub fn instruction_count(&self) -> u64 {
        match self {
            Executable::Instructions(instructions) => instructions.len() as u64,
            Executable::ContractCall(_) | Executable::Ivm(_) => 0,
            Executable::IvmProved(proved) => proved.overlay.len() as u64,
            Executable::Batch(items) => items
                .iter()
                .filter(|item| matches!(item, ExecutableBatchItem::Instruction(_)))
                .count() as u64,
        }
    }
    /// Returns bytecode size if this is `Executable::Ivm`, otherwise `0`.
    pub fn ivm_size_bytes(&self) -> usize {
        match self {
            Executable::Ivm(b) => b.size_bytes(),
            Executable::ContractCall(_) | Executable::Instructions(_) | Executable::Batch(_) => 0,
            Executable::IvmProved(proved) => proved.bytecode.size_bytes(),
        }
    }
}

impl norito::json::JsonDeserialize for Executable {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        parser.skip_ws();
        parser.consume_char(b'{')?;
        parser.skip_ws();
        let key = parser.parse_key()?;
        let exec = match key.as_str() {
            "Instructions" => {
                let instrs =
                    iroha_primitives::const_vec::ConstVec::<InstructionBox>::json_deserialize(
                        parser,
                    )?;
                Executable::Instructions(instrs)
            }
            "ContractCall" => {
                Executable::ContractCall(ContractInvocation::json_deserialize(parser)?)
            }
            "Batch" => Executable::Batch(iroha_primitives::const_vec::ConstVec::<
                ExecutableBatchItem,
            >::json_deserialize(parser)?),
            "Ivm" => Executable::Ivm(IvmBytecode::json_deserialize(parser)?),
            "IvmProved" => {
                parser.skip_ws();
                parser.consume_char(b'{')?;
                let mut bytecode: Option<IvmBytecode> = None;
                let mut overlay: Option<iroha_primitives::const_vec::ConstVec<InstructionBox>> =
                    None;
                let mut events_commitment: Option<iroha_crypto::Hash> = None;
                let mut gas_policy_commitment: Option<iroha_crypto::Hash> = None;
                loop {
                    parser.skip_ws();
                    if parser.try_consume_char(b'}')? {
                        break;
                    }
                    let field = parser.parse_key()?;
                    match field.as_str() {
                        "bytecode" => {
                            bytecode = Some(IvmBytecode::json_deserialize(parser)?);
                        }
                        "overlay" => {
                            overlay = Some(
                                iroha_primitives::const_vec::ConstVec::<InstructionBox>::json_deserialize(parser)?,
                            );
                        }
                        "events_commitment" => {
                            events_commitment = Some(iroha_crypto::Hash::json_deserialize(parser)?);
                        }
                        "gas_policy_commitment" => {
                            gas_policy_commitment =
                                Some(iroha_crypto::Hash::json_deserialize(parser)?);
                        }
                        other => {
                            return Err(norito::json::Error::unknown_field(other.to_owned()));
                        }
                    }
                    if !parser.consume_comma_if_present()? {
                        parser.skip_ws();
                        parser.consume_char(b'}')?;
                        break;
                    }
                }
                let bytecode = bytecode.ok_or_else(|| {
                    norito::json::Error::Message("missing field `bytecode`".to_owned())
                })?;
                let overlay = overlay.ok_or_else(|| {
                    norito::json::Error::Message("missing field `overlay`".to_owned())
                })?;
                let events_commitment = events_commitment.ok_or_else(|| {
                    norito::json::Error::Message("missing field `events_commitment`".to_owned())
                })?;
                let gas_policy_commitment = gas_policy_commitment.ok_or_else(|| {
                    norito::json::Error::Message("missing field `gas_policy_commitment`".to_owned())
                })?;
                Executable::IvmProved(IvmProved {
                    bytecode,
                    overlay,
                    events_commitment,
                    gas_policy_commitment,
                })
            }
            other => return Err(norito::json::Error::unknown_field(other.to_owned())),
        };
        parser.skip_ws();
        parser.consume_char(b'}')?;
        Ok(exec)
    }
}

impl norito::json::FastJsonWrite for Executable {
    fn write_json(&self, out: &mut String) {
        out.push('{');
        match self {
            Executable::Instructions(instrs) => {
                norito::json::write_json_string("Instructions", out);
                out.push(':');
                norito::json::JsonSerialize::json_serialize(instrs, out);
            }
            Executable::ContractCall(invocation) => {
                norito::json::write_json_string("ContractCall", out);
                out.push(':');
                norito::json::JsonSerialize::json_serialize(invocation, out);
            }
            Executable::Ivm(bytecode) => {
                norito::json::write_json_string("Ivm", out);
                out.push(':');
                norito::json::JsonSerialize::json_serialize(bytecode, out);
            }
            Executable::IvmProved(proved) => {
                norito::json::write_json_string("IvmProved", out);
                out.push(':');
                out.push('{');
                norito::json::write_json_string("bytecode", out);
                out.push(':');
                norito::json::JsonSerialize::json_serialize(&proved.bytecode, out);
                out.push(',');
                norito::json::write_json_string("overlay", out);
                out.push(':');
                norito::json::JsonSerialize::json_serialize(&proved.overlay, out);
                out.push(',');
                norito::json::write_json_string("events_commitment", out);
                out.push(':');
                norito::json::JsonSerialize::json_serialize(&proved.events_commitment, out);
                out.push(',');
                norito::json::write_json_string("gas_policy_commitment", out);
                out.push(':');
                norito::json::JsonSerialize::json_serialize(&proved.gas_policy_commitment, out);
                out.push('}');
            }
            Executable::Batch(items) => {
                norito::json::write_json_string("Batch", out);
                out.push(':');
                norito::json::JsonSerialize::json_serialize(items, out);
            }
        }
        out.push('}');
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push('{')?;
            match self {
                Executable::Instructions(instructions) => {
                    out.push_str("\"Instructions\":")?;
                    norito::json::JsonSerialize::json_serialize_to(instructions, out)?;
                }
                Executable::ContractCall(invocation) => {
                    out.push_str("\"ContractCall\":")?;
                    norito::json::JsonSerialize::json_serialize_to(invocation, out)?;
                }
                Executable::Ivm(bytecode) => {
                    out.push_str("\"Ivm\":")?;
                    norito::json::JsonSerialize::json_serialize_to(bytecode, out)?;
                }
                Executable::IvmProved(proved) => {
                    out.push_str("\"IvmProved\":")?;
                    norito::json::JsonSerialize::json_serialize_to(proved, out)?;
                }
                Executable::Batch(items) => {
                    out.push_str("\"Batch\":")?;
                    norito::json::JsonSerialize::json_serialize_to(items, out)?;
                }
            }
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use norito::core::DecodeFromSlice as _;
    use std::any::Any;
    #[derive(Debug, Clone)]
    struct DummyInstruction(pub u32);
    impl crate::seal::Instruction for DummyInstruction {}
    impl Instruction for DummyInstruction {
        fn dyn_encode(&self) -> Vec<u8> {
            Vec::new()
        }
        fn dyn_write_frame(
            &self,
            _writer: &mut dyn std::io::Write,
        ) -> Result<(), norito::core::Error> {
            Err(norito::core::Error::LengthMismatch)
        }
        fn dyn_frame_len(&self) -> Result<usize, norito::core::Error> {
            Err(norito::core::Error::LengthMismatch)
        }
        fn dyn_write_pair(
            &self,
            _writer: &mut norito::core::Encoder<'_>,
            _wire_id: &str,
        ) -> Result<(), norito::core::Error> {
            Err(norito::core::Error::LengthMismatch)
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
    }
    // Provide a local conversion so tests can collect DummyInstruction
    // directly into an Executable without extra boilerplate.
    impl From<DummyInstruction> for InstructionBox {
        fn from(i: DummyInstruction) -> Self {
            Instruction::into_instruction_box(Box::new(i))
        }
    }
    #[test]
    fn ivm_bytecode_debug_repr_should_contain_just_len() {
        // IVM bytecode debug output should only show its length
        let ivm_bytecode = IvmBytecode::from_compiled(vec![0, 1, 2, 3, 4]);
        assert_eq!(format!("{ivm_bytecode:?}"), "IVM bytecode(len = 5)");
    }

    #[test]
    fn manual_executable_json_families_have_closed_bounds() {
        fn assert_bounded<T: norito::json::JsonSerialize>(value: &T) {
            let expected = norito::json::to_json(value).expect("serialize ordinary JSON");
            assert_eq!(
                norito::json::to_json_bounded(value, expected.len()).expect("exact JSON bound"),
                expected
            );
            assert_eq!(
                norito::json::to_json_bounded(value, expected.len() - 1),
                Err(norito::json::BoundedJsonError::BodyTooLarge)
            );
        }
        let arguments =
            ContractArgumentRecord::try_new(vec![0, 1, 2, 255]).expect("bounded argument record");
        assert_bounded(&arguments);
        let bytecode = IvmBytecode::from_compiled(vec![0, 1, 2, 3, 4]);
        assert_bounded(&bytecode);
        assert_bounded(&Executable::Ivm(bytecode.clone()));
        let proved = IvmProved {
            bytecode,
            overlay: Vec::<InstructionBox>::new().into(),
            events_commitment: iroha_crypto::Hash::new(b"events"),
            gas_policy_commitment: iroha_crypto::Hash::new(b"gas"),
        };
        assert_bounded(&proved);
        assert_bounded(&Executable::IvmProved(proved));
        let instruction = InstructionBox::from(crate::isi::Log::new(
            crate::Level::INFO,
            "bounded".to_owned(),
        ));
        assert_bounded(&ExecutableBatchItem::Instruction(instruction));
    }
    #[test]
    fn executable_kind_reports_gas_limit_requirement() {
        assert!(
            !Executable::from_iter(Vec::<InstructionBox>::new()).requires_transaction_gas_limit()
        );
        assert!(
            Executable::Ivm(IvmBytecode::from_compiled(vec![1])).requires_transaction_gas_limit()
        );
        assert!(
            Executable::ContractCall(ContractInvocation {
                contract_address: "irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh"
                    .parse()
                    .expect("contract address"),
                expected_code_hash: iroha_crypto::Hash::new(b"ping-contract-code"),
                entrypoint: "ping".to_owned(),
                arguments: None,
            })
            .requires_transaction_gas_limit()
        );
        let instruction_only_batch = Executable::Batch(
            vec![ExecutableBatchItem::Instruction(
                crate::isi::Log::new(crate::Level::INFO, "batched log".into()).into(),
            )]
            .into(),
        );
        assert!(!instruction_only_batch.requires_transaction_gas_limit());
        let mixed_batch = Executable::Batch(
            vec![ExecutableBatchItem::ContractCall(ContractInvocation {
                contract_address: "irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh"
                    .parse()
                    .expect("contract address"),
                expected_code_hash: iroha_crypto::Hash::new(b"batch-contract-code"),
                entrypoint: "run".to_owned(),
                arguments: None,
            })]
            .into(),
        );
        assert!(mixed_batch.requires_transaction_gas_limit());
    }
    #[test]
    fn executable_batch_preserves_wire_tags_and_order() {
        let first: InstructionBox = crate::isi::Log::new(crate::Level::INFO, "first".into()).into();
        let last: InstructionBox = crate::isi::Log::new(crate::Level::INFO, "last".into()).into();
        let invocation = ContractInvocation {
            contract_address: "irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh"
                .parse()
                .expect("contract address"),
            expected_code_hash: iroha_crypto::Hash::new(b"ordered-batch-contract"),
            entrypoint: "run".to_owned(),
            arguments: None,
        };
        let batch = Executable::Batch(
            vec![
                ExecutableBatchItem::Instruction(first),
                ExecutableBatchItem::ContractCall(invocation),
                ExecutableBatchItem::Instruction(last),
            ]
            .into(),
        );
        let encoded = batch.encode();
        assert_eq!(&encoded[..4], &4_u32.to_le_bytes());
        let mut input = encoded.as_slice();
        let decoded = Executable::decode(&mut input).expect("decode mixed executable batch");
        assert_eq!(decoded, batch);
        assert!(input.is_empty());
        assert_eq!(decoded.instruction_count(), 2);
        let Executable::Batch(items) = decoded else {
            panic!("expected mixed executable batch");
        };
        assert!(matches!(items[0], ExecutableBatchItem::Instruction(_)));
        assert!(matches!(items[1], ExecutableBatchItem::ContractCall(_)));
        assert!(matches!(items[2], ExecutableBatchItem::Instruction(_)));
        assert_eq!(&items[0].encode()[..4], &0_u32.to_le_bytes());
        assert_eq!(&items[1].encode()[..4], &1_u32.to_le_bytes());
        assert_eq!(&items[2].encode()[..4], &0_u32.to_le_bytes());
        assert_eq!(batch.explicit_instructions().count(), 2);
    }
    #[test]
    fn contract_argument_record_rejects_oversized_length_before_allocation() {
        assert!(
            ContractArgumentRecord::try_new(vec![0; MAX_CONTRACT_ARGUMENT_RECORD_BYTES + 1])
                .is_err()
        );
        let declared = u64::try_from(MAX_CONTRACT_ARGUMENT_RECORD_BYTES + 1)
            .expect("argument bound fits u64")
            .to_le_bytes();
        assert!(ContractArgumentRecord::decode_from_slice(&declared).is_err());
        let mut truncated = 4_u64.to_le_bytes().to_vec();
        truncated.extend_from_slice(&[1, 2]);
        assert!(ContractArgumentRecord::decode_from_slice(&truncated).is_err());
    }
    #[test]
    fn contract_argument_record_accepts_and_roundtrips_the_exact_wire_cap() {
        let record =
            ContractArgumentRecord::try_new(vec![0xA5; MAX_CONTRACT_ARGUMENT_RECORD_BYTES])
                .expect("the signed argument-record cap is inclusive");
        assert_eq!(record.as_bytes().len(), MAX_CONTRACT_ARGUMENT_RECORD_BYTES);
        let encoded = norito::to_bytes(&record).expect("encode exact-cap argument record");
        let decoded = norito::decode_from_bytes::<ContractArgumentRecord>(&encoded)
            .expect("decode exact-cap argument record");
        assert_eq!(decoded, record);
        assert_eq!(decoded.as_bytes().len(), MAX_CONTRACT_ARGUMENT_RECORD_BYTES);
    }
    #[test]
    fn contract_argument_record_uses_the_bounded_vec_wire_layout() {
        let record =
            ContractArgumentRecord::try_new(vec![1, 2, 3, 4]).expect("bounded argument record");
        let encoded = record.encode();
        assert_eq!(&encoded[..8], &4_u64.to_le_bytes());
        assert_eq!(&encoded[8..], &[1, 2, 3, 4]);
        let mut input = encoded.as_slice();
        assert_eq!(
            ContractArgumentRecord::decode(&mut input).expect("decode bounded argument record"),
            record
        );
    }
    #[test]
    fn containing_contract_invocation_uses_fallible_bounded_decode() {
        let record_bytes = [1_u8, 2, 3, 4];
        let invocation = ContractInvocation {
            contract_address: "irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh"
                .parse()
                .expect("contract address"),
            expected_code_hash: iroha_crypto::Hash::new(b"call-contract-code"),
            entrypoint: "call".to_owned(),
            arguments: Some(
                ContractArgumentRecord::try_new(record_bytes.to_vec())
                    .expect("bounded argument fixture"),
            ),
        };
        let mut encoded = norito::to_bytes(&invocation).expect("encode invocation");
        assert_eq!(
            norito::decode_from_bytes::<ContractInvocation>(&encoded)
                .expect("decode contract invocation"),
            invocation,
            "the expected code hash must round-trip in the canonical invocation wire layout"
        );
        let mut needle = 4_u64.to_le_bytes().to_vec();
        needle.extend_from_slice(&record_bytes);
        let count_offset = encoded
            .windows(needle.len())
            .position(|window| window == needle)
            .expect("embedded argument sequence");
        encoded[count_offset..count_offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        let decoded =
            std::panic::catch_unwind(|| norito::decode_from_bytes::<ContractInvocation>(&encoded));
        assert!(
            decoded.is_ok(),
            "hostile lengths must not reach deserialize panic"
        );
        assert!(
            decoded.expect("decode did not panic").is_err(),
            "derived containing-type decode must call the bounded fallible decoder"
        );
    }
    #[test]
    fn transaction_gas_limit_reads_signed_fee_intent() {
        let without_limit = FeePaymentIntent::authority(Vec::new(), None);
        assert_eq!(parse_transaction_gas_limit(&without_limit), None);
        let with_limit = FeePaymentIntent::authority(
            Vec::new(),
            Some(std::num::NonZeroU64::new(42).expect("nonzero gas limit")),
        );
        assert_eq!(parse_transaction_gas_limit(&with_limit), Some(42));
        assert_eq!(
            require_transaction_gas_limit(&with_limit).expect("gas_limit should be required"),
            42
        );
    }
    #[test]
    fn transaction_gas_limit_requires_explicit_signed_value() {
        let intent = FeePaymentIntent::authority(Vec::new(), None);
        assert_eq!(
            require_transaction_gas_limit(&intent),
            Err(TransactionGasLimitError::Missing)
        );
        assert_eq!(
            TransactionGasLimitError::Missing.to_string(),
            "missing gas limit in fee payment intent"
        );
    }
    #[test]
    fn executable_from_iter_should_preserve_order() {
        let executable = Executable::from_iter(vec![
            DummyInstruction(1),
            DummyInstruction(2),
            DummyInstruction(3),
        ]);
        let Executable::Instructions(instructions) = executable else {
            panic!("expected instructions variant");
        };
        let ids: Vec<u32> = instructions
            .into_iter()
            .map(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<DummyInstruction>()
                    .unwrap()
                    .0
            })
            .collect();
        assert_eq!(ids, vec![1, 2, 3]);
    }
    #[test]
    fn executable_instructions_decode_from_slice_roundtrips() {
        let instruction: InstructionBox =
            crate::isi::Log::new(crate::Level::INFO, "slice executable".into()).into();
        let executable = Executable::from_iter([instruction]);
        let bytes = norito::codec::encode_adaptive(&executable);
        let (decoded, used) =
            <Executable as norito::core::DecodeFromSlice>::decode_from_slice(&bytes)
                .expect("decode executable instructions");
        assert_eq!(used, bytes.len());
        assert_eq!(decoded, executable);
    }

    #[test]
    fn ivm_bytecode_should_serialize_and_deserialize() {
        let bytecode = IvmBytecode::from_compiled(vec![1, 2, 3, 4, 5]);
        let json = norito::json::to_json(&bytecode).expect("serialize");
        let deserialized: IvmBytecode = norito::json::from_str(&json).expect("deserialize");
        assert_eq!(bytecode, deserialized);
    }

    #[test]
    fn executable_json_roundtrip_for_all_variants() {
        let instruction: InstructionBox =
            crate::isi::Log::new(crate::Level::INFO, "json executable".into()).into();
        let executable = Executable::from_iter([instruction]);
        let json = norito::json::to_json(&executable).expect("serialize instructions");
        let deserialized: Executable = norito::json::from_str(&json).expect("deserialize");
        assert_eq!(executable, deserialized);
        let ivm_executable = Executable::Ivm(IvmBytecode::from_compiled(vec![9, 8, 7]));
        let json = norito::json::to_json(&ivm_executable).expect("serialize ivm");
        let deserialized: Executable = norito::json::from_str(&json).expect("deserialize ivm");
        assert_eq!(ivm_executable, deserialized);
        let contract_call_executable = Executable::ContractCall(ContractInvocation {
            contract_address: "irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh"
                .parse()
                .expect("contract address"),
            expected_code_hash: iroha_crypto::Hash::new(b"contribute-contract-code"),
            entrypoint: "contribute".to_owned(),
            arguments: Some(
                ContractArgumentRecord::try_new(vec![0x4b, 0x4f, 0x54, 0x4f])
                    .expect("bounded argument fixture"),
            ),
        });
        let json =
            norito::json::to_json(&contract_call_executable).expect("serialize contract call");
        let deserialized: Executable =
            norito::json::from_str(&json).expect("deserialize contract call");
        assert_eq!(contract_call_executable, deserialized);
        let mut missing_hash: norito::json::Value =
            norito::json::from_str(&json).expect("parse contract call JSON value");
        missing_hash
            .get_mut("ContractCall")
            .and_then(norito::json::Value::as_object_mut)
            .expect("contract call JSON object")
            .remove("expected_code_hash");
        assert!(
            norito::json::from_value::<Executable>(missing_hash).is_err(),
            "first-release JSON must not decode a ContractInvocation without expected_code_hash"
        );
        let proved_executable = Executable::IvmProved(IvmProved {
            bytecode: IvmBytecode::from_compiled(vec![7, 7, 7]),
            overlay: Vec::<InstructionBox>::new().into(),
            events_commitment: iroha_crypto::Hash::new(b"events"),
            gas_policy_commitment: iroha_crypto::Hash::new(b"gas-policy"),
        });
        let json = norito::json::to_json(&proved_executable).expect("serialize proved");
        let deserialized: Executable = norito::json::from_str(&json).expect("deserialize proved");
        assert_eq!(proved_executable, deserialized);
        let batch_executable = Executable::Batch(
            vec![
                ExecutableBatchItem::Instruction(
                    crate::isi::Log::new(crate::Level::INFO, "before".into()).into(),
                ),
                ExecutableBatchItem::ContractCall(ContractInvocation {
                    contract_address:
                        "irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh"
                            .parse()
                            .expect("contract address"),
                    expected_code_hash: iroha_crypto::Hash::new(b"json-batch-contract"),
                    entrypoint: "run".to_owned(),
                    arguments: None,
                }),
            ]
            .into(),
        );
        let json = norito::json::to_json(&batch_executable).expect("serialize batch");
        assert!(json.contains("\"Batch\""));
        assert!(json.contains("\"Instruction\""));
        assert!(json.contains("\"ContractCall\""));
        let deserialized: Executable = norito::json::from_str(&json).expect("deserialize batch");
        assert_eq!(batch_executable, deserialized);
    }
}

#[cfg(test)]
mod checked_container_cleanup_tests {
    //! Original owning writer refusal and nested-depth controls.
    use super::*;
    use crate::checked_container_refusal_controls::audit;

    #[test]
    fn original_batch_item_checked_container_retains_bytes_errors_and_depth() {
        audit(&ExecutableBatchItem::Instruction(
            crate::isi::Log::new(crate::Level::INFO, "original".into()).into(),
        ));
        audit(&ExecutableBatchItem::ContractCall(ContractInvocation {
            contract_address: "irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh"
                .parse()
                .unwrap(),
            expected_code_hash: iroha_crypto::Hash::new(b"original contract"),
            entrypoint: "original".into(),
            arguments: Some(ContractArgumentRecord::try_new(vec![1, 2, 255]).unwrap()),
        }));
    }

    #[test]
    fn original_ivm_proved_checked_container_retains_overlay_and_depth() {
        let value = IvmProved {
            bytecode: IvmBytecode::from_compiled(vec![0, 1, 255]),
            overlay: vec![crate::isi::Log::new(crate::Level::INFO, "overlay".into()).into()].into(),
            events_commitment: iroha_crypto::Hash::new(b"original events"),
            gas_policy_commitment: iroha_crypto::Hash::new(b"original gas"),
        };
        let bytecode = value.bytecode.0.as_ptr();
        let overlay = value.overlay.as_ptr();
        audit(&value);
        assert_eq!(value.bytecode.0.as_ptr(), bytecode);
        assert_eq!(value.overlay.as_ptr(), overlay);
    }

    #[test]
    fn original_executable_checked_container_retains_every_legal_variant_and_depth() {
        audit(&Executable::Instructions(
            vec![crate::isi::Log::new(crate::Level::INFO, "original".into()).into()].into(),
        ));
        audit(&Executable::ContractCall(ContractInvocation {
            contract_address: "irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh"
                .parse()
                .unwrap(),
            expected_code_hash: iroha_crypto::Hash::new(b"original contract"),
            entrypoint: "original".into(),
            arguments: Some(ContractArgumentRecord::try_new(vec![1, 2, 255]).unwrap()),
        }));
        audit(&Executable::Ivm(IvmBytecode::from_compiled(vec![
            0, 1, 255,
        ])));
        audit(&Executable::IvmProved(IvmProved {
            bytecode: IvmBytecode::from_compiled(vec![0, 1, 255]),
            overlay: vec![crate::isi::Log::new(crate::Level::INFO, "overlay".into()).into()].into(),
            events_commitment: iroha_crypto::Hash::new(b"original events"),
            gas_policy_commitment: iroha_crypto::Hash::new(b"original gas"),
        }));
        audit(&Executable::Batch(
            vec![ExecutableBatchItem::ContractCall(ContractInvocation {
                contract_address: "irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh"
                    .parse()
                    .unwrap(),
                expected_code_hash: iroha_crypto::Hash::new(b"original contract"),
                entrypoint: "original".into(),
                arguments: Some(ContractArgumentRecord::try_new(vec![1, 2, 255]).unwrap()),
            })]
            .into(),
        ));
    }
}
