//! Borrowed native history projections; no instruction or metadata graph is copied for JSON.
//!
//! Selected rows retain their original authenticated block and stable native indices. The sole
//! instruction representation is the model's canonical `InstructionBox` JSON frame, with its
//! native registry identifier and a hash of that same frame. The checked model writer streams
//! directly into the request's finite destination; it never constructs an unframed hex payload
//! or a second parsed JSON tree.

use std::{fmt, time::Duration};

use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    account::AccountId,
    block::{BlockHeader, SharedSignedBlock},
    isi::InstructionBox,
    transaction::{
        SignedTransaction, TransactionEntrypoint, TransactionResult,
        error::TransactionRejectionReason, executable::Executable,
    },
};
use iroha_model_base::metadata::Metadata;
use norito::json::{self, BoundedJsonError, FastJsonWrite, JsonSerialize, JsonWriteSink};
use sha2::{Digest as _, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    explorer::ExplorerHistoryCursorMeta, json_macros::JsonSerialize as DeriveJsonSerialize,
};

/// UTC date text written into the final JSON sink with fixed native formatter scratch.
#[derive(Clone, Copy, Debug)]
pub struct HistoryTime(pub(crate) Duration);
impl FastJsonWrite for HistoryTime {
    fn write_json(&self, out: &mut String) {
        json::write_json_unbounded(self, out);
    }
    fn write_json_to(&self, out: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        struct DateWriter<'a>(&'a mut dyn JsonWriteSink);
        impl std::io::Write for DateWriter<'_> {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                let text = std::str::from_utf8(bytes).map_err(std::io::Error::other)?;
                self.0.push_str(text).map_err(std::io::Error::other)?;
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let nanos = i128::from(self.0.as_secs())
            .saturating_mul(1_000_000_000)
            .saturating_add(i128::from(self.0.subsec_nanos()));
        let date = OffsetDateTime::from_unix_timestamp_nanos(nanos)
            .map_err(|_| BoundedJsonError::LengthMismatch)?;
        out.push('"')?;
        date.format_into(&mut DateWriter(out), &Rfc3339)
            .map_err(|_| BoundedJsonError::LengthMismatch)?;
        out.push('"')
    }
}

#[derive(Clone, Copy)]
struct HexBytes<'a>(&'a [u8]);
impl FastJsonWrite for HexBytes<'_> {
    fn write_json(&self, out: &mut String) {
        json::write_json_unbounded(self, out);
    }
    fn write_json_to(&self, out: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        out.push('"')?;
        for byte in self.0 {
            let pair = [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 15)]];
            out.push_str(std::str::from_utf8(&pair).expect("literal hex alphabet"))?;
        }
        out.push('"')
    }
}

/// Compact selector over one authenticated native Network entrypoint.
#[derive(Clone, Debug)]
pub struct HistoryTransactionRow {
    pub(crate) block: SharedSignedBlock,
    pub(crate) entrypoint_index: usize,
    pub(crate) entrypoint_hash: HashOf<TransactionEntrypoint>,
}
impl HistoryTransactionRow {
    fn source(&self) -> Result<(&SignedTransaction, &TransactionResult), BoundedJsonError> {
        let source = self
            .block
            .network_entrypoint_at(self.entrypoint_index)
            .ok_or(BoundedJsonError::LengthMismatch)?;
        let transaction = match source {
            TransactionEntrypoint::External(transaction) => transaction,
            TransactionEntrypoint::SealedReveal(reveal) => reveal.signed_transaction(),
            TransactionEntrypoint::SealedCommitment(_)
            | TransactionEntrypoint::AnonymousBallot(_) => {
                return Err(BoundedJsonError::LengthMismatch);
            }
        };
        let index =
            u32::try_from(self.entrypoint_index).map_err(|_| BoundedJsonError::LengthMismatch)?;
        let (_, output) = self
            .block
            .network_output_at(index)
            .ok_or(BoundedJsonError::LengthMismatch)?;
        Ok((transaction, &output.result))
    }
    fn projection(&self) -> Result<TransactionProjection<'_>, BoundedJsonError> {
        let (transaction, result) = self.source()?;
        Ok(TransactionProjection {
            authority: transaction.authority(),
            hash: &self.entrypoint_hash,
            block: self.block.header().height().get(),
            created_at: HistoryTime(transaction.creation_time()),
            executable: executable_label(transaction.instructions()),
            status: status(result),
        })
    }
}
#[derive(DeriveJsonSerialize)]
struct TransactionProjection<'a> {
    authority: &'a AccountId,
    hash: &'a HashOf<TransactionEntrypoint>,
    block: u64,
    created_at: HistoryTime,
    executable: &'static str,
    status: &'static str,
}
impl FastJsonWrite for HistoryTransactionRow {
    fn write_json(&self, out: &mut String) {
        json::write_json_unbounded(self, out);
    }
    fn write_json_to(&self, out: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        self.projection()?.json_serialize_to(out)
    }
}

/// A detail view borrows large metadata, invocation arguments and rejection evidence.
#[derive(Debug)]
pub struct HistoryTransactionDetail(pub(crate) HistoryTransactionRow);
#[derive(DeriveJsonSerialize)]
struct TransactionDetailProjection<'a> {
    authority: &'a AccountId,
    hash: &'a HashOf<TransactionEntrypoint>,
    block: u64,
    created_at: HistoryTime,
    executable: &'static str,
    status: &'static str,
    rejection_reason: Option<RejectionProjection<'a>>,
    executable_payload: ExecutableProjection<'a>,
    metadata: &'a Metadata,
    nonce: Option<u64>,
    signature: HexBytes<'a>,
    time_to_live: Option<DurationProjection>,
}
#[derive(DeriveJsonSerialize)]
struct DurationProjection {
    ms: u64,
}
#[derive(DeriveJsonSerialize)]
struct RejectionProjection<'a> {
    /// Sole model-owned canonical JSON representation of the original native reason.
    reason: RejectionReason<'a>,
    message: RejectionMessage<'a>,
}
/// Borrow the model's sole canonical reason codec without copying its graph.
struct RejectionReason<'a>(&'a TransactionRejectionReason);
impl FastJsonWrite for RejectionReason<'_> {
    fn write_json(&self, out: &mut String) {
        json::write_json_unbounded(self, out);
    }
    fn write_json_to(&self, out: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        self.0.json_serialize_to(out)
    }
}
struct RejectionMessage<'a>(&'a TransactionRejectionReason);
impl fmt::Display for RejectionMessage<'_> {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        use iroha_data_model::{ValidationFail, isi::error::InstructionExecutionError};
        match self.0 {
            TransactionRejectionReason::Validation(fail) => {
                out.write_str("Validation failed: ")?;
                match fail {
                    ValidationFail::InstructionFailed(error) => {
                        out.write_str("Instruction execution failed: ")?;
                        match error {
                            InstructionExecutionError::Find(error) => fmt::Display::fmt(error, out),
                            InstructionExecutionError::Repetition(error) => {
                                fmt::Display::fmt(error, out)
                            }
                            error => fmt::Display::fmt(error, out),
                        }
                    }
                    fail => fmt::Display::fmt(fail, out),
                }
            }
            reason => {
                fmt::Display::fmt(reason, out)?;
                let mut source = std::error::Error::source(reason);
                while let Some(error) = source {
                    write!(out, ": {error}")?;
                    source = error.source();
                }
                Ok(())
            }
        }
    }
}
impl FastJsonWrite for RejectionMessage<'_> {
    fn write_json(&self, out: &mut String) {
        json::write_json_unbounded(self, out);
    }
    fn write_json_to(&self, out: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        json::write_json_display_to(self, out)
    }
}
impl FastJsonWrite for HistoryTransactionDetail {
    fn write_json(&self, out: &mut String) {
        json::write_json_unbounded(self, out);
    }
    fn write_json_to(&self, out: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        let (transaction, result) = self.0.source()?;
        TransactionDetailProjection {
            authority: transaction.authority(),
            hash: &self.0.entrypoint_hash,
            block: self.0.block.header().height().get(),
            created_at: HistoryTime(transaction.creation_time()),
            executable: executable_label(transaction.instructions()),
            status: status(result),
            rejection_reason: result.as_ref().err().map(|reason| RejectionProjection {
                reason: RejectionReason(reason),
                message: RejectionMessage(reason),
            }),
            executable_payload: ExecutableProjection(transaction.instructions()),
            metadata: transaction.metadata(),
            nonce: transaction.nonce().map(|value| u64::from(value.get())),
            signature: HexBytes(transaction.signature().payload().payload()),
            time_to_live: transaction
                .time_to_live()
                .map(|duration| {
                    u64::try_from(duration.as_millis())
                        .map(|ms| DurationProjection { ms })
                        .map_err(|_| BoundedJsonError::LengthMismatch)
                })
                .transpose()?,
        }
        .json_serialize_to(out)
    }
}

struct ExecutableProjection<'a>(&'a Executable);
impl FastJsonWrite for ExecutableProjection<'_> {
    fn write_json(&self, out: &mut String) {
        json::write_json_unbounded(self, out);
    }
    fn write_json_to(&self, out: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        #[derive(DeriveJsonSerialize)]
        struct Instructions {
            instruction_count: usize,
        }
        #[derive(DeriveJsonSerialize)]
        struct Bytecode {
            bytecode_len: usize,
        }
        #[derive(DeriveJsonSerialize)]
        struct Proved<'a> {
            bytecode_len: usize,
            overlay_count: usize,
            events_commitment: &'a Hash,
            gas_policy_commitment: &'a Hash,
        }
        #[derive(DeriveJsonSerialize)]
        #[expect(
            clippy::struct_field_names,
            reason = "Count suffixes distinguish aggregate cardinalities in the public JSON projection."
        )]
        struct Batch {
            item_count: usize,
            instruction_count: usize,
            contract_call_count: usize,
        }
        match self.0 {
            Executable::Instructions(values) => Instructions {
                instruction_count: values.len(),
            }
            .json_serialize_to(out),
            Executable::ContractCall(invocation) => invocation.json_serialize_to(out),
            Executable::Ivm(bytecode) => Bytecode {
                bytecode_len: bytecode.size_bytes(),
            }
            .json_serialize_to(out),
            Executable::IvmProved(proved) => Proved {
                bytecode_len: proved.bytecode.size_bytes(),
                overlay_count: proved.overlay.len(),
                events_commitment: &proved.events_commitment,
                gas_policy_commitment: &proved.gas_policy_commitment,
            }
            .json_serialize_to(out),
            Executable::Batch(items) => {
                let instruction_count = items
                    .iter()
                    .filter(|item| {
                        matches!(
                            item,
                            iroha_data_model::transaction::ExecutableBatchItem::Instruction(_)
                        )
                    })
                    .count();
                Batch {
                    item_count: items.len(),
                    instruction_count,
                    contract_call_count: items.len() - instruction_count,
                }
                .json_serialize_to(out)
            }
        }
    }
}
fn executable_label(executable: &Executable) -> &'static str {
    match executable {
        Executable::Instructions(_) => "Instructions",
        Executable::ContractCall(_) => "ContractCall",
        Executable::Ivm(_) => "Ivm",
        Executable::IvmProved(_) => "IvmProved",
        Executable::Batch(_) => "Batch",
    }
}
fn status(result: &TransactionResult) -> &'static str {
    if result.as_ref().is_ok() {
        "Committed"
    } else {
        "Rejected"
    }
}

/// Compact native instruction selector; only its final response contains the encoded frame.
#[derive(Clone, Debug)]
pub struct HistoryInstructionRow {
    pub(crate) transaction: HistoryTransactionRow,
    pub(crate) instruction_index: u32,
}
#[derive(DeriveJsonSerialize)]
struct InstructionProjection<'a> {
    authority: &'a AccountId,
    created_at: HistoryTime,
    kind: &'a str,
    #[norito(rename = "box")]
    instruction: InstructionProjectionBox<'a>,
    transaction_hash: &'a HashOf<TransactionEntrypoint>,
    transaction_status: &'static str,
    block: u64,
    index: u32,
}
#[derive(DeriveJsonSerialize)]
struct InstructionProjectionBox<'a> {
    wire_id: &'a str,
    framed_sha256: FrameHash,
    instruction: &'a InstructionBox,
}
struct FrameHash([u8; 32]);
impl FrameHash {
    fn instruction(instruction: &InstructionBox) -> Result<Self, BoundedJsonError> {
        struct HashWriter(Sha256);
        impl std::io::Write for HashWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.update(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut hash = HashWriter(Sha256::new());
        norito::core::write_canonical_to_writer(instruction, &mut hash)
            .map_err(|_| BoundedJsonError::LengthMismatch)?;
        Ok(Self(hash.0.finalize().into()))
    }
}
impl FastJsonWrite for FrameHash {
    fn write_json(&self, out: &mut String) {
        json::write_json_unbounded(self, out);
    }
    fn write_json_to(&self, out: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        HexBytes(&self.0).write_json_to(out)
    }
}
impl FastJsonWrite for HistoryInstructionRow {
    fn write_json(&self, out: &mut String) {
        json::write_json_unbounded(self, out);
    }
    fn write_json_to(&self, out: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        let (transaction, result) = self.transaction.source()?;
        let instruction = transaction
            .instructions()
            .explicit_instructions()
            .nth(self.instruction_index as usize)
            .ok_or(BoundedJsonError::LengthMismatch)?;
        let wire_id = iroha_data_model::isi::instruction_wire_id(instruction)
            .ok_or(BoundedJsonError::Unsupported)?;
        let kind = crate::explorer::instruction_kind(instruction);
        let kind = if kind == crate::explorer::ExplorerInstructionKind::Custom {
            wire_id.rsplit("::").next().unwrap_or(wire_id)
        } else {
            kind.as_str()
        };
        InstructionProjection {
            authority: transaction.authority(),
            created_at: HistoryTime(transaction.creation_time()),
            kind,
            instruction: InstructionProjectionBox {
                wire_id,
                framed_sha256: FrameHash::instruction(instruction)?,
                instruction,
            },
            transaction_hash: &self.transaction.entrypoint_hash,
            transaction_status: status(result),
            block: self.transaction.block.header().height().get(),
            index: self.instruction_index,
        }
        .json_serialize_to(out)
    }
}

/// A selected page holds compact source selectors and one bounded continuation.
#[derive(DeriveJsonSerialize)]
pub struct HistoryPage<T> {
    pub(crate) pagination: ExplorerHistoryCursorMeta,
    pub(crate) items: Vec<T>,
}
/// Latest reads add one fixed UTC sample without copying the selected native sources.
#[derive(DeriveJsonSerialize)]
pub struct LatestHistoryPage<T> {
    pub(crate) sampled_at: HistoryTime,
    pub(crate) pagination: ExplorerHistoryCursorMeta,
    pub(crate) items: Vec<T>,
}

/// Block summaries own only fixed identity/count values, never an entrypoint-index vector.
#[derive(Debug, DeriveJsonSerialize)]
pub struct HistoryBlockRow {
    pub(crate) hash: HashOf<BlockHeader>,
    pub(crate) height: u64,
    pub(crate) created_at: HistoryBlockTime,
    pub(crate) prev_block_hash: Option<HashOf<BlockHeader>>,
    pub(crate) transactions_hash:
        Option<iroha_crypto::HashOf<iroha_crypto::MerkleTree<TransactionEntrypoint>>>,
    pub(crate) transactions_rejected: u32,
    pub(crate) transactions_total: u32,
}

impl HistoryBlockRow {
    /// Report only authenticated committed-journal identity when its body is absent.
    #[cfg(test)]
    pub(crate) fn from_hash_only(
        height: u64,
        hash: HashOf<BlockHeader>,
        prev_block_hash: Option<HashOf<BlockHeader>>,
    ) -> Self {
        Self {
            hash,
            height,
            created_at: HistoryBlockTime(None),
            prev_block_hash,
            transactions_hash: None,
            transactions_rejected: 0,
            transactions_total: 0,
        }
    }
    /// Project only fixed native values; visibility never materializes an index collection.
    pub(crate) fn from_block(
        block: &iroha_data_model::block::SignedBlock,
        mut visible: impl FnMut(usize) -> bool,
    ) -> Self {
        let header = block.header();
        let mut total = 0_u32;
        let mut rejected = 0_u32;
        for index in 0..block.network_entrypoint_count() {
            if !visible(index) {
                continue;
            }
            total = total.saturating_add(1);
            if block
                .network_output_at(u32::try_from(index).unwrap_or(u32::MAX))
                .is_some_and(|(_, output)| output.result.is_err())
            {
                rejected = rejected.saturating_add(1);
            }
        }
        Self {
            hash: block.hash(),
            height: header.height().get(),
            created_at: HistoryBlockTime(Some(header.creation_time())),
            prev_block_hash: header.prev_block_hash(),
            transactions_hash: header.merkle_root(),
            transactions_rejected: rejected,
            transactions_total: total,
        }
    }
}

/// Canonical summary time keeps unavailable journal-only timestamps explicit as empty text.
#[derive(Debug)]
pub struct HistoryBlockTime(pub(crate) Option<Duration>);
impl FastJsonWrite for HistoryBlockTime {
    fn write_json(&self, out: &mut String) {
        json::write_json_unbounded(self, out);
    }
    fn write_json_to(&self, out: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        match self.0 {
            Some(time) => HistoryTime(time).write_json_to(out),
            None => out.push_str("\"\""),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_rejection_borrows_the_checked_native_reason_codec() {
        let reason =
            TransactionRejectionReason::Validation(iroha_data_model::ValidationFail::TooComplex);
        let projected = RejectionProjection {
            reason: RejectionReason(&reason),
            message: RejectionMessage(&reason),
        };
        let body = json::to_json_bounded_boxed(&projected, 4096).unwrap();
        let object: json::Value = json::from_slice(&body).unwrap();
        let decoded: TransactionRejectionReason =
            json::from_value(object.get("reason").unwrap().clone()).unwrap();
        assert_eq!(decoded, reason);
        assert!(
            object
                .get("message")
                .unwrap()
                .as_str()
                .unwrap()
                .contains("Operation is too complex")
        );
        assert!(json::to_json_bounded_boxed(&projected, body.len() - 1).is_err());
    }

    #[test]
    fn history_instruction_has_one_native_frame_and_exact_frame_digest() {
        let instruction: InstructionBox = iroha_data_model::isi::Log::new(
            iroha_data_model::Level::INFO,
            "native history instruction".to_owned(),
        )
        .into();
        let wire_id = iroha_data_model::isi::instruction_wire_id(&instruction).unwrap();
        let frame = norito::encode_canonical(&instruction).unwrap();
        let digest: [u8; 32] = Sha256::digest(&frame).into();
        let payload = InstructionProjectionBox {
            wire_id,
            framed_sha256: FrameHash::instruction(&instruction).unwrap(),
            instruction: &instruction,
        };
        let body = json::to_json_bounded_boxed(&payload, frame.len() * 2 + 512).unwrap();
        let object: json::Value = json::from_slice(&body).unwrap();
        assert_eq!(object.as_object().unwrap().len(), 3);
        assert!(object.get("encoded").is_none());
        assert!(object.get("json").is_none());
        let decoded: InstructionBox =
            json::from_value(object.get("instruction").unwrap().clone()).unwrap();
        assert_eq!(decoded, instruction);
        let expected = json::to_json_bounded_boxed(&HexBytes(&digest), 66).unwrap();
        assert_eq!(
            object.get("framed_sha256").unwrap(),
            &json::from_slice::<json::Value>(&expected).unwrap()
        );
    }

    #[test]
    fn history_instruction_large_native_payload_refuses_the_counted_destination() {
        let instruction: InstructionBox =
            iroha_data_model::isi::Log::new(iroha_data_model::Level::INFO, "x".repeat(512 * 1024))
                .into();
        let payload = InstructionProjectionBox {
            wire_id: iroha_data_model::isi::instruction_wire_id(&instruction).unwrap(),
            framed_sha256: FrameHash::instruction(&instruction).unwrap(),
            instruction: &instruction,
        };
        assert!(matches!(
            json::to_json_bounded_boxed(&payload, 4096),
            Err(BoundedJsonError::BodyTooLarge)
        ));
        let context = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
            4096, 4096, 4096, 4096, 32,
        ));
        assert!(
            context
                .with(|| json::to_json_bounded_boxed(&payload, 4096))
                .is_err()
        );
        assert_eq!(
            context.consumed_allocated_bytes(),
            0,
            "counting must refuse before body allocation"
        );
    }

    #[test]
    fn history_timestamp_streams_the_native_utc_formatter_without_an_owned_string() {
        let duration = Duration::from_millis(1_735_689_600_123);
        let encoded = json::to_json_bounded_boxed(&HistoryTime(duration), 64).unwrap();
        let expected = OffsetDateTime::from_unix_timestamp_nanos(
            i128::from(duration.as_millis() as u64) * 1_000_000,
        )
        .unwrap()
        .format(&Rfc3339)
        .unwrap();
        assert_eq!(json::from_slice::<String>(&encoded).unwrap(), expected);
        assert!(json::to_json_bounded_boxed(&HistoryTime(duration), 8).is_err());
    }
}
