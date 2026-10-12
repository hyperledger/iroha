//! Pure transaction-artifact preparation and inspection for Torii MCP.
//!
//! These helpers canonicalize unsigned transaction payloads and inspect complete
//! signed transaction wires. They deliberately have no state, queue, transport,
//! or signing dependencies: callers retain private keys behind their own signing
//! boundary and submit only a complete caller-signed transaction through Torii's
//! existing transaction route.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use iroha_crypto::Hash;
use iroha_data_model::{
    NetworkId,
    isi::instruction_wire_id,
    transaction::{
        Executable, ExecutableBatchItem, FeePaymentIntent, SignedTransaction, TransactionBuilder,
        TransactionDomain, TransactionPayload, signed::TransactionSignatureError,
    },
};
use iroha_version::codec::DecodeVersioned as _;
use norito::json::{Map, Value};

/// Maximum number of stable instruction wire identifiers returned in one
/// structural summary.
pub(crate) const MAX_SUMMARY_INSTRUCTION_WIRE_IDS: usize = 64;

/// Exact artifact type selected for inspection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TransactionArtifactKind {
    /// Canonical unsigned bytes emitted by [`TransactionBuilder::encode_payload`].
    TransactionPayload,
    /// Canonical fixed-V1 bytes emitted by [`SignedTransaction::encode_wire_v1`].
    SignedTransaction,
}

impl TransactionArtifactKind {
    /// Stable MCP-facing discriminator.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::TransactionPayload => "transaction_payload",
            Self::SignedTransaction => "signed_transaction",
        }
    }
}

/// Closed failures from pure transaction-artifact handling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TransactionArtifactError {
    /// An ordinary external-signing flow received the genesis-only domain.
    GenesisDomain,
    /// The payload binds a network other than the Torii network being served.
    NetworkMismatch {
        /// Network expected by the serving Torii instance.
        expected: NetworkId,
        /// Network committed by the supplied transaction payload.
        actual: NetworkId,
    },
    /// The unsigned payload is malformed, invalid, or not canonical.
    InvalidTransactionPayload(String),
    /// Canonical re-encoding changed the unsigned payload bytes.
    NonCanonicalTransactionPayload,
    /// The complete signed transaction wire is malformed or not fixed-V1 canonical.
    InvalidSignedTransaction(String),
    /// Canonical re-encoding changed the complete signed transaction bytes.
    NonCanonicalSignedTransaction,
}

impl fmt::Display for TransactionArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GenesisDomain => formatter.write_str(
                "genesis transaction payloads are not accepted by ordinary external-signing flows",
            ),
            Self::NetworkMismatch { expected, actual } => write!(
                formatter,
                "transaction payload network mismatch: expected {expected}, got {actual}"
            ),
            Self::InvalidTransactionPayload(error) => {
                write!(formatter, "invalid canonical transaction payload: {error}")
            }
            Self::NonCanonicalTransactionPayload => {
                formatter.write_str("transaction payload changed during canonical re-encoding")
            }
            Self::InvalidSignedTransaction(error) => {
                write!(formatter, "invalid canonical signed transaction: {error}")
            }
            Self::NonCanonicalSignedTransaction => {
                formatter.write_str("signed transaction changed during canonical re-encoding")
            }
        }
    }
}

impl std::error::Error for TransactionArtifactError {}

/// Bounded, content-minimizing description of a transaction payload.
///
/// Metadata values, proof bytes, contract arguments, IVM bytecode, instruction
/// fields, and signatures are intentionally excluded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TransactionStructuralSummary {
    /// Canonical account authorizing the payload.
    pub(crate) authority: String,
    /// Exact network bound into the payload.
    pub(crate) network_id: String,
    /// Signature-bound Unix creation timestamp in milliseconds.
    pub(crate) creation_time_ms: u64,
    /// Required signature-bound lifetime in milliseconds.
    pub(crate) time_to_live_ms: Option<u64>,
    /// Whether a nonce is present, without echoing its value.
    pub(crate) has_nonce: bool,
    /// Stable top-level executable discriminator.
    pub(crate) executable_kind: &'static str,
    /// Number of direct items in the top-level executable.
    pub(crate) executable_item_count: usize,
    /// Number of native instructions visible without executing bytecode.
    pub(crate) native_instruction_count: usize,
    /// Number of deployed-contract calls visible in the executable.
    pub(crate) contract_call_count: usize,
    /// Raw IVM bytecode bytes committed by an IVM executable.
    pub(crate) ivm_bytecode_bytes: usize,
    /// Instruction count in an `IvmProved` precomputed overlay.
    pub(crate) proved_overlay_instruction_count: usize,
    /// Stable registered wire identifiers, capped by
    /// [`MAX_SUMMARY_INSTRUCTION_WIRE_IDS`]. An unregistered instruction is
    /// represented by `None`, never by an invented identifier.
    pub(crate) instruction_wire_ids: Vec<Option<String>>,
    /// Whether additional wire identifiers were omitted from the summary.
    pub(crate) instruction_wire_ids_truncated: bool,
    /// Number of signature-bound metadata entries, without their keys or values.
    pub(crate) metadata_entry_count: usize,
    /// Number of signature-bound proof attachments, without their contents.
    pub(crate) proof_attachment_count: usize,
    /// Stable fee payer discriminator.
    pub(crate) fee_payment_kind: &'static str,
    /// Number of signature-bound fee component limits.
    pub(crate) fee_charge_limit_count: usize,
    /// Signature-bound executable gas limit, when present.
    pub(crate) gas_limit: Option<u64>,
}

impl TransactionStructuralSummary {
    fn from_payload(payload: &TransactionPayload) -> Self {
        let mut executable = ExecutableSummary::default();
        executable.observe(payload.instructions());
        let fee_payment = payload.fee_payment_intent();
        Self {
            authority: payload.authority().to_string(),
            network_id: payload
                .network_id()
                .map(ToString::to_string)
                .unwrap_or_else(|| "genesis".to_owned()),
            creation_time_ms: payload.creation_time_ms,
            time_to_live_ms: payload.time_to_live_ms.map(Into::into),
            has_nonce: payload.nonce.is_some(),
            executable_kind: executable.kind,
            executable_item_count: executable.item_count,
            native_instruction_count: executable.native_instruction_count,
            contract_call_count: executable.contract_call_count,
            ivm_bytecode_bytes: executable.ivm_bytecode_bytes,
            proved_overlay_instruction_count: executable.proved_overlay_instruction_count,
            instruction_wire_ids_truncated: executable.native_instruction_count
                > executable.instruction_wire_ids.len(),
            instruction_wire_ids: executable.instruction_wire_ids,
            metadata_entry_count: payload.metadata.iter().len(),
            proof_attachment_count: payload
                .attachments
                .as_ref()
                .map_or(0, |attachments| attachments.occurrences().len()),
            fee_payment_kind: fee_payment_kind(fee_payment),
            fee_charge_limit_count: fee_payment.charge_limits().len(),
            gas_limit: fee_payment.gas_limit().map(Into::into),
        }
    }

    /// Convert the summary to a closed MCP structured-content value.
    pub(crate) fn to_mcp_value(&self) -> Value {
        let mut object = Map::new();
        object.insert("authority".into(), Value::String(self.authority.clone()));
        object.insert("network_id".into(), Value::String(self.network_id.clone()));
        object.insert(
            "creation_time_ms".into(),
            Value::from(self.creation_time_ms),
        );
        object.insert(
            "time_to_live_ms".into(),
            optional_u64_value(self.time_to_live_ms),
        );
        object.insert("has_nonce".into(), Value::Bool(self.has_nonce));
        object.insert(
            "executable_kind".into(),
            Value::String(self.executable_kind.to_owned()),
        );
        object.insert(
            "executable_item_count".into(),
            count_value(self.executable_item_count),
        );
        object.insert(
            "native_instruction_count".into(),
            count_value(self.native_instruction_count),
        );
        object.insert(
            "contract_call_count".into(),
            count_value(self.contract_call_count),
        );
        object.insert(
            "ivm_bytecode_bytes".into(),
            count_value(self.ivm_bytecode_bytes),
        );
        object.insert(
            "proved_overlay_instruction_count".into(),
            count_value(self.proved_overlay_instruction_count),
        );
        object.insert(
            "instruction_wire_ids".into(),
            Value::Array(
                self.instruction_wire_ids
                    .iter()
                    .map(|wire_id| optional_string_value(wire_id.as_deref()))
                    .collect(),
            ),
        );
        object.insert(
            "instruction_wire_ids_truncated".into(),
            Value::Bool(self.instruction_wire_ids_truncated),
        );
        object.insert(
            "metadata_entry_count".into(),
            count_value(self.metadata_entry_count),
        );
        object.insert(
            "proof_attachment_count".into(),
            count_value(self.proof_attachment_count),
        );
        object.insert(
            "fee_payment_kind".into(),
            Value::String(self.fee_payment_kind.to_owned()),
        );
        object.insert(
            "fee_charge_limit_count".into(),
            count_value(self.fee_charge_limit_count),
        );
        object.insert("gas_limit".into(), optional_u64_value(self.gas_limit));
        Value::Object(object)
    }
}

#[derive(Debug)]
struct ExecutableSummary {
    kind: &'static str,
    item_count: usize,
    native_instruction_count: usize,
    contract_call_count: usize,
    ivm_bytecode_bytes: usize,
    proved_overlay_instruction_count: usize,
    instruction_wire_ids: Vec<Option<String>>,
}

impl Default for ExecutableSummary {
    fn default() -> Self {
        Self {
            kind: "instructions",
            item_count: 0,
            native_instruction_count: 0,
            contract_call_count: 0,
            ivm_bytecode_bytes: 0,
            proved_overlay_instruction_count: 0,
            instruction_wire_ids: Vec::new(),
        }
    }
}

impl ExecutableSummary {
    fn observe(&mut self, executable: &Executable) {
        match executable {
            Executable::Instructions(instructions) => {
                self.kind = "instructions";
                self.item_count = instructions.len();
                for instruction in instructions {
                    self.observe_instruction(instruction);
                }
            }
            Executable::ContractCall(_) => {
                self.kind = "contract_call";
                self.item_count = 1;
                self.contract_call_count = 1;
            }
            Executable::Ivm(bytecode) => {
                self.kind = "ivm";
                self.item_count = 1;
                self.ivm_bytecode_bytes = bytecode.size_bytes();
            }
            Executable::IvmProved(proved) => {
                self.kind = "ivm_proved";
                self.item_count = 1;
                self.ivm_bytecode_bytes = proved.bytecode.size_bytes();
                self.proved_overlay_instruction_count = proved.overlay.len();
                for instruction in &proved.overlay {
                    self.observe_instruction(instruction);
                }
            }
            Executable::Batch(items) => {
                self.kind = "batch";
                self.item_count = items.len();
                for item in items {
                    match item {
                        ExecutableBatchItem::Instruction(instruction) => {
                            self.observe_instruction(instruction);
                        }
                        ExecutableBatchItem::ContractCall(_) => {
                            self.contract_call_count = self.contract_call_count.saturating_add(1);
                        }
                    }
                }
            }
        }
    }

    fn observe_instruction(&mut self, instruction: &iroha_data_model::isi::InstructionBox) {
        self.native_instruction_count = self.native_instruction_count.saturating_add(1);
        if self.instruction_wire_ids.len() < MAX_SUMMARY_INSTRUCTION_WIRE_IDS {
            self.instruction_wire_ids
                .push(instruction_wire_id(instruction).map(str::to_owned));
        }
    }
}

/// Canonical unsigned payload plus its exact external-signing message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedTransactionArtifact {
    canonical_payload_bytes: Vec<u8>,
    signing_message_bytes: [u8; Hash::LENGTH],
    payload_hash_hex: String,
    /// Bounded structural description of the prepared payload.
    pub(crate) summary: TransactionStructuralSummary,
}

impl PreparedTransactionArtifact {
    fn from_builder(
        expected_network_id: &NetworkId,
        builder: TransactionBuilder,
    ) -> Result<Self, TransactionArtifactError> {
        ensure_expected_network(expected_network_id, builder.payload())?;
        let canonical_payload_bytes = builder.encode_payload();
        let decoded = decode_canonical_payload_builder(&canonical_payload_bytes)?;
        if decoded.payload() != builder.payload() {
            return Err(TransactionArtifactError::NonCanonicalTransactionPayload);
        }
        let signing_message_bytes = builder.payload_hash_bytes();
        Ok(Self {
            payload_hash_hex: hex::encode(signing_message_bytes),
            signing_message_bytes,
            summary: TransactionStructuralSummary::from_payload(builder.payload()),
            canonical_payload_bytes,
        })
    }

    /// Exact canonical bytes that an external signer must retain unchanged.
    pub(crate) fn canonical_payload_bytes(&self) -> &[u8] {
        &self.canonical_payload_bytes
    }

    /// Exact typed transaction prehash signed outside Torii.
    pub(crate) const fn signing_message_bytes(&self) -> &[u8; Hash::LENGTH] {
        &self.signing_message_bytes
    }

    /// Lowercase hexadecimal form of [`Self::signing_message_bytes`].
    pub(crate) fn payload_hash_hex(&self) -> &str {
        &self.payload_hash_hex
    }

    /// Canonical padded standard-Base64 unsigned payload.
    pub(crate) fn transaction_payload_base64(&self) -> String {
        BASE64_STANDARD.encode(self.canonical_payload_bytes())
    }

    /// Canonical padded standard-Base64 signing message.
    pub(crate) fn signing_message_base64(&self) -> String {
        BASE64_STANDARD.encode(self.signing_message_bytes())
    }

    /// Convert the prepared artifact to closed MCP structured content.
    pub(crate) fn to_mcp_value(&self) -> Value {
        let mut object = Map::new();
        object.insert("submitted".into(), Value::Bool(false));
        object.insert("canonical".into(), Value::Bool(true));
        object.insert(
            "transaction_payload_base64".into(),
            Value::String(self.transaction_payload_base64()),
        );
        object.insert(
            "signing_message_base64".into(),
            Value::String(self.signing_message_base64()),
        );
        object.insert(
            "payload_hash_hex".into(),
            Value::String(self.payload_hash_hex().to_owned()),
        );
        object.insert("summary".into(), self.summary.to_mcp_value());
        Value::Object(object)
    }
}

/// Signature verification outcome for an inspected artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SignatureVerification {
    /// Unsigned payloads have no authorization proof to verify.
    NotPresent,
    /// The canonical data-model verifier accepted every required signature.
    Valid,
    /// Verification failed with a stable, non-secret reason code.
    Invalid {
        /// Closed failure code; raw cryptographic diagnostics are not echoed.
        code: &'static str,
    },
}

impl SignatureVerification {
    fn from_signed_transaction(transaction: &SignedTransaction) -> Self {
        match transaction.verify_signature() {
            Ok(()) => Self::Valid,
            Err(error) => Self::Invalid {
                code: signature_error_code(&error),
            },
        }
    }

    /// Convert the verification result to a closed MCP value.
    pub(crate) fn to_mcp_value(self) -> Value {
        let (status, valid, failure_code) = match self {
            Self::NotPresent => ("not_present", Value::Null, Value::Null),
            Self::Valid => ("valid", Value::Bool(true), Value::Null),
            Self::Invalid { code } => (
                "invalid",
                Value::Bool(false),
                Value::String(code.to_owned()),
            ),
        };
        let mut object = Map::new();
        object.insert("status".into(), Value::String(status.to_owned()));
        object.insert("valid".into(), valid);
        object.insert("failure_code".into(), failure_code);
        Value::Object(object)
    }
}

/// Pure inspection result for either an unsigned payload or complete signed wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InspectedTransactionArtifact {
    /// Exact artifact kind that was decoded.
    pub(crate) kind: TransactionArtifactKind,
    /// Canonical unsigned payload and signing material derived from the artifact.
    pub(crate) prepared: PreparedTransactionArtifact,
    /// Signature verification outcome.
    pub(crate) signature_verification: SignatureVerification,
    /// Number of authorization signatures in a complete signed envelope.
    pub(crate) signature_count: Option<usize>,
    /// Canonical signed transaction identity, when a complete envelope was supplied.
    pub(crate) transaction_hash: Option<String>,
    /// Canonical entrypoint identity, when a complete envelope was supplied.
    pub(crate) entrypoint_hash: Option<String>,
    /// Exact decoded input length.
    pub(crate) artifact_bytes_len: usize,
}

impl InspectedTransactionArtifact {
    /// Convert the inspection result to closed MCP structured content.
    pub(crate) fn to_mcp_value(&self) -> Value {
        let mut object = Map::new();
        object.insert(
            "artifact_kind".into(),
            Value::String(self.kind.as_str().to_owned()),
        );
        object.insert("canonical".into(), Value::Bool(true));
        object.insert(
            "artifact_bytes_len".into(),
            count_value(self.artifact_bytes_len),
        );
        object.insert(
            "transaction_payload_base64".into(),
            Value::String(self.prepared.transaction_payload_base64()),
        );
        object.insert(
            "signing_message_base64".into(),
            Value::String(self.prepared.signing_message_base64()),
        );
        object.insert(
            "payload_hash_hex".into(),
            Value::String(self.prepared.payload_hash_hex.clone()),
        );
        object.insert(
            "signature_verification".into(),
            self.signature_verification.to_mcp_value(),
        );
        object.insert(
            "signature_count".into(),
            self.signature_count.map_or(Value::Null, count_value),
        );
        object.insert(
            "transaction_hash".into(),
            optional_string_value(self.transaction_hash.as_deref()),
        );
        object.insert(
            "entrypoint_hash".into(),
            optional_string_value(self.entrypoint_hash.as_deref()),
        );
        object.insert("summary".into(), self.prepared.summary.to_mcp_value());
        Value::Object(object)
    }
}

/// Canonicalize a complete typed unsigned payload for external signing.
pub(crate) fn prepare_transaction_payload(
    expected_network_id: &NetworkId,
    payload: TransactionPayload,
) -> Result<PreparedTransactionArtifact, TransactionArtifactError> {
    ensure_expected_network(expected_network_id, &payload)?;
    let builder = TransactionBuilder::from_payload(payload)
        .map_err(|error| TransactionArtifactError::InvalidTransactionPayload(error.to_string()))?;
    PreparedTransactionArtifact::from_builder(expected_network_id, builder)
}

/// Decode and canonicalize exact bytes previously emitted by
/// [`TransactionBuilder::encode_payload`].
pub(crate) fn prepare_transaction_payload_bytes(
    expected_network_id: &NetworkId,
    payload_bytes: &[u8],
) -> Result<PreparedTransactionArtifact, TransactionArtifactError> {
    let builder = decode_canonical_payload_builder(payload_bytes)?;
    PreparedTransactionArtifact::from_builder(expected_network_id, builder)
}

fn decode_canonical_payload_builder(
    payload_bytes: &[u8],
) -> Result<TransactionBuilder, TransactionArtifactError> {
    // `TransactionBuilder::decode_payload` is a bare fixed-layout decoder. Enter
    // the same input-derived allocation and element budget used by canonical
    // Norito slice decoders before it observes artifact bytes.
    let builder =
        norito::with_decode_limits(norito::canonical_decode_limits(payload_bytes.len()), || {
            TransactionBuilder::decode_payload(payload_bytes)
        })
        .map_err(|error| TransactionArtifactError::InvalidTransactionPayload(error.to_string()))?;
    if builder.encode_payload().as_slice() != payload_bytes {
        return Err(TransactionArtifactError::NonCanonicalTransactionPayload);
    }
    Ok(builder)
}

/// Inspect either exact unsigned payload bytes or a complete canonical signed wire.
pub(crate) fn inspect_transaction_artifact(
    expected_network_id: &NetworkId,
    kind: TransactionArtifactKind,
    artifact_bytes: &[u8],
) -> Result<InspectedTransactionArtifact, TransactionArtifactError> {
    match kind {
        TransactionArtifactKind::TransactionPayload => {
            inspect_transaction_payload(expected_network_id, artifact_bytes)
        }
        TransactionArtifactKind::SignedTransaction => {
            inspect_signed_transaction(expected_network_id, artifact_bytes)
        }
    }
}

/// Inspect exact unsigned payload bytes without signing or submitting them.
pub(crate) fn inspect_transaction_payload(
    expected_network_id: &NetworkId,
    payload_bytes: &[u8],
) -> Result<InspectedTransactionArtifact, TransactionArtifactError> {
    let prepared = prepare_transaction_payload_bytes(expected_network_id, payload_bytes)?;
    Ok(InspectedTransactionArtifact {
        kind: TransactionArtifactKind::TransactionPayload,
        prepared,
        signature_verification: SignatureVerification::NotPresent,
        signature_count: None,
        transaction_hash: None,
        entrypoint_hash: None,
        artifact_bytes_len: payload_bytes.len(),
    })
}

/// Inspect a complete canonical fixed-V1 signed transaction wire.
pub(crate) fn inspect_signed_transaction(
    expected_network_id: &NetworkId,
    signed_wire_bytes: &[u8],
) -> Result<InspectedTransactionArtifact, TransactionArtifactError> {
    let transaction = SignedTransaction::decode_all_versioned(signed_wire_bytes)
        .map_err(|error| TransactionArtifactError::InvalidSignedTransaction(error.to_string()))?;
    let canonical_wire = transaction
        .encode_wire_v1()
        .map_err(|error| TransactionArtifactError::InvalidSignedTransaction(error.to_string()))?;
    if canonical_wire != signed_wire_bytes {
        return Err(TransactionArtifactError::NonCanonicalSignedTransaction);
    }
    ensure_expected_network(expected_network_id, transaction.payload())?;
    let prepared = prepare_transaction_payload(expected_network_id, transaction.payload().clone())?;
    let signature_verification = SignatureVerification::from_signed_transaction(&transaction);
    let signature_count = transaction.signature_count();
    Ok(InspectedTransactionArtifact {
        kind: TransactionArtifactKind::SignedTransaction,
        prepared,
        signature_verification,
        signature_count: Some(signature_count),
        transaction_hash: Some(transaction.hash().to_string()),
        entrypoint_hash: Some(transaction.hash_as_entrypoint().to_string()),
        artifact_bytes_len: signed_wire_bytes.len(),
    })
}

fn ensure_expected_network(
    expected_network_id: &NetworkId,
    payload: &TransactionPayload,
) -> Result<(), TransactionArtifactError> {
    match payload.domain() {
        TransactionDomain::Genesis => Err(TransactionArtifactError::GenesisDomain),
        TransactionDomain::Network(actual) if actual == expected_network_id => Ok(()),
        TransactionDomain::Network(actual) => Err(TransactionArtifactError::NetworkMismatch {
            expected: *expected_network_id,
            actual: *actual,
        }),
    }
}

const fn fee_payment_kind(intent: &FeePaymentIntent) -> &'static str {
    match intent {
        FeePaymentIntent::Authority(_) => "authority",
        FeePaymentIntent::Sponsor(_) => "sponsor",
    }
}

fn signature_error_code(error: &TransactionSignatureError) -> &'static str {
    match error {
        TransactionSignatureError::UnsupportedMultisigAuthority => "unsupported_multisig_authority",
        TransactionSignatureError::AlgorithmNotPermitted(_) => "algorithm_not_permitted",
        TransactionSignatureError::AuthorityKeyMismatch => "authority_key_mismatch",
        TransactionSignatureError::CryptoError(_) => "cryptographic_verification_failed",
        TransactionSignatureError::NoSignatures => "no_signatures",
        TransactionSignatureError::MissingMultisigSignatures => "missing_multisig_signatures",
        TransactionSignatureError::UnexpectedMultisigSignatures => "unexpected_multisig_signatures",
        TransactionSignatureError::UnknownMultisigSigner => "unknown_multisig_signer",
        TransactionSignatureError::NonCanonicalMultisigSignatures => {
            "noncanonical_multisig_signatures"
        }
        TransactionSignatureError::InvalidFeePaymentIntent(_) => "invalid_fee_payment_intent",
        TransactionSignatureError::MissingTimeToLive => "missing_time_to_live",
        TransactionSignatureError::GenesisDomainNotAllowed => "genesis_domain_not_allowed",
        TransactionSignatureError::GenesisDomainRequired => "genesis_domain_required",
        TransactionSignatureError::InsufficientMultisigWeight { .. } => {
            "insufficient_multisig_weight"
        }
    }
}

fn count_value(count: usize) -> Value {
    Value::from(u64::try_from(count).unwrap_or(u64::MAX))
}

fn optional_u64_value(value: Option<u64>) -> Value {
    value.map_or(Value::Null, Value::from)
}

fn optional_string_value(value: Option<&str>) -> Value {
    value.map_or(Value::Null, |value| Value::String(value.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Hash, HashOf};
    use iroha_data_model::{
        Level,
        block::BlockHeader,
        isi::{InstructionBox, Log},
    };

    const COMPACT_HASH_FIXTURE: &str =
        include_str!("../../../../fixtures/norito_rpc/iroha_compact_hash_vector.properties");

    fn fixture_property(name: &str) -> &str {
        COMPACT_HASH_FIXTURE
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .find_map(|line| {
                let (key, value) = line.split_once('=')?;
                (key == name).then_some(value)
            })
            .unwrap_or_else(|| panic!("missing compact-hash fixture property `{name}`"))
    }

    fn fixture_signed_wire() -> Vec<u8> {
        BASE64_STANDARD
            .decode(fixture_property("versioned.base64"))
            .expect("fixture versioned.base64 must decode")
    }

    fn fixture_signed_transaction() -> SignedTransaction {
        SignedTransaction::decode_all_versioned(&fixture_signed_wire())
            .expect("fixture must be a canonical versioned SignedTransaction")
    }

    fn fixture_network_id() -> NetworkId {
        *fixture_signed_transaction()
            .network_id()
            .expect("ordinary fixture has a network id")
    }

    fn different_network_id() -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
            b"torii-mcp-transaction-artifact-wrong-network",
        )))
    }

    #[test]
    fn prepare_returns_exact_padded_external_signing_artifact() {
        let transaction = fixture_signed_transaction();
        let network_id = *transaction.network_id().expect("fixture network id");
        let prepared = prepare_transaction_payload(&network_id, transaction.payload().clone())
            .expect("prepare fixture payload");

        assert_eq!(
            prepared.payload_hash_hex(),
            fixture_property("payload.prehash")
        );
        assert_eq!(
            BASE64_STANDARD
                .decode(prepared.transaction_payload_base64())
                .expect("decode prepared payload"),
            prepared.canonical_payload_bytes()
        );
        assert_eq!(
            BASE64_STANDARD
                .decode(prepared.signing_message_base64())
                .expect("decode signing message"),
            prepared.signing_message_bytes()
        );
        assert_eq!(
            BASE64_STANDARD.encode(prepared.signing_message_bytes()),
            prepared.signing_message_base64(),
            "signing message must use canonical padded standard Base64"
        );
        assert!(prepared.signing_message_base64().ends_with('='));
        assert_eq!(prepared.summary.network_id, network_id.to_string());
        assert_eq!(prepared.summary.native_instruction_count, 1);
        assert_eq!(
            prepared.summary.instruction_wire_ids,
            vec![Some("iroha.transfer".to_owned())]
        );

        let value = prepared.to_mcp_value();
        assert_eq!(value["submitted"], Value::Bool(false));
        assert_eq!(value["canonical"], Value::Bool(true));
        assert!(value.get("private_key").is_none());
        assert!(value.get("signature").is_none());
        assert!(value.get("transaction_hash").is_none());
    }

    #[test]
    fn payload_inspection_roundtrips_without_an_authorization_proof() {
        let transaction = fixture_signed_transaction();
        let network_id = *transaction.network_id().expect("fixture network id");
        let prepared = prepare_transaction_payload(&network_id, transaction.payload().clone())
            .expect("prepare fixture payload");
        let inspected = inspect_transaction_artifact(
            &network_id,
            TransactionArtifactKind::TransactionPayload,
            prepared.canonical_payload_bytes(),
        )
        .expect("inspect canonical payload");

        assert_eq!(
            inspected.signature_verification,
            SignatureVerification::NotPresent
        );
        assert_eq!(inspected.transaction_hash, None);
        assert_eq!(inspected.entrypoint_hash, None);
        assert_eq!(
            inspected.prepared.signing_message_bytes(),
            prepared.signing_message_bytes()
        );
        assert_eq!(
            inspected.to_mcp_value()["signature_verification"]["status"],
            Value::String("not_present".to_owned())
        );
    }

    #[test]
    fn signed_inspection_verifies_fixture_and_returns_canonical_identities() {
        let signed_wire = fixture_signed_wire();
        let network_id = fixture_network_id();
        let inspected = inspect_signed_transaction(&network_id, &signed_wire)
            .expect("inspect canonical signed fixture");

        assert_eq!(
            inspected.signature_verification,
            SignatureVerification::Valid
        );
        assert_eq!(
            inspected.transaction_hash.as_deref(),
            Some(fixture_property("canonical.hash"))
        );
        assert_eq!(
            inspected.entrypoint_hash.as_deref(),
            Some(fixture_property("canonical.hash"))
        );
        assert_eq!(
            inspected.prepared.payload_hash_hex(),
            fixture_property("payload.prehash")
        );
        assert_eq!(inspected.artifact_bytes_len, signed_wire.len());
        assert_eq!(inspected.signature_count, Some(1));
        assert_eq!(
            inspected.to_mcp_value()["signature_verification"]["valid"],
            Value::Bool(true)
        );
    }

    #[test]
    fn signed_inspection_reports_invalid_signature_without_echoing_diagnostics() {
        let mut transaction = fixture_signed_transaction();
        let mut signature = transaction.signature().payload().payload().to_vec();
        signature[0] ^= 0x01;
        transaction.set_signature(iroha_data_model::transaction::TransactionSignature(
            iroha_crypto::SignatureOf::from_signature(iroha_crypto::Signature::from_bytes(
                &signature,
            )),
        ));
        // Canonical Norito frames may compress signature bytes; mutate the typed
        // signature and re-encode instead of searching inside a compressed frame.
        let signed_wire = transaction
            .encode_wire_v1()
            .expect("encode changed signature");
        let network_id = fixture_network_id();

        let inspected = inspect_signed_transaction(&network_id, &signed_wire)
            .expect("a structurally valid wire with a bad signature remains inspectable");
        assert_eq!(
            inspected.signature_verification,
            SignatureVerification::Invalid {
                code: "cryptographic_verification_failed"
            }
        );
        let verification = &inspected.to_mcp_value()["signature_verification"];
        assert_eq!(verification["valid"], Value::Bool(false));
        assert_eq!(
            verification["failure_code"],
            Value::String("cryptographic_verification_failed".to_owned())
        );
        assert!(verification.get("message").is_none());
    }

    #[test]
    fn prepare_and_inspect_reject_wrong_network_and_noncanonical_tails() {
        let transaction = fixture_signed_transaction();
        let network_id = *transaction.network_id().expect("fixture network id");
        let wrong_network = different_network_id();
        assert_ne!(network_id, wrong_network);
        assert!(matches!(
            prepare_transaction_payload(&wrong_network, transaction.payload().clone()),
            Err(TransactionArtifactError::NetworkMismatch { .. })
        ));
        assert!(matches!(
            inspect_signed_transaction(&wrong_network, &fixture_signed_wire()),
            Err(TransactionArtifactError::NetworkMismatch { .. })
        ));

        let prepared = prepare_transaction_payload(&network_id, transaction.payload().clone())
            .expect("prepare fixture payload");
        let mut payload_with_tail = prepared.canonical_payload_bytes().to_vec();
        payload_with_tail.push(0);
        assert!(matches!(
            prepare_transaction_payload_bytes(&network_id, &payload_with_tail),
            Err(TransactionArtifactError::InvalidTransactionPayload(_))
        ));

        let mut signed_with_tail = fixture_signed_wire();
        signed_with_tail.push(0);
        assert!(matches!(
            inspect_signed_transaction(&network_id, &signed_with_tail),
            Err(TransactionArtifactError::InvalidSignedTransaction(_))
        ));
    }

    #[test]
    fn structural_summary_caps_wire_ids_and_omits_instruction_content() {
        const SECRET_FREE_MARKER: &str = "summary-must-not-echo-this-log-message";
        let transaction = fixture_signed_transaction();
        let network_id = *transaction.network_id().expect("fixture network id");
        let mut payload = transaction.payload().clone();
        let instructions = (0..MAX_SUMMARY_INSTRUCTION_WIRE_IDS + 3)
            .map(|index| {
                InstructionBox::from(Log::new(
                    Level::INFO,
                    format!("{SECRET_FREE_MARKER}-{index}"),
                ))
            })
            .collect::<Vec<_>>();
        payload.instructions = Executable::Instructions(instructions.into());

        let prepared = prepare_transaction_payload(&network_id, payload)
            .expect("prepare long instruction list");
        assert_eq!(
            prepared.summary.native_instruction_count,
            MAX_SUMMARY_INSTRUCTION_WIRE_IDS + 3
        );
        assert_eq!(
            prepared.summary.instruction_wire_ids.len(),
            MAX_SUMMARY_INSTRUCTION_WIRE_IDS
        );
        assert!(prepared.summary.instruction_wire_ids_truncated);
        assert!(
            prepared
                .summary
                .instruction_wire_ids
                .iter()
                .all(|wire_id| wire_id.as_deref() == Some("iroha.log"))
        );
        let summary_json = norito::json::to_json(&prepared.summary.to_mcp_value())
            .expect("encode structural summary");
        assert!(!summary_json.contains(SECRET_FREE_MARKER));
    }
}
