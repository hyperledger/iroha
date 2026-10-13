//! Canonical multisig proposal intent and exact response/payload validation.

use super::{
    MultisigProposeRequest, MultisigResponse, canonicalize_hex32_literal,
    validate_canonical_standard_base64,
};
use base64::Engine as _;
use eyre::{Result, WrapErr as _, eyre};
use iroha_crypto::HashOf;
use iroha_data_model::{
    Level, NetworkId,
    isi::{InstructionBox, Log},
    transaction::TransactionBuilder,
};
use iroha_executor_data_model::isi::multisig::MultisigProposalId;
use iroha_model_base::metadata::Metadata;
use std::time::Duration;

/// Instructions, metadata and their canonical content commitment validated together.
pub(super) struct ProposalIntent {
    pub(super) instructions: Vec<InstructionBox>,
    pub(super) metadata: Metadata,
    pub(super) hash: HashOf<Vec<InstructionBox>>,
}

const RETAIL_ASSESSMENT_MARKER_PREFIX: &str = "iroha:retail_fee:assessment:v1:";

fn normalized_multisig_request_string(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

pub(super) fn canonical_propose_intent(request: &MultisigProposeRequest) -> Result<ProposalIntent> {
    let mut proposal_instructions = request.instructions.clone();
    if proposal_instructions.iter().any(|instruction| {
        instruction
            .as_any()
            .downcast_ref::<Log>()
            .is_some_and(|log| log.msg.starts_with(RETAIL_ASSESSMENT_MARKER_PREFIX))
    }) {
        return Err(eyre!(
            "multisig instructions must not contain a caller-supplied fee assessment marker"
        ));
    }

    let mut metadata = Metadata::default();
    if let Some(memo) = normalized_multisig_request_string(request.memo.as_deref()) {
        metadata.insert(
            "memo".parse().expect("static metadata key `memo`"),
            iroha_primitives::json::Json::new(memo.to_owned()),
        );
    }
    if let Some(assessment) = &request.validation_fee_assessment {
        let bytes = norito::encode_canonical(assessment).wrap_err("encode fee assessment")?;
        proposal_instructions.push(
            Log::new(
                Level::TRACE,
                format!("{RETAIL_ASSESSMENT_MARKER_PREFIX}{}", hex::encode(bytes)),
            )
            .into(),
        );
    }

    let proposal_hash = HashOf::new(&proposal_instructions);
    Ok(ProposalIntent {
        instructions: proposal_instructions,
        metadata,
        hash: proposal_hash,
    })
}

fn decode_unsigned_payload(
    response: &MultisigResponse,
    request: &MultisigProposeRequest,
    transaction_payload_b64: &str,
    signing_message_b64: &str,
) -> Result<TransactionBuilder> {
    const MAX_TRANSACTION_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
    validate_canonical_standard_base64(
        transaction_payload_b64,
        MAX_TRANSACTION_PAYLOAD_BYTES,
        "multisig response.transaction_payload_b64",
    )?;
    validate_canonical_standard_base64(
        signing_message_b64,
        64,
        "multisig response.signing_message_b64",
    )?;
    let transaction_payload = base64::engine::general_purpose::STANDARD
        .decode(transaction_payload_b64)
        .wrap_err("decode multisig response transaction payload")?;
    let builder = TransactionBuilder::decode_payload(&transaction_payload)
        .wrap_err("decode canonical multisig response transaction payload")?;
    let signing_message = base64::engine::general_purpose::STANDARD
        .decode(signing_message_b64)
        .wrap_err("decode multisig response signing message")?;
    if signing_message.as_slice() != builder.payload_hash_bytes().as_slice() {
        return Err(eyre!(
            "multisig response signing message does not match the transaction payload"
        ));
    }
    if builder.payload().fee_payment != response.fee_payment {
        return Err(eyre!(
            "multisig response fee_payment does not match the transaction payload"
        ));
    }
    if builder.payload().authority() != &request.signer_account_id {
        return Err(eyre!(
            "multisig response transaction authority does not match the requested signer"
        ));
    }
    if response.creation_time_ms != Some(builder.payload().creation_time_ms) {
        return Err(eyre!(
            "multisig response creation_time_ms does not match the transaction payload"
        ));
    }
    Ok(builder)
}

fn validate_unsigned_instructions(
    response: &MultisigResponse,
    request: &MultisigProposeRequest,
    network_id: NetworkId,
    intent: ProposalIntent,
    builder: &TransactionBuilder,
) -> Result<()> {
    let ProposalIntent {
        instructions: proposal_instructions,
        metadata: expected_metadata,
        hash: proposal_hash,
    } = intent;
    let creation_time_ms = response
        .creation_time_ms
        .expect("creation time was matched to the decoded payload above");
    let propose_instruction = InstructionBox::from(
        iroha_executor_data_model::isi::multisig::MultisigPropose::new(
            request.multisig_account_id.clone(),
            request.proposal_nonce,
            proposal_instructions,
            None,
        ),
    );
    let approve_instruction = InstructionBox::from(
        iroha_executor_data_model::isi::multisig::MultisigApprove::new(
            request.multisig_account_id.clone(),
            MultisigProposalId::derive(
                &network_id,
                &request.multisig_account_id,
                &request.proposal_nonce,
            ),
            proposal_hash,
        ),
    );
    let mut expected_builder = TransactionBuilder::new(
        network_id,
        request.signer_account_id.clone(),
        response.fee_payment.clone(),
    );
    expected_builder.set_creation_time(Duration::from_millis(creation_time_ms));
    let expected_builder = expected_builder.with_metadata(expected_metadata);
    let propose_only = expected_builder
        .clone()
        .with_instructions(core::iter::once(propose_instruction.clone()));
    let propose_and_approve =
        expected_builder.with_instructions([propose_instruction, approve_instruction]);
    if builder.payload() != propose_only.payload()
        && builder.payload() != propose_and_approve.payload()
    {
        return Err(eyre!(
            "multisig response transaction payload does not match the exact requested executable and metadata"
        ));
    }
    if response.tx_hash_hex.is_some() || response.executed_tx_hash_hex.is_some() {
        return Err(eyre!(
            "unsubmitted multisig response must not contain transaction hashes"
        ));
    }
    Ok(())
}

pub(super) fn validate_response(
    response: &MultisigResponse,
    request: &MultisigProposeRequest,
    network_id: NetworkId,
) -> Result<()> {
    if !response.ok {
        return Err(eyre!("multisig response.ok must be true"));
    }
    if request.multisig_account_id != response.resolved_multisig_account_id {
        return Err(eyre!(
            "multisig response resolved account does not match the requested account"
        ));
    }
    if request
        .validation_fee_assessment
        .as_ref()
        .is_some_and(|assessment| assessment.account_id != response.resolved_multisig_account_id)
    {
        return Err(eyre!(
            "retail fee assessment account does not match the resolved multisig execution account"
        ));
    }
    if !request
        .fee_payment
        .has_same_payer_and_gas_bound(&response.fee_payment)
    {
        return Err(eyre!(
            "multisig response fee_payment changed the requested payer, sponsor revision, or gas bound"
        ));
    }
    response
        .fee_payment
        .validate()
        .map_err(|error| eyre!("multisig response fee_payment is invalid: {error}"))?;
    if request
        .creation_time_ms
        .is_some_and(|expected| response.creation_time_ms != Some(expected))
    {
        return Err(eyre!(
            "multisig response creation_time_ms is not bound to the request"
        ));
    }
    for (field, value) in [
        ("multisig response.tx_hash_hex", &response.tx_hash_hex),
        (
            "multisig response.executed_tx_hash_hex",
            &response.executed_tx_hash_hex,
        ),
    ] {
        if let Some(value) = value {
            canonicalize_hex32_literal(value, field)?;
        }
    }
    let intent = canonical_propose_intent(request)?;
    let expected_proposal_id = MultisigProposalId::derive(
        &network_id,
        &request.multisig_account_id,
        &request.proposal_nonce,
    );
    if response.proposal_id != expected_proposal_id.to_string()
        || response.instructions_hash != hex::encode(intent.hash.as_ref())
    {
        return Err(eyre!(
            "multisig response occurrence or content hash does not match the exact requested intent"
        ));
    }
    match (
        response.submitted,
        response.transaction_payload_b64.as_deref(),
        response.signing_message_b64.as_deref(),
    ) {
        (true, None, None) => {
            if response.tx_hash_hex.is_none() {
                return Err(eyre!(
                    "submitted multisig response must contain tx_hash_hex"
                ));
            }
        }
        (false, Some(transaction_payload_b64), Some(signing_message_b64)) => {
            let builder = decode_unsigned_payload(
                response,
                request,
                transaction_payload_b64,
                signing_message_b64,
            )?;
            validate_unsigned_instructions(response, request, network_id, intent, &builder)?;
        }
        _ => {
            return Err(eyre!(
                "multisig response must contain either a submitted transaction hash or an exact transaction-payload/signing-message pair"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::{transaction::FeePaymentIntent, validation_fee::RetailFeeAssessmentV1};
    use iroha_primitives::json::Json;

    fn assessment() -> RetailFeeAssessmentV1 {
        RetailFeeAssessmentV1 {
            account_id: iroha_test_samples::ALICE_ID.clone(),
            retail_enrolled: true,
            billing_month_start_ms: 1_700_000_000_000,
            policy_revision: 1,
            payments_used_before: 0,
            qualifying_payments: 1,
            fee_minor: 0,
            state_commitment: [1; 32],
            intent_hash: [2; 32],
            expires_at_ms: 1_700_000_060_000,
        }
    }

    fn request() -> MultisigProposeRequest {
        MultisigProposeRequest {
            proposal_nonce: iroha_executor_data_model::isi::multisig::MultisigProposalNonce::new(
                [7; 32],
            )
            .unwrap(),
            multisig_account_id: iroha_test_samples::ALICE_ID.clone(),
            signer_account_id: iroha_test_samples::BOB_ID.clone(),
            public_key_hex: None,
            signature_b64: None,
            creation_time_ms: Some(123),
            fee_payment: FeePaymentIntent::authority(Vec::new(), None),
            memo: Some("  approved intent  ".to_owned()),
            validation_fee_assessment: Some(assessment()),
            instructions: vec![Log::new(Level::INFO, "exact proposal".to_owned()).into()],
        }
    }

    #[test]
    fn typed_assessment_uses_one_signed_marker_and_memo_only_outer_metadata() {
        let request = request();
        let intent = canonical_propose_intent(&request).unwrap();
        let assessment_bytes = norito::encode_canonical(&assessment()).unwrap();
        let expected_marker: InstructionBox = Log::new(
            Level::TRACE,
            format!(
                "{RETAIL_ASSESSMENT_MARKER_PREFIX}{}",
                hex::encode(assessment_bytes)
            ),
        )
        .into();
        assert_eq!(intent.instructions.len(), 2);
        assert_eq!(intent.instructions[0], request.instructions[0]);
        assert_eq!(intent.instructions[1], expected_marker);
        let mut expected_metadata = Metadata::default();
        expected_metadata.insert("memo".parse().unwrap(), Json::new("approved intent"));
        assert_eq!(intent.metadata, expected_metadata);
        assert_eq!(intent.hash, HashOf::new(&intent.instructions));

        let mut altered = request;
        altered
            .validation_fee_assessment
            .as_mut()
            .unwrap()
            .fee_minor = 1;
        assert_ne!(
            canonical_propose_intent(&altered).unwrap().hash,
            intent.hash
        );
    }

    #[test]
    fn caller_supplied_assessment_markers_reject_before_hashing() {
        for level in [Level::TRACE, Level::WARN] {
            let mut request = request();
            request
                .instructions
                .push(Log::new(level, format!("{RETAIL_ASSESSMENT_MARKER_PREFIX}00")).into());
            assert!(canonical_propose_intent(&request).is_err());
        }
    }

    #[test]
    fn proposal_request_requires_independently_selected_concrete_account() {
        let canonical = norito::json::to_value(&request()).unwrap();
        let mut missing = canonical.clone();
        missing
            .as_object_mut()
            .unwrap()
            .remove("multisig_account_id");
        assert!(norito::json::from_value::<MultisigProposeRequest>(missing.clone()).is_err());
        missing.as_object_mut().unwrap().insert(
            "multisig_account_alias".to_owned(),
            norito::json::Value::from("council@bank.universal"),
        );
        assert!(norito::json::from_value::<MultisigProposeRequest>(missing).is_err());
        let mut ambiguous = canonical;
        ambiguous.as_object_mut().unwrap().insert(
            "multisig_account_alias".to_owned(),
            norito::json::Value::from("council@bank.universal"),
        );
        assert!(norito::json::from_value::<MultisigProposeRequest>(ambiguous).is_err());
    }

    #[test]
    fn retired_positional_fee_fields_reject_at_request_decode() {
        for retired in [
            "validation_fee_policy_version",
            "validation_fee_policy_hash",
            "validation_fee_hijiri_fee_quote_hash",
            "validation_fee_instruction_index",
            "validation_fee_transfer_entry_index",
        ] {
            let mut encoded = norito::json::to_value(&request()).unwrap();
            encoded
                .as_object_mut()
                .unwrap()
                .insert(retired.to_owned(), norito::json::Value::from("retired"));
            assert!(
                norito::json::from_value::<MultisigProposeRequest>(encoded).is_err(),
                "retired field {retired} must reject"
            );
        }
    }
}
