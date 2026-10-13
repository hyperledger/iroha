// Bounded, non-authorizing signer stream-token wire claims. Final receipt/observer authority
// belongs exclusively to the caller's independently pinned shared evidence verifier.
use crate::runtime_provider_registry::StreamTokenSignerRuntimeBindingV1;
use iroha_torii::sorafs::{
    StreamTokenObserverReplyV1, StreamTokenSignerCallErrorV1, StreamTokenSignerReceiptV1,
};
use sorafs_manifest::signer::{
    custody::SIGNER_CUSTODY_MAX_BYTES_V1,
    stream_token::{
        SIGNER_STREAM_TOKEN_MAX_PAYLOAD_BYTES_V1, SIGNER_STREAM_TOKEN_RECEIPT_MAX_BYTES_V1,
        SignerStreamTokenExpectedV1, SignerStreamTokenReceiptV1,
        prepare_stream_token_signing_payload_v1, stream_token_binding_digest_v1,
    },
    stream_token_evidence::{
        SIGNER_STREAM_TOKEN_EVIDENCE_MAX_BYTES_V1,
        SIGNER_STREAM_TOKEN_OBSERVATION_REQUEST_MAX_BYTES_V1,
        SignerStreamTokenEvidenceAdmissionErrorV1, SignerStreamTokenObservationRequestSubjectV1,
        SignerStreamTokenObservationRequestV1, SignerStreamTokenStateObservationV1,
    },
};

// The largest reply contains one 16 KiB custody claim plus one 64 KiB observation. The remaining
// 16 KiB covers the full canonical enum, operation/transport envelopes and bounded full binding.
// The token and signing payload retain their independent, unchanged 2048-byte shared ceilings.
const MAX_STREAM_TOKEN_HARDWARE_FRAME_BYTES_V1: usize =
    SIGNER_CUSTODY_MAX_BYTES_V1 + SIGNER_STREAM_TOKEN_EVIDENCE_MAX_BYTES_V1 + 16 * 1024;
const MAX_STREAM_TOKEN_METADATA_BYTES_V1: usize = 8 * 1024;
const STREAM_TOKEN_HARDWARE_DECODE_POLICY_V1: DecodeResourcePolicyV1 = DecodeResourcePolicyV1::new(
    (
        MAX_STREAM_TOKEN_HARDWARE_FRAME_BYTES_V1,
        MAX_STREAM_TOKEN_HARDWARE_FRAME_BYTES_V1,
    ),
    (512 * 1024, 2 * 1024 * 1024),
    (16 * 1024, 2 * 1024 * 1024),
    32,
    operation_resource_caps(MAX_STREAM_TOKEN_HARDWARE_FRAME_BYTES_V1, 2 * 1024 * 1024, 5),
);

fn stream_token_backend_error(error: StreamTokenSignerCallErrorV1, mutating: bool) -> BrokerError {
    match error {
        StreamTokenSignerCallErrorV1::Refused => BrokerError::Rejected,
        StreamTokenSignerCallErrorV1::AmbiguousCompletion
        | StreamTokenSignerCallErrorV1::InvalidResponse
            if mutating =>
        {
            BrokerError::Ambiguous
        }
        StreamTokenSignerCallErrorV1::Unavailable
        | StreamTokenSignerCallErrorV1::AmbiguousCompletion => BrokerError::Unavailable,
        StreamTokenSignerCallErrorV1::InvalidResponse => BrokerError::Protocol,
    }
}

fn stream_token_transport_error(error: BrokerError) -> StreamTokenSignerCallErrorV1 {
    match error {
        BrokerError::Unavailable => StreamTokenSignerCallErrorV1::Unavailable,
        BrokerError::Ambiguous => StreamTokenSignerCallErrorV1::AmbiguousCompletion,
        BrokerError::Rejected | BrokerError::Conflict | BrokerError::StaleOrRevoked => {
            StreamTokenSignerCallErrorV1::Refused
        }
        BrokerError::Protocol | BrokerError::BindingMismatch => {
            StreamTokenSignerCallErrorV1::InvalidResponse
        }
    }
}

// The fixed broker outcome preserves operational versus semantic classification.
// TODO: retain the original phase and exact returned bytes across pre-return
// transport refusals; Unavailable alone does not authorize another observe call.
fn stream_token_evidence_error(
    error: &SignerStreamTokenEvidenceAdmissionErrorV1,
    rejected: BrokerError,
) -> BrokerError {
    if error.is_retryable() {
        BrokerError::Unavailable
    } else {
        rejected
    }
}

fn prepare_stream_token_broker_request(
    binding: &ProviderBindingWireV1,
    payload: &[u8],
) -> Result<
    (
        sorafs_manifest::StreamTokenBodyV1,
        SignerStreamTokenExpectedV1,
    ),
    BrokerError,
> {
    let signer_backend = required_binding_ref!(binding, stream_token_signer_binding);
    signer_backend
        .validate()
        .map_err(|_| BrokerError::BindingMismatch)?;
    reserve_external_canonical_decode(payload.len(), SIGNER_STREAM_TOKEN_MAX_PAYLOAD_BYTES_V1)?;
    prepare_stream_token_signing_payload_v1(payload, signer_backend.custody())
        .map_err(|_| BrokerError::Rejected)
}

fn decode_stream_token_check_request(
    binding: &ProviderBindingWireV1,
    bytes: &[u8],
) -> Result<iroha_data_model::isi::sorafs::MutateSorafsStreamTokenAuthority, BrokerError> {
    use iroha_data_model::sorafs::stream_token_authority::{
        STREAM_TOKEN_AUTHORITY_REQUEST_MAX_BYTES_V1, StreamTokenAuthorityActionV1,
        validate_stream_token_check_claim_v1,
    };
    let metadata = required_binding_ref!(binding, stream_token_signer_binding);
    let instruction = decode_canonical::<
        iroha_data_model::isi::sorafs::MutateSorafsStreamTokenAuthority,
    >(bytes, STREAM_TOKEN_AUTHORITY_REQUEST_MAX_BYTES_V1)?;
    let StreamTokenAuthorityActionV1::Check(check) = &instruction.request.action else {
        return Err(BrokerError::Rejected);
    };
    let sorafs_manifest::signer::protocol::SignerPurposeBindingV1::StreamToken { provider_id } =
        metadata.custody().purpose
    else {
        return Err(BrokerError::BindingMismatch);
    };
    if instruction.request.network_id != metadata.custody().network_id
        || instruction.request.provider_id.0 != provider_id
        || check.reviewed.request.binding_digest
            != stream_token_binding_digest_v1(metadata.custody())
                .map_err(|_| BrokerError::BindingMismatch)?
    {
        return Err(BrokerError::BindingMismatch);
    }
    validate_stream_token_check_claim_v1(
        &instruction.request,
        metadata.custody().network_id,
        instruction.request.provider_id,
        instruction.request.expected_control_revision,
        instruction.request.expected_control_digest,
        &check.expected_operator,
        &check.expected_observer,
        check.challenge,
        check.floor,
        &check.reviewed,
        &check.phase,
    )
    .map_err(|_| BrokerError::Rejected)?;
    Ok(instruction)
}

fn decode_stream_token_check_result(
    binding: &ProviderBindingWireV1,
    payload: &[u8],
    result: &[u8],
) -> Result<iroha_data_model::transaction::SignedTransaction, BrokerError> {
    use iroha_data_model::{isi::InstructionBox, transaction::Executable};
    let instruction = decode_stream_token_check_request(binding, payload)?;
    let iroha_data_model::sorafs::stream_token_authority::StreamTokenAuthorityActionV1::Check(
        check,
    ) = &instruction.request.action
    else {
        return Err(BrokerError::Protocol);
    };
    let signed =
        decode_canonical::<iroha_data_model::transaction::SignedTransaction>(result, 32 * 1024)?;
    let metadata = required_binding_ref!(binding, stream_token_signer_binding);
    if signed.authority() != &check.expected_observer
        || signed.network_id().map(|network| *network.as_bytes())
            != Some(metadata.custody().network_id)
    {
        return Err(BrokerError::BindingMismatch);
    }
    let Executable::Instructions(instructions) = signed.instructions() else {
        return Err(BrokerError::Protocol);
    };
    if instructions.len() != 1 || instructions.first() != Some(&InstructionBox::from(instruction)) {
        return Err(BrokerError::Protocol);
    }
    signed
        .verify_signature()
        .map_err(|_| BrokerError::Protocol)?;
    Ok(signed)
}

fn validate_stream_token_metadata_result(
    binding: &ProviderBindingWireV1,
    result: &[u8],
) -> Result<(), BrokerError> {
    let expected = required_binding_ref!(binding, stream_token_signer_binding);
    let observed = decode_canonical_with_policy::<StreamTokenSignerRuntimeBindingV1>(
        result,
        MAX_STREAM_TOKEN_METADATA_BYTES_V1,
        STREAM_TOKEN_HARDWARE_DECODE_POLICY_V1,
    )?;
    observed.validate().map_err(|_| BrokerError::Protocol)?;
    if &observed != expected {
        return Err(BrokerError::Protocol);
    }
    Ok(())
}

fn validate_stream_token_receipt_result(
    request: &OperationRequestV1,
    result: &[u8],
) -> Result<(), BrokerError> {
    let (_, expected) = prepare_stream_token_broker_request(&request.binding, &request.payload)?;
    if result.is_empty() || result.len() > SIGNER_STREAM_TOKEN_RECEIPT_MAX_BYTES_V1 {
        return Err(BrokerError::Protocol);
    }
    reserve_external_canonical_decode(result.len(), SIGNER_STREAM_TOKEN_RECEIPT_MAX_BYTES_V1)?;
    let claims = StreamTokenBrokerReceiptClaimsV1::new(
        SignerStreamTokenReceiptV1::decode_canonical(result).map_err(|_| BrokerError::Protocol)?,
    );
    claims.validate(request, &expected)
}

// Every signature copy owned after successful bounded decoding or crypto admission remains here.
// The guard is established before shape, binding or signature validation can return an error.
struct StreamTokenBrokerReceiptClaimsV1 {
    receipt: SignerStreamTokenReceiptV1,
    role_signature: [u8; 64],
    signature: Option<iroha_crypto::Signature>,
    #[cfg(test)]
    drop_audit: Option<Arc<Mutex<Option<StreamTokenReceiptDropAuditV1>>>>,
}
impl StreamTokenBrokerReceiptClaimsV1 {
    fn new(receipt: SignerStreamTokenReceiptV1) -> Self {
        Self {
            receipt,
            role_signature: [0; 64],
            signature: None,
            #[cfg(test)]
            drop_audit: None,
        }
    }

    fn validate(
        mut self,
        request: &OperationRequestV1,
        expected: &SignerStreamTokenExpectedV1,
    ) -> Result<(), BrokerError> {
        self.role_signature = self
            .receipt
            .role_signature_claim()
            .map_err(|_| BrokerError::Protocol)?;
        if self.receipt.request.operation_id != expected.operation_id()
            || self.receipt.request.binding_digest != expected.binding_digest()
            || self.receipt.request.signing_payload_digest != expected.signing_payload_digest()
            || self.receipt.request.signing_payload_size != expected.signing_payload_size()
            || self.receipt.request.issued_at_unix_ms != expected.issued_at_unix_ms()
            || self.receipt.request.expires_at_unix_ms != expected.expires_at_unix_ms()
        {
            return Err(BrokerError::Protocol);
        }
        let binding = required_binding_ref!(&request.binding, stream_token_signer_binding);
        self.signature = Some(
            iroha_crypto::Signature::try_from_bytes(&self.role_signature)
                .map_err(|_| BrokerError::Protocol)?,
        );
        // Reuse the existing strict Ed25519 verifier with borrowed pinned key/signature. Calling
        // the generic broker helper would copy the role array into an unguarded by-value argument.
        self.signature
            .as_ref()
            .ok_or(BrokerError::Protocol)?
            .verify(&binding.custody().public_key, &request.payload)
            .map_err(|_| BrokerError::Protocol)
    }

    #[cfg(test)]
    fn with_drop_audit(mut self, audit: Arc<Mutex<Option<StreamTokenReceiptDropAuditV1>>>) -> Self {
        self.drop_audit = Some(audit);
        self
    }
}
impl Drop for StreamTokenBrokerReceiptClaimsV1 {
    fn drop(&mut self) {
        #[cfg(test)]
        let signature_bytes = self
            .receipt
            .signatures
            .iter()
            .map(|value| value.signature.len())
            .sum();
        for value in &mut self.receipt.signatures {
            iroha_crypto::zeroize_value_for_confidential_discard(&mut value.signature);
        }
        iroha_crypto::zeroize_value_for_confidential_discard(&mut self.role_signature);
        if let Some(signature) = &mut self.signature {
            iroha_crypto::zeroize_value_for_confidential_discard(signature);
        }
        #[cfg(test)]
        if let Some(audit) = &self.drop_audit {
            *audit.lock().expect("isolated receipt drop audit") =
                Some(StreamTokenReceiptDropAuditV1 {
                    signature_bytes,
                    receipt_signatures_zero: self
                        .receipt
                        .signatures
                        .iter()
                        .all(|value| value.signature.iter().all(|byte| *byte == 0)),
                    role_signature_zero: self.role_signature.iter().all(|byte| *byte == 0),
                    parsed_signature_zero: self
                        .signature
                        .as_ref()
                        .map(|signature| signature.payload().iter().all(|byte| *byte == 0)),
                });
        }
    }
}
#[cfg(test)]
#[derive(Debug)]
struct StreamTokenReceiptDropAuditV1 {
    signature_bytes: usize,
    receipt_signatures_zero: bool,
    role_signature_zero: bool,
    parsed_signature_zero: Option<bool>,
}

fn decode_stream_token_observer_request(
    binding: &ProviderBindingWireV1,
    bytes: &[u8],
) -> Result<SignerStreamTokenObservationRequestV1, BrokerError> {
    let signer_backend = required_binding_ref!(binding, stream_token_signer_binding);
    let expected = stream_token_binding_digest_v1(signer_backend.custody())
        .map_err(|_| BrokerError::BindingMismatch)?;
    reserve_external_canonical_decode(
        bytes.len(),
        SIGNER_STREAM_TOKEN_OBSERVATION_REQUEST_MAX_BYTES_V1,
    )?;
    let request = SignerStreamTokenObservationRequestV1::decode_canonical(bytes)
        .map_err(|error| stream_token_evidence_error(&error, BrokerError::Rejected))?;
    let (SignerStreamTokenObservationRequestSubjectV1::CurrentCustody { binding_digest }
    | SignerStreamTokenObservationRequestSubjectV1::CompletedOperation {
        binding_digest, ..
    }) = request.subject;
    if binding_digest != expected {
        return Err(BrokerError::BindingMismatch);
    }
    Ok(request)
}

#[derive(norito::NoritoSchema)]
#[norito_schema(name = "irohad::runtime_provider_broker::protocol::StreamTokenObserverReplyWireV1")]
#[derive(Decode, Encode)]
enum StreamTokenObserverReplyWireV1 {
    Current {
        record: Vec<u8>,
        observation: Vec<u8>,
    },
    Completed {
        observation: Vec<u8>,
    },
}
impl Drop for StreamTokenObserverReplyWireV1 {
    fn drop(&mut self) {
        match self {
            Self::Current {
                record,
                observation,
            } => {
                iroha_crypto::zeroize_value_for_confidential_discard(record);
                iroha_crypto::zeroize_value_for_confidential_discard(observation);
            }
            Self::Completed { observation } => {
                iroha_crypto::zeroize_value_for_confidential_discard(observation)
            }
        }
    }
}

#[cfg(test)]
fn prepare_stream_token_observer_wire(
    request: &SignerStreamTokenObservationRequestV1,
    reply: &StreamTokenObserverReplyV1,
) -> Result<StreamTokenObserverReplyWireV1, CanonicalAttemptErrorV1> {
    let limit = MAX_STREAM_TOKEN_HARDWARE_FRAME_BYTES_V1;
    Ok(match request.subject {
        SignerStreamTokenObservationRequestSubjectV1::CurrentCustody { .. } => {
            let (record, observation) = reply.current_evidence().ok_or(BrokerError::Protocol)?;
            let mut record = canonical_attempt::copy(record, limit)?;
            let mut observation = canonical_attempt::copy(observation, limit)?;
            StreamTokenObserverReplyWireV1::Current {
                record: record.take(),
                observation: observation.take(),
            }
        }
        SignerStreamTokenObservationRequestSubjectV1::CompletedOperation { .. } => {
            let observation = reply.completed_observation().ok_or(BrokerError::Protocol)?;
            let mut observation = canonical_attempt::copy(observation, limit)?;
            StreamTokenObserverReplyWireV1::Completed {
                observation: observation.take(),
            }
        }
    })
}
#[cfg(test)]
fn encode_stream_token_observer_reply(
    request: &SignerStreamTokenObservationRequestV1,
    reply: &StreamTokenObserverReplyV1,
) -> Result<Vec<u8>, BrokerError> {
    let wire = prepare_stream_token_observer_wire(request, reply)
        .map_err(|error| error.service_error())?;
    encode_canonical(&wire, MAX_STREAM_TOKEN_HARDWARE_FRAME_BYTES_V1)
}

fn take_stream_token_observer_reply(
    expected: &SignerStreamTokenObservationRequestV1,
    wire: &mut StreamTokenObserverReplyWireV1,
) -> Result<StreamTokenObserverReplyV1, BrokerError> {
    match (&expected.subject, wire) {
        (
            SignerStreamTokenObservationRequestSubjectV1::CurrentCustody { .. },
            StreamTokenObserverReplyWireV1::Current {
                record,
                observation,
            },
        ) => {
            StreamTokenObserverReplyV1::current(std::mem::take(record), std::mem::take(observation))
        }
        (
            SignerStreamTokenObservationRequestSubjectV1::CompletedOperation { .. },
            StreamTokenObserverReplyWireV1::Completed { observation },
        ) => StreamTokenObserverReplyV1::completed(std::mem::take(observation)),
        _ => return Err(BrokerError::Protocol),
    }
    .map_err(|_| BrokerError::Protocol)
}

fn validate_stream_token_observer_body(
    binding: &ProviderBindingWireV1,
    expected: &SignerStreamTokenObservationRequestV1,
    observation: &SignerStreamTokenStateObservationV1,
) -> Result<(), SignerStreamTokenEvidenceAdmissionErrorV1> {
    let signer_backend = binding
        .stream_token_signer_binding
        .as_ref()
        .ok_or(sorafs_manifest::signer::stream_token_evidence::SignerStreamTokenEvidenceErrorV1::SourceMismatch)?;
    if observation.body.request_digest != expected.digest()?
        || observation.body.phase != expected.phase
        || observation.body.chain_id != signer_backend.custody().chain_id
        || observation.body.network_id != signer_backend.custody().network_id
    {
        return Err(sorafs_manifest::signer::stream_token_evidence::SignerStreamTokenEvidenceErrorV1::SourceMismatch.into());
    }
    Ok(())
}

fn decode_stream_token_observer_reply(
    binding: &ProviderBindingWireV1,
    payload: &[u8],
    result: &[u8],
) -> Result<StreamTokenObserverReplyV1, BrokerError> {
    let expected = decode_stream_token_observer_request(binding, payload)?;
    let mut wire = decode_canonical_with_policy::<StreamTokenObserverReplyWireV1>(
        result,
        MAX_STREAM_TOKEN_HARDWARE_FRAME_BYTES_V1,
        STREAM_TOKEN_HARDWARE_DECODE_POLICY_V1,
    )?;
    let reply = take_stream_token_observer_reply(&expected, &mut wire)?;
    let observation_bytes = reply
        .current_evidence()
        .map(|(_, observation)| observation)
        .or_else(|| reply.completed_observation())
        .ok_or(BrokerError::Protocol)?;
    reserve_external_canonical_decode(
        observation_bytes.len(),
        SIGNER_STREAM_TOKEN_EVIDENCE_MAX_BYTES_V1,
    )?;
    let observation = SignerStreamTokenStateObservationV1::decode_canonical(observation_bytes)
        .map_err(|error| stream_token_evidence_error(&error, BrokerError::Protocol))?;
    validate_stream_token_observer_body(binding, &expected, &observation)
        .map_err(|error| stream_token_evidence_error(&error, BrokerError::Protocol))?;
    // No signature, custody, freshness, ancestry or completed-state authority is minted here.
    Ok(reply)
}
