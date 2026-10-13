//! Typed Torii surface for Parliament-governed validation-fee state.
use crate::{
    Error, JsonBody, NoritoBody, NoritoJson, NoritoQuery, SharedAppState, check_access,
    require_runtime_governance_account, utils::extractors::NoritoOnly,
};
use axum::{
    extract::{ConnectInfo, Extension, Path, State},
    http::HeaderMap,
};
use iroha_core::governance::parliament::{
    canonical_governance_attempt_ids_v1, validate_parliament_randomness_redraw_lineage_v1,
};
use iroha_core::state::{StateReadOnly, WorldReadOnly};
use iroha_data_model::{
    account::AccountId,
    governance::types::{
        GovernanceAttemptStatusV1, GovernanceCertificateId, GovernanceCertificateV1,
        ProposalContentId, ProposalKind,
    },
    isi::{
        InstructionBox,
        governance::{ProposeValidationFeePayoutLifecycle, ProposeValidationFeePolicy},
    },
    validation_fee::{ValidationFeePolicyRegistryV1, ValidationFeePolicySnapshotCommitmentV1},
};
use iroha_torii_shared::validation_fee_api::{
    VALIDATION_FEE_POLICY_PROOF_MAX_FINALITY_CHAIN_BYTES,
    VALIDATION_FEE_POLICY_PROOF_MAX_RESPONSE_BYTES, VALIDATION_FEE_POLICY_PROOF_VERSION_V1,
    VALIDATION_FEE_PROPOSAL_API_VERSION_V1, VALIDATION_FEE_PROPOSAL_PAGE_MAX_LIMIT_V1,
    ValidationFeeCurrentPolicyProofRequestV1, ValidationFeeCurrentPolicyProofV1,
    ValidationFeeProposalDetailQueryV1, ValidationFeeProposalDetailV1,
    ValidationFeeProposalDraftPayloadV1, ValidationFeeProposalDraftRequestV1,
    ValidationFeeProposalDraftResponseV1, ValidationFeeProposalInstructionDraftV1,
    ValidationFeeProposalListQueryV1, ValidationFeeProposalListV1, ValidationFeeProposalRecordV1,
    ValidationFeeProposalStatusV1, decode_validation_fee_proposal_cursor_v1,
    encode_validation_fee_proposal_cursor_v1, validation_fee_policy_proof_page_tip,
};
use mv::storage::StorageReadOnly as _;
use std::ops::Bound::{Excluded, Unbounded};
fn fee_read_transport_error(
    error: iroha_core::execution_attempt::ExecutionAttemptError<String>,
    rejected: impl FnOnce(String) -> Error,
) -> Error {
    match error {
        iroha_core::execution_attempt::ExecutionAttemptError::Rejected(message) => {
            rejected(message)
        }
        iroha_core::execution_attempt::ExecutionAttemptError::Deferred(_) => {
            Error::AppServiceUnavailable {
                code: "retail_fee_local_resources_unavailable",
                message: "Local fee projection did not complete; retry the original request".into(),
            }
        }
    }
}
fn inconsistent(message: impl Into<String>) -> Error {
    let message = message.into();
    if message.contains(iroha_data_model::validation_fee::RETAIL_FEE_CATCH_UP_REQUIRED) {
        return catch_up_required();
    }
    Error::AppServiceUnavailable {
        code: "validation_fee_state_inconsistent",
        message: message.into(),
    }
}
fn catch_up_required() -> Error {
    Error::AppServiceUnavailable {
        code: "ledger_catch_up_required",
        message: "Consensus is completing bounded historical month settlement; retry after ledger catch-up".into(),
    }
}
fn bad_request(message: impl Into<String>) -> Error {
    Error::AppQueryValidation {
        code: "validation_fee_request_invalid",
        message: message.into(),
    }
}
fn quote_unavailable(message: impl Into<String>) -> Error {
    let message = message.into();
    if message.contains(iroha_data_model::validation_fee::RETAIL_FEE_CATCH_UP_REQUIRED) {
        return catch_up_required();
    }
    Error::AppConflict {
        code: "retail_fee_quote_unavailable",
        message: message.into(),
    }
}
fn not_found(message: impl Into<String>) -> Error {
    Error::AppNotFound {
        code: "validation_fee_proposal_not_found",
        message: message.into(),
    }
}
fn parse_proposal_id(value: &str) -> Result<[u8; 32], Error> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(bad_request(
            "proposal_id must be exactly 64 lowercase hexadecimal digits",
        ));
    }
    let bytes = hex::decode(value)
        .map_err(|_| bad_request("proposal_id must be exactly 64 lowercase hexadecimal digits"))?;
    bytes
        .try_into()
        .map_err(|_| bad_request("proposal_id must decode to exactly 32 bytes"))
}
fn retained_proposal_operator(proposal_kind: &ProposalKind) -> Result<&AccountId, Error> {
    match proposal_kind {
        ProposalKind::ValidationFeePolicy(payload) => Ok(&payload.proposal_operator),
        ProposalKind::ValidationFeePayoutLifecycle(payload) => Ok(&payload.proposal_operator),
        ProposalKind::DeployContract(_)
        | ProposalKind::ContractLifecycleGovernance(_)
        | ProposalKind::ContractEmergencyHold(_)
        | ProposalKind::RuntimeUpgrade(_)
        | ProposalKind::SccpRouteGovernance(_)
        | ProposalKind::SorafsProviderGovernance(_)
        | ProposalKind::MusubiRegistryGovernance(_)
        | ProposalKind::GlobalDataTriggerPermissionGovernance(_) => Err(inconsistent(
            "non-validation-fee proposal reached the typed validation-fee projection",
        )),
    }
}
fn public_proposal_record(
    state: &impl StateReadOnly,
    registry: Option<&ValidationFeePolicyRegistryV1>,
    proposal_id: [u8; 32],
    proposal: &iroha_core::state::GovernanceProposalRecord,
) -> Result<
    (
        ValidationFeeProposalRecordV1,
        Option<GovernanceCertificateV1>,
    ),
    Error,
> {
    let world = state.world();
    if !matches!(
        proposal.kind,
        ProposalKind::ValidationFeePolicy(_) | ProposalKind::ValidationFeePayoutLifecycle(_)
    ) {
        return Err(inconsistent(
            "non-validation-fee proposal reached the typed validation-fee projection",
        ));
    }
    if proposal.kind.fingerprint() != proposal_id {
        return Err(inconsistent(
            "validation-fee proposal identifier differs from its native fingerprint",
        ));
    }
    if retained_proposal_operator(&proposal.kind)? != &proposal.proposer {
        return Err(inconsistent(
            "validation-fee proposal operator differs from its retained proposer",
        ));
    }
    let proposal_content_id = ProposalContentId::new(proposal_id);
    let mut attempts = Vec::new();
    let mut history_ended = false;
    for attempt_id in canonical_governance_attempt_ids_v1(proposal_content_id) {
        let Some(attempt) = world.parliament_attempts().get(&attempt_id) else {
            history_ended = true;
            continue;
        };
        if history_ended {
            return Err(inconsistent(
                "validation-fee proposal attempt history is not an exact contiguous sequence",
            ));
        }
        attempt.validate().map_err(|error| {
            inconsistent(format!(
                "validation-fee proposal retained an invalid Parliament attempt: {error}"
            ))
        })?;
        if attempt.attempt().id != attempt_id
            || attempt.proposal_content_id() != proposal_content_id
        {
            return Err(inconsistent(
                "validation-fee proposal retained a Parliament attempt under the wrong canonical key",
            ));
        }
        attempt
            .validate_proposal_bindings_v1(&proposal.kind)
            .map_err(|error| {
                inconsistent(format!(
                    "validation-fee proposal retained a Parliament attempt with mismatched proposal bindings: {error}"
                ))
            })?;
        attempts.push(attempt);
    }
    validate_parliament_randomness_redraw_lineage_v1(attempts.iter().copied()).map_err(
        |error| {
            inconsistent(format!(
                "validation-fee proposal retained an invalid Parliament attempt lineage: {error}"
            ))
        },
    )?;
    let latest_attempt = attempts.last().copied();
    let expected_status = latest_attempt.map_or(
        iroha_core::state::GovernanceProposalStatus::Proposed,
        |attempt| match attempt.attempt().status {
            GovernanceAttemptStatusV1::Active | GovernanceAttemptStatusV1::Certified => {
                iroha_core::state::GovernanceProposalStatus::Proposed
            }
            GovernanceAttemptStatusV1::Rejected => {
                iroha_core::state::GovernanceProposalStatus::Rejected
            }
            GovernanceAttemptStatusV1::Enacted => {
                iroha_core::state::GovernanceProposalStatus::Enacted
            }
            GovernanceAttemptStatusV1::Superseded => {
                iroha_core::state::GovernanceProposalStatus::Superseded
            }
            GovernanceAttemptStatusV1::ExecutionFailed => {
                iroha_core::state::GovernanceProposalStatus::ExecutionFailed
            }
        },
    );
    if proposal.status != expected_status {
        return Err(inconsistent(
            "validation-fee proposal status differs from its latest Parliament attempt",
        ));
    }
    let certificate = latest_attempt.and_then(|attempt| attempt.certificate().cloned());
    let mut authorization = retained_registry_authorization(registry, proposal_id)?.cloned();
    if proposal.status == iroha_core::state::GovernanceProposalStatus::Enacted {
        let enacted_attempt_count = attempts
            .iter()
            .filter(|attempt| attempt.attempt().status == GovernanceAttemptStatusV1::Enacted)
            .count();
        let attempt = latest_attempt.ok_or_else(|| {
            inconsistent("enacted validation-fee proposal has no Parliament attempt")
        })?;
        let certificate = certificate.as_ref().ok_or_else(|| {
            inconsistent("enacted validation-fee proposal has no Parliament certificate")
        })?;
        if authorization.is_none() {
            // Compaction leaves the complete original authorization in its enactment corpus.
            // Never derive a replacement authorization from a present-day proposal record.
            let original = iroha_core::query::native_receipts::fee_evidence_block_proof(
                state,
                certificate.enact_at_height,
            )
            .map_err(|error| {
                inconsistent(format!("enacted policy archive is unavailable: {error}"))
            })?;
            authorization =
                retained_registry_authorization(original.registry(), proposal_id)?.cloned();
        }
        let authorization = authorization.ok_or_else(|| {
            inconsistent("enacted validation-fee proposal has no original registry authorization")
        })?;
        if enacted_attempt_count != 1
            || attempt.terminal_height() != Some(certificate.enact_at_height)
            || authorization.invariant_error().is_some()
            || authorization.proposal_fingerprint != proposal_id
            || authorization.proposal_operator != proposal.proposer
            || authorization.governance_certificate_id
                != GovernanceCertificateId::derive_v1(certificate)
            || &authorization.governance_certificate != certificate
            || authorization.enacted_at_height != certificate.enact_at_height
        {
            return Err(inconsistent(
                "protected validation-fee authorization differs from the unique enacted Parliament attempt",
            ));
        }
    } else if authorization.is_some() {
        return Err(inconsistent(
            "unenacted validation-fee proposal unexpectedly has protected registry authorization",
        ));
    }
    let status = match proposal.status {
        iroha_core::state::GovernanceProposalStatus::Proposed => {
            ValidationFeeProposalStatusV1::Proposed
        }
        iroha_core::state::GovernanceProposalStatus::Rejected => {
            ValidationFeeProposalStatusV1::Rejected
        }
        iroha_core::state::GovernanceProposalStatus::Enacted => {
            ValidationFeeProposalStatusV1::Enacted
        }
        iroha_core::state::GovernanceProposalStatus::Superseded => {
            ValidationFeeProposalStatusV1::Superseded
        }
        iroha_core::state::GovernanceProposalStatus::ExecutionFailed => {
            ValidationFeeProposalStatusV1::ExecutionFailed
        }
    };
    Ok((
        ValidationFeeProposalRecordV1 {
            proposer: proposal.proposer.clone(),
            kind: proposal.kind.clone(),
            created_height: proposal.created_height,
            status,
        },
        certificate,
    ))
}
fn current_validation_fee_registry(
    world: &impl WorldReadOnly,
) -> Result<Option<ValidationFeePolicyRegistryV1>, Error> {
    let parameter_id = ValidationFeePolicyRegistryV1::parameter_id();
    let Some(custom) = world.parameters().custom().get(&parameter_id) else {
        return Ok(None);
    };
    let registry = ValidationFeePolicyRegistryV1::from_custom_parameter(custom)
        .ok_or_else(|| inconsistent("protected validation-fee registry cannot be decoded"))?;
    registry
        .validate()
        .map_err(|error| inconsistent(format!("protected registry is invalid: {error}")))?;
    Ok(Some(registry))
}
fn retained_registry_authorization<'a>(
    registry: Option<&'a ValidationFeePolicyRegistryV1>,
    proposal_id: [u8; 32],
) -> Result<
    Option<&'a iroha_data_model::validation_fee::ValidationFeeParliamentAuthorizationV1>,
    Error,
> {
    let Some(registry) = registry else {
        return Ok(None);
    };
    let mut found = None;
    let authorizations = registry
        .registered_policies
        .iter()
        .map(|entry| &entry.parliament_authorization)
        .chain(
            registry
                .payout_policies
                .entries
                .iter()
                .map(|entry| &entry.parliament_authorization),
        );
    for authorization in authorizations {
        if authorization.proposal_fingerprint == proposal_id
            && found.replace(authorization).is_some()
        {
            return Err(inconsistent(
                "protected registry contains duplicate proposal certificate bindings",
            ));
        }
    }
    Ok(found)
}
fn bounded_validation_fee_proposal_keys<'a>(
    indexed: impl Iterator<Item = (&'a (u64, [u8; 32]), &'a ())>,
    limit: usize,
) -> (Vec<(u64, [u8; 32])>, bool) {
    let mut keys = indexed
        .take(limit.saturating_add(1))
        .map(|(key, ())| *key)
        .collect::<Vec<_>>();
    let has_more = keys.len() > limit;
    if has_more {
        keys.pop();
    }
    (keys, has_more)
}
/// Return one bounded page of typed validation-fee Parliament proposals.
pub(crate) async fn handler_proposals(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    ConnectInfo(remote): ConnectInfo<std::net::SocketAddr>,
    NoritoQuery(query): NoritoQuery<ValidationFeeProposalListQueryV1>,
) -> Result<JsonBody<ValidationFeeProposalListV1>, Error> {
    check_access(
        &app,
        &headers,
        Some(remote.ip()),
        "v1/validation-fee/proposals",
    )
    .await?;
    if query.limit == 0 || query.limit > VALIDATION_FEE_PROPOSAL_PAGE_MAX_LIMIT_V1 {
        return Err(bad_request(format!(
            "limit must be between 1 and {VALIDATION_FEE_PROPOSAL_PAGE_MAX_LIMIT_V1}"
        )));
    }
    let after = query
        .cursor
        .as_deref()
        .map(decode_validation_fee_proposal_cursor_v1)
        .transpose()
        .map_err(bad_request)?;
    let view = app.state.view();
    let world = view.world();
    let registry = current_validation_fee_registry(world)?;
    let index = world.validation_fee_proposal_index();
    let indexed: Box<dyn Iterator<Item = (&(u64, [u8; 32]), &())> + '_> = match after {
        Some(after) => Box::new(index.range((Excluded(after), Unbounded))),
        None => Box::new(index.iter()),
    };
    let limit = usize::try_from(query.limit).expect("bounded u32 page limit fits usize");
    let (page_keys, has_more) = bounded_validation_fee_proposal_keys(indexed, limit);
    let mut proposals = Vec::with_capacity(limit);
    let mut last_key = None;
    for (created_height, proposal_id) in page_keys {
        let proposal = world
            .governance_proposals()
            .get(&proposal_id)
            .ok_or_else(|| inconsistent("validation-fee proposal index references no proposal"))?;
        if proposal.created_height != created_height
            || !matches!(
                proposal.kind,
                ProposalKind::ValidationFeePolicy(_)
                    | ProposalKind::ValidationFeePayoutLifecycle(_)
            )
        {
            return Err(inconsistent(
                "validation-fee proposal index does not match its exact typed proposal",
            ));
        }
        let (record, _) = public_proposal_record(&view, registry.as_ref(), proposal_id, proposal)?;
        proposals.push(record);
        last_key = Some((created_height, proposal_id));
    }
    let next_cursor = if has_more {
        last_key.map(|(created_height, proposal_id)| {
            encode_validation_fee_proposal_cursor_v1(created_height, proposal_id)
        })
    } else {
        None
    };
    Ok(JsonBody(ValidationFeeProposalListV1 {
        version: VALIDATION_FEE_PROPOSAL_API_VERSION_V1,
        limit: query.limit,
        proposals,
        next_cursor,
    }))
}
/// Return one typed validation-fee Parliament proposal.
pub(crate) async fn handler_proposal_detail(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    ConnectInfo(remote): ConnectInfo<std::net::SocketAddr>,
    Path(proposal_id): Path<String>,
    NoritoQuery(_query): NoritoQuery<ValidationFeeProposalDetailQueryV1>,
) -> Result<JsonBody<ValidationFeeProposalDetailV1>, Error> {
    check_access(
        &app,
        &headers,
        Some(remote.ip()),
        "v1/validation-fee/proposals/{proposal_id}",
    )
    .await?;
    let proposal_id_bytes = parse_proposal_id(&proposal_id)?;
    let view = app.state.view();
    let world = view.world();
    let proposal = world
        .governance_proposals()
        .get(&proposal_id_bytes)
        .ok_or_else(|| not_found("validation-fee proposal was not found"))?;
    if !matches!(
        proposal.kind,
        ProposalKind::ValidationFeePolicy(_) | ProposalKind::ValidationFeePayoutLifecycle(_)
    ) {
        return Err(not_found("validation-fee proposal was not found"));
    }
    let registry = current_validation_fee_registry(world)?;
    let (proposal, governance_certificate) =
        public_proposal_record(&view, registry.as_ref(), proposal_id_bytes, proposal)?;
    Ok(JsonBody(ValidationFeeProposalDetailV1 {
        version: VALIDATION_FEE_PROPOSAL_API_VERSION_V1,
        proposal,
        current_height: u64::try_from(app.state.committed_height())
            .unwrap_or(u64::MAX)
            .to_string(),
        governance_certificate,
    }))
}
fn canonical_draft_instruction(
    request: &ValidationFeeProposalDraftRequestV1,
) -> Result<(ProposalKind, InstructionBox), Error> {
    if request.version != VALIDATION_FEE_PROPOSAL_API_VERSION_V1 {
        return Err(bad_request(
            "unsupported validation-fee proposal draft version",
        ));
    }
    let proposal_kind = request.proposal.proposal_kind(&request.proposal_operator);
    let instruction: InstructionBox = match &request.proposal {
        ValidationFeeProposalDraftPayloadV1::Policy { policy } => {
            if let Some(reason) = policy.policy_invariant_error() {
                return Err(bad_request(format!(
                    "invalid validation-fee policy: {reason}"
                )));
            }
            ProposeValidationFeePolicy {
                policy: policy.clone(),
            }
            .into()
        }
        ValidationFeeProposalDraftPayloadV1::PayoutLifecycle { payout_binding } => {
            if let Some(reason) = payout_binding.invariant_error() {
                return Err(bad_request(format!(
                    "invalid validation-fee payout lifecycle: {reason}"
                )));
            }
            let lifecycle_seal = payout_binding.lifecycle_seal().map_err(|error| {
                bad_request(format!(
                    "validation-fee payout lifecycle cannot be encoded: {error}"
                ))
            })?;
            if lifecycle_seal == [0; 32] {
                return Err(bad_request(
                    "validation-fee payout lifecycle derives an invalid zero seal",
                ));
            }
            ProposeValidationFeePayoutLifecycle {
                payout_binding: payout_binding.clone(),
            }
            .into()
        }
    };
    Ok((proposal_kind, instruction))
}
fn framed_instruction_draft(
    instruction: &InstructionBox,
) -> Result<ValidationFeeProposalInstructionDraftV1, Error> {
    let (wire_id, framed) = iroha_data_model::isi::framed_instruction_payload(instruction)
        .ok_or_else(|| inconsistent("native validation-fee instruction has no V1 wire ID"))?;
    Ok(ValidationFeeProposalInstructionDraftV1 {
        wire_id: wire_id.to_owned(),
        payload_hex: hex::encode(framed),
    })
}
/// Build one exact native validation-fee proposal instruction for local signing.
pub(crate) async fn handler_proposal_draft(
    State(app): State<SharedAppState>,
    Extension(verified): Extension<crate::app_auth::VerifiedCanonicalRequest>,
    headers: HeaderMap,
    ConnectInfo(remote): ConnectInfo<std::net::SocketAddr>,
    NoritoJson(request): NoritoJson<ValidationFeeProposalDraftRequestV1>,
) -> Result<JsonBody<ValidationFeeProposalDraftResponseV1>, Error> {
    check_access(
        &app,
        &headers,
        Some(remote.ip()),
        "v1/validation-fee/proposals/draft",
    )
    .await?;
    require_runtime_governance_account(
        &request.proposal_operator,
        &verified.account,
        "validation-fee proposal draft",
    )?;
    let (proposal_kind, instruction) = canonical_draft_instruction(&request)?;
    let proposal_id = proposal_kind.fingerprint();
    let instruction = framed_instruction_draft(&instruction)?;
    Ok(JsonBody(ValidationFeeProposalDraftResponseV1 {
        version: VALIDATION_FEE_PROPOSAL_API_VERSION_V1,
        proposal_operator: request.proposal_operator,
        proposal_id: hex::encode(proposal_id),
        proposal_kind,
        tx_instructions: vec![instruction],
    }))
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    #[test]
    fn validation_fee_projection_rejects_unrelated_current_proposal() {
        use iroha_data_model::governance::types::{
            GlobalDataTriggerPermissionGovernanceActionV1,
            GlobalDataTriggerPermissionGovernanceProposalV1,
        };

        let proposal = ProposalKind::GlobalDataTriggerPermissionGovernance(
            GlobalDataTriggerPermissionGovernanceProposalV1 {
                authority: iroha_test_samples::ALICE_ID.clone(),
                action: GlobalDataTriggerPermissionGovernanceActionV1::Grant,
            },
        );
        assert!(matches!(
            retained_proposal_operator(&proposal),
            Err(Error::AppServiceUnavailable {
                code: "validation_fee_state_inconsistent",
                ..
            })
        ));
    }
    #[test]
    fn compacted_proposal_uses_exact_original_authorization_and_requires_archive_custody() {
        use iroha_core::governance::parliament::enacted_parliament_attempt_for_testing;
        use iroha_data_model::{
            governance::types::ValidationFeePayoutLifecycleProposal,
            parameter::Parameter,
            validation_fee::{
                ValidationFeeParliamentAuthorizationV1, ValidationFeePayoutPolicyEntryV1,
                ValidationFeePayoutPolicyRegistryV1,
            },
        };
        let (mut chain, _, owner, _, _, asset) =
            crate::routing::validation_fee_torii_ingress_tests::native_fee_fixture();
        while chain.height() < 19 {
            chain.commit_at((chain.height() + 1) * 1_000, Vec::new());
        }
        let original_binding = crate::routing::validation_fee_torii_ingress_tests::payout_binding(
            chain.state(),
            &owner,
            &asset,
        );
        let mut registry = ValidationFeePolicyRegistryV1 {
            history: None,
            registered_policies: Vec::new(),
            payout_policies: ValidationFeePayoutPolicyRegistryV1 {
                entries: Vec::new(),
            },
        };
        let mut proposals = Vec::new();
        for revision in 1..=2 {
            let mut binding = original_binding.clone();
            binding.min_reward_claim_xor_minor = revision;
            let kind =
                ProposalKind::ValidationFeePayoutLifecycle(ValidationFeePayoutLifecycleProposal {
                    proposal_operator: owner.clone(),
                    payout_binding: binding.clone(),
                });
            let candidates = (220_u8..=243)
                .map(|seed| {
                    AccountId::new(
                        iroha_crypto::KeyPair::from_seed(
                            vec![seed; 32],
                            iroha_crypto::Algorithm::Ed25519,
                        )
                        .public_key()
                        .clone(),
                    )
                })
                .collect();
            let attempt =
                enacted_parliament_attempt_for_testing(&kind, candidates, &chain.network_id(), 20);
            let certificate = attempt.certificate().unwrap().clone();
            let authorization = ValidationFeeParliamentAuthorizationV1 {
                proposal_operator: owner.clone(),
                proposal_fingerprint: kind.fingerprint(),
                governance_certificate_id: GovernanceCertificateId::derive_v1(&certificate),
                governance_certificate: certificate,
                enacted_at_height: 20,
            };
            registry
                .payout_policies
                .entries
                .push(ValidationFeePayoutPolicyEntryV1 {
                    revision,
                    proposal_id: kind.fingerprint(),
                    lifecycle_seal: binding.lifecycle_seal().unwrap(),
                    payout_binding: binding,
                    parliament_authorization: authorization,
                });
            proposals.push((kind, attempt));
        }
        registry.validate().unwrap();
        // Honiara month boundaries must be representable after the Unix epoch.
        let now = 1_735_650_000_000;
        chain.setup_world_at(now, |stx| {
            for (kind, attempt) in &proposals {
                stx.world.governance_proposals_mut().insert(
                    kind.fingerprint(),
                    iroha_core::state::GovernanceProposalRecord {
                        proposer: owner.clone(),
                        kind: kind.clone(),
                        created_height: 1,
                        status: iroha_core::state::GovernanceProposalStatus::Enacted,
                    },
                );
                stx.world
                    .put_parliament_attempt_for_testing(attempt.attempt().id, attempt.clone())
                    .unwrap();
            }
            stx.world
                .parameters_mut_for_testing()
                .get_mut()
                .set_parameter(Parameter::Custom(
                    registry.clone().into_custom_parameter().expect(
                        "validation-fee fixture registry fits the canonical JSON parameter",
                    ),
                ));
        });
        chain.commit_at(now, Vec::new());
        let proposal_id = proposals[0].0.fingerprint();
        let hot = {
            let view = chain.state().view();
            let proposal = view
                .world()
                .governance_proposals()
                .get(&proposal_id)
                .unwrap();
            public_proposal_record(&view, Some(&registry), proposal_id, proposal).unwrap()
        };
        chain.commit_at(now + 1_000, Vec::new());
        chain.commit_at(now + 2_000, Vec::new());
        let view = chain.state().view();
        let compacted = current_validation_fee_registry(view.world())
            .unwrap()
            .unwrap();
        assert_eq!(compacted.payout_policies.entries.len(), 1);
        assert!(
            retained_registry_authorization(Some(&compacted), proposal_id)
                .unwrap()
                .is_none()
        );
        let proposal = view
            .world()
            .governance_proposals()
            .get(&proposal_id)
            .unwrap();
        let cold = public_proposal_record(&view, Some(&compacted), proposal_id, proposal).unwrap();
        assert_eq!(
            cold, hot,
            "public proposal and exact original certificate survive compaction"
        );
        let path = chain
            .kura()
            .store_root()
            .join("native-contexts")
            .join(format!(
                "{:020}-{}.nrt",
                20,
                hex::encode(chain.committed(20).block_hash().as_ref())
            ));
        let original = std::fs::read(&path).unwrap();
        let hidden = path.with_extension("policy-original");
        std::fs::rename(&path, &hidden).unwrap();
        let missing = public_proposal_record(&view, Some(&compacted), proposal_id, proposal);
        std::fs::rename(&hidden, &path).unwrap();
        assert!(matches!(missing, Err(Error::AppServiceUnavailable { .. })));
        std::fs::write(&path, b"corrupt original registry archive").unwrap();
        let corrupt = public_proposal_record(&view, Some(&compacted), proposal_id, proposal);
        std::fs::write(&path, original).unwrap();
        assert!(matches!(corrupt, Err(Error::AppServiceUnavailable { .. })));
        assert_eq!(
            public_proposal_record(&view, Some(&compacted), proposal_id, proposal).unwrap(),
            hot
        );
    }

    #[test]
    fn catch_up_responses_are_temporary_service_unavailability() {
        for error in [
            inconsistent(iroha_data_model::validation_fee::RETAIL_FEE_CATCH_UP_REQUIRED),
            quote_unavailable(iroha_data_model::validation_fee::RETAIL_FEE_CATCH_UP_REQUIRED),
        ] {
            assert!(matches!(
                error,
                Error::AppServiceUnavailable {
                    code: "ledger_catch_up_required",
                    ..
                }
            ));
        }
    }
    #[test]
    fn proposal_page_traversal_reads_only_limit_plus_one_index_rows() {
        let rows = (0_u64..10_000)
            .map(|created_height| {
                let mut proposal_id = [0_u8; 32];
                proposal_id[..8].copy_from_slice(&created_height.to_be_bytes());
                ((created_height, proposal_id), ())
            })
            .collect::<Vec<_>>();
        let visited = Cell::new(0_usize);
        let indexed = rows
            .iter()
            .inspect(|_| visited.set(visited.get().saturating_add(1)))
            .map(|(key, value)| (key, value));
        let (keys, has_more) = bounded_validation_fee_proposal_keys(indexed, 3);
        assert_eq!(visited.get(), 4, "one lookahead row is the exact bound");
        assert_eq!(keys.len(), 3);
        assert!(has_more);
        assert_eq!(keys[0].0, 0);
        assert_eq!(keys[2].0, 2);
    }
    #[test]
    fn proposal_list_cannot_reintroduce_a_full_governance_scan() {
        let source = include_str!("validation_fee_api.rs");
        let start = source
            .find("fn bounded_validation_fee_proposal_keys")
            .expect("bounded proposal-key projection");
        let tail = &source[start..];
        let end = tail
            .find("/// Return one typed validation-fee Parliament proposal.")
            .expect("proposal-list handler terminator");
        let implementation = &tail[..end];
        assert!(implementation.contains("validation_fee_proposal_index()"));
        assert!(implementation.contains("bounded_validation_fee_proposal_keys(indexed, limit)"));
        assert!(!implementation.contains("governance_proposals().iter()"));
        assert!(!implementation.contains(".sort"));
    }
}
/// Return one bounded finality page for the current validation-fee registry.
pub(crate) async fn handler_current_policy_proof(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    ConnectInfo(remote): ConnectInfo<std::net::SocketAddr>,
    NoritoOnly(request): NoritoOnly<ValidationFeeCurrentPolicyProofRequestV1>,
) -> Result<NoritoBody<ValidationFeeCurrentPolicyProofV1>, Error> {
    check_access(
        &app,
        &headers,
        Some(remote.ip()),
        "v1/validation-fee/policy/current/proof",
    )
    .await?;
    if request.version != VALIDATION_FEE_POLICY_PROOF_VERSION_V1
        || request.trusted_checkpoint_height == 0
    {
        return Err(bad_request(
            "validation-fee proof version or checkpoint height is invalid",
        ));
    }
    let state_view = app.state.view();
    let observed_ledger_tip_height = u64::try_from(state_view.height())
        .map_err(|_| inconsistent("ledger height does not fit the public validation-fee proof"))?;
    if request.trusted_checkpoint_height > observed_ledger_tip_height {
        return Err(bad_request(
            "trusted checkpoint is newer than the observed ledger tip",
        ));
    }
    let evaluated_height = validation_fee_policy_proof_page_tip(
        request.trusted_checkpoint_height,
        observed_ledger_tip_height,
    )
    .ok_or_else(|| bad_request("trusted checkpoint cannot begin a finality page"))?;
    // A hot registry may have compacted since this page tip. Only the exact original
    // certified corpus can open the historical registry commitment.
    let registry =
        iroha_core::query::native_receipts::fee_evidence_block_proof(&state_view, evaluated_height)
            .map_err(|error| {
                inconsistent(format!("original policy registry is unavailable: {error}"))
            })?
            .registry()
            .cloned();
    let proof_view = state_view;
    let evaluated_timestamp_ms =
        iroha_core::sumeragi::certified_chain::committed_block(&proof_view, evaluated_height)
            .map_err(|error| {
                inconsistent(format!("evaluated policy block is unavailable: {error}"))
            })?
            .block_time_ms();
    let expected_commitment = ValidationFeePolicySnapshotCommitmentV1::from_registry(
        evaluated_height,
        evaluated_timestamp_ms,
        registry.as_ref(),
    );
    let policy_witness = iroha_core::query::native_receipts::validation_fee_policy_witness(
        &proof_view,
        evaluated_height,
    )
    .map_err(|error| {
        inconsistent(format!(
            "original native fee policy proof is invalid: {error}"
        ))
    })?;
    if policy_witness.commitment().map_err(inconsistent)? != expected_commitment {
        return Err(inconsistent(
            "retained policy witness differs from the historical protected registry",
        ));
    }
    let proof_count = evaluated_height
        .checked_sub(request.trusted_checkpoint_height)
        .and_then(|gap| gap.checked_add(1))
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(|| bad_request("trusted checkpoint is newer than the evaluated block"))?;
    let chain = iroha_core::sumeragi::certified_chain::CertifiedChain::new(&proof_view)
        .map_err(|error| inconsistent(format!("native finality source is unavailable: {error}")))?;
    let mut finality_chain = Vec::with_capacity(proof_count);
    for height in request.trusted_checkpoint_height..=evaluated_height {
        finality_chain.push(
            iroha_core::sumeragi::finality::build_proof(&proof_view, height).map_err(|error| {
                inconsistent(format!(
                    "finality proof at height {height} is unavailable: {error}"
                ))
            })?,
        );
    }
    let finality_encoded_bytes = norito::core::encoded_frame_len(&finality_chain)
        .map_err(|error| inconsistent(format!("finality chain cannot be encoded: {error}")))?;
    if finality_encoded_bytes > VALIDATION_FEE_POLICY_PROOF_MAX_FINALITY_CHAIN_BYTES {
        return Err(Error::AppConflict {
            code: "validation_fee_finality_page_too_large",
            message: "The bounded finality page exceeds the response byte budget.".to_owned(),
        });
    }
    let evaluated = finality_chain
        .last()
        .ok_or_else(|| inconsistent("finality chain is empty"))?;
    let evaluated_native = chain.committed(evaluated_height).map_err(|error| {
        inconsistent(format!(
            "evaluated native commitment is unavailable: {error}"
        ))
    })?;
    let evaluated_context_id = iroha_crypto::Hash::from(evaluated_native.id().0);
    let evaluated_block_hash = evaluated.block_header.hash();
    let response = ValidationFeeCurrentPolicyProofV1 {
        version: VALIDATION_FEE_POLICY_PROOF_VERSION_V1,
        registry,
        policy_witness,
        finality_chain,
        evaluated_context_id,
        evaluated_block_height: evaluated_height,
        evaluated_block_hash: hex::encode(evaluated_block_hash.as_ref()),
        observed_ledger_tip_height,
        more_available: evaluated_height < observed_ledger_tip_height,
    };
    let response_encoded_bytes = norito::core::encoded_frame_len(&response)
        .map_err(|error| inconsistent(format!("policy proof cannot be encoded: {error}")))?;
    if response_encoded_bytes > VALIDATION_FEE_POLICY_PROOF_MAX_RESPONSE_BYTES {
        return Err(Error::AppConflict {
            code: "validation_fee_policy_proof_too_large",
            message: "The validation-fee proof exceeds the response byte budget.".to_owned(),
        });
    }
    Ok(NoritoBody(response))
}

fn authorize_retail_account(
    world: &impl WorldReadOnly,
    requested: &AccountId,
    authenticated: &AccountId,
) -> Result<(), Error> {
    if requested == authenticated
        || crate::routing::is_live_multisig_signatory_in_world(world, requested, authenticated)
            .unwrap_or(false)
        || iroha_core::retail_fee::is_account_issuer_for_primary_alias(
            world,
            authenticated,
            requested,
        )
        .map_err(|error| fee_read_transport_error(error, inconsistent))?
    {
        return Ok(());
    }
    Err(Error::AppForbidden{code:"retail_fee_account_mismatch",message:"authenticated account must be the wallet, its direct multisig signatory, or its registered primary-alias domain issuer".into()})
}
/// Evaluate actual finalized wallet counters and bind the complete ordered payment intent.
pub(crate) async fn handler_retail_quote(
    State(app): State<SharedAppState>,
    Extension(verified): Extension<crate::app_auth::VerifiedCanonicalRequest>,
    headers: HeaderMap,
    ConnectInfo(remote): ConnectInfo<std::net::SocketAddr>,
    NoritoJson(request): NoritoJson<iroha_data_model::validation_fee::RetailFeeQuoteRequestV1>,
) -> Result<JsonBody<iroha_torii_shared::validation_fee_api::RetailFeeQuoteResponseV1>, Error> {
    check_access(&app, &headers, Some(remote.ip()), "v1/validation-fee/quote").await?;
    let state = app.state.view();
    authorize_retail_account(state.world(), &request.account_id, &verified.account)?;
    let height =
        u64::try_from(state.height()).map_err(|_| inconsistent("ledger height overflow"))?;
    let now_ms = state.query_ledger_time_ms();
    let assessment = iroha_core::retail_fee::quote(state.world(), height, now_ms, &request)
        .map_err(|error| fee_read_transport_error(error, quote_unavailable))?;
    let policy = iroha_core::retail_fee::policy_at(state.world(), height, now_ms)
        .map_err(|error| fee_read_transport_error(error, inconsistent))?
        .ok_or_else(|| quote_unavailable("fee policy is not active"))?;
    Ok(JsonBody(
        iroha_torii_shared::validation_fee_api::RetailFeeQuoteResponseV1 {
            request,
            assessment,
            policy_hash_hex: hex::encode(
                policy
                    .policy_hash()
                    .map_err(|e| inconsistent(e.to_string()))?,
            ),
            ledger_finalised_height: height,
        },
    ))
}
/// Return logically settled maintenance and allowance status for an authenticated wallet.
pub(crate) async fn handler_retail_status(
    State(app): State<SharedAppState>,
    Extension(verified): Extension<crate::app_auth::VerifiedCanonicalRequest>,
    headers: HeaderMap,
    ConnectInfo(remote): ConnectInfo<std::net::SocketAddr>,
    Path(account_id): Path<String>,
) -> Result<JsonBody<iroha_torii_shared::validation_fee_api::RetailFeeStatusResponseV1>, Error> {
    check_access(
        &app,
        &headers,
        Some(remote.ip()),
        "v1/validation-fee/accounts/{account_id}/status",
    )
    .await?;
    let account = AccountId::parse_encoded(&account_id).map_err(|e| bad_request(e.to_string()))?;
    let state = app.state.view();
    authorize_retail_account(state.world(), &account, &verified.account)?;
    let height =
        u64::try_from(state.height()).map_err(|_| inconsistent("ledger height overflow"))?;
    let now_ms = state.query_ledger_time_ms();
    let policy = iroha_core::retail_fee::policy_at(state.world(), height, now_ms)
        .map_err(|error| fee_read_transport_error(error, inconsistent))?
        .ok_or_else(|| quote_unavailable("fee policy is not active"))?;
    let account_state = iroha_core::retail_fee::status(state.world(), &account, now_ms)
        .map_err(|error| fee_read_transport_error(error, inconsistent))?;
    let estimated_maintenance_minor = account_state
        .as_ref()
        .map(|account| {
            policy
                .retail_schedule
                .monthly_fee(account.balance_time_minor_ms, account.active_time_ms)
        })
        .transpose()
        .map_err(inconsistent)?
        .unwrap_or(0);
    let registry = current_validation_fee_registry(state.world())?;
    let forthcoming_policy = registry.and_then(|registry| {
        registry
            .registered_policies
            .into_iter()
            .find(|entry| entry.policy.effective_from_ms > now_ms)
            .map(|entry| entry.policy)
    });
    Ok(JsonBody(
        iroha_torii_shared::validation_fee_api::RetailFeeStatusResponseV1 {
            account_state,
            policy_hash_hex: hex::encode(
                policy
                    .policy_hash()
                    .map_err(|e| inconsistent(e.to_string()))?,
            ),
            ledger_finalised_height: height,
            institutional_fee_minor: iroha_data_model::fastpq::normalized_numeric_to_u64(
                policy.fee.as_numeric(),
                2,
            )
            .ok_or_else(|| inconsistent("institutional fee is not exact SBD cents"))?,
            retail_schedule: policy.retail_schedule,
            estimated_maintenance_minor,
            forthcoming_policy,
        },
    ))
}

/// Query immutable native receipts without reconstructing fees from treasury deposits.
pub(crate) async fn handler_retail_receipts(
    State(app): State<SharedAppState>,
    Extension(verified): Extension<crate::app_auth::VerifiedCanonicalRequest>,
    headers: HeaderMap,
    ConnectInfo(remote): ConnectInfo<std::net::SocketAddr>,
    Path(account_id): Path<String>,
    NoritoQuery(query): NoritoQuery<
        iroha_torii_shared::validation_fee_api::RetailFeeReceiptsQueryV1,
    >,
) -> Result<JsonBody<iroha_torii_shared::validation_fee_api::RetailFeeReceiptsResponseV1>, Error> {
    check_access(
        &app,
        &headers,
        Some(remote.ip()),
        "v1/validation-fee/accounts/{account_id}/receipts",
    )
    .await?;
    let account = AccountId::parse_encoded(&account_id).map_err(|e| bad_request(e.to_string()))?;
    let state = app.state.view();
    authorize_retail_account(state.world(), &account, &verified.account)?;
    let limit = query.limit.unwrap_or(50) as usize;
    let after = query
        .after_receipt_id
        .as_deref()
        .map(parse_proposal_id)
        .transpose()?;
    let receipts = iroha_core::retail_fee::receipts(state.world(), &account, after, limit)
        .map_err(|error| fee_read_transport_error(error, bad_request))?;
    let next_receipt_id = (receipts.len() == limit)
        .then(|| {
            receipts
                .last()
                .map(|receipt| hex::encode(receipt.receipt_id))
        })
        .flatten();
    let ledger_finalised_height =
        u64::try_from(state.height()).map_err(|_| inconsistent("ledger height overflow"))?;
    let mut proof_by_height = std::collections::BTreeMap::new();
    let mut receipt_proofs = Vec::with_capacity(receipts.len());
    for receipt in &receipts {
        let key = iroha_data_model::validation_fee::retail_fee_receipt_state_key_v1(receipt)
            .map_err(inconsistent)?;
        let proof = iroha_core::query::native_receipts::fee_evidence_record_proof(
            &state,
            receipt.recorded_at_height,
            &key,
        )
        .map_err(|e| inconsistent(format!("native fee receipt proof unavailable: {e}")))?
        .ok_or_else(|| {
            inconsistent("native fee receipt has no immutable finalized membership proof")
        })?;
        if !proof_by_height.contains_key(&receipt.recorded_at_height) {
            let finality =
                iroha_core::sumeragi::finality::build_proof(&state, receipt.recorded_at_height)
                    .map_err(|e| inconsistent(format!("receipt finality unavailable: {e}")))?;
            proof_by_height.insert(receipt.recorded_at_height, finality);
        }
        let root = proof_by_height[&receipt.recorded_at_height]
            .decode_checked(
                state
                    .native_execution_tip()
                    .ok_or_else(|| inconsistent("native execution scope unavailable"))?
                    .root_scope()
                    .into(),
            )
            .map_err(|e| inconsistent(format!("receipt finality is malformed: {e}")))?
            .execution()
            .ordinary_writes_root;
        if !proof.verify(root)
            || proof.record.payload
                != iroha_data_model::fee_evidence::FeeEvidencePayloadV1::RetailReceipt(
                    receipt.clone(),
                )
        {
            return Err(inconsistent(
                "immutable native receipt proof differs from its finalized receipt",
            ));
        }
        receipt_proofs.push(proof);
    }
    let response = iroha_torii_shared::validation_fee_api::RetailFeeReceiptsResponseV1 {
        receipts,
        receipt_proofs,
        finality_proofs: proof_by_height.into_values().collect(),
        ledger_finalised_height,
        next_receipt_id,
        assurance: "NATIVE_RECEIPT_MEMBERSHIP_PROOFS_REQUIRING_TRUSTED_FINALITY_VERIFICATION"
            .into(),
    };
    if norito::json::to_vec(&response)
        .map_err(|e| inconsistent(e.to_string()))?
        .len()
        > 8 * 1024 * 1024
    {
        return Err(Error::AppConflict {
            code: "retail_fee_receipt_page_too_large",
            message:
                "Receipt evidence exceeds the bounded response budget; request a smaller page."
                    .into(),
        });
    }
    Ok(JsonBody(response))
}

/// Read one current cumulative wallet head against exactly matching finalized evidence.
pub(crate) async fn handler_retail_statement_head(
    State(app): State<SharedAppState>,
    Extension(verified): Extension<crate::app_auth::VerifiedCanonicalRequest>,
    headers: HeaderMap,
    ConnectInfo(remote): ConnectInfo<std::net::SocketAddr>,
    Path(account_id): Path<String>,
) -> Result<JsonBody<iroha_torii_shared::validation_fee_api::RetailFeeCurrentHeadResponseV1>, Error>
{
    use iroha_data_model::fee_evidence::RetailFeeCurrentHeadProofV1;
    check_access(
        &app,
        &headers,
        Some(remote.ip()),
        "v1/validation-fee/accounts/{account_id}/statement/head",
    )
    .await?;
    let account = AccountId::parse_encoded(&account_id).map_err(|e| bad_request(e.to_string()))?;
    let state = app.state.view();
    authorize_retail_account(state.world(), &account, &verified.account)?;
    let head = iroha_core::retail_fee::receipt_head(state.world(), &account)
        .map_err(|error| fee_read_transport_error(error, inconsistent))?
        .ok_or_else(|| Error::AppNotFound {
            code: "retail_fee_head_unavailable",
            message: "wallet has no committed receipt head".into(),
        })?;
    let height =
        u64::try_from(state.height()).map_err(|_| inconsistent("ledger height overflow"))?;
    let (root, head_siblings) =
        iroha_core::validation_fee_rewards::receipt_head_membership(state.world(), &head)
            .map_err(|error| fee_read_transport_error(error, inconsistent))?;
    let evidence = iroha_core::query::native_receipts::fee_evidence_block_proof(&state, height)
        .map_err(|e| inconsistent(format!("finalized wallet head evidence unavailable: {e}")))?;
    if evidence
        .snapshot_witness
        .commitment()
        .map_err(inconsistent)?
        .account_heads_root
        != root
    {
        return Err(inconsistent(
            "current wallet head tree differs from its exact finalized block; retry with a matching checkpoint",
        ));
    }
    let finality_proof = iroha_core::sumeragi::finality::build_proof(&state, height)
        .map_err(|e| inconsistent(format!("wallet head finality unavailable: {e}")))?;
    let scope = state
        .native_execution_tip()
        .ok_or_else(|| inconsistent("native execution scope unavailable"))?
        .root_scope()
        .into();
    drop(state);
    let ordinary_writes_root = finality_proof
        .decode_checked(scope)
        .map_err(|e| inconsistent(format!("wallet head finality is malformed: {e}")))?
        .execution()
        .ordinary_writes_root;
    let wallet_id = head.wallet_id.clone();
    let proof = RetailFeeCurrentHeadProofV1 {
        snapshot_witness: evidence.snapshot_witness,
        head,
        head_siblings,
    };
    proof
        .verify(ordinary_writes_root, &wallet_id, &account, height)
        .map_err(inconsistent)?;
    let response = iroha_torii_shared::validation_fee_api::RetailFeeCurrentHeadResponseV1 {
        proof,
        finality_proof,
    };
    if norito::json::to_vec(&response)
        .map_err(|e| inconsistent(e.to_string()))?
        .len()
        > 8 * 1024 * 1024
    {
        return Err(Error::AppConflict {
            code: "retail_fee_head_proof_too_large",
            message: "native wallet head and finality proof exceed the 8 MiB response budget"
                .into(),
        });
    }
    Ok(JsonBody(response))
}
/// Return bounded immutable account history without requiring intervening block proofs.
pub(crate) async fn handler_retail_statement(
    State(app): State<SharedAppState>,
    Extension(verified): Extension<crate::app_auth::VerifiedCanonicalRequest>,
    headers: HeaderMap,
    ConnectInfo(remote): ConnectInfo<std::net::SocketAddr>,
    Path(account_id): Path<String>,
    NoritoJson(request): NoritoJson<
        iroha_torii_shared::validation_fee_api::RetailFeeStatementRequestV1,
    >,
) -> Result<JsonBody<iroha_torii_shared::validation_fee_api::RetailFeeStatementResponseV1>, Error> {
    check_access(
        &app,
        &headers,
        Some(remote.ip()),
        "v1/validation-fee/accounts/{account_id}/statement",
    )
    .await?;
    let account = AccountId::parse_encoded(&account_id).map_err(|e| bad_request(e.to_string()))?;
    let state = app.state.view();
    authorize_retail_account(state.world(), &account, &verified.account)?;
    let expected_wallet = iroha_core::retail_fee::receipt_wallet_id(state.world(), &account)
        .map_err(|error| fee_read_transport_error(error, inconsistent))?;
    if request.cursor.wallet_id != expected_wallet {
        return Err(Error::AppForbidden {
            code: "retail_fee_account_mismatch",
            message:
                "receipt frontier must select exactly the authorized protected wallet identity"
                    .into(),
        });
    }
    let page = iroha_core::retail_fee::receipt_page(
        state.world(),
        &request.cursor,
        request.limit as usize,
    )
    .map_err(|error| fee_read_transport_error(error, bad_request))?;
    let next_cursor = page.verify(&request.cursor).map_err(inconsistent)?;
    let response = iroha_torii_shared::validation_fee_api::RetailFeeStatementResponseV1 {
        cursor: request.cursor,
        page,
        next_cursor,
    };
    if norito::json::to_vec(&response)
        .map_err(|e| inconsistent(e.to_string()))?
        .len()
        > 1024 * 1024
    {
        return Err(Error::AppConflict { code: "retail_fee_statement_too_large", message: "private receipt page exceeds 1 MiB; request a smaller page using the same verified frontier".into() });
    }
    Ok(JsonBody(response))
}
