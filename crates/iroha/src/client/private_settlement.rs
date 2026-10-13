//! Fail-closed Rust client surface for atomic private settlement Torii routes.
//!
//! Account-authenticated operations use the client's transaction authority.
//! Committee and auditor operations require an explicitly supplied role key so
//! consensus, auditor, and ordinary operator identities never share implicit
//! client state.

use super::*;

mod operation;
mod verified;
pub use operation::{
    PrivateSettlementError, PrivateSettlementOperation, PrivateSettlementRecovery,
    PrivateSettlementRequest, PrivateSettlementResult, PrivateSettlementRunOptions,
};
pub use verified::{PrivateSettlementReceiptError, VerifiedPrivateSettlementReceipt};

use iroha_data_model::{
    isi::private_settlement::{
        AbortAtomicPrivateSettlementV1, FinalizeAtomicPrivateSettlementV1,
        RegisterAtomicPrivateSettlementPrepareV1,
    },
    nexus::{
        ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1, AtomicPrivateSettlementV1,
        PRIVATE_SETTLEMENT_BLS_BYTES_V1, PRIVATE_SETTLEMENT_COMMITTEE_QUORUM_V1,
        PRIVATE_SETTLEMENT_COMMITTEE_VALIDATORS_V1, PRIVATE_SETTLEMENT_MAX_RECEIPT_BYTES_V1,
        PrivateSettlementAbortReasonV1, PrivateSettlementAuthorityCatalogV1,
        PrivateSettlementAvailabilityShareV1, PrivateSettlementCommitBundleV1,
        PrivateSettlementCommitteeAuthorityV1, PrivateSettlementDeltaV1,
        PrivateSettlementLegReceiptV1, PrivateSettlementPhaseBodyV1,
        PrivateSettlementPhaseCertificateV1, PrivateSettlementPhaseV1,
        PrivateSettlementPhaseVoteV1, PrivateSettlementPrepareBarrierV1,
        PrivateSettlementProvisionalLegMaterialV1, PrivateSettlementSidecarAvailabilityBodyV1,
        PrivateSettlementSidecarAvailabilityV1,
    },
    transaction::Executable,
};
use iroha_model_base::peer::PeerId;
use iroha_torii_shared::private_settlement_api::{
    PrivateSettlementAuditApprovalRequestV1, PrivateSettlementAuditApprovalResponseV1,
    PrivateSettlementAuditorCapsuleRequestV1, PrivateSettlementAuditorCapsuleResponseV1,
    PrivateSettlementAvailabilityShareRequestV1, PrivateSettlementAvailabilityShareResponseV1,
    PrivateSettlementBundleReceiptResponseV1, PrivateSettlementBundleStatusResponseV1,
    PrivateSettlementBundleSubmitRequestV1, PrivateSettlementBundleSubmitResponseV1,
    PrivateSettlementCommitVoteRequestV1, PrivateSettlementCommitteeProofResponseV1,
    PrivateSettlementLegStatusResponseV1, PrivateSettlementLegUploadRequestV1,
    PrivateSettlementLegUploadResponseV1, PrivateSettlementLifecycleDtoV1,
    PrivateSettlementPhaseCertificateRequestV1, PrivateSettlementPhaseCertificateResponseV1,
    PrivateSettlementPhaseCertificatesResponseV1, PrivateSettlementPhaseVoteResponseV1,
    PrivateSettlementPrepareVoteRequestV1, validate_private_settlement_audit_approval_response_v1,
    validate_private_settlement_auditor_capsule_response_v1,
    validate_private_settlement_auditor_identity_v1,
    validate_private_settlement_committee_proof_response_v1,
};
use std::collections::{BTreeMap, BTreeSet};

const PRIVATE_SETTLEMENT_RESPONSE_MAX_BYTES_V1: usize = 32 * 1024 * 1024;

// Diagnostic values are closed local categories or recognized public codes.
// Never retain the request URL, headers, body, or arbitrary transport/server text.
#[derive(Clone, Copy, Debug, thiserror::Error)]
enum PrivateSettlementAvailabilityFailureV1 {
    #[error("invalid_provisional_material")]
    InvalidMaterial,
    #[error("manifest_sponsor_required")]
    SponsorRequired,
    #[error("request_encoding_failed")]
    RequestEncoding,
    #[error("request_signing_failed")]
    RequestSigning,
    #[error("transport_failed")]
    Transport,
    #[error("transport_timeout")]
    TransportTimeout,
    #[error("http_status={status}, public_code={public_code:?}")]
    Http {
        status: u16,
        public_code: Option<&'static str>,
    },
    #[error("invalid_response_content_type")]
    InvalidContentType,
    #[error("invalid_response_json")]
    InvalidJson,
    #[error("invalid_availability_share")]
    InvalidShare,
    #[error("substituted_response_binding")]
    SubstitutedResponse,
    #[error("request_failed")]
    Request,
}

impl PrivateSettlementAvailabilityFailureV1 {
    fn transport(error: &eyre::Report) -> Self {
        if error.chain().any(|cause| {
            cause
                .downcast_ref::<reqwest::Error>()
                .is_some_and(reqwest::Error::is_timeout)
                || cause
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::TimedOut)
        }) {
            Self::TransportTimeout
        } else {
            Self::Transport
        }
    }
}

#[derive(Debug)]
struct PrivateSettlementAvailabilityQuorumFailureV1 {
    valid_shares: usize,
    // Bounded to the four roster positions by the collector below.
    failures: Vec<(usize, PrivateSettlementAvailabilityFailureV1)>,
}

impl std::fmt::Display for PrivateSettlementAvailabilityQuorumFailureV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "private-settlement availability quorum is unavailable: valid_shares={}, required_quorum={}",
            self.valid_shares, PRIVATE_SETTLEMENT_COMMITTEE_QUORUM_V1
        )?;
        for (index, failure) in &self.failures {
            write!(formatter, "; roster[{index}]={failure}")?;
        }
        Ok(())
    }
}

impl std::error::Error for PrivateSettlementAvailabilityQuorumFailureV1 {}

fn private_settlement_availability_public_code_v1(
    response: &Response<Vec<u8>>,
) -> Option<&'static str> {
    const CODES: &[&str] = &[
        "request_payload_too_large",
        "request_body_read_failed",
        "request_timeout",
        "rate_limited",
        "request_rate_limited",
        "service_unavailable",
        "bad_request",
        "not_found",
        "method_not_allowed",
        "conflict",
        "gone",
        "request_content_type_unsupported",
        "unprocessable_entity",
        "not_implemented",
        "bad_gateway",
        "gateway_timeout",
        "internal_server_error",
        "http_error",
        "route_unavailable",
        "unauthorized",
        "forbidden",
        "private_settlement_unavailable",
        "private_settlement_invalid_request",
        "private_settlement_conflict",
        "private_settlement_invalid_transition",
        "private_settlement_capacity_exceeded",
        "private_settlement_service_unavailable",
        "private_settlement_height_unavailable",
        "private_settlement_sponsor_required",
        "private_settlement_control_invalid",
        "private_settlement_controlled_loss",
    ];
    let recognized = |value: &str| CODES.iter().copied().find(|known| *known == value);
    let mut headers = response.headers().get_all("x-iroha-reject-code").iter();
    if let Some(header) = headers.next()
        && headers.next().is_none()
        && header.as_bytes().len() <= 96
        && let Ok(value) = header.to_str()
        && let Some(code) = recognized(value)
    {
        return Some(code);
    }
    // The route's error envelope exposes only a public `code`. A small parse
    // bound avoids parsing arbitrary large rejection bodies for diagnostics.
    if response.body().len() > 4096
        || !Client::is_json_content_type(Client::response_content_type(response))
    {
        return None;
    }
    let value: norito::json::Value = norito::json::from_slice(response.body()).ok()?;
    recognized(value.get("code")?.as_str()?)
}

fn decode_private_settlement_availability_response_v1(
    response: &Response<Vec<u8>>,
) -> Result<PrivateSettlementAvailabilityShareResponseV1> {
    if response.status() != StatusCode::OK {
        return Err(eyre!(PrivateSettlementAvailabilityFailureV1::Http {
            status: response.status().as_u16(),
            public_code: private_settlement_availability_public_code_v1(response),
        }));
    }
    if !Client::is_json_content_type(Client::response_content_type(response)) {
        return Err(eyre!(
            PrivateSettlementAvailabilityFailureV1::InvalidContentType
        ));
    }
    norito::json::from_slice(response.body())
        .map_err(|_| eyre!(PrivateSettlementAvailabilityFailureV1::InvalidJson))
}

fn collect_private_settlement_availability_shares_v1(
    authority: &PrivateSettlementCommitteeAuthorityV1,
    mut request: impl FnMut(usize) -> Result<PrivateSettlementAvailabilityShareResponseV1>,
) -> Result<Vec<PrivateSettlementAvailabilityShareV1>> {
    let roster_len = PRIVATE_SETTLEMENT_COMMITTEE_VALIDATORS_V1;
    if authority.validators.len() != roster_len {
        return Err(eyre!(
            "private-settlement availability requires the four-validator roster"
        ));
    }
    let mut shares = Vec::with_capacity(roster_len);
    let mut failures = Vec::with_capacity(roster_len);
    for index in 0..roster_len {
        let response = match request(index) {
            Ok(response) => response,
            Err(error) => {
                let cause = error
                    .downcast_ref::<PrivateSettlementAvailabilityFailureV1>()
                    .copied()
                    .unwrap_or(PrivateSettlementAvailabilityFailureV1::Request);
                failures.push((index, cause));
                continue;
            }
        };
        if response.share.signer != authority.validators[index] {
            return Err(eyre!(
                "private-settlement availability endpoint identity is substituted at roster[{index}]"
            ));
        }
        shares.push(response.share);
    }
    if shares.len() < usize::from(PRIVATE_SETTLEMENT_COMMITTEE_QUORUM_V1) {
        return Err(eyre!(PrivateSettlementAvailabilityQuorumFailureV1 {
            valid_shares: shares.len(),
            failures,
        }));
    }
    Ok(shares)
}

/// Issue one Prepare request per committee member and join every initiated worker.
///
/// Results retain roster order, including ordinary request rejections. A local
/// worker launch or panic is a fatal orchestration error, never an unavailable
/// validator vote. No response is consumed until all initiated requests finish.
fn collect_private_settlement_prepare_responses_v1<T, F>(request: F) -> Result<Vec<Result<T>>>
where
    T: Send,
    F: Fn(usize) -> Result<T> + Sync,
{
    const REQUESTS: usize = PRIVATE_SETTLEMENT_COMMITTEE_VALIDATORS_V1;
    std::thread::scope(|scope| {
        let request = &request;
        let children: [_; REQUESTS] = std::array::from_fn(|index| {
            std::thread::Builder::new()
                .name(format!("aps-prepare-{index}"))
                .spawn_scoped(scope, move || request(index))
        });
        // Array::map completes every join before Result collection can return
        // the first roster-ordered orchestration error. Do not fuse these into
        // an iterator that could short-circuit and discard an initiated owner.
        let joined = children.map(|child| {
            child.map_or_else(
                |_| {
                    Err(eyre!(
                        "private-settlement Prepare request worker could not start"
                    ))
                },
                |child| {
                    child
                        .join()
                        .map_err(|_| eyre!("private-settlement Prepare request worker panicked"))
                },
            )
        });
        joined.into_iter().collect()
    })
}

fn validate_private_settlement_audit_approval_request_identity_v1(
    network_id: &NetworkId,
    auditor_signing_key: &PublicKey,
    request: &PrivateSettlementAuditApprovalRequestV1,
) -> Result<()> {
    request
        .audit_policy
        .validate()
        .map_err(|_| eyre!("private-settlement auditor approval identity is invalid"))?;
    let auditor = request
        .audit_policy
        .body
        .auditors
        .iter()
        .find(|auditor| auditor.auditor_id == request.approval.body.auditor_id)
        .ok_or_else(|| eyre!("private-settlement auditor approval identity is invalid"))?;
    if request.approval.body.version != ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1
        || &request.approval.body.network_id != network_id
        || request.approval.body.dataspace_id != request.audit_policy.body.dataspace_id
        || request.approval.body.audit_policy_digest != request.audit_policy.policy_digest
        || request.approval.body.audit_key_epoch != request.audit_policy.body.key_epoch
        || &auditor.signing_key != auditor_signing_key
    {
        return Err(eyre!(
            "private-settlement auditor approval identity is invalid"
        ));
    }
    request
        .approval
        .signature
        .verify(auditor_signing_key, &request.approval.body)
        .map_err(|_| eyre!("private-settlement auditor approval identity is invalid"))
}

fn private_settlement_resource_path_v1(kind: &str, identifier: &Hash, suffix: &str) -> String {
    format!("v1/nexus/private-settlements/{kind}/{identifier}{suffix}")
}

#[cfg(test)]
struct ExactPrivateSettlementQuorumViewV1<T> {
    representative: T,
    count: usize,
    authoritative_heights: Vec<u64>,
}

struct PrivateSettlementAuthenticatedQuorumCandidateV1<T> {
    endpoint_index: usize,
    authority: PrivateSettlementCommitteeAuthorityV1,
    responder: PeerId,
    canonical_view: Vec<u8>,
    authoritative_height: u64,
    response: T,
}

struct ExactPrivateSettlementAuthenticatedQuorumViewV1<T> {
    responses: Vec<(u64, T)>,
    responders: BTreeSet<PeerId>,
}

fn validate_private_settlement_endpoint_v1(endpoint: &Url) -> Result<()> {
    if !matches!(endpoint.scheme(), "http" | "https")
        || endpoint.cannot_be_a_base()
        || endpoint.host().is_none()
        || !endpoint.path().ends_with('/')
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(eyre!("private-settlement committee endpoint is invalid"));
    }
    Ok(())
}

fn validate_private_settlement_committee_endpoints_v1(endpoints: &[Url]) -> Result<()> {
    for endpoint in endpoints {
        validate_private_settlement_endpoint_v1(endpoint)?;
    }
    let unique = endpoints.iter().map(Url::as_str).collect::<BTreeSet<_>>();
    if endpoints.len() != PRIVATE_SETTLEMENT_COMMITTEE_VALIDATORS_V1
        || unique.len() != PRIVATE_SETTLEMENT_COMMITTEE_VALIDATORS_V1
    {
        return Err(eyre!(
            "private-settlement committee endpoints must be four distinct URLs"
        ));
    }
    Ok(())
}

fn admit_private_settlement_auditor_responder_v1(
    authority: &PrivateSettlementCommitteeAuthorityV1,
    endpoint_index: usize,
    responder: &PeerId,
    admitted: &mut BTreeSet<PeerId>,
) -> Result<()> {
    if authority.validators.get(endpoint_index) != Some(responder) {
        return Err(eyre!(
            "private-settlement auditor endpoint identity is substituted"
        ));
    }
    if !admitted.insert(responder.clone()) {
        return Err(eyre!(
            "private-settlement auditor responder identity is duplicated"
        ));
    }
    Ok(())
}

fn select_private_settlement_authenticated_quorum_v1<T>(
    expected_authority: Option<&PrivateSettlementCommitteeAuthorityV1>,
    candidates: Vec<PrivateSettlementAuthenticatedQuorumCandidateV1<T>>,
) -> Result<T> {
    let mut views = BTreeMap::<Vec<u8>, ExactPrivateSettlementAuthenticatedQuorumViewV1<T>>::new();
    for candidate in candidates {
        let authority = if let Some(expected) = expected_authority {
            if candidate.authority != *expected {
                continue;
            }
            expected
        } else {
            &candidate.authority
        };
        let entry = views.entry(candidate.canonical_view).or_insert_with(|| {
            ExactPrivateSettlementAuthenticatedQuorumViewV1 {
                responses: Vec::with_capacity(PRIVATE_SETTLEMENT_COMMITTEE_VALIDATORS_V1),
                responders: BTreeSet::new(),
            }
        });
        if admit_private_settlement_auditor_responder_v1(
            authority,
            candidate.endpoint_index,
            &candidate.responder,
            &mut entry.responders,
        )
        .is_err()
        {
            continue;
        }
        entry
            .responses
            .push((candidate.authoritative_height, candidate.response));
    }
    let mut exact = views
        .into_values()
        .find(|view| view.responses.len() >= usize::from(PRIVATE_SETTLEMENT_COMMITTEE_QUORUM_V1))
        .ok_or_else(|| eyre!("private-settlement exact auditor quorum is unavailable"))?
        .responses;
    exact.sort_by_key(|(authoritative_height, _)| *authoritative_height);
    let median_index = exact.len() / 2;
    Ok(exact.swap_remove(median_index).1)
}

#[cfg(test)]
fn collect_exact_private_settlement_quorum_v1<T, Request, Normalize>(
    endpoints: &[Url],
    mut request: Request,
    mut normalize: Normalize,
    unavailable_message: &'static str,
) -> Result<(T, u64)>
where
    Request: FnMut(&Url) -> Result<T>,
    Normalize: FnMut(&T) -> Result<(Vec<u8>, u64)>,
{
    validate_private_settlement_committee_endpoints_v1(endpoints)?;
    let mut views = BTreeMap::<Vec<u8>, ExactPrivateSettlementQuorumViewV1<T>>::new();
    for endpoint in endpoints {
        let Ok(response) = request(endpoint) else {
            continue;
        };
        let Ok((canonical_view, authoritative_height)) = normalize(&response) else {
            continue;
        };
        let entry =
            views
                .entry(canonical_view)
                .or_insert_with(|| ExactPrivateSettlementQuorumViewV1 {
                    representative: response,
                    count: 0,
                    authoritative_heights: Vec::with_capacity(
                        PRIVATE_SETTLEMENT_COMMITTEE_VALIDATORS_V1,
                    ),
                });
        entry.count = entry.count.saturating_add(1);
        entry.authoritative_heights.push(authoritative_height);
    }
    views
        .into_values()
        .find(|view| view.count >= usize::from(PRIVATE_SETTLEMENT_COMMITTEE_QUORUM_V1))
        .map(|mut view| {
            view.authoritative_heights.sort_unstable();
            // With at least three responses and at most one Byzantine member,
            // the middle order statistic is bounded by honest observations.
            // A lone high or low outlier therefore cannot choose the policy
            // evaluation height.
            let quorum_height = view.authoritative_heights[view.authoritative_heights.len() / 2];
            (view.representative, quorum_height)
        })
        .ok_or_else(|| eyre!(unavailable_message))
}

fn private_settlement_leg_ordinal_for_payload_v1(
    manifest: &AtomicPrivateSettlementV1,
    payload_digest: Hash,
) -> Result<u8> {
    let mut matches = manifest
        .legs
        .iter()
        .filter(|leg| leg.payload_digest == payload_digest);
    let ordinal = matches
        .next()
        .map(|leg| leg.ordinal)
        .ok_or_else(|| eyre!("private-settlement payload is not in the manifest"))?;
    if matches.next().is_some() {
        return Err(eyre!("private-settlement payload digest is duplicated"));
    }
    Ok(ordinal)
}

fn exact_private_settlement_carrier_v1(
    transaction: &SignedTransaction,
) -> Result<&AtomicPrivateSettlementV1> {
    let Executable::Instructions(instructions) = transaction.instructions() else {
        return Err(eyre!(
            "private-settlement bundle submission requires one direct carrier"
        ));
    };
    if instructions.len() != 1 {
        return Err(eyre!(
            "private-settlement bundle submission requires one direct carrier"
        ));
    }
    let instruction = instructions[0].as_any();
    if let Some(carrier) = instruction.downcast_ref::<RegisterAtomicPrivateSettlementPrepareV1>() {
        return Ok(&carrier.barrier.manifest);
    }
    if let Some(carrier) = instruction.downcast_ref::<FinalizeAtomicPrivateSettlementV1>() {
        return Ok(&carrier.commit_bundle.manifest);
    }
    if let Some(carrier) = instruction.downcast_ref::<AbortAtomicPrivateSettlementV1>() {
        return Ok(&carrier.manifest);
    }
    Err(eyre!(
        "private-settlement bundle submission requires one direct carrier"
    ))
}

// One validator for the final manifest over the exact retained all-leg snapshot.
fn private_settlement_manifest_with_availability_v1(
    materials: &[PrivateSettlementProvisionalLegMaterialV1],
    certificates: &[PrivateSettlementSidecarAvailabilityV1],
) -> Result<AtomicPrivateSettlementV1> {
    let first = materials
        .first()
        .ok_or_else(|| eyre!("private-settlement provisional leg set is empty"))?;
    if materials.len() != first.manifest.legs.len() || certificates.len() != materials.len() {
        return Err(eyre!(
            "private-settlement availability snapshot is incomplete"
        ));
    }
    let mut manifest = first.manifest.clone();
    for (index, (material, certificate)) in materials.iter().zip(certificates).enumerate() {
        material
            .validate()
            .map_err(|_| eyre!("private-settlement provisional leg is invalid"))?;
        if material.manifest != first.manifest
            || usize::from(material.statement.leg_ordinal) != index
            || certificate.body != material.availability_body
        {
            return Err(eyre!(
                "private-settlement availability snapshot is substituted"
            ));
        }
        validate_availability_certificate_v1(certificate, &material.committee_authority)?;
        manifest.legs[index].availability_certificate_digest = certificate.digest()?;
    }
    manifest
        .validate()
        .map_err(|_| eyre!("private-settlement final manifest is invalid"))?;
    Ok(manifest)
}

fn validate_availability_certificate_v1(
    certificate: &PrivateSettlementSidecarAvailabilityV1,
    authority: &PrivateSettlementCommitteeAuthorityV1,
) -> Result<()> {
    certificate
        .validate_shape()
        .map_err(|_| eyre!("private-settlement availability certificate is invalid"))?;
    authority
        .validate()
        .map_err(|_| eyre!("private-settlement availability certificate is invalid"))?;
    let authority_digest = authority
        .digest()
        .map_err(|_| eyre!("private-settlement availability certificate is invalid"))?;
    if certificate.body.route != authority.route
        || certificate.body.authority_digest != authority_digest
    {
        return Err(eyre!(
            "private-settlement availability certificate is invalid"
        ));
    }
    let mut signer_keys = Vec::with_capacity(3);
    let mut signer_pops = Vec::with_capacity(3);
    for (index, (validator, pop)) in authority
        .validators
        .iter()
        .zip(&authority.validator_pops)
        .enumerate()
    {
        if validator.public_key().try_algorithm().ok() != Some(Algorithm::BlsNormal)
            || iroha_crypto::bls_normal_pop_verify(validator.public_key(), pop).is_err()
        {
            return Err(eyre!(
                "private-settlement availability certificate is invalid"
            ));
        }
        if certificate.signers_bitmap & (1_u8 << index) != 0 {
            signer_keys.push(validator.public_key());
            signer_pops.push(pop.as_slice());
        }
    }
    let preimage = certificate
        .signature_preimage()
        .map_err(|_| eyre!("private-settlement availability certificate is invalid"))?;
    iroha_crypto::bls_normal_verify_preaggregated_same_message(
        &preimage,
        &certificate.aggregate_signature,
        &signer_keys,
        &signer_pops,
    )
    .map_err(|_| eyre!("private-settlement availability certificate is invalid"))
}

fn validate_availability_share_v1(
    share: &PrivateSettlementAvailabilityShareV1,
    body: &PrivateSettlementSidecarAvailabilityBodyV1,
    authority: &PrivateSettlementCommitteeAuthorityV1,
) -> Result<usize> {
    share
        .validate_shape()
        .map_err(|_| eyre!("private-settlement availability share is invalid"))?;
    authority
        .validate()
        .map_err(|_| eyre!("private-settlement availability share is invalid"))?;
    let authority_digest = authority
        .digest()
        .map_err(|_| eyre!("private-settlement availability share is invalid"))?;
    let index = authority
        .validators
        .iter()
        .position(|validator| validator == &share.signer)
        .ok_or_else(|| eyre!("private-settlement availability share is invalid"))?;
    let pop = authority
        .validator_pops
        .get(index)
        .ok_or_else(|| eyre!("private-settlement availability share is invalid"))?;
    if &share.body != body
        || body.route != authority.route
        || body.authority_digest != authority_digest
        || share.signer.public_key().try_algorithm().ok() != Some(Algorithm::BlsNormal)
        || iroha_crypto::bls_normal_pop_verify(share.signer.public_key(), pop).is_err()
    {
        return Err(eyre!("private-settlement availability share is invalid"));
    }
    let signature = Signature::try_from_bytes(&share.signature)
        .map_err(|_| eyre!("private-settlement availability share is invalid"))?;
    signature
        .verify(
            share.signer.public_key(),
            &body
                .signature_preimage()
                .map_err(|_| eyre!("private-settlement availability share is invalid"))?,
        )
        .map_err(|_| eyre!("private-settlement availability share is invalid"))?;
    Ok(index)
}

fn aggregate_availability_shares_v1(
    body: PrivateSettlementSidecarAvailabilityBodyV1,
    authority: &PrivateSettlementCommitteeAuthorityV1,
    shares: &[PrivateSettlementAvailabilityShareV1],
) -> Result<PrivateSettlementSidecarAvailabilityV1> {
    if shares.len() != usize::from(PRIVATE_SETTLEMENT_COMMITTEE_QUORUM_V1) {
        return Err(eyre!("private-settlement availability quorum is invalid"));
    }
    let mut indexed = BTreeMap::new();
    for share in shares {
        let index = validate_availability_share_v1(share, &body, authority)?;
        if indexed.insert(index, share.signature.clone()).is_some() {
            return Err(eyre!("private-settlement availability share is invalid"));
        }
    }
    let mut signers_bitmap = 0_u8;
    let signatures = indexed
        .into_iter()
        .map(|(index, signature)| {
            signers_bitmap |= 1_u8 << index;
            signature
        })
        .collect::<Vec<_>>();
    let signature_refs = signatures.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let certificate = PrivateSettlementSidecarAvailabilityV1 {
        body,
        signers_bitmap,
        aggregate_signature: iroha_crypto::bls_normal_aggregate_signatures(&signature_refs)
            .map_err(|_| eyre!("private-settlement availability share is invalid"))?,
    };
    validate_availability_certificate_v1(&certificate, authority)?;
    Ok(certificate)
}

fn canonical_availability_share_quorum_v1(
    shares: &[PrivateSettlementAvailabilityShareV1],
) -> Result<&[PrivateSettlementAvailabilityShareV1]> {
    shares
        .get(..usize::from(PRIVATE_SETTLEMENT_COMMITTEE_QUORUM_V1))
        .ok_or_else(|| eyre!("private-settlement availability quorum is unavailable"))
}

fn private_settlement_reserved_prepared_digest_v1() -> Hash {
    Hash::prehashed([0; Hash::LENGTH])
}

fn phase_signature_preimage_v1(body: &PrivateSettlementPhaseBodyV1) -> Result<Vec<u8>> {
    body.signature_preimage()
        .map_err(|_| eyre!("private-settlement phase body encoding failed"))
}

fn prepared_bundle_digest_v1(
    manifest: &AtomicPrivateSettlementV1,
    authority_catalog: &PrivateSettlementAuthorityCatalogV1,
    deltas: &[PrivateSettlementDeltaV1],
    prepare_certificates: &[PrivateSettlementPhaseCertificateV1],
) -> Result<Hash> {
    if authority_catalog.validate_for_manifest(manifest).is_err()
        || deltas.len() != manifest.legs.len()
        || prepare_certificates.len() != manifest.legs.len()
    {
        return Err(eyre!("private-settlement Prepare barrier is incomplete"));
    }
    PrivateSettlementPrepareBarrierV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        manifest: manifest.clone(),
        authority_catalog: authority_catalog.clone(),
        deltas: deltas.to_vec(),
        prepare_certificates: prepare_certificates.to_vec(),
        prepared_bundle_digest: private_settlement_reserved_prepared_digest_v1(),
    }
    .computed_prepared_bundle_digest()
    .map_err(|_| eyre!("private-settlement Prepare barrier encoding failed"))
}

fn expected_phase_body_v1(
    manifest: &AtomicPrivateSettlementV1,
    leg_ordinal: u8,
    authority: &PrivateSettlementCommitteeAuthorityV1,
    phase: PrivateSettlementPhaseV1,
    prepared_bundle_digest: Hash,
) -> Result<PrivateSettlementPhaseBodyV1> {
    manifest
        .validate()
        .map_err(|_| eyre!("private-settlement phase manifest is invalid"))?;
    authority
        .validate()
        .map_err(|_| eyre!("private-settlement phase authority is invalid"))?;
    let leg = manifest
        .legs
        .get(usize::from(leg_ordinal))
        .ok_or_else(|| eyre!("private-settlement phase leg is invalid"))?;
    let reserved = private_settlement_reserved_prepared_digest_v1();
    if authority.route != leg.route
        || match phase {
            PrivateSettlementPhaseV1::Prepare => prepared_bundle_digest != reserved,
            PrivateSettlementPhaseV1::Commit => prepared_bundle_digest == reserved,
        }
    {
        return Err(eyre!("private-settlement phase binding is invalid"));
    }
    Ok(PrivateSettlementPhaseBodyV1 {
        network_id: manifest.network_id,
        bundle_id: manifest.bundle_id,
        manifest_digest: manifest
            .manifest_digest()
            .map_err(|_| eyre!("private-settlement phase manifest encoding failed"))?,
        leg_ordinal,
        route: leg.route,
        delta_digest: leg.delta_digest,
        authority_digest: authority
            .digest()
            .map_err(|_| eyre!("private-settlement phase authority encoding failed"))?,
        prepared_bundle_digest,
        phase,
        authority_context_height: manifest.authority_context_height,
        expiry_height: manifest.expiry_height,
    })
}

fn validate_phase_vote_v1(
    vote: &PrivateSettlementPhaseVoteV1,
    expected_body: &PrivateSettlementPhaseBodyV1,
    authority: &PrivateSettlementCommitteeAuthorityV1,
) -> Result<usize> {
    vote.validate_shape()
        .map_err(|_| eyre!("private-settlement phase vote is invalid"))?;
    authority
        .validate()
        .map_err(|_| eyre!("private-settlement phase vote is invalid"))?;
    let index = authority
        .validators
        .iter()
        .position(|validator| validator == &vote.signer)
        .ok_or_else(|| eyre!("private-settlement phase vote is invalid"))?;
    let pop = authority
        .validator_pops
        .get(index)
        .ok_or_else(|| eyre!("private-settlement phase vote is invalid"))?;
    if &vote.body != expected_body
        || vote.version != ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1
        || vote.signature.len() != PRIVATE_SETTLEMENT_BLS_BYTES_V1
        || vote.signer.public_key().try_algorithm().ok() != Some(Algorithm::BlsNormal)
        || iroha_crypto::bls_normal_pop_verify(vote.signer.public_key(), pop).is_err()
    {
        return Err(eyre!("private-settlement phase vote is invalid"));
    }
    let signature = Signature::try_from_bytes(&vote.signature)
        .map_err(|_| eyre!("private-settlement phase vote is invalid"))?;
    signature
        .verify(
            vote.signer.public_key(),
            &phase_signature_preimage_v1(&vote.body)?,
        )
        .map_err(|_| eyre!("private-settlement phase vote is invalid"))?;
    Ok(index)
}

fn validate_phase_certificate_v1(
    certificate: &PrivateSettlementPhaseCertificateV1,
    expected_body: &PrivateSettlementPhaseBodyV1,
    authority_catalog_index: u8,
    authority: &PrivateSettlementCommitteeAuthorityV1,
) -> Result<()> {
    certificate
        .validate_shape()
        .map_err(|_| eyre!("private-settlement phase certificate is invalid"))?;
    if &certificate.body != expected_body
        || certificate.authority_catalog_index != authority_catalog_index
        || expected_body.authority_digest
            != authority
                .digest()
                .map_err(|_| eyre!("private-settlement phase certificate is invalid"))?
    {
        return Err(eyre!("private-settlement phase certificate is invalid"));
    }
    let mut signer_keys = Vec::with_capacity(usize::from(PRIVATE_SETTLEMENT_COMMITTEE_QUORUM_V1));
    let mut signer_pops = Vec::with_capacity(usize::from(PRIVATE_SETTLEMENT_COMMITTEE_QUORUM_V1));
    for (index, (validator, pop)) in authority
        .validators
        .iter()
        .zip(&authority.validator_pops)
        .enumerate()
    {
        if validator.public_key().try_algorithm().ok() != Some(Algorithm::BlsNormal)
            || iroha_crypto::bls_normal_pop_verify(validator.public_key(), pop).is_err()
        {
            return Err(eyre!("private-settlement phase certificate is invalid"));
        }
        if certificate.signers_bitmap & (1_u8 << index) != 0 {
            signer_keys.push(validator.public_key());
            signer_pops.push(pop.as_slice());
        }
    }
    iroha_crypto::bls_normal_verify_preaggregated_same_message(
        &phase_signature_preimage_v1(expected_body)?,
        &certificate.aggregate_signature,
        &signer_keys,
        &signer_pops,
    )
    .map_err(|_| eyre!("private-settlement phase certificate is invalid"))
}

#[derive(Clone, Copy)]
enum PrivateSettlementPhaseRecoveryV1<'a> {
    Prepare,
    Commit {
        prepared_bundle_digest: Hash,
        expected_prepare: &'a PrivateSettlementPhaseCertificateV1,
    },
}

fn phase_certificate_acknowledgement_is_valid_v1(
    phase: PrivateSettlementPhaseV1,
    lifecycle: PrivateSettlementLifecycleDtoV1,
) -> bool {
    match phase {
        PrivateSettlementPhaseV1::Prepare => matches!(
            lifecycle,
            PrivateSettlementLifecycleDtoV1::Prepared
                | PrivateSettlementLifecycleDtoV1::CommitCertified
        ),
        PrivateSettlementPhaseV1::Commit => {
            lifecycle == PrivateSettlementLifecycleDtoV1::CommitCertified
        }
    }
}

fn aggregate_phase_votes_v1(
    body: &PrivateSettlementPhaseBodyV1,
    authority_catalog_index: u8,
    authority: &PrivateSettlementCommitteeAuthorityV1,
    votes: &[PrivateSettlementPhaseVoteV1],
) -> Result<PrivateSettlementPhaseCertificateV1> {
    if votes.len() != usize::from(PRIVATE_SETTLEMENT_COMMITTEE_QUORUM_V1) {
        return Err(eyre!("private-settlement phase quorum is invalid"));
    }
    let mut indexed = BTreeMap::new();
    for vote in votes {
        let index = validate_phase_vote_v1(vote, body, authority)?;
        if indexed.insert(index, vote.signature.clone()).is_some() {
            return Err(eyre!("private-settlement phase vote is duplicated"));
        }
    }
    let mut signers_bitmap = 0_u8;
    let signatures = indexed
        .into_iter()
        .map(|(index, signature)| {
            signers_bitmap |= 1_u8 << index;
            signature
        })
        .collect::<Vec<_>>();
    let signature_refs = signatures.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let certificate = PrivateSettlementPhaseCertificateV1 {
        body: *body,
        authority_catalog_index,
        signers_bitmap,
        aggregate_signature: iroha_crypto::bls_normal_aggregate_signatures(&signature_refs)
            .map_err(|_| eyre!("private-settlement phase aggregation failed"))?,
    };
    validate_phase_certificate_v1(&certificate, body, authority_catalog_index, authority)?;
    Ok(certificate)
}

fn canonical_phase_vote_quorum_v1(
    votes: &[PrivateSettlementPhaseVoteV1],
) -> Result<&[PrivateSettlementPhaseVoteV1]> {
    votes
        .get(..usize::from(PRIVATE_SETTLEMENT_COMMITTEE_QUORUM_V1))
        .ok_or_else(|| eyre!("private-settlement phase quorum is unavailable"))
}

fn validate_prepare_barrier_v1(barrier: &PrivateSettlementPrepareBarrierV1) -> Result<()> {
    barrier
        .validate_shape()
        .map_err(|_| eyre!("private-settlement Prepare barrier is invalid"))?;
    for (index, (certificate, _delta)) in barrier
        .prepare_certificates
        .iter()
        .zip(&barrier.deltas)
        .enumerate()
    {
        let ordinal = u8::try_from(index)
            .map_err(|_| eyre!("private-settlement Prepare barrier is invalid"))?;
        let authority = barrier
            .authority_catalog
            .authority_for_leg(&barrier.manifest, index)
            .map_err(|_| eyre!("private-settlement Prepare barrier is invalid"))?;
        let expected = expected_phase_body_v1(
            &barrier.manifest,
            ordinal,
            &authority,
            PrivateSettlementPhaseV1::Prepare,
            private_settlement_reserved_prepared_digest_v1(),
        )?;
        validate_phase_certificate_v1(certificate, &expected, ordinal, &authority)?;
        if barrier.deltas[index]
            .digest()
            .map_err(|_| eyre!("private-settlement Prepare barrier is invalid"))?
            != expected.delta_digest
        {
            return Err(eyre!("private-settlement Prepare barrier is invalid"));
        }
    }
    if barrier.prepared_bundle_digest
        != prepared_bundle_digest_v1(
            &barrier.manifest,
            &barrier.authority_catalog,
            &barrier.deltas,
            &barrier.prepare_certificates,
        )?
    {
        return Err(eyre!("private-settlement Prepare barrier is invalid"));
    }
    Ok(())
}

fn validate_leg_status_response_v1(
    requested: Hash,
    response: &PrivateSettlementLegStatusResponseV1,
) -> Result<()> {
    if response.payload_digest != requested
        || response.route.dataspace_id == iroha_model_base::topology::DataSpaceId::UNIVERSAL
        || response.stored_at_height == 0
        || response.lifecycle_height < response.stored_at_height
        || response.expiry_height <= response.stored_at_height
    {
        return Err(eyre!(
            "private-settlement leg status response is invalid or substituted"
        ));
    }
    Ok(())
}

fn validate_phase_certificates_response_v1(
    requested: Hash,
    response: &PrivateSettlementPhaseCertificatesResponseV1,
) -> Result<()> {
    if response.payload_digest != requested {
        return Err(eyre!(
            "private-settlement phase-certificate recovery response is substituted"
        ));
    }
    let validate = |certificate: &PrivateSettlementPhaseCertificateV1,
                    phase: PrivateSettlementPhaseV1|
     -> Result<()> {
        certificate.validate_shape().map_err(|_| {
            eyre!("private-settlement phase-certificate recovery response is invalid")
        })?;
        if certificate.body.bundle_id != response.bundle_id
            || certificate.body.leg_ordinal != response.leg_ordinal
            || certificate.body.phase != phase
        {
            return Err(eyre!(
                "private-settlement phase-certificate recovery response is substituted"
            ));
        }
        Ok(())
    };
    if let Some(prepare) = response.prepare_certificate.as_ref() {
        validate(prepare, PrivateSettlementPhaseV1::Prepare)?;
    }
    if let Some(commit) = response.commit_certificate.as_ref() {
        validate(commit, PrivateSettlementPhaseV1::Commit)?;
        let prepare = response.prepare_certificate.as_ref().ok_or_else(|| {
            eyre!("private-settlement phase-certificate recovery response is incomplete")
        })?;
        if commit.body.network_id != prepare.body.network_id
            || commit.body.manifest_digest != prepare.body.manifest_digest
            || commit.body.route != prepare.body.route
            || commit.body.delta_digest != prepare.body.delta_digest
            || commit.body.authority_digest != prepare.body.authority_digest
            || commit.body.authority_context_height != prepare.body.authority_context_height
            || commit.body.expiry_height != prepare.body.expiry_height
        {
            return Err(eyre!(
                "private-settlement phase-certificate recovery response is inconsistent"
            ));
        }
    }
    if response.lifecycle == PrivateSettlementLifecycleDtoV1::CommitCertified
        && (response.prepare_certificate.is_none() || response.commit_certificate.is_none())
    {
        return Err(eyre!(
            "private-settlement phase-certificate recovery response is incomplete"
        ));
    }
    Ok(())
}

fn phase_certificates_are_quorum_equivalent_v1(
    left: &PrivateSettlementPhaseCertificateV1,
    right: &PrivateSettlementPhaseCertificateV1,
) -> bool {
    left.body == right.body && left.authority_catalog_index == right.authority_catalog_index
}

fn retain_canonical_phase_certificate_v1(
    recovered: &mut Option<PrivateSettlementPhaseCertificateV1>,
    candidate: PrivateSettlementPhaseCertificateV1,
) {
    if recovered
        .as_ref()
        .is_none_or(|existing| &candidate < existing)
    {
        *recovered = Some(candidate);
    }
}

fn validate_bundle_status_response_v1(
    requested: Hash,
    response: &PrivateSettlementBundleStatusResponseV1,
) -> Result<()> {
    if let Some(manifest) = &response.manifest {
        manifest
            .validate()
            .map_err(|_| eyre!("private-settlement bundle status is invalid or substituted"))?;
        if manifest.bundle_id != requested {
            return Err(eyre!(
                "private-settlement bundle status is invalid or substituted"
            ));
        }
    }
    match response.lifecycle {
        PrivateSettlementLifecycleDtoV1::Finalized
        | PrivateSettlementLifecycleDtoV1::Aborted
        | PrivateSettlementLifecycleDtoV1::Expired => {
            if response.finalized_height.is_none() {
                return Err(eyre!(
                    "private-settlement bundle status is invalid or substituted"
                ));
            }
        }
        _ if response.finalized_height.is_some() => {
            return Err(eyre!(
                "private-settlement bundle status is invalid or substituted"
            ));
        }
        _ => {}
    }
    Ok(())
}

fn validate_bundle_receipt_response_v1(
    requested: Hash,
    response: &PrivateSettlementBundleReceiptResponseV1,
) -> Result<()> {
    match response {
        PrivateSettlementBundleReceiptResponseV1::Pending { bundle_id, .. } => {
            if *bundle_id != requested {
                return Err(eyre!(
                    "private-settlement receipt is invalid or substituted"
                ));
            }
        }
        PrivateSettlementBundleReceiptResponseV1::Finalized(receipt) => {
            receipt
                .validate_shape()
                .map_err(|_| eyre!("private-settlement receipt is invalid or substituted"))?;
            if receipt.manifest.bundle_id != requested {
                return Err(eyre!(
                    "private-settlement receipt is invalid or substituted"
                ));
            }
        }
        PrivateSettlementBundleReceiptResponseV1::Aborted(receipt) => {
            receipt
                .validate()
                .map_err(|_| eyre!("private-settlement receipt is invalid or substituted"))?;
            if receipt.bundle_id != requested {
                return Err(eyre!(
                    "private-settlement receipt is invalid or substituted"
                ));
            }
        }
    }
    Ok(())
}

// Authenticate Commit certificates against the caller-validated complete Prepare barrier.
fn build_private_settlement_commit_bundle_v1(
    barrier: &PrivateSettlementPrepareBarrierV1,
    commit_certificates: &[PrivateSettlementPhaseCertificateV1],
) -> Result<PrivateSettlementCommitBundleV1> {
    if commit_certificates.len() != barrier.manifest.legs.len() {
        return Err(eyre!(
            "private-settlement finalization Commit barrier is incomplete"
        ));
    }

    let mut legs = Vec::with_capacity(barrier.manifest.legs.len());
    for (index, ((delta, prepare), commit)) in barrier
        .deltas
        .iter()
        .zip(&barrier.prepare_certificates)
        .zip(commit_certificates)
        .enumerate()
    {
        let ordinal = u8::try_from(index)
            .map_err(|_| eyre!("private-settlement finalization ordinal is invalid"))?;
        let authority = barrier
            .authority_catalog
            .authority_for_leg(&barrier.manifest, index)
            .map_err(|_| eyre!("private-settlement authority catalog is invalid"))?;
        let expected = expected_phase_body_v1(
            &barrier.manifest,
            ordinal,
            &authority,
            PrivateSettlementPhaseV1::Commit,
            barrier.prepared_bundle_digest,
        )?;
        validate_phase_certificate_v1(commit, &expected, ordinal, &authority)?;
        legs.push(PrivateSettlementLegReceiptV1 {
            delta: delta.clone(),
            prepare: prepare.clone(),
            commit: commit.clone(),
        });
    }

    let bundle = PrivateSettlementCommitBundleV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        manifest: barrier.manifest.clone(),
        authority_catalog: barrier.authority_catalog.clone(),
        legs,
    };
    bundle
        .clone()
        .into_receipt(barrier.manifest.authority_context_height)
        .validate_shape()
        .map_err(|_| eyre!("private-settlement finalization bundle is invalid"))?;
    Ok(bundle)
}

fn validate_private_settlement_sponsor_context_v1(
    manifest: &AtomicPrivateSettlementV1,
    network_id: &NetworkId,
    sponsor: &AccountId,
    context: &'static str,
) -> Result<()> {
    if &manifest.network_id != network_id || &manifest.sponsor != sponsor {
        return Err(eyre!("{context}"));
    }
    Ok(())
}

impl Client {
    fn decode_private_settlement_response_v1<T>(
        response: &Response<Vec<u8>>,
        context: &'static str,
    ) -> Result<T>
    where
        T: norito::json::JsonDeserializeOwned,
    {
        Self::decode_private_settlement_response_with_status_v1(response, StatusCode::OK, context)
    }

    fn decode_private_settlement_accepted_response_v1<T>(
        response: &Response<Vec<u8>>,
        context: &'static str,
    ) -> Result<T>
    where
        T: norito::json::JsonDeserializeOwned,
    {
        Self::decode_private_settlement_response_with_status_v1(
            response,
            StatusCode::ACCEPTED,
            context,
        )
    }

    fn decode_private_settlement_response_with_status_v1<T>(
        response: &Response<Vec<u8>>,
        expected_status: StatusCode,
        context: &'static str,
    ) -> Result<T>
    where
        T: norito::json::JsonDeserializeOwned,
    {
        if response.status() != expected_status {
            return Err(eyre!(
                "{context}: unexpected HTTP status {}; expected {expected_status}",
                response.status()
            ));
        }
        let content_type = Self::response_content_type(response);
        if !Self::is_json_content_type(content_type) {
            return Err(eyre!(
                "{context}: invalid content-type (expected application/json)"
            ));
        }
        norito::json::from_slice(response.body())
            .map_err(|_| eyre!("{context}: invalid JSON response"))
    }

    fn send_private_settlement_builder_v1(
        &self,
        builder: DefaultRequestBuilder,
    ) -> Result<Response<Vec<u8>>> {
        self.send_builder(builder.max_response_bytes(PRIVATE_SETTLEMENT_RESPONSE_MAX_BYTES_V1))
    }

    /// Read the redacted APS state commitment from this exact test-network validator.
    ///
    /// The route and this method are compiled only for the feature-isolated
    /// release harness. The request uses the client's configured operator key;
    /// Torii additionally requires that identity to be the local validator.
    ///
    /// # Errors
    ///
    /// Fails if operator signing is unavailable, Torii rejects the identity,
    /// the response is cacheable, or the strict V1 response cannot be decoded.
    #[cfg(feature = "test-network-private-settlement-evidence")]
    pub fn private_settlement_test_network_state_evidence_v1(
        &self,
    ) -> Result<super::PrivateSettlementTestNetworkStateEvidenceResponseV1> {
        let url = join_torii_url(
            &self.torii_url,
            "v1/nexus/private-settlements/test-network/state-commitment",
        );
        let response = self.send_private_settlement_builder_v1(
            self.operator_signed_request(HttpMethod::GET, url, Vec::new())?
                .header("Accept", APPLICATION_JSON),
        )?;
        let cache_control = response
            .headers()
            .get("cache-control")
            .and_then(|value| value.to_str().ok());
        if cache_control != Some("private, no-store") {
            return Err(eyre!(
                "private-settlement test-network state evidence is missing no-store"
            ));
        }
        let decoded: super::PrivateSettlementTestNetworkStateEvidenceResponseV1 =
            Self::decode_private_settlement_response_v1(
                &response,
                "private-settlement test-network state evidence failed",
            )?;
        if decoded.format_version != 1
            || decoded.commitment == Hash::prehashed([0_u8; Hash::LENGTH])
            || decoded.ledger_commitment == Hash::prehashed([0_u8; Hash::LENGTH])
            || decoded.replicated_staged_lock_commitment == Hash::prehashed([0_u8; Hash::LENGTH])
            || decoded.staged_lock_commitment == Hash::prehashed([0_u8; Hash::LENGTH])
        {
            return Err(eyre!(
                "private-settlement test-network state evidence is malformed"
            ));
        }
        Ok(decoded)
    }

    /// Ask one committee endpoint to durably persist provisional material and sign it.
    ///
    /// The request is authenticated as the manifest sponsor. The returned
    /// share is verified locally against the exact request body and authority.
    ///
    /// # Errors
    ///
    /// Fails on local binding errors, request signing/transport failure, Torii
    /// rejection, or a malformed/substituted share.
    pub fn request_private_settlement_availability_share_v1(
        &self,
        endpoint: &Url,
        material: &PrivateSettlementProvisionalLegMaterialV1,
    ) -> Result<PrivateSettlementAvailabilityShareResponseV1> {
        material
            .validate()
            .map_err(|_| eyre!(PrivateSettlementAvailabilityFailureV1::InvalidMaterial))?;
        if material.manifest.sponsor != self.account {
            return Err(eyre!(
                PrivateSettlementAvailabilityFailureV1::SponsorRequired
            ));
        }
        let request = PrivateSettlementAvailabilityShareRequestV1 {
            material: material.clone(),
        };
        let body = norito::json::to_vec(&request)
            .map_err(|_| eyre!(PrivateSettlementAvailabilityFailureV1::RequestEncoding))?;
        let url = join_torii_url(
            endpoint,
            "v1/nexus/private-settlements/legs/availability-shares",
        );
        let response = self
            .send_private_settlement_builder_v1(
                self.account_signed_request(HttpMethod::POST, url, body)
                    .map_err(|_| eyre!(PrivateSettlementAvailabilityFailureV1::RequestSigning))?
                    .header("Content-Type", APPLICATION_JSON)
                    .header("Accept", APPLICATION_JSON),
            )
            .map_err(|error| eyre!(PrivateSettlementAvailabilityFailureV1::transport(&error)))?;
        let decoded = decode_private_settlement_availability_response_v1(&response)?;
        validate_availability_share_v1(
            &decoded.share,
            &material.availability_body,
            &material.committee_authority,
        )
        .map_err(|_| eyre!(PrivateSettlementAvailabilityFailureV1::InvalidShare))?;
        if decoded.bundle_id != material.manifest.bundle_id
            || decoded.payload_digest != material.availability_body.payload_digest
            || decoded.leg_ordinal != material.statement.leg_ordinal
        {
            return Err(eyre!(
                PrivateSettlementAvailabilityFailureV1::SubstitutedResponse
            ));
        }
        Ok(decoded)
    }

    /// Collect and aggregate exactly three shares from four roster-aligned endpoints.
    ///
    /// Endpoints must be supplied in the same order as the authority roster.
    /// Unavailable endpoints are skipped; every accepted response must be
    /// signed by the validator at its endpoint's roster index.
    ///
    /// # Errors
    ///
    /// Fails if endpoint ordering is invalid or fewer than three exact shares
    /// can be verified. Quorum failures include the valid-share count, required
    /// quorum, and a bounded failure category for each failed zero-based roster index.
    /// HTTP failures include status and a recognized public rejection code when
    /// available; request contents, endpoint URLs and raw error bodies are omitted.
    pub fn certify_private_settlement_leg_availability_v1(
        &self,
        committee_endpoints: &[Url],
        material: &PrivateSettlementProvisionalLegMaterialV1,
    ) -> Result<PrivateSettlementSidecarAvailabilityV1> {
        material
            .validate()
            .map_err(|_| eyre!("private-settlement provisional leg is invalid"))?;
        if committee_endpoints.len() != material.committee_authority.validators.len() {
            return Err(eyre!(
                "private-settlement availability endpoints must match the four-validator roster"
            ));
        }
        let shares = collect_private_settlement_availability_shares_v1(
            &material.committee_authority,
            |index| {
                self.request_private_settlement_availability_share_v1(
                    &committee_endpoints[index],
                    material,
                )
            },
        )?;
        let selected = canonical_availability_share_quorum_v1(&shares)?;
        aggregate_availability_shares_v1(
            material.availability_body,
            &material.committee_authority,
            selected,
        )
    }

    /// Ask one participant endpoint to independently verify, stage, and vote Prepare.
    ///
    /// # Errors
    ///
    /// Fails on sponsor/binding errors, transport rejection, or a malformed or
    /// substituted node vote.
    pub fn request_private_settlement_prepare_vote_v1(
        &self,
        endpoint: &Url,
        manifest: &AtomicPrivateSettlementV1,
        payload_digest: Hash,
        authority: &PrivateSettlementCommitteeAuthorityV1,
    ) -> Result<PrivateSettlementPhaseVoteResponseV1> {
        manifest
            .validate()
            .map_err(|_| eyre!("private-settlement Prepare manifest is invalid"))?;
        if manifest.sponsor != self.account {
            return Err(eyre!(
                "private-settlement Prepare requires the manifest sponsor"
            ));
        }
        let ordinal = private_settlement_leg_ordinal_for_payload_v1(manifest, payload_digest)?;
        let expected = expected_phase_body_v1(
            manifest,
            ordinal,
            authority,
            PrivateSettlementPhaseV1::Prepare,
            private_settlement_reserved_prepared_digest_v1(),
        )?;
        let request = PrivateSettlementPrepareVoteRequestV1 {
            manifest: manifest.clone(),
            payload_digest,
        };
        let body = norito::json::to_vec(&request)
            .wrap_err("failed to encode private-settlement Prepare request")?;
        let url = join_torii_url(
            endpoint,
            "v1/nexus/private-settlements/phases/prepare-votes",
        );
        let response = self.send_private_settlement_builder_v1(
            self.account_signed_request(HttpMethod::POST, url, body)?
                .header("Content-Type", APPLICATION_JSON)
                .header("Accept", APPLICATION_JSON),
        )?;
        let decoded: PrivateSettlementPhaseVoteResponseV1 =
            Self::decode_private_settlement_response_v1(
                &response,
                "private-settlement Prepare vote failed",
            )?;
        validate_phase_vote_v1(&decoded.vote, &expected, authority)?;
        if decoded.bundle_id != manifest.bundle_id
            || decoded.payload_digest != payload_digest
            || decoded.leg_ordinal != ordinal
        {
            return Err(eyre!("private-settlement Prepare response is substituted"));
        }
        Ok(decoded)
    }

    /// Fsync one exact aggregate participant certificate on a selected signer endpoint.
    ///
    /// # Errors
    ///
    /// Fails on sponsor/binding errors, transport rejection, or a substituted acknowledgement.
    pub fn persist_private_settlement_phase_certificate_v1(
        &self,
        endpoint: &Url,
        manifest: &AtomicPrivateSettlementV1,
        payload_digest: Hash,
        certificate: &PrivateSettlementPhaseCertificateV1,
    ) -> Result<PrivateSettlementPhaseCertificateResponseV1> {
        if manifest.sponsor != self.account {
            return Err(eyre!(
                "private-settlement phase persistence requires the manifest sponsor"
            ));
        }
        let request = PrivateSettlementPhaseCertificateRequestV1 {
            manifest: manifest.clone(),
            payload_digest,
            certificate: certificate.clone(),
        };
        let body = norito::json::to_vec(&request)
            .wrap_err("failed to encode private-settlement phase certificate")?;
        let url = join_torii_url(endpoint, "v1/nexus/private-settlements/phases/certificates");
        let response = self.send_private_settlement_builder_v1(
            self.account_signed_request(HttpMethod::POST, url, body)?
                .header("Content-Type", APPLICATION_JSON)
                .header("Accept", APPLICATION_JSON),
        )?;
        let decoded: PrivateSettlementPhaseCertificateResponseV1 =
            Self::decode_private_settlement_response_v1(
                &response,
                "private-settlement phase certificate persistence failed",
            )?;
        if decoded.bundle_id != manifest.bundle_id
            || decoded.payload_digest != payload_digest
            || decoded.leg_ordinal != certificate.body.leg_ordinal
            || decoded.phase != certificate.body.phase
            || !phase_certificate_acknowledgement_is_valid_v1(
                certificate.body.phase,
                decoded.lifecycle,
            )
        {
            return Err(eyre!(
                "private-settlement phase certificate acknowledgement is substituted"
            ));
        }
        Ok(decoded)
    }

    fn recover_private_settlement_phase_certificate_v1(
        &self,
        committee_endpoints: &[Url],
        manifest: &AtomicPrivateSettlementV1,
        payload_digest: Hash,
        authority: &PrivateSettlementCommitteeAuthorityV1,
        recovery: PrivateSettlementPhaseRecoveryV1<'_>,
    ) -> Result<Option<PrivateSettlementPhaseCertificateV1>> {
        let (phase, prepared_bundle_digest, expected_prepare) = match recovery {
            PrivateSettlementPhaseRecoveryV1::Prepare => (
                PrivateSettlementPhaseV1::Prepare,
                private_settlement_reserved_prepared_digest_v1(),
                None,
            ),
            PrivateSettlementPhaseRecoveryV1::Commit {
                prepared_bundle_digest,
                expected_prepare,
            } => (
                PrivateSettlementPhaseV1::Commit,
                prepared_bundle_digest,
                Some(expected_prepare),
            ),
        };
        if committee_endpoints.len() != authority.validators.len() {
            return Err(eyre!(
                "private-settlement recovery endpoints must match the four-validator roster"
            ));
        }
        for (index, endpoint) in committee_endpoints.iter().enumerate() {
            if committee_endpoints[..index].contains(endpoint) {
                return Err(eyre!(
                    "private-settlement recovery endpoints must be distinct"
                ));
            }
        }
        if manifest.sponsor != self.account {
            return Err(eyre!(
                "private-settlement phase recovery requires the manifest sponsor"
            ));
        }
        let ordinal = private_settlement_leg_ordinal_for_payload_v1(manifest, payload_digest)?;
        let expected =
            expected_phase_body_v1(manifest, ordinal, authority, phase, prepared_bundle_digest)?;
        let expected_prepare_body = expected_phase_body_v1(
            manifest,
            ordinal,
            authority,
            PrivateSettlementPhaseV1::Prepare,
            private_settlement_reserved_prepared_digest_v1(),
        )?;
        let mut recovered: Option<PrivateSettlementPhaseCertificateV1> = None;
        let mut valid_responses = 0_usize;
        for endpoint in committee_endpoints {
            let response = match self
                .private_settlement_phase_certificates_from_v1(endpoint, payload_digest)
            {
                Ok(response) => response,
                Err(_) => continue,
            };
            if response.bundle_id != manifest.bundle_id || response.leg_ordinal != ordinal {
                continue;
            }
            if let Some(prepare) = response.prepare_certificate.as_ref() {
                if validate_phase_certificate_v1(
                    prepare,
                    &expected_prepare_body,
                    ordinal,
                    authority,
                )
                .is_err()
                {
                    continue;
                }
                if expected_prepare.is_some_and(|expected| {
                    !phase_certificates_are_quorum_equivalent_v1(expected, prepare)
                }) {
                    continue;
                }
            }
            let candidate = match phase {
                PrivateSettlementPhaseV1::Prepare => response.prepare_certificate,
                PrivateSettlementPhaseV1::Commit => response.commit_certificate,
            };
            if let Some(candidate) = candidate {
                if validate_phase_certificate_v1(&candidate, &expected, ordinal, authority).is_err()
                {
                    continue;
                }
                retain_canonical_phase_certificate_v1(&mut recovered, candidate);
            }
            valid_responses += 1;
        }
        if valid_responses < usize::from(PRIVATE_SETTLEMENT_COMMITTEE_QUORUM_V1) {
            return Err(eyre!(
                "private-settlement phase recovery requires three valid committee responses"
            ));
        }
        Ok(recovered)
    }

    /// Recover one exact durable Prepare QC after a coordinator restart.
    ///
    /// At least three endpoints must answer. Quorum-equivalent certificates
    /// over the same body are ordered canonically; their signer-set encodings
    /// do not alter the normalized complete-bundle digest.
    ///
    /// # Errors
    ///
    /// Fails with fewer than three valid endpoint responses or without a
    /// cryptographically valid certificate when one is returned.
    pub fn recover_private_settlement_prepare_certificate_v1(
        &self,
        committee_endpoints: &[Url],
        manifest: &AtomicPrivateSettlementV1,
        payload_digest: Hash,
        authority: &PrivateSettlementCommitteeAuthorityV1,
    ) -> Result<Option<PrivateSettlementPhaseCertificateV1>> {
        self.recover_private_settlement_phase_certificate_v1(
            committee_endpoints,
            manifest,
            payload_digest,
            authority,
            PrivateSettlementPhaseRecoveryV1::Prepare,
        )
    }

    /// Recover one exact durable Commit QC against an already recovered barrier.
    ///
    /// # Errors
    ///
    /// Fails with fewer than three valid endpoint responses, malformed
    /// evidence, or a certified statement mismatch with the barrier.
    pub fn recover_private_settlement_commit_certificate_v1(
        &self,
        committee_endpoints: &[Url],
        payload_digest: Hash,
        barrier: &PrivateSettlementPrepareBarrierV1,
        authority: &PrivateSettlementCommitteeAuthorityV1,
    ) -> Result<Option<PrivateSettlementPhaseCertificateV1>> {
        validate_prepare_barrier_v1(barrier)?;
        let ordinal =
            private_settlement_leg_ordinal_for_payload_v1(&barrier.manifest, payload_digest)?;
        let expected_prepare = barrier
            .prepare_certificates
            .get(usize::from(ordinal))
            .ok_or_else(|| eyre!("private-settlement Prepare barrier is incomplete"))?;
        self.recover_private_settlement_phase_certificate_v1(
            committee_endpoints,
            &barrier.manifest,
            payload_digest,
            authority,
            PrivateSettlementPhaseRecoveryV1::Commit {
                prepared_bundle_digest: barrier.prepared_bundle_digest,
                expected_prepare,
            },
        )
    }

    /// Fan out to all four validators, select exactly three votes canonically,
    /// and durably hand the QC back to every successfully staged node.
    ///
    /// Exactly four scoped requests run concurrently and all initiated requests
    /// finish before response selection or certificate handoff. Endpoint order
    /// must exactly match the authority roster. Request failures do not count
    /// toward quorum; an otherwise valid vote from the wrong endpoint is fatal.
    /// On rejection, later endpoints may already hold durable Prepare staging;
    /// recovery remains responsible for that staging and any interrupted QC handoff.
    ///
    /// # Errors
    ///
    /// Fails for a non-four-node roster, fewer than three valid votes, or any
    /// failed durable certificate handoff.
    pub fn certify_private_settlement_prepare_v1(
        &self,
        committee_endpoints: &[Url],
        manifest: &AtomicPrivateSettlementV1,
        payload_digest: Hash,
        authority: &PrivateSettlementCommitteeAuthorityV1,
    ) -> Result<PrivateSettlementPhaseCertificateV1> {
        self.certify_private_settlement_prepare_with_recovered_v1(
            committee_endpoints,
            manifest,
            payload_digest,
            authority,
            None,
            false,
        )
    }

    /// Recover an existing Prepare QC or safely create one after checking every node.
    ///
    /// This is the restart-safe counterpart to
    /// [`Self::certify_private_settlement_prepare_v1`]. All four recovery reads
    /// must reach quorum before fresh votes are allowed. A certificate orphaned
    /// by an interrupted prior handoff can be reused, while another valid
    /// signer subset over the same body remains logically equivalent.
    ///
    /// # Errors
    ///
    /// Fails under the recovery or certification conditions documented by the
    /// corresponding lower-level methods.
    pub fn recover_or_certify_private_settlement_prepare_v1(
        &self,
        committee_endpoints: &[Url],
        manifest: &AtomicPrivateSettlementV1,
        payload_digest: Hash,
        authority: &PrivateSettlementCommitteeAuthorityV1,
    ) -> Result<PrivateSettlementPhaseCertificateV1> {
        let recovered = self.recover_private_settlement_prepare_certificate_v1(
            committee_endpoints,
            manifest,
            payload_digest,
            authority,
        )?;
        self.certify_private_settlement_prepare_with_recovered_v1(
            committee_endpoints,
            manifest,
            payload_digest,
            authority,
            recovered,
            true,
        )
    }

    fn certify_private_settlement_prepare_with_recovered_v1(
        &self,
        committee_endpoints: &[Url],
        manifest: &AtomicPrivateSettlementV1,
        payload_digest: Hash,
        authority: &PrivateSettlementCommitteeAuthorityV1,
        recovered: Option<PrivateSettlementPhaseCertificateV1>,
        verify_durable_handoff: bool,
    ) -> Result<PrivateSettlementPhaseCertificateV1> {
        if committee_endpoints.len() != authority.validators.len() {
            return Err(eyre!(
                "private-settlement Prepare endpoints must match the four-validator roster"
            ));
        }
        let ordinal = private_settlement_leg_ordinal_for_payload_v1(manifest, payload_digest)?;
        let body = expected_phase_body_v1(
            manifest,
            ordinal,
            authority,
            PrivateSettlementPhaseV1::Prepare,
            private_settlement_reserved_prepared_digest_v1(),
        )?;
        // The validated authority fixes this operation to four roster-indexed
        // requests. Later roster members may stage before an earlier identity
        // rejection is observed; every request is joined before that rejection
        // returns, and no QC handoff starts until the ordered checks succeed.
        let responses = collect_private_settlement_prepare_responses_v1(|index| {
            self.request_private_settlement_prepare_vote_v1(
                &committee_endpoints[index],
                manifest,
                payload_digest,
                authority,
            )
        })?;
        let mut votes = Vec::with_capacity(authority.validators.len());
        let mut responders = Vec::with_capacity(authority.validators.len());
        for (index, response) in responses.into_iter().enumerate() {
            let Ok(response) = response else {
                continue;
            };
            if response.vote.signer != authority.validators[index] {
                return Err(eyre!(
                    "private-settlement Prepare endpoint identity is substituted"
                ));
            }
            votes.push(response.vote);
            responders.push(index);
        }
        let selected = canonical_phase_vote_quorum_v1(&votes)?;
        let certificate = if let Some(certificate) = recovered {
            validate_phase_certificate_v1(&certificate, &body, ordinal, authority)?;
            certificate
        } else {
            aggregate_phase_votes_v1(&body, ordinal, authority, selected)?
        };
        for index in responders {
            let endpoint = &committee_endpoints[index];
            self.persist_private_settlement_phase_certificate_v1(
                endpoint,
                manifest,
                payload_digest,
                &certificate,
            )?;
        }
        if verify_durable_handoff {
            let confirmed = self
                .recover_private_settlement_prepare_certificate_v1(
                    committee_endpoints,
                    manifest,
                    payload_digest,
                    authority,
                )?
                .ok_or_else(|| eyre!("private-settlement recovered Prepare QC was not durable"))?;
            if !phase_certificates_are_quorum_equivalent_v1(&confirmed, &certificate) {
                return Err(eyre!(
                    "private-settlement recovered Prepare statement did not converge durably"
                ));
            }
        }
        Ok(certificate)
    }

    /// Build the exact complete all-Prepare barrier used by every Commit vote.
    ///
    /// # Errors
    ///
    /// Rejects incomplete, reordered, substituted, or cryptographically invalid material.
    pub fn build_private_settlement_prepare_barrier_v1(
        manifest: AtomicPrivateSettlementV1,
        authority_catalog: &[PrivateSettlementCommitteeAuthorityV1],
        deltas: Vec<PrivateSettlementDeltaV1>,
        prepare_certificates: Vec<PrivateSettlementPhaseCertificateV1>,
    ) -> Result<PrivateSettlementPrepareBarrierV1> {
        let authority_catalog =
            PrivateSettlementAuthorityCatalogV1::from_leg_authorities(&manifest, authority_catalog)
                .map_err(|_| eyre!("private-settlement authority catalog is invalid"))?;
        let prepared_bundle_digest = prepared_bundle_digest_v1(
            &manifest,
            &authority_catalog,
            &deltas,
            &prepare_certificates,
        )?;
        let barrier = PrivateSettlementPrepareBarrierV1 {
            version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
            manifest,
            authority_catalog,
            deltas,
            prepare_certificates,
            prepared_bundle_digest,
        };
        validate_prepare_barrier_v1(&barrier)?;
        Ok(barrier)
    }

    /// Prepare every canonical participant leg and construct the complete barrier.
    ///
    /// # Errors
    ///
    /// Fails on incomplete endpoint/authority/delta matrices or any per-leg
    /// verification, quorum, or certificate-persistence failure.
    pub fn prepare_private_settlement_bundle_v1(
        &self,
        committee_endpoints: &[Vec<Url>],
        manifest: &AtomicPrivateSettlementV1,
        authority_catalog: &[PrivateSettlementCommitteeAuthorityV1],
        deltas: &[PrivateSettlementDeltaV1],
    ) -> Result<PrivateSettlementPrepareBarrierV1> {
        if committee_endpoints.len() != manifest.legs.len()
            || authority_catalog.len() != manifest.legs.len()
            || deltas.len() != manifest.legs.len()
        {
            return Err(eyre!("private-settlement Prepare matrix is incomplete"));
        }
        let mut certificates = Vec::with_capacity(manifest.legs.len());
        for (index, ((endpoints, authority), delta)) in committee_endpoints
            .iter()
            .zip(authority_catalog)
            .zip(deltas)
            .enumerate()
        {
            if usize::from(delta.leg_ordinal) != index
                || delta
                    .digest()
                    .map_err(|_| eyre!("private-settlement delta encoding failed"))?
                    != manifest.legs[index].delta_digest
            {
                return Err(eyre!("private-settlement Prepare matrix is substituted"));
            }
            certificates.push(self.certify_private_settlement_prepare_v1(
                endpoints,
                manifest,
                manifest.legs[index].payload_digest,
                authority,
            )?);
        }
        Self::build_private_settlement_prepare_barrier_v1(
            manifest.clone(),
            authority_catalog,
            deltas.to_vec(),
            certificates,
        )
    }

    /// Restart-safe Prepare certification and complete-barrier reconstruction.
    ///
    /// Every committee is queried to quorum for an orphaned valid Prepare QC
    /// before fresh certification. Quorum-equivalent signer subsets reconstruct
    /// the same normalized prepared-bundle digest after a coordinator restart.
    ///
    /// # Errors
    ///
    /// Fails on an incomplete or substituted matrix, any unavailable recovery
    /// quorum, invalid certified statements, or a certification/handoff failure.
    pub fn recover_or_prepare_private_settlement_bundle_v1(
        &self,
        committee_endpoints: &[Vec<Url>],
        manifest: &AtomicPrivateSettlementV1,
        authority_catalog: &[PrivateSettlementCommitteeAuthorityV1],
        deltas: &[PrivateSettlementDeltaV1],
    ) -> Result<PrivateSettlementPrepareBarrierV1> {
        if committee_endpoints.len() != manifest.legs.len()
            || authority_catalog.len() != manifest.legs.len()
            || deltas.len() != manifest.legs.len()
        {
            return Err(eyre!("private-settlement Prepare matrix is incomplete"));
        }
        let mut certificates = Vec::with_capacity(manifest.legs.len());
        for (index, ((endpoints, authority), delta)) in committee_endpoints
            .iter()
            .zip(authority_catalog)
            .zip(deltas)
            .enumerate()
        {
            if usize::from(delta.leg_ordinal) != index
                || delta
                    .digest()
                    .map_err(|_| eyre!("private-settlement delta encoding failed"))?
                    != manifest.legs[index].delta_digest
            {
                return Err(eyre!("private-settlement Prepare matrix is substituted"));
            }
            certificates.push(self.recover_or_certify_private_settlement_prepare_v1(
                endpoints,
                manifest,
                manifest.legs[index].payload_digest,
                authority,
            )?);
        }
        Self::build_private_settlement_prepare_barrier_v1(
            manifest.clone(),
            authority_catalog,
            deltas.to_vec(),
            certificates,
        )
    }

    /// Ask one participant endpoint for a Commit vote over the exact complete barrier.
    ///
    /// # Errors
    ///
    /// Fails on invalid barrier material, transport rejection, or a malformed
    /// or substituted node vote.
    pub fn request_private_settlement_commit_vote_v1(
        &self,
        endpoint: &Url,
        payload_digest: Hash,
        barrier: &PrivateSettlementPrepareBarrierV1,
        authority: &PrivateSettlementCommitteeAuthorityV1,
    ) -> Result<PrivateSettlementPhaseVoteResponseV1> {
        validate_prepare_barrier_v1(barrier)?;
        if barrier.manifest.sponsor != self.account {
            return Err(eyre!(
                "private-settlement Commit requires the manifest sponsor"
            ));
        }
        let ordinal =
            private_settlement_leg_ordinal_for_payload_v1(&barrier.manifest, payload_digest)?;
        let expected = expected_phase_body_v1(
            &barrier.manifest,
            ordinal,
            authority,
            PrivateSettlementPhaseV1::Commit,
            barrier.prepared_bundle_digest,
        )?;
        let request = PrivateSettlementCommitVoteRequestV1 {
            payload_digest,
            barrier: barrier.clone(),
        };
        let body = norito::json::to_vec(&request)
            .wrap_err("failed to encode private-settlement Commit request")?;
        let url = join_torii_url(endpoint, "v1/nexus/private-settlements/phases/commit-votes");
        let response = self.send_private_settlement_builder_v1(
            self.account_signed_request(HttpMethod::POST, url, body)?
                .header("Content-Type", APPLICATION_JSON)
                .header("Accept", APPLICATION_JSON),
        )?;
        let decoded: PrivateSettlementPhaseVoteResponseV1 =
            Self::decode_private_settlement_response_v1(
                &response,
                "private-settlement Commit vote failed",
            )?;
        validate_phase_vote_v1(&decoded.vote, &expected, authority)?;
        if decoded.bundle_id != barrier.manifest.bundle_id
            || decoded.payload_digest != payload_digest
            || decoded.leg_ordinal != ordinal
        {
            return Err(eyre!("private-settlement Commit response is substituted"));
        }
        Ok(decoded)
    }

    /// Fan out to all four validators, select exactly three Commit votes
    /// canonically, and durably hand the QC back to every successful responder.
    ///
    /// # Errors
    ///
    /// Fails for incomplete local Prepare persistence, fewer than three exact
    /// votes, identity substitution, or any failed Commit-QC handoff.
    pub fn certify_private_settlement_commit_v1(
        &self,
        committee_endpoints: &[Url],
        payload_digest: Hash,
        barrier: &PrivateSettlementPrepareBarrierV1,
        authority: &PrivateSettlementCommitteeAuthorityV1,
    ) -> Result<PrivateSettlementPhaseCertificateV1> {
        self.certify_private_settlement_commit_with_recovered_v1(
            committee_endpoints,
            payload_digest,
            barrier,
            authority,
            None,
            false,
        )
    }

    /// Recover an existing Commit QC or safely create one after checking every node.
    ///
    /// # Errors
    ///
    /// Fails under the recovery or certification conditions documented by the
    /// corresponding lower-level methods.
    pub fn recover_or_certify_private_settlement_commit_v1(
        &self,
        committee_endpoints: &[Url],
        payload_digest: Hash,
        barrier: &PrivateSettlementPrepareBarrierV1,
        authority: &PrivateSettlementCommitteeAuthorityV1,
    ) -> Result<PrivateSettlementPhaseCertificateV1> {
        let recovered = self.recover_private_settlement_commit_certificate_v1(
            committee_endpoints,
            payload_digest,
            barrier,
            authority,
        )?;
        self.certify_private_settlement_commit_with_recovered_v1(
            committee_endpoints,
            payload_digest,
            barrier,
            authority,
            recovered,
            true,
        )
    }

    fn certify_private_settlement_commit_with_recovered_v1(
        &self,
        committee_endpoints: &[Url],
        payload_digest: Hash,
        barrier: &PrivateSettlementPrepareBarrierV1,
        authority: &PrivateSettlementCommitteeAuthorityV1,
        recovered: Option<PrivateSettlementPhaseCertificateV1>,
        verify_durable_handoff: bool,
    ) -> Result<PrivateSettlementPhaseCertificateV1> {
        if committee_endpoints.len() != authority.validators.len() {
            return Err(eyre!(
                "private-settlement Commit endpoints must match the four-validator roster"
            ));
        }
        let ordinal =
            private_settlement_leg_ordinal_for_payload_v1(&barrier.manifest, payload_digest)?;
        let body = expected_phase_body_v1(
            &barrier.manifest,
            ordinal,
            authority,
            PrivateSettlementPhaseV1::Commit,
            barrier.prepared_bundle_digest,
        )?;
        let mut votes = Vec::with_capacity(authority.validators.len());
        let mut responders = Vec::with_capacity(authority.validators.len());
        for (index, endpoint) in committee_endpoints.iter().enumerate() {
            let Ok(response) = self.request_private_settlement_commit_vote_v1(
                endpoint,
                payload_digest,
                barrier,
                authority,
            ) else {
                continue;
            };
            if response.vote.signer != authority.validators[index] {
                return Err(eyre!(
                    "private-settlement Commit endpoint identity is substituted"
                ));
            }
            votes.push(response.vote);
            responders.push(index);
        }
        let selected = canonical_phase_vote_quorum_v1(&votes)?;
        let certificate = if let Some(certificate) = recovered {
            validate_phase_certificate_v1(&certificate, &body, ordinal, authority)?;
            certificate
        } else {
            aggregate_phase_votes_v1(&body, ordinal, authority, selected)?
        };
        for index in responders {
            let endpoint = &committee_endpoints[index];
            self.persist_private_settlement_phase_certificate_v1(
                endpoint,
                &barrier.manifest,
                payload_digest,
                &certificate,
            )?;
        }
        if verify_durable_handoff {
            let confirmed = self
                .recover_private_settlement_commit_certificate_v1(
                    committee_endpoints,
                    payload_digest,
                    barrier,
                    authority,
                )?
                .ok_or_else(|| eyre!("private-settlement recovered Commit QC was not durable"))?;
            if !phase_certificates_are_quorum_equivalent_v1(&confirmed, &certificate) {
                return Err(eyre!(
                    "private-settlement recovered Commit statement did not converge durably"
                ));
            }
        }
        Ok(certificate)
    }

    /// Commit every participant leg against one exact complete Prepare barrier.
    ///
    /// # Errors
    ///
    /// Fails on an incomplete endpoint matrix or any per-leg Commit quorum or persistence error.
    pub fn commit_private_settlement_bundle_v1(
        &self,
        committee_endpoints: &[Vec<Url>],
        barrier: &PrivateSettlementPrepareBarrierV1,
    ) -> Result<Vec<PrivateSettlementPhaseCertificateV1>> {
        validate_prepare_barrier_v1(barrier)?;
        if committee_endpoints.len() != barrier.manifest.legs.len() {
            return Err(eyre!("private-settlement Commit matrix is incomplete"));
        }
        committee_endpoints
            .iter()
            .enumerate()
            .map(|(index, endpoints)| {
                let authority = barrier
                    .authority_catalog
                    .authority_for_leg(&barrier.manifest, index)
                    .map_err(|_| eyre!("private-settlement authority catalog is invalid"))?;
                self.certify_private_settlement_commit_v1(
                    endpoints,
                    barrier.manifest.legs[index].payload_digest,
                    barrier,
                    &authority,
                )
            })
            .collect()
    }

    /// Restart-safe Commit certification for every participant leg.
    ///
    /// Every four-validator committee is queried to quorum for orphaned durable
    /// QCs before any fresh Commit certificate is created.
    ///
    /// # Errors
    ///
    /// Fails on an incomplete endpoint matrix or any per-leg recovery,
    /// certification, substitution, or persistence error.
    pub fn recover_or_commit_private_settlement_bundle_v1(
        &self,
        committee_endpoints: &[Vec<Url>],
        barrier: &PrivateSettlementPrepareBarrierV1,
    ) -> Result<Vec<PrivateSettlementPhaseCertificateV1>> {
        validate_prepare_barrier_v1(barrier)?;
        if committee_endpoints.len() != barrier.manifest.legs.len() {
            return Err(eyre!("private-settlement Commit matrix is incomplete"));
        }
        committee_endpoints
            .iter()
            .enumerate()
            .map(|(index, endpoints)| {
                let authority = barrier
                    .authority_catalog
                    .authority_for_leg(&barrier.manifest, index)
                    .map_err(|_| eyre!("private-settlement authority catalog is invalid"))?;
                self.recover_or_certify_private_settlement_commit_v1(
                    endpoints,
                    barrier.manifest.legs[index].payload_digest,
                    barrier,
                    &authority,
                )
            })
            .collect()
    }

    /// Construct the exact sponsor-signed global all-Prepare registration request.
    ///
    /// This control carrier must reach global finality before any participant
    /// committee is asked for a Commit vote. It uses the manifest's bounded
    /// public fee intent through the ordinary transaction admission path; no
    /// fee-free control-plane exception is constructed.
    ///
    /// # Errors
    ///
    /// Rejects an invalid or incomplete barrier, sponsor/network/fee
    /// substitution, signing or canonical encoding failure, and both direct
    /// instruction and complete signed-wire size overflow.
    pub fn build_private_settlement_prepare_registration_request_v1(
        &self,
        barrier: &PrivateSettlementPrepareBarrierV1,
        max_carrier_bytes: u64,
    ) -> Result<PrivateSettlementBundleSubmitRequestV1> {
        let hard_max = u64::try_from(PRIVATE_SETTLEMENT_MAX_RECEIPT_BYTES_V1)
            .expect("private-settlement V1 carrier ceiling fits u64");
        if !(1..=hard_max).contains(&max_carrier_bytes) {
            return Err(eyre!(
                "private-settlement governed carrier byte limit is invalid"
            ));
        }
        validate_prepare_barrier_v1(barrier)?;
        validate_private_settlement_sponsor_context_v1(
            &barrier.manifest,
            &self.network_id,
            &self.account,
            "private-settlement Prepare registration sponsor or network binding is invalid",
        )?;
        let instruction = RegisterAtomicPrivateSettlementPrepareV1::new(barrier.clone());
        let instruction_bytes = u64::try_from(
            norito::encode_canonical(&instruction)
                .map_err(|_| eyre!("private-settlement Prepare registration encoding failed"))?
                .len(),
        )
        .map_err(|_| eyre!("private-settlement Prepare registration is too large"))?;
        if instruction_bytes > max_carrier_bytes {
            return Err(eyre!(
                "private-settlement Prepare registration exceeds the governed byte limit"
            ));
        }
        let expected_manifest = barrier.manifest.clone();
        let transaction = {
            let account = self.account_client()?;
            account
                .prepare_transaction(crate::client::AccountTransactionDraft::new(
                    [InstructionBox::from(instruction)],
                    expected_manifest.public_fee_intent.clone(),
                    Metadata::default(),
                ))
                .and_then(|payload| account.sign_transaction(payload))
        }?;
        let signed_manifest = exact_private_settlement_carrier_v1(&transaction)?;
        if signed_manifest != &expected_manifest
            || transaction.network_id() != Some(&expected_manifest.network_id)
            || transaction.authority() != &expected_manifest.sponsor
            || transaction.fee_payment_intent() != &expected_manifest.public_fee_intent
        {
            return Err(eyre!(
                "private-settlement Prepare registration signed carrier binding is invalid"
            ));
        }
        let signed_bytes = u64::try_from(
            transaction
                .encode_wire_v1()
                .map_err(|_| {
                    eyre!("private-settlement Prepare registration transaction encoding failed")
                })?
                .len(),
        )
        .map_err(|_| eyre!("private-settlement Prepare registration transaction is too large"))?;
        if signed_bytes > max_carrier_bytes {
            return Err(eyre!(
                "private-settlement Prepare registration signed carrier exceeds the governed byte limit"
            ));
        }
        Ok(PrivateSettlementBundleSubmitRequestV1 { transaction })
    }

    /// Submit the exact all-Prepare control-lock carrier and wait for global
    /// state-resolved `Applied` finality.
    ///
    /// Commit fanout must start only after this method returns successfully;
    /// committee Commit voters consult the replicated lock and therefore
    /// reject an admission-only or cache-only registration.
    ///
    /// # Errors
    ///
    /// Fails under the same conditions as
    /// [`Self::build_private_settlement_prepare_registration_request_v1`] and
    /// [`Self::submit_private_settlement_bundle_v1`], or when the exact signed
    /// registration transaction is rejected, expires, or does not reach
    /// state-resolved `Applied` finality within `wait_options`.
    pub fn register_private_settlement_prepare_and_wait_v1(
        &self,
        barrier: &PrivateSettlementPrepareBarrierV1,
        max_carrier_bytes: u64,
        wait_options: TransactionWaitOptions,
    ) -> Result<PrivateSettlementBundleSubmitResponseV1> {
        let request = self
            .build_private_settlement_prepare_registration_request_v1(barrier, max_carrier_bytes)?;
        let transaction_hash = request.transaction.hash();
        let accepted = self.submit_private_settlement_bundle_v1(&request)?;
        self.wait_for_transaction_applied(transaction_hash, wait_options)?;
        Ok(accepted)
    }

    /// Construct one exact sponsor-signed public abort-marker request.
    ///
    /// The returned request contains only the immutable public manifest and
    /// non-sensitive reason class. Submit it through
    /// [`Self::submit_private_settlement_bundle_v1`]. Torii and consensus apply
    /// the authoritative-height rule: `Expired` is admissible only after the
    /// manifest expiry, while the other reason classes are admissible only
    /// through expiry.
    ///
    /// `max_carrier_bytes` must be the active governed limit obtained for the
    /// target deployment. Both the canonical boxed abort instruction and the
    /// complete signed transaction wire are measured before the request is
    /// returned.
    ///
    /// # Errors
    ///
    /// Rejects an invalid governed limit or manifest, sponsor/network/fee
    /// substitution, signing or canonical encoding failure, or a carrier that
    /// exceeds the governed byte limit.
    pub fn build_private_settlement_abort_request_v1(
        &self,
        manifest: &AtomicPrivateSettlementV1,
        reason: PrivateSettlementAbortReasonV1,
        max_carrier_bytes: u64,
    ) -> Result<PrivateSettlementBundleSubmitRequestV1> {
        let hard_max = u64::try_from(PRIVATE_SETTLEMENT_MAX_RECEIPT_BYTES_V1)
            .expect("private-settlement V1 carrier ceiling fits u64");
        if !(1..=hard_max).contains(&max_carrier_bytes) {
            return Err(eyre!(
                "private-settlement governed carrier byte limit is invalid"
            ));
        }
        manifest
            .validate()
            .map_err(|_| eyre!("private-settlement abort manifest is invalid"))?;
        validate_private_settlement_sponsor_context_v1(
            manifest,
            &self.network_id,
            &self.account,
            "private-settlement abort sponsor or network binding is invalid",
        )?;

        let instruction = AbortAtomicPrivateSettlementV1::new(manifest.clone(), reason);
        let boxed_instruction = InstructionBox::from(instruction);
        let instruction_bytes = u64::try_from(
            norito::encode_canonical(&boxed_instruction)
                .map_err(|_| eyre!("private-settlement abort carrier encoding failed"))?
                .len(),
        )
        .map_err(|_| eyre!("private-settlement abort carrier is too large"))?;
        if instruction_bytes > max_carrier_bytes {
            return Err(eyre!(
                "private-settlement abort carrier exceeds the governed byte limit"
            ));
        }

        let expected_manifest = manifest.clone();
        let transaction = {
            let account = self.account_client()?;
            account
                .prepare_transaction(crate::client::AccountTransactionDraft::new(
                    [boxed_instruction],
                    expected_manifest.public_fee_intent.clone(),
                    Metadata::default(),
                ))
                .and_then(|payload| account.sign_transaction(payload))
        }?;
        let signed_manifest = exact_private_settlement_carrier_v1(&transaction)?;
        if signed_manifest != &expected_manifest
            || transaction.network_id() != Some(&expected_manifest.network_id)
            || transaction.authority() != &expected_manifest.sponsor
            || transaction.fee_payment_intent() != &expected_manifest.public_fee_intent
        {
            return Err(eyre!(
                "private-settlement abort signed carrier binding is invalid"
            ));
        }
        let signed_bytes = u64::try_from(
            transaction
                .encode_wire_v1()
                .map_err(|_| eyre!("private-settlement abort transaction encoding failed"))?
                .len(),
        )
        .map_err(|_| eyre!("private-settlement abort transaction is too large"))?;
        if signed_bytes > max_carrier_bytes {
            return Err(eyre!(
                "private-settlement abort signed carrier exceeds the governed byte limit"
            ));
        }
        Ok(PrivateSettlementBundleSubmitRequestV1 { transaction })
    }

    /// Construct the exact sponsor-signed global finalization request for one complete barrier.
    ///
    /// `max_carrier_bytes` must be the active governed limit obtained for the
    /// target deployment. The client deliberately does not assume the V1 hard
    /// ceiling because a deployment may govern a lower limit. Both the boxed
    /// finalization instruction and the complete signed transaction wire are
    /// measured before the request is returned.
    ///
    /// # Errors
    ///
    /// Rejects an invalid governed limit, an incomplete or substituted barrier,
    /// any missing, duplicated, reordered, mis-bound, or unauthenticated Commit
    /// certificate, a sponsor/network/fee mismatch, signing or encoding failure,
    /// or a carrier that exceeds the governed byte limit.
    pub fn build_private_settlement_finalization_request_v1(
        &self,
        barrier: &PrivateSettlementPrepareBarrierV1,
        commit_certificates: &[PrivateSettlementPhaseCertificateV1],
        max_carrier_bytes: u64,
    ) -> Result<PrivateSettlementBundleSubmitRequestV1> {
        let hard_max = u64::try_from(PRIVATE_SETTLEMENT_MAX_RECEIPT_BYTES_V1)
            .expect("private-settlement V1 carrier ceiling fits u64");
        if !(1..=hard_max).contains(&max_carrier_bytes) {
            return Err(eyre!(
                "private-settlement governed carrier byte limit is invalid"
            ));
        }
        validate_prepare_barrier_v1(barrier)?;
        validate_private_settlement_sponsor_context_v1(
            &barrier.manifest,
            &self.network_id,
            &self.account,
            "private-settlement finalization sponsor or network binding is invalid",
        )?;
        let bundle = build_private_settlement_commit_bundle_v1(barrier, commit_certificates)?;
        let instruction_bytes = u64::try_from(
            bundle
                .canonical_carrier_bytes_len()
                .map_err(|_| eyre!("private-settlement finalization carrier encoding failed"))?,
        )
        .map_err(|_| eyre!("private-settlement finalization carrier is too large"))?;
        if instruction_bytes > max_carrier_bytes {
            return Err(eyre!(
                "private-settlement finalization carrier exceeds the governed byte limit"
            ));
        }

        let expected_manifest = barrier.manifest.clone();
        let transaction = {
            let account = self.account_client()?;
            account
                .prepare_transaction(crate::client::AccountTransactionDraft::new(
                    [InstructionBox::from(
                        FinalizeAtomicPrivateSettlementV1::new(bundle),
                    )],
                    expected_manifest.public_fee_intent.clone(),
                    Metadata::default(),
                ))
                .and_then(|payload| account.sign_transaction(payload))
        }?;
        let signed_manifest = exact_private_settlement_carrier_v1(&transaction)?;
        if signed_manifest != &expected_manifest
            || transaction.network_id() != Some(&expected_manifest.network_id)
            || transaction.authority() != &expected_manifest.sponsor
            || transaction.fee_payment_intent() != &expected_manifest.public_fee_intent
        {
            return Err(eyre!(
                "private-settlement finalization signed carrier binding is invalid"
            ));
        }
        let signed_bytes = u64::try_from(
            transaction
                .encode_wire_v1()
                .map_err(|_| eyre!("private-settlement finalization transaction encoding failed"))?
                .len(),
        )
        .map_err(|_| eyre!("private-settlement finalization transaction is too large"))?;
        if signed_bytes > max_carrier_bytes {
            return Err(eyre!(
                "private-settlement finalization signed carrier exceeds the governed byte limit"
            ));
        }
        Ok(PrivateSettlementBundleSubmitRequestV1 { transaction })
    }

    /// Upload one encrypted, fixed-shape settlement leg with sponsor authentication.
    ///
    /// # Errors
    ///
    /// Fails on local structural inconsistency, request signing/transport failure,
    /// Torii rejection, or a substituted response identity.
    pub fn upload_private_settlement_leg_v1(
        &self,
        request: &PrivateSettlementLegUploadRequestV1,
    ) -> Result<PrivateSettlementLegUploadResponseV1> {
        self.upload_private_settlement_leg_to_v1(&self.torii_url, request)
    }

    /// Upload one certified leg to a selected participant endpoint.
    ///
    /// # Errors
    ///
    /// Fails under the same conditions as [`Self::upload_private_settlement_leg_v1`].
    pub fn upload_private_settlement_leg_to_v1(
        &self,
        endpoint: &Url,
        request: &PrivateSettlementLegUploadRequestV1,
    ) -> Result<PrivateSettlementLegUploadResponseV1> {
        request
            .manifest
            .validate()
            .map_err(|_| eyre!("private-settlement leg upload is invalid"))?;
        request
            .payload
            .validate_against(&request.manifest, &request.audit_policy)
            .map_err(|_| eyre!("private-settlement leg upload is invalid"))?;
        validate_availability_certificate_v1(
            &request.payload.availability,
            &request.committee_authority,
        )
        .map_err(|_| eyre!("private-settlement leg upload is invalid"))?;
        if request.manifest.sponsor != self.account {
            return Err(eyre!(
                "private-settlement leg upload requires the manifest sponsor"
            ));
        }
        let body = norito::json::to_vec(request)
            .wrap_err("failed to encode private-settlement leg upload")?;
        let url = join_torii_url(endpoint, "v1/nexus/private-settlements/legs");
        let response = self.send_private_settlement_builder_v1(
            self.account_signed_request(HttpMethod::POST, url, body)?
                .header("Content-Type", APPLICATION_JSON)
                .header("Accept", APPLICATION_JSON),
        )?;
        let decoded: PrivateSettlementLegUploadResponseV1 =
            Self::decode_private_settlement_response_v1(
                &response,
                "private-settlement leg upload failed",
            )?;
        if decoded.bundle_id != request.manifest.bundle_id
            || decoded.payload_digest != request.payload.availability.body.payload_digest
            || decoded.leg_ordinal != request.payload.statement.leg_ordinal
        {
            return Err(eyre!(
                "private-settlement leg upload response is substituted"
            ));
        }
        Ok(decoded)
    }

    /// Certify every leg, finalize one common manifest, and promote each leg on a healthy quorum.
    ///
    /// `committee_endpoints[leg][validator]` is aligned with the canonical leg
    /// ordinal and that leg's four-validator authority roster. Exactly three
    /// shares per leg are aggregated after all four endpoints have been tried;
    /// the completed sidecar is then submitted to every available responder.
    ///
    /// # Errors
    ///
    /// Fails on inconsistent provisional manifests, endpoint matrices,
    /// insufficient shares, final manifest validation, or fewer than `q = n - f`
    /// exact upload acknowledgements for any leg. These acknowledgements are a
    /// transport preflight; the independent Prepare QC remains protocol authority.
    pub fn certify_and_upload_private_settlement_legs_v1(
        &self,
        materials: &[PrivateSettlementProvisionalLegMaterialV1],
        committee_endpoints: &[Vec<Url>],
    ) -> Result<Vec<PrivateSettlementLegUploadResponseV1>> {
        let first = materials
            .first()
            .ok_or_else(|| eyre!("private-settlement provisional leg set is empty"))?;
        if materials.len() != first.manifest.legs.len()
            || committee_endpoints.len() != materials.len()
        {
            return Err(eyre!(
                "private-settlement provisional leg set is incomplete"
            ));
        }
        first
            .manifest
            .validate_provisional()
            .map_err(|_| eyre!("private-settlement provisional manifest is invalid"))?;
        let mut certificates = Vec::with_capacity(materials.len());
        for (index, (material, endpoints)) in materials.iter().zip(committee_endpoints).enumerate()
        {
            if material.manifest != first.manifest
                || usize::from(material.statement.leg_ordinal) != index
            {
                return Err(eyre!(
                    "private-settlement provisional leg set is inconsistent"
                ));
            }
            certificates
                .push(self.certify_private_settlement_leg_availability_v1(endpoints, material)?);
        }
        self.promote_private_settlement_legs_v1(materials, &certificates, committee_endpoints)
    }

    // Promote the original exact availability snapshot using q = n - f bound endpoint
    // acknowledgements as transport preflight. These unsigned acknowledgements are not
    // committee authority: Prepare independently verifies the proof and obtains its QC.
    // Original availability signers are not a mandatory later liveness set.
    fn promote_private_settlement_legs_v1(
        &self,
        materials: &[PrivateSettlementProvisionalLegMaterialV1],
        certificates: &[PrivateSettlementSidecarAvailabilityV1],
        committee_endpoints: &[Vec<Url>],
    ) -> Result<Vec<PrivateSettlementLegUploadResponseV1>> {
        let final_manifest =
            private_settlement_manifest_with_availability_v1(materials, certificates)?;
        validate_private_settlement_sponsor_context_v1(
            &final_manifest,
            &self.network_id,
            &self.account,
            "private-settlement promotion sponsor or network binding is invalid",
        )?;
        if committee_endpoints.len() != materials.len() {
            return Err(eyre!(
                "private-settlement promotion endpoint matrix is incomplete"
            ));
        }
        for (material, endpoints) in materials.iter().zip(committee_endpoints) {
            validate_private_settlement_committee_endpoints_v1(endpoints)?;
            if endpoints.len() != material.committee_authority.validators.len() {
                return Err(eyre!(
                    "private-settlement promotion endpoints do not match authority"
                ));
            }
        }
        let mut responses = Vec::new();
        for ((material, certificate), endpoints) in
            materials.iter().zip(certificates).zip(committee_endpoints)
        {
            let request = PrivateSettlementLegUploadRequestV1 {
                manifest: final_manifest.clone(),
                audit_policy: material.audit_policy.clone(),
                committee_authority: material.committee_authority.clone(),
                payload: material.payload_with_certificate(certificate.clone()),
            };
            let n = material.committee_authority.validators.len();
            let required = n - (n - 1) / 3;
            let mut promoted = 0;
            let mut first_failure = None;
            let mut failed = Vec::with_capacity(n);
            for (index, endpoint) in endpoints.iter().enumerate() {
                match self.upload_private_settlement_leg_to_v1(endpoint, &request) {
                    Ok(response) => {
                        promoted += 1;
                        responses.push(response);
                    }
                    Err(error) => {
                        failed.push(index);
                        first_failure.get_or_insert(error);
                    }
                }
            }
            if promoted < required {
                // A returned replica may have missed the original provisional upload.
                // Rehydrate only failed endpoints, with the exact original material,
                // at most once per replica in this call. A verified new share confirms
                // its identity/custody but is never selected into a new certificate.
                for index in failed {
                    let endpoint = &endpoints[index];
                    let hydrated =
                        self.request_private_settlement_availability_share_v1(endpoint, material);
                    let Ok(hydrated) = hydrated else {
                        continue;
                    };
                    if hydrated.share.signer != material.committee_authority.validators[index] {
                        continue;
                    }
                    if let Ok(response) =
                        self.upload_private_settlement_leg_to_v1(endpoint, &request)
                    {
                        promoted += 1;
                        responses.push(response);
                    }
                }
            }
            if promoted < required {
                let error = first_failure
                    .unwrap_or_else(|| eyre!("private-settlement promotion has no quorum"));
                return Err(error).wrap_err(format!("private-settlement promotion acknowledgements unavailable ({promoted}/{required})"));
            }
        }
        Ok(responses)
    }

    /// Read one account-authenticated, redacted leg lifecycle projection.
    ///
    /// # Errors
    ///
    /// Fails on request signing/transport failure, Torii rejection, or a
    /// malformed/substituted status response.
    pub fn private_settlement_leg_status_v1(
        &self,
        payload_digest: Hash,
    ) -> Result<PrivateSettlementLegStatusResponseV1> {
        let path = private_settlement_resource_path_v1("legs", &payload_digest, "/status");
        let url = join_torii_url(&self.torii_url, &path);
        let response = self.send_private_settlement_builder_v1(
            self.account_signed_request(HttpMethod::GET, url, Vec::new())?
                .header("Accept", APPLICATION_JSON),
        )?;
        let decoded = Self::decode_private_settlement_response_v1(
            &response,
            "private-settlement leg status failed",
        )?;
        validate_leg_status_response_v1(payload_digest, &decoded)?;
        Ok(decoded)
    }

    /// Recover exact locally durable Prepare and Commit QCs from one participant node.
    ///
    /// This sponsor-authenticated read is intended for coordinator restart
    /// recovery. It returns only public quorum material and never proof bytes,
    /// capsules, approvals, or audit plaintext.
    ///
    /// # Errors
    ///
    /// Fails on request signing/transport failure, authorization denial, or a
    /// malformed/substituted recovery response.
    pub fn private_settlement_phase_certificates_from_v1(
        &self,
        endpoint: &Url,
        payload_digest: Hash,
    ) -> Result<PrivateSettlementPhaseCertificatesResponseV1> {
        let path =
            private_settlement_resource_path_v1("legs", &payload_digest, "/phase-certificates");
        let url = join_torii_url(endpoint, &path);
        let response = self.send_private_settlement_builder_v1(
            self.account_signed_request(HttpMethod::GET, url, Vec::new())?
                .header("Accept", APPLICATION_JSON),
        )?;
        let decoded = Self::decode_private_settlement_response_v1(
            &response,
            "private-settlement phase-certificate recovery failed",
        )?;
        validate_phase_certificates_response_v1(payload_digest, &decoded)?;
        Ok(decoded)
    }

    /// Recover exact locally durable Prepare and Commit QCs from the default Torii node.
    ///
    /// # Errors
    ///
    /// Fails under the same conditions as
    /// [`Self::private_settlement_phase_certificates_from_v1`].
    pub fn private_settlement_phase_certificates_v1(
        &self,
        payload_digest: Hash,
    ) -> Result<PrivateSettlementPhaseCertificatesResponseV1> {
        self.private_settlement_phase_certificates_from_v1(&self.torii_url, payload_digest)
    }

    /// Fetch proof material as one exact committee validator identity.
    ///
    /// Encrypted capsule bytes are never returned by this route.
    ///
    /// # Errors
    ///
    /// Fails on identity signing/transport failure, authorization denial, or a
    /// malformed/substituted proof view.
    pub fn private_settlement_committee_proof_v1(
        &self,
        payload_digest: Hash,
        validator_key: &KeyPair,
    ) -> Result<PrivateSettlementCommitteeProofResponseV1> {
        let path = private_settlement_resource_path_v1("legs", &payload_digest, "/committee-proof");
        let url = join_torii_url(&self.torii_url, &path);
        let response = self.send_private_settlement_builder_v1(
            self.identity_signed_request(validator_key, HttpMethod::GET, url, Vec::new())?
                .header("Accept", APPLICATION_JSON),
        )?;
        let decoded = Self::decode_private_settlement_response_v1(
            &response,
            "private-settlement committee proof fetch failed",
        )?;
        validate_private_settlement_committee_proof_response_v1(
            &self.network_id,
            payload_digest,
            &decoded,
        )
        .map_err(|_| eyre!("private-settlement committee response is invalid or substituted"))?;
        Ok(decoded)
    }

    /// Fetch one padded encrypted capsule from an exact committee endpoint.
    ///
    /// `auditor_signer` may be supplied by a deployment-owned signing service.
    /// Its advertised key must be an exact governed auditor signing key and
    /// must not be reused by the participant committee.
    ///
    /// # Errors
    ///
    /// Fails on identity signing/transport failure, authorization denial, or a
    /// malformed/substituted auditor view.
    pub fn private_settlement_auditor_capsule_from_v1<S>(
        &self,
        endpoint: &Url,
        payload_digest: Hash,
        request: &PrivateSettlementAuditorCapsuleRequestV1,
        auditor_signer: &S,
    ) -> Result<PrivateSettlementAuditorCapsuleResponseV1>
    where
        S: IdentityRequestSignerV1 + ?Sized,
    {
        let auditor_signing_key = auditor_signer.public_key().clone();
        validate_private_settlement_endpoint_v1(endpoint)?;
        request
            .audit_policy
            .validate()
            .map_err(|_| eyre!("private-settlement auditor access policy is invalid"))?;
        let body = norito::json::to_vec(request)
            .wrap_err("failed to encode private-settlement auditor capsule request")?;
        let path = private_settlement_resource_path_v1("legs", &payload_digest, "/audit-capsule");
        let url = join_torii_url(endpoint, &path);
        let response = self.send_private_settlement_builder_v1(
            self.identity_signed_request_with_signer(auditor_signer, HttpMethod::POST, url, body)?
                .header("Content-Type", APPLICATION_JSON)
                .header("Accept", APPLICATION_JSON),
        )?;
        let decoded = Self::decode_private_settlement_response_v1(
            &response,
            "private-settlement auditor capsule fetch failed",
        )?;
        validate_private_settlement_auditor_capsule_response_v1(
            &self.network_id,
            payload_digest,
            request,
            &decoded,
        )
        .map_err(|_| eyre!("private-settlement auditor response is invalid or substituted"))?;
        validate_private_settlement_auditor_identity_v1(&auditor_signing_key, &decoded)
            .map_err(|_| eyre!("private-settlement auditor response is invalid or substituted"))?;
        Ok(decoded)
    }

    fn private_settlement_auditor_capsule_quorum_inner_v1<S>(
        &self,
        committee_endpoints: &[Url],
        expected_authority: Option<&PrivateSettlementCommitteeAuthorityV1>,
        payload_digest: Hash,
        request: &PrivateSettlementAuditorCapsuleRequestV1,
        auditor_signer: &S,
    ) -> Result<PrivateSettlementAuditorCapsuleResponseV1>
    where
        S: IdentityRequestSignerV1 + ?Sized,
    {
        validate_private_settlement_committee_endpoints_v1(committee_endpoints)?;
        if let Some(authority) = expected_authority {
            authority
                .validate()
                .map_err(|_| eyre!("private-settlement expected committee authority is invalid"))?;
            for (validator, pop) in authority.validators.iter().zip(&authority.validator_pops) {
                if validator.public_key().try_algorithm().ok() != Some(Algorithm::BlsNormal)
                    || iroha_crypto::bls_normal_pop_verify(validator.public_key(), pop).is_err()
                {
                    return Err(eyre!(
                        "private-settlement expected committee authority is invalid"
                    ));
                }
            }
            if authority.validators.len() != committee_endpoints.len() {
                return Err(eyre!(
                    "private-settlement auditor endpoints must match the expected authority roster"
                ));
            }
        }

        let mut candidates = Vec::with_capacity(committee_endpoints.len());
        for (endpoint_index, endpoint) in committee_endpoints.iter().enumerate() {
            let Ok(response) = self.private_settlement_auditor_capsule_from_v1(
                endpoint,
                payload_digest,
                request,
                auditor_signer,
            ) else {
                continue;
            };
            let mut canonical_view = response.view_digest_material();
            canonical_view.authoritative_height = 0;
            if matches!(
                response.lifecycle,
                PrivateSettlementLifecycleDtoV1::Collecting
                    | PrivateSettlementLifecycleDtoV1::Audited
            ) {
                canonical_view.lifecycle_code =
                    PrivateSettlementLifecycleDtoV1::Collecting.attestation_code();
            }
            let encoded = norito::encode_canonical(&canonical_view)
                .map_err(|_| eyre!("private-settlement auditor quorum response is invalid"))?;
            candidates.push(PrivateSettlementAuthenticatedQuorumCandidateV1 {
                endpoint_index,
                authority: response.committee_authority.clone(),
                responder: response.responder_attestation.body.responder.clone(),
                canonical_view: encoded,
                authoritative_height: response.authoritative_height,
                response,
            });
        }
        select_private_settlement_authenticated_quorum_v1(expected_authority, candidates)
    }

    /// Fetch one authority-pinned committee-quorum auditor view.
    ///
    /// Exactly four distinct endpoints must be aligned with the ordered
    /// `expected_authority.validators` roster. Every accepted response carries
    /// a purpose-separated BLS attestation by the validator at that endpoint's
    /// roster index. At least three views must be identical after normalizing
    /// the approval-retry lifecycle and height; the returned view is the
    /// actually signed middle-height response, so no authenticated field is
    /// rewritten after verification.
    ///
    /// # Errors
    ///
    /// Fails on malformed endpoints or fewer than three exact, unique,
    /// authority- and roster-aligned authenticated views. Substituted,
    /// misaligned, and duplicate responses are excluded from the quorum.
    pub fn private_settlement_auditor_capsule_quorum_for_authority_v1<S>(
        &self,
        committee_endpoints: &[Url],
        expected_authority: &PrivateSettlementCommitteeAuthorityV1,
        payload_digest: Hash,
        request: &PrivateSettlementAuditorCapsuleRequestV1,
        auditor_signer: &S,
    ) -> Result<PrivateSettlementAuditorCapsuleResponseV1>
    where
        S: IdentityRequestSignerV1 + ?Sized,
    {
        self.private_settlement_auditor_capsule_quorum_inner_v1(
            committee_endpoints,
            Some(expected_authority),
            payload_digest,
            request,
            auditor_signer,
        )
    }

    /// Fetch an authenticated quorum without an external authority trust anchor.
    ///
    /// This compatibility surface verifies node signatures and endpoint/roster
    /// alignment, but learns the authority from the responses themselves. It
    /// is unsuitable for production coordination; production callers must use
    /// [`Self::private_settlement_auditor_capsule_quorum_for_authority_v1`]
    /// with a separately governed authority record.
    ///
    /// # Errors
    ///
    /// Fails under the same response, identity, and quorum checks as the pinned
    /// method, except that no external authority equality check is possible.
    pub fn private_settlement_auditor_capsule_quorum_v1<S>(
        &self,
        committee_endpoints: &[Url],
        payload_digest: Hash,
        request: &PrivateSettlementAuditorCapsuleRequestV1,
        auditor_signer: &S,
    ) -> Result<PrivateSettlementAuditorCapsuleResponseV1>
    where
        S: IdentityRequestSignerV1 + ?Sized,
    {
        self.private_settlement_auditor_capsule_quorum_inner_v1(
            committee_endpoints,
            None,
            payload_digest,
            request,
            auditor_signer,
        )
    }

    /// Fetch one padded encrypted capsule from the default Torii endpoint.
    ///
    /// This software-key compatibility adapter delegates to
    /// [`Self::private_settlement_auditor_capsule_from_v1`].
    ///
    /// # Errors
    ///
    /// Fails under the same conditions as the endpoint-aware method.
    pub fn private_settlement_auditor_capsule_v1(
        &self,
        payload_digest: Hash,
        request: &PrivateSettlementAuditorCapsuleRequestV1,
        auditor_signing_key: &KeyPair,
    ) -> Result<PrivateSettlementAuditorCapsuleResponseV1> {
        self.private_settlement_auditor_capsule_from_v1(
            &self.torii_url,
            payload_digest,
            request,
            &BorrowedKeyPairIdentityRequestSignerV1::new(auditor_signing_key),
        )
    }

    /// Submit one auditor approval to one self-authenticating endpoint.
    ///
    /// `auditor_signer` authenticates the transport request. The client first
    /// verifies that the already purpose-separated approval signature was made
    /// by the same advertised key. The response signature and self-asserted
    /// authority are verified, but this single-endpoint compatibility method
    /// has no external authority/endpoint trust anchor and is not a production
    /// quorum coordination surface.
    ///
    /// # Errors
    ///
    /// Fails on identity mismatch, request signing/transport failure, Torii
    /// rejection, or a malformed/substituted acknowledgement.
    pub fn submit_private_settlement_audit_approval_to_v1<S>(
        &self,
        endpoint: &Url,
        payload_digest: Hash,
        auditor_signer: &S,
        request: &PrivateSettlementAuditApprovalRequestV1,
    ) -> Result<PrivateSettlementAuditApprovalResponseV1>
    where
        S: IdentityRequestSignerV1 + ?Sized,
    {
        let auditor_signing_key = auditor_signer.public_key().clone();
        validate_private_settlement_endpoint_v1(endpoint)?;
        validate_private_settlement_audit_approval_request_identity_v1(
            &self.network_id,
            &auditor_signing_key,
            request,
        )?;
        let body = norito::json::to_vec(request)
            .wrap_err("failed to encode private-settlement auditor approval")?;
        let path = private_settlement_resource_path_v1("legs", &payload_digest, "/audit-approvals");
        let url = join_torii_url(endpoint, &path);
        let response = self.send_private_settlement_builder_v1(
            self.identity_signed_request_with_signer(auditor_signer, HttpMethod::POST, url, body)?
                .header("Content-Type", APPLICATION_JSON)
                .header("Accept", APPLICATION_JSON),
        )?;
        let decoded: PrivateSettlementAuditApprovalResponseV1 =
            Self::decode_private_settlement_response_v1(
                &response,
                "private-settlement auditor approval failed",
            )?;
        validate_private_settlement_audit_approval_response_v1(payload_digest, request, &decoded)
            .map_err(|_| eyre!("private-settlement auditor approval response is substituted"))?;
        Ok(decoded)
    }

    fn submit_private_settlement_audit_approval_quorum_inner_v1<S>(
        &self,
        committee_endpoints: &[Url],
        expected_authority: Option<&PrivateSettlementCommitteeAuthorityV1>,
        payload_digest: Hash,
        auditor_signer: &S,
        request: &PrivateSettlementAuditApprovalRequestV1,
    ) -> Result<PrivateSettlementAuditApprovalResponseV1>
    where
        S: IdentityRequestSignerV1 + ?Sized,
    {
        validate_private_settlement_committee_endpoints_v1(committee_endpoints)?;
        if let Some(authority) = expected_authority {
            authority
                .validate()
                .map_err(|_| eyre!("private-settlement expected committee authority is invalid"))?;
            for (validator, pop) in authority.validators.iter().zip(&authority.validator_pops) {
                if validator.public_key().try_algorithm().ok() != Some(Algorithm::BlsNormal)
                    || iroha_crypto::bls_normal_pop_verify(validator.public_key(), pop).is_err()
                {
                    return Err(eyre!(
                        "private-settlement expected committee authority is invalid"
                    ));
                }
            }
            if authority.validators.len() != committee_endpoints.len() {
                return Err(eyre!(
                    "private-settlement approval endpoints must match the expected authority roster"
                ));
            }
        }
        let auditor_signing_key = auditor_signer.public_key().clone();
        validate_private_settlement_audit_approval_request_identity_v1(
            &self.network_id,
            &auditor_signing_key,
            request,
        )?;
        let mut candidates = Vec::with_capacity(committee_endpoints.len());
        for (endpoint_index, endpoint) in committee_endpoints.iter().enumerate() {
            let Ok(response) = self.submit_private_settlement_audit_approval_to_v1(
                endpoint,
                payload_digest,
                auditor_signer,
                request,
            ) else {
                continue;
            };
            let mut canonical_view = response.acknowledgement_digest_material();
            canonical_view.authoritative_height = 0;
            canonical_view.newly_recorded = false;
            let encoded = norito::encode_canonical(&canonical_view)
                .map_err(|_| eyre!("private-settlement approval acknowledgement is invalid"))?;
            candidates.push(PrivateSettlementAuthenticatedQuorumCandidateV1 {
                endpoint_index,
                authority: response.committee_authority.clone(),
                responder: response.responder_attestation.body.responder.clone(),
                canonical_view: encoded,
                authoritative_height: response.authoritative_height,
                response,
            });
        }
        select_private_settlement_authenticated_quorum_v1(expected_authority, candidates)
    }

    /// Submit one approval to an authority-pinned four-validator committee.
    ///
    /// All four distinct endpoints must be ordered like
    /// `expected_authority.validators`. Every accepted acknowledgement is
    /// purpose-separated, BLS-authenticated by the exact endpoint responder,
    /// and counted at most once. One unavailable or substituted endpoint is
    /// excluded without vetoing three exact roster-aligned acknowledgements.
    /// `newly_recorded` and authoritative height are retry observations: they
    /// are normalized only for quorum grouping, and an actually signed
    /// middle-height response is returned unchanged.
    ///
    /// # Errors
    ///
    /// Fails before dispatch for malformed endpoints, authority, or approval
    /// identity, or after all attempts when fewer than three exact unique
    /// authenticated acknowledgements exist.
    pub fn submit_private_settlement_audit_approval_quorum_for_authority_v1<S>(
        &self,
        committee_endpoints: &[Url],
        expected_authority: &PrivateSettlementCommitteeAuthorityV1,
        payload_digest: Hash,
        auditor_signer: &S,
        request: &PrivateSettlementAuditApprovalRequestV1,
    ) -> Result<PrivateSettlementAuditApprovalResponseV1>
    where
        S: IdentityRequestSignerV1 + ?Sized,
    {
        self.submit_private_settlement_audit_approval_quorum_inner_v1(
            committee_endpoints,
            Some(expected_authority),
            payload_digest,
            auditor_signer,
            request,
        )
    }

    /// Submit one approval quorum without an external authority trust anchor.
    ///
    /// This compatibility surface verifies response signatures and internally
    /// self-asserted rosters, but it is unsuitable for production coordination.
    /// Production callers must use
    /// [`Self::submit_private_settlement_audit_approval_quorum_for_authority_v1`].
    ///
    /// # Errors
    ///
    /// Fails under the same response and quorum checks as the authority-pinned
    /// method, except external authority equality cannot be established.
    pub fn submit_private_settlement_audit_approval_quorum_v1<S>(
        &self,
        committee_endpoints: &[Url],
        payload_digest: Hash,
        auditor_signer: &S,
        request: &PrivateSettlementAuditApprovalRequestV1,
    ) -> Result<PrivateSettlementAuditApprovalResponseV1>
    where
        S: IdentityRequestSignerV1 + ?Sized,
    {
        self.submit_private_settlement_audit_approval_quorum_inner_v1(
            committee_endpoints,
            None,
            payload_digest,
            auditor_signer,
            request,
        )
    }

    /// Submit one approval through the software key to the default Torii endpoint.
    ///
    /// This compatibility adapter delegates to
    /// [`Self::submit_private_settlement_audit_approval_to_v1`] and is likewise
    /// unsuitable as a production quorum trust anchor.
    ///
    /// # Errors
    ///
    /// Fails under the same conditions as the endpoint-aware method.
    pub fn submit_private_settlement_audit_approval_v1(
        &self,
        payload_digest: Hash,
        auditor_signing_key: &KeyPair,
        request: &PrivateSettlementAuditApprovalRequestV1,
    ) -> Result<PrivateSettlementAuditApprovalResponseV1> {
        self.submit_private_settlement_audit_approval_to_v1(
            &self.torii_url,
            payload_digest,
            &BorrowedKeyPairIdentityRequestSignerV1::new(auditor_signing_key),
            request,
        )
    }

    /// Submit one exact sponsor-signed global Prepare-lock, finalization, or abort carrier.
    ///
    /// # Errors
    ///
    /// Fails before dispatch if the transaction is not the exact direct carrier
    /// for this client sponsor, or after dispatch if Torii returns a substituted
    /// carrier identity.
    pub fn submit_private_settlement_bundle_v1(
        &self,
        request: &PrivateSettlementBundleSubmitRequestV1,
    ) -> Result<PrivateSettlementBundleSubmitResponseV1> {
        let manifest = exact_private_settlement_carrier_v1(&request.transaction)?;
        if manifest.sponsor != self.account
            || request.transaction.authority() != &self.account
            || request.transaction.fee_payment_intent() != &manifest.public_fee_intent
        {
            return Err(eyre!(
                "private-settlement bundle carrier sponsor binding is invalid"
            ));
        }
        let expected_bundle = manifest.bundle_id;
        let expected_carrier = Hash::from(request.transaction.hash());
        let body = norito::json::to_vec(request)
            .wrap_err("failed to encode private-settlement bundle carrier")?;
        let url = join_torii_url(&self.torii_url, "v1/nexus/private-settlements/bundles");
        let response = self.send_private_settlement_builder_v1(
            self.account_signed_request(HttpMethod::POST, url, body)?
                .header("Content-Type", APPLICATION_JSON)
                .header("Accept", APPLICATION_JSON),
        )?;
        let decoded: PrivateSettlementBundleSubmitResponseV1 =
            Self::decode_private_settlement_accepted_response_v1(
                &response,
                "private-settlement bundle submission failed",
            )?;
        if decoded.bundle_id != expected_bundle || decoded.carrier_id != expected_carrier {
            return Err(eyre!("private-settlement bundle response is substituted"));
        }
        Ok(decoded)
    }

    /// Read the public allowlisted lifecycle for one bundle.
    ///
    /// # Errors
    ///
    /// Fails on transport/Torii error or a malformed/substituted status.
    pub fn private_settlement_bundle_status_v1(
        &self,
        bundle_id: Hash,
    ) -> Result<PrivateSettlementBundleStatusResponseV1> {
        let path = private_settlement_resource_path_v1("bundles", &bundle_id, "");
        let url = join_torii_url(&self.torii_url, &path);
        let response = self.send_private_settlement_builder_v1(
            self.request_without_iroha_identity_auth(HttpMethod::GET, url)
                .header("Accept", APPLICATION_JSON),
        )?;
        let decoded = Self::decode_private_settlement_response_v1(
            &response,
            "private-settlement bundle status failed",
        )?;
        validate_bundle_status_response_v1(bundle_id, &decoded)?;
        Ok(decoded)
    }

    /// Read the public terminal receipt or pending marker for one bundle.
    ///
    /// # Errors
    ///
    /// Fails on transport/Torii error or a malformed/substituted receipt.
    pub fn private_settlement_bundle_receipt_v1(
        &self,
        bundle_id: Hash,
    ) -> Result<PrivateSettlementBundleReceiptResponseV1> {
        let path = private_settlement_resource_path_v1("bundles", &bundle_id, "/receipt");
        let url = join_torii_url(&self.torii_url, &path);
        let response = self.send_private_settlement_builder_v1(
            self.request_without_iroha_identity_auth(HttpMethod::GET, url)
                .header("Accept", APPLICATION_JSON),
        )?;
        let decoded = Self::decode_private_settlement_response_v1(
            &response,
            "private-settlement bundle receipt failed",
        )?;
        validate_bundle_receipt_response_v1(bundle_id, &decoded)?;
        Ok(decoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::evidence_http_tests::{
        SnapshotStore, base_url, client_with_base_url, respond_with, with_mock_http,
    };
    use iroha_data_model::{
        nexus::{PrivateSettlementLegCommitmentV1, PrivateSettlementRouteV1},
        privacy::{
            PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_BYTES_V1, PrivacyCommitmentV1,
            PrivacyEncryptedOutputV1, PrivacyEncryptionKeyV1, PrivacyNullifierV1, PrivacyPoolIdV1,
            PrivacyRecipientIdV1, PrivacyRootV1,
        },
    };
    use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
    use std::{
        num::NonZeroU64,
        sync::{Arc, Mutex},
    };

    #[test]
    fn prepare_request_fanout_overlaps_and_restores_reverse_completion_order() {
        use std::sync::mpsc;
        let (started_tx, started_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let (release_tx, release_rx): (Vec<_>, Vec<_>) =
            (0..4).map(|_| mpsc::channel::<()>()).unzip();
        let release_rx = release_rx.into_iter().map(Mutex::new).collect::<Vec<_>>();
        let timeout = Duration::from_secs(5);
        let responses = std::thread::scope(|scope| {
            let controller = scope.spawn(move || {
                let started = (0..4)
                    .map(|_| started_rx.recv_timeout(timeout).expect("all four overlap"))
                    .collect::<BTreeSet<_>>();
                assert_eq!(started, BTreeSet::from([0, 1, 2, 3]));
                for index in (0..4).rev() {
                    release_tx[index].send(()).expect("release live request");
                    assert_eq!(
                        finished_rx.recv_timeout(timeout).expect("request finished"),
                        index
                    );
                }
            });
            let responses = collect_private_settlement_prepare_responses_v1(|index| {
                started_tx.send(index).expect("controller exists");
                release_rx[index]
                    .lock()
                    .expect("release receiver")
                    .recv_timeout(timeout)
                    .expect("controller releases request");
                finished_tx
                    .send(index)
                    .expect("controller observes completion");
                if index == 1 {
                    Err(eyre!("ordinary request rejection"))
                } else {
                    Ok(index)
                }
            });
            controller.join().expect("completion controller");
            responses.expect("all request owners joined")
        });
        assert_eq!(responses.len(), 4);
        assert_eq!(*responses[0].as_ref().expect("roster zero"), 0);
        assert!(
            responses[1]
                .as_ref()
                .expect_err("request rejection retained")
                .to_string()
                .contains("ordinary request rejection")
        );
        assert_eq!(*responses[2].as_ref().expect("roster two"), 2);
        assert_eq!(*responses[3].as_ref().expect("roster three"), 3);
    }

    #[test]
    fn prepare_request_fanout_joins_every_worker_after_an_early_panic() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Finished<'a>(&'a AtomicUsize, usize);
        impl Drop for Finished<'_> {
            fn drop(&mut self) {
                self.0.fetch_or(1 << self.1, Ordering::SeqCst);
            }
        }
        let finished = AtomicUsize::new(0);
        let result = collect_private_settlement_prepare_responses_v1(|index| {
            let _finished = Finished(&finished, index);
            assert_ne!(index, 0, "intentional request-worker panic");
            Ok(index)
        });
        assert!(
            result
                .expect_err("worker panic must fail closed")
                .to_string()
                .contains("request worker panicked")
        );
        assert_eq!(
            finished.load(Ordering::SeqCst),
            0b1111,
            "a returned error must not detach any initiated request"
        );
    }

    #[test]
    fn prepare_vote_fanout_preserves_quorum_rejection_and_durable_recovery() {
        // Each case uses the real request/response validation and BLS signatures
        // through the existing client-owned mock transport, without a network.
        for case in 0..7 {
            let client = client_with_base_url(base_url());
            let (manifest, _) = finalization_manifest_v1(&client);
            let (authority, keys) = finalization_authority_v1(manifest.legs[0].route, 0);
            let payload_digest = manifest.legs[0].payload_digest;
            let body = expected_phase_body_v1(
                &manifest,
                0,
                &authority,
                PrivateSettlementPhaseV1::Prepare,
                private_settlement_reserved_prepared_digest_v1(),
            )
            .expect("valid Prepare body");
            let votes = phase_votes_v1(&authority, &keys, &body, &[0, 1, 2, 3]);
            let recovered = aggregate_phase_votes_v1(
                &body,
                0,
                &authority,
                &phase_votes_v1(&authority, &keys, &body, &[0, 1, 3]),
            )
            .expect("independent recovered signer subset");
            let responses = votes
                .iter()
                .enumerate()
                .map(|(index, vote)| {
                    let mut vote = vote.clone();
                    if case == 2 && index == 0 {
                        vote.signature[0] ^= 1;
                    }
                    if case == 3 && index == 0 {
                        // Valid cryptography from the wrong roster endpoint is fatal,
                        // even though another request below is also unavailable.
                        vote = votes[1].clone();
                    }
                    let mut response = PrivateSettlementPhaseVoteResponseV1 {
                        bundle_id: manifest.bundle_id,
                        payload_digest,
                        leg_ordinal: 0,
                        vote,
                    };
                    if case == 2 && index == 2 {
                        response.payload_digest = Hash::new(b"substituted-response-payload");
                    }
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", APPLICATION_JSON)
                        .body(norito::json::to_vec(&response).expect("vote response JSON"))
                        .expect("vote HTTP response")
                })
                .collect::<Vec<_>>();
            let ack = PrivateSettlementPhaseCertificateResponseV1 {
                bundle_id: manifest.bundle_id,
                payload_digest,
                leg_ordinal: 0,
                phase: PrivateSettlementPhaseV1::Prepare,
                lifecycle: PrivateSettlementLifecycleDtoV1::Prepared,
            };
            let recovery_response = PrivateSettlementPhaseCertificatesResponseV1 {
                bundle_id: manifest.bundle_id,
                payload_digest,
                leg_ordinal: 0,
                lifecycle: PrivateSettlementLifecycleDtoV1::Prepared,
                prepare_certificate: Some(recovered.clone()),
                commit_certificate: None,
            };
            let events = Arc::new(Mutex::new(Vec::new()));
            let observed = Arc::clone(&events);
            let handed_off = Arc::new(Mutex::new(Vec::new()));
            let recorded = Arc::clone(&handed_off);
            let endpoints = committee_endpoint_fixture_v1();
            let result = with_mock_http(
                move |snapshot| {
                    let index = usize::from(snapshot.url.port().expect("fixture port") - 24_000);
                    if snapshot.url.path().ends_with("/prepare-votes") {
                        observed.lock().expect("event log").push(("vote", index));
                        if (case == 1 && index == 1) || (case == 3 && index == 3) {
                            return Err(eyre!("unavailable fixture endpoint"));
                        }
                        return Ok(responses[index].clone());
                    }
                    if snapshot.url.path().ends_with("/phases/certificates") {
                        observed.lock().expect("event log").push(("persist", index));
                        let request: PrivateSettlementPhaseCertificateRequestV1 =
                            norito::json::from_slice(&snapshot.body)
                                .expect("exact QC handoff request");
                        recorded
                            .lock()
                            .expect("handoff log")
                            .push(request.certificate);
                        let mut response = ack;
                        if case == 5 && index == 2 {
                            response.lifecycle = PrivateSettlementLifecycleDtoV1::Audited;
                        }
                        return Ok(Response::builder()
                            .status(StatusCode::OK)
                            .header("Content-Type", APPLICATION_JSON)
                            .body(norito::json::to_vec(&response).expect("handoff JSON"))
                            .expect("handoff response"));
                    }
                    assert!(snapshot.url.path().ends_with("/phase-certificates"));
                    observed.lock().expect("event log").push(("recover", index));
                    let mut response = recovery_response.clone();
                    if case == 6 && index >= 2 {
                        response.payload_digest = Hash::new(b"recovery-quorum-rejected");
                    }
                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", APPLICATION_JSON)
                        .body(norito::json::to_vec(&response).expect("recovery JSON"))
                        .expect("recovery response"))
                },
                |transport| {
                    let client = client.clone().with_test_http_transport(transport);
                    if case == 4 || case == 6 {
                        client.recover_or_certify_private_settlement_prepare_v1(
                            &endpoints,
                            &manifest,
                            payload_digest,
                            &authority,
                        )
                    } else {
                        client.certify_private_settlement_prepare_v1(
                            &endpoints,
                            &manifest,
                            payload_digest,
                            &authority,
                        )
                    }
                },
            );
            let events = events.lock().expect("events");
            if case == 6 {
                assert!(
                    result
                        .expect_err("failed recovery blocks fresh votes")
                        .to_string()
                        .contains("three valid committee responses")
                );
                assert_eq!(
                    *events,
                    vec![
                        ("recover", 0),
                        ("recover", 1),
                        ("recover", 2),
                        ("recover", 3)
                    ]
                );
                assert!(handed_off.lock().expect("handoffs").is_empty());
                continue;
            }
            let prefix = if case == 4 { 4 } else { 0 };
            assert_eq!(
                events[prefix..prefix + 4]
                    .iter()
                    .map(|(phase, index)| {
                        assert_eq!(*phase, "vote");
                        *index
                    })
                    .collect::<BTreeSet<_>>(),
                BTreeSet::from([0, 1, 2, 3])
            );
            if case == 2 || case == 3 {
                let error = result.expect_err("invalid quorum or endpoint identity must fail");
                assert!(error.to_string().contains(if case == 2 {
                    "phase quorum is unavailable"
                } else {
                    "Prepare endpoint identity is substituted"
                }));
                assert_eq!(events.len(), 4);
                assert!(handed_off.lock().expect("handoffs").is_empty());
                continue;
            }
            let expected_responders = if case == 1 {
                vec![0, 2, 3]
            } else if case == 5 {
                vec![0, 1, 2]
            } else {
                vec![0, 1, 2, 3]
            };
            assert_eq!(
                events
                    .iter()
                    .filter_map(|(phase, index)| (*phase == "persist").then_some(*index))
                    .collect::<Vec<_>>(),
                expected_responders
            );
            if case == 5 {
                assert!(
                    result
                        .expect_err("failed durable handoff cannot succeed")
                        .to_string()
                        .contains("acknowledgement is substituted")
                );
                assert_eq!(events.len(), 7);
                continue;
            }
            let certificate = result.expect("complete exact quorum and handoff");
            assert_eq!(
                certificate.signers_bitmap,
                if case == 1 {
                    0b1101
                } else if case == 4 {
                    0b1011
                } else {
                    0b0111
                }
            );
            validate_phase_certificate_v1(&certificate, &body, 0, &authority)
                .expect("returned QC cryptographically validates");
            assert!(
                handed_off
                    .lock()
                    .expect("handoffs")
                    .iter()
                    .all(|qc| qc == &certificate)
            );
            if case == 4 {
                assert_eq!(certificate, recovered, "preserve recovered aggregate bytes");
                let recovery = vec![
                    ("recover", 0),
                    ("recover", 1),
                    ("recover", 2),
                    ("recover", 3),
                ];
                assert_eq!(&events[..4], recovery.as_slice());
                assert_eq!(&events[12..], recovery.as_slice());
            }
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct MockExactQuorumViewV1 {
        view: u8,
        authoritative_height: u64,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct MockApprovalAcknowledgementV1 {
        collected: u8,
        required: u8,
        newly_recorded: bool,
        authoritative_height: u64,
    }

    fn committee_endpoint_fixture_v1() -> Vec<Url> {
        (0_u16..4)
            .map(|index| {
                Url::parse(&format!("http://127.0.0.1:{}", 24_000 + index))
                    .expect("committee endpoint fixture is valid")
            })
            .collect()
    }

    #[test]
    fn auditor_responder_must_be_unique_and_endpoint_roster_aligned() {
        let validators = (0_u8..4)
            .map(|index| {
                iroha_model_base::peer::PeerId::from(
                    iroha_crypto::KeyPair::from_seed(
                        vec![0x91_u8.saturating_add(index); 32],
                        Algorithm::BlsNormal,
                    )
                    .public_key()
                    .clone(),
                )
            })
            .collect::<Vec<_>>();
        let authority = PrivateSettlementCommitteeAuthorityV1 {
            route: PrivateSettlementRouteV1 {
                dataspace_id: DataSpaceId::new(71),
                lane_id: LaneId::new(5),
                lane_incarnation: Hash::new(b"auditor responder roster incarnation"),
            },
            validator_set_hash: iroha_crypto::HashOf::new(&validators),
            validators: validators.clone(),
            validator_pops: vec![vec![0xA5; PRIVATE_SETTLEMENT_BLS_BYTES_V1]; 4],
        };
        let mut admitted = BTreeSet::new();
        admit_private_settlement_auditor_responder_v1(&authority, 0, &validators[0], &mut admitted)
            .expect("first aligned responder");
        assert!(
            admit_private_settlement_auditor_responder_v1(
                &authority,
                0,
                &validators[0],
                &mut admitted,
            )
            .is_err(),
            "the same responder cannot be counted through a second URL"
        );
        assert!(
            admit_private_settlement_auditor_responder_v1(
                &authority,
                1,
                &validators[0],
                &mut BTreeSet::new(),
            )
            .is_err(),
            "an endpoint cannot authenticate as a different roster index"
        );
    }

    fn mock_auditor_quorum_candidate_v1(
        authority: &PrivateSettlementCommitteeAuthorityV1,
        endpoint_index: usize,
        responder_index: usize,
        view: u8,
        authoritative_height: u64,
    ) -> PrivateSettlementAuthenticatedQuorumCandidateV1<MockExactQuorumViewV1> {
        PrivateSettlementAuthenticatedQuorumCandidateV1 {
            endpoint_index,
            authority: authority.clone(),
            responder: authority.validators[responder_index].clone(),
            canonical_view: vec![view],
            authoritative_height,
            response: MockExactQuorumViewV1 {
                view,
                authoritative_height,
            },
        }
    }

    #[test]
    fn auditor_quorum_ignores_one_substituted_responder() {
        let validators = (0_u8..4)
            .map(|index| {
                PeerId::from(
                    KeyPair::from_seed(
                        vec![0xA1_u8.saturating_add(index); 32],
                        Algorithm::BlsNormal,
                    )
                    .public_key()
                    .clone(),
                )
            })
            .collect::<Vec<_>>();
        let authority = PrivateSettlementCommitteeAuthorityV1 {
            route: PrivateSettlementRouteV1 {
                dataspace_id: DataSpaceId::new(72),
                lane_id: LaneId::new(6),
                lane_incarnation: Hash::new(b"auditor quorum liveness incarnation"),
            },
            validator_set_hash: iroha_crypto::HashOf::new(&validators),
            validators,
            validator_pops: vec![vec![0xA6; PRIVATE_SETTLEMENT_BLS_BYTES_V1]; 4],
        };
        let candidates = vec![
            mock_auditor_quorum_candidate_v1(&authority, 0, 0, 7, 11),
            mock_auditor_quorum_candidate_v1(&authority, 1, 1, 7, 13),
            mock_auditor_quorum_candidate_v1(&authority, 2, 2, 7, 17),
            // Endpoint three is Byzantine and replays validator zero's identity.
            mock_auditor_quorum_candidate_v1(&authority, 3, 0, 7, 19),
        ];
        let response =
            select_private_settlement_authenticated_quorum_v1(Some(&authority), candidates)
                .expect("three aligned responders form quorum despite one substitution");
        assert_eq!(response.view, 7);
        assert_eq!(response.authoritative_height, 13);
    }

    #[test]
    fn auditor_quorum_rejects_fewer_than_three_aligned_responders() {
        let validators = (0_u8..4)
            .map(|index| {
                PeerId::from(
                    KeyPair::from_seed(
                        vec![0xB1_u8.saturating_add(index); 32],
                        Algorithm::BlsNormal,
                    )
                    .public_key()
                    .clone(),
                )
            })
            .collect::<Vec<_>>();
        let authority = PrivateSettlementCommitteeAuthorityV1 {
            route: PrivateSettlementRouteV1 {
                dataspace_id: DataSpaceId::new(73),
                lane_id: LaneId::new(6),
                lane_incarnation: Hash::new(b"auditor quorum subthreshold incarnation"),
            },
            validator_set_hash: iroha_crypto::HashOf::new(&validators),
            validators,
            validator_pops: vec![vec![0xA7; PRIVATE_SETTLEMENT_BLS_BYTES_V1]; 4],
        };
        let candidates = vec![
            mock_auditor_quorum_candidate_v1(&authority, 0, 0, 7, 11),
            mock_auditor_quorum_candidate_v1(&authority, 1, 1, 7, 13),
            mock_auditor_quorum_candidate_v1(&authority, 2, 0, 7, 17),
            mock_auditor_quorum_candidate_v1(&authority, 3, 1, 7, 19),
        ];
        assert!(
            select_private_settlement_authenticated_quorum_v1(Some(&authority), candidates)
                .is_err(),
            "two aligned and two substituted responders cannot form quorum"
        );
    }

    #[test]
    fn exact_quorum_rejects_duplicate_committee_urls_before_dispatch() {
        let mut endpoints = committee_endpoint_fixture_v1();
        endpoints[3] = endpoints[0].clone();
        let mut attempts = 0_usize;
        let result = collect_exact_private_settlement_quorum_v1(
            &endpoints,
            |_| {
                attempts += 1;
                Ok(MockExactQuorumViewV1 {
                    view: 7,
                    authoritative_height: 10,
                })
            },
            |response| Ok((vec![response.view], response.authoritative_height)),
            "mock exact quorum unavailable",
        );
        assert!(result.is_err());
        assert_eq!(attempts, 0, "invalid endpoint rosters fail before I/O");
    }

    #[test]
    fn exact_quorum_attempts_all_four_and_rejects_two_successes() {
        let endpoints = committee_endpoint_fixture_v1();
        let mut attempts = 0_usize;
        let result = collect_exact_private_settlement_quorum_v1(
            &endpoints,
            |_| {
                let attempt = attempts;
                attempts += 1;
                if attempt < 2 {
                    Ok(MockExactQuorumViewV1 {
                        view: 7,
                        authoritative_height: 10,
                    })
                } else {
                    Err(eyre!("mock endpoint unavailable"))
                }
            },
            |response| Ok((vec![response.view], response.authoritative_height)),
            "mock exact quorum unavailable",
        );
        assert!(result.is_err());
        assert_eq!(attempts, 4, "every committee endpoint must be attempted");
    }

    #[test]
    fn exact_quorum_rejects_split_two_plus_two_views() {
        let endpoints = committee_endpoint_fixture_v1();
        let mut attempts = 0_usize;
        let result = collect_exact_private_settlement_quorum_v1(
            &endpoints,
            |_| {
                let attempt = attempts;
                attempts += 1;
                Ok(MockExactQuorumViewV1 {
                    view: if attempt < 2 { 7 } else { 8 },
                    authoritative_height: 10 + u64::try_from(attempt).expect("attempt fits u64"),
                })
            },
            |response| Ok((vec![response.view], response.authoritative_height)),
            "mock exact quorum unavailable",
        );
        assert!(result.is_err());
        assert_eq!(attempts, 4);
    }

    #[test]
    fn exact_quorum_ignores_one_substituted_view_and_returns_middle_matching_height() {
        let endpoints = committee_endpoint_fixture_v1();
        let responses = [
            MockExactQuorumViewV1 {
                view: 7,
                authoritative_height: 11,
            },
            MockExactQuorumViewV1 {
                view: 7,
                authoritative_height: 19,
            },
            MockExactQuorumViewV1 {
                view: 8,
                authoritative_height: 200,
            },
            MockExactQuorumViewV1 {
                view: 7,
                authoritative_height: 17,
            },
        ];
        let mut attempts = 0_usize;
        let (response, quorum_height) = collect_exact_private_settlement_quorum_v1(
            &endpoints,
            |_| {
                let response = responses[attempts];
                attempts += 1;
                Ok(response)
            },
            |response| Ok((vec![response.view], response.authoritative_height)),
            "mock exact quorum unavailable",
        )
        .expect("three identical views form a quorum");
        assert_eq!(attempts, 4);
        assert_eq!(response.view, 7);
        assert_eq!(quorum_height, 17);
    }

    #[test]
    fn exact_quorum_height_rejects_one_same_view_high_outlier() {
        let endpoints = committee_endpoint_fixture_v1();
        let responses = [11_u64, 12, 13, 200];
        let mut attempts = 0_usize;
        let (_, quorum_height) = collect_exact_private_settlement_quorum_v1(
            &endpoints,
            |_| {
                let authoritative_height = responses[attempts];
                attempts += 1;
                Ok(MockExactQuorumViewV1 {
                    view: 7,
                    authoritative_height,
                })
            },
            |response| Ok((vec![response.view], response.authoritative_height)),
            "mock exact quorum unavailable",
        )
        .expect("four identical views form a quorum despite one height outlier");
        assert_eq!(attempts, 4);
        assert_eq!(quorum_height, 13, "one high outlier cannot select height");
    }

    #[test]
    fn approval_acknowledgement_quorum_ignores_one_substituted_responder() {
        let keys = (0_u8..4)
            .map(|index| KeyPair::from_seed(vec![0xC1 + index; 32], Algorithm::BlsNormal))
            .collect::<Vec<_>>();
        let validators = keys
            .iter()
            .map(|key| PeerId::from(key.public_key().clone()))
            .collect::<Vec<_>>();
        let authority = PrivateSettlementCommitteeAuthorityV1 {
            route: PrivateSettlementRouteV1 {
                dataspace_id: DataSpaceId::new(74),
                lane_id: LaneId::new(7),
                lane_incarnation: Hash::new(b"approval acknowledgement quorum incarnation"),
            },
            validator_set_hash: iroha_crypto::HashOf::new(&validators),
            validators,
            validator_pops: vec![vec![0xA8; PRIVATE_SETTLEMENT_BLS_BYTES_V1]; 4],
        };
        let candidate = |endpoint_index: usize,
                         responder_index: usize,
                         newly_recorded: bool,
                         authoritative_height: u64| {
            let response = MockApprovalAcknowledgementV1 {
                collected: 1,
                required: 1,
                newly_recorded,
                authoritative_height,
            };
            PrivateSettlementAuthenticatedQuorumCandidateV1 {
                endpoint_index,
                authority: authority.clone(),
                responder: authority.validators[responder_index].clone(),
                canonical_view: vec![response.collected, response.required, 1],
                authoritative_height,
                response,
            }
        };
        let candidates = vec![
            candidate(0, 0, true, 11),
            candidate(1, 1, false, 13),
            candidate(2, 2, true, 17),
            candidate(3, 0, false, 19),
        ];
        let response =
            select_private_settlement_authenticated_quorum_v1(Some(&authority), candidates)
                .expect("three aligned signed acknowledgements form quorum");
        assert_eq!(response.authoritative_height, 13);
        assert!(!response.newly_recorded);
    }

    #[test]
    fn approval_acknowledgement_quorum_rejects_fewer_than_three_aligned_responders() {
        let validators = (0_u8..4)
            .map(|index| {
                PeerId::from(
                    KeyPair::from_seed(vec![0xD1 + index; 32], Algorithm::BlsNormal)
                        .public_key()
                        .clone(),
                )
            })
            .collect::<Vec<_>>();
        let authority = PrivateSettlementCommitteeAuthorityV1 {
            route: PrivateSettlementRouteV1 {
                dataspace_id: DataSpaceId::new(75),
                lane_id: LaneId::new(7),
                lane_incarnation: Hash::new(b"approval acknowledgement subquorum incarnation"),
            },
            validator_set_hash: iroha_crypto::HashOf::new(&validators),
            validators,
            validator_pops: vec![vec![0xA9; PRIVATE_SETTLEMENT_BLS_BYTES_V1]; 4],
        };
        let candidates = [(0, 0), (1, 1), (2, 0), (3, 1)]
            .into_iter()
            .map(|(endpoint_index, responder_index)| {
                let response = MockApprovalAcknowledgementV1 {
                    collected: 1,
                    required: 1,
                    newly_recorded: endpoint_index == 0,
                    authoritative_height: 11 + u64::try_from(endpoint_index).expect("index fits"),
                };
                PrivateSettlementAuthenticatedQuorumCandidateV1 {
                    endpoint_index,
                    authority: authority.clone(),
                    responder: authority.validators[responder_index].clone(),
                    canonical_view: vec![response.collected, response.required, 1],
                    authoritative_height: response.authoritative_height,
                    response,
                }
            })
            .collect();
        assert!(
            select_private_settlement_authenticated_quorum_v1(Some(&authority), candidates)
                .is_err(),
            "two aligned and two substituted acknowledgement responders cannot form quorum"
        );
    }

    fn phase_fixture_v1() -> (
        PrivateSettlementCommitteeAuthorityV1,
        Vec<iroha_crypto::KeyPair>,
        PrivateSettlementPhaseBodyV1,
    ) {
        let route = iroha_data_model::nexus::PrivateSettlementRouteV1 {
            dataspace_id: iroha_model_base::topology::DataSpaceId::new(31),
            lane_id: iroha_model_base::topology::LaneId::new(7),
            lane_incarnation: Hash::new(b"client-phase-incarnation"),
        };
        let keys = (0_u8..4)
            .map(|index| {
                iroha_crypto::KeyPair::from_seed(
                    vec![0x81_u8.saturating_add(index); 32],
                    Algorithm::BlsNormal,
                )
            })
            .collect::<Vec<_>>();
        let validators = keys
            .iter()
            .map(|key| iroha_model_base::peer::PeerId::from(key.public_key().clone()))
            .collect::<Vec<_>>();
        let authority = PrivateSettlementCommitteeAuthorityV1 {
            route,
            validator_set_hash: iroha_crypto::HashOf::new(&validators),
            validators,
            validator_pops: keys
                .iter()
                .map(|key| {
                    iroha_crypto::bls_normal_pop_prove(key.private_key()).expect("validator PoP")
                })
                .collect(),
        };
        let body = PrivateSettlementPhaseBodyV1 {
            network_id: iroha_data_model::NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
                iroha_data_model::block::BlockHeader,
            >::from_untyped_unchecked(
                Hash::new(b"client-phase-network"),
            )),
            bundle_id: Hash::new(b"client-phase-bundle"),
            manifest_digest: Hash::new(b"client-phase-manifest"),
            leg_ordinal: 0,
            route,
            delta_digest: Hash::new(b"client-phase-delta"),
            authority_digest: authority.digest().expect("authority digest"),
            prepared_bundle_digest: private_settlement_reserved_prepared_digest_v1(),
            phase: PrivateSettlementPhaseV1::Prepare,
            authority_context_height: 10,
            expiry_height: 100,
        };
        (authority, keys, body)
    }

    pub(super) fn phase_votes_v1(
        authority: &PrivateSettlementCommitteeAuthorityV1,
        keys: &[iroha_crypto::KeyPair],
        body: &PrivateSettlementPhaseBodyV1,
        indexes: &[usize],
    ) -> Vec<PrivateSettlementPhaseVoteV1> {
        let preimage = phase_signature_preimage_v1(body).expect("phase preimage");
        indexes
            .iter()
            .map(|index| PrivateSettlementPhaseVoteV1 {
                version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
                body: *body,
                signer: authority.validators[*index].clone(),
                signature: Signature::try_new(keys[*index].private_key(), &preimage)
                    .expect("phase signature")
                    .payload()
                    .to_vec(),
            })
            .collect()
    }

    fn availability_shares_v1(
        authority: &PrivateSettlementCommitteeAuthorityV1,
        keys: &[iroha_crypto::KeyPair],
    ) -> Vec<PrivateSettlementAvailabilityShareV1> {
        let body = PrivateSettlementSidecarAvailabilityBodyV1 {
            version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
            network_id: iroha_data_model::NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
                iroha_data_model::block::BlockHeader,
            >::from_untyped_unchecked(
                Hash::new(b"client-availability-network"),
            )),
            bundle_id: Hash::new(b"client-availability-bundle"),
            leg_ordinal: 0,
            route: authority.route,
            authority_digest: authority.digest().expect("authority digest"),
            authority_context_height: 10,
            payload_digest: Hash::new(b"client-availability-payload"),
            payload_bytes: 128,
            retention_until_height: 100,
        };
        let preimage = body.signature_preimage().expect("availability preimage");
        keys.iter()
            .enumerate()
            .map(|(index, key)| PrivateSettlementAvailabilityShareV1 {
                version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
                body,
                signer: authority.validators[index].clone(),
                signature: Signature::try_new(key.private_key(), &preimage)
                    .expect("availability signature")
                    .payload()
                    .to_vec(),
            })
            .collect()
    }

    fn finalization_route_v1(index: usize) -> PrivateSettlementRouteV1 {
        let dataspace = u64::try_from(index + 41).expect("fixture dataspace fits u64");
        PrivateSettlementRouteV1 {
            dataspace_id: DataSpaceId::new(dataspace),
            lane_id: LaneId::new(u32::try_from(index + 11).expect("fixture lane fits u32")),
            lane_incarnation: Hash::new_from_chunks(&[
                b"client-finalization-route-v1",
                &dataspace.to_le_bytes(),
            ]),
        }
    }

    pub(super) fn finalization_authority_v1(
        route: PrivateSettlementRouteV1,
        ordinal: u8,
    ) -> (
        PrivateSettlementCommitteeAuthorityV1,
        Vec<iroha_crypto::KeyPair>,
    ) {
        let keys = (0_u8..4)
            .map(|index| {
                iroha_crypto::KeyPair::from_seed(
                    vec![0x90_u8.saturating_add(ordinal * 4).saturating_add(index); 32],
                    Algorithm::BlsNormal,
                )
            })
            .collect::<Vec<_>>();
        let validators = keys
            .iter()
            .map(|key| iroha_model_base::peer::PeerId::from(key.public_key().clone()))
            .collect::<Vec<_>>();
        let authority = PrivateSettlementCommitteeAuthorityV1 {
            route,
            validator_set_hash: iroha_crypto::HashOf::new(&validators),
            validators,
            validator_pops: keys
                .iter()
                .map(|key| {
                    iroha_crypto::bls_normal_pop_prove(key.private_key())
                        .expect("finalization fixture validator PoP")
                })
                .collect(),
        };
        (authority, keys)
    }

    pub(super) fn finalization_delta_v1(
        manifest: &AtomicPrivateSettlementV1,
        index: usize,
    ) -> PrivateSettlementDeltaV1 {
        let leg = &manifest.legs[index];
        let base = 0x20_u8.saturating_add(
            u8::try_from(index)
                .expect("fixture index fits u8")
                .saturating_mul(16),
        );
        let output_commitments = (0_u8..3)
            .map(|slot| PrivacyCommitmentV1::new([base.saturating_add(slot); 32]))
            .collect::<Vec<_>>();
        let encrypted_outputs = output_commitments
            .iter()
            .copied()
            .enumerate()
            .map(|(slot, commitment)| {
                let slot = u8::try_from(slot).expect("fixture slot fits u8");
                let seed = base.saturating_add(8).saturating_add(slot);
                let mut ciphertext = vec![seed; PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_BYTES_V1];
                ciphertext[..4].copy_from_slice(b"IPNE");
                PrivacyEncryptedOutputV1 {
                    recipient: PrivacyRecipientIdV1::new([seed; 32]),
                    ephemeral_public_key: PrivacyEncryptionKeyV1::new([seed.saturating_add(1); 32]),
                    commitment,
                    ciphertext,
                }
            })
            .collect::<Vec<_>>();
        let delta = PrivateSettlementDeltaV1 {
            version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
            bundle_id: manifest.bundle_id,
            leg_ordinal: leg.ordinal,
            route: leg.route,
            pool_id: leg.pool_id,
            asset_binding_commitment: leg.asset_binding_commitment,
            old_root: PrivacyRootV1::new([base.saturating_add(11); 32]),
            new_root: PrivacyRootV1::new([base.saturating_add(12); 32]),
            old_epoch: 7,
            new_epoch: 8,
            nullifiers: vec![
                PrivacyNullifierV1::new([base.saturating_add(13); 32]),
                PrivacyNullifierV1::new([base.saturating_add(14); 32]),
            ],
            output_commitments,
            encrypted_outputs,
            statement_digest: Hash::new_from_chunks(&[
                b"client-finalization-statement-v1",
                &[leg.ordinal],
            ]),
            proof_digest: Hash::new_from_chunks(&[b"client-finalization-proof-v1", &[leg.ordinal]]),
            capsule_digest: Hash::new_from_chunks(&[
                b"client-finalization-capsule-v1",
                &[leg.ordinal],
            ]),
            audit_policy_digest: leg.audit_policy_digest,
            audit_key_epoch: 3,
        };
        delta
            .validate_public_shape()
            .expect("finalization fixture delta validates");
        delta
    }

    fn finalization_manifest_v1(
        client: &Client,
    ) -> (AtomicPrivateSettlementV1, Vec<PrivateSettlementDeltaV1>) {
        let mut manifest = AtomicPrivateSettlementV1 {
            version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
            network_id: client.network_id,
            bundle_id: Hash::new(b"client-finalization-bundle-placeholder"),
            authority_context_height: 10,
            expiry_height: 100,
            sponsor: client.account.clone(),
            public_fee_intent: FeePaymentIntent::authority(Vec::new(), None),
            fee_intent_digest: Hash::new(b"client-finalization-fee-placeholder"),
            reimbursement_terms_commitment: Hash::new(b"client-finalization-reimbursement-terms"),
            reimbursement_leg_ordinal: 0,
            legs: (0_usize..2)
                .map(|index| {
                    let ordinal = u8::try_from(index).expect("fixture ordinal fits u8");
                    PrivateSettlementLegCommitmentV1 {
                        ordinal,
                        route: finalization_route_v1(index),
                        pool_id: PrivacyPoolIdV1::new([0x11_u8.saturating_add(ordinal); 32]),
                        asset_binding_commitment: Hash::new_from_chunks(&[
                            b"client-finalization-asset-v1",
                            &[ordinal],
                        ]),
                        audit_policy_digest: Hash::new_from_chunks(&[
                            b"client-finalization-policy-v1",
                            &[ordinal],
                        ]),
                        payload_digest: Hash::new_from_chunks(&[
                            b"client-finalization-payload-v1",
                            &[ordinal],
                        ]),
                        availability_certificate_digest: Hash::new_from_chunks(&[
                            b"client-finalization-availability-v1",
                            &[ordinal],
                        ]),
                        delta_digest: Hash::new_from_chunks(&[
                            b"client-finalization-delta-placeholder-v1",
                            &[ordinal],
                        ]),
                    }
                })
                .collect(),
        };
        manifest.fee_intent_digest = manifest
            .computed_fee_intent_digest()
            .expect("finalization fixture fee hashes");
        manifest.bundle_id = manifest
            .computed_bundle_id()
            .expect("finalization fixture bundle hashes");
        let deltas = (0..manifest.legs.len())
            .map(|index| finalization_delta_v1(&manifest, index))
            .collect::<Vec<_>>();
        for (leg, delta) in manifest.legs.iter_mut().zip(&deltas) {
            leg.delta_digest = delta.digest().expect("finalization fixture delta hashes");
        }
        manifest
            .validate()
            .expect("finalization fixture manifest validates");

        (manifest, deltas)
    }

    fn finalization_fixture_v1(
        client: &Client,
    ) -> (
        PrivateSettlementPrepareBarrierV1,
        Vec<PrivateSettlementPhaseCertificateV1>,
    ) {
        let (manifest, deltas) = finalization_manifest_v1(client);
        let authority_material = manifest
            .legs
            .iter()
            .map(|leg| finalization_authority_v1(leg.route, leg.ordinal))
            .collect::<Vec<_>>();
        let authorities = authority_material
            .iter()
            .map(|(authority, _)| authority.clone())
            .collect::<Vec<_>>();
        let prepare_certificates = authority_material
            .iter()
            .enumerate()
            .map(|(index, (authority, keys))| {
                let ordinal = u8::try_from(index).expect("fixture ordinal fits u8");
                let body = expected_phase_body_v1(
                    &manifest,
                    ordinal,
                    authority,
                    PrivateSettlementPhaseV1::Prepare,
                    private_settlement_reserved_prepared_digest_v1(),
                )
                .expect("finalization fixture Prepare body");
                aggregate_phase_votes_v1(
                    &body,
                    ordinal,
                    authority,
                    &phase_votes_v1(authority, keys, &body, &[0, 1, 2]),
                )
                .expect("finalization fixture Prepare QC")
            })
            .collect::<Vec<_>>();
        let barrier = Client::build_private_settlement_prepare_barrier_v1(
            manifest,
            &authorities,
            deltas,
            prepare_certificates,
        )
        .expect("finalization fixture barrier validates");
        let commits = authority_material
            .iter()
            .enumerate()
            .map(|(index, (authority, keys))| {
                let ordinal = u8::try_from(index).expect("fixture ordinal fits u8");
                let body = expected_phase_body_v1(
                    &barrier.manifest,
                    ordinal,
                    authority,
                    PrivateSettlementPhaseV1::Commit,
                    barrier.prepared_bundle_digest,
                )
                .expect("finalization fixture Commit body");
                aggregate_phase_votes_v1(
                    &body,
                    ordinal,
                    authority,
                    &phase_votes_v1(authority, keys, &body, &[0, 1, 2]),
                )
                .expect("finalization fixture Commit QC")
            })
            .collect();
        (barrier, commits)
    }

    #[test]
    fn sponsor_context_checks_network_and_authority_independently() {
        let client = client_with_base_url(base_url());
        let (barrier, _) = finalization_fixture_v1(&client);
        let manifest = &barrier.manifest;
        validate_private_settlement_sponsor_context_v1(
            manifest,
            &client.network_id,
            &client.account,
            "binding mismatch",
        )
        .expect("exact sponsor context");
        let other_network = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
            Hash::new(b"private-settlement-other-network"),
        ));
        let (other_sponsor, _) = iroha_test_samples::gen_account_in("other-settlement-sponsor");
        for (network_id, sponsor) in [
            (&other_network, &client.account),
            (&client.network_id, &other_sponsor),
        ] {
            let error = validate_private_settlement_sponsor_context_v1(
                manifest,
                network_id,
                sponsor,
                "binding mismatch",
            )
            .expect_err("each independent context substitution must fail");
            assert_eq!(error.to_string(), "binding mismatch");
        }
    }

    fn phase_recovery_response_fixture_v1(
        response: &PrivateSettlementPhaseCertificatesResponseV1,
    ) -> Response<Vec<u8>> {
        Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, APPLICATION_JSON)
            .body(norito::json::to_vec(response).expect("encode recovery fixture"))
            .expect("response build")
    }

    #[test]
    fn recovery_scope_selects_bound_certificates_and_rejects_substitution() {
        let client = client_with_base_url(base_url());
        let (barrier, commits) = finalization_fixture_v1(&client);
        let endpoints = committee_endpoint_fixture_v1();
        let payload_digest = barrier.manifest.legs[0].payload_digest;
        let authority = barrier
            .authority_catalog
            .authority_for_leg(&barrier.manifest, 0)
            .expect("fixture authority");
        let response = PrivateSettlementPhaseCertificatesResponseV1 {
            bundle_id: barrier.manifest.bundle_id,
            payload_digest,
            leg_ordinal: 0,
            lifecycle: PrivateSettlementLifecycleDtoV1::CommitCertified,
            prepare_certificate: Some(barrier.prepare_certificates[0].clone()),
            commit_certificate: Some(commits[0].clone()),
        };
        for phase in [
            PrivateSettlementPhaseV1::Prepare,
            PrivateSettlementPhaseV1::Commit,
        ] {
            let snapshots: SnapshotStore = Arc::new(Mutex::new(Vec::new()));
            let recovered = with_mock_http(
                respond_with(&snapshots, phase_recovery_response_fixture_v1(&response)),
                |transport| {
                    let context = client.clone().with_test_http_transport(transport);
                    match phase {
                        PrivateSettlementPhaseV1::Prepare => context
                            .recover_private_settlement_prepare_certificate_v1(
                                &endpoints,
                                &barrier.manifest,
                                payload_digest,
                                &authority,
                            ),
                        PrivateSettlementPhaseV1::Commit => context
                            .recover_private_settlement_commit_certificate_v1(
                                &endpoints,
                                payload_digest,
                                &barrier,
                                &authority,
                            ),
                    }
                },
            )
            .expect("exact committee recovery")
            .expect("certificate exists");
            let expected = match phase {
                PrivateSettlementPhaseV1::Prepare => &barrier.prepare_certificates[0],
                PrivateSettlementPhaseV1::Commit => &commits[0],
            };
            assert_eq!(&recovered, expected);
            assert_eq!(snapshots.lock().expect("snapshots").len(), 4);
        }
        let mut substituted = response;
        substituted
            .commit_certificate
            .as_mut()
            .expect("fixture Commit certificate")
            .body
            .prepared_bundle_digest = Hash::new(b"substituted-recovery-barrier");
        let snapshots: SnapshotStore = Arc::new(Mutex::new(Vec::new()));
        let error = with_mock_http(
            respond_with(&snapshots, phase_recovery_response_fixture_v1(&substituted)),
            |transport| {
                client
                    .clone()
                    .with_test_http_transport(transport)
                    .recover_private_settlement_commit_certificate_v1(
                        &endpoints,
                        payload_digest,
                        &barrier,
                        &authority,
                    )
            },
        )
        .expect_err("Commit recovery cannot substitute its prepared bundle");
        assert!(
            error
                .to_string()
                .contains("three valid committee responses")
        );
        assert_eq!(snapshots.lock().expect("snapshots").len(), 4);
    }

    #[test]
    fn resource_paths_are_exact_and_query_free() {
        let digest = Hash::new(b"private-settlement-client-path");
        let encoded = digest.to_string();
        assert_eq!(
            private_settlement_resource_path_v1("legs", &digest, "/status"),
            format!("v1/nexus/private-settlements/legs/{encoded}/status")
        );
        assert_eq!(
            private_settlement_resource_path_v1("bundles", &digest, "/receipt"),
            format!("v1/nexus/private-settlements/bundles/{encoded}/receipt")
        );
        assert_eq!(
            private_settlement_resource_path_v1("legs", &digest, "/phase-certificates"),
            format!("v1/nexus/private-settlements/legs/{encoded}/phase-certificates")
        );
    }

    #[test]
    fn client_phase_aggregation_requires_exact_three_distinct_valid_votes() {
        let (authority, keys, body) = phase_fixture_v1();
        let exact = phase_votes_v1(&authority, &keys, &body, &[0, 1, 3]);
        let certificate =
            aggregate_phase_votes_v1(&body, 0, &authority, &exact).expect("exact quorum");
        assert_eq!(certificate.signers_bitmap, 0b1011);
        assert!(validate_phase_certificate_v1(&certificate, &body, 0, &authority).is_ok());

        assert!(
            aggregate_phase_votes_v1(
                &body,
                0,
                &authority,
                &phase_votes_v1(&authority, &keys, &body, &[0, 1]),
            )
            .is_err()
        );
        assert!(
            aggregate_phase_votes_v1(
                &body,
                0,
                &authority,
                &phase_votes_v1(&authority, &keys, &body, &[0, 1, 2, 3]),
            )
            .is_err()
        );

        let mut duplicate = phase_votes_v1(&authority, &keys, &body, &[0, 1, 2]);
        duplicate[1] = duplicate[0].clone();
        assert!(aggregate_phase_votes_v1(&body, 0, &authority, &duplicate).is_err());
        let mut malformed = phase_votes_v1(&authority, &keys, &body, &[0, 1, 2]);
        malformed[2].signature[0] ^= 1;
        assert!(aggregate_phase_votes_v1(&body, 0, &authority, &malformed).is_err());

        let all_four = phase_votes_v1(&authority, &keys, &body, &[0, 1, 2, 3]);
        let selected = canonical_phase_vote_quorum_v1(&all_four)
            .expect("four-endpoint fanout deterministically selects a quorum");
        assert_eq!(selected.len(), 3);
        assert_eq!(selected[0].signer, authority.validators[0]);
        assert_eq!(selected[1].signer, authority.validators[1]);
        assert_eq!(selected[2].signer, authority.validators[2]);
        assert!(
            canonical_phase_vote_quorum_v1(&phase_votes_v1(&authority, &keys, &body, &[0, 1],))
                .is_err()
        );
    }

    #[test]
    fn phase_certificate_recovery_response_is_exact_and_monotonic() {
        let (authority, keys, prepare_body) = phase_fixture_v1();
        let prepare = aggregate_phase_votes_v1(
            &prepare_body,
            0,
            &authority,
            &phase_votes_v1(&authority, &keys, &prepare_body, &[0, 1, 2]),
        )
        .expect("Prepare QC");
        let payload_digest = Hash::new(b"client-recovered-phase-payload");
        let prepared = PrivateSettlementPhaseCertificatesResponseV1 {
            bundle_id: prepare_body.bundle_id,
            payload_digest,
            leg_ordinal: 0,
            lifecycle: PrivateSettlementLifecycleDtoV1::Prepared,
            prepare_certificate: Some(prepare.clone()),
            commit_certificate: None,
        };
        assert!(validate_phase_certificates_response_v1(payload_digest, &prepared).is_ok());

        let mut incomplete = prepared.clone();
        incomplete.lifecycle = PrivateSettlementLifecycleDtoV1::CommitCertified;
        assert!(validate_phase_certificates_response_v1(payload_digest, &incomplete).is_err());

        let mut commit_body = prepare_body;
        commit_body.phase = PrivateSettlementPhaseV1::Commit;
        commit_body.prepared_bundle_digest = Hash::new(b"client-recovered-prepared-bundle");
        let commit = aggregate_phase_votes_v1(
            &commit_body,
            0,
            &authority,
            &phase_votes_v1(&authority, &keys, &commit_body, &[0, 1, 2]),
        )
        .expect("Commit QC");
        let complete = PrivateSettlementPhaseCertificatesResponseV1 {
            lifecycle: PrivateSettlementLifecycleDtoV1::CommitCertified,
            commit_certificate: Some(commit),
            ..prepared
        };
        assert!(validate_phase_certificates_response_v1(payload_digest, &complete).is_ok());

        let mut substituted = complete;
        substituted.payload_digest = Hash::new(b"substituted-recovery-payload");
        assert!(validate_phase_certificates_response_v1(payload_digest, &substituted).is_err());
    }

    #[test]
    fn phase_certificate_acknowledgement_accepts_monotonic_prepare_replay() {
        assert!(phase_certificate_acknowledgement_is_valid_v1(
            PrivateSettlementPhaseV1::Prepare,
            PrivateSettlementLifecycleDtoV1::Prepared,
        ));
        assert!(phase_certificate_acknowledgement_is_valid_v1(
            PrivateSettlementPhaseV1::Prepare,
            PrivateSettlementLifecycleDtoV1::CommitCertified,
        ));
        assert!(!phase_certificate_acknowledgement_is_valid_v1(
            PrivateSettlementPhaseV1::Prepare,
            PrivateSettlementLifecycleDtoV1::Audited,
        ));
        assert!(phase_certificate_acknowledgement_is_valid_v1(
            PrivateSettlementPhaseV1::Commit,
            PrivateSettlementLifecycleDtoV1::CommitCertified,
        ));
        assert!(!phase_certificate_acknowledgement_is_valid_v1(
            PrivateSettlementPhaseV1::Commit,
            PrivateSettlementLifecycleDtoV1::Prepared,
        ));
    }

    #[test]
    fn recovered_phase_certificates_normalize_quorum_equivalent_signer_sets() {
        let (authority, keys, body) = phase_fixture_v1();
        let first = aggregate_phase_votes_v1(
            &body,
            0,
            &authority,
            &phase_votes_v1(&authority, &keys, &body, &[0, 1, 2]),
        )
        .expect("first exact quorum");
        let second = aggregate_phase_votes_v1(
            &body,
            0,
            &authority,
            &phase_votes_v1(&authority, &keys, &body, &[1, 2, 3]),
        )
        .expect("second exact quorum");
        assert_ne!(first, second);
        assert!(phase_certificates_are_quorum_equivalent_v1(&first, &second));

        let expected = std::cmp::min(first.clone(), second.clone());
        let mut recovered = None;
        retain_canonical_phase_certificate_v1(&mut recovered, second);
        retain_canonical_phase_certificate_v1(&mut recovered, first.clone());
        assert_eq!(recovered, Some(expected));

        let mut different_statement = first;
        different_statement.body.delta_digest = Hash::new(b"different recovered statement");
        assert!(!phase_certificates_are_quorum_equivalent_v1(
            recovered.as_ref().expect("canonical recovery"),
            &different_statement,
        ));
    }

    #[test]
    fn prepare_registration_builder_constructs_one_exact_fee_bound_carrier() {
        let client = client_with_base_url(base_url());
        let (barrier, _) = finalization_fixture_v1(&client);
        let request = client
            .build_private_settlement_prepare_registration_request_v1(
                &barrier,
                u64::try_from(PRIVATE_SETTLEMENT_MAX_RECEIPT_BYTES_V1)
                    .expect("hard carrier ceiling fits u64"),
            )
            .expect("complete Prepare barrier builds a registration request");

        assert_eq!(
            exact_private_settlement_carrier_v1(&request.transaction)
                .expect("registration is an exact direct carrier"),
            &barrier.manifest
        );
        assert_eq!(request.transaction.authority(), &barrier.manifest.sponsor);
        assert_eq!(
            request.transaction.fee_payment_intent(),
            &barrier.manifest.public_fee_intent
        );
        let Executable::Instructions(instructions) = request.transaction.instructions() else {
            panic!("registration builder emitted a non-instruction executable");
        };
        let [instruction] = instructions.as_ref() else {
            panic!("registration builder did not emit exactly one instruction");
        };
        let registration = instruction
            .as_any()
            .downcast_ref::<RegisterAtomicPrivateSettlementPrepareV1>()
            .expect("sole instruction is the Prepare registration carrier");
        assert_eq!(registration.barrier, barrier);
    }

    #[test]
    fn abort_builder_constructs_one_exact_fee_bound_carrier() {
        let client = client_with_base_url(base_url());
        let (barrier, _) = finalization_fixture_v1(&client);
        let reason = PrivateSettlementAbortReasonV1::ParticipantRejected;
        let request = client
            .build_private_settlement_abort_request_v1(
                &barrier.manifest,
                reason,
                u64::try_from(PRIVATE_SETTLEMENT_MAX_RECEIPT_BYTES_V1)
                    .expect("hard carrier ceiling fits u64"),
            )
            .expect("valid manifest builds an abort request");

        assert_eq!(
            exact_private_settlement_carrier_v1(&request.transaction)
                .expect("abort is an exact direct carrier"),
            &barrier.manifest
        );
        assert_eq!(
            request.transaction.network_id(),
            Some(&barrier.manifest.network_id)
        );
        assert_eq!(request.transaction.authority(), &barrier.manifest.sponsor);
        assert_eq!(
            request.transaction.fee_payment_intent(),
            &barrier.manifest.public_fee_intent
        );
        let Executable::Instructions(instructions) = request.transaction.instructions() else {
            panic!("abort builder emitted a non-instruction executable");
        };
        let [instruction] = instructions.as_ref() else {
            panic!("abort builder did not emit exactly one instruction");
        };
        let abort = instruction
            .as_any()
            .downcast_ref::<AbortAtomicPrivateSettlementV1>()
            .expect("sole instruction is the abort carrier");
        assert_eq!(abort.manifest, barrier.manifest);
        assert_eq!(abort.reason, reason);
    }

    #[test]
    fn abort_builder_rejects_invalid_manifest_sponsor_and_wire_bounds() {
        let client = client_with_base_url(base_url());
        let (barrier, _) = finalization_fixture_v1(&client);
        let reason = PrivateSettlementAbortReasonV1::SidecarUnavailable;
        let hard_max = u64::try_from(PRIVATE_SETTLEMENT_MAX_RECEIPT_BYTES_V1)
            .expect("hard carrier ceiling fits u64");

        assert!(
            client
                .build_private_settlement_abort_request_v1(&barrier.manifest, reason, 0)
                .is_err()
        );
        assert!(
            client
                .build_private_settlement_abort_request_v1(&barrier.manifest, reason, hard_max + 1,)
                .is_err()
        );

        let request = client
            .build_private_settlement_abort_request_v1(&barrier.manifest, reason, hard_max)
            .expect("hard ceiling admits fixture");
        let exact_signed_bytes = u64::try_from(
            request
                .transaction
                .encode_wire_v1()
                .expect("fixture signed abort transaction encodes")
                .len(),
        )
        .expect("fixture signed abort length fits u64");
        client
            .build_private_settlement_abort_request_v1(
                &barrier.manifest,
                reason,
                exact_signed_bytes,
            )
            .expect("an exact signed-wire bound is inclusive");
        assert!(
            client
                .build_private_settlement_abort_request_v1(
                    &barrier.manifest,
                    reason,
                    exact_signed_bytes - 1,
                )
                .is_err()
        );

        let mut malformed = barrier.manifest.clone();
        malformed.bundle_id = Hash::new(b"substituted-client-abort-bundle");
        assert!(
            client
                .build_private_settlement_abort_request_v1(&malformed, reason, hard_max)
                .is_err()
        );

        let mut substituted_sponsor = barrier.manifest.clone();
        let (outsider, _) = iroha_test_samples::gen_account_in("client-abort-outsider");
        substituted_sponsor.sponsor = outsider;
        substituted_sponsor.bundle_id = substituted_sponsor
            .computed_bundle_id()
            .expect("substituted sponsor manifest hashes");
        substituted_sponsor
            .validate()
            .expect("substituted sponsor manifest remains structurally valid");
        assert!(
            client
                .build_private_settlement_abort_request_v1(&substituted_sponsor, reason, hard_max,)
                .is_err()
        );
    }

    #[test]
    fn blocking_prepare_registration_retries_until_state_applied() {
        let snapshots: SnapshotStore = Arc::new(Mutex::new(Vec::new()));
        let admitted: Arc<Mutex<Option<(String, Hash, Hash)>>> = Arc::new(Mutex::new(None));
        let status_polls = Arc::new(Mutex::new(0_u64));
        let client = client_with_base_url(base_url());
        let (barrier, _) = finalization_fixture_v1(&client);
        let responder = {
            let snapshots = Arc::clone(&snapshots);
            let admitted = Arc::clone(&admitted);
            let status_polls = Arc::clone(&status_polls);
            move |snapshot: crate::http_default::RequestSnapshot| {
                let path = snapshot.url.path().to_owned();
                snapshots
                    .lock()
                    .expect("snapshot lock")
                    .push(snapshot.clone());
                if path == "/v1/nexus/private-settlements/bundles" {
                    let request: PrivateSettlementBundleSubmitRequestV1 =
                        norito::json::from_slice(&snapshot.body)
                            .expect("decode submitted Prepare registration");
                    let manifest = exact_private_settlement_carrier_v1(&request.transaction)
                        .expect("submitted registration is exact");
                    let signed_hash = request.transaction.hash();
                    let signed_hash_literal = signed_hash.to_string();
                    let carrier_id = Hash::from(signed_hash);
                    *admitted.lock().expect("admission lock") =
                        Some((signed_hash_literal, carrier_id, manifest.bundle_id));
                    let response = PrivateSettlementBundleSubmitResponseV1 {
                        bundle_id: manifest.bundle_id,
                        accepted_at_height: 9,
                        carrier_id,
                    };
                    return Ok(Response::builder()
                        .status(StatusCode::ACCEPTED)
                        .header(http::header::CONTENT_TYPE, APPLICATION_JSON)
                        .body(norito::json::to_vec(&response).expect("encode admission response"))
                        .expect("admission response"));
                }
                assert_eq!(path, "/v1/pipeline/transactions/status");
                let (hash, _, _) = admitted
                    .lock()
                    .expect("admission lock")
                    .clone()
                    .expect("status cannot precede admission");
                let mut polls = status_polls.lock().expect("status poll lock");
                *polls += 1;
                let resolved_from = if *polls == 1 { "cache" } else { "state" };
                let response = norito::json!({
                    "hash": hash,
                    "status": { "kind": "Applied", "block_height": 10 },
                    "scope": "global",
                    "resolved_from": resolved_from
                });
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(http::header::CONTENT_TYPE, APPLICATION_JSON)
                    .body(
                        norito::json::to_vec(&response)
                            .expect("encode transaction status response"),
                    )
                    .expect("transaction status response"))
            }
        };

        let accepted = with_mock_http(responder, |mock_transport| {
            let client = client
                .clone()
                .with_test_http_transport(mock_transport.clone());

            client.register_private_settlement_prepare_and_wait_v1(
                &barrier,
                u64::try_from(PRIVATE_SETTLEMENT_MAX_RECEIPT_BYTES_V1)
                    .expect("hard carrier ceiling fits u64"),
                TransactionWaitOptions {
                    timeout: Duration::from_millis(50),
                    poll_interval: Duration::from_millis(1),
                },
            )
        })
        .expect("registration waits through cache-only status until state finality");
        let (_, carrier_id, bundle_id) = admitted
            .lock()
            .expect("admission lock")
            .clone()
            .expect("registration was submitted");
        assert_eq!(accepted.carrier_id, carrier_id);
        assert_eq!(accepted.bundle_id, bundle_id);
        assert_eq!(*status_polls.lock().expect("status poll lock"), 2);
        let paths = snapshots
            .lock()
            .expect("snapshot lock")
            .iter()
            .map(|snapshot| snapshot.url.path().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            paths,
            [
                "/v1/nexus/private-settlements/bundles",
                "/v1/pipeline/transactions/status",
                "/v1/pipeline/transactions/status",
            ]
        );
    }

    #[test]
    fn finalization_builder_constructs_one_exact_sponsor_signed_carrier() {
        let client = client_with_base_url(base_url());
        let (barrier, commits) = finalization_fixture_v1(&client);
        let request = client
            .build_private_settlement_finalization_request_v1(
                &barrier,
                &commits,
                u64::try_from(PRIVATE_SETTLEMENT_MAX_RECEIPT_BYTES_V1)
                    .expect("hard carrier ceiling fits u64"),
            )
            .expect("complete certified barrier builds a finalization request");

        let signed_manifest = exact_private_settlement_carrier_v1(&request.transaction)
            .expect("builder emits an exact direct carrier");
        assert_eq!(signed_manifest, &barrier.manifest);
        assert_eq!(
            request.transaction.network_id(),
            Some(&barrier.manifest.network_id)
        );
        assert_eq!(request.transaction.authority(), &barrier.manifest.sponsor);
        assert_eq!(
            request.transaction.fee_payment_intent(),
            &barrier.manifest.public_fee_intent
        );
        let Executable::Instructions(instructions) = request.transaction.instructions() else {
            panic!("finalization builder emitted a non-instruction executable");
        };
        assert_eq!(instructions.len(), 1);
        let carrier = instructions[0]
            .as_any()
            .downcast_ref::<FinalizeAtomicPrivateSettlementV1>()
            .expect("sole instruction is the finalization carrier");
        assert_eq!(carrier.commit_bundle.manifest, barrier.manifest);
        assert_eq!(
            carrier.commit_bundle.authority_catalog,
            barrier.authority_catalog
        );
        assert_eq!(
            carrier.commit_bundle.legs.len(),
            barrier.manifest.legs.len()
        );
        for (index, leg) in carrier.commit_bundle.legs.iter().enumerate() {
            assert_eq!(leg.delta, barrier.deltas[index]);
            assert_eq!(leg.prepare, barrier.prepare_certificates[index]);
            assert_eq!(leg.commit, commits[index]);
        }
    }

    #[test]
    fn finalization_builder_enforces_governed_and_exact_signed_wire_bounds() {
        let client = client_with_base_url(base_url());
        let (barrier, commits) = finalization_fixture_v1(&client);
        let hard_max = u64::try_from(PRIVATE_SETTLEMENT_MAX_RECEIPT_BYTES_V1)
            .expect("hard carrier ceiling fits u64");
        assert!(
            client
                .build_private_settlement_finalization_request_v1(&barrier, &commits, 0)
                .is_err()
        );
        assert!(
            client
                .build_private_settlement_finalization_request_v1(&barrier, &commits, hard_max + 1,)
                .is_err()
        );

        let first = client
            .build_private_settlement_finalization_request_v1(&barrier, &commits, hard_max)
            .expect("hard ceiling admits fixture");
        let exact_signed_bytes = u64::try_from(
            first
                .transaction
                .encode_wire_v1()
                .expect("fixture signed transaction encodes")
                .len(),
        )
        .expect("fixture signed length fits u64");
        client
            .build_private_settlement_finalization_request_v1(
                &barrier,
                &commits,
                exact_signed_bytes,
            )
            .expect("an exact signed-wire bound is inclusive");
        assert!(
            client
                .build_private_settlement_finalization_request_v1(
                    &barrier,
                    &commits,
                    exact_signed_bytes - 1,
                )
                .is_err()
        );
    }

    #[test]
    fn finalization_builder_rejects_missing_duplicate_reordered_and_substituted_commits() {
        let client = client_with_base_url(base_url());
        let (barrier, commits) = finalization_fixture_v1(&client);
        let hard_max = u64::try_from(PRIVATE_SETTLEMENT_MAX_RECEIPT_BYTES_V1)
            .expect("hard carrier ceiling fits u64");
        assert!(
            client
                .build_private_settlement_finalization_request_v1(
                    &barrier,
                    &commits[..1],
                    hard_max,
                )
                .is_err()
        );

        let duplicate = vec![commits[0].clone(), commits[0].clone()];
        assert!(
            client
                .build_private_settlement_finalization_request_v1(&barrier, &duplicate, hard_max,)
                .is_err()
        );
        let mut reordered = commits.clone();
        reordered.reverse();
        assert!(
            client
                .build_private_settlement_finalization_request_v1(&barrier, &reordered, hard_max,)
                .is_err()
        );

        let other_client = client_with_base_url(base_url());
        let (_, other_commits) = finalization_fixture_v1(&other_client);
        let mut substituted = commits.clone();
        substituted[0] = other_commits[0].clone();
        assert!(
            client
                .build_private_settlement_finalization_request_v1(&barrier, &substituted, hard_max,)
                .is_err()
        );

        let mut unauthenticated = commits;
        unauthenticated[0].aggregate_signature[0] ^= 1;
        assert!(
            client
                .build_private_settlement_finalization_request_v1(
                    &barrier,
                    &unauthenticated,
                    hard_max,
                )
                .is_err()
        );
    }

    #[test]
    fn finalization_builder_rejects_commit_digest_phase_and_route_mismatches() {
        let client = client_with_base_url(base_url());
        let (barrier, commits) = finalization_fixture_v1(&client);
        let hard_max = u64::try_from(PRIVATE_SETTLEMENT_MAX_RECEIPT_BYTES_V1)
            .expect("hard carrier ceiling fits u64");

        let mut wrong_digest = commits.clone();
        wrong_digest[0].body.prepared_bundle_digest =
            Hash::new(b"substituted-client-prepared-bundle");
        assert!(
            client
                .build_private_settlement_finalization_request_v1(
                    &barrier,
                    &wrong_digest,
                    hard_max,
                )
                .is_err()
        );

        let mut wrong_phase = commits.clone();
        wrong_phase[0].body.phase = PrivateSettlementPhaseV1::Prepare;
        assert!(
            client
                .build_private_settlement_finalization_request_v1(&barrier, &wrong_phase, hard_max,)
                .is_err()
        );

        let mut wrong_route = commits;
        wrong_route[0].body.route = barrier.manifest.legs[1].route;
        assert!(
            client
                .build_private_settlement_finalization_request_v1(&barrier, &wrong_route, hard_max,)
                .is_err()
        );
    }

    #[test]
    fn finalization_builder_and_submission_fail_closed_on_envelope_binding() {
        let client = client_with_base_url(base_url());
        let (barrier, commits) = finalization_fixture_v1(&client);
        let hard_max = u64::try_from(PRIVATE_SETTLEMENT_MAX_RECEIPT_BYTES_V1)
            .expect("hard carrier ceiling fits u64");

        let other_client = client_with_base_url(base_url());
        let (other_barrier, other_commits) = finalization_fixture_v1(&other_client);
        assert!(
            client
                .build_private_settlement_finalization_request_v1(
                    &other_barrier,
                    &other_commits,
                    hard_max,
                )
                .is_err()
        );

        let mut wrong_network_client = client.clone();
        wrong_network_client.network_id =
            iroha_data_model::NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
                iroha_data_model::block::BlockHeader,
            >::from_untyped_unchecked(
                Hash::new(b"substituted-client-finalization-network"),
            ));
        assert!(
            wrong_network_client
                .build_private_settlement_finalization_request_v1(&barrier, &commits, hard_max,)
                .is_err()
        );

        let mut substituted_fee_barrier = barrier.clone();
        substituted_fee_barrier.manifest.public_fee_intent =
            FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(1));
        assert!(
            client
                .build_private_settlement_finalization_request_v1(
                    &substituted_fee_barrier,
                    &commits,
                    hard_max,
                )
                .is_err()
        );

        let valid = client
            .build_private_settlement_finalization_request_v1(&barrier, &commits, hard_max)
            .expect("valid finalization request");
        let Executable::Instructions(instructions) = valid.transaction.instructions() else {
            panic!("valid builder result is not an instruction transaction");
        };
        let carrier = instructions[0]
            .as_any()
            .downcast_ref::<FinalizeAtomicPrivateSettlementV1>()
            .expect("valid builder result contains a finalization carrier")
            .clone();
        let multiple = {
            let account = client
                .account_client()
                .expect("bind private-settlement fixture account");
            account
                .prepare_transaction(crate::client::AccountTransactionDraft::new(
                    [
                        InstructionBox::from(carrier.clone()),
                        InstructionBox::from(carrier.clone()),
                    ],
                    barrier.manifest.public_fee_intent.clone(),
                    Metadata::default(),
                ))
                .and_then(|payload| account.sign_transaction(payload))
        }
        .expect("fixture multi-carrier transaction signs");
        assert!(exact_private_settlement_carrier_v1(&multiple).is_err());
        assert!(
            client
                .submit_private_settlement_bundle_v1(&PrivateSettlementBundleSubmitRequestV1 {
                    transaction: multiple
                })
                .is_err()
        );

        let wrong_fee = {
            let account = client
                .account_client()
                .expect("bind private-settlement fixture account");
            account
                .prepare_transaction(crate::client::AccountTransactionDraft::new(
                    [InstructionBox::from(carrier)],
                    FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(1)),
                    Metadata::default(),
                ))
                .and_then(|payload| account.sign_transaction(payload))
        }
        .expect("fixture fee-substituted transaction signs");
        assert!(
            client
                .submit_private_settlement_bundle_v1(&PrivateSettlementBundleSubmitRequestV1 {
                    transaction: wrong_fee
                })
                .is_err()
        );
    }

    #[test]
    fn availability_fanout_selects_the_canonical_three_of_four() {
        let (authority, keys, _) = phase_fixture_v1();
        let all_four = availability_shares_v1(&authority, &keys);
        let selected = canonical_availability_share_quorum_v1(&all_four)
            .expect("four-endpoint availability fanout has a quorum");
        assert_eq!(selected.len(), 3);
        assert_eq!(selected[0].signer, authority.validators[0]);
        assert_eq!(selected[1].signer, authority.validators[1]);
        assert_eq!(selected[2].signer, authority.validators[2]);
        let certificate = aggregate_availability_shares_v1(all_four[0].body, &authority, selected)
            .expect("canonical availability quorum");
        assert_eq!(certificate.signers_bitmap, 0b0111);
        assert!(canonical_availability_share_quorum_v1(&all_four[..2]).is_err());
    }

    fn availability_response_fixture_v1(
        share: PrivateSettlementAvailabilityShareV1,
    ) -> PrivateSettlementAvailabilityShareResponseV1 {
        PrivateSettlementAvailabilityShareResponseV1 {
            bundle_id: share.body.bundle_id,
            payload_digest: share.body.payload_digest,
            leg_ordinal: share.body.leg_ordinal,
            disposition: iroha_torii_shared::private_settlement_api::PrivateSettlementLegUploadDispositionV1::Stored,
            share,
        }
    }

    // Structural fixture for the public availability request/certifier:
    // it uses opaque proof/capsule bytes, real committee keys/PoPs/signatures and the
    // real material validator. It neither generates nor verifies a native proof.
    // Binding order follows Core sidecar_store::provisional_material_fixture;
    // padded opaque capsule shape follows torii_shared's response-validation fixture.
    pub(super) fn availability_material_fixture_v1(
        client: &Client,
    ) -> (
        PrivateSettlementProvisionalLegMaterialV1,
        Vec<PrivateSettlementAvailabilityShareV1>,
    ) {
        use iroha_data_model::nexus::{
            PRIVATE_SETTLEMENT_ML_KEM_768_CIPHERTEXT_BYTES_V1,
            PRIVATE_SETTLEMENT_WRAPPED_DEK_BYTES_V1, PrivateSettlementAuditAadV1,
            PrivateSettlementAuditCapsuleV1, PrivateSettlementAuditPolicyBodyV1,
            PrivateSettlementAuditPolicyV1, PrivateSettlementAuditorV1,
            PrivateSettlementCapsulePaddingV1, PrivateSettlementHybridPublicKeyV1,
            PrivateSettlementProofProfileV1, PrivateSettlementProofStatementV1,
            PrivateSettlementWrappedDekV1,
        };
        let (mut manifest, _) = finalization_manifest_v1(client);
        let route = manifest.legs[0].route;
        let (authority, keys) = finalization_authority_v1(route, 0);
        let auditor = KeyPair::from_seed(vec![0xE1; 32], Algorithm::Ed25519);
        let auditor_id = AccountId::new(auditor.public_key().clone());
        let mut rng = iroha_crypto::rng_from_seed_slice(b"client availability fixture auditor");
        let hybrid = iroha_crypto::HybridKeyPair::generate(&mut rng).expect("fixture hybrid key");
        let policy = PrivateSettlementAuditPolicyV1::new(PrivateSettlementAuditPolicyBodyV1 {
            version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
            dataspace_id: route.dataspace_id,
            policy_id: Hash::new(b"client availability fixture policy"),
            revision: 1,
            key_epoch: 3,
            activation_height: 5,
            retirement_height: None,
            min_approvals: 1,
            auditors: vec![PrivateSettlementAuditorV1 {
                auditor_id: auditor_id.clone(),
                signing_key: auditor.public_key().clone(),
                encryption_key: PrivateSettlementHybridPublicKeyV1::from_hybrid(hybrid.public()),
            }],
        })
        .expect("fixture audit policy");
        manifest.legs[0].audit_policy_digest = policy.policy_digest;
        for leg in &mut manifest.legs {
            leg.availability_certificate_digest = Hash::prehashed([0; Hash::LENGTH]);
        }
        manifest.bundle_id = manifest.computed_bundle_id().expect("fixture bundle id");
        for index in 0..manifest.legs.len() {
            let digest = finalization_delta_v1(&manifest, index)
                .digest()
                .expect("fixture delta digest");
            manifest.legs[index].delta_digest = digest;
        }
        let mut delta = finalization_delta_v1(&manifest, 0);
        let authority_digest = authority.digest().expect("fixture authority digest");
        let plaintext_commitment = Hash::new(b"client availability fixture plaintext");
        let padding = PrivateSettlementCapsulePaddingV1::KiB4;
        let audit_capsule = PrivateSettlementAuditCapsuleV1 {
            version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
            aad: PrivateSettlementAuditAadV1 {
                network_id: manifest.network_id,
                bundle_id: manifest.bundle_id,
                leg_ordinal: 0,
                route,
                authority_digest,
                authority_context_height: manifest.authority_context_height,
                audit_policy_digest: policy.policy_digest,
                audit_key_epoch: policy.body.key_epoch,
                plaintext_commitment,
            },
            padding,
            nonce: [0xE2; 24],
            ciphertext: vec![0xE3; padding.ciphertext_bytes()],
            wrapped_deks: vec![PrivateSettlementWrappedDekV1 {
                auditor_id,
                ephemeral_x25519: [0xE4; 32],
                ml_kem_ciphertext: vec![0xE5; PRIVATE_SETTLEMENT_ML_KEM_768_CIPHERTEXT_BYTES_V1],
                nonce: [0xE6; 24],
                wrapped_dek: vec![0xE7; PRIVATE_SETTLEMENT_WRAPPED_DEK_BYTES_V1],
            }],
        };
        let profile = PrivateSettlementProofProfileV1::IvmPrivateNoteFixed2In3Out;
        let statement = PrivateSettlementProofStatementV1 {
            version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
            profile,
            proof_profile_digest: profile.digest(),
            network_id: manifest.network_id,
            bundle_id: manifest.bundle_id,
            leg_ordinal: 0,
            route,
            authority_context_height: manifest.authority_context_height,
            pool_id: delta.pool_id,
            asset_binding_commitment: delta.asset_binding_commitment,
            old_root: delta.old_root,
            new_root: delta.new_root,
            old_epoch: delta.old_epoch,
            new_epoch: delta.new_epoch,
            nullifiers: delta.nullifiers.clone(),
            output_commitments: delta.output_commitments.clone(),
            encrypted_outputs: delta.encrypted_outputs.clone(),
            audit_plaintext_commitment: plaintext_commitment,
            audit_input_commitment: [0xE8; 32],
            audit_capsule_digest: audit_capsule.digest().expect("fixture capsule digest"),
            audit_policy_digest: policy.policy_digest,
            audit_key_epoch: policy.body.key_epoch,
            fee_intent_digest: manifest.fee_intent_digest,
            reimbursement_terms_commitment: manifest.reimbursement_terms_commitment,
            reimbursement_leg_ordinal: manifest.reimbursement_leg_ordinal,
            expiry_height: manifest.expiry_height,
        };
        let proof = b"availability-request-proof-canary".to_vec();
        delta.statement_digest = statement.digest().expect("fixture statement digest");
        delta.proof_digest = iroha_data_model::nexus::private_settlement_proof_digest_v1(&proof);
        delta.capsule_digest = statement.audit_capsule_digest;
        manifest.legs[0].delta_digest = delta.digest().expect("fixture bound delta digest");
        let availability_body = PrivateSettlementSidecarAvailabilityBodyV1 {
            version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
            network_id: manifest.network_id,
            bundle_id: manifest.bundle_id,
            leg_ordinal: 0,
            route,
            authority_digest,
            authority_context_height: manifest.authority_context_height,
            payload_digest: Hash::new(b"client availability fixture provisional digest"),
            payload_bytes: 1,
            retention_until_height: manifest.expiry_height,
        };
        let mut material = PrivateSettlementProvisionalLegMaterialV1 {
            version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
            manifest,
            audit_policy: policy,
            committee_authority: authority,
            statement,
            proof,
            delta,
            audit_capsule,
            availability_body,
        };
        let payload_digest = material.payload_digest().expect("fixture payload digest");
        material.manifest.legs[0].payload_digest = payload_digest;
        material.availability_body.payload_digest = payload_digest;
        material.availability_body.payload_bytes = u32::try_from(
            material
                .sidecar_material_bytes_len()
                .expect("fixture material size"),
        )
        .expect("fixture size fits u32");
        material
            .validate()
            .expect("complete provisional material must validate");
        let preimage = material
            .availability_body
            .signature_preimage()
            .expect("fixture preimage");
        let shares = keys
            .iter()
            .enumerate()
            .map(|(index, key)| PrivateSettlementAvailabilityShareV1 {
                version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
                body: material.availability_body,
                signer: material.committee_authority.validators[index].clone(),
                signature: Signature::try_new(key.private_key(), &preimage)
                    .expect("fixture availability signature")
                    .payload()
                    .to_vec(),
            })
            .collect();
        (material, shares)
    }

    pub(super) fn availability_endpoints_fixture_v1() -> Vec<Url> {
        (0..4)
            .map(|index| {
                Url::parse(&format!("http://availability-{index}.mock/")).expect("fixture endpoint")
            })
            .collect()
    }

    #[test]
    fn availability_public_certifier_retains_all_four_http_rejections_without_private_text() {
        const CANARY: &str = "availability-response-auth-capsule-canary";
        let client = client_with_base_url(base_url());
        let (material, _) = availability_material_fixture_v1(&client);
        let endpoints = availability_endpoints_fixture_v1();
        let snapshots: SnapshotStore = Arc::new(Mutex::new(Vec::new()));
        let response = Response::builder()
            .status(413)
            .header("Content-Type", APPLICATION_JSON)
            .header("x-iroha-reject-code", "request_payload_too_large")
            .body(
                format!(r#"{{"code":"request_payload_too_large","message":"{CANARY}"}}"#)
                    .into_bytes(),
            )
            .expect("fixture HTTP rejection");
        let error = with_mock_http(respond_with(&snapshots, response), |transport| {
            client
                .clone()
                .with_test_http_transport(transport)
                .certify_private_settlement_leg_availability_v1(&endpoints, &material)
        })
        .expect_err("all four HTTP rejections prevent quorum");
        let requests = snapshots.lock().expect("snapshot lock");
        assert_eq!(requests.len(), 4);
        for (index, request) in requests.iter().enumerate() {
            assert_eq!(request.url.host_str(), endpoints[index].host_str());
            assert_eq!(
                request.url.path(),
                "/v1/nexus/private-settlements/legs/availability-shares"
            );
            let decoded: PrivateSettlementAvailabilityShareRequestV1 =
                norito::json::from_slice(&request.body).expect("real provisional request JSON");
            assert_eq!(decoded.material, material);
        }
        let text = format!("{error:#}");
        assert!(text.contains("valid_shares=0"));
        for index in 0..4 {
            assert!(text.contains(&format!("roster[{index}]=http_status=413")));
        }
        assert!(text.contains("request_payload_too_large"));
        for text in [text, format!("{error:?}")] {
            assert!(!text.contains(CANARY));
            assert!(!text.contains("availability-request-proof-canary"));
            assert!(!text.contains(".mock"));
        }
    }

    #[test]
    fn availability_public_certifier_tolerates_one_http_failure_and_verifies_three_real_shares() {
        let client = client_with_base_url(base_url());
        let (material, shares) = availability_material_fixture_v1(&client);
        let endpoints = availability_endpoints_fixture_v1();
        let expected = aggregate_availability_shares_v1(
            material.availability_body,
            &material.committee_authority,
            &[shares[0].clone(), shares[2].clone(), shares[3].clone()],
        )
        .expect("expected exact-three certificate");
        let snapshots: SnapshotStore = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&snapshots);
        let response_endpoints = endpoints.clone();
        let certificate = with_mock_http(
            move |request| {
                let index = response_endpoints
                    .iter()
                    .position(|endpoint| endpoint.host_str() == request.url.host_str())
                    .expect("requested fixture endpoint");
                captured.lock().expect("snapshot lock").push(request);
                let (status, body) = if index == 1 {
                    (
                        503,
                        br#"{"code":"service_unavailable","message":"unavailable"}"#.to_vec(),
                    )
                } else {
                    (
                        200,
                        norito::json::to_vec(&availability_response_fixture_v1(
                            shares[index].clone(),
                        ))
                        .expect("fixture signed response"),
                    )
                };
                Ok(Response::builder()
                    .status(status)
                    .header("Content-Type", APPLICATION_JSON)
                    .body(body)
                    .expect("fixture response"))
            },
            |transport| {
                client
                    .clone()
                    .with_test_http_transport(transport)
                    .certify_private_settlement_leg_availability_v1(&endpoints, &material)
            },
        )
        .expect("one endpoint failure is tolerated through the real public request method");
        assert_eq!(certificate, expected);
        assert_eq!(certificate.signers_bitmap, 0b1101);
        assert_eq!(snapshots.lock().expect("snapshot lock").len(), 4);
    }

    #[test]
    fn availability_collection_preserves_every_three_of_four_quorum_and_roster_failure() {
        let (authority, keys, _) = phase_fixture_v1();
        let all_four = availability_shares_v1(&authority, &keys);
        for available in 0_u8..16 {
            let mut requested = Vec::new();
            let result = collect_private_settlement_availability_shares_v1(&authority, |index| {
                requested.push(index);
                if available & (1 << index) == 0 {
                    Err(eyre!(PrivateSettlementAvailabilityFailureV1::Http {
                        status: 503,
                        public_code: Some("private_settlement_service_unavailable"),
                    }))
                } else {
                    Ok(availability_response_fixture_v1(all_four[index].clone()))
                }
            });
            assert_eq!(requested, vec![0, 1, 2, 3]);
            let count = available.count_ones() as usize;
            if count >= 3 {
                let shares = result.expect("one unavailable endpoint is tolerated");
                let selected =
                    canonical_availability_share_quorum_v1(&shares).expect("exact quorum");
                assert_eq!(selected.len(), 3);
                let certificate =
                    aggregate_availability_shares_v1(all_four[0].body, &authority, selected)
                        .expect("valid exact-three certificate");
                let expected = (0..4)
                    .filter(|index| available & (1 << index) != 0)
                    .take(3)
                    .fold(0_u8, |mask, index| mask | (1 << index));
                assert_eq!(certificate.signers_bitmap, expected);
                assert_eq!(certificate.signers_bitmap.count_ones(), 3);
            } else {
                let error = result.expect_err("fewer than three must fail");
                let details = error
                    .downcast_ref::<PrivateSettlementAvailabilityQuorumFailureV1>()
                    .expect("typed bounded quorum detail");
                assert_eq!(details.valid_shares, count);
                let expected = (0..4)
                    .filter(|index| available & (1 << index) == 0)
                    .collect::<Vec<_>>();
                assert_eq!(
                    details
                        .failures
                        .iter()
                        .map(|(index, _)| *index)
                        .collect::<Vec<_>>(),
                    expected
                );
                let text = format!("{error:#}");
                assert!(text.contains(&format!("valid_shares={count}, required_quorum=3")));
                for index in expected {
                    assert!(text.contains(&format!("roster[{index}]=http_status=503")));
                }
            }
        }
    }

    #[test]
    fn availability_collection_keeps_substituted_roster_identity_fatal_even_after_three_shares() {
        let (authority, keys, _) = phase_fixture_v1();
        let shares = availability_shares_v1(&authority, &keys);
        let error = collect_private_settlement_availability_shares_v1(&authority, |index| {
            Ok(availability_response_fixture_v1(
                shares[if index == 3 { 0 } else { index }].clone(),
            ))
        })
        .expect_err("wrong endpoint signer must not be tolerated as unavailable");
        assert_eq!(
            error.to_string(),
            "private-settlement availability endpoint identity is substituted at roster[3]"
        );
    }

    #[test]
    fn availability_collection_rejects_invalid_roster_before_requesting() {
        let (mut authority, _, _) = phase_fixture_v1();
        authority.validators.pop();
        let error = collect_private_settlement_availability_shares_v1(&authority, |_| {
            panic!("invalid roster must not initiate a request")
        })
        .expect_err("four validator roster required");
        assert!(error.to_string().contains("four-validator roster"));
    }

    #[test]
    fn availability_http_diagnostics_keep_status_and_only_recognized_public_codes() {
        const CANARY: &str = "private-proof-capsule-auth-response-canary";
        for (status, header, body, expected) in [
            (413, None, CANARY.to_owned(), None),
            (
                429,
                Some("request_rate_limited"),
                CANARY.to_owned(),
                Some("request_rate_limited"),
            ),
            (
                503,
                None,
                r#"{"code":"service_unavailable","message":"public rejection"}"#.to_owned(),
                Some("service_unavailable"),
            ),
            (
                413,
                Some("request_payload_too_large"),
                CANARY.to_owned(),
                Some("request_payload_too_large"),
            ),
            (
                503,
                None,
                format!(
                    r#"{{"code":"private_settlement_service_unavailable","details":"{CANARY}"}}"#
                ),
                Some("private_settlement_service_unavailable"),
            ),
            (403, Some(CANARY), format!(r#"{{"code":"{CANARY}"}}"#), None),
            (500, None, "x".repeat(4097), None),
            (
                500,
                None,
                format!(r#"{{"code":"private_settlement_unavailable","code":"{CANARY}"}}"#),
                None,
            ),
        ] {
            let mut builder = Response::builder()
                .status(status)
                .header("Content-Type", APPLICATION_JSON);
            if let Some(header) = header {
                builder = builder.header("x-iroha-reject-code", header);
            }
            let response = builder.body(body.into_bytes()).expect("failure response");
            let error = decode_private_settlement_availability_response_v1(&response)
                .expect_err("HTTP rejection");
            let Some(PrivateSettlementAvailabilityFailureV1::Http {
                status: actual,
                public_code,
            }) = error.downcast_ref::<PrivateSettlementAvailabilityFailureV1>()
            else {
                panic!("typed HTTP failure");
            };
            assert_eq!(*actual, status);
            assert_eq!(*public_code, expected);
            for text in [format!("{error:#}"), format!("{error:?}")] {
                assert!(text.contains(&status.to_string()));
                assert!(!text.contains(CANARY));
            }
            assert!(error.to_string().len() < 256);
        }
    }

    #[test]
    fn availability_public_codes_reject_duplicate_oversized_and_non_json_sources() {
        let response = |headers: &[&str], content_type: &str, body: Vec<u8>| {
            let mut builder = Response::builder()
                .status(413)
                .header("Content-Type", content_type);
            for header in headers {
                builder = builder.header("x-iroha-reject-code", *header);
            }
            builder.body(body).expect("response")
        };
        let known = br#"{"code":"private_settlement_unavailable"}"#.to_vec();
        assert_eq!(
            private_settlement_availability_public_code_v1(&response(
                &["request_payload_too_large", "request_payload_too_large"],
                "text/plain",
                vec![]
            )),
            None
        );
        assert_eq!(
            private_settlement_availability_public_code_v1(&response(
                &[&"x".repeat(97)],
                APPLICATION_JSON,
                vec![]
            )),
            None
        );
        assert_eq!(
            private_settlement_availability_public_code_v1(&response(
                &[],
                "text/plain",
                known.clone()
            )),
            None
        );
        let mut oversized = known;
        oversized.resize(4097, b' ');
        assert_eq!(
            private_settlement_availability_public_code_v1(&response(
                &[],
                APPLICATION_JSON,
                oversized
            )),
            None
        );
    }

    #[test]
    fn availability_decoder_accepts_exact_json_and_sanitizes_malformed_success() {
        const CANARY: &str = "private-invalid-json-content-type-canary";
        let (authority, keys, _) = phase_fixture_v1();
        let share = availability_shares_v1(&authority, &keys).remove(0);
        let dto = availability_response_fixture_v1(share);
        let response = Response::builder()
            .status(200)
            .header("Content-Type", APPLICATION_JSON)
            .body(norito::json::to_vec(&dto).expect("encode share"))
            .expect("response");
        let decoded = decode_private_settlement_availability_response_v1(&response)
            .expect("exact share JSON");
        assert_eq!(decoded.share.signer, dto.share.signer);
        for (content_type, expected) in [
            (APPLICATION_JSON, "invalid_response_json"),
            (CANARY, "invalid_response_content_type"),
        ] {
            let response = Response::builder()
                .status(200)
                .header("Content-Type", content_type)
                .body(CANARY.as_bytes().to_vec())
                .expect("response");
            let error = decode_private_settlement_availability_response_v1(&response)
                .expect_err("malformed response");
            assert_eq!(error.to_string(), expected);
            assert!(!format!("{error:#}").contains(CANARY));
        }
    }

    #[test]
    fn availability_transport_and_unknown_error_chains_never_enter_quorum_diagnostics() {
        const CANARY: &str = "secret-url-proof-capsule-authorization-canary";
        let timeout = eyre::Report::new(std::io::Error::new(std::io::ErrorKind::TimedOut, CANARY))
            .wrap_err(CANARY);
        assert!(matches!(
            PrivateSettlementAvailabilityFailureV1::transport(&timeout),
            PrivateSettlementAvailabilityFailureV1::TransportTimeout
        ));
        let arbitrary = eyre!(CANARY);
        assert!(matches!(
            PrivateSettlementAvailabilityFailureV1::transport(&arbitrary),
            PrivateSettlementAvailabilityFailureV1::Transport
        ));
        let (authority, _, _) = phase_fixture_v1();
        let error =
            collect_private_settlement_availability_shares_v1(&authority, |index| match index {
                0 => Err(eyre!(PrivateSettlementAvailabilityFailureV1::Http {
                    status: 413,
                    public_code: None
                })
                .wrap_err(CANARY)),
                1 => Err(eyre!(
                    PrivateSettlementAvailabilityFailureV1::TransportTimeout
                )),
                2 => Err(eyre!(PrivateSettlementAvailabilityFailureV1::InvalidShare)),
                _ => Err(eyre!(CANARY).wrap_err(CANARY)),
            })
            .expect_err("all four fail");
        let text = format!("{error:#}");
        assert!(text.contains("valid_shares=0, required_quorum=3"));
        for (index, expected) in [
            "http_status=413",
            "transport_timeout",
            "invalid_availability_share",
            "request_failed",
        ]
        .iter()
        .enumerate()
        {
            assert!(text.contains(&format!("roster[{index}]={expected}")));
        }
        assert!(!text.contains(CANARY));
        assert!(!format!("{error:?}").contains(CANARY));
        assert!(text.len() < 1024);
    }

    #[test]
    fn pending_receipt_rejects_identifier_substitution() {
        let requested = Hash::new(b"requested-private-settlement-bundle");
        let substituted = Hash::new(b"substituted-private-settlement-bundle");
        let response = PrivateSettlementBundleReceiptResponseV1::Pending {
            bundle_id: substituted,
        };
        assert!(validate_bundle_receipt_response_v1(requested, &response).is_err());
    }

    #[test]
    fn nonterminal_status_rejects_a_finalized_height() {
        let bundle_id = Hash::new(b"private-settlement-status-bundle");
        let response = PrivateSettlementBundleStatusResponseV1 {
            manifest: None,
            lifecycle: PrivateSettlementLifecycleDtoV1::Prepared,
            finalized_height: Some(42),
        };
        assert!(validate_bundle_status_response_v1(bundle_id, &response).is_err());
    }

    #[test]
    fn response_decoders_require_the_exact_route_status_without_echoing_bodies() {
        const CANARY: &str = "private-settlement-response-body-canary";
        let payload = norito::json!({"canary": CANARY});
        let body = norito::json::to_vec(&payload).expect("encode response payload");
        let response = |status| {
            Response::builder()
                .status(status)
                .header(http::header::CONTENT_TYPE, APPLICATION_JSON)
                .body(body.clone())
                .expect("response build")
        };

        let decoded: norito::json::Value = Client::decode_private_settlement_response_v1(
            &response(StatusCode::OK),
            "private-settlement exact-200 test",
        )
        .expect("ordinary routes accept 200");
        assert_eq!(decoded, payload);
        let decoded: norito::json::Value = Client::decode_private_settlement_accepted_response_v1(
            &response(StatusCode::ACCEPTED),
            "private-settlement exact-202 test",
        )
        .expect("bundle admission accepts 202");
        assert_eq!(decoded, payload);

        for status in [
            StatusCode::ACCEPTED,
            StatusCode::CREATED,
            StatusCode::NO_CONTENT,
        ] {
            let error = Client::decode_private_settlement_response_v1::<norito::json::Value>(
                &response(status),
                "private-settlement exact-200 test",
            )
            .expect_err("ordinary routes reject alternate 2xx responses");
            assert!(error.to_string().contains("expected 200 OK"));
            assert!(!error.to_string().contains(CANARY));
        }
        for status in [StatusCode::OK, StatusCode::CREATED, StatusCode::NO_CONTENT] {
            let error =
                Client::decode_private_settlement_accepted_response_v1::<norito::json::Value>(
                    &response(status),
                    "private-settlement exact-202 test",
                )
                .expect_err("bundle admission rejects alternate 2xx responses");
            assert!(error.to_string().contains("expected 202 Accepted"));
            assert!(!error.to_string().contains(CANARY));
        }

        let malformed = Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, APPLICATION_JSON)
            .body(format!(r#"{{"{CANARY}":1,"{CANARY}":2}}"#).into_bytes())
            .expect("malformed response build");
        let error = Client::decode_private_settlement_response_v1::<norito::json::Value>(
            &malformed,
            "private-settlement malformed response test",
        )
        .expect_err("malformed response is rejected without retaining parser details");
        assert_eq!(
            error.to_string(),
            "private-settlement malformed response test: invalid JSON response"
        );
        assert!(!error.to_string().contains(CANARY));

        let malicious_content_type = Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, format!("text/{CANARY}"))
            .body(body)
            .expect("malicious content-type response build");
        let error = Client::decode_private_settlement_response_v1::<norito::json::Value>(
            &malicious_content_type,
            "private-settlement content-type response test",
        )
        .expect_err("untrusted content type is rejected without echoing it");
        assert!(!error.to_string().contains(CANARY));
    }

    #[test]
    fn public_bundle_status_strips_iroha_identity_headers_but_retains_gateway_auth() {
        let snapshots: SnapshotStore = Arc::new(Mutex::new(Vec::new()));
        let mut client = client_with_base_url(base_url());
        client
            .headers
            .insert("Authorization".to_owned(), "Basic gateway".to_owned());
        for header in [
            HEADER_ACCOUNT,
            HEADER_SIGNATURE,
            HEADER_TIMESTAMP_MS,
            HEADER_NONCE,
            HEADER_OPERATOR_PUBLIC_KEY,
            HEADER_OPERATOR_TIMESTAMP_MS,
            HEADER_OPERATOR_NONCE,
            HEADER_OPERATOR_SIGNATURE,
        ] {
            client
                .headers
                .insert(header.to_owned(), "must-not-leak".to_owned());
        }
        let bundle_id = Hash::new(b"public-private-settlement-status");
        let _ = with_mock_http(
            respond_with(
                &snapshots,
                Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Vec::new())
                    .expect("response build"),
            ),
            |mock_transport| {
                let client = client
                    .clone()
                    .with_test_http_transport(mock_transport.clone());
                client.private_settlement_bundle_status_v1(bundle_id)
            },
        )
        .expect_err("mocked missing bundle fails");
        let snapshots = snapshots.lock().expect("lock snapshots");
        assert_eq!(snapshots.len(), 1);
        let request = &snapshots[0];
        assert_eq!(request.method, HttpMethod::GET);
        assert!(request.url.query().is_none());
        assert!(request.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("authorization") && value == "Basic gateway"
        }));
        for header in [
            HEADER_ACCOUNT,
            HEADER_SIGNATURE,
            HEADER_TIMESTAMP_MS,
            HEADER_NONCE,
            HEADER_OPERATOR_PUBLIC_KEY,
            HEADER_OPERATOR_TIMESTAMP_MS,
            HEADER_OPERATOR_NONCE,
            HEADER_OPERATOR_SIGNATURE,
        ] {
            assert!(
                !request
                    .headers
                    .iter()
                    .any(|(name, _)| name.eq_ignore_ascii_case(header)),
                "public query leaked {header}"
            );
        }
    }

    #[test]
    fn committee_fetch_uses_the_explicit_identity_key() {
        let snapshots: SnapshotStore = Arc::new(Mutex::new(Vec::new()));
        let client = client_with_base_url(base_url());
        let validator = checked_random_keypair();
        let payload_digest = Hash::new(b"committee-private-settlement-proof");
        let _ = with_mock_http(
            respond_with(
                &snapshots,
                Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Vec::new())
                    .expect("response build"),
            ),
            |mock_transport| {
                let client = client
                    .clone()
                    .with_test_http_transport(mock_transport.clone());
                client.private_settlement_committee_proof_v1(payload_digest, &validator)
            },
        )
        .expect_err("mocked unauthorized committee read fails");
        let snapshots = snapshots.lock().expect("lock snapshots");
        assert_eq!(snapshots.len(), 1);
        let request = &snapshots[0];
        assert_eq!(request.method, HttpMethod::GET);
        assert!(request.url.path().ends_with("/committee-proof"));
        assert!(request.body.is_empty());
        let expected_key = validator
            .public_key()
            .try_to_multihash_string()
            .expect("encode validator key");
        assert!(request.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case(HEADER_OPERATOR_PUBLIC_KEY) && value == &expected_key
        }));
    }

    #[test]
    fn phase_certificate_recovery_uses_sponsor_auth_and_exact_path() {
        let snapshots: SnapshotStore = Arc::new(Mutex::new(Vec::new()));
        let client = client_with_base_url(base_url());
        let payload_digest = Hash::new(b"sponsor-phase-recovery-payload");
        let response = PrivateSettlementPhaseCertificatesResponseV1 {
            bundle_id: Hash::new(b"sponsor-phase-recovery-bundle"),
            payload_digest,
            leg_ordinal: 0,
            lifecycle: PrivateSettlementLifecycleDtoV1::Audited,
            prepare_certificate: None,
            commit_certificate: None,
        };
        let response_body = norito::json::to_vec(&response).expect("encode recovery response");
        let decoded = with_mock_http(
            respond_with(
                &snapshots,
                Response::builder()
                    .status(StatusCode::OK)
                    .header(http::header::CONTENT_TYPE, APPLICATION_JSON)
                    .body(response_body)
                    .expect("response build"),
            ),
            |mock_transport| {
                let client = client
                    .clone()
                    .with_test_http_transport(mock_transport.clone());
                client.private_settlement_phase_certificates_v1(payload_digest)
            },
        )
        .expect("sponsor recovery response");
        assert_eq!(decoded, response);

        let snapshots = snapshots.lock().expect("lock snapshots");
        assert_eq!(snapshots.len(), 1);
        let request = &snapshots[0];
        assert_eq!(request.method, HttpMethod::GET);
        assert_eq!(
            request.url.path(),
            format!("/v1/nexus/private-settlements/legs/{payload_digest}/phase-certificates")
        );
        assert!(request.body.is_empty());
        assert!(
            request
                .headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case(HEADER_ACCOUNT))
        );
        assert!(
            request
                .headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case(HEADER_SIGNATURE))
        );
    }
}
