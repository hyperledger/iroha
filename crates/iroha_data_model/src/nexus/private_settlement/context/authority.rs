//! One portable native lane/committee rule shared by execution and context authentication.
use crate::{
    nexus::{
        PRIVATE_SETTLEMENT_BLS_BYTES_V1, PRIVATE_SETTLEMENT_COMMITTEE_VALIDATORS_V1,
        PrivateSettlementCommitteeAuthorityV1, PrivateSettlementRouteV1,
        PrivateSettlementValidationError,
    },
    sumeragi_lanes::{SumeragiLaneRecord, SumeragiLaneState},
};
use iroha_crypto::{Algorithm, Hash};

/// Validate the exact fixed roster and BLS proofs of possession.
///
/// This checks cryptography only; it does not establish a committed assignment.
/// # Errors
/// Invalid geometry, ordering, validator hash, algorithm or proof of possession.
pub fn validate_private_settlement_authority_cryptography_v1(
    authority: &PrivateSettlementCommitteeAuthorityV1,
) -> Result<(), PrivateSettlementValidationError> {
    authority.validate()?;
    if authority.validators.len() != PRIVATE_SETTLEMENT_COMMITTEE_VALIDATORS_V1
        || authority.validator_pops.len() != PRIVATE_SETTLEMENT_COMMITTEE_VALIDATORS_V1
        || authority
            .validators
            .iter()
            .zip(&authority.validator_pops)
            .any(|(validator, pop)| {
                validator.public_key().try_algorithm().ok() != Some(Algorithm::BlsNormal)
                    || pop.len() != PRIVATE_SETTLEMENT_BLS_BYTES_V1
                    || iroha_crypto::bls_normal_pop_verify(validator.public_key(), pop).is_err()
            })
    {
        return Err(PrivateSettlementValidationError::InvalidCommitteeAuthority);
    }
    Ok(())
}

/// Resolve one exact native incarnation at an authenticated Global anchor.
///
/// Callers establish the authenticity of `lanes`; deployment catalogs never grant authority.
/// # Errors
/// Missing, inactive, closed, universal, wrong-dataspace or substituted incarnation.
pub fn private_settlement_native_route_v1(
    lanes: &SumeragiLaneState,
    route: PrivateSettlementRouteV1,
    height: u64,
) -> Result<&SumeragiLaneRecord, PrivateSettlementValidationError> {
    lanes
        .lane(route.lane_id)
        .filter(|record| {
            height != 0
                && record.lane != iroha_model_base::topology::LaneId::SINGLE
                && record.dataspace == route.dataspace_id
                && record.admits_anchor(height)
                && Hash::from_marked_bytes(record.incarnation) == Some(route.lane_incarnation)
        })
        .ok_or(PrivateSettlementValidationError::InvalidCommitteeAuthority)
}

/// Compare the complete ordered roster and PoPs against one committed lane record.
///
/// Lifecycle of each Committee-role registry key must also be checked at the same height.
/// # Errors
/// Invalid roster cryptography, route or any ordered member/PoP substitution.
pub fn validate_private_settlement_committee_assignment_v1(
    lanes: &SumeragiLaneState,
    authority: &PrivateSettlementCommitteeAuthorityV1,
    height: u64,
) -> Result<(), PrivateSettlementValidationError> {
    validate_private_settlement_authority_cryptography_v1(authority)?;
    let record = private_settlement_native_route_v1(lanes, authority.route, height)?;
    if record.committee.len() != PRIVATE_SETTLEMENT_COMMITTEE_VALIDATORS_V1
        || record
            .committee
            .iter()
            .zip(&authority.validators)
            .zip(&authority.validator_pops)
            .any(|((member, validator), pop)| member.peer != *validator || member.pop != *pop)
    {
        return Err(PrivateSettlementValidationError::InvalidCommitteeAuthority);
    }
    Ok(())
}
