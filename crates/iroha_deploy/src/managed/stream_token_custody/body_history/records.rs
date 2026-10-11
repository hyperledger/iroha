//! Sole bounded outer enrollment selection and immutable unsigned body records.

use super::*;
use crate::localnet::service_authorities::RetainedProviderServicePlan;
use iroha_data_model::NetworkId;
use norito::{Decode, Encode};
use std::borrow::Borrow;

pub(super) const MAX_BODIES: u8 = 64;
pub(super) const MAX_SELECTION_BYTES: usize = 128 * 1024;
pub(super) const MAX_BODY_BYTES: usize = journal::MAX_ORIGINAL_BYTES + 128 * 1024;
pub(super) const MAX_ALL_BODY_BYTES: usize = 128 * 1024 * 1024;

/// Stable native purpose and predecessor. No dispatch UTC or active body is authority here.
#[derive(Clone, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::stream_token_custody::body_history::Selection")]
pub(super) struct Selection {
    pub network: NetworkId,
    pub genesis: [u8; 32],
    pub profile: [u8; 32],
    pub purpose: Purpose,
    pub predecessor: StreamTokenCustodySelection,
    pub fees: Fees,
    pub provider_from: u64,
    pub provider_until: u64,
}
impl Selection {
    pub(super) fn new(
        owner: &ManagedStreamTokenCustody,
        purpose: CustodyPurpose,
        unsigned: &UnsignedEnrollment,
        fees: &Fees,
    ) -> Result<Self> {
        let plan = owner.authority.provider_plan()?;
        unsigned.validate(owner, purpose, || Ok(&plan))?;
        fees.validate()?;
        let material = plan.admission_material();
        let value = Self {
            network: owner.authority.config.network_id,
            genesis: *owner.authority.genesis.genesis.hash().as_ref(),
            profile: *plan.original_profile_commitment().as_ref(),
            purpose: dispatch_purpose(purpose, owner.authority.provider_id()?)?,
            predecessor: unsigned.selection.clone(),
            fees: fees.clone(),
            provider_from: material
                .issued_at
                .checked_mul(1000)
                .ok_or_else(|| invalid("provider interval overflow"))?,
            provider_until: material
                .retention_epoch
                .checked_mul(1000)
                .ok_or_else(|| invalid("provider interval overflow"))?,
        };
        encode(&value, MAX_SELECTION_BYTES)?;
        Ok(value)
    }
    pub(super) fn validate(
        &self,
        owner: &ManagedStreamTokenCustody,
        purpose: CustodyPurpose,
        plan: &RetainedProviderServicePlan,
    ) -> Result<()> {
        encode(self, MAX_SELECTION_BYTES)?;
        self.fees.validate()?;
        let material = plan.admission_material();
        if self.network != owner.authority.config.network_id
            || self.genesis != *owner.authority.genesis.genesis.hash().as_ref()
            || self.profile != *plan.original_profile_commitment().as_ref()
            || self.purpose != dispatch_purpose(purpose, owner.authority.provider_id()?)?
            || self.predecessor.provider_id != owner.authority.provider_id()?
            || self.provider_from
                != material
                    .issued_at
                    .checked_mul(1000)
                    .ok_or_else(|| invalid("provider interval overflow"))?
            || self.provider_until
                != material
                    .retention_epoch
                    .checked_mul(1000)
                    .ok_or_else(|| invalid("provider interval overflow"))?
        {
            return Err(invalid(
                "enrollment operation changed its original profile or purpose",
            ));
        }
        let control = control(&self.predecessor)?;
        owner.validate_policy(&control.policy)?;
        if control.policy.binding != self.predecessor.binding
            || control.signer_revoked
            || control.attester_revoked
            || self
                .predecessor
                .current
                .as_ref()
                .is_none_or(|record| record.revision != self.predecessor.expected_revision)
            || self
                .predecessor
                .current
                .as_ref()
                .ok_or_else(|| invalid("enrollment predecessor absent"))?
                .canonical_digest()
                .map_err(|_| invalid("invalid enrollment predecessor"))?
                != self.predecessor.expected_digest
            || control.next_sequence != sequence(purpose)?
        {
            return Err(invalid(
                "enrollment operation changed its full native predecessor",
            ));
        }
        Ok(())
    }
    pub(super) fn matches_unsigned(&self, unsigned: &UnsignedEnrollment) -> Result<()> {
        if encode(&self.predecessor, 64 * 1024)? != encode(&unsigned.selection, 64 * 1024)? {
            return Err(ManagedBootstrapFailure::EnrollmentPredecessorChanged.into());
        }
        if unsigned.statement.issued_at_unix_ms < self.provider_from
            || unsigned.statement.expires_at_unix_ms > self.provider_until
        {
            return Err(invalid(
                "enrollment body exceeds original provider interval",
            ));
        }
        Ok(())
    }
    pub(super) fn digest(&self) -> Result<[u8; 32]> {
        attempts::semantic_digest(self, MAX_SELECTION_BYTES)
    }
}

/// The exact statement and native evidence are retained before the sole attester is opened.
#[derive(Clone, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_deploy::managed::stream_token_custody::body_history::UnsignedEnrollment"
)]
pub(in crate::managed::stream_token_custody) struct UnsignedEnrollment {
    pub selection: StreamTokenCustodySelection,
    pub statement: SignerCustodyStatementV1,
    pub selected_at_unix_ms: u64,
    pub checkpoint: Vec<u8>,
}
impl UnsignedEnrollment {
    pub(in crate::managed::stream_token_custody) fn validate_with_imports<
        P: Borrow<RetainedProviderServicePlan>,
    >(
        &self,
        owner: &ManagedStreamTokenCustody,
        purpose: CustodyPurpose,
        provider_plan: impl FnOnce() -> Result<P>,
        imports: &mut crate::managed::service_authority::CheckpointImports<'_, '_>,
    ) -> Result<()> {
        self.validate_using(owner, purpose, provider_plan, || {
            imports.decode(&self.checkpoint)
        })
    }

    pub(in crate::managed::stream_token_custody) fn validate<
        P: Borrow<RetainedProviderServicePlan>,
    >(
        &self,
        owner: &ManagedStreamTokenCustody,
        purpose: CustodyPurpose,
        provider_plan: impl FnOnce() -> Result<P>,
    ) -> Result<()> {
        self.validate_using(owner, purpose, provider_plan, || {
            owner.authority.decode_checkpoint(&self.checkpoint)
        })
    }
    pub(in crate::managed::stream_token_custody) fn validate_with_checkpoint<
        P: Borrow<RetainedProviderServicePlan>,
    >(
        &self,
        owner: &ManagedStreamTokenCustody,
        purpose: CustodyPurpose,
        verifier: &FinalityVerifier,
        provider_plan: impl FnOnce() -> Result<P>,
    ) -> Result<()> {
        self.validate_using(owner, purpose, provider_plan, || {
            self.matching_checkpoint(owner, verifier)
        })
    }
    // The caller retains a canonically authenticated verifier. Reuse is bound to this entire
    // immutable frame and the original authority, not merely a height, hash or parsed shape.
    pub(in crate::managed::stream_token_custody) fn matching_checkpoint<'a>(
        &self,
        owner: &ManagedStreamTokenCustody,
        verifier: &'a FinalityVerifier,
    ) -> Result<&'a FinalityVerifier> {
        if checkpoint_bytes(verifier)? != self.checkpoint
            || verifier.checkpoint().network_id() != owner.authority.config.network_id
            || verifier.checkpoint().chain_id() != owner.authority.config.chain.as_str()
        {
            return Err(invalid(
                "unsigned enrollment differs from retained checkpoint",
            ));
        }
        Ok(verifier)
    }
    fn validate_using<P: Borrow<RetainedProviderServicePlan>, V: Borrow<FinalityVerifier>>(
        &self,
        owner: &ManagedStreamTokenCustody,
        purpose: CustodyPurpose,
        provider_plan: impl FnOnce() -> Result<P>,
        checkpoint: impl FnOnce() -> Result<V>,
    ) -> Result<()> {
        encode(self, MAX_BODY_BYTES)?;
        if self.checkpoint.is_empty() || self.checkpoint.len() > MAX_CHECKPOINT_BYTES {
            return Err(invalid("unsigned enrollment checkpoint exceeds bound"));
        }
        let verifier = checkpoint()?;
        Self::validate_checkpoint_scope(owner, verifier.borrow())?;
        self.validate_selection_against_checkpoint(owner, purpose, provider_plan, verifier.borrow())
    }

    // Cold checkpoint authentication finishes before statement validation owns its working values.
    #[inline(never)]
    fn validate_checkpoint_scope(
        owner: &ManagedStreamTokenCustody,
        verifier: &FinalityVerifier,
    ) -> Result<()> {
        verifier
            .verified_tip_ref()
            .map_err(|_| invalid("unsigned enrollment checkpoint invalid"))?
            .verify_global_scope(
                owner.authority.config.network_id,
                &owner.authority.config.chain.to_string(),
            )
            .map_err(|_| invalid("unsigned enrollment checkpoint changed Global scope"))
    }

    #[inline(never)]
    fn validate_selection_against_checkpoint<P: Borrow<RetainedProviderServicePlan>>(
        &self,
        owner: &ManagedStreamTokenCustody,
        purpose: CustodyPurpose,
        provider_plan: impl FnOnce() -> Result<P>,
        verifier: &FinalityVerifier,
    ) -> Result<()> {
        let governed = control(&self.selection)?;
        owner.validate_policy(&governed.policy)?;
        let record = self
            .selection
            .current
            .as_ref()
            .ok_or_else(|| invalid("unsigned enrollment predecessor absent"))?;
        self.statement
            .signing_payload()
            .map_err(|_| invalid("unsigned enrollment statement invalid"))?;
        if self.selection.provider_id != owner.authority.provider_id()?
            || self.selection.binding != governed.policy.binding
            || self.selection.expected_revision != record.revision
            || self.selection.expected_digest
                != record
                    .canonical_digest()
                    .map_err(|_| invalid("unsigned enrollment predecessor digest invalid"))?
            || self.statement.binding != self.selection.binding
            || self.statement.authority != governed.policy.attester_authority
            || self.statement.anchor.state_digest != self.selection.expected_digest
            || self.statement.anchor.height != verifier.checkpoint().height()
            || self.statement.anchor.block_hash
                != *verifier.checkpoint().tip().block_header.hash().as_ref()
            || self.statement.sequence != sequence(purpose)?
            || self.statement.sequence != governed.next_sequence
            || self.statement.predecessor_digest != governed.predecessor_digest
            || self.statement.evidence_digest
                != owner.evidence_digest(&governed.policy, &self.selection, &self.checkpoint)?
            || governed.signer_revoked
            || governed.attester_revoked
            || self.selected_at_unix_ms == 0
            || self.statement.issued_at_unix_ms > self.selected_at_unix_ms
            || self.statement.expires_at_unix_ms <= self.selected_at_unix_ms
            || self.statement.issued_at_unix_ms < governed.policy.active_from_unix_ms
            || self.statement.expires_at_unix_ms > governed.policy.active_until_unix_ms
            || self.statement.expires_at_unix_ms - self.statement.issued_at_unix_ms
                > governed.policy.max_validity_ms
        {
            return Err(invalid(
                "unsigned enrollment differs from its exact native selection",
            ));
        }
        match purpose {
            CustodyPurpose::InitialEnroll
                if record.revision != 1
                    || governed.active_head.is_some()
                    || record.active_enrollment.is_some() =>
            {
                return Err(invalid(
                    "initial unsigned enrollment changed configured predecessor",
                ));
            }
            CustodyPurpose::Renewal(next) => {
                let expected = renewal::validate_renewal_validity(
                    record,
                    &governed,
                    next,
                    self.selected_at_unix_ms,
                    provider_plan,
                )?;
                if expected.issued_at_unix_ms != self.statement.issued_at_unix_ms
                    || expected.expires_at_unix_ms != self.statement.expires_at_unix_ms
                {
                    return Err(invalid(
                        "unsigned renewal changed its selected finite interval",
                    ));
                }
            }
            CustodyPurpose::Configure => {
                return Err(invalid("Configure cannot select an enrollment body"));
            }
            _ => {}
        }
        Ok(())
    }
    pub(in crate::managed::stream_token_custody) fn matches_original(
        &self,
        original: &Original,
    ) -> Result<()> {
        let Action::Enroll {
            anchor,
            selected_at_unix_ms,
            validity,
            enrollment,
        } = &original.action
        else {
            return Err(invalid("enrollment body has another purpose"));
        };
        let record = enrollment::decode_enrollment(enrollment)?;
        if encode(&original.selection, 64 * 1024)? != encode(&self.selection, 64 * 1024)?
            || original.checkpoint != self.checkpoint
            || record.statement != self.statement
            || *anchor != self.statement.anchor
            || *selected_at_unix_ms != self.selected_at_unix_ms
            || validity.issued_at_unix_ms != self.statement.issued_at_unix_ms
            || validity.expires_at_unix_ms != self.statement.expires_at_unix_ms
        {
            return Err(invalid(
                "signed enrollment differs from its retained unsigned selection",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::stream_token_custody::body_history::Reservation")]
pub(super) struct Reservation {
    pub ordinal: u8,
    pub outer: [u8; 32],
    pub previous_body: Option<[u8; 32]>,
    pub previous_semantic: Option<[u8; 32]>,
    pub unsigned: UnsignedEnrollment,
}
impl Reservation {
    pub(super) fn digest(&self) -> Result<[u8; 32]> {
        attempts::semantic_digest(self, MAX_BODY_BYTES)
    }
}
#[derive(Clone, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::stream_token_custody::body_history::Anchor")]
pub(super) struct Anchor {
    pub outer: [u8; 32],
    pub highest: u8,
    pub active: Option<u8>,
    pub completed: Option<[u8; 32]>,
    pub pending: Option<Reservation>,
}
#[derive(Clone, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::stream_token_custody::body_history::Activation")]
pub(super) struct Activation {
    pub reservation: [u8; 32],
    pub preceding_retirement: Option<[u8; 32]>,
}
#[derive(Clone, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::stream_token_custody::body_history::UnusedClosure")]
pub(super) struct UnusedClosure {
    pub reservation: [u8; 32],
    pub successor: [u8; 32],
}
#[derive(Clone, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::stream_token_custody::body_history::Reference")]
pub(super) struct Reference {
    pub purpose: Purpose,
    pub outer: [u8; 32],
}

pub(super) fn sequence(purpose: CustodyPurpose) -> Result<u64> {
    match purpose {
        CustodyPurpose::InitialEnroll => Ok(1),
        CustodyPurpose::Renewal(value) => {
            renewal::directory_name(value)?;
            Ok(value)
        }
        CustodyPurpose::Configure => Err(invalid("Configure has no enrollment sequence")),
    }
}
pub(super) fn dispatch_purpose(
    purpose: CustodyPurpose,
    provider: iroha_data_model::sorafs::capacity::ProviderId,
) -> Result<Purpose> {
    Ok(match purpose {
        CustodyPurpose::InitialEnroll => Purpose::CustodyEnroll(provider),
        CustodyPurpose::Renewal(value) => {
            renewal::directory_name(value)?;
            Purpose::CustodyRenewal {
                provider,
                sequence: value,
            }
        }
        CustodyPurpose::Configure => return Err(invalid("Configure has no body history")),
    })
}
pub(super) fn control(
    selection: &StreamTokenCustodySelection,
) -> Result<sorafs_manifest::signer::custody_control::SignerCustodyControlStateV1> {
    let record = selection
        .current
        .as_ref()
        .ok_or_else(|| invalid("enrollment predecessor absent"))?;
    let value = norito::decode_canonical_with_limits(
        &record.control_state,
        norito::DecodeLimits::new(4096, 16 * 1024, 16 * 1024, 1024 * 1024, 32),
    )
    .map_err(|_| invalid("invalid original enrollment control"))?;
    Ok(value)
}

#[cfg(test)]
#[path = "records/borrowed_tip_tests.rs"]
mod borrowed_tip_tests;
