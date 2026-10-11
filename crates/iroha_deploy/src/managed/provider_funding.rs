//! Immutable automatic provider economics composed through the existing native child owners.
//!
//! The earlier policy and registration workflow must complete first. The selected current proof
//! authenticates those facts but supplies no first-created provenance. This private owner retains
//! amounts before paid work and never signs, quotes, submits or verifies a transaction itself.
//! Completion reports the original economic operations, never current funding or service Serving.

use super::{
    ManagedHistoricalReserveTopUp, ManagedHistoricalReserveTopUpApproval,
    ManagedInitialProviderCredit, ManagedInitialProviderCreditIntent,
    ManagedInitialProviderCreditProgress, ManagedProviderCapacity, ManagedProviderCapacityProgress,
    ManagedReserveTopUpApproval, ManagedReserveTopUpApprovalIntent,
    ManagedReserveTopUpApprovalProgress, ManagedReserveTopUpIntent, ManagedReserveTopUpProgress,
    ManagedReserveTopUpRequest, PreparedLocalnet, Result,
    native_operation::{
        Fees, MAX_CHECKPOINT_BYTES, ManagedTransactionFinality, checkpoint_bytes, encode, invalid,
        read_optional, require_deadline, require_empty,
    },
    provider_economics,
    service_authority::{CheckpointImportScope, ProviderPurpose, ServiceAuthority},
};
use super::{
    native_operation::attempts::Purpose, service_bootstrap::authorization::FundingAuthorization,
};
use crate::{
    localnet::service_authorities::RetainedProviderServicePlan, verify::finality::FinalityVerifier,
};
use iroha_data_model::{
    asset::AssetDefinitionId,
    sorafs::reserve::{ReserveAuthorityPolicyV1, account_proof::VerifiedReserveAccountStateV1},
};
use iroha_wallet::operations::OperationStatus;
use std::time::Instant;

#[path = "provider_funding/original.rs"]
mod original;
#[path = "provider_funding/stage.rs"]
mod stage;
use original::Original;
use stage::{SelectedStage, Stage};

/// The next original economic operation, without a claim of live eligibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FundingStep {
    Request,
    Approval,
    Credit,
    Capacity,
}
/// Reports are never accepted as authority by this owner. Every completed operation below came
/// directly from its original journal owner in this call, independently verified by that owner.
#[derive(Debug)]
pub(super) enum ProviderFundingProgress {
    Unprepared {
        step: FundingStep,
        status: OperationStatus,
    },
    Request(ManagedReserveTopUpProgress),
    Approval(ManagedReserveTopUpApprovalProgress),
    Credit(ManagedInitialProviderCreditProgress),
    Capacity(ManagedProviderCapacityProgress),
    Complete {
        request: Option<ManagedHistoricalReserveTopUp>,
        approval: Option<ManagedHistoricalReserveTopUpApproval>,
        credit: ManagedTransactionFinality,
        capacity: ManagedTransactionFinality,
    },
}
// Only genuine early Request/Approval reports can leave the first paired phase. Completion
// proceeds through borrowed history slots, without the impossible later-stage report payload.
enum RequestApprovalIncomplete {
    Unprepared(FundingStep),
    Request(ManagedReserveTopUpProgress),
    Approval(ManagedReserveTopUpApprovalProgress),
}
impl RequestApprovalIncomplete {
    #[inline(never)]
    fn into_progress(self) -> ProviderFundingProgress {
        match self {
            Self::Unprepared(step) => ProviderFundingProgress::Unprepared {
                step,
                status: OperationStatus::Absent,
            },
            Self::Request(report) => ProviderFundingProgress::Request(report),
            Self::Approval(report) => ProviderFundingProgress::Approval(report),
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Advance,
    Recover,
    Local,
}
// One phase borrows the same retained parent inputs. Every field is a reference or Copy scalar;
// this view owns no selected proof, current state, child authority or history graph.
#[derive(Clone, Copy)]
struct FundingPhase<'a, 'authorization> {
    directory: &'a iroha_fs::PrivateDirectory,
    original: &'a Original,
    provider: iroha_data_model::sorafs::capacity::ProviderId,
    deadline: Instant,
    mode: Mode,
    authorization: Option<&'a FundingAuthorization<'authorization>>,
}
/// Fixed generated-profile composition. No caller-supplied movement, amount or credit projection.
pub(super) struct ProviderFundingBootstrap {
    authority: ServiceAuthority,
}
impl ProviderFundingBootstrap {
    pub(super) fn open(
        prepared: &PreparedLocalnet,
        provider: iroha_data_model::sorafs::capacity::ProviderId,
    ) -> Result<Self> {
        let owner = Self {
            authority: ServiceAuthority::open_provider(
                prepared,
                provider,
                ProviderPurpose::ProviderFundingBootstrap,
            )?,
        };
        owner.plan()?;
        Ok(owner)
    }
    /// Admit the fixed funding purpose and its original plan from immutable parent intent.
    /// The native child lock and fresh plan postcondition remain independently required.
    pub(super) fn open_from_original(
        parent: &ServiceAuthority,
        provider: iroha_data_model::sorafs::capacity::ProviderId,
    ) -> Result<Self> {
        let owner = Self {
            authority: ServiceAuthority::open_provider_from_original(
                parent,
                provider,
                ProviderPurpose::ProviderFundingBootstrap,
            )?,
        };
        owner.plan()?;
        Ok(owner)
    }

    // The real standalone producer remains the test baseline for physical admission parity.
    #[cfg(test)]
    pub(super) fn open_existing(
        prepared: &PreparedLocalnet,
        provider: iroha_data_model::sorafs::capacity::ProviderId,
    ) -> Result<Option<Self>> {
        Self::from_existing_authority(ServiceAuthority::open_provider_existing(
            prepared,
            provider,
            ProviderPurpose::ProviderFundingBootstrap,
        )?)
    }

    /// Preserve the existing plan postcondition while borrowing the original read-only profile.
    /// Optional lexical import work supplies no source, transaction or current-state verdict.
    pub(super) fn open_existing_from_original(
        parent: &ServiceAuthority,
        provider: iroha_data_model::sorafs::capacity::ProviderId,
        scope: Option<&CheckpointImportScope>,
    ) -> Result<Option<Self>> {
        Self::from_existing_authority(ServiceAuthority::open_provider_existing_from_original(
            parent,
            provider,
            ProviderPurpose::ProviderFundingBootstrap,
            scope,
        )?)
    }

    fn from_existing_authority(authority: Option<ServiceAuthority>) -> Result<Option<Self>> {
        let Some(authority) = authority else {
            return Ok(None);
        };
        let owner = Self { authority };
        owner.plan()?;
        Ok(Some(owner))
    }
    pub(super) fn advance_selected(
        &mut self,
        policy: &ReserveAuthorityPolicyV1,
        authorization: &FundingAuthorization<'_>,
        deadline: Instant,
    ) -> Result<ProviderFundingProgress> {
        let deadline = authorization.validate(&self.authority, deadline)?;
        if policy != &authorization.policies().network.reserve {
            return Err(invalid(
                "funding policy differs from original startup authorization",
            ));
        }
        self.select_economics(policy, authorization.fees(), deadline)?;
        authorization.validate(&self.authority, deadline)?;
        self.run(deadline, Mode::Advance, Some(authorization))
    }
    // Retained economics are intent, never signing authority. This single selector preserves
    // pricing, movement identity, amounts and the original native checkpoint before any child.
    fn select_economics(
        &mut self,
        policy: &ReserveAuthorityPolicyV1,
        fees: &Fees,
        deadline: Instant,
    ) -> Result<()> {
        require_deadline(deadline)?;
        self.authority.validate_profile()?;
        self.validate_policy(policy)?;
        fees.validate()?;
        let plan = self.plan()?;
        let directory = self.authority.directory.ensure_child("funding")?;
        if let Some(original) = original::read(&directory, &plan)? {
            self.validate_original(&plan, &original)?;
            return original.matches(&plan, policy, fees);
        }
        require_empty(&directory)?;
        self.require_no_child_material()?;
        let (verifier, current) = self.observe(policy, deadline)?;
        let original = Original::select(&plan, policy, &current, &verifier, fees.clone())?;
        self.validate_original(&plan, &original)?;
        require_deadline(deadline)?;
        original::publish(&directory, &plan, &original)
    }
    pub(super) fn recover_selected_if_present(
        &mut self,
        policy: &ReserveAuthorityPolicyV1,
        fees: &Fees,
        deadline: Instant,
    ) -> Result<Option<ProviderFundingProgress>> {
        self.recover_selected(policy, fees, deadline, Mode::Recover)
    }
    pub(super) fn recover_local_selected_if_present(
        &mut self,
        policy: &ReserveAuthorityPolicyV1,
        fees: &Fees,
        deadline: Instant,
    ) -> Result<Option<ProviderFundingProgress>> {
        self.recover_selected(policy, fees, deadline, Mode::Local)
    }
    fn recover_selected(
        &mut self,
        policy: &ReserveAuthorityPolicyV1,
        fees: &Fees,
        deadline: Instant,
        mode: Mode,
    ) -> Result<Option<ProviderFundingProgress>> {
        require_deadline(deadline)?;
        self.authority.validate_profile()?;
        self.validate_policy(policy)?;
        let plan = self.plan()?;
        let Some(directory) = self.authority.directory.open_child_optional("funding")? else {
            self.require_no_child_material()?;
            return Ok(None);
        };
        let Some(original) = original::read(&directory, &plan)? else {
            self.require_no_child_material()?;
            return Ok(None);
        };
        self.validate_original(&plan, &original)?;
        original.matches(&plan, policy, fees)?;
        self.run(deadline, mode, None).map(Some)
    }
    fn run(
        &mut self,
        deadline: Instant,
        mode: Mode,
        authorization: Option<&FundingAuthorization<'_>>,
    ) -> Result<ProviderFundingProgress> {
        require_deadline(deadline)?;
        self.authority.validate_profile()?;
        let plan = self.plan()?;
        let directory = self.authority.directory.open_child("funding")?;
        let original = original::read(&directory, &plan)?
            .ok_or_else(|| invalid("original funding economics are absent"))?;
        self.validate_original(&plan, &original)?;
        let provider = self.authority.provider_id()?;
        if let Some(authorization) = authorization {
            authorization.validate(&self.authority, deadline)?;
            original.matches(&plan, &original.policy, authorization.fees())?;
        } else if mode == Mode::Advance {
            return Err(invalid("funding advance lacks live startup authorization"));
        }
        let mut request_history = None;
        let mut approval_history = None;
        let original_height = self
            .authority
            .decode_checkpoint(&original.checkpoint)?
            .checkpoint()
            .height();
        let mut minimum_height = original_height;
        if original.top_up().is_none() {
            self.require_empty_child(ProviderPurpose::ReserveTopUpRequest, "request")?;
            self.require_empty_child(ProviderPurpose::ReserveTopUpApproval, "approval")?;
            if directory
                .entries(3)?
                .iter()
                .any(|name| name == "approval-selection.nrt")
            {
                return Err(invalid("zero top-up has retained approval selection"));
            }
        }
        let phase = FundingPhase {
            directory: &directory,
            original: &original,
            provider,
            deadline,
            mode,
            authorization,
        };
        if let Some(incomplete) = self.run_request_approval(
            phase,
            &mut minimum_height,
            &mut request_history,
            &mut approval_history,
        )? {
            return Ok(incomplete.into_progress());
        }
        self.run_credit_capacity(
            phase,
            minimum_height,
            &mut request_history,
            &mut approval_history,
        )
    }
    // Request custody remains held through approval. The caller retains the original funding
    // owner and history slots; this phase cannot carry the later complete report on success.
    #[inline(never)]
    fn run_request_approval(
        &mut self,
        phase: FundingPhase<'_, '_>,
        minimum_height: &mut u64,
        request_history: &mut Option<ManagedHistoricalReserveTopUp>,
        approval_history: &mut Option<ManagedHistoricalReserveTopUpApproval>,
    ) -> Result<Option<RequestApprovalIncomplete>> {
        let FundingPhase {
            original,
            provider,
            deadline,
            mode,
            authorization,
            ..
        } = phase;
        if let Some(intent) = original.top_up() {
            let mut request = match (if mode == Mode::Advance {
                ManagedReserveTopUpRequest::open_existing_from_original(
                    &self.authority,
                    provider,
                    None,
                )
            } else {
                ManagedReserveTopUpRequest::open_existing_from_original(
                    &self.authority,
                    provider,
                    self.authority.checkpoint_import_scope(),
                )
            })? {
                Some(owner) => owner,
                None if mode == Mode::Advance => {
                    self.require_no_later_material(FundingStep::Request)?;
                    authorization
                        .ok_or_else(|| invalid("funding startup authorization absent"))?
                        .validate(&self.authority, deadline)?;
                    ManagedReserveTopUpRequest::open_from_original(&self.authority, provider)?
                }
                None => {
                    return self
                        .unprepared_step(FundingStep::Request)
                        .map(|step| Some(RequestApprovalIncomplete::Unprepared(step)));
                }
            };
            let mut result = recover_progress(if mode == Mode::Local {
                request.recover_local_selected_if_present(&intent, &original.fees, deadline)
            } else {
                request.recover_selected_if_present(&intent, &original.fees, deadline)
            })?;
            if result
                .as_ref()
                .is_none_or(|report| report.historical().is_none())
                && self.may_create(mode, authorization, original, deadline)?
            {
                self.require_no_later_material(FundingStep::Request)?;
                let child = authorization
                    .ok_or_else(|| invalid("funding authorization absent"))?
                    .child(Purpose::FundingRequest(provider))?;
                result = Some(request.advance_selected(&intent, &child, deadline)?);
            }
            let Some(result) = result else {
                return self
                    .unprepared_step(FundingStep::Request)
                    .map(|step| Some(RequestApprovalIncomplete::Unprepared(step)));
            };
            let Some(history) = result.historical().cloned() else {
                self.require_no_later_material(FundingStep::Request)?;
                return Ok(Some(RequestApprovalIncomplete::Request(result)));
            };
            self.validate_request(original, &history)?;
            *minimum_height = history.original().height;
            *request_history = Some(history.clone());
            return self.run_approval(phase, minimum_height, approval_history, &history);
        }
        Ok(None)
    }
    // Authenticate the approval selection before reserving its child-body scratch. The caller
    // keeps the original request owner and report through both non-inlined phases.
    #[inline(never)]
    fn run_approval(
        &mut self,
        phase: FundingPhase<'_, '_>,
        minimum_height: &mut u64,
        approval_history: &mut Option<ManagedHistoricalReserveTopUpApproval>,
        history: &ManagedHistoricalReserveTopUp,
    ) -> Result<Option<RequestApprovalIncomplete>> {
        let FundingPhase {
            directory,
            original,
            deadline,
            mode,
            authorization,
            ..
        } = phase;
        let approval_selection = match self.selected_stage(
            directory,
            Stage::Approval,
            original,
            *minimum_height,
            mode,
            authorization,
            deadline,
        )? {
            Some(value) => value,
            None => {
                return self
                    .unprepared_step(FundingStep::Approval)
                    .map(|step| Some(RequestApprovalIncomplete::Unprepared(step)));
            }
        };
        self.run_selected_approval(
            phase,
            minimum_height,
            approval_history,
            history,
            &approval_selection,
        )
    }
    // Only the selected child body owns approval scratch. The original request remains in
    // run_request_approval while the prefix authenticates its retained selection first.
    #[inline(never)]
    fn run_selected_approval(
        &mut self,
        phase: FundingPhase<'_, '_>,
        minimum_height: &mut u64,
        approval_history: &mut Option<ManagedHistoricalReserveTopUpApproval>,
        history: &ManagedHistoricalReserveTopUp,
        approval_selection: &SelectedStage,
    ) -> Result<Option<RequestApprovalIncomplete>> {
        let FundingPhase {
            original,
            provider,
            deadline,
            mode,
            authorization,
            ..
        } = phase;
        let intent = approval_selection.approval(original)?;
        let mut approval = match (if mode == Mode::Advance {
            ManagedReserveTopUpApproval::open_existing_from_original(
                &self.authority,
                provider,
                None,
            )
        } else {
            ManagedReserveTopUpApproval::open_existing_from_original(
                &self.authority,
                provider,
                self.authority.checkpoint_import_scope(),
            )
        })? {
            Some(owner) => owner,
            None if mode == Mode::Advance => {
                self.require_no_later_material(FundingStep::Approval)?;
                authorization
                    .ok_or_else(|| invalid("funding startup authorization absent"))?
                    .validate(&self.authority, deadline)?;
                ManagedReserveTopUpApproval::open_from_original(&self.authority, provider)?
            }
            None => {
                return self
                    .unprepared_step(FundingStep::Approval)
                    .map(|step| Some(RequestApprovalIncomplete::Unprepared(step)));
            }
        };
        let mut result = recover_progress(if mode == Mode::Local {
            approval.recover_local_selected_if_present(history, &intent, &original.fees, deadline)
        } else {
            approval.recover_selected_if_present(history, &intent, &original.fees, deadline)
        })?;
        if result
            .as_ref()
            .is_none_or(|report| report.historical().is_none())
            && self.may_create(mode, authorization, original, deadline)?
        {
            self.require_no_later_material(FundingStep::Approval)?;
            let child = authorization
                .ok_or_else(|| invalid("funding authorization absent"))?
                .child(Purpose::FundingApproval(provider))?;
            result = Some(approval.advance_selected(history, &intent, &child, deadline)?);
        }
        let Some(result) = result else {
            return self
                .unprepared_step(FundingStep::Approval)
                .map(|step| Some(RequestApprovalIncomplete::Unprepared(step)));
        };
        let Some(history) = result.historical().cloned() else {
            self.require_no_later_material(FundingStep::Approval)?;
            return Ok(Some(RequestApprovalIncomplete::Approval(result)));
        };
        if history.requested_provider_revision() != approval_selection.partition.revision
            || history.policy_digest()
                != original
                    .policy
                    .digest()
                    .map_err(|_| invalid("invalid original funding policy digest"))?
            || history.rationale() != intent.rationale
        {
            return Err(invalid(
                "funding approval differs from its exact retained selection",
            ));
        }
        *minimum_height = history.original().height;
        *approval_history = Some(history);
        Ok(None)
    }
    // Credit custody remains held through capacity. Original histories move only at the same
    // final Complete construction, after all child and exact predecessor checks have succeeded.
    #[inline(never)]
    fn run_credit_capacity(
        &mut self,
        phase: FundingPhase<'_, '_>,
        minimum_height: u64,
        request_history: &mut Option<ManagedHistoricalReserveTopUp>,
        approval_history: &mut Option<ManagedHistoricalReserveTopUpApproval>,
    ) -> Result<ProviderFundingProgress> {
        let FundingPhase {
            directory,
            original,
            provider,
            deadline,
            mode,
            authorization,
        } = phase;
        let credit_selection = match self.selected_stage(
            directory,
            Stage::Credit,
            original,
            minimum_height,
            mode,
            authorization,
            deadline,
        )? {
            Some(value) => value,
            None => return self.unprepared(FundingStep::Credit),
        };
        let intent = credit_selection.credit(original)?;
        let mut credit = match (if mode == Mode::Advance {
            ManagedInitialProviderCredit::open_existing_from_original(
                &self.authority,
                provider,
                None,
            )
        } else {
            ManagedInitialProviderCredit::open_existing_from_original(
                &self.authority,
                provider,
                self.authority.checkpoint_import_scope(),
            )
        })? {
            Some(owner) => owner,
            None if mode == Mode::Advance => {
                self.require_no_later_material(FundingStep::Credit)?;
                authorization
                    .ok_or_else(|| invalid("funding startup authorization absent"))?
                    .validate(&self.authority, deadline)?;
                ManagedInitialProviderCredit::open_from_original(&self.authority, provider)?
            }
            None => return self.unprepared(FundingStep::Credit),
        };
        let mut result = recover_progress(if mode == Mode::Local {
            credit.recover_local_selected_if_present(&intent, &original.fees, deadline)
        } else {
            credit.recover_selected_if_present(&intent, &original.fees, deadline)
        })?;
        if result
            .as_ref()
            .is_none_or(|report| report.finalized.is_none())
            && self.may_create(mode, authorization, original, deadline)?
        {
            self.require_no_later_material(FundingStep::Credit)?;
            let child = authorization
                .ok_or_else(|| invalid("funding authorization absent"))?
                .child(Purpose::FundingCredit(provider))?;
            result = Some(credit.advance_selected(&intent, &child, deadline)?);
        }
        let Some(result) = result else {
            return self.unprepared(FundingStep::Credit);
        };
        let Some(credit_finality) = result.finalized else {
            self.require_no_later_material(FundingStep::Credit)?;
            return Ok(ProviderFundingProgress::Credit(result));
        };
        if credit_finality.height <= minimum_height {
            return Err(invalid("funding credit carrier predates prerequisites"));
        }
        let mut capacity = match (if mode == Mode::Advance {
            ManagedProviderCapacity::open_existing_from_original(&self.authority, provider, None)
        } else {
            ManagedProviderCapacity::open_existing_from_original(
                &self.authority,
                provider,
                self.authority.checkpoint_import_scope(),
            )
        })? {
            Some(owner) => owner,
            None if mode == Mode::Advance => {
                self.require_no_later_material(FundingStep::Capacity)?;
                authorization
                    .ok_or_else(|| invalid("funding startup authorization absent"))?
                    .validate(&self.authority, deadline)?;
                ManagedProviderCapacity::open_from_original(&self.authority, provider)?
            }
            None => return self.unprepared(FundingStep::Capacity),
        };
        let mut result = recover_progress(if mode == Mode::Local {
            capacity.recover_local_selected_if_present(
                &original.policy,
                &credit_selection.partition,
                &intent.record,
                &original.fees,
                deadline,
            )
        } else {
            capacity.recover_selected_if_present(
                &original.policy,
                &credit_selection.partition,
                &intent.record,
                &original.fees,
                deadline,
            )
        })?;
        if result
            .as_ref()
            .is_none_or(|report| report.finalized.is_none())
            && self.may_create(mode, authorization, original, deadline)?
        {
            // The child binds this exact parent intent at its own authenticated read before
            // publishing or signing; an earlier parent read cannot authorize a later replacement.
            self.require_no_later_material(FundingStep::Capacity)?;
            let child = authorization
                .ok_or_else(|| invalid("funding authorization absent"))?
                .child(Purpose::FundingCapacity(provider))?;
            result = Some(capacity.advance_selected(
                &original.policy,
                &credit_selection.partition,
                &intent.record,
                credit_finality.height,
                &child,
                deadline,
            )?);
        }
        let Some(result) = result else {
            return self.unprepared(FundingStep::Capacity);
        };
        let Some(capacity_finality) = result.finalized else {
            return Ok(ProviderFundingProgress::Capacity(result));
        };
        if capacity_finality.height <= credit_finality.height {
            return Err(invalid("funding capacity carrier predates original credit"));
        }
        Ok(ProviderFundingProgress::Complete {
            request: request_history.take(),
            approval: approval_history.take(),
            credit: credit_finality,
            capacity: capacity_finality,
        })
    }
    fn selected_stage(
        &mut self,
        directory: &iroha_fs::PrivateDirectory,
        stage: Stage,
        original: &Original,
        minimum_height: u64,
        mode: Mode,
        authorization: Option<&FundingAuthorization<'_>>,
        deadline: Instant,
    ) -> Result<Option<SelectedStage>> {
        let selected = match stage::read(directory, stage, original)? {
            Some(selected) => selected,
            None => {
                let (step, purpose, child) = match stage {
                    Stage::Approval => (
                        FundingStep::Approval,
                        ProviderPurpose::ReserveTopUpApproval,
                        "approval",
                    ),
                    Stage::Credit => (
                        FundingStep::Credit,
                        ProviderPurpose::InitialProviderCredit,
                        "install",
                    ),
                };
                self.require_no_later_material(step)?;
                self.require_empty_child(purpose, child)?;
                if !self.may_create(mode, authorization, original, deadline)? {
                    return Ok(None);
                }
                let (verifier, current) = self.observe(&original.policy, deadline)?;
                let selected =
                    SelectedStage::select(stage, original, &current, &verifier, minimum_height)?;
                self.validate_stage(&selected, stage, original, minimum_height)?;
                authorization
                    .ok_or_else(|| invalid("funding authorization absent"))?
                    .validate(&self.authority, deadline)?;
                stage::publish(directory, stage, original, &selected)?;
                selected
            }
        };
        self.validate_stage(&selected, stage, original, minimum_height)?;
        Ok(Some(selected))
    }
    fn may_create(
        &self,
        mode: Mode,
        authorization: Option<&FundingAuthorization<'_>>,
        original: &Original,
        deadline: Instant,
    ) -> Result<bool> {
        if mode != Mode::Advance {
            return Ok(false);
        }
        let authorization = authorization
            .ok_or_else(|| invalid("funding advance lacks live startup authorization"))?;
        authorization.validate(&self.authority, deadline)?;
        if authorization.fees() != &original.fees {
            return Err(invalid("original funding fee authorization changed"));
        }
        Ok(true)
    }
    fn unprepared(&self, step: FundingStep) -> Result<ProviderFundingProgress> {
        let step = self.unprepared_step(step)?;
        Ok(ProviderFundingProgress::Unprepared {
            step,
            status: OperationStatus::Absent,
        })
    }
    fn unprepared_step(&self, step: FundingStep) -> Result<FundingStep> {
        self.require_no_later_material(step)?;
        Ok(step)
    }
    // Presence is only a refusal condition. This census does not decode a wallet or select
    // native state, and cannot turn retained files into transaction or finality authority.
    fn require_no_later_material(&self, step: FundingStep) -> Result<()> {
        let directory = self.authority.directory.open_child("funding")?;
        let names = directory.entries(3)?;
        if (step == FundingStep::Request
            && names.iter().any(|name| name == "approval-selection.nrt"))
            || (matches!(step, FundingStep::Request | FundingStep::Approval)
                && names.iter().any(|name| name == "credit-selection.nrt"))
        {
            return Err(invalid(
                "funding selection follows an incomplete original prerequisite",
            ));
        }
        let stages = [
            (
                FundingStep::Request,
                ProviderPurpose::ReserveTopUpRequest,
                "request",
            ),
            (
                FundingStep::Approval,
                ProviderPurpose::ReserveTopUpApproval,
                "approval",
            ),
            (
                FundingStep::Credit,
                ProviderPurpose::InitialProviderCredit,
                "install",
            ),
            (
                FundingStep::Capacity,
                ProviderPurpose::ProviderCapacityDeclaration,
                "declare",
            ),
        ];
        let position = stages
            .iter()
            .position(|(stage, _, _)| *stage == step)
            .expect("closed funding step");
        for (_, purpose, child) in stages.into_iter().skip(position + 1) {
            self.require_empty_child(purpose, child)?;
        }
        Ok(())
    }
    fn require_no_child_material(&self) -> Result<()> {
        for (purpose, child) in [
            (ProviderPurpose::ReserveTopUpRequest, "request"),
            (ProviderPurpose::ReserveTopUpApproval, "approval"),
            (ProviderPurpose::InitialProviderCredit, "install"),
            (ProviderPurpose::ProviderCapacityDeclaration, "declare"),
        ] {
            self.require_empty_child(purpose, child)?;
        }
        Ok(())
    }
    fn require_empty_child(&self, purpose: ProviderPurpose, child: &str) -> Result<()> {
        let Some(owner) = ServiceAuthority::open_provider_existing_from_original(
            &self.authority,
            self.authority.provider_id()?,
            purpose,
            None,
        )?
        else {
            return Ok(());
        };
        owner.validate_profile()?;
        if owner
            .directory
            .entries(2)?
            .iter()
            .any(|name| name != "operation.lock" && name != child)
        {
            return Err(invalid(
                "later funding purpose contains unknown retained material",
            ));
        }
        match owner.directory.open_child_optional(child)? {
            Some(directory) => require_empty(&directory),
            None => Ok(()),
        }
    }
    fn plan(&self) -> Result<RetainedProviderServicePlan> {
        self.authority.provider_plan()
    }
    fn validate_policy(&self, policy: &ReserveAuthorityPolicyV1) -> Result<()> {
        encode(policy, provider_economics::MAX_POLICY_BYTES)?;
        policy
            .validate()
            .map_err(|_| invalid("invalid selected funding policy"))?;
        let asset = AssetDefinitionId::parse_address_literal(
            crate::genesis::profile::TAIRA_XOR_ASSET_DEFINITION_ID,
        )
        .map_err(|_| invalid("invalid canonical generated funding asset"))?;
        if policy.asset_definition != asset
            || policy.custody_account != self.authority.manifest.network.reserve_accounts.custody
            || policy.treasury_account != self.authority.manifest.network.reserve_accounts.treasury
            || &policy.operations_authority
                != self
                    .authority
                    .network_role(crate::localnet::service_authorities::NetworkServiceAuthorityRole::ReserveOperations)?
            || policy.decision_authority != self.authority.config.account
        {
            return Err(invalid(
                "funding policy differs from original generated roles",
            ));
        }
        Ok(())
    }
    fn validate_original(
        &self,
        plan: &RetainedProviderServicePlan,
        original: &Original,
    ) -> Result<()> {
        original.validate(plan)?;
        self.validate_policy(&original.policy)?;
        let verifier = self.authority.decode_checkpoint(&original.checkpoint)?;
        let tip = verifier
            .verified_tip()
            .map_err(|_| invalid("invalid original funding checkpoint"))?;
        tip.verify_global_scope(
            self.authority.config.network_id,
            &self.authority.config.chain.to_string(),
        )
        .map_err(|_| invalid("original funding checkpoint is not selected Global root"))?;
        if tip.header().creation_time_ms != original.observed_block_time_ms {
            return Err(invalid(
                "original funding time differs from retained certified cut",
            ));
        }
        Ok(())
    }
    fn validate_stage(
        &self,
        selected: &SelectedStage,
        stage: Stage,
        original: &Original,
        minimum_height: u64,
    ) -> Result<()> {
        selected.validate(stage, original)?;
        let verifier = self.authority.decode_checkpoint(&selected.checkpoint)?;
        let tip = verifier
            .verified_tip()
            .map_err(|_| invalid("invalid funding child checkpoint"))?;
        tip.verify_global_scope(
            self.authority.config.network_id,
            &self.authority.config.chain.to_string(),
        )
        .map_err(|_| invalid("funding child checkpoint is not selected Global root"))?;
        if tip.height() < minimum_height {
            return Err(invalid(
                "funding child checkpoint predates original prerequisite",
            ));
        }
        Ok(())
    }
    fn validate_request(
        &self,
        original: &Original,
        history: &ManagedHistoricalReserveTopUp,
    ) -> Result<()> {
        if history.network_id() != original.network_id
            || history.provider_id() != original.partition.terms.provider_id
            || history.provider_account() != &original.partition.terms.provider_account
            || history.movement_id() != original.movement_id
            || history.amount() != &original.economics.top_up
            || history.requested_provider_revision() != original.partition.revision
            || history.policy_digest()
                != original
                    .policy
                    .digest()
                    .map_err(|_| invalid("invalid original funding digest"))?
            || history.original().height
                <= self
                    .authority
                    .decode_checkpoint(&original.checkpoint)?
                    .checkpoint()
                    .height()
        {
            return Err(invalid(
                "funding request differs from original economic intent",
            ));
        }
        Ok(())
    }
    fn observe(
        &mut self,
        policy: &ReserveAuthorityPolicyV1,
        deadline: Instant,
    ) -> Result<(FinalityVerifier, VerifiedReserveAccountStateV1)> {
        let verifier = self.authority.observe_finality(deadline)?;
        let current = self
            .authority
            .read_reserve_account(policy, &verifier, deadline)?;
        Ok((verifier, current))
    }
}

// A validated interrupted unsigned transition is incomplete. Only the live generated child
// capability can reconcile it. Every custody, fee, wallet and native-proof error stays fatal.
fn recover_progress<T>(result: Result<Option<T>>) -> Result<Option<T>> {
    match result {
        Err(super::Error::Bootstrap(super::ManagedBootstrapFailure::TransitionPending)) => Ok(None),
        other => other,
    }
}

#[cfg(test)]
#[path = "provider_funding/native_tests.rs"]
mod native_tests;
#[cfg(test)]
#[path = "provider_funding/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "provider_funding/bootstrap_test_support.rs"]
mod bootstrap_test_support;

#[cfg(test)]
#[path = "provider_funding/creating_original_tests.rs"]
mod creating_original_tests;

#[cfg(test)]
#[path = "provider_funding/absence_original_tests.rs"]
mod absence_original_tests;
