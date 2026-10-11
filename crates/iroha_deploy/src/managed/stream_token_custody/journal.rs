//! Immutable native custody bodies; dispatch clocks and paid authorization live in bounded attempts.

use super::*;
use crate::managed::native_operation::attempts::{
    self, History, HistoryScope, Observation, Purpose, Selected,
};
use norito::{Decode, Encode};
use sorafs_manifest::signer::{
    custody::{
        SignerCustodyAnchorV1, SignerCustodyEnrollmentContextV1,
        verify_signer_custody_enrollment_v1,
    },
    custody_control::SignerCustodyControlStateV1,
};

pub(super) const MAX_ORIGINAL_BYTES: usize = MAX_CHECKPOINT_BYTES + 128 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::stream_token_custody::EnrollmentValidity")]
pub(super) struct EnrollmentValidity {
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}
impl EnrollmentValidity {
    pub(super) fn from_interval(interval: ManagedCustodyEnrollmentInterval) -> Self {
        Self {
            issued_at_unix_ms: interval.issued_at_unix_ms,
            expires_at_unix_ms: interval.expires_at_unix_ms,
        }
    }
    pub(super) fn interval(self, deadline_unix_ms: u64) -> ManagedCustodyEnrollmentInterval {
        ManagedCustodyEnrollmentInterval {
            issued_at_unix_ms: self.issued_at_unix_ms,
            expires_at_unix_ms: self.expires_at_unix_ms,
            deadline_unix_ms,
        }
    }
}
#[derive(Clone, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::stream_token_custody::Action")]
pub(super) enum Action {
    Configure(SignerCustodyPolicyV1),
    Enroll {
        anchor: SignerCustodyAnchorV1,
        selected_at_unix_ms: u64,
        validity: EnrollmentValidity,
        enrollment: Vec<u8>,
    },
}
#[derive(Clone, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::stream_token_custody::Original")]
pub(super) struct Original {
    pub selection: StreamTokenCustodySelection,
    pub action: Action,
    pub checkpoint: Vec<u8>,
}
pub(super) enum Request {
    Configure(StreamTokenCustodyConfigureRequest),
    Enroll(StreamTokenCustodyEnrollRequest),
}
impl Request {
    pub(super) fn inspect(
        &self,
        account: &AccountService,
        path: &std::path::Path,
    ) -> Result<iroha_wallet::operations::VerifiedNativePreparation> {
        match self {
            Self::Configure(request) => {
                account.inspect_stream_token_custody_configure_preparation(path, request)
            }
            Self::Enroll(request) => {
                account.inspect_stream_token_custody_enroll_preparation(path, request)
            }
        }
        .map_err(|_| invalid("custody wallet preparation differs from original request"))
    }
    pub(super) fn retain(
        &self,
        account: &AccountService,
        path: &std::path::Path,
    ) -> Result<iroha_wallet::operations::VerifiedNativePreparation> {
        match self {
            Self::Configure(request) => {
                account.retain_stream_token_custody_configure_request(request, path)
            }
            Self::Enroll(request) => {
                account.retain_stream_token_custody_enroll_request(request, path)
            }
        }
        .map_err(|_| invalid("cannot retain exact unsigned custody request"))
    }
    pub(super) fn retire(
        &self,
        account: &AccountService,
        path: &std::path::Path,
    ) -> Result<iroha_wallet::operations::RetiredNativeRequest> {
        match self {
            Self::Configure(request) => {
                account.retire_stream_token_custody_configure_unprepared(path, request)
            }
            Self::Enroll(request) => {
                account.retire_stream_token_custody_enroll_unprepared(path, request)
            }
        }
        .map_err(|_| invalid("custody unsigned request could not retire"))
    }
}
impl Original {
    pub fn request(
        &self,
        terms: &Terms,
        observation: Observation,
        deadline: Instant,
    ) -> Result<Request> {
        Ok(match &self.action {
            Action::Configure(policy) => Request::Configure(StreamTokenCustodyConfigureRequest {
                selection: self.selection.clone(),
                policy: policy.clone(),
                deadline_unix_ms: terms.signing_deadline_unix_ms,
                options: terms.options(deadline),
            }),
            Action::Enroll {
                anchor,
                validity,
                enrollment,
                ..
            } => Request::Enroll(StreamTokenCustodyEnrollRequest {
                selection: self.selection.clone(),
                anchor: *anchor,
                anchor_observed_at_unix_ms: observation.enrollment_observed_at_unix_ms.ok_or_else(
                    || invalid("enrollment request has no retained native observation"),
                )?,
                issued_at_unix_ms: validity.issued_at_unix_ms,
                expires_at_unix_ms: validity.expires_at_unix_ms,
                enrollment: enrollment.clone(),
                deadline_unix_ms: terms.signing_deadline_unix_ms,
                options: terms.options(deadline),
            }),
        })
    }
    pub fn initial_observation(&self) -> Observation {
        Observation {
            enrollment_observed_at_unix_ms: match &self.action {
                Action::Configure(_) => None,
                Action::Enroll {
                    selected_at_unix_ms,
                    ..
                } => Some(*selected_at_unix_ms),
            },
        }
    }
    pub fn dispatch_purpose(&self) -> Result<Purpose> {
        let provider = self.selection.provider_id;
        match &self.action {
            Action::Configure(_) => Ok(Purpose::CustodyConfigure(provider)),
            Action::Enroll { enrollment, .. } => {
                let sequence = enrollment::decode_enrollment(enrollment)?
                    .statement
                    .sequence;
                if sequence == 1 {
                    Ok(Purpose::CustodyEnroll(provider))
                } else {
                    renewal::directory_name(sequence)?;
                    Ok(Purpose::CustodyRenewal { provider, sequence })
                }
            }
        }
    }
    pub fn digest(&self) -> Result<[u8; 32]> {
        attempts::semantic_digest(self, MAX_ORIGINAL_BYTES)
    }
    pub fn control(&self) -> Result<SignerCustodyControlStateV1> {
        let predecessor = self
            .selection
            .current
            .as_ref()
            .ok_or_else(|| invalid("original enrollment lacks its selected predecessor"))?;
        if predecessor.control_state.len() > 16 * 1024 {
            return Err(invalid("original custody control exceeds its bound"));
        }
        norito::decode_canonical_with_limits(
            &predecessor.control_state,
            norito::DecodeLimits::new(4096, 16 * 1024, 16 * 1024, 1024 * 1024, 32),
        )
        .map_err(|_| invalid("invalid original custody control"))
    }
    pub fn validate(&self) -> Result<()> {
        if self.checkpoint.is_empty()
            || self.checkpoint.len() > MAX_CHECKPOINT_BYTES
            || norito::canonical_frame_len(&self.selection)
                .map_err(|_| invalid("invalid custody selection"))?
                > 64 * 1024
        {
            return Err(invalid("original custody intent exceeds bound"));
        }
        match &self.action {
            Action::Configure(policy) => {
                encode(policy, 16 * 1024)?;
            }
            Action::Enroll {
                enrollment,
                validity,
                selected_at_unix_ms,
                anchor,
            } => {
                if enrollment.is_empty()
                    || enrollment.len() > 16 * 1024
                    || *selected_at_unix_ms == 0
                    || validity.issued_at_unix_ms == 0
                    || validity.issued_at_unix_ms > *selected_at_unix_ms
                    || validity.expires_at_unix_ms <= *selected_at_unix_ms
                    || validity.expires_at_unix_ms == u64::MAX
                {
                    return Err(invalid(
                        "original enrollment differs from immutable body validity",
                    ));
                }
                let control = self.control()?;
                let verified = verify_signer_custody_enrollment_v1(
                    enrollment,
                    &self.selection.binding,
                    &control.policy.custody_trust(),
                    &SignerCustodyEnrollmentContextV1 {
                        now_unix_ms: *selected_at_unix_ms,
                        anchor_observed_at_unix_ms: *selected_at_unix_ms,
                        current_anchor: *anchor,
                        next_sequence: control.next_sequence,
                        predecessor_digest: control.predecessor_digest,
                        signer_revoked: control.signer_revoked,
                        attester_revoked: control.attester_revoked,
                    },
                )
                .map_err(|_| {
                    invalid("enrollment exceeds its original governed custody authorization")
                })?;
                if verified.statement().issued_at_unix_ms != validity.issued_at_unix_ms
                    || verified.statement().expires_at_unix_ms != validity.expires_at_unix_ms
                {
                    return Err(invalid(
                        "enrollment statement differs from original requested interval",
                    ));
                }
            }
        }
        Ok(())
    }
    pub fn matches_configuration(&self, policy: &SignerCustodyPolicyV1) -> Result<()> {
        self.validate()?;
        if !matches!(&self.action, Action::Configure(saved) if saved == policy) {
            return Err(invalid("initial custody configuration cannot be replaced"));
        }
        Ok(())
    }
    pub fn matches_enrollment_policy(&self, policy: &SignerCustodyPolicyV1) -> Result<()> {
        self.validate()?;
        if !matches!(self.action, Action::Enroll { .. }) || self.control()?.policy != *policy {
            return Err(invalid(
                "initial custody enrollment policy cannot be replaced",
            ));
        }
        Ok(())
    }
}
impl Selected<Original> {
    pub fn request(&self, deadline: Instant) -> Result<Request> {
        Original::request(self, &self.terms, self.observation()?, deadline)
    }
    pub fn interval(&self) -> Result<ManagedCustodyEnrollmentInterval> {
        match self.action {
            Action::Enroll { validity, .. } => {
                Ok(validity.interval(self.terms.requested_deadline_unix_ms))
            }
            Action::Configure(_) => Err(invalid("configuration is not an enrollment interval")),
        }
    }
    pub fn matches_configuration(
        &self,
        policy: &SignerCustodyPolicyV1,
        utc: u64,
        options: &BoundedTransactionOptions,
    ) -> Result<()> {
        Original::matches_configuration(self, policy)?;
        self.terms.matches(utc, options)
    }
    pub fn matches_enrollment(
        &self,
        interval: ManagedCustodyEnrollmentInterval,
        options: &BoundedTransactionOptions,
    ) -> Result<()> {
        self.validate()?;
        if self.interval()? != interval {
            return Err(invalid("initial custody enrollment cannot be renewed"));
        }
        self.terms.matches(interval.deadline_unix_ms, options)
    }
    pub fn matches_selected_enrollment(
        &self,
        policy: &SignerCustodyPolicyV1,
        interval: ManagedCustodyEnrollmentInterval,
        options: &BoundedTransactionOptions,
    ) -> Result<()> {
        self.matches_enrollment_policy(policy)?;
        self.matches_enrollment(interval, options)
    }
}
pub(super) fn read_intent(directory: &PrivateDirectory) -> Result<Option<Original>> {
    let names = directory.entries(4)?;
    if names.iter().any(|name| {
        !["original.nrt", "dispatch.nrt", "attempts", "epochs"]
            .iter()
            .any(|allowed| name == *allowed)
    }) {
        return Err(invalid("custody intent contains unknown material"));
    }
    let Some(bytes) = read_optional(directory, "original.nrt", MAX_ORIGINAL_BYTES)? else {
        require_empty(directory)?;
        return Ok(None);
    };
    decode_original(&bytes).map(Some)
}
/// BodyHistory owns this directory census and anchored absence; the Original decoder is shared.
pub(super) fn read_body_intent(directory: &PrivateDirectory) -> Result<Option<Original>> {
    read_optional(directory, "original.nrt", MAX_ORIGINAL_BYTES)?
        .map(|bytes| decode_original(&bytes))
        .transpose()
}
fn decode_original(bytes: &[u8]) -> Result<Original> {
    let original: Original = norito::decode_canonical_with_limits(
        bytes,
        norito::DecodeLimits::new(
            MAX_CHECKPOINT_BYTES,
            MAX_ORIGINAL_BYTES,
            MAX_ORIGINAL_BYTES,
            96 * 1024 * 1024,
            40,
        ),
    )
    .map_err(|_| invalid("invalid bounded original custody intent"))?;
    original.validate()?;
    Ok(original)
}
pub(super) fn read_original(directory: &PrivateDirectory) -> Result<Option<Selected<Original>>> {
    let Some(intent) = read_intent(directory)? else {
        return Ok(None);
    };
    if !matches!(intent.action, Action::Configure(_)) {
        return Err(invalid(
            "enrollment must use its complete anchored body history",
        ));
    }
    let history = History::read(
        directory,
        intent.dispatch_purpose()?,
        intent.digest()?,
        &HistoryScope::FixedBody,
    )?;
    Selected::from_history(intent, history).map(Some)
}
pub(super) fn required_original(directory: &PrivateDirectory) -> Result<Selected<Original>> {
    read_original(directory)?.ok_or_else(|| invalid("original custody request is absent"))
}
pub(super) fn publish_intent(directory: &PrivateDirectory, original: &Original) -> Result<()> {
    if !matches!(original.action, Action::Configure(_)) {
        return Err(invalid(
            "enrollment publication requires its unsigned body reservation",
        ));
    }
    publish_body_intent(directory, original)
}
pub(super) fn publish_body_intent(directory: &PrivateDirectory, original: &Original) -> Result<()> {
    original.validate()?;
    let bytes = encode(original, MAX_ORIGINAL_BYTES)?;
    if let Some(retained) = read_optional(directory, "original.nrt", MAX_ORIGINAL_BYTES)? {
        if retained != bytes {
            return Err(invalid("original native custody body changed"));
        }
        return Ok(());
    }
    directory.write_atomic("original.nrt", &bytes, PublishMode::CreateNew)?;
    Ok(())
}
pub(super) fn explicit(
    directory: &PrivateDirectory,
    original: &Original,
    utc: u64,
    options: &BoundedTransactionOptions,
    account: &AccountService,
    scope: &HistoryScope,
) -> Result<()> {
    let purpose = original.dispatch_purpose()?;
    let history = History::read(directory, purpose, original.digest()?, scope)?;
    let terms = match history.retained_terms() {
        Some(terms) => {
            terms.matches(utc, options)?;
            terms.clone()
        }
        None => Terms::new(utc, options)?,
    };
    attempts::initial(
        history,
        terms,
        original.initial_observation(),
        options.deadline,
        |attempt| {
            original
                .request(attempt.terms(), attempt.observation()?, options.deadline)?
                .inspect(account, &attempt.wallet_path())
        },
        |attempt, observation, deadline| {
            original
                .request(attempt.terms(), observation, deadline)?
                .retain(account, &attempt.wallet_path())
        },
    )
}
