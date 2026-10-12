//! First-release privacy protocol governance and admission budgets.
//!
//! This module is deliberately independent of individual proof engines. It owns the
//! consensus-critical state-machine rules which every engine shares: one immutable activation
//! record per protocol version, explicit governed activation, fail-closed lifecycle transitions, and
//! transaction-atomic resource charging.
use crate::privacy_profiles::{
    CompiledPrivacyProfileValidationErrorV1, validate_compiled_privacy_activation_v1,
};
use iroha_data_model::{
    ValidationFail,
    isi::privacy::SubmitPrivacyProofV1,
    privacy::{
        PrivacyActivationValidationError, PrivacyConsensusLimitsV1,
        PrivacyConsensusLimitsValidationError, PrivacyLifecycleTransitionError,
        PrivacyProtocolActivationRecordV1, PrivacyProtocolIdV1, PrivacyProtocolLifecycleV1,
        PrivacyTransactionIntentDigestV1,
    },
    transaction::SignedTransaction,
};
use std::collections::{BTreeMap, btree_map::Entry};
use thiserror::Error;
const PRIVACY_SIGNED_SUBMISSION_HASH_DOMAIN_V1: &[u8] = b"iroha.privacy.signed-submission-hash.v1";
/// Hash the complete typed privacy submission authorized by the transaction signature.
///
/// Unlike the transaction-intent digest, this internal one-shot fingerprint includes the final
/// statement digests and proof bytes. It prevents a child contract, trigger, or VM overlay from
/// substituting another submission after admission has validated the signed direct instruction.
pub(crate) fn privacy_signed_submission_hash_v1(
    submission: &SubmitPrivacyProofV1,
) -> Result<iroha_crypto::Hash, norito::Error> {
    let encoded = norito::encode_canonical(submission)?;
    let encoded_len = u64::try_from(encoded.len())
        .expect("Norito output length always fits u64 on supported targets");
    let mut preimage = Vec::with_capacity(
        PRIVACY_SIGNED_SUBMISSION_HASH_DOMAIN_V1.len()
            + core::mem::size_of::<u64>()
            + encoded.len(),
    );
    preimage.extend_from_slice(PRIVACY_SIGNED_SUBMISSION_HASH_DOMAIN_V1);
    preimage.extend_from_slice(&encoded_len.to_le_bytes());
    preimage.extend_from_slice(&encoded);
    Ok(iroha_crypto::Hash::new(preimage))
}
/// Recompute and validate the optional privacy intent in one signed payload.
///
/// Ordinary transactions return `Ok(None)`. Any privacy-bearing payload must contain exactly one
/// direct typed submission, have both derived digests correct, and avoid every dynamic/opaque V1
/// path before this function returns its one-shot state binding.
pub(crate) fn signed_privacy_transaction_intent_binding_v1(
    transaction: &SignedTransaction,
) -> Result<Option<(PrivacyTransactionIntentDigestV1, iroha_crypto::Hash)>, ValidationFail> {
    let Some((digest, submission)) = transaction
        .privacy_transaction_intent_binding_if_present_v1()
        .map_err(|error| {
            ValidationFail::NotPermitted(format!(
                "privacy transaction-intent admission failed: {error}"
            ))
        })?
    else {
        return Ok(None);
    };
    let submission_hash = privacy_signed_submission_hash_v1(submission).map_err(|error| {
        ValidationFail::InternalError(format!(
            "failed to encode the signed privacy submission: {error}"
        ))
    })?;
    Ok(Some((digest, submission_hash)))
}
/// Closed first-release registry of governed privacy protocol activations.
///
/// A protocol identity can be registered exactly once. Its artifact bindings are immutable;
/// governance may only advance its lifecycle. A parameter or verifier change therefore requires a
/// new protocol identity in a new data model release instead of a compatibility alias.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivacyProtocolRegistryV1 {
    limits: PrivacyConsensusLimitsV1,
    records: BTreeMap<PrivacyProtocolIdV1, PrivacyProtocolActivationRecordV1>,
}
impl PrivacyProtocolRegistryV1 {
    /// Construct an empty registry with the chain-wide consensus limits.
    ///
    /// # Errors
    ///
    /// Returns an error if any limit is zero, inconsistent, or above a first-release hard ceiling.
    pub fn new(limits: PrivacyConsensusLimitsV1) -> Result<Self, PrivacyRegistryError> {
        limits
            .validate()
            .map_err(PrivacyRegistryError::InvalidConsensusLimits)?;
        Ok(Self {
            limits,
            records: BTreeMap::new(),
        })
    }
    /// Return the exact chain-wide privacy limits.
    #[must_use]
    pub const fn limits(&self) -> &PrivacyConsensusLimitsV1 {
        &self.limits
    }
    /// Return the registered record for `protocol_id`, if present.
    #[must_use]
    pub fn record(
        &self,
        protocol_id: PrivacyProtocolIdV1,
    ) -> Option<&PrivacyProtocolActivationRecordV1> {
        self.records.get(&protocol_id)
    }
    /// Return an active record at `current_height`.
    ///
    /// Activation requires an explicit governance transition. This accessor remains
    /// read-only so proof verification and height changes cannot activate a proposal.
    #[must_use]
    pub fn active_record(
        &self,
        protocol_id: PrivacyProtocolIdV1,
        current_height: u64,
    ) -> Option<&PrivacyProtocolActivationRecordV1> {
        let record = self.records.get(&protocol_id)?;
        let PrivacyProtocolLifecycleV1::Active(active) = record.lifecycle else {
            return None;
        };
        (current_height >= active.state_since_height).then_some(record)
    }
    /// Register one immutable proposal for explicit governed activation.
    ///
    /// Registration is accepted only in the proposed state at the exact current height.
    /// Governance may activate it in the same transaction; no block-count delay or
    /// automatic promotion applies. All activations share the registry's resource budget.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed records, duplicate protocol identities,
    /// historical/future proposal heights, or
    /// activation-specific limits that differ from the global limits.
    pub fn register(
        &mut self,
        record: PrivacyProtocolActivationRecordV1,
        current_height: u64,
    ) -> Result<(), PrivacyRegistryError> {
        validate_privacy_registration_v1(
            &self.limits,
            self.records.get(&record.protocol_id),
            &record,
            current_height,
        )?;
        match self.records.entry(record.protocol_id) {
            Entry::Vacant(entry) => {
                entry.insert(record);
                Ok(())
            }
            Entry::Occupied(_) => {
                unreachable!("the stateless duplicate check ran before entry insertion")
            }
        }
    }
    /// Apply an explicit fail-closed lifecycle transition.
    ///
    /// Validation uses the stored lifecycle without any height-driven promotion, so an invalid
    /// governance instruction has no partial effect. Successful transitions replace only the
    /// lifecycle; artifact bindings cannot be supplied here and therefore cannot be changed.
    ///
    /// # Errors
    ///
    /// Returns an error when the protocol is unknown, transition history is invalid, or the
    /// transition does not become effective at the current height.
    pub fn transition(
        &mut self,
        protocol_id: PrivacyProtocolIdV1,
        next: PrivacyProtocolLifecycleV1,
        current_height: u64,
    ) -> Result<(), PrivacyRegistryError> {
        let record = self
            .records
            .get_mut(&protocol_id)
            .ok_or(PrivacyRegistryError::NotRegistered { protocol_id })?;
        validate_privacy_lifecycle_transition_v1(record, next, current_height)?;
        record.lifecycle = next;
        Ok(())
    }
    /// Iterate over records in canonical protocol-discriminant order.
    pub fn iter(
        &self,
    ) -> impl ExactSizeIterator<Item = (&PrivacyProtocolIdV1, &PrivacyProtocolActivationRecordV1)>
    {
        self.records.iter()
    }
}
/// Validate a persisted activation registration without constructing an in-memory registry.
///
/// World-state handlers use this function before inserting a record into typed storage. Keeping the
/// rule here prevents persistence adapters from reimplementing consensus logic.
///
/// # Errors
///
/// Returns the same deterministic error as [`PrivacyProtocolRegistryV1::register`].
pub fn validate_privacy_registration_v1(
    chain_limits: &PrivacyConsensusLimitsV1,
    existing: Option<&PrivacyProtocolActivationRecordV1>,
    record: &PrivacyProtocolActivationRecordV1,
    current_height: u64,
) -> Result<(), PrivacyRegistryError> {
    chain_limits
        .validate()
        .map_err(PrivacyRegistryError::InvalidConsensusLimits)?;
    record
        .validate()
        .map_err(PrivacyRegistryError::InvalidActivation)?;
    if record.pending_protocol_limits_tightening.is_some() {
        return Err(PrivacyRegistryError::RegistrationHasPendingProtocolLimits);
    }
    validate_compiled_privacy_activation_v1(record)
        .map_err(PrivacyRegistryError::CompiledProfile)?;
    if existing.is_some() {
        return Err(PrivacyRegistryError::AlreadyRegistered {
            protocol_id: record.protocol_id,
        });
    }
    let PrivacyProtocolLifecycleV1::Proposed(proposed) = record.lifecycle else {
        return Err(PrivacyRegistryError::RegistrationMustBeProposed);
    };
    if proposed.proposed_at_height != current_height {
        return Err(PrivacyRegistryError::ProposalHeightMismatch {
            current_height,
            proposed_at_height: proposed.proposed_at_height,
        });
    }
    Ok(())
}
/// Validate a lifecycle transition against a persisted activation record.
///
/// Only the signed governance instruction advances the stored lifecycle. An initial
/// activation may share the proposal's block, and its effective height must be this block.
///
/// # Errors
///
/// Returns an error for a spoofed transition height or an invalid lifecycle edge/history.
pub fn validate_privacy_lifecycle_transition_v1(
    current: &PrivacyProtocolActivationRecordV1,
    next: PrivacyProtocolLifecycleV1,
    current_height: u64,
) -> Result<(), PrivacyRegistryError> {
    current
        .validate()
        .map_err(PrivacyRegistryError::InvalidActivation)?;
    let effective_height = lifecycle_effective_height(next);
    if effective_height != current_height {
        return Err(PrivacyRegistryError::TransitionHeightMismatch {
            current_height,
            transition_height: effective_height,
        });
    }
    current
        .lifecycle
        .validate_transition_to(&next)
        .map_err(PrivacyRegistryError::InvalidLifecycleTransition)?;
    if next.is_active() {
        let mut successor = *current;
        successor.lifecycle = next;
        validate_compiled_privacy_activation_v1(&successor)
            .map_err(PrivacyRegistryError::CompiledProfile)?;
    }
    Ok(())
}
fn lifecycle_effective_height(lifecycle: PrivacyProtocolLifecycleV1) -> u64 {
    match lifecycle {
        PrivacyProtocolLifecycleV1::Proposed(state) => state.proposed_at_height,
        PrivacyProtocolLifecycleV1::Active(state) => state.state_since_height,
        PrivacyProtocolLifecycleV1::Suspended(state) => state.state_since_height,
        PrivacyProtocolLifecycleV1::Retired(state) => state.state_since_height,
    }
}
impl Default for PrivacyProtocolRegistryV1 {
    fn default() -> Self {
        Self::new(PrivacyConsensusLimitsV1::taira_default())
            .expect("the compiled Taira privacy limits are valid")
    }
}
/// Failure applying a privacy registry governance operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum PrivacyRegistryError {
    /// The chain-wide consensus limits are invalid.
    #[error("invalid chain-wide privacy limits: {0}")]
    InvalidConsensusLimits(PrivacyConsensusLimitsValidationError),
    /// The proposed activation record is invalid.
    #[error("invalid privacy activation record: {0}")]
    InvalidActivation(PrivacyActivationValidationError),
    /// Governed artifacts or limits differ from the executable native profile.
    #[error("privacy activation does not match compiled native profile: {0}")]
    CompiledProfile(CompiledPrivacyProfileValidationErrorV1),
    /// A new activation cannot smuggle in an already-pending policy change.
    #[error("a newly registered privacy activation cannot contain pending protocol limits")]
    RegistrationHasPendingProtocolLimits,
    /// A newly registered record was not in the proposed state.
    #[error("a privacy activation must be registered in the proposed state")]
    RegistrationMustBeProposed,
    /// The proposal does not record the exact block that registered it.
    #[error(
        "privacy proposal height {proposed_at_height} differs from current height {current_height}"
    )]
    ProposalHeightMismatch {
        /// Current block height.
        current_height: u64,
        /// Height claimed in the proposal.
        proposed_at_height: u64,
    },
    /// A protocol identity already has an immutable record.
    #[error("privacy protocol {protocol_id:?} is already registered")]
    AlreadyRegistered {
        /// Duplicate protocol identity.
        protocol_id: PrivacyProtocolIdV1,
    },
    /// No record exists for the requested protocol identity.
    #[error("privacy protocol {protocol_id:?} is not registered")]
    NotRegistered {
        /// Missing protocol identity.
        protocol_id: PrivacyProtocolIdV1,
    },
    /// The explicit transition does not become effective in this block.
    #[error(
        "privacy transition height {transition_height} differs from current height {current_height}"
    )]
    TransitionHeightMismatch {
        /// Current block height.
        current_height: u64,
        /// Height claimed by the transition.
        transition_height: u64,
    },
    /// The requested lifecycle edge or immutable history is invalid.
    #[error("invalid privacy lifecycle transition: {0}")]
    InvalidLifecycleTransition(PrivacyLifecycleTransitionError),
}
/// Resource budget already committed by privacy actions in one block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivacyBlockBudgetV1 {
    limits: PrivacyConsensusLimitsV1,
    actions: u32,
    bytes: u64,
}
impl PrivacyBlockBudgetV1 {
    /// Construct an empty block budget.
    ///
    /// # Errors
    ///
    /// Returns an error when `limits` is not a valid first-release profile.
    pub fn new(limits: PrivacyConsensusLimitsV1) -> Result<Self, PrivacyBudgetError> {
        limits
            .validate()
            .map_err(PrivacyBudgetError::InvalidLimits)?;
        Ok(Self {
            limits,
            actions: 0,
            bytes: 0,
        })
    }
    /// Start a transaction-local budget.
    ///
    /// Charges remain local until [`PrivacyTransactionBudgetV1::commit`] is
    /// called.  Dropping the value rolls every reservation back.
    pub fn begin_transaction(&mut self) -> PrivacyTransactionBudgetV1<'_> {
        PrivacyTransactionBudgetV1 {
            block: self,
            actions: 0,
            bytes: 0,
        }
    }
    /// Number of committed privacy actions in this block.
    #[must_use]
    pub const fn actions(&self) -> u32 {
        self.actions
    }
    /// Number of committed canonical privacy bytes in this block.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }
    /// Exact chain-wide limits bound to this block budget.
    #[must_use]
    pub const fn limits(&self) -> &PrivacyConsensusLimitsV1 {
        &self.limits
    }
}
impl Default for PrivacyBlockBudgetV1 {
    fn default() -> Self {
        Self::new(PrivacyConsensusLimitsV1::taira_default())
            .expect("the compiled Taira privacy limits are valid")
    }
}
/// Transaction-local, rollback-safe privacy admission budget.
#[must_use = "dropping a privacy transaction budget rolls back its reservations"]
pub struct PrivacyTransactionBudgetV1<'block> {
    block: &'block mut PrivacyBlockBudgetV1,
    actions: u32,
    bytes: u64,
}
impl PrivacyTransactionBudgetV1<'_> {
    /// Reserve one canonically encoded privacy action.
    ///
    /// `action_index` must equal the number of privacy actions already
    /// reserved in this transaction.  This binds statement contexts to their
    /// exact ordering and rejects duplicate or skipped indexes.
    ///
    /// # Errors
    ///
    /// Returns an error without changing either transaction or block counters
    /// if any action, transaction, or block bound would be exceeded.
    pub fn reserve(
        &mut self,
        action_index: u32,
        encoded_action_bytes: u64,
    ) -> Result<(), PrivacyBudgetError> {
        if action_index != self.actions {
            return Err(PrivacyBudgetError::ActionIndexMismatch {
                expected: self.actions,
                actual: action_index,
            });
        }
        if encoded_action_bytes == 0 {
            return Err(PrivacyBudgetError::ZeroActionBytes);
        }
        if encoded_action_bytes > u64::from(self.block.limits.max_action_bytes) {
            return Err(PrivacyBudgetError::ActionTooLarge {
                bytes: encoded_action_bytes,
                max: self.block.limits.max_action_bytes,
            });
        }
        let next_tx_actions = self
            .actions
            .checked_add(1)
            .ok_or(PrivacyBudgetError::ArithmeticOverflow)?;
        if next_tx_actions > self.block.limits.max_actions_per_transaction {
            return Err(PrivacyBudgetError::TransactionActionsExceeded {
                actions: next_tx_actions,
                max: self.block.limits.max_actions_per_transaction,
            });
        }
        let next_block_actions = self
            .block
            .actions
            .checked_add(next_tx_actions)
            .ok_or(PrivacyBudgetError::ArithmeticOverflow)?;
        if next_block_actions > self.block.limits.max_actions_per_block {
            return Err(PrivacyBudgetError::BlockActionsExceeded {
                actions: next_block_actions,
                max: self.block.limits.max_actions_per_block,
            });
        }
        let next_tx_bytes = self
            .bytes
            .checked_add(encoded_action_bytes)
            .ok_or(PrivacyBudgetError::ArithmeticOverflow)?;
        if next_tx_bytes > u64::from(self.block.limits.max_privacy_bytes_per_transaction) {
            return Err(PrivacyBudgetError::TransactionBytesExceeded {
                bytes: next_tx_bytes,
                max: self.block.limits.max_privacy_bytes_per_transaction,
            });
        }
        let next_block_bytes = self
            .block
            .bytes
            .checked_add(next_tx_bytes)
            .ok_or(PrivacyBudgetError::ArithmeticOverflow)?;
        if next_block_bytes > u64::from(self.block.limits.max_privacy_bytes_per_block) {
            return Err(PrivacyBudgetError::BlockBytesExceeded {
                bytes: next_block_bytes,
                max: self.block.limits.max_privacy_bytes_per_block,
            });
        }
        self.actions = next_tx_actions;
        self.bytes = next_tx_bytes;
        Ok(())
    }
    /// Commit every transaction-local reservation into the block budget.
    ///
    /// The method consumes the transaction budget, so a successful reservation
    /// set cannot be committed twice.
    pub fn commit(self) {
        self.block.actions = self
            .block
            .actions
            .checked_add(self.actions)
            .expect("reserve prevalidated the block action count");
        self.block.bytes = self
            .block
            .bytes
            .checked_add(self.bytes)
            .expect("reserve prevalidated the block byte count");
    }
    /// Number of locally reserved privacy actions.
    #[must_use]
    pub const fn actions(&self) -> u32 {
        self.actions
    }
    /// Number of locally reserved canonical privacy bytes.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }
}
/// Failure reserving privacy resources.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum PrivacyBudgetError {
    /// The supplied consensus limits are invalid.
    #[error("invalid privacy budget limits: {0}")]
    InvalidLimits(PrivacyConsensusLimitsValidationError),
    /// Action indexes must be contiguous and begin at zero.
    #[error("privacy action index {actual} differs from expected index {expected}")]
    ActionIndexMismatch {
        /// Required next index.
        expected: u32,
        /// Supplied index.
        actual: u32,
    },
    /// A canonical encoded action cannot be empty.
    #[error("privacy action byte length must be non-zero")]
    ZeroActionBytes,
    /// One encoded action exceeds its hard bound.
    #[error("privacy action uses {bytes} bytes, exceeding maximum {max}")]
    ActionTooLarge {
        /// Supplied canonical byte count.
        bytes: u64,
        /// Maximum bytes in one action.
        max: u32,
    },
    /// The transaction contains too many privacy actions.
    #[error("privacy transaction has {actions} actions, exceeding maximum {max}")]
    TransactionActionsExceeded {
        /// Resulting transaction action count.
        actions: u32,
        /// Maximum transaction action count.
        max: u32,
    },
    /// The block contains too many privacy actions.
    #[error("privacy block has {actions} actions, exceeding maximum {max}")]
    BlockActionsExceeded {
        /// Resulting block action count.
        actions: u32,
        /// Maximum block action count.
        max: u32,
    },
    /// Canonical privacy bytes exceed the transaction budget.
    #[error("privacy transaction uses {bytes} bytes, exceeding maximum {max}")]
    TransactionBytesExceeded {
        /// Resulting transaction byte count.
        bytes: u64,
        /// Maximum transaction byte count.
        max: u32,
    },
    /// Canonical privacy bytes exceed the block budget.
    #[error("privacy block uses {bytes} bytes, exceeding maximum {max}")]
    BlockBytesExceeded {
        /// Resulting block byte count.
        bytes: u64,
        /// Maximum block byte count.
        max: u32,
    },
    /// A counter addition overflowed.
    #[error("privacy budget arithmetic overflow")]
    ArithmeticOverflow,
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_profiles::{CompiledPrivacyProfileErrorV1, compiled_privacy_profile_v1};
    use iroha_data_model::privacy::{
        PrivacyActiveLifecycleV1, PrivacyProofSystemIdV1, PrivacyProposedLifecycleV1,
        PrivacyRetiredLifecycleV1, PrivacySuspendedLifecycleV1,
    };
    const PROPOSAL_HEIGHT: u64 = 1_000;
    const ACTIVATION_HEIGHT: u64 = PROPOSAL_HEIGHT;
    #[test]
    fn signed_submission_hash_ignores_ambient_layout_flags_and_binds_proof_bytes() {
        for sample in iroha_data_model::privacy::privacy_action_role_samples_v1()
            .expect("all canonical privacy roles")
        {
            let mut submission = SubmitPrivacyProofV1::new(sample.envelope);
            let expected = privacy_signed_submission_hash_v1(&submission).expect("canonical hash");
            let alternate_flags =
                norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
            let _layout = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            assert_eq!(
                privacy_signed_submission_hash_v1(&submission).unwrap(),
                expected
            );
            submission.envelope.proof.bytes_mut().bytes.push(0xA5);
            assert_ne!(
                privacy_signed_submission_hash_v1(&submission).unwrap(),
                expected
            );
        }
    }
    fn proposal() -> PrivacyProtocolActivationRecordV1 {
        compiled_privacy_profile_v1(PrivacyProtocolIdV1::VeRangeTransparentRangeV1)
            .expect("compiled VeRange profile")
            .activation_record(PrivacyProtocolLifecycleV1::Proposed(
                PrivacyProposedLifecycleV1 {
                    proposed_at_height: PROPOSAL_HEIGHT,
                },
            ))
    }
    #[test]
    fn proposal_requires_explicit_activation_even_after_height_advances() {
        let mut registry = PrivacyProtocolRegistryV1::default();
        let proposal = proposal();
        let protocol_id = proposal.protocol_id;
        registry
            .register(proposal, PROPOSAL_HEIGHT)
            .expect("valid proposal");
        for height in [PROPOSAL_HEIGHT, PROPOSAL_HEIGHT + 300, u64::MAX] {
            assert!(registry.active_record(protocol_id, height).is_none());
            assert_eq!(registry.record(protocol_id), Some(&proposal));
        }
        let active = PrivacyProtocolLifecycleV1::Active(PrivacyActiveLifecycleV1 {
            proposed_at_height: PROPOSAL_HEIGHT,
            activated_at_height: PROPOSAL_HEIGHT,
            state_since_height: PROPOSAL_HEIGHT,
        });
        registry
            .transition(protocol_id, active, PROPOSAL_HEIGHT)
            .expect("governance can activate in the registration block");
        assert_eq!(
            registry
                .active_record(protocol_id, PROPOSAL_HEIGHT)
                .expect("explicit activation is immediately effective")
                .lifecycle,
            active
        );
    }
    #[test]
    fn registration_rejects_historical_future_and_duplicate_records() {
        let mut registry = PrivacyProtocolRegistryV1::default();
        for height in [PROPOSAL_HEIGHT - 1, PROPOSAL_HEIGHT + 1] {
            let mut mismatched = proposal();
            mismatched.lifecycle =
                PrivacyProtocolLifecycleV1::Proposed(PrivacyProposedLifecycleV1 {
                    proposed_at_height: height,
                });
            assert!(matches!(
                registry.register(mismatched, PROPOSAL_HEIGHT),
                Err(PrivacyRegistryError::ProposalHeightMismatch { .. })
            ));
            assert_eq!(registry.iter().len(), 0);
        }
        registry
            .register(proposal(), PROPOSAL_HEIGHT)
            .expect("first registration");
        assert!(matches!(
            registry.register(proposal(), PROPOSAL_HEIGHT),
            Err(PrivacyRegistryError::AlreadyRegistered { .. })
        ));
    }
    #[test]
    fn registration_rejects_prepopulated_protocol_limit_schedule() {
        let limits = PrivacyConsensusLimitsV1::taira_default();
        let mut registry = PrivacyProtocolRegistryV1::new(limits).expect("valid limits");
        let mut mismatched = proposal();
        let mut next_limits = mismatched.protocol_limits;
        let iroha_data_model::privacy::PrivacyProtocolActivationLimitsV1::VeRangeTransparentRangeV1(
            ref mut next,
        ) = next_limits
        else {
            unreachable!("VeRange fixture")
        };
        next.max_aggregation_count -= 1;
        mismatched.pending_protocol_limits_tightening = Some(
            iroha_data_model::privacy::PrivacyProtocolLimitsTighteningV1 {
                scheduled_at_height: PROPOSAL_HEIGHT,
                effective_at_height: PROPOSAL_HEIGHT + 300,
                next_limits,
            },
        );
        assert_eq!(
            registry.register(mismatched, PROPOSAL_HEIGHT),
            Err(PrivacyRegistryError::RegistrationHasPendingProtocolLimits)
        );
    }
    #[test]
    fn registration_rejects_artifact_hash_substitution_without_mutation() {
        let mut registry = PrivacyProtocolRegistryV1::default();
        let mut substituted = proposal();
        substituted.verifier_digest.0[0] ^= 1;
        assert_eq!(
            registry.register(substituted, PROPOSAL_HEIGHT),
            Err(PrivacyRegistryError::CompiledProfile(
                CompiledPrivacyProfileValidationErrorV1::VerifierDigestMismatch
            ))
        );
        assert_eq!(registry.iter().len(), 0);
    }
    #[test]
    fn suspension_resume_and_retirement_are_forward_only() {
        let mut registry = PrivacyProtocolRegistryV1::default();
        let protocol_id = proposal().protocol_id;
        registry
            .register(proposal(), PROPOSAL_HEIGHT)
            .expect("valid proposal");
        registry
            .transition(
                protocol_id,
                PrivacyProtocolLifecycleV1::Active(PrivacyActiveLifecycleV1 {
                    proposed_at_height: PROPOSAL_HEIGHT,
                    activated_at_height: ACTIVATION_HEIGHT,
                    state_since_height: ACTIVATION_HEIGHT,
                }),
                ACTIVATION_HEIGHT,
            )
            .expect("explicit governed activation");
        let suspend_height = ACTIVATION_HEIGHT + 1;
        registry
            .transition(
                protocol_id,
                PrivacyProtocolLifecycleV1::Suspended(PrivacySuspendedLifecycleV1 {
                    proposed_at_height: PROPOSAL_HEIGHT,
                    activated_at_height: ACTIVATION_HEIGHT,
                    state_since_height: suspend_height,
                }),
                suspend_height,
            )
            .expect("active protocol can be suspended");
        assert!(
            registry
                .active_record(protocol_id, suspend_height)
                .is_none()
        );
        let resume_height = suspend_height + 1;
        registry
            .transition(
                protocol_id,
                PrivacyProtocolLifecycleV1::Active(PrivacyActiveLifecycleV1 {
                    proposed_at_height: PROPOSAL_HEIGHT,
                    activated_at_height: ACTIVATION_HEIGHT,
                    state_since_height: resume_height,
                }),
                resume_height,
            )
            .expect("suspended protocol can resume");
        let retire_height = resume_height + 1;
        registry
            .transition(
                protocol_id,
                PrivacyProtocolLifecycleV1::Retired(PrivacyRetiredLifecycleV1 {
                    proposed_at_height: PROPOSAL_HEIGHT,
                    activated_at_height: Some(ACTIVATION_HEIGHT),
                    state_since_height: retire_height,
                }),
                retire_height,
            )
            .expect("active protocol can retire");
        assert!(registry.active_record(protocol_id, retire_height).is_none());
        assert!(matches!(
            registry.transition(
                protocol_id,
                PrivacyProtocolLifecycleV1::Active(PrivacyActiveLifecycleV1 {
                    proposed_at_height: PROPOSAL_HEIGHT,
                    activated_at_height: ACTIVATION_HEIGHT,
                    state_since_height: retire_height + 1,
                }),
                retire_height + 1,
            ),
            Err(PrivacyRegistryError::InvalidLifecycleTransition(
                PrivacyLifecycleTransitionError::RetiredIsTerminal
            ))
        ));
    }
    #[test]
    fn transition_height_must_equal_current_height() {
        let mut registry = PrivacyProtocolRegistryV1::default();
        let protocol_id = proposal().protocol_id;
        registry
            .register(proposal(), PROPOSAL_HEIGHT)
            .expect("valid proposal");
        registry
            .transition(
                protocol_id,
                PrivacyProtocolLifecycleV1::Active(PrivacyActiveLifecycleV1 {
                    proposed_at_height: PROPOSAL_HEIGHT,
                    activated_at_height: ACTIVATION_HEIGHT,
                    state_since_height: ACTIVATION_HEIGHT,
                }),
                ACTIVATION_HEIGHT,
            )
            .expect("explicit governed activation");
        let next_height = ACTIVATION_HEIGHT + 1;
        assert!(matches!(
            registry.transition(
                protocol_id,
                PrivacyProtocolLifecycleV1::Suspended(PrivacySuspendedLifecycleV1 {
                    proposed_at_height: PROPOSAL_HEIGHT,
                    activated_at_height: ACTIVATION_HEIGHT,
                    state_since_height: next_height + 1,
                },),
                next_height,
            ),
            Err(PrivacyRegistryError::TransitionHeightMismatch { .. })
        ));
    }
    #[test]
    fn unavailable_compiled_engine_has_no_candidate_activation_path() {
        assert_eq!(
            compiled_privacy_profile_v1(PrivacyProtocolIdV1::IrohaZkX509StarkP256V1),
            Err(CompiledPrivacyProfileErrorV1::EngineUnavailable {
                protocol_id: PrivacyProtocolIdV1::IrohaZkX509StarkP256V1,
            })
        );
    }
    #[test]
    fn rejected_transition_does_not_mutate_pending_proposal() {
        let mut registry = PrivacyProtocolRegistryV1::default();
        let proposal = proposal();
        let protocol_id = proposal.protocol_id;
        registry
            .register(proposal, PROPOSAL_HEIGHT)
            .expect("valid proposal");
        let before = *registry.record(protocol_id).expect("registered record");
        let invalid = PrivacyProtocolLifecycleV1::Retired(PrivacyRetiredLifecycleV1 {
            proposed_at_height: PROPOSAL_HEIGHT + 1,
            activated_at_height: None,
            state_since_height: ACTIVATION_HEIGHT + 1,
        });
        assert!(
            registry
                .transition(protocol_id, invalid, ACTIVATION_HEIGHT + 1)
                .is_err()
        );
        assert_eq!(
            *registry.record(protocol_id).expect("registered record"),
            before,
            "a rejected governance instruction must have no partial effect"
        );
    }
    #[test]
    fn dropped_transaction_budget_rolls_back_all_charges() {
        let mut block = PrivacyBlockBudgetV1::default();
        {
            let mut transaction = block.begin_transaction();
            transaction.reserve(0, 7).expect("valid reservation");
            assert_eq!(transaction.actions(), 1);
            assert_eq!(transaction.bytes(), 7);
        }
        assert_eq!(block.actions(), 0);
        assert_eq!(block.bytes(), 0);
    }
    #[test]
    fn privacy_block_counts_and_actual_aggregate_bytes_are_independent() {
        let limits = PrivacyConsensusLimitsV1::taira_default();
        let mut block = PrivacyBlockBudgetV1::new(limits).expect("valid limits");
        let first_bytes = u64::from(limits.max_action_bytes);
        let remaining = u64::from(limits.max_privacy_bytes_per_block) - first_bytes;
        assert!(remaining < first_bytes, "two maximal envelopes cannot fit");
        {
            let mut transaction = block.begin_transaction();
            transaction
                .reserve(0, first_bytes)
                .expect("maximum first action");
            transaction.commit();
        }
        {
            let mut transaction = block.begin_transaction();
            for bytes in [first_bytes, remaining + 1] {
                assert_eq!(
                    transaction.reserve(0, bytes),
                    Err(PrivacyBudgetError::BlockBytesExceeded {
                        bytes: first_bytes + bytes,
                        max: limits.max_privacy_bytes_per_block,
                    })
                );
                assert_eq!(transaction.actions(), 0);
                assert_eq!(transaction.bytes(), 0);
            }
            transaction
                .reserve(0, remaining)
                .expect("exact remaining aggregate bytes");
            transaction.commit();
        }
        assert_eq!(block.actions(), 2);
        assert_eq!(block.bytes(), u64::from(limits.max_privacy_bytes_per_block));
        let mut third = block.begin_transaction();
        assert!(matches!(
            third.reserve(0, 1),
            Err(PrivacyBudgetError::BlockActionsExceeded { .. })
        ));
        drop(third);
        assert_eq!(block.actions(), 2);
    }
    #[test]
    fn budget_rejects_index_skips_zero_length_and_oversize_without_mutation() {
        let limits = PrivacyConsensusLimitsV1::taira_default();
        let mut block = PrivacyBlockBudgetV1::new(limits).expect("valid limits");
        let mut transaction = block.begin_transaction();
        assert_eq!(
            transaction.reserve(1, 1),
            Err(PrivacyBudgetError::ActionIndexMismatch {
                expected: 0,
                actual: 1,
            })
        );
        assert_eq!(
            transaction.reserve(0, 0),
            Err(PrivacyBudgetError::ZeroActionBytes)
        );
        assert_eq!(
            transaction.reserve(0, u64::from(limits.max_action_bytes) + 1),
            Err(PrivacyBudgetError::ActionTooLarge {
                bytes: u64::from(limits.max_action_bytes) + 1,
                max: limits.max_action_bytes,
            })
        );
        assert_eq!(transaction.actions(), 0);
        assert_eq!(transaction.bytes(), 0);
    }
    #[test]
    fn one_transaction_cannot_smuggle_a_second_privacy_action() {
        let mut block = PrivacyBlockBudgetV1::default();
        let mut transaction = block.begin_transaction();
        transaction.reserve(0, 1).expect("first action");
        assert!(matches!(
            transaction.reserve(1, 1),
            Err(PrivacyBudgetError::TransactionActionsExceeded { .. })
        ));
        assert_eq!(transaction.actions(), 1);
        assert_eq!(transaction.bytes(), 1);
    }
    #[test]
    fn registration_and_activation_at_max_height_need_no_delay_arithmetic() {
        let mut registry = PrivacyProtocolRegistryV1::default();
        let mut proposal = proposal();
        proposal.lifecycle = PrivacyProtocolLifecycleV1::Proposed(PrivacyProposedLifecycleV1 {
            proposed_at_height: u64::MAX,
        });
        registry
            .register(proposal, u64::MAX)
            .expect("nonzero exact proposal height");
        let active = PrivacyProtocolLifecycleV1::Active(PrivacyActiveLifecycleV1 {
            proposed_at_height: u64::MAX,
            activated_at_height: u64::MAX,
            state_since_height: u64::MAX,
        });
        registry
            .transition(proposal.protocol_id, active, u64::MAX)
            .expect("same-block activation does not add an arbitrary delay");
        assert_eq!(
            registry
                .active_record(proposal.protocol_id, u64::MAX)
                .expect("active at exact committed height")
                .lifecycle,
            active
        );
    }
    #[test]
    fn protocol_mapping_is_not_caller_selectable() {
        let mut registry = PrivacyProtocolRegistryV1::default();
        let mut mismatched = proposal();
        mismatched.proof_system_id = PrivacyProofSystemIdV1::Halo2IpaPasta;
        assert!(matches!(
            registry.register(mismatched, PROPOSAL_HEIGHT),
            Err(PrivacyRegistryError::InvalidActivation(
                PrivacyActivationValidationError::ProofSystemMismatch { .. }
            ))
        ));
    }
}
