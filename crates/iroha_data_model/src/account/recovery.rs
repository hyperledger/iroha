//! Native account recovery policy and request types.
use super::{AccountController, AccountId, rekey::AccountAlias};
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};
use std::{collections::BTreeSet, num::NonZeroU64, vec::Vec};
use thiserror::Error;
/// Guardian that can participate in social recovery for an account alias.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(no_fast_from_json)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::account::recovery::RecoveryGuardian")]
pub struct RecoveryGuardian {
    /// Guardian account allowed to approve recovery.
    pub account: AccountId,
    /// Approval weight contributed by this guardian.
    pub weight: u16,
}
impl RecoveryGuardian {
    /// Construct a recovery guardian entry.
    #[must_use]
    pub fn new(account: AccountId, weight: u16) -> Self {
        Self { account, weight }
    }
}
/// Alias-keyed social recovery policy for an account.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(no_fast_from_json)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::account::recovery::AccountRecoveryPolicy")]
pub struct AccountRecoveryPolicy {
    /// Guardian set authorised to approve recovery.
    pub guardians: Vec<RecoveryGuardian>,
    /// Total guardian approval weight required to finalize recovery.
    pub quorum: u16,
    /// Delay before a quorum-approved recovery can be finalized.
    pub timelock_ms: NonZeroU64,
}
impl AccountRecoveryPolicy {
    /// Construct and validate a recovery policy.
    ///
    /// # Errors
    ///
    /// Returns [`AccountRecoveryPolicyError`] when the guardian set or quorum is invalid.
    pub fn new(
        guardians: Vec<RecoveryGuardian>,
        quorum: u16,
        timelock_ms: NonZeroU64,
    ) -> Result<Self, AccountRecoveryPolicyError> {
        if guardians.is_empty() {
            return Err(AccountRecoveryPolicyError::EmptyGuardians);
        }
        if quorum == 0 {
            return Err(AccountRecoveryPolicyError::ZeroQuorum);
        }
        let mut seen = BTreeSet::new();
        let mut total_weight = 0u32;
        for guardian in &guardians {
            if guardian.weight == 0 {
                return Err(AccountRecoveryPolicyError::GuardianWeightZero {
                    account: guardian.account.clone(),
                });
            }
            if !seen.insert(guardian.account.subject_id()) {
                return Err(AccountRecoveryPolicyError::DuplicateGuardian {
                    account: guardian.account.clone(),
                });
            }
            total_weight += u32::from(guardian.weight);
        }
        if u32::from(quorum) > total_weight {
            return Err(AccountRecoveryPolicyError::QuorumExceedsTotalWeight {
                quorum,
                total_weight,
            });
        }
        Ok(Self {
            guardians,
            quorum,
            timelock_ms,
        })
    }
    /// Borrow the guardian set.
    #[must_use]
    pub fn guardians(&self) -> &[RecoveryGuardian] {
        &self.guardians
    }
    /// Sum the configured guardian weights.
    #[must_use]
    pub fn total_weight(&self) -> u32 {
        self.guardians
            .iter()
            .map(|guardian| u32::from(guardian.weight))
            .sum()
    }
    /// Return the configured quorum as a plain integer.
    #[must_use]
    pub fn quorum(&self) -> u16 {
        self.quorum
    }
    /// Return the configured timelock.
    #[must_use]
    pub fn timelock_ms(&self) -> NonZeroU64 {
        self.timelock_ms
    }
    /// Compute the cumulative weight of a set of guardian approvals.
    #[must_use]
    pub fn approval_weight(&self, approvals: &BTreeSet<AccountId>) -> u32 {
        self.guardians
            .iter()
            .filter(|guardian| approvals.contains(&guardian.account.subject_id()))
            .map(|guardian| u32::from(guardian.weight))
            .sum()
    }
    /// Return `true` when the approval set satisfies the quorum.
    #[must_use]
    pub fn quorum_reached(&self, approvals: &BTreeSet<AccountId>) -> bool {
        self.approval_weight(approvals) >= u32::from(self.quorum)
    }
    /// Return `true` when the account is configured as a guardian.
    #[must_use]
    pub fn contains_guardian(&self, account: &AccountId) -> bool {
        let subject = account.subject_id();
        self.guardians
            .iter()
            .any(|guardian| guardian.account.subject_id() == subject)
    }
}
/// Lifecycle state of an account recovery request.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(tag = "status", content = "value", rename_all = "snake_case")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::account::recovery::AccountRecoveryStatus")]
pub enum AccountRecoveryStatus {
    /// Recovery request is active and can still be approved, cancelled, or finalized.
    Pending,
    /// Recovery request was cancelled before finalization.
    Cancelled,
    /// Recovery request has already finalized.
    Finalized,
}
/// Alias-keyed account recovery request tracked in world state.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(no_fast_from_json)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::account::recovery::AccountRecoveryRequest")]
pub struct AccountRecoveryRequest {
    /// Stable alias targeted by the recovery request.
    pub alias: AccountAlias,
    /// Monotonic alias-local request identity, retained after terminal outcomes.
    pub request_generation: NonZeroU64,
    /// Account active behind the alias when the request was proposed.
    pub active_account_id_at_proposal: AccountId,
    /// Controller that should replace the active controller once finalized.
    pub proposed_controller: AccountController,
    /// Guardian approvals collected so far.
    pub approvals: BTreeSet<AccountId>,
    /// Independent guardian cancellation votes, exclusive with replacement approvals.
    pub cancellation_approvals: BTreeSet<AccountId>,
    /// Native multisig proposals invalidated atomically by finalization.
    ///
    /// The native occurrence identity bytes are retained on the terminal request so clients can resolve corresponding
    /// `CANCELED` or already-`EXPIRED` evidence after the alias rekeys.
    pub invalidated_multisig_proposal_ids: Vec<[u8; 32]>,
    /// Account that proposed the recovery request.
    pub proposed_by: AccountId,
    /// Earliest block-time timestamp (unix ms) at which finalization is permitted.
    pub execute_after_ms: u64,
    /// Current lifecycle state of the request.
    pub status: AccountRecoveryStatus,
}
impl AccountRecoveryRequest {
    /// Construct a new pending recovery request.
    #[must_use]
    pub fn new(
        alias: AccountAlias,
        request_generation: NonZeroU64,
        active_account_id_at_proposal: AccountId,
        proposed_controller: AccountController,
        proposed_by: AccountId,
        execute_after_ms: u64,
    ) -> Self {
        Self {
            alias,
            request_generation,
            active_account_id_at_proposal,
            proposed_controller,
            approvals: BTreeSet::new(),
            cancellation_approvals: BTreeSet::new(),
            invalidated_multisig_proposal_ids: Vec::new(),
            proposed_by,
            execute_after_ms,
            status: AccountRecoveryStatus::Pending,
        }
    }
    /// Return `true` when the request is still active.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.status == AccountRecoveryStatus::Pending
    }
    /// Add an approval keyed by guardian subject id.
    pub fn approve(&mut self, account: &AccountId) {
        self.approvals.insert(account.subject_id());
    }
    /// Record an irreversible cancellation vote and withdraw this guardian's replacement vote.
    pub fn approve_cancellation(&mut self, account: &AccountId) {
        let subject = account.subject_id();
        self.approvals.remove(&subject);
        self.cancellation_approvals.insert(subject);
    }
    /// Mark the request as cancelled.
    pub fn cancel(&mut self) {
        self.status = AccountRecoveryStatus::Cancelled;
    }
    /// Mark the request as finalized.
    pub fn finalize(&mut self) {
        self.status = AccountRecoveryStatus::Finalized;
    }
}
/// Validation error returned by [`AccountRecoveryPolicy::new`].
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AccountRecoveryPolicyError {
    /// Recovery policy must include at least one guardian.
    #[error("account recovery policy requires at least one guardian")]
    EmptyGuardians,
    /// Recovery policy quorum must be non-zero.
    #[error("account recovery policy quorum must be non-zero")]
    ZeroQuorum,
    /// Recovery guardian weights must be non-zero.
    #[error("recovery guardian `{account}` must have non-zero weight")]
    GuardianWeightZero {
        /// Guardian configured with zero approval weight.
        account: AccountId,
    },
    /// Recovery guardian list must not contain duplicates.
    #[error("recovery guardian `{account}` is duplicated")]
    DuplicateGuardian {
        /// Duplicate guardian account found while validating the policy.
        account: AccountId,
    },
    /// Recovery policy quorum must be reachable from total guardian weight.
    #[error("account recovery policy quorum {quorum} exceeds total guardian weight {total_weight}")]
    QuorumExceedsTotalWeight {
        /// Required approval quorum declared by the policy.
        quorum: u16,
        /// Sum of all guardian weights present in the policy.
        total_weight: u32,
    },
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_model_base::topology::DataSpaceId;
    use std::num::NonZeroU64;
    fn account(seed: u8) -> AccountId {
        let keypair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("derive checked account-recovery fixture keypair");
        AccountId::new(keypair.public_key().clone())
    }
    #[test]
    fn recovery_policy_rejects_duplicate_guardians() {
        let guardian = RecoveryGuardian::new(account(1), 1);
        let err = AccountRecoveryPolicy::new(
            vec![guardian.clone(), guardian],
            1,
            NonZeroU64::new(1).unwrap(),
        )
        .expect_err("duplicate guardian must fail");
        assert!(matches!(
            err,
            AccountRecoveryPolicyError::DuplicateGuardian { .. }
        ));
    }
    #[test]
    fn recovery_policy_rejects_zero_weight() {
        let err = AccountRecoveryPolicy::new(
            vec![RecoveryGuardian::new(account(1), 0)],
            1,
            NonZeroU64::new(1).unwrap(),
        )
        .expect_err("zero weight must fail");
        assert!(matches!(
            err,
            AccountRecoveryPolicyError::GuardianWeightZero { .. }
        ));
    }
    #[test]
    fn recovery_policy_rejects_unreachable_quorum() {
        let err = AccountRecoveryPolicy::new(
            vec![RecoveryGuardian::new(account(1), 1)],
            2,
            NonZeroU64::new(1).unwrap(),
        )
        .expect_err("unreachable quorum must fail");
        assert!(matches!(
            err,
            AccountRecoveryPolicyError::QuorumExceedsTotalWeight { .. }
        ));
    }
    #[test]
    fn recovery_policy_computes_approval_weight() {
        let first = account(1);
        let second = account(2);
        let policy = AccountRecoveryPolicy::new(
            vec![
                RecoveryGuardian::new(first.clone(), 2),
                RecoveryGuardian::new(second.clone(), 3),
            ],
            4,
            NonZeroU64::new(5_000).unwrap(),
        )
        .expect("policy");
        let approvals = BTreeSet::from([first.subject_id(), second.subject_id()]);
        assert_eq!(policy.approval_weight(&approvals), 5);
        assert!(policy.quorum_reached(&approvals));
    }
    #[test]
    fn recovery_request_roundtrips_terminal_multisig_evidence() {
        let alias = AccountAlias::domainless(
            "company".parse().expect("account alias name"),
            DataSpaceId::UNIVERSAL,
        );
        let active = account(1);
        let mut request = AccountRecoveryRequest::new(
            alias,
            NonZeroU64::new(7).expect("positive request generation"),
            active,
            AccountController::single(
                account(2)
                    .controller()
                    .single_signatory()
                    .expect("single-key fixture")
                    .clone(),
            ),
            account(3),
            259_200_001,
        );
        request.invalidated_multisig_proposal_ids = vec![[0x51; 32]];
        let cancellation_guardian = account(4);
        request.approve(&cancellation_guardian);
        request.approve_cancellation(&cancellation_guardian);
        assert!(request.approvals.is_empty());
        assert!(
            request
                .cancellation_approvals
                .contains(&cancellation_guardian.subject_id())
        );
        request.finalize();
        let encoded = norito::to_bytes(&request).expect("encode recovery request");
        let decoded = norito::decode_from_bytes::<AccountRecoveryRequest>(&encoded)
            .expect("decode recovery request");
        assert_eq!(decoded, request);

        {
            let json = norito::json::to_json(&request).expect("encode recovery request JSON");
            let decoded = norito::json::from_str::<AccountRecoveryRequest>(&json)
                .expect("decode recovery request JSON");
            assert_eq!(decoded, request);
            let mut missing_generation = norito::json::to_value(&request).unwrap();
            missing_generation
                .as_object_mut()
                .unwrap()
                .remove("request_generation");
            assert!(
                norito::json::from_str::<AccountRecoveryRequest>(
                    &norito::json::to_json(&missing_generation).unwrap(),
                )
                .is_err()
            );
        }
    }
}

#[cfg(test)]
mod captured_recovery_schema_tests;
