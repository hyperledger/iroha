//! Native global carrier execution for atomic private settlement.

use super::*;
use crate::private_settlement::carrier::{
    private_settlement_abort_carrier_instruction_digest_v1,
    private_settlement_carrier_instruction_digest_v1, private_settlement_commit_bundle_digest_v1,
    private_settlement_prepare_lock_carrier_instruction_digest_v1,
};
use iroha_data_model::isi::private_settlement::{
    AbortAtomicPrivateSettlementV1, ActivatePrivateSettlementPoolV1,
    FinalizeAtomicPrivateSettlementV1, RegisterAtomicPrivateSettlementPrepareV1,
    RotatePrivateSettlementPoolPolicyV1,
};
use iroha_data_model::nexus::PrivateSettlementPoolGovernanceProjectionV1;
use iroha_data_model::nexus::{
    ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1, PrivateSettlementAbortReasonV1,
    PrivateSettlementAbortReceiptV1,
};

impl Execute for ActivatePrivateSettlementPoolV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        super::privacy::ensure_privacy_governance(authority, state_transaction)?;
        self.validate().map_err(|_| invalid_pool_activation())?;
        let projection = PrivateSettlementPoolGovernanceProjectionV1 {
            version: self.version,
            route: self.route,
            pool_id: self.pool_id,
            asset_binding_commitment: self.asset_binding_commitment,
            audit_policy_digest: self.audit_policy_digest,
            audit_key_epoch: self.audit_key_epoch,
            lifecycle: self.lifecycle,
            governance_digest: self.governance_digest,
            prior_revisions: Vec::new(),
        };
        state_transaction
            .bootstrap_private_settlement_pool_v1(projection, &self.initial_commitments)
            .map_err(|_| invalid_pool_activation())?;
        Ok(())
    }
}

impl Execute for RotatePrivateSettlementPoolPolicyV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        super::privacy::ensure_privacy_governance(authority, state_transaction)?;
        self.validate().map_err(|_| invalid_pool_activation())?;
        let replacement = PrivateSettlementPoolGovernanceProjectionV1 {
            version: self.version,
            route: self.route,
            pool_id: self.pool_id,
            asset_binding_commitment: self.asset_binding_commitment,
            audit_policy_digest: self.audit_policy_digest,
            audit_key_epoch: self.audit_key_epoch,
            lifecycle: self.lifecycle,
            governance_digest: self.governance_digest,
            prior_revisions: Vec::new(),
        };
        state_transaction
            .rotate_private_settlement_pool_policy_v1(self.expected_governance_digest, replacement)
            .map_err(|_| invalid_pool_activation())?;
        Ok(())
    }
}

impl Execute for FinalizeAtomicPrivateSettlementV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        if authority != &self.commit_bundle.manifest.sponsor {
            return Err(invalid_carrier());
        }
        let bundle_digest = private_settlement_commit_bundle_digest_v1(&self.commit_bundle)
            .map_err(|_| invalid_carrier())?;
        let instruction_digest = private_settlement_carrier_instruction_digest_v1(&self)
            .map_err(|_| invalid_carrier())?;
        state_transaction
            .consume_private_settlement_carrier_binding_v1(bundle_digest, instruction_digest)
            .map_err(|_| invalid_carrier())?;

        let finalized_height = state_transaction.block_height();
        let receipt = self.commit_bundle.into_receipt(finalized_height);
        state_transaction
            .apply_private_settlement_receipt_v1(receipt)
            .map_err(|_| invalid_carrier())?;
        Ok(())
    }
}

impl Execute for RegisterAtomicPrivateSettlementPrepareV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        if authority != &self.barrier.manifest.sponsor {
            return Err(invalid_carrier());
        }
        let payload_digest = self.barrier.prepared_bundle_digest;
        let instruction_digest =
            private_settlement_prepare_lock_carrier_instruction_digest_v1(&self)
                .map_err(|_| invalid_carrier())?;
        state_transaction
            .consume_private_settlement_carrier_binding_v1(payload_digest, instruction_digest)
            .map_err(|_| invalid_carrier())?;
        state_transaction
            .apply_private_settlement_prepare_locks_v1(self.barrier)
            .map_err(|_| invalid_carrier())?;
        Ok(())
    }
}

impl Execute for AbortAtomicPrivateSettlementV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        if authority != &self.manifest.sponsor {
            return Err(invalid_abort());
        }
        let manifest_digest = self
            .manifest
            .manifest_digest()
            .map_err(|_| invalid_abort())?;
        let instruction_digest = private_settlement_abort_carrier_instruction_digest_v1(&self)
            .map_err(|_| invalid_abort())?;
        state_transaction
            .consume_private_settlement_carrier_binding_v1(manifest_digest, instruction_digest)
            .map_err(|_| invalid_abort())?;

        let finalized_height = state_transaction.block_height();
        let receipt = private_settlement_abort_receipt_v1(self, authority, finalized_height)?;
        state_transaction
            .apply_private_settlement_abort_v1(receipt)
            .map_err(|_| invalid_abort())?;
        Ok(())
    }
}

fn private_settlement_abort_receipt_v1(
    carrier: AbortAtomicPrivateSettlementV1,
    authority: &AccountId,
    finalized_height: u64,
) -> Result<PrivateSettlementAbortReceiptV1, Error> {
    carrier.manifest.validate().map_err(|_| invalid_abort())?;
    if authority != &carrier.manifest.sponsor
        || finalized_height < carrier.manifest.authority_context_height
        || (finalized_height > carrier.manifest.expiry_height)
            != (carrier.reason == PrivateSettlementAbortReasonV1::Expired)
    {
        return Err(invalid_abort());
    }
    let manifest_digest = carrier
        .manifest
        .manifest_digest()
        .map_err(|_| invalid_abort())?;
    let receipt = PrivateSettlementAbortReceiptV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        network_id: carrier.manifest.network_id,
        bundle_id: carrier.manifest.bundle_id,
        manifest_digest,
        finalized_height,
        reason: carrier.reason,
    };
    receipt.validate().map_err(|_| invalid_abort())?;
    Ok(receipt)
}

fn invalid_carrier() -> Error {
    Error::InvariantViolation("private-settlement global carrier is invalid".into())
}

fn invalid_pool_activation() -> Error {
    Error::InvariantViolation("private-settlement pool activation is invalid or inactive".into())
}

fn invalid_abort() -> Error {
    Error::InvariantViolation("private-settlement abort carrier is invalid".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private_settlement::global_state::tests::fixture;
    use iroha_data_model::nexus::PrivateSettlementAbortReasonV1;
    use iroha_test_samples::gen_account_in;

    #[test]
    fn abort_carrier_derives_only_the_bound_public_receipt() {
        let (_, finalized, _) = fixture();
        let manifest = finalized.manifest;
        let sponsor = manifest.sponsor.clone();
        let height = manifest.expiry_height;
        let expected_digest = manifest.manifest_digest().expect("manifest digest");
        let receipt = private_settlement_abort_receipt_v1(
            AbortAtomicPrivateSettlementV1::new(
                manifest.clone(),
                PrivateSettlementAbortReasonV1::ParticipantRejected,
            ),
            &sponsor,
            height,
        )
        .expect("valid sponsor abort");

        assert_eq!(receipt.network_id, manifest.network_id);
        assert_eq!(receipt.bundle_id, manifest.bundle_id);
        assert_eq!(receipt.manifest_digest, expected_digest);
        assert_eq!(receipt.finalized_height, height);
        assert_eq!(
            receipt.reason,
            PrivateSettlementAbortReasonV1::ParticipantRejected
        );
    }

    #[test]
    fn abort_carrier_rejects_wrong_authority_and_expiry_reason() {
        let (_, finalized, _) = fixture();
        let manifest = finalized.manifest;
        let (outsider, _) = gen_account_in("private-settlement-abort-outsider");
        assert!(
            private_settlement_abort_receipt_v1(
                AbortAtomicPrivateSettlementV1::new(
                    manifest.clone(),
                    PrivateSettlementAbortReasonV1::ParticipantRejected,
                ),
                &outsider,
                manifest.expiry_height,
            )
            .is_err()
        );
        assert!(
            private_settlement_abort_receipt_v1(
                AbortAtomicPrivateSettlementV1::new(
                    manifest.clone(),
                    PrivateSettlementAbortReasonV1::ParticipantRejected,
                ),
                &manifest.sponsor,
                manifest.expiry_height + 1,
            )
            .is_err()
        );
        assert!(
            private_settlement_abort_receipt_v1(
                AbortAtomicPrivateSettlementV1::new(
                    manifest.clone(),
                    PrivateSettlementAbortReasonV1::Expired,
                ),
                &manifest.sponsor,
                manifest.expiry_height,
            )
            .is_err()
        );
    }
}
