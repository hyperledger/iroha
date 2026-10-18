//! Exact signed scope extraction for every atomic settlement movement.
//!
//! Global balances route to the universal coordinator. Scoped balances route to
//! their exact dataspace even when an account or asset alias names another scope.
//! Conditional escrow legs always debit Global buckets into Global custody.
//! Execution separately validates the signed bucket against live asset policy.

use super::RoutingResolveError;
use iroha_data_model::{
    asset::AssetBalanceScope,
    isi::{Instruction, SettleAtomic, SettlementInstructionBox},
};
use iroha_model_base::topology::DataSpaceId;
use std::collections::BTreeSet;

/// Borrow the same exact atomic instruction from either in-memory dispatch form.
pub(super) fn instruction(value: &dyn Instruction) -> Option<&SettleAtomic> {
    let any = value.as_any();
    if let Some(atomic) = any.downcast_ref::<SettleAtomic>() {
        return Some(atomic);
    }
    match any.downcast_ref::<SettlementInstructionBox>()? {
        SettlementInstructionBox::Atomic(atomic) => Some(atomic),
        SettlementInstructionBox::Dvp(_)
        | SettlementInstructionBox::Pvp(_)
        | SettlementInstructionBox::SetFxCorridorPolicy(_)
        | SettlementInstructionBox::FundFxCorridorEscrow(_)
        | SettlementInstructionBox::RefundFxCorridorEscrow(_)
        | SettlementInstructionBox::SettleFxCorridor(_) => None,
    }
}

/// Retain every explicit balance scope; never collapse a mixed batch to one participant.
pub(super) fn concrete_dataspaces(
    atomic: &SettleAtomic,
) -> Result<BTreeSet<DataSpaceId>, RoutingResolveError> {
    atomic
        .validate()
        .map_err(|reason| RoutingResolveError::InvalidAtomicSettlement { reason })?;
    // Destination uses this same signed definition/scope. There is no second
    // independently inferred destination scope to merge or authorize. Escrow
    // legs debit validated Global buckets into Global protocol custody.
    Ok(atomic
        .movements
        .as_slice()
        .iter()
        .map(|movement| movement.source.scope())
        .chain(
            atomic
                .escrows
                .as_slice()
                .iter()
                .map(|escrow| escrow.source.scope()),
        )
        .map(|scope| match scope {
            AssetBalanceScope::Global => DataSpaceId::UNIVERSAL,
            AssetBalanceScope::Dataspace(dataspace) => *dataspace,
        })
        .collect())
}

/// Select the single scope or the universal coordinator for multiple scopes.
pub(super) fn target(atomic: &SettleAtomic) -> Result<Option<DataSpaceId>, RoutingResolveError> {
    let scopes = concrete_dataspaces(atomic)?;
    Ok(if scopes.len() == 1 {
        scopes.first().copied()
    } else {
        Some(DataSpaceId::UNIVERSAL)
    })
}

/// Require coordinator execution for any Global balance or cross-dataspace batch.
pub(super) fn requires_universal_coordinator(
    atomic: &SettleAtomic,
) -> Result<bool, RoutingResolveError> {
    let scopes = concrete_dataspaces(atomic)?;
    Ok(scopes.len() > 1 || scopes.contains(&DataSpaceId::UNIVERSAL))
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
    use iroha_data_model::{
        NetworkId,
        asset::{AssetDefinitionId, AssetId},
        block::BlockHeader,
        isi::{
            AtomicSettlementEscrows, AtomicSettlementMovement, AtomicSettlementMovements,
            InstructionBox,
        },
        prelude::AccountId,
    };
    use iroha_model_base::metadata::Metadata;
    use iroha_primitives::numeric::Quantity;
    use std::num::NonZeroU64;

    fn account(seed: u8) -> AccountId {
        let mut material = vec![0xA5; 32];
        material[0] = seed;
        AccountId::new(
            KeyPair::try_from_seed(material, Algorithm::Ed25519)
                .expect("deterministic fixture key")
                .public_key()
                .clone(),
        )
    }

    fn batch(scopes: &[AssetBalanceScope]) -> SettleAtomic {
        let asset = AssetDefinitionId::from_uuid_bytes([
            1, 2, 3, 4, 5, 6, 0x47, 8, 0x89, 10, 11, 12, 13, 14, 15, 16,
        ])
        .expect("UUIDv4 fixture");
        let mut movements = scopes
            .iter()
            .enumerate()
            .map(|(index, scope)| AtomicSettlementMovement {
                source: AssetId::with_scope(
                    asset.clone(),
                    account(u8::try_from(index).expect("fixture value fits u8")),
                    *scope,
                ),
                recipient: account(
                    u8::try_from(index.wrapping_add(1)).expect("fixture value fits u8"),
                ),
                quantity: Quantity::from(index as u64 + 42),
            })
            .collect::<Vec<_>>();
        movements.sort_by(|a, b| (&a.source, &a.recipient).cmp(&(&b.source, &b.recipient)));
        SettleAtomic::new(
            NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
                b"routing-fixture",
            ))),
            iroha_data_model::isi::SettlementId::new(
                movements[0].source.account().clone(),
                "routing_atomic".parse().expect("business reference"),
            ),
            AtomicSettlementMovements::try_from(movements).expect("canonical movements"),
            AtomicSettlementEscrows::empty(),
            NonZeroU64::new(500).expect("expiry"),
            Metadata::default(),
        )
    }

    #[test]
    fn escrow_legs_route_to_the_universal_coordinator() {
        use iroha_data_model::escrow::{
            ConditionalEscrowCondition, ConditionalEscrowOracleCondition,
            ConditionalEscrowPredicate, ConditionalEscrowValue, EscrowId,
        };
        let scope = AssetBalanceScope::Dataspace(DataSpaceId::new(7));
        let mut atomic = batch(&[scope, scope]);
        assert_eq!(target(&atomic).expect("scoped"), Some(DataSpaceId::new(7)));
        assert!(!requires_universal_coordinator(&atomic).expect("scoped"));
        let source = atomic.movements.as_slice()[0].source.clone();
        atomic.escrows = AtomicSettlementEscrows::try_from(vec![
            iroha_data_model::isi::AtomicSettlementEscrow {
                source: AssetId::new(source.definition().clone(), source.account().clone()),
                escrow_id: EscrowId::new(Hash::new(b"routing-escrow")),
                beneficiary: account(9),
                amount: Quantity::one(),
                conditions: vec![ConditionalEscrowCondition::Oracle(
                    ConditionalEscrowOracleCondition {
                        id: "condition".parse().expect("condition id"),
                        attestor: account(10),
                        predicate: ConditionalEscrowPredicate::Equals(
                            ConditionalEscrowValue::Bool(true),
                        ),
                        sequence: core::num::NonZeroU32::new(1).expect("sequence"),
                    },
                )],
                expires_at_ms: 1,
                evidence_hashes: Vec::new(),
            },
        ])
        .expect("one global escrow leg");
        assert!(
            concrete_dataspaces(&atomic)
                .expect("valid")
                .contains(&DataSpaceId::UNIVERSAL)
        );
        assert_eq!(
            target(&atomic).expect("mixed"),
            Some(DataSpaceId::UNIVERSAL)
        );
        assert!(requires_universal_coordinator(&atomic).expect("mixed"));
    }

    #[test]
    fn direct_and_boxed_atomic_routing_retains_all_255_scopes() {
        let scopes = (1..=255)
            .map(|id| AssetBalanceScope::Dataspace(DataSpaceId::new(id)))
            .collect::<Vec<_>>();
        let atomic = batch(&scopes);
        let boxed = SettlementInstructionBox::Atomic(atomic.clone());
        let expected = (1..=255).map(DataSpaceId::new).collect::<BTreeSet<_>>();
        let instructions: [&dyn Instruction; 2] = [&atomic, &boxed];
        for instruction_value in instructions {
            let resolved = instruction(instruction_value).expect("atomic dispatch");
            assert_eq!(resolved, &atomic);
            assert_eq!(concrete_dataspaces(resolved).expect("all scopes"), expected);
            assert_eq!(
                target(resolved).expect("target"),
                Some(DataSpaceId::UNIVERSAL)
            );
            assert!(requires_universal_coordinator(resolved).expect("coordinator"));
            assert!(
                !super::super::instruction_transaction_dataspace_target_needs_state(
                    instruction_value
                )
            );
            assert_eq!(
                super::super::instruction_transaction_dataspace_target(
                    instruction_value,
                    None,
                    None
                )
                .expect("live target"),
                Some(DataSpaceId::UNIVERSAL)
            );
            assert_eq!(
                super::super::deferred_instruction_concrete_dataspace_targets(
                    instruction_value,
                    None,
                    None
                )
                .expect("live concrete"),
                Some(expected.clone())
            );
            assert!(
                super::super::instruction_transaction_target_requires_universal_coordinator(
                    instruction_value,
                    None,
                    None
                )
                .expect("live coordinator")
            );
        }
    }

    #[test]
    fn shared_scoped_balances_use_their_exact_scope() {
        let ds = DataSpaceId::new(7);
        let atomic = batch(&[AssetBalanceScope::Dataspace(ds); 3]);
        assert_eq!(
            concrete_dataspaces(&atomic).expect("scopes"),
            BTreeSet::from([ds])
        );
        assert_eq!(target(&atomic).expect("target"), Some(ds));
        assert!(!requires_universal_coordinator(&atomic).expect("single scope"));
    }

    #[test]
    fn global_balances_are_explicit_coordinator_targets() {
        for scopes in [
            vec![AssetBalanceScope::Global; 3],
            vec![
                AssetBalanceScope::Global,
                AssetBalanceScope::Dataspace(DataSpaceId::new(7)),
            ],
        ] {
            let atomic = batch(&scopes);
            assert!(
                concrete_dataspaces(&atomic)
                    .expect("scopes")
                    .contains(&DataSpaceId::UNIVERSAL)
            );
            assert_eq!(
                target(&atomic).expect("target"),
                Some(DataSpaceId::UNIVERSAL)
            );
            assert!(requires_universal_coordinator(&atomic).expect("global coordinator"));
        }
    }

    #[test]
    fn instruction_box_conversion_preserves_complete_atomic_routing() {
        let atomic = batch(&[
            AssetBalanceScope::Dataspace(DataSpaceId::new(3)),
            AssetBalanceScope::Dataspace(DataSpaceId::new(9)),
        ]);
        let converted = InstructionBox::from(atomic.clone());
        assert_eq!(instruction(&*converted), Some(&atomic));
        assert_eq!(
            concrete_dataspaces(instruction(&*converted).expect("boxed")).expect("scopes"),
            BTreeSet::from([DataSpaceId::new(3), DataSpaceId::new(9)])
        );
    }
}
