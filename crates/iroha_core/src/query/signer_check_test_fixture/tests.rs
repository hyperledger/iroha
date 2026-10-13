//! Public test facade retains exact native outcomes on its own certified chain.
use super::*;
use crate::query::{
    signer_custody_history::{AccountPurpose, CustodyPurpose, ReceiptPurpose, control_head_key},
    signer_finality::verify_signer_finality_v1,
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    IntoKeyValue, Level, Registrable,
    account::{Account, AccountId},
    isi::{InstructionBox, Log, Register, sorafs::MutateSorafsFinalPromotionAccountCustody},
    sorafs::final_promotion_account_custody::FinalPromotionAccountCustodyActionV1,
    transaction::{FeePaymentIntent, TransactionBuilder, TransactionEntrypoint},
};
use std::{
    num::NonZeroUsize,
    panic::{AssertUnwindSafe, catch_unwind},
    time::Duration,
};

fn key() -> KeyPair {
    KeyPair::try_from_seed(vec![0xA1; 32], Algorithm::Ed25519).unwrap()
}

#[test]
fn final_promotion_setup_executes_scoped_grants_without_native_history() {
    use crate::state::WorldReadOnly;
    use iroha_executor_data_model::permission::sorafs::{
        CanCheckSorafsFinalPromotion, CanCheckSorafsFinalPromotionAccountCustody,
        CanManageSorafsFinalPromotionAccountCustody, CanManageSorafsFinalPromotionCustody,
        CanOperateSorafsFinalPromotion,
    };
    let account = |seed| {
        AccountId::new(
            KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
                .unwrap()
                .public_key()
                .clone(),
        )
    };
    let (manager, operator, observer) = (account(1), account(2), account(3));
    let fixture = NativeCheckTestFixtureV1::with_final_promotion_accounts(
        "promotion-primary",
        manager.clone(),
        operator.clone(),
        observer.clone(),
    );
    // Only the signed genesis is committed; it is the first floor.
    let (height, block_hash, _) = fixture.finalized_floor();
    let view = fixture.state().view();
    assert_eq!(view.height(), 1);
    assert_eq!(height, 1);
    assert_eq!(block_hash, *view.block_hashes().get(0).unwrap().as_ref());
    // Registration and grants must not create custody, Check or operation history.
    let keys = view
        .world
        .smart_contract_state
        .iter()
        .map(|(key, _)| key.clone())
        .collect::<std::collections::BTreeSet<_>>();
    for namespace in [ReceiptPurpose::NAMESPACE, AccountPurpose::NAMESPACE] {
        assert!(
            keys.iter().all(|key| !key.as_ref().starts_with(namespace)),
            "setup must not seed any row in {namespace}"
        );
    }
    // The three role accounts, the genesis account and the chain's clock account.
    assert_eq!(view.world.accounts.iter().count(), 5);
    let expected: [(AccountId, Vec<iroha_data_model::permission::Permission>); 3] = [
        (
            manager,
            vec![
                CanManageSorafsFinalPromotionCustody {
                    deployment_id: "promotion-primary".into(),
                }
                .into(),
                CanManageSorafsFinalPromotionAccountCustody {
                    deployment_id: "promotion-primary".into(),
                }
                .into(),
            ],
        ),
        (
            operator,
            vec![
                CanOperateSorafsFinalPromotion {
                    deployment_id: "promotion-primary".into(),
                }
                .into(),
            ],
        ),
        (
            observer,
            vec![
                CanCheckSorafsFinalPromotion {
                    deployment_id: "promotion-primary".into(),
                }
                .into(),
                CanCheckSorafsFinalPromotionAccountCustody {
                    deployment_id: "promotion-primary".into(),
                }
                .into(),
            ],
        ),
    ];
    for (account, grants) in expected {
        assert!(view.world.accounts.get(&account).is_some());
        assert_eq!(
            view.world.account_permissions.get(&account).unwrap().len(),
            grants.len()
        );
        for permission in grants {
            assert!(
                view.world
                    .account_contains_inherent_permission(&account, &permission)
            );
        }
    }
}
fn world() -> World {
    let authority = AccountId::new(key().public_key().clone());
    let (id, account) = Account::new(authority.clone())
        .build(&authority)
        .into_key_value();
    let mut world = World::new();
    world.accounts.insert(id, account);
    world
}
fn signed(fixture: &NativeCheckTestFixtureV1, instruction: InstructionBox) -> SignedTransaction {
    let mut builder = TransactionBuilder::new(
        *fixture.state().network_id_ref(),
        AccountId::new(key().public_key().clone()),
        FeePaymentIntent::authority(Vec::new(), None),
    );
    builder.set_creation_time(Duration::from_millis(1_000));
    builder
        .with_instructions([instruction])
        .try_sign(key().private_key())
        .unwrap()
}

#[test]
fn test_facade_retains_exact_executed_results_membership_and_certified_parents() {
    let mut fixture = NativeCheckTestFixtureV1::new(world());
    let genesis = fixture.finalized_floor();
    assert_eq!(genesis.0, 1);
    let state = Arc::clone(fixture.state());
    let success = signed(
        &fixture,
        Log::new(Level::INFO, "native fixture".into()).into(),
    );
    let failure = signed(
        &fixture,
        MutateSorafsFinalPromotionAccountCustody {
            deployment_id: "promotion-primary".into(),
            expected_control_revision: 0,
            expected_control_digest: [0; 32],
            action: FinalPromotionAccountCustodyActionV1::Configure(Vec::new()),
        }
        .into(),
    );
    let transactions = [success, failure];
    assert_eq!(fixture.commit(1_000, transactions.to_vec()), [true, false]);
    assert!(Arc::ptr_eq(&state, fixture.state()));
    let first = fixture.finalized_floor();
    assert_eq!(first.0, 2);
    let block = state
        .block_by_height(NonZeroUsize::new(2).unwrap())
        .expect("committed history read completes")
        .expect("committed execution is retained");
    block.validate_output_merkle_cache().unwrap();
    for (index, signed) in transactions.into_iter().enumerate() {
        assert!(state.has_committed_entrypoint(signed.hash_as_entrypoint()));
        assert_eq!(
            block.network_entrypoint_at(index),
            Some(&TransactionEntrypoint::External(signed))
        );
        let (_, output) = block.network_output_at(index.try_into().unwrap()).unwrap();
        assert_eq!(output.input_index as usize, index);
        assert_eq!(output.result.is_ok(), index == 0);
    }
    // The block's local certificate verifies under the four-validator committee.
    let view = state.view();
    let certified = crate::sumeragi::certified_chain::CertifiedChain::new(&view)
        .unwrap()
        .certified(2)
        .unwrap();
    assert_eq!(
        certified.verification(),
        crate::sumeragi::certified_chain::QcVerification::Verified
    );
    assert_eq!(certified.id(), first.2);
    verify_signer_finality_v1(&view, first.0, first.1).unwrap();
    drop(view);
    assert!(fixture.commit(2_000, Vec::new()).is_empty());
    let second = fixture.finalized_floor();
    assert_eq!(second.0, 3);
    assert_ne!(second.1, first.1);
    assert_eq!(
        fixture
            .chain()
            .committed(3)
            .block()
            .header()
            .prev_block_hash(),
        Some(block.hash())
    );
    verify_signer_finality_v1(&state.view(), second.0, second.1).unwrap();
}

#[test]
fn test_facade_executes_every_instruction_through_the_real_executor() {
    let mut fixture = NativeCheckTestFixtureV1::new(world());
    let other = AccountId::new(
        KeyPair::try_from_seed(vec![0xA2; 32], Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone(),
    );
    let register = signed(
        &fixture,
        Register::account(Account::new(other.clone())).into(),
    );
    let log = signed(
        &fixture,
        Log::new(Level::INFO, "first source".into()).into(),
    );
    let outcomes = fixture.commit(1_000, vec![log.clone(), register]);
    assert!(outcomes[0]);
    assert_eq!(
        fixture.state().view().world.accounts.get(&other).is_some(),
        outcomes[1],
        "the registration's outcome is the one the executor produced"
    );
    assert!(
        fixture
            .state()
            .has_committed_entrypoint(log.hash_as_entrypoint())
    );
}

#[test]
fn test_facade_rejects_preseeded_history_and_foreign_network_before_publication() {
    let mut seeded = world();
    seeded.smart_contract_state.insert(
        control_head_key::<AccountPurpose>("promotion-primary").unwrap(),
        vec![1],
    );
    assert!(catch_unwind(AssertUnwindSafe(|| NativeCheckTestFixtureV1::new(seeded))).is_err());
    let mut fixture = NativeCheckTestFixtureV1::new(world());
    let original = signed(
        &fixture,
        Log::new(Level::INFO, "network fixture".into()).into(),
    );
    let mut payload = original.payload().clone();
    payload.domain = iroha_data_model::transaction::TransactionDomain::Genesis;
    let foreign = TransactionBuilder::from_genesis_payload(payload)
        .unwrap()
        .try_sign(key().private_key())
        .unwrap();
    assert!(catch_unwind(AssertUnwindSafe(|| fixture.commit(1_000, vec![foreign]))).is_err());
    assert_eq!(fixture.finalized_floor().0, 1);
    assert_eq!(fixture.state().committed_height(), 1);
    assert_eq!(fixture.commit(1_000, vec![original]), [true]);
}
