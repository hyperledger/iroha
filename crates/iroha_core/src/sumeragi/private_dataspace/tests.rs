//! Parent registration authorization, persistence and certified cursor regression coverage.

use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::isi::sccp::test_support::{authority, header},
    state::{State, StateBlock, World},
    sumeragi::lanes::routing::test_support,
};
use iroha_data_model::{
    Registrable,
    account::{Account, AccountAddress},
    isi::SetParameter,
    parameter::{CustomParameter, Parameter},
    sns::{NameControllerV1, NameRecordV1},
    sumeragi_finality::{authenticated_genesis, test_fixtures::NativeFinalityFixture},
};
use iroha_model_base::metadata::Metadata;
use norito::codec::Encode;

fn policy() -> PrivateDataspaceAdmissionPolicy {
    PrivateDataspaceAdmissionPolicy {
        max_registered_roots: 8,
        max_roots_per_owner: 2,
    }
}

fn lease(owner: &AccountId) -> NameRecordV1 {
    NameRecordV1::new(
        crate::sns::selector_for_dataspace_alias("acme").unwrap(),
        owner.clone(),
        vec![NameControllerV1::account(
            &AccountAddress::from_account_id(owner).unwrap(),
        )],
        0,
        0,
        100_000,
        200_000,
        300_000,
        Metadata::default(),
    )
}

fn state(
    scope: Option<SumeragiRootScope>,
    admission: Option<PrivateDataspaceAdmissionPolicy>,
) -> State {
    State::new_for_testing(
        world(scope, admission),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    )
}

fn world(
    scope: Option<SumeragiRootScope>,
    admission: Option<PrivateDataspaceAdmissionPolicy>,
) -> World {
    let owner = authority(1);
    let relayer = authority(2);
    let accounts = [
        Account::new(owner.clone()).build(&owner),
        Account::new(relayer).build(&owner),
    ];
    let mut world = World::with([], accounts, []);
    let record = lease(&owner);
    world.smart_contract_state_mut_for_testing().insert(
        crate::sns::record_storage_key(&record.selector),
        record.encode(),
    );
    {
        let mut parameters = world.parameters.block();
        if let Some(scope) = scope {
            parameters.set_parameter(test_support::metadata(scope));
        }
        if let Some(policy) = admission {
            parameters.set_parameter(Parameter::Custom(policy.into_custom_parameter().unwrap()));
        }
        parameters.commit();
    }
    world
}

fn registration(state: &State) -> (NativeFinalityFixture, RegisterPrivateDataspace) {
    let dataspace_id = crate::sns::dataspace_id_for_sns_alias("acme").unwrap();
    let scope = SumeragiRootScope::Dataspace {
        parent_network_id: *state.network_id_ref(),
        dataspace_id,
    };
    let child = NativeFinalityFixture::start_with_scope("acme-private", scope);
    let result = child
        .verifier()
        .verify_retained_decision(child.genesis_proof())
        .unwrap()
        .result()
        .0;
    let registration = PrivateDataspaceRegistration::new(
        scope,
        child.chain_id().parse().unwrap(),
        child.network_id(),
        result,
        authenticated_genesis(child.genesis())
            .map(|genesis| genesis.into_parts().0)
            .unwrap(),
    )
    .unwrap();
    (
        child,
        RegisterPrivateDataspace {
            alias: "acme".into(),
            expected_ownership_generation: 1,
            registration: norito::encode_canonical(&registration).unwrap(),
        },
    )
}

fn execute(
    block: &mut StateBlock<'_>,
    signer: &AccountId,
    instruction: impl Execute,
) -> Result<(), Error> {
    let mut transaction = block.transaction();
    instruction.execute(signer, &mut transaction)?;
    transaction.apply();
    Ok(())
}

#[test]
fn parent_registration_requires_committed_global_scope_active_owner_and_admission() {
    let parent = state(Some(SumeragiRootScope::Global), Some(policy()));
    let (_, register) = registration(&parent);
    let mut block = parent.block(header(2));
    for (signer, candidate, message) in [
        (authority(2), register.clone(), "authority"),
        (authority(3), register.clone(), "not registered"),
        (
            authority(1),
            RegisterPrivateDataspace {
                expected_ownership_generation: 2,
                ..register.clone()
            },
            "generation",
        ),
        (
            authority(1),
            RegisterPrivateDataspace {
                alias: "unknown".into(),
                ..register.clone()
            },
            "unknown",
        ),
        (
            authority(1),
            RegisterPrivateDataspace {
                registration: vec![0; 8],
                ..register.clone()
            },
            "private dataspace",
        ),
    ] {
        let error = execute(&mut block, &signer, candidate).unwrap_err();
        assert!(error.to_string().contains(message), "{error}");
        assert!(block.world.private_dataspaces().records().is_empty());
    }
    execute(&mut block, &authority(1), register.clone()).unwrap();
    assert_eq!(block.world.private_dataspaces().records().len(), 1);
    let private_id = crate::sns::dataspace_id_for_sns_alias("acme").unwrap();
    assert!(ensure_parent_execution_separate(&block.world, [private_id]).is_err());
    assert!(ensure_parent_execution_separate(&block.world, [DataSpaceId::UNIVERSAL]).is_ok());
    for scope in [
        None,
        Some(SumeragiRootScope::Dataspace {
            parent_network_id: *parent.network_id_ref(),
            dataspace_id: DataSpaceId::new(9),
        }),
    ] {
        let other = state(scope, Some(policy()));
        let mut block = other.block(header(2));
        assert!(
            execute(&mut block, &authority(1), register.clone())
                .unwrap_err()
                .to_string()
                .contains("global root")
        );
    }
    let disabled = state(Some(SumeragiRootScope::Global), None);
    let mut block = disabled.block(header(2));
    assert!(
        execute(&mut block, &authority(1), register)
            .unwrap_err()
            .to_string()
            .contains("disabled")
    );
}

#[test]
fn parent_records_only_public_credentials_and_certified_cursor_witness() {
    let parent = state(Some(SumeragiRootScope::Global), Some(policy()));
    let (mut child, register) = registration(&parent);
    let registration = PrivateDataspaceRegistration::decode(&register.registration).unwrap();
    let mut block = parent.block(header(2));
    let _guard = crate::exec_witness::exec_witness_guard();
    crate::exec_witness::start_block();
    execute(&mut block, &authority(1), register.clone()).unwrap();
    let body = child.block_with_submitted_work(child.next_header());
    let proof = child.certify(body);
    let decision = child.verifier().verify_retained_decision(&proof).unwrap();
    let anchor = PrivateDataspaceAnchor::from_certificate(
        &registration,
        decision.block().commit_certificate().unwrap(),
    )
    .unwrap();
    let instruction = AnchorPrivateDataspace {
        dataspace_id: anchor.dataspace_id,
        anchor: norito::encode_canonical(&anchor).unwrap(),
    };
    // Any registered relayer can submit the genuine QC; it cannot replace owner authorization.
    execute(&mut block, &authority(2), instruction.clone()).unwrap();
    execute(&mut block, &authority(2), instruction).unwrap();
    execute(&mut block, &authority(1), register).unwrap();
    let record = block
        .world
        .private_dataspaces()
        .get(anchor.dataspace_id)
        .unwrap();
    assert_eq!(record.anchor.cursor().height, 2);
    let public = norito::encode_canonical(record).unwrap();
    assert!(
        !public
            .windows(b"fixture submitted work".len())
            .any(|chunk| chunk == b"fixture submitted work")
    );
    let witness = crate::exec_witness::drain_exec_witness();
    assert!(
        witness
            .writes
            .iter()
            .any(|write| write.key == record.witness_key() && write.value == public)
    );
    block.world.private_dataspaces().validate().unwrap();
}

#[test]
fn parent_anchor_rechecks_expiry_generation_and_exact_child_binding() {
    let parent = state(Some(SumeragiRootScope::Global), Some(policy()));
    let (mut child, register) = registration(&parent);
    let registration = PrivateDataspaceRegistration::decode(&register.registration).unwrap();
    let body = child.block_with_submitted_work(child.next_header());
    let proof = child.certify(body);
    let decision = child.verifier().verify_retained_decision(&proof).unwrap();
    let anchor = PrivateDataspaceAnchor::from_certificate(
        &registration,
        decision.block().commit_certificate().unwrap(),
    )
    .unwrap();
    let instruction = AnchorPrivateDataspace {
        dataspace_id: anchor.dataspace_id,
        anchor: norito::encode_canonical(&anchor).unwrap(),
    };
    let mut block = parent.block(header(2));
    execute(&mut block, &authority(1), register).unwrap();
    let retained = block.world.private_dataspaces().clone();
    for changed in [
        NameRecordV1 {
            ownership_generation: 2,
            ..lease(&authority(1))
        },
        NameRecordV1 {
            expires_at_ms: 1,
            ..lease(&authority(1))
        },
        lease(&authority(2)),
    ] {
        {
            let mut tx = block.transaction();
            tx.world.smart_contract_state.insert(
                crate::sns::record_storage_key(&changed.selector),
                changed.encode(),
            );
            tx.apply();
        }
        assert!(execute(&mut block, &authority(2), instruction.clone()).is_err());
        assert_eq!(block.world.private_dataspaces(), &retained);
    }
    assert_eq!(
        retained
            .get(anchor.dataspace_id)
            .unwrap()
            .anchor
            .cursor()
            .height,
        1
    );
}

#[test]
fn admission_parameter_rejects_malformed_payload_and_retains_previous_policy() {
    let parent = state(Some(SumeragiRootScope::Global), Some(policy()));
    let mut block = parent.block(header(2));
    let id = PrivateDataspaceAdmissionPolicy::parameter_id();
    for payload in [
        "{}",
        "{\"max_registered_roots\":1,\"max_roots_per_owner\":2}",
    ] {
        let parameter = Parameter::Custom(CustomParameter::new(
            id.clone(),
            payload.parse::<iroha_primitives::json::Json>().unwrap(),
        ));
        assert!(execute(&mut block, &authority(1), SetParameter::new(parameter)).is_err());
        assert_eq!(
            PrivateDataspaceAdmissionPolicy::from_custom_parameter(
                block.world.parameters().custom().get(&id).unwrap()
            )
            .unwrap(),
            policy()
        );
    }
}

#[test]
fn parent_receipt_uses_original_certified_archive_and_survives_native_replay() {
    use crate::query::native_receipts::private_dataspace_record_proof;
    use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::sumeragi_finality::{FinalityValidator, SumeragiFinalityVerifier};

    let config = || TestChainConfig::new(world(None, Some(policy())), 1_000);
    let mut chain = CertifiedTestChain::start(config()).unwrap();
    let (_, register) = registration(chain.state());
    let id = crate::sns::dataspace_id_for_sns_alias("acme").unwrap();
    let key = KeyPair::from_seed(vec![1; 32], Algorithm::Ed25519);
    let transaction = chain.sign(&key, [register.into()], 1_999);
    assert_eq!(chain.commit_at(2_000, vec![transaction]), vec![true]);
    let receipt = private_dataspace_record_proof(&chain.state().view(), 2, id)
        .unwrap()
        .unwrap();
    assert_eq!(receipt.record.anchor.cursor().height, 1);
    let validators = authenticated_genesis(chain.genesis())
        .map(|genesis| genesis.into_parts().0)
        .unwrap()
        .committee
        .into_iter()
        .map(|member| FinalityValidator {
            public_key: member.validator.public_key().clone(),
            proof_of_possession: member.proof_of_possession,
        })
        .collect();
    let mut verifier =
        SumeragiFinalityVerifier::new(chain.genesis(), "sumeragi-certified-test-chain", validators)
            .unwrap();
    verifier
        .verify(&crate::sumeragi::finality::build_proof(&chain.state().view(), 1).unwrap())
        .unwrap();
    let certified = verifier
        .verify(&crate::sumeragi::finality::build_proof(&chain.state().view(), 2).unwrap())
        .unwrap();
    receipt.verify(id, &certified).unwrap();
    assert!(private_dataspace_record_proof(&chain.state().view(), 1, id).is_err());
    assert!(
        private_dataspace_record_proof(&chain.state().view(), 2, DataSpaceId::UNIVERSAL)
            .unwrap()
            .is_none()
    );
    let mut replayed = CertifiedTestChain::start(config()).unwrap();
    replayed.replay_from(&chain).unwrap();
    assert_eq!(
        private_dataspace_record_proof(&replayed.state().view(), 2, id).unwrap(),
        Some(receipt)
    );
}
