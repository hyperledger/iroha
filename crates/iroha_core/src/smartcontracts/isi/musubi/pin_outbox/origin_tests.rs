//! Exact original signed-input ownership and inherited allocation controls.

use super::*;
use crate::{
    state::World,
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_crypto::KeyPair;
use iroha_data_model::{
    block::BlockHeader,
    transaction::{TransactionBuilder, signed::MultisigSignatures},
};

fn fixture() -> (CertifiedTestChain, KeyPair, AdvanceMusubiPinOutboxV1) {
    let key = KeyPair::from_seed(vec![0xa1; 32], Algorithm::Ed25519);
    let mut configuration = TestChainConfig::new(World::new(), 1_000);
    configuration.genesis_key = key.clone();
    let chain = CertifiedTestChain::start(configuration).unwrap();
    let instruction = AdvanceMusubiPinOutboxV1 {
        network_id: chain.network_id(),
        pin_authority: AccountId::new(key.public_key().clone()),
        session_id: [0x51; 32],
        expected_revision: 0,
        expected_inventory_digest: [0; 32],
        inventory_digest: [0x52; 32],
    };
    (chain, key, instruction)
}

fn header(chain: &CertifiedTestChain) -> BlockHeader {
    let tip = chain.committed(chain.height());
    BlockHeader::new(
        std::num::NonZeroU64::new(chain.height() + 1).unwrap(),
        Some(tip.block_hash()),
        None,
        tip.block_time_ms() + 2,
        0,
    )
}

// Boundary controls enter the actual original signed identities a production Network executor
// carries. They call the same private capture owner and cannot construct its private fields.
fn bind(tx: &mut StateTransaction<'_, '_>, signed: &SignedTransaction) {
    tx.current_tx_hash = Some(signed.hash());
    tx.current_network_entrypoint_hash = Some(signed.hash_as_entrypoint());
    tx.tx_call_hash = Some(Hash::from(signed.hash_as_entrypoint()));
    tx.current_entrypoint_index = Some(0);
}

#[test]
fn native_origin_is_one_use_and_rejects_changed_original_identities_or_instruction() {
    let (chain, key, instruction) = fixture();
    let boxed: InstructionBox = instruction.clone().into();
    let signed = chain.sign(&key, [boxed.clone()], 1_001);
    let mut block = chain.state().block(header(&chain));
    for field in 0..5 {
        let mut tx = block.transaction();
        bind(&mut tx, &signed);
        tx.current_direct_musubi_pin_outbox_origin =
            capture_pin_outbox_operation_origin(&mut tx, &signed, &boxed, true).unwrap();
        assert!(tx.current_direct_musubi_pin_outbox_origin.is_some());
        let mut changed = instruction.clone();
        match field {
            0 => tx.current_tx_hash = None,
            1 => tx.current_network_entrypoint_hash = None,
            2 => tx.tx_call_hash = None,
            3 => tx.current_entrypoint_index = Some(1),
            4 => changed.inventory_digest = [0x91; 32],
            _ => unreachable!(),
        }
        assert!(changed.execute(signed.authority(), &mut tx).is_err());
        assert!(tx.current_direct_musubi_pin_outbox_origin.is_none());
        assert!(
            tx.world
                .musubi_pin_outbox_high_waters
                .get(signed.authority())
                .is_none()
        );
    }
    let mut tx = block.transaction();
    bind(&mut tx, &signed);
    assert!(
        instruction
            .clone()
            .execute(signed.authority(), &mut tx)
            .is_err(),
        "current_tx_hash alone grants no origin"
    );
    tx.current_direct_musubi_pin_outbox_origin =
        capture_pin_outbox_operation_origin(&mut tx, &signed, &boxed, true).unwrap();
    instruction
        .clone()
        .execute(signed.authority(), &mut tx)
        .unwrap();
    assert!(tx.current_direct_musubi_pin_outbox_origin.is_none());
    assert!(instruction.execute(signed.authority(), &mut tx).is_err());
}

#[test]
fn native_origin_rejects_nested_attachments_multisig_bad_signature_and_outer_substitution() {
    let (chain, key, instruction) = fixture();
    let boxed: InstructionBox = instruction.into();
    let original = chain.sign(&key, [boxed.clone()], 1_001);
    let mut block = chain.state().block(header(&chain));
    for case in 0..5 {
        let mut tx = block.transaction();
        let mut signed = original.clone();
        match case {
            1 => {
                let attachment = iroha_data_model::proof::ProofAttachment::new_ref(
                    "halo2/ipa".into(),
                    iroha_data_model::proof::ProofBox::new("halo2/ipa".into(), vec![1]),
                    iroha_data_model::proof::VerifyingKeyId::new(
                        "halo2/ipa",
                        "native-outbox-reject",
                    ),
                );
                signed = TransactionBuilder::from_payload(original.payload().clone())
                    .unwrap()
                    .with_proof_attachments(vec![attachment])
                    .expect("valid proof carriers")
                    .sign(key.private_key());
            }
            2 => signed.set_multisig_signatures(MultisigSignatures::new(Vec::new())),
            3 => {
                let wrong = KeyPair::from_seed(vec![0xa2; 32], Algorithm::Ed25519);
                signed.set_signature(iroha_data_model::transaction::TransactionSignature(
                    iroha_crypto::SignatureOf::new(wrong.private_key(), original.payload()),
                ));
            }
            _ => {}
        }
        bind(&mut tx, &signed);
        if case == 4 {
            tx.current_network_entrypoint_hash =
                Some(HashOf::from_untyped_unchecked(Hash::new([0xee; 32])));
        }
        assert!(
            capture_pin_outbox_operation_origin(&mut tx, &signed, &boxed, case != 0)
                .unwrap()
                .is_none(),
            "case {case}"
        );
        assert!(tx.current_direct_musubi_pin_outbox_origin.is_none());
    }
}

#[test]
fn native_origin_cannot_be_minted_from_genesis_header_or_ivm_payload() {
    use iroha_data_model::transaction::{FeePaymentIntent, IvmBytecode};

    let (chain, key, instruction) = fixture();
    let boxed: InstructionBox = instruction.clone().into();
    let signed = chain.sign(&key, [boxed.clone()], 1_001);
    {
        let mut block = chain.state().block(chain.committed(1).block().header());
        let mut tx = block.transaction();
        bind(&mut tx, &signed);
        assert!(
            capture_pin_outbox_operation_origin(&mut tx, &signed, &boxed, true)
                .unwrap()
                .is_none()
        );
        assert!(instruction.execute(signed.authority(), &mut tx).is_err());
    }
    let mut program = ivm::ProgramMetadata {
        max_cycles: 100,
        ..Default::default()
    }
    .encode();
    program.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
    let mut builder = TransactionBuilder::new(
        chain.network_id(),
        signed.authority().clone(),
        FeePaymentIntent::authority(vec![], std::num::NonZeroU64::new(100)),
    );
    builder.set_creation_time(std::time::Duration::from_millis(1_001));
    let ivm_signed = builder
        .with_executable(Executable::Ivm(IvmBytecode::from_compiled(program)))
        .sign(key.private_key());
    let mut block = chain.state().block(header(&chain));
    let mut tx = block.transaction();
    bind(&mut tx, &signed);
    tx.current_direct_musubi_pin_outbox_origin =
        capture_pin_outbox_operation_origin(&mut tx, &signed, &boxed, true).unwrap();
    assert!(tx.current_direct_musubi_pin_outbox_origin.is_some());
    bind(&mut tx, &ivm_signed);
    assert!(
        capture_pin_outbox_operation_origin(&mut tx, &ivm_signed, &boxed, true)
            .unwrap()
            .is_none()
    );
    assert!(tx.current_direct_musubi_pin_outbox_origin.is_none());
}

#[test]
fn native_pin_outbox_rejects_original_signed_genesis_execution() {
    let (chain, key, advance) = fixture();
    let floor = chain.committed(1);
    let check = CheckMusubiPinOutboxV1 {
        network_id: advance.network_id,
        pin_authority: advance.pin_authority.clone(),
        session_id: advance.session_id,
        inventory_digest: advance.inventory_digest,
        challenge: [0x53; 32],
        floor: iroha_data_model::musubi::MusubiPinOutboxCheckFloorV1 {
            height: 1,
            block_hash: *floor.block_hash().as_ref(),
            context_id: floor.id(),
        },
        expected: MusubiPinOutboxCheckExpectationV1::Absent,
    };
    for instruction in [InstructionBox::from(advance), check.into()] {
        let mut configuration = TestChainConfig::new(World::new(), 1_000);
        configuration.genesis_key = key.clone();
        configuration.genesis_instructions.push(instruction);
        let failure = CertifiedTestChain::start(configuration).unwrap_err();
        assert!(
            format!("{:?}", failure.error)
                .contains("Musubi pin-outbox requires a sole direct signed External"),
            "{:?}",
            failure.error
        );
        assert_eq!(failure.state.view().height(), 0);
        assert!(
            failure
                .state
                .view()
                .world
                .musubi_pin_outbox_high_waters
                .is_empty()
        );
    }
}

fn private_fixture() -> (CertifiedTestChain, KeyPair) {
    use iroha_data_model::{
        Registrable,
        account::Account,
        asset::{
            Asset, AssetBalancePolicy, AssetBalanceScope, AssetDefinition, AssetDefinitionId,
            AssetId,
        },
        block::consensus::RootFeePolicy,
        domain::Domain,
        nexus::{DataSpaceCatalog, DataSpaceMetadata, LaneCatalog, LaneConfig, LaneVisibility},
        parameter::Parameter,
    };
    use iroha_model_base::topology::DataSpaceId;

    let ds = DataSpaceId::new(u64::MAX - 15);
    let key = KeyPair::from_seed(vec![0xcc; 32], Algorithm::Ed25519);
    let owner = AccountId::new(key.public_key().clone());
    let domain =
        iroha_model_base::domain::DomainId::parse_fully_qualified("app.private-pin-test").unwrap();
    let asset = AssetDefinitionId::derive_from_components(domain.clone(), "gas".parse().unwrap());
    let mut definition = AssetDefinition::numeric(
        asset.clone(),
        "Private gas",
        AssetBalancePolicy::DataspaceRestricted,
        Some(domain.clone()),
    )
    .build(&owner);
    definition.total_quantity = 1_000_000_u32.into();
    let world = World::with_assets(
        [Domain::new(domain).build(&owner)],
        [Account::new(owner.clone()).build(&owner)],
        [definition],
        [Asset::new(
            AssetId::with_scope(asset.clone(), owner, AssetBalanceScope::Dataspace(ds)),
            1_000_000_u32,
        )],
        [],
    );
    let mut configuration = TestChainConfig::new(world, 1_000);
    configuration.genesis_parameters.push(Parameter::Custom(
        RootFeePolicy {
            fee_asset_id: asset.clone(),
            base_fee: 1_u32.into(),
            per_byte_fee: 0_u32.into(),
            per_instruction_fee: 1_u32.into(),
            per_gas_unit_fee: 1_u32.into(),
            ..iroha_config::parameters::defaults::nexus::fees::genesis_policy()
        }
        .into_custom_parameter()
        .unwrap(),
    ));
    configuration.root_scope = SumeragiRootScope::Dataspace {
        parent_network_id: iroha_data_model::NetworkId::from_genesis_hash(
            HashOf::from_untyped_unchecked(Hash::new(b"independent public parent")),
        ),
        dataspace_id: ds,
    };
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.fees.fee_asset_id = asset.clone();
    nexus.lane_catalog = LaneCatalog::new(
        std::num::NonZeroU32::new(1).unwrap(),
        vec![LaneConfig {
            dataspace_id: ds,
            visibility: LaneVisibility::Restricted,
            ..LaneConfig::default()
        }],
    )
    .unwrap();
    nexus.configured_lane_catalog = nexus.lane_catalog.clone();
    nexus.lane_config =
        iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
    nexus.dataspace_catalog = DataSpaceCatalog::new(vec![DataSpaceMetadata {
        id: ds,
        alias: "private-pin-test".into(),
        description: None,
        fault_tolerance: 1,
    }])
    .unwrap();
    nexus.configured_dataspace_catalog = nexus.dataspace_catalog.clone();
    nexus.routing_policy.default_dataspace = ds;
    configuration.nexus = Some(nexus);
    (CertifiedTestChain::start(configuration).unwrap(), key)
}

#[test]
fn native_pin_outbox_rejects_actual_private_root_for_advance_and_check() {
    let (chain, key) = private_fixture();
    let authority = AccountId::new(key.public_key().clone());
    let advance = AdvanceMusubiPinOutboxV1 {
        network_id: chain.network_id(),
        pin_authority: authority.clone(),
        session_id: [0x51; 32],
        expected_revision: 0,
        expected_inventory_digest: [0; 32],
        inventory_digest: [0x52; 32],
    };
    let floor = chain.committed(1);
    let check = CheckMusubiPinOutboxV1 {
        network_id: chain.network_id(),
        pin_authority: authority.clone(),
        session_id: advance.session_id,
        inventory_digest: advance.inventory_digest,
        challenge: [0x53; 32],
        floor: iroha_data_model::musubi::MusubiPinOutboxCheckFloorV1 {
            height: 1,
            block_hash: *floor.block_hash().as_ref(),
            context_id: floor.id(),
        },
        expected: MusubiPinOutboxCheckExpectationV1::Absent,
    };
    for instruction in [InstructionBox::from(advance), check.into()] {
        let original = chain.sign(
            &key,
            [instruction.clone()],
            chain.committed(chain.height()).block_time_ms() + 1,
        );
        let accepted =
            crate::tx::AcceptedTransaction::new_unchecked(std::borrow::Cow::Borrowed(&original));
        let next_header = header(&chain);
        {
            let view = chain.state().view();
            let routing = crate::sumeragi::lanes::routing::RoutingSnapshot::of(&view)
                .expect("actual private-root routing snapshot");
            assert!(
                routing
                    .inputs(view.world())
                    .execution_route(&accepted, next_header.height().get())
                    .expect("actual private-root routing read")
                    .is_none(),
                "global pin-outbox work has no admitted private-root route"
            );
        }
        // Routing refuses this signed work before assembly. Exercise the independent
        // native origin boundary on the same actual private State and signed input.
        let before_height = chain.height();
        let mut block = chain.state().block(next_header);
        let mut transaction = block.transaction();
        bind(&mut transaction, &original);
        transaction.current_direct_musubi_pin_outbox_origin =
            capture_pin_outbox_operation_origin(&mut transaction, &original, &instruction, true)
                .expect("bounded original signed origin");
        assert!(
            transaction
                .current_direct_musubi_pin_outbox_origin
                .is_some()
        );
        let result = if let Some(advance) = instruction
            .as_any()
            .downcast_ref::<AdvanceMusubiPinOutboxV1>()
        {
            advance.clone().execute(&authority, &mut transaction)
        } else {
            instruction
                .as_any()
                .downcast_ref::<CheckMusubiPinOutboxV1>()
                .expect("native Check fixture")
                .clone()
                .execute(&authority, &mut transaction)
        };
        assert!(
            format!("{result:?}").contains("Musubi pin-outbox requires the original Global root"),
            "{result:?}"
        );
        assert!(
            transaction
                .current_direct_musubi_pin_outbox_origin
                .is_none()
        );
        assert!(
            transaction
                .world
                .musubi_pin_outbox_high_waters
                .get(&authority)
                .is_none()
        );
        drop(transaction);
        drop(block);
        assert_eq!(chain.height(), before_height);
        assert!(
            chain
                .state()
                .view()
                .world
                .musubi_pin_outbox_high_waters
                .get(&authority)
                .is_none()
        );
    }
}

#[test]
fn native_origin_refusal_preclears_origin_and_preserves_original_allocation_owner() {
    use crate::execution_attempt::ExecutionAttemptError;
    use ivm::error::ExecutionDeferral;
    let (chain, key, instruction) = fixture();
    let boxed: InstructionBox = instruction.into();
    let signed = chain.sign(&key, [boxed.clone()], 1_001);
    let mut block = chain.state().block(header(&chain));
    let budget = iroha_allocation::AllocationBudget::new(8);
    let occupied = budget.try_reserve_bytes(8).unwrap();
    let refusal = budget.try_reserve_bytes(1).unwrap_err();
    for sticky in [false, true] {
        let mut tx = block.transaction();
        bind(&mut tx, &signed);
        tx.current_direct_musubi_pin_outbox_origin =
            capture_pin_outbox_operation_origin(&mut tx, &signed, &boxed, true).unwrap();
        assert!(tx.current_direct_musubi_pin_outbox_origin.is_some());
        if sticky {
            tx.attempt_error_to_instruction_error(ExecutionAttemptError::Deferred(
                refusal.clone().into(),
            ));
        }
        let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);
        assert!(
            norito::with_decode_limits_scope(limits, || capture_pin_outbox_operation_origin(
                &mut tx, &signed, &boxed, true
            ))
            .is_err()
        );
        assert!(tx.current_direct_musubi_pin_outbox_origin.is_none());
        let original = tx.borrow_execution_deferral().unwrap();
        assert_eq!(original.reason(), ExecutionDeferral::ActiveMemoryCapacity);
        assert_eq!(original.allocation_refusal(), sticky.then_some(&refusal));
        assert!(
            tx.world
                .musubi_pin_outbox_high_waters
                .get(signed.authority())
                .is_none()
        );
    }
    drop(occupied);
}

#[test]
fn native_owned_frame_bound_and_cumulative_charge_are_exact() {
    let value = vec![1_u64, 2, 3, 5];
    let expected = norito::encode_canonical(&value).unwrap();
    let length = expected.len();
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, length, 64);
    norito::with_decode_limits_scope(limits, || {
        assert!(matches!(
            encode_owned_frame(&value, length - 1),
            Err(norito::Error::LengthMismatch)
        ));
        assert_eq!(encode_owned_frame(&value, length).unwrap(), expected);
        assert!(matches!(
            encode_owned_frame(&value, length),
            Err(norito::Error::TotalAllocationExceeded { .. })
        ));
    });
    norito::with_decode_limits_scope(limits, || {
        let bytes = encode_owned_frame(&value, length).unwrap();
        assert!(matches!(
            norito::decode_canonical::<Vec<u64>>(&bytes),
            Err(norito::Error::TotalAllocationExceeded { .. })
        ));
    });
}
