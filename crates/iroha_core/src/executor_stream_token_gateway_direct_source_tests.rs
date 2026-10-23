/// Native gateway provenance remains distinct from signer-operation and contract execution.
mod gateway_direct_source {
    use super::*;
    use crate::{
        executor::Executor,
        smartcontracts::isi::sorafs_stream_token_gateway::direct_source::execution,
    };
    use iroha_data_model::{
        isi::sorafs::MutateSorafsStreamTokenGateway,
        sorafs::stream_token_gateway::native::{
            StreamTokenGatewayActionV1, StreamTokenGatewayRequestV1,
        },
        transaction::{IvmProved, signed::SealedTransactionReveal},
    };

    fn fixture() -> State {
        state_for_testing(World::with(
            [],
            [Account::new(ALICE_ID.clone()).build(&ALICE_ID)],
            [],
        ))
    }

    fn instruction(state: &State) -> MutateSorafsStreamTokenGateway {
        MutateSorafsStreamTokenGateway {
            request: StreamTokenGatewayRequestV1 {
                network_id: state.network_id,
                gateway_id: [0x71; 32],
                expected_policy_revision: 1,
                expected_policy_digest: [0x72; 32],
                action: StreamTokenGatewayActionV1::Expire { max_items: 1 },
            },
        }
    }

    fn signed(state: &State, executable: Executable) -> SignedTransaction {
        TransactionBuilder::new(
            state.network_id,
            ALICE_ID.clone(),
            FeePaymentIntent::authority(Vec::new(), core::num::NonZeroU64::new(50_000_000)),
        )
        .with_executable(executable)
        .sign(ALICE_KEYPAIR.private_key())
    }

    fn bind(tx: &mut StateTransaction<'_, '_>, signed: &SignedTransaction) {
        tx.current_network_entrypoint_hash = Some(signed.hash_as_entrypoint());
        tx.tx_call_hash = Some(Hash::from(signed.hash_as_entrypoint()));
        tx.current_tx_hash = Some(signed.hash());
        tx.current_entrypoint_index = Some(7);
    }

    fn call(state: &State) -> ContractInvocation {
        ContractInvocation {
            contract_address: ContractAddress::derive(
                &state.network_id,
                &ALICE_ID,
                71,
                DataSpaceId::UNIVERSAL,
            )
            .unwrap(),
            expected_code_hash: Hash::new(b"unregistered gateway provenance contract"),
            entrypoint: "main".to_owned(),
            arguments: None,
        }
    }

    #[test]
    fn gateway_ordinal_binds_exact_body_position_and_each_signed_entry_identity() {
        let state = fixture();
        let native = instruction(&state);
        let direct: InstructionBox = native.clone().into();
        let source = signed(
            &state,
            Executable::Instructions(vec![direct.clone()].into()),
        );
        let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 1_000, 0));
        let mut tx = block.transaction();
        bind(&mut tx, &source);
        assert_eq!(
            Executor::direct_stream_token_gateway_instruction_index(&tx, &source, &direct, 0, true)
                .unwrap(),
            Some(0)
        );
        for (index, direct_body) in [(0, false), (1, true), (usize::MAX, true)] {
            assert_eq!(
                Executor::direct_stream_token_gateway_instruction_index(
                    &tx,
                    &source,
                    &direct,
                    index,
                    direct_body,
                )
                .unwrap(),
                None
            );
        }
        let mut substituted = native;
        substituted.request.action = StreamTokenGatewayActionV1::Expire { max_items: 2 };
        assert_eq!(
            Executor::direct_stream_token_gateway_instruction_index(
                &tx,
                &source,
                &substituted.into(),
                0,
                true,
            )
            .unwrap(),
            None
        );
        let unrelated: InstructionBox = Log::new(Level::INFO, "not a gateway action".into()).into();
        assert_eq!(
            Executor::direct_stream_token_gateway_instruction_index(
                &tx, &source, &unrelated, 0, true,
            )
            .unwrap(),
            None
        );
        assert_eq!(
            Executor::direct_stream_token_instruction_index(&tx, &source, &direct, 0, true)
                .unwrap(),
            None,
            "a gateway action cannot receive the signer-operation ordinal"
        );
        let other = signed(&state, Executable::Instructions(vec![unrelated].into()));
        for mismatch in 0..5 {
            bind(&mut tx, &source);
            match mismatch {
                0 => tx.current_network_entrypoint_hash = Some(other.hash_as_entrypoint()),
                1 => tx.tx_call_hash = Some(Hash::from(other.hash_as_entrypoint())),
                2 => tx.current_tx_hash = Some(other.hash()),
                3 => tx.current_entrypoint_index = None,
                4 => tx.current_entrypoint_index = Some(u64::from(u32::MAX) + 1),
                _ => unreachable!(),
            }
            assert_eq!(
                Executor::direct_stream_token_gateway_instruction_index(
                    &tx, &source, &direct, 0, true,
                )
                .unwrap(),
                None
            );
        }
        let mixed = signed(
            &state,
            Executable::Batch(
                vec![
                    ExecutableBatchItem::Instruction(Log::new(Level::INFO, "first".into()).into()),
                    ExecutableBatchItem::ContractCall(call(&state)),
                    ExecutableBatchItem::Instruction(direct.clone()),
                ]
                .into(),
            ),
        );
        bind(&mut tx, &mixed);
        for (index, expected) in [(0, None), (1, None), (2, Some(2))] {
            assert_eq!(
                Executor::direct_stream_token_gateway_instruction_index(
                    &tx, &mixed, &direct, index, true,
                )
                .unwrap(),
                expected,
                "the ordinal counts original batch positions, including contract calls"
            );
        }
    }

    #[test]
    fn gateway_ordinal_rejects_contract_raw_ivm_proved_overlay_and_sealed_reveal_sources() {
        let state = fixture();
        let direct: InstructionBox = instruction(&state).into();
        let bytecode = IvmBytecode::from_compiled(Vec::new());
        let variants = [
            Executable::ContractCall(call(&state)),
            Executable::Ivm(bytecode.clone()),
            Executable::IvmProved(IvmProved {
                bytecode,
                overlay: vec![direct.clone()].into(),
                events_commitment: Hash::new(b"gateway test events"),
                gas_policy_commitment: Hash::new(b"gateway test gas"),
            }),
        ];
        let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 1_000, 0));
        let mut tx = block.transaction();
        for executable in variants {
            let source = signed(&state, executable);
            bind(&mut tx, &source);
            assert_eq!(
                Executor::direct_stream_token_gateway_instruction_index(
                    &tx, &source, &direct, 0, true,
                )
                .unwrap(),
                None,
                "claimed emitted/overlay instructions are not the signed native body"
            );
        }
        let source = signed(
            &state,
            Executable::Instructions(vec![direct.clone()].into()),
        );
        bind(&mut tx, &source);
        let sealed = TransactionEntrypoint::SealedReveal(SealedTransactionReveal::new(
            Hash::new(b"gateway sealed outer commitment"),
            source.clone(),
            [0x73; 32],
        ));
        tx.current_network_entrypoint_hash = Some(sealed.hash());
        assert_eq!(
            Executor::direct_stream_token_gateway_instruction_index(&tx, &source, &direct, 0, true)
                .unwrap(),
            None
        );
    }

    #[test]
    fn gateway_ordinal_rejects_genesis_and_foreign_network_with_exact_signed_context() {
        let state = fixture();
        let direct: InstructionBox = instruction(&state).into();
        let genesis = TransactionBuilder::new_genesis(
            ALICE_ID.clone(),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([direct.clone()])
        .sign(ALICE_KEYPAIR.private_key());
        let foreign_network = iroha_data_model::NetworkId::from_genesis_hash(
            HashOf::from_untyped_unchecked(Hash::new(b"foreign gateway source network")),
        );
        assert_ne!(foreign_network, state.network_id);
        let foreign = TransactionBuilder::new(
            foreign_network,
            ALICE_ID.clone(),
            FeePaymentIntent::authority(Vec::new(), core::num::NonZeroU64::new(50_000_000)),
        )
        .with_instructions([direct.clone()])
        .sign(ALICE_KEYPAIR.private_key());
        assert_eq!(genesis.network_id(), None);
        assert_eq!(foreign.network_id(), Some(&foreign_network));
        let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 1_000, 0));
        let mut tx = block.transaction();
        for source in [genesis, foreign] {
            bind(&mut tx, &source);
            assert_eq!(
                Executor::direct_stream_token_gateway_instruction_index(
                    &tx, &source, &direct, 0, true,
                )
                .unwrap(),
                None,
                "matching body and signed hashes cannot replace the actual Network binding"
            );
        }
    }

    #[test]
    fn gateway_execution_consumes_only_its_marker_on_success_and_every_context_rejection() {
        let state = fixture();
        let direct: InstructionBox = instruction(&state).into();
        let source = signed(
            &state,
            Executable::Instructions(vec![direct.clone()].into()),
        );
        let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 1_000, 0));
        let mut tx = block.transaction();
        bind(&mut tx, &source);
        tx.current_direct_stream_token_instruction_index = Some(41);
        assert!(execution(&mut tx, &ALICE_ID).is_err());
        assert_eq!(tx.current_direct_stream_token_instruction_index, Some(41));
        tx.current_direct_stream_token_gateway_instruction_index =
            Executor::direct_stream_token_gateway_instruction_index(&tx, &source, &direct, 0, true)
                .unwrap();
        let exact = execution(&mut tx, &ALICE_ID).unwrap();
        assert_eq!(exact.height, 1);
        assert_eq!(
            exact.transaction_hash,
            *source.hash_as_entrypoint().as_ref()
        );
        assert_eq!((exact.entry_index, exact.instruction_index), (7, 0));
        assert_eq!(exact.recorded_at_unix_ms, 1_000);
        assert_eq!(exact.authority, ALICE_ID.clone());
        assert_eq!(
            tx.current_direct_stream_token_gateway_instruction_index,
            None
        );
        assert_eq!(tx.current_direct_stream_token_instruction_index, Some(41));
        assert!(execution(&mut tx, &ALICE_ID).is_err());
        let sealed = TransactionEntrypoint::SealedReveal(SealedTransactionReveal::new(
            Hash::new(b"gateway consumed sealed mismatch"),
            source.clone(),
            [0x74; 32],
        ));
        for mismatch in 0..6 {
            bind(&mut tx, &source);
            tx.current_direct_stream_token_gateway_instruction_index = Some(0);
            match mismatch {
                0 => tx.current_network_entrypoint_hash = None,
                1 => tx.current_network_entrypoint_hash = Some(sealed.hash()),
                2 => tx.tx_call_hash = None,
                3 => tx.current_tx_hash = None,
                4 => tx.current_entrypoint_index = None,
                5 => tx.current_entrypoint_index = Some(u64::from(u32::MAX) + 1),
                _ => unreachable!(),
            }
            assert!(execution(&mut tx, &ALICE_ID).is_err());
            assert_eq!(
                tx.current_direct_stream_token_gateway_instruction_index,
                None
            );
            assert_eq!(tx.current_direct_stream_token_instruction_index, Some(41));
        }
    }

    #[test]
    fn gateway_execution_rejects_nonadjacent_height_and_invalid_block_time_after_consumption() {
        for (height, timestamp) in [(2_u64, 1_000_u64), (1, 0), (1, u64::MAX)] {
            let state = fixture();
            let source = signed(
                &state,
                Executable::Instructions(vec![instruction(&state).into()].into()),
            );
            let mut block = state.block(BlockHeader::new(
                height.try_into().unwrap(),
                None,
                None,
                timestamp,
                0,
            ));
            let mut tx = block.transaction();
            bind(&mut tx, &source);
            tx.current_direct_stream_token_gateway_instruction_index = Some(0);
            assert!(execution(&mut tx, &ALICE_ID).is_err());
            assert_eq!(
                tx.current_direct_stream_token_gateway_instruction_index,
                None
            );
        }
    }

    #[test]
    fn gateway_marker_is_cleared_by_both_real_direct_loops_on_success_and_rejection() {
        for mixed in [false, true] {
            for rejected in [false, true] {
                let chain = crate::sumeragi::test_chain::CertifiedTestChain::start(
                    crate::sumeragi::test_chain::TestChainConfig::new(
                        World::with([], [Account::new(ALICE_ID.clone()).build(&ALICE_ID)], []),
                        999,
                    ),
                )
                .expect("authenticated genesis establishes immutable global instruction scope");
                let state = chain.state();
                let instruction: InstructionBox = if rejected {
                    // The absent account cannot be unregistered; rejection occurs in dispatch.
                    Unregister::account(BOB_ID.clone()).into()
                } else {
                    Log::new(Level::INFO, "gateway ordinal reset".into()).into()
                };
                let executable = if mixed {
                    Executable::Batch(vec![ExecutableBatchItem::Instruction(instruction)].into())
                } else {
                    Executable::Instructions(vec![instruction].into())
                };
                let source = signed(state, executable);
                let mut block =
                    state.block(BlockHeader::new(nonzero!(2_u64), None, None, 1_000, 0));
                let mut tx =
                    block.transaction_for_fastpq_testing(Hash::from(source.hash_as_entrypoint()));
                // The normal global network route captures Universal for both overlay owners.
                tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
                tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
                tx.current_direct_stream_token_gateway_instruction_index = Some(77);
                let result = Executor::Initial
                    .execute_transaction(&mut tx, &ALICE_ID, &source, &mut IvmCache::new())
                    .map_err(crate::execution_attempt::expect_completed_rejection);
                assert_eq!(result.is_err(), rejected, "mixed={mixed}: {result:?}");
                assert!(tx.last_tx_gas_used > 0, "the authored set reached dispatch");
                assert_eq!(
                    tx.current_direct_stream_token_gateway_instruction_index,
                    None
                );
            }
        }
    }

    #[test]
    fn gateway_marker_is_cleared_before_contract_resolution_even_when_resolution_rejects() {
        let state = fixture();
        let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 1_000, 0));
        let mut tx = block.transaction();
        tx.current_direct_stream_token_gateway_instruction_index = Some(77);
        assert!(
            Executor::Initial
                .execute_contract_invocation(
                    &mut tx,
                    &ALICE_ID,
                    &call(&state),
                    &mut IvmCache::new(),
                    50_000_000,
                    1_000,
                    None,
                )
                .is_err()
        );
        assert_eq!(
            tx.current_direct_stream_token_gateway_instruction_index,
            None
        );
        assert!(execution(&mut tx, &ALICE_ID).is_err());
    }
}
