#[cfg(all(test, feature = "transparent_api"))]
mod canonical_output_inclusion_tests {
    use super::*;
    use crate::block::{SignedBlock, output_test_support as fixture};
    use iroha_crypto::{Hash, HashOf, MerkleProof};
    use norito::codec::DecodeAll as _;
    fn execution_fixture() -> (SignedBlock, CommittedTransaction) {
        let mut block = fixture::proposal(2);
        let rows = vec![
            fixture::network(0, Ok(Vec::default())),
            fixture::network(1, Ok(Vec::default())),
            fixture::simple_time(&block, 0),
        ];
        fixture::install(&mut block, rows, 3).unwrap();
        let committed = fixture::committed(&block, 0);
        (block, committed)
    }
    fn commitment(block: &SignedBlock) -> crate::sumeragi_finality::ExecutionCommitment {
        let wire = block.encode_wire().unwrap();
        // A selected structural execution projection, not self-authenticating finality.
        crate::sumeragi_finality::ExecutionCommitment {
            parent_state_root: Hash::new(b"parent"),
            post_state_root: Hash::new(b"post"),
            ordinary_writes_root: Hash::new(b"writes"),
            parent_world_state_root: Hash::new(b"parent world"),
            world_state_root: Hash::new(b"world"),
            event_commitment: None,
            executed_block_wire_len: wire.len() as u64,
            executed_block_wire_hash: Hash::new(&wire),
            transaction_input_commitment: block.network_input_merkle_commitment(),
            transaction_output_commitment: block.output_merkle_commitment(),
        }
    }
    #[test]
    fn native_execution_commitment_rejects_a_retired_extra_carrier_slot() {
        #[derive(norito::codec::Encode)]
        struct RetiredExecution {
            parent_state_root: Hash,
            post_state_root: Hash,
            ordinary_writes_root: Hash,
            parent_world_state_root: Hash,
            world_state_root: Hash,
            event_commitment: Option<iroha_crypto::MerkleTreeCommitment<crate::events::EventBox>>,
            executed_block_wire_len: u64,
            executed_block_wire_hash: Hash,
            transaction_input_commitment:
                Option<iroha_crypto::MerkleTreeCommitment<TransactionEntrypoint>>,
            transaction_output_commitment: Option<
                iroha_crypto::MerkleTreeCommitment<
                    crate::block::execution_output::ExecutionOutputV1,
                >,
            >,
            merge_carrier: Option<()>,
        }
        // The retired monetary top-up slots are not an accepted alternative layout either.
        #[derive(norito::codec::Encode)]
        struct RetiredTopUpExecution {
            parent_state_root: Hash,
            post_state_root: Hash,
            ordinary_writes_root: Hash,
            top_up_root: Option<Hash>,
            top_up_count: u32,
            parent_world_state_root: Hash,
            world_state_root: Hash,
            event_commitment: Option<iroha_crypto::MerkleTreeCommitment<crate::events::EventBox>>,
            executed_block_wire_len: u64,
            executed_block_wire_hash: Hash,
            transaction_input_commitment:
                Option<iroha_crypto::MerkleTreeCommitment<TransactionEntrypoint>>,
            transaction_output_commitment: Option<
                iroha_crypto::MerkleTreeCommitment<
                    crate::block::execution_output::ExecutionOutputV1,
                >,
            >,
        }
        let (block, _) = execution_fixture();
        let current = commitment(&block);
        let old = RetiredExecution {
            parent_state_root: current.parent_state_root,
            post_state_root: current.post_state_root,
            ordinary_writes_root: current.ordinary_writes_root,
            parent_world_state_root: current.parent_world_state_root,
            world_state_root: current.world_state_root,
            event_commitment: current.event_commitment,
            executed_block_wire_len: current.executed_block_wire_len,
            executed_block_wire_hash: current.executed_block_wire_hash,
            transaction_input_commitment: current.transaction_input_commitment,
            transaction_output_commitment: current.transaction_output_commitment,
            merge_carrier: None,
        };
        assert_eq!(
            crate::sumeragi_finality::ExecutionCommitment::decode_all(
                &mut current.encode().as_slice()
            )
            .unwrap(),
            current
        );
        assert!(
            crate::sumeragi_finality::ExecutionCommitment::decode_all(&mut old.encode().as_slice())
                .is_err()
        );
        let top_ups = RetiredTopUpExecution {
            parent_state_root: current.parent_state_root,
            post_state_root: current.post_state_root,
            ordinary_writes_root: current.ordinary_writes_root,
            top_up_root: None,
            top_up_count: 0,
            parent_world_state_root: current.parent_world_state_root,
            world_state_root: current.world_state_root,
            event_commitment: current.event_commitment,
            executed_block_wire_len: current.executed_block_wire_len,
            executed_block_wire_hash: current.executed_block_wire_hash,
            transaction_input_commitment: current.transaction_input_commitment,
            transaction_output_commitment: current.transaction_output_commitment,
        };
        assert!(
            crate::sumeragi_finality::ExecutionCommitment::decode_all(
                &mut top_ups.encode().as_slice()
            )
            .is_err()
        );
    }
    #[test]
    fn selective_inclusion_binds_both_qc_roots_counts_network_and_source_join() {
        let (block, committed) = execution_fixture();
        let expected = commitment(&block);
        let TransactionEntrypoint::External(signed) = committed.entrypoint() else {
            panic!("external fixture");
        };
        let network = signed.network_id().unwrap();
        assert!(committed.verify_selective_in_authenticated_execution(
            network,
            &block.header(),
            &expected
        ));
        let other_network = crate::NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
            Hash::new(b"foreign network"),
        ));
        assert!(!committed.verify_selective_in_authenticated_execution(
            &other_network,
            &block.header(),
            &expected
        ));
        for mutation in 0..4 {
            let mut wrong = expected;
            match mutation {
                0 => wrong.transaction_input_commitment = None,
                1 => wrong.transaction_output_commitment = None,
                2 => {
                    let previous = wrong.transaction_input_commitment.unwrap();
                    wrong.transaction_input_commitment =
                        Some(iroha_crypto::MerkleTreeCommitment::new(
                            *previous.root(),
                            core::num::NonZeroU64::new(previous.leaf_count().get() + 1).unwrap(),
                        ));
                }
                _ => {
                    let previous = wrong.transaction_output_commitment.unwrap();
                    wrong.transaction_output_commitment =
                        Some(iroha_crypto::MerkleTreeCommitment::new(
                            HashOf::from_untyped_unchecked(Hash::new(b"altered output root")),
                            previous.leaf_count(),
                        ));
                }
            }
            assert!(!committed.verify_selective_in_authenticated_execution(
                network,
                &block.header(),
                &wrong
            ));
        }
        let mut wrong = committed.clone();
        wrong.output_hash = HashOf::from_untyped_unchecked(Hash::new(b"altered output"));
        assert!(!wrong.verify_selective_in_authenticated_execution(
            network,
            &block.header(),
            &expected
        ));
        let mut wrong = committed.clone();
        wrong.entrypoint_proof = fixture::committed(&block, 1).entrypoint_proof().clone();
        assert!(!wrong.verify_selective_in_authenticated_execution(
            network,
            &block.header(),
            &expected
        ));
        let mut foreign_header = block.header();
        foreign_header.creation_time_ms += 1;
        assert!(!committed.verify_selective_in_authenticated_execution(
            network,
            &foreign_header,
            &expected
        ));
        // Both substituted rows carry VALID proofs under the same output root.
        // Row 1 is another input's Network output; row 2 is an internal output.
        // Neither may be joined to this external signed input.
        for index in [1_u32, 2] {
            let mut wrong = committed.clone();
            wrong.output = block.execution_outputs()[index as usize].clone();
            wrong.output_hash = HashOf::new(&wrong.output);
            wrong.output_proof = block.output_proof(index).unwrap();
            assert!(!wrong.verify_selective_in_authenticated_execution(
                network,
                &block.header(),
                &expected
            ));
        }
        // Keep the header and source, but change the executable result and its
        // self-consistent proof. Only the original QC-authenticated root wins.
        let mut rewritten = block.clone();
        let mut rows = rewritten.execution_outputs().to_vec();
        rows[0] = fixture::network(
            0,
            Err(
                crate::transaction::error::TransactionRejectionReason::Validation(
                    crate::ValidationFail::NotPermitted("substituted result".into()),
                ),
            ),
        );
        fixture::install(&mut rewritten, rows, 3).unwrap();
        let altered = fixture::committed(&rewritten, 0);
        assert_eq!(rewritten.header(), block.header());
        assert!(!altered.verify_selective_in_authenticated_execution(
            network,
            &block.header(),
            &expected
        ));
        assert!(altered.verify_selective_in_authenticated_execution(
            network,
            &rewritten.header(),
            &commitment(&rewritten)
        ));
        // Inclusion may prove rejection. Only the application checks success.
    }

    #[test]
    fn selective_commitments_reject_incomplete_and_substituted_native_carriers() {
        let (block, committed) = execution_fixture();
        let expected = commitment(&block);
        assert!(committed.verify_inclusion_in_authenticated_execution(&block, &expected));
        assert!(
            !committed.verify_inclusion_in_authenticated_execution(
                &block
                    .canonical_resultless_proposal()
                    .expect("valid original proposal"),
                &expected
            )
        );
        let mut other = block.clone();
        let mut header = other.header();
        header.creation_time_ms += 1;
        other.replace_header_for_testing(header);
        assert!(!committed.verify_inclusion_in_authenticated_execution(&other, &expected));
        let mut value = norito::json::to_value(&block).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .get_mut("result")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(
                "output_merkle".into(),
                norito::json::to_value(&iroha_crypto::MerkleTree::<
                    crate::block::execution_output::ExecutionOutputV1,
                >::default())
                .unwrap(),
            );
        let stale: SignedBlock = norito::json::from_value(value).unwrap();
        assert!(!committed.verify_inclusion_in_authenticated_execution(&stale, &expected));
    }
    #[test]
    fn ordinary_committed_transaction_verifies_against_exact_carrier_block() {
        let (block, committed) = execution_fixture();
        assert!(committed.verify_inclusion_in_block(&block));
        let bytes = committed.encode();
        let decoded = CommittedTransaction::decode_all(&mut bytes.as_slice()).unwrap();
        assert_eq!(decoded, committed);
        let mut altered = committed.clone();
        altered.entrypoint_hash = HashOf::from_untyped_unchecked(Hash::new(b"wrong"));
        assert!(!altered.verify_inclusion_in_block(&block));
        let mut foreign = block.clone();
        let mut header = block.header();
        header.creation_time_ms += 1;
        foreign.replace_header_for_testing(header);
        assert!(!committed.verify_inclusion_in_block(&foreign));
    }
    #[test]
    fn authenticated_execution_inclusion_binds_complete_carrier_and_output_geometry() {
        let (block, committed) = execution_fixture();
        let expected = commitment(&block);
        assert!(committed.verify_inclusion_in_authenticated_execution(&block, &expected));
        let decoded =
            crate::block::decode_framed_signed_block(&block.encode_wire().unwrap()).unwrap();
        assert!(committed.verify_inclusion_in_authenticated_execution(&decoded, &expected));
        for mutation in 0..3 {
            let mut wrong = expected;
            match mutation {
                0 => wrong.executed_block_wire_len += 1,
                1 => wrong.executed_block_wire_hash = Hash::new(b"foreign"),
                _ => {
                    wrong.transaction_output_commitment = None;
                }
            }
            assert!(!committed.verify_inclusion_in_authenticated_execution(&block, &wrong));
        }
    }
    #[test]
    fn authenticated_execution_inclusion_rejects_unbound_wire_and_header_material() {
        let (original, committed) = execution_fixture();
        let expected = commitment(&original);
        let mut rewritten = original.clone();
        let mut rows = rewritten.execution_outputs().to_vec();
        rows[0] = fixture::network(
            0,
            Err(
                crate::transaction::error::TransactionRejectionReason::Validation(
                    crate::ValidationFail::NotPermitted("substituted result".into()),
                ),
            ),
        );
        fixture::install(&mut rewritten, rows, 3).unwrap();
        let changed = fixture::committed(&rewritten, 0);
        assert_eq!(rewritten.header(), original.header());
        assert_ne!(
            rewritten.output_merkle_commitment(),
            original.output_merkle_commitment()
        );
        assert!(changed.verify_inclusion_in_block(&rewritten));
        assert!(!changed.verify_inclusion_in_authenticated_execution(&rewritten, &expected));
        assert!(!committed.verify_inclusion_in_block(&rewritten));
        let mut unbound = original.clone();
        let mut header = unbound.header();
        header.creation_time_ms += 1;
        unbound.replace_header_for_testing(header);
        let mut evidence = committed.clone();
        evidence.block_hash = unbound.hash();
        assert!(!evidence.verify_inclusion_in_authenticated_execution(&unbound, &expected));
        let mut json = norito::json::to_value(&original).unwrap();
        json.as_object_mut()
            .unwrap()
            .get_mut("result")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(
                "output_merkle".into(),
                norito::json::to_value(&iroha_crypto::MerkleTree::<
                    crate::block::execution_output::ExecutionOutputV1,
                >::default())
                .unwrap(),
            );
        let stale: SignedBlock = norito::json::from_value(json).unwrap();
        assert!(stale.validate_output_merkle_cache().is_err());
        assert!(!committed.verify_inclusion_in_authenticated_execution(&stale, &expected));
    }
    #[test]
    fn authenticated_execution_inclusion_joins_network_indices_without_time_inputs() {
        let (block, network) = execution_fixture();
        let expected = commitment(&block);
        assert_eq!(
            block
                .network_input_merkle_commitment()
                .unwrap()
                .leaf_count()
                .get(),
            2
        );
        assert_eq!(
            block.output_merkle_commitment().unwrap().leaf_count().get(),
            3
        );
        assert!(network.verify_inclusion_in_authenticated_execution(&block, &expected));
        for index in [1_u32, 2] {
            let mut substituted = network.clone();
            substituted.output = block.execution_outputs()[index as usize].clone();
            substituted.output_hash = HashOf::new(&substituted.output);
            substituted.output_proof = block.output_proof(index).unwrap();
            assert!(!substituted.verify_inclusion_in_authenticated_execution(&block, &expected));
        }
        let mut wrong = network.clone();
        wrong.entrypoint_proof = MerkleProof::from_audit_path(1, vec![]);
        assert!(!wrong.verify_inclusion_in_authenticated_execution(&block, &expected));
        assert!(
            !network.verify_inclusion_in_authenticated_execution(
                &block
                    .canonical_resultless_proposal()
                    .expect("valid original proposal"),
                &expected
            )
        );
    }
    #[test]
    fn committed_query_rejects_retired_parallel_result_and_merge_wire() {
        #[derive(norito::codec::Encode)]
        struct RetiredCommitted {
            block_hash: HashOf<crate::block::BlockHeader>,
            entrypoint_hash: HashOf<TransactionEntrypoint>,
            entrypoint_proof: MerkleProof<TransactionEntrypoint>,
            entrypoint: TransactionEntrypoint,
            result_hash: HashOf<crate::transaction::TransactionResult>,
            result_proof: MerkleProof<crate::transaction::TransactionResult>,
            result: crate::transaction::TransactionResult,
            merge_inclusion: Option<()>,
        }
        let (_, committed) = execution_fixture();
        let mut json = norito::json::to_value(&committed).unwrap();
        json.as_object_mut()
            .unwrap()
            .insert("merge_inclusion".into(), norito::json::Value::Null);
        assert!(norito::json::from_value::<CommittedTransaction>(json).is_err());
        let result = committed.result().clone();
        let old = RetiredCommitted {
            block_hash: committed.block_hash,
            entrypoint_hash: committed.entrypoint_hash,
            entrypoint_proof: committed.entrypoint_proof,
            entrypoint: committed.entrypoint,
            result_hash: result.hash(),
            result_proof: MerkleProof::from_audit_path(0, vec![]),
            result,
            merge_inclusion: None,
        };
        assert!(CommittedTransaction::decode_all(&mut old.encode().as_slice()).is_err());
    }
}
#[cfg(all(test, feature = "fault_injection"))]
mod fault_injection_tests {
    use super::*;
    use crate::transaction::TransactionEntrypoint;
    use crate::{
        Level,
        events::data::prelude::{AssetBatchTransferLegStatus, AssetBatchTransferOutcome},
        isi::{InstructionBox, Log},
    };
    use iroha_crypto::{Hash, HashOf, MerkleProof};
    fn fixture() -> CommittedTransaction {
        let key =
            iroha_crypto::KeyPair::try_from_seed(vec![0x19; 32], iroha_crypto::Algorithm::Ed25519)
                .unwrap();
        let entrypoint = TransactionEntrypoint::External(
            crate::transaction::TransactionBuilder::new_genesis(
                AccountId::new(key.public_key().clone()),
                crate::transaction::FeePaymentIntent::authority(vec![], None),
            )
            .sign(key.private_key()),
        );
        let output = crate::block::output_test_support::network(0, Ok(Vec::default()));
        CommittedTransaction {
            block_hash: HashOf::from_untyped_unchecked(Hash::new(b"fault carrier")),
            entrypoint_hash: entrypoint.hash(),
            entrypoint_proof: MerkleProof::from_audit_path(0, vec![]),
            entrypoint,
            output_hash: HashOf::new(&output),
            output_proof: MerkleProof::from_audit_path(0, vec![]),
            output,
        }
    }
    #[test]
    fn network_entrypoint_injection_appends_instructions() {
        let mut tx = fixture();
        let original = tx.entrypoint_hash;
        let injected: InstructionBox = Log::new(Level::WARN, "tamper".into()).into();
        tx.inject_instructions([injected.clone()]);
        assert_ne!(tx.entrypoint_hash, original);
        let TransactionEntrypoint::External(signed) = &tx.entrypoint else {
            unreachable!()
        };
        let crate::transaction::Executable::Instructions(instructions) = signed.instructions()
        else {
            panic!("instructions")
        };
        assert_eq!(instructions.as_ref(), [injected]);
    }
    #[test]
    fn result_swap_preserves_independent_batch_receipts_as_untrusted_fault_evidence() {
        let mut tx = fixture();
        let authority = tx.entrypoint.authority().clone();
        let outcome = AssetBatchTransferOutcome {
            leg_index: 0,
            leg_id: "fault".into(),
            asset: AssetId::new(
                crate::asset::AssetDefinitionId::derive_from_components(
                    DomainId::try_new("wonderland", "universal").unwrap(),
                    "rose".parse().unwrap(),
                ),
                authority.clone(),
            ),
            destination: authority,
            amount: crate::prelude::Quantity::from(1_u32),
            status: AssetBatchTransferLegStatus::Applied,
        };
        let crate::block::execution_output::ExecutionOutputV1::Network(row) = &mut tx.output else {
            unreachable!()
        };
        row.result
            .set_batch_transfer_outcomes(vec![outcome.clone()]);
        tx.output_hash = HashOf::new(&tx.output);
        let old_hash = tx.output_hash;
        let proof = tx.output_proof.clone();
        tx.swap_result();
        assert!(tx.result().0.is_err());
        assert_eq!(tx.result().batch_transfer_outcomes(), [outcome]);
        assert_ne!(tx.output_hash, old_hash);
        assert_eq!(tx.output_hash, HashOf::new(&tx.output));
        assert_eq!(tx.output_proof, proof);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::KeyPair;
    use norito::json;
    use std::num::NonZeroU64;
    #[test]
    fn proof_backend_query_payload_roundtrips() {
        use norito::codec::{Decode, Encode};
        let query =
            proof::prelude::FindProofRecordsByBackend::new("test/nonexistent-proof-backend".into());
        let encoded = query.encode();
        assert!(
            !encoded.is_empty(),
            "backend query payload must carry the backend identifier"
        );
        let mut bytes = encoded.as_slice();
        let decoded =
            proof::prelude::FindProofRecordsByBackend::decode(&mut bytes).expect("decode query");
        assert!(bytes.is_empty(), "decoder must consume the whole payload");
        assert_eq!(decoded.backend, query.backend);
    }
    #[test]
    fn sorafs_authoritative_singular_query_payloads_roundtrip() {
        use norito::codec::{Decode, Encode};
        let juror = AccountId::new(KeyPair::random().public_key().clone());
        let orderbook_cursor = crate::sorafs::orderbook::OrderbookFinalizedCursorV1 {
            height: 7,
            block_hash: [0xA7; 32],
        };
        let reserve_cursor = crate::sorafs::reserve::ReserveFinalizedCursorV1 {
            height: 7,
            block_hash: [0xB7; 32],
        };
        let pin_cursor = crate::sorafs::pin_registry::PinManifestFinalizedCursorV1 {
            height: 7,
            block_hash: [0xC7; 32],
        };
        let repair_cursor = crate::sorafs::moderation_ledger::RepairFinalizedCursorV1 {
            height: 8,
            block_hash: [0xA8; 32],
        };
        let proof_outcome_cursor = crate::sorafs::proof_ledger::ProofOutcomeFinalizedCursorV1 {
            height: 9,
            block_hash: [0xA9; 32],
        };
        let reputation_cursor = crate::sorafs::reputation::ReputationJournalFinalizedCursorV1 {
            height: 10,
            block_hash: [0xAA; 32],
            finalized_at_unix_ms: 1_700_000_010_000,
        };
        let queries: Vec<SingularQueryBox> = vec![
            sorafs::prelude::FindSorafsOrderbookPolicy.into(),
            sorafs::prelude::FindSorafsOrderbookOrderById::new([0x11; 32]).into(),
            sorafs::prelude::FindSorafsOrderbookCancellationByOrderId::new([0x12; 32]).into(),
            sorafs::prelude::FindSorafsOrderbookReceiptById::new([0x13; 32]).into(),
            sorafs::prelude::FindSorafsOrderbookTradeById::new([0x17; 32]).into(),
            sorafs::prelude::FindSorafsOrderbookChannelById::new([0x18; 32]).into(),
            sorafs::prelude::FindSorafsOrderbookStatus.into(),
            sorafs::prelude::FindSorafsOrderbookOrders::new(
                Some(orderbook_cursor),
                Some(crate::sorafs::orderbook::OrderbookOrderStatusV1::Open),
                Some([0x14; 32]),
                25,
            )
            .into(),
            sorafs::prelude::FindSorafsOrderbookReceipts::new(
                Some(orderbook_cursor),
                Some([0x15; 32]),
                Some([0x16; 32]),
                25,
            )
            .into(),
            sorafs::prelude::FindSorafsOrderbookTrades::new(
                Some(orderbook_cursor),
                Some([0x19; 32]),
                25,
            )
            .into(),
            sorafs::prelude::FindSorafsOrderbookChannels::new(
                Some(orderbook_cursor),
                Some(crate::sorafs::orderbook::OrderbookSettlementChannelStatusV1::Open),
                Some([0x1A; 32]),
                25,
            )
            .into(),
            sorafs::prelude::FindSorafsOrderbookEvents::new(
                Some(orderbook_cursor),
                Some(crate::sorafs::orderbook::OrderbookFinalizedEventCursorV1 {
                    sequence: 2,
                    block_height: 7,
                    block_hash: [0xA7; 32],
                    event_index: 1,
                }),
                25,
            )
            .into(),
            sorafs::prelude::FindSorafsReservePolicy.into(),
            sorafs::prelude::FindSorafsReserveProviderById::new(
                crate::sorafs::capacity::ProviderId::new([0x1B; 32]),
            )
            .into(),
            sorafs::prelude::FindSorafsReserveMovementById::new([0x1C; 32]).into(),
            sorafs::prelude::FindSorafsReserveAppealById::new([0x1D; 32]).into(),
            sorafs::prelude::FindSorafsReserveProviders::new(
                Some(reserve_cursor),
                Some(crate::sorafs::capacity::ProviderId::new([0x1E; 32])),
                25,
            )
            .into(),
            sorafs::prelude::FindSorafsReserveMovements::new(
                Some(reserve_cursor),
                Some([0x1F; 32]),
                25,
            )
            .into(),
            sorafs::prelude::FindSorafsReserveAppeals::new(
                Some(reserve_cursor),
                Some([0x20; 32]),
                25,
            )
            .into(),
            sorafs::prelude::FindSorafsReserveEvents::new(
                Some(reserve_cursor),
                Some(crate::sorafs::reserve::ReserveFinalizedEventCursorV1 {
                    sequence: 3,
                    block_height: 7,
                    block_hash: reserve_cursor.block_hash,
                    event_index: 2,
                }),
                25,
            )
            .into(),
            sorafs::prelude::FindSorafsCitizenBondBySerialCommitment::new([0x21; 32]).into(),
            sorafs::prelude::FindSorafsCitizenBondSnapshot.into(),
            sorafs::prelude::FindSorafsPinManifest::new(
                crate::sorafs::pin_registry::ManifestDigest::new([0x24; 32]),
                Some(pin_cursor),
            )
            .into(),
            sorafs::prelude::FindSorafsPinManifests::new(
                Some(pin_cursor),
                Some(crate::sorafs::pin_registry::PinStatusKindV1::Approved),
                Some(crate::sorafs::pin_registry::ManifestDigest::new([0x25; 32])),
                25,
                16 * 1024,
            )
            .into(),
            sorafs::prelude::FindSorafsRepairTask::new("REP-1".to_owned(), Some(repair_cursor))
                .into(),
            sorafs::prelude::FindSorafsRepairTasks::new(Some(repair_cursor), Some([0x23; 32]), 25)
                .into(),
            sorafs::prelude::FindSorafsRepairStatus::new(Some(repair_cursor)).into(),
            sorafs::prelude::FindSorafsRepairEvents::new(
                Some(repair_cursor),
                Some(
                    crate::sorafs::moderation_ledger::RepairFinalizedEventCursorV1 {
                        sequence: 6,
                        block_height: 8,
                        block_hash: [0xA8; 32],
                        event_index: 2,
                    },
                ),
                25,
            )
            .into(),
            sorafs::prelude::FindSorafsProofOutcome::new(
                crate::sorafs::proof_ledger::ProofOutcomeKindV1::Pdp,
                [0x24; 32],
                Some(proof_outcome_cursor),
            )
            .into(),
            sorafs::prelude::FindSorafsProofOutcomeEvents::new(
                Some(proof_outcome_cursor),
                Some(
                    crate::sorafs::proof_ledger::ProofOutcomeFinalizedEventCursorV1 {
                        sequence: 7,
                        block_height: 9,
                        block_hash: [0xA9; 32],
                        event_index: 0,
                    },
                ),
                25,
            )
            .into(),
            sorafs::prelude::FindSorafsReputationJournalAuthorityPolicy.into(),
            sorafs::prelude::FindSorafsReputationJournalEventBySourceId::new(
                crate::sorafs::reputation::ReputationJournalSourceIdV1([0x25; 32]),
                Some(reputation_cursor),
            )
            .into(),
            sorafs::prelude::FindSorafsReputationJournalEvents::new(
                Some(reputation_cursor),
                Some(
                    crate::sorafs::reputation::ReputationJournalFinalizedEventCursorV1 {
                        sequence: 8,
                        block_height: 10,
                        block_hash: reputation_cursor.block_hash,
                        event_index: 1,
                    },
                ),
                25,
            )
            .into(),
            sorafs::prelude::FindSorafsModerationPolicy.into(),
            sorafs::prelude::FindSorafsModerationAppeal::new(
                "case-1".to_owned(),
                "round-1".to_owned(),
            )
            .into(),
            sorafs::prelude::FindSorafsModerationCase::new(
                "case-1".to_owned(),
                "round-1".to_owned(),
            )
            .into(),
            sorafs::prelude::FindSorafsModerationCommit::new(
                "case-1".to_owned(),
                "round-1".to_owned(),
                juror.clone(),
            )
            .into(),
            sorafs::prelude::FindSorafsModerationReveal::new(
                "case-1".to_owned(),
                "round-1".to_owned(),
                juror.clone(),
            )
            .into(),
            sorafs::prelude::FindSorafsModerationChallenge::new(
                "case-1".to_owned(),
                "round-1".to_owned(),
                "challenge-1".to_owned(),
            )
            .into(),
            sorafs::prelude::FindSorafsModerationOutcome::new(
                "case-1".to_owned(),
                "round-1".to_owned(),
            )
            .into(),
            sorafs::prelude::FindSorafsModerationNoShow::new(
                "case-1".to_owned(),
                "round-1".to_owned(),
                juror,
            )
            .into(),
            sorafs::prelude::FindSorafsModerationStatus.into(),
            sorafs::prelude::FindSorafsModerationSnapshot::new(64, 128).into(),
            sorafs::prelude::FindSorafsModerationEvents::new(
                crate::sorafs::moderation_ledger::ModerationFinalizedCursorV1 {
                    height: 9,
                    block_hash: [0x31; 32],
                },
                Some(
                    crate::sorafs::moderation_ledger::ModerationFinalizedEventCursorV1 {
                        sequence: 12,
                        block_height: 8,
                        block_hash: [0x32; 32],
                        event_index: 2,
                    },
                ),
                25,
            )
            .into(),
        ];
        for query in queries {
            let encoded = query.encode();
            let mut bytes = encoded.as_slice();
            let decoded = SingularQueryBox::decode(&mut bytes).expect("decode orderbook query");
            assert!(bytes.is_empty(), "decoder must consume the whole query");
            assert_eq!(decoded, query);
        }
    }
    #[test]
    fn query_output_batch_box_json_roundtrip() {
        let batch = QueryOutputBatchBox::String(vec!["hello".to_owned()]);
        let as_value = json::to_value(&batch).expect("serialize batch");
        assert_eq!(
            as_value,
            norito::json!({ "kind": "String", "content": ["hello"] })
        );
        let decoded: QueryOutputBatchBox = json::from_value(as_value).expect("deserialize batch");
        assert_eq!(decoded, batch);
    }
    #[test]
    fn query_response_iterable_json_roundtrip() {
        let cursor = parameters::ForwardCursor {
            query: "query-id".to_owned(),
            cursor: NonZeroU64::new(1).expect("nonzero"),
            gas_budget: None,
        };
        let output = QueryOutput {
            batch: QueryOutputBatchBoxTuple::from_batch(QueryOutputBatchBox::Numeric(vec![
                Numeric::from(42_u32),
            ])),
            remaining_items: Some(0),
            has_more: true,
            continue_cursor: Some(cursor),
        };
        let response = QueryResponse::Iterable(output.clone());
        let as_value = json::to_value(&response).expect("serialize response");
        let decoded: QueryResponse =
            json::from_value(as_value.clone()).expect("deserialize response");
        assert_eq!(decoded, response);
        // Ensure JSON structure exposes iterable wrapper with batch payload.
        match as_value {
            json::Value::Object(map) => {
                assert_eq!(map.get("kind"), Some(&norito::json!("Iterable")));
                assert!(map.contains_key("content"));
            }
            other => panic!("expected object for iterable response, got {other:?}"),
        }
    }
}
