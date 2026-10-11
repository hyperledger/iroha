//! Wallet preflight and real canonical transfer/redemption workflow tests.

use super::*;
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::block::BlockHeader;

fn context() -> (NetworkId, AssetDefinitionId) {
    (
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
            b"confidential-wallet-local-test",
        ))),
        AssetDefinitionId::from_uuid_bytes([
            1, 2, 3, 4, 5, 6, 0x47, 8, 0x89, 10, 11, 12, 13, 14, 15, 16,
        ])
        .unwrap(),
    )
}

fn input(amount: u128, leaf_index: usize) -> native::ConfidentialUnshieldInputV2 {
    native::ConfidentialUnshieldInputV2 {
        amount,
        rho: [92; 32],
        diversifier: native::default_confidential_diversifier_v2(),
        leaf_index,
    }
}

#[test]
fn context_rejects_zero_key_and_redacts_private_state() {
    let (network, asset) = context();
    assert_eq!(
        ConfidentialProver::new(network, &asset, Zeroizing::new([0; 32])).unwrap_err(),
        ConfidentialProverError::InvalidSpendKey
    );
    let prover = ConfidentialProver::new(network, &asset, Zeroizing::new([91; 32])).unwrap();
    assert_eq!(
        format!("{prover:?}"),
        "ConfidentialProver { private_context: [REDACTED] }"
    );
}

#[test]
fn saved_change_conversion_checks_shape_and_uses_the_default_owner() {
    let change = || native::ConfidentialUnshieldOutputV3 {
        amount: 3,
        rho: [94; 32],
    };
    let input = change().into_input(65_535).unwrap();
    assert_eq!(input.amount, 3);
    assert_eq!(input.rho, [94; 32]);
    assert_eq!(input.leaf_index, 65_535);
    assert_eq!(
        input.diversifier,
        native::default_confidential_diversifier_v2()
    );
    for index in [65_536, usize::MAX] {
        assert_eq!(
            change().into_input(index).unwrap_err(),
            ConfidentialProverError::InputIndex
        );
    }
    assert_eq!(
        native::ConfidentialUnshieldOutputV3 {
            amount: 0,
            rho: [94; 32],
        }
        .into_input(0)
        .unwrap_err(),
        ConfidentialProverError::InvalidInputAmounts
    );
}

#[test]
fn tree_rejects_missing_duplicate_and_over_capacity_notes_before_proving() {
    let leaves = [[1; 32], [2; 32]];
    let tree = ConfidentialTree::Commitments {
        root: [3; 32],
        leaves: &leaves,
    };
    assert!(tree.validate([0].into_iter()).is_ok());
    assert!(tree.validate([0, 1].into_iter()).is_ok());
    assert!(tree.validate([].into_iter()).is_err());
    assert!(tree.validate([0, 1, 2].into_iter()).is_err());
    assert!(tree.validate([0, 0].into_iter()).is_err());
    assert!(tree.validate([2].into_iter()).is_err());
    let oversized = vec![[0; 32]; (1 << native::CONFIDENTIAL_TREE_DEPTH_V2) + 1];
    assert!(
        ConfidentialTree::Commitments {
            root: [0; 32],
            leaves: &oversized
        }
        .validate([0].into_iter())
        .is_err()
    );
    let mut paths = [native::compute_confidential_merkle_path_v2(&leaves, 0).unwrap()];
    let root = paths[0].root;
    assert!(
        ConfidentialTree::Paths {
            root,
            paths: &paths
        }
        .validate([0].into_iter())
        .is_ok()
    );
    assert_eq!(
        ConfidentialTree::Paths {
            root,
            paths: &paths
        }
        .validate([1].into_iter()),
        Err(ConfidentialProverError::PathIndexMismatch),
        "a valid path for leaf zero cannot describe leaf one",
    );
    assert!(
        ConfidentialTree::Paths {
            root,
            paths: &paths
        }
        .validate([0, 1].into_iter())
        .is_err()
    );
    assert!(
        ConfidentialTree::Paths {
            root: [0; 32],
            paths: &paths
        }
        .validate([0].into_iter())
        .is_err()
    );
    paths[0].witness_nodes.clear();
    assert!(
        ConfidentialTree::Paths {
            root,
            paths: &paths
        }
        .validate([0].into_iter())
        .is_ok()
    );
    paths[0].witness_nodes.push([0; 32]);
    assert!(
        ConfidentialTree::Paths {
            root,
            paths: &paths
        }
        .validate([0].into_iter())
        .is_err()
    );
    paths[0].witness_nodes.clear();
    paths[0].directions[0] = 2;
    assert!(
        ConfidentialTree::Paths {
            root,
            paths: &paths
        }
        .validate([0].into_iter())
        .is_err()
    );
}

#[test]
fn invalid_transfer_and_redemption_fail_before_key_preparation() {
    let (network, asset) = context();
    let prover = ConfidentialProver::new(network, &asset, Zeroizing::new([91; 32])).unwrap();
    let leaves = [[1; 32], [2; 32]];
    let tree = || ConfidentialTree::Commitments {
        root: [0; 32],
        leaves: &leaves,
    };
    let transfer_input = native::ConfidentialTransferInputV2 {
        amount: 9,
        rho: [1; 32],
        diversifier: [1; 32],
        leaf_index: 0,
    };
    assert_eq!(
        prover
            .prove_transfer(tree(), vec![transfer_input.clone()], vec![])
            .unwrap_err(),
        ConfidentialProverError::OutputCount
    );
    for amount in [0, 8, 10] {
        let output = native::ConfidentialTransferOutputV2 {
            amount,
            rho: [2; 32],
            owner_tag: [3; 32],
        };
        assert_eq!(
            prover
                .prove_transfer(tree(), vec![transfer_input.clone()], vec![output])
                .unwrap_err(),
            ConfidentialProverError::InvalidTransferAmounts
        );
    }
    assert!(
        prover
            .prove_unshield(tree(), vec![input(9, 0)], 10, None)
            .is_err()
    );
    assert!(
        prover
            .prove_unshield(tree(), vec![input(9, 0)], 0, None)
            .is_err()
    );
    assert_eq!(
        prover
            .prove_unshield(tree(), vec![input(0, 0), input(9, 1)], 9, None)
            .unwrap_err(),
        ConfidentialProverError::InvalidInputAmounts
    );
    assert_eq!(
        prover
            .prove_unshield(tree(), vec![input(9, 0)], 4, None)
            .unwrap_err(),
        ConfidentialProverError::InvalidChange
    );
    assert!(
        prover
            .prove_unshield(
                tree(),
                vec![input(9, 0)],
                9,
                Some(native::ConfidentialUnshieldOutputV3 {
                    amount: 0,
                    rho: [1; 32]
                })
            )
            .is_err()
    );
    assert!(
        prover
            .prove_unshield(tree(), vec![input(u128::MAX, 0), input(1, 1)], 1, None)
            .is_err()
    );
}

#[test]
fn canonical_wallet_proves_transfer_full_redemption_and_private_change() {
    let (network, asset) = context();
    let prover = ConfidentialProver::new(network, &asset, Zeroizing::new([91; 32])).unwrap();
    let note = input(9, 0);
    let owner =
        native::derive_confidential_owner_tag_v2_with_diversifier(&[91; 32], note.diversifier)
            .unwrap();
    let commitment =
        native::derive_confidential_note_v2(&asset.to_string(), 9, note.rho, owner).unwrap();
    let leaves = [commitment];
    let paths = [native::compute_confidential_merkle_path_v2(&leaves, 0).unwrap()];
    let root = paths[0].root;
    let transfer = prover
        .prove_transfer(
            ConfidentialTree::Commitments {
                root,
                leaves: &leaves,
            },
            vec![native::ConfidentialTransferInputV2 {
                amount: 9,
                rho: note.rho,
                diversifier: note.diversifier,
                leaf_index: 0,
            }],
            vec![native::ConfidentialTransferOutputV2 {
                amount: 9,
                rho: [93; 32],
                owner_tag: owner,
            }],
        )
        .unwrap();
    let full = prover
        .prove_unshield(
            ConfidentialTree::Paths {
                root,
                paths: &paths,
            },
            vec![input(9, 0)],
            9,
            None,
        )
        .unwrap();
    let change = prover
        .prove_unshield(
            ConfidentialTree::Paths {
                root,
                paths: &paths,
            },
            vec![input(9, 0)],
            4,
            Some(native::ConfidentialUnshieldOutputV3 {
                amount: 5,
                rho: [94; 32],
            }),
        )
        .unwrap();
    assert_eq!(transfer.relation, ProofRelation::ConfidentialTransfer);
    assert_eq!(full.relation, ProofRelation::ConfidentialFullUnshield);
    assert_eq!(change.relation, ProofRelation::ConfidentialChangeUnshield);
    assert_eq!(transfer.output_commitments.len(), 1);
    assert!(full.output_commitments.is_empty());
    assert_eq!(change.output_commitments.len(), 1);
    for result in [&transfer, &full, &change] {
        assert_eq!(result.root, root);
        assert_eq!(result.nullifiers.len(), 1);
        let key = match result.relation {
            ProofRelation::ConfidentialTransfer => native::confidential_transfer_v2_vk_box(),
            ProofRelation::ConfidentialFullUnshield => native::confidential_unshield_v2_vk_box(),
            ProofRelation::ConfidentialChangeUnshield => native::confidential_unshield_v3_vk_box(),
            _ => unreachable!("only confidential wallet relations"),
        }
        .unwrap();
        let policy = crate::ZkVerifyGuardrails {
            pipa_r_enabled: true,
            pipa_r_max_envelope_bytes: 8 * 1024 * 1024,
            pipa_r_max_proof_bytes: 8 * 1024 * 1024,
            stark_enabled: false,
            stark_max_envelope_bytes: 0,
            stark_max_proof_bytes: 0,
        };
        crate::verify_for_relation(result.relation, &result.proof, &key, policy).unwrap();
    }
}

#[test]
fn retained_change_from_a_nondefault_input_can_be_fully_redeemed() {
    let (network, asset) = context();
    let prover = ConfidentialProver::new(network, &asset, Zeroizing::new([91; 32])).unwrap();
    let mut original = input(7, 0);
    original.diversifier = native::derive_confidential_diversifier_v2(b"nondefault-wallet-input");
    assert_ne!(
        original.diversifier,
        native::default_confidential_diversifier_v2()
    );
    let owner =
        native::derive_confidential_owner_tag_v2_with_diversifier(&[91; 32], original.diversifier)
            .unwrap();
    let commitment = native::derive_confidential_note_v2(
        &asset.to_string(),
        original.amount,
        original.rho,
        owner,
    )
    .unwrap();
    let leaves = [commitment];
    let root = native::compute_confidential_root_v2(&leaves).unwrap();
    let change = native::ConfidentialUnshieldOutputV3 {
        amount: 3,
        rho: [94; 32],
    };
    // Model restoring an opening persisted securely before proof construction.
    let saved_change = change.clone();
    let first = prover
        .prove_unshield(
            ConfidentialTree::Commitments {
                root,
                leaves: &leaves,
            },
            vec![original],
            4,
            Some(change),
        )
        .unwrap();
    assert_eq!(first.relation, ProofRelation::ConfidentialChangeUnshield);
    assert_eq!(first.output_commitments.len(), 1);

    let next = saved_change.into_input(0).unwrap();
    let next_owner =
        native::derive_confidential_owner_tag_v2_with_diversifier(&[91; 32], next.diversifier)
            .unwrap();
    assert_ne!(next_owner, owner);
    let next_commitment =
        native::derive_confidential_note_v2(&asset.to_string(), next.amount, next.rho, next_owner)
            .unwrap();
    assert_eq!(first.output_commitments, [next_commitment]);
    let next_leaves = [next_commitment];
    let next_root = native::compute_confidential_root_v2(&next_leaves).unwrap();
    let second = prover
        .prove_unshield(
            ConfidentialTree::Commitments {
                root: next_root,
                leaves: &next_leaves,
            },
            vec![next],
            3,
            None,
        )
        .unwrap();
    assert_eq!(second.relation, ProofRelation::ConfidentialFullUnshield);
    assert_eq!(second.root, next_root);
    assert!(second.output_commitments.is_empty());
    assert_ne!(first.nullifiers, second.nullifiers);
}
