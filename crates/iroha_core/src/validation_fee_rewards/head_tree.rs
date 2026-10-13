//! Incremental compressed sparse commitment to all current canonical wallet heads.
//! Only branching prefixes are stored (at most N-1 for N wallets); leaf shortcuts
//! retain the native 256-level SMT hash without allocating a path per wallet.
use crate::execution_attempt::{ExecutionAttemptError, norito_decode_attempt_error};
use crate::state::{WorldReadOnly, WorldTransaction};
use iroha_crypto::Hash;
use iroha_data_model::{
    fee_evidence::{
        retail_fee_head_leaf_hash_v1, retail_fee_head_node_hash_v1, retail_fee_head_path_v1,
    },
    validation_fee::RetailFeeReceiptHeadV1,
};
use iroha_model_base::state_path::StatePath;
use mv::storage::StorageReadOnly;
use norito::codec::{Decode, Encode};

const PREFIX: &str = "retail_fee_head_tree_v1";
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::validation_fee_rewards::head_tree::NodeRef")]
struct NodeRef {
    path: [u8; 32],
    depth: u16,
    hash: Hash,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::validation_fee_rewards::head_tree::Branch")]
struct Branch {
    left: NodeRef,
    right: NodeRef,
}
fn root_key() -> StatePath {
    format!("{PREFIX}/Root")
        .parse()
        .expect("fixed native head root key")
}
fn node_key(node: NodeRef) -> Result<StatePath, ExecutionAttemptError<String>> {
    format!("{PREFIX}/Node/{:03}/{}", node.depth, hex::encode(node.path))
        .parse()
        .map_err(|e| ExecutionAttemptError::Rejected(format!("head tree path: {e}")))
}
fn right(path: &[u8; 32], bit: u16) -> bool {
    path[usize::from(bit / 8)] & (1 << (bit % 8)) != 0
}
fn prefix(mut path: [u8; 32], depth: u16) -> [u8; 32] {
    for bit in depth..256 {
        path[usize::from(bit / 8)] &= !(1 << (bit % 8));
    }
    path
}
fn expand(node: NodeRef, depth: u16) -> Result<Hash, ExecutionAttemptError<String>> {
    if depth > node.depth || node.depth > 256 {
        return Err(ExecutionAttemptError::Rejected(
            "invalid compressed head-tree depth".into(),
        ));
    }
    let mut current = node.hash;
    let empty = Hash::new([]);
    for bit in (depth..node.depth).rev() {
        current = if right(&node.path, bit) {
            retail_fee_head_node_hash_v1(empty, current)
        } else {
            retail_fee_head_node_hash_v1(current, empty)
        };
    }
    Ok(current)
}
fn read_root(world: &impl WorldReadOnly) -> Result<Option<NodeRef>, ExecutionAttemptError<String>> {
    world
        .smart_contract_state()
        .get(&root_key())
        .map(|b| {
            norito::decode_canonical(b)
                .map_err(|error| norito_decode_attempt_error(error, |error| error.to_string()))
        })
        .transpose()
}
fn read_branch(
    world: &impl WorldReadOnly,
    node: NodeRef,
) -> Result<Branch, ExecutionAttemptError<String>> {
    if node.depth >= 256 || prefix(node.path, node.depth) != node.path {
        return Err(ExecutionAttemptError::Rejected(
            "invalid protected head-tree branch".into(),
        ));
    }
    let branch: Branch = norito::decode_canonical(
        world
            .smart_contract_state()
            .get(&node_key(node)?)
            .ok_or_else(|| "missing protected head-tree branch".to_owned())?,
    )
    .map_err(|error| norito_decode_attempt_error(error, |error| error.to_string()))?;
    if branch.left.depth <= node.depth
        || branch.right.depth <= node.depth
        || prefix(branch.left.path, node.depth) != node.path
        || prefix(branch.right.path, node.depth) != node.path
        || right(&branch.left.path, node.depth)
        || !right(&branch.right.path, node.depth)
        || retail_fee_head_node_hash_v1(
            expand(branch.left, node.depth + 1)?,
            expand(branch.right, node.depth + 1)?,
        ) != node.hash
    {
        return Err(ExecutionAttemptError::Rejected(
            "protected head-tree branch/hash is inconsistent".into(),
        ));
    }
    Ok(branch)
}
fn store_branch(
    world: &mut WorldTransaction<'_, '_>,
    path: [u8; 32],
    depth: u16,
    branch: Branch,
) -> Result<NodeRef, ExecutionAttemptError<String>> {
    let node = NodeRef {
        path: prefix(path, depth),
        depth,
        hash: retail_fee_head_node_hash_v1(
            expand(branch.left, depth + 1)?,
            expand(branch.right, depth + 1)?,
        ),
    };
    world.smart_contract_state.insert(
        node_key(node)?,
        norito::to_bytes(&branch)
            .map_err(|error| norito_decode_attempt_error(error, |error| error.to_string()))?,
    );
    Ok(node)
}
fn update(
    world: &mut WorldTransaction<'_, '_>,
    node: NodeRef,
    leaf: NodeRef,
) -> Result<NodeRef, ExecutionAttemptError<String>> {
    if node.depth > 256 {
        return Err(ExecutionAttemptError::Rejected(
            "invalid native head-tree depth".into(),
        ));
    }
    let common = (0..node.depth)
        .find(|bit| right(&node.path, *bit) != right(&leaf.path, *bit))
        .unwrap_or(node.depth);
    if common < node.depth {
        let branch = if right(&leaf.path, common) {
            Branch {
                left: node,
                right: leaf,
            }
        } else {
            Branch {
                left: leaf,
                right: node,
            }
        };
        return store_branch(world, leaf.path, common, branch);
    }
    if node.depth == 256 {
        return Ok(leaf);
    }
    let mut branch = read_branch(world, node)?;
    if right(&leaf.path, node.depth) {
        branch.right = update(world, branch.right, leaf)?;
    } else {
        branch.left = update(world, branch.left, leaf)?;
    }
    store_branch(world, node.path, node.depth, branch)
}
/// Update the cumulative wallet-head commitment atomically with a native head write.
pub(crate) fn update_receipt_head_tree(
    world: &mut WorldTransaction<'_, '_>,
    head: &RetailFeeReceiptHeadV1,
) -> Result<(), ExecutionAttemptError<String>> {
    if head.updated_at_height == 0 || (head.sequence == 0) != head.last_receipt_hash.is_none() {
        return Err(ExecutionAttemptError::Rejected(
            "invalid native receipt head".into(),
        ));
    }
    let leaf = NodeRef {
        path: retail_fee_head_path_v1(&head.wallet_id)?,
        depth: 256,
        hash: retail_fee_head_leaf_hash_v1(head)?,
    };
    let root = match read_root(world)? {
        Some(root) => update(world, root, leaf)?,
        None => leaf,
    };
    world.smart_contract_state.insert(
        root_key(),
        norito::to_bytes(&root)
            .map_err(|error| norito_decode_attempt_error(error, |error| error.to_string()))?,
    );
    Ok(())
}
/// Read the current cumulative commitment without scanning wallets or cold history.
pub(crate) fn receipt_head_root(
    world: &impl WorldReadOnly,
) -> Result<Hash, ExecutionAttemptError<String>> {
    read_root(world)?
        .map(|root| expand(root, 0))
        .transpose()
        .map(|root| root.unwrap_or_else(|| Hash::new([])))
}
/// Build a private current-state head membership proof in at most 256 branches.
/// The caller must match the returned root to immutable finality before responding.
///
/// # Errors
/// Returns an error if the wallet path or leaf cannot be derived, retained
/// tree data is missing or malformed, the wallet/head does not match the tree,
/// or traversal exceeds its depth bound. Original decoder refusals are preserved.
pub fn receipt_head_membership(
    world: &impl WorldReadOnly,
    head: &RetailFeeReceiptHeadV1,
) -> Result<(Hash, Vec<Hash>), ExecutionAttemptError<String>> {
    let path = retail_fee_head_path_v1(&head.wallet_id)?;
    let mut node =
        read_root(world)?.ok_or_else(|| "native cumulative head tree is absent".to_owned())?;
    let root = expand(node, 0)?;
    let mut siblings = vec![Hash::new([]); 256];
    for _ in 0..=256 {
        if node.depth > 256 || prefix(path, node.depth) != node.path {
            return Err(ExecutionAttemptError::Rejected(
                "requested wallet is absent from cumulative head tree".into(),
            ));
        }
        if node.depth == 256 {
            if node.hash != retail_fee_head_leaf_hash_v1(head)? {
                return Err(ExecutionAttemptError::Rejected(
                    "current wallet head changed while constructing its proof".into(),
                ));
            }
            return Ok((root, siblings));
        }
        let branch = read_branch(world, node)?;
        let (next, sibling) = if right(&path, node.depth) {
            (branch.right, branch.left)
        } else {
            (branch.left, branch.right)
        };
        siblings[255 - usize::from(node.depth)] = expand(sibling, node.depth + 1)?;
        node = next;
    }
    Err(ExecutionAttemptError::Rejected(
        "native head-tree traversal exceeded depth".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::{
        account::AccountId,
        block::{
            BlockHeader,
            consensus::{ExecKv, ExecWitness},
        },
        fee_evidence::{
            FEE_EVIDENCE_WITNESS_KEY_V1, FeeEvidenceSnapshotV1, RetailFeeCurrentHeadProofV1,
        },
    };
    use std::collections::BTreeMap;
    fn account(seed: u8) -> AccountId {
        AccountId::new(
            iroha_crypto::KeyPair::from_seed(vec![seed; 32], iroha_crypto::Algorithm::Ed25519)
                .public_key()
                .clone(),
        )
    }
    #[test]
    fn compressed_current_head_tree_matches_native_smt_and_bootstraps_dormant_wallets() {
        let state = crate::state::State::new_for_testing(
            crate::state::World::with([], [], []),
            crate::kura::Kura::blank_kura_for_testing(),
            crate::query::store::LiveQueryStore::start_test(),
        );
        let mut block = state.block(BlockHeader::new(
            std::num::NonZeroU64::new(10).unwrap(),
            None,
            None,
            1_793_451_600_000,
            0,
        ));
        let mut stx = block.transaction();
        let mut heads = BTreeMap::new();
        for seed in 20..28 {
            let wallet = account(seed);
            let head = RetailFeeReceiptHeadV1 {
                wallet_id: wallet.clone(),
                current_account_id: wallet.clone(),
                sequence: 0,
                last_receipt_hash: None,
                updated_at_height: 1,
            };
            update_receipt_head_tree(&mut stx.world, &head).unwrap();
            heads.insert(wallet, head);
            let ordinary = heads
                .values()
                .map(|head| {
                    crate::exec_witness::smt::KvPair::new(
                        iroha_data_model::validation_fee::retail_fee_receipt_head_state_key_v1(
                            &head.wallet_id,
                        )
                        .unwrap()
                        .as_ref()
                        .as_bytes()
                        .to_vec(),
                        norito::encode_canonical(head).unwrap(),
                    )
                })
                .collect::<Vec<_>>();
            assert_eq!(
                receipt_head_root(&stx.world).unwrap(),
                crate::exec_witness::smt::compute_post_state_root(&[], &ordinary)
            );
        }
        let wallet = account(20);
        let mut tampered_value = heads[&wallet].clone();
        tampered_value.sequence = 1;
        tampered_value.last_receipt_hash = Some([7; 32]);
        tampered_value.updated_at_height = 10;
        tampered_value.current_account_id = account(99);
        update_receipt_head_tree(&mut stx.world, &tampered_value).unwrap();
        heads.insert(wallet.clone(), tampered_value.clone());
        let nodes = stx
            .world
            .smart_contract_state
            .iter()
            .filter(|(key, _)| key.as_ref().starts_with("retail_fee_head_tree_v1/"))
            .count();
        assert_eq!(
            nodes,
            heads.len(),
            "one root plus at most N-1 compressed branches; updating a head creates no history leak"
        );
        let mut snapshot = FeeEvidenceSnapshotV1::from_records(10, &[]).unwrap();
        snapshot.account_heads_root = receipt_head_root(&stx.world).unwrap();
        let witness = ExecWitness {
            writes: vec![ExecKv {
                key: FEE_EVIDENCE_WITNESS_KEY_V1.to_vec(),
                value: norito::to_bytes(&snapshot).unwrap(),
            }],
            ..Default::default()
        };
        let (block_proof, ordinary_root) =
            crate::receiver_snapshot::fee_evidence_block_proof_v1(&witness).unwrap();
        for head in heads.values() {
            let (root, siblings) = receipt_head_membership(&stx.world, head).unwrap();
            assert_eq!(root, snapshot.account_heads_root);
            let proof = RetailFeeCurrentHeadProofV1 {
                snapshot_witness: block_proof.snapshot_witness.clone(),
                head: head.clone(),
                head_siblings: siblings,
            };
            let cursor = proof
                .verify(ordinary_root, &head.wallet_id, &head.current_account_id, 10)
                .unwrap();
            assert_eq!(cursor.next_sequence, head.sequence);
            let mut corrupt = proof.clone();
            corrupt.head_siblings[0] = Hash::new(b"wrong-head-branch");
            assert!(
                corrupt
                    .verify(ordinary_root, &head.wallet_id, &head.current_account_id, 10)
                    .is_err()
            );
            assert!(
                proof
                    .verify(ordinary_root, &head.wallet_id, &account(101), 10)
                    .is_err()
            );
        }
        let mut outdated = tampered_value;
        outdated.last_receipt_hash = Some([8; 32]);
        assert!(receipt_head_membership(&stx.world, &outdated).is_err());
    }
}
