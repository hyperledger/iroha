//! Native TON graph and signature attempts retain the original physical allocation custody.

use super::*;
use crate::native_memory::AttemptError;
use iroha_allocation::{AllocationBudget, ChargedBufferError};

#[test]
fn every_tiny_canonical_graph_refusal_releases_original_backing_before_retry() {
    let bytes = [0xb5, 0xee, 0x9c, 0x72, 1, 1, 1, 1, 0, 2, 0, 0, 0];
    let root = ton_canonical_boc_single_root_hash_v1(&bytes).unwrap();
    let mut first_success = None;
    for limit in 0..4096 {
        let budget = AllocationBudget::new(limit);
        let memory = Memory::admitted(&budget);
        match memory.finish(ton_open_canonical_with(&bytes, &root, &memory)) {
            Ok((boc, computed, index)) => {
                assert_eq!(ton_proven_root_hash(&boc, &computed, index), Some(root));
                assert!(
                    budget.reserved_bytes() > 0,
                    "actual graph and hashes remain charged"
                );
                assert!(matches!(boc.cells, Buffer::Admitted(_)));
                assert!(matches!(boc.roots, Buffer::Admitted(_)));
                assert!(matches!(boc.cells[0].data, Buffer::Admitted(_)));
                assert!(matches!(boc.cells[0].refs, Buffer::Admitted(_)));
                drop((boc, computed));
                assert_eq!(budget.reserved_bytes(), 0);
                first_success = Some(limit);
                break;
            }
            Err(AttemptError::Allocation(ChargedBufferError::Admission(_))) => {
                assert_eq!(
                    budget.reserved_bytes(),
                    0,
                    "partial graph must retire on refusal"
                );
            }
            other => panic!("unexpected bounded attempt: {other:?}"),
        }
    }
    assert!(first_success.is_some_and(|limit| limit > size_of::<TonBocCell>()));
    let budget = AllocationBudget::new(first_success.unwrap());
    let memory = Memory::admitted(&budget);
    let owner = memory
        .finish(ton_open_canonical_with(&bytes, &root, &memory))
        .unwrap();
    let moved = owner;
    assert!(budget.reserved_bytes() > 0);
    drop(moved);
    assert_eq!(budget.reserved_bytes(), 0);
    let mut foreign = root;
    foreign[0] ^= 1;
    assert!(matches!(
        memory.finish(ton_open_canonical_with(&bytes, &foreign, &memory)),
        Err(AttemptError::Protocol(TonNativeSourceError::InvalidBoc))
    ));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn captured_masterchain_config_and_signature_use_one_original_pool() {
    use crate::test_support::ton_capture::{forward_link, key_block_config};
    let config = key_block_config();
    let link = forward_link("get_block_proof_forward");
    let budget = AllocationBudget::new(64 * 1024 * 1024);
    let memory = Memory::admitted(&budget);
    let (header, _) = memory
        .finish(ton_open_masterchain_block_with(
            config.block,
            &config.state_proof,
            None,
            &memory,
        ))
        .unwrap();
    assert_eq!(
        budget.reserved_bytes(),
        0,
        "header is fixed and releases graph scratch"
    );
    let epoch = memory
        .finish(ton_open_state_config_with(
            &header.new_state_hash.unwrap(),
            &config.config_proof,
            &memory,
        ))
        .unwrap();
    let retained = budget.reserved_bytes();
    assert_eq!(
        retained,
        epoch.validators.validators.len() * size_of::<TonValidatorV1>()
    );
    let (block, _) = memory
        .finish(ton_open_masterchain_block_with(
            link.to,
            &link.dest_proof,
            None,
            &memory,
        ))
        .unwrap();
    memory
        .finish(ton_verify_masterchain_signatures_with(
            &block,
            epoch.validators.as_ref(),
            &link.signatures,
            &memory,
        ))
        .unwrap();
    assert_eq!(
        budget.reserved_bytes(),
        retained,
        "signature scratch retires before success"
    );
    drop(epoch);
    assert_eq!(budget.reserved_bytes(), 0);

    let empty = AllocationBudget::new(0);
    let refusal = Memory::admitted(&empty);
    assert!(matches!(
        refusal.finish(ton_open_masterchain_block_with(
            config.block,
            &config.state_proof,
            None,
            &refusal
        )),
        Err(AttemptError::Allocation(ChargedBufferError::Admission(_)))
    ));
    assert_eq!(empty.reserved_bytes(), 0);
}
