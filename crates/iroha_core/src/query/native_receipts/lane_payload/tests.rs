//! Real original carrier authentication and exact archive-byte refusal custody.
use super::*;
use crate::{
    query::native_context_archive::NativeContextArchive,
    state::{NativeExecutionProjectionV1, World},
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};

fn source(chain: &CertifiedTestChain, height: u64, budget: &AllocationBudget) -> ChargedBuffer<u8> {
    let archive = NativeContextArchive::open_existing(
        chain.kura(),
        budget.clone(),
        chain.kura().native_context_archive_max_bytes(),
    )
    .unwrap();
    archive
        .read_exact(height, chain.committed(height).block().hash())
        .unwrap()
}
fn chain() -> CertifiedTestChain {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    chain.commit(Vec::new());
    chain.commit(Vec::new());
    chain
}

#[test]
fn lane_payload_keeps_the_exact_original_source_and_refunds_temporary_graphs() {
    let chain = chain();
    let budget = AllocationBudget::new(64 << 20);
    let bytes = source(&chain, 2, &budget);
    let pointer = bytes.as_slice().as_ptr();
    let length = bytes.as_slice().len();
    let projection: NativeExecutionProjectionV1 =
        norito::decode_canonical(bytes.as_slice()).unwrap();
    let read = LanePayloadRead::new(
        bytes,
        budget.clone(),
        chain.network_id(),
        &chain.committed(2),
    );
    let owner = read
        .authenticate()
        .unwrap_or_else(|(_, error)| panic!("original lane payload: {error}"));
    assert_eq!(owner.bytes.as_slice().as_ptr(), pointer);
    assert_eq!(
        owner.payload(),
        norito::codec::Encode::encode(&projection.lanes)
    );
    assert_eq!(
        owner.carrier(),
        (chain.network_id(), 2, chain.committed(2).block().hash())
    );
    assert!(owner.belongs_to(&budget));
    assert!(owner.lane_record(&[1; 32]).unwrap().is_none());
    assert!(!owner.belongs_to(&AllocationBudget::new(64 << 20)));
    assert_eq!(budget.reserved_bytes(), length);
    drop(owner);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn lane_payload_refusal_retains_source_selection_for_the_unchanged_retry() {
    let chain = chain();
    let budget = AllocationBudget::new(64 << 20);
    let bytes = source(&chain, 2, &budget);
    let pointer = bytes.as_slice().as_ptr();
    let held = budget.reserved_bytes();
    let read = LanePayloadRead::new(
        bytes,
        budget.clone(),
        chain.network_id(),
        &chain.committed(2),
    );
    budget.set_limit_bytes(held);
    let (read, error) = read
        .authenticate()
        .err()
        .expect("no capacity for original write graph");
    assert!(error.is_local_refusal(), "{error}");
    let LanePayloadError::Admission(AllocationRefusal::ExceedsLimit {
        requested_bytes, ..
    }) = error
    else {
        panic!("the complete graph cannot fit the original ceiling");
    };
    budget.set_limit_bytes(held + requested_bytes - 1);
    let (read, error) = read
        .authenticate()
        .err()
        .expect("one byte short with original source retained");
    assert!(matches!(
        error,
        LanePayloadError::Admission(AllocationRefusal::Capacity { .. })
    ));
    assert!(error.is_local_refusal(), "{error}");
    assert!(!LanePayloadError::Admission(AllocationRefusal::DemandOverflow).is_local_refusal());
    assert!(!LanePayloadError::Source.is_local_refusal());
    assert_eq!(read.bytes.as_slice().as_ptr(), pointer);
    assert_eq!(read.height, 2);
    assert_eq!(budget.reserved_bytes(), held);
    budget.set_limit_bytes(64 << 20);
    let owner = read
        .authenticate()
        .unwrap_or_else(|(_, error)| panic!("same source retry: {error}"));
    assert_eq!(owner.bytes.as_slice().as_ptr(), pointer);
    assert_eq!(budget.reserved_bytes(), held);
    drop(owner);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn lane_payload_rejects_foreign_carrier_pool_network_and_changed_complete_state() {
    let chain = chain();
    for case in 0..5 {
        let budget = AllocationBudget::new(64 << 20);
        let mut bytes = source(&chain, 2, &budget);
        let mut network = chain.network_id();
        if case == 2 {
            network = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
                b"foreign network",
            )));
        }
        if case >= 3 {
            let mut projection: NativeExecutionProjectionV1 =
                norito::decode_canonical(bytes.as_slice()).unwrap();
            if case == 3 {
                projection.lanes.incarnations += 1;
            } else {
                projection
                    .ordinary_writes
                    .push(iroha_data_model::block::consensus::ExecKv {
                        key: b"foreign-write".to_vec(),
                        value: vec![1],
                    });
            }
            let changed = norito::encode_canonical(&projection).unwrap();
            bytes = ChargedBuffer::new(changed.len(), &budget).unwrap();
            bytes.append(&changed).unwrap();
        }
        let offered = if case == 1 {
            AllocationBudget::new(64 << 20)
        } else {
            budget.clone()
        };
        let height = if case == 0 { 3 } else { 2 };
        let pointer = bytes.as_slice().as_ptr();
        let read = LanePayloadRead::new(bytes, offered.clone(), network, &chain.committed(height));
        let (read, error) = read
            .authenticate()
            .err()
            .expect("foreign original source rejected");
        assert!(!error.is_local_refusal(), "case {case}: {error}");
        assert_eq!(read.bytes.as_slice().as_ptr(), pointer);
        if case == 1 {
            assert_eq!(offered.reserved_bytes(), 0);
        }
        drop(read);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn lane_payload_classifies_typed_decode_refusal_without_masking_invalid_source() {
    for error in [
        norito::Error::ArchiveLengthExceeded {
            length: 2,
            limit: 1,
        },
        norito::Error::SequenceLengthExceeded {
            length: 2,
            limit: 1,
        },
        norito::Error::FieldLengthExceeded {
            length: 2,
            limit: 1,
        },
        norito::Error::TotalElementsExceeded {
            attempted: 2,
            limit: 1,
        },
        norito::Error::TotalAllocationExceeded {
            attempted: 2,
            limit: 1,
        },
        norito::Error::NestingDepthExceeded {
            depth: 2,
            limit: 1,
            context: "lane custody",
        },
        norito::Error::AllocationFailed { bytes: 1 },
    ] {
        assert!(LanePayloadError::Codec(error).is_local_refusal());
    }
    for error in [
        norito::Error::LengthMismatch,
        norito::Error::ChecksumMismatch,
        norito::Error::NonCanonicalEncoding,
        norito::Error::MissingLayoutFlags,
    ] {
        assert!(!LanePayloadError::Codec(error).is_local_refusal());
    }
    assert!(!LanePayloadError::Source.is_local_refusal());
    assert!(!LanePayloadError::Commitment.is_local_refusal());
    assert!(!LanePayloadError::Admission(AllocationRefusal::DemandOverflow).is_local_refusal());
}

#[test]
fn genuine_sccp_delta_preimage_and_original_write_root_are_both_required() {
    let (chain, _) = crate::smartcontracts::isi::sccp::forgery::tests::active_member_chain();
    for mutation in 0..7 {
        let budget = AllocationBudget::new(64 << 20);
        let mut bytes = source(&chain, 2, &budget);
        let mut projection: NativeExecutionProjectionV1 =
            norito::decode_canonical(bytes.as_slice()).unwrap();
        assert!(!projection.sccp_delta.is_empty());
        let key = crate::smartcontracts::isi::sccp::witness::SCCP_STATE_DELTA_WITNESS_KEY_V1;
        match mutation {
            0 => {}
            1 => projection.sccp_delta.clear(),
            2 => projection.sccp_delta[0] ^= 1,
            3 => projection.ordinary_writes.retain(|write| write.key != key),
            4 => {
                let duplicate = projection
                    .ordinary_writes
                    .iter()
                    .find(|write| write.key == key)
                    .unwrap()
                    .clone();
                projection.ordinary_writes.push(duplicate);
            }
            5 => {
                projection.sccp_delta[0] ^= 1;
                let replacement =
                    crate::smartcontracts::isi::sccp::witness::state_delta_witness_write(
                        2,
                        &projection.sccp_delta,
                    )
                    .unwrap();
                *projection
                    .ordinary_writes
                    .iter_mut()
                    .find(|write| write.key == key)
                    .unwrap() = replacement;
            }
            6 => {
                let replacement =
                    crate::smartcontracts::isi::sccp::witness::state_delta_witness_write(
                        3,
                        &projection.sccp_delta,
                    )
                    .unwrap();
                *projection
                    .ordinary_writes
                    .iter_mut()
                    .find(|write| write.key == key)
                    .unwrap() = replacement;
            }
            _ => unreachable!(),
        }
        if mutation != 0 {
            let changed = norito::encode_canonical(&projection).unwrap();
            bytes = ChargedBuffer::new(changed.len(), &budget).unwrap();
            bytes.append(&changed).unwrap();
        }
        let pointer = bytes.as_slice().as_ptr();
        let read = LanePayloadRead::new(
            bytes,
            budget.clone(),
            chain.network_id(),
            &chain.committed(2),
        );
        let result = read.authenticate();
        if mutation == 0 {
            let owner = result.unwrap_or_else(|(_, error)| panic!("genuine SCCP archive: {error}"));
            assert_eq!(owner.bytes.as_slice().as_ptr(), pointer);
            assert_eq!(owner.carrier().1, 2);
            drop(owner);
        } else {
            let (read, error) = result
                .err()
                .expect("substituted/omitted delta cannot authenticate");
            assert!(!error.is_local_refusal(), "case {mutation}: {error}");
            assert_eq!(read.bytes.as_slice().as_ptr(), pointer);
            drop(read);
        }
        assert_eq!(budget.reserved_bytes(), 0);
    }
}
