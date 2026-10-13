//! Exact selected graph demand, immutable source retry and canonical authority parity.

use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
use iroha_data_model::{
    NetworkId,
    sumeragi_lanes::{SumeragiLaneMember, SumeragiLaneRecord, SumeragiLaneState},
};
use iroha_model_base::{peer::PeerId, topology::DataSpaceId};
use norito::codec::Encode;

use super::*;

fn record() -> (NetworkId, SumeragiLaneRecord) {
    let network = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"original prepaid lane authority",
    )));
    let mut members = (1..=4)
        .map(|seed| {
            let key = KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal);
            SumeragiLaneMember {
                peer: PeerId::new(key.public_key().clone()),
                pop: iroha_crypto::bls_normal_pop_prove(key.private_key()).unwrap(),
            }
        })
        .collect::<Vec<_>>();
    members.sort_by(|a, b| a.peer.cmp(&b.peer));
    let mut record = SumeragiLaneRecord {
        da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
        lane: LaneId::new(7),
        dataspace: DataSpaceId::new(11),
        incarnation: [17; 32],
        params: iroha_data_model::parameter::system::SumeragiParameters::default(),
        committee: members,
        created_at: 20,
        active_from: 22,
        closing: None,
        anchor_freshness: 16,
        merged: SumeragiLaneFrontier::default(),
        merged_at: 22,
        rescued: 0,
    };
    record.merged = SumeragiLaneFrontier {
        height: 0,
        block_hash: crate::sumeragi::lanes::lane_genesis_hash(&network, &record).0,
        result: crate::sumeragi::lanes::lane_genesis_result(&record).0,
    };
    (network, record)
}
fn source(
    network: NetworkId,
    record: &SumeragiLaneRecord,
    budget: &AllocationBudget,
) -> LanePayload {
    let state = SumeragiLaneState {
        lanes: vec![record.clone()],
        ..SumeragiLaneState::default()
    };
    let encoded = state.encode();
    let mut bytes = ChargedBuffer::new(encoded.len(), budget).unwrap();
    bytes.append(&encoded).unwrap();
    // Only this private fixture can select raw bytes directly. Production LanePayload is
    // constructed exclusively from an independently authenticated original receipt/write root.
    LanePayload {
        bytes,
        range: 0..encoded.len(),
        delta_range: encoded.len()..encoded.len(),
        network,
        height: record.created_at,
        carrier: HashOf::from_untyped_unchecked(Hash::new(b"original creation carrier")),
    }
}

#[test]
fn selected_authority_matches_existing_creation_context_and_exact_original_credentials() {
    let (network, record) = record();
    let encoded = record.encode();
    let raw = RawAuthority::parse(&encoded).unwrap();
    assert_eq!(raw.context().unwrap().0, record.merged.result);
    assert_eq!(raw.frontier().unwrap(), record.merged);
    assert_eq!(
        raw.params,
        crate::sumeragi::schedule::ChainParamsRecord::from_parameters(&record.params)
    );
    let expected = crate::sumeragi::lanes::lane_height_config(&record).unwrap();
    let budget = AllocationBudget::new(1 << 20);
    let source = source(network, &record, &budget);
    let held = budget.reserved_bytes();
    let demand = raw.demand().unwrap().bytes;
    let owner = LaneAuthorityRead::new(source, record.incarnation)
        .complete(&budget)
        .unwrap_or_else(|(_, error)| panic!("selected original authority: {error}"));
    assert_eq!(owner.config(), &expected);
    assert_eq!(owner.lane(), record.lane);
    assert!(owner.belongs_to(&budget));
    assert_eq!(budget.reserved_bytes(), held + demand);
    let mut index = 0;
    owner
        .visit_members(|key, pop| {
            assert_eq!(
                key,
                record.committee[index]
                    .peer
                    .public_key()
                    .try_to_bytes()
                    .unwrap()
                    .1
            );
            assert_eq!(pop, record.committee[index].pop);
            index += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(index, record.committee.len());
    drop(owner);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn selected_authority_refuses_before_graph_allocation_then_retries_same_source_at_exact_demand() {
    let (network, record) = record();
    let budget = AllocationBudget::new(1 << 20);
    let source = source(network, &record, &budget);
    let pointer = source.bytes.as_slice().as_ptr();
    let held = budget.reserved_bytes();
    let demand = RawAuthority::parse(&record.encode())
        .unwrap()
        .demand()
        .unwrap()
        .bytes;
    let read = LaneAuthorityRead::new(source, record.incarnation);
    let foreign = AllocationBudget::new(1 << 20);
    let (read, error) = read
        .complete(&foreign)
        .err()
        .expect("foreign source refused");
    assert!(matches!(error, LanePayloadError::Source));
    assert_eq!(foreign.reserved_bytes(), 0);
    budget.set_limit_bytes(held + demand - 1);
    let (read, error) = read
        .complete(&budget)
        .err()
        .expect("one byte under exact demand");
    assert!(error.is_local_refusal());
    assert_eq!(budget.reserved_bytes(), held);
    assert_eq!(read.source.bytes.as_slice().as_ptr(), pointer);
    budget.set_limit_bytes(held + demand);
    let owner = read
        .complete(&budget)
        .unwrap_or_else(|(_, error)| panic!("same source retry: {error}"));
    assert_eq!(owner.source.bytes.as_slice().as_ptr(), pointer);
    assert_eq!(budget.reserved_bytes(), held + demand);
    budget.set_limit_bytes(0);
    assert_eq!(owner.config().committee.n(), 4);
    drop(owner);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn selected_authority_rejects_noncreation_or_changed_geometry_before_reserving_graph() {
    let (network, original) = record();
    for case in 0..7 {
        let mut record = original.clone();
        match case {
            0 => record.committee.swap(0, 1),
            1 => record.committee[1] = record.committee[0].clone(),
            2 => {
                record.committee.pop();
            }
            3 => record.closing = Some(record.created_at + 1),
            4 => record.merged.result = Hash::new(b"foreign creation result").into(),
            5 => record.active_from += 1,
            6 => record.da_layout.chunk_size_bytes = 0,
            _ => unreachable!(),
        }
        let budget = AllocationBudget::new(1 << 20);
        let source = source(network, &record, &budget);
        let held = budget.reserved_bytes();
        let (read, error) = LaneAuthorityRead::new(source, record.incarnation)
            .complete(&budget)
            .err()
            .expect("invalid independent creation authority");
        assert!(!error.is_local_refusal());
        assert_eq!(budget.reserved_bytes(), held);
        drop(read);
        assert_eq!(budget.reserved_bytes(), 0);
    }
    let budget = AllocationBudget::new(1 << 20);
    let mut source = source(network, &original, &budget);
    source.height += 1;
    let (read, error) = LaneAuthorityRead::new(source, original.incarnation)
        .complete(&budget)
        .err()
        .expect("newer carrier cannot substitute the original creation receipt");
    assert!(matches!(error, LanePayloadError::Source));
    drop(read);
    assert_eq!(budget.reserved_bytes(), 0);
}

fn custody_source(
    network: NetworkId,
    record: &SumeragiLaneRecord,
    row: Option<iroha_data_model::sumeragi_lanes::SumeragiLaneCustody>,
    height: u64,
    budget: &AllocationBudget,
) -> LanePayload {
    let state = SumeragiLaneState {
        lanes: (height == record.created_at)
            .then(|| record.clone())
            .into_iter()
            .collect(),
        custody: row.into_iter().collect(),
        ..SumeragiLaneState::default()
    };
    let encoded = state.encode();
    let mut bytes = ChargedBuffer::new(encoded.len(), budget).unwrap();
    bytes.append(&encoded).unwrap();
    LanePayload {
        bytes,
        range: 0..encoded.len(),
        delta_range: encoded.len()..encoded.len(),
        network,
        height,
        carrier: HashOf::from_untyped_unchecked(Hash::new(height.to_le_bytes())),
    }
}

#[test]
fn original_custody_binding_survives_retirement_and_rejects_later_tenure_or_policy_substitution() {
    use iroha_data_model::sumeragi_lanes::{
        SumeragiLaneCustody, SumeragiLaneSignerCustody, SumeragiLaneStakeBinding,
    };
    let (network, record) = record();
    let instance = Hash32([9; 32]);
    let original = SumeragiLaneCustody {
        lane: record.lane,
        incarnation: record.incarnation,
        instance: instance.0,
        created_at: record.created_at,
        merged: record.merged,
        signer_count: 4,
        signers: vec![SumeragiLaneSignerCustody {
            signer: 2,
            binding: SumeragiLaneStakeBinding {
                owner_lane: LaneId::SINGLE,
                validator: Hash::new(b"original account"),
                activation_height: 17,
                tenure: Hash::new(b"original registration and escrow"),
            },
        }]
        .try_into()
        .unwrap(),
        evidence_horizon: 7,
        slashing_delay: 3,
        retired_at: None,
    };
    let budget = AllocationBudget::new(1 << 20);
    let creation = custody_source(
        network,
        &record,
        Some(original.clone()),
        record.created_at,
        &budget,
    );
    let owner = LaneAuthorityRead::new(creation, record.incarnation)
        .complete(&budget)
        .unwrap_or_else(|(_, error)| panic!("original custody creation: {error}"));
    for case in 0..9 {
        let mut row = original.clone();
        row.retired_at = Some(30);
        row.merged = SumeragiLaneFrontier {
            height: 9_999,
            block_hash: [31; 32],
            result: [32; 32],
        };
        match case {
            0 => {}
            1 => row.instance[0] ^= 1,
            2 => row.created_at += 1,
            3 => row.signer_count = 7,
            4 => row.evidence_horizon += 1,
            5 => row.slashing_delay += 1,
            6 => row.retired_at = Some(41),
            7 => {
                let mut signer = row.signers.as_slice()[0];
                signer.binding.tenure = Hash::new(b"later registration and escrow");
                row.signers = vec![signer].try_into().unwrap();
            }
            8 => {
                row.signers =
                    iroha_data_model::sumeragi_lanes::SumeragiLaneCustodySigners::default()
            }
            _ => unreachable!(),
        }
        let source = custody_source(network, &record, Some(row), 40, &budget);
        let held = budget.reserved_bytes();
        let result = owner.validate_custody(&source, instance, Some((7, 3)), &budget);
        assert_eq!(result.is_ok(), case == 0, "case {case}");
        assert_eq!(
            budget.reserved_bytes(),
            held,
            "borrowed comparison allocates no graph"
        );
    }
    let foreign = AllocationBudget::new(1 << 20);
    let foreign_source = custody_source(network, &record, Some(original), 40, &foreign);
    let original_held = budget.reserved_bytes();
    let foreign_held = foreign.reserved_bytes();
    assert!(matches!(
        owner.validate_custody(&foreign_source, instance, Some((7, 3)), &budget),
        Err(LanePayloadError::Source)
    ));
    assert!(matches!(
        owner.validate_custody(&foreign_source, instance, Some((7, 3)), &foreign),
        Err(LanePayloadError::Source)
    ));
    assert_eq!(budget.reserved_bytes(), original_held);
    assert_eq!(foreign.reserved_bytes(), foreign_held);
    drop(foreign_source);
    assert_eq!(foreign.reserved_bytes(), 0);
    let reclaimed = custody_source(network, &record, None, 40, &budget);
    assert!(
        owner
            .validate_custody(&reclaimed, instance, Some((7, 3)), &budget)
            .is_ok(),
        "reclaimed original custody grants only historical storage authority"
    );
    assert!(
        reclaimed
            .custody_record(&record.incarnation)
            .unwrap()
            .is_none()
    );
    drop(reclaimed);
    drop(owner);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn native_ancestry_returns_the_exact_funded_authority_on_uncovered_subject_without_cloning() {
    use crate::sumeragi::lanes::evidence::{LaneAncestry, LaneAncestryError};
    let (network, record) = record();
    let budget = AllocationBudget::new(1 << 20);
    let input = source(network, &record, &budget);
    let pointer = input.bytes.as_slice().as_ptr();
    let authority = LaneAuthorityRead::new(input, record.incarnation)
        .complete(&budget)
        .unwrap_or_else(|(_, error)| panic!("original authority: {error}"));
    let held = budget.reserved_bytes();
    let genesis = authority.genesis();
    let window = record.params.demotion_window.get();
    budget.set_limit_bytes(0);
    let (authority, error) =
        LaneAncestry::new(Hash32([2; 32]), authority, genesis, genesis, 2, window)
            .err()
            .expect("an uncovered native parent retains its original owner");
    assert_eq!(error, LaneAncestryError::Uncovered);
    assert_eq!(authority.source.bytes.as_slice().as_ptr(), pointer);
    assert_eq!(budget.reserved_bytes(), held);
    let cursor = LaneAncestry::new(Hash32([2; 32]), authority, genesis, genesis, 1, window)
        .unwrap_or_else(|(_, error)| panic!("original genesis selection: {error}"));
    assert_eq!(cursor.config().committee.n(), 4);
    assert_eq!(cursor.next_height(), None);
    assert_eq!(budget.reserved_bytes(), held);
    drop(cursor);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn selected_authority_copy_prepays_second_graph_in_original_pool_and_refunds_exactly() {
    let (network, record) = record();
    let budget = AllocationBudget::new(1 << 20);
    let source = source(network, &record, &budget);
    let source_pointer = source.bytes.as_slice().as_ptr();
    let source_bytes = budget.reserved_bytes();
    let demand = RawAuthority::parse(&record.encode())
        .unwrap()
        .demand()
        .unwrap()
        .bytes;
    let owner = LaneAuthorityRead::new(source, record.incarnation)
        .complete(&budget)
        .unwrap_or_else(|(_, error)| panic!("original authority: {error}"));
    let original_epoch = std::ptr::from_ref(owner.config().epoch.as_ref());
    let held = source_bytes + demand;
    assert_eq!(budget.reserved_bytes(), held);
    let foreign = AllocationBudget::new(1 << 20);
    assert!(matches!(
        owner.copy_config(&foreign),
        Err(LanePayloadError::Source)
    ));
    assert_eq!(foreign.reserved_bytes(), 0);
    budget.set_limit_bytes(held + demand - 1);
    let error = owner
        .copy_config(&budget)
        .err()
        .expect("one byte below second graph");
    assert!(error.is_local_refusal());
    assert_eq!(budget.reserved_bytes(), held);
    assert_eq!(owner.source.bytes.as_slice().as_ptr(), source_pointer);
    assert_eq!(
        std::ptr::from_ref(owner.config().epoch.as_ref()),
        original_epoch
    );
    budget.set_limit_bytes(held + demand);
    let copy = owner.copy_config(&budget).unwrap();
    assert!(copy.belongs_to(&budget));
    assert_eq!(copy.get(), owner.config());
    assert_ne!(
        std::ptr::from_ref(copy.get().epoch.as_ref()),
        original_epoch
    );
    assert_eq!(budget.reserved_bytes(), held + demand);
    drop(copy);
    assert_eq!(budget.reserved_bytes(), held);
    assert_eq!(owner.source.bytes.as_slice().as_ptr(), source_pointer);
    drop(owner);
    assert_eq!(budget.reserved_bytes(), 0);
}
