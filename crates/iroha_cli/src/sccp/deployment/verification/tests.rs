//! Refusal controls for pre-vote destination selection and locked EVM observations.

use super::*;
use iroha::data_model::sccp::deployment::{SccpCommitteePinV1, SccpEvmDeploymentV1};
use iroha_sccp::v1::evm_abi::CommitteeViewV1;

pub(super) fn args() -> ConstructorArgsV1 {
    ConstructorArgsV1 {
        taira_network_id: [1; 32],
        consensus_instance: [2; 32],
        network: SccpNetworkV1::EthereumMainnet,
        route_revision: 3,
        max_wrapped_supply: 1000,
        pin: SccpCommitteePinV1 {
            generation: 4,
            committee_root: [5; 32],
            start_height: 6,
            until_ms: 7000,
        },
    }
}

fn read(args: &ConstructorArgsV1, call: ViewCallV1) -> Result<ViewReturnV1> {
    Ok(match call {
        ViewCallV1::TairaNetworkId => ViewReturnV1::Bytes32(args.taira_network_id),
        ViewCallV1::ConsensusInstance => ViewReturnV1::Bytes32(args.consensus_instance),
        ViewCallV1::RouteRevision => ViewReturnV1::U32(args.route_revision),
        ViewCallV1::MaxWrappedSupply => ViewReturnV1::U128(args.max_wrapped_supply),
        ViewCallV1::InitialCommittee => ViewReturnV1::InitialCommittee(args.pin),
        ViewCallV1::OpCount | ViewCallV1::ControlNonce => ViewReturnV1::U64(0),
        ViewCallV1::Equivocated => ViewReturnV1::Bool(false),
        ViewCallV1::PauseState => ViewReturnV1::PauseState(PauseViewV1 {
            parliament_paused: false,
            fast_pause_until_ms: 0,
            control_nonce: 0,
            effective: false,
        }),
        ViewCallV1::CommitteeState => ViewReturnV1::CommitteeState(CommitteeViewV1 {
            root: args.pin.committee_root,
            until_ms: args.pin.until_ms,
            start: args.pin.start_height,
            high: 0,
            generation: args.pin.generation,
        }),
        _ => return Err(eyre!("unexpected view")),
    })
}

#[test]
fn pristine_evm_refuses_each_monetary_control_and_identity_mismatch() {
    let args = args();
    let state = require_pristine_evm(&args, |call| read(&args, call), &[0; 32]).unwrap();
    assert_eq!(state.generation, 4);
    for call in [
        ViewCallV1::TairaNetworkId,
        ViewCallV1::ConsensusInstance,
        ViewCallV1::RouteRevision,
        ViewCallV1::MaxWrappedSupply,
        ViewCallV1::InitialCommittee,
        ViewCallV1::OpCount,
        ViewCallV1::ControlNonce,
        ViewCallV1::Equivocated,
        ViewCallV1::PauseState,
        ViewCallV1::CommitteeState,
    ] {
        assert!(
            require_pristine_evm(
                &args,
                |current| if current == call {
                    Ok(ViewReturnV1::U64(1))
                } else {
                    read(&args, current)
                },
                &[0; 32]
            )
            .is_err(),
            "{call:?}"
        );
    }
    for supply in [vec![], vec![0; 31], vec![1; 32], vec![0; 33]] {
        assert!(require_pristine_evm(&args, |call| read(&args, call), &supply).is_err());
    }
}

#[test]
fn runtime_materializes_every_constructor_immutable_and_preserves_template() {
    let original = args();
    let code = locked_evm_runtime(&original).unwrap();
    let lock: norito::json::Value = norito::json::from_str(ARTIFACT_LOCK).unwrap();
    let contract =
        &lock["targets"]["evm"]["contracts"]["contracts/evm/sccp/SccpTairaXor.sol:SccpTairaXor"];
    let template = hex::decode(
        contract["runtime_template_hex"]
            .as_str()
            .unwrap()
            .strip_prefix("0x")
            .unwrap(),
    )
    .unwrap();
    assert_eq!(code.len(), template.len());
    let mut mask = vec![false; code.len()];
    for entry in contract["immutable_references"].as_array().unwrap() {
        let start = usize::try_from(entry["start"].as_u64().unwrap()).unwrap();
        mask[start..start + 32].fill(true);
    }
    for (index, byte) in code.iter().enumerate() {
        if !mask[index] {
            assert_eq!(*byte, template[index]);
        }
    }
    for field in 0..9 {
        let mut changed = original;
        match field {
            0 => changed.taira_network_id[0] ^= 1,
            1 => changed.consensus_instance[0] ^= 1,
            2 => changed.network = SccpNetworkV1::BscMainnet,
            3 => changed.route_revision += 1,
            4 => changed.max_wrapped_supply += 1,
            5 => changed.pin.generation += 1,
            6 => changed.pin.committee_root[0] ^= 1,
            7 => changed.pin.start_height += 1,
            _ => changed.pin.until_ms += 1,
        }
        assert_ne!(locked_evm_runtime(&changed).unwrap(), code, "field {field}");
        assert_ne!(changed.address(), original.address());
    }
}

#[test]
fn proposed_registration_selection_needs_exact_unique_network_revision() {
    let args = args();
    let registration = SccpRegisterRouteActionV1 {
        network: args.network,
        revision: args.route_revision,
        deployment: SccpDeploymentV1::Evm(SccpEvmDeploymentV1 {
            address: args.address(),
            runtime_code_hash: keccak256(&[&locked_evm_runtime(&args).unwrap()]),
        }),
        max_wrapped_supply: args.max_wrapped_supply,
        initial_committee: args.pin,
    };
    let actions = vec![SccpGovernanceActionV1::RegisterRoute(registration)];
    assert_eq!(
        select_registration(&actions, args.network, 3).unwrap(),
        registration
    );
    assert!(select_registration(&actions, args.network, 2).is_err());
    assert!(select_registration(&actions, SccpNetworkV1::BscMainnet, 3).is_err());
    assert!(select_registration(&[], args.network, 3).is_err());
    assert!(
        select_registration(&[actions[0].clone(), actions[0].clone()], args.network, 3).is_err()
    );
}

#[test]
fn ton_artifact_lock_checks_hash_and_depth_for_each_contract() {
    for name in [
        "SccpTairaXorMinter",
        "SccpTairaXorWallet",
        "SccpConsumedBucket",
    ] {
        let reference = locked_ton_code(name).unwrap();
        require_locked_ton_code(name, reference).unwrap();
        let mut hash = reference;
        hash.hash[0] ^= 1;
        assert!(require_locked_ton_code(name, hash).is_err());
        let mut depth = reference;
        depth.depth += 1;
        assert!(require_locked_ton_code(name, depth).is_err());
    }
    assert!(locked_ton_code("another contract").is_err());
}
