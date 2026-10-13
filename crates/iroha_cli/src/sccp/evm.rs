//! EVM destination actions of `iroha sccp` for Ethereum and BSC (`specs/sccp.md` §7.1, §7.4).
//!
//! Every bundle and rotation chain read from Taira is verified locally against the
//! destination's current committee and original consensus instance before a transaction is built; the key comes only from an
//! owner-only key file.

use std::{collections::BTreeMap, path::Path};

use eyre::{Result, WrapErr as _, ensure, eyre};
use iroha::data_model::{bridge::SccpNetworkV1, sccp::deployment::SccpCommitteePinV1};
use iroha_sccp::{
    api::{SccpMessageProofBundleV1, SccpRotationV1},
    v1::{
        committee::CommitteeStateV1,
        destination::DestinationFlavor,
        evm_abi::{
            ConstructorArgsV1, PauseViewV1, SCCP_EVM_DEPLOYER as DEPLOYER, ViewCallV1,
            ViewReturnV1, create2_address,
        },
        proof::DestinationV1,
    },
};
use iroha_sccp_rpc::{
    EndpointSet, EvmClient, FailoverPolicy, HttpConfig, HttpTransport,
    evm::{BlockId, BlockTag, EvmCallRequest},
};
use iroha_sccp_wallet::pure::{
    bundle::{BundlePurposeV1, CertificateUseV1, DestinationContextV1, verify_message_bundle},
    evm::{
        Eip1559TransactionV1, EvmSigningKey, eip1559_chain_id, finalize_calldata,
        submit_checkpoints_calldata,
    },
    rotation::verify_rotation_steps,
};

/// One coherent observation from a selected destination block hash.
struct Observation {
    network: [u8; 32],
    instance: [u8; 32],
    committee: CommitteeStateV1,
    pause: PauseViewV1,
    checkpoints: BTreeMap<u64, [u8; 32]>,
    now_ms: u64,
}
impl Observation {
    fn context(&self, destination: DestinationV1) -> DestinationContextV1<'_> {
        DestinationContextV1 {
            taira_network_id: self.network,
            consensus_instance: self.instance,
            destination,
            flavor: DestinationFlavor::Evm,
            committee_state: self.committee,
            ton_keys: None,
            checkpoints: &self.checkpoints,
            now_ms: self.now_ms,
        }
    }
}

/// One EVM deployment reached through a JSON-RPC endpoint.
pub(super) struct EvmDestination {
    client: EvmClient,
    network: SccpNetworkV1,
    contract: [u8; 20],
    destination: DestinationV1,
    code_hash: [u8; 32],
}
impl EvmDestination {
    /// Connect to the selected deployment; every observation checks its original code hash.
    pub(super) fn connect(
        rpc_url: &str,
        network: SccpNetworkV1,
        contract: [u8; 20],
        destination: DestinationV1,
        code_hash: [u8; 32],
    ) -> Result<Self> {
        Ok(Self {
            client: connect_chain(rpc_url, network)?,
            network,
            contract,
            destination,
            code_hash,
        })
    }

    fn observe(&self, heights: impl IntoIterator<Item = u64>) -> Result<Observation> {
        let block = self
            .client
            .block_by_number(BlockTag::Latest)
            .map_err(|e| eyre!("latest block: {e}"))?
            .ok_or_else(|| eyre!("the RPC endpoint has no latest block"))?;
        let at = BlockId::Hash(block.header.hash);
        let now_ms = block
            .header
            .timestamp
            .checked_mul(1000)
            .ok_or_else(|| eyre!("block timestamp overflows"))?;
        let code = self
            .client
            .code(&self.contract, at)
            .map_err(|e| eyre!("eth_getCode: {e}"))?;
        ensure!(
            !code.is_empty() && iroha_sccp::v1::hashes::keccak256(&[&code]) == self.code_hash,
            "destination code differs from the selected registered deployment"
        );
        read_observation(self.destination.route_revision, now_ms, heights, |call| {
            let data = self
                .client
                .call(&EvmCallRequest::new(self.contract, call.calldata()), at)
                .map_err(|e| eyre!("destination view {call:?}: {e}"))?;
            call.decode_return(&data)
                .map_err(|e| eyre!("destination view {call:?}: {e}"))
        })
    }

    /// Read the actual current committee and latch from one destination block.
    pub(super) fn committee_state(&self) -> Result<CommitteeStateV1> {
        Ok(self.observe([])?.committee)
    }
    /// Verify against selected destination identity and encode an accepted current source.
    pub(super) fn finalize_call(
        &self,
        bundle: &SccpMessageProofBundleV1,
        network: [u8; 32],
        instance: [u8; 32],
    ) -> Result<Vec<u8>> {
        let observed = self.observe([bundle.certificate.height])?;
        ensure!(
            observed.network == network && observed.instance == instance,
            "Taira and the selected deployment have different network or consensus identities"
        );
        ensure!(!observed.pause.effective, "the destination is paused");
        let source = if observed
            .checkpoints
            .contains_key(&bundle.certificate.height)
        {
            CertificateUseV1::Checkpoint
        } else {
            CertificateUseV1::Inline
        };
        let verified = verify_message_bundle(
            bundle,
            &observed.context(self.destination),
            BundlePurposeV1::Finalize,
            source,
        )
        .map_err(|e| eyre!("proof bundle: {e}"))?;
        finalize_calldata(&verified).map_err(|e| eyre!("finalize calldata: {e:?}"))
    }
    /// Verify a bounded current rotation page and return its checkpoint calldata.
    /// The next invocation re-observes the destination; a page is never authority by itself.
    pub(super) fn rotation_calls(
        &self,
        steps: &[SccpRotationV1],
        target: u64,
        network: [u8; 32],
        instance: [u8; 32],
    ) -> Result<Vec<Vec<u8>>> {
        let observed = self.observe(steps.iter().map(|step| step.certificate.height))?;
        ensure!(
            observed.network == network && observed.instance == instance,
            "Taira and the selected deployment have different network or consensus identities"
        );
        let plan = verify_rotation_steps(steps, &observed.context(self.destination), target)
            .map_err(|e| eyre!("committee checkpoint chain: {e}"))?;
        Ok(submit_checkpoints_calldata(&plan))
    }
    /// Sign and broadcast verified calldata with the selected fee-paying key.
    pub(super) fn send(&self, key: &EvmSigningKey, data: Vec<u8>) -> Result<[u8; 32]> {
        send_transaction(&self.client, self.network, key, Some(self.contract), data)
            .map(|(hash, _)| hash)
    }
}

fn read_observation(
    revision: u32,
    now_ms: u64,
    heights: impl IntoIterator<Item = u64>,
    mut read: impl FnMut(ViewCallV1) -> Result<ViewReturnV1>,
) -> Result<Observation> {
    let ViewReturnV1::CommitteeState(committee) = read(ViewCallV1::CommitteeState)? else {
        return Err(eyre!("invalid committee view"));
    };
    let ViewReturnV1::Bool(latched) = read(ViewCallV1::Equivocated)? else {
        return Err(eyre!("invalid latch view"));
    };
    let ViewReturnV1::PauseState(pause) = read(ViewCallV1::PauseState)? else {
        return Err(eyre!("invalid pause view"));
    };
    let ViewReturnV1::Bytes32(network) = read(ViewCallV1::TairaNetworkId)? else {
        return Err(eyre!("invalid network view"));
    };
    let ViewReturnV1::Bytes32(instance) = read(ViewCallV1::ConsensusInstance)? else {
        return Err(eyre!("invalid consensus instance view"));
    };
    let ViewReturnV1::U32(actual_revision) = read(ViewCallV1::RouteRevision)? else {
        return Err(eyre!("invalid revision view"));
    };
    ensure!(
        actual_revision == revision,
        "destination route revision differs from selected registry record"
    );
    ensure!(
        network != [0; 32] && instance != [0; 32],
        "destination identity is zero"
    );
    ensure!(
        pause.effective == (pause.parliament_paused || now_ms < pause.fast_pause_until_ms),
        "destination pause projection is inconsistent at the selected block time"
    );
    let mut checkpoints = BTreeMap::new();
    for height in heights {
        ensure!(height != 0, "checkpoint height must be positive");
        let ViewReturnV1::Bytes32(id) = read(ViewCallV1::CheckpointHeader(height))? else {
            return Err(eyre!("invalid checkpoint view"));
        };
        if id != [0; 32] {
            checkpoints.insert(height, id);
        }
    }
    Ok(Observation {
        network,
        instance,
        committee: committee.with_equivocated(latched),
        pause,
        checkpoints,
        now_ms,
    })
}

/// Connect to `rpc_url` and check that it serves `network`.
pub(super) fn connect_chain(rpc_url: &str, network: SccpNetworkV1) -> Result<EvmClient> {
    let endpoints =
        EndpointSet::parse(&[rpc_url], &[]).map_err(|error| eyre!("RPC endpoint: {error}"))?;
    let transport = HttpTransport::new(endpoints, HttpConfig::default(), FailoverPolicy::default())
        .map_err(|error| eyre!("RPC transport: {error}"))?;
    let client = EvmClient::new(transport);
    let expected = eip1559_chain_id(network).map_err(|error| eyre!("{error:?}"))?;
    let served = client
        .chain_id()
        .map_err(|error| eyre!("eth_chainId: {error}"))?;
    if served != expected {
        return Err(eyre!(
            "the RPC endpoint serves chain {served}, not {} ({expected})",
            network.profile_key()
        ));
    }
    Ok(client)
}

/// Sign and broadcast a call of `to` (a contract creation when `None`) with `key`, returning
/// the transaction hash and the sender nonce it used.
pub(super) fn send_transaction(
    client: &EvmClient,
    network: SccpNetworkV1,
    key: &EvmSigningKey,
    to: Option<[u8; 20]>,
    data: Vec<u8>,
) -> Result<([u8; 32], u64)> {
    let sender = key.address();
    let nonce = client
        .transaction_count(&sender, BlockId::Tag(BlockTag::Pending))
        .map_err(|error| eyre!("eth_getTransactionCount: {error}"))?;
    let gas = match to {
        Some(to) => {
            let mut request = EvmCallRequest::new(to, data.clone());
            request.from = Some(sender);
            client
                .estimate_gas(&request)
                .map_err(|error| eyre!("eth_estimateGas (the call would revert): {error}"))?
        }
        // Creation of the ~15 KiB SCCP contract; unused gas is refunded.
        None => 6_000_000,
    };
    let gas_limit = gas.saturating_add(gas / 5);
    let priority = client
        .max_priority_fee_per_gas()
        .map_err(|error| eyre!("eth_maxPriorityFeePerGas: {error}"))?
        .to_u128()
        .ok_or_else(|| eyre!("priority fee overflows"))?;
    let base_fee = client
        .block_by_number(BlockTag::Latest)
        .map_err(|error| eyre!("latest block: {error}"))?
        .and_then(|block| block.header.base_fee_per_gas)
        .and_then(iroha_sccp_rpc::evm::U256::to_u128)
        .ok_or_else(|| eyre!("the latest block has no base fee"))?;
    let transaction = Eip1559TransactionV1 {
        chain_id: eip1559_chain_id(network).map_err(|error| eyre!("{error:?}"))?,
        nonce,
        max_priority_fee_per_gas: priority,
        max_fee_per_gas: base_fee.saturating_mul(2).saturating_add(priority),
        gas_limit,
        to,
        value: 0,
        data,
    };
    transaction
        .validate()
        .map_err(|error| eyre!("transaction: {error:?}"))?;
    let signed = transaction
        .sign(key)
        .map_err(|error| eyre!("signing: {error:?}"))?;
    let hash = client
        .send_raw_transaction(&signed.raw())
        .map_err(|error| eyre!("eth_sendRawTransaction: {error}"))?;
    Ok((hash, nonce))
}

const DEPLOYER_RUNTIME: &str = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3";
/// Check the canonical proxy bytecode before paying for deterministic deployment.
pub(super) fn deploy_current(
    client: &EvmClient,
    network: SccpNetworkV1,
    key: &EvmSigningKey,
    init_code: Vec<u8>,
) -> Result<([u8; 32], [u8; 20])> {
    let actual = client
        .code(&DEPLOYER, BlockId::Tag(BlockTag::Latest))
        .map_err(|e| eyre!("deployment proxy: {e}"))?;
    ensure!(
        actual == hex::decode(DEPLOYER_RUNTIME).expect("fixed proxy code"),
        "canonical deterministic deployment proxy is absent or has different code"
    );
    let address = create2_address(&DEPLOYER, &[0; 32], &init_code);
    let mut calldata = vec![0; 32];
    calldata.extend(init_code);
    let (hash, _) = send_transaction(client, network, key, Some(DEPLOYER), calldata)?;
    Ok((hash, address))
}

/// Exact nine static constructor words of the current native deployment.
#[must_use]
pub(super) fn constructor_args(
    taira_network_id: &[u8; 32],
    consensus_instance: &[u8; 32],
    network: SccpNetworkV1,
    route_revision: u32,
    max_wrapped_supply: u128,
    pin: &SccpCommitteePinV1,
) -> Vec<u8> {
    ConstructorArgsV1 {
        taira_network_id: *taira_network_id,
        consensus_instance: *consensus_instance,
        network,
        route_revision,
        max_wrapped_supply,
        pin: *pin,
    }
    .encode()
}

/// The deployed runtime code hash of `contract`, as `RegisterRoute` records it.
pub(super) fn runtime_code_hash(client: &EvmClient, contract: &[u8; 20]) -> Result<[u8; 32]> {
    let code = client
        .code(contract, BlockId::Tag(BlockTag::Latest))
        .map_err(|error| eyre!("eth_getCode: {error}"))?;
    if code.is_empty() {
        return Err(eyre!("no code at the contract address yet"));
    }
    Ok(iroha_sccp::v1::hashes::keccak256(&[&code]))
}

/// Load the owner-only EVM key file at `path`.
pub(super) fn load_key(path: &Path) -> Result<EvmSigningKey> {
    EvmSigningKey::load(path)
        .map_err(|error| eyre!("EVM key file {}: {error:?}", path.display()))
        .wrap_err("external keys come only from owner-only key files")
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_sccp::v1::{
        evm_abi::{CommitteeViewV1, PauseViewV1},
        hashes::{word_u64, word_u128},
    };
    #[test]
    fn deterministic_deployment_follows_eip1014_and_binds_every_constructor_word() {
        assert_eq!(
            hex::encode(create2_address(&[0; 20], &[0; 32], &[0])),
            "4d1a2e2bb4f88f0250f26ffff098b0b30b26bf38"
        );
        let pin = SccpCommitteePinV1 {
            generation: 2,
            committee_root: [3; 32],
            start_height: 4,
            until_ms: 5,
        };
        let encoded = constructor_args(
            &[7; 32],
            &[8; 32],
            SccpNetworkV1::EthereumMainnet,
            1,
            1000,
            &pin,
        );
        let words = [
            [7; 32],
            [8; 32],
            word_u64(0x41),
            word_u64(1),
            word_u128(1000),
            word_u64(2),
            [3; 32],
            word_u64(4),
            word_u64(5),
        ];
        assert_eq!(encoded, words.concat());
        assert_eq!(encoded.len(), 9 * 32);
        let original = create2_address(&DEPLOYER, &[0; 32], &encoded);
        for index in 0..9 {
            let mut changed = encoded.clone();
            changed[index * 32 + 31] ^= 1;
            assert_ne!(create2_address(&DEPLOYER, &[0; 32], &changed), original);
        }
        assert_eq!(hex::decode(DEPLOYER_RUNTIME).unwrap().len(), 69);
    }
    #[test]
    fn destination_observation_preserves_latch_checkpoint_and_identity_and_rejects_mixed_pause() {
        let build = |bad_pause: bool, revision: u32| {
            read_observation(1, 100, [7, 8], |call| {
                Ok(match call {
                    ViewCallV1::CommitteeState => ViewReturnV1::CommitteeState(CommitteeViewV1 {
                        root: [9; 32],
                        until_ms: 1000,
                        start: 1,
                        high: 7,
                        generation: 2,
                    }),
                    ViewCallV1::Equivocated => ViewReturnV1::Bool(true),
                    ViewCallV1::PauseState => ViewReturnV1::PauseState(PauseViewV1 {
                        parliament_paused: false,
                        fast_pause_until_ms: 101,
                        control_nonce: 3,
                        effective: !bad_pause,
                    }),
                    ViewCallV1::TairaNetworkId => ViewReturnV1::Bytes32([1; 32]),
                    ViewCallV1::ConsensusInstance => ViewReturnV1::Bytes32([2; 32]),
                    ViewCallV1::RouteRevision => ViewReturnV1::U32(revision),
                    ViewCallV1::CheckpointHeader(7) => ViewReturnV1::Bytes32([7; 32]),
                    ViewCallV1::CheckpointHeader(8) => ViewReturnV1::Bytes32([0; 32]),
                    _ => unreachable!(),
                })
            })
        };
        let observed = build(false, 1).unwrap();
        assert!(observed.committee.equivocated);
        assert_eq!(observed.network, [1; 32]);
        assert_eq!(observed.instance, [2; 32]);
        assert_eq!(observed.checkpoints, BTreeMap::from([(7, [7; 32])]));
        assert!(observed.pause.effective);
        assert!(build(true, 1).is_err());
        assert!(build(false, 2).is_err());
        assert!(read_observation(1, 100, [], |_| Ok(ViewReturnV1::Bool(false))).is_err());
    }
}
