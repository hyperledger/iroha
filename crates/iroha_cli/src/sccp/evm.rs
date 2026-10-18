//! EVM destination actions of `iroha sccp` for Ethereum and BSC (`specs/sccp.md` §7.1, §7.4).
//!
//! Every bundle and rotation chain read from Taira is verified locally against the
//! destination's current committee and original consensus instance before a transaction is built; the key comes only from an
//! owner-only key file.

use std::{collections::BTreeMap, path::Path};

use eyre::{Result, WrapErr as _, ensure, eyre};
use iroha::data_model::{bridge::SccpNetworkV1, sccp::deployment::SccpCommitteePinV1};
use iroha_sccp::{
    api::{SccpControlProofBundleV1, SccpMessageProofBundleV1, SccpRotationV1},
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
    EndpointSet, EvmClient, FailoverPolicy, HttpTransport,
    evm::{BlockId, BlockTag, EvmCallRequest},
};
use iroha_sccp_wallet::pure::{
    bundle::{BundlePurposeV1, CertificateUseV1, DestinationContextV1, verify_message_bundle},
    control::{DestinationControlStateV1, verify_control_bundle},
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
        config: &iroha_sccp_wallet::config::SccpClientConfig,
        rpc_url: &str,
        network: SccpNetworkV1,
        contract: [u8; 20],
        destination: DestinationV1,
        code_hash: [u8; 32],
    ) -> Result<Self> {
        Ok(Self {
            client: connect_chain_config(config, rpc_url, network)?,
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

    /// Verify against selected destination identity and encode an accepted current source.
    pub(super) fn finalize_call(
        &self,
        bundle: &SccpMessageProofBundleV1,
        network: [u8; 32],
        instance: [u8; 32],
        required_control: u64,
    ) -> Result<Vec<u8>> {
        let observed = self.observe([bundle.certificate.height])?;
        ensure!(
            observed.network == network && observed.instance == instance,
            "Taira and the selected deployment have different network or consensus identities"
        );
        super::administration::require_latest_control(
            observed.pause.control_nonce,
            required_control,
        )?;
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
    /// Verify a complete control against the same code-bound destination observation.
    pub(super) fn control_call(
        &self,
        bundle: &SccpControlProofBundleV1,
        network: [u8; 32],
        instance: [u8; 32],
    ) -> Result<Vec<u8>> {
        let observed = self.observe([bundle.certificate.height])?;
        ensure!(
            observed.network == network && observed.instance == instance,
            "Taira and destination identities differ"
        );
        let applied = DestinationControlStateV1 {
            control_nonce: observed.pause.control_nonce,
            parliament_paused: observed.pause.parliament_paused,
            fast_pause_until_ms: observed.pause.fast_pause_until_ms,
        };
        let source = if observed
            .checkpoints
            .contains_key(&bundle.certificate.height)
        {
            CertificateUseV1::Checkpoint
        } else {
            CertificateUseV1::Inline
        };
        let verified = verify_control_bundle(
            bundle,
            &observed.context(self.destination),
            &applied,
            source,
        )
        .map_err(|e| eyre!("control proof: {e}"))?;
        Ok(iroha_sccp_wallet::pure::evm::apply_control_calldata(
            &verified,
        ))
    }

    /// Read complete applied control fields at one code-bound destination block.
    pub(super) fn control_observation(
        &self,
        network: [u8; 32],
        instance: [u8; 32],
    ) -> Result<(DestinationControlStateV1, u64)> {
        let observed = self.observe([])?;
        ensure!(
            observed.network == network && observed.instance == instance,
            "Taira and the selected deployment have different identities"
        );
        Ok((
            DestinationControlStateV1 {
                control_nonce: observed.pause.control_nonce,
                parliament_paused: observed.pause.parliament_paused,
                fast_pause_until_ms: observed.pause.fast_pause_until_ms,
            },
            observed.now_ms,
        ))
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
    /// Replay-protected transaction adapter for this selected destination.
    pub(super) fn transport(&self) -> EvmTransport<'_> {
        EvmTransport {
            client: &self.client,
            network: self.network,
            contract: self.contract,
            code_hash: self.code_hash,
        }
    }
}

/// Original EIP-1559 custody and finalized receipts for one explicit call target.
pub(super) struct EvmTransport<'a> {
    client: &'a EvmClient,
    network: SccpNetworkV1,
    contract: [u8; 20],
    code_hash: [u8; 32],
}

impl EvmTransport<'_> {
    /// Quote an exact unsigned transaction for an external payer, without loading a key.
    pub(super) fn unsigned(&self, payer: [u8; 20], data: Vec<u8>) -> Result<Eip1559TransactionV1> {
        unsigned_transaction(self.client, self.network, payer, Some(self.contract), data)
    }
    /// Sign without network dispatch; the caller must persist these exact bytes first.
    pub(super) fn prepare(&self, key: &EvmSigningKey, data: Vec<u8>) -> Result<Vec<u8>> {
        prepare_transaction(&self.client, self.network, key, Some(self.contract), data)
            .map(|(raw, _)| raw)
    }

    /// Check that a retained signed transaction is this exact requested contract call.
    pub(super) fn retained_hash(&self, raw: &[u8], calldata: &[u8]) -> Result<[u8; 32]> {
        let signed = iroha_sccp_wallet::pure::evm::SignedEip1559V1::decode(raw)
            .map_err(|error| eyre!("retained EVM transaction: {error:?}"))?;
        ensure!(
            signed.transaction.chain_id
                == eip1559_chain_id(self.network).map_err(|error| eyre!("{error:?}"))?
                && signed.transaction.to == Some(self.contract)
                && signed.transaction.value == 0
                && signed.transaction.data == calldata
                && signed.raw() == raw,
            "retained transaction differs from the selected chain, contract or exact call"
        );
        Ok(signed.hash())
    }

    /// Broadcast only bytes retained by a durable pre-dispatch marker.
    pub(super) fn broadcast(&self, raw: &[u8]) -> Result<[u8; 32]> {
        self.client
            .send_raw_transaction(raw)
            .map_err(|error| eyre!("eth_sendRawTransaction: {error}"))
    }
}

fn require_finalized_log(
    logs: &[iroha_sccp_rpc::evm::EvmLog],
    contract: [u8; 20],
    expected: iroha_sccp::v1::evm_abi::FinalizedLogV1,
) -> Result<()> {
    ensure!(
        logs.iter()
            .filter(|log| !log.removed
                && log.address == contract
                && iroha_sccp::v1::evm_abi::FinalizedLogV1::decode(&log.topics, &log.data)
                    == Ok(expected))
            .count()
            == 1,
        "receipt must contain exactly the original recipient, amount, nonce and message finalized event"
    );
    Ok(())
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

/// Configured endpoint custody, including runtime-only headers and request deadlines.
pub(super) fn connect_chain_config(
    config: &iroha_sccp_wallet::config::SccpClientConfig,
    rpc_override: &str,
    network: SccpNetworkV1,
) -> Result<EvmClient> {
    let kind = match network {
        SccpNetworkV1::EthereumMainnet => iroha_sccp_rpc::HttpEndpointKind::EthereumExecution,
        SccpNetworkV1::BscMainnet => iroha_sccp_rpc::HttpEndpointKind::Bsc,
        _ => return Err(eyre!("network has no EVM transport")),
    };
    let endpoints = if rpc_override.trim().is_empty() {
        config.endpoint_set(kind)?
    } else {
        EndpointSet::parse(
            &rpc_override.split(',').map(str::trim).collect::<Vec<_>>(),
            &config.secret_headers,
        )?
    };
    let client = EvmClient::new(HttpTransport::new(
        endpoints,
        config.http_config(),
        FailoverPolicy::default(),
    )?);
    ensure!(
        client.chain_id()? == eip1559_chain_id(network).map_err(|error| eyre!("{error:?}"))?,
        "configured RPC serves another chain"
    );
    Ok(client)
}

fn prepare_transaction(
    client: &EvmClient,
    network: SccpNetworkV1,
    key: &EvmSigningKey,
    to: Option<[u8; 20]>,
    data: Vec<u8>,
) -> Result<(Vec<u8>, u64)> {
    let transaction = unsigned_transaction(client, network, key.address(), to, data)?;
    let nonce = transaction.nonce;
    let signed = transaction
        .sign(key)
        .map_err(|error| eyre!("signing: {error:?}"))?;
    Ok((signed.raw(), nonce))
}

fn unsigned_transaction(
    client: &EvmClient,
    network: SccpNetworkV1,
    sender: [u8; 20],
    to: Option<[u8; 20]>,
    data: Vec<u8>,
) -> Result<Eip1559TransactionV1> {
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
    Ok(transaction)
}

use iroha_sccp::v1::constants::SCCP_EVM_DEPLOYER_RUNTIME;
/// A deterministic deployment, bound to the canonical proxy and original constructor bytes.
pub(super) struct Deployment {
    client: EvmClient,
    network: SccpNetworkV1,
    pub(super) address: [u8; 20],
    pub(super) calldata: Vec<u8>,
}
impl Deployment {
    pub(super) fn transport(&self) -> EvmTransport<'_> {
        EvmTransport {
            client: &self.client,
            network: self.network,
            contract: DEPLOYER,
            code_hash: iroha_sccp::v1::hashes::keccak256(&[&SCCP_EVM_DEPLOYER_RUNTIME]),
        }
    }
    pub(super) fn runtime_code_hash(&self) -> Result<[u8; 32]> {
        runtime_code_hash(&self.client, &self.address)
    }
}

/// Check the canonical proxy before preparing any paid deployment transaction.
pub(super) fn deployment(
    config: &iroha_sccp_wallet::config::SccpClientConfig,
    rpc_url: &str,
    network: SccpNetworkV1,
    init_code: Vec<u8>,
) -> Result<Deployment> {
    let client = connect_chain_config(config, rpc_url, network)?;
    let actual = client
        .code(&DEPLOYER, BlockId::Tag(BlockTag::Latest))
        .map_err(|error| eyre!("deployment proxy: {error}"))?;
    ensure!(
        actual.as_slice() == SCCP_EVM_DEPLOYER_RUNTIME,
        "canonical deterministic deployment proxy is absent or has different code"
    );
    let address = create2_address(&DEPLOYER, &[0; 32], &init_code);
    let mut calldata = vec![0; 32];
    calldata.extend(init_code);
    Ok(Deployment {
        client,
        network,
        address,
        calldata,
    })
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

    #[test]
    fn finalized_receipt_requires_exact_original_effect_once() {
        let expected = iroha_sccp::v1::evm_abi::FinalizedLogV1 {
            message_id: [1; 32],
            nonce: 7,
            recipient: [2; 20],
            token_amount: 31,
        };
        let (topics, data) = expected.encode();
        let log = iroha_sccp_rpc::evm::EvmLog {
            address: [3; 20],
            topics,
            data,
            log_index: Some(0),
            transaction_index: Some(0),
            transaction_hash: Some([4; 32]),
            block_hash: Some([5; 32]),
            block_number: Some(6),
            removed: false,
        };
        require_finalized_log(std::slice::from_ref(&log), [3; 20], expected).unwrap();
        assert!(require_finalized_log(&[], [3; 20], expected).is_err());
        assert!(require_finalized_log(&[log.clone(), log.clone()], [3; 20], expected).is_err());
        for changed in [
            iroha_sccp::v1::evm_abi::FinalizedLogV1 {
                message_id: [8; 32],
                ..expected
            },
            iroha_sccp::v1::evm_abi::FinalizedLogV1 {
                nonce: 8,
                ..expected
            },
            iroha_sccp::v1::evm_abi::FinalizedLogV1 {
                recipient: [8; 20],
                ..expected
            },
            iroha_sccp::v1::evm_abi::FinalizedLogV1 {
                token_amount: 8,
                ..expected
            },
        ] {
            assert!(require_finalized_log(std::slice::from_ref(&log), [3; 20], changed).is_err());
        }
        assert!(require_finalized_log(std::slice::from_ref(&log), [8; 20], expected).is_err());
        assert!(
            require_finalized_log(
                &[iroha_sccp_rpc::evm::EvmLog {
                    removed: true,
                    ..log
                }],
                [3; 20],
                expected
            )
            .is_err()
        );
    }
    use iroha_sccp::v1::{
        evm_abi::{CommitteeViewV1, PauseViewV1},
        hashes::{word_u64, word_u128},
    };
    #[test]
    fn source_endpoint_lists_preserve_order_and_enforce_chain_identity() {
        use std::{
            io::{BufRead as _, Read as _, Write as _},
            net::TcpListener,
        };
        for (chain, accepted) in [("0x1", true), ("0x38", false)] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let worker = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut input = std::io::BufReader::new(&mut stream);
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    input.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = value.trim().parse().unwrap();
                    }
                }
                let mut body = vec![0; length];
                input.read_exact(&mut body).unwrap();
                let request: norito::json::Value = norito::json::from_slice(&body).unwrap();
                assert_eq!(request["method"].as_str(), Some("eth_chainId"));
                let body = format!(
                    r#"{{"jsonrpc":"2.0","id":{},"result":"{}"}}"#,
                    request["id"].as_u64().unwrap(),
                    chain
                );
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
            });
            let config = iroha_sccp_wallet::config::SccpClientConfig::from_user(
                Default::default(),
                Path::new("target/sccp-continuation/export-test-journal"),
            )
            .unwrap();
            let result = connect_chain_config(
                &config,
                &format!(" http://{address} , http://127.0.0.1:1 "),
                SccpNetworkV1::EthereumMainnet,
            );
            if accepted {
                let client = result.unwrap();
                assert_eq!(client.transport().endpoints().len(), 2);
                assert_eq!(client.transport().endpoints().preferred(), 0);
            } else {
                assert!(result.is_err());
            }
            worker.join().unwrap();
        }
    }

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
        assert_eq!(SCCP_EVM_DEPLOYER_RUNTIME.len(), 69);
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

impl EvmDestination {
    /// Bind burn nonce and identity to the registered immutable destination before signing.
    pub(super) fn burn_call(
        &self,
        key: &EvmSigningKey,
        recipient: &[u8],
        amount: u128,
        network: [u8; 32],
        instance: [u8; 32],
    ) -> Result<Vec<u8>> {
        let observed = self.observe([])?;
        ensure!(
            observed.network == network && observed.instance == instance,
            "burn destination identity differs"
        );
        let call = ViewCallV1::TransferNonces(key.address());
        let bytes = self
            .client
            .call(
                &EvmCallRequest::new(self.contract, call.calldata()),
                BlockId::Tag(BlockTag::Latest),
            )
            .map_err(|error| eyre!("burn nonce: {error}"))?;
        let ViewReturnV1::U64(nonce) = call
            .decode_return(&bytes)
            .map_err(|error| eyre!("burn nonce: {error}"))?
        else {
            return Err(eyre!("burn nonce has the wrong type"));
        };
        iroha_sccp_wallet::pure::evm::transfer_to_taira_calldata(recipient, amount, nonce)
            .map_err(Into::into)
    }
}

impl EvmDestination {
    /// Verify the exact expired message or actual freeze before encoding one permanent void.
    pub(super) fn void_call(
        &self,
        bundle: Option<&SccpMessageProofBundleV1>,
        nonce: u64,
        frozen: bool,
        network: [u8; 32],
        instance: [u8; 32],
    ) -> Result<Vec<u8>> {
        let observed = self.observe(bundle.map(|bundle| bundle.certificate.height))?;
        ensure!(
            observed.network == network && observed.instance == instance,
            "void destination identity differs"
        );
        if frozen {
            ensure!(
                !observed.committee.is_live(observed.now_ms),
                "destination is not frozen"
            );
            return iroha_sccp_wallet::pure::evm::void_frozen_calldata(nonce, 1)
                .map_err(Into::into);
        }
        let bundle = bundle.ok_or_else(|| eyre!("expired void requires the original proof"))?;
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
            BundlePurposeV1::VoidExpired,
            source,
        )?;
        ensure!(verified.nonce() == nonce, "void proof names another nonce");
        iroha_sccp_wallet::pure::evm::void_expired_calldata(&verified).map_err(Into::into)
    }
}

impl EvmDestination {
    /// Refuse a new source transfer unless the current destination and full handoff horizon verify.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn record_preflight(
        &self,
        client: &iroha::blocking::Client,
        original: &super::origin::AuthenticatedOrigin,
        revision: &iroha::data_model::sccp::registry::SccpRouteRevisionV1,
        parameters: &iroha::data_model::sccp::params::SccpParametersV1,
        current: u64,
        margin_ms: u64,
    ) -> Result<Vec<iroha_sccp_wallet::journal::SccpEvidenceItemV1>> {
        let observed = self.observe([])?;
        let applied = DestinationControlStateV1 {
            control_nonce: observed.pause.control_nonce,
            parliament_paused: observed.pause.parliament_paused,
            fast_pause_until_ms: observed.pause.fast_pause_until_ms,
        };
        super::record::preflight(
            client,
            original,
            revision,
            &observed.context(self.destination),
            &applied,
            parameters,
            current,
            margin_ms,
        )
    }
}

#[path = "evm_monitor.rs"]
mod monitor;

#[path = "evm_receipt.rs"]
mod receipt;
