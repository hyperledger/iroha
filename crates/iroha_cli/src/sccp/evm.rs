//! EVM destination actions of `iroha sccp` for Ethereum and BSC (`specs/sccp.md` §7.1, §7.4).
//!
//! Every bundle and rotation chain read from Taira is verified locally against the
//! destination's native `committeeState()` before a transaction is built; the key comes only from an
//! owner-only key file.

use std::path::Path;

use eyre::{Result, WrapErr as _, eyre};
use iroha_sccp::{
    api::{SccpMessageProofBundleV1, SccpRotationV1},
    v1::{
        committee::CommitteeStateV1,
        destination::{
            CheckpointObservationsV1, DeploymentV1, DestinationObservationV1, MessagePurposeV1,
            PauseStateV1,
        },
        evm_abi::{ViewCallV1, ViewReturnV1, decode_u128_return},
    },
};
use iroha_sccp_rpc::{
    EndpointSet, EvmClient, FailoverPolicy, HttpConfig, HttpTransport,
    evm::{BlockId, BlockTag, EvmCallRequest},
};
use iroha_sccp_wallet::pure::{
    bundle::{BundleSourceV1, verify_message_bundle},
    evm::{
        Eip1559TransactionV1, EvmSigningKey, eip1559_chain_id, finalize_calldata,
        submit_checkpoints_calldata,
    },
    rotation::verify_rotation_steps,
};

use iroha::data_model::bridge::SccpNetworkV1;

/// A destination RPC observation is independent of Torii carriers and bound to local pins.
/// It still relies on the explicitly selected external-chain RPC; it is not a light client.
pub(super) struct EvmDestination {
    client: EvmClient,
    network: SccpNetworkV1,
    contract: [u8; 20],
    deployment: DeploymentV1,
}
impl EvmDestination {
    pub(super) fn connect(
        rpc_url: &str,
        network: SccpNetworkV1,
        contract: [u8; 20],
        deployment: DeploymentV1,
    ) -> Result<Self> {
        eyre::ensure!(
            deployment.destination_word == iroha_sccp::v1::hashes::word_address(&contract),
            "registry destination word/address mismatch"
        );
        let mut init = super::locked_creation_template()?;
        init.extend(constructor_for_deployment(&deployment));
        eyre::ensure!(
            created_address(&init) == contract,
            "destination address is not the locked native CREATE2 deployment under the selected initial pin"
        );
        Ok(Self {
            client: connect_chain(rpc_url, network)?,
            network,
            contract,
            deployment,
        })
    }
    fn view(&self, view: ViewCallV1, block: BlockId) -> Result<ViewReturnV1> {
        let data = self
            .client
            .call(&EvmCallRequest::new(self.contract, view.calldata()), block)
            .map_err(|error| eyre!("native destination view {view:?}: {error}"))?;
        view.decode_return(&data)
            .map_err(|error| eyre!("native view {view:?} decoding: {error:?}"))
    }
    fn snapshot(&self) -> Result<(BlockId, u64)> {
        let block = self
            .client
            .block_by_number(BlockTag::Latest)
            .map_err(|error| eyre!("latest block: {error}"))?
            .ok_or_else(|| eyre!("RPC has no latest block"))?;
        Ok((
            BlockId::Hash(block.header.hash),
            block
                .header
                .timestamp
                .checked_mul(1000)
                .ok_or_else(|| eyre!("block time overflow"))?,
        ))
    }
    pub(super) fn observation(&self, heights: &[u64]) -> Result<DestinationObservationV1> {
        let (block, now) = self.snapshot()?;
        self.observe_at(block, now, heights)
    }
    fn observe_at(
        &self,
        block: BlockId,
        now: u64,
        heights: &[u64],
    ) -> Result<DestinationObservationV1> {
        let d = &self.deployment;
        for (view, expected) in [
            (
                ViewCallV1::TairaNetworkId,
                ViewReturnV1::Bytes32(d.taira_network_id),
            ),
            (
                ViewCallV1::ConsensusInstance,
                ViewReturnV1::Bytes32(d.consensus_instance),
            ),
            (
                ViewCallV1::RouteRevision,
                ViewReturnV1::U32(d.route_revision),
            ),
            (
                ViewCallV1::MaxWrappedSupply,
                ViewReturnV1::U128(d.max_wrapped_supply),
            ),
            (
                ViewCallV1::MaxValidityMs,
                ViewReturnV1::U64(iroha_sccp::v1::finality::MAX_VALIDITY_MS),
            ),
            (
                ViewCallV1::InitialCommittee,
                ViewReturnV1::InitialCommittee(iroha_sccp::v1::evm_abi::InitialCommitteeViewV1 {
                    generation: d.pin_generation,
                    root: d.pin_root,
                    start: d.pin_start_height,
                    until_ms: d.pin_until_ms,
                }),
            ),
        ] {
            eyre::ensure!(
                self.view(view, block)? == expected,
                "destination immutable {view:?} does not match independently selected pin"
            );
        }
        let ViewReturnV1::CommitteeState(c) = self.view(ViewCallV1::CommitteeState, block)? else {
            return Err(eyre!("committee view type"));
        };
        let ViewReturnV1::Bool(equivocated) = self.view(ViewCallV1::Equivocated, block)? else {
            return Err(eyre!("latch view type"));
        };
        let ViewReturnV1::PauseState(p) = self.view(ViewCallV1::PauseState, block)? else {
            return Err(eyre!("pause view type"));
        };
        let mut checkpoints = std::collections::BTreeMap::new();
        for &height in heights {
            let ViewReturnV1::Bytes32(id) =
                self.view(ViewCallV1::CheckpointHeader(height), block)?
            else {
                return Err(eyre!("checkpoint view type"));
            };
            checkpoints.insert(height, (id != [0; 32]).then_some(id));
        }
        DestinationObservationV1::new(
            d.clone(),
            CommitteeStateV1 {
                root: c.root,
                generation: c.generation,
                start: c.start,
                high: c.high,
                until_ms: c.until_ms,
                equivocated,
            },
            None,
            CheckpointObservationsV1::Evm(checkpoints),
            PauseStateV1 {
                parliament_paused: p.parliament_paused,
                fast_pause_until_ms: p.fast_pause_until_ms,
                control_nonce: p.control_nonce,
                effective: p.effective,
            },
            now,
        )
        .map_err(|error| eyre!("native destination observation: {error}"))
    }
    pub(super) fn finalize_call(
        &self,
        bundle: &SccpMessageProofBundleV1,
        expected_id: &[u8; 32],
        source: BundleSourceV1,
    ) -> Result<Vec<u8>> {
        let (block, now) = self.snapshot()?;
        let observation = self.observe_at(block, now, &[bundle.certificate.height])?;
        let verified = verify_message_bundle(
            bundle,
            expected_id,
            &observation,
            source,
            MessagePurposeV1::Finalize,
        )?;
        eyre::ensure!(
            self.view(ViewCallV1::IsConsumed(verified.nonce()), block)?
                == ViewReturnV1::Bool(false),
            "nonce was already consumed"
        );
        let supply = self
            .client
            .call(
                &EvmCallRequest::new(self.contract, vec![0x18, 0x16, 0x0d, 0xdd]),
                block,
            )
            .map_err(|error| eyre!("totalSupply: {error}"))?;
        let supply =
            decode_u128_return(&supply).map_err(|error| eyre!("totalSupply: {error:?}"))?;
        eyre::ensure!(
            supply <= self.deployment.max_wrapped_supply
                && verified.amount() <= self.deployment.max_wrapped_supply - supply,
            "mint exceeds current supply cap"
        );
        finalize_calldata(&verified).map_err(|error| eyre!("native finalize encoding: {error}"))
    }
    pub(super) fn checkpoint_calls(&self, steps: &[SccpRotationV1]) -> Result<Vec<Vec<u8>>> {
        eyre::ensure!(steps.len() <= 16, "rotation page exceeds 16");
        let heights = steps
            .iter()
            .map(|step| step.certificate.height)
            .collect::<Vec<_>>();
        let observation = self.observation(&heights)?;
        let target = super::rotation_target(steps, observation.committee().generation)?;
        let plan = verify_rotation_steps(steps, None, &observation, target)?;
        // This submits only the checked prefix, including an explicit persisted freeze/latch.
        submit_checkpoints_calldata(&plan)
            .map_err(|error| eyre!("native checkpoint encoding: {error}"))
    }
    pub(super) fn send(&self, key: &EvmSigningKey, data: Vec<u8>) -> Result<[u8; 32]> {
        send_transaction(&self.client, self.network, key, self.contract, data).map(|(hash, _)| hash)
    }
}

/// Timestamp of the selected latest external block, in milliseconds.
pub(super) fn now_ms(client: &EvmClient) -> Result<u64> {
    client
        .block_by_number(BlockTag::Latest)
        .map_err(|error| eyre!("latest block: {error}"))?
        .ok_or_else(|| eyre!("RPC has no latest block"))?
        .header
        .timestamp
        .checked_mul(1000)
        .ok_or_else(|| eyre!("block time overflow"))
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

/// Sign and broadcast a call of `to` with `key`, returning
/// the transaction hash and the sender nonce it used.
pub(super) fn send_transaction(
    client: &EvmClient,
    network: SccpNetworkV1,
    key: &EvmSigningKey,
    to: [u8; 20],
    data: Vec<u8>,
) -> Result<([u8; 32], u64)> {
    let sender = key.address();
    let nonce = client
        .transaction_count(&sender, BlockId::Tag(BlockTag::Pending))
        .map_err(|error| eyre!("eth_getTransactionCount: {error}"))?;
    let mut request = EvmCallRequest::new(to, data.clone());
    request.from = Some(sender);
    let gas = client
        .estimate_gas(&request)
        .map_err(|error| eyre!("eth_estimateGas (the call would revert): {error}"))?;
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
        to: Some(to),
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

/// Canonical keyless CREATE2 deployer, salt zero (§5.2.1).
const DEPLOYER: [u8; 20] = [
    0x4e, 0x59, 0xb4, 0x48, 0x47, 0xb3, 0x79, 0x57, 0x85, 0x88, 0x92, 0x0c, 0xa7, 0x8f, 0xbf, 0x26,
    0xc0, 0xb4, 0x95, 0x6c,
];

/// Address of the exact native init code under the sole SCCP deployment scheme.
#[must_use]
pub(super) fn created_address(init_code: &[u8]) -> [u8; 20] {
    let hash = iroha_sccp::v1::hashes::keccak256(&[
        &[0xff],
        &DEPLOYER,
        &[0; 32],
        &iroha_sccp::v1::hashes::keccak256(&[init_code]),
    ]);
    hash[12..].try_into().expect("fixed hash suffix")
}

/// Submit only the canonical keyless proxy call; no direct CREATE fallback.
pub(super) fn deploy(
    client: &EvmClient,
    network: SccpNetworkV1,
    key: &EvmSigningKey,
    init_code: Vec<u8>,
) -> Result<[u8; 32]> {
    eyre::ensure!(
        !client
            .code(&DEPLOYER, BlockId::Tag(BlockTag::Latest))
            .map_err(|error| eyre!("deployer code: {error}"))?
            .is_empty(),
        "canonical keyless deployer is unavailable"
    );
    // TODO: pin the common proxy runtime hash after the canonical cross-network qualification.
    let mut data = vec![0; 32];
    data.extend(init_code);
    send_transaction(client, network, key, DEPLOYER, data).map(|(hash, _)| hash)
}

/// The exact nine native constructor words (§5.2.1).
#[must_use]
pub(super) fn constructor_args(
    pin: &super::NativePin,
    network: SccpNetworkV1,
    revision: u32,
    cap: u128,
) -> Vec<u8> {
    constructor_for_deployment(&pin.deployment(network, revision, [0; 32], cap))
}
fn constructor_for_deployment(d: &DeploymentV1) -> Vec<u8> {
    use iroha_sccp::v1::{
        evm_abi::{AbiToken, encode_tokens},
        hashes::{word_u64, word_u128},
    };
    encode_tokens(&[
        AbiToken::Word(d.taira_network_id),
        AbiToken::Word(d.consensus_instance),
        AbiToken::Word(word_u64(u64::from(iroha_sccp::v1::network::tag(d.network)))),
        AbiToken::Word(word_u64(u64::from(d.route_revision))),
        AbiToken::Word(word_u128(d.max_wrapped_supply)),
        AbiToken::Word(word_u64(d.pin_generation)),
        AbiToken::Word(d.pin_root),
        AbiToken::Word(word_u64(d.pin_start_height)),
        AbiToken::Word(word_u64(d.pin_until_ms)),
    ])
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
    fn created_addresses_follow_the_keyless_create2_rule() {
        let init = hex::decode("60006000f3").unwrap();
        // Independent PyCryptodome Keccak reference, retained in this migration packet.
        assert_eq!(
            hex::encode(created_address(&init)),
            "5415ff926e55733ba02095045bd818a5100325c9"
        );
        assert_eq!(
            hex::encode(created_address(&[0])),
            "24c4fd2db1cf4cb1aec651cc0e060a00d400e784"
        );
        assert_ne!(created_address(&init), created_address(&[0]));
    }
    #[test]
    fn constructor_arguments_pin_all_nine_native_words() {
        let pin = super::super::tests::native_pin();
        let encoded = constructor_args(&pin, SccpNetworkV1::EthereumMainnet, 1, 1000);
        assert_eq!(&encoded[..32], &pin.network_id);
        assert_eq!(&encoded[32..64], &pin.instance);
        assert_eq!(encoded[95], 0x41);
        assert_eq!(encoded[127], 1);
        assert_eq!(
            u128::from_be_bytes(encoded[144..160].try_into().unwrap()),
            1000
        );
        assert_eq!(&encoded[192..224], &pin.committee.committee_root);
        assert_eq!(encoded.len(), 9 * 32);
        assert_eq!(encoded.len() % 32, 0);
        let mut changed = pin.clone();
        changed.instance[0] ^= 1;
        assert_ne!(
            encoded,
            constructor_args(&changed, SccpNetworkV1::EthereumMainnet, 1, 1000)
        );
    }
}
