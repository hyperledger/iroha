//! TON destination actions of `iroha sccp` (`specs/sccp.md` §5.3, §7.1, §7.4).
//!
//! ADNL get methods guide preparation, while native masterchain, shard and account proofs
//! authenticate journal completion and retirement of the original wallet sequence. Verified
//! bundles become internal messages from the user's deployed `v5r1` wallet, signed with an
//! owner-only Ed25519 key file.

use super::{
    BlockingClient, BuildError, LightClientReplayV1, SccpLcConsensusSetV1, SccpLightClientV1,
    SccpNetworkV1, origin,
};
use eyre::{Result, ensure, eyre};
use iroha_sccp::{
    api::{SccpControlProofBundleV1, SccpMessageProofBundleV1, SccpRotationV1},
    v1::{
        committee::{CommitteeStateV1, committee_root, is_valid_committee_size},
        destination::DestinationFlavor,
        proof::DestinationV1,
        ton_cell::Cell,
    },
};
use iroha_sccp_rpc::{
    FailoverPolicy,
    ton::{AccountId, BlockIdExt, LiteClient, LiteClientConfig, LiteServerSet},
};
use iroha_sccp_wallet::pure::{
    bundle::{BundlePurposeV1, CertificateUseV1, DestinationContextV1, verify_message_bundle},
    control::{DestinationControlStateV1, verify_control_bundle},
    rotation::verify_rotation_steps,
    ton::{
        SEND_MODE_PAY_FEES_SEPARATELY_IGNORE_ERRORS, TonAccountV1, TonWalletKeyV1, TvmIntV1,
        TvmStackValueV1, WALLET_V5R1_MAINNET_ID, checkpoint_body, finalize_body, get_method_id,
        internal_message, parse_stack, quote_with_margin, stack_of_uints, wallet_v5_transfer,
    },
};
use std::collections::BTreeMap;

/// Lifetime of a wallet external message (seconds).
const EXTERNAL_LIFETIME_S: u32 = 120;

/// Configured liteservers and deadlines, with an optional explicit list override.
pub(super) fn connect_config(
    config: &iroha_sccp_wallet::config::SccpClientConfig,
    liteservers: &str,
) -> Result<LiteClient> {
    let servers = if liteservers.trim().is_empty() {
        LiteServerSet::from_config(&config.endpoints.ton_liteservers)?
    } else {
        LiteServerSet::parse(&liteservers.split(',').map(str::trim).collect::<Vec<_>>())?
    };
    Ok(LiteClient::new(
        servers,
        LiteClientConfig {
            connect_timeout: config.request_timeout,
            request_timeout: config.request_timeout,
            ..LiteClientConfig::default()
        },
        FailoverPolicy::default(),
    ))
}

/// Parse a raw workchain-0 address `0:<64 hex>`.
pub(super) fn parse_account(text: &str) -> Result<TonAccountV1> {
    let hex_part = text
        .strip_prefix("0:")
        .ok_or_else(|| eyre!("a TON account is a raw `0:<64 hex>` address"))?;
    let bytes = hex::decode(hex_part).map_err(|_| eyre!("TON account id is not hex"))?;
    <[u8; 32]>::try_from(bytes).map_err(|_| eyre!("TON account id must be 32 bytes"))
}

pub(super) fn last_block(lite: &LiteClient) -> Result<BlockIdExt> {
    Ok(lite
        .get_masterchain_info()
        .map_err(|error| eyre!("getMasterchainInfo: {error}"))?
        .last)
}

/// Time from a hash-bound opened header at the exact block selected for all state queries.
/// The independently selected liteserver remains the external-chain observation boundary;
/// this helper does not claim to verify a TON finality chain.
pub(super) fn block_time_ms(lite: &LiteClient, block: BlockIdExt) -> Result<u64> {
    let proof = lite
        .get_block_header(block, 0)
        .map_err(|error| eyre!("getBlockHeader: {error}"))?;
    let seconds = iroha_sccp::ton_masterchain_generation_time_seconds(
        iroha_sccp_rpc::builders::ton::block_id(&block),
        &proof.header_proof,
    )
    .map_err(|error| eyre!("opened requested masterchain header: {error}"))?;
    Ok(u64::from(seconds) * 1000)
}

/// Run a current result stack at one explicitly selected masterchain block.
pub(super) fn run_stack_at(
    lite: &LiteClient,
    at: BlockIdExt,
    account: &TonAccountV1,
    method: &str,
    args: &[u64],
) -> Result<Vec<TvmStackValueV1>> {
    let result = lite
        .run_smc_method(
            4,
            at,
            AccountId {
                workchain: 0,
                address: *account,
            },
            get_method_id(method),
            stack_of_uints(args).map_err(|e| eyre!("{method} arguments: {e}"))?,
        )
        .map_err(|e| eyre!("runSmcMethod {method}: {e}"))?;
    ensure!(result.id == at, "get-method returned another block");
    ensure!(
        result.exit_code == 0 || result.exit_code == 1,
        "{method} exited with code {}",
        result.exit_code
    );
    parse_stack(
        &result
            .result
            .ok_or_else(|| eyre!("{method} returned no stack"))?,
    )
    .map_err(|e| eyre!("{method} result: {e}"))
}
fn integer_stack(values: Vec<TvmStackValueV1>) -> Result<Vec<Option<TvmIntV1>>> {
    values
        .into_iter()
        .map(|value| match value {
            TvmStackValueV1::Null => Ok(None),
            TvmStackValueV1::Integer(value) => Ok(Some(value)),
            TvmStackValueV1::Cell(_) => Err(eyre!("expected an integer result, received a cell")),
        })
        .collect()
}
/// Run an existing integer-only wallet/quote get method at the latest block.
fn run_method(
    lite: &LiteClient,
    account: &TonAccountV1,
    method: &str,
    args: &[u64],
) -> Result<Vec<Option<TvmIntV1>>> {
    integer_stack(run_stack_at(
        lite,
        last_block(lite)?,
        account,
        method,
        args,
    )?)
}

fn int_at(values: &[Option<TvmIntV1>], index: usize, what: &str) -> Result<TvmIntV1> {
    values
        .get(index)
        .copied()
        .flatten()
        .ok_or_else(|| eyre!("the minter state has no integer `{what}`"))
}

/// The user's deployed `v5r1` wallet and its key.
pub(super) struct TonWallet {
    address: TonAccountV1,
    key: TonWalletKeyV1,
}

impl TonWallet {
    /// Load `key_file` for the wallet at `address` and check the wallet's public key.
    pub(super) fn load(
        lite: &LiteClient,
        address: &str,
        key_file: &std::path::Path,
    ) -> Result<Self> {
        let address = parse_account(address)?;
        let key = TonWalletKeyV1::load(key_file).map_err(|error| eyre!("TON key file: {error}"))?;
        let public = run_method(lite, &address, "get_public_key", &[])?;
        ensure!(
            public.len() == 1,
            "wallet public-key reply has extra fields"
        );
        let public = int_at(&public, 0, "public key")?
            .to_u256()
            .ok_or_else(|| eyre!("the wallet public key is not a 256-bit value"))?;
        if public != key.public_key() {
            return Err(eyre!(
                "the key file does not control wallet 0:{}",
                hex::encode(address)
            ));
        }
        Ok(Self { address, key })
    }

    /// The wallet account.
    pub(super) const fn address(&self) -> &TonAccountV1 {
        &self.address
    }

    /// Prepare exact signed bytes without sending; the caller retains them before dispatch.
    pub(super) fn prepare(
        &self,
        lite: &LiteClient,
        messages: &[(iroha_sccp::v1::ton_cell::Cell, u8)],
    ) -> Result<Vec<u8>> {
        let (seqno, valid_until) = wallet_coordinates(lite, &self.address)?;
        let boc = wallet_v5_transfer(
            &self.address,
            WALLET_V5R1_MAINNET_ID,
            seqno,
            valid_until,
            messages,
            &self.key,
        )
        .map_err(|error| eyre!("wallet message: {error}"))?;
        Ok(boc)
    }
}

fn wallet_coordinates(lite: &LiteClient, address: &TonAccountV1) -> Result<(u32, u32)> {
    let block = last_block(lite)?;
    let seqno = wallet_seqno_at(lite, block, address)?;
    let now = u32::try_from(block_time_ms(lite, block)? / 1000)?;
    Ok((
        seqno,
        now.checked_add(EXTERNAL_LIFETIME_S)
            .ok_or_else(|| eyre!("wallet message deadline overflows"))?,
    ))
}

fn wallet_seqno_at(lite: &LiteClient, block: BlockIdExt, address: &TonAccountV1) -> Result<u32> {
    let seqno = integer_stack(run_stack_at(lite, block, address, "seqno", &[])?)?;
    ensure!(seqno.len() == 1, "wallet seqno reply has extra fields");
    int_at(&seqno, 0, "seqno")?
        .to_u64()
        .and_then(|seqno| u32::try_from(seqno).ok())
        .ok_or_else(|| eyre!("the wallet seqno is not a u32"))
}

/// Authenticated retirement and the complete evidence needed to independently replay it.
#[derive(norito::derive::JsonSerialize)]
pub(super) struct WalletRetirement {
    wallet: String,
    original_seqno: u32,
    verified: iroha_sccp::light_client::ton::wallet_state::VerifiedTonWalletStateV1,
    proof: iroha_sccp::light_client::ton::wallet_state::TonAccountStateProofV1,
    light_client: SccpLightClientV1,
    signing_set: SccpLcConsensusSetV1,
    verification_time_ms: u64,
}

impl WalletRetirement {
    pub(super) fn retired(&self) -> bool {
        self.verified.seqno() > self.original_seqno
    }
}

pub(super) struct AuthenticatedAccountEvidence {
    pub(super) profiles: iroha_sccp::light_client::profile::SccpChainProfilesV1,
    pub(super) replay: LightClientReplayV1,
    pub(super) proof: iroha_sccp::light_client::ton::wallet_state::TonAccountStateProofV1,
    pub(super) now: u64,
    pub(super) light_client: SccpLightClientV1,
    pub(super) signing_set: SccpLcConsensusSetV1,
}

pub(super) fn account_state_evidence(
    client: &BlockingClient,
    origin: &origin::AuthenticatedOrigin,
    lite: &LiteClient,
    account: [u8; 32],
) -> Result<Option<AuthenticatedAccountEvidence>> {
    let bounded_client = lite
        .budget()
        .deadline()
        .map(|deadline| client.with_request_deadline(deadline))
        .transpose()?;
    let client = bounded_client.as_ref().unwrap_or(client);
    let profiles = origin.light_client_profiles(client)?;
    let network = SccpNetworkV1::TonMainnet;
    let light_client = client.sccp().light_client(network)?.light_client;
    let newest = client
        .sccp()
        .light_client_sets(network)?
        .into_iter()
        .find(|set| set.set_id == light_client.head.latest_set_id)
        .ok_or_else(|| eyre!("the original TON signing set is unavailable"))?;
    origin.verify_burn_light_client(network, &light_client, &newest)?;
    let now = origin.source_verification_time_ms(super::wall_clock_ms());
    let replay = LightClientReplayV1::new(
        &profiles,
        network,
        light_client,
        vec![newest.clone()],
        vec![],
    );
    let proof_lite = LiteClient::new(
        lite.servers().clone(),
        *lite.config(),
        FailoverPolicy::default(),
    )
    .with_budget(lite.budget().clone());
    let builder = iroha_sccp_rpc::builders::ton::TonBuilder::new(profiles.ton, proof_lite);
    let proof = match builder.account_state_proof(account, &replay, now) {
        Ok(proof) => proof,
        Err(BuildError::Unavailable(_)) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    Ok(Some(AuthenticatedAccountEvidence {
        profiles,
        replay,
        proof,
        now,
        light_client,
        signing_set: newest,
    }))
}

pub(super) fn wallet_retirement(
    client: &BlockingClient,
    origin: &origin::AuthenticatedOrigin,
    lite: &LiteClient,
    original: &[u8],
) -> Result<Option<WalletRetirement>> {
    use iroha_sccp::light_client::ton::wallet_state::verify_wallet_state;
    let envelope = iroha_sccp_wallet::pure::ton::wallet_v5_envelope(original)?;
    // The canonical envelope parser admits only addr_std workchain zero.
    let account = envelope.wallet;
    let Some(evidence) = account_state_evidence(client, origin, lite, account)? else {
        return Ok(None);
    };
    let verified = verify_wallet_state(
        &evidence.profiles.ton,
        evidence.replay.state(),
        &evidence.proof,
        account,
        envelope.wallet_id,
        evidence.now,
    )?;
    Ok(Some(WalletRetirement {
        wallet: hex::encode(envelope.wallet),
        original_seqno: envelope.seqno,
        verified,
        proof: evidence.proof,
        light_client: evidence.light_client,
        signing_set: evidence.signing_set,
        verification_time_ms: evidence.now,
    }))
}

/// Build the exact unsigned v5r1 request without loading or invoking a private key.
pub(super) fn unsigned_wallet_request(
    lite: &LiteClient,
    wallet: &TonAccountV1,
    messages: &[(Cell, u8)],
) -> Result<Cell> {
    let (seqno, valid_until) = wallet_coordinates(lite, wallet)?;
    Ok(iroha_sccp_wallet::pure::ton::wallet_v5_unsigned_request(
        WALLET_V5R1_MAINNET_ID,
        seqno,
        valid_until,
        messages,
    )?)
}

/// Submit only an already retained external message; its seqno and deadline remain unchanged.
pub(super) fn broadcast(lite: &LiteClient, boc: &[u8]) -> Result<[u8; 32]> {
    let hash = iroha_sccp::ton_boc_single_root_hash_v1(boc)
        .ok_or_else(|| eyre!("original wallet message is not a canonical single-root BoC"))?;
    let response = lite
        .send_message(boc.to_vec())
        .map_err(|error| eyre!("sendMessage: {error}"))?;
    ensure!(
        response.status == 1,
        "liteserver refused original message ({})",
        response.status
    );
    Ok(hash)
}

/// One TON deployment (the minter) reached through liteservers.
pub(super) struct TonDestination {
    lite: LiteClient,
    config: iroha_sccp_wallet::config::SccpClientConfig,
    liteservers: String,
    minter: TonAccountV1,
    destination: DestinationV1,
}

#[derive(norito::derive::JsonSerialize, norito::derive::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct HistoryProgress {
    account: [u8; 32],
    lt: u64,
    hash: [u8; 32],
}

fn history_start(
    step: &iroha_sccp_wallet::journal::SccpJournalStep,
    account: [u8; 32],
    head: iroha_sccp::ton_watch::Cursor,
) -> Result<iroha_sccp::ton_watch::Cursor> {
    let cursor = step
        .discovery::<HistoryProgress>()?
        .filter(|hint| hint.account == account && hint.lt != 0 && hint.hash != [0; 32])
        .map_or(head, |hint| iroha_sccp::ton_watch::Cursor {
            lt: hint.lt,
            hash: hint.hash,
        });
    history_next(step, account, Some(cursor))?;
    Ok(cursor)
}

fn history_next(
    step: &iroha_sccp_wallet::journal::SccpJournalStep,
    account: [u8; 32],
    cursor: Option<iroha_sccp::ton_watch::Cursor>,
) -> Result<()> {
    let (lt, hash) = cursor.map_or((0, [0; 32]), |cursor| (cursor.lt, cursor.hash));
    step.save_discovery(&HistoryProgress { account, lt, hash })?;
    Ok(())
}

impl TonDestination {
    /// Fund only the original retained operation id, never a new finalize or burn.
    pub(super) fn prepare_retry(&self, wallet: &TonWallet, operation_id: u64) -> Result<Vec<u8>> {
        let body =
            iroha_sccp_wallet::pure::ton::retry_body(operation_id, operation_id, wallet.address())?;
        let value = self.quoted_value("retry_required_value", &[])?;
        let message =
            iroha_sccp_wallet::pure::ton::internal_message(&self.minter, value, true, body, None)?;
        wallet.prepare(
            &self.lite,
            &[(message, SEND_MODE_PAY_FEES_SEPARATELY_IGNORE_ERRORS)],
        )
    }

    /// Connect to configured liteservers, optionally overriding their public list.
    pub(super) fn connect(
        config: &iroha_sccp_wallet::config::SccpClientConfig,
        liteservers: &str,
        minter: TonAccountV1,
        destination: DestinationV1,
    ) -> Result<Self> {
        Ok(Self {
            lite: connect_config(config, liteservers)?,
            config: config.clone(),
            liteservers: liteservers.to_owned(),
            minter,
            destination,
        })
    }

    /// The liteserver client.
    pub(super) const fn lite(&self) -> &LiteClient {
        &self.lite
    }

    fn observe(&self) -> Result<Observation> {
        let at = last_block(&self.lite)?;
        let state = integer_stack(run_stack_at(
            &self.lite,
            at,
            &self.minter,
            "get_sccp_state",
            &[],
        )?)?;
        let committee = run_stack_at(&self.lite, at, &self.minter, "get_sccp_committee", &[])?;
        let checkpoints = integer_stack(run_stack_at(
            &self.lite,
            at,
            &self.minter,
            "get_sccp_checkpoints",
            &[],
        )?)?;
        parse_observation(
            self.destination.route_revision,
            &state,
            committee,
            &checkpoints,
            block_time_ms(&self.lite, at)?,
        )
    }
    /// Get method `method` of the minter returning one value in nanotons (a required-value
    /// quote, §5.3.5), plus the [`quote_with_margin`] margin: the minter returns what its step
    /// does not use.
    fn quoted_value(&self, method: &str, args: &[u64]) -> Result<u128> {
        let values = run_method(&self.lite, &self.minter, method, args)?;
        ensure!(values.len() == 1, "quote reply has extra fields");
        Ok(quote_with_margin(ton_coins(int_at(&values, 0, method)?)?))
    }

    /// Verify the actual current source and send a finalization from the selected wallet.
    pub(super) fn prepare_finalize(
        &self,
        bundle: &SccpMessageProofBundleV1,
        network: [u8; 32],
        instance: [u8; 32],
        required_control: u64,
        wallet: &TonWallet,
    ) -> Result<Vec<u8>> {
        let message = self.finalize_message(
            bundle,
            network,
            instance,
            required_control,
            wallet.address(),
        )?;
        wallet.prepare(
            &self.lite,
            &[(message, SEND_MODE_PAY_FEES_SEPARATELY_IGNORE_ERRORS)],
        )
    }

    /// Verify the same original bundle for signed submission and unsigned export.
    pub(super) fn finalize_message(
        &self,
        bundle: &SccpMessageProofBundleV1,
        network: [u8; 32],
        instance: [u8; 32],
        required_control: u64,
        response_wallet: &TonAccountV1,
    ) -> Result<Cell> {
        let observed = self.observe()?;
        ensure!(
            observed.network == network && observed.instance == instance,
            "Taira and minter identities differ"
        );
        super::administration::require_latest_control(
            observed.control.control_nonce,
            required_control,
        )?;
        ensure!(!observed.paused, "the destination is paused");
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
        let nonce = verified.nonce();
        let value = self.quoted_value("finalize_required_value", &[nonce])?;
        let body = finalize_body(&verified, verified.nonce(), response_wallet)
            .map_err(|e| eyre!("finalize: {e}"))?;
        let message = internal_message(&self.minter, value, true, body, None)
            .map_err(|e| eyre!("internal message: {e}"))?;
        Ok(message)
    }
    /// Authenticate and send one complete destination control.
    pub(super) fn prepare_control(
        &self,
        bundle: &SccpControlProofBundleV1,
        network: [u8; 32],
        instance: [u8; 32],
        wallet: &TonWallet,
    ) -> Result<Vec<u8>> {
        let message = self.control_message(bundle, network, instance, wallet.address())?;
        wallet.prepare(
            &self.lite,
            &[(message, SEND_MODE_PAY_FEES_SEPARATELY_IGNORE_ERRORS)],
        )
    }

    /// Verified control internal message shared by signed and external-signer paths.
    pub(super) fn control_message(
        &self,
        bundle: &SccpControlProofBundleV1,
        network: [u8; 32],
        instance: [u8; 32],
        response_wallet: &TonAccountV1,
    ) -> Result<Cell> {
        let observed = self.observe()?;
        ensure!(
            observed.network == network && observed.instance == instance,
            "Taira and minter identities differ"
        );
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
            &observed.control,
            source,
        )
        .map_err(|e| eyre!("control proof: {e}"))?;
        let value = self.quoted_value("apply_control_required_value", &[])?;
        let body = iroha_sccp_wallet::pure::ton::apply_control_body(
            &verified,
            verified.control_nonce(),
            response_wallet,
        )
        .map_err(|e| eyre!("control body: {e}"))?;
        let message = internal_message(&self.minter, value, true, body, None)
            .map_err(|e| eyre!("control message: {e}"))?;
        Ok(message)
    }

    /// Check the selected minter's original identity through its current strict getters.
    pub(super) fn verify_identity(&self, network: [u8; 32], instance: [u8; 32]) -> Result<()> {
        let observed = self.observe()?;
        ensure!(
            observed.network == network && observed.instance == instance,
            "Taira and minter identities differ"
        );
        Ok(())
    }

    /// Read complete applied control fields at one selected masterchain block.
    pub(super) fn control_observation(
        &self,
        network: [u8; 32],
        instance: [u8; 32],
    ) -> Result<(
        iroha_sccp_wallet::pure::control::DestinationControlStateV1,
        u64,
    )> {
        let observed = self.observe()?;
        ensure!(
            observed.network == network && observed.instance == instance,
            "Taira and the selected minter have different identities"
        );
        Ok((observed.control, observed.now_ms))
    }

    /// Verify a genuine checkpoint chain and send its current TON checkpoint messages in order.
    pub(super) fn prepare_rotation(
        &self,
        steps: &[SccpRotationV1],
        target: u64,
        network: [u8; 32],
        instance: [u8; 32],
        wallet: &TonWallet,
    ) -> Result<Vec<u8>> {
        let messages =
            self.rotation_messages(steps, target, network, instance, wallet.address())?;
        wallet.prepare(&self.lite, &messages)
    }

    /// Verified bounded checkpoint actions shared by signed and external-signer paths.
    pub(super) fn rotation_messages(
        &self,
        steps: &[SccpRotationV1],
        target: u64,
        network: [u8; 32],
        instance: [u8; 32],
        response_wallet: &TonAccountV1,
    ) -> Result<Vec<(Cell, u8)>> {
        let observed = self.observe()?;
        ensure!(
            observed.network == network && observed.instance == instance,
            "Taira and minter identities differ"
        );
        let plan = verify_rotation_steps(steps, &observed.context(self.destination), target)
            .map_err(|e| eyre!("committee checkpoint chain: {e}"))?;
        ensure!(!plan.is_empty(), "committee is already current");
        let value = self.quoted_value("checkpoint_required_value", &[])?;
        let messages = plan
            .steps()
            .iter()
            .map(|step| {
                let body = checkpoint_body(
                    step,
                    iroha_sccp::v1::finality::SccpFinalityHeaderV1::parse(
                        &step.certificate().header,
                    )
                    .map_err(|e| eyre!("verified header: {e}"))?
                    .height(),
                    response_wallet,
                )
                .map_err(|e| eyre!("checkpoint message: {e}"))?;
                Ok((
                    internal_message(&self.minter, value, true, body, None)
                        .map_err(|e| eyre!("internal message: {e}"))?,
                    SEND_MODE_PAY_FEES_SEPARATELY_IGNORE_ERRORS,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(messages)
    }
}

struct Observation {
    network: [u8; 32],
    instance: [u8; 32],
    committee: CommitteeStateV1,
    keys: Vec<[u8; 48]>,
    checkpoints: BTreeMap<u64, [u8; 32]>,
    paused: bool,
    control: DestinationControlStateV1,
    now_ms: u64,
}
impl Observation {
    fn context(&self, destination: DestinationV1) -> DestinationContextV1<'_> {
        DestinationContextV1 {
            taira_network_id: self.network,
            consensus_instance: self.instance,
            destination,
            flavor: DestinationFlavor::Ton,
            committee_state: self.committee,
            ton_keys: Some(&self.keys),
            checkpoints: &self.checkpoints,
            now_ms: self.now_ms,
        }
    }
}
fn bool_at(values: &[Option<TvmIntV1>], index: usize) -> Result<bool> {
    let value = int_at(values, index, "bool")?;
    if value.0 == [0; 33] {
        Ok(false)
    } else if value.0 == [0xff; 33] {
        Ok(true)
    } else {
        Err(eyre!("noncanonical TVM boolean"))
    }
}
fn ton_coins(value: TvmIntV1) -> Result<u128> {
    let bytes = value.to_u256().ok_or_else(|| eyre!("negative TON Coins"))?;
    ensure!(bytes[..17] == [0; 17], "value exceeds TON Coins");
    Ok(u128::from_be_bytes(bytes[16..].try_into()?))
}
fn keys_from_chunks(root: &Cell, n: usize) -> Result<Vec<[u8; 48]>> {
    ensure!(is_valid_committee_size(n), "invalid native committee size");
    let mut keys = Vec::with_capacity(n);
    let mut node = root;
    loop {
        let count = (n - keys.len()).min(2);
        let bytes = count * 48;
        let more = keys.len() + count < n;
        ensure!(
            node.bit_len() == bytes * 8 + 1 && node.refs().len() == usize::from(more),
            "noncanonical key chunk shape"
        );
        ensure!(
            (node.data()[bytes] & 0x80 != 0) == more,
            "noncanonical key chunk continuation"
        );
        for key in node.data()[..bytes].chunks_exact(48) {
            keys.push(key.try_into().expect("fixed key"));
        }
        if !more {
            return Ok(keys);
        }
        node = node.refs()[0]
            .cell()
            .ok_or_else(|| eyre!("opaque key chunk"))?;
    }
}
fn parse_observation(
    revision: u32,
    state: &[Option<TvmIntV1>],
    mut committee: Vec<TvmStackValueV1>,
    checkpoints: &[Option<TvmIntV1>],
    now_ms: u64,
) -> Result<Observation> {
    ensure!(
        state.len() == 24 && committee.len() == 7 && checkpoints.len() == 7,
        "current minter result arity differs"
    );
    let u64_at = |values: &[Option<TvmIntV1>], i| {
        int_at(values, i, "uint64")?
            .to_u64()
            .ok_or_else(|| eyre!("invalid uint64 field"))
    };
    let word_at = |values: &[Option<TvmIntV1>], i| {
        int_at(values, i, "uint256")?
            .to_u256()
            .ok_or_else(|| eyre!("invalid uint256 field"))
    };
    ensure!(bool_at(state, 0)?, "minter is uninitialized");
    ensure!(
        u64_at(state, 4)? == u64::from(revision),
        "minter revision differs from selected registry record"
    );
    let current = CommitteeStateV1 {
        root: word_at(state, 9)?,
        until_ms: u64_at(state, 10)?,
        start: u64_at(state, 11)?,
        high: u64_at(state, 12)?,
        generation: u64_at(state, 13)?,
        equivocated: bool_at(state, 1)?,
    };
    let TvmStackValueV1::Cell(keys) = committee.pop().expect("checked arity") else {
        return Err(eyre!("committee key result is not a cell"));
    };
    let fields = integer_stack(committee)?;
    ensure!(
        word_at(&fields, 0)? == current.root
            && u64_at(&fields, 1)? == current.until_ms
            && u64_at(&fields, 2)? == current.start
            && u64_at(&fields, 3)? == current.high
            && u64_at(&fields, 4)? == current.generation,
        "committee and minter observations differ"
    );
    let keys = keys_from_chunks(&keys, usize::try_from(u64_at(&fields, 5)?)?)?;
    ensure!(
        committee_root(&keys) == Some(current.root),
        "stored canonical keys differ from current root"
    );
    let count = usize::try_from(u64_at(checkpoints, 0)?)?;
    ensure!(count <= 3, "too many TON checkpoints");
    let mut stored = BTreeMap::new();
    let mut previous = 0;
    for index in 0..3 {
        let height = u64_at(checkpoints, 1 + 2 * index)?;
        let id = word_at(checkpoints, 2 + 2 * index)?;
        if index < count {
            ensure!(
                height > previous && id != [0; 32],
                "invalid or reordered checkpoint slot"
            );
            stored.insert(height, id);
            previous = height;
        } else {
            ensure!(
                height == 0 && id == [0; 32],
                "unused checkpoint slot is nonzero"
            );
        }
    }
    let network = word_at(state, 2)?;
    let instance = word_at(state, 3)?;
    ensure!(
        network != [0; 32] && instance != [0; 32],
        "zero minter identity"
    );
    let parliament_paused = bool_at(state, 16)?;
    let fast_pause_until_ms = u64_at(state, 17)?;
    let paused = bool_at(state, 18)?;
    ensure!(
        paused == (parliament_paused || now_ms < fast_pause_until_ms),
        "pause observation differs from selected block time"
    );
    Ok(Observation {
        network,
        instance,
        committee: current,
        keys,
        checkpoints: stored,
        paused,
        control: DestinationControlStateV1 {
            control_nonce: u64_at(state, 19)?,
            parliament_paused,
            fast_pause_until_ms,
        },
        now_ms,
    })
}

#[cfg(test)]
pub(super) fn test_wallet_retirement(observed_seqno: u32) -> WalletRetirement {
    tests::retirement(observed_seqno)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sccp::flows;

    pub(super) fn retirement(observed_seqno: u32) -> WalletRetirement {
        use iroha_data_model::sccp::light_client::{
            SccpLcInitExpectationV1, SccpLightClientParamsV1,
        };
        use iroha_sccp::{
            light_client::{
                initialize_light_client_with_profiles, profile::SccpChainProfilesV1,
                state::SccpLcMemoryStateV1, ton::wallet_state::verify_wallet_state,
            },
            test_support::ton::SyntheticTonChainV1,
        };
        let chain = SyntheticTonChainV1::new([71; 32]);
        let profiles = SccpChainProfilesV1::genesis();
        let time = 1_790_000_000;
        let now = u64::from(time) * 1000 + 60_000;
        let network = SccpNetworkV1::TonMainnet;
        let mut state = SccpLcMemoryStateV1::new();
        let initial = initialize_light_client_with_profiles(
            profiles,
            &state,
            network,
            SccpLcInitExpectationV1::Absent,
            &SccpLightClientParamsV1::defaults_for(network).unwrap(),
            &chain.bootstrap(100, 0, time, time + 65536),
            now,
        )
        .unwrap();
        state.install(network, &initial);
        let code_hash =
            hex::decode("20834b7b72b112147e1b2fb457b84e74d1a30f04f737d4f62a668e9552d2b72f")
                .unwrap()
                .try_into()
                .unwrap();
        let proof = chain.wallet_state_proof(
            [9; 32],
            WALLET_V5R1_MAINNET_ID,
            observed_seqno,
            code_hash,
            time,
        );
        let verified = verify_wallet_state(
            &profiles.ton,
            &state,
            &proof,
            [9; 32],
            WALLET_V5R1_MAINNET_ID,
            now,
        )
        .unwrap();
        WalletRetirement {
            wallet: hex::encode([9; 32]),
            original_seqno: 7,
            verified,
            proof,
            light_client: initial.light_client,
            signing_set: initial.sets[0].clone(),
            verification_time_ms: now,
        }
    }

    #[test]
    fn terminal_and_maintenance_evidence_both_require_original_wallet_retirement() {
        use iroha_sccp_wallet::journal::{SccpEvidenceItemV1, SccpStepOutcomeKindV1};
        let effect = || {
            vec![SccpEvidenceItemV1 {
                label: "verified.original_terminal_or_upkeep".to_owned(),
                bytes: vec![1, 2, 3],
            }]
        };
        for kind in [
            SccpStepOutcomeKindV1::Confirmed,
            SccpStepOutcomeKindV1::Superseded,
        ] {
            for seqno in [6, 7] {
                assert!(
                    flows::retired_ton_outcome(Some(effect()), kind, [3; 32], || {
                        Ok(Some(retirement(seqno)))
                    })
                    .unwrap()
                    .is_none(),
                    "even an exact terminal effect must leave a live wallet envelope pending"
                );
            }
            assert!(
                flows::retired_ton_outcome(None, kind, [3; 32], || {
                    panic!("retired wallet nonce alone cannot prove the intended effect")
                })
                .unwrap()
                .is_none()
            );
            assert!(
                flows::retired_ton_outcome(Some(effect()), kind, [3; 32], || {
                    Err(eyre!("original wallet observation unavailable"))
                })
                .is_err()
            );
            let outcome = flows::retired_ton_outcome(Some(effect()), kind, [3; 32], || {
                Ok(Some(retirement(8)))
            })
            .unwrap()
            .unwrap();
            assert_eq!(outcome.outcome, kind);
            assert_eq!(outcome.transaction, vec![3; 32]);
            assert_eq!(outcome.evidence[0], effect()[0]);
            assert_eq!(outcome.evidence[1].label, "ton.original_wallet_retirement");
            let retained: norito::json::Value =
                norito::json::from_slice(&outcome.evidence[1].bytes).unwrap();
            assert_eq!(retained["original_seqno"].as_u64(), Some(7));
            assert_eq!(retained["verified"]["seqno"].as_u64(), Some(8));
        }
    }

    #[test]
    fn unrelated_upkeep_does_not_release_a_live_original_wallet_seqno() {
        use iroha_data_model::{NetworkId, bridge::SccpNetworkV1};
        use iroha_sccp_wallet::{
            flow::{SccpFlowActionV1 as Action, SccpFlowV1, drive_step},
            journal::{
                SccpEvidenceItemV1, SccpFlowIdV1, SccpFlowKindV1, SccpJournalOutcomeV1,
                SccpJournalRoot, SccpStepOutcomeKindV1,
            },
        };
        let base =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/sccp-continuation");
        std::fs::create_dir_all(&base).unwrap();
        let dir = tempfile::Builder::new()
            .prefix("ton-nonce-retirement-")
            .tempdir_in(base)
            .unwrap();
        let network = NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
            iroha_crypto::Hash::prehashed([7; 32]),
        ));
        let journal = SccpJournalRoot::open(&dir.path().join("journal"))
            .unwrap()
            .network(&network)
            .unwrap()
            .flow(&SccpFlowIdV1 {
                kind: SccpFlowKindV1::CommitteeSync,
                id: [3; 32],
            })
            .unwrap();
        let flow = SccpFlowV1::open(journal, *network.as_bytes()).unwrap();
        let evidence = || {
            vec![SccpEvidenceItemV1 {
                label: "verified.prerequisite".to_owned(),
                bytes: vec![1],
            }]
        };
        let step = flow
            .prepare(
                Action::Checkpoint,
                SccpNetworkV1::TonMainnet,
                vec![7],
                evidence(),
            )
            .unwrap();
        step.begin_submission().unwrap();
        for observed in [6, 7] {
            let outcome = drive_step::<eyre::Report>(
                &step,
                |_| {
                    Ok(retirement(observed)
                        .retired()
                        .then(|| SccpJournalOutcomeV1 {
                            outcome: SccpStepOutcomeKindV1::Confirmed,
                            transaction: vec![7],
                            evidence: evidence(),
                        }))
                },
                |_| panic!("observation-only recovery must not dispatch"),
            )
            .unwrap();
            assert!(
                outcome.is_none(),
                "another relayer's upkeep does not retire our wallet nonce"
            );
        }
        drop(step);
        assert!(flow.pending().unwrap().is_some());
        assert!(
            flow.prepare(
                Action::Control,
                SccpNetworkV1::TonMainnet,
                vec![7, 1],
                evidence()
            )
            .is_err(),
            "a second action cannot reuse the live original seqno"
        );
        let step = flow.latest(Action::Checkpoint).unwrap().unwrap();
        assert!(
            drive_step::<eyre::Report>(
                &step,
                |_| Ok(retirement(8).retired().then(|| SccpJournalOutcomeV1 {
                    outcome: SccpStepOutcomeKindV1::Confirmed,
                    transaction: vec![7],
                    evidence: evidence(),
                })),
                |_| panic!("retired original must not dispatch")
            )
            .unwrap()
            .is_some()
        );
        drop(step);
        assert!(
            flow.prepare(
                Action::Control,
                SccpNetworkV1::TonMainnet,
                vec![8],
                evidence()
            )
            .is_ok()
        );
    }

    #[test]
    fn coin_quotes_preserve_the_full_ton_width() {
        assert_eq!(ton_coins(uint(u64::MAX)).unwrap(), u128::from(u64::MAX));
        let maximum = (1_u128 << 120) - 1;
        let mut bytes = [0; 33];
        bytes[17..].copy_from_slice(&maximum.to_be_bytes());
        assert_eq!(ton_coins(TvmIntV1(bytes)).unwrap(), maximum);
        bytes[17] = 1;
        assert!(ton_coins(TvmIntV1(bytes)).is_err());
        assert!(ton_coins(TvmIntV1([0xff; 33])).is_err());
    }

    #[test]
    fn raw_accounts_parse() {
        assert_eq!(
            parse_account(&format!("0:{}", "ab".repeat(32))).expect("parses"),
            [0xab; 32]
        );
        assert!(parse_account("-1:00").is_err());
        assert!(parse_account("0:zz").is_err());
        let config = iroha_sccp_wallet::config::SccpClientConfig::from_user(
            iroha::config::sccp::SccpClientConfigUser::default(),
            std::path::Path::new("target/sccp-continuation/ton-config-test"),
        )
        .unwrap();
        assert!(connect_config(&config, "not-a-server").is_err());
    }
    fn uint(value: u64) -> TvmIntV1 {
        let mut bytes = [0; 33];
        bytes[25..].copy_from_slice(&value.to_be_bytes());
        TvmIntV1(bytes)
    }
    fn word(value: [u8; 32]) -> TvmIntV1 {
        let mut bytes = [0; 33];
        bytes[1..].copy_from_slice(&value);
        TvmIntV1(bytes)
    }
    type GetterFixture = (
        Vec<Option<TvmIntV1>>,
        Vec<TvmStackValueV1>,
        Vec<Option<TvmIntV1>>,
        Vec<[u8; 48]>,
    );

    fn fixture() -> GetterFixture {
        use iroha_crypto::{Algorithm, KeyPair};
        let mut keys: Vec<[u8; 48]> = (1..=4)
            .map(|seed| {
                KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal)
                    .unwrap()
                    .public_key()
                    .to_bytes()
                    .1
                    .try_into()
                    .unwrap()
            })
            .collect();
        keys.sort_unstable();
        let root = committee_root(&keys).unwrap();
        let mut state = vec![Some(uint(0)); 24];
        state[0] = Some(TvmIntV1([0xff; 33]));
        state[1] = Some(TvmIntV1([0xff; 33]));
        state[2] = Some(word([1; 32]));
        state[3] = Some(word([2; 32]));
        state[4] = Some(uint(3));
        state[9] = Some(word(root));
        state[10] = Some(uint(1000));
        state[11] = Some(uint(1));
        state[12] = Some(uint(7));
        state[13] = Some(uint(2));
        state[16] = Some(TvmIntV1([0xff; 33]));
        state[18] = Some(TvmIntV1([0xff; 33]));
        state[19] = Some(uint(7));
        let mut committee = [word(root), uint(1000), uint(1), uint(7), uint(2), uint(4)]
            .into_iter()
            .map(TvmStackValueV1::Integer)
            .collect::<Vec<_>>();
        committee.push(TvmStackValueV1::Cell(
            iroha_sccp::v1::ton_cell::key_chunks(&keys).unwrap(),
        ));
        let checkpoints = vec![
            Some(uint(2)),
            Some(uint(3)),
            Some(word([3; 32])),
            Some(uint(7)),
            Some(word([7; 32])),
            Some(uint(0)),
            Some(word([0; 32])),
        ];
        (state, committee, checkpoints, keys)
    }
    #[test]
    fn native_minter_observation_retains_current_keys_latch_and_checkpoint_slots() {
        let (state, committee, checkpoints, keys) = fixture();
        let observed = parse_observation(3, &state, committee, &checkpoints, 100).unwrap();
        assert_eq!(observed.network, [1; 32]);
        assert_eq!(observed.instance, [2; 32]);
        assert_eq!(observed.keys, keys);
        assert_eq!(observed.committee.root, committee_root(&keys).unwrap());
        assert!(observed.committee.equivocated);
        assert!(observed.paused);
        assert_eq!(observed.control.control_nonce, 7);
        assert!(observed.control.parliament_paused);
        assert_eq!(observed.control.fast_pause_until_ms, 0);
        assert_eq!(
            observed.checkpoints,
            BTreeMap::from([(3, [3; 32]), (7, [7; 32])])
        );
        assert_eq!(observed.now_ms, 100);
    }
    #[test]
    fn native_minter_observation_rejects_mixed_schema_keys_and_checkpoint_slots() {
        let (state, committee, checkpoints, _) = fixture();
        for case in 0..10 {
            let mut state = state.clone();
            let mut committee = committee.clone();
            let mut checkpoints = checkpoints.clone();
            match case {
                0 => {
                    state.pop();
                }
                1 => state[0] = Some(uint(1)),
                2 => state[4] = Some(uint(4)),
                3 => committee[4] = TvmStackValueV1::Integer(uint(3)),
                4 => committee[5] = TvmStackValueV1::Integer(uint(5)),
                5 => committee[6] = TvmStackValueV1::Null,
                6 => checkpoints[3] = Some(uint(3)),
                7 => checkpoints[6] = Some(word([8; 32])),
                8 => state[2] = Some(word([0; 32])),
                _ => state[16] = Some(uint(0)),
            }
            assert!(
                parse_observation(3, &state, committee, &checkpoints, 100).is_err(),
                "case {case}"
            );
        }
    }
    #[test]
    fn key_chunks_and_integer_projection_reject_wrong_physical_shapes() {
        use iroha_sccp::v1::ton_cell::{CellBuilder, CellRef, key_chunks};
        let (_, _, _, keys) = fixture();
        let root = key_chunks(&keys).unwrap();
        assert_eq!(keys_from_chunks(&root, 4).unwrap(), keys);
        assert!(keys_from_chunks(&root, 31).is_err());
        assert!(keys_from_chunks(&root, 0).is_err());
        let mut opaque = CellBuilder::new();
        opaque
            .store_bytes(&keys[..2].concat())
            .unwrap()
            .store_bit(true)
            .unwrap()
            .store_ref(CellRef::opaque(
                *root.refs()[0].hash(),
                root.refs()[0].depth(),
            ))
            .unwrap();
        assert!(keys_from_chunks(&opaque.build(), 4).is_err());
        let mut trailing = CellBuilder::new();
        trailing.store_bytes(root.data()).unwrap();
        assert!(keys_from_chunks(&trailing.build(), 4).is_err());
        assert!(integer_stack(vec![TvmStackValueV1::Cell(root)]).is_err());
        assert_eq!(
            integer_stack(vec![
                TvmStackValueV1::Null,
                TvmStackValueV1::Integer(uint(7))
            ])
            .unwrap(),
            vec![None, Some(uint(7))]
        );
    }
}

impl TonDestination {
    /// Find an exact completed effect in bounded linked history, then verify TON finality.
    /// Absence leaves the original request unresolved and never authorizes a new mint.
    pub(super) fn terminal_evidence(
        &self,
        client: &iroha::blocking::Client,
        original: &origin::AuthenticatedOrigin,
        profiles: &iroha_sccp::light_client::profile::SccpChainProfilesV1,
        step: &iroha_sccp_wallet::journal::SccpJournalStep,
        expected: iroha_sccp::ton_watch::TerminalEvent,
    ) -> Result<Option<Vec<iroha_sccp_wallet::journal::SccpEvidenceItemV1>>> {
        use iroha_sccp::ton_watch;
        let account = AccountId {
            workchain: 0,
            address: self.minter,
        };
        let at = last_block(&self.lite)?;
        let state = self
            .lite
            .get_account_state(at, account)
            .map_err(|error| eyre!("minter account: {error}"))?;
        let Some(head) = ton_watch::account_cursor(&state.proof, &self.minter) else {
            return Ok(None);
        };
        let mut cursor = history_start(step, self.minter, head)?;
        let mut found = None;
        for _ in 0..16 {
            let page = self
                .lite
                .get_transactions(16, account, cursor.lt, cursor.hash)
                .map_err(|error| eyre!("minter history: {error}"))?;
            let next =
                ton_watch::terminal_events(&page.transactions, &self.minter, cursor, |event| {
                    if event.event == expected {
                        found = Some(event);
                    }
                    true
                })
                .map_err(|error| eyre!("linked minter history: {error}"))?;
            if found.is_some() {
                break;
            }
            history_next(step, self.minter, next)?;
            let Some(next) = next else { break };
            cursor = next;
        }
        let Some(event) = found else { return Ok(None) };
        let reference = iroha_sccp_rpc::builders::SourceEventRefV1::Ton {
            minter: self.minter,
            lt: event.transaction.lt,
            hash: event.transaction.hash,
            message_index: event.message_index,
        };
        let builder = iroha_sccp_rpc::builders::ton::TonBuilder::new(
            profiles.ton,
            connect_config(&self.config, &self.liteservers)?
                .with_budget(self.lite.budget().clone()),
        );
        let bounded_client = self
            .lite
            .budget()
            .deadline()
            .map(|deadline| client.with_request_deadline(deadline))
            .transpose()?;
        let client = bounded_client.as_ref().unwrap_or(client);
        let (evidence, verified, trust) = super::prove(
            profiles,
            client,
            original,
            iroha::data_model::bridge::SccpNetworkV1::TonMainnet,
            &builder,
            &reference,
        )?;
        require_ton_terminal(&verified.event, self.minter, expected)?;
        let mut retained = vec![
            trust,
            iroha_sccp_wallet::journal::SccpEvidenceItemV1 {
                label: "ton.finalized_effect.proof".to_owned(),
                bytes: evidence.proof.as_bytes().to_vec(),
            },
        ];
        for advance in evidence.backfills {
            retained.push(iroha_sccp_wallet::journal::SccpEvidenceItemV1 {
                label: "ton.finalized_effect.backfill".to_owned(),
                bytes: advance.as_bytes().to_vec(),
            });
        }
        Ok(Some(retained))
    }
}

impl TonDestination {
    /// Prepare a complete expired/frozen void message without transmitting it.
    pub(super) fn prepare_void(
        &self,
        bundle: Option<&SccpMessageProofBundleV1>,
        nonce: u64,
        frozen: bool,
        network: [u8; 32],
        instance: [u8; 32],
        wallet: &TonWallet,
    ) -> Result<Vec<u8>> {
        let observed = self.observe()?;
        ensure!(
            observed.network == network && observed.instance == instance,
            "void minter identity differs"
        );
        let body = if frozen {
            ensure!(
                !observed.committee.is_live(observed.now_ms),
                "destination is not frozen"
            );
            iroha_sccp_wallet::pure::ton::void_frozen_body(nonce, 1, nonce, wallet.address())?
        } else {
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
            iroha_sccp_wallet::pure::ton::void_expired_body(&verified, nonce, wallet.address())?
        };
        let value = self.quoted_value(
            if frozen {
                "void_frozen_required_value"
            } else {
                "void_required_value"
            },
            &[nonce],
        )?;
        let message = internal_message(&self.minter, value, true, body, None)?;
        wallet.prepare(
            &self.lite,
            &[(message, SEND_MODE_PAY_FEES_SEPARATELY_IGNORE_ERRORS)],
        )
    }
}

impl TonDestination {
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
        let observed = self.observe()?;
        let applied = observed.control;
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

/// Borrowed coordinates of the original burn that linked-history evidence must match.
#[derive(Clone, Copy)]
pub struct BurnObservation<'a> {
    pub(super) wallet_code: iroha::data_model::sccp::deployment::SccpTonCodeRefV1,
    pub(super) owner: &'a [u8; 32],
    pub(super) query_id: u64,
    pub(super) recipient: &'a [u8],
    pub(super) amount: u128,
}

impl TonDestination {
    /// Prepare the standard Jetton burn with the mandatory SCCP recipient and unique flow query.
    pub(super) fn prepare_burn(
        &self,
        wallet: &TonWallet,
        wallet_code: iroha::data_model::sccp::deployment::SccpTonCodeRefV1,
        query_id: u64,
        recipient: &[u8],
        amount: u128,
        (network, instance): ([u8; 32], [u8; 32]),
    ) -> Result<Vec<u8>> {
        self.verify_identity(network, instance)?;
        ensure!(
            amount > 0 && amount < (1u128 << 96),
            "TON burn amount is outside the contract bound"
        );
        let jetton = iroha_sccp::v1::ton_cell::wallet_account_id(
            0,
            wallet.address(),
            &self.minter,
            wallet_code,
        )?;
        let quote = run_method(&self.lite, &jetton, "burn_required_value", &[])?;
        ensure!(quote.len() == 1, "burn quote has extra fields");
        let value = quote_with_margin(ton_coins(int_at(&quote, 0, "burn_required_value")?)?);
        let body =
            iroha_sccp_wallet::pure::ton::burn_body(query_id, amount, wallet.address(), recipient)?;
        let message = internal_message(&jetton, value, true, body, None)?;
        wallet.prepare(
            &self.lite,
            &[(message, SEND_MODE_PAY_FEES_SEPARATELY_IGNORE_ERRORS)],
        )
    }

    /// Reconcile the original burn notification, including its unique flow query and wallet.
    pub(super) fn burn_evidence(
        &self,
        client: &iroha::blocking::Client,
        original: &origin::AuthenticatedOrigin,
        profiles: &iroha_sccp::light_client::profile::SccpChainProfilesV1,
        step: &iroha_sccp_wallet::journal::SccpJournalStep,
        expected: &BurnObservation<'_>,
    ) -> Result<Option<Vec<iroha_sccp_wallet::journal::SccpEvidenceItemV1>>> {
        use iroha_sccp::ton_watch;
        #[derive(norito::derive::JsonSerialize)]
        struct BurnLocator {
            message_id: String,
            transaction: String,
            message_index: u16,
        }
        let BurnObservation {
            wallet_code,
            owner,
            query_id,
            recipient,
            amount,
        } = *expected;
        let jetton =
            iroha_sccp::v1::ton_cell::wallet_account_id(0, owner, &self.minter, wallet_code)?;
        let account = AccountId {
            workchain: 0,
            address: self.minter,
        };
        let state = self
            .lite
            .get_account_state(last_block(&self.lite)?, account)
            .map_err(|error| eyre!("burn minter state: {error}"))?;
        let Some(head) = ton_watch::account_cursor(&state.proof, &self.minter) else {
            return Ok(None);
        };
        let mut cursor = history_start(step, self.minter, head)?;
        let mut found = None;
        for _ in 0..16 {
            let page = self
                .lite
                .get_transactions(16, account, cursor.lt, cursor.hash)
                .map_err(|error| eyre!("burn history: {error}"))?;
            let next = ton_watch::burns(&page.transactions, &self.minter, cursor, |burn| {
                if burn.query_id == query_id
                    && burn.notification_sender == jetton
                    && burn.owner == *owner
                    && burn.amount == amount
                {
                    let mut sender = vec![0; 4];
                    sender.extend_from_slice(owner);
                    if let Ok(payload) = iroha_sccp::v1::payload::SccpTransferPayloadV1::inbound(
                        iroha::data_model::bridge::SccpNetworkV1::TonMainnet,
                        burn.nonce,
                        self.destination.route_revision,
                        amount,
                        sender,
                        recipient.to_vec(),
                    )
                    .and_then(|payload| payload.encode())
                        && iroha_sccp::v1::hashes::payload_hash(&payload) == burn.payload_hash
                    {
                        found = Some(burn);
                    }
                }
                true
            })
            .map_err(|error| eyre!("burn linked history: {error}"))?;
            if found.is_some() {
                break;
            }
            history_next(step, self.minter, next)?;
            let Some(next) = next else { break };
            cursor = next;
        }
        let Some(burn) = found else { return Ok(None) };
        let reference = iroha_sccp_rpc::builders::SourceEventRefV1::Ton {
            minter: self.minter,
            lt: burn.transaction.lt,
            hash: burn.transaction.hash,
            message_index: burn.message_index,
        };
        let builder = iroha_sccp_rpc::builders::ton::TonBuilder::new(
            profiles.ton,
            connect_config(&self.config, &self.liteservers)?
                .with_budget(self.lite.budget().clone()),
        );
        let bounded_client = self
            .lite
            .budget()
            .deadline()
            .map(|deadline| client.with_request_deadline(deadline))
            .transpose()?;
        let client = bounded_client.as_ref().unwrap_or(client);
        let (evidence, verified, trust) = super::prove(
            profiles,
            client,
            original,
            iroha::data_model::bridge::SccpNetworkV1::TonMainnet,
            &builder,
            &reference,
        )?;
        require_ton_burn(&verified.event, self.minter, &burn)?;
        let locator = BurnLocator {
            message_id: hex::encode(burn.message_id),
            transaction: format!(
                "{}:{}",
                burn.transaction.lt,
                hex::encode(burn.transaction.hash)
            ),
            message_index: burn.message_index,
        };
        let mut items = vec![
            trust,
            super::flows::evidence("ton.original_burn.locator", &locator)?,
            iroha_sccp_wallet::journal::SccpEvidenceItemV1 {
                label: "ton.original_burn.proof".to_owned(),
                bytes: evidence.proof.as_bytes().to_vec(),
            },
        ];
        for advance in evidence.backfills {
            items.push(iroha_sccp_wallet::journal::SccpEvidenceItemV1 {
                label: "ton.original_burn.backfill".to_owned(),
                bytes: advance.as_bytes().to_vec(),
            });
        }
        Ok(Some(items))
    }
}

impl TonDestination {
    /// Authenticate destination progress from the exact registered minter's native account.
    pub(super) fn progress_evidence(
        &self,
        client: &BlockingClient,
        original: &origin::AuthenticatedOrigin,
        control: Option<u64>,
        generation: Option<u64>,
    ) -> Result<Option<Vec<iroha_sccp_wallet::journal::SccpEvidenceItemV1>>> {
        super::ton_state::progress(
            client,
            original,
            &self.lite,
            self.minter,
            self.destination.route_revision,
            control,
            generation,
        )
    }

    /// Exact registered basechain minter account selected for this destination.
    pub(super) const fn minter(&self) -> [u8; 32] {
        self.minter
    }
}

#[path = "ton_monitor.rs"]
mod monitor;

fn require_ton_terminal(
    verified: &iroha_sccp::light_client::proof::SccpNormalizedEventV1,
    minter: [u8; 32],
    expected: iroha_sccp::ton_watch::TerminalEvent,
) -> Result<()> {
    use iroha_sccp::{
        light_client::proof::{SccpNormalizedEventV1 as Event, SccpSourceEmitterV1},
        ton_watch::TerminalEvent,
    };
    ensure!(
        *verified.emitter() == SccpSourceEmitterV1::Ton(minter),
        "authenticated TON event names another minter"
    );
    let matches = match (verified, expected) {
        (
            Event::Finalized {
                message_id, nonce, ..
            },
            TerminalEvent::Finalized {
                message_id: expected_id,
                nonce: expected_nonce,
            },
        ) => *message_id == expected_id && *nonce == expected_nonce,
        (
            Event::Void {
                first_nonce,
                count,
                message_id_or_zero,
                ..
            },
            TerminalEvent::Voided {
                message_id,
                first_nonce: expected_nonce,
                count: expected_count,
            },
        ) => {
            *first_nonce == expected_nonce
                && *count == u64::from(expected_count)
                && *message_id_or_zero == message_id
        }
        _ => false,
    };
    ensure!(
        matches,
        "authenticated TON effect differs from original terminal intent"
    );
    Ok(())
}

fn require_ton_burn(
    verified: &iroha_sccp::light_client::proof::SccpNormalizedEventV1,
    minter: [u8; 32],
    expected: &iroha_sccp::ton_watch::BurnObservation,
) -> Result<()> {
    use iroha_sccp::light_client::proof::{SccpNormalizedEventV1 as Event, SccpSourceEmitterV1};
    let Event::TransferToTaira {
        emitter,
        message_id,
        sender,
        nonce,
        payload_hash,
        ..
    } = verified
    else {
        return Err(eyre!("authenticated TON event is not the original burn"));
    };
    let mut owner = vec![0; 4];
    owner.extend_from_slice(&expected.owner);
    ensure!(
        *emitter == SccpSourceEmitterV1::Ton(minter)
            && *message_id == expected.message_id
            && *nonce == expected.nonce
            && sender.codec == iroha_sccp::v1::constants::CODEC_TON_ACCOUNT36
            && sender.bytes == owner
            && *payload_hash == expected.payload_hash,
        "authenticated TON burn differs from the original query-bound discovery"
    );
    Ok(())
}

#[cfg(test)]
#[path = "ton_binding_tests.rs"]
mod binding_tests;
