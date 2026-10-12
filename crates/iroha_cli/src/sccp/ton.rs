//! TON destination actions of `iroha sccp` (`specs/sccp.md` §5.3, §7.1, §7.4).
//!
//! The minter's state is read with get methods over ADNL liteservers, every bundle and rotation
//! chain is verified locally against it, and the resulting minter messages are sent as
//! internal messages from the user's deployed `v5r1` wallet, signed with an owner-only Ed25519
//! key file.

use eyre::{Result, eyre};
use iroha_sccp::{
    api::{SccpMessageProofBundleV1, SccpRotationV1},
    v1::{
        committee::CommitteeStateV1,
        destination::{
            CheckpointObservationsV1, DeploymentV1, DestinationObservationV1, MessagePurposeV1,
            PauseStateV1,
        },
    },
};
use iroha_sccp_rpc::{
    FailoverPolicy,
    ton::{AccountId, BlockIdExt, LiteClient, LiteClientConfig, LiteServerSet},
};
use iroha_sccp_wallet::pure::{
    bundle::{BundleSourceV1, verify_message_bundle},
    rotation::verify_rotation_steps,
    ton::{
        SEND_MODE_PAY_FEES_SEPARATELY_IGNORE_ERRORS, TonAccountV1, TonWalletKeyV1, TvmIntV1,
        TvmStackValueV1, WALLET_V5R1_MAINNET_ID, checkpoint_body, finalize_body, get_method_id,
        internal_message, parse_int_stack, parse_key_chunks, parse_native_stack, quote_with_margin,
        stack_of_uints, wallet_v5_transfer,
    },
};

/// Lifetime of a wallet external message (seconds).
const EXTERNAL_LIFETIME_S: u32 = 120;

/// Connect to liteservers: a comma-separated list of `<ip>:<port>:<base64 key>` entries, or
/// the compiled public list when empty.
pub(super) fn connect(liteservers: &str) -> Result<LiteClient> {
    let servers = if liteservers.trim().is_empty() {
        LiteServerSet::compiled_defaults()
    } else {
        let entries: Vec<&str> = liteservers.split(',').map(str::trim).collect();
        LiteServerSet::parse(&entries).map_err(|error| eyre!("liteservers: {error}"))?
    };
    Ok(LiteClient::new(
        servers,
        LiteClientConfig::default(),
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

fn raw_method(
    lite: &LiteClient,
    account: &TonAccountV1,
    block: BlockIdExt,
    method: &str,
    args: &[u64],
) -> Result<Vec<u8>> {
    let result = lite
        .run_smc_method(
            4,
            block,
            AccountId {
                workchain: 0,
                address: *account,
            },
            get_method_id(method),
            stack_of_uints(args).map_err(|error| eyre!("{method} arguments: {error}"))?,
        )
        .map_err(|error| eyre!("runSmcMethod {method}: {error}"))?;
    eyre::ensure!(result.id == block, "get-method returned another block");
    eyre::ensure!(
        result.exit_code == 0 || result.exit_code == 1,
        "{method} exited with {}",
        result.exit_code
    );
    result
        .result
        .ok_or_else(|| eyre!("{method} returned no stack"))
}
fn run_at(
    lite: &LiteClient,
    account: &TonAccountV1,
    block: BlockIdExt,
    method: &str,
    args: &[u64],
) -> Result<Vec<Option<TvmIntV1>>> {
    parse_int_stack(&raw_method(lite, account, block, method, args)?)
        .map_err(|error| eyre!("{method} result: {error}"))
}
fn run_method(
    lite: &LiteClient,
    account: &TonAccountV1,
    method: &str,
    args: &[u64],
) -> Result<Vec<Option<TvmIntV1>>> {
    run_at(lite, account, last_block(lite)?, method, args)
}
fn boolean(value: TvmIntV1) -> Result<bool> {
    if value.0 == [0; 33] {
        Ok(false)
    } else if value.0 == [0xff; 33] {
        Ok(true)
    } else {
        Err(eyre!("TVM boolean must be 0 or -1"))
    }
}
fn unsigned(values: &[Option<TvmIntV1>], index: usize, name: &str) -> Result<u64> {
    int_at(values, index, name)?
        .to_u64()
        .ok_or_else(|| eyre!("{name} is not a u64"))
}
fn word(values: &[Option<TvmIntV1>], index: usize, name: &str) -> Result<[u8; 32]> {
    int_at(values, index, name)?
        .to_u256()
        .ok_or_else(|| eyre!("{name} is not a word"))
}
fn amount(values: &[Option<TvmIntV1>], index: usize, name: &str) -> Result<u128> {
    let bytes = word(values, index, name)?;
    eyre::ensure!(bytes[..17] == [0; 17], "{name} exceeds TON Coins");
    Ok(u128::from_be_bytes(bytes[16..].try_into()?))
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
        eyre::ensure!(
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

    /// Send `messages` (internal messages with send modes) and return the external message
    /// `BoC` hash.
    pub(super) fn send(
        &self,
        lite: &LiteClient,
        messages: &[(iroha_sccp::v1::ton_cell::Cell, u8)],
    ) -> Result<[u8; 32]> {
        let block = last_block(lite)?;
        let seqno = run_at(lite, &self.address, block, "seqno", &[])?;
        eyre::ensure!(seqno.len() == 1, "wallet seqno reply has extra fields");
        let seqno = int_at(&seqno, 0, "seqno")?
            .to_u64()
            .and_then(|seqno| u32::try_from(seqno).ok())
            .ok_or_else(|| eyre!("the wallet seqno is not a u32"))?;
        let now = u32::try_from(block_time_ms(lite, block)? / 1000)?;
        let boc = wallet_v5_transfer(
            &self.address,
            WALLET_V5R1_MAINNET_ID,
            seqno,
            now.checked_add(EXTERNAL_LIFETIME_S)
                .ok_or_else(|| eyre!("wallet message deadline overflows"))?,
            messages,
            &self.key,
        )
        .map_err(|error| eyre!("wallet message: {error}"))?;
        let hash = iroha_sccp::ton_boc_single_root_hash_v1(&boc)
            .ok_or_else(|| eyre!("signed wallet message has no canonical single-root hash"))?;
        let status = lite
            .send_message(boc.clone())
            .map_err(|error| eyre!("sendMessage: {error}"))?;
        if status.status != 1 {
            return Err(eyre!(
                "the liteserver refused the message ({})",
                status.status
            ));
        }
        Ok(hash)
    }
}

/// One TON deployment. Initial pin keys remain separate from the queried current keys.
pub(super) struct TonDestination {
    lite: LiteClient,
    minter: TonAccountV1,
    deployment: DeploymentV1,
    bucket_code: iroha::data_model::sccp::deployment::SccpTonCodeRefV1,
}
impl TonDestination {
    pub(super) fn connect(
        liteservers: &str,
        minter: TonAccountV1,
        deployment: DeploymentV1,
        bucket_code: iroha::data_model::sccp::deployment::SccpTonCodeRefV1,
    ) -> Result<Self> {
        eyre::ensure!(
            deployment.destination_word == minter,
            "registry minter identity mismatch"
        );
        Ok(Self {
            lite: connect(liteservers)?,
            minter,
            deployment,
            bucket_code,
        })
    }
    pub(super) const fn lite(&self) -> &LiteClient {
        &self.lite
    }
    pub(super) fn observation(&self) -> Result<DestinationObservationV1> {
        let block = last_block(&self.lite)?;
        self.observe_at(block).map(|(observation, _)| observation)
    }
    fn observe_at(
        &self,
        block: BlockIdExt,
    ) -> Result<(DestinationObservationV1, Vec<Option<TvmIntV1>>)> {
        let now = block_time_ms(&self.lite, block)?;
        let state = run_at(&self.lite, &self.minter, block, "get_sccp_state", &[])?;
        eyre::ensure!(
            state.len() == 24,
            "get_sccp_state must return exactly 24 fields"
        );
        eyre::ensure!(
            boolean(int_at(&state, 0, "initialized")?)?,
            "minter is not initialized"
        );
        let d = &self.deployment;
        eyre::ensure!(
            word(&state, 2, "network")? == d.taira_network_id
                && word(&state, 3, "instance")? == d.consensus_instance
                && unsigned(&state, 4, "revision")? == u64::from(d.route_revision)
                && unsigned(&state, 5, "initial generation")? == d.pin_generation
                && word(&state, 6, "initial root")? == d.pin_root
                && unsigned(&state, 7, "initial start")? == d.pin_start_height
                && unsigned(&state, 8, "initial deadline")? == d.pin_until_ms
                && amount(&state, 22, "cap")? == d.max_wrapped_supply,
            "minter immutables differ from independently selected native pin"
        );
        let committee = CommitteeStateV1 {
            root: word(&state, 9, "root")?,
            until_ms: unsigned(&state, 10, "until")?,
            start: unsigned(&state, 11, "start")?,
            high: unsigned(&state, 12, "high")?,
            generation: unsigned(&state, 13, "generation")?,
            equivocated: boolean(int_at(&state, 1, "latch")?)?,
        };
        let raw = parse_native_stack(&raw_method(
            &self.lite,
            &self.minter,
            block,
            "get_sccp_committee",
            &[],
        )?)
        .map_err(|error| eyre!("committee stack: {error}"))?;
        eyre::ensure!(
            raw.len() == 7,
            "get_sccp_committee must return six integers and a cell"
        );
        let ints = raw[..6]
            .iter()
            .map(|value| match value {
                TvmStackValueV1::Int(value) => Ok(Some(*value)),
                _ => Err(eyre!("committee field is not an integer")),
            })
            .collect::<Result<Vec<_>>>()?;
        eyre::ensure!(
            word(&ints, 0, "root")? == committee.root
                && unsigned(&ints, 1, "until")? == committee.until_ms
                && unsigned(&ints, 2, "start")? == committee.start
                && unsigned(&ints, 3, "high")? == committee.high
                && unsigned(&ints, 4, "generation")? == committee.generation,
            "committee and state observations disagree"
        );
        let TvmStackValueV1::Cell(cell) = &raw[6] else {
            return Err(eyre!("committee keys are not a cell"));
        };
        let keys = parse_key_chunks(cell, usize::try_from(unsigned(&ints, 5, "count")?)?)
            .map_err(|error| eyre!("committee key chunks: {error}"))?;
        let checkpoint_values =
            run_at(&self.lite, &self.minter, block, "get_sccp_checkpoints", &[])?;
        let slots = decode_checkpoints(&checkpoint_values)?;
        let pause = PauseStateV1 {
            parliament_paused: boolean(int_at(&state, 16, "parliament pause")?)?,
            fast_pause_until_ms: unsigned(&state, 17, "fast pause")?,
            effective: boolean(int_at(&state, 18, "effective pause")?)?,
            control_nonce: unsigned(&state, 19, "control nonce")?,
        };
        let observation = DestinationObservationV1::new(
            d.clone(),
            committee,
            Some(keys),
            CheckpointObservationsV1::Ton(slots),
            pause,
            now,
        )?;
        Ok((observation, state))
    }
    fn quoted_value(&self, block: BlockIdExt, method: &str, args: &[u64]) -> Result<u128> {
        let values = run_at(&self.lite, &self.minter, block, method, args)?;
        eyre::ensure!(values.len() == 1, "{method} returned extra fields");
        Ok(quote_with_margin(u128::from(unsigned(&values, 0, method)?)))
    }
    pub(super) fn finalize(
        &self,
        bundle: &SccpMessageProofBundleV1,
        expected: &[u8; 32],
        source: BundleSourceV1,
        wallet: &TonWallet,
    ) -> Result<[u8; 32]> {
        let block = last_block(&self.lite)?;
        let (observation, state) = self.observe_at(block)?;
        let verified = verify_message_bundle(
            bundle,
            expected,
            &observation,
            source,
            MessagePurposeV1::Finalize,
        )?;
        let total = amount(&state, 20, "total supply")?;
        let pending = amount(&state, 21, "pending supply")?;
        let cap = self.deployment.max_wrapped_supply;
        eyre::ensure!(
            total <= cap && pending <= cap - total && verified.amount() <= cap - total - pending,
            "mint exceeds current total/pending supply cap"
        );
        let nonce = verified.nonce();
        if verified.nonce() >> 9 < unsigned(&state, 23, "deployed buckets")? {
            let bucket = iroha_sccp::v1::ton_cell::bucket_account_id(
                &self.minter,
                verified.nonce() >> 9,
                self.bucket_code,
            )?;
            let used = run_at(&self.lite, &bucket, block, "is_consumed", &[nonce])?;
            eyre::ensure!(
                used.len() == 1 && !boolean(int_at(&used, 0, "consumed")?)?,
                "nonce was already consumed"
            );
        }
        let value = self.quoted_value(block, "finalize_required_value", &[nonce])?;
        let body = finalize_body(&verified, verified.nonce(), wallet.address())?;
        let message = internal_message(&self.minter, value, true, body, None)?;
        wallet.send(
            &self.lite,
            &[(message, SEND_MODE_PAY_FEES_SEPARATELY_IGNORE_ERRORS)],
        )
    }
    /// One native checkpoint per invocation. TON messages are asynchronous; another invocation
    /// re-reads the observed committee after this message completes instead of assuming delivery.
    pub(super) fn checkpoints(
        &self,
        steps: &[SccpRotationV1],
        wallet: &TonWallet,
    ) -> Result<Vec<[u8; 32]>> {
        eyre::ensure!(steps.len() <= 16, "rotation page exceeds 16");
        let Some(first) = steps.first() else {
            return Ok(Vec::new());
        };
        let block = last_block(&self.lite)?;
        let (observation, _) = self.observe_at(block)?;
        let one = std::slice::from_ref(first);
        let plan = verify_rotation_steps(
            one,
            None,
            &observation,
            super::rotation_target(one, observation.committee().generation)?,
        )?;
        let Some(checkpoint) = plan.checkpoints().first() else {
            return Ok(Vec::new());
        };
        let value = self.quoted_value(block, "checkpoint_required_value", &[])?;
        let body = checkpoint_body(checkpoint, first.certificate.height, wallet.address())?;
        let message = internal_message(&self.minter, value, true, body, None)?;
        Ok(vec![wallet.send(
            &self.lite,
            &[(message, SEND_MODE_PAY_FEES_SEPARATELY_IGNORE_ERRORS)],
        )?])
    }
}

fn decode_checkpoints(values: &[Option<TvmIntV1>]) -> Result<[Option<(u64, [u8; 32])>; 3]> {
    eyre::ensure!(
        values.len() == 7,
        "get_sccp_checkpoints must return seven integers"
    );
    let count = usize::try_from(unsigned(values, 0, "count")?)?;
    eyre::ensure!(count <= 3, "checkpoint count exceeds three");
    let mut slots = [None; 3];
    let mut previous = 0;
    for (index, slot) in slots.iter_mut().enumerate() {
        let height = unsigned(values, 1 + index * 2, "checkpoint height")?;
        let id = word(values, 2 + index * 2, "checkpoint id")?;
        if index < count {
            eyre::ensure!(
                height > previous && id != [0; 32],
                "checkpoint slots are not strictly ordered and nonzero"
            );
            *slot = Some((height, id));
            previous = height;
        } else {
            eyre::ensure!(
                height == 0 && id == [0; 32],
                "unused checkpoint slot is not zero"
            );
        }
    }
    Ok(slots)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_accounts_parse() {
        assert_eq!(
            parse_account(&format!("0:{}", "ab".repeat(32))).expect("parses"),
            [0xab; 32]
        );
        assert!(parse_account("-1:00").is_err());
        assert!(parse_account("0:zz").is_err());
        assert!(connect("not-a-server").is_err());
    }
    fn integer(value: u64) -> Option<TvmIntV1> {
        let mut bytes = [0; 33];
        bytes[25..].copy_from_slice(&value.to_be_bytes());
        Some(TvmIntV1(bytes))
    }
    #[test]
    fn checkpoint_slots_distinguish_complete_absence_from_malformed_data() {
        let empty = vec![integer(0); 7];
        assert_eq!(decode_checkpoints(&empty).unwrap(), [None; 3]);
        let mut one = empty.clone();
        one[0] = integer(1);
        one[1] = integer(7);
        one[2] = integer(8);
        assert_eq!(
            decode_checkpoints(&one).unwrap()[0],
            Some((7, word(&one, 2, "id").unwrap()))
        );
        let mut malformed = one.clone();
        malformed[3] = integer(1);
        assert!(decode_checkpoints(&malformed).is_err());
        malformed = one.clone();
        malformed[0] = integer(4);
        assert!(decode_checkpoints(&malformed).is_err());
        malformed = one.clone();
        malformed[2] = integer(0);
        assert!(decode_checkpoints(&malformed).is_err());
        malformed = one.clone();
        malformed[0] = integer(2);
        malformed[3] = integer(7);
        malformed[4] = integer(9);
        assert!(decode_checkpoints(&malformed).is_err());
        assert!(decode_checkpoints(&one[..6]).is_err());
        malformed = one;
        malformed[1] = None;
        assert!(decode_checkpoints(&malformed).is_err());
    }
    #[test]
    fn native_tvm_booleans_and_coins_have_exact_width() {
        assert!(!boolean(TvmIntV1([0; 33])).unwrap());
        assert!(boolean(TvmIntV1([0xff; 33])).unwrap());
        assert!(boolean(integer(1).unwrap()).is_err());
        let mut high = [0; 33];
        high[18] = 0xff;
        let values = vec![Some(TvmIntV1(high))];
        assert!(amount(&values, 0, "coins").is_ok());
        high[17] = 1;
        assert!(amount(&[Some(TvmIntV1(high))], 0, "coins").is_err());
    }
}
