//! TON destination actions of `iroha sccp` (`specs/sccp.md` §5.3, §7.1, §7.4).
//!
//! The minter's state is read with get methods over ADNL liteservers, every bundle and rotation
//! chain is verified locally against it, and the resulting minter messages are sent as
//! internal messages from the user's deployed `v5r1` wallet, signed with an owner-only Ed25519
//! key file.

use eyre::{Result, ensure, eyre};
use iroha_sccp::{
    api::{SccpMessageProofBundleV1, SccpRotationV1},
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

/// Run a current result stack at one explicitly selected masterchain block.
fn run_stack_at(
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

    /// Send `messages` (internal messages with send modes) and return the external message
    /// `BoC` hash.
    pub(super) fn send(
        &self,
        lite: &LiteClient,
        messages: &[(iroha_sccp::v1::ton_cell::Cell, u8)],
    ) -> Result<[u8; 32]> {
        let block = last_block(lite)?;
        let seqno = integer_stack(run_stack_at(lite, block, &self.address, "seqno", &[])?)?;
        ensure!(seqno.len() == 1, "wallet seqno reply has extra fields");
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
            .ok_or_else(|| eyre!("wallet message has no canonical single root"))?;
        let status = lite
            .send_message(boc)
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

/// One TON deployment (the minter) reached through liteservers.
pub(super) struct TonDestination {
    lite: LiteClient,
    minter: TonAccountV1,
    destination: DestinationV1,
}

impl TonDestination {
    /// Connect to `liteservers` (see [`connect`]).
    pub(super) fn connect(
        liteservers: &str,
        minter: TonAccountV1,
        destination: DestinationV1,
    ) -> Result<Self> {
        Ok(Self {
            lite: connect(liteservers)?,
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
    /// The actual stored committee and equivocation latch at one minter observation.
    pub(super) fn committee_state(&self) -> Result<CommitteeStateV1> {
        Ok(self.observe()?.committee)
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
    pub(super) fn finalize(
        &self,
        bundle: &SccpMessageProofBundleV1,
        network: [u8; 32],
        instance: [u8; 32],
        wallet: &TonWallet,
    ) -> Result<[u8; 32]> {
        let observed = self.observe()?;
        ensure!(
            observed.network == network && observed.instance == instance,
            "Taira and minter identities differ"
        );
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
        let body = finalize_body(&verified, verified.nonce(), wallet.address())
            .map_err(|e| eyre!("finalize: {e}"))?;
        let message = internal_message(&self.minter, value, true, body, None)
            .map_err(|e| eyre!("internal message: {e}"))?;
        wallet.send(
            &self.lite,
            &[(message, SEND_MODE_PAY_FEES_SEPARATELY_IGNORE_ERRORS)],
        )
    }
    /// Verify a genuine checkpoint chain and send its current TON checkpoint messages in order.
    pub(super) fn rotate(
        &self,
        steps: &[SccpRotationV1],
        target: u64,
        network: [u8; 32],
        instance: [u8; 32],
        wallet: &TonWallet,
    ) -> Result<Vec<[u8; 32]>> {
        let observed = self.observe()?;
        ensure!(
            observed.network == network && observed.instance == instance,
            "Taira and minter identities differ"
        );
        let plan = verify_rotation_steps(steps, &observed.context(self.destination), target)
            .map_err(|e| eyre!("committee checkpoint chain: {e}"))?;
        if plan.is_empty() {
            return Ok(Vec::new());
        }
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
                    wallet.address(),
                )
                .map_err(|e| eyre!("checkpoint message: {e}"))?;
                Ok((
                    internal_message(&self.minter, value, true, body, None)
                        .map_err(|e| eyre!("internal message: {e}"))?,
                    SEND_MODE_PAY_FEES_SEPARATELY_IGNORE_ERRORS,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(vec![wallet.send(&self.lite, &messages)?])
    }
}

struct Observation {
    network: [u8; 32],
    instance: [u8; 32],
    committee: CommitteeStateV1,
    keys: Vec<[u8; 48]>,
    checkpoints: BTreeMap<u64, [u8; 32]>,
    paused: bool,
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
        now_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(connect("not-a-server").is_err());
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
    fn fixture() -> (
        Vec<Option<TvmIntV1>>,
        Vec<TvmStackValueV1>,
        Vec<Option<TvmIntV1>>,
        Vec<[u8; 48]>,
    ) {
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
        keys.sort();
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
