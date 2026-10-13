//! TON evidence builders (spec §4.13.3, §4.13.5, §7.2, §7.3).
//!
//! Key-block hops (the forward links of `liteServer.getBlockProof` with `getBlockHeader` and
//! `getConfigParams` proofs of each key block), bootstraps, and transaction proofs (the
//! `getShardBlockProof` walk from the burn's own masterchain block to its shard block and the
//! `getOneTransaction` proof), all over ADNL liteservers ([`TonBuilder`]). Liteserver `BoC`s are
//! re-encoded in the canonical proof form the light client accepts. Everything built is
//! untrusted until `iroha_sccp` verifies it.
//!
//! **Evidence.** The proof hangs from the masterchain block that registers the burn's shard
//! block (`T`):
//!
//! 1. signed: `T` with its own signatures, by the validator epoch its `prev_key_block_seqno`
//!    names, while the light client stores that epoch and it is still fresh
//!    [`super::FRESHNESS_MARGIN_MS`] from now (until `utime_until + stake_held_for` less the
//!    profile's margin), so a burn stays provable across later key-block hops;
//! 2. otherwise an `OldMcBlocksInfo` back link: the first block after the newest stored key
//!    block, signed by the newest epoch, whose state lists `T` (`liteServer.getBlockProof`
//!    backward from it to `T`). Archive liteservers serve old blocks, so the window is
//!    unlimited while the light client is kept fresh.
//!
//! TODO(ws3A): captured-mainnet fixtures of every liteserver answer the builders use.

use iroha_data_model::{
    bridge::SccpNetworkV1,
    sccp::light_client::{SccpLcAdvanceBytesV1, SccpLcBootstrapV1, SccpLcConsensusSetV1},
};
use iroha_sccp::{
    TonBlockIdExtV1, TonBlockSignaturesV1, TonOrdinaryBlockSignaturesV1,
    TonSimplexBlockSignaturesV1, TonValidatorSignatureV1,
    light_client::{
        profile::TonChainProfileV1,
        proof::{SccpLcAdvanceV1, SccpLcBootstrapDataV1, SccpLcSetDataV1, SccpSourceProofV1},
        ton::{
            TonBackLinkV1, TonKeyBlockHopV1, TonLcAdvanceV1, TonLcBootstrapV1,
            TonMasterchainAnchorV1, TonShardLinkV1, TonSignedBlockV1, TonSourceProofV1,
        },
    },
    ton_canonical_boc_v1, ton_header_key_block_v1,
};

use super::{
    AdvanceBudgetV1, BuildError, FRESHNESS_MARGIN_MS, SourceChainBuilder, SourceEventRefV1,
    SourceEvidenceV1, TairaLightClientView, fit_advance,
};
use crate::ton::{
    AccountId, BlockIdExt, LiteClient, LiteClientError,
    schema::{BlockLink, ShardBlockProof, SignatureSet},
};

mod wallet_state;

/// `getBlockHeader` mode: state update, extra and shard hashes.
pub const HEADER_MODE: u32 = 1 | 16 | 32;
/// Config parameters every epoch needs: election timings, catchain and current validators.
pub const EPOCH_CONFIG_PARAMS: [i32; 3] = [15, 28, 34];

fn lite(error: &LiteClientError) -> BuildError {
    BuildError::Unavailable(format!("liteserver: {error}"))
}

fn canonical(bytes: &[u8], what: &str) -> Result<Vec<u8>, BuildError> {
    ton_canonical_boc_v1(bytes)
        .ok_or_else(|| BuildError::Inconsistent(format!("the {what} BoC is malformed")))
}

fn canonical_transaction(bytes: &[u8], expected_hash: [u8; 32]) -> Result<Vec<u8>, BuildError> {
    let bytes = canonical(bytes, "transaction")?;
    if iroha_sccp::ton_canonical_boc_single_root_hash_v1(&bytes) != Some(expected_hash) {
        return Err(BuildError::Inconsistent(
            "the returned transaction differs from the requested hash".into(),
        ));
    }
    Ok(bytes)
}

/// The light client's block id of a liteserver block id.
#[must_use]
pub fn block_id(id: &BlockIdExt) -> TonBlockIdExtV1 {
    TonBlockIdExtV1 {
        workchain: id.workchain,
        shard: id.shard,
        seqno: id.seqno,
        root_hash: id.root_hash,
        file_hash: id.file_hash,
    }
}

/// The liteserver block id of a light-client block id.
#[must_use]
pub fn lite_block_id(id: &TonBlockIdExtV1) -> BlockIdExt {
    BlockIdExt {
        workchain: id.workchain,
        shard: id.shard,
        seqno: id.seqno,
        root_hash: id.root_hash,
        file_hash: id.file_hash,
    }
}

/// The light client's signatures of a liteserver signature set, in node-id order.
#[must_use]
pub fn signatures(set: &SignatureSet) -> TonBlockSignaturesV1 {
    let mut entries: Vec<TonValidatorSignatureV1> = set
        .signatures()
        .iter()
        .map(|signature| TonValidatorSignatureV1 {
            node_id_short: signature.node_id_short,
            signature: signature.signature.clone(),
        })
        .collect();
    entries.sort_by_key(|entry| entry.node_id_short);
    match set {
        SignatureSet::Ordinary(set) => {
            TonBlockSignaturesV1::Ordinary(TonOrdinaryBlockSignaturesV1 {
                catchain_seqno: set.catchain_seqno,
                validator_list_hash_short: set.validator_set_hash,
                signatures: entries,
            })
        }
        SignatureSet::Simplex(set) => TonBlockSignaturesV1::Simplex(TonSimplexBlockSignaturesV1 {
            catchain_seqno: set.cc_seqno,
            validator_list_hash_short: set.validator_set_hash,
            session_id: set.session_id,
            slot: set.slot,
            candidate_data: set.candidate.clone(),
            signatures: entries,
        }),
    }
}

/// The Taira time from which the stored epoch of key block `seqno` no longer signs:
/// `(utime_until + stake_held_for) · 1000` less the profile's margin (§4.13.3). `None` when the
/// light client does not store it.
#[must_use]
pub fn epoch_stale_from_ms(
    profile: &TonChainProfileV1,
    sets: &[SccpLcConsensusSetV1],
    seqno: u32,
) -> Option<u64> {
    let set = sets.iter().find(|set| set.set_id == u64::from(seqno))?;
    let SccpLcSetDataV1::Ton(epoch) = SccpLcSetDataV1::from_frame(&set.set_bytes).ok()? else {
        return None;
    };
    Some(
        (u64::from(epoch.validators.valid_until) + u64::from(epoch.stake_held_for))
            .saturating_mul(1_000)
            .saturating_sub(profile.freshness_margin_ms),
    )
}

fn epoch_fresh_with_margin(
    profile: &TonChainProfileV1,
    sets: &[SccpLcConsensusSetV1],
    seqno: u32,
    now_ms: u64,
) -> bool {
    epoch_stale_from_ms(profile, sets, seqno)
        .is_some_and(|stale_from| now_ms.saturating_add(FRESHNESS_MARGIN_MS) < stale_from)
}

fn key_block_fields(header_proof: &[u8]) -> Result<(u32, bool, u32), BuildError> {
    ton_header_key_block_v1(header_proof)
        .ok_or_else(|| BuildError::Inconsistent("malformed masterchain header proof".into()))
}

// ---------------------------------------------------------------------------------------------
// Source
// ---------------------------------------------------------------------------------------------

/// A burn's minter transaction and the walk to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TonBurnV1 {
    /// The masterchain block registering the first shard block of the walk.
    pub masterchain: TonBlockIdExtV1,
    /// Shard blocks from the registered one down to the event block.
    pub shard_blocks: Vec<TonShardLinkV1>,
    /// Canonical proof `BoC` of the event block reaching the transaction.
    pub event_block_proof: Vec<u8>,
    /// Canonical transaction `BoC`.
    pub transaction: Vec<u8>,
}

/// TON data an evidence builder reads. [`TonBuilder`] serves it from ADNL liteservers.
pub trait TonSource {
    /// The full id of masterchain block `seqno`.
    ///
    /// # Errors
    ///
    /// Any liteserver failure.
    fn masterchain_block(&self, seqno: u32) -> Result<TonBlockIdExtV1, BuildError>;

    /// The canonical header proof of masterchain block `block` (state update, extra and shard
    /// hashes).
    ///
    /// # Errors
    ///
    /// Any liteserver failure or a malformed answer.
    fn header_proof(&self, block: TonBlockIdExtV1) -> Result<Vec<u8>, BuildError>;

    /// The signatures of masterchain block `target` by the validator epoch of key block `key`
    /// (a forward link of `liteServer.getBlockProof`).
    ///
    /// # Errors
    ///
    /// Any liteserver failure, or no forward link from `key` to `target`.
    fn signatures(
        &self,
        key: TonBlockIdExtV1,
        target: TonBlockIdExtV1,
    ) -> Result<TonBlockSignaturesV1, BuildError>;

    /// The canonical state proof of masterchain block `fresh` opening its
    /// `prev_blocks[target.seqno]` (`OldMcBlocksInfo`; the backward link of
    /// `liteServer.getBlockProof` from `fresh` to `target`).
    ///
    /// # Errors
    ///
    /// Any liteserver failure, or no one-step backward link.
    fn back_link_state_proof(
        &self,
        fresh: TonBlockIdExtV1,
        target: TonBlockIdExtV1,
    ) -> Result<Vec<u8>, BuildError>;

    /// The minter transaction `(lt, hash)` of `minter` and the walk to it from its masterchain
    /// block.
    ///
    /// # Errors
    ///
    /// Any liteserver failure, or a transaction that is not served.
    fn burn(&self, minter: [u8; 32], lt: u64, hash: [u8; 32]) -> Result<TonBurnV1, BuildError>;
}

// ---------------------------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------------------------

/// The anchor of a proof hanging from masterchain block `target` (header proof
/// `target_header`): `target` signed by its own epoch while that epoch is stored and fresh,
/// otherwise a back link from the block after the newest stored key block.
fn masterchain_anchor<S: TonSource + ?Sized>(
    source: &S,
    profile: &TonChainProfileV1,
    target: TonBlockIdExtV1,
    target_header: Vec<u8>,
    newest_key_block: u64,
    sets: &[SccpLcConsensusSetV1],
    now_ms: u64,
) -> Result<TonMasterchainAnchorV1, BuildError> {
    let (seqno, _, epoch) = key_block_fields(&target_header)?;
    if seqno != target.seqno {
        return Err(BuildError::Inconsistent(format!(
            "the header proof of masterchain block {} names block {seqno}",
            target.seqno
        )));
    }
    if epoch_fresh_with_margin(profile, sets, epoch, now_ms) {
        let key = source.masterchain_block(epoch)?;
        return Ok(TonMasterchainAnchorV1::Signed(TonSignedBlockV1 {
            block_id: target,
            header_proof: target_header,
            signatures: source.signatures(key, target)?,
        }));
    }
    let newest = u32::try_from(newest_key_block)
        .map_err(|_| BuildError::Inconsistent("key block seqno overflows".into()))?;
    if target.seqno > newest {
        return Err(BuildError::Unavailable(format!(
            "masterchain block {} lies in the epoch of key block {epoch}, which the TON light \
             client does not store yet; advance it first",
            target.seqno
        )));
    }
    if !epoch_fresh_with_margin(profile, sets, newest, now_ms) {
        return Err(BuildError::Unavailable(format!(
            "the newest stored TON epoch (key block {newest}) is stale or about to be; the light \
             client needs an advance or a re-initialization"
        )));
    }
    let fresh_seqno = newest
        .checked_add(1)
        .ok_or_else(|| BuildError::Inconsistent("key block seqno overflows".into()))?;
    let fresh = source.masterchain_block(fresh_seqno)?;
    let fresh_header = source.header_proof(fresh)?;
    if key_block_fields(&fresh_header)? != (fresh_seqno, false, newest) {
        return Err(BuildError::Unavailable(format!(
            "masterchain block {fresh_seqno} is not an ordinary block of the epoch of key block \
             {newest}"
        )));
    }
    let key = source.masterchain_block(newest)?;
    Ok(TonMasterchainAnchorV1::BackLink(TonBackLinkV1 {
        fresh: TonSignedBlockV1 {
            block_id: fresh,
            header_proof: fresh_header,
            signatures: source.signatures(key, fresh)?,
        },
        state_proof: source.back_link_state_proof(fresh, target)?,
        block_id: target,
        header_proof: target_header,
    }))
}

/// Build the evidence of the minter transaction `(lt, hash)` emitting external message
/// `message_index` against the light client `taira` stores (see the module documentation for
/// the anchor), with epochs fresh at `now_ms`.
///
/// # Errors
///
/// Any source failure, a burn in an epoch the light client has not learned yet, or a stale
/// newest epoch.
pub fn build_evidence<S: TonSource + ?Sized>(
    source: &S,
    profile: &TonChainProfileV1,
    (minter, lt, hash, message_index): ([u8; 32], u64, [u8; 32], u16),
    taira: &dyn TairaLightClientView,
    now_ms: u64,
) -> Result<SourceEvidenceV1, BuildError> {
    let light_client = taira.light_client()?;
    let sets = taira.sets()?;
    let burn = source.burn(minter, lt, hash)?;
    let header = source.header_proof(burn.masterchain)?;
    let masterchain = masterchain_anchor(
        source,
        profile,
        burn.masterchain,
        header,
        light_client.head.latest_set_id,
        &sets,
        now_ms,
    )?;
    let proof = SccpSourceProofV1::Ton(TonSourceProofV1 {
        masterchain,
        shard_blocks: burn.shard_blocks,
        event_block_proof: burn.event_block_proof,
        transaction: burn.transaction,
        transaction_lt: lt,
        message_index,
        minter,
    })
    .to_bytes()
    .map_err(|error| BuildError::Inconsistent(format!("proof frame: {error}")))?;
    Ok(SourceEvidenceV1 {
        backfills: Vec::new(),
        proof,
    })
}

// ---------------------------------------------------------------------------------------------
// Liteserver builder
// ---------------------------------------------------------------------------------------------

/// TON evidence builder over a liteserver client.
pub struct TonBuilder {
    lite: LiteClient,
    profile: TonChainProfileV1,
}

impl TonBuilder {
    /// A builder over `lite` under the profile selected by committed Taira state.
    #[must_use]
    pub fn new(profile: TonChainProfileV1, lite: LiteClient) -> Self {
        Self { lite, profile }
    }

    /// Select the profile resolved from the current committed Taira cut before building.
    pub fn set_profile(&mut self, profile: TonChainProfileV1) {
        self.profile = profile;
    }

    /// Moves the liteclient to its next liteserver, for a caller whose build failed on the data
    /// it was served or whose verification rejected what was built.
    pub fn rotate_endpoints(&self) {
        self.lite.rotate_preferred();
    }

    fn header(&self, id: BlockIdExt) -> Result<Vec<u8>, BuildError> {
        let header = self
            .lite
            .get_block_header(id, HEADER_MODE)
            .map_err(|error| lite(&error))?;
        canonical(&header.header_proof, "block header")
    }

    fn config_proof(&self, id: BlockIdExt) -> Result<Vec<u8>, BuildError> {
        let config = self
            .lite
            .get_config_params(0, id, EPOCH_CONFIG_PARAMS.to_vec())
            .map_err(|error| lite(&error))?;
        canonical(&config.config_proof, "config")
    }

    /// The masterchain block with seqno `seqno` (its full liteserver id).
    fn lookup(&self, seqno: u32) -> Result<BlockIdExt, BuildError> {
        Ok(self
            .lite
            .lookup_block(
                crate::ton::BlockId::masterchain(seqno),
                crate::ton::LookupKey::Seqno,
            )
            .map_err(|error| lite(&error))?
            .id)
    }

    /// Seqno of the newest masterchain key block.
    ///
    /// # Errors
    ///
    /// Any liteserver failure or malformed answer.
    pub fn newest_key_block(&self) -> Result<u32, BuildError> {
        let last = self
            .lite
            .get_masterchain_info()
            .map_err(|error| lite(&error))?
            .last;
        // The last block is a key block or names the newest one in `prev_key_block_seqno`.
        let (seqno, key_block, previous) = key_block_fields(&self.header(last)?)?;
        Ok(if key_block { seqno } else { previous })
    }

    /// Seqno of the key block before key block `seqno` (its `prev_key_block_seqno`).
    ///
    /// # Errors
    ///
    /// Any liteserver failure, a malformed answer, or a block that is not a key block.
    pub fn previous_key_block(&self, seqno: u32) -> Result<u32, BuildError> {
        match key_block_fields(&self.header(self.lookup(seqno)?)?)? {
            (_, true, previous) => Ok(previous),
            _ => Err(BuildError::Inconsistent(format!(
                "masterchain block {seqno} is not a key block"
            ))),
        }
    }

    /// Build the `InitializeLightClient` bootstrap of key block `key_seqno`, so every
    /// Parliament member can rebuild the exact bootstrap a proposal names.
    ///
    /// # Errors
    ///
    /// Any liteserver failure or malformed answer.
    pub fn bootstrap_at(&self, key_seqno: u32) -> Result<SccpLcBootstrapV1, BuildError> {
        let key = self.lookup(key_seqno)?;
        SccpLcBootstrapDataV1::Ton(TonLcBootstrapV1 {
            block_id: block_id(&key),
            header_proof: self.header(key)?,
            config_proof: self.config_proof(key)?,
        })
        .to_bootstrap()
        .map_err(|error| BuildError::Inconsistent(format!("bootstrap frame: {error}")))
    }

    /// The burned payload of the minter transaction `(lt, hash)` emitting
    /// `sccp_transfer_to_taira` as external message `message_index`.
    ///
    /// # Errors
    ///
    /// Any liteserver failure, or a transaction without that event.
    pub fn transfer_payload(
        &self,
        minter: [u8; 32],
        lt: u64,
        hash: [u8; 32],
        message_index: u16,
    ) -> Result<Vec<u8>, BuildError> {
        let account = AccountId {
            workchain: 0,
            address: minter,
        };
        let list = self
            .lite
            .get_transactions(1, account, lt, hash)
            .map_err(|error| lite(&error))?;
        let block = *list
            .ids
            .first()
            .ok_or_else(|| BuildError::Unavailable("the transaction is not served".into()))?;
        let transaction = self
            .lite
            .get_one_transaction(block, account, lt)
            .map_err(|error| lite(&error))?;
        iroha_sccp::ton_sccp_transfer_payload_v1(
            &transaction.transaction,
            minter,
            lt,
            message_index,
        )
        .ok_or_else(|| {
            BuildError::Inconsistent("the transaction emitted no sccp_transfer_to_taira".into())
        })
    }
}

impl TonSource for TonBuilder {
    fn masterchain_block(&self, seqno: u32) -> Result<TonBlockIdExtV1, BuildError> {
        Ok(block_id(&self.lookup(seqno)?))
    }

    fn header_proof(&self, block: TonBlockIdExtV1) -> Result<Vec<u8>, BuildError> {
        self.header(lite_block_id(&block))
    }

    fn signatures(
        &self,
        key: TonBlockIdExtV1,
        target: TonBlockIdExtV1,
    ) -> Result<TonBlockSignaturesV1, BuildError> {
        let target = lite_block_id(&target);
        self.lite
            .get_block_proof(lite_block_id(&key), Some(target))
            .map_err(|error| lite(&error))?
            .steps
            .into_iter()
            .rev()
            .find_map(|step| match step {
                BlockLink::Forward(link) if link.to == target => Some(signatures(&link.signatures)),
                _ => None,
            })
            .ok_or_else(|| {
                BuildError::Unavailable(format!(
                    "the liteserver links key block {} forward to no signatures of block {}",
                    key.seqno, target.seqno
                ))
            })
    }

    fn back_link_state_proof(
        &self,
        fresh: TonBlockIdExtV1,
        target: TonBlockIdExtV1,
    ) -> Result<Vec<u8>, BuildError> {
        let (from, to) = (lite_block_id(&fresh), lite_block_id(&target));
        let proof = self
            .lite
            .get_block_proof(from, Some(to))
            .map_err(|error| lite(&error))?;
        let link = proof
            .steps
            .iter()
            .find_map(|step| match step {
                BlockLink::Back(link) if link.from == from && link.to == to => Some(link),
                _ => None,
            })
            .ok_or_else(|| {
                BuildError::Unavailable(format!(
                    "the liteserver links masterchain block {} back to block {} in more than \
                     one step",
                    fresh.seqno, target.seqno
                ))
            })?;
        canonical(&link.state_proof, "back-link state")
    }

    fn burn(&self, minter: [u8; 32], lt: u64, hash: [u8; 32]) -> Result<TonBurnV1, BuildError> {
        let account = AccountId {
            workchain: 0,
            address: minter,
        };
        let list = self
            .lite
            .get_transactions(1, account, lt, hash)
            .map_err(|error| lite(&error))?;
        let event_block = *list
            .ids
            .first()
            .ok_or_else(|| BuildError::Unavailable("the transaction is not served".into()))?;
        let transaction = self
            .lite
            .get_one_transaction(event_block, account, lt)
            .map_err(|error| lite(&error))?;
        let transaction_bytes = canonical_transaction(&transaction.transaction, hash)?;
        let walk = self
            .lite
            .get_shard_block_proof(event_block)
            .map_err(|error| lite(&error))?;
        let shard_blocks = shard_links(&walk, &event_block, &transaction.proof)?;
        Ok(TonBurnV1 {
            masterchain: block_id(&walk.masterchain_id),
            shard_blocks,
            event_block_proof: canonical(&transaction.proof, "transaction proof")?,
            transaction: transaction_bytes,
        })
    }
}

/// The light client's shard walk from a `getShardBlockProof` answer for `event_block`, whose
/// transaction proof (rooted at `event_block`, with its header) is `transaction_proof`.
///
/// A liteserver link proves the link's block from the block before it: link 0's proof is the
/// masterchain block's `ShardHashes` path (the signed anchor's header proof carries it) and link
/// `i + 1`'s proof is rooted at link `i`, opening its `prev_ref`. The light client wants each
/// block's own header proof, so link `i` takes link `i + 1`'s proof and the event block takes the
/// transaction proof.
///
/// # Errors
///
/// [`BuildError::Inconsistent`] for an empty walk, a link outside the basechain, a walk that does
/// not end at `event_block`, or a malformed proof.
pub fn shard_links(
    walk: &ShardBlockProof,
    event_block: &BlockIdExt,
    transaction_proof: &[u8],
) -> Result<Vec<TonShardLinkV1>, BuildError> {
    if walk.links.last().map(|link| &link.id) != Some(event_block)
        || walk.links.iter().any(|link| link.id.workchain != 0)
    {
        return Err(BuildError::Inconsistent(
            "the shard-block proof does not walk the basechain down to the event block".into(),
        ));
    }
    walk.links
        .iter()
        .enumerate()
        .map(|(index, link)| {
            let header_proof = match walk.links.get(index + 1) {
                Some(next) => canonical(&next.proof, "shard block")?,
                None => canonical(transaction_proof, "transaction proof")?,
            };
            Ok(TonShardLinkV1 {
                block_id: block_id(&link.id),
                header_proof,
            })
        })
        .collect()
}

impl SourceChainBuilder for TonBuilder {
    fn source_attempts(&self) -> usize {
        self.lite.servers().len()
    }

    fn rotate_endpoints(&self) {
        TonBuilder::rotate_endpoints(self);
    }

    fn network(&self) -> SccpNetworkV1 {
        SccpNetworkV1::TonMainnet
    }

    /// The bootstrap of the newest key block.
    fn bootstrap(&self) -> Result<SccpLcBootstrapV1, BuildError> {
        self.bootstrap_at(self.newest_key_block()?)
    }

    /// The forward key-block links from the newest stored key block `latest_set_id` to the
    /// liteserver's last block, stepped to `budget`.
    fn advance(
        &self,
        latest_set_id: u64,
        budget: AdvanceBudgetV1,
    ) -> Result<SccpLcAdvanceBytesV1, BuildError> {
        let known = self.lookup(
            u32::try_from(latest_set_id)
                .map_err(|_| BuildError::Inconsistent("key block seqno overflows".into()))?,
        )?;
        let max_hops = budget.max_items;
        let mut hops = Vec::new();
        let mut from = known;
        while hops.len() < max_hops {
            let proof = self
                .lite
                .get_block_proof(from, None)
                .map_err(|error| lite(&error))?;
            let mut advanced = false;
            for step in &proof.steps {
                let BlockLink::Forward(link) = step else {
                    continue;
                };
                if !link.to_key_block || hops.len() == max_hops {
                    continue;
                }
                hops.push(TonKeyBlockHopV1 {
                    block: TonSignedBlockV1 {
                        block_id: block_id(&link.to),
                        header_proof: self.header(link.to)?,
                        signatures: signatures(&link.signatures),
                    },
                    config_proof: self.config_proof(link.to)?,
                });
                from = link.to;
                advanced = true;
            }
            if proof.complete || !advanced {
                break;
            }
        }
        if hops.is_empty() {
            return Err(BuildError::Unavailable(
                "no key block follows the stored epoch yet".into(),
            ));
        }
        fit_advance(hops, budget, |hops| {
            SccpLcAdvanceV1::Ton(TonLcAdvanceV1 { hops })
        })
    }

    fn evidence(
        &self,
        event: &SourceEventRefV1,
        light_client: &dyn TairaLightClientView,
        now_ms: u64,
    ) -> Result<SourceEvidenceV1, BuildError> {
        match *event {
            SourceEventRefV1::Ton {
                minter,
                lt,
                hash,
                message_index,
            } => build_evidence(
                self,
                &self.profile,
                (minter, lt, hash, message_index),
                light_client,
                now_ms,
            ),
            SourceEventRefV1::Evm { .. } => Err(BuildError::Inconsistent("not a TON event".into())),
        }
    }
}

#[cfg(test)]
mod evidence_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        FailoverPolicy,
        ton::{
            LiteClientConfig, LiteServerSet,
            schema::{OrdinarySignatureSet, Signature},
        },
    };

    #[test]
    fn rotating_moves_the_liteclient_to_its_next_liteserver() {
        const KEY: &str = "n4VDnSCUuSpjnCyUk9e3QOOd6o0ItSWYbTnW3Wnn8wk=";
        let servers =
            LiteServerSet::parse(&[&format!("127.0.0.1:1:{KEY}"), &format!("127.0.0.1:2:{KEY}")])
                .expect("loopback liteservers");
        let mut builder = TonBuilder::new(
            iroha_sccp::light_client::profile::SccpChainProfilesV1::latest().ton,
            LiteClient::new(
                servers,
                LiteClientConfig::default(),
                FailoverPolicy::default(),
            ),
        );
        let mut selected = builder.profile;
        selected.supported_until_ms = 1;
        builder.set_profile(selected);
        assert_eq!(builder.profile, selected);
        assert_eq!(builder.source_attempts(), 2);
        assert_eq!(builder.lite.servers().preferred(), 0);
        builder.rotate_endpoints();
        assert_eq!(builder.lite.servers().preferred(), 1);
        builder.rotate_endpoints();
        assert_eq!(builder.lite.servers().preferred(), 0);
    }

    fn id(workchain: i32, seqno: u32) -> BlockIdExt {
        BlockIdExt {
            workchain,
            shard: 0x8000_0000_0000_0000,
            seqno,
            root_hash: [3; 32],
            file_hash: [4; 32],
        }
    }

    /// A canonical one-cell `BoC` whose cell carries `byte`.
    fn boc(byte: u8) -> Vec<u8> {
        vec![
            0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x03, 0x00, 0x00, 0x02, byte,
        ]
    }

    #[test]
    fn transaction_custody_rejects_a_different_well_formed_root() {
        let root = iroha_sccp::v1::ton_cell::CellBuilder::new()
            .store_uint(7, 8)
            .unwrap()
            .build();
        assert_eq!(
            canonical_transaction(&boc(7), *root.hash()).unwrap(),
            boc(7)
        );
        assert!(matches!(
            canonical_transaction(&boc(8), *root.hash()),
            Err(BuildError::Inconsistent(message))
                if message == "the returned transaction differs from the requested hash"
        ));
        assert!(canonical_transaction(&boc(7), [0; 32]).is_err());
        assert!(canonical_transaction(&[1, 2, 3], *root.hash()).is_err());
    }

    #[test]
    fn shard_links_take_each_blocks_own_header_proof() {
        use crate::ton::schema::ShardBlockLink;
        let link = |seqno: u32, byte: u8| ShardBlockLink {
            id: id(0, seqno),
            proof: boc(byte),
        };
        let walk = ShardBlockProof {
            masterchain_id: id(-1, 100),
            links: vec![link(12, 1), link(11, 2), link(10, 3)],
        };
        let links = shard_links(&walk, &id(0, 10), &boc(9)).expect("walk");
        let proofs: Vec<Vec<u8>> = links.iter().map(|link| link.header_proof.clone()).collect();
        assert_eq!(proofs, vec![boc(2), boc(3), boc(9)]);
        assert_eq!(
            links
                .iter()
                .map(|link| link.block_id.seqno)
                .collect::<Vec<_>>(),
            vec![12, 11, 10]
        );
        assert!(shard_links(&walk, &id(0, 11), &boc(9)).is_err());
        let mut foreign = walk.clone();
        foreign.links[0].id.workchain = -1;
        assert!(shard_links(&foreign, &id(0, 10), &boc(9)).is_err());
        let empty = ShardBlockProof {
            masterchain_id: id(-1, 100),
            links: Vec::new(),
        };
        assert!(shard_links(&empty, &id(0, 10), &boc(9)).is_err());
    }

    #[test]
    fn signature_sets_convert_in_node_order() {
        let set = SignatureSet::Ordinary(OrdinarySignatureSet {
            validator_set_hash: 9,
            catchain_seqno: 3,
            signatures: vec![
                Signature {
                    node_id_short: [2; 32],
                    signature: vec![1; 64],
                },
                Signature {
                    node_id_short: [1; 32],
                    signature: vec![2; 64],
                },
            ],
        });
        let TonBlockSignaturesV1::Ordinary(converted) = signatures(&set) else {
            panic!("ordinary");
        };
        assert_eq!(converted.catchain_seqno, 3);
        assert_eq!(converted.validator_list_hash_short, 9);
        assert_eq!(converted.signatures[0].node_id_short, [1; 32]);
        let id = BlockIdExt {
            workchain: -1,
            shard: 0x8000_0000_0000_0000,
            seqno: 5,
            root_hash: [3; 32],
            file_hash: [4; 32],
        };
        assert_eq!(block_id(&id).seqno, 5);
        assert!(canonical(&[1, 2, 3], "junk").is_err());
    }
}
