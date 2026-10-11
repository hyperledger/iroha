//! BSC evidence builders (spec §4.13.3, §4.13.5, §7.2, §7.3).
//!
//! Skipping advances (every set-transition checkpoint after the newest stored set, then a step
//! from the latest finalized epoch checkpoint, which re-announces the newest set and refreshes
//! its freshness), bootstraps and receipt proofs, built from standard BSC JSON-RPC
//! ([`BscBuilder`]): `eth_getBlockByNumber` (BSC resolves the `finalized` tag by fast finality),
//! `eth_getTransactionReceipt` and `eth_getBlockReceipts`. Vote attestations are read from the
//! `extraData` of descendant headers. Everything built is untrusted until `iroha_sccp` verifies
//! it; the builders check header hashes, parent links and receipt roots locally, so a lying
//! endpoint is caught before submission.
//!
//! **Evidence.** The event block `B` is proven from the first anchor that works:
//!
//! 1. a vote attestation finalizing `B` or a descendant within 256 headers, under the stored set
//!    covering its target, when that set is still fresh [`super::FRESHNESS_MARGIN_MS`] from now
//!    (a superseded set until `ws_bound_ms` after its successor's checkpoint time, the newest
//!    set until `ws_bound_ms` after the newest finalized epoch checkpoint that re-announces it,
//!    `head.latest_finalized`);
//! 2. the nearest retained checkpoint `C ≥ B` with the headers `B ..= C` (`C − B ≤ 255`), for
//!    example an epoch checkpoint an advance recorded;
//! 3. otherwise `Backfill` segments of `max_backfill_headers` (256) headers from `C` down to
//!    within 255 blocks of `B`, then the headers up to the last backfilled checkpoint.

use std::ops::RangeInclusive;

use iroha_data_model::{
    bridge::SccpNetworkV1,
    sccp::{
        inbound::SccpSourceProofBytesV1,
        light_client::{
            SccpLcAdvanceBytesV1, SccpLcBootstrapV1, SccpLcCheckpointV1, SccpLcConsensusSetV1,
            SccpLightClientV1,
        },
    },
};
use iroha_sccp::{
    light_client::{
        bsc::{
            BscAdvanceStepV1, BscFinalityV1, BscHeaderSegmentV1, BscLcAdvanceV1, BscLcBootstrapV1,
            BscProofAnchorV1, BscSourceProofV1, BscStoredCheckpointRefV1, BscValidatorV1,
            BscVoteV1, activation_offset, header_announced_set, header_attestation, header_summary,
        },
        ethereum::EthereumEventSelectorV1,
        profile::{BSC_MAX_SEGMENT_HEADERS, BscChainProfileV1, SccpChainProfilesV1},
        proof::{SccpLcAdvanceV1, SccpLcBootstrapDataV1, SccpLcSegmentV1, SccpSourceProofV1},
    },
    v1::hashes::keccak256,
};

use super::{
    AdvanceBudgetV1, BuildError, SourceChainBuilder, SourceEventRefV1, SourceEvidenceV1,
    TairaLightClientView, backfill_bytes,
    ethereum::{EthereumEventV1, EvmEventBlockV1, evm_event_block, evm_headers_at},
    fit_advance, fresh_with_margin, plan_backfill,
};
use crate::{EvmClient, evm::BlockTag};

/// Headers scanned after a block for a vote attestation finalizing it.
pub const MAX_ATTESTATION_SCAN: u64 = 32;

/// The stored set covering vote target `target` and its successor, from the light client's
/// stored sets (any order): the set with the highest first covered height at or below `target`.
///
/// # Errors
///
/// [`BuildError::Unavailable`] when no stored set covers `target`.
pub fn covering_set(
    sets: &[SccpLcConsensusSetV1],
    target: u64,
) -> Result<(u64, Option<u64>), BuildError> {
    let mut ordered: Vec<(u64, u64)> = sets
        .iter()
        .map(|set| (set.valid_from_source_height, set.set_id))
        .collect();
    ordered.sort_unstable();
    let position = ordered
        .iter()
        .rposition(|(valid_from, _)| *valid_from <= target)
        .ok_or_else(|| {
            BuildError::Unavailable(format!("no stored BSC set covers vote target {target}"))
        })?;
    Ok((
        ordered[position].1,
        ordered.get(position + 1).map(|(_, set_id)| *set_id),
    ))
}

/// Whether the stored set `set_id` is still fresh [`super::FRESHNESS_MARGIN_MS`] after `now_ms`:
/// a superseded set until `ws_bound_ms` after its successor's checkpoint time, the newest set
/// until `ws_bound_ms` after the newest finalized epoch checkpoint that re-announces it
/// (`head.latest_finalized`, §4.13.3).
#[must_use]
pub fn set_fresh_with_margin(
    sets: &[SccpLcConsensusSetV1],
    set_id: u64,
    light_client: &SccpLightClientV1,
    now_ms: u64,
) -> bool {
    sets.iter()
        .find(|set| set.set_id == set_id)
        .is_some_and(|set| {
            let expiry = set
                .superseded_at_source_ms
                .unwrap_or(light_client.head.latest_finalized.source_time_ms);
            fresh_with_margin(Some(expiry), light_client.params.ws_bound_ms, now_ms)
        })
}

// ---------------------------------------------------------------------------------------------
// Source
// ---------------------------------------------------------------------------------------------

/// BSC data an evidence builder reads. [`BscBuilder`] serves it from public JSON-RPC.
pub trait BscSource {
    /// Height of the latest block BSC fast finality has finalized.
    ///
    /// # Errors
    ///
    /// Any endpoint failure.
    fn finalized_number(&self) -> Result<u64, BuildError>;

    /// Height of the latest block.
    ///
    /// # Errors
    ///
    /// Any endpoint failure.
    fn latest_number(&self) -> Result<u64, BuildError>;

    /// Hash-checked header RLPs of the blocks `numbers`, in request order.
    ///
    /// # Errors
    ///
    /// Any endpoint failure or a block that is not served.
    fn headers_at(&self, numbers: &[u64]) -> Result<Vec<Vec<u8>>, BuildError>;

    /// The block of transaction `tx_hash` and the receipt proof of the transaction.
    ///
    /// # Errors
    ///
    /// Any endpoint failure, a transaction that is not mined, or an inconsistent response.
    fn event_block(&self, tx_hash: &[u8; 32]) -> Result<EvmEventBlockV1, BuildError>;

    /// The first vote attestation, carried by one of the [`MAX_ATTESTATION_SCAN`] headers after
    /// `from`, that finalizes a block in `from..=until`, with its vote.
    ///
    /// # Errors
    ///
    /// Any endpoint failure, a malformed header, or no such attestation yet.
    fn finalizing_vote(&self, from: u64, until: u64) -> Result<(Vec<u8>, BscVoteV1), BuildError> {
        // TODO(B11): parse under the profile version active on the target Taira (Torii
        // capabilities) rather than the newest compiled one.
        let profile = SccpChainProfilesV1::latest().bsc;
        let end = from
            .saturating_add(MAX_ATTESTATION_SCAN)
            .min(self.latest_number()?);
        if end <= from {
            return Err(BuildError::Unavailable(format!(
                "BSC block {from} has no descendants yet"
            )));
        }
        for header in headers(self, from + 1..=end)? {
            let vote = header_attestation(&profile, &header)
                .map_err(|error| BuildError::Inconsistent(format!("BSC header: {error}")))?;
            if let Some((attestation, vote)) = vote
                && vote.finalizes_source()
                && (from..=until).contains(&vote.source_number)
            {
                return Ok((attestation, vote));
            }
        }
        Err(BuildError::Unavailable(format!(
            "no vote attestation finalizes a BSC block in {from}..={until} yet"
        )))
    }
}

fn headers<S: BscSource + ?Sized>(
    source: &S,
    range: RangeInclusive<u64>,
) -> Result<Vec<Vec<u8>>, BuildError> {
    let numbers: Vec<u64> = range.collect();
    source.headers_at(&numbers)
}

/// Check that `chain` starts at the event block `event_header` and is parent-linked; returns
/// the hash of its last header.
fn check_chain(event_header: &[u8], chain: &[Vec<u8>]) -> Result<[u8; 32], BuildError> {
    let summary = |header: &[u8]| {
        header_summary(header)
            .map_err(|error| BuildError::Inconsistent(format!("BSC header: {error}")))
    };
    let first = chain
        .first()
        .ok_or_else(|| BuildError::Inconsistent("an empty BSC header chain".into()))?;
    if keccak256(&[first]) != keccak256(&[event_header]) {
        return Err(BuildError::Inconsistent(
            "the served headers do not start at the event block".into(),
        ));
    }
    let mut previous = summary(first)?;
    for header in &chain[1..] {
        let next = summary(header)?;
        if next.parent_hash != previous.hash || previous.number.checked_add(1) != Some(next.number)
        {
            return Err(BuildError::Inconsistent(format!(
                "BSC block {} does not follow block {}",
                next.number, previous.number
            )));
        }
        previous = next;
    }
    Ok(previous.hash)
}

// ---------------------------------------------------------------------------------------------
// Advance
// ---------------------------------------------------------------------------------------------

fn announced(header: &[u8]) -> Result<(Vec<BscValidatorV1>, u8), BuildError> {
    header_announced_set(header)
        .map_err(|error| BuildError::Inconsistent(format!("BSC epoch checkpoint: {error}")))
}

fn activation(checkpoint: u64, previous: &(Vec<BscValidatorV1>, u8)) -> Result<u64, BuildError> {
    activation_offset(previous.0.len(), previous.1)
        .ok()
        .and_then(|offset| checkpoint.checked_add(offset)?.checked_add(1))
        .ok_or_else(|| BuildError::Inconsistent("BSC activation height overflows".into()))
}

/// Build an advance from the newest stored set `latest_set_id` (its checkpoint height): a
/// transition step for every later finalized checkpoint that announces another set, then a step
/// from the latest finalized epoch checkpoint (re-announcing the newest set) to the first block a
/// vote finalizes, stepped to `budget`. The light client measures the newest set's freshness from
/// that checkpoint (§4.13.3).
///
/// # Errors
///
/// Any source failure, an inconsistent response, or nothing to advance.
pub fn build_advance<S: BscSource + ?Sized>(
    source: &S,
    profile: &BscChainProfileV1,
    latest_set_id: u64,
    budget: AdvanceBudgetV1,
) -> Result<SccpLcAdvanceBytesV1, BuildError> {
    let epoch = profile.epoch_length;
    let max_steps = budget.max_items;
    let finalized = source.finalized_number()?;
    let stored = source.headers_at(&[latest_set_id.saturating_sub(epoch), latest_set_id])?;
    let mut newest = latest_set_id;
    let mut current = announced(&stored[1])?;
    let mut valid_from = activation(latest_set_id, &announced(&stored[0])?)?;
    let checkpoints: Vec<u64> = (1..)
        .map_while(|index: u64| latest_set_id.checked_add(index.checked_mul(epoch)?))
        .take_while(|height| *height <= finalized)
        .collect();
    let mut steps = Vec::new();
    for (height, header) in checkpoints.iter().zip(source.headers_at(&checkpoints)?) {
        if steps.len() == max_steps {
            break;
        }
        let next = announced(&header)?;
        if next == current {
            continue;
        }
        let next_valid_from = activation(*height, &current)?;
        let until = height
            .saturating_add(BSC_MAX_SEGMENT_HEADERS as u64 - 1)
            .min(next_valid_from.saturating_sub(2))
            .min(finalized);
        let (attestation, vote) = source.finalizing_vote(*height, until)?;
        steps.push(BscAdvanceStepV1 {
            headers: headers(source, *height..=vote.source_number)?,
            finality: BscFinalityV1 {
                set_id: newest,
                successor_set_id: None,
                attestation,
            },
        });
        newest = *height;
        current = next;
        valid_from = next_valid_from;
    }
    let checkpoint = finalized / epoch * epoch;
    let from = checkpoint.max(valid_from.saturating_sub(1));
    let until = checkpoint
        .saturating_add(BSC_MAX_SEGMENT_HEADERS as u64 - 1)
        .min(finalized);
    if steps.len() < max_steps && checkpoint > newest && from <= until {
        let (attestation, vote) = source.finalizing_vote(from, until)?;
        steps.push(BscAdvanceStepV1 {
            headers: headers(source, checkpoint..=vote.source_number)?,
            finality: BscFinalityV1 {
                set_id: newest,
                successor_set_id: None,
                attestation,
            },
        });
    }
    if steps.is_empty() {
        return Err(BuildError::Unavailable(
            "no finalized BSC epoch checkpoint after the newest set yet".into(),
        ));
    }
    fit_advance(steps, budget, |steps| {
        SccpLcAdvanceV1::Bsc(BscLcAdvanceV1 { steps })
    })
}

// ---------------------------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------------------------

fn proof_bytes(
    anchor: BscProofAnchorV1,
    headers: Vec<Vec<u8>>,
    block: &EvmEventBlockV1,
    event: EthereumEventSelectorV1,
) -> Result<SccpSourceProofBytesV1, BuildError> {
    SccpSourceProofV1::Bsc(BscSourceProofV1 {
        anchor,
        headers,
        transaction_index: block.transaction_index,
        receipt_proof: block.receipt_proof.clone(),
        event,
    })
    .to_bytes()
    .map_err(|error| BuildError::Inconsistent(format!("proof frame: {error}")))
}

/// A proof under a vote attestation finalizing the event block or a descendant within
/// `max_headers` headers, signed by a stored set that is still fresh.
fn finality_proof<S: BscSource + ?Sized>(
    source: &S,
    block: &EvmEventBlockV1,
    light_client: &SccpLightClientV1,
    sets: &[SccpLcConsensusSetV1],
    max_headers: u64,
    event: EthereumEventSelectorV1,
    now_ms: u64,
) -> Result<SccpSourceProofBytesV1, BuildError> {
    let stale = |set_id: u64| {
        BuildError::Unavailable(format!(
            "the stored set {set_id} covering BSC block {} is stale or about to be",
            block.number
        ))
    };
    let (first_set, _) = covering_set(sets, block.number.saturating_add(1))?;
    if !set_fresh_with_margin(sets, first_set, light_client, now_ms) {
        return Err(stale(first_set));
    }
    let until = block.number.saturating_add(max_headers.saturating_sub(1));
    let (attestation, vote) = source.finalizing_vote(block.number, until)?;
    let chain = headers(source, block.number..=vote.source_number)?;
    if check_chain(&block.header, &chain)? != vote.source_hash {
        return Err(BuildError::Inconsistent(
            "the attestation finalizes another block than the served headers".into(),
        ));
    }
    let (set_id, successor_set_id) = covering_set(sets, vote.target_number)?;
    if !set_fresh_with_margin(sets, set_id, light_client, now_ms) {
        return Err(stale(set_id));
    }
    proof_bytes(
        BscProofAnchorV1::Finality(BscFinalityV1 {
            set_id,
            successor_set_id,
            attestation,
        }),
        chain,
        block,
        event,
    )
}

/// Evidence anchored at the stored `checkpoint` at or above the event block, with `Backfill`
/// segments when it lies more than `max_headers − 1` blocks above it.
fn checkpoint_evidence<S: BscSource + ?Sized>(
    source: &S,
    block: &EvmEventBlockV1,
    checkpoint: &SccpLcCheckpointV1,
    max_headers: u64,
    max_backfill: u64,
    event: EthereumEventSelectorV1,
) -> Result<SourceEvidenceV1, BuildError> {
    let top = checkpoint.data.source_height;
    let plan = plan_backfill(
        block.number,
        top,
        max_headers.saturating_sub(1),
        max_backfill,
    )?;
    let chain = headers(source, block.number..=top)?;
    if check_chain(&block.header, &chain)? != checkpoint.data.block_hash {
        return Err(BuildError::Inconsistent(format!(
            "the served BSC block {top} is not the stored checkpoint"
        )));
    }
    let index = |number: u64| usize::try_from(number - block.number).unwrap_or(usize::MAX);
    let backfills = plan
        .segments
        .iter()
        .map(|(first, last)| {
            backfill_bytes(SccpLcSegmentV1::Bsc(BscHeaderSegmentV1 {
                headers: chain[index(*first)..=index(*last)].to_vec(),
            }))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SourceEvidenceV1 {
        backfills,
        proof: proof_bytes(
            BscProofAnchorV1::StoredCheckpoint(BscStoredCheckpointRefV1 {
                source_height: plan.anchor,
            }),
            chain[..=index(plan.anchor)].to_vec(),
            block,
            event,
        )?,
    })
}

/// Build the evidence of `event` in transaction `tx_hash` against the light client `taira`
/// stores (see the module documentation for the anchor order), with sets fresh at `now_ms`.
///
/// # Errors
///
/// Any source failure, or a block that neither a fresh set nor a retained checkpoint (with at
/// most [`super::MAX_BACKFILL_SEGMENTS`] backfills) reaches.
pub fn build_evidence<S: BscSource + ?Sized>(
    source: &S,
    tx_hash: &[u8; 32],
    event: EthereumEventV1,
    taira: &dyn TairaLightClientView,
    now_ms: u64,
) -> Result<SourceEvidenceV1, BuildError> {
    let light_client = taira.light_client()?;
    let bound = |param: u32| u64::from(param).min(BSC_MAX_SEGMENT_HEADERS as u64);
    let max_headers = bound(light_client.params.max_ancestry_headers);
    let max_backfill = bound(light_client.params.max_backfill_headers);
    let block = source.event_block(tx_hash)?;
    let selector = event.selector();
    let sets = taira.sets()?;
    let finality_error = match finality_proof(
        source,
        &block,
        &light_client,
        &sets,
        max_headers,
        selector,
        now_ms,
    ) {
        Ok(proof) => {
            return Ok(SourceEvidenceV1 {
                backfills: Vec::new(),
                proof,
            });
        }
        Err(error) => error,
    };
    let Some(checkpoint) = taira.checkpoint_covering(block.number)? else {
        return Err(BuildError::Unavailable(format!(
            "{finality_error}; Taira retains no checkpoint at or above BSC block {}",
            block.number
        )));
    };
    checkpoint_evidence(
        source,
        &block,
        &checkpoint,
        max_headers,
        max_backfill,
        selector,
    )
}

// ---------------------------------------------------------------------------------------------
// Public-RPC builder
// ---------------------------------------------------------------------------------------------

/// BSC evidence builder over one JSON-RPC endpoint.
pub struct BscBuilder {
    rpc: EvmClient,
    profile: BscChainProfileV1,
}

impl BscBuilder {
    /// A builder over `rpc` under the newest compiled BSC profile version.
    ///
    /// TODO(B11): build under the version active on the target Taira (Torii capabilities)
    /// rather than the newest compiled one.
    #[must_use]
    pub fn new(rpc: EvmClient) -> Self {
        Self {
            rpc,
            profile: SccpChainProfilesV1::latest().bsc,
        }
    }

    /// Moves the JSON-RPC client to its next endpoint, for a caller whose build failed on the
    /// data it was served or whose verification rejected what was built.
    pub fn rotate_endpoints(&self) {
        self.rpc.transport().rotate_preferred();
    }
}

impl BscSource for BscBuilder {
    fn finalized_number(&self) -> Result<u64, BuildError> {
        Ok(self
            .rpc
            .block_by_number(BlockTag::Finalized)?
            .ok_or_else(|| BuildError::Unavailable("no finalized BSC block is served".into()))?
            .header
            .number)
    }

    fn latest_number(&self) -> Result<u64, BuildError> {
        Ok(self.rpc.block_number()?)
    }

    fn headers_at(&self, numbers: &[u64]) -> Result<Vec<Vec<u8>>, BuildError> {
        evm_headers_at(&self.rpc, numbers)
    }

    fn event_block(&self, tx_hash: &[u8; 32]) -> Result<EvmEventBlockV1, BuildError> {
        evm_event_block(&self.rpc, tx_hash)
    }
}

impl SourceChainBuilder for BscBuilder {
    fn network(&self) -> SccpNetworkV1 {
        SccpNetworkV1::BscMainnet
    }

    /// The bootstrap of the latest finalized epoch checkpoint.
    fn bootstrap(&self) -> Result<SccpLcBootstrapV1, BuildError> {
        let epoch = self.profile.epoch_length;
        let checkpoint = self.finalized_number()? / epoch * epoch;
        if checkpoint < epoch {
            return Err(BuildError::Unavailable(
                "no finalized BSC epoch checkpoint".into(),
            ));
        }
        let headers = self.headers_at(&[checkpoint - epoch, checkpoint])?;
        SccpLcBootstrapDataV1::Bsc(BscLcBootstrapV1 {
            previous_checkpoint_header: headers[0].clone(),
            checkpoint_header: headers[1].clone(),
        })
        .to_bootstrap()
        .map_err(|error| BuildError::Inconsistent(format!("bootstrap frame: {error}")))
    }

    fn advance(
        &self,
        latest_set_id: u64,
        budget: AdvanceBudgetV1,
    ) -> Result<SccpLcAdvanceBytesV1, BuildError> {
        build_advance(self, &self.profile, latest_set_id, budget)
    }

    fn evidence(
        &self,
        event: &SourceEventRefV1,
        light_client: &dyn TairaLightClientView,
        now_ms: u64,
    ) -> Result<SourceEvidenceV1, BuildError> {
        match event {
            SourceEventRefV1::Evm { tx_hash, event } => {
                build_evidence(self, tx_hash, *event, light_client, now_ms)
            }
            SourceEventRefV1::Ton { .. } => Err(BuildError::Inconsistent("not a BSC event".into())),
        }
    }
}

#[cfg(test)]
mod evidence_tests;

#[cfg(test)]
mod tests {
    use iroha_data_model::sccp::light_client::{
        SccpLcHeadV1, SccpLcPointV1, SccpLightClientParamsV1,
    };

    use super::*;
    use crate::builders::FRESHNESS_MARGIN_MS;

    fn set(set_id: u64, valid_from_source_height: u64) -> SccpLcConsensusSetV1 {
        SccpLcConsensusSetV1 {
            set_id,
            valid_from_source_height,
            superseded_at_source_ms: None,
            set_bytes: Vec::new(),
        }
    }

    #[test]
    fn covering_sets_name_their_successor() {
        let sets = vec![set(7_000, 7_176), set(5_000, 5_176), set(9_000, 9_200)];
        assert_eq!(
            covering_set(&sets, 7_100).expect("covered"),
            (5_000, Some(7_000))
        );
        assert_eq!(
            covering_set(&sets, 7_176).expect("covered"),
            (7_000, Some(9_000))
        );
        assert_eq!(covering_set(&sets, 9_500).expect("covered"), (9_000, None));
        assert!(matches!(
            covering_set(&sets, 5_000),
            Err(BuildError::Unavailable(_))
        ));
        assert!(covering_set(&[], 1).is_err());
    }

    #[test]
    fn set_freshness_follows_supersession_or_the_newest_finalized_block() {
        let params = SccpLightClientParamsV1::defaults_for(SccpNetworkV1::BscMainnet)
            .expect("external network");
        let light_client = SccpLightClientV1 {
            params,
            head: SccpLcHeadV1 {
                latest_set_id: 7_000,
                latest_finalized: SccpLcPointV1 {
                    source_height: 7_500,
                    block_hash: [1; 32],
                    source_time_ms: 50_000_000,
                },
                last_progress_taira_ms: 0,
            },
            frozen: None,
            state_hash: [0; 32],
        };
        let mut old = set(5_000, 5_176);
        old.superseded_at_source_ms = Some(10_000_000);
        let sets = vec![old, set(7_000, 7_176)];
        let old_edge = 10_000_000 + params.ws_bound_ms - FRESHNESS_MARGIN_MS;
        assert!(set_fresh_with_margin(
            &sets,
            5_000,
            &light_client,
            old_edge - 1
        ));
        assert!(!set_fresh_with_margin(
            &sets,
            5_000,
            &light_client,
            old_edge
        ));
        let newest_edge = 50_000_000 + params.ws_bound_ms - FRESHNESS_MARGIN_MS;
        assert!(set_fresh_with_margin(
            &sets,
            7_000,
            &light_client,
            newest_edge - 1
        ));
        assert!(!set_fresh_with_margin(
            &sets,
            7_000,
            &light_client,
            newest_edge
        ));
        assert!(!set_fresh_with_margin(&sets, 9_000, &light_client, 0));
    }

    #[test]
    fn rotating_moves_the_client_to_its_next_endpoint() {
        let builder = BscBuilder::new(EvmClient::new(
            crate::builders::test_support::two_endpoint_transport(),
        ));
        assert_eq!(builder.rpc.transport().endpoints().preferred(), 0);
        builder.rotate_endpoints();
        assert_eq!(builder.rpc.transport().endpoints().preferred(), 1);
        builder.rotate_endpoints();
        assert_eq!(builder.rpc.transport().endpoints().preferred(), 0);
    }
}
