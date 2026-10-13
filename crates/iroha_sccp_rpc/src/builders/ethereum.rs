//! Ethereum evidence builders (spec §4.13.3, §4.13.5, §7.2, §7.3).
//!
//! Sync-committee advances, bootstraps and inbound and void proofs, built from the standard
//! beacon light-client API (JSON) and execution JSON-RPC ([`EthereumBuilder`]), or from any other
//! [`EthereumSource`]. Everything built is untrusted until `iroha_sccp` verifies it; the builders
//! check header hashes, parent links and receipt roots locally, so a lying endpoint is caught
//! before submission.
//!
//! **Advance.** The committee update of every period from the stored one up to the latest
//! finality's period, oldest first, then the finality update, stepped to the
//! [`AdvanceBudgetV1`]: a light client further behind than one advance holds receives the oldest
//! updates that fit and catches up over the following advances.
//!
//! **Evidence.** The event block `B` is proven from the first anchor that works:
//!
//! 1. the latest finality update, whose finalized execution block is `E`, when the light client
//!    stores the committee of its signature period. Ancestry is `SameBlock` (`E = B`),
//!    `HeaderChain` when `E − B ≤` [`PREFERRED_HEADER_CHAIN`], `HistoryContract` (EIP-2935
//!    `eth_getProof` at `E`, `1 ≤ E − B ≤ 8191`, `E` after the Prague activation), and
//!    `HeaderChain` up to `max_ancestry_headers` (256) when the endpoint does not serve the state
//!    of `E`;
//! 2. the nearest retained checkpoint `C ≥ B` (`GET /v1/sccp/light-clients/{network}/
//!    checkpoints?covering=B`), with the same ancestry rules (`HistoryContract` at `C` needs an
//!    endpoint that serves the state of `C`, usually an archive node);
//! 3. otherwise `Backfill` segments of `max_backfill_headers` (256) headers from `C` down to
//!    within 256 blocks of `B`, then a `HeaderChain` from the last backfilled checkpoint.

use iroha_data_model::bridge::SccpNetworkV1;
use iroha_data_model::sccp::{
    inbound::SccpSourceProofBytesV1,
    light_client::{SccpLcAdvanceBytesV1, SccpLcBootstrapV1},
};
use iroha_sccp::{
    BeaconBlockHeader, BlsPublicKey, BlsSignature, CapellaExecutionPayloadHeader,
    CurrentSyncCommitteeBranch, DenebExecutionPayloadHeader, EthereumFork, ExtraData,
    FinalityBranch, ForkSchedule, LightClientBootstrap, LightClientHeader, LightClientUpdate,
    NextSyncCommitteeBranch, NextSyncCommitteeProof, Root, SyncAggregate, SyncCommittee,
    ethereum_source::{
        EthereumLogV1, EthereumNativeLightClientBootstrapV1, EthereumNativeLightClientUpdateV1,
        EthereumNativeMptProofV1, EthereumReceiptV1, decode_execution_header, encode_receipt,
        rlp_encode_bytes, rlp_encode_list, rlp_encode_u64, rlp_encode_uint_bytes,
    },
    light_client::{
        ethereum::{
            EthereumAncestryV1, EthereumEventSelectorV1, EthereumHeaderSegmentV1,
            EthereumHistoryProofV1, EthereumLcAdvanceV1, EthereumLogRangeV1, EthereumLogRefV1,
            EthereumProofAnchorV1, EthereumSourceProofV1, EthereumStoredCheckpointRefV1,
        },
        profile::{
            ETHEREUM_MAX_ANCESTRY_HEADERS, ETHEREUM_MAX_BACKFILL_HEADERS, EthereumChainProfileV1,
        },
        proof::{SccpLcAdvanceV1, SccpLcBootstrapDataV1, SccpLcSegmentV1, SccpSourceProofV1},
    },
    v1::hashes::{keccak256, word_u64},
};
use norito::json::Value;

use super::{
    AdvanceBudgetV1, BuildError, SourceChainBuilder, SourceEventRefV1, SourceEvidenceV1,
    TairaLightClientView, backfill_bytes, fit_advance, plan_backfill,
};
use crate::{
    BeaconClient, EvmClient,
    evm::{BlockId, BlockTag, EvmBlock, EvmHeader, EvmReceipt, format_data},
    http::MAX_JSON_RPC_BATCH,
};

/// Distance `E − B` up to which a `HeaderChain` is preferred to a `HistoryContract` proof: a few
/// headers are smaller than an account and storage proof and need no state at `E`.
pub const PREFERRED_HEADER_CHAIN: u64 = 8;
/// Sync-committee period length in slots.
const SLOTS_PER_PERIOD: u64 = 8_192;

fn json(detail: impl Into<String>) -> BuildError {
    BuildError::Json(detail.into())
}

// ---------------------------------------------------------------------------------------------
// Beacon JSON
// ---------------------------------------------------------------------------------------------

fn field<'a>(value: &'a Value, key: &str) -> Result<&'a Value, BuildError> {
    value
        .get(key)
        .ok_or_else(|| json(format!("missing field `{key}`")))
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, BuildError> {
    field(value, key)?
        .as_str()
        .ok_or_else(|| json(format!("field `{key}` is not a string")))
}

fn decimal(value: &Value, key: &str) -> Result<u64, BuildError> {
    text(value, key)?
        .parse()
        .map_err(|_| json(format!("field `{key}` is not a decimal integer")))
}

fn hex_bytes(text: &str) -> Result<Vec<u8>, BuildError> {
    hex::decode(text.strip_prefix("0x").unwrap_or(text))
        .map_err(|_| json(format!("`{text}` is not hex")))
}

fn hex_fixed<const N: usize>(value: &Value, key: &str) -> Result<[u8; N], BuildError> {
    hex_bytes(text(value, key)?)?
        .try_into()
        .map_err(|_| json(format!("field `{key}` is not {N} bytes")))
}

fn hex_list(value: &Value, key: &str) -> Result<Vec<Vec<u8>>, BuildError> {
    field(value, key)?
        .as_array()
        .ok_or_else(|| json(format!("field `{key}` is not an array")))?
        .iter()
        .map(|item| {
            item.as_str()
                .ok_or_else(|| json(format!("`{key}` holds a non-string")))
                .and_then(hex_bytes)
        })
        .collect()
}

fn roots<const N: usize>(value: &Value, key: &str) -> Result<[Root; N], BuildError> {
    hex_list(value, key)?
        .into_iter()
        .map(|root| {
            Root::try_from(root.as_slice()).map_err(|_| json("a branch root is not 32 bytes"))
        })
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| json(format!("branch `{key}` has the wrong length")))
}

fn le_u256_from_decimal(text: &str) -> Result<[u8; 32], BuildError> {
    let value: u128 = text
        .parse()
        .map_err(|_| json("base fee is not a decimal below 2^128"))?;
    let mut out = [0_u8; 32];
    out[..16].copy_from_slice(&value.to_le_bytes());
    Ok(out)
}

fn fork_from_version(response: &Value) -> Result<EthereumFork, BuildError> {
    match text(response, "version")? {
        "capella" => Ok(EthereumFork::Capella),
        "deneb" => Ok(EthereumFork::Deneb),
        "electra" => Ok(EthereumFork::Electra),
        "fulu" => Ok(EthereumFork::Fulu),
        other => Err(json(format!("unsupported consensus version `{other}`"))),
    }
}

fn beacon_header(value: &Value) -> Result<BeaconBlockHeader, BuildError> {
    Ok(BeaconBlockHeader {
        slot: decimal(value, "slot")?,
        proposer_index: decimal(value, "proposer_index")?,
        parent_root: hex_fixed(value, "parent_root")?,
        state_root: hex_fixed(value, "state_root")?,
        body_root: hex_fixed(value, "body_root")?,
    })
}

fn light_client_header(value: &Value, fork: EthereumFork) -> Result<LightClientHeader, BuildError> {
    let beacon = beacon_header(field(value, "beacon")?)?;
    let execution = field(value, "execution")?;
    let capella = CapellaExecutionPayloadHeader {
        parent_hash: hex_fixed(execution, "parent_hash")?,
        fee_recipient: hex_fixed(execution, "fee_recipient")?,
        state_root: hex_fixed(execution, "state_root")?,
        receipts_root: hex_fixed(execution, "receipts_root")?,
        logs_bloom: hex_fixed(execution, "logs_bloom")?,
        prev_randao: hex_fixed(execution, "prev_randao")?,
        block_number: decimal(execution, "block_number")?,
        gas_limit: decimal(execution, "gas_limit")?,
        gas_used: decimal(execution, "gas_used")?,
        timestamp: decimal(execution, "timestamp")?,
        extra_data: ExtraData::new(hex_bytes(text(execution, "extra_data")?)?)
            .map_err(|_| json("extra data exceeds 32 bytes"))?,
        base_fee_per_gas: le_u256_from_decimal(text(execution, "base_fee_per_gas")?)?,
        block_hash: hex_fixed(execution, "block_hash")?,
        transactions_root: hex_fixed(execution, "transactions_root")?,
        withdrawals_root: hex_fixed(execution, "withdrawals_root")?,
    };
    let execution_branch: [Root; 4] = roots(value, "execution_branch")?;
    let deneb = || -> Result<DenebExecutionPayloadHeader, BuildError> {
        Ok(DenebExecutionPayloadHeader {
            capella,
            blob_gas_used: decimal(execution, "blob_gas_used")?,
            excess_blob_gas: decimal(execution, "excess_blob_gas")?,
        })
    };
    Ok(match fork {
        EthereumFork::Capella => LightClientHeader::Capella {
            beacon,
            execution: capella,
            execution_branch,
        },
        EthereumFork::Deneb => LightClientHeader::Deneb {
            beacon,
            execution: deneb()?,
            execution_branch,
        },
        EthereumFork::Electra => LightClientHeader::Electra {
            beacon,
            execution: deneb()?,
            execution_branch,
        },
        EthereumFork::Fulu => LightClientHeader::Fulu {
            beacon,
            execution: deneb()?,
            execution_branch,
        },
        EthereumFork::Altair | EthereumFork::Bellatrix => {
            return Err(json("pre-Capella light-client headers are not supported"));
        }
    })
}

fn committee(value: &Value) -> Result<SyncCommittee, BuildError> {
    let keys = hex_list(value, "pubkeys")?
        .into_iter()
        .map(|key| {
            <[u8; 48]>::try_from(key)
                .map(BlsPublicKey::new)
                .map_err(|_| json("a committee key is not 48 bytes"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SyncCommittee::new(
        keys.as_slice()
            .try_into()
            .map_err(|_| json("a sync committee has 512 keys"))?,
        BlsPublicKey::new(hex_fixed(value, "aggregate_pubkey")?),
    ))
}

/// Parse a beacon `/light_client/bootstrap` JSON response (`{version, data}`).
///
/// # Errors
///
/// Returns [`BuildError::Json`] for any shape or width mismatch.
pub fn bootstrap_from_beacon_json(
    response: &Value,
) -> Result<EthereumNativeLightClientBootstrapV1, BuildError> {
    let fork = fork_from_version(response)?;
    let data = field(response, "data")?;
    let electra = matches!(fork, EthereumFork::Electra | EthereumFork::Fulu);
    let branch = if electra {
        CurrentSyncCommitteeBranch::Electra(roots(data, "current_sync_committee_branch")?)
    } else {
        CurrentSyncCommitteeBranch::PreElectra(roots(data, "current_sync_committee_branch")?)
    };
    Ok(EthereumNativeLightClientBootstrapV1::from_native(
        &LightClientBootstrap {
            header: light_client_header(field(data, "header")?, fork)?,
            current_sync_committee: committee(field(data, "current_sync_committee")?)?,
            current_sync_committee_branch: branch,
        },
    ))
}

/// Parse one beacon light-client update or finality update JSON object (`{version, data}`).
///
/// The finalized header is decoded with the fork its slot has in `schedule`, which may be
/// earlier than the attested header's `version`.
///
/// # Errors
///
/// Returns [`BuildError::Json`] for any shape or width mismatch.
pub fn update_from_beacon_json(
    response: &Value,
    schedule: &ForkSchedule,
) -> Result<EthereumNativeLightClientUpdateV1, BuildError> {
    let fork = fork_from_version(response)?;
    let data = field(response, "data")?;
    let electra = matches!(fork, EthereumFork::Electra | EthereumFork::Fulu);
    let finalized = field(data, "finalized_header")?;
    let finalized_slot = decimal(field(finalized, "beacon")?, "slot")?;
    let finalized_fork = schedule
        .fork_at_slot(finalized_slot)
        .map_err(|_| json("the finalized slot precedes Altair"))?
        .0;
    let next_sync_committee = match data.get("next_sync_committee") {
        Some(next) => Some(NextSyncCommitteeProof {
            committee: committee(next)?,
            branch: if electra {
                NextSyncCommitteeBranch::Electra(roots(data, "next_sync_committee_branch")?)
            } else {
                NextSyncCommitteeBranch::PreElectra(roots(data, "next_sync_committee_branch")?)
            },
        }),
        None => None,
    };
    let aggregate = field(data, "sync_aggregate")?;
    Ok(EthereumNativeLightClientUpdateV1::from_native(
        &LightClientUpdate {
            attested_header: light_client_header(field(data, "attested_header")?, fork)?,
            next_sync_committee,
            finalized_header: light_client_header(finalized, finalized_fork)?,
            finality_branch: if electra {
                FinalityBranch::Electra(roots(data, "finality_branch")?)
            } else {
                FinalityBranch::PreElectra(roots(data, "finality_branch")?)
            },
            sync_aggregate: SyncAggregate::new(
                hex_fixed(aggregate, "sync_committee_bits")?,
                BlsSignature::new(hex_fixed(aggregate, "sync_committee_signature")?),
            ),
            signature_slot: decimal(data, "signature_slot")?,
        },
    ))
}

// ---------------------------------------------------------------------------------------------
// Execution RLP
// ---------------------------------------------------------------------------------------------

/// Re-encode `header` as its consensus RLP (London through Prague fields in order; optional
/// trailing fields are included when present).
#[must_use]
pub fn header_rlp(header: &EvmHeader) -> Vec<u8> {
    let mut fields = vec![
        rlp_encode_bytes(&header.parent_hash),
        rlp_encode_bytes(&header.ommers_hash),
        rlp_encode_bytes(&header.beneficiary),
        rlp_encode_bytes(&header.state_root),
        rlp_encode_bytes(&header.transactions_root),
        rlp_encode_bytes(&header.receipts_root),
        rlp_encode_bytes(&header.logs_bloom),
        rlp_encode_uint_bytes(header.difficulty.minimal_be_bytes()),
        rlp_encode_u64(header.number),
        rlp_encode_u64(header.gas_limit),
        rlp_encode_u64(header.gas_used),
        rlp_encode_u64(header.timestamp),
        rlp_encode_bytes(&header.extra_data),
        rlp_encode_bytes(&header.mix_hash),
        rlp_encode_bytes(&header.nonce),
    ];
    if let Some(base_fee) = header.base_fee_per_gas {
        fields.push(rlp_encode_uint_bytes(base_fee.minimal_be_bytes()));
    }
    if let Some(root) = header.withdrawals_root {
        fields.push(rlp_encode_bytes(&root));
    }
    if let Some(value) = header.blob_gas_used {
        fields.push(rlp_encode_u64(value));
    }
    if let Some(value) = header.excess_blob_gas {
        fields.push(rlp_encode_u64(value));
    }
    if let Some(root) = header.parent_beacon_block_root {
        fields.push(rlp_encode_bytes(&root));
    }
    if let Some(hash) = header.requests_hash {
        fields.push(rlp_encode_bytes(&hash));
    }
    rlp_encode_list(&fields)
}

/// Re-encode `receipt` in its receipts-trie form.
#[must_use]
pub fn receipt_rlp(receipt: &EvmReceipt) -> Vec<u8> {
    let parsed = EthereumReceiptV1 {
        tx_type: receipt.tx_type,
        success: receipt.status == Some(1),
        cumulative_gas_used: receipt.cumulative_gas_used,
        logs: receipt
            .logs
            .iter()
            .map(|log| EthereumLogV1 {
                address: log.address,
                topics: log.topics.clone(),
                data: log.data.clone(),
            })
            .collect(),
    };
    encode_receipt(&parsed, &receipt.logs_bloom)
}

// ---------------------------------------------------------------------------------------------
// Execution data shared with BSC
// ---------------------------------------------------------------------------------------------

/// Which source event a proof selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthereumEventV1 {
    /// One `SccpTransferToTaira` log at this index within the receipt.
    TransferToTaira {
        /// Log index within the receipt.
        log_index: u32,
    },
    /// A run of void logs within the receipt.
    Void {
        /// First log index within the receipt.
        first_log_index: u32,
        /// Number of logs.
        log_count: u32,
    },
}

impl EthereumEventV1 {
    /// The verifier's selector of this event.
    #[must_use]
    pub const fn selector(self) -> EthereumEventSelectorV1 {
        match self {
            Self::TransferToTaira { log_index } => {
                EthereumEventSelectorV1::TransferToTaira(EthereumLogRefV1 { log_index })
            }
            Self::Void {
                first_log_index,
                log_count,
            } => EthereumEventSelectorV1::Void(EthereumLogRangeV1 {
                first_log_index,
                log_count,
            }),
        }
    }
}

/// The block of an EVM event and the receipt proof of its transaction (Ethereum and BSC).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvmEventBlockV1 {
    /// Header RLP; its keccak is the block hash.
    pub header: Vec<u8>,
    /// Block number.
    pub number: u64,
    /// Index of the transaction and its receipt in the block.
    pub transaction_index: u32,
    /// Receipt MPT proof under the block's receipts root.
    pub receipt_proof: EthereumNativeMptProofV1,
}

/// Re-encode `block`'s header and check that it hashes to the block hash.
///
/// # Errors
///
/// [`BuildError::Inconsistent`] when the RLP does not hash to the reported hash.
pub fn checked_header_rlp(block: &EvmBlock) -> Result<Vec<u8>, BuildError> {
    let rlp = header_rlp(&block.header);
    if keccak256(&[&rlp]) != block.header.hash {
        return Err(BuildError::Inconsistent(format!(
            "the RLP of block {} does not hash to its hash",
            block.header.number
        )));
    }
    Ok(rlp)
}

/// Hash-checked header RLPs of the blocks `numbers` from `execution`, in request order, fetched
/// in JSON-RPC batches.
///
/// # Errors
///
/// Any endpoint failure, a block that is not served, or a header that does not hash to its hash.
pub fn evm_headers_at(execution: &EvmClient, numbers: &[u64]) -> Result<Vec<Vec<u8>>, BuildError> {
    let mut out = Vec::with_capacity(numbers.len());
    for chunk in numbers.chunks(MAX_JSON_RPC_BATCH) {
        for (number, block) in chunk.iter().zip(execution.blocks_by_number(chunk)?) {
            let block = block
                .ok_or_else(|| BuildError::Unavailable(format!("block {number} is not served")))?;
            if block.header.number != *number {
                return Err(BuildError::Inconsistent(format!(
                    "asked for block {number}, got {}",
                    block.header.number
                )));
            }
            out.push(checked_header_rlp(&block)?);
        }
    }
    Ok(out)
}

/// The block of transaction `tx_hash` and the receipt proof of the transaction, from
/// `execution`. The header must hash to the receipt's block hash and the block's receipts must
/// rebuild its receipts root.
///
/// # Errors
///
/// Any endpoint failure, a transaction that is not mined, or an inconsistent response.
pub fn evm_event_block(
    execution: &EvmClient,
    tx_hash: &[u8; 32],
    max_proof_bytes: usize,
) -> Result<EvmEventBlockV1, BuildError> {
    let receipt = execution
        .transaction_receipt(tx_hash)?
        .ok_or_else(|| BuildError::Unavailable("the transaction is not mined".into()))?;
    let number = receipt.block_number;
    let block = execution
        .block_by_number(BlockTag::Number(number))?
        .ok_or_else(|| BuildError::Unavailable(format!("block {number} is not served")))?;
    if block.header.hash != receipt.block_hash {
        return Err(BuildError::Inconsistent(format!(
            "block {number} is not the receipt's block; retry after the reorganization settles"
        )));
    }
    let header = checked_header_rlp(&block)?;
    let receipt_proof =
        execution.block_receipt_proof(&block, receipt.transaction_index, max_proof_bytes)?;
    Ok(EvmEventBlockV1 {
        header,
        number,
        transaction_index: u32::try_from(receipt.transaction_index)
            .map_err(|_| BuildError::Inconsistent("transaction index overflows".into()))?,
        receipt_proof,
    })
}

// ---------------------------------------------------------------------------------------------
// Source
// ---------------------------------------------------------------------------------------------

/// Ethereum data an evidence builder reads. [`EthereumBuilder`] serves it from public RPC.
pub trait EthereumSource {
    /// The latest finality update.
    ///
    /// # Errors
    ///
    /// Any endpoint or JSON failure.
    fn finality_update(&self) -> Result<EthereumNativeLightClientUpdateV1, BuildError>;

    /// The best committee updates of at most `count` sync-committee periods from
    /// `start_period`, oldest first.
    ///
    /// # Errors
    ///
    /// Any endpoint or JSON failure.
    fn committee_updates(
        &self,
        start_period: u64,
        count: u64,
    ) -> Result<Vec<EthereumNativeLightClientUpdateV1>, BuildError>;

    /// The block of transaction `tx_hash` and the receipt proof of the transaction.
    ///
    /// # Errors
    ///
    /// Any endpoint failure, a transaction that is not mined, or an inconsistent response.
    fn event_block(
        &self,
        tx_hash: &[u8; 32],
        max_proof_bytes: usize,
    ) -> Result<EvmEventBlockV1, BuildError>;

    /// Hash-checked execution header RLPs of blocks `first..=last`, ascending (empty when
    /// `first > last`).
    ///
    /// # Errors
    ///
    /// Any endpoint failure or a block that is not served.
    fn headers(&self, first: u64, last: u64) -> Result<Vec<Vec<u8>>, BuildError>;

    /// The EIP-2935 account and storage proof, under the state of block `anchor`, of the slot
    /// holding the hash `event_hash` of block `event`.
    ///
    /// # Errors
    ///
    /// Any endpoint failure (the state of `anchor` is not served), or a slot that does not hold
    /// `event_hash`.
    fn history_proof(
        &self,
        anchor: u64,
        event: u64,
        event_hash: [u8; 32],
    ) -> Result<EthereumHistoryProofV1, BuildError>;
}

// ---------------------------------------------------------------------------------------------
// Advance
// ---------------------------------------------------------------------------------------------

/// Build an advance from the stored committee period `stored_period`: the committee update of
/// every period from it to the latest finality's period, oldest first, then the finality update,
/// stepped to `budget`. A light client further behind than `budget` holds receives the oldest
/// updates that fit; each teaches the committee the next one is signed by, so the following
/// advances continue from the new head.
///
/// # Errors
///
/// Any source failure, or not even one update fitting `budget`.
pub fn build_advance<S: EthereumSource + ?Sized>(
    source: &S,
    stored_period: u64,
    budget: AdvanceBudgetV1,
) -> Result<SccpLcAdvanceBytesV1, BuildError> {
    let finality = source.finality_update()?;
    let behind = (finality.signature_slot / SLOTS_PER_PERIOD).saturating_sub(stored_period);
    let wanted = behind.min(u64::try_from(budget.max_items).unwrap_or(u64::MAX));
    let mut updates = if wanted == 0 {
        Vec::new()
    } else {
        source.committee_updates(stored_period, wanted)?
    };
    if u64::try_from(updates.len()).ok() == Some(behind) {
        updates.push(finality);
    }
    fit_advance(updates, budget, |updates| {
        SccpLcAdvanceV1::Ethereum(EthereumLcAdvanceV1 { updates })
    })
}

// ---------------------------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------------------------

/// An ancestry kind from an anchor `E` to the event block `B` (§4.13.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EthereumAncestryKindV1 {
    /// `B = E`.
    SameBlock,
    /// Parent-linked headers `B + 1 ..= E`.
    HeaderChain,
    /// EIP-2935 proof under the state of `E`.
    HistoryContract,
}

/// The anchor block `E` of a proof, as ancestry selection needs it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EthereumAnchorPointV1 {
    /// Execution block number.
    pub number: u64,
    /// Execution block hash.
    pub hash: [u8; 32],
    /// Execution timestamp (ms).
    pub time_ms: u64,
    /// Whether the anchor carries a state root (a `HistoryContract` proof opens it).
    pub has_state_root: bool,
}

/// Ancestry kinds to try, in order, from `anchor` to the event block `event` under `profile`,
/// with at most `max_headers` headers in a `HeaderChain`: `SameBlock` when `E = B`; a
/// `HeaderChain` first up to [`PREFERRED_HEADER_CHAIN`] headers; a `HistoryContract` when
/// `1 ≤ E − B ≤ history_serve_window` and `E` is after the Prague activation; a longer
/// `HeaderChain` last. Empty when the anchor is below the event or too far above it.
#[must_use]
pub fn ancestry_candidates(
    profile: &EthereumChainProfileV1,
    event: u64,
    anchor: &EthereumAnchorPointV1,
    max_headers: u64,
) -> Vec<EthereumAncestryKindV1> {
    let Some(distance) = anchor.number.checked_sub(event) else {
        return Vec::new();
    };
    if distance == 0 {
        return vec![EthereumAncestryKindV1::SameBlock];
    }
    let history = anchor.has_state_root
        && distance <= profile.history_serve_window
        && profile
            .history_contract_active_from_ms()
            .is_some_and(|active| anchor.time_ms >= active);
    let chain = distance <= max_headers;
    let mut candidates = Vec::with_capacity(2);
    if chain && distance <= PREFERRED_HEADER_CHAIN {
        candidates.push(EthereumAncestryKindV1::HeaderChain);
    }
    if history {
        candidates.push(EthereumAncestryKindV1::HistoryContract);
    }
    if chain && distance > PREFERRED_HEADER_CHAIN {
        candidates.push(EthereumAncestryKindV1::HeaderChain);
    }
    candidates
}

/// Check that `headers` continue the header `parent` one block at a time and end at the block
/// `end_hash`.
fn check_links(parent: &[u8], headers: &[Vec<u8>], end_hash: [u8; 32]) -> Result<(), BuildError> {
    let decode = |rlp: &[u8]| {
        decode_execution_header(rlp)
            .map_err(|error| BuildError::Inconsistent(format!("execution header: {error}")))
    };
    let mut previous = decode(parent)?;
    for header in headers {
        let next = decode(header)?;
        if next.parent_hash != previous.hash || previous.number.checked_add(1) != Some(next.number)
        {
            return Err(BuildError::Inconsistent(format!(
                "block {} does not follow block {}",
                next.number, previous.number
            )));
        }
        previous = next;
    }
    if previous.hash != end_hash {
        return Err(BuildError::Inconsistent(format!(
            "the headers do not end at the anchor block {}",
            previous.number
        )));
    }
    Ok(())
}

fn build_ancestry<S: EthereumSource + ?Sized>(
    source: &S,
    kind: EthereumAncestryKindV1,
    block: &EvmEventBlockV1,
    anchor: &EthereumAnchorPointV1,
) -> Result<EthereumAncestryV1, BuildError> {
    let event_hash = keccak256(&[&block.header]);
    match kind {
        EthereumAncestryKindV1::SameBlock => {
            if anchor.hash != event_hash {
                return Err(BuildError::Inconsistent(format!(
                    "the anchor at block {} is another block than the event's",
                    anchor.number
                )));
            }
            Ok(EthereumAncestryV1::SameBlock)
        }
        EthereumAncestryKindV1::HeaderChain => {
            let headers = source.headers(block.number + 1, anchor.number)?;
            check_links(&block.header, &headers, anchor.hash)?;
            Ok(EthereumAncestryV1::HeaderChain(EthereumHeaderSegmentV1 {
                headers,
            }))
        }
        EthereumAncestryKindV1::HistoryContract => Ok(EthereumAncestryV1::HistoryContract(
            source.history_proof(anchor.number, block.number, event_hash)?,
        )),
    }
}

fn proof_bytes(
    anchor: EthereumProofAnchorV1,
    ancestry: EthereumAncestryV1,
    block: &EvmEventBlockV1,
    event: EthereumEventSelectorV1,
) -> Result<SccpSourceProofBytesV1, BuildError> {
    SccpSourceProofV1::Ethereum(EthereumSourceProofV1 {
        anchor,
        ancestry,
        event_header: block.header.clone(),
        transaction_index: block.transaction_index,
        receipt_proof: block.receipt_proof.clone(),
        event,
    })
    .to_bytes()
    .map_err(|error| BuildError::Inconsistent(format!("proof frame: {error}")))
}

/// The finalized execution block of `update`.
///
/// # Errors
///
/// [`BuildError::Inconsistent`] when the update authenticates no execution block.
pub fn finalized_anchor(
    update: &EthereumNativeLightClientUpdateV1,
) -> Result<EthereumAnchorPointV1, BuildError> {
    let block = update
        .finalized_header
        .to_native()
        .ok()
        .and_then(|header| header.authenticated_execution_block())
        .ok_or_else(|| {
            BuildError::Inconsistent("the finality update has no execution block".into())
        })?;
    Ok(EthereumAnchorPointV1 {
        number: block.block_number,
        hash: block.block_hash,
        time_ms: block.timestamp.saturating_mul(1_000),
        has_state_root: true,
    })
}

fn header_bound(param: u32, hard: usize) -> u64 {
    u64::from(param).min(u64::try_from(hard).unwrap_or(u64::MAX))
}

/// Build the evidence of `event` in transaction `tx_hash` against the light client `taira`
/// stores (see the module documentation for the anchor order).
///
/// # Errors
///
/// Any source failure, a block that is not finalized yet, or a block that neither the latest
/// finality nor any retained checkpoint (with at most
/// [`super::MAX_BACKFILL_SEGMENTS`] backfills) reaches.
pub fn build_evidence<S: EthereumSource + ?Sized>(
    profile: &EthereumChainProfileV1,
    source: &S,
    tx_hash: &[u8; 32],
    event: EthereumEventV1,
    taira: &dyn TairaLightClientView,
) -> Result<SourceEvidenceV1, BuildError> {
    let light_client = taira.light_client()?;
    let max_headers = header_bound(
        light_client.params.max_ancestry_headers,
        ETHEREUM_MAX_ANCESTRY_HEADERS,
    );
    let max_backfill = header_bound(
        light_client.params.max_backfill_headers,
        ETHEREUM_MAX_BACKFILL_HEADERS,
    );
    let block = source.event_block(tx_hash, light_client.params.max_proof_bytes as usize)?;
    let selector = event.selector();
    let mut failures = Vec::new();
    // 1. The latest finality update.
    let finality = source.finality_update()?;
    let finalized = finalized_anchor(&finality)?;
    if finalized.number < block.number {
        return Err(BuildError::Unavailable(format!(
            "block {} is not finalized yet (finalized: {})",
            block.number, finalized.number
        )));
    }
    let finality_period = finality.signature_slot / SLOTS_PER_PERIOD;
    if finality_period > light_client.head.latest_set_id {
        failures.push(format!(
            "the light client does not store the committee of period {finality_period} yet; \
             advance it first"
        ));
    } else {
        for kind in ancestry_candidates(profile, block.number, &finalized, max_headers) {
            match build_ancestry(source, kind, &block, &finalized) {
                Ok(ancestry) => {
                    return Ok(SourceEvidenceV1 {
                        backfills: Vec::new(),
                        proof: proof_bytes(
                            EthereumProofAnchorV1::FinalityUpdate(Box::new(finality)),
                            ancestry,
                            &block,
                            selector,
                        )?,
                    });
                }
                Err(error) => failures.push(format!("{kind:?} from the finality update: {error}")),
            }
        }
        if finalized.number - block.number > profile.history_serve_window {
            failures.push(format!(
                "block {} is more than {} blocks below the finalized block {}",
                block.number, profile.history_serve_window, finalized.number
            ));
        }
    }
    // 2. The nearest retained checkpoint at or above the event block.
    let Some(checkpoint) = taira.checkpoint_covering(block.number)? else {
        failures.push(format!(
            "Taira retains no checkpoint at or above block {}",
            block.number
        ));
        return Err(BuildError::Unavailable(failures.join("; ")));
    };
    let stored = EthereumAnchorPointV1 {
        number: checkpoint.data.source_height,
        hash: checkpoint.data.block_hash,
        time_ms: checkpoint.data.source_time_ms,
        has_state_root: checkpoint.data.state_root.is_some(),
    };
    let anchor_at = |source_height| {
        EthereumProofAnchorV1::StoredCheckpoint(EthereumStoredCheckpointRefV1 { source_height })
    };
    for kind in ancestry_candidates(profile, block.number, &stored, max_headers) {
        match build_ancestry(source, kind, &block, &stored) {
            Ok(ancestry) => {
                return Ok(SourceEvidenceV1 {
                    backfills: Vec::new(),
                    proof: proof_bytes(anchor_at(stored.number), ancestry, &block, selector)?,
                });
            }
            Err(error) => failures.push(format!(
                "{kind:?} from checkpoint {}: {error}",
                stored.number
            )),
        }
    }
    // 3. Backfill segments from the checkpoint down to the event.
    let plan = plan_backfill(block.number, stored.number, max_headers, max_backfill)?;
    if plan.segments.is_empty() {
        return Err(BuildError::Unavailable(failures.join("; ")));
    }
    let mut chain = vec![block.header.clone()];
    chain.extend(source.headers(block.number + 1, stored.number)?);
    check_links(&block.header, &chain[1..], stored.hash)?;
    let index = |number: u64| usize::try_from(number - block.number).unwrap_or(usize::MAX);
    let backfills = plan
        .segments
        .iter()
        .map(|(first, last)| {
            backfill_bytes(SccpLcSegmentV1::Ethereum(EthereumHeaderSegmentV1 {
                headers: chain[index(*first)..=index(*last)].to_vec(),
            }))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let ancestry = if plan.anchor == block.number {
        EthereumAncestryV1::SameBlock
    } else {
        EthereumAncestryV1::HeaderChain(EthereumHeaderSegmentV1 {
            headers: chain[1..=index(plan.anchor)].to_vec(),
        })
    };
    Ok(SourceEvidenceV1 {
        backfills,
        proof: proof_bytes(anchor_at(plan.anchor), ancestry, &block, selector)?,
    })
}

// ---------------------------------------------------------------------------------------------
// Public-RPC builder
// ---------------------------------------------------------------------------------------------

/// Ethereum evidence builder over one beacon endpoint and one execution endpoint.
pub struct EthereumBuilder {
    profile: EthereumChainProfileV1,
    beacon: BeaconClient,
    execution: EvmClient,
}

impl EthereumBuilder {
    /// A builder over `beacon` and `execution`.
    #[must_use]
    pub fn new(
        profile: EthereumChainProfileV1,
        beacon: BeaconClient,
        execution: EvmClient,
    ) -> Self {
        Self {
            profile,
            beacon,
            execution,
        }
    }

    /// Select the profile resolved from the current committed Taira cut before building.
    pub fn set_profile(&mut self, profile: EthereumChainProfileV1) {
        self.profile = profile;
    }

    /// Moves the beacon and the execution client to their next endpoints, for a caller whose
    /// build failed on the data it was served or whose verification rejected what was built.
    pub fn rotate_endpoints(&self) {
        // Enumerate execution endpoints within each beacon endpoint, including mixed
        // pairs. Lockstep rotation would miss healthy pairs when list lengths share factors.
        self.execution.transport().rotate_preferred();
        if self.execution.transport().endpoints().preferred() == 0 {
            self.beacon.transport().rotate_preferred();
        }
    }

    fn schedule(&self) -> Result<ForkSchedule, BuildError> {
        self.profile
            .schedule()
            .map_err(|error| BuildError::Inconsistent(format!("fork schedule: {error:?}")))
    }

    /// Build the `InitializeLightClient` bootstrap of the finalized beacon block `block_root`,
    /// so every Parliament member can rebuild the exact bootstrap a proposal names.
    ///
    /// # Errors
    ///
    /// Any endpoint or JSON failure.
    pub fn bootstrap_at(&self, block_root: &[u8; 32]) -> Result<SccpLcBootstrapV1, BuildError> {
        let response = self.beacon.transport().get_json(&format!(
            "/eth/v1/beacon/light_client/bootstrap/{}",
            format_data(block_root)
        ))?;
        SccpLcBootstrapDataV1::Ethereum(bootstrap_from_beacon_json(&response)?)
            .to_bootstrap()
            .map_err(|error| BuildError::Inconsistent(format!("bootstrap frame: {error}")))
    }
}

impl EthereumSource for EthereumBuilder {
    fn finality_update(&self) -> Result<EthereumNativeLightClientUpdateV1, BuildError> {
        let response = self
            .beacon
            .transport()
            .get_json("/eth/v1/beacon/light_client/finality_update")?;
        update_from_beacon_json(&response, &self.schedule()?)
    }

    fn committee_updates(
        &self,
        start_period: u64,
        count: u64,
    ) -> Result<Vec<EthereumNativeLightClientUpdateV1>, BuildError> {
        let schedule = self.schedule()?;
        let response = self.beacon.transport().get_json(&format!(
            "/eth/v1/beacon/light_client/updates?start_period={start_period}&count={count}"
        ))?;
        response
            .as_array()
            .ok_or_else(|| json("light-client updates are not an array"))?
            .iter()
            .take(usize::try_from(count).unwrap_or(usize::MAX))
            .map(|item| update_from_beacon_json(item, &schedule))
            .collect()
    }

    fn event_block(
        &self,
        tx_hash: &[u8; 32],
        max_proof_bytes: usize,
    ) -> Result<EvmEventBlockV1, BuildError> {
        evm_event_block(&self.execution, tx_hash, max_proof_bytes)
    }

    fn headers(&self, first: u64, last: u64) -> Result<Vec<Vec<u8>>, BuildError> {
        let numbers: Vec<u64> = (first..=last).collect();
        evm_headers_at(&self.execution, &numbers)
    }

    fn history_proof(
        &self,
        anchor: u64,
        event: u64,
        event_hash: [u8; 32],
    ) -> Result<EthereumHistoryProofV1, BuildError> {
        let profile = &self.profile;
        let window = profile.history_serve_window;
        if window == 0 {
            return Err(BuildError::Unavailable(
                "the compiled profile has no history window".into(),
            ));
        }
        let proof = self.execution.proof(
            &profile.history_storage_address,
            &[word_u64(event % window)],
            BlockId::from(anchor),
        )?;
        let slot = proof
            .storage_proof
            .first()
            .ok_or_else(|| BuildError::Inconsistent("eth_getProof returned no slot".into()))?;
        if slot.value.to_be_bytes() != event_hash {
            return Err(BuildError::Inconsistent(format!(
                "the history contract at block {anchor} does not hold the hash of block {event}"
            )));
        }
        Ok(EthereumHistoryProofV1 {
            account_proof: EthereumNativeMptProofV1 {
                nodes: proof.account_proof,
            },
            storage_proof: EthereumNativeMptProofV1 {
                nodes: slot.proof.clone(),
            },
        })
    }
}

impl SourceChainBuilder for EthereumBuilder {
    fn source_attempts(&self) -> usize {
        self.beacon
            .transport()
            .endpoints()
            .len()
            .saturating_mul(self.execution.transport().endpoints().len())
    }

    fn rotate_endpoints(&self) {
        EthereumBuilder::rotate_endpoints(self);
    }

    fn network(&self) -> SccpNetworkV1 {
        SccpNetworkV1::EthereumMainnet
    }

    fn bootstrap(&self) -> Result<SccpLcBootstrapV1, BuildError> {
        let root = self.beacon.finalized_header()?.root;
        self.bootstrap_at(&root)
    }

    fn advance(
        &self,
        latest_set_id: u64,
        budget: AdvanceBudgetV1,
    ) -> Result<SccpLcAdvanceBytesV1, BuildError> {
        build_advance(self, latest_set_id, budget)
    }

    fn evidence(
        &self,
        event: &SourceEventRefV1,
        light_client: &dyn TairaLightClientView,
        _now_ms: u64,
    ) -> Result<SourceEvidenceV1, BuildError> {
        match event {
            SourceEventRefV1::Evm { tx_hash, event } => {
                build_evidence(&self.profile, self, tx_hash, *event, light_client)
            }
            SourceEventRefV1::Ton { .. } => {
                Err(BuildError::Inconsistent("not an Ethereum event".into()))
            }
        }
    }
}

#[cfg(test)]
mod evidence_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotating_moves_both_clients_to_their_next_endpoints() {
        use crate::builders::test_support::two_endpoint_transport;

        let mut builder = EthereumBuilder::new(
            iroha_sccp::light_client::profile::SccpChainProfilesV1::latest().ethereum,
            BeaconClient::new(two_endpoint_transport()),
            EvmClient::new(two_endpoint_transport()),
        );
        let preferred = |builder: &EthereumBuilder| {
            (
                builder.beacon.transport().endpoints().preferred(),
                builder.execution.transport().endpoints().preferred(),
            )
        };
        let mut selected = builder.profile;
        selected.supported_until_epoch = 1;
        builder.set_profile(selected);
        assert_eq!(builder.profile, selected);
        assert_eq!(preferred(&builder), (0, 0));
        builder.rotate_endpoints();
        assert_eq!(preferred(&builder), (0, 1));
        builder.rotate_endpoints();
        assert_eq!(preferred(&builder), (1, 0));
        builder.rotate_endpoints();
        assert_eq!(preferred(&builder), (1, 1));
        builder.rotate_endpoints();
        assert_eq!(preferred(&builder), (0, 0));
        assert_eq!(builder.source_attempts(), 4);
    }

    #[test]
    fn json_helpers_reject_malformed_fields() {
        let value = norito::json!({"a": "0x0102", "b": "7", "c": 5, "d": ["0x01"]});
        assert_eq!(
            hex_bytes(text(&value, "a").expect("a")).expect("hex"),
            vec![1, 2]
        );
        assert_eq!(decimal(&value, "b").expect("decimal"), 7);
        assert!(decimal(&value, "c").is_err());
        assert!(text(&value, "missing").is_err());
        assert!(hex_fixed::<2>(&value, "a").is_ok());
        assert!(hex_fixed::<3>(&value, "a").is_err());
        assert_eq!(hex_list(&value, "d").expect("list"), vec![vec![1]]);
        assert!(fork_from_version(&norito::json!({"version": "altair"})).is_err());
        assert_eq!(
            fork_from_version(&norito::json!({"version": "electra"})).expect("fork"),
            EthereumFork::Electra
        );
    }

    #[test]
    fn base_fees_are_little_endian_words() {
        let word = le_u256_from_decimal("258").expect("fee");
        assert_eq!(&word[..2], &[2, 1]);
        assert!(le_u256_from_decimal("-1").is_err());
    }

    #[test]
    fn events_map_to_verifier_selectors() {
        assert_eq!(
            EthereumEventV1::TransferToTaira { log_index: 3 }.selector(),
            EthereumEventSelectorV1::TransferToTaira(EthereumLogRefV1 { log_index: 3 })
        );
        assert_eq!(
            EthereumEventV1::Void {
                first_log_index: 1,
                log_count: 4
            }
            .selector(),
            EthereumEventSelectorV1::Void(EthereumLogRangeV1 {
                first_log_index: 1,
                log_count: 4
            })
        );
    }

    fn anchor(number: u64, time_ms: u64, has_state_root: bool) -> EthereumAnchorPointV1 {
        EthereumAnchorPointV1 {
            number,
            hash: [1; 32],
            time_ms,
            has_state_root,
        }
    }

    #[test]
    fn ancestry_candidates_follow_the_windows() {
        use EthereumAncestryKindV1::{HeaderChain, HistoryContract, SameBlock};
        let profile = iroha_sccp::light_client::profile::SccpChainProfilesV1::latest().ethereum;
        let prague = profile
            .history_contract_active_from_ms()
            .expect("activation");
        let at = |distance: u64| anchor(100_000 + distance, prague, true);
        let candidates = |distance| ancestry_candidates(&profile, 100_000, &at(distance), 256);
        assert_eq!(candidates(0), vec![SameBlock]);
        assert_eq!(candidates(1), vec![HeaderChain, HistoryContract]);
        assert_eq!(candidates(8), vec![HeaderChain, HistoryContract]);
        assert_eq!(candidates(9), vec![HistoryContract, HeaderChain]);
        assert_eq!(candidates(256), vec![HistoryContract, HeaderChain]);
        assert_eq!(candidates(257), vec![HistoryContract]);
        assert_eq!(candidates(8_191), vec![HistoryContract]);
        assert!(candidates(8_192).is_empty());
        // Without a state root, or before Prague, only headers remain.
        let stateless = anchor(100_256, prague, false);
        assert_eq!(
            ancestry_candidates(&profile, 100_000, &stateless, 256),
            vec![HeaderChain]
        );
        let early = anchor(100_256, prague - 1, true);
        assert_eq!(
            ancestry_candidates(&profile, 100_000, &early, 256),
            vec![HeaderChain]
        );
        // A smaller parameter bound narrows the header chain; an anchor below the event has
        // none.
        assert_eq!(
            ancestry_candidates(&profile, 100_000, &anchor(100_100, prague, false), 64),
            Vec::<EthereumAncestryKindV1>::new()
        );
        assert!(
            ancestry_candidates(&profile, 100_000, &anchor(99_999, prague, true), 256).is_empty()
        );
    }
}
