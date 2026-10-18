//! Ethereum wire formats and execution-layer primitives for the SCCP v1 light client
//! (`specs/sccp.md` §4.13.3).
//!
//! This module holds the Norito wire representations of the Ethereum light-client objects that
//! travel inside SCCP frames (headers, sync committees, bootstraps and updates), their strict
//! conversions to the [`crate::ethereum_native`] SSZ types, and the execution-layer primitives the
//! verifier opens under an authenticated block: canonical RLP, Merkle-Patricia inclusion proofs,
//! execution headers read by field index, state accounts, storage words and typed receipts. A
//! deterministic Merkle-Patricia builder produces roots and proofs for receipt, account and
//! storage tries, so wallets, the keeper and tests build exactly the proofs the verifier opens.
//!
//! Nothing here consults stored light-client state; [`crate::light_client::ethereum`] composes
//! these checks.
use super::H256;
use crate::ethereum_native::{
    BeaconBlockHeader, BlsPublicKey, BlsSignature, CapellaExecutionPayloadHeader,
    CurrentSyncCommitteeBranch, DenebExecutionPayloadHeader, EthereumFork,
    EthereumLightClientError, ExtraData, FinalityBranch, LightClientBootstrap, LightClientHeader,
    LightClientUpdate, NextSyncCommitteeBranch, NextSyncCommitteeProof, Root,
    SYNC_COMMITTEE_BITS_BYTES, SYNC_COMMITTEE_SIZE, SyncAggregate, SyncCommittee,
};
use alloc::vec::Vec;
use core::fmt;
use tiny_keccak::{Hasher as _, Keccak};
/// Maximum explicit nodes in one Merkle-Patricia proof.
pub const MAX_MPT_PROOF_NODES: usize = 64;
/// Maximum bytes of one Merkle-Patricia proof node.
pub const MAX_MPT_NODE_BYTES: usize = 1024 * 1024;
/// Maximum aggregate bytes of one Merkle-Patricia proof.
pub const MAX_MPT_PROOF_BYTES: usize = 4 * 1024 * 1024;
/// Maximum logs in one receipt.
pub const MAX_RECEIPT_LOGS: usize = 1_024;
/// Maximum topics in one log.
pub const MAX_LOG_TOPICS: usize = 4;
/// Maximum bytes of one RLP execution header.
pub const MAX_EXECUTION_HEADER_BYTES: usize = 4_096;
/// Minimum field count of a post-London execution header.
pub const MIN_EXECUTION_HEADER_FIELDS: usize = 16;
/// Maximum field count accepted in an execution header (fields are read by index).
pub const MAX_EXECUTION_HEADER_FIELDS: usize = 32;
/// Keccak-256 of the empty Merkle-Patricia trie (`keccak256(rlp(""))`).
pub const EMPTY_TRIE_ROOT: H256 = [
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
];
/// Closed Ethereum fork tag used by the SCCP wire DTOs.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
)]
#[norito(tag = "fork", content = "detail", rename_all = "snake_case")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_sccp::ethereum_source::EthereumNativeForkV1")]
pub enum EthereumNativeForkV1 {
    /// Altair.
    Altair,
    /// Bellatrix.
    Bellatrix,
    /// Capella.
    Capella,
    /// Deneb.
    Deneb,
    /// Electra.
    Electra,
    /// Fulu.
    Fulu,
}
impl From<EthereumNativeForkV1> for EthereumFork {
    fn from(value: EthereumNativeForkV1) -> Self {
        match value {
            EthereumNativeForkV1::Altair => Self::Altair,
            EthereumNativeForkV1::Bellatrix => Self::Bellatrix,
            EthereumNativeForkV1::Capella => Self::Capella,
            EthereumNativeForkV1::Deneb => Self::Deneb,
            EthereumNativeForkV1::Electra => Self::Electra,
            EthereumNativeForkV1::Fulu => Self::Fulu,
        }
    }
}
impl From<EthereumFork> for EthereumNativeForkV1 {
    fn from(value: EthereumFork) -> Self {
        match value {
            EthereumFork::Altair => Self::Altair,
            EthereumFork::Bellatrix => Self::Bellatrix,
            EthereumFork::Capella => Self::Capella,
            EthereumFork::Deneb => Self::Deneb,
            EthereumFork::Electra => Self::Electra,
            EthereumFork::Fulu => Self::Fulu,
        }
    }
}
/// Wire representation of the official SSZ `BeaconBlockHeader`.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_sccp::ethereum_source::EthereumNativeBeaconHeaderV1")]
pub struct EthereumNativeBeaconHeaderV1 {
    /// Beacon slot.
    #[norito(with = "crate::json_utils::u64_string")]
    pub slot: u64,
    /// Proposer validator index.
    #[norito(with = "crate::json_utils::u64_string")]
    pub proposer_index: u64,
    /// Parent beacon block root.
    #[norito(with = "crate::json_utils::hex32")]
    pub parent_root: H256,
    /// Beacon state root.
    #[norito(with = "crate::json_utils::hex32")]
    pub state_root: H256,
    /// Beacon block body root.
    #[norito(with = "crate::json_utils::hex32")]
    pub body_root: H256,
}
impl EthereumNativeBeaconHeaderV1 {
    /// Convert to the SSZ type.
    pub const fn to_native(self) -> BeaconBlockHeader {
        BeaconBlockHeader {
            slot: self.slot,
            proposer_index: self.proposer_index,
            parent_root: self.parent_root,
            state_root: self.state_root,
            body_root: self.body_root,
        }
    }
    /// Convert from the SSZ type.
    pub const fn from_native(header: &BeaconBlockHeader) -> Self {
        Self {
            slot: header.slot,
            proposer_index: header.proposer_index,
            parent_root: header.parent_root,
            state_root: header.state_root,
            body_root: header.body_root,
        }
    }
}
/// Wire representation of the Capella execution payload header.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_sccp::ethereum_source::EthereumNativeCapellaExecutionHeaderV1")]
pub struct EthereumNativeCapellaExecutionHeaderV1 {
    /// Parent execution block hash.
    #[norito(with = "crate::json_utils::hex32")]
    pub parent_hash: H256,
    /// Fee recipient.
    #[norito(with = "crate::json_utils::bytes_hex")]
    pub fee_recipient: Vec<u8>,
    /// State trie root.
    #[norito(with = "crate::json_utils::hex32")]
    pub state_root: H256,
    /// Receipts trie root.
    #[norito(with = "crate::json_utils::hex32")]
    pub receipts_root: H256,
    /// 256-byte execution logs bloom.
    #[norito(with = "crate::json_utils::bytes_hex")]
    pub logs_bloom: Vec<u8>,
    /// Previous RANDAO mix.
    #[norito(with = "crate::json_utils::hex32")]
    pub prev_randao: H256,
    /// Execution block number.
    #[norito(with = "crate::json_utils::u64_string")]
    pub block_number: u64,
    /// Gas limit.
    #[norito(with = "crate::json_utils::u64_string")]
    pub gas_limit: u64,
    /// Gas used.
    #[norito(with = "crate::json_utils::u64_string")]
    pub gas_used: u64,
    /// Execution timestamp.
    #[norito(with = "crate::json_utils::u64_string")]
    pub timestamp: u64,
    /// SSZ `ByteList[32]` extra data.
    #[norito(with = "crate::json_utils::bytes_hex")]
    pub extra_data: Vec<u8>,
    /// Little-endian SSZ `uint256` base fee.
    #[norito(with = "crate::json_utils::hex32")]
    pub base_fee_per_gas: H256,
    /// Execution block hash.
    #[norito(with = "crate::json_utils::hex32")]
    pub block_hash: H256,
    /// Transactions list root.
    #[norito(with = "crate::json_utils::hex32")]
    pub transactions_root: H256,
    /// Withdrawals list root.
    #[norito(with = "crate::json_utils::hex32")]
    pub withdrawals_root: H256,
}
impl EthereumNativeCapellaExecutionHeaderV1 {
    /// Convert to the SSZ type, checking fixed widths and the extra-data bound.
    ///
    /// # Errors
    ///
    /// Returns [`EthereumExecutionError::MalformedWire`] or the extra-data bound error.
    pub fn to_native(&self) -> Result<CapellaExecutionPayloadHeader, EthereumExecutionError> {
        let fee_recipient = <[u8; 20]>::try_from(self.fee_recipient.as_slice())
            .map_err(|_| EthereumExecutionError::MalformedWire("fee recipient"))?;
        let logs_bloom = <[u8; 256]>::try_from(self.logs_bloom.as_slice())
            .map_err(|_| EthereumExecutionError::MalformedWire("logs bloom"))?;
        Ok(CapellaExecutionPayloadHeader {
            parent_hash: self.parent_hash,
            fee_recipient,
            state_root: self.state_root,
            receipts_root: self.receipts_root,
            logs_bloom,
            prev_randao: self.prev_randao,
            block_number: self.block_number,
            gas_limit: self.gas_limit,
            gas_used: self.gas_used,
            timestamp: self.timestamp,
            extra_data: ExtraData::new(&self.extra_data)?,
            base_fee_per_gas: self.base_fee_per_gas,
            block_hash: self.block_hash,
            transactions_root: self.transactions_root,
            withdrawals_root: self.withdrawals_root,
        })
    }
    /// Convert from the SSZ type.
    pub fn from_native(header: &CapellaExecutionPayloadHeader) -> Self {
        Self {
            parent_hash: header.parent_hash,
            fee_recipient: header.fee_recipient.to_vec(),
            state_root: header.state_root,
            receipts_root: header.receipts_root,
            logs_bloom: header.logs_bloom.to_vec(),
            prev_randao: header.prev_randao,
            block_number: header.block_number,
            gas_limit: header.gas_limit,
            gas_used: header.gas_used,
            timestamp: header.timestamp,
            extra_data: header.extra_data.as_slice().to_vec(),
            base_fee_per_gas: header.base_fee_per_gas,
            block_hash: header.block_hash,
            transactions_root: header.transactions_root,
            withdrawals_root: header.withdrawals_root,
        }
    }
}
/// Wire representation of the Deneb execution payload header used through Fulu.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_sccp::ethereum_source::EthereumNativeDenebExecutionHeaderV1")]
pub struct EthereumNativeDenebExecutionHeaderV1 {
    /// Capella-compatible header fields.
    pub base: EthereumNativeCapellaExecutionHeaderV1,
    /// Blob gas used.
    #[norito(with = "crate::json_utils::u64_string")]
    pub blob_gas_used: u64,
    /// Excess blob gas.
    #[norito(with = "crate::json_utils::u64_string")]
    pub excess_blob_gas: u64,
}
impl EthereumNativeDenebExecutionHeaderV1 {
    /// Convert to the SSZ type.
    ///
    /// # Errors
    ///
    /// See [`EthereumNativeCapellaExecutionHeaderV1::to_native`].
    pub fn to_native(&self) -> Result<DenebExecutionPayloadHeader, EthereumExecutionError> {
        Ok(DenebExecutionPayloadHeader {
            capella: self.base.to_native()?,
            blob_gas_used: self.blob_gas_used,
            excess_blob_gas: self.excess_blob_gas,
        })
    }
    /// Convert from the SSZ type.
    pub fn from_native(header: &DenebExecutionPayloadHeader) -> Self {
        Self {
            base: EthereumNativeCapellaExecutionHeaderV1::from_native(&header.capella),
            blob_gas_used: header.blob_gas_used,
            excess_blob_gas: header.excess_blob_gas,
        }
    }
}
/// Fork-closed execution payload header carried by a light-client header.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
)]
#[norito(tag = "layout", content = "header", rename_all = "snake_case")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_sccp::ethereum_source::EthereumNativeExecutionHeaderV1")]
pub enum EthereumNativeExecutionHeaderV1 {
    /// Capella layout.
    Capella(EthereumNativeCapellaExecutionHeaderV1),
    /// Deneb layout, inherited unchanged by Electra and Fulu.
    Deneb(EthereumNativeDenebExecutionHeaderV1),
}
/// Wire representation of a fork-specific Ethereum `LightClientHeader`.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_sccp::ethereum_source::EthereumNativeLightClientHeaderV1")]
pub struct EthereumNativeLightClientHeaderV1 {
    /// Closed fork layout used by this header.
    pub fork: EthereumNativeForkV1,
    /// Beacon header.
    pub beacon: EthereumNativeBeaconHeaderV1,
    /// Execution header; absent exactly for Altair and Bellatrix.
    pub execution: Option<EthereumNativeExecutionHeaderV1>,
    /// Execution-payload Merkle branch; empty before Capella, four roots after.
    #[norito(with = "crate::json_utils::vec_bytes_hex")]
    pub execution_branch: Vec<Vec<u8>>,
}
impl EthereumNativeLightClientHeaderV1 {
    /// Convert to the fork-closed SSZ type; the fork tag must match the execution layout.
    ///
    /// # Errors
    ///
    /// Returns [`EthereumExecutionError::MalformedWire`] for a layout or width mismatch.
    pub fn to_native(&self) -> Result<LightClientHeader, EthereumExecutionError> {
        let beacon = self.beacon.to_native();
        match (self.fork, &self.execution) {
            (EthereumNativeForkV1::Altair, None) if self.execution_branch.is_empty() => {
                Ok(LightClientHeader::Altair { beacon })
            }
            (EthereumNativeForkV1::Bellatrix, None) if self.execution_branch.is_empty() => {
                Ok(LightClientHeader::Bellatrix { beacon })
            }
            (
                EthereumNativeForkV1::Capella,
                Some(EthereumNativeExecutionHeaderV1::Capella(execution)),
            ) => Ok(LightClientHeader::Capella {
                beacon,
                execution: execution.to_native()?,
                execution_branch: fixed_roots::<4>(&self.execution_branch, "execution branch")?,
            }),
            (fork, Some(EthereumNativeExecutionHeaderV1::Deneb(execution))) => {
                let execution = execution.to_native()?;
                let execution_branch =
                    fixed_roots::<4>(&self.execution_branch, "execution branch")?;
                match fork {
                    EthereumNativeForkV1::Deneb => Ok(LightClientHeader::Deneb {
                        beacon,
                        execution,
                        execution_branch,
                    }),
                    EthereumNativeForkV1::Electra => Ok(LightClientHeader::Electra {
                        beacon,
                        execution,
                        execution_branch,
                    }),
                    EthereumNativeForkV1::Fulu => Ok(LightClientHeader::Fulu {
                        beacon,
                        execution,
                        execution_branch,
                    }),
                    _ => Err(EthereumExecutionError::MalformedWire(
                        "fork-specific light-client header",
                    )),
                }
            }
            _ => Err(EthereumExecutionError::MalformedWire(
                "fork-specific light-client header",
            )),
        }
    }
    /// Convert from the SSZ type.
    pub fn from_native(header: &LightClientHeader) -> Self {
        let beacon = EthereumNativeBeaconHeaderV1::from_native(header.beacon());
        let (execution, execution_branch) = match header {
            LightClientHeader::Altair { .. } | LightClientHeader::Bellatrix { .. } => {
                (None, Vec::new())
            }
            LightClientHeader::Capella {
                execution,
                execution_branch,
                ..
            } => (
                Some(EthereumNativeExecutionHeaderV1::Capella(
                    EthereumNativeCapellaExecutionHeaderV1::from_native(execution),
                )),
                roots_to_wire(execution_branch),
            ),
            LightClientHeader::Deneb {
                execution,
                execution_branch,
                ..
            }
            | LightClientHeader::Electra {
                execution,
                execution_branch,
                ..
            }
            | LightClientHeader::Fulu {
                execution,
                execution_branch,
                ..
            } => (
                Some(EthereumNativeExecutionHeaderV1::Deneb(
                    EthereumNativeDenebExecutionHeaderV1::from_native(execution),
                )),
                roots_to_wire(execution_branch),
            ),
        };
        Self {
            fork: header.fork().into(),
            beacon,
            execution,
            execution_branch,
        }
    }
}
/// Wire representation of the official 512-position sync committee.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_sccp::ethereum_source::EthereumNativeSyncCommitteeV1")]
pub struct EthereumNativeSyncCommitteeV1 {
    /// Compressed 48-byte min-pk public keys in positional order.
    #[norito(with = "crate::json_utils::vec_bytes_hex")]
    pub public_keys: Vec<Vec<u8>>,
    /// Compressed aggregate public key committed by beacon state.
    #[norito(with = "crate::json_utils::bytes_hex")]
    pub aggregate_public_key: Vec<u8>,
}
impl EthereumNativeSyncCommitteeV1 {
    /// Convert to the SSZ type, checking the 512-position length and key widths.
    ///
    /// Curve membership is checked separately by [`SyncCommittee::validate`].
    ///
    /// # Errors
    ///
    /// Returns [`EthereumExecutionError::MalformedWire`].
    pub fn to_native(&self) -> Result<SyncCommittee, EthereumExecutionError> {
        if self.public_keys.len() != SYNC_COMMITTEE_SIZE {
            return Err(EthereumExecutionError::MalformedWire(
                "sync committee length",
            ));
        }
        #[expect(
            clippy::large_stack_arrays,
            reason = "The protocol fixes 512 keys; conversion must not allocate an unadmitted committee"
        )]
        let mut public_keys = [BlsPublicKey::new([0; 48]); SYNC_COMMITTEE_SIZE];
        for (output, key) in public_keys.iter_mut().zip(&self.public_keys) {
            *output =
                BlsPublicKey::new(<[u8; 48]>::try_from(key.as_slice()).map_err(|_| {
                    EthereumExecutionError::MalformedWire("sync committee public key")
                })?);
        }
        let aggregate_public_key = <[u8; 48]>::try_from(self.aggregate_public_key.as_slice())
            .map_err(|_| {
                EthereumExecutionError::MalformedWire("sync committee aggregate public key")
            })?;
        Ok(SyncCommittee::new(
            &public_keys,
            BlsPublicKey::new(aggregate_public_key),
        ))
    }
    /// Convert from the SSZ type.
    pub fn from_native(committee: &SyncCommittee) -> Self {
        Self {
            public_keys: committee
                .pubkeys()
                .iter()
                .map(|key| key.to_bytes().to_vec())
                .collect(),
            aggregate_public_key: committee.aggregate_pubkey().to_bytes().to_vec(),
        }
    }
}
/// Wire representation of a `LightClientBootstrap`.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_sccp::ethereum_source::EthereumNativeLightClientBootstrapV1")]
pub struct EthereumNativeLightClientBootstrapV1 {
    /// Bootstrap light-client header.
    pub header: EthereumNativeLightClientHeaderV1,
    /// Current sync committee committed by the header state root.
    pub current_sync_committee: EthereumNativeSyncCommitteeV1,
    /// Fork-shaped current-committee branch.
    #[norito(with = "crate::json_utils::vec_bytes_hex")]
    pub current_sync_committee_branch: Vec<Vec<u8>>,
}
impl EthereumNativeLightClientBootstrapV1 {
    /// Convert to the SSZ type.
    ///
    /// # Errors
    ///
    /// Returns [`EthereumExecutionError::MalformedWire`] for a layout or width mismatch.
    pub fn to_native(&self) -> Result<LightClientBootstrap, EthereumExecutionError> {
        Ok(LightClientBootstrap {
            header: self.header.to_native()?,
            current_sync_committee: self.current_sync_committee.to_native()?,
            current_sync_committee_branch: current_committee_branch_from_wire(
                self.header.fork,
                &self.current_sync_committee_branch,
            )?,
        })
    }
    /// Convert from the SSZ type.
    pub fn from_native(bootstrap: &LightClientBootstrap) -> Self {
        Self {
            header: EthereumNativeLightClientHeaderV1::from_native(&bootstrap.header),
            current_sync_committee: EthereumNativeSyncCommitteeV1::from_native(
                &bootstrap.current_sync_committee,
            ),
            current_sync_committee_branch: match &bootstrap.current_sync_committee_branch {
                CurrentSyncCommitteeBranch::PreElectra(branch) => roots_to_wire(branch),
                CurrentSyncCommitteeBranch::Electra(branch) => roots_to_wire(branch),
            },
        }
    }
}
/// Wire representation of a next sync committee with its attested-state branch.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_sccp::ethereum_source::EthereumNativeNextSyncCommitteeV1")]
pub struct EthereumNativeNextSyncCommitteeV1 {
    /// Next sync committee.
    pub committee: EthereumNativeSyncCommitteeV1,
    /// Fork-shaped next-committee branch.
    #[norito(with = "crate::json_utils::vec_bytes_hex")]
    pub branch: Vec<Vec<u8>>,
}
/// Wire representation of one Ethereum `LightClientUpdate` or finality update.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_sccp::ethereum_source::EthereumNativeLightClientUpdateV1")]
pub struct EthereumNativeLightClientUpdateV1 {
    /// Sync-committee-attested header.
    pub attested_header: EthereumNativeLightClientHeaderV1,
    /// Next committee committed by the attested state; absent in finality updates.
    pub next_sync_committee: Option<EthereumNativeNextSyncCommitteeV1>,
    /// Header committed by the finalized checkpoint.
    pub finalized_header: EthereumNativeLightClientHeaderV1,
    /// Fork-shaped finalized-checkpoint branch.
    #[norito(with = "crate::json_utils::vec_bytes_hex")]
    pub finality_branch: Vec<Vec<u8>>,
    /// Little-endian positional `Bitvector[512]`.
    #[norito(with = "crate::json_utils::bytes_hex")]
    pub sync_committee_bits: Vec<u8>,
    /// Compressed 96-byte aggregate BLS signature.
    #[norito(with = "crate::json_utils::bytes_hex")]
    pub sync_committee_signature: Vec<u8>,
    /// Slot at which the aggregate signature was created.
    #[norito(with = "crate::json_utils::u64_string")]
    pub signature_slot: u64,
}
impl EthereumNativeLightClientUpdateV1 {
    /// Convert to the SSZ type.
    ///
    /// # Errors
    ///
    /// Returns [`EthereumExecutionError::MalformedWire`] for a layout or width mismatch.
    pub fn to_native(&self) -> Result<LightClientUpdate, EthereumExecutionError> {
        let sync_committee_bits =
            <[u8; SYNC_COMMITTEE_BITS_BYTES]>::try_from(self.sync_committee_bits.as_slice())
                .map_err(|_| EthereumExecutionError::MalformedWire("sync committee bitvector"))?;
        let sync_committee_signature =
            <[u8; 96]>::try_from(self.sync_committee_signature.as_slice())
                .map_err(|_| EthereumExecutionError::MalformedWire("sync committee signature"))?;
        let next_sync_committee = self
            .next_sync_committee
            .as_ref()
            .map(|next| -> Result<_, EthereumExecutionError> {
                Ok(NextSyncCommitteeProof {
                    committee: next.committee.to_native()?,
                    branch: next_committee_branch_from_wire(
                        self.attested_header.fork,
                        &next.branch,
                    )?,
                })
            })
            .transpose()?;
        Ok(LightClientUpdate {
            attested_header: self.attested_header.to_native()?,
            next_sync_committee,
            finalized_header: self.finalized_header.to_native()?,
            finality_branch: finality_branch_from_wire(
                self.attested_header.fork,
                &self.finality_branch,
            )?,
            sync_aggregate: SyncAggregate::new(
                sync_committee_bits,
                BlsSignature::new(sync_committee_signature),
            ),
            signature_slot: self.signature_slot,
        })
    }
    /// Convert from the SSZ type.
    pub fn from_native(update: &LightClientUpdate) -> Self {
        Self {
            attested_header: EthereumNativeLightClientHeaderV1::from_native(
                &update.attested_header,
            ),
            next_sync_committee: update.next_sync_committee.as_ref().map(|next| {
                EthereumNativeNextSyncCommitteeV1 {
                    committee: EthereumNativeSyncCommitteeV1::from_native(&next.committee),
                    branch: match &next.branch {
                        NextSyncCommitteeBranch::PreElectra(branch) => roots_to_wire(branch),
                        NextSyncCommitteeBranch::Electra(branch) => roots_to_wire(branch),
                    },
                }
            }),
            finalized_header: EthereumNativeLightClientHeaderV1::from_native(
                &update.finalized_header,
            ),
            finality_branch: match &update.finality_branch {
                FinalityBranch::PreElectra(branch) => roots_to_wire(branch),
                FinalityBranch::Electra(branch) => roots_to_wire(branch),
            },
            sync_committee_bits: update.sync_aggregate.bits().to_vec(),
            sync_committee_signature: update.sync_aggregate.signature().to_bytes().to_vec(),
            signature_slot: update.signature_slot,
        }
    }
}
/// Canonical Ethereum MPT inclusion nodes ordered from root to leaf.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_sccp::ethereum_source::EthereumNativeMptProofV1")]
pub struct EthereumNativeMptProofV1 {
    /// Raw canonical RLP nodes. Inline children are embedded in their parent
    /// and must not be repeated as separate proof elements.
    #[norito(with = "crate::json_utils::vec_bytes_hex")]
    pub nodes: Vec<Vec<u8>>,
}
impl EthereumNativeMptProofV1 {
    /// Total bytes of all nodes.
    pub fn byte_len(&self) -> usize {
        self.nodes.iter().map(Vec::len).sum()
    }
}
/// Trie opened by a Merkle-Patricia proof, used in precise errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EthereumMptRoleV1 {
    /// Execution state account opening.
    Account,
    /// Contract storage slot opening.
    Storage,
    /// Transaction receipt opening.
    Receipt,
    /// Original signed transaction envelope opening.
    Transaction,
}
/// Errors produced by the Ethereum wire conversions and execution-layer openings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EthereumExecutionError {
    /// Local physical backing for a detached convenience operation was unavailable.
    ResourceLimit,
    /// A fixed-width or fork-shaped wire field was malformed.
    MalformedWire(&'static str),
    /// A consensus-layer SSZ rule failed during conversion.
    LightClient(EthereumLightClientError),
    /// An MPT root was the zero sentinel or the empty trie.
    EmptyTrieRoot(EthereumMptRoleV1),
    /// An MPT proof exceeded node, per-node, or aggregate byte bounds.
    MptProofBounds(EthereumMptRoleV1),
    /// An MPT proof repeated an explicit node.
    DuplicateMptNode(EthereumMptRoleV1),
    /// An MPT node did not match its authenticated hash or inline reference.
    MptNodeReferenceMismatch(EthereumMptRoleV1),
    /// An MPT node or child reference was not canonical RLP/trie form.
    NonCanonicalMpt(EthereumMptRoleV1),
    /// The authenticated MPT path did not equal the requested key.
    MptKeyMismatch(EthereumMptRoleV1),
    /// Extra explicit nodes remained after a successful inclusion opening.
    UnusedMptNodes(EthereumMptRoleV1),
    /// The canonical state account was malformed.
    MalformedAccount,
    /// A storage value was not a canonical RLP integer of at most 32 bytes.
    MalformedStorageValue,
    /// The receipt envelope or receipt tuple was malformed.
    MalformedReceipt,
    /// The execution header was not a bounded canonical RLP list.
    MalformedHeader,
}
impl From<EthereumLightClientError> for EthereumExecutionError {
    fn from(value: EthereumLightClientError) -> Self {
        Self::LightClient(value)
    }
}
impl fmt::Display for EthereumExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ResourceLimit => formatter.write_str("native Ethereum allocation unavailable"),
            Self::MalformedWire(field) => {
                write!(formatter, "malformed Ethereum wire field: {field}")
            }
            Self::LightClient(error) => write!(formatter, "Ethereum light-client error: {error}"),
            Self::EmptyTrieRoot(role) => write!(formatter, "zero or empty {role:?} trie root"),
            Self::MptProofBounds(role) => write!(formatter, "{role:?} MPT proof exceeds bounds"),
            Self::DuplicateMptNode(role) => {
                write!(formatter, "duplicate explicit {role:?} MPT node")
            }
            Self::MptNodeReferenceMismatch(role) => {
                write!(formatter, "{role:?} MPT node reference mismatch")
            }
            Self::NonCanonicalMpt(role) => write!(formatter, "non-canonical {role:?} MPT"),
            Self::MptKeyMismatch(role) => write!(formatter, "{role:?} MPT key mismatch"),
            Self::UnusedMptNodes(role) => write!(formatter, "unused {role:?} MPT nodes"),
            Self::MalformedAccount => formatter.write_str("malformed canonical Ethereum account"),
            Self::MalformedStorageValue => {
                formatter.write_str("malformed canonical Ethereum storage value")
            }
            Self::MalformedReceipt => formatter.write_str("malformed canonical Ethereum receipt"),
            Self::MalformedHeader => {
                formatter.write_str("malformed canonical Ethereum execution header")
            }
        }
    }
}
impl std::error::Error for EthereumExecutionError {}
fn roots_to_wire(roots: &[Root]) -> Vec<Vec<u8>> {
    roots.iter().map(|root| root.to_vec()).collect()
}
fn fixed_roots<const N: usize>(
    roots: &[Vec<u8>],
    field: &'static str,
) -> Result<[Root; N], EthereumExecutionError> {
    if roots.len() != N {
        return Err(EthereumExecutionError::MalformedWire(field));
    }
    let mut out = [[0_u8; 32]; N];
    for (slot, root) in out.iter_mut().zip(roots) {
        *slot = <Root>::try_from(root.as_slice())
            .map_err(|_| EthereumExecutionError::MalformedWire(field))?;
    }
    Ok(out)
}
const fn uses_electra_layout(fork: EthereumNativeForkV1) -> bool {
    matches!(
        fork,
        EthereumNativeForkV1::Electra | EthereumNativeForkV1::Fulu
    )
}
fn current_committee_branch_from_wire(
    fork: EthereumNativeForkV1,
    roots: &[Vec<u8>],
) -> Result<CurrentSyncCommitteeBranch, EthereumExecutionError> {
    Ok(if uses_electra_layout(fork) {
        CurrentSyncCommitteeBranch::Electra(fixed_roots::<6>(roots, "current committee branch")?)
    } else {
        CurrentSyncCommitteeBranch::PreElectra(fixed_roots::<5>(roots, "current committee branch")?)
    })
}
fn next_committee_branch_from_wire(
    fork: EthereumNativeForkV1,
    roots: &[Vec<u8>],
) -> Result<NextSyncCommitteeBranch, EthereumExecutionError> {
    Ok(if uses_electra_layout(fork) {
        NextSyncCommitteeBranch::Electra(fixed_roots::<6>(roots, "next committee branch")?)
    } else {
        NextSyncCommitteeBranch::PreElectra(fixed_roots::<5>(roots, "next committee branch")?)
    })
}
fn finality_branch_from_wire(
    fork: EthereumNativeForkV1,
    roots: &[Vec<u8>],
) -> Result<FinalityBranch, EthereumExecutionError> {
    Ok(if uses_electra_layout(fork) {
        FinalityBranch::Electra(fixed_roots::<7>(roots, "finality branch")?)
    } else {
        FinalityBranch::PreElectra(fixed_roots::<6>(roots, "finality branch")?)
    })
}
// ---------------------------------------------------------------------------------------------
// RLP
// ---------------------------------------------------------------------------------------------
#[derive(Clone, Copy)]
pub(crate) enum RlpItem<'a> {
    Bytes { payload: &'a [u8] },
    List { payload: &'a [u8], raw: &'a [u8] },
}
fn read_big_endian_len(bytes: &[u8]) -> Option<usize> {
    if bytes.is_empty() || bytes[0] == 0 || bytes.len() > core::mem::size_of::<usize>() {
        return None;
    }
    bytes.iter().try_fold(0usize, |value, byte| {
        value.checked_mul(256)?.checked_add(usize::from(*byte))
    })
}
fn parse_rlp_item_at<'a>(bytes: &'a [u8], cursor: &mut usize) -> Option<RlpItem<'a>> {
    let start = *cursor;
    let first = *bytes.get(start)?;
    match first {
        0x00..=0x7f => {
            *cursor = start.checked_add(1)?;
            Some(RlpItem::Bytes {
                payload: bytes.get(start..*cursor)?,
            })
        }
        0x80..=0xb7 => {
            let len = usize::from(first - 0x80);
            let payload_start = start.checked_add(1)?;
            let end = payload_start.checked_add(len)?;
            let payload = bytes.get(payload_start..end)?;
            if len == 1 && payload[0] < 0x80 {
                return None;
            }
            *cursor = end;
            Some(RlpItem::Bytes { payload })
        }
        0xb8..=0xbf => {
            let len_len = usize::from(first - 0xb7);
            let length_start = start.checked_add(1)?;
            let length_end = length_start.checked_add(len_len)?;
            let len = read_big_endian_len(bytes.get(length_start..length_end)?)?;
            if len < 56 {
                return None;
            }
            let end = length_end.checked_add(len)?;
            let payload = bytes.get(length_end..end)?;
            *cursor = end;
            Some(RlpItem::Bytes { payload })
        }
        0xc0..=0xf7 => {
            let len = usize::from(first - 0xc0);
            let payload_start = start.checked_add(1)?;
            let end = payload_start.checked_add(len)?;
            let payload = bytes.get(payload_start..end)?;
            *cursor = end;
            Some(RlpItem::List {
                payload,
                raw: bytes.get(start..end)?,
            })
        }
        0xf8..=0xff => {
            let len_len = usize::from(first - 0xf7);
            let length_start = start.checked_add(1)?;
            let length_end = length_start.checked_add(len_len)?;
            let len = read_big_endian_len(bytes.get(length_start..length_end)?)?;
            if len < 56 {
                return None;
            }
            let end = length_end.checked_add(len)?;
            let payload = bytes.get(length_end..end)?;
            *cursor = end;
            Some(RlpItem::List {
                payload,
                raw: bytes.get(start..end)?,
            })
        }
    }
}
pub(crate) fn parse_single_rlp(bytes: &[u8]) -> Option<RlpItem<'_>> {
    let mut cursor = 0usize;
    let item = parse_rlp_item_at(bytes, &mut cursor)?;
    (cursor == bytes.len()).then_some(item)
}
pub(crate) fn parse_rlp_list(bytes: &[u8], max_items: usize) -> Option<RlpItems<'_>> {
    let RlpItem::List { payload, .. } = parse_single_rlp(bytes)? else {
        return None;
    };
    parse_rlp_list_payload(payload, max_items)
}
/// Fixed protocol field table; receipt log collections use a separately admitted owner.
pub(crate) struct RlpItems<'a> {
    items: [RlpItem<'a>; MAX_EXECUTION_HEADER_FIELDS],
    len: usize,
}
impl<'a> core::ops::Deref for RlpItems<'a> {
    type Target = [RlpItem<'a>];
    fn deref(&self) -> &Self::Target {
        &self.items[..self.len]
    }
}
fn parse_rlp_list_payload(payload: &[u8], max_items: usize) -> Option<RlpItems<'_>> {
    if max_items > MAX_EXECUTION_HEADER_FIELDS {
        return None;
    }
    let mut cursor = 0usize;
    let mut items = RlpItems {
        items: [RlpItem::Bytes { payload: &[] }; MAX_EXECUTION_HEADER_FIELDS],
        len: 0,
    };
    while cursor < payload.len() {
        if items.len() == max_items {
            return None;
        }
        items.items[items.len] = parse_rlp_item_at(payload, &mut cursor)?;
        items.len += 1;
    }
    (cursor == payload.len()).then_some(items)
}
pub(crate) const fn rlp_bytes(item: RlpItem<'_>) -> Option<&[u8]> {
    match item {
        RlpItem::Bytes { payload, .. } => Some(payload),
        RlpItem::List { .. } => None,
    }
}
pub(crate) fn rlp_list_items(item: RlpItem<'_>, max_items: usize) -> Option<RlpItems<'_>> {
    match item {
        RlpItem::List { payload, .. } => parse_rlp_list_payload(payload, max_items),
        RlpItem::Bytes { .. } => None,
    }
}
pub(crate) fn rlp_h256(item: RlpItem<'_>) -> Option<H256> {
    H256::try_from(rlp_bytes(item)?).ok()
}
fn canonical_uint_bytes(item: RlpItem<'_>, max_bytes: usize) -> Option<&[u8]> {
    let bytes = rlp_bytes(item)?;
    if bytes.len() > max_bytes || bytes.first() == Some(&0) {
        return None;
    }
    Some(bytes)
}
pub(crate) fn canonical_u64(item: RlpItem<'_>) -> Option<u64> {
    let bytes = canonical_uint_bytes(item, 8)?;
    Some(
        bytes
            .iter()
            .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte)),
    )
}
fn rlp_length_prefix(len: usize, short: u8, long: u8) -> Vec<u8> {
    if len < 56 {
        // `len < 56` fits in one byte.
        return vec![short + u8::try_from(len).unwrap_or(0)];
    }
    let raw = len.to_be_bytes();
    let first = raw
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(raw.len() - 1);
    let len_bytes = &raw[first..];
    let mut out = Vec::with_capacity(1 + len_bytes.len());
    out.push(long + u8::try_from(len_bytes.len()).unwrap_or(0));
    out.extend_from_slice(len_bytes);
    out
}
/// Canonical RLP encoding of a byte string.
pub fn rlp_encode_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        return bytes.to_vec();
    }
    let mut out = rlp_length_prefix(bytes.len(), 0x80, 0xb7);
    out.extend_from_slice(bytes);
    out
}
/// Canonical RLP encoding of a list whose items are already RLP-encoded.
pub fn rlp_encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let len = items.iter().map(Vec::len).sum();
    let mut out = rlp_length_prefix(len, 0xc0, 0xf7);
    for item in items {
        out.extend_from_slice(item);
    }
    out
}
/// Canonical RLP encoding of an unsigned integer given as big-endian bytes (leading zeros are
/// stripped; zero is the empty string).
pub fn rlp_encode_uint_bytes(big_endian: &[u8]) -> Vec<u8> {
    let first = big_endian
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(big_endian.len());
    rlp_encode_bytes(&big_endian[first..])
}
/// Canonical RLP encoding of a `u64`.
pub fn rlp_encode_u64(value: u64) -> Vec<u8> {
    rlp_encode_uint_bytes(&value.to_be_bytes())
}
fn keccak(bytes: &[u8]) -> H256 {
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    output
}
// ---------------------------------------------------------------------------------------------
// Merkle-Patricia inclusion
// ---------------------------------------------------------------------------------------------
fn key_nibbles(bytes: &[u8]) -> Vec<u8> {
    let mut nibbles = Vec::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        nibbles.push(byte >> 4);
        nibbles.push(byte & 0x0f);
    }
    nibbles
}
#[derive(Clone, Copy)]
struct Nibbles<'a> {
    bytes: &'a [u8],
    start: usize,
}
impl Nibbles<'_> {
    fn len(self) -> usize {
        self.bytes.len() * 2 - self.start
    }
    fn is_empty(self) -> bool {
        self.len() == 0
    }
    fn get(self, index: usize) -> Option<u8> {
        let index = self.start.checked_add(index)?;
        self.bytes
            .get(index / 2)
            .map(|byte| if index % 2 == 0 { byte >> 4 } else { byte & 15 })
    }
}
fn decode_compact_path(bytes: &[u8]) -> Option<(bool, Nibbles<'_>)> {
    let first = *bytes.first()?;
    let flag = first >> 4;
    if flag > 3 || (flag & 1 == 0 && first & 15 != 0) {
        return None;
    }
    Some((
        flag & 2 != 0,
        Nibbles {
            bytes,
            start: if flag & 1 == 0 { 2 } else { 1 },
        },
    ))
}
#[derive(Clone, Copy)]
enum MptNodeReference<'a> {
    Hash(H256),
    Inline(&'a [u8]),
}
fn child_reference(item: RlpItem<'_>) -> Result<Option<MptNodeReference<'_>>, ()> {
    match item {
        RlpItem::Bytes { payload: [] } => Ok(None),
        RlpItem::Bytes { payload, .. } => {
            let hash = H256::try_from(payload).map_err(|_| ())?;
            if hash.iter().all(|byte| *byte == 0) {
                return Err(());
            }
            Ok(Some(MptNodeReference::Hash(hash)))
        }
        RlpItem::List { raw, .. } if raw.len() < 32 => Ok(Some(MptNodeReference::Inline(raw))),
        RlpItem::List { .. } => Err(()),
    }
}
fn validate_mpt_proof_bounds(
    proof: &EthereumNativeMptProofV1,
    role: EthereumMptRoleV1,
) -> Result<(), EthereumExecutionError> {
    if proof.nodes.is_empty() || proof.nodes.len() > MAX_MPT_PROOF_NODES {
        return Err(EthereumExecutionError::MptProofBounds(role));
    }
    let mut total = 0usize;
    for (index, node) in proof.nodes.iter().enumerate() {
        if node.is_empty() || node.len() > MAX_MPT_NODE_BYTES {
            return Err(EthereumExecutionError::MptProofBounds(role));
        }
        total = total
            .checked_add(node.len())
            .ok_or(EthereumExecutionError::MptProofBounds(role))?;
        if total > MAX_MPT_PROOF_BYTES {
            return Err(EthereumExecutionError::MptProofBounds(role));
        }
        if proof.nodes[..index].iter().any(|previous| previous == node) {
            return Err(EthereumExecutionError::DuplicateMptNode(role));
        }
    }
    Ok(())
}
fn resolve_mpt_node_reference<'a>(
    reference: MptNodeReference<'a>,
    proof: &'a EthereumNativeMptProofV1,
    proof_cursor: &mut usize,
    first_node: bool,
    role: EthereumMptRoleV1,
) -> Result<&'a [u8], EthereumExecutionError> {
    match reference {
        MptNodeReference::Hash(expected_hash) => {
            let raw = proof
                .nodes
                .get(*proof_cursor)
                .ok_or(EthereumExecutionError::MptNodeReferenceMismatch(role))?;
            *proof_cursor = (*proof_cursor)
                .checked_add(1)
                .ok_or(EthereumExecutionError::MptProofBounds(role))?;
            if keccak(raw) != expected_hash || (!first_node && raw.len() < 32) {
                return Err(EthereumExecutionError::MptNodeReferenceMismatch(role));
            }
            Ok(raw)
        }
        MptNodeReference::Inline(raw) => Ok(raw),
    }
}
/// Open the value stored under `key` in the Merkle-Patricia trie with root `root`.
///
/// `proof.nodes` lists every hash-referenced node from the root to the value, in path order;
/// inline (shorter than 32 bytes) children stay embedded in their parents. Every node must be
/// canonical, the path must consume the key exactly, and no node may be unused or repeated.
///
/// # Errors
///
/// Returns the first violated rule for `role`.
pub fn verify_mpt_inclusion(
    root: H256,
    key: &[u8],
    proof: &EthereumNativeMptProofV1,
    role: EthereumMptRoleV1,
) -> Result<Vec<u8>, EthereumExecutionError> {
    verify_mpt_inclusion_ref(root, key, proof, role).map(<[u8]>::to_vec)
}
/// Borrow an authenticated trie value from its original proof owner without copying any node.
///
/// # Errors
/// Returns the same canonical path, bound, and reference errors as [`verify_mpt_inclusion`].
pub fn verify_mpt_inclusion_ref<'a>(
    root: H256,
    key: &[u8],
    proof: &'a EthereumNativeMptProofV1,
    role: EthereumMptRoleV1,
) -> Result<&'a [u8], EthereumExecutionError> {
    if root.iter().all(|byte| *byte == 0) || root == EMPTY_TRIE_ROOT {
        return Err(EthereumExecutionError::EmptyTrieRoot(role));
    }
    validate_mpt_proof_bounds(proof, role)?;
    let path = Nibbles {
        bytes: key,
        start: 0,
    };
    let mut path_cursor = 0usize;
    let mut proof_cursor = 0usize;
    let mut expected = MptNodeReference::Hash(root);
    let mut first_node = true;
    let mut previous_was_extension = false;
    loop {
        let raw = resolve_mpt_node_reference(expected, proof, &mut proof_cursor, first_node, role)?;
        first_node = false;
        let items = parse_rlp_list(raw, 17).ok_or(EthereumExecutionError::NonCanonicalMpt(role))?;
        match items.len() {
            17 => {
                previous_was_extension = false;
                let mut child_count = 0usize;
                for item in &items[..16] {
                    if child_reference(*item)
                        .map_err(|()| EthereumExecutionError::NonCanonicalMpt(role))?
                        .is_some()
                    {
                        child_count += 1;
                    }
                }
                let value =
                    rlp_bytes(items[16]).ok_or(EthereumExecutionError::NonCanonicalMpt(role))?;
                if (value.is_empty() && child_count < 2) || (!value.is_empty() && child_count == 0)
                {
                    return Err(EthereumExecutionError::NonCanonicalMpt(role));
                }
                if path_cursor == path.len() {
                    if value.is_empty() {
                        return Err(EthereumExecutionError::MptKeyMismatch(role));
                    }
                    if proof_cursor != proof.nodes.len() {
                        return Err(EthereumExecutionError::UnusedMptNodes(role));
                    }
                    return Ok(value);
                }
                let nibble = usize::from(
                    path.get(path_cursor)
                        .ok_or(EthereumExecutionError::MptKeyMismatch(role))?,
                );
                path_cursor += 1;
                expected = child_reference(items[nibble])
                    .map_err(|()| EthereumExecutionError::NonCanonicalMpt(role))?
                    .ok_or(EthereumExecutionError::MptKeyMismatch(role))?;
            }
            2 => {
                let compact =
                    rlp_bytes(items[0]).ok_or(EthereumExecutionError::NonCanonicalMpt(role))?;
                let (is_leaf, partial_path) = decode_compact_path(compact)
                    .ok_or(EthereumExecutionError::NonCanonicalMpt(role))?;
                if !is_leaf && (partial_path.is_empty() || previous_was_extension) {
                    return Err(EthereumExecutionError::NonCanonicalMpt(role));
                }
                if partial_path.len() > path.len().saturating_sub(path_cursor)
                    || (0..partial_path.len())
                        .any(|offset| path.get(path_cursor + offset) != partial_path.get(offset))
                {
                    return Err(EthereumExecutionError::MptKeyMismatch(role));
                }
                path_cursor = path_cursor
                    .checked_add(partial_path.len())
                    .ok_or(EthereumExecutionError::MptProofBounds(role))?;
                if is_leaf {
                    if path_cursor != path.len() {
                        return Err(EthereumExecutionError::MptKeyMismatch(role));
                    }
                    let value = rlp_bytes(items[1])
                        .filter(|value| !value.is_empty())
                        .ok_or(EthereumExecutionError::NonCanonicalMpt(role))?;
                    if proof_cursor != proof.nodes.len() {
                        return Err(EthereumExecutionError::UnusedMptNodes(role));
                    }
                    return Ok(value);
                }
                expected = child_reference(items[1])
                    .map_err(|()| EthereumExecutionError::NonCanonicalMpt(role))?
                    .ok_or(EthereumExecutionError::NonCanonicalMpt(role))?;
                previous_was_extension = true;
            }
            _ => return Err(EthereumExecutionError::NonCanonicalMpt(role)),
        }
    }
}
// ---------------------------------------------------------------------------------------------
// Merkle-Patricia builder
// ---------------------------------------------------------------------------------------------
fn compact_path(nibbles: &[u8], leaf: bool) -> Vec<u8> {
    let flag = if leaf { 2_u8 } else { 0 };
    let mut out = Vec::with_capacity(1 + nibbles.len() / 2);
    let rest = if nibbles.len() % 2 == 1 {
        out.push(((flag + 1) << 4) | nibbles[0]);
        &nibbles[1..]
    } else {
        out.push(flag << 4);
        nibbles
    };
    for pair in rest.chunks_exact(2) {
        out.push((pair[0] << 4) | pair[1]);
    }
    out
}
fn common_prefix_len(entries: &[(Vec<u8>, &[u8])], depth: usize) -> usize {
    let first = &entries[0].0;
    let last = &entries[entries.len() - 1].0;
    first[depth..]
        .iter()
        .zip(&last[depth..])
        .take_while(|(left, right)| left == right)
        .count()
}
fn child_ref_rlp(node: &[u8]) -> Vec<u8> {
    if node.len() < 32 {
        node.to_vec()
    } else {
        rlp_encode_bytes(&keccak(node))
    }
}
/// `entries` is sorted, deduplicated, non-empty, and shares `nibbles[..depth]`.
fn mpt_node_rlp(entries: &[(Vec<u8>, &[u8])], depth: usize) -> Vec<u8> {
    if let [(nibbles, value)] = entries {
        return rlp_encode_list(&[
            rlp_encode_bytes(&compact_path(&nibbles[depth..], true)),
            rlp_encode_bytes(value),
        ]);
    }
    let prefix = common_prefix_len(entries, depth);
    if prefix > 0 {
        let child = mpt_node_rlp(entries, depth + prefix);
        return rlp_encode_list(&[
            rlp_encode_bytes(&compact_path(&entries[0].0[depth..depth + prefix], false)),
            child_ref_rlp(&child),
        ]);
    }
    let mut items = Vec::with_capacity(17);
    for nibble in 0..16_u8 {
        let group: Vec<(Vec<u8>, &[u8])> = entries
            .iter()
            .filter(|(nibbles, _)| nibbles.get(depth) == Some(&nibble))
            .cloned()
            .collect();
        if group.is_empty() {
            items.push(rlp_encode_bytes(&[]));
        } else {
            items.push(child_ref_rlp(&mpt_node_rlp(&group, depth + 1)));
        }
    }
    let value = entries
        .iter()
        .find(|(nibbles, _)| nibbles.len() == depth)
        .map_or(&[][..], |(_, value)| *value);
    items.push(rlp_encode_bytes(value));
    rlp_encode_list(&items)
}
fn sorted_entries(entries: &[(Vec<u8>, Vec<u8>)]) -> Option<Vec<(Vec<u8>, &[u8])>> {
    let mut sorted: Vec<(Vec<u8>, &[u8])> = entries
        .iter()
        .map(|(key, value)| (key_nibbles(key), value.as_slice()))
        .collect();
    sorted.sort_by(|left, right| left.0.cmp(&right.0));
    let distinct = sorted.windows(2).all(|pair| pair[0].0 != pair[1].0);
    let non_empty_values = sorted.iter().all(|(_, value)| !value.is_empty());
    (distinct && non_empty_values).then_some(sorted)
}
/// Root of the Merkle-Patricia trie holding `entries` (`(key, value)` pairs).
///
/// Returns `None` for duplicate keys or empty values; an empty entry list has
/// [`EMPTY_TRIE_ROOT`].
pub fn mpt_root(entries: &[(Vec<u8>, Vec<u8>)]) -> Option<H256> {
    if entries.is_empty() {
        return Some(EMPTY_TRIE_ROOT);
    }
    let sorted = sorted_entries(entries)?;
    Some(keccak(&mpt_node_rlp(&sorted, 0)))
}
/// Inclusion proof of `key` in the trie holding `entries`, in the form
/// [`verify_mpt_inclusion`] opens (hash-referenced nodes only, root first).
///
/// Returns `None` when `key` is absent or the entries are invalid (see [`mpt_root`]).
pub fn mpt_proof(entries: &[(Vec<u8>, Vec<u8>)], key: &[u8]) -> Option<EthereumNativeMptProofV1> {
    let sorted = sorted_entries(entries)?;
    let target = key_nibbles(key);
    if !sorted.iter().any(|(nibbles, _)| *nibbles == target) {
        return None;
    }
    let mut nodes = vec![mpt_node_rlp(&sorted, 0)];
    let mut current = sorted;
    let mut depth = 0usize;
    loop {
        if current.len() == 1 {
            return Some(EthereumNativeMptProofV1 { nodes });
        }
        let prefix = common_prefix_len(&current, depth);
        if prefix > 0 {
            depth += prefix;
            let child = mpt_node_rlp(&current, depth);
            if child.len() >= 32 {
                nodes.push(child);
            }
            continue;
        }
        if target.len() == depth {
            return Some(EthereumNativeMptProofV1 { nodes });
        }
        let nibble = target[depth];
        current.retain(|(nibbles, _)| nibbles.get(depth) == Some(&nibble));
        depth += 1;
        let child = mpt_node_rlp(&current, depth);
        if child.len() >= 32 {
            nodes.push(child);
        }
    }
}
// ---------------------------------------------------------------------------------------------
// Execution-layer objects
// ---------------------------------------------------------------------------------------------
/// Fields of an execution header read by index, plus its hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EthereumExecutionHeaderFieldsV1 {
    /// `keccak256` of the RLP header: the block hash.
    pub hash: H256,
    /// Field 0: parent block hash.
    pub parent_hash: H256,
    /// Field 3: state root.
    pub state_root: H256,
    /// Field 4: transactions root.
    pub transactions_root: H256,
    /// Field 5: receipts root.
    pub receipts_root: H256,
    /// Field 8: block number.
    pub number: u64,
    /// Field 11: timestamp in seconds.
    pub timestamp: u64,
}
/// Decode a canonical RLP execution header and read its fields by index (§4.13.3).
///
/// The header must be a bounded RLP list of 16..=32 items; fields 0, 3, 4 and 5 are 32-byte
/// strings and fields 8 and 11 canonical integers of at most 8 bytes. The remaining fields are
/// bound by the hash only.
///
/// # Errors
///
/// Returns [`EthereumExecutionError::MalformedHeader`].
pub fn decode_execution_header(
    rlp: &[u8],
) -> Result<EthereumExecutionHeaderFieldsV1, EthereumExecutionError> {
    if rlp.len() > MAX_EXECUTION_HEADER_BYTES {
        return Err(EthereumExecutionError::MalformedHeader);
    }
    let items = parse_rlp_list(rlp, MAX_EXECUTION_HEADER_FIELDS)
        .ok_or(EthereumExecutionError::MalformedHeader)?;
    if items.len() < MIN_EXECUTION_HEADER_FIELDS {
        return Err(EthereumExecutionError::MalformedHeader);
    }
    let field =
        |index: usize| rlp_h256(items[index]).ok_or(EthereumExecutionError::MalformedHeader);
    let integer =
        |index: usize| canonical_u64(items[index]).ok_or(EthereumExecutionError::MalformedHeader);
    Ok(EthereumExecutionHeaderFieldsV1 {
        hash: keccak(rlp),
        parent_hash: field(0)?,
        state_root: field(3)?,
        transactions_root: field(4)?,
        receipts_root: field(5)?,
        number: integer(8)?,
        timestamp: integer(11)?,
    })
}
/// A canonical state account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EthereumAccountV1 {
    /// Account nonce.
    pub nonce: u64,
    /// Storage trie root.
    pub storage_root: H256,
    /// Keccak-256 of the account code.
    pub code_hash: H256,
}
/// Decode the canonical `[nonce, balance, storageRoot, codeHash]` account value.
///
/// # Errors
///
/// Returns [`EthereumExecutionError::MalformedAccount`].
pub fn decode_account(value: &[u8]) -> Result<EthereumAccountV1, EthereumExecutionError> {
    let fields = parse_rlp_list(value, 4).ok_or(EthereumExecutionError::MalformedAccount)?;
    if fields.len() != 4 || canonical_uint_bytes(fields[1], 32).is_none() {
        return Err(EthereumExecutionError::MalformedAccount);
    }
    Ok(EthereumAccountV1 {
        nonce: canonical_u64(fields[0]).ok_or(EthereumExecutionError::MalformedAccount)?,
        storage_root: rlp_h256(fields[2]).ok_or(EthereumExecutionError::MalformedAccount)?,
        code_hash: rlp_h256(fields[3]).ok_or(EthereumExecutionError::MalformedAccount)?,
    })
}
/// Decode a storage-trie value: the canonical RLP of a nonzero integer of at most 32 bytes,
/// returned as a big-endian word.
///
/// # Errors
///
/// Returns [`EthereumExecutionError::MalformedStorageValue`].
pub fn decode_storage_word(value: &[u8]) -> Result<H256, EthereumExecutionError> {
    let item = parse_single_rlp(value).ok_or(EthereumExecutionError::MalformedStorageValue)?;
    let bytes = canonical_uint_bytes(item, 32)
        .filter(|bytes| !bytes.is_empty())
        .ok_or(EthereumExecutionError::MalformedStorageValue)?;
    let mut word = [0_u8; 32];
    word[32 - bytes.len()..].copy_from_slice(bytes);
    Ok(word)
}
/// One receipt log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EthereumLogV1 {
    /// Emitting contract.
    pub address: [u8; 20],
    /// Up to four topics.
    pub topics: Vec<H256>,
    /// Unindexed data.
    pub data: Vec<u8>,
}
/// A decoded post-Byzantium receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EthereumReceiptV1 {
    /// EIP-2718 transaction type (0 for a legacy receipt).
    pub tx_type: u8,
    /// Whether the transaction succeeded (`status = 1`).
    pub success: bool,
    /// Cumulative gas used in the block after this transaction.
    pub cumulative_gas_used: u64,
    /// Logs in emission order.
    pub logs: Vec<EthereumLogV1>,
}
/// Decode a receipt as stored in the receipts trie: a legacy RLP list, or an EIP-2718 type byte
/// (`0x01..=0x7f`) followed by the RLP list `[status, cumulativeGasUsed, logsBloom, logs]`.
///
/// Pre-Byzantium receipts (a 32-byte state root instead of the status) are rejected.
///
/// # Errors
///
/// Returns [`EthereumExecutionError::MalformedReceipt`].
pub fn decode_receipt(bytes: &[u8]) -> Result<EthereumReceiptV1, EthereumExecutionError> {
    let memory = crate::native_memory::Memory::detached();
    let receipt = memory
        .finish(decode_receipt_native(bytes, &memory))
        .map_err(|error| match error {
            crate::native_memory::AttemptError::Protocol(error) => error,
            crate::native_memory::AttemptError::Allocation(_) => {
                EthereumExecutionError::ResourceLimit
            }
        })?;
    Ok(EthereumReceiptV1 {
        tx_type: receipt.tx_type,
        success: receipt.success,
        cumulative_gas_used: receipt.cumulative_gas_used,
        logs: receipt
            .logs
            .iter()
            .map(|log| EthereumLogV1 {
                address: log.address,
                topics: log.topics().to_vec(),
                data: log.data.to_vec(),
            })
            .collect(),
    })
}

/// Receipt log borrowing the original authenticated proof bytes.
#[derive(Clone, Copy)]
pub(crate) struct EthereumLogRef<'a> {
    pub(crate) address: [u8; 20],
    topics: [H256; MAX_LOG_TOPICS],
    topic_count: usize,
    pub(crate) data: &'a [u8],
}
impl EthereumLogRef<'_> {
    pub(crate) fn topics(&self) -> &[H256] {
        &self.topics[..self.topic_count]
    }
}
/// Indexed borrowed log descriptors retain their actual original allocation owner.
pub(crate) struct EthereumReceiptOwner<'a> {
    pub(crate) tx_type: u8,
    pub(crate) success: bool,
    pub(crate) cumulative_gas_used: u64,
    pub(crate) logs: crate::native_memory::Buffer<EthereumLogRef<'a>>,
}
pub(crate) fn decode_receipt_native<'a>(
    bytes: &'a [u8],
    memory: &crate::native_memory::Memory<'_>,
) -> Result<EthereumReceiptOwner<'a>, EthereumExecutionError> {
    let bad = EthereumExecutionError::MalformedReceipt;
    let (tx_type, body) = match bytes.first() {
        Some(&first) if (0x01..=0x7f).contains(&first) => (first, &bytes[1..]),
        Some(&first) if first >= 0xc0 => (0, bytes),
        _ => return Err(bad),
    };
    let fields = parse_rlp_list(body, 4).ok_or(bad)?;
    if fields.len() != 4 {
        return Err(bad);
    }
    let success = match rlp_bytes(fields[0]) {
        Some([]) => false,
        Some([1]) => true,
        _ => return Err(bad),
    };
    let cumulative_gas_used = canonical_u64(fields[1]).ok_or(bad)?;
    if rlp_bytes(fields[2]).map(<[u8]>::len) != Some(256) {
        return Err(bad);
    }
    let RlpItem::List { payload, .. } = fields[3] else {
        return Err(bad);
    };
    // Validate cardinality before admitting the exact descriptor table; payload bytes stay borrowed.
    let mut cursor = 0;
    let mut count = 0;
    while cursor < payload.len() {
        parse_rlp_item_at(payload, &mut cursor).ok_or(bad)?;
        count += 1;
        if count > MAX_RECEIPT_LOGS {
            return Err(bad);
        }
    }
    let mut logs = memory
        .buffer(count)
        .ok_or(EthereumExecutionError::ResourceLimit)?;
    cursor = 0;
    while cursor < payload.len() {
        let item = parse_rlp_item_at(payload, &mut cursor).ok_or(bad)?;
        logs.push(decode_log_ref(item)?)
            .ok_or(EthereumExecutionError::ResourceLimit)?;
    }
    Ok(EthereumReceiptOwner {
        tx_type,
        success,
        cumulative_gas_used,
        logs,
    })
}
fn decode_log_ref(item: RlpItem<'_>) -> Result<EthereumLogRef<'_>, EthereumExecutionError> {
    let bad = EthereumExecutionError::MalformedReceipt;
    let fields = rlp_list_items(item, 3).ok_or(bad)?;
    if fields.len() != 3 {
        return Err(bad);
    }
    let address = rlp_bytes(fields[0])
        .and_then(|bytes| <[u8; 20]>::try_from(bytes).ok())
        .ok_or(bad)?;
    let items = rlp_list_items(fields[1], MAX_LOG_TOPICS).ok_or(bad)?;
    let mut topics = [[0; 32]; MAX_LOG_TOPICS];
    for (index, topic) in items.iter().enumerate() {
        topics[index] = rlp_h256(*topic).ok_or(bad)?;
    }
    let data = rlp_bytes(fields[2]).ok_or(bad)?;
    Ok(EthereumLogRef {
        address,
        topics,
        topic_count: items.len(),
        data,
    })
}
/// Encode a receipt in its receipts-trie form (see [`decode_receipt`]).
pub fn encode_receipt(receipt: &EthereumReceiptV1, logs_bloom: &[u8; 256]) -> Vec<u8> {
    let logs = receipt
        .logs
        .iter()
        .map(|log| {
            rlp_encode_list(&[
                rlp_encode_bytes(&log.address),
                rlp_encode_list(
                    &log.topics
                        .iter()
                        .map(|topic| rlp_encode_bytes(topic))
                        .collect::<Vec<_>>(),
                ),
                rlp_encode_bytes(&log.data),
            ])
        })
        .collect::<Vec<_>>();
    let body = rlp_encode_list(&[
        rlp_encode_bytes(if receipt.success { &[1] } else { &[] }),
        rlp_encode_u64(receipt.cumulative_gas_used),
        rlp_encode_bytes(logs_bloom),
        rlp_encode_list(&logs),
    ]);
    if receipt.tx_type == 0 {
        body
    } else {
        let mut typed = Vec::with_capacity(1 + body.len());
        typed.push(receipt.tx_type);
        typed.extend_from_slice(&body);
        typed
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn single_leaf_proof(key: &[u8], value: &[u8]) -> (H256, EthereumNativeMptProofV1) {
        let mut compact_path = Vec::with_capacity(1 + key.len());
        compact_path.push(0x20);
        compact_path.extend_from_slice(key);
        let node = rlp_encode_list(&[rlp_encode_bytes(&compact_path), rlp_encode_bytes(value)]);
        (
            keccak(&node),
            EthereumNativeMptProofV1 { nodes: vec![node] },
        )
    }
    #[test]
    fn independently_constructed_single_leaf_mpt_vector_is_canonical() {
        let key = [0x12, 0x34];
        let value = [0xab, 0xcd, 0xef];
        let (root, proof) = single_leaf_proof(&key, &value);
        assert_eq!(
            root,
            [
                0x34, 0x4c, 0xda, 0xee, 0x19, 0x09, 0x3a, 0x13, 0x81, 0x10, 0xb4, 0x1c, 0x8c, 0xd7,
                0x16, 0xeb, 0x26, 0x57, 0x1b, 0xda, 0x75, 0xb7, 0x0b, 0x5c, 0xb7, 0x55, 0x8b, 0x3f,
                0xde, 0x33, 0xa1, 0xf6,
            ]
        );
        assert_eq!(
            verify_mpt_inclusion(root, &key, &proof, EthereumMptRoleV1::Account),
            Ok(value.to_vec())
        );
        let entries = vec![(key.to_vec(), value.to_vec())];
        assert_eq!(mpt_root(&entries), Some(root));
        assert_eq!(mpt_proof(&entries, &key), Some(proof));
    }
    #[test]
    fn transaction_opening_preserves_opaque_bytes_and_diagnostic_role() {
        let key = rlp_encode_u64(1);
        let value = [0x7f, 0x00, 0xff];
        let (root, proof) = single_leaf_proof(&key, &value);
        assert_eq!(
            verify_mpt_inclusion_ref(root, &key, &proof, EthereumMptRoleV1::Transaction),
            Ok(value.as_slice())
        );
        assert_eq!(
            verify_mpt_inclusion_ref(
                root,
                &rlp_encode_u64(2),
                &proof,
                EthereumMptRoleV1::Transaction,
            ),
            Err(EthereumExecutionError::MptKeyMismatch(
                EthereumMptRoleV1::Transaction
            ))
        );
    }

    #[test]
    fn mpt_rejects_wrong_key_trailing_and_duplicate_nodes() {
        let key = [0x12, 0x34];
        let (root, proof) = single_leaf_proof(&key, &[0xab]);
        assert_eq!(
            verify_mpt_inclusion(root, &[0x12, 0x35], &proof, EthereumMptRoleV1::Account),
            Err(EthereumExecutionError::MptKeyMismatch(
                EthereumMptRoleV1::Account
            ))
        );
        let mut trailing = proof.clone();
        trailing.nodes.push(vec![0xc0]);
        assert_eq!(
            verify_mpt_inclusion(root, &key, &trailing, EthereumMptRoleV1::Account),
            Err(EthereumExecutionError::UnusedMptNodes(
                EthereumMptRoleV1::Account
            ))
        );
        let mut duplicate = proof.clone();
        duplicate.nodes.push(duplicate.nodes[0].clone());
        assert_eq!(
            verify_mpt_inclusion(root, &key, &duplicate, EthereumMptRoleV1::Account),
            Err(EthereumExecutionError::DuplicateMptNode(
                EthereumMptRoleV1::Account
            ))
        );
    }
    #[test]
    fn mpt_rejects_noncanonical_leaf_encodings() {
        let noncanonical = EthereumNativeMptProofV1 {
            nodes: vec![vec![0xc4, 0x81, 0x20, 0x81, 0x01]],
        };
        assert_eq!(
            verify_mpt_inclusion(
                keccak(&noncanonical.nodes[0]),
                &[],
                &noncanonical,
                EthereumMptRoleV1::Receipt,
            ),
            Err(EthereumExecutionError::NonCanonicalMpt(
                EthereumMptRoleV1::Receipt
            ))
        );
        let bad_compact = EthereumNativeMptProofV1 {
            nodes: vec![rlp_encode_list(&[
                rlp_encode_bytes(&[0x21]),
                rlp_encode_bytes(&[1]),
            ])],
        };
        assert_eq!(
            verify_mpt_inclusion(
                keccak(&bad_compact.nodes[0]),
                &[],
                &bad_compact,
                EthereumMptRoleV1::Receipt,
            ),
            Err(EthereumExecutionError::NonCanonicalMpt(
                EthereumMptRoleV1::Receipt
            ))
        );
    }
    #[test]
    fn mpt_short_children_reject_explicit_and_hashed_aliases() {
        let inline_leaf = rlp_encode_list(&[rlp_encode_bytes(&[0x32]), rlp_encode_bytes(&[1])]);
        assert!(inline_leaf.len() < 32);
        let inline_extension = rlp_encode_list(&[rlp_encode_bytes(&[0x11]), inline_leaf.clone()]);
        let inline_root = keccak(&inline_extension);
        let inline_proof = EthereumNativeMptProofV1 {
            nodes: vec![inline_extension.clone()],
        };
        assert_eq!(
            verify_mpt_inclusion(
                inline_root,
                &[0x12],
                &inline_proof,
                EthereumMptRoleV1::Account
            ),
            Ok(vec![1])
        );
        let inline_repeated = EthereumNativeMptProofV1 {
            nodes: vec![inline_extension, inline_leaf.clone()],
        };
        assert_eq!(
            verify_mpt_inclusion(
                inline_root,
                &[0x12],
                &inline_repeated,
                EthereumMptRoleV1::Account,
            ),
            Err(EthereumExecutionError::UnusedMptNodes(
                EthereumMptRoleV1::Account
            ))
        );
        let hashed_extension = rlp_encode_list(&[
            rlp_encode_bytes(&[0x11]),
            rlp_encode_bytes(&keccak(&inline_leaf)),
        ]);
        let hashed_alias = EthereumNativeMptProofV1 {
            nodes: vec![hashed_extension.clone(), inline_leaf],
        };
        assert_eq!(
            verify_mpt_inclusion(
                keccak(&hashed_extension),
                &[0x12],
                &hashed_alias,
                EthereumMptRoleV1::Account,
            ),
            Err(EthereumExecutionError::MptNodeReferenceMismatch(
                EthereumMptRoleV1::Account
            ))
        );
    }
    #[test]
    fn mpt_builder_proofs_open_every_key_of_a_receipt_like_trie() {
        let entries: Vec<(Vec<u8>, Vec<u8>)> = (0..300_u64)
            .map(|index| {
                let value = vec![
                    u8::try_from(index % 251).unwrap_or(0);
                    40 + usize::try_from(index % 7).unwrap_or(0)
                ];
                (rlp_encode_u64(index), value)
            })
            .collect();
        let root = mpt_root(&entries).expect("valid entries");
        for (key, value) in entries.iter().step_by(13) {
            let proof = mpt_proof(&entries, key).expect("present key");
            assert_eq!(
                verify_mpt_inclusion(root, key, &proof, EthereumMptRoleV1::Receipt),
                Ok(value.clone())
            );
        }
        assert_eq!(mpt_proof(&entries, &rlp_encode_u64(300)), None);
        assert_eq!(mpt_root(&[]), Some(EMPTY_TRIE_ROOT));
        let duplicate = vec![(vec![1], vec![1]), (vec![1], vec![2])];
        assert_eq!(mpt_root(&duplicate), None);
        assert_eq!(mpt_root(&[(vec![1], Vec::new())]), None);
        // Small values produce inline children that the proof must not repeat.
        let small: Vec<(Vec<u8>, Vec<u8>)> = (0..20_u8)
            .map(|index| (vec![index, 0x55], vec![index + 1]))
            .collect();
        let small_root = mpt_root(&small).expect("valid");
        for (key, value) in &small {
            let proof = mpt_proof(&small, key).expect("present");
            assert_eq!(
                verify_mpt_inclusion(small_root, key, &proof, EthereumMptRoleV1::Storage),
                Ok(value.clone())
            );
        }
    }
    #[test]
    fn mpt_builder_matches_the_known_receipt_key_layout() {
        // Keys `rlp(0)` = 0x80 and `rlp(1)` = 0x01 diverge at the first nibble.
        let entries = vec![
            (rlp_encode_u64(0), vec![0xaa; 40]),
            (rlp_encode_u64(1), vec![0xbb; 40]),
        ];
        let root = mpt_root(&entries).expect("valid");
        let proof = mpt_proof(&entries, &rlp_encode_u64(0)).expect("present");
        assert_eq!(proof.nodes.len(), 2);
        assert_eq!(
            verify_mpt_inclusion(root, &[0x80], &proof, EthereumMptRoleV1::Receipt),
            Ok(vec![0xaa; 40])
        );
    }
    #[test]
    fn proof_bounds_reject_empty_oversized_and_zero_roots() {
        assert_eq!(
            validate_mpt_proof_bounds(
                &EthereumNativeMptProofV1 { nodes: Vec::new() },
                EthereumMptRoleV1::Account,
            ),
            Err(EthereumExecutionError::MptProofBounds(
                EthereumMptRoleV1::Account
            ))
        );
        assert_eq!(
            validate_mpt_proof_bounds(
                &EthereumNativeMptProofV1 {
                    nodes: vec![vec![0; MAX_MPT_NODE_BYTES + 1]],
                },
                EthereumMptRoleV1::Receipt,
            ),
            Err(EthereumExecutionError::MptProofBounds(
                EthereumMptRoleV1::Receipt
            ))
        );
        let (_, small_proof) = single_leaf_proof(&[1], &[2]);
        assert_eq!(small_proof.byte_len(), small_proof.nodes[0].len());
        for root in [[0; 32], EMPTY_TRIE_ROOT] {
            assert_eq!(
                verify_mpt_inclusion(root, &[1], &small_proof, EthereumMptRoleV1::Account),
                Err(EthereumExecutionError::EmptyTrieRoot(
                    EthereumMptRoleV1::Account
                ))
            );
        }
    }
    #[test]
    fn account_and_storage_values_are_strict() {
        let account = rlp_encode_list(&[
            rlp_encode_u64(1),
            rlp_encode_u64(0),
            rlp_encode_bytes(&[0x41; 32]),
            rlp_encode_bytes(&[0x22; 32]),
        ]);
        assert_eq!(
            decode_account(&account),
            Ok(EthereumAccountV1 {
                nonce: 1,
                storage_root: [0x41; 32],
                code_hash: [0x22; 32],
            })
        );
        let leading_zero_nonce = rlp_encode_list(&[
            rlp_encode_bytes(&[0]),
            rlp_encode_bytes(&[]),
            rlp_encode_bytes(&[0x41; 32]),
            rlp_encode_bytes(&[0x22; 32]),
        ]);
        assert_eq!(
            decode_account(&leading_zero_nonce),
            Err(EthereumExecutionError::MalformedAccount)
        );
        let mut word = [0_u8; 32];
        word[31] = 5;
        assert_eq!(decode_storage_word(&rlp_encode_bytes(&[5])), Ok(word));
        assert_eq!(
            decode_storage_word(&rlp_encode_bytes(&[0x6d; 32])),
            Ok([0x6d; 32])
        );
        assert_eq!(
            decode_storage_word(&rlp_encode_bytes(&[0, 5])),
            Err(EthereumExecutionError::MalformedStorageValue)
        );
        assert_eq!(
            decode_storage_word(&rlp_encode_bytes(&[])),
            Err(EthereumExecutionError::MalformedStorageValue)
        );
        assert_eq!(
            decode_storage_word(&rlp_encode_bytes(&[1; 33])),
            Err(EthereumExecutionError::MalformedStorageValue)
        );
    }
    #[test]
    fn receipts_roundtrip_and_reject_malformed_envelopes() {
        let receipt = EthereumReceiptV1 {
            tx_type: 2,
            success: true,
            cumulative_gas_used: 21_000,
            logs: vec![EthereumLogV1 {
                address: [0x11; 20],
                topics: vec![[0x22; 32], [0x33; 32]],
                data: vec![1, 2, 3],
            }],
        };
        let encoded = encode_receipt(&receipt, &[0; 256]);
        assert_eq!(encoded[0], 2);
        assert_eq!(decode_receipt(&encoded), Ok(receipt.clone()));
        let legacy = EthereumReceiptV1 {
            tx_type: 0,
            success: false,
            ..receipt.clone()
        };
        assert_eq!(
            decode_receipt(&encode_receipt(&legacy, &[0; 256])),
            Ok(legacy)
        );
        assert_eq!(
            decode_receipt(&[0x80]),
            Err(EthereumExecutionError::MalformedReceipt)
        );
        assert_eq!(
            decode_receipt(&[]),
            Err(EthereumExecutionError::MalformedReceipt)
        );
        let mut short_bloom = encode_receipt(&receipt, &[0; 256]);
        short_bloom.truncate(short_bloom.len() - 1);
        assert_eq!(
            decode_receipt(&short_bloom),
            Err(EthereumExecutionError::MalformedReceipt)
        );
        let too_many_topics = EthereumReceiptV1 {
            logs: vec![EthereumLogV1 {
                address: [0x11; 20],
                topics: vec![[0; 32]; 5],
                data: Vec::new(),
            }],
            ..receipt
        };
        assert_eq!(
            decode_receipt(&encode_receipt(&too_many_topics, &[0; 256])),
            Err(EthereumExecutionError::MalformedReceipt)
        );
    }
    #[test]
    fn execution_headers_are_read_by_index_and_hash() {
        let mut fields: Vec<Vec<u8>> = (0..21_u8)
            .map(|index| rlp_encode_bytes(&[index + 1; 32]))
            .collect();
        fields[8] = rlp_encode_u64(26_069_527);
        fields[11] = rlp_encode_u64(1_790_522_000);
        let rlp = rlp_encode_list(&fields);
        let header = decode_execution_header(&rlp).expect("valid header");
        assert_eq!(header.hash, keccak(&rlp));
        assert_eq!(header.parent_hash, [1; 32]);
        assert_eq!(header.state_root, [4; 32]);
        assert_eq!(header.transactions_root, [5; 32]);
        assert_eq!(header.receipts_root, [6; 32]);
        assert_eq!(header.number, 26_069_527);
        assert_eq!(header.timestamp, 1_790_522_000);
        let mut short = fields.clone();
        short.truncate(15);
        assert_eq!(
            decode_execution_header(&rlp_encode_list(&short)),
            Err(EthereumExecutionError::MalformedHeader)
        );
        let mut bad_number = fields;
        bad_number[8] = rlp_encode_bytes(&[0, 1]);
        assert_eq!(
            decode_execution_header(&rlp_encode_list(&bad_number)),
            Err(EthereumExecutionError::MalformedHeader)
        );
        assert_eq!(
            decode_execution_header(&vec![0xc0; MAX_EXECUTION_HEADER_BYTES + 1]),
            Err(EthereumExecutionError::MalformedHeader)
        );
    }
    #[test]
    fn rlp_encoders_are_canonical() {
        assert_eq!(rlp_encode_u64(0), vec![0x80]);
        assert_eq!(rlp_encode_u64(0x7f), vec![0x7f]);
        assert_eq!(rlp_encode_u64(0x80), vec![0x81, 0x80]);
        assert_eq!(rlp_encode_uint_bytes(&[0, 0, 1, 0]), vec![0x82, 1, 0]);
        let long = vec![7_u8; 60];
        let encoded = rlp_encode_bytes(&long);
        assert_eq!(&encoded[..2], &[0xb8, 60]);
        let list = rlp_encode_list(core::slice::from_ref(&encoded));
        assert_eq!(&list[..2], &[0xf8, 62]);
        let parsed = parse_rlp_list(&list, 1).expect("canonical");
        assert_eq!(rlp_bytes(parsed[0]), Some(long.as_slice()));
    }
    #[test]
    fn wire_conversions_reject_layout_mismatches() {
        let header = EthereumNativeLightClientHeaderV1 {
            fork: EthereumNativeForkV1::Altair,
            beacon: EthereumNativeBeaconHeaderV1 {
                slot: 1,
                proposer_index: 2,
                parent_root: [3; 32],
                state_root: [4; 32],
                body_root: [5; 32],
            },
            execution: None,
            execution_branch: Vec::new(),
        };
        let native = header.to_native().expect("Altair header");
        assert_eq!(
            EthereumNativeLightClientHeaderV1::from_native(&native),
            header
        );
        let mut capella_without_execution = header.clone();
        capella_without_execution.fork = EthereumNativeForkV1::Capella;
        assert_eq!(
            capella_without_execution.to_native(),
            Err(EthereumExecutionError::MalformedWire(
                "fork-specific light-client header"
            ))
        );
        let committee = EthereumNativeSyncCommitteeV1 {
            public_keys: vec![vec![1; 48]; 511],
            aggregate_public_key: vec![1; 48],
        };
        assert_eq!(
            committee.to_native(),
            Err(EthereumExecutionError::MalformedWire(
                "sync committee length"
            ))
        );
        assert_eq!(
            fixed_roots::<2>(&[vec![0; 32]], "branch"),
            Err(EthereumExecutionError::MalformedWire("branch"))
        );
        for fork in [
            EthereumNativeForkV1::Altair,
            EthereumNativeForkV1::Bellatrix,
            EthereumNativeForkV1::Capella,
            EthereumNativeForkV1::Deneb,
            EthereumNativeForkV1::Electra,
            EthereumNativeForkV1::Fulu,
        ] {
            assert_eq!(EthereumNativeForkV1::from(EthereumFork::from(fork)), fork);
        }
    }
}
