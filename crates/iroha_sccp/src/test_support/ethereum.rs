//! Synthetic Ethereum beacon chain and execution helpers (`specs/sccp.md` §4.13.3, §11).
//!
//! [`SyntheticBeaconChainV1`] derives a deterministic 512-member sync committee per period from a
//! seed and signs light-client updates with the same BLS implementation (`blstrs`) and
//! proof-of-possession DST the verifier uses, under the compiled mainnet profile (genesis time
//! `1606824023`, 12-second slots, mainnet fork versions and genesis validators root). Its
//! finalized headers commit to any execution payload through a valid execution branch, so an
//! integration test can install a fresh Ethereum light client through the Parliament
//! ([`SyntheticBeaconChainV1::bootstrap_at_unix_ms`]) and prove burns made on a local EVM (EDR)
//! with the production verifier ([`SyntheticBeaconChainV1::finality_update_for`]).
//!
//! The execution helpers build RLP headers, receipt tries, SCCP logs and EIP-2935 history state,
//! and the `*_from_*_json` parsers turn captured beacon and execution RPC responses
//! (`fixtures/sccp/rpc/eth/`) into the verifier's wire types.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, PoisonError},
};

use blstrs::{G1Projective, G2Projective, Scalar};
use group::Group as _;
use iroha_crypto::ETHEREUM_BLS_POP_DST;
use iroha_data_model::sccp::light_client::{SccpLcAdvanceBytesV1, SccpLcBootstrapV1};
use norito::json::Value;

use crate::{
    ethereum_native::{
        BeaconBlockHeader, BlsPublicKey, BlsSignature, CapellaExecutionPayloadHeader,
        CurrentSyncCommitteeBranch, DenebExecutionPayloadHeader, EXECUTION_PAYLOAD_GINDEX,
        EthereumFork, ExtraData, FinalityBranch, ForkSchedule, LightClientBootstrap,
        LightClientHeader, LightClientUpdate, NextSyncCommitteeBranch, NextSyncCommitteeProof,
        Root, SYNC_COMMITTEE_BITS_BYTES, SYNC_COMMITTEE_SIZE, SyncAggregate, SyncCommittee,
        generalized_indices, hash_nodes, sync_committee_period_at_slot,
        sync_committee_signing_root,
    },
    ethereum_source::{
        EthereumLogV1, EthereumNativeLightClientBootstrapV1, EthereumNativeLightClientUpdateV1,
        EthereumNativeMptProofV1, EthereumNativeSyncCommitteeV1, EthereumReceiptV1, encode_receipt,
        mpt_proof, mpt_root, rlp_encode_bytes, rlp_encode_list, rlp_encode_u64,
        rlp_encode_uint_bytes,
    },
    light_client::{
        ethereum::{EthereumHistoryProofV1, EthereumLcAdvanceV1},
        profile::{ETHEREUM_MAINNET, EthereumChainProfileV1},
        proof::{SccpLcAdvanceV1, SccpLcBootstrapDataV1},
    },
    v1::{
        evm_abi::{TransferToTairaLogV1, VoidedLogV1},
        hashes::{keccak256, word_u64},
    },
};

/// Default seed of [`SyntheticBeaconChainV1::mainnet`].
pub const SYNTHETIC_BEACON_SEED_V1: [u8; 32] = [0x5c; 32];
const SLOTS_PER_PERIOD: u64 = 8_192;

/// Execution payload fields a synthetic finalized beacon header commits to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyntheticExecutionHeaderV1 {
    /// Execution block hash (keccak of the block's RLP header).
    pub block_hash: [u8; 32],
    /// Execution block number.
    pub number: u64,
    /// Execution state root.
    pub state_root: [u8; 32],
    /// Execution receipts root.
    pub receipts_root: [u8; 32],
    /// Execution timestamp (seconds).
    pub timestamp: u64,
}

/// Parameters of one synthetic update.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyntheticUpdateSpecV1 {
    /// Slot of the attested header.
    pub attested_slot: u64,
    /// Slot of the finalized header.
    pub finalized_slot: u64,
    /// Execution payload of the finalized header.
    pub finalized_execution: SyntheticExecutionHeaderV1,
    /// Signature slot.
    pub signature_slot: u64,
    /// Whether the update carries the next sync committee of the attested period.
    pub include_next_committee: bool,
    /// Number of participating positions (the first `participants` bits).
    pub participants: usize,
    /// Committee period that signs; `None` = `period(signature_slot)`.
    pub signing_period: Option<u64>,
    /// Committee period whose committee is presented as `next_sync_committee`; `None` =
    /// `period(attested_slot) + 1`.
    pub next_committee_period: Option<u64>,
}

struct SyntheticCommitteeV1 {
    secrets: Vec<Scalar>,
    native: SyncCommittee,
    wire: EthereumNativeSyncCommitteeV1,
}

/// Deterministic synthetic Ethereum beacon chain.
pub struct SyntheticBeaconChainV1 {
    seed: [u8; 32],
    profile: EthereumChainProfileV1,
    schedule: ForkSchedule,
    committees: Mutex<BTreeMap<u64, Arc<SyntheticCommitteeV1>>>,
}

fn seeded(parts: &[&[u8]]) -> [u8; 32] {
    let mut all: Vec<&[u8]> = vec![b"SCCP/SYNTHETIC/BEACON/V1"];
    all.extend_from_slice(parts);
    keccak256(&all)
}

fn secret_scalar(seed: &[u8; 32], period: u64, index: u64) -> Scalar {
    let mut bytes = seeded(&[seed, b"sync", &period.to_be_bytes(), &index.to_be_bytes()]);
    // Clearing the top two bits keeps the value below the BLS12-381 group order.
    bytes[0] &= 0x3f;
    bytes[31] |= 1;
    Scalar::from_bytes_be(&bytes).expect("a value below 2^254 is a canonical scalar")
}

fn compressed_g1(scalar: &Scalar) -> [u8; 48] {
    (G1Projective::generator() * scalar).to_compressed()
}

fn sparse_node(gindex: u64, max_depth: u32, explicit: &BTreeMap<u64, Root>) -> Root {
    if let Some(value) = explicit.get(&gindex) {
        return *value;
    }
    if u64::BITS - 1 - gindex.leading_zeros() == max_depth {
        return [0; 32];
    }
    hash_nodes(
        &sparse_node(gindex * 2, max_depth, explicit),
        &sparse_node(gindex * 2 + 1, max_depth, explicit),
    )
}

fn sparse_branch(target: u64, max_depth: u32, explicit: &BTreeMap<u64, Root>) -> Vec<Root> {
    let depth = u64::BITS - 1 - target.leading_zeros();
    let mut node = target;
    (0..depth)
        .map(|_| {
            let sibling = sparse_node(node ^ 1, max_depth, explicit);
            node >>= 1;
            sibling
        })
        .collect()
}

fn max_depth(explicit: &BTreeMap<u64, Root>) -> u32 {
    explicit
        .keys()
        .map(|gindex| u64::BITS - 1 - gindex.leading_zeros())
        .max()
        .unwrap_or(0)
}

fn fixed<const N: usize>(roots: Vec<Root>) -> [Root; N] {
    roots
        .try_into()
        .expect("sparse branch has the gindex depth")
}

impl SyntheticBeaconChainV1 {
    /// A chain under the compiled mainnet profile with `seed`.
    #[must_use]
    pub fn new(seed: [u8; 32]) -> Self {
        Self::with_profile(seed, ETHEREUM_MAINNET)
    }

    /// A chain under the compiled mainnet profile with [`SYNTHETIC_BEACON_SEED_V1`].
    #[must_use]
    pub fn mainnet() -> Self {
        Self::new(SYNTHETIC_BEACON_SEED_V1)
    }

    /// A chain under another profile (for example one with a moved `supported_until`).
    #[must_use]
    pub fn with_profile(seed: [u8; 32], profile: EthereumChainProfileV1) -> Self {
        Self {
            seed,
            profile,
            schedule: profile.schedule().expect("synthetic profiles are valid"),
            committees: Mutex::new(BTreeMap::new()),
        }
    }

    /// The chain profile.
    #[must_use]
    pub const fn profile(&self) -> &EthereumChainProfileV1 {
        &self.profile
    }

    /// The slot in progress at unix time `unix_ms`.
    #[must_use]
    pub const fn slot_at_unix_ms(&self, unix_ms: u64) -> u64 {
        self.profile.slot_at_ms(unix_ms)
    }

    /// Unix time of the start of `slot` in milliseconds.
    #[must_use]
    pub fn slot_unix_ms(&self, slot: u64) -> u64 {
        self.profile
            .slot_start_ms(slot)
            .expect("slot time fits in u64")
    }

    fn committee_entry(&self, period: u64) -> Arc<SyntheticCommitteeV1> {
        if let Some(entry) = self
            .committees
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&period)
        {
            return Arc::clone(entry);
        }
        let secrets: Vec<Scalar> = (0..SYNC_COMMITTEE_SIZE as u64)
            .map(|index| secret_scalar(&self.seed, period, index))
            .collect();
        let pubkeys: Vec<BlsPublicKey> = secrets
            .iter()
            .map(|secret| BlsPublicKey::new(compressed_g1(secret)))
            .collect();
        let sum = secrets
            .iter()
            .fold(Scalar::from(0_u64), |sum, secret| sum + secret);
        let native = SyncCommittee::new(
            pubkeys.as_slice().try_into().expect("512 positions"),
            BlsPublicKey::new(compressed_g1(&sum)),
        );
        let entry = Arc::new(SyntheticCommitteeV1 {
            wire: EthereumNativeSyncCommitteeV1::from_native(&native),
            native,
            secrets,
        });
        Arc::clone(
            self.committees
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .entry(period)
                .or_insert(entry),
        )
    }

    /// The sync committee of `period`.
    #[must_use]
    pub fn committee(&self, period: u64) -> EthereumNativeSyncCommitteeV1 {
        self.committee_entry(period).wire.clone()
    }

    /// A synthetic execution payload for `slot`: number = slot, time = slot time, and roots and
    /// hash derived from the seed.
    #[must_use]
    pub fn synthetic_execution(&self, slot: u64) -> SyntheticExecutionHeaderV1 {
        SyntheticExecutionHeaderV1 {
            block_hash: seeded(&[&self.seed, b"execution-hash", &slot.to_be_bytes()]),
            number: slot,
            state_root: seeded(&[&self.seed, b"execution-state", &slot.to_be_bytes()]),
            receipts_root: seeded(&[&self.seed, b"execution-receipts", &slot.to_be_bytes()]),
            timestamp: self.slot_unix_ms(slot) / 1_000,
        }
    }

    fn fork_at(&self, slot: u64) -> EthereumFork {
        self.schedule
            .fork_at_slot(slot)
            .expect("synthetic slots are after Altair")
            .0
    }

    fn light_client_header(
        &self,
        slot: u64,
        state_root: Root,
        execution: &SyntheticExecutionHeaderV1,
    ) -> LightClientHeader {
        let fork = self.fork_at(slot);
        let capella = CapellaExecutionPayloadHeader {
            parent_hash: seeded(&[&self.seed, b"execution-parent", &slot.to_be_bytes()]),
            fee_recipient: [0; 20],
            state_root: execution.state_root,
            receipts_root: execution.receipts_root,
            logs_bloom: [0; 256],
            prev_randao: [0; 32],
            block_number: execution.number,
            gas_limit: 30_000_000,
            gas_used: 0,
            timestamp: execution.timestamp,
            extra_data: ExtraData::default(),
            base_fee_per_gas: [0; 32],
            block_hash: execution.block_hash,
            transactions_root: [0; 32],
            withdrawals_root: [0; 32],
        };
        let deneb = DenebExecutionPayloadHeader {
            capella,
            blob_gas_used: 0,
            excess_blob_gas: 0,
        };
        let execution_root = if fork == EthereumFork::Capella {
            capella.hash_tree_root()
        } else {
            deneb.hash_tree_root()
        };
        let body = BTreeMap::from([(EXECUTION_PAYLOAD_GINDEX, execution_root)]);
        let execution_branch: [Root; 4] = fixed(sparse_branch(EXECUTION_PAYLOAD_GINDEX, 4, &body));
        let beacon = BeaconBlockHeader {
            slot,
            proposer_index: slot % 1_000_000,
            parent_root: seeded(&[&self.seed, b"beacon-parent", &slot.to_be_bytes()]),
            state_root,
            body_root: sparse_node(1, 4, &body),
        };
        match fork {
            EthereumFork::Altair | EthereumFork::Bellatrix => {
                panic!("synthetic headers carry execution payloads (Capella or later)")
            }
            EthereumFork::Capella => LightClientHeader::Capella {
                beacon,
                execution: capella,
                execution_branch,
            },
            EthereumFork::Deneb => LightClientHeader::Deneb {
                beacon,
                execution: deneb,
                execution_branch,
            },
            EthereumFork::Electra => LightClientHeader::Electra {
                beacon,
                execution: deneb,
                execution_branch,
            },
            EthereumFork::Fulu => LightClientHeader::Fulu {
                beacon,
                execution: deneb,
                execution_branch,
            },
        }
    }

    /// Bootstrap wire object of the header at `slot` committing to `execution`.
    #[must_use]
    pub fn bootstrap_wire(
        &self,
        slot: u64,
        execution: &SyntheticExecutionHeaderV1,
    ) -> EthereumNativeLightClientBootstrapV1 {
        let fork = self.fork_at(slot);
        let gindex = generalized_indices(fork).current_sync_committee;
        let committee = self.committee_entry(sync_committee_period_at_slot(slot));
        let state = BTreeMap::from([(gindex, committee.native.hash_tree_root())]);
        let depth = max_depth(&state);
        let header = self.light_client_header(slot, sparse_node(1, depth, &state), execution);
        let branch = sparse_branch(gindex, depth, &state);
        let current_sync_committee_branch = if gindex == 86 {
            CurrentSyncCommitteeBranch::Electra(fixed(branch))
        } else {
            CurrentSyncCommitteeBranch::PreElectra(fixed(branch))
        };
        EthereumNativeLightClientBootstrapV1::from_native(&LightClientBootstrap {
            header,
            current_sync_committee: committee.native,
            current_sync_committee_branch,
        })
    }

    /// `InitializeLightClient` bootstrap of the header at `slot` committing to `execution`.
    #[must_use]
    pub fn bootstrap_with_execution(
        &self,
        slot: u64,
        execution: &SyntheticExecutionHeaderV1,
    ) -> SccpLcBootstrapV1 {
        SccpLcBootstrapDataV1::Ethereum(self.bootstrap_wire(slot, execution))
            .to_bootstrap()
            .expect("synthetic bootstraps encode")
    }

    /// `InitializeLightClient` bootstrap whose header slot is the slot in progress at `unix_ms`,
    /// committing to [`Self::synthetic_execution`] of that slot.
    #[must_use]
    pub fn bootstrap_at_unix_ms(&self, unix_ms: u64) -> SccpLcBootstrapV1 {
        let slot = self.slot_at_unix_ms(unix_ms);
        self.bootstrap_with_execution(slot, &self.synthetic_execution(slot))
    }

    /// A signed update built from `spec`.
    #[must_use]
    pub fn update(&self, spec: &SyntheticUpdateSpecV1) -> EthereumNativeLightClientUpdateV1 {
        let finalized_header = self.light_client_header(
            spec.finalized_slot,
            seeded(&[
                &self.seed,
                b"finalized-state",
                &spec.finalized_slot.to_be_bytes(),
            ]),
            &spec.finalized_execution,
        );
        let attested_period = sync_committee_period_at_slot(spec.attested_slot);
        let indices = generalized_indices(self.fork_at(spec.attested_slot));
        let mut state = BTreeMap::from([
            (
                indices.finalized_root,
                finalized_header.beacon().hash_tree_root(),
            ),
            (
                indices.current_sync_committee,
                self.committee_entry(attested_period)
                    .native
                    .hash_tree_root(),
            ),
        ]);
        let next_period = spec.next_committee_period.unwrap_or(attested_period + 1);
        let next = self.committee_entry(next_period);
        state.insert(indices.next_sync_committee, next.native.hash_tree_root());
        let depth = max_depth(&state);
        let attested_header = self.light_client_header(
            spec.attested_slot,
            sparse_node(1, depth, &state),
            &self.synthetic_execution(spec.attested_slot),
        );
        let electra = indices.finalized_root == 169;
        let finality = sparse_branch(indices.finalized_root, depth, &state);
        let finality_branch = if electra {
            FinalityBranch::Electra(fixed(finality))
        } else {
            FinalityBranch::PreElectra(fixed(finality))
        };
        let next_branch = sparse_branch(indices.next_sync_committee, depth, &state);
        let next_sync_committee = spec.include_next_committee.then(|| NextSyncCommitteeProof {
            committee: next.native,
            branch: if electra {
                NextSyncCommitteeBranch::Electra(fixed(next_branch))
            } else {
                NextSyncCommitteeBranch::PreElectra(fixed(next_branch))
            },
        });
        let signer = self.committee_entry(
            spec.signing_period
                .unwrap_or_else(|| sync_committee_period_at_slot(spec.signature_slot)),
        );
        let mut bits = [0_u8; SYNC_COMMITTEE_BITS_BYTES];
        let mut secret = Scalar::from(0_u64);
        for position in 0..spec.participants.min(SYNC_COMMITTEE_SIZE) {
            bits[position / 8] |= 1 << (position % 8);
            secret += signer.secrets[position];
        }
        let signing_root =
            sync_committee_signing_root(&attested_header, spec.signature_slot, &self.schedule)
                .expect("synthetic signature slots are after Altair");
        let signature = (G2Projective::hash_to_curve(&signing_root, ETHEREUM_BLS_POP_DST, &[])
            * secret)
            .to_compressed();
        EthereumNativeLightClientUpdateV1::from_native(&LightClientUpdate {
            attested_header,
            next_sync_committee,
            finalized_header,
            finality_branch,
            sync_aggregate: SyncAggregate::new(bits, BlsSignature::new(signature)),
            signature_slot: spec.signature_slot,
        })
    }

    /// The earliest signature slot whose start is not before `execution`'s timestamp.
    ///
    /// The verifier rejects a finalized execution payload timestamped after the start of the
    /// update's signature slot (a block is finalized only after it exists), so a burn on a local
    /// EVM is finalized with this slot or a later one.
    #[must_use]
    pub fn signature_slot_for(&self, execution: &SyntheticExecutionHeaderV1) -> u64 {
        let execution_ms = execution.timestamp.saturating_mul(1_000);
        let slot = self.slot_at_unix_ms(execution_ms);
        if self.slot_unix_ms(slot) < execution_ms {
            slot + 1
        } else {
            slot
        }
    }

    /// A finality update (no next committee, full participation) whose finalized header commits
    /// to `execution`: attested at `signature_slot - 1`, finalized two epochs earlier.
    ///
    /// `execution.timestamp` must not lie after the start of `signature_slot`
    /// ([`Self::signature_slot_for`]).
    #[must_use]
    pub fn finality_update_for(
        &self,
        execution: SyntheticExecutionHeaderV1,
        signature_slot: u64,
    ) -> EthereumNativeLightClientUpdateV1 {
        let attested_slot = signature_slot - 1;
        self.update(&SyntheticUpdateSpecV1 {
            attested_slot,
            finalized_slot: attested_slot.saturating_sub(64),
            finalized_execution: execution,
            signature_slot,
            include_next_committee: false,
            participants: SYNC_COMMITTEE_SIZE,
            signing_period: None,
            next_committee_period: None,
        })
    }

    /// An update inside `period` (signed by its committee) that teaches the committee of
    /// `period + 1`, finalizing [`Self::synthetic_execution`] of its finalized slot.
    #[must_use]
    pub fn period_update(&self, period: u64) -> EthereumNativeLightClientUpdateV1 {
        let start = period * SLOTS_PER_PERIOD;
        self.update(&SyntheticUpdateSpecV1 {
            attested_slot: start + 199,
            finalized_slot: start + 128,
            finalized_execution: self.synthetic_execution(start + 128),
            signature_slot: start + 200,
            include_next_committee: true,
            participants: SYNC_COMMITTEE_SIZE,
            signing_period: None,
            next_committee_period: None,
        })
    }

    /// An advance teaching the committees of `from_period + 1 ..= to_period` (at most 16).
    #[must_use]
    pub fn catch_up_advance(&self, from_period: u64, to_period: u64) -> SccpLcAdvanceV1 {
        SccpLcAdvanceV1::Ethereum(EthereumLcAdvanceV1 {
            updates: (from_period..to_period)
                .map(|period| self.period_update(period))
                .collect(),
        })
    }
}

/// Wrap an advance for `AdvanceSccpLightClientV1`.
#[must_use]
pub fn advance_bytes(advance: &SccpLcAdvanceV1) -> SccpLcAdvanceBytesV1 {
    advance
        .to_bytes()
        .expect("synthetic advances fit the wrapper")
}

// ---------------------------------------------------------------------------------------------
// Execution-layer helpers
// ---------------------------------------------------------------------------------------------

/// Header fields of a synthetic execution block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyntheticBlockFieldsV1 {
    /// Parent block hash.
    pub parent_hash: [u8; 32],
    /// Block number.
    pub number: u64,
    /// Timestamp (seconds).
    pub timestamp: u64,
    /// State root.
    pub state_root: [u8; 32],
    /// Receipts root.
    pub receipts_root: [u8; 32],
}

/// A 21-field Prague-shaped execution header RLP with the given fields.
#[must_use]
pub fn execution_header_rlp(fields: &SyntheticBlockFieldsV1) -> Vec<u8> {
    rlp_encode_list(&[
        rlp_encode_bytes(&fields.parent_hash),
        rlp_encode_bytes(&[0x1d; 32]),
        rlp_encode_bytes(&[0; 20]),
        rlp_encode_bytes(&fields.state_root),
        rlp_encode_bytes(&[0x56; 32]),
        rlp_encode_bytes(&fields.receipts_root),
        rlp_encode_bytes(&[0; 256]),
        rlp_encode_u64(0),
        rlp_encode_u64(fields.number),
        rlp_encode_u64(30_000_000),
        rlp_encode_u64(21_000),
        rlp_encode_u64(fields.timestamp),
        rlp_encode_bytes(&[]),
        rlp_encode_bytes(&[0; 32]),
        rlp_encode_bytes(&[0; 8]),
        rlp_encode_u64(7),
        rlp_encode_bytes(&[0x56; 32]),
        rlp_encode_u64(0),
        rlp_encode_u64(0),
        rlp_encode_bytes(&[0; 32]),
        rlp_encode_bytes(&[0xe3; 32]),
    ])
}

/// The execution payload fields of an RLP header.
#[must_use]
pub fn execution_of(header_rlp: &[u8]) -> SyntheticExecutionHeaderV1 {
    let fields = crate::ethereum_source::decode_execution_header(header_rlp)
        .expect("synthetic headers decode");
    SyntheticExecutionHeaderV1 {
        block_hash: fields.hash,
        number: fields.number,
        state_root: fields.state_root,
        receipts_root: fields.receipts_root,
        timestamp: fields.timestamp,
    }
}

/// `count` parent-linked headers following `parent` (each 12 seconds later).
#[must_use]
pub fn header_chain(parent: &[u8], count: usize) -> Vec<Vec<u8>> {
    let mut previous = execution_of(parent);
    let mut chain = Vec::with_capacity(count);
    for _ in 0..count {
        let header = execution_header_rlp(&SyntheticBlockFieldsV1 {
            parent_hash: previous.block_hash,
            number: previous.number + 1,
            timestamp: previous.timestamp + 12,
            state_root: seeded(&[b"chain-state", &previous.block_hash]),
            receipts_root: seeded(&[b"chain-receipts", &previous.block_hash]),
        });
        previous = execution_of(&header);
        chain.push(header);
    }
    chain
}

/// `SccpTransferToTaira` log of `emitter`.
#[must_use]
pub fn transfer_log(emitter: [u8; 20], log: &TransferToTairaLogV1) -> EthereumLogV1 {
    let (topics, data) = log.encode();
    EthereumLogV1 {
        address: emitter,
        topics,
        data,
    }
}

/// `SccpVoided` log of `emitter`.
#[must_use]
pub fn voided_log(emitter: [u8; 20], message_id: [u8; 32], nonce: u64) -> EthereumLogV1 {
    let (topics, data) = VoidedLogV1 { message_id, nonce }.encode();
    EthereumLogV1 {
        address: emitter,
        topics,
        data,
    }
}

/// A successful type-2 receipt carrying `logs`.
#[must_use]
pub fn successful_receipt(logs: Vec<EthereumLogV1>) -> EthereumReceiptV1 {
    EthereumReceiptV1 {
        tx_type: 2,
        success: true,
        cumulative_gas_used: 100_000,
        logs,
    }
}

/// Receipts trie entries (`rlp(index)` to encoded receipt).
#[must_use]
pub fn receipt_entries(receipts: &[EthereumReceiptV1]) -> Vec<(Vec<u8>, Vec<u8>)> {
    receipts
        .iter()
        .zip(0_u64..)
        .map(|(receipt, index)| (rlp_encode_u64(index), encode_receipt(receipt, &[0; 256])))
        .collect()
}

/// Receipts root and the inclusion proof of receipt `index`.
#[must_use]
pub fn receipt_root_and_proof(
    receipts: &[EthereumReceiptV1],
    index: u64,
) -> ([u8; 32], EthereumNativeMptProofV1) {
    let entries = receipt_entries(receipts);
    (
        mpt_root(&entries).expect("receipt keys are distinct"),
        mpt_proof(&entries, &rlp_encode_u64(index)).expect("receipt index exists"),
    )
}

/// State root and EIP-2935 proof whose history slot of `block_number` holds `block_hash`, under
/// the history contract code hash of `profile`.
#[must_use]
pub fn history_state(
    profile: &EthereumChainProfileV1,
    block_number: u64,
    block_hash: [u8; 32],
) -> ([u8; 32], EthereumHistoryProofV1) {
    let window = profile.history_serve_window;
    let slot_key = keccak256(&[&word_u64(block_number % window)]);
    let mut storage = vec![(slot_key.to_vec(), rlp_encode_uint_bytes(&block_hash))];
    for other in 1..40_u64 {
        let key = keccak256(&[&word_u64((block_number + other) % window)]);
        storage.push((
            key.to_vec(),
            rlp_encode_bytes(&seeded(&[b"slot", &other.to_be_bytes()])),
        ));
    }
    let storage_root = mpt_root(&storage).expect("distinct slots");
    let account = rlp_encode_list(&[
        rlp_encode_u64(1),
        rlp_encode_u64(0),
        rlp_encode_bytes(&storage_root),
        rlp_encode_bytes(&profile.history_storage_code_hash),
    ]);
    let account_key = keccak256(&[&profile.history_storage_address]);
    let mut accounts = vec![(account_key.to_vec(), account)];
    for other in 0..30_u8 {
        let key = keccak256(&[&[other; 20]]);
        let value = rlp_encode_list(&[
            rlp_encode_u64(u64::from(other)),
            rlp_encode_u64(1),
            rlp_encode_bytes(&crate::ethereum_source::EMPTY_TRIE_ROOT),
            rlp_encode_bytes(&[0xc5; 32]),
        ]);
        accounts.push((key.to_vec(), value));
    }
    (
        mpt_root(&accounts).expect("distinct accounts"),
        EthereumHistoryProofV1 {
            account_proof: mpt_proof(&accounts, &account_key).expect("account present"),
            storage_proof: mpt_proof(&storage, &slot_key).expect("slot present"),
        },
    )
}

// ---------------------------------------------------------------------------------------------
// Captured RPC parsers
// ---------------------------------------------------------------------------------------------

fn hex_digits(text: &str) -> &str {
    text.strip_prefix("0x").expect("0x-prefixed hex")
}

/// Decode `0x`-prefixed hex of even length.
#[must_use]
pub fn hex_bytes(text: &str) -> Vec<u8> {
    let digits = hex_digits(text);
    assert!(digits.len().is_multiple_of(2), "even-length hex: {text}");
    (0..digits.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&digits[index..index + 2], 16).expect("hex digit"))
        .collect()
}

fn hex32(text: &str) -> [u8; 32] {
    hex_bytes(text).try_into().expect("32-byte hex")
}

/// Big-endian bytes of a JSON-RPC quantity (`0x0` is empty).
#[must_use]
pub fn quantity_bytes(text: &str) -> Vec<u8> {
    let digits = hex_digits(text);
    let padded = if digits.len() % 2 == 1 {
        format!("0{digits}")
    } else {
        digits.to_owned()
    };
    let bytes = hex_bytes(&format!("0x{padded}"));
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    bytes[first..].to_vec()
}

fn quantity_u64(text: &str) -> u64 {
    quantity_bytes(text)
        .iter()
        .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte))
}

fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    value
        .get(key)
        .unwrap_or_else(|| panic!("missing field {key}"))
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    field(value, key)
        .as_str()
        .unwrap_or_else(|| panic!("field {key} is not a string"))
}

fn decimal(value: &Value, key: &str) -> u64 {
    text(value, key).parse().expect("decimal string")
}

fn hex_list(value: &Value, key: &str) -> Vec<Vec<u8>> {
    field(value, key)
        .as_array()
        .expect("array")
        .iter()
        .map(|item| hex_bytes(item.as_str().expect("hex string")))
        .collect()
}

fn le_u256_from_decimal(text: &str) -> [u8; 32] {
    let value: u128 = text.parse().expect("base fee fits in u128");
    let mut out = [0_u8; 32];
    out[..16].copy_from_slice(&value.to_le_bytes());
    out
}

fn beacon_header_from_json(value: &Value) -> BeaconBlockHeader {
    BeaconBlockHeader {
        slot: decimal(value, "slot"),
        proposer_index: decimal(value, "proposer_index"),
        parent_root: hex32(text(value, "parent_root")),
        state_root: hex32(text(value, "state_root")),
        body_root: hex32(text(value, "body_root")),
    }
}

fn light_client_header_from_json(value: &Value, fork: EthereumFork) -> LightClientHeader {
    let beacon = beacon_header_from_json(field(value, "beacon"));
    let execution = field(value, "execution");
    let capella = CapellaExecutionPayloadHeader {
        parent_hash: hex32(text(execution, "parent_hash")),
        fee_recipient: hex_bytes(text(execution, "fee_recipient"))
            .try_into()
            .expect("20-byte fee recipient"),
        state_root: hex32(text(execution, "state_root")),
        receipts_root: hex32(text(execution, "receipts_root")),
        logs_bloom: hex_bytes(text(execution, "logs_bloom"))
            .try_into()
            .expect("256-byte bloom"),
        prev_randao: hex32(text(execution, "prev_randao")),
        block_number: decimal(execution, "block_number"),
        gas_limit: decimal(execution, "gas_limit"),
        gas_used: decimal(execution, "gas_used"),
        timestamp: decimal(execution, "timestamp"),
        extra_data: ExtraData::new(hex_bytes(text(execution, "extra_data")))
            .expect("bounded extra data"),
        base_fee_per_gas: le_u256_from_decimal(text(execution, "base_fee_per_gas")),
        block_hash: hex32(text(execution, "block_hash")),
        transactions_root: hex32(text(execution, "transactions_root")),
        withdrawals_root: hex32(text(execution, "withdrawals_root")),
    };
    let execution_branch: [Root; 4] = hex_list(value, "execution_branch")
        .into_iter()
        .map(|root| <Root>::try_from(root.as_slice()).expect("32-byte root"))
        .collect::<Vec<_>>()
        .try_into()
        .expect("four execution roots");
    let deneb = || DenebExecutionPayloadHeader {
        capella,
        blob_gas_used: decimal(execution, "blob_gas_used"),
        excess_blob_gas: decimal(execution, "excess_blob_gas"),
    };
    match fork {
        EthereumFork::Capella => LightClientHeader::Capella {
            beacon,
            execution: capella,
            execution_branch,
        },
        EthereumFork::Deneb => LightClientHeader::Deneb {
            beacon,
            execution: deneb(),
            execution_branch,
        },
        EthereumFork::Electra => LightClientHeader::Electra {
            beacon,
            execution: deneb(),
            execution_branch,
        },
        EthereumFork::Fulu => LightClientHeader::Fulu {
            beacon,
            execution: deneb(),
            execution_branch,
        },
        EthereumFork::Altair | EthereumFork::Bellatrix => {
            panic!("captured headers are Capella or later")
        }
    }
}

fn fork_from_version(value: &Value) -> EthereumFork {
    match text(value, "version") {
        "capella" => EthereumFork::Capella,
        "deneb" => EthereumFork::Deneb,
        "electra" => EthereumFork::Electra,
        "fulu" => EthereumFork::Fulu,
        other => panic!("unsupported consensus version {other}"),
    }
}

fn committee_from_json(value: &Value) -> SyncCommittee {
    let keys: Vec<BlsPublicKey> = hex_list(value, "pubkeys")
        .into_iter()
        .map(|key| BlsPublicKey::new(key.try_into().expect("48-byte key")))
        .collect();
    SyncCommittee::new(
        keys.as_slice().try_into().expect("512 keys"),
        BlsPublicKey::new(
            hex_bytes(text(value, "aggregate_pubkey"))
                .try_into()
                .expect("48-byte aggregate key"),
        ),
    )
}

fn roots<const N: usize>(value: &Value, key: &str) -> [Root; N] {
    hex_list(value, key)
        .into_iter()
        .map(|root| <Root>::try_from(root.as_slice()).expect("32-byte root"))
        .collect::<Vec<_>>()
        .try_into()
        .expect("branch length")
}

/// Parse a beacon `/light_client/bootstrap` JSON response (`{version, data}`).
#[must_use]
pub fn bootstrap_from_beacon_json(response: &Value) -> EthereumNativeLightClientBootstrapV1 {
    let fork = fork_from_version(response);
    let data = field(response, "data");
    let electra = matches!(fork, EthereumFork::Electra | EthereumFork::Fulu);
    EthereumNativeLightClientBootstrapV1::from_native(&LightClientBootstrap {
        header: light_client_header_from_json(field(data, "header"), fork),
        current_sync_committee: committee_from_json(field(data, "current_sync_committee")),
        current_sync_committee_branch: if electra {
            CurrentSyncCommitteeBranch::Electra(roots(data, "current_sync_committee_branch"))
        } else {
            CurrentSyncCommitteeBranch::PreElectra(roots(data, "current_sync_committee_branch"))
        },
    })
}

/// Parse one beacon light-client update or finality update JSON object (`{version, data}`).
///
/// The finalized header is decoded with the fork its slot has in `schedule`, which may be
/// earlier than the attested header's `version`.
#[must_use]
pub fn update_from_beacon_json(
    response: &Value,
    schedule: &ForkSchedule,
) -> EthereumNativeLightClientUpdateV1 {
    let fork = fork_from_version(response);
    let data = field(response, "data");
    let electra = matches!(fork, EthereumFork::Electra | EthereumFork::Fulu);
    let finalized = field(data, "finalized_header");
    let finalized_slot = decimal(field(finalized, "beacon"), "slot");
    let finalized_fork = schedule
        .fork_at_slot(finalized_slot)
        .expect("finalized slot is after Altair")
        .0;
    let next_sync_committee =
        data.get("next_sync_committee")
            .map(|committee| NextSyncCommitteeProof {
                committee: committee_from_json(committee),
                branch: if electra {
                    NextSyncCommitteeBranch::Electra(roots(data, "next_sync_committee_branch"))
                } else {
                    NextSyncCommitteeBranch::PreElectra(roots(data, "next_sync_committee_branch"))
                },
            });
    let aggregate = field(data, "sync_aggregate");
    EthereumNativeLightClientUpdateV1::from_native(&LightClientUpdate {
        attested_header: light_client_header_from_json(field(data, "attested_header"), fork),
        next_sync_committee,
        finalized_header: light_client_header_from_json(finalized, finalized_fork),
        finality_branch: if electra {
            FinalityBranch::Electra(roots(data, "finality_branch"))
        } else {
            FinalityBranch::PreElectra(roots(data, "finality_branch"))
        },
        sync_aggregate: SyncAggregate::new(
            hex_bytes(text(aggregate, "sync_committee_bits"))
                .try_into()
                .expect("64-byte bitvector"),
            BlsSignature::new(
                hex_bytes(text(aggregate, "sync_committee_signature"))
                    .try_into()
                    .expect("96-byte signature"),
            ),
        ),
        signature_slot: decimal(data, "signature_slot"),
    })
}

/// Re-encode an `eth_getBlockByNumber` result as its RLP header (London through Prague fields,
/// in consensus order; optional trailing fields are included when present).
#[must_use]
pub fn header_rlp_from_rpc_json(block: &Value) -> Vec<u8> {
    let data = |key: &str| rlp_encode_bytes(&hex_bytes(text(block, key)));
    let quantity = |key: &str| rlp_encode_bytes(&quantity_bytes(text(block, key)));
    let mut fields = vec![
        data("parentHash"),
        data("sha3Uncles"),
        data("miner"),
        data("stateRoot"),
        data("transactionsRoot"),
        data("receiptsRoot"),
        data("logsBloom"),
        quantity("difficulty"),
        quantity("number"),
        quantity("gasLimit"),
        quantity("gasUsed"),
        quantity("timestamp"),
        data("extraData"),
        data("mixHash"),
        data("nonce"),
        quantity("baseFeePerGas"),
    ];
    for (key, is_quantity) in [
        ("withdrawalsRoot", false),
        ("blobGasUsed", true),
        ("excessBlobGas", true),
        ("parentBeaconBlockRoot", false),
        ("requestsHash", false),
    ] {
        if block.get(key).is_some() {
            fields.push(if is_quantity {
                quantity(key)
            } else {
                data(key)
            });
        }
    }
    rlp_encode_list(&fields)
}

/// Re-encode an `eth_getBlockReceipts` entry in its receipts-trie form.
#[must_use]
pub fn receipt_from_rpc_json(receipt: &Value) -> Vec<u8> {
    let logs = field(receipt, "logs")
        .as_array()
        .expect("logs array")
        .iter()
        .map(|log| EthereumLogV1 {
            address: hex_bytes(text(log, "address"))
                .try_into()
                .expect("20-byte address"),
            topics: hex_list(log, "topics")
                .into_iter()
                .map(|topic| topic.try_into().expect("32-byte topic"))
                .collect(),
            data: hex_bytes(text(log, "data")),
        })
        .collect();
    let parsed = EthereumReceiptV1 {
        tx_type: u8::try_from(quantity_u64(text(receipt, "type"))).expect("receipt type"),
        success: quantity_u64(text(receipt, "status")) == 1,
        cumulative_gas_used: quantity_u64(text(receipt, "cumulativeGasUsed")),
        logs,
    };
    let bloom: [u8; 256] = hex_bytes(text(receipt, "logsBloom"))
        .try_into()
        .expect("256-byte bloom");
    encode_receipt(&parsed, &bloom)
}

/// Parse the proof node list of an `eth_getProof` field.
#[must_use]
pub fn mpt_proof_from_rpc_json(value: &Value, key: &str) -> EthereumNativeMptProofV1 {
    EthereumNativeMptProofV1 {
        nodes: hex_list(value, key),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ethereum_native::FINALITY_PARTICIPANT_THRESHOLD;

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn synthetic_committees_are_deterministic_and_valid() {
        assert_send_sync::<SyntheticBeaconChainV1>();
        let chain = SyntheticBeaconChainV1::mainnet();
        let committee = chain.committee(1_868);
        assert_eq!(committee, chain.committee(1_868));
        assert_ne!(committee, chain.committee(1_869));
        let native = committee.to_native().expect("wire committee converts");
        native
            .validate()
            .expect("every synthetic key passes KeyValidate");
        assert_ne!(
            SyntheticBeaconChainV1::new([1; 32]).committee(1_868),
            committee
        );
    }

    #[test]
    fn synthetic_updates_verify_with_the_production_checks() {
        let chain = SyntheticBeaconChainV1::mainnet();
        let schedule = chain.profile().schedule().expect("mainnet");
        let slot = 1_868 * SLOTS_PER_PERIOD + 500;
        let update = chain.finality_update_for(chain.synthetic_execution(slot - 70), slot);
        let native = update.to_native().expect("wire update converts");
        native.verify_structure(&schedule).expect("structure");
        native
            .verify_signature(
                &chain.committee(1_868).to_native().expect("committee"),
                &schedule,
            )
            .expect("synthetic signature verifies");
        let bootstrap = chain.bootstrap_wire(slot, &chain.synthetic_execution(slot));
        bootstrap
            .to_native()
            .expect("wire bootstrap converts")
            .verify(&schedule)
            .expect("bootstrap branch verifies");
        let sparse = chain.update(&SyntheticUpdateSpecV1 {
            participants: FINALITY_PARTICIPANT_THRESHOLD,
            ..SyntheticUpdateSpecV1 {
                attested_slot: slot - 1,
                finalized_slot: slot - 10,
                finalized_execution: chain.synthetic_execution(slot - 10),
                signature_slot: slot,
                include_next_committee: true,
                participants: SYNC_COMMITTEE_SIZE,
                signing_period: None,
                next_committee_period: None,
            }
        });
        let native = sparse.to_native().expect("converts");
        assert_eq!(
            native.sync_aggregate.participant_count(),
            FINALITY_PARTICIPANT_THRESHOLD
        );
        native.verify_structure(&schedule).expect("structure");
        native
            .verify_signature(
                &chain.committee(1_868).to_native().expect("committee"),
                &schedule,
            )
            .expect("threshold signature verifies");
    }

    #[test]
    fn bootstrap_slot_tracks_wall_clock_time() {
        let chain = SyntheticBeaconChainV1::mainnet();
        let now_ms = 1_790_522_303_000;
        let slot = chain.slot_at_unix_ms(now_ms);
        assert!(chain.slot_unix_ms(slot) <= now_ms);
        assert!(chain.slot_unix_ms(slot + 1) > now_ms);
        let bootstrap = chain.bootstrap_at_unix_ms(now_ms);
        let decoded = SccpLcBootstrapDataV1::from_frame(&bootstrap.bytes).expect("frame");
        let SccpLcBootstrapDataV1::Ethereum(wire) = decoded else {
            panic!("an Ethereum bootstrap");
        };
        assert_eq!(wire.header.beacon.slot, slot);
    }

    #[test]
    fn signature_slot_for_starts_at_or_after_the_execution_time() {
        let chain = SyntheticBeaconChainV1::mainnet();
        let slot = 1_868 * SLOTS_PER_PERIOD + 500;
        let aligned = chain.synthetic_execution(slot);
        assert_eq!(chain.signature_slot_for(&aligned), slot);
        let inside = SyntheticExecutionHeaderV1 {
            timestamp: aligned.timestamp + 5,
            ..aligned
        };
        assert_eq!(chain.signature_slot_for(&inside), slot + 1);
        let update = chain.finality_update_for(inside, chain.signature_slot_for(&inside));
        let native = update.to_native().expect("converts");
        assert!(
            chain.slot_unix_ms(native.signature_slot)
                >= native
                    .finalized_header
                    .authenticated_execution_block()
                    .expect("payload")
                    .timestamp
                    * 1_000
        );
    }

    #[test]
    fn execution_helpers_build_linked_headers_receipts_and_history_state() {
        let genesis = execution_header_rlp(&SyntheticBlockFieldsV1 {
            parent_hash: [0; 32],
            number: 10,
            timestamp: 1_000,
            state_root: [1; 32],
            receipts_root: [2; 32],
        });
        let chain = header_chain(&genesis, 3);
        assert_eq!(chain.len(), 3);
        let first = crate::ethereum_source::decode_execution_header(&chain[0]).expect("decodes");
        assert_eq!(first.parent_hash, execution_of(&genesis).block_hash);
        assert_eq!(first.number, 11);
        let receipts = vec![
            successful_receipt(vec![voided_log([3; 20], [4; 32], 5)]),
            successful_receipt(Vec::new()),
        ];
        let (root, proof) = receipt_root_and_proof(&receipts, 0);
        let opened = crate::ethereum_source::verify_mpt_inclusion(
            root,
            &rlp_encode_u64(0),
            &proof,
            crate::ethereum_source::EthereumMptRoleV1::Receipt,
        )
        .expect("opens");
        assert_eq!(
            crate::ethereum_source::decode_receipt(&opened).expect("decodes"),
            receipts[0]
        );
        let (state_root, history) = history_state(&ETHEREUM_MAINNET, 123, [9; 32]);
        assert_ne!(state_root, [0; 32]);
        assert!(!history.account_proof.nodes.is_empty());
    }

    #[test]
    fn rpc_hex_helpers_are_strict() {
        assert_eq!(hex_bytes("0x0a0b"), vec![10, 11]);
        assert_eq!(quantity_bytes("0x0"), Vec::<u8>::new());
        assert_eq!(quantity_bytes("0x100"), vec![1, 0]);
        assert_eq!(quantity_u64("0x18dca17"), 26_069_527);
        assert_eq!(le_u256_from_decimal("258")[..2], [2, 1]);
    }
}
