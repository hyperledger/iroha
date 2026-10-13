//! Executable model of the SCCP destination contracts (`specs/sccp.md` §5.1, revision 5).
//!
//! One [`Destination`] is one deployed route revision on one chain: its immutables
//! ([`DeploymentV1`], §5.1.1), its state ([`DestinationStateV1`]) and its entry points:
//!
//! | Entry point | Model | Spec |
//! |---|---|---|
//! | `submitCheckpoints` | [`Destination::submit_checkpoints`] | §5.1.2, §5.1.3 |
//! | `finalizeFromTaira`, `finalizeFromCheckpoint` | [`Destination::finalize`] | §5.1.4, §5.1.5 |
//! | `applyControl`, `applyControlFromCheckpoint` | [`Destination::apply_control`] | §5.1.6 |
//! | `voidExpired`, `voidExpiredFromCheckpoint` | [`Destination::void_expired`] | §5.1.8 |
//! | `voidFrozen` | [`Destination::void_frozen`] | §5.1.8 |
//!
//! The TON minter takes the same calls as messages (`sccp_checkpoint`, `sccp_finalize`, …,
//! §5.3.3).
//!
//! The model is the Rust reference for both contracts and the behavioural twin of the
//! independent Python model (`scripts/sccp_reference/destination.py`): for the same call it
//! gives the same outcome, events and state, and it checks in the same order. The shared
//! scenario tables (`fixtures/sccp/committee_transitions_v1.json`, `control_v1.json`) are
//! runs of it.
//!
//! **Calls are atomic.** An entry point returns [`CallOutcome`] with the events it emitted, or
//! a [`DestinationError`] and then nothing has changed, as when an EVM call reverts. A latch,
//! and a rotation that leaves the destination not `Live`, are not errors: they persist, stop
//! `submitCheckpoints` and are reported as [`CallOutcome::stopped`].
//!
//! **Flavours.** [`DestinationFlavor::Evm`] takes the committee and each signer's `y` from
//! calldata, keeps every checkpoint and batches up to 16 certificates.
//! [`DestinationFlavor::Ton`] reads the committee keys from storage, keeps three checkpoint
//! slots, needs `next_keys` for a key-changing rotation and voids a frozen range inside one
//! bucket. The flavour is bound to the profile ([`DeploymentV1::network`]), which fixes the
//! lane, the payload domain and the recipient codec: an EVM destination is deployed on
//! Ethereum or BSC and a TON destination on TON ([`DeploymentError::Flavor`] otherwise). A
//! real contract computes its lane and its destination word from its own chain and address,
//! so a row of any other pair could not be replayed against it.
//!
//! **Check order** (§5.1.2 "Check order and errors", §5.1.3). `submitCheckpoints` checks
//! `TooManyCertificates`, an empty batch (`NothingToDo`), `Live`, then each certificate. An
//! inline entry point obtains `X` first (`VerifyCertificate`, then V1–V3 → `LatchRequired`)
//! and checks `Live` after it. A checkpoint entry point checks the length of `X`
//! (`BadHeader`), the stored id (`UnknownCheckpoint`), X1–X7 with `ACTIVE` (`BadHeader`),
//! `Live`, then eligibility (`CommitteeNotAccepted`). `voidFrozen` checks its range before
//! `Frozen`. A failed `Live` check answers `Equivocated` when latched and
//! `CommitteeNotAccepted` when expired. A TON finalize or void checks the payload and its
//! recipient before it obtains `X` (§5.3.4: the required value of the message depends on the
//! payload nonce), where EVM checks them after `X`, `Live`, the pause and the block
//! reference. On both flavours the deadline is checked before the leaf path.
//!
//! **Time.** `now_ms` is the destination clock, `block.timestamp × 1000` on EVM and
//! `now() × 1000` on TON (§0), so a real destination only ever sees whole seconds. The model
//! is a function of any `now_ms`.
//!
//! **Arithmetic** (§5.1.2). No call aborts for arithmetic and no value wraps: the two time
//! sums saturate, a `voidFrozen` range and the supply cap are compared without forming a
//! value above their width, and X6 bounds what a rotation adds to. The two counters have a
//! top: `opCount` only increments and saturates at `2^64 − 1` ([`bumped_op_count`], §5.1.1).
//! A sender's source nonces are `0 ..= 2^64 − 2`, so a stored next nonce of `2^64 − 1` is
//! exhausted ([`next_source_nonce`], §5.1.7).
//!
//! **Signatures** (§5.1.3 steps 10–11). Both flavours go through
//! `iroha_crypto::bls::consensus`, the only API that hashes under `DST_SIG`, and each reports
//! what its contract can observe:
//!
//! - **EVM** adds the signer points with `G1ADD`, which accepts any point of the curve, and
//!   passes the sum to `PAIRING_CHECK`, which requires its inputs to be in their subgroups
//!   ([`verify_certificate_by_aggregate`]). A signer point off the curve, then `apk = O`,
//!   answer `BadCommittee`, before `σ` is read as a point. An aggregate outside G1 answers
//!   `BadSignature`. The contract never sees a single key: signer keys outside G1 whose
//!   components outside the subgroup cancel are accepted when the pairing holds.
//! - **TON** has one verdict, the result of `BLS_FASTAGGREGATEVERIFY`, and `false` throws
//!   `BadSignature` (§5.3.4 item 5): a stored signer key that is no canonical point, is the
//!   identity or lies outside G1, an identity aggregate, a `σ` that is no point of G2 and a
//!   failed pairing ([`verify_certificate`], which applies `KeyValidate` to every signer
//!   key).
//!
//! A committee root admitted by Taira holds validated keys only (§3.8), so the two flavours
//! differ on no certificate under a genuine root.
//!
//! The Acton harness and the shared fixture rows pin the opcode's refusal of a signer
//! key that is the identity, is no point or lies outside G1.
//!
//! Not modelled: the chain-identity check (`WrongChain`), the ERC-20 and Jetton surfaces,
//! value and fee rules, and `transferToTaira` (§5.1.7) as an entry point, because the model
//! keeps no balances of senders. The source nonce is checked by [`next_source_nonce`];
//! [`check_ton_burn_payload`] models the complete wrapper and recipient admission that both
//! TON wallet and minter perform before changing balances or forwarding a notification.
//!
//! TON's asynchronous bucket round trip and bounce recovery of §5.3.4 (`pending_supply`,
//! `sccp_consume`, `sccp_unconsume` and `retries`) are covered by the contract Acton harness,
//! including that a bounce never decrements `opCount` and a repeated finalization counts
//! again. This model gives a TON finalize or void the outcome of the minter's own checks and
//! consumes its nonce at once. Two error names are therefore model-only on TON and occur in
//! no TON row of the shared tables: `AlreadyConsumed` stands for the bucket's
//! `sccp_already_consumed` or `sccp_range_rejected` reply, on which the minter throws nothing.
//! `TooManyCertificates` needs a batch that a TON harness never sends, since one
//! `sccp_checkpoint` message carries one certificate.

use std::collections::{BTreeMap, BTreeSet};

use iroha_data_model::bridge::SccpNetworkV1;

pub use super::destination_abi::DestinationError;
use super::{
    committee::{
        CheckpointOutcomeV1, CommitteeError, CommitteeStateV1, EVM_SIGNATURE_LEN, FP_LEN,
        IDENTITY_KEY, IDENTITY_SIGNATURE, IDENTITY_SIGNATURE_EVM, KEY_LEN, RotationV1,
        SIGNATURE_LEN, ViolationV1, committee_keys, committee_root, fp_is_canonical, quorum,
        signature_from_evm192, signature_to_evm192, signer_coordinates_name_a_finite_point,
        signer_indices, signer_key_flags_match, signer_point_is_on_curve, signer_point_sum,
        signer_ys, successor_keys_match,
    },
    constants::{
        MAX_BLOCK_LEAVES, MAX_TAIRA_ACCOUNT_BYTES, MAX_VOID_FROZEN_RANGE_EVM,
        MAX_VOID_FROZEN_RANGE_TON,
    },
    control::{
        ControlLeafV1, applied_fast_pause_until_ms, check_control_constraints,
        control_leaf_unchecked,
    },
    destination_abi::{
        EVENT_CERTIFICATE, EVENT_CHECKPOINTED, EVENT_COMMITTEE_ROTATED, EVENT_CONTROL_APPLIED,
        EVENT_FINALIZED, EVENT_LATCHED, EVENT_VOIDED, TOPIC_CERTIFICATE, TOPIC_CHECKPOINTED,
        TOPIC_COMMITTEE_ROTATED, TOPIC_CONTROL_APPLIED, TOPIC_FINALIZED, TOPIC_LATCHED,
        TOPIC_VOIDED,
    },
    finality::{
        CertificateError, MAX_VALIDITY_MS, QcFixedV1, SccpFinalityHeaderV1, X_LEN, check_signers,
        checkpoint_id, verify_certificate, verify_certificate_by_aggregate,
    },
    hashes::{history_leaf, message_id, payload_hash, transfer_leaf},
    history::verify_history_inclusion,
    merkle::verify_block_inclusion,
    network::{domain, lane_bytes, route_id},
    payload::{PayloadError, SccpTransferPayloadV1},
    ton_cell::{Cell, TON_BURN_TO_TAIRA_OP, TonCellError, parse_snake_bytes},
};

/// `MAX_CERTIFICATES_PER_CALL` (§3.9): the largest `submitCheckpoints` batch.
pub const MAX_CERTIFICATES_PER_CALL: usize = 16;
/// The checkpoint slots of a TON destination (§3.9, §5.1.3).
pub const TON_CHECKPOINT_SLOTS: usize = 3;
/// `MAX_INIT_SLACK_MS` (§3.9): the slack of the constructor and `sccp_init` bound on the
/// pinned `untilMs`, one hour.
pub const MAX_INIT_SLACK_MS: u64 = 3_600_000;
/// Nonces per TON consumed bucket: nonce `n` lives in bucket `n >> 9`, and one
/// `sccp_void_frozen` range stays inside one bucket (§5.1.8).
pub const TON_BUCKET_NONCES: u64 = 512;

/// Offset of `height` in `X` (§3.6). A checkpoint lookup reads it before `X` is parsed.
const X_OFFSET_HEIGHT: usize = 48;
/// Length of the lane preimage `network_bytes(sora-taira) ‖ network_bytes(own)` (§2.2).
const LANE_LEN: usize = 66;

const _: () = assert!(MAX_VOID_FROZEN_RANGE_TON == TON_BUCKET_NONCES);
const _: () = assert!(X_OFFSET_HEIGHT + 8 <= X_LEN);

// ---------------------------------------------------------------------------------------------
// Deployment (§5.1.1)
// ---------------------------------------------------------------------------------------------

/// Which contract family a destination is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DestinationFlavor {
    /// The EVM contract (`SccpTairaXor.sol`): the committee and each signer's `y` arrive in
    /// calldata, every checkpoint is kept, and `submitCheckpoints` takes a batch.
    Evm,
    /// The TON minter: the committee keys are stored, three checkpoints are kept, and a
    /// key-changing rotation brings `next_keys`.
    Ton,
}

impl DestinationFlavor {
    /// The flavour name of the shared vectors: `evm` or `ton`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Evm => "evm",
            Self::Ton => "ton",
        }
    }

    /// How many checkpoints the destination keeps: all of them on EVM, three on TON.
    #[must_use]
    pub const fn checkpoint_slots(self) -> Option<usize> {
        match self {
            Self::Evm => None,
            Self::Ton => Some(TON_CHECKPOINT_SLOTS),
        }
    }

    /// The largest `count` of one `voidFrozen` call: 256 on EVM, 512 (one bucket) on TON.
    #[must_use]
    pub const fn max_void_frozen_range(self) -> u64 {
        match self {
            Self::Evm => MAX_VOID_FROZEN_RANGE_EVM,
            Self::Ton => MAX_VOID_FROZEN_RANGE_TON,
        }
    }
}

unit_error! {
    /// Why a deployment is not one a destination can be constructed with (§5.2.1, §5.3.1).
    /// The contracts answer `BadConfig`.
    pub enum DeploymentError {
        /// The profile is not Ethereum, BSC or TON.
        Network => "the destination profile is not Ethereum, BSC or TON",
        /// The flavour is not the one of the profile: EVM on Ethereum or BSC, TON on TON.
        Flavor => "an EVM destination is deployed on Ethereum or BSC and a TON one on TON",
        /// `routeRevision` is zero.
        ZeroRevision => "the route revision must be nonzero",
        /// `maxWrappedSupply` is zero.
        ZeroSupplyCap => "the supply cap must be nonzero",
        /// The pin has generation 0, a zero committee root or start height 0.
        Pin => "the pin needs a generation, a committee root and a start height of at least 1",
        /// A TON deployment does not store a valid committee, in canonical order, whose root
        /// is the pinned root.
        TonKeys => "a TON deployment stores the keys of the pinned committee root",
        /// The pinned `untilMs` is not after the deployment time, or is more than
        /// `MAX_VALIDITY_MS + MAX_INIT_SLACK_MS` after it.
        UntilMs => "the pinned untilMs is outside (now, now + MAX_VALIDITY_MS + MAX_INIT_SLACK_MS]",
    }
}

/// Whether a constructor (EVM) or `sccp_init` (TON) at `now_ms` accepts the pinned
/// `until_ms` (§5.2.1, §5.3.1): `now_ms < until_ms ≤ now_ms + MAX_VALIDITY_MS +
/// MAX_INIT_SLACK_MS`.
///
/// The bound is compared as a difference, so no value above `u64` is formed. A contract
/// answers `BadConfig` otherwise.
#[must_use]
pub const fn init_until_ms_is_valid(now_ms: u64, until_ms: u64) -> bool {
    now_ms < until_ms && until_ms - now_ms <= MAX_VALIDITY_MS + MAX_INIT_SLACK_MS
}

/// The immutables of one destination (§5.1.1).
///
/// The bound of the constructor and of `sccp_init` on `pin_until_ms` depends on the
/// deployment time, which [`Destination::new`] does not take:
/// [`DeploymentV1::check_init_time`] checks it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeploymentV1 {
    /// The contract family.
    pub flavor: DestinationFlavor,
    /// `tairaNetworkId`: Taira's `NetworkId`.
    pub taira_network_id: [u8; 32],
    /// `consensusInstance`: Taira's `I`.
    pub consensus_instance: [u8; 32],
    /// The profile of the destination chain: it fixes the lane, the payload domain, the
    /// route id and the recipient codec.
    pub network: SccpNetworkV1,
    /// The destination word of §3.4: `word(address)` of the EVM contract, or the account id
    /// of the TON minter.
    pub destination_word: [u8; 32],
    /// `routeRevision`; nonzero.
    pub route_revision: u32,
    /// `maxWrappedSupply` in token units (= Taira units); nonzero.
    pub max_wrapped_supply: u128,
    /// The pinned generation; at least 1.
    pub pin_generation: u64,
    /// The pinned committee root; nonzero.
    pub pin_root: [u8; 32],
    /// The first height of the pinned generation; at least 1.
    pub pin_start_height: u64,
    /// The trust deadline of the pinned generation.
    pub pin_until_ms: u64,
    /// The keys of the pinned committee in canonical order. A TON destination stores them.
    /// An EVM destination never reads them: a deployment may carry them for reference.
    pub pin_keys: Option<Vec<[u8; KEY_LEN]>>,
}

impl DeploymentV1 {
    /// The committee state a constructor or `sccp_init` leaves: `cur = {root, generation,
    /// start, high = start − 1, untilMs}`, not latched.
    ///
    /// Returns `None` for a pin no destination deploys ([`CommitteeStateV1::from_pin`]).
    #[must_use]
    pub fn initial_committee(&self) -> Option<CommitteeStateV1> {
        CommitteeStateV1::from_pin(
            self.pin_generation,
            self.pin_root,
            self.pin_start_height,
            self.pin_until_ms,
        )
    }

    /// The check of the constructor (EVM) and of `sccp_init` (TON) on the pinned `untilMs`
    /// at the deployment time `now_ms` ([`init_until_ms_is_valid`]).
    ///
    /// # Errors
    /// [`DeploymentError::UntilMs`] when the pinned `untilMs` is outside the bound.
    pub const fn check_init_time(&self, now_ms: u64) -> Result<(), DeploymentError> {
        if init_until_ms_is_valid(now_ms, self.pin_until_ms) {
            Ok(())
        } else {
            Err(DeploymentError::UntilMs)
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Call inputs (§5.2.2, §5.3.2)
// ---------------------------------------------------------------------------------------------

/// A Taira certificate as an entry point takes it, in both wire forms.
///
/// `qc`, `header`, `signature`, `committee` and `signer_ys` are the fields of the EVM struct
/// `TairaCertificateV1` (§5.2.2). A TON destination reads `qc` and `header` with
/// `ton_signature`: its `TairaCert` cell (§5.3.2) carries `signers` as the last four bytes of
/// `qc`, the `QcFixed` cell as the bytes before them, and `XHead ‖ XTail = header`; the
/// committee comes from storage. A destination ignores the fields of the other flavour, so
/// one value drives both models.
///
/// Every field is raw bytes of any length: the destination checks the lengths
/// (`VerifyCertificate` step 1).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TairaCertificateV1 {
    /// `QC_FIXED`: 116 bytes.
    pub qc: Vec<u8>,
    /// The finality header `X`: 221 bytes.
    pub header: Vec<u8>,
    /// EVM: the aggregate signature as four 48-byte limbs `x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1`.
    pub signature: Vec<u8>,
    /// EVM: the `48n` bytes of the committee's compressed keys in canonical order.
    pub committee: Vec<u8>,
    /// EVM: `signerYs`, the `y` of every signer in ascending index order, 48 bytes each.
    pub signer_ys: Vec<u8>,
    /// TON: the compressed aggregate signature, 96 bytes.
    pub ton_signature: Vec<u8>,
}

impl TairaCertificateV1 {
    /// The certificate of `header` in both wire forms, from what Taira serves: the fields of
    /// the `CommitQC`, the compressed aggregate signature and the keys of the signing
    /// committee in canonical order.
    ///
    /// Returns `None` when `signature` is not the canonical encoding of a point of the curve,
    /// or when `qc.signers` names a key outside `keys` or a key that is not a finite point of
    /// the curve.
    #[must_use]
    pub fn new(
        qc: &QcFixedV1,
        header: &SccpFinalityHeaderV1,
        signature: &[u8; SIGNATURE_LEN],
        keys: &[[u8; KEY_LEN]],
    ) -> Option<Self> {
        Some(Self {
            qc: qc.encode().to_vec(),
            header: header.as_bytes().to_vec(),
            signature: signature_to_evm192(signature)?.to_vec(),
            committee: keys.concat(),
            signer_ys: signer_ys(keys, qc.signers)?,
            ton_signature: signature.to_vec(),
        })
    }
}

/// Borrowed authority for the destination's exact certificate verification kernel.
///
/// The caller obtains the network, instance, committee (including its latch) and checkpoint
/// lookup from one selected destination state. Construction authenticates no remote source;
/// it checks the TON key/root relation so a supplied key slice cannot substitute authority.
/// `Live` and entry-point violation/update rules remain the caller's responsibility.
#[derive(Clone, Copy, Debug)]
pub struct CertificateAuthorityV1<'a> {
    flavor: DestinationFlavor,
    taira_network_id: &'a [u8; 32],
    consensus_instance: &'a [u8; 32],
    committee: &'a CommitteeStateV1,
    ton_keys: Option<&'a [[u8; KEY_LEN]]>,
}
/// The result of the common certificate kernel, before entry-point state transitions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CertificateVerificationV1 {
    /// Verified current-generation header.
    pub header: SccpFinalityHeaderV1,
    /// `keccak256(X)` of that header.
    pub checkpoint_id: [u8; 32],
    /// Whether the full cryptographic path ran, requiring certificate publication.
    pub full_path: bool,
}
impl<'a> CertificateAuthorityV1<'a> {
    /// Borrow the actual selected destination authority. EVM obtains keys from each certificate;
    /// TON requires the stored canonical keys and their exact current committee root.
    ///
    /// # Errors
    /// Returns `BadCommittee` for absent, substituted or malformed TON committee keys.
    pub fn new(
        flavor: DestinationFlavor,
        taira_network_id: &'a [u8; 32],
        consensus_instance: &'a [u8; 32],
        committee: &'a CommitteeStateV1,
        ton_keys: Option<&'a [[u8; KEY_LEN]]>,
    ) -> Result<Self, DestinationError> {
        if flavor == DestinationFlavor::Ton
            && !ton_keys.is_some_and(|keys| successor_keys_match(keys, &committee.root))
        {
            return Err(DestinationError::BadCommittee);
        }
        Ok(Self {
            flavor,
            taira_network_id,
            consensus_instance,
            committee,
            ton_keys,
        })
    }
    /// Verify steps 1–12 of §5.1.3 against this borrowed authority.
    /// `checkpoint_at` reads the selected destination's stored id at the requested height.
    /// A stored matching id takes the mandatory cheap path only after checks 1–6.
    ///
    /// This operation has no effects and does not assert `Live` or accept a state transition.
    /// Apply the entry point's committee rules to the returned header before using it.
    ///
    /// # Errors
    /// Returns the same first failed certificate check as the destination entry points.
    pub fn verify(
        &self,
        certificate: &TairaCertificateV1,
        checkpoint_at: impl FnOnce(u64) -> Option<[u8; 32]>,
    ) -> Result<CertificateVerificationV1, DestinationError> {
        let cur = self.committee;
        let flavor = self.flavor;

        // 1. Exact lengths: `QC_FIXED`, `X`, the signature, and on EVM the committee and
        //    `signerYs`. TON reads the committee from storage.
        let qc = QcFixedV1::parse(&certificate.qc).map_err(|_| DestinationError::BadCertificate)?;
        let raw_header = <&[u8; X_LEN]>::try_from(&certificate.header[..])
            .map_err(|_| DestinationError::BadHeader)?;
        let calldata_keys;
        let (keys, signature, ys): (&[[u8; KEY_LEN]], &[u8], &[[u8; FP_LEN]]) = match flavor {
            DestinationFlavor::Evm => {
                if certificate.signature.len() != EVM_SIGNATURE_LEN {
                    return Err(DestinationError::BadCertificate);
                }
                calldata_keys =
                    committee_keys(&certificate.committee).ok_or(DestinationError::BadCommittee)?;
                let (ys, rest) = certificate.signer_ys.as_chunks::<FP_LEN>();
                if !rest.is_empty() || Some(ys.len()) != quorum(calldata_keys.len()) {
                    return Err(DestinationError::BadCertificate);
                }
                (
                    calldata_keys.as_slice(),
                    certificate.signature.as_slice(),
                    ys,
                )
            }
            DestinationFlavor::Ton => {
                if certificate.ton_signature.len() != SIGNATURE_LEN {
                    return Err(DestinationError::BadCertificate);
                }
                (
                    self.ton_keys.unwrap_or_default(),
                    certificate.ton_signature.as_slice(),
                    <&[[u8; FP_LEN]]>::default(),
                )
            }
        };

        // 2. `X` is a header of this Taira network with `ACTIVE` set.
        let header = SccpFinalityHeaderV1::parse(raw_header)
            .ok()
            .filter(|header| header.network_id() == *self.taira_network_id && header.is_active())
            .ok_or(DestinationError::BadHeader)?;

        // 3. Classification: only a certificate of the current generation goes on.
        if !cur.is_current(&header) {
            return Err(DestinationError::CommitteeNotAccepted);
        }

        // 4. EVM: the calldata committee is the current one.
        if flavor == DestinationFlavor::Evm && committee_root(keys) != Some(cur.root) {
            return Err(DestinationError::BadCommittee);
        }

        // 5. The signer set: no spare bit and exactly `q` signers.
        check_signers(qc.signers, keys.len()).map_err(CertificateError::destination_error)?;
        let indices =
            signer_indices(qc.signers, keys.len()).ok_or(DestinationError::BadCertificate)?;
        let signer_keys: Vec<[u8; KEY_LEN]> = indices.iter().map(|index| keys[*index]).collect();

        // 6. Encodings, before the cheap path and before any curve operation. Both flavours
        //    refuse the identity signature first. EVM then requires every signer `y` below
        //    `p`, every limb of `σ` below `p`, and for every signer key its flags, an `x`
        //    below `p` and coordinates other than `(0, 0)`.
        match flavor {
            DestinationFlavor::Evm => {
                if *signature == IDENTITY_SIGNATURE_EVM {
                    return Err(DestinationError::BadSignature);
                }
                if !ys.iter().all(fp_is_canonical) {
                    return Err(DestinationError::BadCommittee);
                }
                let (limbs, _) = signature.as_chunks::<FP_LEN>();
                if !limbs.iter().all(fp_is_canonical) {
                    return Err(DestinationError::BadSignature);
                }
                if !signer_keys.iter().zip(ys).all(|(key, y)| {
                    signer_key_flags_match(key, y) && signer_coordinates_name_a_finite_point(key, y)
                }) {
                    return Err(DestinationError::BadCommittee);
                }
            }
            DestinationFlavor::Ton => {
                if *signature == IDENTITY_SIGNATURE {
                    return Err(DestinationError::BadSignature);
                }
            }
        }

        // 7. The checkpoint id. `R` belongs to the full path.
        let id = checkpoint_id(raw_header);

        // 8. Cheap path (mandatory): a stored `X` is already certified, so its signature is
        //    not checked and it is not published again.
        if checkpoint_at(header.height()) == Some(id) {
            return Ok(CertificateVerificationV1 {
                header,
                checkpoint_id: id,
                full_path: false,
            });
        }

        // 9–11. The aggregate key and the pairing check, as each contract observes them.
        match flavor {
            DestinationFlavor::Evm => {
                // 10. `G1ADD` over the signer points: a point off the curve, then `apk = O`,
                //     answer `BadCommittee` before `σ` is read as a point.
                if !signer_keys
                    .iter()
                    .zip(ys)
                    .all(|(key, y)| signer_point_is_on_curve(key, y))
                {
                    return Err(DestinationError::BadCommittee);
                }
                match signer_point_sum(keys, qc.signers) {
                    Some(sum) if sum != IDENTITY_KEY => {}
                    _ => return Err(DestinationError::BadCommittee),
                }
                // 11. `PAIRING_CHECK` validates its inputs and sees the aggregate key only.
                let compressed = <&[u8; EVM_SIGNATURE_LEN]>::try_from(signature)
                    .ok()
                    .and_then(|limbs| signature_from_evm192(limbs).ok())
                    .ok_or(DestinationError::BadSignature)?;
                verify_certificate_by_aggregate(
                    self.consensus_instance,
                    &certificate.qc,
                    raw_header,
                    &compressed,
                    keys,
                )
                .map_err(CertificateError::destination_error)?;
            }
            DestinationFlavor::Ton => {
                // `BLS_FASTAGGREGATEVERIFY` is one verdict (§5.3.4 item 5): a stored key that
                // is no valid key, an identity aggregate, a `σ` that is no point of G2 and a
                // failed pairing all throw `BadSignature`.
                let compressed = <[u8; SIGNATURE_LEN]>::try_from(signature)
                    .ok()
                    .filter(|signature| signature_to_evm192(signature).is_some())
                    .ok_or(DestinationError::BadSignature)?;
                verify_certificate(
                    self.consensus_instance,
                    &certificate.qc,
                    raw_header,
                    &compressed,
                    keys,
                )
                .map_err(CertificateError::ton_destination_error)?;
            }
        }

        // 12. Report publication to the owner; the caller emits only when the full path ran.
        Ok(CertificateVerificationV1 {
            header,
            checkpoint_id: id,
            full_path: true,
        })
    }
}

/// `CheckpointRefV1`: the header of a stored checkpoint (§5.1.3 "Using a checkpoint").
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CheckpointRefV1 {
    /// `X`: 221 bytes whose `keccak256` the destination stores at `X.height`.
    pub header: Vec<u8>,
}

/// Where an entry point takes its certified header from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertificateSourceV1<'a> {
    /// The inline form (`finalizeFromTaira`, `applyControl`, `voidExpired`): a certificate of
    /// the current generation, verified in the call.
    Inline(&'a TairaCertificateV1),
    /// The checkpoint form (`*FromCheckpoint`): a header the destination already stores.
    Checkpoint(&'a CheckpointRefV1),
}

/// `BlockRefV1`: the block that holds a leaf, relative to a certified header (§5.1.5).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlockRefV1 {
    /// Height of the block.
    pub height: u64,
    /// `sccp_root` of the block.
    pub sccp_root: [u8; 32],
    /// `message_count` of the block.
    pub message_count: u32,
    /// Index of the block's history leaf; 0 when the block is the certified one.
    pub history_index: u64,
    /// History path up to the certified header's `history_root`; empty when the block is the
    /// certified one.
    pub history_path: Vec<[u8; 32]>,
}

/// `MessageProofV1`: a transfer payload with its leaf path (§5.1.5).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MessageProofV1 {
    /// The transfer payload of §3.2.
    pub payload: Vec<u8>,
    /// Index of the transfer leaf in its block.
    pub leaf_index: u32,
    /// Path from the leaf to the block's `sccp_root`.
    pub path: Vec<[u8; 32]>,
    /// The block that holds the leaf.
    pub block: BlockRefV1,
}

/// `ControlProofV1`: the fields of a control leaf with its leaf path (§5.1.6).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ControlProofV1 {
    /// `control_nonce` of the leaf.
    pub control_nonce: u64,
    /// `track` of the leaf: 1 Parliament, 2 fast pause.
    pub track: u8,
    /// `parliament_paused` of the leaf as its raw byte. The EVM ABI and the TON cell carry a
    /// `bool`, which is 0 or 1.
    pub parliament_paused: u8,
    /// `fast_pause_until_ms` of the leaf.
    pub fast_pause_until_ms: u64,
    /// `certificate_id` of the leaf.
    pub certificate_id: [u8; 32],
    /// `effect_hash` of the leaf.
    pub effect_hash: [u8; 32],
    /// Index of the control leaf in its block.
    pub leaf_index: u32,
    /// Path from the leaf to the block's `sccp_root`.
    pub path: Vec<[u8; 32]>,
    /// The block that holds the leaf.
    pub block: BlockRefV1,
}

// ---------------------------------------------------------------------------------------------
// Call outputs (§5.2.2, §5.3.3)
// ---------------------------------------------------------------------------------------------

/// An SCCP event of a destination: an EVM log, or the TON external-out message of the same
/// content. The ERC-20 `Transfer` of a mint is implied by [`Self::Finalized`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DestinationEvent {
    /// `SccpCertificate`: a certificate passed the full verification path (§5.1.3 step 12).
    Certificate {
        /// `X.height`.
        height: u64,
        /// `X.generation`.
        generation: u64,
        /// `QC_FIXED` as presented.
        qc: Vec<u8>,
        /// `X` as presented.
        header: Vec<u8>,
        /// The signature as presented: 192 bytes on EVM, 96 on TON.
        signature: Vec<u8>,
    },
    /// `SccpCheckpointed`: a checkpoint was recorded.
    Checkpointed {
        /// `X.height`.
        height: u64,
        /// `keccak256(X)`.
        id: [u8; 32],
    },
    /// `SccpCommitteeRotated`: a successor generation was installed.
    CommitteeRotated(RotationV1),
    /// `SccpLatched`: a violation V1–V3 latched the destination.
    Latched(ViolationV1),
    /// `SccpControlApplied`: a control leaf set the pause state.
    ControlApplied {
        /// The nonce of the control.
        control_nonce: u64,
        /// The track of the control.
        track: u8,
        /// `parliamentPaused` after the control.
        parliament_paused: bool,
        /// `fastPauseUntilMs` after the control: the leaf's expiry, clamped.
        fast_pause_until_ms: u64,
        /// The certificate that enacted the control on Taira.
        certificate_id: [u8; 32],
    },
    /// `SccpFinalized`: a transfer was minted.
    Finalized {
        /// The message id of the transfer.
        message_id: [u8; 32],
        /// The outbound nonce of the transfer.
        nonce: u64,
        /// The recipient bytes of the payload: 20 bytes on EVM, 36 on TON.
        recipient: Vec<u8>,
        /// The minted amount in token units.
        token_amount: u128,
    },
    /// `SccpVoided`: one nonce was voided. `message_id` is zero for `voidFrozen` on EVM, which
    /// emits one event per nonce.
    Voided {
        /// The message id of the voided transfer, or zero.
        message_id: [u8; 32],
        /// The voided nonce.
        nonce: u64,
    },
    /// TON `sccp_voided` of a frozen range: one message for the whole range.
    VoidedRange {
        /// Always zero: a frozen void names no message.
        message_id: [u8; 32],
        /// The first voided nonce.
        first_nonce: u64,
        /// How many nonces were voided.
        count: u64,
    },
}

impl DestinationEvent {
    /// The EVM event name, which the shared vectors use on every chain.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Certificate { .. } => "SccpCertificate",
            Self::Checkpointed { .. } => "SccpCheckpointed",
            Self::CommitteeRotated(_) => "SccpCommitteeRotated",
            Self::Latched(_) => "SccpLatched",
            Self::ControlApplied { .. } => "SccpControlApplied",
            Self::Finalized { .. } => "SccpFinalized",
            Self::Voided { .. } | Self::VoidedRange { .. } => "SccpVoided",
        }
    }

    /// The canonical signature of the EVM event (§5.2.2).
    #[must_use]
    pub const fn signature(&self) -> &'static str {
        match self {
            Self::Certificate { .. } => EVENT_CERTIFICATE,
            Self::Checkpointed { .. } => EVENT_CHECKPOINTED,
            Self::CommitteeRotated(_) => EVENT_COMMITTEE_ROTATED,
            Self::Latched(_) => EVENT_LATCHED,
            Self::ControlApplied { .. } => EVENT_CONTROL_APPLIED,
            Self::Finalized { .. } => EVENT_FINALIZED,
            Self::Voided { .. } | Self::VoidedRange { .. } => EVENT_VOIDED,
        }
    }

    /// `topic0` of the EVM event (§5.2.2).
    #[must_use]
    pub const fn topic0(&self) -> [u8; 32] {
        match self {
            Self::Certificate { .. } => TOPIC_CERTIFICATE,
            Self::Checkpointed { .. } => TOPIC_CHECKPOINTED,
            Self::CommitteeRotated(_) => TOPIC_COMMITTEE_ROTATED,
            Self::Latched(_) => TOPIC_LATCHED,
            Self::ControlApplied { .. } => TOPIC_CONTROL_APPLIED,
            Self::Finalized { .. } => TOPIC_FINALIZED,
            Self::Voided { .. } | Self::VoidedRange { .. } => TOPIC_VOIDED,
        }
    }
}

/// Why `submitCheckpoints` stopped before the end of its batch. The state persists either
/// way and the call succeeds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StopReasonV1 {
    /// A violation V1–V3 latched the destination.
    Latch,
    /// A rotation installed a successor whose deadline has already passed.
    Frozen,
}

impl StopReasonV1 {
    /// The name the shared vectors use: `latch` or `frozen`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Latch => "latch",
            Self::Frozen => "frozen",
        }
    }
}

/// What a successful call did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CallOutcome {
    /// The events of the call, in emission order.
    pub events: Vec<DestinationEvent>,
    /// `submitCheckpoints`: why processing stopped early, if it did.
    pub stopped: Option<StopReasonV1>,
    /// `finalize*`: the message id the call returns.
    pub returned: Option<[u8; 32]>,
}

/// `pauseState()` at a clock value (§5.1.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PauseStateV1 {
    /// The Parliament pause flag.
    pub parliament_paused: bool,
    /// The expiry of the fast pause, or 0.
    pub fast_pause_until_ms: u64,
    /// The nonce of the last applied control, 0 initially.
    pub control_nonce: u64,
    /// The effective pause: `parliamentPaused ∨ now_ms < fastPauseUntilMs`.
    pub effective: bool,
}

// ---------------------------------------------------------------------------------------------
// State (§5.1.1)
// ---------------------------------------------------------------------------------------------

/// The mutable state of a destination (§5.1.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DestinationStateV1 {
    /// `cur` and the latch.
    pub committee: CommitteeStateV1,
    /// TON: the keys of the current committee in canonical order. `None` on EVM.
    pub keys: Option<Vec<[u8; KEY_LEN]>>,
    /// `checkpoint[height] = keccak256(X)`: every height on EVM, at most three on TON.
    pub checkpoints: BTreeMap<u64, [u8; 32]>,
    /// The Parliament pause flag.
    pub parliament_paused: bool,
    /// The expiry of the fast pause, or 0.
    pub fast_pause_until_ms: u64,
    /// The nonce of the last applied control, 0 initially.
    pub control_nonce: u64,
    /// `opCount`: finalizations, voids and applied controls; not checkpoints or rotations. It
    /// saturates at `2^64 − 1` ([`bumped_op_count`]).
    pub op_count: u64,
    /// The consumed outbound nonces.
    pub consumed: BTreeSet<u64>,
    /// The token supply.
    pub total_supply: u128,
    /// The minted balance of every recipient, keyed by the recipient bytes of the payload.
    pub balances: BTreeMap<Vec<u8>, u128>,
}

// ---------------------------------------------------------------------------------------------
// The destination
// ---------------------------------------------------------------------------------------------

/// One destination revision: its deployment and its state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Destination {
    deployment: DeploymentV1,
    /// `lane_bytes(sora-taira, own network)` with the own `tairaNetworkId`.
    lane: [u8; LANE_LEN],
    state: DestinationStateV1,
}

/// What `submitCheckpoints` did with one certificate.
enum CheckpointStep {
    /// The certificate was applied; whether it changed any state.
    Applied(bool),
    /// The certificate latched the destination or froze it: processing stops.
    Stopped(StopReasonV1),
}

/// Which deadline rule a message proof is checked under.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MessageUse {
    /// A mint: `now_ms ≤ deadline_ms`.
    Finalize,
    /// A void: `now_ms > deadline_ms`.
    Void,
}

/// What a destination reads of a transfer payload addressed to it.
struct AddressedPayload {
    nonce: u64,
    deadline_ms: u64,
    amount: u128,
    recipient: Vec<u8>,
}

/// What the body of an entry point gives: for a successful call, why it stopped early and
/// the value it returns.
type CallResult = Result<(Option<StopReasonV1>, Option<[u8; 32]>), DestinationError>;

impl Destination {
    /// Deploy a destination: the state a constructor (EVM) or `sccp_init` (TON) leaves.
    ///
    /// # Errors
    /// In this order: [`DeploymentError::Network`], [`DeploymentError::Flavor`],
    /// [`DeploymentError::ZeroRevision`], [`DeploymentError::ZeroSupplyCap`],
    /// [`DeploymentError::Pin`], and for a TON deployment [`DeploymentError::TonKeys`].
    pub fn new(deployment: DeploymentV1) -> Result<Self, DeploymentError> {
        // The flavour of each profile: the EVM constructor takes `networkTag` 0x41 or 0x42
        // only (§5.2.1), and a TON minter requires `GLOBALID = −239` (§5.3.1).
        let flavor_of_profile = match deployment.network {
            SccpNetworkV1::EthereumMainnet | SccpNetworkV1::BscMainnet => DestinationFlavor::Evm,
            SccpNetworkV1::TonMainnet => DestinationFlavor::Ton,
            _ => return Err(DeploymentError::Network),
        };
        let lane = lane_bytes(
            SccpNetworkV1::SoraTaira,
            deployment.network,
            &deployment.taira_network_id,
        )
        .ok_or(DeploymentError::Network)?;
        if deployment.flavor != flavor_of_profile {
            return Err(DeploymentError::Flavor);
        }
        if deployment.route_revision == 0 {
            return Err(DeploymentError::ZeroRevision);
        }
        if deployment.max_wrapped_supply == 0 {
            return Err(DeploymentError::ZeroSupplyCap);
        }
        let committee = deployment.initial_committee().ok_or(DeploymentError::Pin)?;
        let keys = match deployment.flavor {
            DestinationFlavor::Evm => None,
            DestinationFlavor::Ton => Some(
                deployment
                    .pin_keys
                    .clone()
                    .filter(|keys| successor_keys_match(keys, &deployment.pin_root))
                    .ok_or(DeploymentError::TonKeys)?,
            ),
        };
        Ok(Self {
            deployment,
            lane,
            state: DestinationStateV1 {
                committee,
                keys,
                checkpoints: BTreeMap::new(),
                parliament_paused: false,
                fast_pause_until_ms: 0,
                control_nonce: 0,
                op_count: 0,
                consumed: BTreeSet::new(),
                total_supply: 0,
                balances: BTreeMap::new(),
            },
        })
    }

    /// The immutables.
    #[must_use]
    pub const fn deployment(&self) -> &DeploymentV1 {
        &self.deployment
    }

    /// The current state.
    #[must_use]
    pub const fn state(&self) -> &DestinationStateV1 {
        &self.state
    }

    // -- views ---------------------------------------------------------------------------------

    /// `Live ⇔ ¬equivocated ∧ now_ms ≤ cur.untilMs`.
    #[must_use]
    pub const fn is_live(&self, now_ms: u64) -> bool {
        self.state.committee.is_live(now_ms)
    }

    /// `mintingPaused()`: the effective pause, `parliamentPaused ∨ now_ms < fastPauseUntilMs`.
    /// It blocks minting only.
    #[must_use]
    pub const fn minting_paused(&self, now_ms: u64) -> bool {
        self.state.parliament_paused || now_ms < self.state.fast_pause_until_ms
    }

    /// `pauseState()` at `now_ms`.
    #[must_use]
    pub const fn pause_state(&self, now_ms: u64) -> PauseStateV1 {
        PauseStateV1 {
            parliament_paused: self.state.parliament_paused,
            fast_pause_until_ms: self.state.fast_pause_until_ms,
            control_nonce: self.state.control_nonce,
            effective: self.minting_paused(now_ms),
        }
    }

    /// `checkpointHeader(height)`: `keccak256(X)` of the stored checkpoint, or zero.
    #[must_use]
    pub fn checkpoint_header(&self, height: u64) -> [u8; 32] {
        self.state
            .checkpoints
            .get(&height)
            .copied()
            .unwrap_or_default()
    }

    /// `isConsumed(nonce)`.
    #[must_use]
    pub fn is_consumed(&self, nonce: u64) -> bool {
        self.state.consumed.contains(&nonce)
    }

    /// The balance minted to `recipient`, the recipient bytes of a payload.
    #[must_use]
    pub fn balance_of(&self, recipient: &[u8]) -> u128 {
        self.state
            .balances
            .get(recipient)
            .copied()
            .unwrap_or_default()
    }

    /// `VerifyCertificate` steps 1–12 (§5.1.3) against the current state, after the `Live`
    /// check, with no effect: nothing is recorded and nothing is published. The violation
    /// predicates and the action of an entry point are not evaluated.
    ///
    /// # Errors
    /// `Equivocated` or `CommitteeNotAccepted` when the destination is not `Live`; otherwise
    /// the first failed check of steps 1–11.
    pub fn verify_certificate(
        &self,
        certificate: &TairaCertificateV1,
        now_ms: u64,
    ) -> Result<(), DestinationError> {
        self.require_live(now_ms)?;
        self.verify(certificate, &mut Vec::new()).map(|_| ())
    }

    // -- entry points --------------------------------------------------------------------------

    /// `submitCheckpoints(certs)` on EVM; on TON each `sccp_checkpoint` message carries one
    /// certificate (§5.1.2 updates, §5.1.3). The model takes a batch on either flavour, as
    /// the Python model does: a TON harness sends one certificate per call.
    ///
    /// `next_keys[i]` accompanies `certificates[i]`: the successor keys a TON message brings
    /// for a key-changing rotation. A missing entry is `None`; EVM ignores them all.
    ///
    /// The certificates are processed in order. A latch, and a rotation that leaves the
    /// destination not `Live`, persist and stop processing ([`CallOutcome::stopped`]). The
    /// call is permissionless, works while paused and does not count toward `opCount`.
    ///
    /// # Errors
    /// In this order: `TooManyCertificates` (more than 16), `NothingToDo` (an empty batch),
    /// `Equivocated` or `CommitteeNotAccepted` (not `Live`), then for each certificate its
    /// verification error or, on TON, `BadCommittee` for `next_keys` that are not the
    /// announced successor; at the end `NothingToDo` when no state changed. Any error
    /// reverts the whole batch.
    pub fn submit_checkpoints(
        &mut self,
        certificates: &[TairaCertificateV1],
        next_keys: &[Option<Vec<[u8; KEY_LEN]>>],
        now_ms: u64,
    ) -> Result<CallOutcome, DestinationError> {
        self.atomically(|destination, events| {
            if certificates.len() > MAX_CERTIFICATES_PER_CALL {
                return Err(DestinationError::TooManyCertificates);
            }
            if certificates.is_empty() {
                return Err(DestinationError::NothingToDo);
            }
            destination.require_live(now_ms)?;
            let mut changed = false;
            for (index, certificate) in certificates.iter().enumerate() {
                let successor_keys = next_keys.get(index).and_then(Option::as_deref);
                match destination.checkpoint_step(certificate, successor_keys, now_ms, events)? {
                    CheckpointStep::Applied(step_changed) => changed |= step_changed,
                    CheckpointStep::Stopped(reason) => return Ok((Some(reason), None)),
                }
            }
            if changed {
                Ok((None, None))
            } else {
                Err(DestinationError::NothingToDo)
            }
        })
    }

    /// `finalizeFromTaira(cert, proof)` or `finalizeFromCheckpoint(ref, proof)`: mint a
    /// transfer to its recipient (§5.1.5). [`CallOutcome::returned`] is the message id.
    ///
    /// # Errors
    /// In this order: the errors of obtaining `X` ([`CertificateSourceV1`]); `Equivocated`
    /// or `CommitteeNotAccepted` (not `Live`); `MintingIsPaused`; `BadProof` (the block
    /// reference); `BadPayload`; `BadRecipient`; `DeadlinePassed`; `BadProof` (the leaf
    /// path); `AlreadyConsumed`; `SupplyCapExceeded`. On TON `BadPayload` and `BadRecipient`
    /// come first, before `X` is obtained (§5.3.4).
    pub fn finalize(
        &mut self,
        source: CertificateSourceV1<'_>,
        proof: &MessageProofV1,
        now_ms: u64,
    ) -> Result<CallOutcome, DestinationError> {
        self.atomically(|destination, events| {
            let early = destination.payload_before_header(proof)?;
            let header = destination.obtain_header(source, now_ms, events)?;
            if destination.minting_paused(now_ms) {
                return Err(DestinationError::MintingIsPaused);
            }
            let (payload, message) =
                destination.check_message(&header, proof, early, now_ms, MessageUse::Finalize)?;
            let cap = destination.deployment.max_wrapped_supply;
            let state = &mut destination.state;
            if !state.consumed.insert(payload.nonce) {
                return Err(DestinationError::AlreadyConsumed {
                    nonce: payload.nonce,
                });
            }
            // `totalSupply + amount ≤ maxWrappedSupply` as a subtraction: the sum of two
            // `u128` values can exceed the width, and `totalSupply ≤ maxWrappedSupply` holds.
            if payload.amount > cap.saturating_sub(state.total_supply) {
                return Err(DestinationError::SupplyCapExceeded);
            }
            state.total_supply += payload.amount;
            *state.balances.entry(payload.recipient.clone()).or_default() += payload.amount;
            state.op_count = bumped_op_count(state.op_count);
            events.push(DestinationEvent::Finalized {
                message_id: message,
                nonce: payload.nonce,
                recipient: payload.recipient,
                token_amount: payload.amount,
            });
            Ok((None, Some(message)))
        })
    }

    /// `applyControl(cert, proof)` or `applyControlFromCheckpoint(ref, proof)`: set the pause
    /// state from a Taira control leaf (§5.1.6). The call is permissionless and is not
    /// blocked by the pause.
    ///
    /// The leaf is computed from the destination's own immutables and the supplied fields.
    /// `fastPauseUntilMs` becomes the leaf's expiry clamped to `now_ms + MAX_FAST_PAUSE_MS`
    /// ([`applied_fast_pause_until_ms`]). Nonce gaps are allowed: only the newest control
    /// needs to be applied.
    ///
    /// # Errors
    /// In this order: the errors of obtaining `X`; `Equivocated` or `CommitteeNotAccepted`
    /// (not `Live`); `BadProof` (the block reference, then the leaf path); `BadControl` (the
    /// §3.4 constraints); `StaleControl` (the nonce is not above the stored one).
    pub fn apply_control(
        &mut self,
        source: CertificateSourceV1<'_>,
        proof: &ControlProofV1,
        now_ms: u64,
    ) -> Result<CallOutcome, DestinationError> {
        self.atomically(|destination, events| {
            let header = destination.obtain_header(source, now_ms, events)?;
            check_block_ref(&proof.block, &header)?;
            let deployment = &destination.deployment;
            let fields = ControlLeafV1 {
                route_revision: deployment.route_revision,
                control_nonce: proof.control_nonce,
                track: proof.track,
                parliament_paused: proof.parliament_paused,
                fast_pause_until_ms: proof.fast_pause_until_ms,
                certificate_id: proof.certificate_id,
                effect_hash: proof.effect_hash,
            };
            // A leaf of refused fields is still a leaf of the tree: the path is checked
            // first, the constraints after it. The deployment's profile is external, so the
            // lane exists.
            let leaf = control_leaf_unchecked(
                &deployment.taira_network_id,
                deployment.network,
                &deployment.destination_word,
                &fields,
            )
            .map_err(|_| DestinationError::BadProof)?;
            check_leaf(&leaf, proof.leaf_index, &proof.path, &proof.block)?;
            check_control_constraints(&fields).map_err(|_| DestinationError::BadControl)?;
            let state = &mut destination.state;
            if proof.control_nonce <= state.control_nonce {
                return Err(DestinationError::StaleControl);
            }
            state.parliament_paused = proof.parliament_paused != 0;
            state.fast_pause_until_ms =
                applied_fast_pause_until_ms(proof.fast_pause_until_ms, now_ms);
            state.control_nonce = proof.control_nonce;
            state.op_count = bumped_op_count(state.op_count);
            events.push(DestinationEvent::ControlApplied {
                control_nonce: proof.control_nonce,
                track: proof.track,
                parliament_paused: state.parliament_paused,
                fast_pause_until_ms: state.fast_pause_until_ms,
                certificate_id: proof.certificate_id,
            });
            Ok((None, None))
        })
    }

    /// `voidExpired(nonce, cert, proof)` or `voidExpiredFromCheckpoint(nonce, ref, proof)`:
    /// consume the nonce of a transfer whose deadline has passed, without minting (§5.1.8).
    /// The pause does not block it.
    ///
    /// # Errors
    /// In this order: the errors of obtaining `X`; `Equivocated` or `CommitteeNotAccepted`
    /// (not `Live`); `BadProof` (the block reference); `BadPayload`; `BadRecipient`;
    /// `DeadlineNotReached`; `BadProof` (the leaf path); `BadNonce` when `nonce` is not the
    /// payload's; `AlreadyConsumed`. On TON `BadPayload` and `BadRecipient` come first,
    /// before `X` is obtained (§5.3.4).
    pub fn void_expired(
        &mut self,
        nonce: u64,
        source: CertificateSourceV1<'_>,
        proof: &MessageProofV1,
        now_ms: u64,
    ) -> Result<CallOutcome, DestinationError> {
        self.atomically(|destination, events| {
            let early = destination.payload_before_header(proof)?;
            let header = destination.obtain_header(source, now_ms, events)?;
            let (payload, message) =
                destination.check_message(&header, proof, early, now_ms, MessageUse::Void)?;
            if nonce != payload.nonce {
                return Err(DestinationError::BadNonce {
                    expected: payload.nonce,
                });
            }
            let state = &mut destination.state;
            if !state.consumed.insert(payload.nonce) {
                return Err(DestinationError::AlreadyConsumed {
                    nonce: payload.nonce,
                });
            }
            state.op_count = bumped_op_count(state.op_count);
            events.push(DestinationEvent::Voided {
                message_id: message,
                nonce: payload.nonce,
            });
            Ok((None, None))
        })
    }

    /// `voidFrozen(firstNonce, count)`: consume a range of nonces of a frozen destination
    /// (§5.1.8). It is permissionless: a frozen destination can never mint again.
    ///
    /// The range is `1 ≤ count ≤ 256` on EVM and `≤ 512` inside one bucket on TON, and its
    /// last nonce is at most `2^64 − 1`: `firstNonce + count = 2^64` is valid and is never
    /// formed. EVM emits `SccpVoided(0, nonce)` per nonce, TON one message for the range.
    ///
    /// # Errors
    /// In this order: `BadAmount` (EVM) or `BadRange` (TON) for the range; `NotFrozen` while
    /// `Live`; `AlreadyConsumed` with the lowest consumed nonce of the range.
    pub fn void_frozen(
        &mut self,
        first_nonce: u64,
        count: u64,
        now_ms: u64,
    ) -> Result<CallOutcome, DestinationError> {
        self.atomically(|destination, events| {
            let flavor = destination.deployment.flavor;
            let Some(last_nonce) = void_frozen_last_nonce(flavor, first_nonce, count) else {
                return Err(match flavor {
                    DestinationFlavor::Evm => DestinationError::BadAmount,
                    DestinationFlavor::Ton => DestinationError::BadRange,
                });
            };
            if destination.is_live(now_ms) {
                return Err(DestinationError::NotFrozen);
            }
            let state = &mut destination.state;
            if let Some(nonce) = state.consumed.range(first_nonce..=last_nonce).next() {
                return Err(DestinationError::AlreadyConsumed { nonce: *nonce });
            }
            state.consumed.extend(first_nonce..=last_nonce);
            state.op_count = bumped_op_count(state.op_count);
            match flavor {
                DestinationFlavor::Evm => {
                    events.extend((first_nonce..=last_nonce).map(|nonce| {
                        DestinationEvent::Voided {
                            message_id: [0; 32],
                            nonce,
                        }
                    }));
                }
                DestinationFlavor::Ton => events.push(DestinationEvent::VoidedRange {
                    message_id: [0; 32],
                    first_nonce,
                    count,
                }),
            }
            Ok((None, None))
        })
    }

    // -- internals -----------------------------------------------------------------------------

    /// Run an entry point as one atomic call: an error restores the state and drops the
    /// events, as a revert does.
    fn atomically(
        &mut self,
        call: impl FnOnce(&mut Self, &mut Vec<DestinationEvent>) -> CallResult,
    ) -> Result<CallOutcome, DestinationError> {
        let saved = self.state.clone();
        let mut events = Vec::new();
        match call(self, &mut events) {
            Ok((stopped, returned)) => Ok(CallOutcome {
                events,
                stopped,
                returned,
            }),
            Err(error) => {
                self.state = saved;
                Err(error)
            }
        }
    }

    /// The `Live` check with its two answers (§5.1.2).
    fn require_live(&self, now_ms: u64) -> Result<(), DestinationError> {
        self.state
            .committee
            .require_live(now_ms)
            .map_err(committee_error)
    }

    /// `VerifyCertificate` steps 1–12 (§5.1.3). Returns `X` and `keccak256(X)`, and pushes
    /// `SccpCertificate` exactly when the full path ran: a certificate whose `X` is stored
    /// takes the mandatory cheap path after the checks of steps 1–6.
    fn verify(
        &self,
        certificate: &TairaCertificateV1,
        events: &mut Vec<DestinationEvent>,
    ) -> Result<(SccpFinalityHeaderV1, [u8; 32]), DestinationError> {
        // These keys were bound to the root by deployment or an authenticated rotation.
        let authority = CertificateAuthorityV1 {
            flavor: self.deployment.flavor,
            taira_network_id: &self.deployment.taira_network_id,
            consensus_instance: &self.deployment.consensus_instance,
            committee: &self.state.committee,
            ton_keys: self.state.keys.as_deref(),
        };
        let checked = authority.verify(certificate, |height| {
            self.state.checkpoints.get(&height).copied()
        })?;
        if checked.full_path {
            events.push(DestinationEvent::Certificate {
                height: checked.header.height(),
                generation: checked.header.generation(),
                qc: certificate.qc.clone(),
                header: certificate.header.clone(),
                signature: match self.deployment.flavor {
                    DestinationFlavor::Evm => certificate.signature.clone(),
                    DestinationFlavor::Ton => certificate.ton_signature.clone(),
                },
            });
        }
        Ok((checked.header, checked.checkpoint_id))
    }

    /// Record `checkpoint[height] = id` if the height is absent. TON keeps three entries: a
    /// new height enters only above the lowest stored one, which it evicts. Returns whether
    /// the checkpoint was recorded.
    fn record_checkpoint(
        &mut self,
        height: u64,
        id: [u8; 32],
        events: &mut Vec<DestinationEvent>,
    ) -> bool {
        let checkpoints = &mut self.state.checkpoints;
        if checkpoints.contains_key(&height) {
            return false;
        }
        if let Some(slots) = self.deployment.flavor.checkpoint_slots()
            && checkpoints.len() >= slots
        {
            let lowest = checkpoints.first_key_value().map(|(lowest, _)| *lowest);
            if lowest.is_none_or(|lowest| height <= lowest) {
                return false;
            }
            checkpoints.pop_first();
        }
        checkpoints.insert(height, id);
        events.push(DestinationEvent::Checkpointed { height, id });
        true
    }

    /// One certificate of `submitCheckpoints`: its verification, V1–V3 with the latch, and
    /// the updates of §5.1.2.
    fn checkpoint_step(
        &mut self,
        certificate: &TairaCertificateV1,
        next_keys: Option<&[[u8; KEY_LEN]]>,
        now_ms: u64,
        events: &mut Vec<DestinationEvent>,
    ) -> Result<CheckpointStep, DestinationError> {
        let (header, id) = self.verify(certificate, events)?;
        let stored = self.state.checkpoints.get(&header.height()).copied();
        // TON stores the keys, so a rotation to another root must bring them. The answer
        // reads `cur.root` before the rotation.
        let needs_keys = self.deployment.flavor == DestinationFlavor::Ton
            && self.state.committee.successor_needs_keys(&header);
        let outcome = self
            .state
            .committee
            .apply_checkpoint(&header, stored.as_ref(), now_ms)
            .map_err(committee_error)?;
        match outcome {
            CheckpointOutcomeV1::Latched(violation) => {
                events.push(DestinationEvent::Latched(violation));
                Ok(CheckpointStep::Stopped(StopReasonV1::Latch))
            }
            CheckpointOutcomeV1::Applied {
                high_raised,
                rotation,
                live,
            } => {
                let recorded = self.record_checkpoint(header.height(), id, events);
                if let Some(rotation) = rotation {
                    if needs_keys {
                        // The error reverts the call, and with it the rotation applied above.
                        let keys = next_keys
                            .filter(|keys| successor_keys_match(keys, &rotation.root))
                            .ok_or(DestinationError::BadCommittee)?;
                        self.state.keys = Some(keys.to_vec());
                    }
                    events.push(DestinationEvent::CommitteeRotated(rotation));
                }
                if live {
                    Ok(CheckpointStep::Applied(
                        recorded || high_raised || rotation.is_some(),
                    ))
                } else {
                    Ok(CheckpointStep::Stopped(StopReasonV1::Frozen))
                }
            }
        }
    }

    /// Obtain the certified header of an entry point and require `Live`.
    ///
    /// Inline: `VerifyCertificate` as CUR, V1–V3 (`LatchRequired`), `Live`, then the
    /// checkpoint is recorded and `high` rises; no successor is installed even when `X` is a
    /// rotation. Checkpoint: the checkpoint use check of §5.1.3, which changes nothing.
    fn obtain_header(
        &mut self,
        source: CertificateSourceV1<'_>,
        now_ms: u64,
        events: &mut Vec<DestinationEvent>,
    ) -> Result<SccpFinalityHeaderV1, DestinationError> {
        match source {
            CertificateSourceV1::Inline(certificate) => {
                let (header, id) = self.verify(certificate, events)?;
                let stored = self.state.checkpoints.get(&header.height()).copied();
                self.state
                    .committee
                    .apply_inline(&header, stored.as_ref(), now_ms)
                    .map_err(committee_error)?;
                self.record_checkpoint(header.height(), id, events);
                Ok(header)
            }
            CertificateSourceV1::Checkpoint(reference) => {
                let raw = <&[u8; X_LEN]>::try_from(&reference.header[..])
                    .map_err(|_| DestinationError::BadHeader)?;
                let mut height = [0_u8; 8];
                height.copy_from_slice(&raw[X_OFFSET_HEIGHT..X_OFFSET_HEIGHT + 8]);
                let stored = self.state.checkpoints.get(&u64::from_be_bytes(height));
                if stored != Some(&checkpoint_id(raw)) {
                    return Err(DestinationError::UnknownCheckpoint);
                }
                // The stored id authenticates the network of `X`; `ACTIVE` is still required.
                let header = SccpFinalityHeaderV1::parse(raw)
                    .ok()
                    .filter(SccpFinalityHeaderV1::is_active)
                    .ok_or(DestinationError::BadHeader)?;
                self.state
                    .committee
                    .require_checkpoint_use(&header, now_ms)
                    .map_err(committee_error)?;
                Ok(header)
            }
        }
    }

    /// The payload of a TON finalize or void, which the minter checks before it obtains `X`
    /// (§5.3.4 finalize step 1): the required value of the message depends on the payload
    /// nonce. EVM checks the payload after `X` ([`Self::check_message`]) and gets `None`.
    fn payload_before_header(
        &self,
        proof: &MessageProofV1,
    ) -> Result<Option<AddressedPayload>, DestinationError> {
        match self.deployment.flavor {
            DestinationFlavor::Evm => Ok(None),
            DestinationFlavor::Ton => self.addressed_payload(&proof.payload).map(Some),
        }
    }

    /// The checks of a message proof against a verified header (§5.1.5 steps 4 and 5): the
    /// block reference, the payload and its recipient (unless TON checked them before `X`
    /// and passes them as `early`), the deadline, then the leaf path. Returns the payload
    /// fields and the message id.
    fn check_message(
        &self,
        header: &SccpFinalityHeaderV1,
        proof: &MessageProofV1,
        early: Option<AddressedPayload>,
        now_ms: u64,
        usage: MessageUse,
    ) -> Result<(AddressedPayload, [u8; 32]), DestinationError> {
        check_block_ref(&proof.block, header)?;
        let payload = match early {
            Some(payload) => payload,
            None => self.addressed_payload(&proof.payload)?,
        };
        match usage {
            MessageUse::Finalize if now_ms > payload.deadline_ms => {
                return Err(DestinationError::DeadlinePassed);
            }
            MessageUse::Void if now_ms <= payload.deadline_ms => {
                return Err(DestinationError::DeadlineNotReached);
            }
            _ => {}
        }
        let message = message_id(&self.lane, &payload_hash(&proof.payload));
        let leaf = transfer_leaf(&message, &self.deployment.destination_word);
        check_leaf(&leaf, proof.leaf_index, &proof.path, &proof.block)?;
        Ok((payload, message))
    }

    /// Decode a transfer payload and require that it is addressed to this revision and to a
    /// recipient this destination can mint to (§5.1.5 step 4).
    ///
    /// `BadPayload` answers every violation of §3.2 and a payload of another lane or
    /// revision. `BadRecipient` answers a recipient of the right length that is not a valid
    /// account of the own codec (EVM: the zero address; TON: another workchain or a zero
    /// account id), and the contract itself.
    fn addressed_payload(&self, bytes: &[u8]) -> Result<AddressedPayload, DestinationError> {
        let deployment = &self.deployment;
        let is_ton = deployment.network == SccpNetworkV1::TonMainnet;
        let own_domain = domain(deployment.network);
        match SccpTransferPayloadV1::decode(bytes) {
            Ok(payload) => {
                if payload.source_domain != domain(SccpNetworkV1::SoraTaira)
                    || payload.dest_domain != own_domain
                    || payload.route_revision != deployment.route_revision
                {
                    return Err(DestinationError::BadPayload);
                }
                // The codec rule holds, so the recipient has its codec's length.
                let recipient = payload.recipient.bytes;
                let is_own = if is_ton {
                    recipient.get(4..) == Some(&deployment.destination_word[..])
                } else {
                    recipient[..] == deployment.destination_word[12..]
                };
                if is_own {
                    return Err(DestinationError::BadRecipient);
                }
                Ok(AddressedPayload {
                    nonce: payload.nonce,
                    deadline_ms: payload.deadline_ms,
                    amount: payload.amount,
                    recipient,
                })
            }
            // Only the recipient's codec rule failed. It is the destination's own rule when
            // everything else about the payload holds: the recipient's length, the route id
            // (the one rule the decoder checks after the recipient) and the address of this
            // revision.
            Err(PayloadError::BadRecipient) => {
                let recipient_len = if is_ton { 36 } else { 20 };
                let addressed = raw_payload(bytes).is_some_and(|raw| {
                    raw.source_domain == domain(SccpNetworkV1::SoraTaira)
                        && raw.dest_domain == own_domain
                        && raw.route_revision == deployment.route_revision
                        && raw.recipient.len() == recipient_len
                        && route_id(deployment.network).map(str::as_bytes) == Some(raw.route_id)
                });
                Err(if addressed {
                    DestinationError::BadRecipient
                } else {
                    DestinationError::BadPayload
                })
            }
            Err(_) => Err(DestinationError::BadPayload),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Checks without state
// ---------------------------------------------------------------------------------------------

/// The §5.2.2 error of a refusal by the committee state machine
/// ([`CommitteeError::destination_error`]).
const fn committee_error(error: CommitteeError) -> DestinationError {
    match error {
        CommitteeError::Equivocated => DestinationError::Equivocated,
        CommitteeError::Expired
        | CommitteeError::NotCurrent
        | CommitteeError::CheckpointRetired => DestinationError::CommitteeNotAccepted,
        CommitteeError::LatchRequired => DestinationError::LatchRequired,
    }
}

/// `opCount` after one more counted operation (§5.1.1): `min(opCount + 1, 2^64 − 1)`.
///
/// The counter saturates at the largest `u64`: it never wraps to 0, and the operation that
/// reaches the bound, like every one after it, still succeeds.
#[must_use]
pub const fn bumped_op_count(op_count: u64) -> u64 {
    op_count.saturating_add(1)
}

/// The source-nonce rule of `transferToTaira` (§5.1.7): the next nonce a sender stores after
/// a burn.
///
/// `stored` is the sender's stored next nonce (`transferNonces[sender]` on EVM) and
/// `expected` the `expectedNonce` of the call; the burn uses `stored`. Source nonces are
/// `0 ..= 2^64 − 2`.
///
/// # Errors
/// `BadNonce { expected: stored }` when `expected` differs from `stored`, and for every
/// `expected` when `stored` is `2^64 − 1`. That value means the sender's nonces are
/// exhausted: it is never used, and the counter never wraps. A refused call changes nothing.
pub const fn next_source_nonce(stored: u64, expected: u64) -> Result<u64, DestinationError> {
    if expected != stored || stored == u64::MAX {
        return Err(DestinationError::BadNonce { expected: stored });
    }
    Ok(stored + 1)
}

/// Admit a TON burn's exact wrapper and complete recipient before any debit or forwarding.
///
/// The wrapper is exactly the 32-bit `sccp_burn_to_taira` opcode and one reference. Its
/// recipient is an ordinary canonical snake of 1..=1024 bytes (§5.3.2, §5.3.4). The ordinary
/// [`Cell`] type and [`super::ton_cell::cell_from_boc`] reject exotic wrappers and children;
/// an opaque reference is refused because its admission cannot be verified.
///
/// # Errors
/// `BadBurnPayload` for an absent wrapper or wrong opcode, `BadSnake` for malformed or
/// unavailable cells, and `BadRecipient` for a recipient exceeding 1024 bytes.
pub fn check_ton_burn_payload(payload: Option<&Cell>) -> Result<Vec<u8>, DestinationError> {
    let payload = payload.ok_or(DestinationError::BadBurnPayload)?;
    if payload.bit_len() != 32 || payload.refs().len() != 1 {
        return Err(DestinationError::BadSnake);
    }
    if payload.data() != TON_BURN_TO_TAIRA_OP.to_be_bytes() {
        return Err(DestinationError::BadBurnPayload);
    }
    let recipient = payload.refs()[0].cell().ok_or(DestinationError::BadSnake)?;
    parse_snake_bytes(recipient, MAX_TAIRA_ACCOUNT_BYTES).map_err(|error| match error {
        TonCellError::SnakeTooLong => DestinationError::BadRecipient,
        _ => DestinationError::BadSnake,
    })
}

/// The last nonce of a `voidFrozen` range, when the range is valid (§5.1.8): `1 ≤ count ≤`
/// the flavour's bound, a last nonce of at most `2^64 − 1`, and on TON one bucket.
///
/// The exclusive end `first_nonce + count` may be `2^64`, so it is never formed.
fn void_frozen_last_nonce(flavor: DestinationFlavor, first_nonce: u64, count: u64) -> Option<u64> {
    if count == 0 || count > flavor.max_void_frozen_range() {
        return None;
    }
    let last_nonce = first_nonce.checked_add(count - 1)?;
    let one_bucket = first_nonce / TON_BUCKET_NONCES == last_nonce / TON_BUCKET_NONCES;
    (flavor == DestinationFlavor::Evm || one_bucket).then_some(last_nonce)
}

/// `BlockRefV1` against a verified header (§5.1.5); `BadProof` otherwise.
///
/// The certified block itself is named with its own root and count and no history path. An
/// older block is proven through the history accumulator of the header.
///
/// # Errors
/// Returns `BadProof` when the block reference is not included in the supplied verified header.
pub fn check_block_ref(
    block: &BlockRefV1,
    header: &SccpFinalityHeaderV1,
) -> Result<(), DestinationError> {
    let verified = if block.height == header.height() {
        block.sccp_root == header.sccp_root()
            && block.sccp_root != [0; 32]
            && block.message_count == header.message_count()
            && block.history_index == 0
            && block.history_path.is_empty()
    } else {
        block.height < header.height()
            && (1..=MAX_BLOCK_LEAVES).contains(&block.message_count)
            && block.sccp_root != [0; 32]
            && verify_history_inclusion(
                &history_leaf(block.height, &block.sccp_root, block.message_count),
                block.history_index,
                header.history_size(),
                &block.history_path,
                &header.history_root(),
            )
            .is_ok()
    };
    if verified {
        Ok(())
    } else {
        Err(DestinationError::BadProof)
    }
}

/// A leaf against the block reference that holds it (path of at most 9 siblings).
///
/// # Errors
/// Returns `BadProof` for a malformed or non-matching inclusion path.
pub fn check_leaf(
    leaf: &[u8; 32],
    leaf_index: u32,
    path: &[[u8; 32]],
    block: &BlockRefV1,
) -> Result<(), DestinationError> {
    verify_block_inclusion(
        leaf,
        leaf_index,
        block.message_count,
        path,
        &block.sccp_root,
    )
    .map_err(|_| DestinationError::BadProof)
}

/// The fields of a §3.2 payload that the destination's own rules read, taken from the
/// layout without validation.
struct RawPayload<'a> {
    source_domain: u32,
    dest_domain: u32,
    route_revision: u32,
    recipient: &'a [u8],
    route_id: &'a [u8],
}

/// Walk the §3.2 layout: `kind ‖ version ‖ u32 source ‖ u32 dest ‖ u64 nonce ‖ u32 revision
/// ‖ u64 deadline ‖ u32 asset home ‖ asset id ‖ u128 amount ‖ sender ‖ recipient ‖ route id`,
/// where each variable field is `u8 codec ‖ u16 len ‖ bytes`.
fn raw_payload(bytes: &[u8]) -> Option<RawPayload<'_>> {
    let word = |offset: usize| {
        let field = bytes.get(offset..offset + 4)?;
        Some(u32::from_be_bytes([field[0], field[1], field[2], field[3]]))
    };
    let (_asset_id, rest) = payload_field(bytes.get(34..)?)?;
    let (_sender, rest) = payload_field(rest.get(16..)?)?;
    let (recipient, rest) = payload_field(rest)?;
    let (route_id, _) = payload_field(rest)?;
    Some(RawPayload {
        source_domain: word(2)?,
        dest_domain: word(6)?,
        route_revision: word(18)?,
        recipient,
        route_id,
    })
}

/// Split `u8 codec ‖ u16 len ‖ bytes` off the front: the bytes of the field and the rest.
fn payload_field(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let len = usize::from(u16::from_be_bytes([*bytes.get(1)?, *bytes.get(2)?]));
    bytes.get(3..)?.split_at_checked(len)
}

#[cfg(test)]
mod tests {
    use blstrs::{G1Affine, G1Projective, G2Affine, Scalar, pairing};
    use group::{Curve as _, Group as _, ff::Field as _, prime::PrimeCurveAffine as _};
    use iroha_crypto::{
        Algorithm, KeyPair, PrivateKey,
        bls::consensus::{aggregate, sign_preimage},
    };
    use norito::json::Value;

    use super::{
        super::{
            committee::{BLS12_381_P, LatchReasonV1, aggregate_public_key, key_y},
            control::{MAX_FAST_PAUSE_MS, TRACK_FAST_PAUSE, TRACK_PARLIAMENT},
            finality::{
                FLAG_ACTIVE, FLAG_ROTATION, FinalityHeaderError, MAX_VALIDITY_MS,
                SccpFinalityHeaderFieldsV1, commit_preimage, outer_result,
                vectors::{bytes, field, keys, number, reference, rows, text, word},
            },
            hashes::word_address,
            history::{history_path, history_root},
            merkle::PromoteOddTree,
            payload::PayloadAccountV1,
        },
        *,
    };

    const NETWORK: [u8; 32] = [0x11; 32];
    const INSTANCE: [u8; 32] = [0x77; 32];
    const T0: u64 = 1_800_000_000_000;
    const SECOND: u64 = 1_000;
    const MINUTE: u64 = 60 * SECOND;
    const HOUR: u64 = 60 * MINUTE;
    const DAY: u64 = 24 * HOUR;
    const VALIDITY: u64 = 1_209_600_000;
    /// The clock of most calls: one minute after the pinned generation started.
    const NOW: u64 = T0 + MINUTE;
    const RECIPIENT: [u8; 20] = [0x44; 20];
    const CAP: u128 = 10_000_000_000;
    const EVM: DestinationFlavor = DestinationFlavor::Evm;
    const TON: DestinationFlavor = DestinationFlavor::Ton;
    const FLAVORS: [DestinationFlavor; 2] = [EVM, TON];

    // -- a small Taira ---------------------------------------------------------------------------

    /// A committee of four with its secret keys, in canonical order.
    struct Committee {
        members: Vec<([u8; KEY_LEN], PrivateKey)>,
    }

    impl Committee {
        fn new(tag: u8) -> Self {
            let mut members: Vec<([u8; KEY_LEN], PrivateKey)> = (0_u8..4)
                .map(|index| {
                    let seed = vec![b'd', b'e', b's', b't', tag, index];
                    let (public, private) =
                        KeyPair::from_seed(seed, Algorithm::BlsNormal).into_parts();
                    let (algorithm, raw) = public.to_bytes();
                    assert_eq!(algorithm, Algorithm::BlsNormal);
                    (<[u8; KEY_LEN]>::try_from(raw).unwrap(), private)
                })
                .collect();
            members.sort_by(|left, right| left.0.cmp(&right.0));
            Self { members }
        }

        fn keys(&self) -> Vec<[u8; KEY_LEN]> {
            self.members.iter().map(|member| member.0).collect()
        }

        fn root(&self) -> [u8; 32] {
            committee_root(&self.keys()).unwrap()
        }

        /// The aggregate signature of the members `signers` names over the Commit preimage of
        /// `header` under `qc`.
        fn sign(&self, qc: &QcFixedV1, header: &SccpFinalityHeaderV1) -> [u8; SIGNATURE_LEN] {
            let result = outer_result(header, &qc.result_body).0;
            let preimage = commit_preimage(&INSTANCE, qc, header.height(), &result);
            let shares: Vec<[u8; SIGNATURE_LEN]> = signer_indices(qc.signers, self.members.len())
                .unwrap()
                .into_iter()
                .map(|index| sign_preimage(&self.members[index].1, &preimage).unwrap())
                .collect();
            aggregate(shares).unwrap()
        }

        /// A certificate of `header` by the three lowest members.
        fn certify(&self, header: &SccpFinalityHeaderV1) -> TairaCertificateV1 {
            self.certify_by(header, 0b0111, [0x66; 32])
        }

        fn certify_by(
            &self,
            header: &SccpFinalityHeaderV1,
            signers: u32,
            result_body: [u8; 32],
        ) -> TairaCertificateV1 {
            let qc = qc_of(header, signers, result_body);
            TairaCertificateV1::new(&qc, header, &self.sign(&qc, header), &self.keys()).unwrap()
        }
    }

    /// The `QC_FIXED` of a test certificate. A destination takes all but `signers` unverified.
    fn qc_of(header: &SccpFinalityHeaderV1, signers: u32, result_body: [u8; 32]) -> QcFixedV1 {
        QcFixedV1 {
            epoch: header.height() / 100,
            epoch_context: [0x88; 32],
            view: 0,
            block_hash: [0x99; 32],
            result_body,
            signers,
        }
    }

    /// The header fields of an empty block at `height`, one block per second with height 1000
    /// at `T0`, certified by generation `generation` of the committee `root`.
    fn plain(root: [u8; 32], generation: u64, height: u64) -> SccpFinalityHeaderFieldsV1 {
        SccpFinalityHeaderFieldsV1 {
            network_id: NETWORK,
            height,
            timestamp_ms: T0 - 1000 * SECOND + height * SECOND,
            flags: FLAG_ACTIVE,
            message_count: 0,
            sccp_root: [0; 32],
            history_size: 0,
            history_root: [0; 32],
            generation,
            committee_root: root,
            validity_ms: 0,
            next_committee_root: [0; 32],
        }
    }

    /// The fields of a handoff to the committee `next` with the validity `VALIDITY`.
    fn handoff(
        root: [u8; 32],
        generation: u64,
        height: u64,
        next: [u8; 32],
    ) -> SccpFinalityHeaderFieldsV1 {
        SccpFinalityHeaderFieldsV1 {
            flags: FLAG_ACTIVE | FLAG_ROTATION,
            validity_ms: VALIDITY,
            next_committee_root: next,
            ..plain(root, generation, height)
        }
    }

    fn x(fields: &SccpFinalityHeaderFieldsV1) -> SccpFinalityHeaderV1 {
        SccpFinalityHeaderV1::from_fields(fields).unwrap()
    }

    fn id(header: &SccpFinalityHeaderV1) -> [u8; 32] {
        checkpoint_id(header.as_bytes())
    }

    fn destination_word() -> [u8; 32] {
        word_address(&[0x22; 20])
    }

    /// The account id of the TON test minter: a placeholder, as in the shared vectors.
    const TON_WORD: [u8; 32] = [0x35; 32];

    /// The profile of a flavour's test deployment and its destination word.
    fn route(flavor: DestinationFlavor) -> (SccpNetworkV1, [u8; 32]) {
        match flavor {
            DestinationFlavor::Evm => (SccpNetworkV1::EthereumMainnet, destination_word()),
            DestinationFlavor::Ton => (SccpNetworkV1::TonMainnet, TON_WORD),
        }
    }

    thread_local! {
        /// The flavour whose route the payload, leaf and dummy-proof helpers of a test build
        /// for: the EVM route unless a pass over one flavour sets another ([`on`]).
        static ROUTE: std::cell::Cell<DestinationFlavor> = const { std::cell::Cell::new(EVM) };
    }

    /// Restores the EVM route when a pass over one flavour ends.
    struct RouteGuard;

    impl Drop for RouteGuard {
        fn drop(&mut self) {
            ROUTE.set(EVM);
        }
    }

    /// Build the transfers, the control leaves and the dummy proofs of this test for the
    /// route of `flavor` until the guard is dropped. A destination accepts leaves of its own
    /// profile only, so a test that runs on both flavours builds its ledger once per pass.
    #[must_use]
    fn on(flavor: DestinationFlavor) -> RouteGuard {
        ROUTE.set(flavor);
        RouteGuard
    }

    /// A message proof for a call that is refused before the proof is read: a payload
    /// addressed to the test deployment of `flavor`, with no path. A TON minter checks the
    /// payload before everything else, so an empty one would answer `BadPayload` there.
    fn dummy_message_on(flavor: DestinationFlavor) -> MessageProofV1 {
        MessageProofV1 {
            payload: transfer_on(flavor, 0, 1, T0 + DAY).0,
            ..MessageProofV1::default()
        }
    }

    /// [`dummy_message_on`] the route of the current pass.
    fn dummy_message() -> MessageProofV1 {
        dummy_message_on(ROUTE.get())
    }

    /// A recipient of the flavour's codec: 20 bytes on EVM, `be32(0) ‖ account_id` on TON.
    fn recipient_of(flavor: DestinationFlavor) -> Vec<u8> {
        match flavor {
            DestinationFlavor::Evm => RECIPIENT.to_vec(),
            DestinationFlavor::Ton => [&[0_u8; 4][..], &[0x44; 32]].concat(),
        }
    }

    /// Generation 5 (`K0`) pinned at height 1000 until `T0 + VALIDITY`, with the committees
    /// `K1` and `K2` that follow it.
    struct World {
        k0: Committee,
        k1: Committee,
        k2: Committee,
    }

    impl World {
        fn new() -> Self {
            Self {
                k0: Committee::new(0),
                k1: Committee::new(1),
                k2: Committee::new(2),
            }
        }

        /// The test deployment of `flavor` on its own profile ([`route`]).
        fn deployment(&self, flavor: DestinationFlavor) -> DeploymentV1 {
            let (network, destination_word) = route(flavor);
            DeploymentV1 {
                flavor,
                taira_network_id: NETWORK,
                consensus_instance: INSTANCE,
                network,
                destination_word,
                route_revision: 1,
                max_wrapped_supply: CAP,
                pin_generation: 5,
                pin_root: self.k0.root(),
                pin_start_height: 1000,
                pin_until_ms: T0 + VALIDITY,
                pin_keys: Some(self.k0.keys()),
            }
        }

        fn destination(&self, flavor: DestinationFlavor) -> Destination {
            Destination::new(self.deployment(flavor)).unwrap()
        }

        /// `X_h` of generation 5: an empty block.
        fn x(&self, height: u64) -> SccpFinalityHeaderV1 {
            x(&plain(self.k0.root(), 5, height))
        }

        /// The certificate of `X_h` by `K0`.
        fn cert(&self, height: u64) -> TairaCertificateV1 {
            self.k0.certify(&self.x(height))
        }

        /// The handoff of generation 5 to `K1` at `height`.
        fn handoff(&self, height: u64) -> SccpFinalityHeaderV1 {
            x(&handoff(self.k0.root(), 5, height, self.k1.root()))
        }
    }

    /// A block of the ledger: its header, its leaves and, when it has leaves, the index of
    /// its history leaf.
    struct Block {
        header: SccpFinalityHeaderV1,
        leaves: Vec<[u8; 32]>,
        history_index: Option<u64>,
    }

    /// The blocks of generation 5 with their leaves, and the history accumulator over the
    /// SCCP-bearing ones.
    #[derive(Default)]
    struct Ledger {
        history: Vec<[u8; 32]>,
        blocks: BTreeMap<u64, Block>,
    }

    impl Ledger {
        /// `X_h` of generation 5 holding `leaves`.
        fn block(
            &mut self,
            world: &World,
            height: u64,
            leaves: &[[u8; 32]],
        ) -> SccpFinalityHeaderV1 {
            self.block_with(world, height, leaves, |_| {})
        }

        fn block_with(
            &mut self,
            world: &World,
            height: u64,
            leaves: &[[u8; 32]],
            adjust: impl FnOnce(&mut SccpFinalityHeaderFieldsV1),
        ) -> SccpFinalityHeaderV1 {
            let mut fields = plain(world.k0.root(), 5, height);
            let mut history_index = None;
            if !leaves.is_empty() {
                fields.message_count = u32::try_from(leaves.len()).unwrap();
                fields.sccp_root = PromoteOddTree::block(leaves).unwrap().root();
                history_index = Some(u64::try_from(self.history.len()).unwrap());
                self.history.push(history_leaf(
                    height,
                    &fields.sccp_root,
                    fields.message_count,
                ));
            }
            fields.history_size = u64::try_from(self.history.len()).unwrap();
            fields.history_root = history_root(&self.history).unwrap();
            adjust(&mut fields);
            let header = x(&fields);
            let block = Block {
                header,
                leaves: leaves.to_vec(),
                history_index,
            };
            self.blocks.insert(height, block);
            header
        }

        /// The reference to block `target` under the certified header `certified`.
        fn block_ref(&self, target: u64, certified: &SccpFinalityHeaderV1) -> BlockRefV1 {
            let Block {
                header,
                history_index,
                ..
            } = &self.blocks[&target];
            let mut block = BlockRefV1 {
                height: target,
                sccp_root: header.sccp_root(),
                message_count: header.message_count(),
                history_index: 0,
                history_path: Vec::new(),
            };
            if target != certified.height() {
                let size = usize::try_from(certified.history_size()).unwrap();
                block.history_index = history_index.expect("an SCCP-bearing block");
                block.history_path =
                    history_path(&self.history[..size], block.history_index).unwrap();
            }
            block
        }

        fn leaf_path(&self, height: u64, leaf_index: u32) -> Vec<[u8; 32]> {
            PromoteOddTree::block(&self.blocks[&height].leaves)
                .unwrap()
                .path(usize::try_from(leaf_index).unwrap())
                .unwrap()
        }

        /// The proof of the transfer `payload` at `leaf_index` of block `height`.
        fn message(
            &self,
            payload: &[u8],
            height: u64,
            leaf_index: u32,
            certified: &SccpFinalityHeaderV1,
        ) -> MessageProofV1 {
            MessageProofV1 {
                payload: payload.to_vec(),
                leaf_index,
                path: self.leaf_path(height, leaf_index),
                block: self.block_ref(height, certified),
            }
        }

        /// The proof of the control `fields` at `leaf_index` of block `height`.
        fn control(
            &self,
            fields: &ControlLeafV1,
            height: u64,
            leaf_index: u32,
            certified: &SccpFinalityHeaderV1,
        ) -> ControlProofV1 {
            ControlProofV1 {
                control_nonce: fields.control_nonce,
                track: fields.track,
                parliament_paused: fields.parliament_paused,
                fast_pause_until_ms: fields.fast_pause_until_ms,
                certificate_id: fields.certificate_id,
                effect_hash: fields.effect_hash,
                leaf_index,
                path: self.leaf_path(height, leaf_index),
                block: self.block_ref(height, certified),
            }
        }
    }

    fn outbound(
        target: SccpNetworkV1,
        nonce: u64,
        revision: u32,
        amount: u128,
        deadline_ms: u64,
        recipient: &[u8],
    ) -> SccpTransferPayloadV1 {
        let sender = [&[0x01][..], &[0x5a; 33]].concat();
        SccpTransferPayloadV1::outbound(
            target,
            nonce,
            revision,
            deadline_ms,
            amount,
            sender,
            recipient.to_vec(),
        )
        .unwrap()
    }

    /// The transfer leaf of `payload` on the lane of the test deployment of `flavor`.
    fn leaf_on(flavor: DestinationFlavor, payload: &[u8]) -> [u8; 32] {
        let (network, word) = route(flavor);
        let lane = lane_bytes(SccpNetworkV1::SoraTaira, network, &NETWORK).unwrap();
        transfer_leaf(&message_id(&lane, &payload_hash(payload)), &word)
    }

    /// A transfer addressed to the test deployment of the current pass ([`on`]; the EVM one
    /// outside a pass): its payload and its leaf.
    fn transfer(nonce: u64, amount: u128, deadline_ms: u64) -> (Vec<u8>, [u8; 32]) {
        transfer_on(ROUTE.get(), nonce, amount, deadline_ms)
    }

    /// A transfer addressed to the test deployment of `flavor`, to a recipient of its codec.
    fn transfer_on(
        flavor: DestinationFlavor,
        nonce: u64,
        amount: u128,
        deadline_ms: u64,
    ) -> (Vec<u8>, [u8; 32]) {
        let payload = outbound(
            route(flavor).0,
            nonce,
            1,
            amount,
            deadline_ms,
            &recipient_of(flavor),
        )
        .encode()
        .unwrap();
        let leaf = leaf_on(flavor, &payload);
        (payload, leaf)
    }

    fn control_fields(nonce: u64, track: u8, paused: u8, until_ms: u64) -> ControlLeafV1 {
        ControlLeafV1 {
            route_revision: 1,
            control_nonce: nonce,
            track,
            parliament_paused: paused,
            fast_pause_until_ms: until_ms,
            certificate_id: [0xc1; 32],
            effect_hash: [0xe1; 32],
        }
    }

    /// The control leaf of `fields` for the test deployment of the current pass ([`on`]).
    fn control_leaf_of(fields: &ControlLeafV1) -> [u8; 32] {
        control_leaf_on(ROUTE.get(), fields)
    }

    /// The control leaf of `fields` for the test deployment of `flavor`.
    fn control_leaf_on(flavor: DestinationFlavor, fields: &ControlLeafV1) -> [u8; 32] {
        let (network, word) = route(flavor);
        control_leaf_unchecked(&NETWORK, network, &word, fields).unwrap()
    }

    fn inline(certificate: &TairaCertificateV1) -> CertificateSourceV1<'_> {
        CertificateSourceV1::Inline(certificate)
    }

    fn stored(header: &SccpFinalityHeaderV1) -> CheckpointRefV1 {
        CheckpointRefV1 {
            header: header.as_bytes().to_vec(),
        }
    }

    /// The error of a refused call, after checking that the call changed nothing.
    fn refused(
        destination: &mut Destination,
        call: impl FnOnce(&mut Destination) -> Result<CallOutcome, DestinationError>,
    ) -> DestinationError {
        let before = destination.clone();
        let error = call(destination).expect_err("the call is refused");
        assert_eq!(*destination, before, "a refused call changes nothing");
        error
    }

    fn submit(
        destination: &mut Destination,
        certificates: &[TairaCertificateV1],
        now_ms: u64,
    ) -> Result<CallOutcome, DestinationError> {
        destination.submit_checkpoints(certificates, &[], now_ms)
    }

    fn certificate_event(
        certificate: &TairaCertificateV1,
        flavor: DestinationFlavor,
    ) -> DestinationEvent {
        let header = SccpFinalityHeaderV1::parse(&certificate.header).unwrap();
        DestinationEvent::Certificate {
            height: header.height(),
            generation: header.generation(),
            qc: certificate.qc.clone(),
            header: certificate.header.clone(),
            signature: match flavor {
                EVM => certificate.signature.clone(),
                TON => certificate.ton_signature.clone(),
            },
        }
    }

    fn checkpointed(header: &SccpFinalityHeaderV1) -> DestinationEvent {
        DestinationEvent::Checkpointed {
            height: header.height(),
            id: id(header),
        }
    }

    /// `p − y` for `0 < y < p`: the `y` of the negated point.
    fn negated(y: &[u8; FP_LEN]) -> [u8; FP_LEN] {
        let mut out = [0_u8; FP_LEN];
        let mut borrow = 0_i16;
        for index in (0..FP_LEN).rev() {
            let digit = i16::from(BLS12_381_P[index]) - i16::from(y[index]) - borrow;
            borrow = i16::from(digit < 0);
            out[index] = u8::try_from(digit.rem_euclid(256)).unwrap();
        }
        out
    }

    /// The compressed form of a point of the curve outside the G1 subgroup: the first small
    /// `x` that has a `y`.
    fn key_outside_the_subgroup() -> [u8; KEY_LEN] {
        (1..=u8::MAX)
            .map(|low| {
                let mut key = [0_u8; KEY_LEN];
                key[0] = 0x80;
                key[KEY_LEN - 1] = low;
                key
            })
            .find(|key| {
                G1Affine::from_compressed_unchecked(key)
                    .into_option()
                    .is_some_and(|point| !bool::from(point.is_torsion_free()))
            })
            .unwrap()
    }

    /// A certificate of `header` under the committee `keys`, with a well-formed signature
    /// that the relation would refuse: the checks before the pairing decide.
    fn unsigned(
        header: &SccpFinalityHeaderV1,
        signers: u32,
        keys: &[[u8; KEY_LEN]],
        signature: &TairaCertificateV1,
        ys: &[[u8; FP_LEN]],
    ) -> TairaCertificateV1 {
        TairaCertificateV1 {
            qc: qc_of(header, signers, [0x66; 32]).encode().to_vec(),
            header: header.as_bytes().to_vec(),
            signature: signature.signature.clone(),
            committee: keys.concat(),
            signer_ys: ys.concat(),
            ton_signature: signature.ton_signature.clone(),
        }
    }

    // -- deployment and views --------------------------------------------------------------------

    #[test]
    fn deployment_gives_the_initial_state_and_refuses_bad_configurations() {
        let world = World::new();
        for flavor in FLAVORS {
            let destination = world.destination(flavor);
            assert_eq!(destination.deployment(), &world.deployment(flavor));
            assert_eq!(
                destination.state(),
                &DestinationStateV1 {
                    committee: CommitteeStateV1 {
                        root: world.k0.root(),
                        generation: 5,
                        start: 1000,
                        high: 999,
                        until_ms: T0 + VALIDITY,
                        equivocated: false,
                    },
                    keys: (flavor == TON).then(|| world.k0.keys()),
                    checkpoints: BTreeMap::new(),
                    parliament_paused: false,
                    fast_pause_until_ms: 0,
                    control_nonce: 0,
                    op_count: 0,
                    consumed: BTreeSet::new(),
                    total_supply: 0,
                    balances: BTreeMap::new(),
                }
            );
            assert_eq!(
                world.deployment(flavor).initial_committee(),
                Some(destination.state().committee)
            );
            // `Live` includes the deadline itself.
            assert!(destination.is_live(T0 + VALIDITY));
            assert!(!destination.is_live(T0 + VALIDITY + SECOND));
            assert!(!destination.minting_paused(NOW));
            assert_eq!(
                destination.pause_state(NOW),
                PauseStateV1 {
                    parliament_paused: false,
                    fast_pause_until_ms: 0,
                    control_nonce: 0,
                    effective: false,
                }
            );
            assert_eq!(destination.checkpoint_header(1000), [0; 32]);
            assert!(!destination.is_consumed(0));
            assert_eq!(destination.balance_of(&RECIPIENT), 0);
        }

        // The lane of a deployment is fixed by its profile, and the profile fixes the
        // flavour: EVM on Ethereum and BSC, TON on TON.
        for (flavor, network) in [
            (EVM, SccpNetworkV1::EthereumMainnet),
            (EVM, SccpNetworkV1::BscMainnet),
            (TON, SccpNetworkV1::TonMainnet),
        ] {
            let deployment = DeploymentV1 {
                network,
                ..world.deployment(flavor)
            };
            let destination = Destination::new(deployment.clone()).unwrap();
            assert_eq!(
                Some(destination.lane),
                lane_bytes(SccpNetworkV1::SoraTaira, network, &NETWORK)
            );
            let other = if flavor == EVM { TON } else { EVM };
            assert_eq!(
                Destination::new(DeploymentV1 {
                    flavor: other,
                    ..deployment
                })
                .err(),
                Some(DeploymentError::Flavor)
            );
        }
        // The flavour is checked after the profile and before everything else.
        assert_eq!(
            Destination::new(DeploymentV1 {
                flavor: TON,
                route_revision: 0,
                ..world.deployment(EVM)
            })
            .err(),
            Some(DeploymentError::Flavor)
        );
        assert_eq!(
            Destination::new(DeploymentV1 {
                network: SccpNetworkV1::SoraTaira,
                flavor: TON,
                ..world.deployment(EVM)
            })
            .err(),
            Some(DeploymentError::Network)
        );

        // The bound of the constructor and of `sccp_init` on the pinned `untilMs`.
        let deployment = world.deployment(EVM);
        let span = MAX_VALIDITY_MS + MAX_INIT_SLACK_MS;
        let until = deployment.pin_until_ms;
        assert_eq!(MAX_INIT_SLACK_MS, 3_600_000);
        assert_eq!(deployment.check_init_time(until - 1), Ok(()));
        assert_eq!(deployment.check_init_time(until - span), Ok(()));
        for now_ms in [until, until + SECOND, until - span - 1, 0] {
            assert_eq!(
                deployment.check_init_time(now_ms),
                Err(DeploymentError::UntilMs),
                "{now_ms}"
            );
        }
        // No value above `u64` is formed at either end of the clock.
        assert!(init_until_ms_is_valid(u64::MAX - 1, u64::MAX));
        assert!(!init_until_ms_is_valid(u64::MAX, u64::MAX));
        assert!(init_until_ms_is_valid(u64::MAX - span, u64::MAX));
        assert!(!init_until_ms_is_valid(u64::MAX - span - 1, u64::MAX));
        assert!(!init_until_ms_is_valid(0, 0));
        // An EVM destination never reads the pinned keys.
        let without_keys = DeploymentV1 {
            pin_keys: None,
            ..world.deployment(EVM)
        };
        assert_eq!(Destination::new(without_keys).unwrap().state().keys, None);

        let refusals = [
            (
                DeploymentV1 {
                    network: SccpNetworkV1::SoraTaira,
                    ..world.deployment(EVM)
                },
                DeploymentError::Network,
            ),
            (
                DeploymentV1 {
                    route_revision: 0,
                    ..world.deployment(EVM)
                },
                DeploymentError::ZeroRevision,
            ),
            (
                DeploymentV1 {
                    max_wrapped_supply: 0,
                    ..world.deployment(EVM)
                },
                DeploymentError::ZeroSupplyCap,
            ),
            (
                DeploymentV1 {
                    pin_generation: 0,
                    ..world.deployment(EVM)
                },
                DeploymentError::Pin,
            ),
            (
                DeploymentV1 {
                    pin_root: [0; 32],
                    ..world.deployment(TON)
                },
                DeploymentError::Pin,
            ),
            (
                DeploymentV1 {
                    pin_start_height: 0,
                    ..world.deployment(EVM)
                },
                DeploymentError::Pin,
            ),
            // TON stores the committee: the keys of the pinned root, in canonical order.
            (
                DeploymentV1 {
                    pin_keys: None,
                    ..world.deployment(TON)
                },
                DeploymentError::TonKeys,
            ),
            (
                DeploymentV1 {
                    pin_keys: Some(world.k1.keys()),
                    ..world.deployment(TON)
                },
                DeploymentError::TonKeys,
            ),
            (
                DeploymentV1 {
                    pin_keys: Some(world.k0.keys()[..3].to_vec()),
                    ..world.deployment(TON)
                },
                DeploymentError::TonKeys,
            ),
        ];
        for (deployment, error) in refusals {
            assert_eq!(Destination::new(deployment), Err(error));
            assert!(!error.to_string().is_empty());
        }
        // The first violated rule is reported.
        let both = DeploymentV1 {
            route_revision: 0,
            max_wrapped_supply: 0,
            ..world.deployment(EVM)
        };
        assert_eq!(Destination::new(both), Err(DeploymentError::ZeroRevision));

        assert_eq!((EVM.name(), TON.name()), ("evm", "ton"));
        assert_eq!(EVM.checkpoint_slots(), None);
        assert_eq!(TON.checkpoint_slots(), Some(3));
        assert_eq!(EVM.max_void_frozen_range(), 256);
        assert_eq!(TON.max_void_frozen_range(), 512);
        assert_eq!(MAX_CERTIFICATES_PER_CALL, 16);
        assert_eq!((TON_CHECKPOINT_SLOTS, TON_BUCKET_NONCES), (3, 512));
        assert_eq!(
            (StopReasonV1::Latch.name(), StopReasonV1::Frozen.name()),
            ("latch", "frozen")
        );
    }

    #[test]
    fn certificate_carries_both_wire_forms() {
        let world = World::new();
        let header = world.x(1010);
        let qc = qc_of(&header, 0b1011, [0x66; 32]);
        let signature = world.k0.sign(&qc, &header);
        let keys = world.k0.keys();
        let certificate = TairaCertificateV1::new(&qc, &header, &signature, &keys).unwrap();
        assert_eq!(certificate.qc, qc.encode());
        assert_eq!(certificate.header, header.as_bytes());
        assert_eq!(certificate.ton_signature, signature);
        assert_eq!(
            certificate.signature,
            signature_to_evm192(&signature).unwrap()
        );
        assert_eq!(certificate.committee.len(), 4 * KEY_LEN);
        assert_eq!(committee_keys(&certificate.committee), Some(keys.clone()));
        // `signerYs` follows the signer set in ascending index order: members 0, 1 and 3.
        let ys = [keys[0], keys[1], keys[3]].map(|key| key_y(&key).unwrap());
        assert_eq!(certificate.signer_ys, ys.concat());
        for flavor in FLAVORS {
            assert_eq!(
                world
                    .destination(flavor)
                    .verify_certificate(&certificate, NOW),
                Ok(())
            );
        }

        // No wire form: a signature that is no point, and a signer outside the committee.
        let mut no_point = signature;
        no_point[0] &= 0x7f;
        assert_eq!(
            TairaCertificateV1::new(&qc, &header, &no_point, &keys),
            None
        );
        let spare = qc_of(&header, 0b1_0011, [0x66; 32]);
        assert_eq!(
            TairaCertificateV1::new(&spare, &header, &signature, &keys),
            None
        );
    }

    // -- VerifyCertificate (§5.1.3) --------------------------------------------------------------

    #[test]
    fn verify_certificate_checks_in_the_order_of_the_specification() {
        let world = World::new();
        let good = world.cert(1010);
        let other = world.cert(1020);
        for flavor in FLAVORS {
            let destination = world.destination(flavor);
            let verify = |certificate: &TairaCertificateV1| {
                destination
                    .verify_certificate(certificate, NOW)
                    .map_err(DestinationError::name)
            };
            let change = |edit: &dyn Fn(&mut TairaCertificateV1)| {
                let mut certificate = good.clone();
                edit(&mut certificate);
                certificate
            };
            assert_eq!(verify(&good), Ok(()));

            // Step 1: exact lengths, in the order `QC_FIXED`, `X`, signature, committee,
            // `signerYs`.
            let short_qc = |certificate: &mut TairaCertificateV1| {
                certificate.qc.pop();
            };
            let short_header = |certificate: &mut TairaCertificateV1| {
                certificate.header.pop();
            };
            let short_signature = |certificate: &mut TairaCertificateV1| {
                certificate.signature.pop();
                certificate.ton_signature.pop();
            };
            let five_keys = |certificate: &mut TairaCertificateV1| {
                certificate.committee.extend_from_slice(&[0x80; KEY_LEN]);
            };
            let short_ys = |certificate: &mut TairaCertificateV1| {
                certificate.signer_ys.truncate(2 * FP_LEN);
            };
            assert_eq!(verify(&change(&short_qc)), Err("BadCertificate"));
            assert_eq!(
                verify(&change(&|certificate| certificate.qc.insert(80, 1))),
                Err("BadCertificate")
            );
            assert_eq!(verify(&change(&short_header)), Err("BadHeader"));
            assert_eq!(verify(&change(&short_signature)), Err("BadCertificate"));
            assert_eq!(
                verify(&change(&|certificate| {
                    short_qc(certificate);
                    short_header(certificate);
                })),
                Err("BadCertificate")
            );
            assert_eq!(
                verify(&change(&|certificate| {
                    short_header(certificate);
                    short_signature(certificate);
                    five_keys(certificate);
                })),
                Err("BadHeader")
            );
            // The committee and `signerYs` are EVM calldata. TON reads neither.
            let (committee, signer_ys, both) = match flavor {
                EVM => (
                    Err("BadCommittee"),
                    Err("BadCertificate"),
                    Err("BadCommittee"),
                ),
                TON => (Ok(()), Ok(()), Ok(())),
            };
            assert_eq!(verify(&change(&five_keys)), committee);
            assert_eq!(verify(&change(&short_ys)), signer_ys);
            assert_eq!(
                verify(&change(&|certificate| {
                    five_keys(certificate);
                    short_ys(certificate);
                })),
                both
            );
            assert_eq!(
                verify(&change(&|certificate| {
                    short_signature(certificate);
                    five_keys(certificate);
                })),
                Err("BadCertificate")
            );

            // Step 2: `X` parses, names this network and is active. The signer set is
            // checked later, so a spare bit does not answer first.
            let spare_bit = |certificate: &mut TairaCertificateV1| {
                certificate.qc[112..].copy_from_slice(&0b1_0111_u32.to_be_bytes());
            };
            let certified = |fields: &SccpFinalityHeaderFieldsV1| world.k0.certify(&x(fields));
            let foreign = SccpFinalityHeaderFieldsV1 {
                network_id: [0x12; 32],
                ..plain(world.k0.root(), 5, 1010)
            };
            assert_eq!(verify(&certified(&foreign)), Err("BadHeader"));
            let inactive = SccpFinalityHeaderV1::inactive(NETWORK, 1010, T0 + 10 * SECOND).unwrap();
            assert_eq!(verify(&world.k0.certify(&inactive)), Err("BadHeader"));
            assert_eq!(
                verify(&change(&|certificate| {
                    certificate.header[0] ^= 0x20;
                    spare_bit(certificate);
                })),
                Err("BadHeader")
            );
            assert_eq!(
                SccpFinalityHeaderV1::parse(
                    &change(&|certificate| certificate.header[0] ^= 0x20).header
                ),
                Err(FinalityHeaderError::X1)
            );

            // Step 3: only the current generation and root, before the signer set.
            for fields in [
                plain(world.k0.root(), 4, 1010),
                plain(world.k0.root(), 6, 1010),
                plain(world.k1.root(), 5, 1010),
            ] {
                let mut certificate = certified(&fields);
                assert_eq!(verify(&certificate), Err("CommitteeNotAccepted"));
                spare_bit(&mut certificate);
                assert_eq!(verify(&certificate), Err("CommitteeNotAccepted"));
            }

            // Step 4 (EVM): the calldata committee is the current one. TON has none.
            let foreign_committee = |certificate: &mut TairaCertificateV1| {
                certificate.committee = world.k1.keys().concat();
            };
            assert_eq!(
                verify(&change(&foreign_committee)),
                match flavor {
                    EVM => Err("BadCommittee"),
                    TON => Ok(()),
                }
            );

            // Step 5: no spare bit and exactly q = 3 signers; a superset is refused. The
            // signer set is checked before the encodings of step 6.
            let signers = |bits: u32| {
                change(&|certificate| {
                    certificate.qc[112..].copy_from_slice(&bits.to_be_bytes());
                })
            };
            for bits in [0b1_0111, 0b0011, 0b1111, 0, 0x8000_0007] {
                assert_eq!(verify(&signers(bits)), Err("BadCertificate"), "{bits:#b}");
            }
            let identity = |certificate: &mut TairaCertificateV1| {
                certificate.signature = IDENTITY_SIGNATURE_EVM.to_vec();
                certificate.ton_signature = IDENTITY_SIGNATURE.to_vec();
            };
            assert_eq!(
                verify(&change(&|certificate| {
                    spare_bit(certificate);
                    identity(certificate);
                })),
                Err("BadCertificate")
            );

            // Step 6: the identity signature, on both flavours.
            assert_eq!(verify(&change(&identity)), Err("BadSignature"));

            // Steps 9–11: a signature of another header, of another signer set, and a
            // result body the committee did not sign.
            let transplanted = |certificate: &mut TairaCertificateV1| {
                certificate.signature.clone_from(&other.signature);
                certificate.ton_signature.clone_from(&other.ton_signature);
            };
            assert_eq!(verify(&change(&transplanted)), Err("BadSignature"));
            assert_eq!(
                verify(&signers(0b1110)),
                Err(match flavor {
                    // `signerYs` no longer belongs to the signers named.
                    EVM => "BadCommittee",
                    TON => "BadSignature",
                })
            );
            assert_eq!(
                verify(&change(&|certificate| certificate.qc[80] ^= 1)),
                Err("BadSignature")
            );
            // Another quorum of the same committee verifies as well.
            assert_eq!(
                verify(&world.k0.certify_by(&world.x(1010), 0b1101, [0x55; 32])),
                Ok(())
            );

            // The `Live` check comes first, and verification has no effect.
            assert_eq!(
                destination.verify_certificate(&change(&short_qc), T0 + VALIDITY + SECOND),
                Err(DestinationError::CommitteeNotAccepted)
            );
            assert_eq!(destination, world.destination(flavor));
        }
    }

    #[test]
    fn evm_encodings_are_checked_before_the_cheap_path_and_before_the_curve() {
        let world = World::new();
        let good = world.cert(1010);
        let other = world.cert(1020);
        let keys = world.k0.keys();
        let ys: Vec<[u8; FP_LEN]> = keys.iter().map(|key| key_y(key).unwrap()).collect();
        let change = |edit: &dyn Fn(&mut TairaCertificateV1)| {
            let mut certificate = good.clone();
            edit(&mut certificate);
            certificate
        };
        let y_not_reduced = change(&|certificate| {
            certificate.signer_ys[..FP_LEN].copy_from_slice(&BLS12_381_P);
        });
        let limb_not_reduced = change(&|certificate| {
            certificate.signature[FP_LEN..2 * FP_LEN].copy_from_slice(&BLS12_381_P);
        });
        let wrong_sign = change(&|certificate| {
            certificate.signer_ys[FP_LEN..2 * FP_LEN].copy_from_slice(&negated(&ys[1]));
        });
        let identity = change(&|certificate| {
            certificate.signature = IDENTITY_SIGNATURE_EVM.to_vec();
        });
        // `y ± 1` keeps the sign class and leaves the curve.
        let off_curve_y = change(&|certificate| certificate.signer_ys[3 * FP_LEN - 1] ^= 1);
        let off_curve_signature = change(&|certificate| certificate.signature[191] ^= 1);
        let transplanted = change(&|certificate| {
            certificate.signature.clone_from(&other.signature);
        });

        let fresh = world.destination(EVM);
        let mut with_checkpoint = world.destination(EVM);
        submit(&mut with_checkpoint, std::slice::from_ref(&good), NOW).unwrap();
        // Step 6, in its order, whether or not `X` is stored.
        for destination in [&fresh, &with_checkpoint] {
            let verify = |certificate: &TairaCertificateV1| {
                destination
                    .verify_certificate(certificate, NOW)
                    .map_err(DestinationError::name)
            };
            assert_eq!(verify(&identity), Err("BadSignature"));
            assert_eq!(verify(&y_not_reduced), Err("BadCommittee"));
            assert_eq!(verify(&limb_not_reduced), Err("BadSignature"));
            assert_eq!(verify(&wrong_sign), Err("BadCommittee"));
            // The identity is refused first, then the `y` bound, then the limb bound.
            assert_eq!(
                verify(&change(&|certificate| {
                    certificate.signature = IDENTITY_SIGNATURE_EVM.to_vec();
                    certificate.signer_ys[..FP_LEN].copy_from_slice(&BLS12_381_P);
                })),
                Err("BadSignature")
            );
            assert_eq!(
                verify(&change(&|certificate| {
                    certificate.signer_ys[..FP_LEN].copy_from_slice(&BLS12_381_P);
                    certificate.signature[..FP_LEN].copy_from_slice(&BLS12_381_P);
                })),
                Err("BadCommittee")
            );
            assert_eq!(
                verify(&change(&|certificate| {
                    certificate.signature[..FP_LEN].copy_from_slice(&BLS12_381_P);
                    certificate.signer_ys[FP_LEN..2 * FP_LEN].copy_from_slice(&negated(&ys[1]));
                })),
                Err("BadSignature")
            );
        }
        // Steps 10 and 11 run on the full path only: a stored `X` is not checked again.
        let verify = |destination: &Destination, certificate: &TairaCertificateV1| {
            destination
                .verify_certificate(certificate, NOW)
                .map_err(DestinationError::name)
        };
        assert_eq!(verify(&fresh, &off_curve_y), Err("BadCommittee"));
        assert_eq!(verify(&fresh, &off_curve_signature), Err("BadSignature"));
        assert_eq!(verify(&fresh, &transplanted), Err("BadSignature"));
        // A signer point off the curve answers before a signature off the curve.
        assert_eq!(
            verify(
                &fresh,
                &change(&|certificate| {
                    certificate.signer_ys[3 * FP_LEN - 1] ^= 1;
                    certificate.signature[191] ^= 1;
                })
            ),
            Err("BadCommittee")
        );
        for certificate in [&off_curve_y, &off_curve_signature, &transplanted] {
            assert_eq!(verify(&with_checkpoint, certificate), Ok(()));
        }

        // The key rules of step 6 need a committee that holds such a key. Members 1–3 of `K0`
        // certify `X` under it, and a second certificate then names the odd key as a signer:
        // the cheap path applies, so only step 6 can refuse it.
        let one = {
            let mut one = [0_u8; FP_LEN];
            one[FP_LEN - 1] = 1;
            one
        };
        let key = |first: u8, rest: u8| {
            let mut key = [rest; KEY_LEN];
            key[0] = first;
            key
        };
        let cases = [
            // The infinity flag beside the compression flag.
            (key(0xc0, 0), [0; FP_LEN], Err("BadCommittee")),
            // No compression flag.
            (key(0x00, 0), one, Err("BadCommittee")),
            // The sign flag without a `y` above `HALF_P`.
            (key(0xa0, 0), one, Err("BadCommittee")),
            // `x ≥ p`.
            (key(0x9f, 0xff), one, Err("BadCommittee")),
            (key(0x9a, 0xff), one, Err("BadCommittee")),
            // `(x, y) = (0, 0)`, which EIP-2537 reads as the point at infinity.
            (key(0x80, 0), [0; FP_LEN], Err("BadCommittee")),
            // Reduced coordinates other than `(0, 0)` pass step 6, on the curve or not.
            (key(0x80, 0), one, Ok(())),
            (key(0x9a, 0), one, Ok(())),
        ];
        for (odd, y, expected) in cases {
            let committee = [odd, keys[1], keys[2], keys[3]];
            let root = committee_root(&committee).unwrap();
            let header = x(&plain(root, 5, 1010));
            let qc = qc_of(&header, 0b1110, [0x66; 32]);
            let genuine =
                TairaCertificateV1::new(&qc, &header, &world.k0.sign(&qc, &header), &committee)
                    .unwrap();
            let mut destination = Destination::new(DeploymentV1 {
                pin_root: root,
                ..world.deployment(EVM)
            })
            .unwrap();
            let probe = unsigned(&header, 0b0111, &committee, &genuine, &[y, ys[1], ys[2]]);
            // Not stored: the odd key cannot be aggregated.
            assert_eq!(
                verify(&destination, &probe),
                Err("BadCommittee"),
                "{odd:02x?}"
            );
            submit(&mut destination, &[genuine], NOW).unwrap();
            assert_eq!(verify(&destination, &probe), expected, "{odd:02x?}");
        }
    }

    #[test]
    fn signer_keys_off_the_curve_or_outside_the_subgroup_are_refused() {
        let world = World::new();
        let keys = world.k0.keys();
        let genuine = world.cert(1010);
        let point = |key: &[u8; KEY_LEN]| G1Affine::from_compressed(key).into_option().unwrap();

        // `apk = O`: a rogue key that cancels two others. Every key is a valid key.
        let rogue = (-(G1Projective::from(point(&keys[0])) + point(&keys[1])))
            .to_affine()
            .to_compressed();
        let mut cancelling = vec![keys[0], keys[1], rogue, keys[3]];
        cancelling.sort_unstable();
        let signers = cancelling
            .iter()
            .enumerate()
            .filter(|(_, key)| **key != keys[3])
            .fold(0_u32, |bits, (index, _)| bits | (1 << index));

        let outside = key_outside_the_subgroup();
        let mut torsion = vec![outside, keys[1], keys[2], keys[3]];
        torsion.sort_unstable();
        assert_eq!(torsion[0], outside);

        for flavor in FLAVORS {
            let pinned = |committee: &[[u8; KEY_LEN]]| {
                Destination::new(DeploymentV1 {
                    pin_root: committee_root(committee).unwrap(),
                    pin_keys: Some(committee.to_vec()),
                    ..world.deployment(flavor)
                })
                .unwrap()
            };
            let probe = |committee: &[[u8; KEY_LEN]], signers: u32| {
                let header = x(&plain(committee_root(committee).unwrap(), 5, 1010));
                let ys: Vec<[u8; FP_LEN]> = signer_indices(signers, committee.len())
                    .unwrap()
                    .into_iter()
                    .map(|index| key_y(&committee[index]).unwrap())
                    .collect();
                unsigned(&header, signers, committee, &genuine, &ys)
            };
            // `apk = O` is `BadCommittee` on EVM (step 10). TON has the opcode's verdict only.
            assert_eq!(
                pinned(&cancelling).verify_certificate(&probe(&cancelling, signers), NOW),
                Err(match flavor {
                    DestinationFlavor::Evm => DestinationError::BadCommittee,
                    DestinationFlavor::Ton => DestinationError::BadSignature,
                })
            );
            // EVM reports `apk = O` before it reads `σ` as a point.
            if flavor == EVM {
                let mut off_curve = probe(&cancelling, signers);
                off_curve.signature[EVM_SIGNATURE_LEN - 1] ^= 0x01;
                assert_eq!(
                    pinned(&cancelling).verify_certificate(&off_curve, NOW),
                    Err(DestinationError::BadCommittee)
                );
                // With a nonzero aggregate the same signature is the first refusal.
                let mut off_curve = genuine.clone();
                off_curve.signature[EVM_SIGNATURE_LEN - 1] ^= 0x01;
                assert_eq!(
                    world.destination(EVM).verify_certificate(&off_curve, NOW),
                    Err(DestinationError::BadSignature)
                );
            }
            // The aggregate is a point outside G1: the pairing precompile refuses it, and
            // TON's opcode refuses the key.
            assert_eq!(
                pinned(&torsion).verify_certificate(&probe(&torsion, 0b0111), NOW),
                Err(DestinationError::BadSignature)
            );
            // The same certificate without the odd key is refused for its signature only.
            assert_eq!(
                pinned(&torsion).verify_certificate(&probe(&torsion, 0b1110), NOW),
                Err(DestinationError::BadSignature)
            );
        }

        // TON stores whatever keys hash to the root. Keys that are no points give no
        // aggregate: the opcode answers false. EVM refuses their flags at step 6.
        let no_points = [
            [0x01; KEY_LEN],
            [0x02; KEY_LEN],
            [0x03; KEY_LEN],
            [0x04; KEY_LEN],
        ];
        let root = committee_root(&no_points).unwrap();
        let header = x(&plain(root, 5, 1010));
        let certificate = unsigned(&header, 0b0111, &no_points, &genuine, &[[0; FP_LEN]; 3]);
        let outcome = |flavor: DestinationFlavor| {
            Destination::new(DeploymentV1 {
                pin_root: root,
                pin_keys: Some(no_points.to_vec()),
                ..world.deployment(flavor)
            })
            .unwrap()
            .verify_certificate(&certificate, NOW)
        };
        assert_eq!(outcome(TON), Err(DestinationError::BadSignature));
        assert_eq!(outcome(EVM), Err(DestinationError::BadCommittee));
        // A TON signature that is no point is refused the same way.
        let mut certificate = genuine.clone();
        certificate.ton_signature[0] &= 0x7f;
        assert_eq!(
            world.destination(TON).verify_certificate(&certificate, NOW),
            Err(DestinationError::BadSignature)
        );

        // A stored TON key that is the identity: the opcode refuses it, so `q − 1` members
        // cannot certify with the identity key filling the quorum. Members 1 and 2 sign; the
        // bitmap also names the identity seat.
        let mut with_identity = vec![IDENTITY_KEY, keys[1], keys[2], keys[3]];
        with_identity.sort_unstable();
        let seat = |key: &[u8; KEY_LEN]| with_identity.iter().position(|k| k == key).unwrap();
        let signers = [IDENTITY_KEY, keys[1], keys[2]]
            .iter()
            .fold(0_u32, |bits, key| bits | (1 << seat(key)));
        let root = committee_root(&with_identity).unwrap();
        let header = x(&plain(root, 5, 1010));
        let qc = qc_of(&header, signers, [0x66; 32]);
        let result = outer_result(&header, &qc.result_body).0;
        let preimage = commit_preimage(&INSTANCE, &qc, header.height(), &result);
        let shares: Vec<[u8; SIGNATURE_LEN]> = [1, 2]
            .into_iter()
            .map(|member| sign_preimage(&world.k0.members[member].1, &preimage).unwrap())
            .collect();
        let mut certificate = genuine.clone();
        certificate.qc = qc.encode().to_vec();
        certificate.header = header.as_bytes().to_vec();
        certificate.ton_signature = aggregate(shares).unwrap().to_vec();
        let minter = Destination::new(DeploymentV1 {
            pin_root: root,
            pin_keys: Some(with_identity.clone()),
            ..world.deployment(TON)
        })
        .unwrap();
        assert_eq!(
            minter.verify_certificate(&certificate, NOW),
            Err(DestinationError::BadSignature)
        );
    }

    /// Where a destination is stricter than the bare pairing equation, and where the two
    /// flavours differ.
    ///
    /// A signer key shifted by a point of the curve outside the G1 subgroup gives the same
    /// pairing value, so `e(apk, H(m)) · e(−g1, σ) = 1` still holds for the genuine
    /// signature, and a model that checks only that equation accepts the certificate. A
    /// destination does not: the EIP-2537 pairing precompile fails on an aggregate key
    /// outside G1, and TON's aggregate-verify opcode refuses the key. When two signer keys
    /// are shifted by `T` and `−T` the aggregate is back in G1: EVM, which sees the
    /// aggregate only, accepts, and TON still refuses each key.
    #[test]
    fn signer_key_shifted_out_of_the_subgroup_is_refused_though_the_pairing_holds() {
        /// The effective cofactor of G1 (RFC 9380 §8.8.1): `h_eff · P` is in G1 for every
        /// point `P` of the curve.
        const H_EFF: u64 = 0xd201_0000_0001_0001;
        // `scalar · point` by double-and-add, for a point in or out of the subgroup.
        let times = |point: G1Projective, scalar: u64| {
            (0..u64::BITS)
                .rev()
                .fold(G1Projective::identity(), |sum, bit| {
                    let doubled = sum.double();
                    if (scalar >> bit) & 1 == 1 {
                        doubled + point
                    } else {
                        doubled
                    }
                })
        };
        let world = World::new();
        // A point `w` of the curve outside the subgroup, and its component outside the
        // r-torsion: `w − (h_eff⁻¹ mod r) · (h_eff · w)`.
        let w = G1Affine::from_compressed_unchecked(&key_outside_the_subgroup()).unwrap();
        let w = G1Projective::from(w);
        let in_subgroup = times(w, H_EFF);
        assert!(bool::from(in_subgroup.to_affine().is_torsion_free()));
        let shift = w - in_subgroup * Scalar::from(H_EFF).invert().unwrap();
        assert!(!bool::from(shift.is_identity()));
        assert!(bool::from(shift.to_affine().is_on_curve()));
        assert!(!bool::from(shift.to_affine().is_torsion_free()));
        assert!(bool::from(times(shift, H_EFF).is_identity()));

        // The committee `K0` with some members listed under other key bytes, in canonical
        // order, and the certificate members 0, 1 and 2 sign with their genuine secrets at
        // the seats that order gives them.
        let genuine = world.k0.keys();
        let point = |key: &[u8; KEY_LEN]| G1Affine::from_compressed(key).unwrap();
        let odd_committee = |listed: [[u8; KEY_LEN]; 4]| {
            let mut seats = [
                (listed[0], 0_usize),
                (listed[1], 1),
                (listed[2], 2),
                (listed[3], 3),
            ];
            seats.sort_unstable();
            let committee = seats.map(|(key, _)| key);
            let signing = seats
                .iter()
                .enumerate()
                .filter(|(_, (_, member))| *member != 3);
            let signers = signing
                .clone()
                .fold(0_u32, |bits, (seat, _)| bits | (1 << seat));
            let header = x(&plain(committee_root(&committee).unwrap(), 5, 1010));
            let qc = qc_of(&header, signers, [0x66; 32]);
            let result = outer_result(&header, &qc.result_body).0;
            let preimage = commit_preimage(&INSTANCE, &qc, header.height(), &result);
            let shares: Vec<[u8; SIGNATURE_LEN]> = signing
                .map(|(_, (_, member))| {
                    sign_preimage(&world.k0.members[*member].1, &preimage).unwrap()
                })
                .collect();
            let certificate =
                TairaCertificateV1::new(&qc, &header, &aggregate(shares).unwrap(), &committee)
                    .unwrap();
            (committee, signers, certificate)
        };
        let pinned = |flavor: DestinationFlavor, committee: &[[u8; KEY_LEN]; 4]| {
            Destination::new(DeploymentV1 {
                pin_root: committee_root(committee).unwrap(),
                pin_keys: Some(committee.to_vec()),
                ..world.deployment(flavor)
            })
            .unwrap()
        };
        let sum_of = |committee: &[[u8; KEY_LEN]; 4], signers: u32| {
            let sum = signer_point_sum(committee, signers).unwrap();
            G1Projective::from(G1Affine::from_compressed_unchecked(&sum).unwrap())
        };
        let sound_sum = sum_of(&[genuine[0], genuine[1], genuine[2], genuine[3]], 0b0111);

        // Member 0 under its shifted key. The aggregate key differs from the genuine one by
        // the shift alone, and the pairing does not see the shift: the equation holds for
        // the genuine signature.
        let shifted = (G1Projective::from(point(&genuine[0])) + shift)
            .to_affine()
            .to_compressed();
        let (committee, signers, certificate) =
            odd_committee([shifted, genuine[1], genuine[2], genuine[3]]);
        let odd_sum = sum_of(&committee, signers);
        assert_eq!(odd_sum - sound_sum, shift);
        assert!(!bool::from(odd_sum.to_affine().is_torsion_free()));
        let generator = G2Affine::generator();
        assert_eq!(
            pairing(&odd_sum.to_affine(), &generator),
            pairing(&sound_sum.to_affine(), &generator)
        );
        for flavor in FLAVORS {
            assert_eq!(
                pinned(flavor, &committee).verify_certificate(&certificate, NOW),
                Err(DestinationError::BadSignature)
            );
            // The same members under their own keys verify.
            assert_eq!(
                world
                    .destination(flavor)
                    .verify_certificate(&world.cert(1010), NOW),
                Ok(())
            );
        }

        // Members 0 and 1 under keys shifted by `T` and `−T`: neither key is in G1, and
        // their sum is the genuine aggregate. EVM sees the aggregate only and accepts; TON's
        // opcode refuses each key.
        let unshifted = (G1Projective::from(point(&genuine[1])) - shift)
            .to_affine()
            .to_compressed();
        let (committee, signers, certificate) =
            odd_committee([shifted, unshifted, genuine[2], genuine[3]]);
        assert_eq!(sum_of(&committee, signers), sound_sum);
        assert_eq!(aggregate_public_key(&committee, signers), None);
        let mut evm = pinned(EVM, &committee);
        assert_eq!(evm.verify_certificate(&certificate, NOW), Ok(()));
        let done = submit(&mut evm, std::slice::from_ref(&certificate), NOW).unwrap();
        assert!(matches!(
            done.events[0],
            DestinationEvent::Certificate { height: 1010, .. }
        ));
        let mut ton = pinned(TON, &committee);
        assert_eq!(
            ton.verify_certificate(&certificate, NOW),
            Err(DestinationError::BadSignature)
        );
        assert_eq!(
            refused(&mut ton, |destination| submit(
                destination,
                std::slice::from_ref(&certificate),
                NOW
            )),
            DestinationError::BadSignature
        );
    }

    #[test]
    fn cheap_path_skips_signature_check_and_certificate_event() {
        let world = World::new();
        let header = world.x(1010);
        let good = world.cert(1010);
        let other = world.cert(1020);
        // The same `X` with fields the committee never signed.
        let mut forged = world.k0.certify_by(&header, 0b1110, [0x55; 32]);
        forged.signature.clone_from(&other.signature);
        forged.ton_signature.clone_from(&other.ton_signature);
        let mut identity = good.clone();
        identity.signature = IDENTITY_SIGNATURE_EVM.to_vec();
        identity.ton_signature = IDENTITY_SIGNATURE.to_vec();

        for flavor in FLAVORS {
            let _route = on(flavor);
            let mut destination = world.destination(flavor);
            // Not stored: the full path refuses the forgery.
            assert_eq!(
                refused(&mut destination, |destination| submit(
                    destination,
                    std::slice::from_ref(&forged),
                    NOW
                )),
                DestinationError::BadSignature
            );
            // The full path publishes the certificate, then records the checkpoint.
            let done = submit(&mut destination, std::slice::from_ref(&good), NOW).unwrap();
            assert_eq!(
                done.events,
                [certificate_event(&good, flavor), checkpointed(&header)]
            );
            assert_eq!(destination.checkpoint_header(1010), id(&header));

            // Stored: the signature is not checked and nothing is published again.
            assert_eq!(destination.verify_certificate(&forged, NOW), Ok(()));
            assert_eq!(
                refused(&mut destination, |destination| submit(
                    destination,
                    std::slice::from_ref(&forged),
                    NOW
                )),
                DestinationError::NothingToDo
            );
            // An inline use of the stored `X` emits no certificate and no checkpoint: the
            // call goes on to its own checks.
            assert_eq!(
                refused(&mut destination, |destination| destination.finalize(
                    inline(&forged),
                    &dummy_message(),
                    NOW
                )),
                DestinationError::BadProof
            );
            // Steps 1–6 still run: the identity signature is refused on both flavours, and
            // so are a wrong signer set and another generation's header.
            assert_eq!(
                destination.verify_certificate(&identity, NOW),
                Err(DestinationError::BadSignature)
            );
            let mut superset = forged.clone();
            superset.qc[112..].copy_from_slice(&0b1111_u32.to_be_bytes());
            assert_eq!(
                destination.verify_certificate(&superset, NOW),
                Err(DestinationError::BadCertificate)
            );
            assert_eq!(
                refused(&mut destination, |destination| submit(
                    destination,
                    std::slice::from_ref(&identity),
                    NOW
                )),
                DestinationError::BadSignature
            );
        }

        // A handoff whose `X` an inline call stored is installed by `submitCheckpoints`
        // through the cheap path, with no second publication.
        // One pass per flavour, each on the route of its own profile.
        for flavor in FLAVORS {
            let _route = on(flavor);
            let mut ledger = Ledger::default();
            let (payload, leaf) = transfer(0, 1_000, T0 + DAY);
            let handoff = ledger.block_with(&world, 1100, &[leaf], |fields| {
                fields.flags |= FLAG_ROTATION;
                fields.validity_ms = VALIDITY;
                fields.next_committee_root = world.k1.root();
            });
            let certificate = world.k0.certify(&handoff);
            let proof = ledger.message(&payload, 1100, 0, &handoff);
            // The calls of the pass, on the ledger built above for its route.
            {
                let mut destination = world.destination(flavor);
                let now_ms = T0 + HOUR;
                let done = destination
                    .finalize(inline(&certificate), &proof, now_ms)
                    .unwrap();
                assert_eq!(done.events.len(), 3);
                assert_eq!(
                    done.events[..2],
                    [
                        certificate_event(&certificate, flavor),
                        checkpointed(&handoff)
                    ]
                );
                // An inline entry point records the checkpoint and raises `high`, and installs
                // no successor.
                let committee = destination.state().committee;
                assert_eq!((committee.generation, committee.high), (5, 1100));
                assert_eq!(committee.root, world.k0.root());

                let done = destination
                    .submit_checkpoints(
                        std::slice::from_ref(&certificate),
                        &[Some(world.k1.keys())],
                        now_ms,
                    )
                    .unwrap();
                assert_eq!(
                    done.events,
                    [DestinationEvent::CommitteeRotated(RotationV1 {
                        generation: 6,
                        root: world.k1.root(),
                        until_ms: handoff.timestamp_ms() + VALIDITY,
                        start: 1101,
                    })]
                );
                assert_eq!(done.stopped, None);
            }
        }
    }

    // -- the committee machine through the entry points (§5.1.2) ---------------------------------

    #[test]
    fn violations_v1_v2_v3_latch_with_reason_codes() {
        let world = World::new();
        let root = world.k0.root();
        for flavor in FLAVORS {
            let _route = on(flavor);
            // V1: a second `X` at a stored height.
            let mut destination = world.destination(flavor);
            let first = world.x(1010);
            submit(&mut destination, &[world.cert(1010)], NOW).unwrap();
            let conflict = x(&SccpFinalityHeaderFieldsV1 {
                timestamp_ms: first.timestamp_ms() + 1,
                ..plain(root, 5, 1010)
            });
            let conflicting = world.k0.certify(&conflict);
            let done = submit(
                &mut destination,
                &[conflicting.clone(), world.cert(1020)],
                NOW,
            )
            .unwrap();
            // Latching does not revert: the certificate is published, the latch is set and
            // processing stops before the next certificate.
            let violation = ViolationV1 {
                reason: LatchReasonV1::ConflictingCheckpoint,
                generation: 5,
                height: 1010,
                a: id(&first),
                b: id(&conflict),
            };
            assert_eq!(violation.reason.code(), 1);
            assert_eq!(
                done,
                CallOutcome {
                    events: vec![
                        certificate_event(&conflicting, flavor),
                        DestinationEvent::Latched(violation),
                    ],
                    stopped: Some(StopReasonV1::Latch),
                    returned: None,
                }
            );
            let state = destination.state();
            assert!(state.committee.equivocated);
            assert_eq!((state.committee.until_ms, state.committee.high), (0, 1010));
            assert_eq!(state.checkpoints, BTreeMap::from([(1010, id(&first))]));
            assert!(!destination.is_live(0));

            // The latch never clears: every entry point that needs `Live` answers
            // `Equivocated`, and frozen voids are open.
            assert_eq!(
                refused(&mut destination, |destination| submit(
                    destination,
                    &[world.cert(1020)],
                    NOW
                )),
                DestinationError::Equivocated
            );
            let certificate = world.cert(1020);
            let proof = dummy_message();
            assert_eq!(
                refused(&mut destination, |destination| destination.finalize(
                    inline(&certificate),
                    &proof,
                    NOW
                )),
                DestinationError::Equivocated
            );
            let checkpoint = stored(&first);
            assert_eq!(
                refused(&mut destination, |destination| destination.apply_control(
                    CertificateSourceV1::Checkpoint(&checkpoint),
                    &ControlProofV1::default(),
                    NOW
                )),
                DestinationError::Equivocated
            );
            assert_eq!(
                destination.verify_certificate(&certificate, NOW),
                Err(DestinationError::Equivocated)
            );
            destination.void_frozen(0, 1, NOW).unwrap();

            // V2: a height before the generation's own tenure.
            let mut destination = world.destination(flavor);
            let early = world.x(999);
            let done = submit(&mut destination, &[world.cert(999)], NOW).unwrap();
            assert_eq!(done.stopped, Some(StopReasonV1::Latch));
            assert_eq!(
                done.events[1],
                DestinationEvent::Latched(ViolationV1 {
                    reason: LatchReasonV1::BelowStart,
                    generation: 5,
                    height: 999,
                    a: root,
                    b: id(&early),
                })
            );
            assert!(destination.state().checkpoints.is_empty());
            // The neighbour at `cur.start` is accepted.
            let mut destination = world.destination(flavor);
            assert_eq!(
                submit(&mut destination, &[world.cert(1000)], NOW)
                    .unwrap()
                    .stopped,
                None
            );

            // V3: a handoff below a height the generation already certified. The latch comes
            // before a TON destination asks for the successor's keys.
            let mut destination = world.destination(flavor);
            submit(&mut destination, &[world.cert(1020)], NOW).unwrap();
            let below = world.handoff(1010);
            let done = submit(&mut destination, &[world.k0.certify(&below)], NOW).unwrap();
            assert_eq!(done.stopped, Some(StopReasonV1::Latch));
            assert_eq!(
                done.events[1],
                DestinationEvent::Latched(ViolationV1 {
                    reason: LatchReasonV1::RotationBelowHigh,
                    generation: 5,
                    height: 1010,
                    a: root,
                    b: id(&below),
                })
            );
            let committee = destination.state().committee;
            assert_eq!((committee.generation, committee.root), (5, root));
            assert!(committee.equivocated);

            // The same `X` under another result body is the same checkpoint: no conflict.
            let mut destination = world.destination(flavor);
            submit(&mut destination, &[world.cert(1010)], NOW).unwrap();
            let again = world.k0.certify_by(&first, 0b0111, [0x55; 32]);
            assert_eq!(
                refused(&mut destination, |destination| submit(
                    destination,
                    &[again],
                    NOW
                )),
                DestinationError::NothingToDo
            );
        }
    }

    #[test]
    fn inline_violation_reverts_latch_required() {
        let world = World::new();
        for flavor in FLAVORS {
            let _route = on(flavor);
            let mut destination = world.destination(flavor);
            submit(&mut destination, &[world.cert(1020)], NOW).unwrap();
            let first = world.x(1020);
            let conflict = x(&SccpFinalityHeaderFieldsV1 {
                timestamp_ms: first.timestamp_ms() + 1,
                ..plain(world.k0.root(), 5, 1020)
            });
            // V1, V2 and V3 through every inline entry point: a revert, never a latch.
            for violating in [conflict, world.x(999), world.handoff(1010)] {
                let certificate = world.k0.certify(&violating);
                let message = dummy_message();
                let control = ControlProofV1::default();
                assert_eq!(
                    refused(&mut destination, |destination| destination.finalize(
                        inline(&certificate),
                        &message,
                        NOW
                    )),
                    DestinationError::LatchRequired
                );
                assert_eq!(
                    refused(&mut destination, |destination| destination.apply_control(
                        inline(&certificate),
                        &control,
                        NOW
                    )),
                    DestinationError::LatchRequired
                );
                assert_eq!(
                    refused(&mut destination, |destination| destination.void_expired(
                        0,
                        inline(&certificate),
                        &message,
                        NOW
                    )),
                    DestinationError::LatchRequired
                );
                // `LatchRequired` answers before the `Live` check.
                assert_eq!(
                    refused(&mut destination, |destination| destination.finalize(
                        inline(&certificate),
                        &message,
                        T0 + VALIDITY + SECOND
                    )),
                    DestinationError::LatchRequired
                );
            }
            assert!(!destination.state().committee.equivocated);
            // The relayer resubmits through `submitCheckpoints`, which latches.
            let done = submit(
                &mut destination,
                &[world.k0.certify(&world.handoff(1010))],
                NOW,
            )
            .unwrap();
            assert_eq!(done.stopped, Some(StopReasonV1::Latch));
            assert!(destination.state().committee.equivocated);
        }
    }

    #[test]
    fn rotation_deadline_uses_t_eff() {
        let world = World::new();
        let root = world.k0.root();
        let next_keys = [Some(world.k1.keys())];
        for flavor in FLAVORS {
            // A handoff certified in the past: the deadline counts from the header's time.
            let mut destination = world.destination(flavor);
            let past = world.handoff(1100);
            let certificate = world.k0.certify(&past);
            let now_ms = past.timestamp_ms() + HOUR;
            let done = destination
                .submit_checkpoints(std::slice::from_ref(&certificate), &next_keys, now_ms)
                .unwrap();
            let rotation = RotationV1 {
                generation: 6,
                root: world.k1.root(),
                until_ms: past.timestamp_ms() + VALIDITY,
                start: 1101,
            };
            assert_eq!(
                done,
                CallOutcome {
                    events: vec![
                        certificate_event(&certificate, flavor),
                        checkpointed(&past),
                        DestinationEvent::CommitteeRotated(rotation),
                    ],
                    stopped: None,
                    returned: None,
                }
            );
            assert_eq!(
                destination.state().committee,
                CommitteeStateV1 {
                    root: world.k1.root(),
                    generation: 6,
                    start: 1101,
                    high: 1100,
                    until_ms: past.timestamp_ms() + VALIDITY,
                    equivocated: false,
                }
            );
            // The handoff is no longer of the current generation: no second rotation.
            assert_eq!(
                refused(&mut destination, |destination| destination
                    .submit_checkpoints(
                        std::slice::from_ref(&certificate),
                        &next_keys,
                        now_ms
                    )),
                DestinationError::CommitteeNotAccepted
            );

            // A future-dated handoff: at most `validity_ms` from the destination's clock.
            let mut destination = world.destination(flavor);
            let future = x(&SccpFinalityHeaderFieldsV1 {
                timestamp_ms: NOW + 30 * DAY,
                ..handoff(root, 5, 1100, world.k1.root())
            });
            destination
                .submit_checkpoints(&[world.k0.certify(&future)], &next_keys, NOW)
                .unwrap();
            assert_eq!(destination.state().committee.until_ms, NOW + VALIDITY);

            // A sub-second deadline: `Live` at the last whole second before it, not after.
            let mut destination = world.destination(flavor);
            let odd = x(&SccpFinalityHeaderFieldsV1 {
                timestamp_ms: T0 + 100 * SECOND + 500,
                validity_ms: DAY,
                ..handoff(root, 5, 1100, world.k1.root())
            });
            destination
                .submit_checkpoints(&[world.k0.certify(&odd)], &next_keys, NOW + HOUR)
                .unwrap();
            let until_ms = T0 + 100 * SECOND + 500 + DAY;
            assert_eq!(destination.state().committee.until_ms, until_ms);
            assert!(destination.is_live(until_ms - 500));
            assert!(!destination.is_live(until_ms + 500));

            // A successor whose deadline has already passed: the rotation applies, the
            // destination is frozen and the rest of the batch is not processed.
            let mut destination = world.destination(flavor);
            let late = x(&SccpFinalityHeaderFieldsV1 {
                validity_ms: MINUTE,
                ..handoff(root, 5, 1100, world.k1.root())
            });
            let after = world.k1.certify(&x(&plain(world.k1.root(), 6, 1101)));
            let now_ms = T0 + DAY;
            let done = destination
                .submit_checkpoints(
                    &[world.k0.certify(&late), after.clone()],
                    &next_keys,
                    now_ms,
                )
                .unwrap();
            assert_eq!(done.stopped, Some(StopReasonV1::Frozen));
            assert_eq!(done.events.len(), 3);
            assert_eq!(
                done.events[2],
                DestinationEvent::CommitteeRotated(RotationV1 {
                    generation: 6,
                    root: world.k1.root(),
                    until_ms: late.timestamp_ms() + MINUTE,
                    start: 1101,
                })
            );
            let committee = destination.state().committee;
            assert_eq!((committee.generation, committee.high), (6, 1100));
            assert!(!committee.equivocated && !destination.is_live(now_ms));
            assert_eq!(destination.state().checkpoints.len(), 1);
            assert_eq!(
                refused(&mut destination, |destination| submit(
                    destination,
                    &[after],
                    now_ms
                )),
                DestinationError::CommitteeNotAccepted
            );
            destination.void_frozen(0, 3, now_ms).unwrap();

            // The deadline saturates at 2^64 − 1: no rotation aborts for arithmetic.
            let mut destination = Destination::new(DeploymentV1 {
                pin_until_ms: u64::MAX,
                ..world.deployment(flavor)
            })
            .unwrap();
            let last = x(&SccpFinalityHeaderFieldsV1 {
                timestamp_ms: u64::MAX - 10,
                validity_ms: MAX_VALIDITY_MS,
                ..handoff(root, 5, 1100, world.k1.root())
            });
            let done = destination
                .submit_checkpoints(&[world.k0.certify(&last)], &next_keys, u64::MAX - 5)
                .unwrap();
            assert_eq!(done.stopped, None);
            assert_eq!(destination.state().committee.until_ms, u64::MAX);
            assert!(destination.is_live(u64::MAX));
        }
    }

    #[test]
    fn non_rotation_never_extends_until_ms() {
        let world = World::new();
        let deadline = T0 + VALIDITY;
        for flavor in FLAVORS {
            let _route = on(flavor);
            let mut destination = world.destination(flavor);
            // A future-dated header, a late one, and replays.
            let far = x(&SccpFinalityHeaderFieldsV1 {
                timestamp_ms: deadline + 10 * VALIDITY,
                ..plain(world.k0.root(), 5, 1500)
            });
            let certificates = [world.cert(1001), world.k0.certify(&far), world.cert(1200)];
            for (certificate, now_ms) in certificates.iter().zip([NOW, NOW + DAY, deadline]) {
                submit(&mut destination, std::slice::from_ref(certificate), now_ms).unwrap();
                assert_eq!(destination.state().committee.until_ms, deadline);
            }
            assert_eq!(destination.state().committee.high, 1500);
            // The same certificates replayed change nothing.
            assert_eq!(
                refused(&mut destination, |destination| submit(
                    destination,
                    &certificates,
                    deadline
                )),
                DestinationError::NothingToDo
            );

            // One clock value later the destination is frozen for good.
            let after = deadline + SECOND;
            assert!(destination.is_live(deadline) && !destination.is_live(after));
            let certificate = world.cert(1600);
            let checkpoint = stored(&world.x(1200));
            assert_eq!(
                refused(&mut destination, |destination| submit(
                    destination,
                    std::slice::from_ref(&certificate),
                    after
                )),
                DestinationError::CommitteeNotAccepted
            );
            assert_eq!(
                refused(&mut destination, |destination| destination.finalize(
                    inline(&certificate),
                    &dummy_message(),
                    after
                )),
                DestinationError::CommitteeNotAccepted
            );
            assert_eq!(
                refused(&mut destination, |destination| destination.void_expired(
                    0,
                    CertificateSourceV1::Checkpoint(&checkpoint),
                    &dummy_message(),
                    after
                )),
                DestinationError::CommitteeNotAccepted
            );
            assert_eq!(destination.state().committee.until_ms, deadline);
        }
    }

    #[test]
    fn ton_checkpoint_slots_evict_lowest() {
        let world = World::new();
        let heights = |destination: &Destination| -> Vec<u64> {
            destination.state().checkpoints.keys().copied().collect()
        };
        let mut ton = world.destination(TON);
        let mut evm = world.destination(EVM);
        for height in [1010, 1020, 1030] {
            for destination in [&mut ton, &mut evm] {
                submit(destination, &[world.cert(height)], NOW).unwrap();
            }
        }
        assert_eq!(heights(&ton), [1010, 1020, 1030]);

        // A fourth height above the lowest stored one enters and evicts it.
        let done = submit(&mut ton, &[world.cert(1015)], NOW).unwrap();
        assert_eq!(done.events.len(), 2);
        assert_eq!(done.events[1], checkpointed(&world.x(1015)));
        assert_eq!(heights(&ton), [1015, 1020, 1030]);
        assert_eq!(ton.checkpoint_header(1010), [0; 32]);
        // A height below every stored one is verified and not recorded: nothing changes.
        assert_eq!(
            refused(&mut ton, |destination| submit(
                destination,
                &[world.cert(1005)],
                NOW
            )),
            DestinationError::NothingToDo
        );
        // A stored height again is a no-op as well.
        assert_eq!(
            refused(&mut ton, |destination| submit(
                destination,
                &[world.cert(1020)],
                NOW
            )),
            DestinationError::NothingToDo
        );
        submit(&mut ton, &[world.cert(1040)], NOW).unwrap();
        assert_eq!(heights(&ton), [1020, 1030, 1040]);
        assert_eq!(ton.state().committee.high, 1040);

        // An evicted checkpoint is unknown to the checkpoint entry points.
        let evicted = stored(&world.x(1015));
        assert_eq!(
            refused(&mut ton, |destination| destination.finalize(
                CertificateSourceV1::Checkpoint(&evicted),
                &dummy_message_on(TON),
                NOW
            )),
            DestinationError::UnknownCheckpoint
        );
        // An inline certificate below the slots is used without being recorded.
        let below = world.cert(1012);
        assert_eq!(
            refused(&mut ton, |destination| destination.finalize(
                inline(&below),
                &dummy_message_on(TON),
                NOW
            )),
            DestinationError::BadProof
        );

        // Conflict detection covers retained entries only.
        let conflict_at = |height: u64| {
            world.k0.certify(&x(&SccpFinalityHeaderFieldsV1 {
                timestamp_ms: T0 + 7,
                ..plain(world.k0.root(), 5, height)
            }))
        };
        assert_eq!(
            refused(&mut ton, |destination| submit(
                destination,
                &[conflict_at(1010)],
                NOW
            )),
            DestinationError::NothingToDo
        );
        let done = submit(&mut ton, &[conflict_at(1020)], NOW).unwrap();
        assert_eq!(done.stopped, Some(StopReasonV1::Latch));

        // EVM keeps every height, so the conflict at 1010 latches there.
        submit(&mut evm, &[world.cert(1015), world.cert(1040)], NOW).unwrap();
        assert_eq!(heights(&evm), [1010, 1015, 1020, 1030, 1040]);
        let done = submit(&mut evm, &[conflict_at(1010)], NOW).unwrap();
        assert_eq!(done.stopped, Some(StopReasonV1::Latch));
    }

    #[test]
    fn ton_rotation_requires_next_keys_on_key_change() {
        let world = World::new();
        let handoff = world.handoff(1100);
        let certificate = world.k0.certify(&handoff);
        let now_ms = T0 + HOUR;
        let rotate = |destination: &mut Destination, keys: Option<Vec<[u8; KEY_LEN]>>| {
            destination.submit_checkpoints(std::slice::from_ref(&certificate), &[keys], now_ms)
        };
        let mut ton = world.destination(TON);
        let mut reversed = world.k1.keys();
        reversed.swap(0, 1);
        // No keys, another committee's keys, keys out of order, and too few keys.
        for keys in [
            None,
            Some(world.k2.keys()),
            Some(world.k0.keys()),
            Some(reversed),
            Some(world.k1.keys()[..3].to_vec()),
            Some(Vec::new()),
        ] {
            assert_eq!(
                refused(&mut ton, |destination| rotate(destination, keys)),
                DestinationError::BadCommittee
            );
        }
        let done = rotate(&mut ton, Some(world.k1.keys())).unwrap();
        assert_eq!(done.events.len(), 3);
        assert_eq!(ton.state().keys, Some(world.k1.keys()));
        assert_eq!(ton.state().committee.root, world.k1.root());
        // The successor's certificates verify against the stored keys.
        let next = x(&plain(world.k1.root(), 6, 1101));
        submit(&mut ton, &[world.k1.certify(&next)], now_ms).unwrap();
        assert_eq!(
            refused(&mut ton, |destination| submit(
                destination,
                &[world.k0.certify(&x(&plain(world.k0.root(), 6, 1102)))],
                now_ms
            )),
            DestinationError::CommitteeNotAccepted
        );

        // A heartbeat keeps the stored keys: none are needed, and supplied ones are ignored.
        let heartbeat = x(&handoff_fields_to_self(&world, 1100));
        for keys in [None, Some(world.k2.keys())] {
            let mut ton = world.destination(TON);
            let done = ton
                .submit_checkpoints(&[world.k0.certify(&heartbeat)], &[keys], now_ms)
                .unwrap();
            assert_eq!(done.events.len(), 3);
            assert_eq!(ton.state().keys, Some(world.k0.keys()));
            assert_eq!(ton.state().committee.generation, 6);
            // Generation 6 has the same keys: its certificates verify.
            submit(
                &mut ton,
                &[world.k0.certify(&x(&plain(world.k0.root(), 6, 1101)))],
                now_ms,
            )
            .unwrap();
        }

        // EVM stores no keys and ignores `next_keys`.
        let mut evm = world.destination(EVM);
        rotate(&mut evm, None).unwrap();
        assert_eq!(evm.state().keys, None);
        assert_eq!(evm.state().committee.root, world.k1.root());
    }

    /// The fields of a heartbeat of generation 5: a handoff to the committee's own root.
    fn handoff_fields_to_self(world: &World, height: u64) -> SccpFinalityHeaderFieldsV1 {
        handoff(world.k0.root(), 5, height, world.k0.root())
    }

    #[test]
    fn batch_is_atomic_and_reports_nothing_to_do_or_too_many() {
        let world = World::new();
        let certificates: Vec<TairaCertificateV1> =
            (1001..=1017).map(|height| world.cert(height)).collect();
        let expired = T0 + VALIDITY + SECOND;
        for flavor in FLAVORS {
            let mut destination = world.destination(flavor);
            // The checks before any certificate: the size, an empty batch, then `Live`.
            assert_eq!(
                refused(&mut destination, |destination| submit(
                    destination,
                    &certificates,
                    NOW
                )),
                DestinationError::TooManyCertificates
            );
            assert_eq!(
                refused(&mut destination, |destination| submit(
                    destination,
                    &certificates,
                    expired
                )),
                DestinationError::TooManyCertificates
            );
            assert_eq!(
                refused(&mut destination, |destination| submit(
                    destination,
                    &[],
                    NOW
                )),
                DestinationError::NothingToDo
            );
            assert_eq!(
                refused(&mut destination, |destination| submit(
                    destination,
                    &[],
                    expired
                )),
                DestinationError::NothingToDo
            );
            assert_eq!(
                refused(&mut destination, |destination| submit(
                    destination,
                    &certificates[..1],
                    expired
                )),
                DestinationError::CommitteeNotAccepted
            );

            // One bad certificate reverts the whole batch, wherever it stands.
            let mut bad = certificates[2].clone();
            bad.signature.clone_from(&certificates[3].signature);
            bad.ton_signature.clone_from(&certificates[3].ton_signature);
            let batch = [certificates[0].clone(), certificates[1].clone(), bad];
            assert_eq!(
                refused(&mut destination, |destination| submit(
                    destination,
                    &batch,
                    NOW
                )),
                DestinationError::BadSignature
            );

            // Sixteen certificates in order: two events each.
            let done = submit(&mut destination, &certificates[..16], NOW).unwrap();
            assert_eq!(done.events.len(), 32);
            assert_eq!(
                done.events[30],
                certificate_event(&certificates[15], flavor)
            );
            assert_eq!(done.events[31], checkpointed(&world.x(1016)));
            assert_eq!((done.stopped, done.returned), (None, None));
            assert_eq!(destination.state().committee.high, 1016);
            assert_eq!(
                destination.state().checkpoints.len(),
                flavor.checkpoint_slots().unwrap_or(16)
            );
            // Checkpoints do not count toward `opCount`.
            assert_eq!(destination.state().op_count, 0);

            // A batch that changes nothing reverts; one new certificate is enough.
            assert_eq!(
                refused(&mut destination, |destination| submit(
                    destination,
                    &certificates[14..16],
                    NOW
                )),
                DestinationError::NothingToDo
            );
            let done = submit(&mut destination, &certificates[15..], NOW).unwrap();
            assert_eq!(
                done.events,
                [
                    certificate_event(&certificates[16], flavor),
                    checkpointed(&world.x(1017))
                ]
            );

            // A handoff and the successor's first certificate in one batch.
            let handoff = world.handoff(1100);
            let next = world.k1.certify(&x(&plain(world.k1.root(), 6, 1101)));
            let done = destination
                .submit_checkpoints(
                    &[world.k0.certify(&handoff), next],
                    &[Some(world.k1.keys())],
                    T0 + HOUR,
                )
                .unwrap();
            assert_eq!(done.events.len(), 5);
            assert_eq!(destination.state().committee.high, 1101);
            assert_eq!(destination.state().committee.generation, 6);
        }
    }

    #[test]
    fn checkpoint_use_requires_a_stored_eligible_header() {
        let world = World::new();
        let k1_root = world.k1.root();
        let first = world.x(1010);
        let handoff_1 = world.handoff(1100);
        let later = x(&plain(k1_root, 6, 1150));
        let handoff_2 = x(&handoff(k1_root, 6, 1200, world.k2.root()));
        // One pass per flavour, each on the route of its own profile.
        for flavor in FLAVORS {
            let _route = on(flavor);
            let message = dummy_message();
            // The outcome of a checkpoint use whose proof is empty: `BadProof` when `X` was
            // obtained, else the refusal of the use itself.
            let probe =
                |destination: &mut Destination, header: &SccpFinalityHeaderV1, now_ms: u64| {
                    let checkpoint = stored(header);
                    let source = CertificateSourceV1::Checkpoint(&checkpoint);
                    let finalize = refused(destination, |destination| {
                        destination.finalize(source, &message, now_ms)
                    });
                    // Every checkpoint entry point obtains `X` the same way.
                    let control = refused(destination, |destination| {
                        destination.apply_control(source, &ControlProofV1::default(), now_ms)
                    });
                    let void = refused(destination, |destination| {
                        destination.void_expired(0, source, &message, now_ms)
                    });
                    assert_eq!((control, void), (finalize, finalize));
                    finalize
                };
            let usable = DestinationError::BadProof;
            let retired = DestinationError::CommitteeNotAccepted;

            // The calls of the pass, on the ledger built above for its route.
            {
                let mut destination = world.destination(flavor);
                let now_ms = T0 + HOUR;
                // The length of `X`, then the stored id, then X1–X7.
                let short = CheckpointRefV1 {
                    header: first.as_bytes()[..220].to_vec(),
                };
                assert_eq!(
                    refused(&mut destination, |destination| destination.finalize(
                        CertificateSourceV1::Checkpoint(&short),
                        &message,
                        now_ms
                    )),
                    DestinationError::BadHeader
                );
                let garbage = CheckpointRefV1 {
                    header: vec![0xab; X_LEN],
                };
                assert_eq!(
                    refused(&mut destination, |destination| destination.finalize(
                        CertificateSourceV1::Checkpoint(&garbage),
                        &message,
                        now_ms
                    )),
                    DestinationError::UnknownCheckpoint
                );
                assert_eq!(
                    probe(&mut destination, &first, now_ms),
                    DestinationError::UnknownCheckpoint
                );
                submit(&mut destination, &[world.cert(1010)], now_ms).unwrap();
                // Another `X` of the stored height is unknown; the stored one is usable (U1).
                let twin = x(&SccpFinalityHeaderFieldsV1 {
                    timestamp_ms: first.timestamp_ms() + 1,
                    ..plain(world.k0.root(), 5, 1010)
                });
                assert_eq!(
                    probe(&mut destination, &twin, now_ms),
                    DestinationError::UnknownCheckpoint
                );
                assert_eq!(probe(&mut destination, &first, now_ms), usable);
                // An unknown checkpoint answers before the `Live` check, a known one after it.
                let expired = T0 + VALIDITY + SECOND;
                assert_eq!(
                    probe(&mut destination, &twin, expired),
                    DestinationError::UnknownCheckpoint
                );
                assert_eq!(probe(&mut destination, &first, expired), retired);

                // Generation 6 installed by the handoff at 1100: the handoff stays usable (U2),
                // the other checkpoints of generation 5 give no new authorization.
                destination
                    .submit_checkpoints(
                        &[world.k0.certify(&handoff_1)],
                        &[Some(world.k1.keys())],
                        now_ms,
                    )
                    .unwrap();
                assert_eq!(probe(&mut destination, &first, now_ms), retired);
                assert_eq!(probe(&mut destination, &handoff_1, now_ms), usable);
                submit(&mut destination, &[world.k1.certify(&later)], now_ms).unwrap();
                assert_eq!(probe(&mut destination, &later, now_ms), usable);

                // Generation 7: the handoff of generation 5 is two generations old.
                destination
                    .submit_checkpoints(
                        &[world.k1.certify(&handoff_2)],
                        &[Some(world.k2.keys())],
                        now_ms,
                    )
                    .unwrap();
                assert_eq!(destination.state().committee.generation, 7);
                assert_eq!(probe(&mut destination, &handoff_1, now_ms), retired);
                assert_eq!(probe(&mut destination, &later, now_ms), retired);
                assert_eq!(probe(&mut destination, &handoff_2, now_ms), usable);
                // TON keeps three checkpoints: the fourth one evicted the oldest.
                assert_eq!(
                    probe(&mut destination, &first, now_ms),
                    match flavor {
                        EVM => retired,
                        TON => DestinationError::UnknownCheckpoint,
                    }
                );
                // U2 never makes a certificate CUR: the old handoff cannot be presented again.
                assert_eq!(
                    refused(&mut destination, |destination| submit(
                        destination,
                        &[world.k1.certify(&handoff_2)],
                        now_ms
                    )),
                    retired
                );
            }
        }
    }

    // -- finalization, controls and voids (§5.1.4–§5.1.8) ----------------------------------------

    #[test]
    fn finalize_mints_once_within_the_deadline_and_the_cap() {
        let world = World::new();
        let deadline = T0 + HOUR;
        // One pass per flavour, each on the route of its own profile.
        for flavor in FLAVORS {
            let _route = on(flavor);
            let (p0, l0) = transfer(0, 2_000_000_000, T0 + DAY);
            let (p1, l1) = transfer(1, 3_000_000_000, T0 + DAY);
            let (p2, l2) = transfer(2, 1_000_000_000, deadline);
            let (p3, l3) = transfer(3, 4_000_000_000, T0 + DAY);
            let (p4, l4) = transfer(4, 2_000_000_000, T0 + DAY);
            let (p5, l5) = transfer(5, 1, deadline);
            let mut ledger = Ledger::default();
            let x1010 = ledger.block(&world, 1010, &[l0, l1, l2, l5]);
            ledger.block(&world, 1020, &[l3, l4]);
            let x1050 = ledger.block(&world, 1050, &[]);
            assert_eq!(x1050.history_size(), 2);
            let c1010 = world.k0.certify(&x1010);
            let c1050 = world.k0.certify(&x1050);
            let at_1010 = stored(&x1010);
            let at_1050 = stored(&x1050);
            let from_1010 = CertificateSourceV1::Checkpoint(&at_1010);
            let from_1050 = CertificateSourceV1::Checkpoint(&at_1050);

            // The calls of the pass, on the ledger built above for its route.
            {
                let mut destination = world.destination(flavor);
                // Inline: the certificate is verified, published and checkpointed, then the
                // transfer is minted and the call returns its message id.
                let proof = ledger.message(&p0, 1010, 0, &x1010);
                let done = destination.finalize(inline(&c1010), &proof, NOW).unwrap();
                let message = message_id(&destination.lane, &payload_hash(&p0));
                assert_eq!(
                    done,
                    CallOutcome {
                        events: vec![
                            certificate_event(&c1010, flavor),
                            checkpointed(&x1010),
                            DestinationEvent::Finalized {
                                message_id: message,
                                nonce: 0,
                                recipient: recipient_of(flavor),
                                token_amount: 2_000_000_000,
                            },
                        ],
                        stopped: None,
                        returned: Some(message),
                    }
                );
                assert_eq!(destination.state().committee.high, 1010);
                assert!(destination.is_consumed(0) && !destination.is_consumed(1));
                assert_eq!(destination.state().total_supply, 2_000_000_000);
                assert_eq!(destination.balance_of(&recipient_of(flavor)), 2_000_000_000);
                assert_eq!(destination.state().op_count, 1);

                // From the stored checkpoint: only the mint is emitted.
                let done = destination
                    .finalize(from_1010, &ledger.message(&p1, 1010, 1, &x1010), NOW)
                    .unwrap();
                assert_eq!(done.events.len(), 1);
                assert_eq!(done.events[0].name(), "SccpFinalized");
                // A nonce mints once, through either form.
                for source in [from_1010, inline(&c1010)] {
                    assert_eq!(
                        refused(&mut destination, |destination| destination
                            .finalize(source, &proof, NOW)),
                        DestinationError::AlreadyConsumed { nonce: 0 }
                    );
                }

                // An older block under a newer certificate, through the history accumulator.
                let done = destination
                    .finalize(inline(&c1050), &ledger.message(&p3, 1020, 0, &x1050), NOW)
                    .unwrap();
                assert_eq!(done.events.len(), 3);
                assert_eq!(destination.state().total_supply, 9_000_000_000);
                // The cap: 9 + 2 > 10. The refused mint consumes nothing.
                let over = ledger.message(&p4, 1020, 1, &x1050);
                assert_eq!(
                    refused(&mut destination, |destination| destination
                        .finalize(from_1050, &over, NOW)),
                    DestinationError::SupplyCapExceeded
                );
                assert!(!destination.is_consumed(4));

                // Proofs that do not reproduce the certified roots.
                let good = ledger.message(&p2, 1010, 2, &x1010);
                let historical = ledger.message(&p4, 1020, 1, &x1050);
                let broken: [(CertificateSourceV1<'_>, MessageProofV1); 9] = [
                    // Another leaf's path, another index, a path that is too long.
                    (
                        from_1010,
                        MessageProofV1 {
                            path: ledger.leaf_path(1010, 0),
                            ..good.clone()
                        },
                    ),
                    (
                        from_1010,
                        MessageProofV1 {
                            leaf_index: 3,
                            ..good.clone()
                        },
                    ),
                    (
                        from_1010,
                        MessageProofV1 {
                            path: vec![[0xab; 32]; 10],
                            ..good.clone()
                        },
                    ),
                    // The certified block named with a history path, a history index, another
                    // count or another root.
                    (
                        from_1010,
                        MessageProofV1 {
                            block: BlockRefV1 {
                                history_path: vec![[0; 32]],
                                ..good.block.clone()
                            },
                            ..good.clone()
                        },
                    ),
                    (
                        from_1010,
                        MessageProofV1 {
                            block: BlockRefV1 {
                                history_index: 1,
                                ..good.block.clone()
                            },
                            ..good.clone()
                        },
                    ),
                    (
                        from_1010,
                        MessageProofV1 {
                            block: BlockRefV1 {
                                message_count: 3,
                                ..good.block.clone()
                            },
                            ..good.clone()
                        },
                    ),
                    // A block above the certified one, and one the history does not hold.
                    (from_1010, ledger.message(&p4, 1020, 1, &x1050)),
                    (
                        from_1050,
                        MessageProofV1 {
                            block: BlockRefV1 {
                                history_index: 0,
                                ..historical.block.clone()
                            },
                            ..historical.clone()
                        },
                    ),
                    (
                        from_1050,
                        MessageProofV1 {
                            block: BlockRefV1 {
                                height: 1021,
                                ..historical.block.clone()
                            },
                            ..historical.clone()
                        },
                    ),
                ];
                for (source, proof) in &broken {
                    assert_eq!(
                        refused(&mut destination, |destination| destination
                            .finalize(*source, proof, NOW)),
                        DestinationError::BadProof
                    );
                }

                // The deadline: one clock value after it the mint is refused, and the deadline
                // is checked before the leaf path. At the deadline itself the mint is accepted.
                let late = deadline + SECOND;
                assert_eq!(
                    refused(&mut destination, |destination| destination
                        .finalize(from_1010, &good, late)),
                    DestinationError::DeadlinePassed
                );
                assert_eq!(
                    refused(&mut destination, |destination| destination.finalize(
                        from_1010,
                        &broken[0].1,
                        late
                    )),
                    DestinationError::DeadlinePassed
                );
                destination.finalize(from_1010, &good, deadline).unwrap();
                // The supply is exactly the cap: even one unit more is refused.
                assert_eq!(destination.state().total_supply, CAP);
                let one_unit = ledger.message(&p5, 1010, 3, &x1010);
                assert_eq!(
                    refused(&mut destination, |destination| destination
                        .finalize(from_1010, &one_unit, NOW)),
                    DestinationError::SupplyCapExceeded
                );
                assert_eq!(destination.balance_of(&recipient_of(flavor)), CAP);
                assert_eq!(destination.state().op_count, 4);
                assert_eq!(destination.state().consumed, BTreeSet::from([0, 1, 2, 3]));
            }
        }
    }

    #[test]
    fn payloads_must_be_addressed_to_the_revision_and_a_mintable_recipient() {
        let world = World::new();
        // Any block with a leaf: the payload rules answer before the leaf path is checked.
        let mut ledger = Ledger::default();
        let header = ledger.block(&world, 1010, &[[0x5c; 32]]);
        let certificate = world.k0.certify(&header);
        let block = ledger.block_ref(1010, &header);
        let now_ms = NOW;
        let outcome = |destination: &mut Destination, payload: Vec<u8>| {
            let proof = MessageProofV1 {
                payload,
                leaf_index: 0,
                path: Vec::new(),
                block: block.clone(),
            };
            let mint = refused(destination, |destination| {
                destination.finalize(inline(&certificate), &proof, now_ms)
            });
            // A void reads the payload the same way.
            let void = refused(destination, |destination| {
                destination.void_expired(0, inline(&certificate), &proof, T0 + 2 * DAY)
            });
            (mint, void)
        };
        let bad_payload = DestinationError::BadPayload;
        let bad_recipient = DestinationError::BadRecipient;
        // A payload that passes every rule of the destination fails at the leaf path.
        let passes = DestinationError::BadProof;

        let eth = SccpNetworkV1::EthereumMainnet;
        let good = outbound(eth, 9, 1, 5, T0 + DAY, &RECIPIENT);
        let own = outbound(eth, 9, 1, 5, T0 + DAY, &[0x22; 20]);
        let zero = SccpTransferPayloadV1 {
            recipient: PayloadAccountV1::new(2, vec![0; 20]),
            ..good.clone()
        };
        let short = SccpTransferPayloadV1 {
            recipient: PayloadAccountV1::new(2, vec![0x44; 19]),
            ..good.clone()
        };
        let mut destination = world.destination(EVM);
        let cases: [(Vec<u8>, DestinationError); 12] = [
            (good.encode().unwrap(), passes),
            // Another lane, another revision, the inbound direction, and bytes that are no
            // payload.
            (
                outbound(SccpNetworkV1::BscMainnet, 9, 1, 5, T0 + DAY, &RECIPIENT)
                    .encode()
                    .unwrap(),
                bad_payload,
            ),
            (
                outbound(eth, 9, 2, 5, T0 + DAY, &RECIPIENT)
                    .encode()
                    .unwrap(),
                bad_payload,
            ),
            (
                SccpTransferPayloadV1::inbound(eth, 9, 1, 5, RECIPIENT.to_vec(), vec![0x01; 34])
                    .unwrap()
                    .encode()
                    .unwrap(),
                bad_payload,
            ),
            (Vec::new(), bad_payload),
            (vec![0x02; 80], bad_payload),
            ([good.encode().unwrap(), vec![0]].concat(), bad_payload),
            // The recipient: the contract itself and the zero address are the destination's
            // own rule; a recipient of the wrong length is no payload.
            (own.encode().unwrap(), bad_recipient),
            (zero.encode_unvalidated().unwrap(), bad_recipient),
            (short.encode_unvalidated().unwrap(), bad_payload),
            // A zero recipient in a payload of another revision or with another route id is
            // not addressed here.
            (
                SccpTransferPayloadV1 {
                    route_revision: 2,
                    ..zero.clone()
                }
                .encode_unvalidated()
                .unwrap(),
                bad_payload,
            ),
            (
                SccpTransferPayloadV1 {
                    route_id: "taira_bsc_xor".to_owned(),
                    ..zero.clone()
                }
                .encode_unvalidated()
                .unwrap(),
                bad_payload,
            ),
        ];
        for (payload, expected) in cases {
            let (mint, void) = outcome(&mut destination, payload.clone());
            assert_eq!(mint, expected, "{payload:02x?}");
            assert_eq!(void, expected, "{payload:02x?}");
        }
        // The block reference is checked before the payload.
        let proof = MessageProofV1 {
            payload: Vec::new(),
            block: BlockRefV1 {
                message_count: 2,
                ..block.clone()
            },
            ..MessageProofV1::default()
        };
        assert_eq!(
            refused(&mut destination, |destination| destination.finalize(
                inline(&certificate),
                &proof,
                now_ms
            )),
            DestinationError::BadProof
        );

        // The TON profile: `addr_std` in workchain 0 with a nonzero account id that is not the
        // minter. The minter checks the payload and its recipient before it obtains `X`.
        let ton = SccpNetworkV1::TonMainnet;
        let minter = TON_WORD;
        let account = |workchain: u8, id: [u8; 32]| [&[0, 0, 0, workchain][..], &id].concat();
        let to = |recipient: Vec<u8>| SccpTransferPayloadV1 {
            recipient: PayloadAccountV1::new(7, recipient),
            ..outbound(ton, 9, 1, 5, T0 + DAY, &account(0, [0x44; 32]))
        };
        {
            let mut destination = world.destination(TON);
            assert_eq!(destination.deployment().network, ton);
            assert_eq!(destination.deployment().destination_word, minter);
            let cases = [
                (account(0, [0x44; 32]), passes),
                (account(0, minter), bad_recipient),
                (account(1, [0x44; 32]), bad_recipient),
                (account(0, [0; 32]), bad_recipient),
                (account(0, [0x44; 32])[..35].to_vec(), bad_payload),
            ];
            for (recipient, expected) in cases {
                let payload = to(recipient).encode_unvalidated().unwrap();
                assert_eq!(outcome(&mut destination, payload).0, expected);
            }
            // The Ethereum payload is of another lane here.
            assert_eq!(
                outcome(&mut destination, good.encode().unwrap()).0,
                bad_payload
            );
            // TON amounts stay below 2^96.
            let large = SccpTransferPayloadV1 {
                amount: 1 << 96,
                ..to(account(0, [0x44; 32]))
            };
            assert_eq!(
                outcome(&mut destination, large.encode_unvalidated().unwrap()).0,
                bad_payload
            );
        }
    }

    #[test]
    fn controls_set_both_pause_tracks_with_the_fast_pause_clamp() {
        let world = World::new();
        let parliament_pause = control_fields(1, TRACK_PARLIAMENT, 1, 0);
        let fast_pause = control_fields(2, TRACK_FAST_PAUSE, 1, T0 + 2 * HOUR);
        let resume = control_fields(5, TRACK_PARLIAMENT, 0, 0);
        let far = control_fields(7, TRACK_FAST_PAUSE, 0, NOW + 40 * DAY);
        let lapsed = control_fields(8, TRACK_FAST_PAUSE, 0, T0 + SECOND);
        let bad_track = control_fields(9, 3, 0, 0);
        let other_revision = ControlLeafV1 {
            route_revision: 2,
            ..control_fields(10, TRACK_PARLIAMENT, 1, 0)
        };
        let controls = [
            parliament_pause,
            fast_pause,
            resume,
            far,
            lapsed,
            bad_track,
            other_revision,
        ];
        // One pass per flavour, each on the route of its own profile.
        for flavor in FLAVORS {
            let _route = on(flavor);
            let (payload, mint_leaf) = transfer(0, 1_000, T0 + DAY);
            // Controls precede transfers in a block.
            let mut leaves: Vec<[u8; 32]> = controls.iter().map(control_leaf_of).collect();
            leaves.push(mint_leaf);
            let mut ledger = Ledger::default();
            let header = ledger.block(&world, 1010, &leaves);
            let certificate = world.k0.certify(&header);
            let checkpoint = stored(&header);
            let from_checkpoint = CertificateSourceV1::Checkpoint(&checkpoint);
            let proof = |index: usize| {
                ledger.control(
                    &controls[index],
                    1010,
                    u32::try_from(index).unwrap(),
                    &header,
                )
            };
            let mint = ledger.message(&payload, 1010, 7, &header);

            // The calls of the pass, on the ledger built above for its route.
            {
                let mut destination = world.destination(flavor);
                // A Parliament pause, inline: the certificate is checkpointed with it.
                let done = destination
                    .apply_control(inline(&certificate), &proof(0), NOW)
                    .unwrap();
                assert_eq!(
                    done.events,
                    [
                        certificate_event(&certificate, flavor),
                        checkpointed(&header),
                        DestinationEvent::ControlApplied {
                            control_nonce: 1,
                            track: TRACK_PARLIAMENT,
                            parliament_paused: true,
                            fast_pause_until_ms: 0,
                            certificate_id: [0xc1; 32],
                        },
                    ]
                );
                assert_eq!(
                    destination.pause_state(NOW),
                    PauseStateV1 {
                        parliament_paused: true,
                        fast_pause_until_ms: 0,
                        control_nonce: 1,
                        effective: true,
                    }
                );
                assert_eq!(destination.state().op_count, 1);
                // The pause blocks minting only: voids, checkpoints and controls go on.
                assert_eq!(
                    refused(&mut destination, |destination| destination.finalize(
                        from_checkpoint,
                        &mint,
                        NOW
                    )),
                    DestinationError::MintingIsPaused
                );
                submit(&mut destination, &[world.cert(1011)], NOW).unwrap();

                // The fast pause on top of it, from the checkpoint.
                let done = destination
                    .apply_control(from_checkpoint, &proof(1), NOW)
                    .unwrap();
                assert_eq!(done.events.len(), 1);
                assert_eq!(
                    destination.pause_state(NOW),
                    PauseStateV1 {
                        parliament_paused: true,
                        fast_pause_until_ms: T0 + 2 * HOUR,
                        control_nonce: 2,
                        effective: true,
                    }
                );
                // The newest nonce wins: an equal or lower one is stale.
                for index in [0, 1] {
                    assert_eq!(
                        refused(&mut destination, |destination| destination.apply_control(
                            from_checkpoint,
                            &proof(index),
                            NOW
                        )),
                        DestinationError::StaleControl
                    );
                }
                // A gap is allowed. The resume carries no fast pause: minting is open again.
                destination
                    .apply_control(from_checkpoint, &proof(2), NOW)
                    .unwrap();
                assert_eq!(
                    destination.pause_state(NOW),
                    PauseStateV1 {
                        parliament_paused: false,
                        fast_pause_until_ms: 0,
                        control_nonce: 5,
                        effective: false,
                    }
                );
                destination.finalize(from_checkpoint, &mint, NOW).unwrap();

                // An expiry 40 days ahead is clamped to `now + MAX_FAST_PAUSE_MS`.
                let done = destination
                    .apply_control(from_checkpoint, &proof(3), NOW)
                    .unwrap();
                let clamped = NOW + MAX_FAST_PAUSE_MS;
                assert_eq!(
                    done.events,
                    [DestinationEvent::ControlApplied {
                        control_nonce: 7,
                        track: TRACK_FAST_PAUSE,
                        parliament_paused: false,
                        fast_pause_until_ms: clamped,
                        certificate_id: [0xc1; 32],
                    }]
                );
                // Paused while `now < fastPauseUntilMs`, open at the expiry with no relay.
                assert!(destination.minting_paused(clamped - SECOND));
                assert!(!destination.minting_paused(clamped));
                // A fast-pause leaf delivered after its expiry consumes its nonce and pauses
                // nothing.
                destination
                    .apply_control(from_checkpoint, &proof(4), NOW)
                    .unwrap();
                assert_eq!(
                    destination.pause_state(NOW),
                    PauseStateV1 {
                        parliament_paused: false,
                        fast_pause_until_ms: T0 + SECOND,
                        control_nonce: 8,
                        effective: false,
                    }
                );
                assert_eq!(destination.state().op_count, 6);

                // A recorded leaf that violates a constraint is proven, then refused. With a
                // path that does not verify, the proof answers first.
                assert_eq!(
                    refused(&mut destination, |destination| destination.apply_control(
                        from_checkpoint,
                        &proof(5),
                        NOW
                    )),
                    DestinationError::BadControl
                );
                let unproven = ControlProofV1 {
                    path: Vec::new(),
                    ..proof(5)
                };
                assert_eq!(
                    refused(&mut destination, |destination| destination.apply_control(
                        from_checkpoint,
                        &unproven,
                        NOW
                    )),
                    DestinationError::BadProof
                );
                // The leaf is computed with the destination's own revision: a leaf of another
                // revision, a transfer leaf and changed fields are not leaves of the tree.
                let as_control = ControlProofV1 {
                    leaf_index: 7,
                    path: ledger.leaf_path(1010, 7),
                    ..proof(2)
                };
                let changed = ControlProofV1 {
                    fast_pause_until_ms: 1,
                    ..proof(2)
                };
                for foreign in [proof(6), as_control, changed] {
                    assert_eq!(
                        refused(&mut destination, |destination| destination.apply_control(
                            from_checkpoint,
                            &foreign,
                            NOW
                        )),
                        DestinationError::BadProof
                    );
                }
                // The block reference is checked before the leaf. The constraints before a
                // stale nonce are `two_faults_report_the_earlier_check`.
                let misplaced = ControlProofV1 {
                    block: BlockRefV1 {
                        history_index: 1,
                        ..proof(5).block
                    },
                    ..proof(5)
                };
                assert_eq!(
                    refused(&mut destination, |destination| destination.apply_control(
                        from_checkpoint,
                        &misplaced,
                        NOW
                    )),
                    DestinationError::BadProof
                );
                // A frozen destination applies no control.
                assert_eq!(
                    refused(&mut destination, |destination| destination.apply_control(
                        inline(&certificate),
                        &proof(2),
                        T0 + VALIDITY + SECOND
                    )),
                    DestinationError::CommitteeNotAccepted
                );
            }
        }

        // The clamp saturates at 2^64 − 1 near the end of the clock.
        let mut destination = Destination::new(DeploymentV1 {
            pin_until_ms: u64::MAX,
            ..world.deployment(EVM)
        })
        .unwrap();
        let forever = control_fields(1, TRACK_FAST_PAUSE, 0, u64::MAX);
        let mut ledger = Ledger::default();
        let header = ledger.block(&world, 1010, &[control_leaf_of(&forever)]);
        destination
            .apply_control(
                inline(&world.k0.certify(&header)),
                &ledger.control(&forever, 1010, 0, &header),
                u64::MAX - 5,
            )
            .unwrap();
        assert_eq!(destination.state().fast_pause_until_ms, u64::MAX);
    }

    #[test]
    fn voids_consume_nonces_without_minting() {
        let world = World::new();
        let deadline = T0 + HOUR;
        let expired = T0 + VALIDITY + SECOND;
        // One pass per flavour, each on the route of its own profile.
        for flavor in FLAVORS {
            let _route = on(flavor);
            let (p0, l0) = transfer(0, 1_000, deadline);
            let (p1, l1) = transfer(1, 1_000, deadline + 999);
            let mut ledger = Ledger::default();
            let header = ledger.block(&world, 1010, &[l0, l1]);
            let certificate = world.k0.certify(&header);
            let checkpoint = stored(&header);
            let from_checkpoint = CertificateSourceV1::Checkpoint(&checkpoint);
            let first = ledger.message(&p0, 1010, 0, &header);
            let second = ledger.message(&p1, 1010, 1, &header);

            // The calls of the pass, on the ledger built above for its route.
            {
                let mut destination = world.destination(flavor);
                // `voidExpired`: only after the deadline, and only for the payload's own nonce.
                assert_eq!(
                    refused(&mut destination, |destination| destination.void_expired(
                        0,
                        inline(&certificate),
                        &first,
                        deadline
                    )),
                    DestinationError::DeadlineNotReached
                );
                assert_eq!(
                    refused(&mut destination, |destination| destination.void_expired(
                        1,
                        inline(&certificate),
                        &first,
                        deadline + SECOND
                    )),
                    DestinationError::BadNonce { expected: 0 }
                );
                let done = destination
                    .void_expired(0, inline(&certificate), &first, deadline + SECOND)
                    .unwrap();
                assert_eq!(done.events.len(), 3);
                assert_eq!(
                    done.events[2],
                    DestinationEvent::Voided {
                        message_id: message_id(&destination.lane, &payload_hash(&p0)),
                        nonce: 0,
                    }
                );
                assert_eq!(done.returned, None);
                assert_eq!(destination.state().total_supply, 0);
                assert_eq!(destination.state().op_count, 1);
                // A voided nonce is consumed: it neither voids nor mints again.
                assert_eq!(
                    refused(&mut destination, |destination| destination.void_expired(
                        0,
                        from_checkpoint,
                        &first,
                        deadline + SECOND
                    )),
                    DestinationError::AlreadyConsumed { nonce: 0 }
                );
                // A deadline ending in 999: the whole-second clock is early one value before it
                // and late at the next.
                assert_eq!(
                    refused(&mut destination, |destination| destination.void_expired(
                        1,
                        from_checkpoint,
                        &second,
                        deadline
                    )),
                    DestinationError::DeadlineNotReached
                );
                assert_eq!(
                    refused(&mut destination, |destination| destination.finalize(
                        from_checkpoint,
                        &second,
                        deadline + SECOND
                    )),
                    DestinationError::DeadlinePassed
                );

                // `voidFrozen` checks its range first, then `Frozen`.
                let range = match flavor {
                    EVM => DestinationError::BadAmount,
                    TON => DestinationError::BadRange,
                };
                let limit = flavor.max_void_frozen_range();
                for now_ms in [NOW, expired] {
                    for (first_nonce, count) in
                        [(10, 0), (10, limit + 1), (u64::MAX, 2), (0, u64::MAX)]
                    {
                        assert_eq!(
                            refused(&mut destination, |destination| destination.void_frozen(
                                first_nonce,
                                count,
                                now_ms
                            )),
                            range,
                            "{first_nonce} + {count}"
                        );
                    }
                }
                assert_eq!(
                    refused(&mut destination, |destination| destination
                        .void_frozen(10, 1, NOW)),
                    DestinationError::NotFrozen
                );
                // Frozen: a range with a consumed nonce reverts with the lowest one.
                assert_eq!(
                    refused(&mut destination, |destination| destination
                        .void_frozen(0, 4, expired)),
                    DestinationError::AlreadyConsumed { nonce: 0 }
                );
                let done = destination.void_frozen(1, 3, expired).unwrap();
                assert_eq!(
                    done.events,
                    match flavor {
                        EVM => (1..=3)
                            .map(|nonce| DestinationEvent::Voided {
                                message_id: [0; 32],
                                nonce,
                            })
                            .collect::<Vec<_>>(),
                        TON => vec![DestinationEvent::VoidedRange {
                            message_id: [0; 32],
                            first_nonce: 1,
                            count: 3,
                        }],
                    }
                );
                // One call is one operation, whatever its range.
                assert_eq!(destination.state().op_count, 2);
                assert_eq!(
                    refused(&mut destination, |destination| destination
                        .void_frozen(3, 2, expired)),
                    DestinationError::AlreadyConsumed { nonce: 3 }
                );
                // The last nonce of all: `firstNonce + count = 2^64` is valid.
                let top = u64::MAX - (limit - 1);
                destination.void_frozen(top, limit, expired).unwrap();
                assert!(destination.is_consumed(u64::MAX) && destination.is_consumed(top));
                assert_eq!(
                    destination.state().consumed.len(),
                    4 + usize::try_from(limit).unwrap()
                );
            }
        }

        // TON voids inside one bucket of 512 nonces.
        let mut ton = world.destination(TON);
        for (first_nonce, count) in [(510, 4), (511, 2), (1, 512), (1023, 2)] {
            assert_eq!(
                refused(&mut ton, |destination| destination.void_frozen(
                    first_nonce,
                    count,
                    expired
                )),
                DestinationError::BadRange
            );
        }
        for (first_nonce, count) in [(0, 512), (512, 512), (1024, 1), (1535, 1)] {
            let done = ton.void_frozen(first_nonce, count, expired).unwrap();
            assert_eq!(done.events.len(), 1);
        }
        // EVM has no buckets: any 256 nonces.
        let mut evm = world.destination(EVM);
        assert_eq!(
            evm.void_frozen(510, 256, expired).unwrap().events.len(),
            256
        );
    }

    /// Two faults in one call: the earlier check of the documented order is the answer.
    #[test]
    fn two_faults_report_the_earlier_check() {
        let world = World::new();
        for flavor in FLAVORS {
            let _route = on(flavor);
            let mut destination = world.destination(flavor);
            // A payload of another revision under a checkpoint that is not stored: EVM
            // obtains `X` first, a TON minter checks the payload first (§5.3.4).
            let payload_first = match flavor {
                DestinationFlavor::Evm => DestinationError::UnknownCheckpoint,
                DestinationFlavor::Ton => DestinationError::BadPayload,
            };
            let recipient_first = match flavor {
                DestinationFlavor::Evm => DestinationError::UnknownCheckpoint,
                DestinationFlavor::Ton => DestinationError::BadRecipient,
            };
            let unknown = stored(&world.x(1010));
            let never_stored = CertificateSourceV1::Checkpoint(&unknown);
            let (network, own_word) = route(flavor);
            let to_contract = match flavor {
                DestinationFlavor::Evm => own_word[12..].to_vec(),
                DestinationFlavor::Ton => [&[0_u8; 4][..], &own_word].concat(),
            };
            let carrying = |payload: SccpTransferPayloadV1| MessageProofV1 {
                payload: payload.encode().unwrap(),
                ..MessageProofV1::default()
            };
            let other_revision =
                carrying(outbound(network, 0, 2, 1, T0 + DAY, &recipient_of(flavor)));
            let own_recipient = carrying(outbound(network, 0, 1, 1, T0 + DAY, &to_contract));
            for (proof, expected) in [
                (&other_revision, payload_first),
                (&own_recipient, recipient_first),
                (&dummy_message(), DestinationError::UnknownCheckpoint),
            ] {
                assert_eq!(
                    refused(&mut destination, |destination| destination.finalize(
                        never_stored,
                        proof,
                        NOW
                    )),
                    expected
                );
                assert_eq!(
                    refused(&mut destination, |destination| destination.void_expired(
                        0,
                        never_stored,
                        proof,
                        NOW
                    )),
                    expected
                );
            }

            let deadline = T0 + HOUR;
            let (payload, leaf) = transfer(0, CAP, deadline);
            let valid = control_fields(5, TRACK_PARLIAMENT, 0, 0);
            let bad_track = ControlLeafV1 {
                control_nonce: 3,
                track: 3,
                ..valid
            };
            let mut ledger = Ledger::default();
            let leaves = [control_leaf_of(&valid), control_leaf_of(&bad_track), leaf];
            let header = ledger.block(&world, 1020, &leaves);
            submit(&mut destination, &[world.k0.certify(&header)], NOW).unwrap();
            let checkpoint = stored(&header);
            let source = CertificateSourceV1::Checkpoint(&checkpoint);

            // The §3.4 constraints before the control nonce: a leaf with track 3 and a nonce
            // below the stored one is `BadControl`, not `StaleControl`.
            destination
                .apply_control(source, &ledger.control(&valid, 1020, 0, &header), NOW)
                .unwrap();
            assert_eq!(destination.state().control_nonce, 5);
            assert_eq!(
                refused(&mut destination, |destination| destination.apply_control(
                    source,
                    &ledger.control(&bad_track, 1020, 1, &header),
                    NOW
                )),
                DestinationError::BadControl
            );

            // The deadline before the leaf path, on both flavours.
            let proof = ledger.message(&payload, 1020, 2, &header);
            let wrong_path = MessageProofV1 {
                path: Vec::new(),
                ..proof.clone()
            };
            assert_eq!(
                refused(&mut destination, |destination| destination.finalize(
                    source,
                    &wrong_path,
                    deadline + SECOND
                )),
                DestinationError::DeadlinePassed
            );
            assert_eq!(
                refused(&mut destination, |destination| destination.finalize(
                    source,
                    &wrong_path,
                    deadline
                )),
                DestinationError::BadProof
            );

            // A consumed nonce before the supply cap: the mint fills the cap, and minting
            // the same message again is `AlreadyConsumed`, not `SupplyCapExceeded`.
            destination.finalize(source, &proof, NOW).unwrap();
            assert_eq!(destination.state().total_supply, CAP);
            assert_eq!(
                refused(&mut destination, |destination| destination
                    .finalize(source, &proof, NOW)),
                DestinationError::AlreadyConsumed { nonce: 0 }
            );
            // The nonce argument of `voidExpired` before the consumed set.
            let late = deadline + SECOND;
            assert_eq!(
                refused(&mut destination, |destination| destination
                    .void_expired(1, source, &proof, late)),
                DestinationError::BadNonce { expected: 0 }
            );
            assert_eq!(
                refused(&mut destination, |destination| destination
                    .void_expired(0, source, &proof, late)),
                DestinationError::AlreadyConsumed { nonce: 0 }
            );
        }
    }

    // -- checks without state --------------------------------------------------------------------

    #[test]
    fn void_frozen_ranges_never_form_a_value_above_u64() {
        // (first, count) → the last nonce, per flavour.
        let cases = [
            ((0, 1), Some(0), Some(0)),
            ((0, 0), None, None),
            ((7, 256), Some(262), Some(262)),
            ((7, 257), None, Some(263)),
            ((0, 512), None, Some(511)),
            ((0, 513), None, None),
            ((1, 512), None, None),
            ((511, 1), Some(511), Some(511)),
            ((511, 2), Some(512), None),
            ((u64::MAX, 1), Some(u64::MAX), Some(u64::MAX)),
            ((u64::MAX, 2), None, None),
            ((u64::MAX - 255, 256), Some(u64::MAX), Some(u64::MAX)),
            ((u64::MAX - 254, 256), None, None),
            ((u64::MAX - 511, 512), None, Some(u64::MAX)),
            ((5, u64::MAX), None, None),
        ];
        for ((first_nonce, count), evm, ton) in cases {
            assert_eq!(
                void_frozen_last_nonce(EVM, first_nonce, count),
                evm,
                "evm {first_nonce} + {count}"
            );
            assert_eq!(
                void_frozen_last_nonce(TON, first_nonce, count),
                ton,
                "ton {first_nonce} + {count}"
            );
        }
    }

    #[test]
    fn op_count_saturates_at_the_u64_end() {
        for (count, next) in [
            (0, 1),
            (1, 2),
            (u64::MAX - 2, u64::MAX - 1),
            (u64::MAX - 1, u64::MAX),
            (u64::MAX, u64::MAX),
        ] {
            assert_eq!(bumped_op_count(count), next, "{count}");
        }

        // The four counted operations of the model at the bound: a mint, a control, a void by
        // proof and a frozen range. Each takes effect and none moves the count.
        let world = World::new();
        let fields = control_fields(1, TRACK_PARLIAMENT, 0, 0);
        let (p0, l0) = transfer(0, 1_000, T0 + DAY);
        let (p1, l1) = transfer(1, 1_000, T0 + HOUR);
        let (p2, l2) = transfer(2, 1_000, T0 + DAY);
        let mut ledger = Ledger::default();
        let header = ledger.block(&world, 1010, &[control_leaf_of(&fields), l0, l1, l2]);
        let checkpoint = stored(&header);
        let from_checkpoint = CertificateSourceV1::Checkpoint(&checkpoint);
        let late = T0 + HOUR + SECOND;
        let frozen = T0 + VALIDITY + SECOND;
        let mut destination = world.destination(EVM);
        submit(&mut destination, &[world.k0.certify(&header)], NOW).unwrap();
        // A checkpoint is not counted.
        assert_eq!(destination.state().op_count, 0);
        destination.state.op_count = u64::MAX - 1;
        destination
            .finalize(from_checkpoint, &ledger.message(&p0, 1010, 1, &header), NOW)
            .unwrap();
        assert_eq!(destination.state().op_count, u64::MAX);
        destination
            .apply_control(
                from_checkpoint,
                &ledger.control(&fields, 1010, 0, &header),
                NOW,
            )
            .unwrap();
        destination
            .void_expired(
                1,
                from_checkpoint,
                &ledger.message(&p1, 1010, 2, &header),
                late,
            )
            .unwrap();
        destination
            .finalize(
                from_checkpoint,
                &ledger.message(&p2, 1010, 3, &header),
                late,
            )
            .unwrap();
        destination.void_frozen(7, 3, frozen).unwrap();
        let state = destination.state();
        assert_eq!(state.op_count, u64::MAX);
        assert_eq!(state.consumed, BTreeSet::from([0, 1, 2, 7, 8, 9]));
        assert_eq!((state.control_nonce, state.total_supply), (1, 2_000));
        // A refused call at the bound changes nothing, the counter included.
        assert_eq!(
            refused(&mut destination, |destination| destination
                .void_frozen(7, 1, frozen)),
            DestinationError::AlreadyConsumed { nonce: 7 }
        );
    }

    #[test]
    fn ton_burn_admission_checks_the_entire_recipient_and_exact_wrapper() {
        use super::super::ton_cell::{CellBuilder, CellRef, burn_to_taira_payload, snake_bytes};

        let wrap = |recipient: Cell| {
            CellBuilder::new()
                .store_uint(u128::from(TON_BURN_TO_TAIRA_OP), 32)
                .unwrap()
                .store_ref(recipient)
                .unwrap()
                .build()
        };
        for len in [1, 127, 128, MAX_TAIRA_ACCOUNT_BYTES] {
            let recipient = vec![0x42; len];
            let payload = burn_to_taira_payload(&recipient).unwrap();
            assert_eq!(check_ton_burn_payload(Some(&payload)), Ok(recipient));
        }
        assert_eq!(
            check_ton_burn_payload(None),
            Err(DestinationError::BadBurnPayload)
        );
        for len in [MAX_TAIRA_ACCOUNT_BYTES + 1, 12_700] {
            let payload = wrap(snake_bytes(&vec![0x42; len]).unwrap());
            assert_eq!(
                check_ton_burn_payload(Some(&payload)),
                Err(DestinationError::BadRecipient)
            );
        }
        let tail = snake_bytes(&[0x42]).unwrap();
        let short_continuation = CellBuilder::new()
            .store_bytes(&[0x42; 126])
            .unwrap()
            .store_ref(tail.clone())
            .unwrap()
            .build();
        let non_byte = CellBuilder::new().store_uint(1, 9).unwrap().build();
        let two_refs = CellBuilder::new()
            .store_bytes(&[0x42; 127])
            .unwrap()
            .store_ref(tail.clone())
            .unwrap()
            .store_ref(tail.clone())
            .unwrap()
            .build();
        let opaque = CellBuilder::new()
            .store_bytes(&[0x42; 127])
            .unwrap()
            .store_ref(CellRef::opaque([1; 32], 0))
            .unwrap()
            .build();
        for recipient in [
            CellBuilder::new().build(),
            short_continuation,
            non_byte,
            two_refs,
            opaque,
        ] {
            assert_eq!(
                check_ton_burn_payload(Some(&wrap(recipient))),
                Err(DestinationError::BadSnake)
            );
        }
        let wrong_op = CellBuilder::new()
            .store_uint(0, 32)
            .unwrap()
            .store_ref(tail.clone())
            .unwrap()
            .build();
        assert_eq!(
            check_ton_burn_payload(Some(&wrong_op)),
            Err(DestinationError::BadBurnPayload)
        );
        for extra_bits in [false, true] {
            let mut wrapper = CellBuilder::new();
            wrapper
                .store_uint(u128::from(TON_BURN_TO_TAIRA_OP), 32)
                .unwrap()
                .store_ref(tail.clone())
                .unwrap();
            if extra_bits {
                wrapper.store_bit(false).unwrap();
            } else {
                wrapper.store_ref(tail.clone()).unwrap();
            }
            assert_eq!(
                check_ton_burn_payload(Some(&wrapper.build())),
                Err(DestinationError::BadSnake)
            );
        }
        let missing_ref = CellBuilder::new()
            .store_uint(u128::from(TON_BURN_TO_TAIRA_OP), 32)
            .unwrap()
            .build();
        assert_eq!(
            check_ton_burn_payload(Some(&missing_ref)),
            Err(DestinationError::BadSnake)
        );
    }

    #[test]
    fn source_nonces_end_at_the_u64_end_without_wrapping() {
        let bad = |stored| Err(DestinationError::BadNonce { expected: stored });
        assert_eq!(next_source_nonce(0, 0), Ok(1));
        assert_eq!(next_source_nonce(7, 7), Ok(8));
        // The last nonce is used like any other, and leaves the exhausted value behind.
        assert_eq!(next_source_nonce(u64::MAX - 1, u64::MAX - 1), Ok(u64::MAX));
        // A wrong expectation names the stored nonce.
        for (stored, expected) in [
            (0, 1),
            (7, 6),
            (7, 8),
            (u64::MAX - 1, u64::MAX),
            (u64::MAX - 1, 0),
        ] {
            assert_eq!(
                next_source_nonce(stored, expected),
                bad(stored),
                "{stored} / {expected}"
            );
        }
        // Exhausted: whatever the call expects, the stored value included, it is refused with
        // `BadNonce(2^64 − 1)`.
        for expected in [u64::MAX, 0, 1, u64::MAX - 1] {
            assert_eq!(
                next_source_nonce(u64::MAX, expected),
                bad(u64::MAX),
                "{expected}"
            );
        }
        // No sequence of burns uses a nonce twice: every stored value is above the one before
        // it, up to the bound.
        let mut stored = u64::MAX - 3;
        let mut used = Vec::new();
        while let Ok(next) = next_source_nonce(stored, stored) {
            assert!(next > stored);
            used.push(stored);
            stored = next;
        }
        assert_eq!(used, [u64::MAX - 3, u64::MAX - 2, u64::MAX - 1]);
        assert_eq!(stored, u64::MAX);
    }

    #[test]
    fn block_references_and_leaves_are_checked_against_the_header() {
        let world = World::new();
        let mut ledger = Ledger::default();
        let leaves = [[0x01; 32], [0x02; 32], [0x03; 32]];
        let first = ledger.block(&world, 1010, &leaves);
        let empty = ledger.block(&world, 1015, &[]);
        let second = ledger.block(&world, 1020, &[[0x04; 32]]);
        let bad = Err(DestinationError::BadProof);

        // The certified block itself.
        let same = ledger.block_ref(1010, &first);
        assert_eq!(check_block_ref(&same, &first), Ok(()));
        assert_eq!((same.history_index, same.history_path.len()), (0, 0));
        // It carries no history proof: a history index or a history path refuses it.
        for broken in [
            BlockRefV1 {
                history_index: 1,
                ..same.clone()
            },
            BlockRefV1 {
                history_path: vec![[0; 32]],
                ..same.clone()
            },
        ] {
            assert_eq!(check_block_ref(&broken, &first), bad, "{broken:?}");
        }
        // A certified block without messages has nothing to prove.
        let none = BlockRefV1 {
            height: 1015,
            ..BlockRefV1::default()
        };
        assert_eq!(check_block_ref(&none, &empty), bad);
        // An older block under a later header, with and without a history path.
        let older = ledger.block_ref(1010, &second);
        assert_eq!(check_block_ref(&older, &second), Ok(()));
        assert_eq!(older.history_path.len(), 1);
        let only = ledger.block_ref(1010, &empty);
        assert_eq!(check_block_ref(&only, &empty), Ok(()));
        assert!(only.history_path.is_empty());
        for broken in [
            BlockRefV1 {
                height: 1011,
                ..older.clone()
            },
            BlockRefV1 {
                height: 1021,
                ..older.clone()
            },
            BlockRefV1 {
                sccp_root: [0; 32],
                ..older.clone()
            },
            BlockRefV1 {
                message_count: 0,
                ..older.clone()
            },
            BlockRefV1 {
                message_count: 513,
                ..older.clone()
            },
            BlockRefV1 {
                history_index: 1,
                ..older.clone()
            },
            BlockRefV1 {
                history_path: Vec::new(),
                ..older.clone()
            },
            BlockRefV1 {
                history_path: vec![[0; 32]; 33],
                ..older.clone()
            },
        ] {
            assert_eq!(check_block_ref(&broken, &second), bad, "{broken:?}");
        }
        // A header without history proves no older block.
        assert_eq!(check_block_ref(&older, &world.x(1030)), bad);

        // Leaves: every index with its own path, and nothing else.
        for (index, leaf) in (0_u32..).zip(&leaves) {
            let path = ledger.leaf_path(1010, index);
            assert_eq!(check_leaf(leaf, index, &path, &same), Ok(()));
            assert_eq!(check_leaf(&[0xee; 32], index, &path, &same), bad);
            assert_eq!(check_leaf(leaf, index + 1, &path, &same), bad);
        }
        assert_eq!(check_leaf(&leaves[0], 0, &[], &same), bad);
        let one = ledger.block_ref(1020, &second);
        assert_eq!(check_leaf(&[0x04; 32], 0, &[], &one), Ok(()));
        assert_eq!(check_leaf(&[0x04; 32], 0, &[[0; 32]], &one), bad);
    }

    #[test]
    fn payload_fields_are_read_from_the_layout() {
        let payload = outbound(SccpNetworkV1::BscMainnet, 9, 7, 5, T0, &RECIPIENT)
            .encode()
            .unwrap();
        let raw = raw_payload(&payload).unwrap();
        assert_eq!(
            (raw.source_domain, raw.dest_domain, raw.route_revision),
            (0, 2, 7)
        );
        assert_eq!(raw.recipient, RECIPIENT);
        assert_eq!(raw.route_id, b"taira_bsc_xor");
        // Every truncation is reported, never read past.
        for len in 0..payload.len() {
            assert!(raw_payload(&payload[..len]).is_none(), "{len}");
        }

        assert_eq!(
            payload_field(&[7, 0, 2, 0xaa, 0xbb, 0xcc]),
            Some((&[0xaa, 0xbb][..], &[0xcc][..]))
        );
        assert_eq!(payload_field(&[7, 0, 0]), Some((&[][..], &[][..])));
        assert_eq!(payload_field(&[7, 0, 2, 0xaa]), None);
        assert_eq!(payload_field(&[7, 0]), None);
        assert_eq!(payload_field(&[]), None);
    }

    #[test]
    fn refusals_of_the_machine_keep_their_names() {
        // The relation's refusals have one mapping per flavour, in `finality`
        // (`CertificateError::destination_error` and `ton_destination_error`), which
        // `Destination::verify` applies; the tests of the odd keys above drive it.
        for error in [
            CommitteeError::Equivocated,
            CommitteeError::Expired,
            CommitteeError::NotCurrent,
            CommitteeError::LatchRequired,
            CommitteeError::CheckpointRetired,
        ] {
            assert_eq!(committee_error(error).name(), error.destination_error());
        }
    }

    #[test]
    fn events_name_their_abi_signature_and_topic() {
        let events = [
            DestinationEvent::Certificate {
                height: 1,
                generation: 1,
                qc: Vec::new(),
                header: Vec::new(),
                signature: Vec::new(),
            },
            DestinationEvent::Checkpointed {
                height: 1,
                id: [0; 32],
            },
            DestinationEvent::CommitteeRotated(RotationV1 {
                generation: 2,
                root: [1; 32],
                until_ms: 3,
                start: 4,
            }),
            DestinationEvent::Latched(ViolationV1 {
                reason: LatchReasonV1::BelowStart,
                generation: 1,
                height: 1,
                a: [0; 32],
                b: [0; 32],
            }),
            DestinationEvent::ControlApplied {
                control_nonce: 1,
                track: 1,
                parliament_paused: true,
                fast_pause_until_ms: 0,
                certificate_id: [1; 32],
            },
            DestinationEvent::Finalized {
                message_id: [1; 32],
                nonce: 0,
                recipient: Vec::new(),
                token_amount: 1,
            },
            DestinationEvent::Voided {
                message_id: [0; 32],
                nonce: 0,
            },
            DestinationEvent::VoidedRange {
                message_id: [0; 32],
                first_nonce: 0,
                count: 1,
            },
        ];
        let table = super::super::destination_abi::EVENT_TOPICS;
        let mut names = BTreeSet::new();
        for event in &events {
            let (_, signature, topic) = table
                .into_iter()
                .find(|(name, _, _)| *name == event.name())
                .unwrap_or_else(|| panic!("`{}` is not an event of the ABI", event.name()));
            assert_eq!(event.signature(), signature);
            assert_eq!(event.topic0(), topic);
            names.insert(event.name());
        }
        // Every event of the ABI except the burn, which the model does not have. A frozen
        // range on TON is the same `SccpVoided`.
        assert_eq!(names.len(), table.len() - 1);
        assert!(!names.contains("SccpTransferToTaira"));
    }

    // -- the shared scenario tables --------------------------------------------------------------

    fn flag(value: &Value, name: &str) -> bool {
        field(value, name)
            .as_bool()
            .unwrap_or_else(|| panic!("reference field `{name}` is not a flag"))
    }

    fn words(value: &Value, name: &str) -> Vec<[u8; 32]> {
        field(value, name)
            .as_array()
            .unwrap_or_else(|| panic!("reference field `{name}` is not an array"))
            .iter()
            .map(|word| {
                bytes(word.as_str().expect("a hex string"))
                    .try_into()
                    .expect("32 bytes")
            })
            .collect()
    }

    fn small<T: TryFrom<u64>>(value: &Value, name: &str) -> T {
        T::try_from(number(value, name))
            .unwrap_or_else(|_| panic!("reference field `{name}` is out of range"))
    }

    fn deployment_of(value: &Value) -> DeploymentV1 {
        let pin = field(value, "pin");
        DeploymentV1 {
            flavor: match text(value, "flavor") {
                "evm" => EVM,
                "ton" => TON,
                other => panic!("unknown flavor `{other}`"),
            },
            taira_network_id: word(value, "taira_network_id"),
            consensus_instance: word(value, "consensus_instance"),
            network: match text(value, "network") {
                "ethereum-mainnet" => SccpNetworkV1::EthereumMainnet,
                "bsc-mainnet" => SccpNetworkV1::BscMainnet,
                "ton-mainnet" => SccpNetworkV1::TonMainnet,
                other => panic!("unknown profile `{other}`"),
            },
            destination_word: word(value, "destination_word"),
            route_revision: small(value, "route_revision"),
            max_wrapped_supply: text(value, "max_wrapped_supply").parse().unwrap(),
            pin_generation: number(pin, "generation"),
            pin_root: word(pin, "committee_root"),
            pin_start_height: number(pin, "start_height"),
            pin_until_ms: number(pin, "until_ms"),
            pin_keys: (!field(pin, "keys").is_null()).then(|| keys(pin, "keys")),
        }
    }

    fn certificate_of(pool: &Value, id: &Value) -> TairaCertificateV1 {
        let entry = field(pool, id.as_str().expect("a pool id"));
        let evm = field(entry, "evm");
        TairaCertificateV1 {
            qc: bytes(text(evm, "qc")),
            header: bytes(text(evm, "header")),
            signature: bytes(text(evm, "signature")),
            committee: bytes(text(evm, "committee")),
            signer_ys: bytes(text(evm, "signerYs")),
            ton_signature: bytes(text(field(entry, "ton"), "signature")),
        }
    }

    fn block_ref_of(value: &Value) -> BlockRefV1 {
        BlockRefV1 {
            height: number(value, "height"),
            sccp_root: word(value, "sccpRoot"),
            message_count: small(value, "messageCount"),
            history_index: number(value, "historyIndex"),
            history_path: words(value, "historyPath"),
        }
    }

    fn message_proof_of(value: &Value) -> MessageProofV1 {
        MessageProofV1 {
            payload: bytes(text(value, "payload")),
            leaf_index: small(value, "leafIndex"),
            path: words(value, "path"),
            block: block_ref_of(field(value, "block")),
        }
    }

    fn control_proof_of(value: &Value) -> ControlProofV1 {
        // The vectors write `parliamentPaused` as a flag when it is 0 or 1.
        let paused = field(value, "parliamentPaused");
        ControlProofV1 {
            control_nonce: number(value, "controlNonce"),
            track: small(value, "track"),
            parliament_paused: paused
                .as_bool()
                .map_or_else(|| small(value, "parliamentPaused"), u8::from),
            fast_pause_until_ms: number(value, "fastPauseUntilMs"),
            certificate_id: word(value, "certificateId"),
            effect_hash: word(value, "effectHash"),
            leaf_index: small(value, "leafIndex"),
            path: words(value, "path"),
            block: block_ref_of(field(value, "block")),
        }
    }

    /// The events a scenario step expects. `SccpCertificate` names a pooled certificate by
    /// its `QC_FIXED` and `X`; the signature is the one presented, which only the pairing
    /// check binds, so it is left empty here and compared by its length.
    /// The events a step expects. An `SccpCertificate` names a pooled certificate: the
    /// event carries its `QC_FIXED`, its header and its signature in the wire form of
    /// `flavor`, which is what the destination publishes.
    fn events_of(
        pool: &Value,
        expected: &Value,
        flavor: DestinationFlavor,
    ) -> Vec<DestinationEvent> {
        let Some(events) = expected.get("events").and_then(Value::as_array) else {
            return Vec::new();
        };
        events
            .iter()
            .map(|event| match text(event, "event") {
                "SccpCertificate" => {
                    let entry = field(pool, text(event, "certificate"));
                    let evm = field(entry, "evm");
                    let signature = match flavor {
                        DestinationFlavor::Evm => bytes(text(evm, "signature")),
                        DestinationFlavor::Ton => bytes(text(field(entry, "ton"), "signature")),
                    };
                    DestinationEvent::Certificate {
                        height: number(event, "height"),
                        generation: number(event, "generation"),
                        qc: bytes(text(evm, "qc")),
                        header: bytes(text(evm, "header")),
                        signature,
                    }
                }
                "SccpCheckpointed" => DestinationEvent::Checkpointed {
                    height: number(event, "height"),
                    id: word(event, "header"),
                },
                "SccpCommitteeRotated" => DestinationEvent::CommitteeRotated(RotationV1 {
                    generation: number(event, "generation"),
                    root: word(event, "root"),
                    until_ms: number(event, "untilMs"),
                    start: number(event, "startHeight"),
                }),
                "SccpLatched" => DestinationEvent::Latched(ViolationV1 {
                    reason: match number(event, "reason") {
                        1 => LatchReasonV1::ConflictingCheckpoint,
                        2 => LatchReasonV1::BelowStart,
                        3 => LatchReasonV1::RotationBelowHigh,
                        other => panic!("unknown latch reason {other}"),
                    },
                    generation: number(event, "generation"),
                    height: number(event, "height"),
                    a: word(event, "a"),
                    b: word(event, "b"),
                }),
                "SccpControlApplied" => DestinationEvent::ControlApplied {
                    control_nonce: number(event, "controlNonce"),
                    track: small(event, "track"),
                    parliament_paused: flag(event, "parliamentPaused"),
                    fast_pause_until_ms: number(event, "fastPauseUntilMs"),
                    certificate_id: word(event, "certificateId"),
                },
                "SccpFinalized" => DestinationEvent::Finalized {
                    message_id: word(event, "messageId"),
                    nonce: number(event, "nonce"),
                    recipient: bytes(text(event, "recipient")),
                    token_amount: text(event, "tokenAmount").parse().unwrap(),
                },
                "SccpVoided" if event.get("nonce").is_some() => DestinationEvent::Voided {
                    message_id: word(event, "messageId"),
                    nonce: number(event, "nonce"),
                },
                "SccpVoided" => DestinationEvent::VoidedRange {
                    message_id: word(event, "messageId"),
                    first_nonce: number(event, "firstNonce"),
                    count: number(event, "count"),
                },
                other => panic!("unknown event `{other}`"),
            })
            .collect()
    }

    /// The state of the model against a `state_after` (or `initial_state`) of the vectors.
    fn assert_state(at: &str, destination: &Destination, expected: &Value, now_ms: Option<u64>) {
        let state = destination.state();
        let committee = field(expected, "committee");
        assert_eq!(
            state.committee,
            CommitteeStateV1 {
                root: word(committee, "root"),
                generation: number(committee, "generation"),
                start: number(committee, "start"),
                high: number(committee, "high"),
                until_ms: number(committee, "until_ms"),
                equivocated: flag(expected, "equivocated"),
            },
            "{at}"
        );
        assert_eq!(
            state.keys,
            committee.get("keys").map(|_| keys(committee, "keys")),
            "{at}"
        );
        let checkpoints: BTreeMap<u64, [u8; 32]> = field(expected, "checkpoints")
            .as_array()
            .expect("a checkpoint list")
            .iter()
            .map(|checkpoint| (number(checkpoint, "height"), word(checkpoint, "id")))
            .collect();
        assert_eq!(state.checkpoints, checkpoints, "{at}");
        let pause = field(expected, "pause");
        assert_eq!(
            (
                state.parliament_paused,
                state.fast_pause_until_ms,
                state.control_nonce
            ),
            (
                flag(pause, "parliament_paused"),
                number(pause, "fast_pause_until_ms"),
                number(pause, "control_nonce")
            ),
            "{at}"
        );
        assert_eq!(state.op_count, number(expected, "op_count"), "{at}");
        let consumed: BTreeSet<u64> = field(expected, "consumed")
            .as_array()
            .expect("a nonce list")
            .iter()
            .map(|nonce| nonce.as_u64().expect("a nonce"))
            .collect();
        assert_eq!(state.consumed, consumed, "{at}");
        assert_eq!(
            state.total_supply.to_string(),
            text(expected, "total_supply"),
            "{at}"
        );
        assert_eq!(
            state.balances.values().sum::<u128>(),
            state.total_supply,
            "{at}"
        );
        if let Some(now_ms) = now_ms {
            assert_eq!(destination.is_live(now_ms), flag(expected, "live"), "{at}");
            assert_eq!(
                destination.minting_paused(now_ms),
                flag(pause, "effective"),
                "{at}"
            );
        }
    }

    /// The views of the model against a `views` step of the vectors.
    fn assert_views(at: &str, destination: &Destination, expected: &Value, now_ms: u64) {
        let state = destination.state();
        let deployment = destination.deployment();
        let committee = field(expected, "committeeState");
        assert_eq!(
            state.committee,
            CommitteeStateV1 {
                root: word(committee, "root"),
                generation: number(committee, "generation"),
                start: number(committee, "start"),
                high: number(committee, "high"),
                until_ms: number(committee, "untilMs"),
                equivocated: flag(expected, "equivocated"),
            },
            "{at}"
        );
        let initial = field(expected, "initialCommittee");
        assert_eq!(
            (
                deployment.pin_generation,
                deployment.pin_root,
                deployment.pin_start_height,
                deployment.pin_until_ms
            ),
            (
                number(initial, "generation"),
                word(initial, "root"),
                number(initial, "start"),
                number(initial, "untilMs")
            ),
            "{at}"
        );
        let pause = field(expected, "pauseState");
        assert_eq!(
            destination.pause_state(now_ms),
            PauseStateV1 {
                parliament_paused: flag(pause, "parliamentPaused"),
                fast_pause_until_ms: number(pause, "fastPauseUntilMs"),
                control_nonce: number(pause, "controlNonce"),
                effective: flag(pause, "effective"),
            },
            "{at}"
        );
        assert_eq!(
            destination.minting_paused(now_ms),
            flag(expected, "mintingPaused"),
            "{at}"
        );
        assert_eq!(
            state.control_nonce,
            number(expected, "controlNonce"),
            "{at}"
        );
        assert_eq!(state.op_count, number(expected, "opCount"), "{at}");
        assert_eq!(destination.is_live(now_ms), flag(expected, "live"), "{at}");
    }

    /// Replay one scenario of the shared tables through the model: every step gives the
    /// outcome, the error arguments, the events, the returned value and the state the
    /// independent Python model recorded. Returns the number of steps.
    fn replay(reference: &Value, scenario: &Value) -> usize {
        let name = text(scenario, "name");
        let pool = field(reference, "certificates");
        let committees = field(reference, "committees");
        let deployment = deployment_of(field(scenario, "deployment"));
        let flavor = deployment.flavor;
        assert_eq!(text(scenario, "flavor"), flavor.name(), "{name}");
        let mut destination = Destination::new(deployment).unwrap();
        assert_state(name, &destination, field(scenario, "initial_state"), None);

        let steps = rows(scenario, "steps");
        let mut previous_ms = 0;
        for (index, step) in steps.iter().enumerate() {
            let at = format!("{name}, step {index}");
            let now_ms = number(step, "now_ms");
            // The destination clock: whole seconds that never run backwards.
            assert!(
                now_ms.is_multiple_of(SECOND) && now_ms >= previous_ms,
                "{at}"
            );
            previous_ms = now_ms;
            let expected = field(step, "expected");
            // A TON row names the message of §5.3.2; the model has one entry point for both.
            let recorded = text(step, "call");
            let call = match recorded {
                "sccp_checkpoint" => "submitCheckpoints",
                "sccp_finalize" => "finalizeFromTaira",
                "sccp_finalize_checkpoint" => "finalizeFromCheckpoint",
                "sccp_apply_control" => "applyControl",
                "sccp_apply_control_checkpoint" => "applyControlFromCheckpoint",
                "sccp_void_expired" => "voidExpired",
                "sccp_void_expired_checkpoint" => "voidExpiredFromCheckpoint",
                "sccp_void_frozen" => "voidFrozen",
                evm => evm,
            };
            assert_eq!(
                recorded != call,
                flavor == TON && call != "views",
                "{at}: `{recorded}` is not a call of the {} flavour",
                flavor.name()
            );
            let certificate = step.get("certificate").map(|id| certificate_of(pool, id));
            let checkpoint = step.get("checkpoint").map(|checkpoint| CheckpointRefV1 {
                header: bytes(text(checkpoint, "header")),
            });
            assert_eq!(
                checkpoint.is_some(),
                call.ends_with("FromCheckpoint"),
                "{at}"
            );
            let source = || match (&certificate, &checkpoint) {
                (Some(certificate), None) => CertificateSourceV1::Inline(certificate),
                (None, Some(checkpoint)) => CertificateSourceV1::Checkpoint(checkpoint),
                _ => panic!("{at}: one certificate source"),
            };
            let result = match call {
                "submitCheckpoints" => {
                    let certificates: Vec<TairaCertificateV1> = field(step, "certificates")
                        .as_array()
                        .expect("pool ids")
                        .iter()
                        .map(|id| certificate_of(pool, id))
                        .collect();
                    let next_keys: Vec<Option<Vec<[u8; KEY_LEN]>>> = step
                        .get("next_keys")
                        .and_then(Value::as_array)
                        .map(|names| {
                            names
                                .iter()
                                .map(|name| {
                                    name.as_str()
                                        .map(|name| keys(field(committees, name), "keys"))
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    destination.submit_checkpoints(&certificates, &next_keys, now_ms)
                }
                "finalizeFromTaira" | "finalizeFromCheckpoint" => {
                    destination.finalize(source(), &message_proof_of(field(step, "proof")), now_ms)
                }
                "applyControl" | "applyControlFromCheckpoint" => destination.apply_control(
                    source(),
                    &control_proof_of(field(step, "proof")),
                    now_ms,
                ),
                "voidExpired" | "voidExpiredFromCheckpoint" => destination.void_expired(
                    number(step, "nonce"),
                    source(),
                    &message_proof_of(field(step, "proof")),
                    now_ms,
                ),
                "voidFrozen" => destination.void_frozen(
                    text(step, "firstNonce").parse().unwrap(),
                    number(step, "count"),
                    now_ms,
                ),
                "views" => {
                    assert_views(&at, &destination, expected, now_ms);
                    assert_state(&at, &destination, field(step, "state_after"), Some(now_ms));
                    continue;
                }
                other => panic!("{at}: unknown call `{other}`"),
            };

            let outcome = text(expected, "outcome");
            let expected_events = events_of(pool, expected, flavor);
            match result {
                Ok(done) => {
                    assert_eq!(outcome, "ok", "{at}");
                    assert_eq!(
                        done.stopped.map(StopReasonV1::name),
                        expected.get("stopped").and_then(Value::as_str),
                        "{at}"
                    );
                    assert_eq!(
                        done.returned,
                        expected.get("return").map(|_| word(expected, "return")),
                        "{at}"
                    );
                    // Whole events, the published signature included.
                    assert_eq!(done.events, expected_events, "{at}");
                }
                Err(error) => {
                    assert_eq!(error.name(), outcome, "{at}");
                    // `AlreadyConsumed(nonce)` and `BadNonce(expected)` carry an argument.
                    let argument = expected.get("error_args").map(|arguments| {
                        arguments
                            .get("nonce")
                            .or_else(|| arguments.get("expected"))
                            .and_then(Value::as_u64)
                            .unwrap_or_else(|| panic!("{at}: an unknown error argument"))
                    });
                    assert_eq!(error.argument(), argument, "{at}");
                    assert!(expected_events.is_empty(), "{at}");
                }
            }
            assert_state(&at, &destination, field(step, "state_after"), Some(now_ms));
        }
        steps.len()
    }

    /// The shapes of the shared tables fit the model: one scenario of
    /// `fixtures/sccp/committee_transitions_v1.json` replayed step by step.
    #[test]
    fn smoke_replays_one_reference_scenario() {
        let reference = reference(
            "committee_transitions_v1.json",
            "iroha.sccp.committee-transitions.v1",
        );
        let scenario = rows(&reference, "scenarios")
            .iter()
            .find(|scenario| text(scenario, "name") == "finalize_proofs_cap_and_voids")
            .expect("the scenario is in the file");
        // Inline and checkpoint mints, a history proof, a replay, the cap, a bad path, both
        // deadline sides, a nonce mismatch, a void, an unknown checkpoint, a bad recipient
        // and a frozen void on a live destination.
        assert_eq!(replay(&reference, scenario), 14);
    }

    /// Every scenario of both shared tables, in the flavour it was recorded for.
    #[test]
    fn model_replays_the_reference_scenarios() {
        for (file, schema, list, scenarios, steps) in [
            (
                "committee_transitions_v1.json",
                "iroha.sccp.committee-transitions.v1",
                "scenarios",
                40,
                189,
            ),
            (
                "control_v1.json",
                "iroha.sccp.control.v1",
                "destination_effects",
                10,
                42,
            ),
        ] {
            let table = reference(file, schema);
            let recorded = rows(&table, list);
            let replayed: usize = recorded
                .iter()
                .map(|scenario| replay(&table, scenario))
                .sum();
            // No table is replayed vacuously.
            assert!(
                recorded.len() >= scenarios,
                "{file}: {} scenarios",
                recorded.len()
            );
            assert!(replayed >= steps, "{file}: {replayed} steps");
        }
        let transitions = reference(
            "committee_transitions_v1.json",
            "iroha.sccp.committee-transitions.v1",
        );
        let flavors: BTreeSet<&str> = rows(&transitions, "scenarios")
            .iter()
            .map(|scenario| text(scenario, "flavor"))
            .collect();
        assert_eq!(flavors, BTreeSet::from(["evm", "ton"]));
        // The limits the model applies are the ones the file states (§3.9).
        let constants = field(&transitions, "constants");
        assert_eq!(
            small::<usize>(constants, "max_certificates_per_call"),
            MAX_CERTIFICATES_PER_CALL
        );
        assert_eq!(
            small::<usize>(constants, "ton_checkpoint_slots"),
            TON_CHECKPOINT_SLOTS
        );
        assert_eq!(
            number(constants, "max_void_frozen_range_evm"),
            EVM.max_void_frozen_range()
        );
        assert_eq!(
            number(constants, "max_void_frozen_range_ton"),
            TON.max_void_frozen_range()
        );
        assert_eq!(number(constants, "max_validity_ms"), MAX_VALIDITY_MS);
        assert_eq!(number(constants, "max_init_slack_ms"), MAX_INIT_SLACK_MS);
        // The deployment bound on the pinned `untilMs`, around both ends.
        let bounds = rows(&transitions, "init_bounds");
        let mut verdicts = BTreeSet::new();
        for row in bounds {
            let accepted = init_until_ms_is_valid(number(row, "now_ms"), number(row, "until_ms"));
            assert_eq!(
                text(row, "expected"),
                if accepted { "ok" } else { "BadConfig" },
                "{}",
                text(row, "label")
            );
            verdicts.insert(accepted);
        }
        assert_eq!((bounds.len(), verdicts.len()), (5, 2));
        // A TON row runs on the TON profile and names TON messages (checked by `replay`).
        for scenario in rows(&transitions, "scenarios") {
            assert_eq!(
                text(scenario, "flavor") == "ton",
                text(field(scenario, "deployment"), "network") == "ton-mainnet",
                "{}",
                text(scenario, "name")
            );
        }
    }
    #[test]
    fn borrowed_certificate_authority_matches_full_and_cached_destination_paths() {
        let world = World::new();
        let cert = world.cert(1010);
        for flavor in FLAVORS {
            let destination = world.destination(flavor);
            let authority = CertificateAuthorityV1::new(
                flavor,
                &NETWORK,
                &INSTANCE,
                &destination.state.committee,
                destination.state.keys.as_deref(),
            )
            .unwrap();
            let full = authority
                .verify(&cert, |height| {
                    assert_eq!(height, 1010);
                    None
                })
                .unwrap();
            assert!(full.full_path);
            assert_eq!(full.header, world.x(1010));
            assert_eq!(destination.verify_certificate(&cert, NOW), Ok(()));
            let mut events = Vec::new();
            assert_eq!(
                destination.verify(&cert, &mut events),
                Ok((full.header, full.checkpoint_id))
            );
            assert_eq!(events.len(), 1);
            assert!(matches!(
                &events[0],
                DestinationEvent::Certificate { height: 1010, .. }
            ));
            // A different valid signature is not a signature of this QC. Stored X takes the
            // mandatory cheap path; an absent or different checkpoint still checks pairing.
            let mut invalid = cert.clone();
            let wrong = world.cert(1011);
            invalid.signature = wrong.signature;
            invalid.ton_signature = wrong.ton_signature;
            assert_eq!(
                authority.verify(&invalid, |_| None),
                Err(DestinationError::BadSignature)
            );
            assert_eq!(
                authority.verify(&invalid, |_| Some([9; 32])),
                Err(DestinationError::BadSignature)
            );
            let cheap = authority
                .verify(&invalid, |height| {
                    assert_eq!(height, 1010);
                    Some(full.checkpoint_id)
                })
                .unwrap();
            assert!(!cheap.full_path);
            assert_eq!(cheap.header, full.header);
            let mut stored = destination;
            stored.state.checkpoints.insert(1010, full.checkpoint_id);
            let mut events = Vec::new();
            assert_eq!(
                stored.verify(&invalid, &mut events),
                Ok((full.header, full.checkpoint_id))
            );
            assert!(events.is_empty());
            invalid.signature = IDENTITY_SIGNATURE_EVM.to_vec();
            invalid.ton_signature = IDENTITY_SIGNATURE.to_vec();
            assert_eq!(
                stored.verify(&invalid, &mut events),
                Err(DestinationError::BadSignature)
            );
            assert!(events.is_empty());
        }
    }

    #[test]
    fn borrowed_ton_authority_binds_original_stored_keys_before_verification() {
        let world = World::new();
        let destination = world.destination(TON);
        let keys = destination.state.keys.as_deref().unwrap();
        let authority = CertificateAuthorityV1::new(
            TON,
            &NETWORK,
            &INSTANCE,
            &destination.state.committee,
            Some(keys),
        )
        .unwrap();
        assert!(core::ptr::eq(
            authority.ton_keys.unwrap().as_ptr(),
            keys.as_ptr()
        ));
        assert_eq!(
            authority
                .verify(&world.cert(1010), |_| None)
                .unwrap()
                .header,
            world.x(1010)
        );
        let other = world.k1.keys();
        let mut reversed = keys.to_vec();
        reversed.reverse();
        for supplied in [
            None,
            Some(other.as_slice()),
            Some(reversed.as_slice()),
            Some(&keys[..3]),
        ] {
            assert_eq!(
                CertificateAuthorityV1::new(
                    TON,
                    &NETWORK,
                    &INSTANCE,
                    &destination.state.committee,
                    supplied
                )
                .unwrap_err(),
                DestinationError::BadCommittee
            );
        }
        let mut changed = destination.state.committee;
        changed.root = [9; 32];
        assert_eq!(
            CertificateAuthorityV1::new(TON, &NETWORK, &INSTANCE, &changed, Some(keys))
                .unwrap_err(),
            DestinationError::BadCommittee
        );
        let mut changed = destination.state.committee;
        changed.generation += 1;
        let authority =
            CertificateAuthorityV1::new(TON, &NETWORK, &INSTANCE, &changed, Some(keys)).unwrap();
        assert_eq!(
            authority.verify(&world.cert(1010), |_| None),
            Err(DestinationError::CommitteeNotAccepted)
        );
        let wrong_instance = [9; 32];
        let authority = CertificateAuthorityV1::new(
            TON,
            &NETWORK,
            &wrong_instance,
            &destination.state.committee,
            Some(keys),
        )
        .unwrap();
        assert_eq!(
            authority.verify(&world.cert(1010), |_| None),
            Err(DestinationError::BadSignature)
        );
        let wrong_network = [9; 32];
        let authority = CertificateAuthorityV1::new(
            TON,
            &wrong_network,
            &INSTANCE,
            &destination.state.committee,
            Some(keys),
        )
        .unwrap();
        assert_eq!(
            authority.verify(&world.cert(1010), |_| None),
            Err(DestinationError::BadHeader)
        );
    }
}
