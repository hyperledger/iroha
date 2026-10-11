//! A deterministic Taira-side producer of finality headers, certificates and proofs.
//!
//! This is not a Taira implementation. It produces only the contract-visible artefacts a
//! destination consumes (`specs/sccp.md` §3.4–§3.8) with the generation bookkeeping of §4.2.2
//! (a rotation at `h` starts generation `g + 1` at `h + 1` with the deadline
//! `t(h) + validity_ms`), so that the destination model can be driven through realistic
//! sequences. It is the Rust twin of `scripts/sccp_reference/taira.py` and of the certificate
//! builder of `finality.py`, and both produce the same bytes.
//!
//! A [`Certificate`] carries its wire fields as raw bytes, because negative vectors mutate
//! them directly, together with the values it was built from ([`CertificateMeta`]).
//! [`CertifyOptions`] holds the overrides that make a signature cover something other than
//! what the wire carries.

use std::collections::BTreeMap;

use iroha_crypto::Hash;
use iroha_data_model::bridge::SccpNetworkV1;
use iroha_sccp::v1::{
    committee::{KEY_LEN, SIGNATURE_LEN, aggregate_public_key, committee_root, quorum, signer_ys},
    control::{ControlLeafV1, control_leaf, control_leaf_unchecked},
    destination::{BlockRefV1, ControlProofV1, MessageProofV1, TairaCertificateV1},
    finality::{
        COMMIT_PREIMAGE_LEN, DST_SIG, FLAG_ACTIVE, FLAG_ROTATION, KIND_COMMIT, QcFixedV1,
        RESULT_TAG, SccpFinalityHeaderFieldsV1, SccpFinalityHeaderV1, TAG_SIG, X_HEAD_LEN,
        bitmap_from_signers, body_digest, commit_message, commit_preimage, outer_result,
    },
    hashes::{history_leaf, message_id, payload_hash, transfer_leaf},
    history::{history_path, history_root},
    merkle::PromoteOddTree,
    network::lane_bytes,
    payload::SccpTransferPayloadV1,
};
use norito::json::Value;
use sha2::{Digest as _, Sha256};

use super::{
    bls_support::{TestKey, g2_evm192, hash_to_g2, sign_consensus, sign_under_dst, test_key},
    hx, hx_string, list, num, obj,
};

/// The sender of every simulated transfer: a Taira account, codec 3.
pub const DEFAULT_SENDER: [u8; 34] = {
    let mut sender = [0x5a; 34];
    sender[0] = 0x01;
    sender
};

/// Offset of `height` in `X` (§3.6): the builder reads it from headers that do not parse.
const X_OFFSET_HEIGHT: usize = 48;

// ---------------------------------------------------------------------------------------------
// Committees
// ---------------------------------------------------------------------------------------------

/// A committee of §11.3 test keys in canonical order (strictly ascending key bytes).
#[derive(Clone, Debug)]
pub struct Committee {
    /// The name the fixtures give the committee.
    pub name: String,
    members: Vec<&'static TestKey>,
}

impl Committee {
    /// The committee of the test keys `indices`.
    ///
    /// # Panics
    /// When an index repeats: a committee holds distinct keys.
    pub fn new(name: &str, indices: impl IntoIterator<Item = u8>) -> Self {
        let mut members: Vec<&'static TestKey> = indices.into_iter().map(test_key).collect();
        members.sort_by(|left, right| left.public.cmp(&right.public));
        assert!(
            members
                .windows(2)
                .all(|pair| pair[0].public < pair[1].public),
            "duplicate committee key in {name}"
        );
        Self {
            name: name.to_owned(),
            members,
        }
    }

    /// The committee size `n`.
    pub fn n(&self) -> usize {
        self.members.len()
    }

    /// `q = n − f`.
    ///
    /// # Panics
    /// Unless `n ∈ {4, 7, …, 31}`.
    pub fn quorum(&self) -> usize {
        quorum(self.n()).expect("a committee of 3f + 1 members")
    }

    /// The members in canonical order: signer index `i` is `members()[i]`.
    pub fn members(&self) -> &[&'static TestKey] {
        &self.members
    }

    /// The compressed keys `PK_0..PK_{n−1}`.
    pub fn keys(&self) -> Vec<[u8; KEY_LEN]> {
        self.members.iter().map(|member| member.public).collect()
    }

    /// The committee root.
    pub fn root(&self) -> [u8; 32] {
        committee_root(&self.keys()).expect("a committee of 1 to 255 keys")
    }

    /// The member that holds `key`.
    ///
    /// # Panics
    /// When `key` is not a key of the committee.
    pub fn member_of(&self, key: &[u8; KEY_LEN]) -> &'static TestKey {
        self.members
            .iter()
            .find(|member| member.public == *key)
            .copied()
            .unwrap_or_else(|| panic!("{} holds no key {}", self.name, hx_string(key)))
    }

    /// The fixture object `{n, q, test_key_indices, keys, root}`. `test_key_indices[i]` is the
    /// test key index at canonical position `i`.
    pub fn as_json(&self) -> Value {
        obj([
            ("n", num(self.n() as u64)),
            ("q", num(self.quorum() as u64)),
            (
                "test_key_indices",
                list(self.members.iter().map(|member| num(member.index.into()))),
            ),
            ("keys", list(self.keys().iter().map(|key| hx(key)))),
            ("root", hx(&self.root())),
        ])
    }
}

/// `Σ 1 << i` over `indices`: the `signers` field that names them.
///
/// # Panics
/// When an index is 32 or more.
pub fn signers_from_indices(indices: &[usize]) -> u32 {
    indices.iter().fold(0, |signers, index| {
        assert!(*index < 32, "signer index {index} does not fit the field");
        signers | 1 << index
    })
}

// ---------------------------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------------------------

/// The values a certificate was built from.
#[derive(Clone, Debug)]
pub struct CertificateMeta {
    /// The size of the signing committee.
    pub n: usize,
    /// The canonical indices whose bits the builder set, ascending.
    pub signer_indices: Vec<usize>,
    /// The `signers` field as encoded: it differs from `signer_indices` in a negative vector.
    pub signers: u32,
    /// The Sumeragi bitmap of `signer_indices`.
    pub bitmap: Vec<u8>,
    /// The `QC_FIXED` fields as encoded.
    pub qc: QcFixedV1,
    /// `R` of the signed header.
    pub result: [u8; 32],
    /// The signed vote preimage.
    pub preimage: [u8; COMMIT_PREIMAGE_LEN],
    /// `m = SHA-256(preimage)`.
    pub message: [u8; 32],
    /// The kind byte of the signed preimage.
    pub kind: u8,
    /// The domain separation tag the signature was made under.
    pub dst: Vec<u8>,
    /// `hash_to_G2(m, dst)`, compressed.
    pub hash_point: [u8; SIGNATURE_LEN],
    /// The aggregate signature as built, compressed.
    pub sigma: [u8; SIGNATURE_LEN],
    /// The aggregate key of `signer_indices`, compressed.
    pub apk: [u8; KEY_LEN],
}

/// A full SCCP certificate in wire form.
///
/// `qc`, `header`, `signature_evm`, `committee` and `signer_ys` are exactly the fields of the
/// EVM `TairaCertificateV1`; `signature_ton` is the 96-byte compressed aggregate of the TON
/// `TairaCert` cell.
#[derive(Clone, Debug)]
pub struct Certificate {
    /// `QC_FIXED`.
    pub qc: Vec<u8>,
    /// The finality header `X`.
    pub header: Vec<u8>,
    /// The aggregate signature in the 192-byte EVM form.
    pub signature_evm: Vec<u8>,
    /// The aggregate signature compressed.
    pub signature_ton: Vec<u8>,
    /// The committee keys, `48n` bytes.
    pub committee: Vec<u8>,
    /// `signerYs`.
    pub signer_ys: Vec<u8>,
    /// What the certificate was built from.
    pub meta: CertificateMeta,
}

impl Certificate {
    /// The certificate as a destination entry point takes it.
    pub fn wire(&self) -> TairaCertificateV1 {
        TairaCertificateV1 {
            qc: self.qc.clone(),
            header: self.header.clone(),
            signature: self.signature_evm.clone(),
            committee: self.committee.clone(),
            signer_ys: self.signer_ys.clone(),
            ton_signature: self.signature_ton.clone(),
        }
    }

    /// The EVM calldata fields `{qc, header, signature, committee, signerYs}`.
    pub fn evm_json(&self) -> Value {
        obj([
            ("qc", hx(&self.qc)),
            ("header", hx(&self.header)),
            ("signature", hx(&self.signature_evm)),
            ("committee", hx(&self.committee)),
            ("signerYs", hx(&self.signer_ys)),
        ])
    }

    /// The contents of the TON `TairaCert` cell. `signers` is the last four bytes of
    /// `QC_FIXED` and `qc_fixed_cell` everything before them, so a `QC_FIXED` of the wrong
    /// length gives a `QcFixed` cell of the wrong length, never a well-formed one.
    pub fn ton_json(&self) -> Value {
        let (cell, signers) = self.qc.split_at(self.qc.len().saturating_sub(4));
        let signers = signers
            .iter()
            .fold(0_u64, |value, byte| value << 8 | u64::from(*byte));
        let (head, tail) = self.header.split_at(X_HEAD_LEN.min(self.header.len()));
        obj([
            ("signature", hx(&self.signature_ton)),
            ("signers", num(signers)),
            ("qc_fixed_cell", hx(cell)),
            ("x_head", hx(head)),
            ("x_tail", hx(tail)),
        ])
    }
}

/// The inputs of [`TairaSim::certify`] beyond the header and the committee. The default
/// signs a genuine certificate with the lowest `q` canonical indices.
#[derive(Clone, Debug, Default)]
pub struct CertifyOptions {
    /// The canonical indices that sign; the lowest `q` when absent.
    pub signer_indices: Option<Vec<usize>>,
    /// Extra bytes of the synthetic result body: another `D_body` for the same `X`.
    pub body_tag: Vec<u8>,
    /// `qc.epoch`, instead of `height / 100`.
    pub epoch: Option<u64>,
    /// `qc.epoch_context`, instead of the synthetic one.
    pub epoch_context: Option<[u8; 32]>,
    /// `qc.view`, instead of 0.
    pub view: Option<u64>,
    /// `qc.block_hash`, instead of the synthetic one.
    pub block_hash: Option<[u8; 32]>,
    /// `qc.result_body`, instead of the synthetic one.
    pub result_body: Option<[u8; 32]>,
    /// The kind byte of the signed preimage, instead of `0x03` (Commit).
    pub kind: Option<u8>,
    /// The tag the signature is made under, instead of `DST_SIG`.
    pub dst: Option<Vec<u8>>,
    /// The height the signed preimage names, instead of `X.height`.
    pub signed_height: Option<u64>,
    /// The instance the signed preimage names, instead of the simulator's.
    pub signed_instance: Option<[u8; 32]>,
    /// The header whose `R` is signed, instead of the one the wire carries.
    pub signed_header: Option<Vec<u8>>,
    /// The keys that sign, instead of those `signer_indices` names.
    pub signing_keys: Option<Vec<[u8; KEY_LEN]>>,
    /// The `signers` field as encoded, instead of the bitset of `signer_indices`.
    pub signers_field: Option<u32>,
}

/// Sign a certificate of `header` with `committee`.
///
/// `fields` gives the `QC_FIXED` fields other than `signers`. The aggregate is the sum of the
/// signers' consensus signatures, which is `(Σ sk_i) · hash_to_G2(m, dst)`; both are computed
/// and compared. `signerYs` always follows the `signers` field actually encoded, as a relayer
/// that misreads the bitmap would build it.
///
/// # Panics
/// When `header` is shorter than its height field, when a signer index is outside the
/// committee, or when the two signing paths disagree.
pub fn build_certificate(
    committee: &Committee,
    header: &[u8],
    instance: &[u8; 32],
    fields: &QcFixedV1,
    options: &CertifyOptions,
) -> Certificate {
    let keys = committee.keys();
    let n = keys.len();
    let mut signer_indices = options
        .signer_indices
        .clone()
        .unwrap_or_else(|| (0..committee.quorum()).collect());
    let named = signers_from_indices(&signer_indices);
    let signers = options.signers_field.unwrap_or(named);
    let qc = QcFixedV1 { signers, ..*fields };

    let signed_header = options.signed_header.as_deref().unwrap_or(header);
    let height = options.signed_height.unwrap_or_else(|| {
        let mut height = [0_u8; 8];
        height.copy_from_slice(&signed_header[X_OFFSET_HEIGHT..X_OFFSET_HEIGHT + 8]);
        u64::from_be_bytes(height)
    });
    // `R = SHA-256(RESULT_TAG ‖ X ‖ D_body)` over the bytes as they are: a dirty `X` has no
    // `R` for a reader, but a Byzantine committee can still sign this value.
    let result: [u8; 32] = Sha256::new()
        .chain_update(RESULT_TAG)
        .chain_update(signed_header)
        .chain_update(qc.result_body)
        .finalize()
        .into();
    if let Ok(parsed) = SccpFinalityHeaderV1::parse(signed_header) {
        assert_eq!(outer_result(&parsed, &qc.result_body).0, result);
    }
    let kind = options.kind.unwrap_or(KIND_COMMIT);
    let mut preimage = commit_preimage(
        options.signed_instance.as_ref().unwrap_or(instance),
        &qc,
        height,
        &result,
    );
    preimage[TAG_SIG.len()] = kind;
    let message = commit_message(&preimage);

    let signer_set: Vec<&TestKey> = options.signing_keys.as_ref().map_or_else(
        || {
            signer_indices
                .iter()
                .map(|index| committee.members()[*index])
                .collect()
        },
        |signing_keys| {
            signing_keys
                .iter()
                .map(|key| committee.member_of(key))
                .collect()
        },
    );
    let dst = options.dst.as_deref().unwrap_or(DST_SIG);
    let mut sigma = sign_under_dst(&signer_set, &message, dst);
    if dst == DST_SIG {
        let aggregate = sign_consensus(&signer_set, &preimage);
        assert_eq!(
            aggregate, sigma,
            "the consensus aggregate is (Σ sk) · hash_to_G2(m, DST_SIG)"
        );
        sigma = aggregate;
    }

    signer_indices.sort_unstable();
    let in_range = signers & (u32::MAX >> (32 - n));
    Certificate {
        qc: qc.encode().to_vec(),
        header: header.to_vec(),
        signature_evm: g2_evm192(&sigma).to_vec(),
        signature_ton: sigma.to_vec(),
        committee: keys.concat(),
        signer_ys: signer_ys(&keys, in_range).expect("the committee keys are points"),
        meta: CertificateMeta {
            n,
            bitmap: bitmap_from_signers(named, n).expect("the signer indices are below n"),
            apk: aggregate_public_key(&keys, named).expect("valid keys with a nonzero sum"),
            signer_indices,
            signers,
            qc,
            result,
            preimage,
            message,
            kind,
            dst: dst.to_vec(),
            hash_point: hash_to_g2(&message, dst),
            sigma,
        },
    }
}

// ---------------------------------------------------------------------------------------------
// The simulator
// ---------------------------------------------------------------------------------------------

/// One committee generation of the simulated chain.
#[derive(Clone, Debug)]
pub struct Generation {
    /// The generation number `g`.
    pub number: u64,
    /// Its committee.
    pub committee: Committee,
    /// Its first height.
    pub start_height: u64,
    /// The time its tenure counts from: the time of the handoff that installed it.
    pub start_timestamp_ms: u64,
    /// The validity it was granted, and grants its successor by default.
    pub validity_ms: u64,
}

impl Generation {
    /// `deadline_ms = start_timestamp_ms + validity_ms`.
    pub fn deadline_ms(&self) -> u64 {
        self.start_timestamp_ms + self.validity_ms
    }
}

/// What a block leaf is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeafKind {
    /// A transfer payload.
    Transfer,
    /// A control.
    Control,
}

/// One SCCP message of a block: a transfer payload or a control.
#[derive(Clone, Debug)]
pub struct LeafItem {
    /// Which of the two.
    pub kind: LeafKind,
    /// The leaf hash.
    pub leaf: [u8; 32],
    /// The payload of a transfer.
    pub payload: Vec<u8>,
    /// The outbound nonce of a transfer.
    pub nonce: u64,
    /// The fields of a control.
    pub control: ControlLeafV1,
}

/// How a block hands over to the next generation.
#[derive(Clone, Debug)]
pub enum Rotate {
    /// A key change: the successor committee.
    Key(Committee),
    /// A heartbeat: the same committee again.
    Heartbeat,
}

/// One block of the simulated chain.
#[derive(Clone, Debug)]
pub struct Block {
    /// The block height.
    pub height: u64,
    /// The block time.
    pub timestamp_ms: u64,
    /// The fields of `X_h`.
    pub header: SccpFinalityHeaderFieldsV1,
    /// The generation that certifies the block.
    pub generation: Generation,
    /// The block's SCCP leaves.
    pub leaves: Vec<LeafItem>,
    /// The index of the block's history leaf, when it has leaves.
    pub history_index: Option<u64>,
}

impl Block {
    /// The 221 bytes of `X_h`.
    pub fn x(&self) -> Vec<u8> {
        self.header.to_bytes().to_vec()
    }
}

/// Produces headers, certificates and proofs for one destination route.
#[derive(Clone, Debug)]
pub struct TairaSim {
    /// Taira's `NetworkId`.
    pub network_id: [u8; 32],
    /// The consensus instance `I`.
    pub instance: [u8; 32],
    /// The profile of the destination chain.
    pub target: SccpNetworkV1,
    /// The destination word of the route.
    pub destination_word: [u8; 32],
    /// The route revision.
    pub route_revision: u32,
    /// Every generation started so far.
    pub generations: BTreeMap<u64, Generation>,
    /// The generation that certifies the next block.
    pub current: Option<Generation>,
    /// The history leaves of the SCCP-bearing blocks, in block order.
    pub history: Vec<[u8; 32]>,
    /// Every block produced so far.
    pub blocks: BTreeMap<u64, Block>,
}

impl TairaSim {
    /// A simulator for route revision 1 of `target` at `destination_word`.
    pub fn new(
        network_id: [u8; 32],
        instance: [u8; 32],
        target: SccpNetworkV1,
        destination_word: [u8; 32],
    ) -> Self {
        Self {
            network_id,
            instance,
            target,
            destination_word,
            route_revision: 1,
            generations: BTreeMap::new(),
            current: None,
            history: Vec::new(),
            blocks: BTreeMap::new(),
        }
    }

    /// Start `generation` with `committee` at `start_height`.
    pub fn start(
        &mut self,
        generation: u64,
        committee: Committee,
        start_height: u64,
        start_timestamp_ms: u64,
        validity_ms: u64,
    ) -> Generation {
        let started = Generation {
            number: generation,
            committee,
            start_height,
            start_timestamp_ms,
            validity_ms,
        };
        self.generations.insert(generation, started.clone());
        self.current = Some(started.clone());
        started
    }

    // -- leaves --------------------------------------------------------------------------------

    /// A transfer leaf from [`DEFAULT_SENDER`].
    ///
    /// # Panics
    /// When the payload violates `specs/sccp.md` §3.2.
    pub fn transfer(
        &self,
        nonce: u64,
        amount: u128,
        deadline_ms: u64,
        recipient: &[u8],
    ) -> LeafItem {
        self.transfer_from(nonce, amount, deadline_ms, recipient, &DEFAULT_SENDER)
    }

    /// A transfer leaf from `sender`.
    ///
    /// # Panics
    /// When the payload violates `specs/sccp.md` §3.2.
    pub fn transfer_from(
        &self,
        nonce: u64,
        amount: u128,
        deadline_ms: u64,
        recipient: &[u8],
        sender: &[u8],
    ) -> LeafItem {
        let payload = SccpTransferPayloadV1::outbound(
            self.target,
            nonce,
            self.route_revision,
            deadline_ms,
            amount,
            sender.to_vec(),
            recipient.to_vec(),
        )
        .and_then(|payload| payload.encode())
        .expect("a valid outbound payload");
        let lane = lane_bytes(SccpNetworkV1::SoraTaira, self.target, &self.network_id)
            .expect("the target is an external profile");
        let message = message_id(&lane, &payload_hash(&payload));
        LeafItem {
            kind: LeafKind::Transfer,
            leaf: transfer_leaf(&message, &self.destination_word),
            payload,
            nonce,
            control: ControlLeafV1::default(),
        }
    }

    /// A control leaf of the simulator's route. With `check`, Taira's recording rules are
    /// enforced; without it the leaf is hashed whatever the fields are.
    ///
    /// # Panics
    /// With `check`, when Taira would not record the control; always when the target is
    /// Taira itself.
    pub fn control(&self, fields: &ControlLeafV1, check: bool) -> LeafItem {
        let fields = ControlLeafV1 {
            route_revision: self.route_revision,
            ..*fields
        };
        let hash = if check {
            control_leaf
        } else {
            control_leaf_unchecked
        };
        LeafItem {
            kind: LeafKind::Control,
            leaf: hash(
                &self.network_id,
                self.target,
                &self.destination_word,
                &fields,
            )
            .unwrap_or_else(|error| panic!("control leaf: {}", error.name())),
            payload: Vec::new(),
            nonce: 0,
            control: fields,
        }
    }

    // -- blocks --------------------------------------------------------------------------------

    /// Produce `X_h` with `leaves`. A rotation grants the successor `validity_ms`, or the
    /// current generation's validity when absent, and starts the next generation at
    /// `height + 1`.
    ///
    /// Controls precede transfers, as the block-start pass runs before the block's
    /// transactions (§4.5).
    ///
    /// # Panics
    /// Before [`Self::start`], or when a control follows a transfer.
    pub fn block(
        &mut self,
        height: u64,
        timestamp_ms: u64,
        leaves: Vec<LeafItem>,
        rotate: Option<Rotate>,
        validity_ms: Option<u64>,
    ) -> Block {
        let generation = self.current.clone().expect("a started generation");
        let first_transfer = leaves
            .iter()
            .position(|item| item.kind == LeafKind::Transfer)
            .unwrap_or(leaves.len());
        assert!(
            leaves[first_transfer..]
                .iter()
                .all(|item| item.kind == LeafKind::Transfer),
            "control leaves precede transfer leaves in a block"
        );
        let mut header = SccpFinalityHeaderFieldsV1 {
            network_id: self.network_id,
            height,
            timestamp_ms,
            flags: FLAG_ACTIVE,
            generation: generation.number,
            committee_root: generation.committee.root(),
            ..SccpFinalityHeaderFieldsV1::default()
        };
        let mut history_index = None;
        if !leaves.is_empty() {
            let hashes: Vec<[u8; 32]> = leaves.iter().map(|item| item.leaf).collect();
            header.message_count = u32::try_from(leaves.len()).expect("a block's leaf count");
            header.sccp_root = PromoteOddTree::new(&hashes).expect("leaves").root();
            history_index = Some(self.history.len() as u64);
            self.history.push(history_leaf(
                height,
                &header.sccp_root,
                header.message_count,
            ));
        }
        header.history_size = self.history.len() as u64;
        header.history_root = history_root(&self.history).expect("a history below 2^32 leaves");
        let successor = rotate.map(|rotate| match rotate {
            Rotate::Key(committee) => committee,
            Rotate::Heartbeat => generation.committee.clone(),
        });
        if let Some(successor) = &successor {
            header.flags |= FLAG_ROTATION;
            header.validity_ms = validity_ms.unwrap_or(generation.validity_ms);
            header.next_committee_root = successor.root();
        }
        let block = Block {
            height,
            timestamp_ms,
            header,
            generation: generation.clone(),
            leaves,
            history_index,
        };
        self.blocks.insert(height, block.clone());
        if let Some(successor) = successor {
            self.start(
                generation.number + 1,
                successor,
                height + 1,
                timestamp_ms,
                header.validity_ms,
            );
        }
        block
    }

    // -- certificates --------------------------------------------------------------------------

    /// The deterministic `QC_FIXED` inputs that destinations take unverified, with no signer:
    ///
    /// ```text
    /// epoch         = height / 100
    /// epoch_context = H_iroha("sccp-reference/epoch-context" ‖ be64(epoch))
    /// view          = 0
    /// block_hash    = H_iroha("sccp-reference/block" ‖ be64(height) ‖ X)
    /// result_body   = D_body of "sccp-reference/result-body" ‖ be64(height) ‖ body_tag
    /// ```
    pub fn qc_fields(height: u64, header: &[u8], body_tag: &[u8]) -> QcFixedV1 {
        let epoch = height / 100;
        let body = [
            &b"sccp-reference/result-body"[..],
            &height.to_be_bytes(),
            body_tag,
        ]
        .concat();
        QcFixedV1 {
            epoch,
            epoch_context: Hash::new_from_chunks(&[
                b"sccp-reference/epoch-context",
                &epoch.to_be_bytes(),
            ])
            .into(),
            view: 0,
            block_hash: Hash::new_from_chunks(&[
                b"sccp-reference/block",
                &height.to_be_bytes(),
                header,
            ])
            .into(),
            result_body: body_digest(&body),
            signers: 0,
        }
    }

    /// Sign the 221 bytes `header` with `committee`: the lowest `q` canonical indices, or what
    /// `options` says.
    pub fn certify(
        &self,
        header: &[u8],
        committee: &Committee,
        options: &CertifyOptions,
    ) -> Certificate {
        let mut height = [0_u8; 8];
        height.copy_from_slice(&header[X_OFFSET_HEIGHT..X_OFFSET_HEIGHT + 8]);
        let mut fields = Self::qc_fields(u64::from_be_bytes(height), header, &options.body_tag);
        fields.epoch = options.epoch.unwrap_or(fields.epoch);
        fields.epoch_context = options.epoch_context.unwrap_or(fields.epoch_context);
        fields.view = options.view.unwrap_or(fields.view);
        fields.block_hash = options.block_hash.unwrap_or(fields.block_hash);
        fields.result_body = options.result_body.unwrap_or(fields.result_body);
        build_certificate(committee, header, &self.instance, &fields, options)
    }

    // -- proofs --------------------------------------------------------------------------------

    /// The reference to block `target_height` under the certified header `certified`.
    ///
    /// # Panics
    /// When the block is unknown, or is an older block without leaves.
    pub fn block_ref(
        &self,
        target_height: u64,
        certified: &SccpFinalityHeaderFieldsV1,
    ) -> BlockRefV1 {
        let block = &self.blocks[&target_height];
        let mut reference = BlockRefV1 {
            height: target_height,
            sccp_root: block.header.sccp_root,
            message_count: block.header.message_count,
            history_index: 0,
            history_path: Vec::new(),
        };
        if target_height != certified.height {
            let size = usize::try_from(certified.history_size).expect("a history size");
            reference.history_index = block.history_index.expect("an SCCP-bearing block");
            reference.history_path = history_path(&self.history[..size], reference.history_index)
                .expect("the block is in the certified history");
        }
        reference
    }

    fn leaf_path(&self, target_height: u64, leaf_index: u32) -> Vec<[u8; 32]> {
        let hashes: Vec<[u8; 32]> = self.blocks[&target_height]
            .leaves
            .iter()
            .map(|item| item.leaf)
            .collect();
        PromoteOddTree::new(&hashes)
            .and_then(|tree| tree.path(leaf_index as usize))
            .expect("a leaf of the block")
    }

    /// The proof of the transfer at `leaf_index` of block `target_height` under `certified`.
    ///
    /// # Panics
    /// When the leaf is not a transfer.
    pub fn message_proof(
        &self,
        target_height: u64,
        leaf_index: u32,
        certified: &SccpFinalityHeaderFieldsV1,
    ) -> MessageProofV1 {
        let item = &self.blocks[&target_height].leaves[leaf_index as usize];
        assert_eq!(item.kind, LeafKind::Transfer);
        MessageProofV1 {
            payload: item.payload.clone(),
            leaf_index,
            path: self.leaf_path(target_height, leaf_index),
            block: self.block_ref(target_height, certified),
        }
    }

    /// The proof of the control at `leaf_index` of block `target_height` under `certified`.
    ///
    /// # Panics
    /// When the leaf is not a control.
    pub fn control_proof(
        &self,
        target_height: u64,
        leaf_index: u32,
        certified: &SccpFinalityHeaderFieldsV1,
    ) -> ControlProofV1 {
        let item = &self.blocks[&target_height].leaves[leaf_index as usize];
        assert_eq!(item.kind, LeafKind::Control);
        ControlProofV1 {
            control_nonce: item.control.control_nonce,
            track: item.control.track,
            parliament_paused: item.control.parliament_paused,
            fast_pause_until_ms: item.control.fast_pause_until_ms,
            certificate_id: item.control.certificate_id,
            effect_hash: item.control.effect_hash,
            leaf_index,
            path: self.leaf_path(target_height, leaf_index),
            block: self.block_ref(target_height, certified),
        }
    }
}
