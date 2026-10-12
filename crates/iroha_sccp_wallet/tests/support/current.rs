//! Genuine current-suite certificate fixtures shared by wallet unit and integration controls.
use iroha_crypto::{
    Algorithm, KeyPair, PrivateKey,
    bls::consensus::{aggregate, sign_preimage},
};
use iroha_data_model::bridge::SccpNetworkV1;
use iroha_sccp::{
    api::{
        SccpBlockRefV1, SccpCertificateV1, SccpControlProofBundleV1, SccpMessageProofBundleV1,
        SccpRotationV1,
    },
    v1::{
        committee::{CommitteeStateV1, committee_root},
        control::{ControlLeafV1, control_leaf},
        finality::{
            FLAG_ACTIVE, FLAG_ROTATION, QcFixedV1, SccpFinalityHeaderFieldsV1,
            SccpFinalityHeaderV1, commit_preimage, outer_result,
        },
        hashes::{transfer_leaf, word_address},
        history::{history_path, history_root},
        merkle::PromoteOddTree,
        payload::SccpTransferPayloadV1,
        proof::DestinationV1,
    },
};
use std::collections::BTreeMap;
/// Selected Taira network.
pub const NETWORK: [u8; 32] = [0x11; 32];
/// Selected original consensus instance.
pub const INSTANCE: [u8; 32] = [0x77; 32];
/// Original generation start time.
pub const T0: u64 = 1_800_000_000_000;
/// Test destination clock.
pub const NOW: u64 = T0 + 1_000;
/// Fourteen-day trust interval.
pub const VALIDITY: u64 = 1_209_600_000;
/// Fixture owns all original signing keys and selected destination checkpoint observations.
pub struct Fixture {
    /// Original canonical committee keys.
    pub keys: Vec<[u8; 48]>,
    secrets: Vec<PrivateKey>,
    /// Immutable target identity.
    pub destination: DestinationV1,
    /// Independently selected current committee.
    pub state: CommitteeStateV1,
    /// Checkpoint observations of the destination.
    pub checkpoints: BTreeMap<u64, [u8; 32]>,
}
impl Default for Fixture {
    fn default() -> Self {
        Self::new()
    }
}
impl Fixture {
    /// Deterministic canonical four-validator fixture with actual consensus signatures.
    pub fn new() -> Self {
        Self::with_tag(0)
    }
    /// A distinct canonical committee, for authenticated handoff and substitution tests.
    pub fn with_tag(tag: u8) -> Self {
        let mut pairs: Vec<_> = (0..4)
            .map(|index| {
                let pair =
                    KeyPair::from_seed(vec![b'w', b'a', b'l', tag, index], Algorithm::BlsNormal);
                let bytes = pair.public_key().to_bytes().1;
                (
                    <[u8; 48]>::try_from(bytes).unwrap(),
                    pair.private_key().clone(),
                )
            })
            .collect();
        pairs.sort_by_key(|(key, _)| *key);
        let (keys, secrets): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
        let root = committee_root(&keys).unwrap();
        Self {
            keys,
            secrets,
            destination: DestinationV1 {
                network: SccpNetworkV1::BscMainnet,
                route_revision: 2,
                destination_word: word_address(&[0x22; 20]),
            },
            state: CommitteeStateV1::from_pin(1, root, 1, T0 + VALIDITY).unwrap(),
            checkpoints: BTreeMap::new(),
        }
    }
    /// Valid active header fields under this original committee.
    pub fn fields(&self, height: u64) -> SccpFinalityHeaderFieldsV1 {
        SccpFinalityHeaderFieldsV1 {
            network_id: NETWORK,
            height,
            timestamp_ms: T0 + height,
            flags: FLAG_ACTIVE,
            message_count: 0,
            sccp_root: [0; 32],
            history_size: 0,
            history_root: [0; 32],
            generation: 1,
            committee_root: committee_root(&self.keys).unwrap(),
            validity_ms: 0,
            next_committee_root: [0; 32],
        }
    }
    /// Sign exactly the lowest three canonical seats using the consensus suite.
    pub fn certify(&self, fields: SccpFinalityHeaderFieldsV1) -> SccpCertificateV1 {
        let header = SccpFinalityHeaderV1::from_fields(&fields).unwrap();
        let qc = QcFixedV1 {
            epoch: 1,
            epoch_context: [0x88; 32],
            view: 0,
            block_hash: [0x99; 32],
            result_body: [0x66; 32],
            signers: 7,
        };
        let result = outer_result(&header, &qc.result_body).0;
        let preimage = commit_preimage(&INSTANCE, &qc, header.height(), &result);
        let shares: Vec<_> = self.secrets[..3]
            .iter()
            .map(|key| sign_preimage(key, &preimage).unwrap())
            .collect();
        SccpCertificateV1 {
            height: header.height(),
            qc: qc.encode(),
            aggregate_signature: aggregate(shares).unwrap(),
            header: *header.as_bytes(),
            committee: self.keys.clone(),
        }
    }
    /// Direct proof of one original outbound payload at height 9.
    pub fn message(&self) -> SccpMessageProofBundleV1 {
        let payload = SccpTransferPayloadV1::outbound(
            self.destination.network,
            1,
            self.destination.route_revision,
            T0 + 86_400_000,
            1_000,
            vec![1, 2, 3],
            vec![0x33; 20],
        )
        .unwrap();
        let message_id = payload.message_id(&NETWORK).unwrap();
        let leaf = transfer_leaf(&message_id, &self.destination.destination_word);
        let tree = PromoteOddTree::block(&[[5; 32], leaf]).unwrap();
        let block = SccpBlockRefV1 {
            height: 9,
            sccp_root: tree.root(),
            message_count: 2,
            history_index: 0,
            history_path: vec![],
        };
        let mut fields = self.fields(9);
        fields.message_count = 2;
        fields.sccp_root = tree.root();
        SccpMessageProofBundleV1 {
            message_id,
            payload: payload.encode().unwrap(),
            deadline_ms: payload.deadline_ms,
            leaf_index: 1,
            path: tree.path(1).unwrap(),
            block,
            certificate: self.certify(fields),
        }
    }
    /// Proof of a current Parliament control with a real cause, at height 9.
    pub fn control(&self) -> SccpControlProofBundleV1 {
        let fields = ControlLeafV1 {
            route_revision: self.destination.route_revision,
            control_nonce: 4,
            track: 1,
            parliament_paused: 1,
            fast_pause_until_ms: 0,
            certificate_id: [7; 32],
            effect_hash: [8; 32],
        };
        let leaf = control_leaf(
            &NETWORK,
            self.destination.network,
            &self.destination.destination_word,
            &fields,
        )
        .unwrap();
        let tree = PromoteOddTree::block(&[[5; 32], leaf]).unwrap();
        let mut header = self.fields(9);
        header.message_count = 2;
        header.sccp_root = tree.root();
        SccpControlProofBundleV1 {
            network: self.destination.network,
            revision: self.destination.route_revision,
            control_nonce: 4,
            track: fields.track,
            parliament_paused: true,
            fast_pause_until_ms: fields.fast_pause_until_ms,
            certificate_id: fields.certificate_id,
            effect_hash: fields.effect_hash,
            leaf_index: 1,
            path: tree.path(1).unwrap(),
            block: SccpBlockRefV1 {
                height: 9,
                sccp_root: tree.root(),
                message_count: 2,
                history_index: 0,
                history_path: vec![],
            },
            certificate: self.certify(header),
        }
    }
    /// Move a genuine message under a later certified history root without altering its original leaf.
    pub fn historical_message(&self) -> SccpMessageProofBundleV1 {
        let mut bundle = self.message();
        let leaves = [
            iroha_sccp::v1::hashes::history_leaf(3, &[3; 32], 1),
            iroha_sccp::v1::hashes::history_leaf(
                bundle.block.height,
                &bundle.block.sccp_root,
                bundle.block.message_count,
            ),
        ];
        bundle.block.history_index = 1;
        bundle.block.history_path = history_path(&leaves, 1).unwrap();
        let mut fields = self.fields(20);
        fields.history_size = 2;
        fields.history_root = history_root(&leaves).unwrap();
        bundle.certificate = self.certify(fields);
        bundle
    }
    /// Authenticated handoff or heartbeat signed by this committee.
    pub fn rotation(&self, generation: u64, height: u64, next: &Fixture) -> SccpRotationV1 {
        let mut fields = self.fields(height);
        fields.generation = generation;
        fields.flags |= FLAG_ROTATION;
        fields.validity_ms = VALIDITY;
        fields.next_committee_root = committee_root(&next.keys).unwrap();
        SccpRotationV1 {
            certificate: self.certify(fields),
            next_committee: next.keys.clone(),
        }
    }
}
