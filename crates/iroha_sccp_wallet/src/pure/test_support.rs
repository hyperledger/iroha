//! Genuine native BLS DATA fixtures shared by pure wallet tests. No fixture is a trust source.

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
        control::{ControlLeafV1, control_leaf_unchecked},
        destination::{
            CheckpointObservationsV1, DeploymentV1, DestinationFlavor, DestinationObservationV1,
            PauseStateV1,
        },
        finality::{
            FLAG_ACTIVE, FLAG_ROTATION, QcFixedV1, SccpFinalityHeaderFieldsV1,
            SccpFinalityHeaderV1, checkpoint_id, commit_preimage, outer_result,
        },
        hashes::{history_leaf, transfer_leaf, word_address},
        history::{history_path, history_root},
        merkle::PromoteOddTree,
        payload::SccpTransferPayloadV1,
    },
};
use std::collections::BTreeMap;

pub const NETWORK: [u8; 32] = [0x11; 32];
pub const INSTANCE: [u8; 32] = [0x77; 32];
pub const T0: u64 = 1_800_000_000_000;
pub const DAY: u64 = 86_400_000;
pub const NOW: u64 = T0 + 60_000;

pub struct Fixture {
    pub members: Vec<([u8; 48], PrivateKey)>,
    pub deployment: DeploymentV1,
}
impl Fixture {
    pub fn new(flavor: DestinationFlavor) -> Self {
        let mut members: Vec<_> = (0_u8..4)
            .map(|index| {
                let (public, private) =
                    KeyPair::from_seed(vec![b'w', b'a', b'l', index], Algorithm::BlsNormal)
                        .into_parts();
                let (_, bytes) = public.to_bytes();
                (<[u8; 48]>::try_from(bytes).expect("BLS key"), private)
            })
            .collect();
        members.sort_by_key(|(key, _)| *key);
        let keys: Vec<_> = members.iter().map(|(key, _)| *key).collect();
        let network = if flavor == DestinationFlavor::Evm {
            SccpNetworkV1::EthereumMainnet
        } else {
            SccpNetworkV1::TonMainnet
        };
        let deployment = DeploymentV1 {
            flavor,
            taira_network_id: NETWORK,
            consensus_instance: INSTANCE,
            network,
            destination_word: if flavor == DestinationFlavor::Evm {
                word_address(&[0x22; 20])
            } else {
                [0x22; 32]
            },
            route_revision: 1,
            max_wrapped_supply: u128::MAX,
            pin_generation: 7,
            pin_root: committee_root(&keys).expect("root"),
            pin_start_height: 100,
            pin_until_ms: T0 + 14 * DAY,
            pin_keys: Some(keys),
        };
        Self {
            members,
            deployment,
        }
    }
    pub fn fields(&self, height: u64, generation: u64) -> SccpFinalityHeaderFieldsV1 {
        SccpFinalityHeaderFieldsV1 {
            network_id: NETWORK,
            height,
            timestamp_ms: T0 + height * 1000,
            flags: FLAG_ACTIVE,
            message_count: 0,
            sccp_root: [0; 32],
            history_size: 0,
            history_root: [0; 32],
            generation,
            committee_root: self.deployment.pin_root,
            validity_ms: 0,
            next_committee_root: [0; 32],
        }
    }
    pub fn certificate(
        &self,
        fields: &SccpFinalityHeaderFieldsV1,
        signers: u32,
    ) -> SccpCertificateV1 {
        let header = SccpFinalityHeaderV1::from_fields(fields).expect("header");
        let qc = QcFixedV1 {
            epoch: 1,
            epoch_context: [0x44; 32],
            view: 2,
            block_hash: [0x55; 32],
            result_body: [0x66; 32],
            signers,
        };
        let result = outer_result(&header, &qc.result_body).0;
        let preimage = commit_preimage(
            &self.deployment.consensus_instance,
            &qc,
            header.height(),
            &result,
        );
        let shares: Vec<_> = self
            .members
            .iter()
            .enumerate()
            .filter(|(i, _)| signers & (1 << i) != 0)
            .map(|(_, (_, private))| sign_preimage(private, &preimage).expect("signature"))
            .collect();
        SccpCertificateV1 {
            height: header.height(),
            qc: qc.encode(),
            aggregate_signature: aggregate(shares).expect("aggregate"),
            header: *header.as_bytes(),
            committee: self.members.iter().map(|(key, _)| *key).collect(),
        }
    }
    pub fn observation(
        &self,
        now: u64,
        reads: BTreeMap<u64, Option<[u8; 32]>>,
    ) -> DestinationObservationV1 {
        self.observation_with(
            now,
            self.deployment.initial_committee().expect("pin"),
            reads,
            PauseStateV1 {
                parliament_paused: false,
                fast_pause_until_ms: 0,
                control_nonce: 0,
                effective: false,
            },
        )
    }
    pub fn observation_with(
        &self,
        now: u64,
        committee: CommitteeStateV1,
        reads: BTreeMap<u64, Option<[u8; 32]>>,
        pause: PauseStateV1,
    ) -> DestinationObservationV1 {
        let (keys, checkpoints) = match self.deployment.flavor {
            DestinationFlavor::Evm => (None, CheckpointObservationsV1::Evm(reads)),
            DestinationFlavor::Ton => {
                let stored: Vec<_> = reads
                    .into_iter()
                    .filter_map(|(h, id)| id.map(|id| (h, id)))
                    .collect();
                assert!(stored.len() <= 3);
                let mut slots = [None; 3];
                for (i, value) in stored.into_iter().enumerate() {
                    slots[i] = Some(value);
                }
                (
                    Some(self.members.iter().map(|(key, _)| *key).collect()),
                    CheckpointObservationsV1::Ton(slots),
                )
            }
        };
        DestinationObservationV1::new(
            self.deployment.clone(),
            committee,
            keys,
            checkpoints,
            pause,
            now,
        )
        .expect("independent observed state")
    }
    pub fn block(
        &self,
        leaf: [u8; 32],
        historical: bool,
    ) -> (SccpBlockRefV1, Vec<[u8; 32]>, SccpCertificateV1) {
        let tree = PromoteOddTree::block(&[[1; 32], leaf, [3; 32]]).expect("tree");
        let mut block = SccpBlockRefV1 {
            height: 100,
            sccp_root: tree.root(),
            message_count: 3,
            history_index: 0,
            history_path: vec![],
        };
        let mut fields = self.fields(if historical { 110 } else { 100 }, 7);
        if historical {
            let history = [history_leaf(100, &tree.root(), 3), [9; 32]];
            fields.history_size = 2;
            fields.history_root = history_root(&history).expect("history");
            block.history_path = history_path(&history, 0).expect("path");
        } else {
            fields.sccp_root = tree.root();
            fields.message_count = 3;
        }
        (
            block,
            tree.path(1).expect("path"),
            self.certificate(&fields, 0b111),
        )
    }
    pub fn message(&self, historical: bool) -> SccpMessageProofBundleV1 {
        let recipient = if self.deployment.flavor == DestinationFlavor::Evm {
            vec![0x44; 20]
        } else {
            [&[0_u8; 4][..], &[0x44; 32]].concat()
        };
        let payload = SccpTransferPayloadV1::outbound(
            self.deployment.network,
            5,
            1,
            T0 + DAY,
            1_000_000_000,
            vec![2, 1, 32, 0x33],
            recipient,
        )
        .expect("payload");
        let message_id = payload.message_id(&NETWORK).expect("id");
        let (block, path, certificate) = self.block(
            transfer_leaf(&message_id, &self.deployment.destination_word),
            historical,
        );
        SccpMessageProofBundleV1 {
            message_id,
            payload: payload.encode().expect("payload"),
            deadline_ms: payload.deadline_ms,
            leaf_index: 1,
            path,
            block,
            certificate,
        }
    }
    pub fn control(
        &self,
        historical: bool,
        parliament_paused: bool,
        until: u64,
    ) -> SccpControlProofBundleV1 {
        let fields = ControlLeafV1 {
            route_revision: 1,
            control_nonce: 4,
            track: if until == 0 { 1 } else { 2 },
            parliament_paused: u8::from(parliament_paused),
            fast_pause_until_ms: until,
            certificate_id: [0x12; 32],
            effect_hash: [0x34; 32],
        };
        let leaf = control_leaf_unchecked(
            &NETWORK,
            self.deployment.network,
            &self.deployment.destination_word,
            &fields,
        )
        .expect("control");
        let (block, path, certificate) = self.block(leaf, historical);
        SccpControlProofBundleV1 {
            network: self.deployment.network,
            revision: 1,
            control_nonce: fields.control_nonce,
            track: fields.track,
            parliament_paused,
            fast_pause_until_ms: until,
            certificate_id: fields.certificate_id,
            effect_hash: fields.effect_hash,
            leaf_index: 1,
            path,
            block,
            certificate,
        }
    }
    pub fn rotations(&self, count: u64) -> Vec<SccpRotationV1> {
        (0..count)
            .map(|i| {
                let mut fields = self.fields(150 + i, 7 + i);
                fields.flags |= FLAG_ROTATION;
                fields.validity_ms = 14 * DAY;
                fields.next_committee_root = self.deployment.pin_root;
                SccpRotationV1 {
                    certificate: self.certificate(&fields, 0b111),
                    next_committee: self.members.iter().map(|(key, _)| *key).collect(),
                }
            })
            .collect()
    }
}
pub fn reads(certificate: &SccpCertificateV1, stored: bool) -> BTreeMap<u64, Option<[u8; 32]>> {
    BTreeMap::from([(
        certificate.height,
        stored.then(|| checkpoint_id(&certificate.header)),
    )])
}
