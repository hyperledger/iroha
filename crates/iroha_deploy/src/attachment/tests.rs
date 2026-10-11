//! Genuine certificate/inclusion and native custody checks over synthetic execution fixtures.
//! These tests do not execute parent business rules or qualify a running private network.

use super::*;
use crate::bootstrap::{
    NetworkRelease, ReleaseCheckpointStore, ReleaseTrust, SignedNetworkCheckpoint,
};
use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::{
    block::consensus::{ExecKv, ExecWitness},
    private_dataspace::{PrivateDataspaceAnchorState, PrivateDataspaceRecord},
    sumeragi_finality::{
        SUMERAGI_LANE_STATE_WITNESS_KEY, SumeragiLaneStateCommitment, authenticated_genesis,
        test_fixtures::NativeFinalityFixture,
    },
    sumeragi_lanes::SumeragiLaneState,
};

pub(super) struct Fixture {
    pub(super) parent: NativeFinalityFixture,
    pub(super) child: NativeFinalityFixture,
    pub(super) identity: AttachmentIdentity,
    record: PrivateDataspaceRecord,
}

impl Fixture {
    pub(super) fn new() -> Self {
        let parent = NativeFinalityFixture::start("attachment-parent");
        let dataspace_id = DataSpaceId::from_hash(
            &NameSelectorV1::new(DATASPACE_ALIAS_SUFFIX_ID, "acme")
                .unwrap()
                .name_hash(),
        );
        let scope = SumeragiRootScope::Dataspace {
            parent_network_id: parent.network_id(),
            dataspace_id,
        };
        let child = NativeFinalityFixture::start_with_scope("attachment-child", scope);
        let genesis_result = child
            .verifier()
            .verify_retained_decision(child.genesis_proof())
            .unwrap()
            .result()
            .0;
        let registration = PrivateDataspaceRegistration::new(
            scope,
            child.chain_id().parse().unwrap(),
            child.network_id(),
            genesis_result,
            authenticated_genesis(child.genesis())
                .map(|genesis| genesis.into_parts().0)
                .unwrap(),
        )
        .unwrap();
        let owner = AccountId::new(
            KeyPair::from_seed(vec![47; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let identity = AttachmentIdentity {
            parent_name: "fixture".into(),
            parent_generation: 1,
            parent_network_id: parent.network_id(),
            parent_chain_id: parent.chain_id().into(),
            alias: "acme".into(),
            owner: owner.clone(),
            ownership_generation: 7,
            registration: registration.clone(),
        };
        let record = PrivateDataspaceRecord {
            dataspace_id,
            alias: "acme".into(),
            owner,
            ownership_generation: 7,
            anchor: PrivateDataspaceAnchorState::from_authorized_registration(registration)
                .unwrap(),
        };
        Self {
            parent,
            child,
            identity,
            record,
        }
    }

    pub(super) fn child_anchor(&mut self) -> PrivateDataspaceAnchor {
        let block = self
            .child
            .block_with_submitted_work(self.child.next_header());
        let proof = self.child.certify(block);
        let verified = self
            .child
            .verifier()
            .verify_retained_decision(&proof)
            .unwrap();
        PrivateDataspaceAnchor::from_certificate(
            &self.identity.registration,
            verified.block().commit_certificate().unwrap(),
        )
        .unwrap()
    }

    pub(super) fn parent_receipt(&mut self) -> (PrivateDataspaceRecordProof, FinalityVerifier) {
        self.parent_receipt_with_delay(0)
    }

    fn parent_receipt_with_delay(
        &mut self,
        delay: u64,
    ) -> (PrivateDataspaceRecordProof, FinalityVerifier) {
        let height = self.parent.next_header().height().get();
        let lanes = SumeragiLaneStateCommitment::from_state(
            self.parent.network_id(),
            height,
            &SumeragiLaneState::default(),
        )
        .unwrap();
        let writes = vec![
            ExecKv {
                key: SUMERAGI_LANE_STATE_WITNESS_KEY.to_vec(),
                value: norito::encode_canonical(&lanes).unwrap(),
            },
            ExecKv {
                key: self.record.witness_key(),
                value: norito::encode_canonical(&self.record).unwrap(),
            },
        ];
        let mut header = self.parent.next_header();
        header.creation_time_ms += delay;
        let block = self.parent.block_with_submitted_work(header);
        let proof = self.parent.certify_with_witness(
            block,
            &ExecWitness {
                writes: writes.clone(),
                ..ExecWitness::default()
            },
        );
        let verified = self
            .parent
            .verifier()
            .verify_retained_decision(&proof)
            .unwrap();
        let receipt = PrivateDataspaceRecordProof::from_writes(
            self.parent.network_id(),
            height,
            verified.result().0,
            writes
                .iter()
                .map(|w| (w.key.as_slice(), w.value.as_slice())),
            self.record.clone(),
        )
        .unwrap();
        let verifier = FinalityVerifier::from_checkpoint(
            self.parent.checkpoint(),
            self.parent.network_id(),
            self.parent.chain_id(),
        )
        .unwrap();
        (receipt, verifier)
    }

    pub(super) fn bootstrap(&self, path: &Path) -> AuthenticatedBootstrap {
        let checkpoint = self.parent.checkpoint();
        let key = KeyPair::from_seed(vec![49; 32], Algorithm::Ed25519);
        let release = NetworkRelease {
            network_name: "fixture".into(),
            serial: 1,
            generation: 1,
            network_id: checkpoint.network_id(),
            chain_id: checkpoint.chain_id().into(),
            issued_at_ms: 1_000,
            expires_at_ms: 10_000,
            torii_roots: vec!["https://parent.example/".into()],
            account_chain_discriminant: 753,
            native_world_schema: Hash::new(b"independently qualified fixture World schema"),
            peers: checkpoint
                .tip()
                .committee
                .iter()
                .map(|validator| crate::bootstrap::ReleasePeer {
                    node_id: iroha_model_base::peer::PeerId::new(validator.public_key.clone()),
                    torii_root: "https://parent.example/".into(),
                })
                .collect(),
            faucet: None,
            build_registry: None,
            checkpoint_hash: Hash::new(checkpoint.encode_canonical().unwrap()),
            checkpoint_height: checkpoint.height(),
            checkpoint_block_hash: checkpoint.block_hash().into(),
        };
        let bytes = SignedNetworkCheckpoint::sign(release, &checkpoint, key.private_key())
            .unwrap()
            .encode_canonical()
            .unwrap();
        let trust = ReleaseTrust::new("fixture".into(), key.public_key().clone(), 1).unwrap();
        ReleaseCheckpointStore::open(path)
            .unwrap()
            .authenticate(&trust, &bytes, 2_000)
            .unwrap()
    }
}

#[test]
fn parent_receipt_is_required_and_retained_across_private_progress_and_restart() {
    let mut fixture = Fixture::new();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("attachment");
    let mut store = AttachmentStore::open(&path, fixture.identity.clone()).unwrap();
    assert_eq!(store.identity(), &fixture.identity);
    assert_eq!(
        store.identity().registration(),
        &fixture.identity.registration
    );
    assert_eq!(store.confirmed(), None);
    let instruction = store.registration_instruction().unwrap();
    assert_eq!(instruction.alias, "acme");
    assert_eq!(instruction.expected_ownership_generation, 7);
    assert_eq!(
        PrivateDataspaceRegistration::decode(&instruction.registration).unwrap(),
        fixture.identity.registration
    );
    let anchor = fixture.child_anchor();
    assert!(store.anchor_instruction(&anchor).is_err());
    let (receipt, _) = fixture.parent_receipt();
    let bootstrap = fixture.bootstrap(&dir.path().join("release"));
    let identity = AttachmentIdentity::new(
        &bootstrap,
        "acme".into(),
        fixture.identity.owner.clone(),
        7,
        fixture.identity.registration.clone(),
    )
    .unwrap();
    assert_eq!(identity, fixture.identity);
    let parent = ParentFinalityStore::open(&dir.path().join("parent"), &bootstrap).unwrap();
    let initial = store.confirm_record(receipt, &parent).unwrap();
    assert_eq!(initial.child.height, 1);
    assert_eq!(parent.network_name(), "fixture");
    assert_eq!(parent.generation(), 1);
    assert_eq!(
        store.confirmed_child_state().unwrap().cursor(),
        initial.child
    );
    assert!(store.registration_instruction().is_err());
    let prepared = store.anchor_instruction(&anchor).unwrap().unwrap();
    assert_eq!(
        PrivateDataspaceAnchor::decode(&prepared.anchor).unwrap(),
        anchor
    );
    assert_eq!(prepared.dataspace_id, fixture.identity.dataspace_id());
    assert_eq!(store.confirmed(), Some(initial)); // local certificate is not parent inclusion
    fixture.record.anchor.apply(&anchor).unwrap();
    let (receipt, verifier) = fixture.parent_receipt();
    let confirmed = store
        .confirm_with_verifier(receipt.clone(), &verifier)
        .unwrap();
    assert_eq!(confirmed.child.height, 2);
    assert_eq!(store.anchor_instruction(&anchor).unwrap(), None);
    assert_eq!(
        store.confirm_with_verifier(receipt, &verifier).unwrap(),
        confirmed
    );
    drop(store);
    let store = AttachmentStore::open(&path, fixture.identity.clone()).unwrap();
    assert_eq!(store.confirmed(), Some(confirmed));
    assert_eq!(store.anchor_instruction(&anchor).unwrap(), None);
}

#[test]
fn foreign_forged_and_regressed_receipts_never_advance_attachment() {
    let mut fixture = Fixture::new();
    let dir = tempfile::tempdir().unwrap();
    let mut store =
        AttachmentStore::open(&dir.path().join("attachment"), fixture.identity.clone()).unwrap();
    let (receipt, verifier) = fixture.parent_receipt();
    let mut corrupt = receipt.clone();
    corrupt.record.owner = AccountId::new(
        KeyPair::from_seed(vec![48; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    assert!(store.confirm_with_verifier(corrupt, &verifier).is_err());
    let mut corrupt = receipt.clone();
    corrupt.parent_result[0] ^= 1;
    assert!(store.confirm_with_verifier(corrupt, &verifier).is_err());
    assert!(store.confirmed().is_none());
    store
        .confirm_with_verifier(receipt.clone(), &verifier)
        .unwrap();
    let mut equivocation = Fixture::new();
    let (fork, fork_verifier) = equivocation.parent_receipt_with_delay(1);
    assert_eq!(fork.record, receipt.record);
    assert!(store.confirm_with_verifier(fork, &fork_verifier).is_err());
    let skipped = fixture.child_anchor();
    let later = fixture.child_anchor();
    assert!(store.anchor_instruction(&later).is_err());
    fixture.record.anchor.apply(&skipped).unwrap();
    let (advanced, advanced_verifier) = fixture.parent_receipt();
    store
        .confirm_with_verifier(advanced, &advanced_verifier)
        .unwrap();
    let before = store.confirmed();
    assert!(store.confirm_with_verifier(receipt, &verifier).is_err());
    assert_eq!(store.confirmed(), before);
    // Even a genuinely parent-signed write cannot silently switch the selected lease generation.
    fixture.record.ownership_generation += 1;
    let (foreign, foreign_verifier) = fixture.parent_receipt();
    assert!(
        store
            .confirm_with_verifier(foreign, &foreign_verifier)
            .is_err()
    );
    assert_eq!(store.confirmed(), before);
    let mut invalid = fixture.identity.clone();
    invalid.alias = "foreign".into();
    assert!(invalid.validate().is_err());
    invalid = fixture.identity.clone();
    invalid.ownership_generation = 0;
    assert!(invalid.validate().is_err());
}

#[test]
fn custody_refuses_concurrent_missing_corrupt_and_uncertain_state() {
    let mut fixture = Fixture::new();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("attachment");
    let mut store = AttachmentStore::open(&path, fixture.identity.clone()).unwrap();
    assert!(AttachmentStore::open(&path, fixture.identity.clone()).is_err());
    let (receipt, verifier) = fixture.parent_receipt();
    // A pinned private store rejects substituted publication targets; failure poisons this owner.
    std::fs::remove_file(path.join("attachment.nrt")).unwrap();
    std::fs::create_dir(path.join("attachment.nrt")).unwrap();
    assert!(
        store
            .confirm_with_verifier(receipt.clone(), &verifier)
            .is_err()
    );
    assert!(store.confirmed().is_none());
    assert!(store.registration_instruction().is_err());
    assert!(store.confirm_with_verifier(receipt, &verifier).is_err());
    drop(store);
    assert!(AttachmentStore::open(&path, fixture.identity.clone()).is_err());

    let second = dir.path().join("missing-lock");
    drop(AttachmentStore::open(&second, fixture.identity.clone()).unwrap());
    std::fs::remove_file(second.join("lock")).unwrap();
    assert!(AttachmentStore::open(&second, fixture.identity.clone()).is_err());

    let third = dir.path().join("corrupt");
    drop(AttachmentStore::open(&third, fixture.identity.clone()).unwrap());
    PrivateDirectory::open(&third)
        .unwrap()
        .write_atomic("attachment.nrt", b"invalid", PublishMode::Replace)
        .unwrap();
    assert!(AttachmentStore::open(&third, fixture.identity.clone()).is_err());
    assert!(encode_bounded(&fixture.identity, 1).is_err());
}
