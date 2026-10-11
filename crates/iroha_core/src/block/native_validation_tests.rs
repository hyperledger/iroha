// Native block-validation fixtures backed by actual executed, certified global history.

use super::*;
use crate::sumeragi::{
    crypto::BlsCrypto,
    lanes::merge::{NoLanes, expand},
    payload::{self, Assembly},
    test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_sumeragi::{message::BlockHeader as NativeHeader, preimage::payload_hash};

/// This fixture supplies only original transactions and a resultless proposal. Production
/// execution derives the result; no test-created historical roots or finality sidecar enter it.
struct NativeValidationFixture {
    chain: CertifiedTestChain,
    user: KeyPair,
}
impl NativeValidationFixture {
    fn new() -> Self {
        Self::with_configuration(|_| {})
    }
    fn with_configuration(configure: impl FnOnce(&mut TestChainConfig)) -> Self {
        let user = KeyPair::from_seed(vec![0x7A; 32], Algorithm::Ed25519);
        let mut config = TestChainConfig::new(World::new(), 1_000);
        config.genesis_instructions.push(
            Register::account(Account::new(AccountId::new(user.public_key().clone()))).into(),
        );
        config.world.account_permissions.insert(
            AccountId::new(user.public_key().clone()),
            BTreeSet::from([iroha_data_model::permission::Permission::from(
                iroha_executor_data_model::permission::parameter::CanSetParameters,
            )]),
        );
        configure(&mut config);
        let mut chain = CertifiedTestChain::start(config).unwrap();
        chain.commit_at(2_000, Vec::new());
        Self { chain, user }
    }
    fn transaction(&self, created_ms: u64, ttl_ms: Option<u64>) -> SignedTransaction {
        self.transaction_with_metadata(created_ms, ttl_ms, Metadata::default())
    }
    fn transaction_with_metadata(
        &self,
        created_ms: u64,
        ttl_ms: Option<u64>,
        metadata: Metadata,
    ) -> SignedTransaction {
        let mut builder = TransactionBuilder::new(
            self.chain.network_id(),
            AccountId::new(self.user.public_key().clone()),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        );
        builder.set_creation_time(Duration::from_millis(created_ms));
        if let Some(ttl_ms) = ttl_ms {
            builder.set_ttl(Duration::from_millis(ttl_ms));
        }
        builder
            .with_instructions([Log::new(Level::INFO, format!("native work {created_ms}"))])
            .with_metadata(metadata)
            .sign(self.user.private_key())
    }
    fn cadence(&self) -> Duration {
        let view = self.chain.state().view();
        Duration::from_millis(
            view.world()
                .consensus_schedule()
                .ready(self.chain.height() + 1)
                .unwrap()
                .params
                .block_time_ms,
        )
    }
    fn proposal(&self, transactions: Vec<SignedTransaction>, cadence: Duration) -> SignedBlock {
        // Deliberately no prior transaction admission: these fixtures exercise the production
        // block boundary, including invalid signatures and expiration, rather than its caller.
        let inputs = transactions
            .into_iter()
            .map(|tx| AcceptedTransaction::new_unchecked(Cow::Owned(tx)))
            .collect::<Vec<_>>();
        self.proposal_from_inputs(inputs, cadence)
    }
    fn proposal_from_inputs(
        &self,
        inputs: Vec<AcceptedTransaction<'static>>,
        cadence: Duration,
    ) -> SignedBlock {
        let parent = self.chain.committed(self.chain.height());
        payload::assemble(
            self.chain.state(),
            Assembly {
                parent: parent.block(),
                view: 0,
                cadence,
            },
            &inputs,
        )
        .unwrap()
    }
    fn header(&self, proposal: &SignedBlock) -> (NativeHeader, Vec<u8>) {
        let bytes = proposal.encode_wire().unwrap();
        let parent = self.chain.committed(self.chain.height());
        let view = self.chain.state().view();
        let scheduled = view
            .world()
            .consensus_schedule()
            .ready(self.chain.height() + 1)
            .unwrap();
        let header = NativeHeader {
            control_witness: Default::default(),
            instance: self.chain.instance(),
            epoch: crate::sumeragi::schedule::core_epoch(&scheduled.epoch)
                .unwrap()
                .id,
            height: proposal.header().height().get(),
            origin_view: proposal.header().view_change_index(),
            parent_hash: parent.core_hash(),
            parent_result: parent.result(),
            payload_hash: payload_hash(&BlsCrypto::new(), &bytes),
            payload_len: u32::try_from(bytes.len()).unwrap(),
            availability_digest: iroha_sumeragi::types::Hash32::ZERO,
            proposer: 0,
            skipped_leaders: Vec::new(),
            attest: proposal.header().height().get() == scheduled.epoch.authorization.last_height,
        };
        let body = self.chain.author_payload(header, bytes.clone());
        (body.header().clone(), bytes)
    }
    fn validate(
        &self,
        proposal: SignedBlock,
    ) -> WithEvents<Result<(ValidBlock, Box<StateBlock<'_>>), Error>> {
        let (header, bytes) = self.header(&proposal);
        self.validate_bound(proposal, &header, &bytes)
    }
    fn validate_bound(
        &self,
        proposal: SignedBlock,
        header: &NativeHeader,
        bytes: &[u8],
    ) -> WithEvents<Result<(ValidBlock, Box<StateBlock<'_>>), Error>> {
        let expansion = expand(self.chain.state(), &proposal, &NoLanes, Duration::ZERO).unwrap();
        self.validate_expanded(proposal, header, bytes, expansion)
    }
    fn validate_expanded<'state>(
        &'state self,
        proposal: SignedBlock,
        header: &NativeHeader,
        bytes: &[u8],
        expansion: crate::sumeragi::lanes::merge::Expansion<'state>,
    ) -> WithEvents<Result<(ValidBlock, Box<StateBlock<'state>>), Error>> {
        let topology = Topology::new(self.chain.validators().iter().map(|(peer, _)| peer.clone()));
        ValidBlock::validate_sumeragi_block(
            proposal,
            &topology,
            self.chain.genesis_account(),
            self.cadence(),
            iroha_data_model::parameter::system::ConsensusMode::Permissioned,
            expansion,
            header,
            bytes,
            self.chain.state(),
        )
    }
}

#[test]
fn native_validation_executes_original_nonempty_proposal_without_publishing_it() {
    let fixture = NativeValidationFixture::new();
    let state = fixture.chain.state();
    let generation = state.state_view_generation();
    let tx = fixture.transaction(2_001, None);
    let proposal = fixture.proposal(vec![tx], fixture.cadence());
    let (valid, overlay) = fixture.validate(proposal).unpack(|_| {}).unwrap();
    assert_eq!(valid.as_ref().external_entrypoint_count(), 1);
    assert!(
        valid
            .as_ref()
            .network_output_at(0)
            .unwrap()
            .1
            .result
            .is_ok()
    );
    drop(overlay);
    assert_eq!(state.view().height(), 2);
    assert_eq!(state.state_view_generation(), generation);
}

#[test]
fn native_validation_populates_stateless_cache() {
    let fixture = NativeValidationFixture::new();
    let tx = fixture.transaction(2_001, None);
    let key = crate::tx::StatelessValidationCacheKey::new(&tx);
    let proposal = fixture.proposal(vec![tx], fixture.cadence());
    let mut events = Vec::new();
    let (_, overlay) = fixture
        .validate(proposal)
        .unpack(|event| events.push(event))
        .unwrap();
    drop(overlay);
    assert!(!events.iter().any(|event| matches!(event, PipelineEventBox::Block(block) if matches!(block.status, BlockStatus::Rejected(_)))));
    assert!(
        fixture
            .chain
            .state()
            .stateless_validation_cache()
            .lock()
            .contains_key(&key)
    );
}

#[test]
fn native_validation_rechecks_signature_despite_forged_positive_cache_entry() {
    let mut fixture = NativeValidationFixture::new();
    let valid = fixture.transaction(2_001, None);
    let good_key = crate::tx::StatelessValidationCacheKey::new(&valid);
    let proposal = fixture.proposal(vec![valid.clone()], fixture.cadence());
    let (_, overlay) = fixture.validate(proposal).unpack(|_| {}).unwrap();
    drop(overlay);
    assert!(
        fixture
            .chain
            .state()
            .stateless_validation_cache()
            .lock()
            .contains_key(&good_key)
    );
    let other = KeyPair::from_seed(vec![0x7B; 32], Algorithm::Ed25519);
    let invalid = valid.with_authority(AccountId::new(other.public_key().clone()));
    let invalid_key = crate::tx::StatelessValidationCacheKey::new(&invalid);
    fixture
        .chain
        .state()
        .stateless_validation_cache()
        .lock()
        .insert_ok(invalid_key.clone(), None, 0);
    assert!(
        fixture
            .chain
            .state()
            .stateless_validation_cache()
            .lock()
            .contains_key(&invalid_key)
    );
    let proposal = fixture.proposal(vec![invalid], fixture.cadence());
    let executor_proposal = proposal.clone();
    let rejected_header = proposal.header();
    let mut events = Vec::new();
    let (_, error) = fixture
        .validate(proposal)
        .unpack(|event| events.push(event))
        .err()
        .unwrap();
    assert!(matches!(
        *error,
        BlockValidationError::TransactionAccept(AcceptTransactionFail::SignatureVerification(_))
    ));
    assert_eq!(events.iter().filter(|event| matches!(event, PipelineEventBox::Block(block) if matches!(block.status, BlockStatus::Rejected(_)))).count(), 1);
    assert_eq!(fixture.chain.state().view().height(), 2);
    fixture
        .chain
        .take_events()
        .expect("drain previously committed events");
    assert!(
        fixture
            .chain
            .begin_proposal(executor_proposal, Default::default())
            .is_err()
    );
    let published = fixture
        .chain
        .take_events()
        .expect("native rejection events");
    assert_eq!(
        published.len(),
        1,
        "only the authenticated rejection is published"
    );
    assert!(matches!(
        &published[0],
        iroha_data_model::events::EventBox::Pipeline(PipelineEventBox::Block(event))
        if event.header == rejected_header
            && event.status == BlockStatus::Rejected(Reason::TransactionValidationFailed)
    ));
    assert_eq!(fixture.chain.state().view().height(), 2);
}

#[test]
fn native_validation_uses_canonical_block_time_for_ttl() {
    let fixture = NativeValidationFixture::new();
    let tx = fixture.transaction(2_001, Some(60_000));
    let proposal = fixture.proposal(vec![tx], fixture.cadence());
    assert!(proposal.header().creation_time() < Duration::from_secs(60));
    let (_, overlay) = fixture.validate(proposal).unpack(|_| {}).unwrap();
    drop(overlay);
    // The production entry has no caller-supplied wall clock or alternate enqueue-time owner.
    let expired = fixture.transaction(1_001, Some(1));
    let proposal = fixture.proposal(vec![expired], fixture.cadence());
    assert!(fixture.validate(proposal).unpack(|_| {}).is_err());
    assert_eq!(fixture.chain.state().view().height(), 2);
}

#[test]
fn native_validation_enforces_original_signed_cadence() {
    let fixture = NativeValidationFixture::new();
    let transaction = fixture.transaction(1_001, None);
    let proposal = fixture.proposal(vec![transaction.clone()], fixture.cadence());
    let (_, overlay) = fixture.validate(proposal).unpack(|_| {}).unwrap();
    drop(overlay);
    for offset in [1, 20] {
        let wrong = fixture.cadence() + Duration::from_millis(offset);
        let proposal = fixture.proposal(vec![transaction.clone()], wrong);
        let (_, error) = fixture.validate(proposal).unpack(|_| {}).err().unwrap();
        assert!(matches!(
            *error,
            BlockValidationError::NonCanonicalBlockTime { .. }
        ));
    }
    assert_eq!(fixture.chain.state().view().height(), 2);
}

#[test]
fn native_validation_rejects_changed_original_header_before_state_publication() {
    let fixture = NativeValidationFixture::new();
    let proposal = fixture.proposal(vec![fixture.transaction(2_001, None)], fixture.cadence());
    let (header, payload) = fixture.header(&proposal);
    let original_generation = fixture.chain.state().state_view_generation();
    for changed in 0..9 {
        let mut header = header.clone();
        match changed {
            0 => header.height += 1,
            1 => header.origin_view += 1,
            2 => header.payload_len += 1,
            3 => header.payload_hash.0[0] ^= 1,
            4 => header.instance.0[0] ^= 1,
            5 => header.parent_hash.0[0] ^= 1,
            6 => header.parent_result.0[0] ^= 1,
            7 => header.epoch.epoch += 1,
            8 => header.epoch.context.0[0] ^= 1,
            _ => unreachable!(),
        }
        let mut events = Vec::new();
        assert!(
            fixture
                .validate_bound(proposal.clone(), &header, &payload)
                .unpack(|event| events.push(event))
                .is_err(),
            "mutation {changed}"
        );
        assert!(
            events.is_empty(),
            "unbound source {changed} must not publish a rejection"
        );
        assert_eq!(fixture.chain.state().view().height(), 2);
        assert_eq!(
            fixture.chain.state().state_view_generation(),
            original_generation
        );
    }
}

#[test]
fn native_validation_rejects_empty_and_da_only_proposals_without_publication() {
    let fixture = NativeValidationFixture::new();
    let parent = fixture.chain.committed(2);
    let time = parent.block().header().creation_time() + fixture.cadence();
    let generation = fixture.chain.state().state_view_generation();
    for da_only in [false, true] {
        let (_, clock) = TimeSource::new_mock(time);
        let mut builder = BlockBuilder::new_with_time_source(Vec::new(), clock)
            .chain(0, Some(parent.block()))
            .with_network_input_time_floor(time)
            .unwrap();
        if da_only {
            builder = builder.with_da_commitments(Some(DaCommitmentBundle::new(vec![
                DaCommitmentRecord::new(
                    LaneId::new(0),
                    1,
                    1,
                    BlobDigest::new([0xAA; 32]),
                    ManifestDigest::new([0xBB; 32]),
                    DaProofScheme::MerkleSha256,
                    Hash::prehashed([0xCC; 32]),
                    None,
                    RetentionClass::default(),
                    StorageTicketId::new([0xEE; 32]),
                    checked_da_ack_signature(0x11),
                ),
            ])));
        }
        let proposal = builder.into_unsigned_proposal();
        let mut events = Vec::new();
        let (_, error) = fixture
            .validate(proposal)
            .unpack(|event| events.push(event))
            .err()
            .unwrap();
        assert!(matches!(*error, BlockValidationError::EmptyBlock));
        assert!(events.iter().any(|event| matches!(event, PipelineEventBox::Block(block) if matches!(block.status, BlockStatus::Rejected(Reason::EmptyBlock)))));
        assert_eq!(fixture.chain.state().view().height(), 2);
        assert_eq!(fixture.chain.state().state_view_generation(), generation);
    }
}

#[test]
fn native_validation_retains_real_rejected_input_without_phantom_fragment() {
    let fixture = NativeValidationFixture::new();
    let absent = KeyPair::from_seed(vec![0x7C; 32], Algorithm::Ed25519);
    let transaction = fixture.chain.sign(
        &absent,
        [InstructionBox::from(Log::new(
            Level::INFO,
            "absent authority".to_owned(),
        ))],
        2_001,
    );
    let proposal = fixture.proposal(vec![transaction], fixture.cadence());
    let (valid, overlay) = fixture.validate(proposal).unpack(|_| {}).unwrap();
    assert_eq!(valid.as_ref().external_transactions().count(), 1);
    assert!(
        valid
            .as_ref()
            .network_output_at(0)
            .unwrap()
            .1
            .result
            .is_err()
    );
    assert_eq!(valid.as_ref().committed_fragment_count(), Some(0));
    assert_eq!(overlay.committed_fragment_count(), 0);
    drop(overlay);
    assert_eq!(fixture.chain.state().view().height(), 2);
}

include!("native_da_validation_tests.rs");

include!("native_input_validation_tests.rs");

include!("native_expansion_receiver_tests.rs");

include!("canonical_carrier_source_tests.rs");
