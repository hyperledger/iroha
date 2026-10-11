//! Genuine parent quorum plus deterministic wallet observations for resumable orchestration.
//! Synthetic execution fixtures test custody/control flow, not live fee or private execution.

use std::{
    cell::{Cell, RefCell},
    num::NonZeroU64,
};

use iroha_crypto::{Algorithm, ExposedPrivateKey, Hash, KeyPair, SignatureOf};
use iroha_data_model::{
    alias_setup::{
        AccountAliasRoleV1, AccountProvisionV1, AliasAccountIntentV1, AliasDataSpaceIntentV1,
        AliasLeaseAcquisitionV1, AliasQuoteGuardV1, ResolvedDataSpaceV1,
    },
    block::consensus::SumeragiRootScope,
    isi::alias_setup::EnsureAlias,
    sns::{lease::SnsLeaseProofV1, record_storage_key},
    sumeragi::{SumeragiFootprint, SumeragiStatus},
    sumeragi_finality::{
        SumeragiFinalityAttestation, SumeragiFinalityAttestationBody, SumeragiFinalityProof,
        WorldStateElementKindV1, WorldStateSnapshotEntryV1, WorldStateSnapshotV1,
        authenticated_genesis, test_fixtures::NativeFinalityFixture, world_state_value_hash_v1,
    },
};
use iroha_model_base::{peer::PeerId, topology::DataSpaceId};
use norito::codec::{Decode as _, Encode as _};

use super::*;
use crate::bootstrap::{
    NetworkRelease, ReleaseCheckpointStore, ReleasePeer, ReleaseTrust, SignedNetworkCheckpoint,
};

struct Fixture {
    directory: tempfile::TempDir,
    parent: NativeFinalityFixture,
    child: Config,
    registration: PrivateDataspaceRegistration,
    bootstrap: AuthenticatedBootstrap,
    lease_proof: SnsLeaseProofV1,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let mut parent = NativeFinalityFixture::start("provisioning-parent");
        let selector = NameSelectorV1::new(DATASPACE_ALIAS_SUFFIX_ID, "acme").unwrap();
        let owner = KeyPair::from_seed(vec![131; 32], Algorithm::Ed25519);
        let now = unix_ms().unwrap();
        let mut lease = NameRecordV1::new(
            selector.clone(),
            AccountId::new(owner.public_key().clone()),
            vec![],
            0,
            1,
            now + 600_000,
            now + 700_000,
            now + 800_000,
            Default::default(),
        );
        lease.ownership_generation = 7;
        let record = lease.encode();
        let lease_proof = SnsLeaseProofV1 {
            world: WorldStateSnapshotV1 {
                schema_hash: Hash::new(b"independently qualified fixture World schema"),
                entries: vec![WorldStateSnapshotEntryV1 {
                    field_id: "world.smart_contract_state".into(),
                    kind: WorldStateElementKindV1::Table,
                    key_hash: Some(
                        world_state_value_hash_v1(&record_storage_key(&selector)).unwrap(),
                    ),
                    value_hash: world_state_value_hash_v1(&record).unwrap(),
                }],
            },
            record,
        };
        let block = parent.block_with_submitted_work(parent.next_header());
        parent.certify_with_world_root(block, lease_proof.world.root().unwrap());
        let scope = SumeragiRootScope::Dataspace {
            parent_network_id: parent.network_id(),
            dataspace_id: DataSpaceId::from_hash(&selector.name_hash()),
        };
        let child_chain = NativeFinalityFixture::start_with_scope("provisioning-child", scope);
        let result = child_chain
            .verifier()
            .verify_retained_decision(child_chain.genesis_proof())
            .unwrap()
            .result()
            .0;
        let registration = PrivateDataspaceRegistration::new(
            scope,
            child_chain.chain_id().parse().unwrap(),
            child_chain.network_id(),
            result,
            authenticated_genesis(child_chain.genesis())
                .map(|genesis| genesis.into_parts().0)
                .unwrap(),
        )
        .unwrap();
        let mut child = Config::load_table(
            "fixture.toml",
            toml::toml! {
                chain = (child_chain.chain_id())
                network_id = (child_chain.network_id().to_string())
                torii_url = "http://127.0.0.1:8080/"
                [account]
                chain_discriminant = 753
                public_key = (owner.public_key().to_string())
                private_key = (ExposedPrivateKey(owner.private_key().clone()).to_string())
            },
        )
        .unwrap();
        child.api_token = Some(iroha::secrecy::SecretString::new(
            "only-the-private-child".into(),
        ));
        let checkpoint = parent.checkpoint();
        let authority = KeyPair::from_seed(vec![132; 32], Algorithm::Ed25519);
        let release = NetworkRelease {
            network_name: "fixture".into(),
            serial: 1,
            generation: 1,
            network_id: parent.network_id(),
            chain_id: parent.chain_id().into(),
            issued_at_ms: now - 1000,
            expires_at_ms: now + 600_000,
            torii_roots: vec!["https://parent.example/".into()],
            account_chain_discriminant: 753,
            native_world_schema: lease_proof.world.schema_hash,
            peers: checkpoint
                .tip()
                .committee
                .iter()
                .map(|validator| ReleasePeer {
                    node_id: PeerId::new(validator.public_key.clone()),
                    torii_root: "https://parent.example/".into(),
                })
                .collect(),
            faucet: Some(ReleaseFaucet {
                torii_root: "https://parent.example/".into(),
                issuer: AccountId::new(authority.public_key().clone()),
                asset_definition_id: iroha_wallet::operations::XOR_ASSET_DEFINITION
                    .parse()
                    .unwrap(),
                amount: 1000_u64.into(),
                max_operation_fee: 2_u64.into(),
                max_namespace_rent: 100_u64.into(),
            }),
            build_registry: None,
            checkpoint_hash: Hash::new(checkpoint.encode_canonical().unwrap()),
            checkpoint_height: checkpoint.height(),
            checkpoint_block_hash: checkpoint.block_hash().into(),
        };
        let bytes = SignedNetworkCheckpoint::sign(release, &checkpoint, authority.private_key())
            .unwrap()
            .encode_canonical()
            .unwrap();
        let bootstrap = ReleaseCheckpointStore::open(&directory.path().join("release"))
            .unwrap()
            .authenticate(
                &ReleaseTrust::new("fixture".into(), authority.public_key().clone(), 1).unwrap(),
                &bytes,
                now,
            )
            .unwrap();
        Self {
            directory,
            parent,
            child,
            registration,
            bootstrap,
            lease_proof,
        }
    }

    fn open(&self) -> Result<RemoteProvisioning> {
        RemoteProvisioning::open_trusted(
            &self.directory.path().join("provisioning"),
            &self.bootstrap,
            self.child.clone(),
            "acme".into(),
            "admin".into(),
            self.registration.clone(),
        )
    }
}

struct Source<'a> {
    chain: &'a NativeFinalityFixture,
    offline: bool,
    reads: Cell<usize>,
}
impl FinalitySource for Source<'_> {
    type Error = std::io::Error;
    fn finality_proof(
        &self,
        height: NonZeroU64,
    ) -> std::result::Result<SumeragiFinalityProof, Self::Error> {
        if height.get() == self.chain.checkpoint().height() {
            Ok(self.chain.latest().clone())
        } else {
            Err(std::io::Error::other("unserved fixture height"))
        }
    }
    fn latest_attestation(
        &self,
        peer: &PeerId,
        challenge: &[u8; 32],
    ) -> std::result::Result<crate::verify::finality::FinalityAttestation, Self::Error> {
        self.reads.set(self.reads.get() + 1);
        if self.offline {
            return Err(std::io::Error::other("offline"));
        }
        let key = (1..=4)
            .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
            .find(|key| key.public_key() == peer.public_key())
            .unwrap();
        let height = self.chain.checkpoint().height();
        let config_fingerprint = Hash::new(b"fixture config");
        let body = SumeragiFinalityAttestationBody {
            observed_at_unix_ms: 1_000_000,
            challenge: *challenge,
            network_id: self.chain.network_id(),
            node_id: peer.clone(),
            node_fingerprint: Hash::new(peer.encode()),
            build_fingerprint: Hash::new(b"fixture build"),
            config_fingerprint,
            genesis_block_hash: self.chain.genesis().hash(),
            genesis_finality_proof: self.chain.genesis_proof().clone(),
            status: SumeragiStatus {
                protocol_version: iroha_data_model::sumeragi::PROTOCOL_VERSION,
                config_fingerprint,
                beacon_horizon: None,
                instance: self.chain.verifier().instance().0,
                height: height + 1,
                view: 0,
                stage: 0,
                leader: None,
                proxy_tail: None,
                high_qc_view: None,
                level: 0,
                start_level: 0,
                t_retx_ms: 100,
                committed_height: height,
                applied_height: height,
                awaiting: false,
                signer: Some(key.public_key().clone()),
                unanchored: false,
                abstaining: false,
                halted: None,
                footprint: SumeragiFootprint::default(),
            },
            finality_proof: self.chain.latest().clone(),
        };
        Ok(SumeragiFinalityAttestation {
            signature: SignatureOf::try_from_hash(key.private_key(), body.signing_hash()).unwrap(),
            body,
        }
        .into())
    }
}

struct Operations {
    binding: Binding,
    calls: RefCell<Vec<&'static str>>,
    fund_status: Cell<OperationStatus>,
    reserve_status: Cell<OperationStatus>,
    lease_proof: SnsLeaseProofV1,
    forged_generation: Cell<bool>,
    reserve_before_journal_failure: Cell<bool>,
    cancel_after: RefCell<Option<(&'static str, Arc<AtomicBool>)>>,
}
impl Operations {
    fn new(store: &RemoteProvisioning, fixture: &Fixture) -> Self {
        Self {
            binding: store.record.binding.clone(),
            calls: RefCell::new(vec![]),
            fund_status: Cell::new(OperationStatus::Applied),
            reserve_status: Cell::new(OperationStatus::Pending),
            lease_proof: fixture.lease_proof.clone(),
            forged_generation: Cell::new(false),
            reserve_before_journal_failure: Cell::new(false),
            cancel_after: RefCell::new(None),
        }
    }
    fn record_call(&self, operation: &'static str) {
        self.calls.borrow_mut().push(operation);
        if let Some((selected, signal)) = self.cancel_after.borrow().as_ref() {
            if *selected == operation {
                signal.store(true, Ordering::Release);
            }
        }
    }
    fn request(&self) -> AliasSetupPlanRequestV1 {
        let valid_until_ms = unix_ms().unwrap() + 120_000;
        AliasSetupPlanRequestV1::new(vec![
            EnsureAlias::new(
                AliasIntentV1::Dataspace(AliasDataSpaceIntentV1 {
                    dataspace: ResolvedDataSpaceV1::new(
                        "acme".parse().unwrap(),
                        self.binding.registration.scope.dataspace_id(),
                    ),
                    owner: self.binding.owner.clone(),
                }),
                AliasLeaseAcquisitionV1::new(1, Some(0)),
                AliasQuoteGuardV1 {
                    expected_policy_version: 1,
                    expected_payment_asset: self.binding.faucet.asset_definition_id.clone(),
                    max_amount: 10_u64.into(),
                    valid_until_ms,
                },
            ),
            EnsureAlias::new(
                AliasIntentV1::AccountAlias(AliasAccountIntentV1 {
                    alias: iroha_wallet::namespace::resolve_private_owner_alias(
                        &self.binding.alias,
                        &self.binding.account_alias,
                    )
                    .unwrap(),
                    target_account: self.binding.owner.clone(),
                    provision: AccountProvisionV1::Existing,
                    role: AccountAliasRoleV1::Additional,
                }),
                AliasLeaseAcquisitionV1::new(1, Some(0)),
                AliasQuoteGuardV1 {
                    expected_policy_version: 1,
                    expected_payment_asset: self.binding.faucet.asset_definition_id.clone(),
                    max_amount: 10_u64.into(),
                    valid_until_ms,
                },
            ),
        ])
    }
}
impl ProvisioningOperations for Operations {
    fn fund(
        &self,
        config: &Config,
        request: &FaucetRequest,
        _: &Path,
        deadline: Instant,
    ) -> Result<OperationStatus> {
        assert!(deadline > Instant::now());
        assert!(config.api_token.is_none());
        assert_eq!(request.amount, self.binding.faucet.amount);
        assert_eq!(request.fee_payment.charge_limits().len(), 1);
        assert_eq!(
            request.fee_payment.charge_limits()[0].max_amount(),
            &self.binding.faucet.max_operation_fee
        );
        self.record_call("fund");
        Ok(self.fund_status.get())
    }
    fn namespace_request(
        &self,
        _: &Config,
        alias: &str,
        account_alias: &str,
        _: Instant,
    ) -> Result<AliasSetupPlanRequestV1> {
        assert_eq!(alias, self.binding.alias);
        assert_eq!(account_alias, self.binding.account_alias);
        self.record_call("quote");
        Ok(self.request())
    }
    fn reserve(
        &self,
        _: &Config,
        request: &AliasSetupPlanRequestV1,
        options: &BoundedTransactionOptions,
        journal: &Path,
    ) -> Result<OperationStatus> {
        self.record_call("reserve");
        if self.reserve_before_journal_failure.get() {
            return Err(ProvisioningError::NamespacePreparation);
        }
        assert_eq!(
            options.max_total_fees[&self.binding.faucet.asset_definition_id],
            self.binding.faucet.max_operation_fee
        );
        if !path_exists(journal)? {
            let _held =
                iroha_operation_journal::Journal::create_prepared(journal, request).unwrap();
        } else {
            let held = iroha_operation_journal::Journal::open(journal).unwrap();
            assert_eq!(
                &held.read_operation::<AliasSetupPlanRequestV1>().unwrap(),
                request
            );
        }
        Ok(self.reserve_status.get())
    }
    fn lease(&self, config: &Config, read: &LeaseRead<'_>) -> Result<VerifiedSnsLeaseV1> {
        self.record_call("lease");
        assert!(read.deadline > Instant::now());
        let mut proof = self.lease_proof.clone();
        if self.forged_generation.get() {
            let mut record = NameRecordV1::decode(&mut proof.record.as_slice()).unwrap();
            record.ownership_generation = 8;
            proof.record = record.encode();
        }
        let selector = NameSelectorV1::new(DATASPACE_ALIAS_SUFFIX_ID, read.alias).unwrap();
        proof
            .verify(
                config.network_id,
                &selector,
                read.owner,
                read.native_schema,
                read.block,
                unix_ms()?,
            )
            .map_err(|_| ProvisioningError::NamespaceObservation)
    }
}

#[test]
fn genuine_private_genesis_owner_is_imported_into_only_its_bound_parent_wallet() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let selector = NameSelectorV1::new(DATASPACE_ALIAS_SUFFIX_ID, "acme").unwrap();
    let spec = crate::localnet::PrivateRootSpec {
        parent_network_id: fixture.parent.network_id(),
        dataspace_id: DataSpaceId::from_hash(&selector.name_hash()),
        dataspace_alias: "acme".into(),
    };
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_private_root(
        "private",
        &fixture.directory.path().join("private"),
        &ports,
        &spec,
    )
    .unwrap();
    let path = fixture.directory.path().join("provisioning");
    assert!(
        RemoteProvisioning::load_parent_config(&path, &fixture.bootstrap, &prepared, "admin")
            .is_err()
    );
    assert!(!path.exists());
    let service = RemoteProvisioning::open(&path, &fixture.bootstrap, &prepared, "admin").unwrap();
    let child = prepared.context.load_client_config().unwrap();
    let parent =
        RemoteProvisioning::load_parent_config(&path, &fixture.bootstrap, &prepared, "admin")
            .unwrap();
    assert_eq!(parent.key_pair, child.key_pair);
    assert_eq!(parent.account, child.account);
    assert_eq!(parent.network_id, fixture.parent.network_id());
    assert_ne!(parent.network_id, child.network_id);
    assert!(child.api_token.is_some());
    assert!(parent.api_token.is_none());
    assert!(parent.basic_auth.is_none());
    assert_eq!(
        service.record.binding.registration,
        prepared.load_private_registration().unwrap()
    );
    let mut substituted = prepared.clone();
    substituted.context.dataspace_alias = "foreign".into();
    assert!(
        RemoteProvisioning::load_parent_config(&path, &fixture.bootstrap, &substituted, "admin")
            .is_err()
    );
    drop(service);
    assert_eq!(
        RemoteProvisioning::open(&path, &fixture.bootstrap, &prepared, "admin")
            .unwrap()
            .parent
            .key_pair,
        parent.key_pair
    );
}

#[test]
fn exact_owner_import_and_exclusive_custody_survive_reopen_but_not_child_replacement() {
    let fixture = Fixture::new();
    let store = fixture.open().unwrap();
    assert_eq!(store.parent.account, fixture.child.account);
    assert!(store.parent.api_token.is_none());
    assert_eq!(store.parent.network_id, fixture.parent.network_id());
    assert_ne!(store.parent.network_id, store.child.network_id);
    assert_eq!(store.progress().stage, ProvisioningStage::Funding);
    let short_deadline = Instant::now() + Duration::from_secs(1);
    assert_eq!(
        store
            .turn_deadline(&fixture.bootstrap, short_deadline)
            .unwrap(),
        short_deadline
    );
    assert!(
        store
            .turn_deadline(
                &fixture.bootstrap,
                Instant::now() + Duration::from_secs(3600)
            )
            .unwrap()
            < Instant::now() + Duration::from_secs(601)
    );
    assert!(fixture.open().is_err());
    let read_parent = |child: &Config| {
        RemoteProvisioning::load_parent_config_trusted(
            &fixture.directory.path().join("provisioning"),
            &fixture.bootstrap,
            child,
            "acme",
            "admin",
            &fixture.registration,
        )
    };
    let parent = read_parent(&fixture.child).unwrap();
    assert_eq!(parent.account, store.parent.account);
    assert_eq!(parent.network_id, store.parent.network_id);
    assert_eq!(parent.key_pair, store.parent.key_pair);
    assert!(parent.api_token.is_none());
    let mut changed = fixture.child.clone();
    changed.account = fixture
        .bootstrap
        .release()
        .faucet
        .as_ref()
        .unwrap()
        .issuer
        .clone();
    assert!(read_parent(&changed).is_err());
    let bytes = store
        .directory
        .read("provisioning.nrt", MAX_RECORD_BYTES)
        .unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("only-the-private-child"));
    assert!(decode_record(&[bytes.as_slice(), b"suffix"].concat()).is_err());
    drop(store);
    let store = fixture.open().unwrap();
    assert_eq!(store.progress().stage.as_str(), "funding");
    drop(store);
    let mut changed = fixture.child.clone();
    changed.account = fixture
        .bootstrap
        .release()
        .faucet
        .as_ref()
        .unwrap()
        .issuer
        .clone();
    assert!(
        RemoteProvisioning::open_trusted(
            &fixture.directory.path().join("provisioning"),
            &fixture.bootstrap,
            changed,
            "acme".into(),
            "admin".into(),
            fixture.registration.clone()
        )
        .is_err()
    );
    let path = fixture
        .directory
        .path()
        .join("provisioning/provisioning.nrt");
    std::fs::remove_file(path).unwrap();
    assert!(fixture.open().is_err());
    assert!(read_parent(&fixture.child).is_err());
}

#[test]
fn fresh_quorum_precedes_funding_and_pending_namespace_resumes_exact_original_request() {
    let fixture = Fixture::new();
    let mut store = fixture.open().unwrap();
    let ops = Operations::new(&store, &fixture);
    let source = Source {
        chain: &fixture.parent,
        offline: true,
        reads: Cell::new(0),
    };
    let deadline = || Instant::now() + Duration::from_secs(30);
    assert!(
        store
            .provision_once(&fixture.bootstrap, Instant::now())
            .is_err()
    );
    assert!(
        store
            .provision_with(&fixture.bootstrap, deadline(), &source, &ops)
            .is_err()
    );
    assert!(source.reads.get() >= 3);
    assert!(ops.calls.borrow().is_empty());
    let source = Source {
        offline: false,
        ..source
    };
    assert!(
        store
            .provision_with(&fixture.bootstrap, Instant::now(), &source, &ops)
            .is_err()
    );
    ops.fund_status.set(OperationStatus::Pending);
    let progress = store
        .provision_with(&fixture.bootstrap, deadline(), &source, &ops)
        .unwrap();
    assert_eq!(progress.stage, ProvisioningStage::Funding);
    assert_eq!(progress.wallet_status, Some(OperationStatus::Pending));
    ops.fund_status.set(OperationStatus::Applied);
    ops.calls.borrow_mut().clear();
    let progress = store
        .provision_with(&fixture.bootstrap, deadline(), &source, &ops)
        .unwrap();
    assert_eq!(progress.stage, ProvisioningStage::Namespace);
    assert!(progress.confirmed.is_none());
    assert_eq!(*ops.calls.borrow(), vec!["fund", "quote", "reserve"]);
    let request = store.record.namespace.clone().unwrap();
    drop(store);
    let mut store = fixture.open().unwrap();
    ops.calls.borrow_mut().clear();
    ops.reserve_status.set(OperationStatus::Applied);
    ops.forged_generation.set(true);
    assert!(
        store
            .provision_with(&fixture.bootstrap, deadline(), &source, &ops)
            .is_err()
    );
    assert_eq!(store.record.lease_generation, None);
    assert_eq!(store.progress().stage, ProvisioningStage::Namespace);
    assert_eq!(*ops.calls.borrow(), vec!["reserve", "lease"]);
    ops.calls.borrow_mut().clear();
    ops.forged_generation.set(false);
    let progress = store
        .provision_with(&fixture.bootstrap, deadline(), &source, &ops)
        .unwrap();
    assert_eq!(*ops.calls.borrow(), vec!["reserve", "lease"]);
    assert_eq!(store.record.namespace.as_ref(), Some(&request));
    assert_eq!(progress.stage, ProvisioningStage::Registering);
    assert!(progress.confirmed.is_none());
    assert_eq!(store.record.lease_generation, Some(7));
    assert!(
        store
            .relay_once(&fixture.bootstrap, Instant::now())
            .is_err()
    );
    drop(store);
    let store = fixture.open().unwrap();
    assert_eq!(store.progress().stage.as_str(), "registering");
}

#[test]
fn retained_owner_alias_cannot_change_on_reopen_or_parent_wallet_read() {
    let fixture = Fixture::new();
    let store = fixture.open().unwrap();
    let path = store.directory.path().to_path_buf();
    let original = std::fs::read(path.join("provisioning.nrt")).unwrap();
    assert_eq!(
        decode_record(&original).unwrap().binding.account_alias,
        "admin"
    );
    assert!(
        RemoteProvisioning::load_parent_config_trusted(
            &path,
            &fixture.bootstrap,
            &fixture.child,
            "acme",
            "treasury",
            &fixture.registration,
        )
        .is_err()
    );
    drop(store);
    assert!(
        RemoteProvisioning::open_trusted(
            &path,
            &fixture.bootstrap,
            fixture.child.clone(),
            "acme".into(),
            "treasury".into(),
            fixture.registration.clone(),
        )
        .is_err()
    );
    assert_eq!(
        std::fs::read(path.join("provisioning.nrt")).unwrap(),
        original
    );
    let reopened = fixture.open().unwrap();
    assert_eq!(reopened.record.binding.account_alias, "admin");
    let mut missing = reopened.record.clone();
    missing.binding.account_alias.clear();
    assert!(record_bytes(&missing).is_err());
}

#[test]
fn namespace_quote_survives_failure_before_journal_without_requoting_or_new_fees() {
    let fixture = Fixture::new();
    let mut store = fixture.open().unwrap();
    let ops = Operations::new(&store, &fixture);
    let source = Source {
        chain: &fixture.parent,
        offline: false,
        reads: Cell::new(0),
    };
    let deadline = || Instant::now() + Duration::from_secs(30);
    ops.reserve_before_journal_failure.set(true);
    assert!(
        store
            .provision_with(&fixture.bootstrap, deadline(), &source, &ops)
            .is_err()
    );
    assert_eq!(*ops.calls.borrow(), vec!["fund", "quote", "reserve"]);
    let request = store.record.namespace.clone().unwrap();
    assert_eq!(request.intents.len(), 2);
    assert!(!store.directory.path().join("operations/namespace").exists());
    drop(store);
    let mut store = fixture.open().unwrap();
    ops.calls.borrow_mut().clear();
    ops.reserve_before_journal_failure.set(false);
    store
        .provision_with(&fixture.bootstrap, deadline(), &source, &ops)
        .unwrap();
    assert_eq!(*ops.calls.borrow(), vec!["reserve"]);
    assert_eq!(store.record.namespace.as_ref(), Some(&request));
    let journal = iroha_operation_journal::Journal::open(
        &store.directory.path().join("operations/namespace"),
    )
    .unwrap();
    assert_eq!(
        journal.read_operation::<AliasSetupPlanRequestV1>().unwrap(),
        request
    );
}

#[test]
fn namespace_allowance_and_authenticated_lease_bind_exact_identity_and_rent() {
    let fixture = Fixture::new();
    let store = fixture.open().unwrap();
    let ops = Operations::new(&store, &fixture);
    let binding = &store.record.binding;
    let original = ops.request();
    binding.validate_namespace(&original).unwrap();
    for mutation in 0..14 {
        let mut changed = original.clone();
        match mutation {
            0 => changed.intents[0].quote_guard.max_amount = 101_u64.into(),
            1 => changed.intents[0].acquisition.term_years = 2,
            2 => changed.intents.push(changed.intents[0].clone()),
            3 => changed.schema_version = 2,
            4 => {
                if let AliasIntentV1::Dataspace(value) = &mut changed.intents[0].intent {
                    value.owner = binding.faucet.issuer.clone();
                }
            }
            5 => changed.intents[1].quote_guard.max_amount = 91_u64.into(),
            6 => changed.intents[1].acquisition.term_years = 2,
            7 => changed.intents[1].quote_guard.valid_until_ms += 1,
            8 => changed.intents.swap(0, 1),
            13 => {
                let mut currency = [41; 16];
                currency[6] = 0x49;
                currency[8] = 0x89;
                changed.intents[1].quote_guard.expected_payment_asset =
                    iroha_data_model::asset::AssetDefinitionId::from_uuid_bytes(currency).unwrap();
            }
            _ => {
                if let AliasIntentV1::AccountAlias(value) = &mut changed.intents[1].intent {
                    match mutation {
                        9 => {
                            value.alias = iroha_wallet::namespace::resolve_private_owner_alias(
                                "acme", "treasury",
                            )
                            .unwrap()
                        }
                        10 => value.target_account = binding.faucet.issuer.clone(),
                        11 => value.role = AccountAliasRoleV1::Primary,
                        12 => value.provision = AccountProvisionV1::Create,
                        _ => unreachable!(),
                    }
                }
            }
        }
        assert!(binding.validate_namespace(&changed).is_err());
    }
    let tip = store.finality.verifier().verified_tip().unwrap();
    let read = LeaseRead {
        alias: "acme",
        owner: &binding.owner,
        native_schema: fixture.bootstrap.release().native_world_schema,
        block: &tip,
        deadline: Instant::now() + Duration::from_secs(1),
    };
    let lease = ops.lease(&store.parent, &read).unwrap();
    let now = unix_ms().unwrap();
    assert_eq!(binding.lease_generation(lease.record(), now).unwrap(), 7);
    for mutation in 0..4 {
        let mut changed = lease.record().clone();
        match mutation {
            0 => changed.ownership_generation = 0,
            1 => changed.owner = binding.faucet.issuer.clone(),
            2 => changed.expires_at_ms = now,
            _ => changed.name_hash = [0; 32],
        };
        assert!(binding.lease_generation(&changed, now).is_err());
    }
    let mut record = store.record.clone();
    record.namespace = Some(original);
    assert!(record.validate().is_err());
    let mut config = store.parent.clone();
    config.api_token = fixture.child.api_token.clone();
    assert!(binding.validate_config(&config).is_err());
    assert!(
        NativeOperations::default()
            .fund(
                &store.parent,
                &binding.faucet_request(),
                &store.directory.path().join("expired"),
                Instant::now()
            )
            .is_err()
    );
    assert!(
        NativeOperations::default()
            .namespace_request(&store.parent, "acme", "admin", Instant::now())
            .is_err()
    );
    assert!(
        NativeOperations::default()
            .reserve(
                &store.parent,
                &ops.request(),
                &binding.options(Instant::now()),
                &store.directory.path().join("expired")
            )
            .is_err()
    );
    assert!(
        NativeOperations::default()
            .lease(
                &store.parent,
                &LeaseRead {
                    deadline: Instant::now(),
                    ..read
                }
            )
            .is_err()
    );
}

#[test]
fn uncertain_publication_retains_previous_record_and_requires_exclusive_reopen() {
    let fixture = Fixture::new();
    let mut store = fixture.open().unwrap();
    let path = store.directory.path().join("provisioning.nrt");
    let saved = std::fs::read(&path).unwrap();
    std::fs::rename(&path, path.with_extension("held")).unwrap();
    std::fs::create_dir(&path).unwrap();
    let mut next = store.record.clone();
    next.faucet_observed = true;
    assert!(store.publish(next).is_err());
    assert_eq!(store.progress().stage, ProvisioningStage::Funding);
    assert!(store.revalidate().is_err());
    std::fs::remove_dir(&path).unwrap();
    std::fs::rename(path.with_extension("held"), &path).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), saved);
    assert!(store.revalidate().is_err());
    drop(store);
    let store = fixture.open().unwrap();
    assert_eq!(store.progress().stage, ProvisioningStage::Funding);
    assert_eq!(ProvisioningStage::Namespace.as_str(), "namespace");
    assert_eq!(ProvisioningStage::Attached.as_str(), "attached");
}

#[test]
fn cancellation_after_funding_or_quote_blocks_the_next_paid_stage_and_keeps_exact_recovery() {
    for point in ["fund", "quote"] {
        let fixture = Fixture::new();
        let signal = Arc::new(AtomicBool::new(false));
        let mut store = fixture
            .open()
            .unwrap()
            .with_cancellation(Arc::clone(&signal))
            .unwrap();
        let ops = Operations::new(&store, &fixture);
        ops.fund_status.set(OperationStatus::Applied);
        *ops.cancel_after.borrow_mut() = Some((point, Arc::clone(&signal)));
        let source = Source {
            chain: &fixture.parent,
            offline: false,
            reads: Cell::new(0),
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        assert!(matches!(
            store.provision_with(&fixture.bootstrap, deadline, &source, &ops),
            Err(ProvisioningError::Cancelled)
        ));
        assert!(signal.load(Ordering::Acquire));
        assert!(store.record.faucet_observed);
        assert_eq!(
            *ops.calls.borrow(),
            if point == "fund" {
                vec!["fund"]
            } else {
                vec!["fund", "quote"]
            }
        );
        assert!(!store.directory.path().join("operations/namespace").exists());
        let original_namespace = store.record.namespace.clone();
        assert_eq!(original_namespace.is_some(), point == "quote");
        let exact_record = store
            .directory
            .read("provisioning.nrt", MAX_RECORD_BYTES)
            .unwrap();
        drop(store);
        let reopened = fixture.open().unwrap();
        assert_eq!(
            reopened
                .directory
                .read("provisioning.nrt", MAX_RECORD_BYTES)
                .unwrap(),
            exact_record
        );
        // The old signal stays cancelled. A new supervisor, never a reset signal, resumes.
        let mut reopened = reopened
            .with_cancellation(Arc::new(AtomicBool::new(false)))
            .unwrap();
        *ops.cancel_after.borrow_mut() = None;
        ops.calls.borrow_mut().clear();
        ops.reserve_status.set(OperationStatus::Applied);
        reopened
            .provision_with(&fixture.bootstrap, deadline, &source, &ops)
            .unwrap();
        assert_eq!(
            *ops.calls.borrow(),
            if point == "fund" {
                vec!["quote", "reserve", "lease"]
            } else {
                vec!["reserve", "lease"]
            }
        );
        if let Some(original) = original_namespace {
            assert_eq!(reopened.record.namespace, Some(original));
        }
        assert_eq!(reopened.progress().stage, ProvisioningStage::Registering);
        assert!(signal.load(Ordering::Acquire));
        assert!(
            reopened
                .attachment
                .as_mut()
                .unwrap()
                .bind_cancellation(Arc::new(AtomicBool::new(false)))
                .is_err(),
            "new attachment must already carry the original provisioning cancellation owner"
        );
        drop(reopened);
        let mut rebound = fixture
            .open()
            .unwrap()
            .with_cancellation(Arc::new(AtomicBool::new(false)))
            .unwrap();
        assert!(
            rebound
                .attachment
                .as_mut()
                .unwrap()
                .bind_cancellation(Arc::new(AtomicBool::new(false)))
                .is_err(),
            "reopened attachment must inherit its new provisioning owner's signal"
        );
    }
}

#[test]
fn cancelled_existing_namespace_can_reconcile_without_replacing_its_retained_request() {
    let fixture = Fixture::new();
    let signal = Arc::new(AtomicBool::new(false));
    let mut store = fixture
        .open()
        .unwrap()
        .with_cancellation(Arc::clone(&signal))
        .unwrap();
    let ops = Operations::new(&store, &fixture);
    ops.fund_status.set(OperationStatus::Applied);
    let source = Source {
        chain: &fixture.parent,
        offline: false,
        reads: Cell::new(0),
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    store
        .provision_with(&fixture.bootstrap, deadline, &source, &ops)
        .unwrap();
    let request = store.record.namespace.clone().unwrap();
    let journal = store
        .directory
        .path()
        .join("operations/namespace/operation.json");
    let original = std::fs::read(&journal).unwrap();
    signal.store(true, Ordering::Release);
    ops.calls.borrow_mut().clear();
    // This backend returns only the existing operation's observation; native wallet guards
    // independently prohibit another preparation/signature/dispatch after cancellation.
    store
        .provision_with(&fixture.bootstrap, deadline, &source, &ops)
        .unwrap();
    assert_eq!(*ops.calls.borrow(), vec!["reserve"]);
    assert_eq!(store.record.namespace, Some(request));
    assert_eq!(std::fs::read(journal).unwrap(), original);
    assert!(signal.load(Ordering::Acquire));
}

#[test]
fn cancellation_owner_cannot_change_and_native_adapters_refuse_new_journals() {
    let fixture = Fixture::new();
    let signal = Arc::new(AtomicBool::new(true));
    let store = fixture
        .open()
        .unwrap()
        .with_cancellation(Arc::clone(&signal))
        .unwrap()
        .with_cancellation(Arc::clone(&signal))
        .unwrap();
    assert!(Arc::ptr_eq(store.cancellation.as_ref().unwrap(), &signal));
    let ops = Operations::new(&store, &fixture);
    let native = NativeOperations {
        cancellation: Some(Arc::clone(&signal)),
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    let faucet = store.directory.path().join("cancelled-faucet");
    assert!(matches!(
        native.fund(
            &store.parent,
            &store.record.binding.faucet_request(),
            &faucet,
            deadline
        ),
        Err(ProvisioningError::FaucetPreparation)
    ));
    assert!(!faucet.exists());
    assert!(matches!(
        native.namespace_request(&store.parent, "acme", "admin", deadline),
        Err(ProvisioningError::Cancelled)
    ));
    let namespace = store.directory.path().join("cancelled-namespace");
    assert!(matches!(
        native.reserve(
            &store.parent,
            &ops.request(),
            &store.record.binding.options(deadline),
            &namespace
        ),
        Err(ProvisioningError::NamespacePreparation)
    ));
    assert!(!namespace.exists());
    assert!(matches!(
        store.with_cancellation(Arc::new(AtomicBool::new(false))),
        Err(ProvisioningError::Invalid(
            "provisioning cancellation owner changed"
        ))
    ));
}

#[test]
fn administrative_amx_provisioning_requires_original_attachment_without_signing() {
    let fixture = Fixture::new();
    let mut provisioning = fixture.open().unwrap();
    assert!(provisioning.attachment.is_none());
    let administrator = fixture.child.clone();
    let options = BoundedTransactionOptions {
        fee_payment: iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        max_total_fees: std::collections::BTreeMap::from([(
            iroha_wallet::operations::XOR_ASSET_DEFINITION
                .parse()
                .unwrap(),
            iroha_primitives::numeric::Quantity::from(1_u32),
        )]),
        deadline: Instant::now() + Duration::from_secs(1),
    };
    assert!(matches!(
        provisioning.register_amx_once(
            &fixture.bootstrap,
            &administrator,
            unix_ms().unwrap() + 60_000,
            &options
        ),
        Err(ProvisioningError::Invalid(
            "namespace provisioning is incomplete; administrative AMX registration is separate"
        ))
    ));
    assert!(provisioning.attachment.is_none());
    assert!(
        !provisioning
            .directory
            .path()
            .join("attachment")
            .join("amx-registration")
            .exists()
    );
}
