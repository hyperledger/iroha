//! Native provider component tests. Signed native actions use real Core execution and local
//! three-of-four BLS certificates; these do not qualify a replicated network or HTTP token ingress.
use super::*;
use iroha_config::parameters::actual;
use iroha_core::{
    state::World,
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_crypto::{Algorithm, ExposedPrivateKey, KeyPair};
use iroha_data_model::{
    Registrable,
    account::Account,
    asset::{AssetBalancePolicy, AssetDefinition, AssetDefinitionId, AssetId},
    domain::Domain,
    isi::{
        Grant, InstructionBox, Mint, Register, Revoke,
        sorafs::{
            AppendSorafsStreamTokenReputationJournalEntry, DecideSorafsReserveMovement,
            RegisterCapacityDeclaration, RegisterSorafsReserveAccount,
            RequestSorafsReserveMovement, SetSorafsReputationJournalAuthorityPolicy,
            SetSorafsReservePolicy, UpsertProviderCredit,
        },
    },
    permission::Permission,
    sorafs::{
        capacity::ProviderId,
        pin_registry::StorageClass,
        pricing::ProviderCreditRecord,
        reputation::{
            ReputationJournalAuthorityPolicyV1, StreamTokenRequestRouteV1,
            StreamTokenValidationRequestContextV1, StreamTokenValidationStatusV1 as Status,
            stream_token_delivery::{
                StreamTokenReputationDeliveryDispositionV1 as Disposition,
                StreamTokenReputationDeliveryTemplateV1,
            },
        },
        reserve::{
            ReserveAuthorityPolicyV1, ReserveDuration, ReserveMovementKindV1, ReservePolicyV1,
            ReserveProviderTermsV1, ReserveTier,
        },
        stream_token_gateway::{
            StreamTokenGatewayQuotaRequestV1, native::StreamTokenGatewayPolicyV1,
        },
    },
    transaction::{Executable, FeePaymentIntent, SignedTransaction, TransactionPayload},
};
use iroha_executor_data_model::permission::sorafs::{
    CanCheckSorafsStreamTokenGateway, CanDeclareSorafsCapacity,
    CanManageSorafsReputationJournalPolicy, CanManageSorafsStreamTokenGateway,
    CanOperateSorafsStreamTokenGateway, CanRecordSorafsReputationJournal,
    CanSetSorafsReservePolicy, CanUpsertSorafsProviderCredit,
};
use iroha_model_base::domain::DomainId;
use iroha_primitives::numeric::Quantity;
use sorafs_manifest::{
    capacity::{
        CAPACITY_DECLARATION_VERSION_V1, CapacityDeclarationV1, CapacityMetadataEntry,
        ChunkerCommitmentV1,
    },
    provider_advert::StakePointer,
};
use std::{
    collections::{BTreeSet, HashSet},
    fs,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use zeroize::Zeroizing;

fn key(seed: u8) -> KeyPair {
    KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).unwrap()
}
fn account(seed: u8) -> AccountId {
    AccountId::new(key(seed).public_key().clone())
}
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap()
}
fn queue() -> Arc<Queue> {
    Arc::new(Queue::from_config(
        actual::Queue::default(),
        tokio::sync::broadcast::channel(32).0,
    ))
}
fn credentials() -> (tempfile::TempDir, SorafsStreamTokenGatewayNativeConfig) {
    let parent = std::env::current_dir().unwrap().join("target");
    fs::create_dir_all(&parent).unwrap();
    let dir = tempfile::tempdir_in(parent).unwrap();
    let private =
        iroha_fs::PrivateDirectory::open_or_create(dir.path().join("credentials")).unwrap();
    let root = private.path().to_path_buf();
    for (name, seed) in [("operator", 2), ("observer", 3), ("reputation-recorder", 4)] {
        let key = Zeroizing::new(
            ExposedPrivateKey(key(seed).private_key().clone())
                .try_to_multihash_string()
                .unwrap(),
        );
        let mut bytes = Zeroizing::new(key.as_bytes().to_vec());
        bytes.push(b'\n');
        private
            .write_atomic(name, &bytes, iroha_fs::PublishMode::CreateNew)
            .unwrap();
    }
    (
        dir,
        SorafsStreamTokenGatewayNativeConfig {
            operator: account(2),
            operator_credential: root.join("operator"),
            observer: account(3),
            observer_credential: root.join("observer"),
            reputation_recorder: account(4),
            reputation_recorder_credential: root.join("reputation-recorder"),
            fee_payment: FeePaymentIntent::authority(Vec::new(), None),
            clock_uncertainty_ms: 0,
        },
    )
}
// Complete the actual native custody prerequisite before the gateway-specific sequence. These
// four nonempty committed blocks precede the original policy times; callback deadlines stay exact.
fn register_capacity_provider(
    chain: &mut CertifiedTestChain,
    provider: ProviderId,
    asset_definition: AssetDefinitionId,
    now: u64,
) {
    let reserve = ReserveAuthorityPolicyV1 {
        version: 1,
        revision: 1,
        predecessor_policy_digest: None,
        economics: ReservePolicyV1::default(),
        asset_definition,
        custody_account: account(5),
        treasury_account: account(6),
        operations_authority: account(1),
        decision_authority: account(1),
        grace_period_days: 7,
        default_after_days: 30,
        max_provider_debt: "1000".parse().unwrap(),
        max_pending_movements_per_provider: 4,
        max_open_appeals_per_provider: 2,
    };
    reserve.validate().unwrap();
    let digest = reserve.digest().unwrap();
    let register = chain.sign(
        &key(1),
        [
            SetSorafsReservePolicy::new(reserve).into(),
            RegisterSorafsReserveAccount::new(
                ReserveProviderTermsV1 {
                    provider_id: provider,
                    provider_account: account(4),
                    tier: ReserveTier::TierA,
                    storage_class: StorageClass::Hot,
                    duration: ReserveDuration::Monthly,
                    capacity_gib: 1,
                },
                digest,
            )
            .into(),
        ],
        now - 8_501,
    );
    assert_eq!(
        chain.commit_at(now - 8_500, vec![register]),
        [true],
        "native reserve setup"
    );
    let top_up = chain.sign(
        &key(4),
        [RequestSorafsReserveMovement::new(
            [0x43; 32],
            provider,
            ReserveMovementKindV1::TopUp,
            "100".parse().unwrap(),
            1,
            digest,
        )
        .into()],
        now - 7_501,
    );
    assert_eq!(
        chain.commit_at(now - 7_500, vec![top_up]),
        [true],
        "owner-funded reserve request"
    );
    let fund_and_credit = chain.sign(
        &key(1),
        [
            DecideSorafsReserveMovement::new(
                [0x43; 32],
                2,
                digest,
                true,
                "fund genuine gateway fixture capacity".into(),
            )
            .into(),
            UpsertProviderCredit::new(
                None,
                ProviderCreditRecord::new(
                    provider,
                    Quantity::zero(),
                    Quantity::from(100_u32),
                    Quantity::from(1_u32),
                    Quantity::zero(),
                    (now - 6_500) / 1_000,
                    (now - 6_500) / 1_000,
                    Default::default(),
                ),
            )
            .into(),
        ],
        now - 6_501,
    );
    assert_eq!(
        chain.commit_at(now - 6_500, vec![fund_and_credit]),
        [true],
        "native custody-backed credit"
    );
    let declaration = CapacityDeclarationV1 {
        version: CAPACITY_DECLARATION_VERSION_V1,
        provider_id: *provider.as_bytes(),
        stake: StakePointer {
            pool_id: [0x42; 32],
            stake_amount: "1".parse().unwrap(),
        },
        committed_capacity_gib: 1,
        chunker_commitments: vec![ChunkerCommitmentV1 {
            profile_id: "sorafs.sf1@1.0.0".into(),
            profile_aliases: None,
            committed_gib: 1,
            capability_refs: Vec::new(),
        }],
        lane_commitments: Vec::new(),
        pricing: None,
        valid_from: (now - 9_000) / 1_000,
        valid_until: (now + 600_000) / 1_000,
        metadata: vec![
            CapacityMetadataEntry {
                key: "sorafs.owner_account_id".into(),
                value: account(4).to_string(),
            },
            CapacityMetadataEntry {
                key: "sorafs.storage_class".into(),
                value: "hot".into(),
            },
        ],
    };
    declaration.validate().unwrap();
    let register = chain.sign(
        &key(4),
        [
            RegisterCapacityDeclaration::new(norito::encode_canonical(&declaration).unwrap())
                .into(),
        ],
        now - 5_501,
    );
    assert_eq!(
        chain.commit_at(now - 5_500, vec![register]),
        [true],
        "native canonical capacity registration"
    );
}

struct Fixture {
    chain: CertifiedTestChain,
    policy: StreamTokenGatewayPolicyV1,
}
impl Fixture {
    fn new() -> Self {
        Self::with_delivery_ttl(600_000)
    }
    fn with_delivery_ttl(time_to_live_ms: u64) -> Self {
        let now = now_ms();
        let world = World::with(
            [],
            (1..=6).map(|seed| Account::new(account(seed)).build(&account(1))),
            [],
        );
        let provider = ProviderId::new([0x41; 32]);
        let reserve_domain = DomainId::try_new("gateway-reserve", "universal").unwrap();
        let reserve_asset = AssetDefinitionId::derive_from_components(
            reserve_domain.clone(),
            "xor".parse().unwrap(),
        );
        // Establish the provider through the existing pre-genesis governance owner. Capacity
        // and its backing below are ordinary signed native transitions, never World row writes.
        let mut governance = actual::Governance::default();
        governance
            .sorafs_provider_owners
            .insert(provider, account(4));
        let mut config = TestChainConfig::new(world, now - 9_000);
        config.governance = Some(governance);
        config.genesis_instructions.extend([
            Register::domain(Domain::new(reserve_domain)).into(),
            Register::asset_definition(AssetDefinition::numeric(
                reserve_asset.clone(),
                "Gateway reserve XOR",
                AssetBalancePolicy::Global,
                None,
            ))
            .into(),
            Mint::asset_quantity(
                Quantity::from(1_000_u32),
                AssetId::of(reserve_asset.clone(), account(4)),
            )
            .into(),
            Grant::account_permission(Permission::from(CanSetSorafsReservePolicy), account(1))
                .into(),
            Grant::account_permission(Permission::from(CanUpsertSorafsProviderCredit), account(1))
                .into(),
            Grant::account_permission(Permission::from(CanDeclareSorafsCapacity), account(4))
                .into(),
        ]);
        config.genesis_instructions.push(
            Grant::account_permission(
                Permission::from(CanManageSorafsStreamTokenGateway),
                account(1),
            )
            .into(),
        );
        config.genesis_instructions.extend([
            Grant::account_permission(
                Permission::from(CanManageSorafsReputationJournalPolicy),
                account(1),
            )
            .into(),
            Grant::account_permission(
                Permission::from(CanRecordSorafsReputationJournal),
                account(4),
            )
            .into(),
        ]);
        let mut chain = CertifiedTestChain::start(config)
            .map_err(|error| error.error)
            .unwrap();
        register_capacity_provider(&mut chain, provider, reserve_asset, now);
        let network_id = *chain.state().network_id_ref();
        let mut policy = StreamTokenGatewayPolicyV1 {
            network_id,
            compliance_gateway_id: "native-provider-fixture".into(),
            qualification: Qualification {
                gateway_id: derive_stream_token_gateway_id_v1(
                    &network_id,
                    "native-provider-fixture",
                )
                .unwrap(),
                revision: 1,
                policy_digest: [0; 32],
                max_pending: 64,
                max_tracked_tokens: 64,
                lease_ttl_ms: 120_000,
            },
            operators: BTreeSet::from([account(2)]),
            observers: BTreeSet::from([account(3)]),
            valid_from_unix_ms: now - 5_000,
            valid_until_unix_ms: now + 600_000,
            max_observation_age_ms: 300_000,
            admission_enabled: true,
        };
        policy.qualification.policy_digest = policy.calculate_policy_digest().unwrap();
        let recorder_policy = ReputationJournalAuthorityPolicyV1 {
            version: 1,
            revision: 1,
            predecessor_policy_digest: None,
            por_recorder_authority: account(1),
            dispute_recorder_authority: account(1),
            token_recorder_authority: account(4),
            stream_token_delivery: StreamTokenReputationDeliveryTemplateV1 {
                allowed_gateways: vec![policy.qualification.gateway_id],
                fee_payment: FeePaymentIntent::authority(Vec::new(), None),
                time_to_live_ms,
                height_ttl: 1_024,
            },
            max_source_age_ms: 3_600_000,
        };
        let signed = chain.sign(
            &key(1),
            [SetSorafsReputationJournalAuthorityPolicy::new(recorder_policy).into()],
            now - 4_501,
        );
        assert_eq!(chain.commit_at(now - 4_500, vec![signed]), [true]);
        let configure = MutateSorafsStreamTokenGateway {
            request: NativeRequest {
                network_id,
                gateway_id: policy.qualification.gateway_id,
                expected_policy_revision: 0,
                expected_policy_digest: [0; 32],
                action: Action::Configure(policy.clone()),
            },
        };
        let signed = chain.sign(&key(1), [InstructionBox::from(configure)], now - 4_001);
        assert_eq!(chain.commit_at(now - 4_000, vec![signed]), [true]);
        let grants = [
            Grant::account_permission(
                Permission::from(CanOperateSorafsStreamTokenGateway {
                    gateway_id: policy.qualification.gateway_id,
                }),
                account(2),
            )
            .into(),
            Grant::account_permission(
                Permission::from(CanCheckSorafsStreamTokenGateway {
                    gateway_id: policy.qualification.gateway_id,
                }),
                account(3),
            )
            .into(),
        ];
        let signed = chain.sign(&key(1), grants, now - 3_001);
        assert_eq!(chain.commit_at(now - 3_000, vec![signed]), [true]);
        Self { chain, policy }
    }
    fn runtime(
        &self,
        config: &SorafsStreamTokenGatewayNativeConfig,
        queue: Arc<Queue>,
    ) -> NativeGateway {
        NativeGateway::new(
            self.chain.state().clone(),
            queue,
            "software://sorafs/stream-admission/primary".into(),
            self.policy.qualification,
            config,
            Duration::from_secs(60),
        )
        .unwrap()
    }
}
fn request() -> Request {
    let now = now_ms();
    Request {
        serving_attempt_id: [0x61; 32],
        context: StreamTokenValidationRequestContextV1::try_new(
            ProviderId::new([0x41; 32]),
            [0x42; 32],
            sorafs_manifest::canonical_manifest_root_cid([0x43; 32]),
            "sorafs.sf1@1.0.0".into(),
            "native-provider-attempt",
            Some(b"Q2Fub25pY2FsVG9rZW4="),
            StreamTokenRequestRouteV1::car_range(64, 1_023).unwrap(),
        )
        .unwrap(),
        token_body_digest: Some([0x44; 32]),
        token_key_version: Some(3),
        validated_at_unix_ms: now,
        status: Status::Accepted,
        quota: Some(StreamTokenGatewayQuotaRequestV1 {
            token_id: "11".repeat(16),
            max_streams: 4,
            requests_per_minute: 120,
            rate_limit_bytes: 1_048_576,
            requested_bytes: 960,
            expires_at_epoch: (now + 600_000) / 1_000,
            observed_at_epoch: now / 1_000,
        }),
    }
}
#[test]
fn native_gateway_clock_interval_is_explicit_checked_and_independent_of_request_time() {
    assert_eq!(
        eligibility_time(UNIX_EPOCH + Duration::from_millis(10_000), 100).unwrap(),
        EligibilityTime {
            earliest_unix_ms: 9_900,
            latest_unix_ms: 10_100
        }
    );
    assert_eq!(
        eligibility_time(UNIX_EPOCH + Duration::from_millis(100), 100),
        Err(ObservationError::Clock)
    );
    assert_eq!(
        eligibility_time(UNIX_EPOCH + Duration::from_millis(10_000), 5_001),
        Err(ObservationError::Clock)
    );
    assert_eq!(
        eligibility_time(UNIX_EPOCH - Duration::from_millis(1), 0),
        Err(ObservationError::Clock)
    );
}
#[test]
fn native_gateway_ack_identity_comes_from_original_execution_not_current_submission() {
    assert_eq!(
        acknowledgement_result([1; 32], [1; 32], false),
        Ack::Acknowledged
    );
    assert_eq!(
        acknowledgement_result([1; 32], [2; 32], false),
        Ack::ExactReplay
    );
    assert_eq!(
        acknowledgement_result([1; 32], [1; 32], true),
        Ack::ExactReplay
    );
}
#[test]
fn native_gateway_deadline_and_custody_reject_before_queue_dispatch() {
    let fixture = Fixture::new();
    let (_dir, mut config) = credentials();
    let queue = queue();
    let runtime = fixture.runtime(&config, queue.clone());
    let expired = Instant::now();
    assert!(runtime.qualification(expired).is_err());
    assert!(runtime.admit(&request(), expired).is_err());
    assert!(runtime.pending(1, expired).is_err());
    assert!(
        runtime
            .qualification(Instant::now() + Duration::from_secs(61))
            .is_err()
    );
    assert_eq!(queue.queued_len(), 0);
    assert!(
        build_native_runtime(
            &SorafsTokenConfig::default(),
            None,
            fixture.chain.state().clone(),
            queue.clone(),
            None,
            false,
        )
        .unwrap()
        .is_none()
    );
    let missing = SorafsTokenConfig {
        enabled: true,
        ..SorafsTokenConfig::default()
    };
    assert!(matches!(
        build_native_runtime(
            &missing,
            None,
            fixture.chain.state().clone(),
            queue.clone(),
            None,
            false
        ),
        Err(StreamTokenGatewayRuntimeErrorV1::MissingProvider)
    ));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(
            &config.operator_credential,
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(
            NativeTransactions::new(
                fixture.chain.state().clone(),
                queue.clone(),
                &config,
                fixture.policy.qualification
            )
            .is_err()
        );
        fs::set_permissions(
            &config.operator_credential,
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    config.observer = config.operator.clone();
    assert!(
        NativeTransactions::new(
            fixture.chain.state().clone(),
            queue.clone(),
            &config,
            fixture.policy.qualification
        )
        .is_err()
    );
    config.observer = account(4);
    assert!(
        NativeTransactions::new(
            fixture.chain.state().clone(),
            queue.clone(),
            &config,
            fixture.policy.qualification
        )
        .is_err()
    );
    assert_eq!(queue.queued_len(), 0);
}
#[test]
fn native_gateway_signing_uses_remaining_deadline_and_exact_action_policy_role() {
    let fixture = Fixture::new();
    let (_dir, config) = credentials();
    let runtime = fixture.runtime(&config, queue());
    let instruction = MutateSorafsStreamTokenGateway {
        request: NativeRequest {
            network_id: fixture.policy.network_id,
            gateway_id: fixture.policy.qualification.gateway_id,
            expected_policy_revision: 1,
            expected_policy_digest: fixture.policy.qualification.policy_digest,
            action: Action::Expire { max_items: 1 },
        },
    };
    let budget = Duration::from_millis(250);
    let signed = runtime
        .transactions
        .sign(&instruction, false, Instant::now() + budget)
        .unwrap();
    assert_eq!(signed.authority(), &config.operator);
    assert!(signed.time_to_live().unwrap() <= budget);
    let another = runtime
        .transactions
        .sign(&instruction, false, Instant::now() + budget)
        .unwrap();
    assert_ne!(
        signed.metadata(),
        another.metadata(),
        "fresh full-width submission identity"
    );
    assert_ne!(signed.hash(), another.hash());
    assert!(
        runtime
            .transactions
            .sign(&instruction, true, Instant::now() + budget)
            .is_err()
    );
    let mut stale = instruction.clone();
    stale.request.expected_policy_revision += 1;
    assert!(
        runtime
            .transactions
            .sign(&stale, false, Instant::now() + budget)
            .is_err()
    );
    stale = instruction.clone();
    stale.request.gateway_id[0] ^= 1;
    assert!(
        runtime
            .transactions
            .sign(&stale, false, Instant::now() + budget)
            .is_err()
    );
    stale = instruction;
    stale.request.action = Action::Configure(fixture.policy.clone());
    assert!(
        runtime
            .transactions
            .sign(&stale, false, Instant::now() + budget)
            .is_err()
    );
}
struct NativeDriver {
    stopped: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<usize>>,
    committed: Arc<Mutex<Vec<SignedTransaction>>>,
}
impl NativeDriver {
    fn start(mut fixture: Fixture, queue: Arc<Queue>) -> Self {
        let state = fixture.chain.state().clone();
        let stopped = Arc::new(AtomicBool::new(false));
        let stop = stopped.clone();
        let committed = Arc::new(Mutex::new(Vec::new()));
        let observed = committed.clone();
        let worker = std::thread::spawn(move || {
            let mut applied = HashSet::new();
            while !stop.load(Ordering::Acquire) {
                let transactions = {
                    let view = state.view();
                    queue.all_transactions(&view).collect::<Vec<_>>()
                };
                for transaction in transactions {
                    let signed: SignedTransaction = transaction.external().unwrap().clone();
                    if applied.insert(signed.hash()) {
                        let mut log = observed.lock().unwrap();
                        let executed = fixture.chain.commit_at(now_ms(), vec![signed.clone()]);
                        if executed == [true] {
                            log.push(signed);
                        }
                        drop(log);
                        if executed != [true] {
                            let height = fixture.chain.height();
                            let committed = fixture.chain.committed(height);
                            let output = committed
                                .block()
                                .network_output_at(0)
                                .map(|(_, output)| &output.result);
                            assert_eq!(
                                executed,
                                [true],
                                "real native action at height {height}, sole network output: {output:?}"
                            );
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            applied.len()
        });
        Self {
            stopped,
            worker: Some(worker),
            committed,
        }
    }
    fn appends(&self) -> Vec<SignedTransaction> {
        self.committed.lock().unwrap().iter().filter(|signed| {
            matches!(signed.instructions(), Executable::Instructions(instructions)
                if instructions.iter().any(|instruction| instruction.as_any().is::<AppendSorafsStreamTokenReputationJournalEntry>()))
        }).cloned().collect()
    }
    fn finish(mut self) -> usize {
        self.stopped.store(true, Ordering::Release);
        self.worker
            .take()
            .unwrap()
            .join()
            .expect("native execution worker")
    }
}
impl Drop for NativeDriver {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            // Join even while unwinding a failed assertion; do not leak a consensus fixture worker.
            let _ = worker.join();
        }
    }
}

#[test]
fn native_gateway_provider_executes_real_admission_ack_serving_and_release_under_one_deadline() {
    let fixture = Fixture::new();
    let (_dir, config) = credentials();
    let queue = queue();
    let runtime = fixture.runtime(&config, queue.clone());
    let driver = NativeDriver::start(fixture, queue);
    let deadline = Instant::now() + Duration::from_secs(60);
    let result = (|| -> Result<(), Error> {
        assert_eq!(runtime.qualification(deadline)?, runtime.qualification);
        let request = request();
        let admitted = runtime.admit(&request, deadline)?;
        assert_eq!(admitted.record.outcome.status, Status::Accepted);
        let pending = runtime.pending(1, deadline)?;
        assert_eq!(pending.records, vec![admitted.record]);
        let proof = runtime.checked(Selector::Admission(request.clone()), deadline)?;
        let original_payload: TransactionPayload = proof
            .consume_for_reputation_delivery(
                &admitted.record,
                || runtime.time(),
                |delivery| {
                    let intent = delivery.append_intent().expect(
                        "live counted source authenticates the exact original append recipe",
                    );
                    intent.payload.clone()
                },
            )
            .map_err(|failure| {
                failure
                    .rejection()
                    .map_or(Error::Unavailable, observation_error)
            })?;
        runtime.deliver(admitted.record, deadline)?;
        let append = driver.appends();
        assert_eq!(
            append.len(),
            1,
            "one source owns one exact Append submission"
        );
        assert_eq!(append[0].authority(), &config.reputation_recorder);
        assert_eq!(append[0].payload(), &original_payload);
        let proof = runtime.checked(Selector::Admission(request.clone()), deadline)?;
        proof
            .consume_for_reputation_delivery(
                &admitted.record,
                || runtime.time(),
                |delivery| {
                    assert!(matches!(
                        delivery.disposition(),
                        Disposition::Delivered { .. }
                    ));
                    assert!(delivery.append_intent().is_none());
                    assert!(!delivery.needs_terminal_check());
                },
            )
            .map_err(|failure| {
                failure
                    .rejection()
                    .map_or(Error::Unavailable, observation_error)
            })?;
        runtime.deliver(admitted.record, deadline)?;
        assert_eq!(
            driver.appends(),
            append,
            "terminal replay cannot sign or submit again"
        );
        assert_eq!(
            runtime.acknowledge(admitted.record, deadline)?,
            Ack::Acknowledged
        );
        assert_eq!(
            runtime.confirm_serving(&request, admitted.record, deadline)?,
            admitted.record
        );
        assert_eq!(
            runtime.acknowledge(admitted.record, deadline)?,
            Ack::ExactReplay
        );
        assert_eq!(
            runtime.release_lease(admitted.record, deadline)?,
            Ack::Acknowledged
        );
        assert!(
            runtime
                .confirm_serving(&request, admitted.record, deadline)
                .is_err()
        );
        Ok(())
    })();
    let applied = driver.finish();
    result.expect("native proof-backed provider completes without renewing the enclosing deadline");
    assert!(
        applied >= 18,
        "every authority came from exact signed native execution"
    );
}

#[test]
fn native_gateway_queue_timeout_retains_only_one_exact_original_envelope() {
    let fixture = Fixture::new();
    let (_dir, config) = credentials();
    let queue = queue();
    let runtime = Arc::new(fixture.runtime(&config, queue.clone()));
    let instruction = MutateSorafsStreamTokenGateway {
        request: NativeRequest {
            network_id: fixture.policy.network_id,
            gateway_id: fixture.policy.qualification.gateway_id,
            expected_policy_revision: fixture.policy.qualification.revision,
            expected_policy_digest: fixture.policy.qualification.policy_digest,
            action: Action::Expire { max_items: 1 },
        },
    };
    let deadline = Instant::now() + Duration::from_secs(1);
    let signed = runtime
        .transactions
        .sign(&instruction, false, deadline)
        .unwrap();
    let submitter = runtime.clone();
    let submitted = signed.clone();
    let worker =
        std::thread::spawn(move || submitter.transactions.submit_and_wait(&submitted, deadline));
    // Inspect the exact original while its signed TTL is still live; the queue correctly
    // suppresses expired entries from its pending view after the operation deadline.
    let retained = loop {
        let values = {
            let view = fixture.chain.state().view();
            queue
                .all_transactions(&view)
                .map(|entry| entry.external().unwrap().clone())
                .collect::<Vec<_>>()
        };
        if !values.is_empty() || Instant::now() >= deadline {
            break values;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(worker.join().unwrap(), Err(Error::Ambiguous));
    assert_eq!(
        retained,
        vec![signed.clone()],
        "no replacement envelope after timeout"
    );
    assert_eq!(
        runtime.transactions.submit_and_wait(&signed, deadline),
        Err(Error::Unavailable)
    );
    assert_eq!(
        queue.queued_len(),
        1,
        "expired entry does not re-enter the queue"
    );
}

#[derive(Debug)]
struct ForbiddenInjectedProvider;
impl StreamTokenGatewayAdmissionProviderV1 for ForbiddenInjectedProvider {
    fn handle(&self) -> &str {
        panic!("startup must not inspect an injected provider")
    }
    fn configured_qualification(&self) -> Qualification {
        panic!("startup must not trust injected configuration pins")
    }
    fn qualification(&self, _: Instant) -> Result<Qualification, Error> {
        panic!("startup must not qualify an injected provider")
    }
    fn admit(&self, _: &Request, _: Instant) -> Result<AdmissionResult, Error> {
        panic!("startup must not admit through an injected provider")
    }
    fn pending(&self, _: u32, _: Instant) -> Result<Readback, Error> {
        panic!("startup must not reconcile an injected provider")
    }
    fn pending_for_background(
        &self,
        _: u32,
        _: Instant,
    ) -> Result<StreamTokenGatewayReconciliationReadV1, Error> {
        panic!("startup must not inspect injected background work")
    }
    fn acknowledge(&self, _: Record, _: Instant) -> Result<Ack, Error> {
        panic!("startup must not acknowledge through an injected provider")
    }
    fn release_lease(&self, _: Record, _: Instant) -> Result<Ack, Error> {
        panic!("startup must not release through an injected provider")
    }
    fn confirm_serving(&self, _: &Request, _: Record, _: Instant) -> Result<Record, Error> {
        panic!("startup must not accept an injected serving claim")
    }
}

#[test]
fn native_gateway_launch_rejects_injection_before_enabled_disabled_or_emergency_selection() {
    let fixture = Fixture::new();
    let (_dir, config) = credentials();
    let queue = queue();
    let injected: Arc<dyn StreamTokenGatewayAdmissionProviderV1> =
        Arc::new(ForbiddenInjectedProvider);
    for enabled in [false, true] {
        let qualification = fixture.policy.qualification;
        let tokens = SorafsTokenConfig {
            enabled,
            admission_native: enabled.then(|| config.clone()),
            admission_provider_handle: enabled
                .then(|| "software://sorafs/stream-admission/primary".into()),
            admission_provider_revision: enabled.then_some(qualification.revision),
            admission_provider_policy_digest: enabled.then_some(qualification.policy_digest),
            admission_max_pending: qualification.max_pending,
            admission_max_tracked_tokens: qualification.max_tracked_tokens,
            admission_lease_ttl_ms: qualification.lease_ttl_ms,
            ..SorafsTokenConfig::default()
        };
        for emergency_fast in [false, true] {
            let assemble = |injected| {
                build_native_runtime(
                    &tokens,
                    Some("native-provider-fixture"),
                    fixture.chain.state().clone(),
                    queue.clone(),
                    injected,
                    emergency_fast,
                )
            };
            assert!(matches!(
                assemble(Some(&injected)),
                Err(StreamTokenGatewayRuntimeErrorV1::UnexpectedProvider)
            ));
            let selected = assemble(None).expect("native-only launch selection");
            assert_eq!(selected.is_some(), enabled && !emergency_fast);
            if let Some(native) = selected {
                assert_eq!(native.provider.configured_qualification(), qualification);
                assert_eq!(native.reputation.configured_qualification(), qualification);
            }
            assert_eq!(
                queue.queued_len(),
                0,
                "assembly and config pins grant no live authority"
            );
            let mut unavailable = tokens.clone();
            if let Some(native) = unavailable.admission_native.as_mut() {
                native.operator_credential = config.operator_credential.with_file_name("absent");
            }
            let without_credential = build_native_runtime(
                &unavailable,
                Some("native-provider-fixture"),
                fixture.chain.state().clone(),
                queue.clone(),
                None,
                emergency_fast,
            );
            if enabled && !emergency_fast {
                assert!(matches!(
                    without_credential,
                    Err(StreamTokenGatewayRuntimeErrorV1::Admission(
                        Error::Unavailable
                    ))
                ));
            } else {
                assert!(without_credential.unwrap().is_none());
            }
            assert_eq!(queue.queued_len(), 0, "selection performs no submission");
        }
    }
}

#[test]
fn native_gateway_delivery_commits_expiry_before_returning_without_an_append() {
    let mut fixture = Fixture::with_delivery_ttl(1);
    let (_dir, config) = credentials();
    let queue = queue();
    let source_time = fixture.policy.valid_from_unix_ms + 3_000;
    let mut original = request();
    original.validated_at_unix_ms = source_time;
    original.quota.as_mut().unwrap().observed_at_epoch = source_time / 1_000;
    let admit = MutateSorafsStreamTokenGateway {
        request: NativeRequest {
            network_id: fixture.policy.network_id,
            gateway_id: fixture.policy.qualification.gateway_id,
            expected_policy_revision: fixture.policy.qualification.revision,
            expected_policy_digest: fixture.policy.qualification.policy_digest,
            action: Action::Admit(original.clone()),
        },
    };
    let signed = fixture
        .chain
        .sign(&key(2), [InstructionBox::from(admit)], source_time);
    assert_eq!(fixture.chain.commit_at(source_time, vec![signed]), [true]);
    let runtime = fixture.runtime(&config, queue.clone());
    let driver = NativeDriver::start(fixture, queue);
    let deadline = Instant::now() + Duration::from_secs(60);
    let proof = runtime
        .checked(Selector::Admission(original.clone()), deadline)
        .unwrap();
    let VerifiedReadback::Admission(result) = proof.readback() else {
        panic!("exact historical admission readback");
    };
    let record = result.record;
    proof
        .consume_for_reputation_delivery(
            &record,
            || runtime.time(),
            |delivery| {
                assert_eq!(delivery.disposition(), &Disposition::Pending);
                assert!(delivery.needs_terminal_check());
                assert!(delivery.append_intent().is_none());
            },
        )
        .unwrap();
    runtime.deliver(record, deadline).unwrap();
    let proof = runtime
        .checked(Selector::Admission(original), deadline)
        .unwrap();
    proof
        .consume_for_reputation_delivery(
            &record,
            || runtime.time(),
            |delivery| {
                assert!(matches!(
                    delivery.disposition(),
                    Disposition::Expired { .. }
                ));
                assert!(delivery.append_intent().is_none());
                assert!(!delivery.needs_terminal_check());
            },
        )
        .unwrap();
    assert_eq!(
        runtime.acknowledge(record, deadline).unwrap(),
        Ack::ExactReplay
    );
    runtime.deliver(record, deadline).unwrap();
    assert!(
        driver.appends().is_empty(),
        "eligibility never authorized an expired Append"
    );
    assert!(
        driver.finish() >= 9,
        "expiry and its terminal readback used actual signed execution"
    );
}

#[test]
fn native_gateway_recorder_custody_rejects_missing_unsafe_and_substituted_credentials() {
    let fixture = Fixture::new();
    let (_dir, config) = credentials();
    let queue = queue();
    let mut cases = Vec::new();
    let mut missing = config.clone();
    missing.reputation_recorder_credential = config
        .reputation_recorder_credential
        .with_file_name("absent");
    cases.push(("missing recorder credential", missing));
    for account in [config.operator.clone(), config.observer.clone(), account(5)] {
        let mut changed = config.clone();
        changed.reputation_recorder = account;
        cases.push(("colliding or mismatched recorder account", changed));
    }
    for path in [
        config.operator_credential.clone(),
        config.observer_credential.clone(),
    ] {
        let mut changed = config.clone();
        changed.reputation_recorder_credential = path;
        cases.push(("colliding recorder credential path", changed));
    }
    for (label, changed) in cases {
        assert!(
            NativeTransactions::new(
                fixture.chain.state().clone(),
                queue.clone(),
                &changed,
                fixture.policy.qualification
            )
            .is_err(),
            "{label}"
        );
        assert_eq!(
            queue.queued_len(),
            0,
            "custody rejection precedes queue access"
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(
            &config.reputation_recorder_credential,
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(
            NativeTransactions::new(
                fixture.chain.state().clone(),
                queue.clone(),
                &config,
                fixture.policy.qualification
            )
            .is_err()
        );
        fs::set_permissions(
            &config.reputation_recorder_credential,
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    // Hard-link aliases violate the shared custody owner on every supported platform, even
    // when account and bytes are correct and the credential file otherwise remains private.
    let alias = config
        .reputation_recorder_credential
        .with_file_name("recorder-alias");
    fs::hard_link(&config.reputation_recorder_credential, &alias).unwrap();
    assert!(
        NativeTransactions::new(
            fixture.chain.state().clone(),
            queue.clone(),
            &config,
            fixture.policy.qualification
        )
        .is_err()
    );
    fs::remove_file(alias).unwrap();
    assert_eq!(queue.queued_len(), 0);
    assert!(
        NativeTransactions::new(
            fixture.chain.state().clone(),
            queue,
            &config,
            fixture.policy.qualification
        )
        .is_ok(),
        "valid independent custody remains usable after negative cases"
    );
}

#[test]
fn native_gateway_delivery_rejects_substitution_permission_drift_and_original_deadline() {
    let fixture = Fixture::new();
    let (_dir, config) = credentials();
    let queue = queue();
    let runtime = fixture.runtime(&config, queue.clone());
    let driver = NativeDriver::start(fixture, queue.clone());
    let deadline = Instant::now() + Duration::from_secs(60);
    let request = request();
    let admitted = runtime.admit(&request, deadline).unwrap();
    let queued_before = queue.queued_len();
    let mut substituted = admitted.record;
    substituted.serving_attempt_id[0] ^= 1;
    assert!(runtime.deliver(substituted, deadline).is_err());
    let expired = Instant::now();
    assert_eq!(
        runtime.deliver(admitted.record, expired),
        Err(Error::Unavailable)
    );
    assert_eq!(
        queue.queued_len(),
        queued_before,
        "rejected source and expired enclosing deadline perform no observer submission"
    );
    assert!(driver.appends().is_empty());
    let revoke = Revoke::account_permission(
        Permission::from(CanRecordSorafsReputationJournal),
        account(4),
    );
    let signed = iroha_data_model::transaction::TransactionBuilder::new(
        *runtime.state.network_id_ref(),
        account(4),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([revoke])
    .try_sign(key(4).private_key())
    .unwrap();
    runtime
        .transactions
        .submit_and_wait(&signed, deadline)
        .unwrap();
    assert!(
        runtime.deliver(admitted.record, deadline).is_err(),
        "current recorder permission is checked after actual finalized revocation"
    );
    assert!(
        driver.appends().is_empty(),
        "neither historical source authority nor a new Check can revive revoked signing permission"
    );
    driver.finish();
}

#[test]
fn native_gateway_consume_refusal_retries_original_check_before_one_capture_sign_and_submit() {
    use crate::native_check_binding::complete_check_with;
    use iroha_core::execution_attempt::ExecutionAttemptError;
    use std::cell::Cell;

    let fixture = Fixture::new();
    let state = fixture.chain.state().clone();
    let (_dir, config) = credentials();
    let queue = queue();
    let runtime = fixture.runtime(&config, queue.clone());
    let driver = NativeDriver::start(fixture, queue);
    let deadline = Instant::now() + Duration::from_secs(60);
    let request = request();
    let admitted = runtime
        .admit(&request, deadline)
        .expect("real native Admit");
    let proof = runtime
        .checked(Selector::Admission(request), deadline)
        .expect("original finalized signed Admission Check");
    assert_eq!(proof.deadline(), deadline);
    let committed_before = driver.committed.lock().unwrap().len();
    assert!(driver.appends().is_empty());
    let pool = state.ivm_execution_budget();
    let original_limit = pool.limit_bytes();
    let retained = pool.reserved_bytes();
    let samples = Cell::new(0);
    let captures = Cell::new(0);
    let signs = Cell::new(0);
    let submits = Cell::new(0);
    let consume = |proof: Verified| {
        proof.consume_for_reputation_delivery(
            &admitted.record,
            || {
                samples.set(samples.get() + 1);
                runtime.time()
            },
            |delivery| {
                captures.set(captures.get() + 1);
                assert!(matches!(delivery.disposition(), Disposition::Pending));
                assert!(!delivery.needs_terminal_check());
                assert!(delivery.append_intent().is_some());
                signs.set(signs.get() + 1);
                runtime
                    .transactions
                    .sign_reputation_delivery(&delivery, deadline)
            },
        )
    };
    pool.set_limit_bytes(0);
    let failed = consume(proof)
        .err()
        .expect("final authenticated consume refuses on the original State pool");
    let signed_check = failed.signed_transaction().clone();
    assert_eq!(failed.deadline(), deadline);
    assert_eq!(
        (samples.get(), captures.get(), signs.get(), submits.get()),
        (0, 0, 0, 0)
    );
    assert_eq!(
        pool.reserved_bytes(),
        retained,
        "refused replay releases only transient owners"
    );
    let mut waits = 0;
    let signed_append = complete_check_with(
        Err(failed),
        |failure| {
            assert_eq!(failure.signed_transaction(), &signed_check);
            assert_eq!(failure.deadline(), deadline);
            let verified = failure.into_pending().verify_finalized(|| runtime.time())?;
            consume(verified)
        },
        Instant::now,
        |failure, delay| {
            waits += 1;
            assert_eq!(delay, Duration::from_millis(1));
            assert_eq!(failure.signed_transaction(), &signed_check);
            assert_eq!(failure.deadline(), deadline);
            let ExecutionAttemptError::Deferred(original) = failure.error() else {
                panic!("original local source refusal");
            };
            assert!(matches!(
                original.allocation_refusal(),
                Some(iroha_allocation::AllocationRefusal::ExceedsLimit { limit_bytes: 0, .. })
            ));
            assert_eq!(
                (samples.get(), captures.get(), signs.get(), submits.get()),
                (0, 0, 0, 0)
            );
            assert_eq!(driver.committed.lock().unwrap().len(), committed_before);
            assert!(driver.appends().is_empty());
            assert_eq!(pool.reserved_bytes(), retained);
            pool.set_limit_bytes(original_limit);
        },
    )
    .unwrap_or_else(|_| panic!("same original Check retries after original capacity is restored"))
    .expect("the one completed signing callback succeeds");
    assert_eq!(waits, 1);
    assert_eq!(
        (samples.get(), captures.get(), signs.get(), submits.get()),
        (1, 1, 1, 0)
    );
    assert_eq!(driver.committed.lock().unwrap().len(), committed_before);
    assert!(driver.appends().is_empty(), "retry never submits an Append");
    assert!(
        pool.reserved_bytes() < retained,
        "consumed Check releases its last original binding owner"
    );
    submits.set(submits.get() + 1);
    runtime
        .transactions
        .submit_and_wait(&signed_append, deadline)
        .expect("submit only the completed callback's exact envelope");
    assert_eq!((captures.get(), signs.get(), submits.get()), (1, 1, 1));
    assert_eq!(driver.appends(), vec![signed_append]);
    assert_eq!(driver.committed.lock().unwrap().len(), committed_before + 1);
    driver.finish();
}

#[test]
fn native_background_idle_does_not_sign_and_revocation_is_not_idle() {
    let mut fixture = Fixture::new();
    let (_dir, config) = credentials();
    let queue = queue();
    let runtime = fixture.runtime(&config, queue.clone());
    let height = fixture.chain.height();
    let owners = Arc::strong_count(fixture.chain.state());
    for _ in 0..2 {
        assert!(matches!(
            runtime.pending_for_background(4, Instant::now() + Duration::from_secs(60)),
            Ok(StreamTokenGatewayReconciliationReadV1::Idle)
        ));
    }
    assert_eq!(runtime.transactions.sign_calls.load(Ordering::Relaxed), 0);
    assert_eq!(queue.queued_len(), 0);
    assert_eq!(fixture.chain.height(), height);
    assert_eq!(Arc::strong_count(fixture.chain.state()), owners);
    assert!(
        runtime
            .pending_for_background(0, Instant::now() + Duration::from_secs(60))
            .is_err()
    );
    assert!(runtime.pending_for_background(4, Instant::now()).is_err());

    let revoke = Revoke::account_permission(
        Permission::from(CanCheckSorafsStreamTokenGateway {
            gateway_id: fixture.policy.qualification.gateway_id,
        }),
        account(3),
    );
    let now = now_ms();
    let signed = fixture
        .chain
        .sign(&key(3), [InstructionBox::from(revoke)], now);
    assert_eq!(fixture.chain.commit_at(now, vec![signed]), [true]);
    assert!(
        runtime
            .pending_for_background(4, Instant::now() + Duration::from_secs(60))
            .is_err(),
        "a genuinely revoked observer must fail fresh preparation despite an empty outbox"
    );
    assert_eq!(runtime.transactions.sign_calls.load(Ordering::Relaxed), 0);
    assert_eq!(queue.queued_len(), 0);
}

#[test]
fn native_background_recovers_external_pending_and_keeps_startup_checks_signed() {
    let mut fixture = Fixture::new();
    let (_dir, config) = credentials();
    let queue = queue();
    let runtime = Arc::new(fixture.runtime(&config, queue.clone()));
    assert!(matches!(
        runtime.pending_for_background(4, Instant::now() + Duration::from_secs(60)),
        Ok(StreamTokenGatewayReconciliationReadV1::Idle)
    ));
    assert_eq!(runtime.transactions.sign_calls.load(Ordering::Relaxed), 0);

    // Commit through the separate chain owner, bypassing this runtime's local admission path.
    // A previous idle poll must not cache away another replica's durable recovery work.
    let original = request();
    let source_time = original.validated_at_unix_ms;
    let admit = MutateSorafsStreamTokenGateway {
        request: NativeRequest {
            network_id: fixture.policy.network_id,
            gateway_id: fixture.policy.qualification.gateway_id,
            expected_policy_revision: fixture.policy.qualification.revision,
            expected_policy_digest: fixture.policy.qualification.policy_digest,
            action: Action::Admit(original),
        },
    };
    let signed = fixture
        .chain
        .sign(&key(2), [InstructionBox::from(admit)], source_time);
    assert_eq!(fixture.chain.commit_at(source_time, vec![signed]), [true]);
    let driver = NativeDriver::start(fixture, queue);
    let capture = StreamTokenAdmissionCaptureV1::try_new(
        runtime.handle().to_owned(),
        runtime.qualification,
        4,
        Duration::from_secs(60),
        runtime.clone(),
        runtime.clone(),
    )
    .unwrap();
    assert_eq!(
        runtime.transactions.sign_calls.load(Ordering::Relaxed),
        1,
        "mandatory startup qualification still signs even before background polling"
    );
    let before_recovery = runtime.transactions.sign_calls.load(Ordering::Relaxed);
    assert_eq!(
        capture.reconcile_background().unwrap(),
        StreamTokenReconciliationOutcomeV1::Reconciled(1)
    );
    assert!(
        runtime.transactions.sign_calls.load(Ordering::Relaxed) > before_recovery,
        "pending recovery signs full native Checks and acknowledgement"
    );
    assert_eq!(
        driver.appends().len(),
        1,
        "one genuine original callback is delivered"
    );
    let after_recovery = runtime.transactions.sign_calls.load(Ordering::Relaxed);
    assert_eq!(
        capture.reconcile_background().unwrap(),
        StreamTokenReconciliationOutcomeV1::Idle
    );
    assert_eq!(
        runtime.transactions.sign_calls.load(Ordering::Relaxed),
        after_recovery
    );

    // Mandatory startup/explicit reconciliation still proves an empty prefix on chain.
    assert_eq!(capture.reconcile_pending().unwrap(), 0);
    assert_eq!(
        runtime.transactions.sign_calls.load(Ordering::Relaxed),
        after_recovery + 1
    );
    capture
        .validate_expected_binding(
            runtime.handle(),
            runtime.qualification,
            4,
            Duration::from_secs(60),
        )
        .unwrap();
    assert_eq!(
        runtime.transactions.sign_calls.load(Ordering::Relaxed),
        after_recovery + 2,
        "independent Torii preflight qualification remains a signed Check"
    );
    driver.finish();
}
