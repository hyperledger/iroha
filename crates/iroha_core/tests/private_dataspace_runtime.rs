//! A runtime catalog addition must become an executable native private lane after finalization.
//! Global blocks use the production certified-chain harness. The private block carries a real
//! exact-quorum BLS certificate over the production admission result, then enters the normal
//! lane store and global merge. No lane state or execution result is installed by this test.

use std::{
    collections::BTreeSet,
    num::NonZeroU32,
    sync::{Arc, OnceLock},
    time::Duration,
};

use iroha_config::parameters::actual;
use iroha_core::{
    state::{StateReadOnly, World, WorldReadOnly, derive_committee_key_id},
    sumeragi::{
        crypto::{BlsCrypto, KeyPairSigner},
        driver::{SharedCrypto, traits::BlockStore as _},
        lanes::{
            Admission, LaneBatch, LaneChainView, admit,
            evidence::verify_lane_entry,
            global::{AppliedWatch, GlobalAnchors, StatelessChecks},
            lane_height_config, lane_instance,
            merge::{self, CommittedLaneBlock, LaneBlockSource},
            registry::LaneStores,
            routing::RoutingSnapshot,
        },
        payload::{self, Assembly},
        test_chain::{CertifiedTestChain, Signers, TestChainConfig},
    },
};
use iroha_crypto::{Algorithm, KeyPair, bls_normal_pop_prove};
use iroha_data_model::{
    HasMetadata as _, Registrable,
    account::{Account, AccountId},
    alias_setup::{
        AccountAliasName, AccountAliasRoleV1, AccountProvisionV1, AliasAccountIntentV1,
        AliasDataSpaceIntentV1, AliasDataspaceBootstrapGrantV1, AliasIntentV1,
        AliasLeaseAcquisitionV1, AliasPlanDispositionV1, AliasQuoteGuardV1, ResolvedAccountAliasV1,
    },
    asset::{AssetBalancePolicy, AssetDefinition, AssetDefinitionId, AssetId},
    block::ExternalExecutionContext,
    consensus::{ConsensusKeyRecord, ConsensusKeyRole, ConsensusKeyStatus},
    domain::Domain,
    isi::{
        InstructionBox, Mint, Register, SetKeyValue, SetParameter, alias_setup::EnsureAlias,
        consensus_keys::RegisterConsensusKey,
    },
    nexus::{
        DataSpaceMetadata, LaneCatalog, LaneConfig, LaneLifecycleParameterV1, LaneVisibility,
        NexusCatalogTransitionV1, RuntimeDataSpaceAdditionV1, RuntimeLaneManifestV1,
    },
    parameter::{
        Parameter,
        system::{SumeragiConsensusMode, SumeragiNposParameters},
    },
    transaction::{
        FeeChargeKind, FeeChargeLimit, FeePaymentIntent, SignedTransaction, TransactionBuilder,
        TransactionEntrypoint,
    },
};
use iroha_executor_data_model::permission::{
    governance::CanManageConsensusKeys, parameter::CanSetParameters,
};
use iroha_model_base::{domain::DomainId, name::Name, peer::PeerId, topology::LaneId};
use iroha_primitives::{json::Json, numeric::Quantity};
use iroha_sumeragi::{
    availability::{PayloadAuthoring, PayloadBytes},
    crypto::{Signer as _, form_qc},
    message::{BlockHeader, Vote, VoteKind},
    preimage::payload_hash,
    types::{ControlWitness, Hash32, SIGNATURE_LEN, Signature},
};
use mv::storage::StorageReadOnly as _;

const PRIVATE_LANE: LaneId = LaneId::new(2);
const GENESIS_MS: u64 = 10_000;
const INITIAL_XOR: u64 = 1_000_000;

/// Bind the real lane store after signed genesis establishes its network identity.
#[derive(Default)]
struct DeferredLaneStores(OnceLock<Arc<LaneStores>>);

impl LaneBlockSource for DeferredLaneStores {
    fn tip(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
    ) -> Result<Option<u64>, iroha_core::execution_attempt::ExecutionAttemptError<std::io::Error>>
    {
        self.0
            .get()
            .map_or(Ok(None), |stores| stores.tip(lane, incarnation))
    }

    fn block(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
        height: u64,
    ) -> Result<
        Option<CommittedLaneBlock>,
        iroha_core::execution_attempt::ExecutionAttemptError<std::io::Error>,
    > {
        self.0
            .get()
            .map_or(Ok(None), |stores| stores.block(lane, incarnation, height))
    }

    fn wait_for(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
        height: u64,
        timeout: Duration,
    ) -> Result<bool, iroha_core::execution_attempt::ExecutionAttemptError<std::io::Error>> {
        self.0.get().map_or(Ok(false), |stores| {
            stores.wait_for(lane, incarnation, height, timeout)
        })
    }
}

fn commit_success(chain: &mut CertifiedTestChain, transaction: SignedTransaction, phase: &str) {
    let results = chain.commit(vec![transaction]);
    let committed = chain.committed(chain.height());
    let failures = committed
        .block()
        .execution_outputs()
        .iter()
        .enumerate()
        .filter(|(_, output)| output.result().is_err())
        .map(|(index, output)| (index, output.result()))
        .collect::<Vec<_>>();
    assert_eq!(
        results,
        vec![true],
        "{phase}: native failed outputs {failures:?}"
    );
}

fn sign_paid(
    chain: &CertifiedTestChain,
    key: &KeyPair,
    instructions: impl IntoIterator<Item = InstructionBox>,
    created_ms: u64,
) -> SignedTransaction {
    let fee_asset =
        AssetDefinitionId::parse_address_literal(&chain.state().view().nexus().fees.fee_asset_id)
            .expect("the signed network fee asset");
    let intent = FeePaymentIntent::authority(
        vec![FeeChargeLimit::new(
            FeeChargeKind::Nexus,
            fee_asset,
            Quantity::from(1_000_u64),
        )],
        None,
    );
    let mut builder = TransactionBuilder::new(
        chain.network_id(),
        AccountId::new(key.public_key().clone()),
        intent,
    );
    builder.set_creation_time(Duration::from_millis(created_ms));
    builder
        .with_instructions(instructions)
        .sign(key.private_key())
}

#[test]
fn runtime_private_dataspace_executes_concrete_work_after_certified_activation() {
    let owner_key = KeyPair::from_seed(vec![0x51; 32], Algorithm::Ed25519);
    let owner = AccountId::new(owner_key.public_key().clone());
    let governance_key = KeyPair::from_seed(vec![0x52; 32], Algorithm::Ed25519);
    let governance = AccountId::new(governance_key.public_key().clone());
    let fee_asset =
        AssetDefinitionId::parse_address_literal(&actual::Nexus::default().fees.fee_asset_id)
            .expect("default network XOR asset");
    let mut validators = (0x61..=0x64)
        .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
        .collect::<Vec<_>>();
    validators.sort_by_key(|key| PeerId::new(key.public_key().clone()));
    let domain_id = DomainId::try_new("records", "private-lane").expect("private domain");
    let accounts = std::iter::once(owner.clone())
        .chain(std::iter::once(governance.clone()))
        .chain(
            validators
                .iter()
                .map(|key| AccountId::new(key.public_key().clone())),
        )
        .map(|id| Account::new(id.clone()).build(&id));
    let mut world = World::with([Domain::new(domain_id.clone()).build(&owner)], accounts, []);
    // Initial governance authority authorizes ordinary native key registration in genesis.
    world.account_permissions_mut_for_testing().insert(
        governance.clone(),
        BTreeSet::from([CanManageConsensusKeys.into(), CanSetParameters.into()]),
    );
    let deferred = Arc::new(DeferredLaneStores::default());
    let mut config = TestChainConfig::new(world, GENESIS_MS);
    config.genesis_key = governance_key.clone();
    config.consensus_mode = SumeragiConsensusMode::Npos;
    config.genesis_parameters.push(Parameter::Custom(
        SumeragiNposParameters::default().into_custom_parameter(),
    ));
    config.validator_keys = Some(validators.clone());
    config.lane_blocks = deferred.clone();
    config.genesis_instructions = validators
        .iter()
        .map(|key| {
            let id = derive_committee_key_id(key.public_key());
            RegisterConsensusKey {
                id: id.clone(),
                record: ConsensusKeyRecord {
                    id,
                    public_key: key.public_key().clone(),
                    pop: Some(bls_normal_pop_prove(key.private_key()).expect("validator PoP")),
                    activation_height: 1,
                    expiry_height: None,
                    replaces: None,
                    status: ConsensusKeyStatus::Active,
                },
            }
            .into()
        })
        .collect();
    config.genesis_instructions.push(
        Register::asset_definition(AssetDefinition::numeric(
            fee_asset.clone(),
            "xor".to_owned(),
            AssetBalancePolicy::Global,
            None,
        ))
        .into(),
    );
    for payer in [&governance, &owner] {
        config.genesis_instructions.push(
            Mint::asset_quantity(INITIAL_XOR, AssetId::new(fee_asset.clone(), payer.clone()))
                .into(),
        );
    }
    let baseline = LaneCatalog::new(
        NonZeroU32::new(2).unwrap(),
        vec![
            LaneConfig::default(),
            LaneConfig {
                id: LaneId::new(1),
                alias: "retained".into(),
                ..LaneConfig::default()
            },
        ],
    )
    .expect("baseline catalog");
    let mut nexus = actual::Nexus::default();
    nexus.configured_lane_catalog = baseline.clone();
    nexus.lane_catalog = baseline.clone();
    nexus.lane_config = actual::LaneConfig::from_catalog(&baseline);
    config.nexus = Some(nexus);
    let mut chain = CertifiedTestChain::start(config).expect("certified genesis");
    {
        let view = chain.state().view();
        for key in &validators {
            let pop = bls_normal_pop_prove(key.private_key()).expect("original validator PoP");
            for role in [ConsensusKeyRole::Validator, ConsensusKeyRole::Committee] {
                assert!(
                    view.world().consensus_keys().iter().any(|(id, record)| {
                        id == &record.id
                            && id.role == role
                            && record.public_key == *key.public_key()
                            && record.is_live_at(1, 0, 0)
                            && record.pop.as_deref() == Some(pop.as_slice())
                    }),
                    "native genesis must retain both global and participant credentials for the same peer"
                );
            }
        }
    }
    let dir = tempfile::tempdir().expect("lane-store directory");
    let bls = Arc::new(BlsCrypto::new());
    let crypto: SharedCrypto = bls.clone();
    let chain_id = chain.state().view().chain_id().to_string();
    let stores = Arc::new(LaneStores::new(
        dir.path().to_path_buf(),
        chain.network_id(),
        chain_id.clone(),
        Arc::clone(&crypto),
        chain.execution_budget(),
        Arc::new(
            iroha_core::sumeragi::test_chain::TestLaneStoreAuthorities::new(
                Arc::clone(chain.state()),
                bls,
            ),
        ),
    ));
    assert!(deferred.0.set(Arc::clone(&stores)).is_ok());

    let bootstrap = AliasDataspaceBootstrapGrantV1::try_new("private-lane", owner.clone())
        .expect("bootstrap name");
    let dataspace = bootstrap.dataspace.dataspace_id;
    let transition = {
        let view = chain.state().view();
        assert!(view.world().sumeragi_lanes().lane(PRIVATE_LANE).is_none());
        let members = validators
            .iter()
            .map(|key| {
                norito::json!({
                    "validator": (AccountId::new(key.public_key().clone()).to_string()),
                    "peer_id": (PeerId::new(key.public_key().clone()).to_string())
                })
            })
            .collect::<Vec<_>>();
        NexusCatalogTransitionV1 {
            version: NexusCatalogTransitionV1::VERSION,
            expected_catalog_hash: LaneLifecycleParameterV1::catalog_hash(
                &view.nexus().lane_catalog,
            ),
            expected_incarnation_root: LaneLifecycleParameterV1::incarnation_root(
                &LaneLifecycleParameterV1::canonical_incarnations(
                    &view.nexus().lane_catalog,
                    &chain.state().lane_incarnations_snapshot(),
                )
                .expect("current incarnations"),
            ),
            expected_runtime_catalog_hash: view.runtime_catalog_hash().expect("current overlay"),
            dataspace_additions: vec![RuntimeDataSpaceAdditionV1 {
                descriptor: DataSpaceMetadata {
                    id: dataspace,
                    alias: "private-lane".into(),
                    description: None,
                    fault_tolerance: 1,
                },
                manifest_hash: bootstrap.name_hash,
            }],
            lane_additions: vec![LaneConfig {
                id: PRIVATE_LANE,
                alias: "private-lane".into(),
                dataspace_id: dataspace,
                visibility: LaneVisibility::Restricted,
                ..LaneConfig::default()
            }],
            manifest_additions: vec![RuntimeLaneManifestV1 {
                lane_id: PRIVATE_LANE,
                manifest: Json::new(norito::json!({
                    "lane": "private-lane", "version": 1,
                    "validators": members, "quorum": 3
                })),
            }],
        }
    };
    let catalog_tx = sign_paid(
        &chain,
        &governance_key,
        [InstructionBox::from(SetParameter::new(Parameter::Custom(
            transition.into_custom_parameter().expect("catalog request"),
        )))],
        GENESIS_MS + 1,
    );
    commit_success(&mut chain, catalog_tx, "catalog registration");
    let record = chain
        .state()
        .view()
        .world()
        .sumeragi_lanes()
        .lane(PRIVATE_LANE)
        .cloned()
        .expect("finalized runtime lane");
    assert_eq!(record.created_at, 2);
    assert_eq!(record.active_from, 4);
    assert_eq!(record.dataspace, dataspace);
    assert_eq!(record.committee.len(), 4);
    assert!(!record.admits_anchor(3));
    assert!(record.admits_anchor(4));
    let bootstrap_tx = sign_paid(
        &chain,
        &governance_key,
        [InstructionBox::from(SetParameter::new(Parameter::Custom(
            bootstrap
                .clone()
                .into_custom_parameter()
                .expect("bootstrap grant"),
        )))],
        GENESIS_MS + 2,
    );
    commit_success(&mut chain, bootstrap_tx, "owner bootstrap");
    let alias_intents = [
        AliasIntentV1::Dataspace(AliasDataSpaceIntentV1 {
            dataspace: bootstrap.dataspace.clone(),
            owner: owner.clone(),
        }),
        AliasIntentV1::AccountAlias(AliasAccountIntentV1 {
            alias: ResolvedAccountAliasV1::new(
                AccountAliasName::try_new("admin", None::<&str>, "private-lane")
                    .expect("scoped admin alias"),
                dataspace,
            ),
            target_account: owner.clone(),
            provision: AccountProvisionV1::Existing,
            role: AccountAliasRoleV1::Additional,
        }),
    ];
    let alias_instructions = {
        let view = chain.state().view();
        let payer_asset = AssetId::new(fee_asset.clone(), governance.clone());
        assert!(
            view.world()
                .assets()
                .get(&payer_asset)
                .expect("operator XOR")
                .as_ref()
                < &Quantity::from(INITIAL_XOR),
            "native operator phases pay real Nexus fees"
        );
        alias_intents
            .iter()
            .map(|intent| {
                let target = intent.target();
                let policy = iroha_core::sns::policy_by_id(
                    view.world(),
                    iroha_core::alias_setup::target_suffix_id(&target),
                )
                .expect("canonical native SNS policy")
                .expect("configured namespace");
                let selector = iroha_core::alias_setup::selector_for_resolved_alias_target(&target)
                    .expect("canonical namespace selector");
                let rent =
                    iroha_data_model::sns::pricing::quote_lease_price(&policy, &selector, 1, None)
                        .expect("actual native lease price");
                assert_eq!(rent.payment_asset, fee_asset);
                InstructionBox::from(EnsureAlias::new(
                    intent.clone(),
                    AliasLeaseAcquisitionV1::new(1, None),
                    AliasQuoteGuardV1 {
                        expected_policy_version: policy.policy_version,
                        expected_payment_asset: rent.payment_asset,
                        max_amount: rent.amount,
                        valid_until_ms: GENESIS_MS + 60_000,
                    },
                ))
            })
            .collect::<Vec<_>>()
    };
    let alias_tx = sign_paid(&chain, &owner_key, alias_instructions, GENESIS_MS + 3);
    commit_success(
        &mut chain,
        alias_tx,
        "paid namespace and admin alias registration",
    );
    assert_eq!(chain.height(), 4);
    let owner_before_private = {
        let view = chain.state().view();
        for intent in &alias_intents {
            assert_eq!(
                iroha_core::alias_setup::classify_alias_intent_with_endorsement_policy(
                    view.world(),
                    &view.nexus().dataspace_catalog,
                    intent,
                    GENESIS_MS + 4,
                    view.nexus().endorsement.quorum > 0,
                )
                .expect("finalized native alias state"),
                AliasPlanDispositionV1::NoOp
            );
        }
        let owner_asset = AssetId::new(fee_asset.clone(), owner.clone());
        view.world()
            .assets()
            .get(&owner_asset)
            .expect("owner XOR after rent")
            .as_ref()
            .clone()
    };

    let metadata_key: Name = "private_result".parse().unwrap();
    let metadata_value = Json::new(norito::json!({"stored": true}));
    let private_tx = sign_paid(
        &chain,
        &owner_key,
        [InstructionBox::from(SetKeyValue::domain(
            domain_id.clone(),
            metadata_key.clone(),
            metadata_value.clone(),
        ))],
        GENESIS_MS + 3,
    );
    {
        let view = chain.state().view();
        let routing =
            RoutingSnapshot::of(&view).expect("completed original private-root routing read");
        assert_eq!(
            routing
                .inputs(view.world())
                .route(private_tx.payload(), 4)
                .expect("completed original pre-activation private route"),
            None,
            "concrete private work cannot escape to the global lane before activation"
        );
        assert_eq!(
            routing
                .inputs(view.world())
                .route(private_tx.payload(), 5)
                .expect("completed original activated private route"),
            Some(PRIVATE_LANE)
        );
    }
    let anchor = chain
        .state()
        .view()
        .latest_block_hash()
        .expect("activation block");
    let anchors = GlobalAnchors::new(
        Arc::clone(chain.state()),
        Arc::new(AppliedWatch::new(4, Some(anchor))),
    );
    let history = LaneChainView::default();
    let payload = LaneBatch {
        anchor_height: 4,
        anchor_hash: anchor,
        transactions: vec![private_tx.clone()],
    }
    .to_payload();
    let height_config = lane_height_config(&record).expect("native lane configuration");
    let Admission::Valid(result) = admit(
        &record,
        &anchors,
        &history,
        &StatelessChecks::new(chain.network_id()),
        &height_config,
        &payload,
    )
    .expect("production lane admission") else {
        panic!("committed anchor is available")
    };
    let instance = lane_instance(&*crypto, &chain.network_id(), &chain_id, &record);
    let header = BlockHeader {
        instance,
        epoch: height_config.epoch.id,
        height: 1,
        origin_view: 0,
        parent_hash: Hash32(record.merged.block_hash),
        parent_result: Hash32(record.merged.result),
        payload_hash: payload_hash(&*crypto, &payload),
        availability_digest: Hash32::ZERO,
        payload_len: u32::try_from(payload.len()).unwrap(),
        proposer: 0,
        skipped_leaders: Vec::new(),
        control_witness: ControlWitness::empty(),
    };
    let budget = chain.execution_budget();
    let mut original = iroha_allocation::ChargedBuffer::new(payload.len(), &budget).unwrap();
    original.append(&payload).unwrap();
    let payload = PayloadBytes::from_charged(original, &budget)
        .unwrap_or_else(|_| panic!("original private lane payload backing/control"));
    let author = validators
        .iter()
        .map(|key| KeyPairSigner::new(key).expect("BLS author"))
        .find(|signer| height_config.committee.get(0) == Some(signer.public_key()))
        .expect("original lane author");
    let authored = PayloadAuthoring::new(header, payload)
        .complete(instance, &height_config, &budget, &*crypto, &author)
        .unwrap_or_else(|(_, error)| panic!("original private lane availability: {error:?}"));
    drop(authored.codeword);
    let block = authored.body;
    let votes = validators
        .iter()
        .take(3)
        .map(|key| {
            let signer = KeyPairSigner::new(key).expect("BLS signer");
            let mut vote = Vote {
                kind: VoteKind::Commit,
                instance,
                epoch: height_config.epoch.id,
                height: 1,
                view: 0,
                block_hash: block.hash(&*crypto),
                result: result.hash(),
                signer: height_config
                    .committee
                    .index_of(signer.public_key())
                    .expect("lane member"),
                sig: Signature([0; SIGNATURE_LEN]),
            };
            vote.sig = signer.sign(&vote.preimage());
            vote
        })
        .collect::<Vec<_>>();
    let qc = form_qc(
        &*crypto,
        height_config.committee.n(),
        &votes.iter().collect::<Vec<_>>(),
    )
    .expect("real exact-quorum lane certificate");
    verify_lane_entry(
        &record,
        &chain.network_id(),
        &chain_id,
        &anchors,
        &history,
        &record.merged,
        &block,
        &qc,
    )
    .expect("authenticate and reproduce actual lane admission");
    let mut forged = qc.clone();
    forged.agg_sig.0[0] ^= 1;
    assert!(
        verify_lane_entry(
            &record,
            &chain.network_id(),
            &chain_id,
            &anchors,
            &history,
            &record.merged,
            &block,
            &forged
        )
        .is_err(),
        "a forged certificate cannot qualify the private work"
    );
    stores
        .store(PRIVATE_LANE, &record.incarnation)
        .expect("open lane store")
        .append(&block, &qc)
        .expect("persist authenticated lane frame");
    let proposal = {
        let view = chain.state().view();
        let parent = view
            .latest_block()
            .expect("parent history read completes")
            .expect("activation parent");
        let merges = merge::propose(&view, &*stores, 5)
            .expect("authenticated private lane storage available");
        let cadence = Duration::from_millis(
            view.world()
                .consensus_schedule()
                .ready(5)
                .expect("authenticated successor schedule")
                .params
                .block_time_ms,
        );
        drop(view);
        payload::assemble_with_merges(
            chain.state(),
            Assembly {
                parent: &parent,
                view: 0,
                cadence,
            },
            &[],
            &merges,
        )
        .expect("production private-lane-only proposal")
    };
    chain.commit_proposal(proposal, Signers::Quorum, ControlWitness::empty());
    assert_eq!(chain.height(), 5);
    let committed = chain.committed(5);
    let entrypoint_hash = TransactionEntrypoint::External(private_tx).hash();
    assert_eq!(committed.block().merged_entrypoint_count(), 1);
    assert!(
        committed
            .block()
            .execution_context()
            .expect("original execution context")
            .external
            .contains(&ExternalExecutionContext::new(
                entrypoint_hash,
                PRIVATE_LANE,
                dataspace
            )),
        "the certified result must bind the exact work to its private lane and dataspace"
    );
    let view = chain.state().view();
    let owner_asset = AssetId::new(fee_asset.clone(), owner.clone());
    assert!(
        view.world()
            .assets()
            .get(&owner_asset)
            .expect("owner XOR after private execution")
            .as_ref()
            < &owner_before_private,
        "merged private work must pay its real native fee after alias rent"
    );
    assert_eq!(
        view.world()
            .domain(&domain_id)
            .expect("private domain")
            .metadata()
            .get(&metadata_key),
        Some(&metadata_value),
        "the globally finalized merge must execute the concrete private write"
    );
    assert_eq!(
        view.world()
            .sumeragi_lanes()
            .lane(PRIVATE_LANE)
            .unwrap()
            .merged
            .height,
        1
    );
}
