//! A native retail activation executed in its physical dataspace lane yields finalized
//! activation evidence only through native certified finality (`specs/sumeragi.md` §12.7).
//!
//! The global chain is the production certified test chain. The activation travels in a real
//! lane block with an exact-quorum BLS lane certificate, is merged and executed by the global
//! chain, and is then authenticated by the portable `SumeragiFinalityVerifier` over
//! `SumeragiFinalityProof`s built from the Kura-certified frames and rooted in the signed genesis.

use std::{
    collections::BTreeSet,
    num::NonZeroU32,
    sync::{Arc, OnceLock},
    time::Duration,
};

use iroha_config::parameters::actual;
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair, bls_normal_pop_prove};
use iroha_data_model::{
    Registrable,
    account::{Account, AccountId},
    alias_setup::{
        AccountAliasName, AccountAliasRoleV1, AccountProvisionV1, AliasAccountIntentV1,
        AliasDataSpaceIntentV1, AliasDataspaceBootstrapGrantV1, AliasIntentV1,
        AliasLeaseAcquisitionV1, AliasQuoteGuardV1, ResolvedAccountAliasV1,
    },
    asset::{
        AssetBalancePolicy, AssetDefinition, AssetDefinitionId, AssetId, RetailDailyLimitPolicyV1,
    },
    block::{
        ExternalExecutionContext,
        proofs::{TrustedBlockProofAnchor, TrustedBlockProofAnchorError},
        retail_activation_proof::{
            RetailActivationProofError, verify_finalized_retail_activation_v1,
        },
    },
    consensus::{ConsensusKeyRecord, ConsensusKeyStatus},
    domain::Domain,
    isi::{
        InstructionBox, Mint, Register, SetParameter, alias_setup::EnsureAlias,
        consensus_keys::RegisterConsensusKey, retail_daily_limit::ActivateRetailDailyLimitV1,
    },
    nexus::{
        DataSpaceMetadata, LaneCatalog, LaneConfig, LaneLifecycleParameterV1, LaneVisibility,
        NexusCatalogTransitionV1, RuntimeDataSpaceAdditionV1, RuntimeLaneManifestV1,
    },
    parameter::{
        Parameter,
        system::{SumeragiConsensusMode, SumeragiNposParameters},
    },
    sumeragi::{PROTOCOL_VERSION, SumeragiFootprint, SumeragiStatus},
    sumeragi_finality::{
        FinalityValidator, SumeragiFinalityProof, SumeragiFinalityVerifier, VerifiedSumeragiBlock,
        authenticated_genesis,
    },
    sumeragi_lanes::{SumeragiLaneRecord, SumeragiLaneRoute},
    transaction::{
        FeeChargeKind, FeeChargeLimit, FeePaymentIntent, SignedTransaction, TransactionBuilder,
        TransactionEntrypoint,
    },
};
use iroha_executor_data_model::permission::{
    governance::CanManageConsensusKeys, parameter::CanSetParameters,
};
use iroha_model_base::{
    domain::DomainId,
    peer::PeerId,
    topology::{DataSpaceId, LaneId},
};
use iroha_primitives::{
    json::Json,
    numeric::{NumericSpec, Quantity},
};
use iroha_sumeragi::{
    availability::{AvailableBody, PayloadAuthoring, PayloadBytes},
    crypto::{Signer as _, form_qc},
    message::{BlockHeader, Qc, Vote, VoteKind},
    preimage::payload_hash,
    types::{ControlWitness, Hash32, SIGNATURE_LEN, Signature},
};

use crate::{
    state::{
        StateReadOnly, World, WorldReadOnly, derive_committee_key_id,
        retail_daily_limit_state as retail_state,
    },
    sumeragi::{
        certified_chain::CertifiedChain,
        crypto::{BlsCrypto, KeyPairSigner},
        driver::{SharedCrypto, traits::BlockStore as _},
        finality::{build_attestation, build_proof},
        lanes::{
            Admission, LaneBatch, LaneChainView, LaneResult, admit,
            evidence::verify_lane_entry,
            global::{AppliedWatch, GlobalAnchors, StatelessChecks},
            lane_height_config, lane_instance, lane_policy,
            merge::{self, CommittedLaneBlock, LaneBlockSource},
            registry::LaneStores,
            routing::RoutingSnapshot,
        },
        node::NodeIdentity,
        payload::{self, Assembly},
        test_chain::{CertifiedTestChain, Signers, TestChainConfig, TestLaneStoreAuthorities},
    },
};

const RETAIL_LANE: LaneId = LaneId::new(2);
const GENESIS_MS: u64 = 10_000;
const INITIAL_XOR: u64 = 1_000_000;
/// Global height at which the activation is merged and executed.
const ACTIVATION_HEIGHT: u64 = 6;

/// Bind the real lane store after signed genesis establishes its network identity.
#[derive(Default)]
struct DeferredLaneStores(OnceLock<Arc<LaneStores>>);

impl LaneBlockSource for DeferredLaneStores {
    fn tip(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
    ) -> Result<Option<u64>, crate::execution_attempt::ExecutionAttemptError<std::io::Error>> {
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
        crate::execution_attempt::ExecutionAttemptError<std::io::Error>,
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
    ) -> Result<bool, crate::execution_attempt::ExecutionAttemptError<std::io::Error>> {
        self.0.get().map_or(Ok(false), |stores| {
            stores.wait_for(lane, incarnation, height, timeout)
        })
    }
}

/// Fixed test-only custody: the retail owner, network governance and the four validators.
struct Keys {
    owner: KeyPair,
    governance: KeyPair,
    reserve: AccountId,
    validators: Vec<KeyPair>,
}

impl Keys {
    fn new() -> Self {
        let mut validators = (0x61..=0x64)
            .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
            .collect::<Vec<_>>();
        validators.sort_by_key(|key| PeerId::new(key.public_key().clone()));
        Self {
            owner: KeyPair::from_seed(vec![0x71; 32], Algorithm::Ed25519),
            governance: KeyPair::from_seed(vec![0x72; 32], Algorithm::Ed25519),
            reserve: AccountId::new(
                KeyPair::from_seed(vec![0x73; 32], Algorithm::Ed25519)
                    .public_key()
                    .clone(),
            ),
            validators,
        }
    }

    fn owner(&self) -> AccountId {
        AccountId::new(self.owner.public_key().clone())
    }

    fn governance(&self) -> AccountId {
        AccountId::new(self.governance.public_key().clone())
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

/// Signed NPoS genesis: the owner's `retail.bpng` domain, fee funding and validator keys.
fn start_chain(
    keys: &Keys,
    domain: &DomainId,
    lanes: Arc<DeferredLaneStores>,
) -> CertifiedTestChain {
    let (owner, governance) = (keys.owner(), keys.governance());
    let fee_asset =
        AssetDefinitionId::parse_address_literal(&actual::Nexus::default().fees.fee_asset_id)
            .expect("default network XOR asset");
    let accounts = [owner.clone(), governance.clone(), keys.reserve.clone()]
        .into_iter()
        .chain(
            keys.validators
                .iter()
                .map(|key| AccountId::new(key.public_key().clone())),
        )
        .map(|id| Account::new(id.clone()).build(&id));
    let mut world = World::with([Domain::new(domain.clone()).build(&owner)], accounts, []);
    world.account_permissions_mut_for_testing().insert(
        governance.clone(),
        BTreeSet::from([CanManageConsensusKeys.into(), CanSetParameters.into()]),
    );
    let mut config = TestChainConfig::new(world, GENESIS_MS);
    config.genesis_key = keys.governance.clone();
    config.consensus_mode = SumeragiConsensusMode::Npos;
    config.genesis_parameters.push(Parameter::Custom(
        SumeragiNposParameters::default().into_custom_parameter(),
    ));
    config.validator_keys = Some(keys.validators.clone());
    config.lane_blocks = lanes;
    config.genesis_instructions = keys
        .validators
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
    for payer in [governance, owner] {
        config
            .genesis_instructions
            .push(Mint::asset_quantity(INITIAL_XOR, AssetId::new(fee_asset.clone(), payer)).into());
    }
    let baseline = LaneCatalog::new(
        NonZeroU32::new(2).expect("two baseline lanes"),
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
    CertifiedTestChain::start(config).expect("certified genesis")
}

/// The runtime catalog addition of the `bpng` dataspace and its restricted fixed lane.
fn catalog_transition(
    chain: &CertifiedTestChain,
    keys: &Keys,
    bootstrap: &AliasDataspaceBootstrapGrantV1,
) -> NexusCatalogTransitionV1 {
    let view = chain.state().view();
    let dataspace = bootstrap.dataspace.dataspace_id;
    let members = keys
        .validators
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
        expected_catalog_hash: LaneLifecycleParameterV1::catalog_hash(&view.nexus().lane_catalog),
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
                alias: "bpng".into(),
                description: None,
                fault_tolerance: 1,
            },
            manifest_hash: bootstrap.name_hash,
        }],
        lane_additions: vec![LaneConfig {
            id: RETAIL_LANE,
            alias: "bpng".into(),
            dataspace_id: dataspace,
            visibility: LaneVisibility::Restricted,
            ..LaneConfig::default()
        }],
        manifest_additions: vec![RuntimeLaneManifestV1 {
            lane_id: RETAIL_LANE,
            manifest: Json::new(norito::json!({
                "lane": "bpng", "version": 1,
                "validators": members, "quorum": 3
            })),
        }],
    }
}

/// Paid `EnsureAlias` instructions for the dataspace namespace and the owner's admin alias.
fn alias_instructions(
    chain: &CertifiedTestChain,
    bootstrap: &AliasDataspaceBootstrapGrantV1,
    owner: &AccountId,
) -> Vec<InstructionBox> {
    let intents = [
        AliasIntentV1::Dataspace(AliasDataSpaceIntentV1 {
            dataspace: bootstrap.dataspace.clone(),
            owner: owner.clone(),
        }),
        AliasIntentV1::AccountAlias(AliasAccountIntentV1 {
            alias: ResolvedAccountAliasV1::new(
                AccountAliasName::try_new("admin", None::<&str>, "bpng")
                    .expect("scoped admin alias"),
                bootstrap.dataspace.dataspace_id,
            ),
            target_account: owner.clone(),
            provision: AccountProvisionV1::Existing,
            role: AccountAliasRoleV1::Additional,
        }),
    ];
    let view = chain.state().view();
    intents
        .iter()
        .map(|intent| {
            let target = intent.target();
            let policy = crate::sns::policy_by_id(
                view.world(),
                crate::alias_setup::target_suffix_id(&target),
            )
            .expect("canonical native SNS policy")
            .expect("configured namespace");
            let selector = crate::alias_setup::selector_for_resolved_alias_target(&target)
                .expect("canonical namespace selector");
            let rent =
                iroha_data_model::sns::pricing::quote_lease_price(&policy, &selector, 1, None)
                    .expect("actual native lease price");
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
        .collect()
}

/// Heights 2..=5: register the `bpng` dataspace lane, bootstrap and name it, and route the
/// one-shot activation to it. Returns the dataspace and the routing transaction's entry.
fn register_retail_lane(
    chain: &mut CertifiedTestChain,
    keys: &Keys,
) -> (DataSpaceId, HashOf<TransactionEntrypoint>) {
    let owner = keys.owner();
    let bootstrap =
        AliasDataspaceBootstrapGrantV1::try_new("bpng", owner.clone()).expect("bootstrap name");
    let transition = catalog_transition(chain, keys, &bootstrap);
    let catalog_tx = sign_paid(
        chain,
        &keys.governance,
        [InstructionBox::from(SetParameter::new(Parameter::Custom(
            transition.into_custom_parameter().expect("catalog request"),
        )))],
        GENESIS_MS + 1,
    );
    commit_success(chain, catalog_tx, "catalog registration");
    let bootstrap_tx = sign_paid(
        chain,
        &keys.governance,
        [InstructionBox::from(SetParameter::new(Parameter::Custom(
            bootstrap
                .clone()
                .into_custom_parameter()
                .expect("bootstrap grant"),
        )))],
        GENESIS_MS + 2,
    );
    commit_success(chain, bootstrap_tx, "owner bootstrap");
    let aliases = alias_instructions(chain, &bootstrap, &owner);
    let alias_tx = sign_paid(chain, &keys.owner, aliases, GENESIS_MS + 3);
    commit_success(
        chain,
        alias_tx,
        "paid namespace and admin alias registration",
    );
    let mut policy = lane_policy(chain.state().view().world())
        .expect("completed original routing metadata read")
        .expect("catalog installed the lane policy");
    policy.routes.push(SumeragiLaneRoute {
        lane: RETAIL_LANE,
        account: None,
        instruction: Some("ActivateRetailDailyLimitV1".to_owned()),
    });
    let route_tx = sign_paid(
        chain,
        &keys.governance,
        [InstructionBox::from(SetParameter::new(Parameter::Custom(
            policy.into_custom_parameter(),
        )))],
        GENESIS_MS + 4,
    );
    let route_entry = TransactionEntrypoint::External(route_tx.clone()).hash();
    commit_success(chain, route_tx, "activation lane route");
    assert_eq!(chain.height(), ACTIVATION_HEIGHT - 1);
    (bootstrap.dataspace.dataspace_id, route_entry)
}

/// An exact-quorum Commit certificate of the lane committee over `body` and `result`.
fn lane_certificate(
    keys: &Keys,
    crypto: &BlsCrypto,
    config: &iroha_sumeragi::types::HeightConfig,
    instance: Hash32,
    body: &AvailableBody,
    result: &LaneResult,
) -> Qc {
    let votes = keys
        .validators
        .iter()
        .take(3)
        .map(|key| {
            let signer = KeyPairSigner::new(key).expect("BLS signer");
            let mut vote = Vote {
                kind: VoteKind::Commit,
                instance,
                epoch: config.epoch.id,
                height: 1,
                view: 0,
                block_hash: body.hash(crypto),
                result: result.hash(),
                signer: config
                    .committee
                    .index_of(signer.public_key())
                    .expect("lane member"),
                sig: Signature([0; SIGNATURE_LEN]),
            };
            vote.sig = signer.sign(&vote.preimage());
            vote
        })
        .collect::<Vec<_>>();
    form_qc(
        crypto,
        config.committee.n(),
        &votes.iter().collect::<Vec<_>>(),
    )
    .expect("real exact-quorum lane certificate")
}

/// Author, certify, authenticate and store lane height one carrying `transaction`.
fn store_lane_block(
    chain: &CertifiedTestChain,
    stores: &LaneStores,
    keys: &Keys,
    record: &SumeragiLaneRecord,
    transaction: SignedTransaction,
) {
    let crypto = BlsCrypto::new();
    let chain_id = chain.state().view().chain_id().to_string();
    let anchor_height = ACTIVATION_HEIGHT - 1;
    let anchor = chain
        .state()
        .view()
        .latest_block_hash()
        .expect("route block");
    let anchors = GlobalAnchors::new(
        Arc::clone(chain.state()),
        Arc::new(AppliedWatch::new(anchor_height, Some(anchor))),
    );
    let history = LaneChainView::default();
    let lane_payload = LaneBatch {
        anchor_height,
        anchor_hash: anchor,
        transactions: vec![transaction],
    }
    .to_payload();
    let config = lane_height_config(record).expect("native lane configuration");
    let Admission::Valid(result) = admit(
        record,
        &anchors,
        &history,
        &StatelessChecks::new(chain.network_id()),
        &config,
        &lane_payload,
    )
    .expect("production lane admission") else {
        panic!("committed anchor is available")
    };
    let instance = lane_instance(&crypto, &chain.network_id(), &chain_id, record);
    let header = BlockHeader {
        instance,
        epoch: config.epoch.id,
        height: 1,
        origin_view: 0,
        parent_hash: Hash32(record.merged.block_hash),
        parent_result: Hash32(record.merged.result),
        payload_hash: payload_hash(&crypto, &lane_payload),
        availability_digest: Hash32::ZERO,
        payload_len: u32::try_from(lane_payload.len()).expect("bounded lane payload"),
        proposer: 0,
        skipped_leaders: Vec::new(),
        control_witness: ControlWitness::empty(),
    };
    let budget = chain.state().ivm_execution_budget();
    let mut original = iroha_allocation::ChargedBuffer::new(lane_payload.len(), &budget)
        .expect("charged lane payload");
    original.append(&lane_payload).expect("lane payload bytes");
    let lane_payload = PayloadBytes::from_charged(original, &budget)
        .unwrap_or_else(|_| panic!("original lane payload backing/control"));
    let author = keys
        .validators
        .iter()
        .map(|key| KeyPairSigner::new(key).expect("BLS author"))
        .find(|signer| config.committee.get(0) == Some(signer.public_key()))
        .expect("original lane author");
    let authored = PayloadAuthoring::new(header, lane_payload)
        .complete(instance, &config, &budget, &crypto, &author)
        .unwrap_or_else(|(_, error)| panic!("original lane availability: {error:?}"));
    drop(authored.codeword);
    let body = authored.body;
    let qc = lane_certificate(keys, &crypto, &config, instance, &body, &result);
    verify_lane_entry(
        record,
        &chain.network_id(),
        &chain_id,
        &anchors,
        &history,
        &record.merged,
        &body,
        &qc,
    )
    .expect("authenticate and reproduce actual lane admission");
    stores
        .store(RETAIL_LANE, &record.incarnation)
        .expect("open lane store")
        .append(&body, &qc)
        .expect("persist authenticated lane frame");
}

/// Commit the global block that merges the stored lane block.
fn merge_lane(chain: &mut CertifiedTestChain, stores: &LaneStores) {
    let proposal = {
        let view = chain.state().view();
        let parent = view
            .latest_block()
            .expect("parent history read completes")
            .expect("route parent");
        let merges = merge::propose(&view, stores, ACTIVATION_HEIGHT)
            .expect("authenticated retail lane storage available");
        let cadence = Duration::from_millis(
            view.world()
                .consensus_schedule()
                .ready(ACTIVATION_HEIGHT)
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
        .expect("production lane-only proposal")
    };
    chain.commit_proposal(proposal, Signers::Quorum, ControlWitness::empty());
    assert_eq!(chain.height(), ACTIVATION_HEIGHT);
}

/// The actual chain up to the activation block and the independently approved coordinates.
struct ActivatedChain {
    chain: CertifiedTestChain,
    owner: AccountId,
    governance: AccountId,
    domain: DomainId,
    definition: AssetDefinitionId,
    dataspace: DataSpaceId,
    policy: RetailDailyLimitPolicyV1,
    route_entry: HashOf<TransactionEntrypoint>,
    activation_entry: HashOf<TransactionEntrypoint>,
    // Keeps the lane-store directory alive for as long as the chain reads its lane frames.
    _lane_dir: tempfile::TempDir,
}

/// Execute one owner-signed activation through a certified lane block merged by the chain.
fn activated_chain() -> ActivatedChain {
    let keys = Keys::new();
    let (owner, governance) = (keys.owner(), keys.governance());
    let domain = DomainId::try_new("retail", "bpng").expect("retail domain");
    let deferred = Arc::new(DeferredLaneStores::default());
    let mut chain = start_chain(&keys, &domain, Arc::clone(&deferred));
    let lane_dir = tempfile::tempdir().expect("lane-store directory");
    let bls = Arc::new(BlsCrypto::new());
    let crypto: SharedCrypto = bls.clone();
    let stores = Arc::new(LaneStores::new(
        lane_dir.path().to_path_buf(),
        chain.network_id(),
        chain.state().view().chain_id().to_string(),
        crypto,
        chain.state().ivm_execution_budget(),
        Arc::new(TestLaneStoreAuthorities::new(
            Arc::clone(chain.state()),
            bls,
        )),
    ));
    assert!(deferred.0.set(Arc::clone(&stores)).is_ok());
    let (dataspace, route_entry) = register_retail_lane(&mut chain, &keys);
    let definition =
        AssetDefinitionId::derive_from_components(domain.clone(), "kina".parse().expect("name"));
    let policy = RetailDailyLimitPolicyV1 {
        asset_definition_id: definition.clone(),
        physical_dataspace: dataspace,
        revision: 1,
        daily_cap: Quantity::from(5_u32),
        identity_issuer: owner.clone(),
        identity_issuer_public_key: keys.owner.public_key().clone(),
        monetary_issuer_account: owner.clone(),
        reserve_account: keys.reserve.clone(),
        institutional_exceptions: BTreeSet::new(),
    };
    let activation_tx = sign_paid(
        &chain,
        &keys.owner,
        [InstructionBox::from(ActivateRetailDailyLimitV1 {
            definition: AssetDefinition::new(
                definition.clone(),
                "Kina".to_owned(),
                NumericSpec::fractional(2),
                AssetBalancePolicy::DataspaceRestricted,
                Some(domain.clone()),
            ),
            policy: policy.clone(),
        })],
        GENESIS_MS + 5,
    );
    let activation_entry = TransactionEntrypoint::External(activation_tx.clone()).hash();
    let record = {
        let view = chain.state().view();
        assert_eq!(
            RoutingSnapshot::of(&view)
                .expect("completed original routing snapshot")
                .inputs(view.world())
                .route(activation_tx.payload(), ACTIVATION_HEIGHT)
                .expect("completed original routing read"),
            Some(RETAIL_LANE),
            "the activation executes only in its physical dataspace lane"
        );
        view.world()
            .sumeragi_lanes()
            .lane(RETAIL_LANE)
            .cloned()
            .expect("finalized runtime lane")
    };
    store_lane_block(&chain, &stores, &keys, &record, activation_tx);
    merge_lane(&mut chain, &stores);
    let committed = chain.committed(ACTIVATION_HEIGHT);
    let input_index = committed
        .block()
        .network_input_hashes()
        .position(|entry| entry == activation_entry)
        .expect("original activation was merged into the certified block");
    let (_, output) = committed
        .block()
        .network_output_at(u32::try_from(input_index).expect("bounded activation input index"))
        .expect("original activation has its exact typed Network output");
    assert!(
        output.result.as_ref().is_ok(),
        "original merged activation failed native execution: {:?}",
        output.result
    );
    ActivatedChain {
        chain,
        owner,
        governance,
        domain,
        definition,
        dataspace,
        policy,
        route_entry,
        activation_entry,
        _lane_dir: lane_dir,
    }
}

/// The trust root a client selects independently: the signed genesis and its own committee.
fn genesis_verifier(chain: &CertifiedTestChain) -> SumeragiFinalityVerifier {
    let committee = authenticated_genesis(chain.genesis())
        .map(|genesis| genesis.into_parts().0)
        .expect("signed genesis epoch")
        .committee
        .into_iter()
        .map(|member| FinalityValidator {
            public_key: member.validator.public_key().clone(),
            proof_of_possession: member.proof_of_possession,
        })
        .collect();
    SumeragiFinalityVerifier::new(
        chain.genesis(),
        &chain.state().view().chain_id().to_string(),
        committee,
    )
    .expect("independently selected signed genesis")
}

/// Verify every served proof contiguously and return it with its authenticated block.
fn verified_prefix(
    chain: &CertifiedTestChain,
) -> Vec<(SumeragiFinalityProof, VerifiedSumeragiBlock)> {
    let view = chain.state().view();
    let mut verifier = genesis_verifier(chain);
    (1..=chain.height())
        .map(|height| {
            let proof = build_proof(&view, height).expect("served native proof");
            let verified = verifier.verify(&proof).expect("contiguous native finality");
            (proof, verified)
        })
        .collect()
}

/// Zero-based prefix index of a one-based height.
fn at(height: u64) -> usize {
    usize::try_from(height - 1).expect("test height fits usize")
}

#[test]
fn finalized_activation_evidence_is_anchored_on_native_certified_finality() {
    let fixture = activated_chain();
    let chain = &fixture.chain;
    let committed = chain.committed(ACTIVATION_HEIGHT);
    assert_eq!(committed.block().merged_entrypoint_count(), 1);
    assert!(
        committed
            .block()
            .execution_context()
            .expect("original execution context")
            .external
            .contains(&ExternalExecutionContext::new(
                fixture.activation_entry,
                RETAIL_LANE,
                fixture.dataspace
            )),
        "the certified result binds the activation to its physical dataspace lane"
    );
    let view = chain.state().view();
    assert_eq!(
        retail_state::policy_for_exact(view.world(), &fixture.definition, fixture.dataspace)
            .expect("native policy state"),
        Some(fixture.policy.clone())
    );
    let executed = retail_state::activation_for_exact(view.world(), &fixture.policy)
        .expect("native activation marker");

    let prefix = verified_prefix(chain);
    let (_, verified) = &prefix[at(ACTIVATION_HEIGHT)];
    let receipt = verify_finalized_retail_activation_v1(
        verified.block(),
        verified,
        fixture.activation_entry,
        &fixture.owner,
        &fixture.policy,
        &fixture.definition,
        &fixture.domain,
        fixture.dataspace,
    )
    .expect("finalized native activation");
    assert_eq!(receipt.height, ACTIVATION_HEIGHT);
    assert_eq!(receipt.block_hash, committed.block_hash());
    assert_eq!(receipt.entry_hash, fixture.activation_entry);
    assert_eq!(receipt.policy, fixture.policy);
    assert_eq!(
        receipt.activation, executed,
        "the marker derived from the certified block time is the one native execution stored"
    );

    // The node's own certified read of the same Kura frame yields the same entry anchor.
    let certified = CertifiedChain::new(&view)
        .expect("certified chain reader")
        .certified(ACTIVATION_HEIGHT)
        .expect("Kura-certified CommitQC");
    assert_eq!(
        certified
            .entry_anchor(&fixture.activation_entry)
            .expect("certified entry anchor"),
        TrustedBlockProofAnchor::from_verified_finality(
            verified.block(),
            verified,
            &fixture.activation_entry
        )
        .expect("portable entry anchor")
    );
}

#[test]
fn activation_evidence_refuses_substituted_coordinates_entries_and_carriers() {
    let fixture = activated_chain();
    let chain = &fixture.chain;
    let prefix = verified_prefix(chain);
    let verify = |verified: &VerifiedSumeragiBlock,
                  entry: HashOf<TransactionEntrypoint>,
                  owner: &AccountId,
                  policy: &RetailDailyLimitPolicyV1,
                  domain: &DomainId| {
        verify_finalized_retail_activation_v1(
            verified.block(),
            verified,
            entry,
            owner,
            policy,
            &fixture.definition,
            domain,
            fixture.dataspace,
        )
    };
    let (_, activation) = &prefix[at(ACTIVATION_HEIGHT)];
    assert_eq!(
        verify(
            activation,
            fixture.activation_entry,
            &fixture.governance,
            &fixture.policy,
            &fixture.domain
        ),
        Err(RetailActivationProofError::WrongOwner)
    );
    let mut raised_cap = fixture.policy.clone();
    raised_cap.daily_cap = Quantity::from(6_u32);
    assert_eq!(
        verify(
            activation,
            fixture.activation_entry,
            &fixture.owner,
            &raised_cap,
            &fixture.domain
        ),
        Err(RetailActivationProofError::WrongPolicy)
    );
    let other_domain = DomainId::try_new("other", "bpng").expect("other domain");
    assert_eq!(
        verify(
            activation,
            fixture.activation_entry,
            &fixture.owner,
            &fixture.policy,
            &other_domain
        ),
        Err(RetailActivationProofError::WrongPolicy)
    );
    // A certified, successful input of another instruction never qualifies, and the
    // activation entry is absent from every other certified block.
    let (_, route_block) = &prefix[at(ACTIVATION_HEIGHT - 1)];
    assert_eq!(
        verify(
            route_block,
            fixture.route_entry,
            &fixture.governance,
            &fixture.policy,
            &fixture.domain
        ),
        Err(RetailActivationProofError::WrongInstruction)
    );
    assert_eq!(
        verify(
            route_block,
            fixture.activation_entry,
            &fixture.owner,
            &fixture.policy,
            &fixture.domain
        ),
        Err(RetailActivationProofError::Finality(
            TrustedBlockProofAnchorError::EntrypointNotFound
        ))
    );

    // A changed carrier never becomes a `VerifiedSumeragiBlock`, and a rejection does not
    // advance the authenticated prefix.
    let mut verifier = genesis_verifier(chain);
    for (proof, _) in &prefix[..at(ACTIVATION_HEIGHT)] {
        verifier.verify(proof).expect("original prefix");
    }
    let (proof, _) = &prefix[at(ACTIVATION_HEIGHT)];
    for attack in 0..4 {
        let mut changed = proof.clone();
        match attack {
            0 => changed.block_header = chain.genesis().header(),
            1 => changed.block_wire.truncate(changed.block_wire.len() - 1),
            2 => changed.committee[0].proof_of_possession[0] ^= 1,
            _ => changed.committee.swap(0, 1),
        }
        assert!(verifier.verify(&changed).is_err(), "attack {attack}");
    }
    assert_eq!(
        verifier
            .verify(proof)
            .expect("the original carrier still extends the prefix")
            .header(),
        chain.committed(ACTIVATION_HEIGHT).block().header()
    );
    // A verifier rooted in another chain's signed genesis admits none of this chain's proofs.
    let foreign = CertifiedTestChain::start(TestChainConfig::new(World::default(), GENESIS_MS))
        .expect("foreign certified genesis");
    assert!(genesis_verifier(&foreign).verify(&prefix[0].0).is_err());
}

/// Print the served native finality JSON of the merging global block, which is the durable
/// tip: its proof as the harness retains it, and the challenge-bound validator attestation
/// that `build_attestation` signs over the same tip (both `norito::json` values, compact).
/// The attestation's driver status is the one a running validator reports at an idle applied
/// tip; the test chain runs no driver. `scripts/tests/fixtures/native_finality/capture.json`
/// records the command; script tests read the resulting fixtures, never invented proof bytes.
#[test]
#[ignore = "explicit deterministic fixture capture, not a qualification gate"]
fn capture_merged_lane_finality_proof_fixture() {
    let fixture = activated_chain();
    let prefix = verified_prefix(&fixture.chain);
    let (proof, verified) = &prefix[at(ACTIVATION_HEIGHT)];
    assert_eq!(verified.height(), ACTIVATION_HEIGHT);
    assert_eq!(fixture.chain.height(), ACTIVATION_HEIGHT);
    let compact = |value: norito::json::Value| {
        norito::json::to_string(&value).expect("compact finality JSON")
    };
    let json = compact(norito::json::to_value(proof).expect("proof JSON value"));

    let signer = Keys::new().validators.swap_remove(0);
    let identity = NodeIdentity {
        node_id: PeerId::new(signer.public_key().clone()),
        config_fingerprint: Hash::new(b"fixture effective consensus configuration"),
    };
    let status = SumeragiStatus {
        protocol_version: PROTOCOL_VERSION,
        config_fingerprint: identity.config_fingerprint,
        beacon_horizon: None,
        instance: fixture.chain.instance().0,
        height: ACTIVATION_HEIGHT + 1,
        view: 0,
        stage: 0,
        leader: None,
        proxy_tail: None,
        high_qc_view: None,
        level: 0,
        start_level: 0,
        t_retx_ms: 100,
        committed_height: ACTIVATION_HEIGHT,
        applied_height: ACTIVATION_HEIGHT,
        awaiting: false,
        signer: Some(signer.public_key().clone()),
        unanchored: false,
        abstaining: false,
        halted: None,
        footprint: SumeragiFootprint::default(),
    };
    let attestation = build_attestation(
        &fixture.chain.state().view(),
        status,
        &identity,
        Hash::new(b"fixture validator executable"),
        ACTIVATION_HEIGHT,
        [0xA5; 32],
        &signer,
    )
    .expect("challenge-bound durable-tip attestation");
    attestation.verify().expect("the node's own signature");
    assert_eq!(&attestation.body.finality_proof, proof);
    let attestation_json =
        compact(norito::json::to_value(&attestation).expect("attestation JSON value"));
    let served = norito::json::to_json_pretty(&attestation).expect("Torii pretty JSON");
    println!(
        "NATIVE_FINALITY_CHAIN_ID={}",
        fixture.chain.state().view().chain_id()
    );
    println!("NATIVE_FINALITY_NETWORK_ID={}", fixture.chain.network_id());
    println!("NATIVE_FINALITY_HEIGHT={ACTIVATION_HEIGHT}");
    println!("NATIVE_FINALITY_PROOF_JSON={json}");
    println!("NATIVE_FINALITY_ATTESTATION_JSON={attestation_json}");
    println!("NATIVE_FINALITY_ATTESTATION_SERVED_BYTES={}", served.len());
}
