#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
//! Release-only real-process tests for atomic private settlement.
//!
//! The ignored test deliberately uses the production wallet prover, encrypted
//! auditor capsule, Torii restricted-DA routes, and node-held BLS committee
//! keys.  There is no fixture proof, hand-made vote, or QC verification bypass.
//! The primary N=3 topology settles one public participant dataspace and two
//! restricted participant dataspaces in the same confidential atomic bundle.
//! The included release-harness entrypoint parameterizes the same production
//! workflow across N=2,3,4,8,16 and publishes only measured process evidence.

#[path = "atomic_private_settlement_observation.rs"]
mod peer_observation;
#[cfg(feature = "atomic-private-settlement-smoke")]
#[path = "atomic_private_settlement_prepared_operation.rs"]
mod prepared_operation;
use peer_observation::collect_bounded_observations;

use super::localnet_npos::npos_override_instruction;
use eyre::{Result, WrapErr, ensure, eyre};
use integration_tests::sandbox;
use iroha::{
    blocking::Client,
    client::{
        BorrowedKeyPairIdentityRequestSignerV1, Client as SdkClient,
        PrivateSettlementAuditApprovalRequestV1, PrivateSettlementAuditorCapsuleRequestV1,
        PrivateSettlementBundleReceiptResponseV1, PrivateSettlementBundleSubmitRequestV1,
        PrivateSettlementLegUploadRequestV1, PrivateSettlementLifecycleDtoV1,
    },
    data_model::{
        Level,
        account::{Account, AccountId},
        asset::{
            AssetBalancePolicy, AssetBalanceScope, AssetDefinition, AssetDefinitionId, AssetId,
        },
        block::BlockHeader,
        domain::Domain,
        isi::{
            Grant, GrantBox, InstructionBox, Log, Mint, Register, SetParameter, Transfer,
            privacy::{RegisterPrivacyProtocolActivationV1, TransitionPrivacyProtocolLifecycleV1},
            private_settlement::{
                ActivatePrivateSettlementPoolV1, FinalizeAtomicPrivateSettlementV1,
            },
            register::RegisterCommitteePeerWithPop,
            settlement::SettleAtomic,
            staking::{ActivatePublicLaneValidator, RegisterPublicLaneValidator},
        },
        nexus::{
            ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1, AtomicPrivateSettlementV1, LaneVisibility,
            PRIVATE_SETTLEMENT_MAX_RECEIPT_BYTES_V1, PrivateSettlementAuditAadV1,
            PrivateSettlementAuditEncryptionOpeningV1, PrivateSettlementAuditNoteOpeningV1,
            PrivateSettlementAuditOutputRoleV1, PrivateSettlementAuditOutputV1,
            PrivateSettlementAuditPayerAuthorizationBodyV1,
            PrivateSettlementAuditPayerAuthorizationV1, PrivateSettlementAuditPayerInputV1,
            PrivateSettlementAuditPayerSignatureV1, PrivateSettlementAuditPlaintextV1,
            PrivateSettlementAuditPolicyBodyV1, PrivateSettlementAuditPolicyV1,
            PrivateSettlementAuditViewKeyAuthorizationBodyV1,
            PrivateSettlementAuditViewKeyAuthorizationV1, PrivateSettlementAuditViewKeySignatureV1,
            PrivateSettlementAuditorV1, PrivateSettlementCapsulePaddingV1,
            PrivateSettlementCommitBundleV1, PrivateSettlementCommitteeAuthorityV1,
            PrivateSettlementDeltaV1, PrivateSettlementHybridPublicKeyV1,
            PrivateSettlementLegCommitmentV1, PrivateSettlementLegReceiptV1,
            PrivateSettlementPoolGovernanceLifecycleV1, PrivateSettlementPoolGovernanceV1,
            PrivateSettlementProofProfileV1, PrivateSettlementProofStatementV1,
            PrivateSettlementProvisionalLegMaterialV1, PrivateSettlementRouteV1,
        },
        parameter::{FastpqSourcePolicyV1, Parameter, system::SumeragiParameters},
        permission::Permission,
        prelude::{FindAssetById, FindAssets, FindPermissionsByAccountId},
        privacy::{
            PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_BYTES_V1, PrivacyActiveLifecycleV1,
            PrivacyCommitmentV1, PrivacyCompiledProfileResultV1, PrivacyEncryptedOutputV1,
            PrivacyEncryptionKeyV1, PrivacyNullifierV1, PrivacyPoolIdV1,
            PrivacyProposedLifecycleV1, PrivacyProtocolActivationRecordV1, PrivacyProtocolIdV1,
            PrivacyProtocolLifecycleV1, PrivacyRecipientIdV1, PrivacyRootV1,
        },
        query::block::prelude::FindBlocks,
        sumeragi_lanes::{SumeragiFixedLane, SumeragiLaneMember, SumeragiLanePolicy},
        transaction::{
            FeeChargeKind, FeeChargeLimit, FeePaymentIntent, SignedTransaction,
            TransactionEntrypoint,
        },
    },
};
use iroha_core::private_settlement::{
    PrivateSettlementAuditEvaluationV1, PrivateSettlementAuditorSidecarViewV1,
    PrivateSettlementSidecarLifecycleV1, approve_private_settlement_leg_v1,
};
use iroha_core_privacy::{
    privacy_engines::{
        atomic_private_settlement::{
            AtomicPrivateSettlementPreparedLegV1, AtomicPrivateSettlementProvisionalLegInputV1,
            atomic_private_settlement_audit_input_commitment_v1,
            complete_atomic_private_settlement_prepared_leg_v1,
            consume_atomic_private_settlement_wallet_bundle_v1,
            derive_atomic_private_settlement_input_nullifiers_v1,
            encode_atomic_private_settlement_wallet_bundle_v1,
            finalize_atomic_private_settlement_provisional_bundle_v1,
            plan_atomic_private_settlement_bootstrap_v1,
            prepare_atomic_private_settlement_funding_note_v1,
            prepare_atomic_private_settlement_input_openings_v1,
            prepare_atomic_private_settlement_outputs_v1,
        },
        ivm_private_note::{
            derive_ivm_private_recipient_id_v1, derive_note_authority_v1,
            ivm_private_recipient_public_key_v1,
        },
    },
    privacy_profiles::compiled_privacy_profile_v1,
};
use iroha_crypto::{Algorithm, Hash, HashOf, HybridKeyPair, KeyPair, SignatureOf};
use iroha_data_model::prelude::QueryBuilderExt;
use iroha_executor_data_model::permission::{
    governance::CanEnactGovernance, settlement::CanExecuteSettlement,
};
use iroha_genesis::GenesisTopologyEntry;
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::peer::PeerId;
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
use iroha_primitives::numeric::{NumericSpec, Quantity};
use iroha_test_network::{
    CommitteeValidatorP2pBootstrap, Network, NetworkBuilder, NetworkPeer,
    unexecuted_genesis_factory_with_post_topology,
};
use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR, SAMPLE_GENESIS_ACCOUNT_ID};
use reqwest::Url;
use std::{
    ops::Range,
    thread,
    time::{Duration, Instant},
};
use toml::{Table, Value as TomlValue};

const PARTICIPANT_COUNT: usize = 3;
const PRIMARY_PUBLIC_PARTICIPANT_ORDINAL: usize = 0;
const VALIDATORS_PER_LANE: usize = 4;
const REAL_PROCESS_VALIDATOR_WORKER_THREADS: u64 = 4;
const REAL_PROCESS_BLOCK_CADENCE: Duration = Duration::from_secs(4);
const GLOBAL_LANE_ID: u32 = 0;
const VALIDATOR_STAKE: u64 = 2_000;
const PRIVACY_GENESIS_PROPOSAL_HEIGHT: u64 = 1;
const PRIVACY_PROFILE_ACTIVATION_HEIGHT: u64 = PRIVACY_GENESIS_PROPOSAL_HEIGHT;
const PRIVATE_SETTLEMENT_MINIMUM_ACTIVATION_NOTICE_BLOCKS: u64 = 1;
const PRIVATE_SETTLEMENT_NOTICE_ACTIVATION_HEIGHT: u64 =
    PRIVACY_GENESIS_PROPOSAL_HEIGHT + PRIVATE_SETTLEMENT_MINIMUM_ACTIVATION_NOTICE_BLOCKS;
const PRIVATE_SETTLEMENT_ACTIVATION_HEIGHT: u64 =
    if PRIVACY_PROFILE_ACTIVATION_HEIGHT > PRIVATE_SETTLEMENT_NOTICE_ACTIVATION_HEIGHT {
        PRIVACY_PROFILE_ACTIVATION_HEIGHT
    } else {
        PRIVATE_SETTLEMENT_NOTICE_ACTIVATION_HEIGHT
    };
const MAX_EXPIRY_BLOCKS: u64 = 4_096;
const SIDECAR_RETENTION_BLOCKS: u64 = 4_096;
const TEST_NEXUS_LOCAL_STORAGE_BUDGET_BYTES: i64 = 1024 * 1024 * 1024;
const NEXUS_FEE_SEED_BALANCE: u64 = 10_000;
const NEXUS_FEE_SIGNED_MAXIMUM: u64 = 1;
const NEXUS_FEE_PER_PRIVATE_SETTLEMENT_CARRIER: &str = "0.001";
const TEST_STACK_BYTES: usize = 64 * 1024 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(250);
const FINALITY_TIMEOUT: Duration = Duration::from_secs(300);
const PRIVATE_SETTLEMENT_LEG_PRIVATE_MATERIAL_DOMAIN_V1: &[u8] =
    b"iroha:atomic-private-settlement:release-leg-private-material:v1\0";
const PRIVATE_SETTLEMENT_REIMBURSEMENT_SALT_DOMAIN_V1: &[u8] =
    b"iroha:atomic-private-settlement:release-reimbursement-salt:v1\0";

fn zero_hash() -> Hash {
    Hash::prehashed([0; Hash::LENGTH])
}

fn approve_all_audit_material(_: PrivateSettlementAuditEvaluationV1<'_>) -> bool {
    true
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TopologyShape {
    participants: usize,
}

impl TopologyShape {
    const fn new(participants: usize) -> Self {
        Self { participants }
    }

    const fn lane_count(self) -> usize {
        self.participants + 1
    }

    const fn global_validator_count(self) -> usize {
        VALIDATORS_PER_LANE
    }

    const fn participant_validator_count(self) -> usize {
        self.participants * VALIDATORS_PER_LANE
    }

    const fn process_count(self) -> usize {
        self.global_validator_count() + self.participant_validator_count()
    }

    fn committee_range(self, lane: usize) -> Range<usize> {
        assert!(lane < self.lane_count(), "committee lane is in range");
        let start = lane * VALIDATORS_PER_LANE;
        start..start + VALIDATORS_PER_LANE
    }

    fn participant_visibility(self, ordinal: usize) -> LaneVisibility {
        assert!(
            ordinal < self.participants,
            "participant ordinal is in range"
        );
        if ordinal == PRIMARY_PUBLIC_PARTICIPANT_ORDINAL {
            LaneVisibility::Public
        } else {
            LaneVisibility::Restricted
        }
    }

    fn participant_visibility_profile(self) -> Vec<LaneVisibility> {
        (0..self.participants)
            .map(|ordinal| self.participant_visibility(ordinal))
            .collect()
    }

    fn p2p_process_counts_by_visibility(self) -> (usize, usize) {
        let participant_visibilities = self.participant_visibility_profile();
        let public_lanes = 1 + participant_visibilities
            .iter()
            .filter(|visibility| **visibility == LaneVisibility::Public)
            .count();
        let restricted_lanes = participant_visibilities
            .iter()
            .filter(|visibility| **visibility == LaneVisibility::Restricted)
            .count();
        (
            public_lanes * VALIDATORS_PER_LANE,
            restricted_lanes * VALIDATORS_PER_LANE,
        )
    }

    fn validate(self) -> Result<()> {
        ensure!(
            matches!(self.participants, 2 | 3 | 4 | 8 | 16),
            "real-process release matrix supports N=2,3,4,8,16"
        );
        Ok(())
    }
}

fn process_peer(network: &Network, index: usize) -> &NetworkPeer {
    network
        .all_peers()
        .nth(index)
        .unwrap_or_else(|| panic!("process index {index} is in range"))
}

fn participant_dataspace_alias(ordinal: usize) -> String {
    let number = ordinal + 1;
    if ordinal == PRIMARY_PUBLIC_PARTICIPANT_ORDINAL {
        format!("public-{number}")
    } else {
        format!("private-{number}")
    }
}

fn participant_lane_alias(ordinal: usize) -> String {
    format!("lane-{}", participant_dataspace_alias(ordinal))
}

const fn visibility_config_value(visibility: LaneVisibility) -> &'static str {
    match visibility {
        LaneVisibility::Public => "public",
        LaneVisibility::Restricted => "restricted",
    }
}

#[derive(Clone)]
struct CommitteeEndpoints {
    authority: PrivateSettlementCommitteeAuthorityV1,
    endpoints: Vec<Url>,
    validator_keys: Vec<KeyPair>,
}

struct GovernedLeg {
    route: PrivateSettlementRouteV1,
    policy: PrivateSettlementAuditPolicyV1,
    governance: PrivateSettlementPoolGovernanceV1,
    auditor_signing: KeyPair,
    auditor_encryption: HybridKeyPair,
}

struct PreparedLeg {
    governed: GovernedLeg,
    prepared: AtomicPrivateSettlementPreparedLegV1,
}

struct PrivateSettlementFunding {
    opening: PrivateSettlementAuditNoteOpeningV1,
    spending_secret: [u8; 32],
    // Preserve the positive input in slot zero and the unspent reserve in slot
    // one. The native bootstrap planner maps these slots into the sorted tree.
    input_commitments: [PrivacyCommitmentV1; 2],
}

impl PrivateSettlementFunding {
    fn activation_commitments(&self) -> [PrivacyCommitmentV1; 2] {
        let mut commitments = self.input_commitments;
        commitments.sort_unstable();
        commitments
    }
}

#[derive(Clone)]
struct PrivateSettlementLegPrivateData {
    payer: KeyPair,
    recipient: KeyPair,
    amount: u128,
    memo: Vec<u8>,
}

const LEAKAGE_ACCOUNT_LEFT_I105: &str = "sorauﾛ1PｺfMﾇﾘｾﾄoﾂﾊﾔH7ZdﾘhﾚmAｸdnｳu1ｱﾄ1ｺﾋuSﾑﾀﾇﾐuHEB5DP";
const LEAKAGE_ACCOUNT_RIGHT_I105: &str = "sorauﾛ1NﾑﾅpﾐTm5Yfﾕ3ｦSヰﾏBｶA5ｻﾔｽｱｼDkDｸkVZBｳﾈyｽﾜヰ9NA1NP";
const LEAKAGE_ASSET_LEFT: &str = "4Zust3cNxfvUrJRuFjSMmNXho9rF";
const LEAKAGE_ASSET_RIGHT: &str = "7fnqfbvxnCke21nA2Zy1C3KktDdi";

fn nexus_fee_asset_definition_id() -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(
        DomainId::try_new("universal", "universal").expect("Nexus fee domain"),
        "xor".parse().expect("Nexus fee asset name"),
    )
}

fn bounded_nexus_fee() -> FeePaymentIntent {
    FeePaymentIntent::authority(
        vec![FeeChargeLimit::new(
            FeeChargeKind::Nexus,
            nexus_fee_asset_definition_id(),
            Quantity::from(NEXUS_FEE_SIGNED_MAXIMUM),
        )],
        None,
    )
}

fn sponsor_nexus_fee_balance(client: &Client) -> Result<Quantity> {
    let asset = client
        .client()
        .query_single(FindAssetById::new(AssetId::new(
            nexus_fee_asset_definition_id(),
            ALICE_ID.clone(),
        )))?;
    Ok(asset.value().clone())
}

fn ensure_exact_private_settlement_carrier_fee(
    before: &Quantity,
    after: &Quantity,
    context: &str,
) -> Result<()> {
    let expected: Quantity = NEXUS_FEE_PER_PRIVATE_SETTLEMENT_CARRIER
        .parse()
        .expect("canonical private-settlement carrier fee");
    let charged = before
        .checked_sub(after)
        .wrap_err_with(|| format!("compute {context} Nexus fee"))?;
    ensure!(
        charged == expected,
        "{context} charged {charged}, expected exactly {expected}"
    );
    Ok(())
}

fn genesis_private_note_proposal() -> PrivacyProtocolActivationRecordV1 {
    compiled_privacy_profile_v1(PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1)
        .expect("compiled IVM private-note profile")
        .activation_record(PrivacyProtocolLifecycleV1::Proposed(
            PrivacyProposedLifecycleV1 {
                proposed_at_height: PRIVACY_GENESIS_PROPOSAL_HEIGHT,
            },
        ))
}

fn genesis_private_note_active_lifecycle() -> PrivacyProtocolLifecycleV1 {
    PrivacyProtocolLifecycleV1::Active(PrivacyActiveLifecycleV1 {
        proposed_at_height: PRIVACY_GENESIS_PROPOSAL_HEIGHT,
        activated_at_height: PRIVACY_PROFILE_ACTIVATION_HEIGHT,
        state_since_height: PRIVACY_PROFILE_ACTIVATION_HEIGHT,
    })
}

fn hash(seed: u8) -> Hash {
    Hash::prehashed([seed.max(1); Hash::LENGTH])
}

fn bytes(seed: u8) -> [u8; 32] {
    [seed.max(1); 32]
}

fn validator_authority_keypair(index: usize) -> KeyPair {
    let mut seed = vec![0_u8; 32];
    seed[0] = 0xC1;
    seed[1..9].copy_from_slice(&u64::try_from(index).unwrap_or(u64::MAX).to_le_bytes());
    KeyPair::try_from_seed(seed, Algorithm::Ed25519).expect("validator authority key")
}

fn stake_asset_definition_id() -> AssetDefinitionId {
    nexus_fee_asset_definition_id()
}

fn settlement_domain_id() -> DomainId {
    DomainId::try_new("settlement", "universal").expect("settlement domain")
}

fn participant_domain_bootstrap() -> [InstructionBox; 2] {
    [
        Register::domain(Domain::new(settlement_domain_id())).into(),
        Transfer::domain(
            SAMPLE_GENESIS_ACCOUNT_ID.clone(),
            settlement_domain_id(),
            ALICE_ID.clone(),
        )
        .into(),
    ]
}

fn cbdc_asset_definition_id(ordinal: usize) -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(
        settlement_domain_id(),
        format!("cbdc{}", ordinal + 1)
            .parse()
            .expect("CBDC asset name"),
    )
}

fn participant_lane_policy(
    shape: TopologyShape,
    committee_validator_entries: &[GenesisTopologyEntry],
) -> SumeragiLanePolicy {
    assert_eq!(
        committee_validator_entries.len(),
        shape.participant_validator_count()
    );
    let lane_params = SumeragiParameters {
        block_cadence_ms: std::num::NonZeroU64::new(
            u64::try_from(REAL_PROCESS_BLOCK_CADENCE.as_millis())
                .expect("signed lane cadence fits u64"),
        )
        .expect("signed lane cadence is positive"),
        ..SumeragiParameters::default()
    };
    let mut policy = SumeragiLanePolicy::for_chain(
        lane_params,
        iroha_sumeragi::availability::recommended_data_availability_layout(),
    );
    policy.fixed = committee_validator_entries
        .chunks_exact(VALIDATORS_PER_LANE)
        .enumerate()
        .map(|(ordinal, entries)| {
            let mut committee = entries
                .iter()
                .map(|entry| SumeragiLaneMember {
                    peer: entry.peer.clone(),
                    pop: entry
                        .pop_bytes()
                        .expect("participant lane PoP is valid hex")
                        .expect("participant lane member carries a PoP"),
                })
                .collect::<Vec<_>>();
            committee.sort_by(|left, right| left.peer.cmp(&right.peer));
            SumeragiFixedLane {
                lane: LaneId::new(u32::try_from(ordinal + 1).expect("lane fits u32")),
                dataspace: DataSpaceId::new(
                    u64::try_from(ordinal + 1).expect("dataspace fits u64"),
                ),
                committee,
            }
        })
        .collect();
    policy
        .validate()
        .expect("canonical fixed participant lanes");
    policy
}

fn genesis_post_topology(
    shape: TopologyShape,
    topology: &[PeerId],
    committee_validator_entries: &[GenesisTopologyEntry],
) -> Vec<Vec<InstructionBox>> {
    assert_eq!(topology.len(), shape.process_count());
    assert_eq!(
        topology.iter().collect::<BTreeSet<_>>().len(),
        topology.len(),
        "global and participant committees must have disjoint process identities"
    );
    assert_eq!(
        committee_validator_entries.len(),
        shape.participant_validator_count()
    );
    let committee_validator_peers = committee_validator_entries
        .iter()
        .map(|entry| entry.peer.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        &topology[shape.global_validator_count()..],
        committee_validator_peers.as_slice(),
        "committee-validator PoP entries must match the participant-process suffix"
    );
    let stake_definition = stake_asset_definition_id();
    // Participant processes are proof-bound WSV peer identities with Committee
    // keys. They are deliberately registered after the exact signed global
    // topology and never become global Sumeragi voters.
    let mut universal = committee_validator_entries
        .iter()
        .map(|entry| {
            let pop = entry
                .pop_bytes()
                .expect("committee-validator topology PoP must be valid hex")
                .expect("committee-validator topology entry must carry a PoP");
            RegisterCommitteePeerWithPop::new(entry.peer.clone(), pop).into()
        })
        .collect::<Vec<InstructionBox>>();
    universal.extend([
        Register::domain(Domain::new(
            DomainId::try_new("universal", "universal").expect("Nexus fee domain"),
        ))
        .into(),
        Register::domain(Domain::new(
            DomainId::try_new("nexus", "universal").expect("nexus domain"),
        ))
        .into(),
        Register::asset_definition(AssetDefinition::new(
            stake_definition.clone(),
            "XOR".to_owned(),
            NumericSpec::fractional(9),
            AssetBalancePolicy::Global,
            None,
        ))
        .into(),
        Mint::asset_quantity(
            NEXUS_FEE_SEED_BALANCE,
            AssetId::new(nexus_fee_asset_definition_id(), ALICE_ID.clone()),
        )
        .into(),
        Grant::account_permission(Permission::from(CanEnactGovernance), ALICE_ID.clone()).into(),
    ]);
    // This static fixture domain is original signed bootstrap state. Raw domain
    // registration is genesis-only; the exact transfer authorizes Alice to
    // register the required CBDCs later through ordinary paid transactions.
    universal.extend(participant_domain_bootstrap());
    let mut stake_funding = Vec::<InstructionBox>::with_capacity(topology.len());
    for (index, _) in topology.iter().enumerate() {
        let validator = AccountId::new(validator_authority_keypair(index).public_key().clone());
        universal.push(Register::account(Account::new(validator.clone())).into());
        stake_funding.push(
            Mint::asset_quantity(
                VALIDATOR_STAKE,
                AssetId::new(stake_definition.clone(), validator),
            )
            .into(),
        );
    }
    // Keep the grant and governed registration in one genesis transaction.
    // Genesis pre-exec evaluates its transactions independently, so a grant in
    // an earlier transaction is not an authorization source for a later one.
    // Instruction order inside this transaction makes the grant visible before
    // the profile is registered and explicitly activated at canonical height one.
    // Both instructions execute the ordinary governance/profile validation path.
    universal
        .push(RegisterPrivacyProtocolActivationV1::new(genesis_private_note_proposal()).into());
    universal.push(
        TransitionPrivacyProtocolLifecycleV1::new(
            PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,
            genesis_private_note_active_lifecycle(),
        )
        .into(),
    );
    universal.push(
        SetParameter::new(Parameter::Custom(
            participant_lane_policy(shape, committee_validator_entries).into_custom_parameter(),
        ))
        .into(),
    );
    let mut transactions = vec![universal];
    // The signed bootstrap source policy bounds each original logical entry.
    // Keep fee funding/profile governance atomic above, and preserve all stake
    // amounts in bounded universal funding and registration entries below.
    let intrinsic = FastpqSourcePolicyV1::bootstrap().intrinsic;
    let monetary_per_entry = usize::try_from(intrinsic.max_transcripts.min(intrinsic.max_deltas))
        .expect("bootstrap source count fits usize");
    transactions.extend(stake_funding.chunks(monetary_per_entry).map(<[_]>::to_vec));
    // Staking uses one globally scoped asset; every targetless entry remains
    // routed through universal, including participant committee registrations.
    let mut authority_registration =
        Vec::with_capacity(shape.lane_count() * VALIDATORS_PER_LANE * 2);
    for lane_ordinal in 0..shape.lane_count() {
        let lane = LaneId::new(u32::try_from(lane_ordinal).expect("lane fits u32"));
        for index in lane_ordinal * VALIDATORS_PER_LANE..(lane_ordinal + 1) * VALIDATORS_PER_LANE {
            let peer = topology.get(index).expect("lane validator peer");
            let validator = AccountId::new(validator_authority_keypair(index).public_key().clone());
            authority_registration.push(
                RegisterPublicLaneValidator::new(
                    lane,
                    validator.clone(),
                    peer.clone(),
                    validator.clone(),
                    Quantity::from(VALIDATOR_STAKE),
                    Metadata::default(),
                    iroha_data_model::nexus::PublicLaneMonetaryPlanV1::genesis_registration(
                        AssetId::new(stake_definition.clone(), validator.clone()),
                        AssetId::new(stake_definition.clone(), ALICE_ID.clone()),
                        Quantity::from(VALIDATOR_STAKE),
                    ),
                )
                .into(),
            );
            authority_registration.push(ActivatePublicLaneValidator::new(lane, validator).into());
        }
    }
    transactions.extend(
        authority_registration
            .chunks(monetary_per_entry * 2)
            .map(<[_]>::to_vec),
    );
    transactions
}

fn localnet_builder(shape: TopologyShape) -> NetworkBuilder {
    let stake_escrow = ALICE_ID
        .canonical_i105()
        .expect("canonical staking escrow account");
    let validator_worker_threads = i64::try_from(REAL_PROCESS_VALIDATOR_WORKER_THREADS)
        .expect("validator worker width fits i64");
    NetworkBuilder::new()
        .with_base_seed("atomic-private-settlement-n3-real-process-v1")
        .with_peers(shape.global_validator_count())
        .with_committee_validator_p2p_bootstrap(
            CommitteeValidatorP2pBootstrap::new(shape.participant_validator_count())
                .expect("participant committee validator count fits the P2P capacity"),
        )
        .expect("global and participant committee validators fit P2P fanout")
        // Keep every release profile, including the correctness-only N=3
        // smoke, on a production-like signed cadence. Privacy activation is
        // explicit in genesis; independent pool-policy notice remains enforced.
        .with_block_cadence(REAL_PROCESS_BLOCK_CADENCE)
        .with_peer_startup_timeout(Duration::from_secs(20 * 60))
        .with_npos_consensus()
        .without_npos_genesis_bootstrap()
        .with_genesis_block_and_committee_validator_entries(
            move |topology, topology_entries, committee_validator_entries| {
                let mut process_topology = topology.iter().cloned().collect::<Vec<_>>();
                process_topology.extend(
                    committee_validator_entries
                        .iter()
                        .map(|entry| entry.peer.clone()),
                );
                assert_eq!(process_topology.len(), shape.process_count());
                unexecuted_genesis_factory_with_post_topology(
                    Vec::new(),
                    genesis_post_topology(shape, &process_topology, &committee_validator_entries),
                    topology,
                    topology_entries,
                )
            },
        )
        .with_genesis_instruction(npos_override_instruction(VALIDATORS_PER_LANE))
        .with_config_layer(move |layer| {
            let lanes = (0..shape.lane_count())
                .map(|lane| {
                    let mut table = Table::new();
                    table.insert("index".into(), TomlValue::Integer(lane as i64));
                    table.insert(
                        "alias".into(),
                        TomlValue::String(if lane == 0 {
                            "lane-global".to_owned()
                        } else {
                            participant_lane_alias(lane - 1)
                        }),
                    );
                    table.insert(
                        "dataspace".into(),
                        TomlValue::String(if lane == 0 {
                            "universal".to_owned()
                        } else {
                            participant_dataspace_alias(lane - 1)
                        }),
                    );
                    table.insert(
                        "visibility".into(),
                        TomlValue::String(
                            if lane == 0 {
                                "public"
                            } else {
                                visibility_config_value(shape.participant_visibility(lane - 1))
                            }
                            .to_owned(),
                        ),
                    );
                    table.insert("metadata".into(), TomlValue::Table(Table::new()));
                    TomlValue::Table(table)
                })
                .collect::<Vec<_>>();
            let dataspaces = (0..shape.lane_count())
                .map(|dataspace| {
                    let mut table = Table::new();
                    table.insert(
                        "alias".into(),
                        TomlValue::String(if dataspace == 0 {
                            "universal".to_owned()
                        } else {
                            participant_dataspace_alias(dataspace - 1)
                        }),
                    );
                    table.insert("id".into(), TomlValue::Integer(dataspace as i64));
                    table.insert("fault_tolerance".into(), TomlValue::Integer(1));
                    table.insert(
                        "description".into(),
                        TomlValue::String(format!("atomic settlement dataspace {dataspace}")),
                    );
                    if dataspace != 0 {
                        table.insert(
                            "manifest_hash".into(),
                            TomlValue::String(format!("{dataspace:02x}{}", "00".repeat(31))),
                        );
                    }
                    TomlValue::Table(table)
                })
                .collect::<Vec<_>>();
            let mut routing = Table::new();
            routing.insert("default_lane".into(), TomlValue::Integer(0));
            routing.insert(
                "default_dataspace".into(),
                TomlValue::String("universal".to_owned()),
            );
            routing.insert("rules".into(), TomlValue::Array(Vec::new()));
            // The writer holds its borrow across the chain; keep the filter in that chain.
            layer
                .write(
                    ["logger", "filter"],
                    "iroha_torii::queue_plan_admission=debug",
                )
                .write(["logger", "format"], "json")
                .write(
                    ["concurrency", "scheduler_min_threads"],
                    validator_worker_threads,
                )
                .write(
                    ["concurrency", "scheduler_max_threads"],
                    validator_worker_threads,
                )
                .write(
                    ["concurrency", "rayon_global_threads"],
                    validator_worker_threads,
                )
                .write(["pipeline", "workers"], validator_worker_threads)
                .write(["nexus", "lane_count"], shape.lane_count() as i64)
                .write(
                    ["nexus", "storage", "local_budget_bytes"],
                    TEST_NEXUS_LOCAL_STORAGE_BUDGET_BYTES,
                )
                .write(["nexus", "lane_catalog"], TomlValue::Array(lanes))
                .write(["nexus", "dataspace_catalog"], TomlValue::Array(dataspaces))
                .write(["nexus", "routing_policy"], TomlValue::Table(routing))
                .write(
                    ["nexus", "fees", "fee_asset_id"],
                    nexus_fee_asset_definition_id().to_string(),
                )
                .write(["nexus", "fees", "base_fee"], "0")
                .write(["nexus", "fees", "per_byte_fee"], "0")
                .write(
                    ["nexus", "fees", "per_instruction_fee"],
                    NEXUS_FEE_PER_PRIVATE_SETTLEMENT_CARRIER,
                )
                .write(["nexus", "fees", "per_gas_unit_fee"], "0")
                .write(
                    ["nexus", "staking", "public_validator_mode"],
                    "stake_elected",
                )
                .write(
                    ["nexus", "staking", "restricted_validator_mode"],
                    "stake_elected",
                )
                .write(
                    ["nexus", "staking", "stake_asset_id"],
                    stake_asset_definition_id().to_string(),
                )
                .write(
                    ["nexus", "staking", "stake_escrow_account_id"],
                    stake_escrow.clone(),
                )
                .write(
                    ["nexus", "staking", "slash_sink_account_id"],
                    stake_escrow.clone(),
                )
                .write(
                    ["nexus", "staking", "max_validators"],
                    VALIDATORS_PER_LANE as i64,
                )
                .write(["nexus", "atomic_private_settlement", "enabled"], true)
                .write(
                    ["nexus", "atomic_private_settlement", "activation_height"],
                    PRIVATE_SETTLEMENT_ACTIVATION_HEIGHT as i64,
                )
                .write(
                    [
                        "nexus",
                        "atomic_private_settlement",
                        "minimum_activation_notice_blocks",
                    ],
                    PRIVATE_SETTLEMENT_MINIMUM_ACTIVATION_NOTICE_BLOCKS as i64,
                )
                .write(
                    ["nexus", "atomic_private_settlement", "max_participants"],
                    16_i64,
                )
                .write(
                    ["nexus", "atomic_private_settlement", "max_expiry_blocks"],
                    MAX_EXPIRY_BLOCKS as i64,
                )
                .write(
                    ["nexus", "atomic_private_settlement", "audit_timeout_blocks"],
                    1_024_i64,
                )
                .write(
                    [
                        "nexus",
                        "atomic_private_settlement",
                        "prepare_timeout_blocks",
                    ],
                    1_024_i64,
                )
                .write(
                    [
                        "nexus",
                        "atomic_private_settlement",
                        "commit_timeout_blocks",
                    ],
                    1_024_i64,
                )
                .write(
                    [
                        "nexus",
                        "atomic_private_settlement",
                        "sidecar_retention_blocks",
                    ],
                    SIDECAR_RETENTION_BLOCKS as i64,
                )
                .write(
                    ["nexus", "atomic_private_settlement", "sidecar_max_records"],
                    64_i64,
                )
                .write(
                    [
                        "nexus",
                        "atomic_private_settlement",
                        "sidecar_max_total_bytes",
                    ],
                    1_073_741_824_i64,
                )
                .write(
                    [
                        "network",
                        "soranet_handshake",
                        "pow",
                        "puzzle",
                        "memory_kib",
                    ],
                    i64::from(iroha_crypto::soranet::puzzle::MIN_MEMORY_KIB),
                )
                .write(
                    ["network", "soranet_handshake", "pow", "puzzle", "time_cost"],
                    1_i64,
                )
                .write(
                    ["network", "soranet_handshake", "pow", "puzzle", "lanes"],
                    1_i64,
                );
        })
}

// EnvFilter matches target prefixes. Keep unselected Sumeragi modules at INFO,
// then enable the selected driver and executor owners.
const N3_DIAGNOSTIC_LOG_FILTER: &str = concat!(
    "iroha_torii::queue_plan_admission=debug,",
    "iroha_core::sumeragi=info,",
    "iroha_core::sumeragi::driver=debug,",
    "iroha_core::sumeragi::executor=debug",
);

fn n3_smoke_builder(shape: TopologyShape) -> NetworkBuilder {
    // Keep the production-like four-second cadence so a release host running
    // sixteen independent validators has enough time to validate and relay the
    // mandatory DA payload before the view deadline. Privacy activation is
    // an explicit governed genesis transition; pool-policy notice is independent.
    // The authenticated test controller exposes the same financial-state
    // observation route used by the release fault campaign. No fault rule is
    // installed by the positive smoke test.
    localnet_builder(shape)
        .with_private_settlement_route_control()
        .with_config_layer(|layer| {
            // This diagnostic-only smoke retains the shared admission filter.
            layer.write(["logger", "filter"], N3_DIAGNOSTIC_LOG_FILTER);
        })
}

fn participant_asset_registrations(shape: TopologyShape) -> Vec<InstructionBox> {
    (0..shape.participants)
        .map(|ordinal| {
            Register::asset_definition(AssetDefinition::numeric(
                cbdc_asset_definition_id(ordinal),
                format!("CBDC {}", ordinal + 1),
                AssetBalancePolicy::Global,
                Some(settlement_domain_id()),
            ))
            .into()
        })
        .collect()
}

fn prepare_participant_assets(network: &Network, shape: TopologyShape) -> Result<()> {
    let sponsor = network.client();
    let account = sponsor.account_client();
    // The signed genesis domain belongs to Alice. Each required CBDC is one
    // ordinary paid global transaction and commits before the next one. For
    // N=3 these real setup transactions occupy heights 2–4, past the native
    // lane active_from=3 boundary, before any measured settlement workflow.
    for instruction in participant_asset_registrations(shape) {
        let transaction = account
            .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                [instruction],
                bounded_nexus_fee(),
                Metadata::default(),
            ))
            .and_then(|payload| account.sign_transaction(payload))
            .wrap_err("build required participant asset registration")?;
        sponsor
            .submit_transaction_and_wait(&transaction)
            .wrap_err("commit required participant asset registration")?;
    }
    Ok(())
}

fn signed_participant_lane_policy(
    network: &Network,
    shape: TopologyShape,
) -> Result<SumeragiLanePolicy> {
    let genesis = network.genesis();
    let mut signed_policy = None;
    for transaction in genesis.0.external_transactions() {
        let iroha::data_model::transaction::Executable::Instructions(instructions) =
            transaction.instructions()
        else {
            return Err(eyre!("signed genesis contains a non-instruction entry"));
        };
        for instruction in instructions {
            let Some(parameter) = instruction.as_any().downcast_ref::<SetParameter>() else {
                continue;
            };
            let Parameter::Custom(custom) = parameter.inner() else {
                continue;
            };
            if let Some(policy) = SumeragiLanePolicy::from_custom_parameter(custom) {
                ensure!(
                    signed_policy.is_none(),
                    "signed genesis repeats its native lane policy"
                );
                signed_policy = Some(policy.map_err(|error| eyre!(error))?);
            }
        }
    }
    let policy =
        signed_policy.ok_or_else(|| eyre!("signed genesis omits its native lane policy"))?;
    let entries = network
        .all_peers()
        .skip(shape.global_validator_count())
        .map(|peer| {
            Ok(GenesisTopologyEntry::new(
                PeerId::new(
                    peer.bls_public_key()
                        .ok_or_else(|| eyre!("participant BLS key missing"))?
                        .clone(),
                ),
                peer.bls_pop()
                    .ok_or_else(|| eyre!("participant BLS PoP missing"))?
                    .to_vec(),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        policy == participant_lane_policy(shape, &entries),
        "signed native policy differs from the exact participant processes or cadence"
    );
    iroha_core::sumeragi::lanes::step::validate_policy(&policy).map_err(|error| eyre!(error))?;
    Ok(policy)
}

fn routes_from_signed_lane_records(
    network_id: iroha::data_model::NetworkId,
    policy: &SumeragiLanePolicy,
    statuses: &[iroha::data_model::sumeragi_lanes::SumeragiLaneStatus],
    committed_height: u64,
) -> Result<Vec<PrivateSettlementRouteV1>> {
    ensure!(
        statuses.len() == policy.fixed.len(),
        "native lane status population differs from signed genesis"
    );
    policy
        .fixed
        .iter()
        .enumerate()
        .map(|(ordinal, fixed)| {
            let incarnation = iroha_core::sumeragi::lanes::step::incarnation(
                &network_id,
                fixed.lane,
                fixed.dataspace,
                PRIVACY_GENESIS_PROPOSAL_HEIGHT,
                u64::try_from(ordinal).expect("lane incarnation counter fits u64"),
            );
            let record = &statuses
                .iter()
                .find(|status| status.record.lane == fixed.lane)
                .ok_or_else(|| {
                    eyre!(
                        "signed participant lane {} is absent from native state",
                        fixed.lane
                    )
                })?
                .record;
            ensure!(
                record.dataspace == fixed.dataspace
                    && record.incarnation == incarnation
                    && record.committee == fixed.committee
                    && record.params == policy.lane_params
                    && record.da_layout == policy.da_layout
                    && record.anchor_freshness == policy.anchor_freshness
                    && record.created_at == PRIVACY_GENESIS_PROPOSAL_HEIGHT
                    && record.active_from == PRIVACY_GENESIS_PROPOSAL_HEIGHT + 2
                    && record.closing.is_none(),
                "native lane {} differs from its exact signed genesis creation",
                fixed.lane
            );
            ensure!(
                record.admits_anchor(committed_height),
                "native lane {} is not active at authenticated height {committed_height}",
                fixed.lane
            );
            Ok(PrivateSettlementRouteV1 {
                dataspace_id: fixed.dataspace,
                lane_id: fixed.lane,
                lane_incarnation: Hash::from_marked_bytes(incarnation)
                    .ok_or_else(|| eyre!("native incarnation lacks its canonical marker"))?,
            })
        })
        .collect()
}

fn routes_from_network(
    network: &Network,
    shape: TopologyShape,
) -> Result<Vec<PrivateSettlementRouteV1>> {
    let status = network.client().client().get_lane_lifecycle_status()?;
    status
        .validate()
        .wrap_err("validate lane lifecycle status")?;
    for ordinal in 0..shape.participants {
        let lane_id = LaneId::new(u32::try_from(ordinal + 1).expect("lane fits u32"));
        let configured = status
            .lanes
            .iter()
            .find(|lane| lane.id == lane_id)
            .ok_or_else(|| eyre!("participant lane {} is absent", ordinal + 1))?;
        let expected = shape.participant_visibility(ordinal);
        ensure!(
            configured.visibility == expected,
            "participant lane {} visibility is {}, expected {}",
            ordinal + 1,
            configured.visibility.as_str(),
            expected.as_str()
        );
    }
    let sponsor = network.client();
    let history = authenticated_native_history(network, &sponsor)?;
    let height = history
        .last()
        .ok_or_else(|| eyre!("participant setup lacks a certified successor"))?
        .committed()
        .block()
        .header()
        .height()
        .get();
    let policy = signed_participant_lane_policy(network, shape)?;
    let native = sponsor.client().get_sumeragi_lanes()?;
    // Route identities come from the independently signed fixed policy and
    // deterministic genesis creation. Endpoint records are consistency checks;
    // this is not a complete current lane-state inclusion proof. The final
    // native finality and signed availability evidence gates remain mandatory.
    routes_from_signed_lane_records(network.network_id(), &policy, &native, height)
}

fn committees_from_network(
    network: &Network,
    shape: TopologyShape,
    routes: &[PrivateSettlementRouteV1],
) -> Result<Vec<CommitteeEndpoints>> {
    routes
        .iter()
        .enumerate()
        .map(|(ordinal, route)| {
            let lane = ordinal + 1;
            let processes = network.all_peers().collect::<Vec<_>>();
            let mut rows = processes[shape.committee_range(lane)]
                .iter()
                .map(|peer: &&NetworkPeer| {
                    let validator = PeerId::from(
                        peer.bls_public_key()
                            .ok_or_else(|| eyre!("validator has no BLS identity"))?
                            .clone(),
                    );
                    let pop = peer
                        .bls_pop()
                        .ok_or_else(|| eyre!("validator has no BLS PoP"))?
                        .to_vec();
                    Ok((
                        validator,
                        pop,
                        Url::parse(&peer.torii_url())?,
                        peer.bls_key_pair()
                            .ok_or_else(|| eyre!("validator has no BLS key pair"))?
                            .clone(),
                    ))
                })
                .collect::<Result<Vec<_>>>()?;
            rows.sort_by(|left, right| left.0.cmp(&right.0));
            let validators = rows.iter().map(|row| row.0.clone()).collect::<Vec<_>>();
            let authority = PrivateSettlementCommitteeAuthorityV1 {
                route: *route,
                validator_set_hash: HashOf::new(&validators),
                validators,
                validator_pops: rows.iter().map(|row| row.1.clone()).collect(),
            };
            authority
                .validate()
                .wrap_err("validate real four-validator authority")?;
            Ok(CommitteeEndpoints {
                authority,
                endpoints: rows.iter().map(|row| row.2.clone()).collect(),
                validator_keys: rows.into_iter().map(|row| row.3).collect(),
            })
        })
        .collect()
}

/// Setup readiness diagnostics are outside settlement measurements.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrivateNoteActivationDiagnostic {
    Call {
        succeeded: bool,
        elapsed: Duration,
    },
    Completed {
        committed_height: u64,
        elapsed: Duration,
    },
}

/// Observe one readiness read without changing its result or error identity.
fn observe_private_note_activation_call<T, E>(
    observe: &mut impl FnMut(PrivateNoteActivationDiagnostic),
    call: impl FnOnce() -> std::result::Result<T, E>,
) -> std::result::Result<T, E> {
    let started = Instant::now();
    let result = call();
    observe(PrivateNoteActivationDiagnostic::Call {
        succeeded: result.is_ok(),
        elapsed: started.elapsed(),
    });
    result
}

/// Emit fixed labels and numeric timing only, never a payload or error value.
fn write_private_note_activation_diagnostic(
    writer: &mut impl std::io::Write,
    diagnostic: PrivateNoteActivationDiagnostic,
) -> std::io::Result<()> {
    match diagnostic {
        PrivateNoteActivationDiagnostic::Call { succeeded, elapsed } => {
            let outcome = if succeeded { "success" } else { "error" };
            writeln!(
                writer,
                "private-note activation diagnostic_timing stage=capability_read outcome={outcome} elapsed_ns={}",
                elapsed.as_nanos()
            )
        }
        PrivateNoteActivationDiagnostic::Completed {
            committed_height,
            elapsed,
        } => {
            writeln!(
                writer,
                "private-note activation diagnostic_completed committed_height={committed_height} elapsed_ns={}",
                elapsed.as_nanos()
            )
        }
    }
}

fn validate_genesis_private_note_readiness(
    activation: &PrivacyProtocolActivationRecordV1,
    compiled_profile: &PrivacyCompiledProfileResultV1,
    committed_height: u64,
) -> Result<u64> {
    let compiled = compiled_privacy_profile_v1(PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1)?;
    let expected = compiled.activation_record(genesis_private_note_active_lifecycle());
    ensure!(
        activation == &expected,
        "governed IVM private-note activation differs from the exact active genesis record"
    );
    ensure!(
        compiled_profile == &PrivacyCompiledProfileResultV1::Available(compiled.into()),
        "active IVM profile differs from the exact compiled private-note profile"
    );
    ensure!(
        committed_height >= PRIVACY_PROFILE_ACTIVATION_HEIGHT,
        "active genesis profile is ahead of the committed authority context"
    );
    Ok(committed_height)
}

fn require_genesis_private_note_active(client: &Client) -> Result<u64> {
    let started = Instant::now();
    let mut observe = |diagnostic| {
        let _ = write_private_note_activation_diagnostic(&mut std::io::stderr().lock(), diagnostic);
    };
    let capability = observe_private_note_activation_call(&mut observe, || {
        client.client().get_privacy_capabilities()
    })
    .wrap_err("read governed IVM private-note genesis activation")?;
    let row = capability
        .protocols
        .iter()
        .find(|row| row.protocol_id == PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1)
        .ok_or_else(|| eyre!("IVM private-note capability row is absent"))?;
    let activation = row
        .activation
        .as_ref()
        .ok_or_else(|| eyre!("governed IVM private-note activation is absent"))?;
    let height = validate_genesis_private_note_readiness(
        activation,
        &row.compiled_profile,
        capability.committed_height,
    )?;
    observe(PrivateNoteActivationDiagnostic::Completed {
        committed_height: height,
        elapsed: started.elapsed(),
    });
    Ok(height)
}

fn signing_key(seed: u8) -> KeyPair {
    KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
}

fn leakage_canary_keypair(variant: &str) -> Result<KeyPair> {
    let seed = match variant {
        "left" => [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ],
        "right" => [
            0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11,
            0x4e, 0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed,
            0x4f, 0xb8, 0xa6, 0xfb,
        ],
        _ => return Err(eyre!("leakage variant must be left or right")),
    };
    KeyPair::try_from_seed(seed.to_vec(), Algorithm::Ed25519)
        .wrap_err("derive the fixed RFC 8032 leakage canary key")
}

fn leakage_canary_account_id(variant: &str) -> Result<AccountId> {
    Ok(AccountId::new(
        leakage_canary_keypair(variant)?.public_key().clone(),
    ))
}

fn leakage_canary_asset_definition_id(variant: &str) -> Result<AssetDefinitionId> {
    let literal = match variant {
        "left" => LEAKAGE_ASSET_LEFT,
        "right" => LEAKAGE_ASSET_RIGHT,
        _ => return Err(eyre!("leakage variant must be left or right")),
    };
    literal
        .parse()
        .wrap_err("parse the fixed canonical leakage asset definition id")
}

fn default_private_settlement_leg_data(ordinal: usize) -> PrivateSettlementLegPrivateData {
    PrivateSettlementLegPrivateData {
        payer: signing_key(0xA1 + ordinal as u8),
        recipient: signing_key(0xB1 + ordinal as u8),
        amount: 42 + ordinal as u128,
        memo: format!("BCK26-private-settlement-leg-{ordinal}").into_bytes(),
    }
}

fn governed_legs(
    routes: &[PrivateSettlementRouteV1],
    authority_context_height: u64,
    expiry_height: u64,
) -> Result<Vec<GovernedLeg>> {
    governed_legs_with_asset_definitions(routes, authority_context_height, expiry_height, None)
}

fn governed_legs_with_asset_definitions(
    routes: &[PrivateSettlementRouteV1],
    authority_context_height: u64,
    expiry_height: u64,
    asset_definition_ids: Option<&[AssetDefinitionId]>,
) -> Result<Vec<GovernedLeg>> {
    if let Some(asset_definition_ids) = asset_definition_ids {
        ensure!(
            asset_definition_ids.len() == routes.len(),
            "private settlement asset override count must equal the route count"
        );
    }
    routes
        .iter()
        .enumerate()
        .map(|(ordinal, route)| {
            let auditor_signing = signing_key(0x30 + ordinal as u8);
            let auditor_id = AccountId::new(auditor_signing.public_key().clone());
            let mut rng = iroha_crypto::rng_from_seed_slice(&bytes(0x40 + ordinal as u8));
            let auditor_encryption = HybridKeyPair::generate(&mut rng)?;
            let policy = PrivateSettlementAuditPolicyV1::new(PrivateSettlementAuditPolicyBodyV1 {
                version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
                dataspace_id: route.dataspace_id,
                policy_id: hash(0x50 + ordinal as u8),
                revision: 1,
                key_epoch: 1,
                activation_height: authority_context_height,
                retirement_height: Some(expiry_height + 1),
                min_approvals: 1,
                auditors: vec![PrivateSettlementAuditorV1 {
                    auditor_id,
                    signing_key: auditor_signing.public_key().clone(),
                    encryption_key: PrivateSettlementHybridPublicKeyV1::from_hybrid(
                        auditor_encryption.public(),
                    ),
                }],
            })?;
            let governance = PrivateSettlementPoolGovernanceV1::from_restricted_mapping(
                *route,
                PrivacyPoolIdV1::new(bytes(0x60 + ordinal as u8)),
                asset_definition_ids.map_or_else(
                    || cbdc_asset_definition_id(ordinal),
                    |ids| ids[ordinal].clone(),
                ),
                bytes(0x70 + ordinal as u8),
                &policy,
                PrivateSettlementPoolGovernanceLifecycleV1 {
                    governance_revision: 1,
                    activation_height: authority_context_height,
                    retirement_height: Some(expiry_height + 1),
                },
            )?;
            Ok(GovernedLeg {
                route: *route,
                policy,
                governance,
                auditor_signing,
                auditor_encryption,
            })
        })
        .collect()
}

fn placeholder_payer_authorization(
    network_id: iroha::data_model::NetworkId,
    route: PrivateSettlementRouteV1,
    payer: &KeyPair,
    expiry_height: u64,
) -> PrivateSettlementAuditPayerAuthorizationV1 {
    let body = PrivateSettlementAuditPayerAuthorizationBodyV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        purpose: hash(0x81),
        network_id,
        bundle_id: hash(0x82),
        leg_ordinal: 0,
        route,
        payer: AccountId::new(payer.public_key().clone()),
        expiry_height,
        inputs: vec![
            PrivateSettlementAuditPayerInputV1 {
                input_ordinal: 0,
                active: true,
                commitment: PrivacyCommitmentV1::new(bytes(0x83)),
                nullifier: PrivacyNullifierV1::new(bytes(0x84)),
                note_spending_authority: bytes(0x85),
                dummy_domain: None,
            },
            PrivateSettlementAuditPayerInputV1 {
                input_ordinal: 1,
                active: false,
                commitment: PrivacyCommitmentV1::new(bytes(0x86)),
                nullifier: PrivacyNullifierV1::new(bytes(0x87)),
                note_spending_authority: bytes(0x88),
                dummy_domain: Some(hash(0x89)),
            },
        ],
    };
    PrivateSettlementAuditPayerAuthorizationV1::new(
        body.clone(),
        vec![PrivateSettlementAuditPayerSignatureV1::new(
            payer.public_key().clone(),
            SignatureOf::try_new(payer.private_key(), &body).expect("placeholder signature"),
        )],
    )
}

fn placeholder_view_authorization(
    network_id: iroha::data_model::NetworkId,
    route: PrivateSettlementRouteV1,
    signer: &KeyPair,
    expiry_height: u64,
) -> PrivateSettlementAuditViewKeyAuthorizationV1 {
    let body = PrivateSettlementAuditViewKeyAuthorizationBodyV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        purpose: hash(0x8A),
        network_id,
        bundle_id: hash(0x8B),
        leg_ordinal: 0,
        route,
        output_ordinal: 0,
        role: PrivateSettlementAuditOutputRoleV1::SettlementRecipient,
        authorized_account: AccountId::new(signer.public_key().clone()),
        recipient_view_key: bytes(0x8C),
        output_active: true,
        note_spending_authority: bytes(0x8D),
        expiry_height,
    };
    PrivateSettlementAuditViewKeyAuthorizationV1::new(
        body.clone(),
        vec![PrivateSettlementAuditViewKeySignatureV1::new(
            signer.public_key().clone(),
            SignatureOf::try_new(signer.private_key(), &body).expect("placeholder signature"),
        )],
    )
}

fn private_settlement_leg_private_material(
    manifest: &AtomicPrivateSettlementV1,
    governed: &GovernedLeg,
    leg_ordinal: usize,
    material_ordinal: usize,
    purpose: &[u8],
) -> [u8; 32] {
    use sha2::Digest as _;

    let mut digest = sha2::Sha256::new();
    digest.update(PRIVATE_SETTLEMENT_LEG_PRIVATE_MATERIAL_DOMAIN_V1);
    digest.update(manifest.bundle_id.as_ref());
    digest.update(governed.governance.governance_digest.as_ref());
    digest.update(
        u64::try_from(leg_ordinal)
            .expect("private-settlement leg ordinal fits u64")
            .to_le_bytes(),
    );
    digest.update(
        u64::try_from(material_ordinal)
            .expect("private-settlement material ordinal fits u64")
            .to_le_bytes(),
    );
    digest.update(
        u64::try_from(purpose.len())
            .expect("private-settlement material purpose length fits u64")
            .to_le_bytes(),
    );
    digest.update(purpose);
    digest.finalize().into()
}

fn private_settlement_funding_material(
    network_id: iroha::data_model::NetworkId,
    governed: &GovernedLeg,
    leg_ordinal: usize,
    note_ordinal: u8,
    field: u8,
) -> [u8; 32] {
    use sha2::Digest as _;

    // Deterministic release-fixture material is bound to the funded pool,
    // independently of the later settlement's bundle and authority height.
    let mut digest = sha2::Sha256::new();
    digest.update(b"iroha:atomic-private-settlement:release-funding:v1\0");
    digest.update(network_id.as_bytes());
    digest.update(governed.governance.governance_digest.as_ref());
    digest.update(
        u64::try_from(leg_ordinal)
            .expect("leg ordinal fits u64")
            .to_le_bytes(),
    );
    digest.update([note_ordinal, field]);
    digest.finalize().into()
}

fn private_settlement_funding(
    network_id: iroha::data_model::NetworkId,
    governed: &GovernedLeg,
    ordinal: usize,
    private_data: &PrivateSettlementLegPrivateData,
) -> Result<PrivateSettlementFunding> {
    let reimbursement = if ordinal == 0 { 5 } else { 0 };
    let input_amount = private_data
        .amount
        .checked_add(7)
        .and_then(|value| value.checked_add(reimbursement))
        .ok_or_else(|| eyre!("private settlement input amount overflow"))?;
    let material = |note, field| {
        private_settlement_funding_material(network_id, governed, ordinal, note, field)
    };
    let mut notes = Vec::with_capacity(2);
    for (note, value) in [(0_u8, input_amount), (1_u8, 1_u128)] {
        let mut opening = PrivateSettlementAuditNoteOpeningV1 {
            active: true,
            commitment: PrivacyCommitmentV1::new([0; 32]),
            value,
            spending_authority: derive_note_authority_v1(&material(note, 0))?,
            rho: material(note, 1),
            blinding: material(note, 2),
            memo_digest: material(note, 3),
            dummy_domain: None,
        };
        prepare_atomic_private_settlement_funding_note_v1(&mut opening)?;
        notes.push(opening);
    }
    // The second funded note stays unspent. The spend's zero-value slot is a
    // fresh bundle-bound virtual dummy, not this reserve note.
    let input_commitments = [notes[0].commitment, notes[1].commitment];
    ensure!(
        input_commitments[0] != input_commitments[1],
        "funding note collision"
    );
    Ok(PrivateSettlementFunding {
        opening: notes.remove(0),
        spending_secret: material(0, 0),
        input_commitments,
    })
}

fn validate_pool_activation_context(
    governed: &[GovernedLeg],
    committed_height: u64,
    expiry_height: u64,
) -> Result<u64> {
    ensure!(!governed.is_empty(), "pool activation omitted every leg");
    ensure!(
        committed_height < expiry_height,
        "pools became active after bundle expiry"
    );
    for leg in governed {
        ensure!(
            leg.policy.is_active_at(committed_height)
                && leg.governance.body.lifecycle.is_active_at(committed_height),
            "pool governance is unavailable at the observed authority context"
        );
    }
    Ok(committed_height)
}

fn governed_pool_activation_instructions(
    network_id: iroha::data_model::NetworkId,
    governed: &[GovernedLeg],
    private_data: &[PrivateSettlementLegPrivateData],
) -> Result<Vec<ActivatePrivateSettlementPoolV1>> {
    ensure!(!governed.is_empty(), "pool setup requires governed legs");
    ensure!(
        governed.len() == private_data.len(),
        "pool funding omitted a leg"
    );
    governed
        .iter()
        .zip(private_data)
        .enumerate()
        .map(|(ordinal, (leg, private_data))| {
            let funding = private_settlement_funding(network_id, leg, ordinal, private_data)?;
            Ok(ActivatePrivateSettlementPoolV1::from_restricted(
                &leg.governance,
                funding.activation_commitments().to_vec(),
            )?)
        })
        .collect()
}

fn activate_governed_private_pools(
    sponsor: &Client,
    network_id: iroha::data_model::NetworkId,
    governed: &[GovernedLeg],
    private_data: &[PrivateSettlementLegPrivateData],
    expiry_height: u64,
) -> Result<u64> {
    // Derive every funded setup instruction before committing any setup work.
    let activations = governed_pool_activation_instructions(network_id, governed, private_data)?;
    let account = sponsor.account_client();
    // These independently governed pools are separate setup operations. Each
    // original transaction is signed for one native route with its own fee bound.
    for (ordinal, activation) in activations.into_iter().enumerate() {
        let timing =
            SmokeDiagnosticSpanV1::start(SmokeDiagnosticPhaseV1::PoolActivation, Some(ordinal));
        let transaction = account
            .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                [activation],
                bounded_nexus_fee(),
                Metadata::default(),
            ))
            .and_then(|payload| account.sign_transaction(payload))
            .wrap_err_with(|| format!("build governed pool activation for leg {ordinal}"))?;
        let transaction_hash = transaction.hash();
        emit_pool_setup_transaction_diagnostic_v1(
            &mut std::io::stderr().lock(),
            SmokeDiagnosticScopeV1::capture().is_some(),
            ordinal,
            transaction_hash,
        );
        sponsor
            .submit_transaction_and_wait(&transaction)
            .wrap_err_with(|| {
                format!(
                    "activate governed pool for leg {ordinal}, transaction {transaction_hash}, before proof generation"
                )
            })?;
        timing.complete();
    }
    // Every pool has applied finality before this shared context is selected.
    // Extra admission blocks and a later capability response are both valid;
    // uploads still enforce the exact historical committee at this height.
    let committed_height = sponsor
        .client()
        .get_privacy_capabilities()?
        .committed_height;
    validate_pool_activation_context(governed, committed_height, expiry_height)
}

/// Public leg identity only, with best-effort output restricted to diagnostic scope.
fn emit_pool_setup_transaction_diagnostic_v1(
    writer: &mut impl std::io::Write,
    diagnostic_active: bool,
    ordinal: usize,
    transaction_hash: HashOf<SignedTransaction>,
) {
    if !diagnostic_active {
        return;
    }
    use std::io::Write as _;
    let mut record = std::io::Cursor::new([0_u8; 256]);
    if writeln!(
        &mut record,
        "APS_POOL_SETUP_TRANSACTION_V1 leg={ordinal} transaction_hash={transaction_hash}"
    )
    .is_ok()
    {
        let length = record.position() as usize;
        let _ = writer.write_all(&record.get_ref()[..length]);
    }
}

#[test]
fn pool_setup_transaction_diagnostic_is_scoped_and_contains_only_public_identity() {
    let transaction_hash = HashOf::<SignedTransaction>::from_untyped_unchecked(hash(0xD1));
    let mut record = Vec::new();
    emit_pool_setup_transaction_diagnostic_v1(&mut record, false, 2, transaction_hash);
    assert!(
        record.is_empty(),
        "ordinary runs emit no setup identity diagnostic"
    );
    emit_pool_setup_transaction_diagnostic_v1(&mut record, true, 2, transaction_hash);
    assert_eq!(
        String::from_utf8(record).unwrap(),
        format!("APS_POOL_SETUP_TRANSACTION_V1 leg=2 transaction_hash={transaction_hash}\n")
    );
}

#[test]
fn pool_setup_transaction_diagnostic_sink_failure_preserves_operation_result() {
    struct FailedSink(usize);
    impl std::io::Write for FailedSink {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            self.0 += 1;
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            panic!("the diagnostic must not flush or own the caller's sink")
        }
    }
    let transaction_hash = HashOf::<SignedTransaction>::from_untyped_unchecked(hash(0xD1));
    let mut sink = FailedSink(0);
    emit_pool_setup_transaction_diagnostic_v1(&mut sink, false, 2, transaction_hash);
    assert_eq!(sink.0, 0);
    for expected in [Ok(7_u64), Err("original submission failure")] {
        let mut operation = || {
            emit_pool_setup_transaction_diagnostic_v1(&mut sink, true, 2, transaction_hash);
            expected
        };
        assert_eq!(operation(), expected);
    }
    assert_eq!(sink.0, 2);
}

fn private_settlement_reimbursement_terms_salt(
    manifest: &AtomicPrivateSettlementV1,
    governed: &GovernedLeg,
) -> [u8; 32] {
    use sha2::Digest as _;

    // `bundle_id` commits to the reimbursement commitment, so derive this
    // salt from the rest of the unique bundle preimage to avoid a cycle.
    let mut digest = sha2::Sha256::new();
    digest.update(PRIVATE_SETTLEMENT_REIMBURSEMENT_SALT_DOMAIN_V1);
    digest.update(manifest.network_id.as_bytes());
    digest.update(manifest.authority_context_height.to_le_bytes());
    digest.update(manifest.expiry_height.to_le_bytes());
    digest.update(manifest.fee_intent_digest.as_ref());
    digest.update(governed.governance.governance_digest.as_ref());
    digest.finalize().into()
}

fn note_opening(
    manifest: &AtomicPrivateSettlementV1,
    governed: &GovernedLeg,
    leg_ordinal: usize,
    purpose: &[u8],
    note_ordinal: usize,
    active: bool,
    value: u128,
) -> PrivateSettlementAuditNoteOpeningV1 {
    let field_base = note_ordinal
        .checked_mul(6)
        .expect("private-settlement note material ordinal fits usize");
    let field = |offset| {
        private_settlement_leg_private_material(
            manifest,
            governed,
            leg_ordinal,
            field_base + offset,
            purpose,
        )
    };
    PrivateSettlementAuditNoteOpeningV1 {
        active,
        commitment: PrivacyCommitmentV1::new(field(0)),
        value,
        spending_authority: field(1),
        rho: field(2),
        blinding: field(3),
        memo_digest: field(4),
        dummy_domain: (!active).then(|| Hash::prehashed(field(5))),
    }
}

fn placeholder_encrypted_output(seed: u8) -> PrivacyEncryptedOutputV1 {
    let mut ciphertext = vec![seed.max(1); PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_BYTES_V1];
    ciphertext[..4].copy_from_slice(b"IPNE");
    PrivacyEncryptedOutputV1 {
        recipient: PrivacyRecipientIdV1::new(bytes(seed.wrapping_add(1))),
        ephemeral_public_key: PrivacyEncryptionKeyV1::new(bytes(seed.wrapping_add(2))),
        commitment: PrivacyCommitmentV1::new(bytes(seed.wrapping_add(3))),
        ciphertext,
    }
}

fn reimbursement_commitment(
    manifest: &AtomicPrivateSettlementV1,
    governed: &GovernedLeg,
) -> Result<Hash> {
    let payer = signing_key(0x91);
    let probe = PrivateSettlementAuditPlaintextV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        network_id: manifest.network_id,
        bundle_id: hash(0x92),
        leg_ordinal: 0,
        route: governed.route,
        pool_id: governed.governance.body.pool_id,
        payer: AccountId::new(payer.public_key().clone()),
        payer_authorization: placeholder_payer_authorization(
            manifest.network_id,
            governed.route,
            &payer,
            manifest.expiry_height,
        ),
        recipient: AccountId::new(signing_key(0x93).public_key().clone()),
        sponsor: manifest.sponsor.clone(),
        asset_definition_id: governed.governance.body.asset_definition_id.clone(),
        asset_binding_salt: governed.governance.body.asset_binding_salt,
        amount: 1,
        sponsor_reimbursement_amount: 5,
        fee_intent_digest: manifest.fee_intent_digest,
        settlement_expiry_height: manifest.expiry_height,
        reimbursement_terms_salt: private_settlement_reimbursement_terms_salt(manifest, governed),
        memo: Vec::new(),
        policy_references: Vec::new(),
        inputs: Vec::new(),
        outputs: Vec::new(),
    };
    Ok(probe.reimbursement_terms_commitment()?)
}

fn proof_manifest(
    network_id: iroha::data_model::NetworkId,
    authority_context_height: u64,
    expiry_height: u64,
    governed: &[GovernedLeg],
) -> Result<AtomicPrivateSettlementV1> {
    let mut manifest = AtomicPrivateSettlementV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        network_id,
        bundle_id: hash(0xA0),
        authority_context_height,
        expiry_height,
        sponsor: ALICE_ID.clone(),
        public_fee_intent: bounded_nexus_fee(),
        fee_intent_digest: hash(0xA1),
        reimbursement_terms_commitment: hash(0xA2),
        reimbursement_leg_ordinal: 0,
        legs: governed
            .iter()
            .enumerate()
            .map(|(ordinal, leg)| PrivateSettlementLegCommitmentV1 {
                ordinal: u8::try_from(ordinal).expect("ordinal fits u8"),
                route: leg.route,
                pool_id: leg.governance.body.pool_id,
                asset_binding_commitment: leg.governance.body.asset_binding_commitment,
                audit_policy_digest: leg.policy.policy_digest,
                payload_digest: hash(0xB0 + ordinal as u8),
                availability_certificate_digest: hash(0xC0 + ordinal as u8),
                delta_digest: hash(0xD0 + ordinal as u8),
            })
            .collect(),
    };
    manifest.fee_intent_digest = manifest.computed_fee_intent_digest()?;
    manifest.reimbursement_terms_commitment = reimbursement_commitment(&manifest, &governed[0])?;
    manifest.bundle_id = manifest.computed_bundle_id()?;
    manifest.validate()?;
    Ok(manifest)
}

/// The three bounded client phases that own one job per participant leg.
#[derive(Clone, Copy, Debug)]
enum SmokeLegJobPhaseV1 {
    Proof,
    AvailabilityCertification,
    RestrictedUpload,
}

impl SmokeLegJobPhaseV1 {
    const fn label(self) -> &'static str {
        match self {
            Self::Proof => "proof",
            Self::AvailabilityCertification => "availability certification",
            Self::RestrictedUpload => "restricted upload",
        }
    }
}

/// Spawn all three phase jobs, then join all owners before ordinal reduction.
///
/// Proof jobs share the process-wide eight-worker Rayon pool. Network jobs use
/// the same immutable SDK client and retain sequential requests within each leg.
/// The caller owns the phase span and must join this phase before starting the next.
fn collect_three_smoke_phase_jobs_v1<T, R, F>(
    phase: SmokeLegJobPhaseV1,
    jobs: [T; 3],
    run: F,
) -> Result<Vec<R>>
where
    T: Send,
    R: Send,
    F: Fn(usize, T) -> Result<R> + Sync,
{
    collect_three_smoke_phase_jobs_with_builders_v1(phase, jobs, run, |ordinal| {
        Ok(thread::Builder::new()
            .name(format!("aps-{}-leg-{ordinal}", phase.label()))
            .stack_size(TEST_STACK_BYTES))
    })
}

/// The builder factory permits deterministic launch-failure ownership controls.
fn collect_three_smoke_phase_jobs_with_builders_v1<T, R, F, B>(
    phase: SmokeLegJobPhaseV1,
    jobs: [T; 3],
    run: F,
    mut builder: B,
) -> Result<Vec<R>>
where
    T: Send,
    R: Send,
    F: Fn(usize, T) -> Result<R> + Sync,
    B: FnMut(usize) -> std::io::Result<thread::Builder>,
{
    let diagnostic_context = SmokeDiagnosticScopeV1::capture();
    thread::scope(|scope| {
        let run = &run;
        let mut ordinal = 0;
        let children = jobs.map(|job| {
            let index = ordinal;
            ordinal += 1;
            let context = diagnostic_context.clone();
            let child = builder(index).and_then(|builder| {
                builder.spawn_scoped(scope, move || {
                    let _diagnostics = SmokeDiagnosticScopeV1::install(context);
                    run(index, job)
                })
            });
            (index, child)
        });
        // Array::map performs every join before Result collection can return.
        // Preserve each operation error and choose the first ordinal error only
        // after every initiated worker has physically finished.
        let joined = children.map(|(ordinal, child)| match child {
            Ok(child) => child.join().unwrap_or_else(|_| {
                Err(eyre!(
                    "private-settlement {} leg {ordinal} worker panicked",
                    phase.label()
                ))
            }),
            Err(error) => Err(eyre!(
                "private-settlement {} leg {ordinal} worker could not start: {error}",
                phase.label()
            )),
        });
        joined.into_iter().collect()
    })
}

fn prepare_leg(
    ordinal: usize,
    governed: GovernedLeg,
    manifest: &AtomicPrivateSettlementV1,
    authority_digest: Hash,
) -> Result<PreparedLeg> {
    let private_data = default_private_settlement_leg_data(ordinal);
    prepare_leg_with_private_data(ordinal, governed, manifest, authority_digest, &private_data)
}

fn prepare_leg_with_private_data(
    ordinal: usize,
    governed: GovernedLeg,
    manifest: &AtomicPrivateSettlementV1,
    authority_digest: Hash,
    private_data: &PrivateSettlementLegPrivateData,
) -> Result<PreparedLeg> {
    let output_rng_seed = private_settlement_leg_private_material(
        manifest,
        &governed,
        ordinal,
        0,
        b"output-encryption-rng",
    );
    let capsule_rng_seed = private_settlement_leg_private_material(
        manifest,
        &governed,
        ordinal,
        0,
        b"audit-capsule-rng",
    );
    let mut output_rng = iroha_crypto::rng_from_seed_slice(&output_rng_seed);
    let mut capsule_rng = iroha_crypto::rng_from_seed_slice(&capsule_rng_seed);
    prepare_leg_with_private_data_and_rngs(
        ordinal,
        governed,
        manifest,
        authority_digest,
        private_data,
        &mut output_rng,
        &mut capsule_rng,
    )
}

fn prepare_leg_with_private_data_and_rngs(
    ordinal: usize,
    governed: GovernedLeg,
    manifest: &AtomicPrivateSettlementV1,
    authority_digest: Hash,
    private_data: &PrivateSettlementLegPrivateData,
    output_rng: &mut (impl rand_core_06::RngCore + rand_core_06::CryptoRng),
    capsule_rng: &mut impl rand::rand_core::TryCryptoRng,
) -> Result<PreparedLeg> {
    let witness_timing = SmokeDiagnosticSpanV1::start(
        SmokeDiagnosticPhaseV1::WitnessAndCapsulePreparation,
        Some(ordinal),
    );
    let profile = PrivateSettlementProofProfileV1::IvmPrivateNoteFixed2In3Out;
    let placeholders = [
        placeholder_encrypted_output(0x11 + ordinal as u8 * 6),
        placeholder_encrypted_output(0x13 + ordinal as u8 * 6),
        placeholder_encrypted_output(0x15 + ordinal as u8 * 6),
    ];
    let mut statement = PrivateSettlementProofStatementV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        profile,
        proof_profile_digest: profile.digest(),
        network_id: manifest.network_id,
        bundle_id: manifest.bundle_id,
        leg_ordinal: ordinal as u8,
        route: governed.route,
        authority_context_height: manifest.authority_context_height,
        pool_id: governed.governance.body.pool_id,
        asset_binding_commitment: governed.governance.body.asset_binding_commitment,
        old_root: PrivacyRootV1::new(bytes(0x20 + ordinal as u8)),
        new_root: PrivacyRootV1::new(bytes(0x24 + ordinal as u8)),
        old_epoch: 1,
        new_epoch: 2,
        nullifiers: vec![
            PrivacyNullifierV1::new(bytes(0x30 + ordinal as u8 * 2)),
            PrivacyNullifierV1::new(bytes(0x31 + ordinal as u8 * 2)),
        ],
        output_commitments: placeholders
            .iter()
            .map(|output| output.commitment)
            .collect(),
        encrypted_outputs: placeholders.to_vec(),
        audit_plaintext_commitment: hash(0x40 + ordinal as u8),
        audit_input_commitment: [0x48 + ordinal as u8; 32],
        audit_capsule_digest: hash(0x50 + ordinal as u8),
        audit_policy_digest: governed.policy.policy_digest,
        audit_key_epoch: governed.policy.body.key_epoch,
        fee_intent_digest: manifest.fee_intent_digest,
        reimbursement_terms_commitment: manifest.reimbursement_terms_commitment,
        reimbursement_leg_ordinal: manifest.reimbursement_leg_ordinal,
        expiry_height: manifest.expiry_height,
    };
    statement.validate()?;

    let payer = &private_data.payer;
    let recipient = &private_data.recipient;
    let funding =
        private_settlement_funding(manifest.network_id, &governed, ordinal, private_data)?;
    let initial_commitments = funding.activation_commitments();
    let input_secrets = [
        funding.spending_secret,
        private_settlement_leg_private_material(
            manifest,
            &governed,
            ordinal,
            1,
            b"input-spending-secret",
        ),
    ];
    let output_secrets = [
        private_settlement_leg_private_material(
            manifest,
            &governed,
            ordinal,
            0,
            b"output-spending-secret",
        ),
        private_settlement_leg_private_material(
            manifest,
            &governed,
            ordinal,
            1,
            b"output-spending-secret",
        ),
        private_settlement_leg_private_material(
            manifest,
            &governed,
            ordinal,
            2,
            b"output-spending-secret",
        ),
    ];
    let view_secrets = [
        private_settlement_leg_private_material(
            manifest,
            &governed,
            ordinal,
            0,
            b"output-view-secret",
        ),
        private_settlement_leg_private_material(
            manifest,
            &governed,
            ordinal,
            1,
            b"output-view-secret",
        ),
        private_settlement_leg_private_material(
            manifest,
            &governed,
            ordinal,
            2,
            b"output-view-secret",
        ),
    ];
    let ephemeral_secrets = [
        private_settlement_leg_private_material(
            manifest,
            &governed,
            ordinal,
            0,
            b"output-ephemeral-secret",
        ),
        private_settlement_leg_private_material(
            manifest,
            &governed,
            ordinal,
            1,
            b"output-ephemeral-secret",
        ),
        private_settlement_leg_private_material(
            manifest,
            &governed,
            ordinal,
            2,
            b"output-ephemeral-secret",
        ),
    ];
    let reimbursement = if ordinal == 0 { 5 } else { 0 };
    let change = 7;
    let amount = private_data.amount;
    let mut plaintext = PrivateSettlementAuditPlaintextV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        network_id: manifest.network_id,
        bundle_id: manifest.bundle_id,
        leg_ordinal: ordinal as u8,
        route: governed.route,
        pool_id: governed.governance.body.pool_id,
        payer: AccountId::new(payer.public_key().clone()),
        payer_authorization: placeholder_payer_authorization(
            manifest.network_id,
            governed.route,
            payer,
            manifest.expiry_height,
        ),
        recipient: AccountId::new(recipient.public_key().clone()),
        sponsor: manifest.sponsor.clone(),
        asset_definition_id: governed.governance.body.asset_definition_id.clone(),
        asset_binding_salt: governed.governance.body.asset_binding_salt,
        amount,
        sponsor_reimbursement_amount: reimbursement,
        fee_intent_digest: manifest.fee_intent_digest,
        settlement_expiry_height: manifest.expiry_height,
        reimbursement_terms_salt: private_settlement_reimbursement_terms_salt(manifest, &governed),
        memo: private_data.memo.clone(),
        policy_references: vec![governed.governance.governance_digest],
        inputs: vec![
            funding.opening,
            note_opening(manifest, &governed, ordinal, b"input-note", 1, false, 0),
        ],
        outputs: vec![
            PrivateSettlementAuditOutputV1 {
                role: PrivateSettlementAuditOutputRoleV1::SettlementRecipient,
                recipient_view_key: ivm_private_recipient_public_key_v1(&view_secrets[0])?,
                view_key_authorization: placeholder_view_authorization(
                    manifest.network_id,
                    governed.route,
                    recipient,
                    manifest.expiry_height,
                ),
                encryption_opening: PrivateSettlementAuditEncryptionOpeningV1 {
                    ephemeral_secret: ephemeral_secrets[0],
                },
                note: note_opening(
                    manifest,
                    &governed,
                    ordinal,
                    b"output-note",
                    0,
                    true,
                    amount,
                ),
            },
            PrivateSettlementAuditOutputV1 {
                role: PrivateSettlementAuditOutputRoleV1::PayerChange,
                recipient_view_key: ivm_private_recipient_public_key_v1(&view_secrets[1])?,
                view_key_authorization: placeholder_view_authorization(
                    manifest.network_id,
                    governed.route,
                    payer,
                    manifest.expiry_height,
                ),
                encryption_opening: PrivateSettlementAuditEncryptionOpeningV1 {
                    ephemeral_secret: ephemeral_secrets[1],
                },
                note: note_opening(
                    manifest,
                    &governed,
                    ordinal,
                    b"output-note",
                    1,
                    true,
                    change,
                ),
            },
            PrivateSettlementAuditOutputV1 {
                role: PrivateSettlementAuditOutputRoleV1::SponsorReimbursement,
                recipient_view_key: ivm_private_recipient_public_key_v1(&view_secrets[2])?,
                view_key_authorization: placeholder_view_authorization(
                    manifest.network_id,
                    governed.route,
                    &ALICE_KEYPAIR,
                    manifest.expiry_height,
                ),
                encryption_opening: PrivateSettlementAuditEncryptionOpeningV1 {
                    ephemeral_secret: ephemeral_secrets[2],
                },
                note: note_opening(
                    manifest,
                    &governed,
                    ordinal,
                    b"output-note",
                    2,
                    ordinal == 0,
                    reimbursement,
                ),
            },
        ],
    };
    for (opening, secret) in plaintext.inputs.iter_mut().zip(input_secrets) {
        opening.spending_authority = derive_note_authority_v1(&secret)?;
    }
    for (output, secret) in plaintext.outputs.iter_mut().zip(output_secrets) {
        output.note.spending_authority = derive_note_authority_v1(&secret)?;
    }
    prepare_atomic_private_settlement_input_openings_v1(
        manifest,
        &statement,
        &mut plaintext.inputs,
    )?;
    ensure!(
        plaintext.inputs[0].commitment == funding.input_commitments[0],
        "settlement changed its already-funded positive input"
    );
    statement.nullifiers = derive_atomic_private_settlement_input_nullifiers_v1(
        manifest,
        &statement,
        &plaintext.inputs,
        &input_secrets,
    )?
    .to_vec();
    let payer_body = plaintext.payer_authorization_body(&statement.nullifiers)?;
    plaintext.payer_authorization = PrivateSettlementAuditPayerAuthorizationV1::new(
        payer_body.clone(),
        vec![PrivateSettlementAuditPayerSignatureV1::new(
            payer.public_key().clone(),
            SignatureOf::try_new(payer.private_key(), &payer_body)?,
        )],
    );
    for (index, signer) in [recipient, payer, &*ALICE_KEYPAIR].into_iter().enumerate() {
        let body = plaintext.output_view_key_authorization_body(index)?;
        plaintext.outputs[index].view_key_authorization =
            PrivateSettlementAuditViewKeyAuthorizationV1::new(
                body.clone(),
                vec![PrivateSettlementAuditViewKeySignatureV1::new(
                    signer.public_key().clone(),
                    SignatureOf::try_new(signer.private_key(), &body)?,
                )],
            );
    }
    statement.audit_plaintext_commitment = plaintext.commitment()?;
    statement.audit_input_commitment =
        atomic_private_settlement_audit_input_commitment_v1(&plaintext.inputs)?;
    statement.encrypted_outputs = prepare_atomic_private_settlement_outputs_v1(
        output_rng,
        manifest,
        &statement,
        &mut plaintext.outputs,
    )?;
    statement.output_commitments = plaintext
        .outputs
        .iter()
        .map(|output| output.note.commitment)
        .collect();
    let canonical_plaintext = norito::encode_canonical(&plaintext)?;
    let aad = PrivateSettlementAuditAadV1 {
        network_id: manifest.network_id,
        bundle_id: manifest.bundle_id,
        leg_ordinal: ordinal as u8,
        route: governed.route,
        authority_digest,
        authority_context_height: manifest.authority_context_height,
        audit_policy_digest: governed.policy.policy_digest,
        audit_key_epoch: governed.policy.body.key_epoch,
        plaintext_commitment: statement.audit_plaintext_commitment,
    };
    let capsule = seal_private_settlement_audit_capsule_v1_with_rng(
        &canonical_plaintext,
        aad,
        PrivateSettlementCapsulePaddingV1::KiB16,
        &governed.policy,
        capsule_rng,
    )?;
    statement.audit_capsule_digest = capsule.digest()?;
    let bootstrap = plan_atomic_private_settlement_bootstrap_v1(
        statement.pool_id,
        funding.input_commitments,
        statement
            .output_commitments
            .as_slice()
            .try_into()
            .map_err(|_| eyre!("private settlement output commitment shape changed"))?,
        input_secrets,
    )?;
    ensure!(
        bootstrap.initial_commitments == initial_commitments,
        "bootstrap origin differs from the canonically activated funding"
    );
    statement.old_root = bootstrap.old_root;
    statement.new_root = bootstrap.new_root;
    statement.old_epoch = bootstrap.old_epoch;
    statement.new_epoch = bootstrap.new_epoch;
    statement.validate()?;
    let wallet_id = format!("atomic-private-settlement-release-leg-{ordinal}");
    let owner_bundle = encode_atomic_private_settlement_wallet_bundle_v1(
        &wallet_id,
        manifest,
        &statement,
        &capsule,
        &governed.policy,
        &plaintext,
        &bootstrap.into_input_secrets(),
    )?;
    let mut owner_material = owner_bundle.to_vec();
    witness_timing.complete();
    let proof_timing = SmokeDiagnosticSpanV1::start(
        SmokeDiagnosticPhaseV1::ProofConstructionWithSelfVerification,
        Some(ordinal),
    );
    let prepared = consume_atomic_private_settlement_wallet_bundle_v1(
        &mut owner_material,
        &wallet_id,
        manifest,
        &statement,
        &capsule,
        &governed.policy,
        *manifest.network_id.as_genesis_hash().as_ref(),
        manifest.authority_context_height,
    )?;
    proof_timing.complete();
    ensure!(
        owner_material.iter().all(|byte| *byte == 0),
        "owner bundle was not wiped"
    );
    let completion_timing =
        SmokeDiagnosticSpanV1::start(SmokeDiagnosticPhaseV1::PreparedLegCompletion, Some(ordinal));
    let prepared = complete_atomic_private_settlement_prepared_leg_v1(prepared)?;
    completion_timing.complete();
    Ok(PreparedLeg { governed, prepared })
}

fn provisional_materials(
    manifest: AtomicPrivateSettlementV1,
    prepared: &[PreparedLeg],
    committees: &[CommitteeEndpoints],
) -> Result<Vec<PrivateSettlementProvisionalLegMaterialV1>> {
    ensure!(
        prepared.len() == committees.len() && prepared.len() == manifest.legs.len(),
        "private-settlement prepared-leg and committee counts must match the manifest"
    );
    let retention_until_height = manifest
        .authority_context_height
        .checked_add(SIDECAR_RETENTION_BLOCKS)
        .and_then(|height| height.checked_add(512))
        .ok_or_else(|| eyre!("private-settlement sidecar retention height overflow"))?;
    let inputs = prepared
        .iter()
        .zip(committees)
        .map(|(leg, committee)| {
            AtomicPrivateSettlementProvisionalLegInputV1::new(
                leg.prepared.clone(),
                leg.governed.policy.clone(),
                committee.authority.clone(),
                retention_until_height,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(finalize_atomic_private_settlement_provisional_bundle_v1(manifest, inputs)?.materials)
}

/// Keep receipt diagnostics scoped to one query without changing its returned value.
fn observe_smoke_receipt_job_v1<R>(
    context: Option<SmokeDiagnosticContextV1>,
    reported_finalized: &AtomicBool,
    query: impl FnOnce() -> R,
    finalized_height: impl FnOnce(&R) -> Option<u64>,
) -> R {
    let _diagnostics = SmokeDiagnosticScopeV1::install(context);
    let response = query();
    if let Some(height) = finalized_height(&response)
        && !reported_finalized.swap(true, Ordering::Relaxed)
    {
        observe_smoke_diagnostic_milestone_v1(
            SmokeDiagnosticPhaseV1::FinalizedReceiptReported,
            height,
        );
    }
    response
}

#[cfg(test)]
#[path = "atomic_private_settlement_receipt_observation_tests.rs"]
mod receipt_observation_controls;

fn assert_no_partial_visibility(network: &Network, bundle_id: Hash, phase: &str) -> Result<()> {
    let peers = network.all_peers().cloned().collect::<Vec<_>>();
    ensure!(!peers.is_empty(), "pending observations omitted every peer");
    let observations = collect_bounded_observations(peers, TEST_STACK_BYTES, |peer| {
        let response = peer
            .client()
            .client()
            .private_settlement_bundle_receipt_v1(bundle_id);
        (peer.id(), response)
    });
    let mut failures = Vec::new();
    for (peer_id, response) in observations {
        match response {
            Ok(PrivateSettlementBundleReceiptResponseV1::Pending { .. }) => {}
            Ok(PrivateSettlementBundleReceiptResponseV1::Finalized(receipt)) => {
                failures.push(format!(
                    "{phase}: peer {peer_id} exposed {} finalized legs before global carrier",
                    receipt.legs.len()
                ));
            }
            Ok(PrivateSettlementBundleReceiptResponseV1::Aborted(_)) => {
                failures.push(format!("{phase}: peer {peer_id} exposed an unexpected abort"));
            }
            Err(error) => failures.push(format!(
                "{phase}: peer {peer_id} receipt query failed instead of proving pending state: {error:?}"
            )),
        }
    }
    ensure!(failures.is_empty(), "{}", failures.join("; "));
    Ok(())
}

fn wait_for_identical_receipt(
    network: &Network,
    bundle_id: Hash,
) -> Result<iroha::data_model::nexus::PrivateSettlementReceiptV1> {
    let started = Instant::now();
    let mut last = String::new();
    let reported_finalized = AtomicBool::new(false);
    while started.elapsed() < FINALITY_TIMEOUT {
        let peers = network.all_peers().cloned().collect::<Vec<_>>();
        let expected_observations = peers.len();
        ensure!(
            expected_observations > 0,
            "receipt observations omitted every peer"
        );
        let diagnostic_context = SmokeDiagnosticScopeV1::capture();
        let observations = collect_bounded_observations(peers, TEST_STACK_BYTES, |peer| {
            let response = observe_smoke_receipt_job_v1(
                diagnostic_context.clone(),
                &reported_finalized,
                || {
                    peer.client()
                        .client()
                        .private_settlement_bundle_receipt_v1(bundle_id)
                },
                |response| match response {
                    Ok(PrivateSettlementBundleReceiptResponseV1::Finalized(receipt)) => {
                        Some(receipt.finalized_height)
                    }
                    _ => None,
                },
            );
            (peer.id(), response)
        });
        let mut receipts = Vec::new();
        let mut not_finalized = Vec::new();
        for (peer_id, response) in observations {
            match response {
                Ok(PrivateSettlementBundleReceiptResponseV1::Finalized(receipt)) => {
                    receipts.push(receipt);
                }
                Ok(other) => not_finalized.push(format!("{peer_id} returned {other:?}")),
                Err(error) => not_finalized.push(format!("{peer_id}: {error:?}")),
            }
        }
        if receipts.len() == expected_observations {
            if receipts.windows(2).all(|pair| pair[0] == pair[1]) {
                return Ok(receipts.remove(0));
            }
            last = "all peers finalized, but their receipts differ".to_owned();
        } else {
            last = not_finalized.join("; ");
        }
        thread::sleep(POLL_INTERVAL);
    }
    Err(benchmark_deadline_error(
        BenchmarkDeadlineStageV1::PrivateReceipt,
        FINALITY_TIMEOUT,
        started.elapsed(),
    )
    .wrap_err(format!(
        "all peers did not converge on one atomic receipt: {last}"
    )))
}

// Diagnostic observer only. These records do not enter registered release metrics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SmokeDiagnosticPhaseV1 {
    NetworkStartup,
    PrivacyActivation,
    PoolActivation,
    EndToEndWorkflow,
    ClientLegConstruction,
    WitnessAndCapsulePreparation,
    ProofConstructionWithSelfVerification,
    PreparedLegCompletion,
    AvailabilityCertification,
    RestrictedUpload,
    AuditorApproval,
    PrepareCertification,
    PrepareRegistration,
    CommitCertification,
    FinalityWorkflow,
    FinalizationSubmission,
    AllPeerReceipt,
    FinalizedReceiptReported,
    FinancialApplicationVerified,
    SignedFinalityEvidence,
    ReplayValidation,
    RestartReconciliation,
}

impl SmokeDiagnosticPhaseV1 {
    fn label(self) -> &'static str {
        match self {
            Self::NetworkStartup => "network_startup",
            Self::PrivacyActivation => "privacy_activation",
            Self::PoolActivation => "pool_activation",
            Self::EndToEndWorkflow => "end_to_end_workflow",
            Self::ClientLegConstruction => "client_leg_construction",
            Self::WitnessAndCapsulePreparation => "witness_and_capsule_preparation",
            Self::ProofConstructionWithSelfVerification => {
                "proof_construction_with_self_verification"
            }
            Self::PreparedLegCompletion => "prepared_leg_completion",
            Self::AvailabilityCertification => "availability_certification",
            Self::RestrictedUpload => "restricted_upload",
            Self::AuditorApproval => "auditor_approval",
            Self::PrepareCertification => "prepare_certification",
            Self::PrepareRegistration => "prepare_registration",
            Self::CommitCertification => "commit_certification",
            Self::FinalityWorkflow => "finality_workflow",
            Self::FinalizationSubmission => "finalization_submission",
            Self::AllPeerReceipt => "all_peer_receipt",
            Self::FinalizedReceiptReported => "finalized_receipt_reported",
            Self::FinancialApplicationVerified => "financial_application_verified",
            Self::SignedFinalityEvidence => "signed_finality_evidence",
            Self::ReplayValidation => "replay_validation",
            Self::RestartReconciliation => "restart_reconciliation",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SmokeDiagnosticKindV1 {
    Begin,
    Complete,
    Incomplete,
    Observation,
}

#[derive(Clone, Copy, Debug)]
struct SmokeDiagnosticEventV1 {
    kind: SmokeDiagnosticKindV1,
    phase: SmokeDiagnosticPhaseV1,
    span: u64,
    parent: u64,
    leg: Option<usize>,
    start_ns: u128,
    end_ns: u128,
    height: Option<u64>,
}

/// Fixed labels and public numbers only; never format a request, witness or error.
fn write_smoke_diagnostic_event_v1(
    writer: &mut impl std::io::Write,
    event: SmokeDiagnosticEventV1,
) -> std::io::Result<()> {
    let kind = match event.kind {
        SmokeDiagnosticKindV1::Begin => "begin",
        SmokeDiagnosticKindV1::Complete => "complete",
        SmokeDiagnosticKindV1::Incomplete => "incomplete",
        SmokeDiagnosticKindV1::Observation => "observation",
    };
    let leg = event
        .leg
        .map_or_else(|| "none".to_owned(), |leg| leg.to_string());
    let height = event
        .height
        .map_or_else(|| "none".to_owned(), |height| height.to_string());
    use std::io::Write as _;
    // Construct the complete bounded record before touching the shared sink.
    // A sink accepting the whole buffer sees one write, avoiding field interleaving.
    let mut record = std::io::Cursor::new([0_u8; 512]);
    writeln!(
        &mut record,
        "APS_DIAGNOSTIC_TIMING_V1 kind={kind} phase={} span={} parent={} leg={leg} start_ns={} end_ns={} duration_ns={} height={height}",
        event.phase.label(),
        event.span,
        event.parent,
        event.start_ns,
        event.end_ns,
        event.end_ns.saturating_sub(event.start_ns)
    )?;
    let length = record.position() as usize;
    writer.write_all(&record.get_ref()[..length])
}

fn emit_smoke_diagnostic_to_v1(writer: &mut impl std::io::Write, event: SmokeDiagnosticEventV1) {
    // Observability must never replace the underlying operation's result.
    let _ = write_smoke_diagnostic_event_v1(writer, event);
}

fn emit_smoke_diagnostic_v1(event: SmokeDiagnosticEventV1) {
    emit_smoke_diagnostic_to_v1(&mut std::io::stderr().lock(), event);
}

#[derive(Clone)]
struct SmokeDiagnosticContextV1 {
    origin: std::time::Instant,
    next_span: std::sync::Arc<std::sync::atomic::AtomicU64>,
    active: Vec<u64>,
}

std::thread_local! {
    // Enabled only inside the N3 diagnostic and its explicitly scoped workers.
    // Registered benchmark helpers otherwise remain observationally unchanged.
    static SMOKE_DIAGNOSTIC_CONTEXT_V1: std::cell::RefCell<Option<SmokeDiagnosticContextV1>> = const { std::cell::RefCell::new(None) };
}

struct SmokeDiagnosticScopeV1 {
    owns_context: bool,
    previous_context: Option<SmokeDiagnosticContextV1>,
}

impl SmokeDiagnosticScopeV1 {
    fn start() -> Self {
        let owns_context = SMOKE_DIAGNOSTIC_CONTEXT_V1
            .try_with(|cell| {
                let Ok(mut context) = cell.try_borrow_mut() else {
                    return false;
                };
                if context.is_some() {
                    return false;
                }
                *context = Some(SmokeDiagnosticContextV1 {
                    origin: std::time::Instant::now(),
                    next_span: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1)),
                    active: Vec::new(),
                });
                true
            })
            .unwrap_or(false);
        Self {
            owns_context,
            previous_context: None,
        }
    }

    fn capture() -> Option<SmokeDiagnosticContextV1> {
        SMOKE_DIAGNOSTIC_CONTEXT_V1
            .try_with(|cell| cell.try_borrow().ok().and_then(|context| context.clone()))
            .ok()
            .flatten()
    }

    fn install(context: Option<SmokeDiagnosticContextV1>) -> Self {
        let previous = SMOKE_DIAGNOSTIC_CONTEXT_V1
            .try_with(|cell| {
                let mut current = cell.try_borrow_mut().ok()?;
                Some(std::mem::replace(&mut *current, context))
            })
            .ok()
            .flatten();
        match previous {
            Some(previous_context) => Self {
                owns_context: true,
                previous_context,
            },
            None => Self {
                owns_context: false,
                previous_context: None,
            },
        }
    }
}

impl Drop for SmokeDiagnosticScopeV1 {
    fn drop(&mut self) {
        if self.owns_context {
            let _ = SMOKE_DIAGNOSTIC_CONTEXT_V1.try_with(|cell| {
                if let Ok(mut context) = cell.try_borrow_mut() {
                    *context = self.previous_context.take();
                }
            });
        }
    }
}

struct SmokeDiagnosticSpanV1 {
    event: Option<SmokeDiagnosticEventV1>,
}

impl SmokeDiagnosticSpanV1 {
    fn start(phase: SmokeDiagnosticPhaseV1, leg: Option<usize>) -> Self {
        let event = SMOKE_DIAGNOSTIC_CONTEXT_V1
            .try_with(|cell| {
                let mut context = cell.try_borrow_mut().ok()?;
                let context = context.as_mut()?;
                // IDs are shared across workers; timing stacks remain thread-local.
                // Relaxed order is sufficient for uniqueness, not clock ordering.
                let span = context
                    .next_span
                    .fetch_update(
                        std::sync::atomic::Ordering::Relaxed,
                        std::sync::atomic::Ordering::Relaxed,
                        |next| next.checked_add(1),
                    )
                    .ok()?;
                let parent = context.active.last().copied().unwrap_or(0);
                let at_ns = context.origin.elapsed().as_nanos();
                context.active.push(span);
                Some(SmokeDiagnosticEventV1 {
                    kind: SmokeDiagnosticKindV1::Begin,
                    phase,
                    span,
                    parent,
                    leg,
                    start_ns: at_ns,
                    end_ns: at_ns,
                    height: None,
                })
            })
            .ok()
            .flatten();
        if let Some(event) = event {
            emit_smoke_diagnostic_v1(event);
        }
        Self { event }
    }

    fn close(&mut self, kind: SmokeDiagnosticKindV1) {
        let Some(mut event) = self.event.take() else {
            return;
        };
        let ended = SMOKE_DIAGNOSTIC_CONTEXT_V1
            .try_with(|cell| {
                let mut context = cell.try_borrow_mut().ok()?;
                let context = context.as_mut()?;
                let ended = context.origin.elapsed().as_nanos();
                context.active.retain(|span| *span != event.span);
                Some(ended)
            })
            .ok()
            .flatten();
        if let Some(ended) = ended {
            event.kind = kind;
            event.end_ns = ended;
            emit_smoke_diagnostic_v1(event);
        }
    }

    fn complete(mut self) {
        self.close(SmokeDiagnosticKindV1::Complete);
    }
}

impl Drop for SmokeDiagnosticSpanV1 {
    fn drop(&mut self) {
        self.close(SmokeDiagnosticKindV1::Incomplete);
    }
}

fn observe_smoke_diagnostic_milestone_v1(phase: SmokeDiagnosticPhaseV1, height: u64) {
    let event = SMOKE_DIAGNOSTIC_CONTEXT_V1
        .try_with(|cell| {
            let context = cell.try_borrow().ok()?;
            let context = context.as_ref()?;
            let at_ns = context.origin.elapsed().as_nanos();
            Some(SmokeDiagnosticEventV1 {
                kind: SmokeDiagnosticKindV1::Observation,
                phase,
                span: 0,
                parent: context.active.last().copied().unwrap_or(0),
                leg: None,
                start_ns: at_ns,
                end_ns: at_ns,
                height: Some(height),
            })
        })
        .ok()
        .flatten();
    if let Some(event) = event {
        emit_smoke_diagnostic_v1(event);
    }
}

#[test]
fn smoke_three_leg_jobs_overlap_and_reduce_reverse_completion_in_ordinal_order() {
    for phase in [
        SmokeLegJobPhaseV1::Proof,
        SmokeLegJobPhaseV1::AvailabilityCertification,
        SmokeLegJobPhaseV1::RestrictedUpload,
    ] {
        use std::collections::BTreeSet;
        use std::sync::{Mutex, mpsc};
        let (started_tx, started_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let (release_tx, release_rx): (Vec<_>, Vec<_>) = (0..3).map(|_| mpsc::channel()).unzip();
        let release_rx = release_rx.into_iter().map(Mutex::new).collect::<Vec<_>>();
        let timeout = Duration::from_secs(5);
        let results = thread::scope(|scope| {
            let controller = scope.spawn(move || {
                let started = (0..3)
                    .map(|_| {
                        started_rx
                            .recv_timeout(timeout)
                            .expect("all three jobs overlap")
                    })
                    .collect::<BTreeSet<_>>();
                assert_eq!(started, BTreeSet::from([0, 1, 2]));
                for ordinal in (0..3).rev() {
                    release_tx[ordinal].send(()).expect("release live worker");
                    assert_eq!(
                        finished_rx.recv_timeout(timeout).expect("worker completed"),
                        ordinal
                    );
                }
            });
            let results =
                collect_three_smoke_phase_jobs_v1(phase, [10, 20, 30], |ordinal, value| {
                    started_tx.send(ordinal).expect("controller observes job");
                    release_rx[ordinal]
                        .lock()
                        .expect("receiver lock")
                        .recv_timeout(timeout)
                        .expect("controller releases job");
                    finished_tx
                        .send(ordinal)
                        .expect("controller observes finish");
                    Ok(value)
                });
            controller.join().expect("controller joined");
            results.expect("all proof owners joined")
        });
        assert_eq!(results, [10, 20, 30]);
    }
}

#[test]
fn smoke_three_leg_jobs_join_all_before_returning_first_ordinal_proof_error() {
    for phase in [
        SmokeLegJobPhaseV1::Proof,
        SmokeLegJobPhaseV1::AvailabilityCertification,
        SmokeLegJobPhaseV1::RestrictedUpload,
    ] {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let finished = AtomicUsize::new(0);
        let result =
            collect_three_smoke_phase_jobs_v1(phase, [0, 1, 2], |ordinal, _| -> Result<usize> {
                finished.fetch_or(1 << ordinal, Ordering::SeqCst);
                if ordinal < 2 {
                    Err(eyre!("proof error at ordinal {ordinal}"))
                } else {
                    Ok(ordinal)
                }
            });
        assert_eq!(finished.load(Ordering::SeqCst), 0b111);
        assert_eq!(result.unwrap_err().to_string(), "proof error at ordinal 0");
    }
}

#[test]
fn smoke_three_leg_jobs_join_every_owner_after_worker_panic() {
    for phase in [
        SmokeLegJobPhaseV1::Proof,
        SmokeLegJobPhaseV1::AvailabilityCertification,
        SmokeLegJobPhaseV1::RestrictedUpload,
    ] {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Finished<'a>(&'a AtomicUsize, usize);
        impl Drop for Finished<'_> {
            fn drop(&mut self) {
                self.0.fetch_or(1 << self.1, Ordering::SeqCst);
            }
        }
        let finished = AtomicUsize::new(0);
        let result = collect_three_smoke_phase_jobs_v1(phase, [0, 1, 2], |ordinal, _| {
            let _finished = Finished(&finished, ordinal);
            assert_ne!(ordinal, 0, "intentional proof worker panic");
            Ok(ordinal)
        });
        assert_eq!(finished.load(Ordering::SeqCst), 0b111);
        assert_eq!(
            result.unwrap_err().to_string(),
            format!("private-settlement {} leg 0 worker panicked", phase.label())
        );
    }
}

#[test]
fn smoke_three_leg_jobs_attempt_all_launches_and_join_after_launch_failure() {
    for phase in [
        SmokeLegJobPhaseV1::Proof,
        SmokeLegJobPhaseV1::AvailabilityCertification,
        SmokeLegJobPhaseV1::RestrictedUpload,
    ] {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let attempted = AtomicUsize::new(0);
        let finished = AtomicUsize::new(0);
        let result = collect_three_smoke_phase_jobs_with_builders_v1(
            phase,
            [0, 1, 2],
            |ordinal, _| {
                finished.fetch_or(1 << ordinal, Ordering::SeqCst);
                Ok(ordinal)
            },
            |ordinal| {
                attempted.fetch_or(1 << ordinal, Ordering::SeqCst);
                if ordinal == 1 {
                    Err(std::io::Error::other("controlled builder failure"))
                } else {
                    Ok(thread::Builder::new())
                }
            },
        );
        assert_eq!(attempted.load(Ordering::SeqCst), 0b111);
        assert_eq!(finished.load(Ordering::SeqCst), 0b101);
        assert_eq!(
            result.unwrap_err().to_string(),
            format!(
                "private-settlement {} leg 1 worker could not start: controlled builder failure",
                phase.label()
            )
        );
    }
}

#[test]
fn smoke_network_leg_jobs_preserve_phase_barrier_and_endpoint_order() {
    use std::sync::Mutex;

    // These are scheduling tokens, not availability certificates or HTTP samples.
    // The compile-time bounds also check the actual immutable worker captures.
    fn require_send_sync<T: Send + Sync>() {}
    require_send_sync::<SdkClient>();
    require_send_sync::<CommitteeEndpoints>();
    require_send_sync::<PrivateSettlementProvisionalLegMaterialV1>();
    require_send_sync::<PrivateSettlementLegUploadRequestV1>();

    let certification_calls: [Mutex<Vec<usize>>; 3] =
        std::array::from_fn(|_| Mutex::new(Vec::new()));
    let certificates = collect_three_smoke_phase_jobs_v1(
        SmokeLegJobPhaseV1::AvailabilityCertification,
        [10, 20, 30],
        |ordinal, value| {
            for endpoint in 0..4 {
                certification_calls[ordinal].lock().unwrap().push(endpoint);
            }
            Ok((ordinal, value))
        },
    )
    .expect("all certificate jobs joined");
    assert_eq!(certificates, [(0, 10), (1, 20), (2, 30)]);
    for calls in &certification_calls {
        assert_eq!(*calls.lock().unwrap(), [0, 1, 2, 3]);
    }

    let upload_calls: [Mutex<Vec<(usize, i32, usize)>>; 3] =
        std::array::from_fn(|_| Mutex::new(Vec::new()));
    let uploaded = collect_three_smoke_phase_jobs_v1(
        SmokeLegJobPhaseV1::RestrictedUpload,
        std::array::from_fn(|ordinal| &certificates[ordinal]),
        |ordinal, certificate| {
            // Upload cannot observe any incomplete certificate leg, even when
            // the network jobs run in a different order from the manifest.
            for calls in &certification_calls {
                assert_eq!(*calls.lock().unwrap(), [0, 1, 2, 3]);
            }
            assert_eq!(certificate.0, ordinal);
            for endpoint in 0..4 {
                upload_calls[ordinal].lock().unwrap().push((
                    certificate.0,
                    certificate.1,
                    endpoint,
                ));
            }
            Ok(*certificate)
        },
    )
    .expect("all upload jobs joined");
    assert_eq!(uploaded, certificates);
    for (ordinal, calls) in upload_calls.iter().enumerate() {
        assert_eq!(
            *calls.lock().unwrap(),
            (0..4)
                .map(|endpoint| (ordinal, certificates[ordinal].1, endpoint))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn smoke_network_leg_jobs_preserve_error_details_and_phase_context() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let _scope = SmokeDiagnosticScopeV1::start();
    let workflow = SmokeDiagnosticSpanV1::start(SmokeDiagnosticPhaseV1::EndToEndWorkflow, None);
    for (phase, timing_phase) in [
        (
            SmokeLegJobPhaseV1::AvailabilityCertification,
            SmokeDiagnosticPhaseV1::AvailabilityCertification,
        ),
        (
            SmokeLegJobPhaseV1::RestrictedUpload,
            SmokeDiagnosticPhaseV1::RestrictedUpload,
        ),
    ] {
        let timing = SmokeDiagnosticSpanV1::start(timing_phase, None);
        let context = SmokeDiagnosticScopeV1::capture().unwrap();
        let next_span = context.next_span.load(Ordering::Relaxed);
        let finished = AtomicUsize::new(0);
        let error = collect_three_smoke_phase_jobs_v1(phase, [0, 1, 2], |ordinal, _| {
            let child = SmokeDiagnosticScopeV1::capture().unwrap();
            assert_eq!(child.origin, context.origin);
            assert_eq!(child.active, context.active);
            assert!(std::sync::Arc::ptr_eq(&child.next_span, &context.next_span));
            finished.fetch_or(1 << ordinal, Ordering::SeqCst);
            if ordinal < 2 {
                return Err(std::io::Error::other(format!(
                    "bounded endpoint failure at leg {ordinal}: HTTP 413"
                ))
                .into());
            }
            Ok(ordinal)
        })
        .unwrap_err();
        assert_eq!(finished.load(Ordering::SeqCst), 0b111);
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().to_string(),
            "bounded endpoint failure at leg 0: HTTP 413"
        );
        assert_eq!(context.next_span.load(Ordering::Relaxed), next_span);
        assert_eq!(
            SmokeDiagnosticScopeV1::capture().unwrap().active,
            context.active
        );
        timing.complete();
        assert_eq!(
            SmokeDiagnosticScopeV1::capture().unwrap().active,
            [workflow.event.unwrap().span]
        );
    }
    workflow.complete();
}

#[test]
fn smoke_worker_diagnostics_share_origin_ids_and_parent_without_sharing_stacks() {
    use std::collections::BTreeSet;
    use std::sync::Arc;
    let scope = SmokeDiagnosticScopeV1::start();
    let workflow = SmokeDiagnosticSpanV1::start(SmokeDiagnosticPhaseV1::EndToEndWorkflow, None);
    let original = SmokeDiagnosticScopeV1::capture().unwrap();
    let parent = workflow.event.unwrap().span;
    let results =
        collect_three_smoke_phase_jobs_v1(SmokeLegJobPhaseV1::Proof, [0, 1, 2], |ordinal, _| {
            let context = SmokeDiagnosticScopeV1::capture().unwrap();
            assert_eq!(context.origin, original.origin);
            assert!(Arc::ptr_eq(&context.next_span, &original.next_span));
            assert_eq!(context.active, [parent]);
            let leg = SmokeDiagnosticSpanV1::start(
                SmokeDiagnosticPhaseV1::ClientLegConstruction,
                Some(ordinal),
            );
            let witness = SmokeDiagnosticSpanV1::start(
                SmokeDiagnosticPhaseV1::WitnessAndCapsulePreparation,
                Some(ordinal),
            );
            let leg_event = leg.event.unwrap();
            let witness_event = witness.event.unwrap();
            assert_eq!(leg_event.parent, parent);
            assert_eq!(witness_event.parent, leg_event.span);
            witness.complete();
            assert_eq!(
                SmokeDiagnosticScopeV1::capture().unwrap().active,
                [parent, leg_event.span]
            );
            leg.complete();
            assert_eq!(SmokeDiagnosticScopeV1::capture().unwrap().active, [parent]);
            Ok([leg_event.span, witness_event.span])
        })
        .expect("joined diagnostic jobs");
    let ids = results.into_iter().flatten().collect::<BTreeSet<_>>();
    assert_eq!(ids, BTreeSet::from([2, 3, 4, 5, 6, 7]));
    assert_eq!(SmokeDiagnosticScopeV1::capture().unwrap().active, [parent]);
    workflow.complete();
    drop(scope);
    assert!(SmokeDiagnosticScopeV1::capture().is_none());
}

#[test]
fn smoke_worker_diagnostics_remain_disabled_without_parent_scope() {
    assert!(SmokeDiagnosticScopeV1::capture().is_none());
    collect_three_smoke_phase_jobs_v1(SmokeLegJobPhaseV1::Proof, [0, 1, 2], |ordinal, _| {
        assert!(SmokeDiagnosticScopeV1::capture().is_none());
        let span = SmokeDiagnosticSpanV1::start(
            SmokeDiagnosticPhaseV1::ClientLegConstruction,
            Some(ordinal),
        );
        assert!(span.event.is_none());
        span.complete();
        Ok(())
    })
    .expect("disabled diagnostics do not alter jobs");
    assert!(SmokeDiagnosticScopeV1::capture().is_none());
}

#[test]
fn smoke_worker_diagnostic_install_restores_context_on_success_error_and_unwind() {
    let _scope = SmokeDiagnosticScopeV1::start();
    let parent = SmokeDiagnosticSpanV1::start(SmokeDiagnosticPhaseV1::EndToEndWorkflow, None);
    let original = SmokeDiagnosticScopeV1::capture().unwrap();
    for outcome in 0..3 {
        let result = std::panic::catch_unwind(|| -> Result<()> {
            let mut installed = original.clone();
            installed.active = vec![100];
            let _installed = SmokeDiagnosticScopeV1::install(Some(installed));
            let _incomplete = SmokeDiagnosticSpanV1::start(
                SmokeDiagnosticPhaseV1::ClientLegConstruction,
                Some(0),
            );
            if outcome == 1 {
                return Err(eyre!("controlled error"));
            }
            assert_ne!(outcome, 2, "controlled unwind");
            Ok(())
        });
        assert_eq!(result.is_err(), outcome == 2);
        if outcome == 1 {
            assert!(result.unwrap().is_err());
        }
        let restored = SmokeDiagnosticScopeV1::capture().unwrap();
        assert_eq!(restored.active, original.active);
        assert_eq!(restored.origin, original.origin);
        assert!(std::sync::Arc::ptr_eq(
            &restored.next_span,
            &original.next_span
        ));
    }
    parent.complete();
}

#[test]
fn smoke_shared_span_counter_exhaustion_never_reuses_identity() {
    let _scope = SmokeDiagnosticScopeV1::start();
    let context = SmokeDiagnosticScopeV1::capture().unwrap();
    context
        .next_span
        .store(u64::MAX, std::sync::atomic::Ordering::Relaxed);
    collect_three_smoke_phase_jobs_v1(SmokeLegJobPhaseV1::Proof, [0, 1, 2], |ordinal, _| {
        let span = SmokeDiagnosticSpanV1::start(
            SmokeDiagnosticPhaseV1::ClientLegConstruction,
            Some(ordinal),
        );
        assert!(span.event.is_none());
        Ok(())
    })
    .expect("diagnostic exhaustion does not replace operation results");
    assert_eq!(
        context.next_span.load(std::sync::atomic::Ordering::Relaxed),
        u64::MAX
    );
    assert!(SmokeDiagnosticScopeV1::capture().unwrap().active.is_empty());
}

#[test]
fn smoke_diagnostic_wire_has_only_declared_public_fields() {
    let event = SmokeDiagnosticEventV1 {
        kind: SmokeDiagnosticKindV1::Complete,
        phase: SmokeDiagnosticPhaseV1::ProofConstructionWithSelfVerification,
        span: 7,
        parent: 2,
        leg: Some(1),
        start_ns: 13,
        end_ns: 41,
        height: None,
    };
    let mut output = Vec::new();
    write_smoke_diagnostic_event_v1(&mut output, event).unwrap();
    assert_eq!(
        String::from_utf8(output).unwrap(),
        "APS_DIAGNOSTIC_TIMING_V1 kind=complete phase=proof_construction_with_self_verification span=7 parent=2 leg=1 start_ns=13 end_ns=41 duration_ns=28 height=none\n"
    );
}

#[test]
fn smoke_diagnostic_disabled_outside_n3_scope() {
    let span = SmokeDiagnosticSpanV1::start(SmokeDiagnosticPhaseV1::ClientLegConstruction, None);
    assert!(span.event.is_none());
    span.complete();
    observe_smoke_diagnostic_milestone_v1(SmokeDiagnosticPhaseV1::FinalizedReceiptReported, 42);
    SMOKE_DIAGNOSTIC_CONTEXT_V1.with(|cell| assert!(cell.borrow().is_none()));
}

#[test]
fn smoke_diagnostic_nested_and_overlapping_spans_keep_identity() {
    let scope = SmokeDiagnosticScopeV1::start();
    let parent = SmokeDiagnosticSpanV1::start(SmokeDiagnosticPhaseV1::EndToEndWorkflow, None);
    let child =
        SmokeDiagnosticSpanV1::start(SmokeDiagnosticPhaseV1::ClientLegConstruction, Some(0));
    let parent_event = parent.event.unwrap();
    let child_event = child.event.unwrap();
    assert_eq!(child_event.parent, parent_event.span);
    assert!(child_event.start_ns >= parent_event.start_ns);
    // Closing one overlapping span must not erase another live span.
    parent.complete();
    SMOKE_DIAGNOSTIC_CONTEXT_V1.with(|cell| {
        assert_eq!(cell.borrow().as_ref().unwrap().active, [child_event.span]);
    });
    child.complete();
    SMOKE_DIAGNOSTIC_CONTEXT_V1
        .with(|cell| assert!(cell.borrow().as_ref().unwrap().active.is_empty()));
    drop(scope);
    SMOKE_DIAGNOSTIC_CONTEXT_V1.with(|cell| assert!(cell.borrow().is_none()));
}

#[test]
fn smoke_diagnostic_early_error_keeps_payload_and_closes_span() {
    let _scope = SmokeDiagnosticScopeV1::start();
    let error = Box::new(23_u8);
    let original = std::ptr::from_ref(error.as_ref());
    let result: std::result::Result<(), Box<u8>> = (|| {
        let _span =
            SmokeDiagnosticSpanV1::start(SmokeDiagnosticPhaseV1::FinalizationSubmission, None);
        Err(error)
    })();
    assert_eq!(std::ptr::from_ref(result.unwrap_err().as_ref()), original);
    SMOKE_DIAGNOSTIC_CONTEXT_V1
        .with(|cell| assert!(cell.borrow().as_ref().unwrap().active.is_empty()));
}

#[test]
fn smoke_diagnostic_failed_sink_never_changes_control_flow() {
    struct Broken;
    impl std::io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let event = SmokeDiagnosticEventV1 {
        kind: SmokeDiagnosticKindV1::Observation,
        phase: SmokeDiagnosticPhaseV1::FinancialApplicationVerified,
        span: 0,
        parent: 1,
        leg: None,
        start_ns: 10,
        end_ns: 10,
        height: Some(42),
    };
    emit_smoke_diagnostic_to_v1(&mut Broken, event);
    let mut output = Vec::new();
    write_smoke_diagnostic_event_v1(&mut output, event).unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("kind=observation phase=financial_application_verified"));
    assert!(output.ends_with("duration_ns=0 height=42\n"));
}

#[test]
fn smoke_diagnostic_maximum_fields_fit_one_complete_sink_write() {
    #[derive(Default)]
    struct Counting {
        writes: usize,
        bytes: Vec<u8>,
    }
    impl std::io::Write for Counting {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.writes += 1;
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut output = Counting::default();
    let event = SmokeDiagnosticEventV1 {
        kind: SmokeDiagnosticKindV1::Observation,
        phase: SmokeDiagnosticPhaseV1::ProofConstructionWithSelfVerification,
        span: u64::MAX,
        parent: u64::MAX,
        leg: Some(usize::MAX),
        start_ns: 0,
        end_ns: u128::MAX,
        height: Some(u64::MAX),
    };
    write_smoke_diagnostic_event_v1(&mut output, event).unwrap();
    assert_eq!(output.writes, 1);
    assert!(output.bytes.len() < 512);
    let expected = format!(
        "APS_DIAGNOSTIC_TIMING_V1 kind=observation phase=proof_construction_with_self_verification span={} parent={} leg={} start_ns=0 end_ns={} duration_ns={} height={}\n",
        u64::MAX,
        u64::MAX,
        usize::MAX,
        u128::MAX,
        u128::MAX,
        u64::MAX
    );
    assert_eq!(output.bytes, expected.as_bytes());
    output = Counting::default();
    write_smoke_diagnostic_event_v1(
        &mut output,
        SmokeDiagnosticEventV1 {
            start_ns: u128::MAX,
            ..event
        },
    )
    .unwrap();
    assert_eq!(output.writes, 1);
    assert!(output.bytes.len() < 512);
    assert!(
        String::from_utf8(output.bytes)
            .unwrap()
            .contains("duration_ns=0")
    );
}

#[test]
fn smoke_diagnostic_partial_and_interrupted_sinks_preserve_complete_record() {
    #[derive(Default)]
    struct Partial {
        interrupted: bool,
        bytes: Vec<u8>,
    }
    impl std::io::Write for Partial {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(std::io::ErrorKind::Interrupted.into());
            }
            let count = bytes.len().min(3);
            self.bytes.extend_from_slice(&bytes[..count]);
            Ok(count)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let event = SmokeDiagnosticEventV1 {
        kind: SmokeDiagnosticKindV1::Complete,
        phase: SmokeDiagnosticPhaseV1::PoolActivation,
        span: 7,
        parent: 2,
        leg: None,
        start_ns: 13,
        end_ns: 41,
        height: None,
    };
    let mut expected = Vec::new();
    write_smoke_diagnostic_event_v1(&mut expected, event).unwrap();
    let mut partial = Partial::default();
    write_smoke_diagnostic_event_v1(&mut partial, event).unwrap();
    assert!(partial.interrupted);
    assert_eq!(partial.bytes, expected);
}

#[cfg(feature = "atomic-private-settlement-smoke")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum N3SettlementExperimentV1 {
    HappyDay,
    RestartRecovery,
}

#[cfg(feature = "atomic-private-settlement-smoke")]
fn run_n3_real_process_experiment(experiment: N3SettlementExperimentV1) -> Result<()> {
    let _diagnostics = SmokeDiagnosticScopeV1::start();
    let (bound, request_sha) = read_bound_real_process_request()?;
    let RealProcessBoundRequestV1::Smoke(smoke_request) = bound else {
        return Err(eyre!("positive smoke received a non-smoke request"));
    };
    let expected_kind = match experiment {
        N3SettlementExperimentV1::HappyDay => "happy_day",
        N3SettlementExperimentV1::RestartRecovery => "smoke",
    };
    ensure!(
        smoke_request.kind == expected_kind,
        "request names a different N=3 experiment"
    );
    let evidence_root = fault_evidence_root().wrap_err("initialize smoke evidence directory")?;
    let mut evidence_files = vec![write_smoke_evidence(
        &evidence_root,
        "request.json",
        &smoke_request,
    )?];
    let shape = TopologyShape::new(PARTICIPANT_COUNT);
    shape.validate()?;
    ensure!(
        shape.global_validator_count() == 4
            && shape.participant_validator_count() == 12
            && shape.process_count() == 16,
        "N=3 requires four global voters plus twelve non-global participant committee validators"
    );
    ensure!(
        shape.participant_visibility_profile()
            == [
                LaneVisibility::Public,
                LaneVisibility::Restricted,
                LaneVisibility::Restricted,
            ],
        "primary N=3 must mix one public and two restricted participant dataspaces"
    );
    let context = "atomic_private_settlement_n3_real_process_smoke";
    let builder = n3_smoke_builder(shape).with_base_seed(format!(
        "aps-smoke:{}:{}:{}",
        smoke_request.seed, smoke_request.run, smoke_request.invocation_nonce
    ));
    let startup_started = Instant::now();
    let startup_timing = SmokeDiagnosticSpanV1::start(SmokeDiagnosticPhaseV1::NetworkStartup, None);
    let started = sandbox::start_network_blocking_or_skip(builder, context)?;
    let Some((network, runtime)) = sandbox::enforce_network_start_requirement(started, context)?
    else {
        return Err(eyre!("required sixteen-process smoke network was skipped"));
    };
    // Finish peer monitors while their runtime is still alive, including error paths.
    // Network's background Drop cleanup cannot retain exits after this runtime drops.
    let result = (|| {
        verify_controller_readiness(&network, &runtime)?;
        let startup_deadline = startup_started
            .checked_add(network.peer_startup_timeout())
            .ok_or_else(|| eyre!("smoke startup deadline exceeds the monotonic clock range"))?;
        let initial_inventory = smoke_process_inventory(
            &network,
            &runtime,
            shape,
            SmokeInventoryReadinessV1::StartupUntil(startup_deadline),
        )?;
        evidence_files.push(write_smoke_evidence(
            &evidence_root,
            "processes-before.json",
            &initial_inventory,
        )?);
        startup_timing.complete();
        let sponsor = network.client();
        prepare_participant_assets(&network, shape)?;
        let privacy_timing =
            SmokeDiagnosticSpanV1::start(SmokeDiagnosticPhaseV1::PrivacyActivation, None);
        let activated_height = require_genesis_private_note_active(&sponsor)?;
        privacy_timing.complete();
        let expiry_height = activated_height + 1_000;
        let routes = routes_from_network(&network, shape)?;
        ensure!(
            routes.len() == 3,
            "exactly three mixed-visibility participant dataspaces are required"
        );
        let committees = committees_from_network(&network, shape, &routes)?;
        let governed = governed_legs(&routes, activated_height, expiry_height)?;
        let private_data = (0..routes.len())
            .map(default_private_settlement_leg_data)
            .collect::<Vec<_>>();
        let pool_timing =
            SmokeDiagnosticSpanV1::start(SmokeDiagnosticPhaseV1::PoolActivation, None);
        let authority_context_height = activate_governed_private_pools(
            &sponsor,
            network.network_id(),
            &governed,
            &private_data,
            expiry_height,
        )?;
        pool_timing.complete();
        let manifest = proof_manifest(
            network.network_id(),
            authority_context_height,
            expiry_height,
            &governed,
        )?;
        // Establish the measurement baseline and continuous observer before client
        // work begins. Proof construction, self-verification, material preparation
        // and settlement remain inside the measured workflow.
        let before = wait_for_converged_fault_state_snapshot(&network, "smoke-before")?;
        ensure!(
            before.validators.len() == shape.process_count(),
            "positive smoke omitted a global or participant validator"
        );

        evidence_files.push(write_smoke_evidence(
            &evidence_root,
            "state-before.json",
            &before,
        )?);
        evidence_files.push(write_smoke_evidence(
            &evidence_root,
            "authorities.json",
            &committees
                .iter()
                .map(|committee| &committee.authority)
                .collect::<Vec<_>>(),
        )?);
        let mut observer = FaultContinuousObserverV1::start_retaining_evidence(
            &network,
            &before,
            shape.participants,
            &manifest.bundle_id,
            false,
        )?;

        let workflow_timing =
            SmokeDiagnosticSpanV1::start(SmokeDiagnosticPhaseV1::EndToEndWorkflow, None);
        ensure!(
            governed.len() == 3 && committees.len() == 3,
            "exactly three proof jobs are required"
        );
        // Authenticate all committee digests before launching any proof worker.
        let jobs: [(GovernedLeg, Hash); 3] = governed
            .into_iter()
            .zip(&committees)
            .map(|(leg, committee)| Ok((leg, committee.authority.digest()?)))
            .collect::<Result<Vec<_>>>()?
            .try_into()
            .map_err(|_| eyre!("exactly three proof jobs are required"))?;
        let prepared = collect_three_smoke_phase_jobs_v1(
            SmokeLegJobPhaseV1::Proof,
            jobs,
            |ordinal, (leg, authority_digest)| {
                let leg_timing = SmokeDiagnosticSpanV1::start(
                    SmokeDiagnosticPhaseV1::ClientLegConstruction,
                    Some(ordinal),
                );
                let prepared = prepare_leg(ordinal, leg, &manifest, authority_digest)?;
                leg_timing.complete();
                Ok(prepared)
            },
        )?;
        let materials = provisional_materials(manifest, &prepared, &committees)?;
        let endpoint_matrix = committees
            .iter()
            .map(|committee| committee.endpoints.clone())
            .collect::<Vec<_>>();
        let journal_directory = tempfile::tempdir_in(network.env_dir())?.keep();
        let operation = prepared_operation::PreparedSdkFlow::new(
            &network,
            &sponsor,
            &materials,
            endpoint_matrix,
            &journal_directory.join("prepared-settlement"),
        )?;
        let availability_timing =
            SmokeDiagnosticSpanV1::start(SmokeDiagnosticPhaseV1::AvailabilityCertification, None);
        // This injects an SDK journal acknowledgement loss after the real durable
        // availability CAS. It is not a process crash; real committee restarts below
        // remain a distinct acceptance check.
        operation.interrupt_after(&runtime, 0)?;
        availability_timing.complete();
        let original_availability_checkpoint = operation.availability_checkpoint()?;
        let certificates = operation
            .round::<Vec<iroha_data_model::nexus::PrivateSettlementSidecarAvailabilityV1>>(0)?;
        let final_manifest = operation.availability_manifest(&materials)?;
        evidence_files.push(write_smoke_evidence(
            &evidence_root,
            "prepared-artifact-sizes.json",
            &prepared_operation::artifact_sizes(&materials, &final_manifest, &certificates)?,
        )?);
        let upload_timing =
            SmokeDiagnosticSpanV1::start(SmokeDiagnosticPhaseV1::RestrictedUpload, None);
        // Run the public SDK before any audit approvals. It promotes the exact
        // persisted certificate and must stop at Prepare. That redacted error alone
        // is not evidence of the cause: the quorum auditor view below authenticates
        // the exact Collecting material, and only approvals change before retry.
        operation.await_independent_audit(&runtime)?;
        upload_timing.complete();
        assert_no_partial_visibility(&network, final_manifest.bundle_id, "collecting")?;
        let state = capture_fault_state_snapshot(&network, "smoke-collecting")?;
        ensure_fault_ledger_unchanged_before_finality(&before, &state)?;
        evidence_files.push(write_smoke_evidence(
            &evidence_root,
            "state-collecting.json",
            &state,
        )?);

        let audit_timing =
            SmokeDiagnosticSpanV1::start(SmokeDiagnosticPhaseV1::AuditorApproval, None);
        for (ordinal, (leg, committee)) in prepared.iter().zip(&committees).enumerate() {
            let auditor_transport_signer =
                BorrowedKeyPairIdentityRequestSignerV1::new(&leg.governed.auditor_signing);
            let capsule_request = PrivateSettlementAuditorCapsuleRequestV1 {
                audit_policy: leg.governed.policy.clone(),
            };
            let fetched = sponsor
                .client()
                .private_settlement_auditor_capsule_quorum_for_authority_v1(
                    &committee.endpoints,
                    &materials[ordinal].committee_authority,
                    final_manifest.legs[ordinal].payload_digest,
                    &capsule_request,
                    &auditor_transport_signer,
                )?;
            ensure!(
                fetched.lifecycle == PrivateSettlementLifecycleDtoV1::Collecting,
                "unexpected audit lifecycle"
            );
            ensure!(
                fetched.manifest == final_manifest
                    && fetched.audit_policy == materials[ordinal].audit_policy
                    && fetched.committee_authority == materials[ordinal].committee_authority
                    && fetched.statement == materials[ordinal].statement
                    && fetched.delta == materials[ordinal].delta
                    && fetched.audit_capsule == materials[ordinal].audit_capsule
                    && fetched.availability == certificates[ordinal],
                "authenticated auditor view replaced original prepared material or availability certificate"
            );
            let authoritative_height = fetched.authoritative_height;
            let view = PrivateSettlementAuditorSidecarViewV1 {
                manifest: fetched.manifest,
                policy: fetched.audit_policy,
                authority: fetched.committee_authority,
                statement: fetched.statement,
                delta: fetched.delta,
                audit_capsule: fetched.audit_capsule,
                availability: fetched.availability,
                lifecycle: PrivateSettlementSidecarLifecycleV1::Collecting,
            };
            let auditor_id = AccountId::new(leg.governed.auditor_signing.public_key().clone());
            let approval = approve_private_settlement_leg_v1(
                &view,
                &leg.governed.governance,
                authoritative_height,
                &auditor_id,
                leg.governed.auditor_encryption.secret(),
                &leg.governed.auditor_signing,
                &approve_all_audit_material,
            )?;
            let response = sponsor
                .client()
                .submit_private_settlement_audit_approval_quorum_for_authority_v1(
                    &committee.endpoints,
                    &materials[ordinal].committee_authority,
                    final_manifest.legs[ordinal].payload_digest,
                    &auditor_transport_signer,
                    &PrivateSettlementAuditApprovalRequestV1 {
                        audit_policy: capsule_request.audit_policy,
                        approval,
                    },
                )?;
            ensure!(
                response.lifecycle == PrivateSettlementLifecycleDtoV1::Audited,
                "approval quorum was not durable"
            );
        }
        audit_timing.complete();
        assert_no_partial_visibility(&network, final_manifest.bundle_id, "audited")?;
        let state = capture_fault_state_snapshot(&network, "smoke-audited")?;
        ensure_fault_ledger_unchanged_before_finality(&before, &state)?;
        evidence_files.push(write_smoke_evidence(
            &evidence_root,
            "state-audited.json",
            &state,
        )?);

        ensure!(
            operation.availability_checkpoint()? == original_availability_checkpoint,
            "independent audit changed the original durable availability snapshot"
        );
        let prepare_timing =
            SmokeDiagnosticSpanV1::start(SmokeDiagnosticPhaseV1::PrepareCertification, None);
        operation.interrupt_after(&runtime, 1)?;
        let barrier = operation.barrier(final_manifest.clone(), &materials)?;
        prepare_timing.complete();
        assert_no_partial_visibility(&network, final_manifest.bundle_id, "prepared")?;
        let state = capture_fault_state_snapshot(&network, "smoke-prepared")?;
        ensure_fault_ledger_unchanged_before_finality(&before, &state)?;
        evidence_files.push(write_smoke_evidence(
            &evidence_root,
            "state-prepared.json",
            &state,
        )?);
        let registration_timing =
            SmokeDiagnosticSpanV1::start(SmokeDiagnosticPhaseV1::PrepareRegistration, None);
        let fee_before_registration = sponsor_nexus_fee_balance(&sponsor)?;
        operation.interrupt_after(&runtime, 2)?;
        let fee_after_registration = sponsor_nexus_fee_balance(&sponsor)?;
        ensure_exact_private_settlement_carrier_fee(
            &fee_before_registration,
            &fee_after_registration,
            "Prepare registration",
        )?;
        // Sponsor Applied is local: wait for its exact replicated registration map
        // before one-shot Commit vote collection across the disjoint committees.
        let registered = wait_for_smoke_prepare_registration(&network, &before, routes.len())?;
        ensure_fault_ledger_unchanged_before_finality(&before, &registered)?;
        registration_timing.complete();
        evidence_files.push(write_smoke_evidence(
            &evidence_root,
            "state-registered.json",
            &registered,
        )?);
        evidence_files.push(write_smoke_evidence(
            &evidence_root,
            "prepare-barrier.json",
            &barrier,
        )?);
        let commit_timing =
            SmokeDiagnosticSpanV1::start(SmokeDiagnosticPhaseV1::CommitCertification, None);
        operation.interrupt_after(&runtime, 3)?;
        let commits = operation
            .round::<Vec<iroha_data_model::nexus::PrivateSettlementPhaseCertificateV1>>(3)?;
        commit_timing.complete();
        evidence_files.push(write_smoke_evidence(
            &evidence_root,
            "commit-certificates.json",
            &commits,
        )?);
        assert_no_partial_visibility(&network, final_manifest.bundle_id, "commit-certified")?;
        let state = capture_fault_state_snapshot(&network, "smoke-commit-certified")?;
        ensure_fault_ledger_unchanged_before_finality(&before, &state)?;
        evidence_files.push(write_smoke_evidence(
            &evidence_root,
            "state-commit-certified.json",
            &state,
        )?);

        let fee_before_finalization = sponsor_nexus_fee_balance(&sponsor)?;
        observer.begin_phase("finalization", &[], true)?;
        observer.checkpoint_active_phase(&[])?;
        let finality_timing =
            SmokeDiagnosticSpanV1::start(SmokeDiagnosticPhaseV1::FinalityWorkflow, None);
        // The public operation includes submission and independent finality reads;
        // its duration belongs to FinalityWorkflow, not an HTTP-only submission span.
        let settled = operation.finish(&runtime)?;
        let verified_receipt = settled.receipt;
        let request = prepared_operation::original_finalization(&verified_receipt)?;
        ensure!(
            operation.availability_checkpoint()? == original_availability_checkpoint,
            "finalization replaced the original durable availability certificate"
        );
        let carrier_norito_bytes = request.transaction.encode_wire_v1()?.len();
        let carrier_json_bytes = norito::json::to_vec(&request)?.len();
        ensure!(carrier_norito_bytes <= PRIVATE_SETTLEMENT_MAX_RECEIPT_BYTES_V1);
        ensure!(
            (carrier_json_bytes as u64)
                <= iroha_config::parameters::defaults::torii::MAX_CONTENT_LEN.0
        );
        evidence_files.push(write_smoke_evidence(
            &evidence_root, "verified-carrier-sizes.json",
            &norito::json!({
                "signed_carrier_norito_bytes": carrier_norito_bytes,
                "signed_carrier_json_bytes": carrier_json_bytes,
                "public_receipt_norito_bytes": (norito::encode_canonical(verified_receipt.receipt())?.len()),
                "carrier_bound_bytes": PRIVATE_SETTLEMENT_MAX_RECEIPT_BYTES_V1,
            }),
        )?);
        let receipt_timing =
            SmokeDiagnosticSpanV1::start(SmokeDiagnosticPhaseV1::AllPeerReceipt, None);
        let receipt = wait_for_identical_receipt(&network, final_manifest.bundle_id)?;
        ensure!(
            &receipt == verified_receipt.receipt(),
            "all-peer informational receipt differs from independently verified successful Finalize"
        );
        receipt_timing.complete();
        let fee_after_finalization = sponsor_nexus_fee_balance(&sponsor)?;
        ensure_exact_private_settlement_carrier_fee(
            &fee_before_finalization,
            &fee_after_finalization,
            "financial finalization",
        )?;
        ensure!(
            receipt.legs.len() == PARTICIPANT_COUNT,
            "receipt does not contain exactly three legs"
        );
        for (ordinal, leg) in receipt.legs.iter().enumerate() {
            ensure!(
                usize::from(leg.delta.leg_ordinal) == ordinal,
                "receipt reordered a leg"
            );
            ensure!(
                receipt
                    .legs
                    .iter()
                    .filter(|candidate| candidate.delta.route == leg.delta.route)
                    .count()
                    == 1,
                "a private leg became visible more than once"
            );
        }
        let after = wait_for_converged_fault_state_snapshot(&network, "smoke-finalized")?;
        ensure_fault_state_finalized_once(&before, &after, shape.participants)?;
        prepared_operation::require_final_tip(
            after
                .validators
                .iter()
                .map(|observation| (observation.peer_index, observation.height)),
            receipt.finalized_height,
        )?;
        observe_smoke_diagnostic_milestone_v1(
            SmokeDiagnosticPhaseV1::FinancialApplicationVerified,
            receipt.finalized_height,
        );
        finality_timing.complete();
        workflow_timing.complete();
        evidence_files.push(write_smoke_evidence(
            &evidence_root,
            "state-finalized.json",
            &after,
        )?);
        evidence_files.push(write_smoke_evidence(
            &evidence_root,
            "receipt.json",
            &receipt,
        )?);
        observer.complete_phase()?;
        let signed_finality_timing =
            SmokeDiagnosticSpanV1::start(SmokeDiagnosticPhaseV1::SignedFinalityEvidence, None);
        let (finality, files) = collect_signed_rs16_finality(
            &network,
            &runtime,
            receipt.finalized_height,
            FinalityObservationV1::LiveTransport,
            Some((&evidence_root, "finality-before")),
        )?;
        evidence_files.extend(files);
        ensure!(
            finality.observations == u64::try_from(shape.process_count())?,
            "positive smoke lacks a signed RS16 finality observation from every process"
        );
        signed_finality_timing.complete();
        let replay_timing =
            SmokeDiagnosticSpanV1::start(SmokeDiagnosticPhaseV1::ReplayValidation, None);
        // Replay the original signed carrier while it is live. The acknowledgment must
        // retain its finalized identity without creating another financial effect.
        let replayed = observe_idempotent_finalized_retry(
            &sponsor,
            &network,
            &final_manifest,
            &request,
            &receipt,
        )?;
        ensure!(
            sponsor_nexus_fee_balance(&sponsor)? == fee_after_finalization,
            "acknowledged finalization retry charged a third carrier fee"
        );
        ensure_fault_state_reverted(&after, &replayed)?;
        prepared_operation::require_final_tip(
            replayed
                .validators
                .iter()
                .map(|observation| (observation.peer_index, observation.height)),
            receipt.finalized_height,
        )?;
        evidence_files.push(write_smoke_evidence(
            &evidence_root,
            "state-replay.json",
            &replayed,
        )?);
        let (summaries, observations) = observer.finish_with_evidence(&replayed)?;
        ensure!(
            summaries.len() == shape.process_count()
                && observations.len() == shape.process_count()
                && summaries.iter().all(|row| row.check_count >= 3
                    && row.finalized_observations > 0
                    && row.poll_failure_count == 0),
            "smoke continuous observer omitted validators, finality or successful polling"
        );
        for (index, (summary, observations)) in summaries.iter().zip(&observations).enumerate() {
            evidence_files.push(write_smoke_evidence(
                &evidence_root,
                &format!("continuous-{index:02}.json"),
                &SmokeContinuousEvidenceV1 {
                    summary: summary.clone(),
                    observations: observations.clone(),
                },
            )?);
        }
        replay_timing.complete();
        if experiment == N3SettlementExperimentV1::HappyDay {
            let final_inventory = smoke_process_inventory(
                &network,
                &runtime,
                shape,
                SmokeInventoryReadinessV1::Immediate,
            )?;
            ensure!(
                initial_inventory
                    .iter()
                    .zip(&final_inventory)
                    .all(|(before, after)| before.peer_id == after.peer_id
                        && before.configuration_sha256 == after.configuration_sha256
                        && before.executable_sha256 == after.executable_sha256
                        && before.pid == after.pid),
                "happy-day experiment changed a validator process, identity or configuration"
            );
            evidence_files.push(write_smoke_evidence(
                &evidence_root,
                "processes-after.json",
                &final_inventory,
            )?);
            write_real_process_result(&RealProcessSmokeResultV1 {
                version: 1,
                protocol: "AtomicPrivateSettlementV1".to_owned(),
                kind: "happy_day".to_owned(),
                request: smoke_request,
                request_sha256: request_sha,
                network_id: norito::json::to_value(&network.network_id())?,
                participants: shape.participants,
                processes: shape.process_count(),
                restarted: 0,
                activation_height: activated_height,
                authority_context_height,
                finalized_height: receipt.finalized_height,
                signed_rs16_observations: finality.observations,
                continuous_checks: summaries.iter().map(|row| row.check_count).sum::<u64>(),
                passed: true,
                artifacts: evidence_files,
            })?;
            println!(
                "APS happy_day completed: participants={} processes={} finalized_height={}",
                shape.participants,
                shape.process_count(),
                receipt.finalized_height
            );
            return Ok(());
        }
        let mut restarts = Vec::new();

        // Recover each durable store while preserving a live 3-of-4 quorum in
        // every committee. A receipt alone would miss duplicated nullifiers,
        // outputs, or residual reservations, so recheck the complete APS state.
        for (peer_index, peer) in network.all_peers().enumerate() {
            let restart_timing =
                SmokeDiagnosticSpanV1::start(SmokeDiagnosticPhaseV1::RestartReconciliation, None);
            let before_pid = runtime
                .block_on(peer.process_id())
                .ok_or_else(|| eyre!("smoke restart target #{peer_index} has no live PID"))?;
            let config_layers = network.config_layers_for_peer(peer).collect::<Vec<_>>();
            ensure!(
                runtime.block_on(peer.shutdown_if_started())
                    && runtime.block_on(peer.process_id()).is_none(),
                "smoke restart target #{peer_index} did not stop"
            );
            runtime
                .block_on(async {
                    tokio::time::timeout(
                        FINALITY_TIMEOUT,
                        peer.start_checked(config_layers.iter(), None),
                    )
                    .await
                })
                .wrap_err_with(|| format!("smoke restart target #{peer_index} timed out"))??;
            let after_pid = runtime
                .block_on(peer.process_id())
                .ok_or_else(|| eyre!("smoke restart target #{peer_index} did not recover"))?;
            ensure!(
                before_pid != after_pid && peer.client().status().get().is_ok(),
                "smoke restart target #{peer_index} lacks a healthy replacement process"
            );
            ensure!(
                wait_for_identical_receipt(&network, final_manifest.bundle_id)? == receipt,
                "smoke restart target #{peer_index} changed the finalized receipt"
            );
            let recovered_receipt = operation.recover(&runtime)?;
            ensure!(
                recovered_receipt.receipt() == verified_receipt.receipt()
                    && recovered_receipt.transaction_hash() == verified_receipt.transaction_hash()
                    && recovered_receipt.context_id() == verified_receipt.context_id()
                    && recovered_receipt.nexus_fee_receipt()
                        == verified_receipt.nexus_fee_receipt(),
                "reopened SDK journal did not recover the exact original successful Finalize after peer restart"
            );
            ensure!(
                operation.availability_checkpoint()? == original_availability_checkpoint,
                "read-only restart recovery replaced the original certificate"
            );
            ensure!(
                sponsor_nexus_fee_balance(&sponsor)? == fee_after_finalization,
                "read-only SDK recovery charged another carrier fee"
            );
            let recovered = wait_for_converged_fault_state_snapshot(&network, "smoke-restarted")?;
            ensure_fault_state_reverted(&after, &recovered)?;
            prepared_operation::require_final_tip(
                recovered
                    .validators
                    .iter()
                    .map(|observation| (observation.peer_index, observation.height)),
                receipt.finalized_height,
            )?;
            evidence_files.push(write_smoke_evidence(
                &evidence_root,
                &format!("state-restarted-{peer_index:02}.json"),
                &recovered,
            )?);
            restart_timing.complete();
            restarts.push(SmokeRestartV1 {
                peer_index,
                before_pid,
                after_pid,
            });
            println!(
                "APS smoke restart verified: peer_index={peer_index} before_pid={before_pid} after_pid={after_pid}"
            );
        }
        let recovered_finality_timing =
            SmokeDiagnosticSpanV1::start(SmokeDiagnosticPhaseV1::SignedFinalityEvidence, None);
        let (recovered_finality, files) = collect_signed_rs16_finality(
            &network,
            &runtime,
            receipt.finalized_height,
            FinalityObservationV1::Restored(finality.anchor),
            Some((&evidence_root, "finality-after")),
        )?;
        ensure!(
            recovered_finality == finality,
            "restarted smoke network changed its finalized block, authority context, or coverage"
        );
        recovered_finality_timing.complete();
        evidence_files.extend(files);
        let recovered_inventory = smoke_process_inventory(
            &network,
            &runtime,
            shape,
            SmokeInventoryReadinessV1::Immediate,
        )?;
        ensure!(
            initial_inventory
                .iter()
                .zip(&recovered_inventory)
                .all(|(before, after)| before.peer_id == after.peer_id
                    && before.configuration_sha256 == after.configuration_sha256
                    && before.pid != after.pid),
            "smoke restart changed identity/configuration or retained its process"
        );
        evidence_files.push(write_smoke_evidence(
            &evidence_root,
            "processes-after.json",
            &recovered_inventory,
        )?);
        evidence_files.push(write_smoke_evidence(
            &evidence_root,
            "restarts.json",
            &restarts,
        )?);
        write_real_process_result(&RealProcessSmokeResultV1 {
            version: 1,
            protocol: "AtomicPrivateSettlementV1".to_owned(),
            kind: "smoke".to_owned(),
            request: smoke_request,
            request_sha256: request_sha,
            network_id: norito::json::to_value(&network.network_id())?,
            participants: shape.participants,
            processes: shape.process_count(),
            restarted: restarts.len(),
            activation_height: activated_height,
            authority_context_height,
            finalized_height: receipt.finalized_height,
            signed_rs16_observations: finality.observations,
            continuous_checks: summaries.iter().map(|row| row.check_count).sum::<u64>(),
            passed: true,
            artifacts: evidence_files,
        })?;
        println!(
            "APS smoke completed: participants={} processes={} restarted={} finalized_height={}",
            shape.participants,
            shape.process_count(),
            shape.process_count(),
            receipt.finalized_height,
        );
        Ok(())
    })();
    runtime.block_on(network.shutdown());
    result
}

#[cfg(feature = "atomic-private-settlement-smoke")]
#[test]
#[ignore = "release-only: starts 16 real validators and generates three native STARK proofs"]
fn atomic_private_settlement_n3_real_process_smoke() -> Result<()> {
    let handle = thread::Builder::new()
        .name("atomic-private-settlement-n3".to_owned())
        .stack_size(TEST_STACK_BYTES)
        .spawn(|| run_n3_real_process_experiment(N3SettlementExperimentV1::RestartRecovery))
        .expect("spawn release smoke thread");
    match handle.join() {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[cfg(feature = "atomic-private-settlement-smoke")]
#[test]
#[ignore = "starts 16 real validators and completes a three-dataspace happy-day payment"]
fn atomic_private_settlement_n3_happy_day() -> Result<()> {
    let handle = thread::Builder::new()
        .name("atomic-private-settlement-n3-happy-day".to_owned())
        .stack_size(TEST_STACK_BYTES)
        .spawn(|| run_n3_real_process_experiment(N3SettlementExperimentV1::HappyDay))
        .expect("spawn happy-day settlement thread");
    match handle.join() {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[test]
fn release_fee_intent_is_bounded_and_uses_canonical_nexus_xor() {
    let intent = bounded_nexus_fee();
    intent.validate().expect("release fee intent is canonical");
    let [limit] = intent.charge_limits() else {
        panic!("release fee intent must contain exactly one Nexus charge limit");
    };
    assert_eq!(limit.kind(), FeeChargeKind::Nexus);
    assert_eq!(
        limit.asset_definition_id(),
        &nexus_fee_asset_definition_id()
    );
    assert_eq!(
        limit.max_amount(),
        &Quantity::from(NEXUS_FEE_SIGNED_MAXIMUM)
    );
}

#[test]
fn release_sources_do_not_construct_fee_free_non_genesis_transactions() {
    let forbidden_constructor = ["FeePaymentIntent::authority(", "Vec::new(), None)"].concat();
    let retired_helper = ["no_", "fee()"].concat();
    for (name, source) in [
        (
            "localnet",
            include_str!("atomic_private_settlement_localnet.rs"),
        ),
        (
            "release harness",
            include_str!("atomic_private_settlement_real_process_harness.rs"),
        ),
    ] {
        assert!(
            !source.contains(&forbidden_constructor),
            "{name} constructs a fee-free non-genesis intent"
        );
        assert!(
            !source.contains(&retired_helper),
            "{name} calls the retired fee-free helper"
        );
    }
    let client_source = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../crates/iroha/src/client/private_settlement.rs"
    ));
    assert!(
        client_source.contains("expected_manifest.public_fee_intent.clone(),"),
        "Prepare registration must carry the manifest's bounded public fee intent"
    );
}

#[test]
fn genesis_registers_only_participant_processes_as_committee_peers() {
    let shape = TopologyShape::new(PARTICIPANT_COUNT);
    let process_entries = (0..shape.process_count())
        .map(|index| {
            let seed = u8::try_from(index + 1).expect("fixture process index fits u8");
            let keypair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal)
                .expect("deterministic BLS process key");
            let pop = iroha_crypto::bls_normal_pop_prove(keypair.private_key())
                .expect("derive process PoP");
            GenesisTopologyEntry::new(PeerId::new(keypair.public_key().clone()), pop)
        })
        .collect::<Vec<_>>();
    let topology = process_entries
        .iter()
        .map(|entry| entry.peer.clone())
        .collect::<Vec<_>>();
    let committee_validator_entries = process_entries[shape.global_validator_count()..].to_vec();

    let transactions = genesis_post_topology(shape, &topology, &committee_validator_entries);
    for bootstrap in participant_domain_bootstrap() {
        assert_eq!(
            transactions
                .iter()
                .flatten()
                .filter(|instruction| *instruction == &bootstrap)
                .count(),
            1,
            "signed genesis contains exactly one domain registration and exact ownership transfer"
        );
    }
    let setup = participant_asset_registrations(shape);
    assert!(
        transactions
            .iter()
            .flatten()
            .all(|genesis_instruction| setup
                .iter()
                .all(|setup_instruction| genesis_instruction != setup_instruction)),
        "required paid CBDC registrations are not repeated in genesis"
    );
    let policies = transactions
        .iter()
        .flatten()
        .filter_map(|instruction| {
            let parameter = instruction.as_any().downcast_ref::<SetParameter>()?;
            let Parameter::Custom(custom) = parameter.inner() else {
                return None;
            };
            SumeragiLanePolicy::from_custom_parameter(custom)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        policies.len(),
        1,
        "genesis signs exactly one native lane policy"
    );
    let policy = policies[0].as_ref().expect("canonical signed lane policy");
    iroha_core::sumeragi::lanes::step::validate_policy(policy)
        .expect("every actual participant BLS PoP verifies");
    assert_eq!(policy.fixed.len(), shape.participants);
    assert_eq!(policy.lane_params.block_cadence_ms.get(), 4_000);
    for (ordinal, lane) in policy.fixed.iter().enumerate() {
        assert_eq!(lane.lane, LaneId::new((ordinal + 1) as u32));
        assert_eq!(lane.dataspace, DataSpaceId::new((ordinal + 1) as u64));
        let mut expected = committee_validator_entries
            [ordinal * VALIDATORS_PER_LANE..(ordinal + 1) * VALIDATORS_PER_LANE]
            .iter()
            .map(|entry| SumeragiLaneMember {
                peer: entry.peer.clone(),
                pop: entry.pop_bytes().unwrap().unwrap(),
            })
            .collect::<Vec<_>>();
        expected.sort_by(|left, right| left.peer.cmp(&right.peer));
        assert_eq!(lane.committee, expected);
        assert!(
            lane.committee
                .iter()
                .all(|member| !topology[..shape.global_validator_count()].contains(&member.peer))
        );
    }
    let intrinsic = FastpqSourcePolicyV1::bootstrap().intrinsic;
    let mut minted = 0;
    for transaction in &transactions {
        let mints = transaction
            .iter()
            .filter(|instruction| {
                matches!(
                    instruction
                        .as_any()
                        .downcast_ref::<iroha::data_model::isi::MintBox>(),
                    Some(iroha::data_model::isi::MintBox::Asset(_))
                )
            })
            .count();
        minted += mints;
        let stake_transfers = transaction
            .iter()
            .filter(|instruction| instruction.as_any().is::<RegisterPublicLaneValidator>())
            .count();
        assert!(
            mints + stake_transfers <= intrinsic.max_deltas as usize,
            "each genesis quantity tape fits the signed bootstrap entry limit"
        );
        assert!(stake_transfers <= intrinsic.max_transcripts as usize);
    }
    assert_eq!(
        minted,
        shape.process_count() + 1,
        "preserve every original stake and fee mint"
    );
    let monetary_registrations = transactions
        .iter()
        .flatten()
        .filter_map(|instruction| {
            instruction
                .as_any()
                .downcast_ref::<RegisterPublicLaneValidator>()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        monetary_registrations.len(),
        shape.lane_count() * VALIDATORS_PER_LANE
    );
    for registration in monetary_registrations {
        assert_eq!(
            registration.monetary_plan.network_scope,
            iroha_data_model::nexus::PublicLaneMonetaryScopeV1::Genesis
        );
        assert_eq!(registration.monetary_plan.valid_until_height, 1);
        assert_eq!(
            registration.monetary_plan.source_asset,
            iroha_data_model::asset::AssetId::new(
                stake_asset_definition_id(),
                registration.validator.clone()
            )
        );
        assert_eq!(
            registration.monetary_plan.destination_asset,
            iroha_data_model::asset::AssetId::new(stake_asset_definition_id(), ALICE_ID.clone())
        );
        assert_eq!(
            registration.monetary_plan.amount,
            registration.initial_stake
        );
        assert_eq!(
            registration.monetary_plan.precondition,
            iroha_data_model::nexus::PublicLaneMonetaryPreconditionV1::Registration(
                iroha_data_model::nexus::PublicLaneMonetaryRegistrationV1 {
                    activation_height: 1
                }
            )
        );
    }
    let registrations = transactions
        .iter()
        .flatten()
        .filter_map(|instruction| {
            instruction
                .as_any()
                .downcast_ref::<RegisterCommitteePeerWithPop>()
        })
        .collect::<Vec<_>>();

    assert_eq!(registrations.len(), shape.participant_validator_count());
    for (registration, entry) in registrations.iter().zip(&committee_validator_entries) {
        assert_eq!(registration.peer, entry.peer);
        assert_eq!(
            registration.pop,
            entry
                .pop_bytes()
                .expect("fixture PoP hex")
                .expect("fixture carries PoP")
        );
    }
    assert!(registrations.iter().all(|registration| {
        !topology[..shape.global_validator_count()].contains(&registration.peer)
    }));
}

#[test]
fn participant_assets_bind_explicit_owned_domain_before_registration() {
    use iroha::data_model::isi::RegisterBox;
    let shape = TopologyShape::new(PARTICIPANT_COUNT);
    let instructions = participant_asset_registrations(shape);
    assert_eq!(instructions.len(), shape.participants);
    for (ordinal, instruction) in instructions.iter().enumerate() {
        let Some(RegisterBox::AssetDefinition(asset)) =
            instruction.as_any().downcast_ref::<RegisterBox>()
        else {
            panic!("each paid setup operation must register one CBDC");
        };
        assert_eq!(asset.object.id, cbdc_asset_definition_id(ordinal));
        assert_eq!(
            asset.object.owning_domain.as_ref(),
            Some(&settlement_domain_id())
        );
        assert_eq!(
            asset.object.balance_scope_policy,
            AssetBalancePolicy::Global
        );
    }
}

#[test]
fn participant_assets_execute_paid_setup_after_signed_genesis_domain_transfer() {
    thread::Builder::new()
        .name("participant-asset-runtime-setup".to_owned())
        .stack_size(TEST_STACK_BYTES)
        .spawn(|| {
            use iroha::data_model::{Registrable, transaction::TransactionBuilder};
            use iroha_core::{
                state::{StateReadOnly, World, WorldReadOnly},
                sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
            };
            use iroha_test_samples::{BOB_ID, BOB_KEYPAIR, SAMPLE_GENESIS_ACCOUNT_KEYPAIR};

            let world = World::with(
                [],
                [
                    Account::new(ALICE_ID.clone()).build(&ALICE_ID),
                    Account::new(BOB_ID.clone()).build(&BOB_ID),
                ],
                [],
            );
            let mut config = TestChainConfig::new(world, 10_000);
            config.genesis_key = SAMPLE_GENESIS_ACCOUNT_KEYPAIR.clone();
            config
                .genesis_instructions
                .extend(participant_domain_bootstrap());
            config.genesis_instructions.extend([
                Register::asset_definition(AssetDefinition::new(
                    nexus_fee_asset_definition_id(),
                    "XOR".to_owned(),
                    NumericSpec::fractional(9),
                    AssetBalancePolicy::Global,
                    None,
                ))
                .into(),
                Mint::asset_quantity(
                    NEXUS_FEE_SEED_BALANCE,
                    AssetId::new(nexus_fee_asset_definition_id(), ALICE_ID.clone()),
                )
                .into(),
                Mint::asset_quantity(
                    NEXUS_FEE_SEED_BALANCE,
                    AssetId::new(nexus_fee_asset_definition_id(), BOB_ID.clone()),
                )
                .into(),
            ]);
            let mut nexus = iroha_config::parameters::actual::Nexus::default();
            nexus.fees.fee_asset_id = nexus_fee_asset_definition_id().to_string();
            nexus.fees.fee_sink_account_id = BOB_ID.to_string();
            nexus.fees.base_fee = Quantity::zero();
            nexus.fees.per_byte_fee = Quantity::zero();
            nexus.fees.per_instruction_fee =
                NEXUS_FEE_PER_PRIVATE_SETTLEMENT_CARRIER.parse().unwrap();
            nexus.fees.per_gas_unit_fee = Quantity::zero();
            config.nexus = Some(nexus);
            let mut chain = CertifiedTestChain::start(config)
                .expect("the actual signed genesis registers and transfers the bootstrap domain");
            assert_eq!(chain.genesis_account(), &SAMPLE_GENESIS_ACCOUNT_ID.clone());
            assert_eq!(chain.height(), 1);
            assert_eq!(
                chain
                    .state()
                    .view()
                    .world()
                    .domain(&settlement_domain_id())
                    .unwrap()
                    .owned_by(),
                &ALICE_ID.clone(),
                "ownership comes from the exact signed genesis transfer"
            );
            let sign = |chain: &CertifiedTestChain, key: &KeyPair, instruction: InstructionBox| {
                let parent_time = chain
                    .state()
                    .view()
                    .latest_block()
                    .expect("funded canonical history read")
                    .unwrap()
                    .header()
                    .creation_time();
                let mut transaction = TransactionBuilder::new(
                    chain.network_id(),
                    AccountId::new(key.public_key().clone()),
                    bounded_nexus_fee(),
                );
                transaction.set_creation_time(parent_time + Duration::from_millis(1));
                transaction
                    .with_instructions([instruction])
                    .sign(key.private_key())
            };
            let balance = |chain: &CertifiedTestChain| {
                chain
                    .state()
                    .view()
                    .world()
                    .asset(&AssetId::new(
                        nexus_fee_asset_definition_id(),
                        ALICE_ID.clone(),
                    ))
                    .unwrap()
                    .value()
                    .as_ref()
                    .clone()
            };
            let shape = TopologyShape::new(PARTICIPANT_COUNT);
            for (ordinal, instruction) in participant_asset_registrations(shape)
                .into_iter()
                .enumerate()
            {
                let before = balance(&chain);
                let transaction = sign(&chain, &ALICE_KEYPAIR, instruction);
                assert_eq!(chain.commit(vec![transaction]), vec![true]);
                assert_eq!(chain.height(), ordinal as u64 + 2);
                ensure_exact_private_settlement_carrier_fee(
                    &before,
                    &balance(&chain),
                    "paid CBDC setup",
                )
                .expect("each required registration pays the ordinary configured fee");
                let definition = chain
                    .state()
                    .view()
                    .world()
                    .asset_definition(&cbdc_asset_definition_id(ordinal))
                    .unwrap();
                assert_eq!(definition.owned_by(), &ALICE_ID.clone());
                assert_eq!(
                    definition.owning_domain().as_ref(),
                    Some(&settlement_domain_id())
                );
            }
            // These go through the same signed transaction/block Runtime path,
            // with real fees and no custom permissive executor or direct Execute call.
            let unauthorized =
                participant_asset_registrations(TopologyShape::new(PARTICIPANT_COUNT + 1))
                    .pop()
                    .unwrap();
            let transaction = sign(&chain, &BOB_KEYPAIR, unauthorized);
            assert_eq!(chain.commit(vec![transaction]), vec![false]);
            assert!(
                chain
                    .state()
                    .view()
                    .world()
                    .asset_definition(&cbdc_asset_definition_id(PARTICIPANT_COUNT))
                    .is_err()
            );
            let rejected = chain.committed(chain.height());
            let (_, output) = rejected
                .block()
                .network_output_at(0)
                .expect("unauthorized registration output");
            assert!(format!("{:?}", output.result).contains("Can't register asset definition"));
            let forbidden_domain = DomainId::try_new("runtime_forbidden", "universal").unwrap();
            let transaction = sign(
                &chain,
                &ALICE_KEYPAIR,
                Register::domain(Domain::new(forbidden_domain.clone())).into(),
            );
            assert_eq!(chain.commit(vec![transaction]), vec![false]);
            assert!(
                chain
                    .state()
                    .view()
                    .world()
                    .domain(&forbidden_domain)
                    .is_err()
            );
            let rejected = chain.committed(chain.height());
            let (_, output) = rejected
                .block()
                .network_output_at(0)
                .expect("rejected transaction output");
            assert!(
                format!("{:?}", output.result)
                    .contains("raw domain registration is reserved for genesis; use EnsureAlias")
            );
        })
        .expect("spawn bounded runtime setup regression")
        .join()
        .expect("runtime setup regression completes");
}

#[test]
fn native_participant_routes_reject_substitution_and_inactive_genesis() {
    use iroha::data_model::sumeragi_lanes::{
        SumeragiLaneFrontier, SumeragiLaneRecord, SumeragiLaneStatus,
    };
    let shape = TopologyShape::new(PARTICIPANT_COUNT);
    let entries = (0..shape.participant_validator_count())
        .map(|index| {
            let key =
                KeyPair::try_from_seed(vec![(index + 1) as u8; 32], Algorithm::BlsNormal).unwrap();
            GenesisTopologyEntry::new(
                PeerId::new(key.public_key().clone()),
                iroha_crypto::bls_normal_pop_prove(key.private_key()).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    let policy = participant_lane_policy(shape, &entries);
    let network_id = iroha::data_model::NetworkId::from_genesis_hash(
        HashOf::<BlockHeader>::from_untyped_unchecked(hash(0xE1)),
    );
    let records = policy
        .fixed
        .iter()
        .enumerate()
        .map(|(ordinal, fixed)| SumeragiLaneStatus {
            record: SumeragiLaneRecord {
                da_layout: policy.da_layout,
                lane: fixed.lane,
                dataspace: fixed.dataspace,
                incarnation: iroha_core::sumeragi::lanes::step::incarnation(
                    &network_id,
                    fixed.lane,
                    fixed.dataspace,
                    1,
                    ordinal as u64,
                ),
                params: policy.lane_params.clone(),
                committee: fixed.committee.clone(),
                created_at: 1,
                active_from: 3,
                closing: None,
                anchor_freshness: policy.anchor_freshness,
                merged: SumeragiLaneFrontier::default(),
                merged_at: 3,
                rescued: 0,
            },
            instance: None,
        })
        .collect::<Vec<_>>();
    let routes = routes_from_signed_lane_records(network_id, &policy, &records, 3).unwrap();
    assert_eq!(routes.len(), PARTICIPANT_COUNT);
    assert!(routes_from_signed_lane_records(network_id, &policy, &records, 2).is_err());
    for mutation in 0..9 {
        let mut changed = records.clone();
        match mutation {
            0 => changed[0].record.incarnation[0] ^= 1,
            1 => changed[0].record.committee = records[1].record.committee.clone(),
            2 => changed[0].record.params = SumeragiParameters::default(),
            3 => changed[0].record.created_at = 2,
            4 => changed[0].record.active_from = 2,
            5 => changed[0].record.closing = Some(4),
            6 => changed[0].record.dataspace = DataSpaceId::new(2),
            7 => {
                changed.pop();
            }
            8 => changed[1] = changed[0].clone(),
            _ => unreachable!(),
        }
        assert!(
            routes_from_signed_lane_records(network_id, &policy, &changed, 3).is_err(),
            "native route substitution {mutation} must fail"
        );
    }
}

#[test]
fn activation_diagnostic_preserves_success_value_and_observation_order() {
    use std::cell::RefCell;

    let trace = RefCell::new(Vec::new());
    let value = Box::new(17_u8);
    let original = std::ptr::from_ref(value.as_ref());
    let result: std::result::Result<_, ()> = observe_private_note_activation_call(
        &mut |event| {
            assert!(matches!(
                event,
                PrivateNoteActivationDiagnostic::Call {
                    succeeded: true,
                    ..
                }
            ));
            trace.borrow_mut().push("observed");
        },
        || {
            trace.borrow_mut().push("called");
            Ok(value)
        },
    );
    trace.borrow_mut().push("returned");
    assert_eq!(std::ptr::from_ref(result.unwrap().as_ref()), original);
    assert_eq!(*trace.borrow(), ["called", "observed", "returned"]);
}

#[test]
fn activation_diagnostic_preserves_error_identity_and_fail_fast_order() {
    use std::cell::RefCell;

    let call_count = 3;
    for failed_index in 0..call_count {
        let trace = RefCell::new(Vec::new());
        let mut error = Some(Box::new(23_u8));
        let original = std::ptr::from_ref(error.as_ref().unwrap().as_ref());
        let result: std::result::Result<(), Box<u8>> = (|| {
            for index in 0..call_count {
                observe_private_note_activation_call(
                    &mut |event| {
                        let PrivateNoteActivationDiagnostic::Call { succeeded, .. } = event else {
                            panic!("call emits only a call diagnostic")
                        };
                        assert_eq!(succeeded, index != failed_index);
                        trace.borrow_mut().push((index, "observed"));
                    },
                    || {
                        trace.borrow_mut().push((index, "called"));
                        if index == failed_index {
                            Err(error.take().unwrap())
                        } else {
                            Ok(())
                        }
                    },
                )?;
            }
            Ok(())
        })();
        assert_eq!(std::ptr::from_ref(result.unwrap_err().as_ref()), original);
        let expected = (0..=failed_index)
            .flat_map(|index| [(index, "called"), (index, "observed")])
            .collect::<Vec<_>>();
        assert_eq!(*trace.borrow(), expected);
    }
}

#[test]
fn activation_diagnostic_output_has_only_declared_fields() {
    let mut output = Vec::new();
    for succeeded in [true, false] {
        write_private_note_activation_diagnostic(
            &mut output,
            PrivateNoteActivationDiagnostic::Call {
                succeeded,
                elapsed: Duration::from_nanos(37),
            },
        )
        .unwrap();
    }
    write_private_note_activation_diagnostic(
        &mut output,
        PrivateNoteActivationDiagnostic::Completed {
            committed_height: 1,
            elapsed: Duration::from_nanos(41),
        },
    )
    .unwrap();
    assert_eq!(
        String::from_utf8(output).unwrap(),
        concat!(
            "private-note activation diagnostic_timing stage=capability_read outcome=success elapsed_ns=37\n",
            "private-note activation diagnostic_timing stage=capability_read outcome=error elapsed_ns=37\n",
            "private-note activation diagnostic_completed committed_height=1 elapsed_ns=41\n",
        )
    );
}

#[test]
fn activation_diagnostic_output_failure_does_not_replace_call_result() {
    struct BrokenWriter;
    impl std::io::Write for BrokenWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    for succeeded in [true, false] {
        let value = Box::new(31_u8);
        let original = std::ptr::from_ref(value.as_ref());
        let mut observation_failed = false;
        let result = observe_private_note_activation_call(
            &mut |event| {
                observation_failed =
                    write_private_note_activation_diagnostic(&mut BrokenWriter, event).is_err();
            },
            || if succeeded { Ok(value) } else { Err(value) },
        );
        assert!(observation_failed);
        assert_eq!(result.is_ok(), succeeded);
        let value = match result {
            Ok(value) | Err(value) => value,
        };
        assert_eq!(std::ptr::from_ref(value.as_ref()), original);
    }
}

#[test]
fn genesis_ivm_private_note_activation_is_exact() {
    assert_eq!(
        PRIVACY_PROFILE_ACTIVATION_HEIGHT, PRIVACY_GENESIS_PROPOSAL_HEIGHT,
        "explicit governed profile activation is committed in genesis"
    );
    assert_eq!(
        PRIVATE_SETTLEMENT_ACTIVATION_HEIGHT,
        PRIVACY_PROFILE_ACTIVATION_HEIGHT.max(PRIVATE_SETTLEMENT_NOTICE_ACTIVATION_HEIGHT),
        "APS must activate at the earliest height satisfying both profile and notice schedules"
    );
    assert!(
        PRIVATE_SETTLEMENT_ACTIVATION_HEIGHT >= PRIVACY_PROFILE_ACTIVATION_HEIGHT
            && PRIVATE_SETTLEMENT_ACTIVATION_HEIGHT
                >= PRIVACY_GENESIS_PROPOSAL_HEIGHT
                    + PRIVATE_SETTLEMENT_MINIMUM_ACTIVATION_NOTICE_BLOCKS,
        "APS activation must not precede either prerequisite"
    );
    let shape = TopologyShape::new(PARTICIPANT_COUNT);
    let topology = (0..shape.process_count())
        .map(|index| PeerId::new(validator_authority_keypair(index).public_key().clone()))
        .collect::<Vec<_>>();
    let committee_validator_entries = topology[shape.global_validator_count()..]
        .iter()
        .cloned()
        .map(|peer| GenesisTopologyEntry::new(peer, vec![1]))
        .collect::<Vec<_>>();
    let transactions = genesis_post_topology(shape, &topology, &committee_validator_entries);
    let governance_permission = Permission::from(CanEnactGovernance);
    let (governance_transaction, governance_instruction) = transactions
        .iter()
        .enumerate()
        .find_map(|(transaction_index, transaction)| {
            transaction
                .iter()
                .position(|instruction| {
                    matches!(
                        instruction.as_any().downcast_ref::<GrantBox>(),
                        Some(GrantBox::Permission(grant))
                            if grant.destination == ALICE_ID.clone()
                                && grant.object == governance_permission
                    )
                })
                .map(|instruction_index| (transaction_index, instruction_index))
        })
        .expect("genesis grants the proposal authority governance permission");
    let activations = transactions
        .iter()
        .enumerate()
        .flat_map(|(transaction_index, transaction)| {
            transaction
                .iter()
                .enumerate()
                .filter_map(move |(instruction_index, instruction)| {
                    instruction
                        .as_any()
                        .downcast_ref::<RegisterPrivacyProtocolActivationV1>()
                        .map(|registration| (transaction_index, instruction_index, registration))
                })
        })
        .collect::<Vec<_>>();
    let [(activation_transaction, activation_instruction, registration)] = activations.as_slice()
    else {
        panic!(
            "genesis must contain exactly one IVM private-note activation, found {}",
            activations.len()
        );
    };
    assert_eq!(
        *activation_transaction, governance_transaction,
        "genesis grant and governed activation must be one atomic transaction"
    );
    assert!(
        *activation_instruction > governance_instruction,
        "governed activation must follow its permission grant"
    );
    assert_eq!(registration.activation, genesis_private_note_proposal());
    assert_eq!(
        registration.activation.lifecycle,
        PrivacyProtocolLifecycleV1::Proposed(PrivacyProposedLifecycleV1 {
            proposed_at_height: PRIVACY_GENESIS_PROPOSAL_HEIGHT,
        })
    );
    let transitions = transactions
        .iter()
        .enumerate()
        .flat_map(|(tx, instructions)| {
            instructions
                .iter()
                .enumerate()
                .filter_map(move |(index, instruction)| {
                    instruction
                        .as_any()
                        .downcast_ref::<TransitionPrivacyProtocolLifecycleV1>()
                        .map(|transition| (tx, index, transition))
                })
        })
        .collect::<Vec<_>>();
    let [(transition_transaction, transition_instruction, transition)] = transitions.as_slice()
    else {
        panic!("genesis must contain exactly one explicit IVM profile activation");
    };
    assert_eq!(*transition_transaction, *activation_transaction);
    assert!(*transition_instruction > *activation_instruction);
    assert_eq!(
        transition.protocol_id,
        PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1
    );
    assert_eq!(
        transition.next_lifecycle,
        genesis_private_note_active_lifecycle()
    );
    // Building the real signed topology pre-executes every normalized genesis
    // transaction through Initial. This catches admission failures and rollback
    // of the earlier stake definition/funding before validator registration.
    // No validator processes are started by this regression.
    let handle = std::thread::Builder::new()
        .name("atomic-private-settlement-genesis".to_owned())
        .stack_size(TEST_STACK_BYTES)
        .spawn(move || {
            let network = n3_smoke_builder(shape).build();
            let validated_genesis = network.genesis();
            signed_participant_lane_policy(&network, shape)
                .expect("signed genesis retains exact native participant committees");
            let intrinsic = FastpqSourcePolicyV1::bootstrap().intrinsic;
            for transaction in validated_genesis.0.external_transactions() {
                let iroha::data_model::transaction::Executable::Instructions(instructions) =
                    transaction.instructions()
                else {
                    panic!("genesis is an instruction batch");
                };
                let monetary = instructions
                    .iter()
                    .filter(|instruction| {
                        instruction.as_any().is::<RegisterPublicLaneValidator>()
                            || matches!(
                                instruction
                                    .as_any()
                                    .downcast_ref::<iroha::data_model::isi::MintBox>(),
                                Some(iroha::data_model::isi::MintBox::Asset(_))
                            )
                    })
                    .count();
                assert!(
                    monetary <= intrinsic.max_deltas as usize,
                    "signed final packing must preserve each original monetary entry bound"
                );
            }
        })
        .expect("spawn normalized genesis regression");
    if let Err(panic) = handle.join() {
        std::panic::resume_unwind(panic);
    }
}

#[test]
fn genesis_private_note_readiness_accepts_committed_explicit_activation() {
    let compiled =
        compiled_privacy_profile_v1(PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1).unwrap();
    let activation = compiled.activation_record(genesis_private_note_active_lifecycle());
    let snapshot = PrivacyCompiledProfileResultV1::Available(compiled.into());
    for height in [
        PRIVACY_GENESIS_PROPOSAL_HEIGHT,
        PRIVACY_GENESIS_PROPOSAL_HEIGHT + 17,
    ] {
        assert_eq!(
            validate_genesis_private_note_readiness(&activation, &snapshot, height).unwrap(),
            height
        );
    }
    assert!(validate_genesis_private_note_readiness(&activation, &snapshot, 0).is_err());
}

#[test]
fn genesis_private_note_readiness_rejects_pending_and_substituted_profiles() {
    let compiled =
        compiled_privacy_profile_v1(PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1).unwrap();
    let active = compiled.activation_record(genesis_private_note_active_lifecycle());
    let snapshot = PrivacyCompiledProfileResultV1::Available(compiled.into());
    let mut wrong_protocol = active;
    wrong_protocol.protocol_id = PrivacyProtocolIdV1::ZkAcePqAuthorizationV1;
    let mut wrong_history = active;
    wrong_history.lifecycle = PrivacyProtocolLifecycleV1::Active(PrivacyActiveLifecycleV1 {
        proposed_at_height: 1,
        activated_at_height: 2,
        state_since_height: 2,
    });
    for candidate in [
        genesis_private_note_proposal(),
        wrong_protocol,
        wrong_history,
    ] {
        assert!(validate_genesis_private_note_readiness(&candidate, &snapshot, 3).is_err());
    }
    let other =
        compiled_privacy_profile_v1(PrivacyProtocolIdV1::VeRangeTransparentRangeV1).unwrap();
    let wrong_snapshot = PrivacyCompiledProfileResultV1::Available(other.into());
    assert!(validate_genesis_private_note_readiness(&active, &wrong_snapshot, 3).is_err());
}

#[test]
fn pool_funding_is_reproducible_and_binds_network_governance_and_value() {
    let route = PrivateSettlementRouteV1 {
        dataspace_id: DataSpaceId::new(1),
        lane_id: LaneId::new(1),
        lane_incarnation: hash(0xE0),
    };
    let network_id = iroha::data_model::NetworkId::from_genesis_hash(
        HashOf::<BlockHeader>::from_untyped_unchecked(hash(0xF8)),
    );
    let other_network = iroha::data_model::NetworkId::from_genesis_hash(
        HashOf::<BlockHeader>::from_untyped_unchecked(hash(0xF9)),
    );
    let governed = governed_legs(&[route], 301, 401).expect("governance");
    let changed_governance = governed_legs(&[route], 302, 402).expect("other governance");
    let data = default_private_settlement_leg_data(0);
    let funding = private_settlement_funding(network_id, &governed[0], 0, &data).unwrap();
    let repeated = private_settlement_funding(network_id, &governed[0], 0, &data).unwrap();
    assert_eq!(funding.opening, repeated.opening);
    assert_eq!(funding.spending_secret, repeated.spending_secret);
    assert_eq!(funding.input_commitments, repeated.input_commitments);
    assert_ne!(funding.input_commitments[0], funding.input_commitments[1]);
    assert_eq!(funding.opening.value, data.amount + 7 + 5);
    assert_eq!(funding.opening.commitment, funding.input_commitments[0]);
    assert_eq!(
        funding.opening.spending_authority,
        derive_note_authority_v1(&funding.spending_secret).unwrap()
    );
    for changed in [
        private_settlement_funding(other_network, &governed[0], 0, &data).unwrap(),
        private_settlement_funding(network_id, &changed_governance[0], 0, &data).unwrap(),
        private_settlement_funding(network_id, &governed[0], 1, &data).unwrap(),
    ] {
        assert_ne!(funding.input_commitments, changed.input_commitments);
        assert_ne!(funding.spending_secret, changed.spending_secret);
    }
    let mut changed_value = data.clone();
    changed_value.amount += 1;
    let changed = private_settlement_funding(network_id, &governed[0], 0, &changed_value).unwrap();
    assert_ne!(funding.input_commitments[0], changed.input_commitments[0]);
    assert_eq!(funding.input_commitments[1], changed.input_commitments[1]);
    changed_value.amount = u128::MAX;
    assert!(private_settlement_funding(network_id, &governed[0], 0, &changed_value).is_err());
}

#[test]
fn pool_activation_orders_commitments_without_reordering_spend_slots() {
    let route = PrivateSettlementRouteV1 {
        dataspace_id: DataSpaceId::new(1),
        lane_id: LaneId::new(1),
        lane_incarnation: hash(0xE0),
    };
    let governed = governed_legs(&[route], 301, 401).expect("governance");
    let data = default_private_settlement_leg_data(0);
    let outputs = [0x60, 0x61, 0x62].map(|value| PrivacyCommitmentV1::new([value; 32]));
    let mut seen_input_orders = [false; 2];
    for seed in 0_u8..16 {
        let network_id = iroha::data_model::NetworkId::from_genesis_hash(
            HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new([seed; 32])),
        );
        let funding = private_settlement_funding(network_id, &governed[0], 0, &data)
            .expect("real deterministic funding notes");
        let input_order = funding.input_commitments;
        seen_input_orders[usize::from(input_order[0] > input_order[1])] = true;
        let initial = funding.activation_commitments();
        assert!(initial[0] < initial[1]);
        assert_eq!(funding.input_commitments, input_order);
        assert_eq!(funding.opening.commitment, input_order[0]);
        assert_eq!(
            funding.opening.spending_authority,
            derive_note_authority_v1(&funding.spending_secret).unwrap()
        );
        let activation = ActivatePrivateSettlementPoolV1::from_restricted(
            &governed[0].governance,
            initial.to_vec(),
        )
        .expect("canonical pool activation accepts either funding input order");
        assert_eq!(
            activation.initial_commitments.as_slice(),
            initial.as_slice()
        );
        let bootstrap = plan_atomic_private_settlement_bootstrap_v1(
            governed[0].governance.body.pool_id,
            input_order,
            outputs,
            [funding.spending_secret, [0x70; 32]],
        )
        .expect("native planner maps original spend slots into the sorted tree");
        assert_eq!(bootstrap.initial_commitments, initial);
        let reordered = plan_atomic_private_settlement_bootstrap_v1(
            governed[0].governance.body.pool_id,
            [input_order[1], input_order[0]],
            outputs,
            [[0x70; 32], funding.spending_secret],
        )
        .expect("the same initial set has the same origin and successor roots");
        assert_eq!(bootstrap.old_root, reordered.old_root);
        assert_eq!(bootstrap.new_root, reordered.new_root);
        assert_eq!((bootstrap.old_epoch, bootstrap.new_epoch), (1, 2));
    }
    assert_eq!(seen_input_orders, [true, true]);
}

#[test]
fn governed_pool_setup_transactions_keep_exact_single_routes() {
    use iroha::data_model::{
        nexus::{DataSpaceCatalog, DataSpaceMetadata, LaneCatalog, LaneConfig},
        transaction::TransactionBuilder,
    };
    use iroha_core::queue::{ConfigLaneRouter, LaneRouter, RoutingDecision, RoutingPlan};
    let routes = (1..=3)
        .map(|id| PrivateSettlementRouteV1 {
            dataspace_id: DataSpaceId::new(u64::from(id)),
            lane_id: LaneId::new(id),
            lane_incarnation: hash(id as u8),
        })
        .collect::<Vec<_>>();
    let network_id = iroha::data_model::NetworkId::from_genesis_hash(
        HashOf::<BlockHeader>::from_untyped_unchecked(hash(0xF8)),
    );
    let governed = governed_legs(&routes, 301, 401).unwrap();
    let private_data = (0..3)
        .map(default_private_settlement_leg_data)
        .collect::<Vec<_>>();
    let activations = governed_pool_activation_instructions(network_id, &governed, &private_data)
        .expect("all funding is derived before any independent setup submission");
    let router = ConfigLaneRouter::new(
        iroha_config::parameters::actual::LaneRoutingPolicy::default(),
        DataSpaceCatalog::new(
            (0..=3)
                .map(|id| DataSpaceMetadata {
                    id: DataSpaceId::new(id),
                    alias: if id == 0 {
                        "universal".to_owned()
                    } else {
                        format!("pool{id}")
                    },
                    description: None,
                    fault_tolerance: 1,
                })
                .collect(),
        )
        .unwrap(),
        LaneCatalog::new(
            std::num::NonZeroU32::new(4).unwrap(),
            (0..=3)
                .map(|id| LaneConfig {
                    id: LaneId::new(id),
                    dataspace_id: DataSpaceId::new(u64::from(id)),
                    alias: format!("lane{id}"),
                    ..LaneConfig::default()
                })
                .collect(),
        )
        .unwrap(),
    );
    for (ordinal, activation) in activations.iter().enumerate() {
        let funding = private_settlement_funding(
            network_id,
            &governed[ordinal],
            ordinal,
            &private_data[ordinal],
        )
        .unwrap();
        assert_eq!(
            activation.initial_commitments,
            funding.activation_commitments()
        );
        assert_eq!(activation.route, routes[ordinal]);
        assert_eq!(
            activation.governance_digest,
            governed[ordinal].governance.governance_digest
        );
        let transaction =
            TransactionBuilder::new(network_id, ALICE_ID.clone(), bounded_nexus_fee())
                .with_instructions([activation.clone()])
                .sign(ALICE_KEYPAIR.private_key());
        let expected = RoutingPlan::single(RoutingDecision::new(
            routes[ordinal].lane_id,
            routes[ordinal].dataspace_id,
        ));
        assert_eq!(
            router
                .try_route_plan_without_state(transaction.payload())
                .unwrap(),
            Some(expected)
        );
    }
    let bundled = TransactionBuilder::new(network_id, ALICE_ID.clone(), bounded_nexus_fee())
        .with_instructions(activations)
        .sign(ALICE_KEYPAIR.private_key());
    let plan = router
        .try_route_plan_without_state(bundled.payload())
        .unwrap()
        .unwrap();
    assert!(
        !matches!(plan, RoutingPlan::Single(_)),
        "a signed multi-pool batch is not admissible as one native transaction"
    );
    assert_eq!(plan.legs().len(), 4);
    assert!(
        governed_pool_activation_instructions(network_id, &governed, &private_data[..2]).is_err()
    );
    assert!(governed_pool_activation_instructions(network_id, &[], &[]).is_err());
}

#[test]
fn pool_activation_context_uses_observed_height_and_rejects_unavailable_governance() {
    let route = PrivateSettlementRouteV1 {
        dataspace_id: DataSpaceId::new(1),
        lane_id: LaneId::new(1),
        lane_incarnation: hash(0xE0),
    };
    let governed = governed_legs(&[route], 301, 401).expect("governance");
    for observed in [301, 304, 310, 400] {
        assert_eq!(
            validate_pool_activation_context(&governed, observed, 401).unwrap(),
            observed
        );
    }
    for unavailable in [0, 300, 401, 402] {
        assert!(validate_pool_activation_context(&governed, unavailable, 401).is_err());
    }
    assert!(validate_pool_activation_context(&[], 304, 401).is_err());
}

#[test]
fn repeat_bundle_private_material_is_reproducible_and_disjoint() {
    let routes = (0..PARTICIPANT_COUNT)
        .map(|ordinal| PrivateSettlementRouteV1 {
            dataspace_id: DataSpaceId::new(
                u64::try_from(ordinal + 1).expect("fixture dataspace ordinal fits u64"),
            ),
            lane_id: LaneId::new(
                u32::try_from(ordinal + 1).expect("fixture lane ordinal fits u32"),
            ),
            lane_incarnation: hash(0xE0 + ordinal as u8),
        })
        .collect::<Vec<_>>();
    let network_id = iroha::data_model::NetworkId::from_genesis_hash(
        HashOf::<BlockHeader>::from_untyped_unchecked(hash(0xF8)),
    );
    let first_authority_height = PRIVATE_SETTLEMENT_ACTIVATION_HEIGHT + 10;
    let first_expiry_height = first_authority_height + 100;
    let first_governed = governed_legs(&routes, first_authority_height, first_expiry_height)
        .expect("first deterministic governance set");
    let first_manifest = proof_manifest(
        network_id,
        first_authority_height,
        first_expiry_height,
        &first_governed,
    )
    .expect("first deterministic manifest");
    let second_authority_height = first_authority_height + 1;
    let second_expiry_height = first_expiry_height + 1;
    let second_governed = governed_legs(&routes, second_authority_height, second_expiry_height)
        .expect("second deterministic governance set");
    let second_manifest = proof_manifest(
        network_id,
        second_authority_height,
        second_expiry_height,
        &second_governed,
    )
    .expect("second deterministic manifest");
    assert_ne!(first_manifest.bundle_id, second_manifest.bundle_id);

    let material_shapes: &[(&[u8], usize)] = &[
        (b"output-encryption-rng", 1),
        (b"audit-capsule-rng", 1),
        (b"input-spending-secret", 2),
        (b"output-spending-secret", 3),
        (b"output-view-secret", 3),
        (b"output-ephemeral-secret", 3),
        (b"input-note", 12),
        (b"output-note", 18),
    ];
    let expected_materials_per_leg = material_shapes
        .iter()
        .map(|(_, count)| count)
        .sum::<usize>()
        + 1;
    let mut materials = std::collections::BTreeSet::<[u8; 32]>::new();
    let mut recipient_ids = std::collections::BTreeSet::<PrivacyRecipientIdV1>::new();
    for (bundle_ordinal, (manifest, governed)) in [
        (&first_manifest, first_governed.as_slice()),
        (&second_manifest, second_governed.as_slice()),
    ]
    .into_iter()
    .enumerate()
    {
        for (leg_ordinal, leg) in governed.iter().enumerate() {
            assert!(
                materials.insert(private_settlement_reimbursement_terms_salt(manifest, leg,)),
                "bundle {bundle_ordinal} leg {leg_ordinal} reused its reimbursement salt"
            );
            for (purpose, count) in material_shapes {
                for material_ordinal in 0..*count {
                    let material = private_settlement_leg_private_material(
                        manifest,
                        leg,
                        leg_ordinal,
                        material_ordinal,
                        purpose,
                    );
                    assert_eq!(
                        material,
                        private_settlement_leg_private_material(
                            manifest,
                            leg,
                            leg_ordinal,
                            material_ordinal,
                            purpose,
                        ),
                        "bundle-private derivation must be reproducible"
                    );
                    assert!(
                        materials.insert(material),
                        "bundle {bundle_ordinal} leg {leg_ordinal} reused {purpose:?} slot {material_ordinal}"
                    );
                }
            }
            for output_ordinal in 0..3 {
                let view_secret = private_settlement_leg_private_material(
                    manifest,
                    leg,
                    leg_ordinal,
                    output_ordinal,
                    b"output-view-secret",
                );
                let view_public = ivm_private_recipient_public_key_v1(&view_secret)
                    .expect("derived view secret is valid");
                let recipient_id = derive_ivm_private_recipient_id_v1(view_public)
                    .expect("derived view public key is valid");
                assert!(
                    recipient_ids.insert(recipient_id),
                    "repeat bundles must not reuse an encrypted-output recipient id"
                );
            }
        }
    }
    assert_eq!(
        materials.len(),
        2 * PARTICIPANT_COUNT * expected_materials_per_leg
    );
    assert_eq!(recipient_ids.len(), 2 * PARTICIPANT_COUNT * 3);
}

#[test]
fn n3_diagnostic_logger_filter_parses_and_preserves_info_and_admission() {
    let logger = iroha_config::parameters::user::Logger {
        level: Level::INFO,
        filter: Some(
            N3_DIAGNOSTIC_LOG_FILTER
                .parse()
                .expect("valid diagnostic directives"),
        ),
        ..Default::default()
    };
    let resolved = logger.resolve_filter().to_string();
    let directives = resolved.split(',').collect::<Vec<_>>();
    assert_eq!(
        directives.len(),
        5,
        "one default and four target directives"
    );
    assert_eq!(directives[0], "info", "ordinary node logging stays at INFO");
    assert!(directives.contains(&"iroha_torii::queue_plan_admission=debug"));
    assert!(directives.contains(&"iroha_core::sumeragi=info"));
    assert!(directives.contains(&"iroha_core::sumeragi::driver=debug"));
    assert!(directives.contains(&"iroha_core::sumeragi::executor=debug"));
}

#[test]
fn n3_correctness_smoke_retains_the_release_network_cadence() {
    let builder = n3_smoke_builder(TopologyShape::new(PARTICIPANT_COUNT));
    assert_eq!(
        builder.configured_block_cadence(),
        Some(Duration::from_secs(4))
    );
}

#[test]
fn n3_topology_has_one_global_and_three_disjoint_four_validator_committees() {
    let shape = TopologyShape::new(3);
    assert_eq!(shape.lane_count(), 4);
    assert_eq!(shape.global_validator_count(), 4);
    assert_eq!(shape.participant_validator_count(), 12);
    assert_eq!(shape.process_count(), 16);
    assert_eq!(shape.committee_range(0), 0..4);
    assert_eq!(shape.committee_range(1), 4..8);
    assert_eq!(shape.committee_range(2), 8..12);
    assert_eq!(shape.committee_range(3), 12..16);
}

#[test]
fn n3_primary_topology_mixes_public_and_permissioned_participant_dataspaces() {
    let shape = TopologyShape::new(PARTICIPANT_COUNT);
    assert_eq!(
        shape.participant_visibility_profile(),
        [
            LaneVisibility::Public,
            LaneVisibility::Restricted,
            LaneVisibility::Restricted,
        ]
    );
    assert_eq!(participant_dataspace_alias(0), "public-1");
    assert_eq!(participant_dataspace_alias(1), "private-2");
    assert_eq!(participant_dataspace_alias(2), "private-3");
    assert_eq!(shape.p2p_process_counts_by_visibility(), (8, 8));
}

#[test]
fn release_matrix_shapes_are_disjoint_and_exact() {
    for participants in [2, 3, 4, 8, 16] {
        let shape = TopologyShape::new(participants);
        shape.validate().expect("supported release shape");
        let ranges = (0..shape.lane_count())
            .map(|lane| shape.committee_range(lane))
            .collect::<Vec<_>>();
        assert_eq!(ranges.first().expect("global range").start, 0);
        assert_eq!(
            ranges.last().expect("last range").end,
            shape.process_count()
        );
        assert!(ranges.windows(2).all(|pair| pair[0].end == pair[1].start));
        assert!(
            ranges
                .iter()
                .all(|range| range.len() == VALIDATORS_PER_LANE)
        );
    }
}

#[test]
fn unsupported_real_process_participant_count_fails_closed() {
    assert!(TopologyShape::new(1).validate().is_err());
    assert!(TopologyShape::new(5).validate().is_err());
    assert!(TopologyShape::new(17).validate().is_err());
    assert_eq!(GLOBAL_LANE_ID, 0);
}

#[test]
fn leakage_canary_identifiers_are_canonical_typed_values() {
    let left_account = leakage_canary_account_id("left").expect("left canary account");
    let right_account = leakage_canary_account_id("right").expect("right canary account");
    assert_eq!(left_account.to_string(), LEAKAGE_ACCOUNT_LEFT_I105);
    assert_eq!(right_account.to_string(), LEAKAGE_ACCOUNT_RIGHT_I105);
    assert_ne!(left_account, right_account);

    let left_asset =
        leakage_canary_asset_definition_id("left").expect("left canary asset definition");
    let right_asset =
        leakage_canary_asset_definition_id("right").expect("right canary asset definition");
    assert_eq!(left_asset.to_string(), LEAKAGE_ASSET_LEFT);
    assert_eq!(right_asset.to_string(), LEAKAGE_ASSET_RIGHT);
    assert_ne!(left_asset, right_asset);
    assert!(leakage_canary_account_id("unknown").is_err());
    assert!(leakage_canary_asset_definition_id("unknown").is_err());
}

include!("atomic_private_settlement_real_process_harness.rs");

use iroha_core_privacy::privacy_engines::atomic_private_settlement::audit::seal_private_settlement_audit_capsule_v1_with_rng;
