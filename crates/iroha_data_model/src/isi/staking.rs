//! Stake-backed public-lane validator admission, custody, and rewards.
use super::*;
#[cfg(test)]
use crate::asset::AssetId;
use crate::{
    account::AccountId,
    nexus::{PublicLaneMonetaryPlanV1, PublicLaneRewardClaimPlanV1},
};
use iroha_crypto::{Hash, SignatureOf};
use iroha_model_base::metadata::Metadata;
use iroha_model_base::peer::PeerId;
use iroha_model_base::topology::LaneId;
use iroha_primitives::numeric::Quantity;
use std::string::String;
isi! {
    /// Activate a pending validator for a public Nexus lane.
    #[derive (crate :: DeriveJsonSerialize , crate :: DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::staking::ActivatePublicLaneValidator")]
    pub struct ActivatePublicLaneValidator {
        /// Lane that the validator targets.
        pub lane_id: LaneId,
        /// Account that signs consensus messages for the lane.
        pub validator: AccountId,
    }
}
impl ActivatePublicLaneValidator {
    /// Build a public-lane validator activation instruction.
    #[must_use]
    pub fn new(lane_id: LaneId, validator: AccountId) -> Self {
        Self { lane_id, validator }
    }
}
isi! {
    /// Request graceful exit for a validator and release its slot.
    #[derive(crate::DeriveJsonSerialize, crate::DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::staking::ExitPublicLaneValidator")]
    pub struct ExitPublicLaneValidator {
        /// Lane that the validator targets.
        pub lane_id: LaneId,
        /// Account that signs consensus messages for the lane.
        pub validator: AccountId,
        /// Timestamp (unix ms) after which the validator is considered fully exited.
        pub release_at_ms: u64,
    }
}
isi! {
    /// Register a validator for a public Nexus lane and bond validator-owned initial stake.
    #[derive (crate :: DeriveJsonSerialize , crate :: DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::staking::RegisterPublicLaneValidator")]
    pub struct RegisterPublicLaneValidator {
        /// Lane that the validator targets.
        pub lane_id: LaneId,
        /// Account that owns validator authority for the lane.
        pub validator: AccountId,
        /// Peer identity that signs consensus messages for the lane.
        pub peer_id: PeerId,
        /// Validator account whose funds are locked as initial self-stake.
        pub stake_account: AccountId,
        /// Amount of stake bonded during registration.
        pub initial_stake: Quantity,
        /// Descriptive metadata such as jurisdiction flags and telemetry ids.
        /// Commission is zero; metadata cannot change reward allocation.
        pub metadata: Metadata,
        /// Signed exact transfer, custody effect, and current-state precondition.
        pub monetary_plan: PublicLaneMonetaryPlanV1,
    }
}
/// Domain-separated consent from a fresh consensus peer to its stake-owning account.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    norito::NoritoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
)]
#[norito_schema(name = "iroha_data_model::isi::staking::PublicLaneCandidateAuthorization")]
pub struct PublicLaneCandidateAuthorization {
    /// Protocol domain separating this signature from every other signed message.
    domain: String,
    /// Genesis-derived identity of the network admitting the candidate.
    pub network_id: crate::NetworkId,
    /// Exact validator identity, lane, peer, stake, and metadata authorized by the peer.
    pub registration: RegisterPublicLaneValidator,
    /// Exact planned eligibility boundary; consent cannot authorize a later tenure.
    pub activation_height: u64,
}
impl PublicLaneCandidateAuthorization {
    /// Build the exact message that a candidate consensus key must sign.
    #[must_use]
    pub fn new(
        network_id: crate::NetworkId,
        registration: RegisterPublicLaneValidator,
        activation_height: u64,
    ) -> Self {
        Self {
            domain: "iroha.staking.public_lane_candidate.v1".to_owned(),
            network_id,
            registration,
            activation_height,
        }
    }
}
isi! {
    /// Atomically admit a fresh consensus peer and escrow its owner's validator stake.
    ///
    /// Admission schedules eligibility after key activation and the next unfrozen election;
    /// it never grants membership of the current committee.
    #[derive(crate::DeriveJsonSerialize, crate::DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::staking::RegisterPublicLaneCandidate")]
    pub struct RegisterPublicLaneCandidate {
        /// Exact registration consented to by the transaction account and consensus peer.
        pub registration: RegisterPublicLaneValidator,
        /// Expected election boundary, signed by the peer and recomputed at admission.
        pub activation_height: u64,
        /// BLS-normal proof of possession for the fresh peer identity.
        pub proof_of_possession: Vec<u8>,
        /// Peer signature over the network-bound candidate authorization.
        pub peer_signature: SignatureOf<PublicLaneCandidateAuthorization>,
    }
}
impl crate::seal::Instruction for RegisterPublicLaneCandidate {}
impl RegisterPublicLaneValidator {
    /// Build a public-lane validator registration instruction.
    #[must_use]
    pub fn new(
        lane_id: LaneId,
        validator: AccountId,
        peer_id: PeerId,
        stake_account: AccountId,
        initial_stake: Quantity,
        metadata: Metadata,
        monetary_plan: PublicLaneMonetaryPlanV1,
    ) -> Self {
        Self {
            lane_id,
            validator,
            peer_id,
            stake_account,
            initial_stake,
            metadata,
            monetary_plan,
        }
    }
}
/// Domain-separated peer consent to a pending validator's replacement binding.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    norito::NoritoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
)]
#[norito_schema(name = "iroha_data_model::isi::staking::PublicLanePeerBindingAuthorization")]
pub struct PublicLanePeerBindingAuthorization {
    /// Protocol domain separating peer rebinding from initial registration.
    domain: String,
    /// Genesis-derived network identity.
    pub network_id: crate::NetworkId,
    /// Lane containing the pending validator.
    pub lane_id: LaneId,
    /// Account that owns validator stake and authority.
    pub validator: AccountId,
    /// Replacement consensus peer consenting to the binding.
    pub peer_id: PeerId,
    /// Pending validator tenure to which this consent is restricted.
    pub activation_height: u64,
    /// Existing peer binding replaced by this consent.
    pub previous_peer_id: PeerId,
}
impl PublicLanePeerBindingAuthorization {
    /// Construct the canonical replacement peer's consent message.
    #[must_use]
    pub fn new(
        network_id: crate::NetworkId,
        lane_id: LaneId,
        validator: AccountId,
        peer_id: PeerId,
        activation_height: u64,
        previous_peer_id: PeerId,
    ) -> Self {
        Self {
            domain: "iroha.staking.public_lane_peer_binding.v1".to_owned(),
            network_id,
            lane_id,
            validator,
            peer_id,
            activation_height,
            previous_peer_id,
        }
    }
}
isi! {
    /// Rebind an existing public-lane validator to a new consensus peer identity.
    #[derive (crate :: DeriveJsonSerialize , crate :: DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::staking::RebindPublicLaneValidatorPeer")]
    pub struct RebindPublicLaneValidatorPeer {
        /// Lane that the validator targets.
        pub lane_id: LaneId,
        /// Account that owns validator authority for the lane.
        pub validator: AccountId,
        /// Replacement peer identity that signs consensus messages for the lane.
        pub peer_id: PeerId,
        /// Exact network, tenure, and previous-binding consent from the replacement peer.
        pub peer_signature: SignatureOf<PublicLanePeerBindingAuthorization>,
    }
}
impl RebindPublicLaneValidatorPeer {
    /// Build a public-lane validator peer-rebinding instruction.
    #[must_use]
    pub fn new(
        lane_id: LaneId,
        validator: AccountId,
        peer_id: PeerId,
        peer_signature: SignatureOf<PublicLanePeerBindingAuthorization>,
    ) -> Self {
        Self {
            lane_id,
            validator,
            peer_id,
            peer_signature,
        }
    }
}
isi! {
    /// Bond additional stake for an existing validator (self or delegator supplied).
    #[derive(crate::DeriveJsonSerialize, crate::DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::staking::BondPublicLaneStake")]
    pub struct BondPublicLaneStake {
        /// Lane identifier.
        pub lane_id: LaneId,
        /// Target validator account.
        pub validator: AccountId,
        /// Account supplying the stake (delegator or validator).
        pub staker: AccountId,
        /// Stake amount to lock.
        pub amount: Quantity,
        /// Optional metadata captured for dashboards/audit trails.
        pub metadata: Metadata,
        /// Signed exact transfer, custody effect, and current-state precondition.
        pub monetary_plan: PublicLaneMonetaryPlanV1,
    }
}
/// Construct an explicit network-bound transfer for codec and dispatch fixtures.
#[cfg(test)]
pub(crate) fn test_monetary_transfer_plan(
    source_asset: AssetId,
    destination_asset: AssetId,
    amount: Quantity,
    precondition: crate::nexus::PublicLaneMonetaryPreconditionV1,
) -> PublicLaneMonetaryPlanV1 {
    PublicLaneMonetaryPlanV1 {
        network_scope: crate::nexus::PublicLaneMonetaryScopeV1::Network(
            crate::NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
                Hash::new(b"staking instruction codec fixture network"),
            )),
        ),
        valid_until_height: 20,
        source_asset,
        destination_asset,
        amount,
        precondition,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        asset::AssetDefinitionId,
        nexus::{
            PublicLaneMonetaryPreconditionV1, PublicLaneMonetaryRegistrationV1,
            PublicLaneMonetaryScopeV1,
        },
        prelude::{AccountId, Algorithm, KeyPair},
    };
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::peer::PeerId;
    fn sample_account() -> AccountId {
        let _domain: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
        let key_pair = KeyPair::try_from_seed(vec![0x11; 32], Algorithm::Ed25519)
            .expect("derive checked staking fixture account keypair");
        AccountId::new(key_pair.public_key().clone())
    }
    fn sample_peer_id() -> PeerId {
        let key_pair = KeyPair::try_from_seed(vec![0x22; 32], Algorithm::Ed25519)
            .expect("derive checked staking fixture peer keypair");
        PeerId::new(key_pair.public_key().clone())
    }
    fn registration_plan(
        network: crate::NetworkId,
        amount: Quantity,
        activation_height: u64,
    ) -> PublicLaneMonetaryPlanV1 {
        let definition = AssetDefinitionId::from_uuid_bytes([
            0x2f, 0x17, 0xc7, 0x24, 0x66, 0xf8, 0x4a, 0x4b, 0xb8, 0xa8, 0xe2, 0x48, 0x84, 0xfd,
            0xcd, 0x2f,
        ])
        .expect("canonical fixture asset definition");
        let escrow = AccountId::new(sample_peer_id().public_key().clone());
        PublicLaneMonetaryPlanV1 {
            network_scope: PublicLaneMonetaryScopeV1::Network(network),
            valid_until_height: activation_height,
            source_asset: AssetId::new(definition.clone(), sample_account()),
            destination_asset: AssetId::new(definition, escrow),
            amount,
            precondition: PublicLaneMonetaryPreconditionV1::Registration(
                PublicLaneMonetaryRegistrationV1 { activation_height },
            ),
        }
    }
    fn candidate_fixture() -> (RegisterPublicLaneCandidate, crate::NetworkId) {
        let network_id = crate::NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"candidate-network")),
        );
        let key = KeyPair::try_from_seed(vec![0x31; 32], Algorithm::BlsNormal)
            .expect("BLS candidate key");
        let registration = RegisterPublicLaneValidator::new(
            LaneId::SINGLE,
            sample_account(),
            PeerId::new(key.public_key().clone()),
            sample_account(),
            Quantity::from(1000_u64),
            Metadata::default(),
            registration_plan(network_id, Quantity::from(1000_u64), 13),
        );
        let authorization =
            PublicLaneCandidateAuthorization::new(network_id, registration.clone(), 13);
        (
            RegisterPublicLaneCandidate {
                registration,
                activation_height: 13,
                proof_of_possession: iroha_crypto::bls_normal_pop_prove(key.private_key())
                    .expect("PoP"),
                peer_signature: SignatureOf::try_new(key.private_key(), &authorization)
                    .expect("peer consent"),
            },
            network_id,
        )
    }
    #[test]
    fn candidate_consent_binds_network_owner_lane_and_amount() {
        let (candidate, network) = candidate_fixture();
        let payload = PublicLaneCandidateAuthorization::new(
            network,
            candidate.registration.clone(),
            candidate.activation_height,
        );
        candidate
            .peer_signature
            .verify(candidate.registration.peer_id.public_key(), &payload)
            .expect("valid consent");
        assert!(payload.registration.monetary_plan.has_canonical_shape());
        let mut alternatives = vec![payload.clone(); 11];
        alternatives[0].network_id = crate::NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"other-network")),
        );
        alternatives[1].registration.validator =
            AccountId::new(sample_peer_id().public_key().clone());
        alternatives[2].registration.lane_id = LaneId::new(7);
        alternatives[3].registration.initial_stake = Quantity::from(999_u64);
        alternatives[4].activation_height += 1;
        alternatives[5].registration.monetary_plan.network_scope =
            PublicLaneMonetaryScopeV1::Genesis;
        alternatives[6]
            .registration
            .monetary_plan
            .valid_until_height += 1;
        alternatives[7].registration.monetary_plan.source_asset =
            payload.registration.monetary_plan.destination_asset.clone();
        alternatives[8].registration.monetary_plan.destination_asset =
            payload.registration.monetary_plan.source_asset.clone();
        alternatives[9].registration.monetary_plan.amount = Quantity::from(999_u64);
        alternatives[10].registration.monetary_plan.precondition =
            PublicLaneMonetaryPreconditionV1::Registration(PublicLaneMonetaryRegistrationV1 {
                activation_height: 14,
            });
        for changed in alternatives {
            assert!(
                candidate
                    .peer_signature
                    .verify(candidate.registration.peer_id.public_key(), &changed)
                    .is_err()
            );
        }
    }
    #[test]
    fn candidate_instruction_roundtrips_through_canonical_registry() {
        let (candidate, _) = candidate_fixture();
        crate::isi::test_support::assert_slice_roundtrip(candidate.clone());
        let registry = crate::isi::InstructionRegistry::new()
            .register_with_id_slice::<RegisterPublicLaneCandidate>(
                "iroha.staking.register_public_lane_candidate",
            );
        crate::isi::test_support::assert_registry_decodes(
            &registry,
            "iroha.staking.register_public_lane_candidate",
            candidate.clone(),
        );
        let json = norito::json::to_json(&candidate).expect("candidate JSON");
        let decoded: RegisterPublicLaneCandidate =
            norito::json::from_str(&json).expect("candidate decode");
        assert_eq!(candidate, decoded);
    }
    #[test]
    #[ignore = "explicit maintenance command prints canonical changed staking frame fixtures"]
    fn print_staking_admission_record_fixture_rows() {
        let (candidate, network_id) = candidate_fixture();
        let peer_key =
            KeyPair::try_from_seed(vec![0x31; 32], Algorithm::BlsNormal).expect("fixture peer");
        let consent = PublicLanePeerBindingAuthorization::new(
            network_id,
            candidate.registration.lane_id,
            candidate.registration.validator.clone(),
            candidate.registration.peer_id.clone(),
            13,
            sample_peer_id(),
        );
        let rebind = RebindPublicLaneValidatorPeer::new(
            candidate.registration.lane_id,
            candidate.registration.validator.clone(),
            candidate.registration.peer_id.clone(),
            SignatureOf::try_new(peer_key.private_key(), &consent)
                .expect("fixture rebind signature"),
        );
        let mut rows = vec![
            crate::isi::generated_record_identity_tests::capture(candidate.registration.clone()),
            crate::isi::generated_record_identity_tests::capture(candidate),
            crate::isi::generated_record_identity_tests::capture(rebind),
        ];
        rows.extend(crate::isi::generated_record_identity_tests::staking_monetary_fixture_rows());
        println!(
            "STAKING_ADMISSION_FIXTURE_ROWS={}",
            norito::json::to_json(&rows).expect("fixture rows")
        );
    }
    #[test]
    fn activate_public_lane_validator_new_sets_fields() {
        let validator = sample_account();
        let instruction = ActivatePublicLaneValidator::new(LaneId::SINGLE, validator.clone());
        assert_eq!(*instruction.lane_id(), LaneId::SINGLE);
        assert_eq!(instruction.validator(), &validator);
    }
    #[test]
    fn register_public_lane_validator_new_sets_fields() {
        let validator = sample_account();
        let peer_id = sample_peer_id();
        let metadata = Metadata::default();
        let (_, network) = candidate_fixture();
        let monetary_plan = registration_plan(network, Quantity::from(10_u64), 13);
        let instruction = RegisterPublicLaneValidator::new(
            LaneId::SINGLE,
            validator.clone(),
            peer_id.clone(),
            validator.clone(),
            Quantity::from(10_u64),
            metadata.clone(),
            monetary_plan.clone(),
        );
        assert_eq!(*instruction.lane_id(), LaneId::SINGLE);
        assert_eq!(instruction.validator(), &validator);
        assert_eq!(instruction.peer_id(), &peer_id);
        assert_eq!(instruction.stake_account(), &validator);
        assert_eq!(instruction.initial_stake(), &Quantity::from(10_u64));
        assert_eq!(instruction.metadata(), &metadata);
        assert_eq!(instruction.monetary_plan(), &monetary_plan);
    }
    fn assert_closed_claim_json<T>(value: &T)
    where
        T: norito::json::JsonSerialize + norito::json::JsonDeserialize,
    {
        let canonical = norito::json::to_value(value).expect("claim JSON");
        let object = canonical.as_object().expect("claim record object");
        let mut malformed = Vec::new();
        for field in object.keys() {
            let mut missing = object.clone();
            missing.remove(field);
            malformed.push(norito::json::Value::Object(missing));
        }
        for field in ["unknown_field", "upto_epoch"] {
            let mut unknown = object.clone();
            unknown.insert(field.into(), norito::json::Value::Null);
            malformed.push(norito::json::Value::Object(unknown));
        }
        for invalid in malformed {
            let text = norito::json::to_json(&invalid).expect("malformed claim JSON");
            assert!(
                norito::json::from_str::<T>(&text).is_err(),
                "accepted {text}"
            );
            assert!(
                norito::json::from_value::<T>(invalid).is_err(),
                "accepted {text}"
            );
        }
    }
    fn reward_claim_fixture() -> ClaimPublicLaneRewards {
        let (_, network) = candidate_fixture();
        let transfer = registration_plan(network, Quantity::from(10_u64), 13);
        let plan = PublicLaneRewardClaimPlanV1 {
            network_scope: transfer.network_scope,
            valid_until_height: 13,
            fee_claim: crate::nexus::PublicLaneFeeRewardClaimV1 {
                lifecycle_seal: [0x81; 32],
                beneficiary_id: sample_account(),
                beneficiary_revision: 3,
                source_asset: transfer.destination_asset.clone(),
                destination_asset: transfer.source_asset.clone(),
                amount: Quantity::from(7_u64),
                expected_claim_sequence: 17,
            },
        };
        assert!(plan.has_canonical_shape(&sample_account()));
        ClaimPublicLaneRewards {
            lane_id: LaneId::SINGLE,
            account: sample_account(),
            claim_plan: plan,
        }
    }
    #[test]
    #[ignore = "explicit maintenance command prints the canonical complete reward claim record"]
    fn print_staking_reward_claim_fixture_row() {
        let row = crate::isi::generated_record_identity_tests::capture(reward_claim_fixture());
        println!(
            "STAKING_CLAIM_FIXTURE_ROW={}",
            norito::json::to_json(&row).expect("canonical complete reward claim row")
        );
    }
    #[test]
    fn reward_claim_records_require_closed_complete_json_and_roundtrip() {
        let instruction = reward_claim_fixture();
        assert_closed_claim_json(&instruction.claim_plan.fee_claim);
        assert_closed_claim_json(&instruction.claim_plan);
        let boxed = crate::isi::InstructionBox::from(instruction.clone());
        let bytes = norito::encode_canonical(&boxed).expect("canonical claim instruction frame");
        let decoded_box: crate::isi::InstructionBox =
            norito::decode_canonical(&bytes).expect("registered claim instruction decode");
        assert_eq!(decoded_box, boxed);
        let json = norito::json::to_json(&instruction).expect("claim instruction JSON");
        let decoded: ClaimPublicLaneRewards = norito::json::from_str(&json).expect("claim decode");
        assert_eq!(decoded, instruction);

        let mut value = norito::json::to_value(&instruction.claim_plan).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("fee_claim".into(), norito::json::Value::Null);
        assert!(norito::json::from_value::<PublicLaneRewardClaimPlanV1>(value).is_err());
    }
    #[test]
    fn fee_reward_claim_shape_requires_exact_global_positive_recipient_payment() {
        let instruction = reward_claim_fixture();
        let mut expired = instruction.claim_plan.clone();
        expired.valid_until_height = 0;
        assert!(!expired.has_canonical_shape(&instruction.account));
        let fee = instruction.claim_plan.fee_claim;
        assert!(fee.has_canonical_shape(&instruction.account));
        for change in 0..5 {
            let mut invalid = fee.clone();
            match change {
                0 => invalid.lifecycle_seal = [0; 32],
                1 => invalid.amount = Quantity::zero(),
                2 => invalid.destination_asset = invalid.source_asset.clone(),
                3 => {
                    invalid.source_asset = AssetId::with_scope(
                        invalid.source_asset.definition().clone(),
                        invalid.source_asset.account().clone(),
                        crate::asset::AssetBalanceScope::Dataspace(
                            iroha_model_base::topology::DataSpaceId::new(1),
                        ),
                    )
                }
                _ => {
                    invalid.destination_asset = AssetId::with_scope(
                        invalid.destination_asset.definition().clone(),
                        instruction.account.clone(),
                        crate::asset::AssetBalanceScope::Dataspace(
                            iroha_model_base::topology::DataSpaceId::new(1),
                        ),
                    )
                }
            }
            assert!(!invalid.has_canonical_shape(&instruction.account));
        }
    }
    #[test]
    fn reward_claim_rejects_retired_bound_only_layout() {
        for json in [r#"{"upto_epoch":null}"#, r#"{"upto_epoch":12}"#] {
            assert!(norito::json::from_str::<PublicLaneRewardClaimPlanV1>(json).is_err());
        }
    }
    #[test]
    fn rebind_public_lane_validator_peer_new_sets_fields() {
        let validator = sample_account();
        let peer_id = sample_peer_id();
        let peer_key =
            KeyPair::try_from_seed(vec![0x22; 32], Algorithm::Ed25519).expect("fixture peer");
        let consent = PublicLanePeerBindingAuthorization::new(
            crate::NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
                Hash::new(b"staking-rebind-constructor"),
            )),
            LaneId::SINGLE,
            validator.clone(),
            peer_id.clone(),
            13,
            sample_peer_id(),
        );
        let signature = SignatureOf::try_new(peer_key.private_key(), &consent)
            .expect("fixture rebind signature");
        let instruction = RebindPublicLaneValidatorPeer::new(
            LaneId::SINGLE,
            validator.clone(),
            peer_id.clone(),
            signature.clone(),
        );
        assert_eq!(*instruction.lane_id(), LaneId::SINGLE);
        assert_eq!(instruction.validator(), &validator);
        assert_eq!(instruction.peer_id(), &peer_id);
        assert_eq!(instruction.peer_signature(), &signature);
    }
}
isi! {
    /// Schedule stake withdrawal for a validator or delegator.
    #[derive(crate::DeriveJsonSerialize, crate::DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::staking::SchedulePublicLaneUnbond")]
    pub struct SchedulePublicLaneUnbond {
        /// Lane identifier.
        pub lane_id: LaneId,
        /// Target validator account.
        pub validator: AccountId,
        /// Account withdrawing stake.
        pub staker: AccountId,
        /// Deterministic identifier supplied by the caller to track the withdrawal.
        pub request_id: Hash,
        /// Amount scheduled for withdrawal.
        pub amount: Quantity,
        /// Timestamp (unix ms) when the withdrawal becomes eligible for finalisation.
        pub release_at_ms: u64,
    }
}
isi! {
    /// Finalise a previously scheduled stake withdrawal once the unlock timer expires.
    #[derive(crate::DeriveJsonSerialize, crate::DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::staking::FinalizePublicLaneUnbond")]
    pub struct FinalizePublicLaneUnbond {
        /// Lane identifier.
        pub lane_id: LaneId,
        /// Target validator account.
        pub validator: AccountId,
        /// Account receiving the unlocked stake.
        pub staker: AccountId,
        /// Identifier of the withdrawal request that is being completed.
        pub request_id: Hash,
        /// Signed exact transfer, custody effect, and current-state precondition.
        pub monetary_plan: PublicLaneMonetaryPlanV1,
    }
}
isi! {
    /// Slash a validator for misbehaviour and emit an audit trail entry.
    #[derive(crate::DeriveJsonSerialize, crate::DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::staking::SlashPublicLaneValidator")]
    pub struct SlashPublicLaneValidator {
        /// Lane identifier.
        pub lane_id: LaneId,
        /// Misbehaving validator account.
        pub validator: AccountId,
        /// Exact consensus height at which the slashable offence occurred.
        pub offence_height: u64,
        /// Unique identifier for the slash event.
        pub slash_id: Hash,
        /// Amount of stake to burn or seize.
        pub amount: Quantity,
        /// Canonical reason code (e.g., `double_sign`, `downtime`).
        pub reason_code: String,
        /// Metadata documenting evidence digests, governance proposal ids, etc.
        pub metadata: Metadata,
        /// Signed exact transfer, custody effect, and current-state precondition.
        pub monetary_plan: PublicLaneMonetaryPlanV1,
    }
}
isi! {
    /// Withdraw one signed exact funded automatic reward entitlement.
    #[derive(crate::DeriveJsonSerialize, crate::DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::staking::ClaimPublicLaneRewards")]
    pub struct ClaimPublicLaneRewards {
        /// Lane identifier.
        pub lane_id: LaneId,
        /// Account receiving the rewards.
        pub account: AccountId,
        /// Exact funded reward payment authorized by the recipient.
        pub claim_plan: PublicLaneRewardClaimPlanV1,
    }
}
impl crate::seal::Instruction for RegisterPublicLaneValidator {}
impl crate::seal::Instruction for RebindPublicLaneValidatorPeer {}
impl crate::seal::Instruction for ActivatePublicLaneValidator {}
impl crate::seal::Instruction for ExitPublicLaneValidator {}
impl crate::seal::Instruction for BondPublicLaneStake {}
impl crate::seal::Instruction for SchedulePublicLaneUnbond {}
impl crate::seal::Instruction for FinalizePublicLaneUnbond {}
impl crate::seal::Instruction for SlashPublicLaneValidator {}
impl crate::seal::Instruction for ClaimPublicLaneRewards {}
fn staking_decode_flags() -> u8 {
    norito::core::effective_decode_flags().unwrap_or_else(norito::core::default_encode_flags)
}
impl<'a> norito::core::DecodeFromSlice<'a> for RegisterPublicLaneCandidate {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = staking_decode_flags();
        let mut offset = 0usize;
        let registration = super::decode_aos_canonical_field::<RegisterPublicLaneValidator>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let activation_height = super::decode_aos_canonical_field::<u64>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let proof_of_possession = super::decode_aos_canonical_field::<Vec<u8>>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let peer_signature = super::decode_aos_canonical_field::<
            SignatureOf<PublicLaneCandidateAuthorization>,
        >(super::read_aos_field(bytes, &mut offset, flags)?, flags)?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((
            Self {
                registration,
                activation_height,
                proof_of_possession,
                peer_signature,
            },
            offset,
        ))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for RegisterPublicLaneValidator {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = staking_decode_flags();
        let mut offset = 0usize;
        let lane_id = super::decode_aos_canonical_field::<LaneId>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let validator = super::decode_aos_canonical_field::<AccountId>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let peer_id = super::decode_aos_canonical_field::<PeerId>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let stake_account = super::decode_aos_canonical_field::<AccountId>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let initial_stake = super::decode_aos_canonical_field::<Quantity>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let metadata = super::decode_aos_canonical_field::<Metadata>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let monetary_plan = super::decode_aos_canonical_field::<PublicLaneMonetaryPlanV1>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((
            Self {
                lane_id,
                validator,
                peer_id,
                stake_account,
                initial_stake,
                metadata,
                monetary_plan,
            },
            offset,
        ))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for RebindPublicLaneValidatorPeer {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = staking_decode_flags();
        let mut offset = 0usize;
        let lane_id = super::decode_aos_canonical_field::<LaneId>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let validator = super::decode_aos_canonical_field::<AccountId>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let peer_id = super::decode_aos_canonical_field::<PeerId>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let peer_signature = super::decode_aos_canonical_field::<
            SignatureOf<PublicLanePeerBindingAuthorization>,
        >(super::read_aos_field(bytes, &mut offset, flags)?, flags)?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((
            Self {
                lane_id,
                validator,
                peer_id,
                peer_signature,
            },
            offset,
        ))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for ActivatePublicLaneValidator {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = staking_decode_flags();
        let mut offset = 0usize;
        let lane_id = super::decode_aos_canonical_field::<LaneId>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let validator = super::decode_aos_canonical_field::<AccountId>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((Self { lane_id, validator }, offset))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for ExitPublicLaneValidator {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = staking_decode_flags();
        let mut offset = 0usize;
        let lane_id = super::decode_aos_canonical_field::<LaneId>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let validator = super::decode_aos_canonical_field::<AccountId>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let release_at_ms = super::decode_aos_canonical_field::<u64>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((
            Self {
                lane_id,
                validator,
                release_at_ms,
            },
            offset,
        ))
    }
}
#[cfg(test)]
mod slice_tests {
    use super::*;
    use crate::NetworkId;
    use crate::isi::test_support::{assert_registry_decodes, assert_slice_roundtrip};
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
    use iroha_primitives::numeric::Numeric;
    use norito::codec::Decode;
    use norito::core::DecodeFromSlice;
    #[derive(norito::codec::Encode)]
    struct ForgedRegisterPublicLaneValidator {
        lane_id: LaneId,
        validator: AccountId,
        peer_id: PeerId,
        stake_account: AccountId,
        initial_stake: Numeric,
        metadata: Metadata,
        monetary_plan: PublicLaneMonetaryPlanV1,
    }
    #[derive(norito::codec::Encode)]
    struct ForgedBondPublicLaneStake {
        lane_id: LaneId,
        validator: AccountId,
        staker: AccountId,
        amount: Numeric,
        metadata: Metadata,
        monetary_plan: PublicLaneMonetaryPlanV1,
    }
    fn account(seed: u8) -> AccountId {
        let key_pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("derive checked staking slice fixture account keypair");
        AccountId::new(key_pair.public_key().clone())
    }
    fn peer(seed: u8) -> PeerId {
        let key_pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("derive checked staking slice fixture peer keypair");
        PeerId::new(key_pair.public_key().clone())
    }
    fn rebind_signature() -> SignatureOf<PublicLanePeerBindingAuthorization> {
        let key_pair = KeyPair::try_from_seed(vec![0x14; 32], Algorithm::Ed25519)
            .expect("derive rebind peer key");
        let consent = PublicLanePeerBindingAuthorization::new(
            NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
                b"staking-slice-rebind",
            ))),
            LaneId::SINGLE,
            account(0x11),
            peer(0x14),
            13,
            peer(0x12),
        );
        SignatureOf::try_new(key_pair.private_key(), &consent).expect("rebind peer signature")
    }
    fn transfer_plan(staker: AccountId, amount: Quantity, bond: bool) -> PublicLaneMonetaryPlanV1 {
        use crate::nexus::{
            PublicLaneMonetaryBondV1, PublicLaneMonetaryPreconditionV1,
            PublicLaneMonetaryRegistrationV1,
        };
        let definition = crate::asset::AssetDefinitionId::from_uuid_bytes([
            1, 2, 3, 4, 5, 6, 0x47, 8, 0x89, 10, 11, 12, 13, 14, 15, 16,
        ])
        .expect("fixture asset definition");
        let precondition = if bond {
            PublicLaneMonetaryPreconditionV1::Bond(PublicLaneMonetaryBondV1 {
                activation_height: 1,
                peer_id: peer(0x12),
            })
        } else {
            PublicLaneMonetaryPreconditionV1::Registration(PublicLaneMonetaryRegistrationV1 {
                activation_height: 1,
            })
        };
        super::test_monetary_transfer_plan(
            AssetId::new(definition.clone(), staker),
            AssetId::new(definition, account(0x55)),
            amount,
            precondition,
        )
    }
    #[test]
    fn staking_decode_from_slice_roundtrips() {
        assert_slice_roundtrip(RegisterPublicLaneValidator {
            lane_id: LaneId::SINGLE,
            validator: account(0x11),
            peer_id: peer(0x12),
            stake_account: account(0x13),
            initial_stake: Quantity::from(10_u64),
            metadata: Metadata::default(),
            monetary_plan: transfer_plan(account(0x13), Quantity::from(10_u64), false),
        });
        assert_slice_roundtrip(RebindPublicLaneValidatorPeer {
            lane_id: LaneId::SINGLE,
            validator: account(0x11),
            peer_id: peer(0x14),
            peer_signature: rebind_signature(),
        });
        assert_slice_roundtrip(ActivatePublicLaneValidator {
            lane_id: LaneId::SINGLE,
            validator: account(0x11),
        });
        assert_slice_roundtrip(ExitPublicLaneValidator {
            lane_id: LaneId::SINGLE,
            validator: account(0x11),
            release_at_ms: 123_456,
        });
    }
    #[test]
    fn staking_registry_decodes_only_stable_ids() {
        let registry = crate::isi::InstructionRegistry::new()
            .register_with_id_slice::<RegisterPublicLaneValidator>(
                "iroha.instruction.v1::staking::RegisterPublicLaneValidator",
            )
            .register_with_id_slice::<RebindPublicLaneValidatorPeer>(
                "iroha.staking.rebind_public_lane_validator_peer",
            )
            .register_with_id_slice::<ActivatePublicLaneValidator>(
                "iroha.staking.activate_public_lane_validator",
            )
            .register_with_id_slice::<ExitPublicLaneValidator>(
                "iroha.staking.exit_public_lane_validator",
            );
        assert_registry_decodes(
            &registry,
            "iroha.instruction.v1::staking::RegisterPublicLaneValidator",
            RegisterPublicLaneValidator {
                lane_id: LaneId::SINGLE,
                validator: account(0x11),
                peer_id: peer(0x12),
                stake_account: account(0x13),
                initial_stake: Quantity::from(10_u64),
                metadata: Metadata::default(),
                monetary_plan: transfer_plan(account(0x13), Quantity::from(10_u64), false),
            },
        );
        assert_registry_decodes(
            &registry,
            "iroha.staking.rebind_public_lane_validator_peer",
            RebindPublicLaneValidatorPeer {
                lane_id: LaneId::SINGLE,
                validator: account(0x11),
                peer_id: peer(0x14),
                peer_signature: rebind_signature(),
            },
        );
        assert_registry_decodes(
            &registry,
            "iroha.staking.activate_public_lane_validator",
            ActivatePublicLaneValidator {
                lane_id: LaneId::SINGLE,
                validator: account(0x11),
            },
        );
        assert_registry_decodes(
            &registry,
            "iroha.staking.exit_public_lane_validator",
            ExitPublicLaneValidator {
                lane_id: LaneId::SINGLE,
                validator: account(0x11),
                release_at_ms: 123_456,
            },
        );
        for type_name in [
            std::any::type_name::<RegisterPublicLaneValidator>(),
            std::any::type_name::<RebindPublicLaneValidatorPeer>(),
            std::any::type_name::<ActivatePublicLaneValidator>(),
            std::any::type_name::<ExitPublicLaneValidator>(),
        ] {
            assert!(registry.decode(type_name, &[]).is_none());
        }
    }
    #[test]
    fn negative_numeric_payloads_cannot_decode_as_staking_instructions() {
        let mut forged_registration = ForgedRegisterPublicLaneValidator {
            lane_id: LaneId::SINGLE,
            validator: account(0x31),
            peer_id: peer(0x32),
            stake_account: account(0x33),
            initial_stake: Numeric::new(-1_i32, 0),
            metadata: Metadata::default(),
            monetary_plan: transfer_plan(account(0x33), Quantity::from(1_u64), false),
        };
        let encoded = norito::codec::Encode::encode(&forged_registration);
        assert!(
            RegisterPublicLaneValidator::decode_from_slice(&encoded).is_err(),
            "a negative signed payload must not decode as validator initial stake"
        );
        forged_registration.initial_stake = Numeric::from(1_u64);
        let positive = norito::codec::Encode::encode(&forged_registration);
        let (decoded, consumed) = RegisterPublicLaneValidator::decode_from_slice(&positive)
            .expect("same complete layout with a positive quantity decodes");
        assert_eq!(consumed, positive.len());
        assert_eq!(decoded.initial_stake, Quantity::from(1_u64));
        assert_eq!(decoded.monetary_plan, forged_registration.monetary_plan);
        let mut forged_bond = ForgedBondPublicLaneStake {
            lane_id: LaneId::SINGLE,
            validator: account(0x34),
            staker: account(0x35),
            amount: Numeric::new(-1_i32, 0),
            metadata: Metadata::default(),
            monetary_plan: transfer_plan(account(0x35), Quantity::from(1_u64), true),
        };
        let encoded = norito::codec::Encode::encode(&forged_bond);
        assert!(
            BondPublicLaneStake::decode(&mut encoded.as_slice()).is_err(),
            "a negative signed payload must not decode as bonded stake"
        );
        forged_bond.amount = Numeric::from(1_u64);
        let positive = norito::codec::Encode::encode(&forged_bond);
        let decoded = BondPublicLaneStake::decode(&mut positive.as_slice())
            .expect("same complete bond layout with a positive quantity decodes");
        assert_eq!(decoded.amount, Quantity::from(1_u64));
        assert_eq!(decoded.monetary_plan, forged_bond.monetary_plan);
    }
}
#[cfg(test)]
mod json_tests {
    use super::{
        ActivatePublicLaneValidator, PublicLanePeerBindingAuthorization,
        RebindPublicLaneValidatorPeer, RegisterPublicLaneValidator,
    };
    use crate::account::AccountId;
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair, SignatureOf};
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::metadata::Metadata;
    use iroha_model_base::peer::PeerId;
    use iroha_model_base::topology::LaneId;
    use iroha_primitives::numeric::Quantity;
    use norito::json::{
        Value,
        value::{from_value, to_value},
    };
    #[test]
    fn register_public_lane_validator_json_roundtrip() {
        let _domain: iroha_model_base::domain::DomainId =
            DomainId::try_new("wonderland", "universal").expect("domain id");
        let validator_key = KeyPair::try_from_seed(vec![0xA1; 32], Algorithm::Ed25519)
            .expect("derive checked staking JSON validator fixture keypair");
        let stake_key = KeyPair::try_from_seed(vec![0xA2; 32], Algorithm::Ed25519)
            .expect("derive checked staking JSON stake fixture keypair");
        let peer_key = KeyPair::try_from_seed(vec![0xA3; 32], Algorithm::Ed25519)
            .expect("derive checked staking JSON peer fixture keypair");
        let validator = AccountId::new(validator_key.public_key().clone());
        let peer_id = PeerId::new(peer_key.public_key().clone());
        let stake_account = AccountId::new(stake_key.public_key().clone());
        let definition = crate::asset::AssetDefinitionId::from_uuid_bytes([
            1, 2, 3, 4, 5, 6, 0x47, 8, 0x89, 10, 11, 12, 13, 14, 15, 16,
        ])
        .expect("fixture definition");
        let isi = RegisterPublicLaneValidator::new(
            LaneId::new(1),
            validator.clone(),
            peer_id,
            stake_account.clone(),
            Quantity::from(42u32),
            Metadata::default(),
            super::test_monetary_transfer_plan(
                crate::asset::AssetId::new(definition.clone(), stake_account),
                crate::asset::AssetId::new(definition, validator.clone()),
                Quantity::from(42_u32),
                crate::nexus::PublicLaneMonetaryPreconditionV1::Registration(
                    crate::nexus::PublicLaneMonetaryRegistrationV1 {
                        activation_height: 1,
                    },
                ),
            ),
        );
        let encoded = to_value(&isi).expect("encode RegisterPublicLaneValidator");
        let decoded: RegisterPublicLaneValidator =
            from_value(encoded).expect("decode RegisterPublicLaneValidator");
        assert_eq!(decoded, isi);
    }
    #[test]
    fn activate_public_lane_validator_json_roundtrip() {
        let _domain: iroha_model_base::domain::DomainId =
            DomainId::try_new("wonderland", "universal").expect("domain id");
        let validator_key = KeyPair::try_from_seed(vec![0xB1; 32], Algorithm::Ed25519)
            .expect("derive checked staking JSON active validator fixture keypair");
        let validator = AccountId::new(validator_key.public_key().clone());
        let isi = ActivatePublicLaneValidator::new(LaneId::new(2), validator);
        let encoded = to_value(&isi).expect("encode ActivatePublicLaneValidator");
        let decoded: ActivatePublicLaneValidator =
            from_value(encoded).expect("decode ActivatePublicLaneValidator");
        assert_eq!(decoded, isi);
    }
    #[test]
    fn rebind_public_lane_validator_peer_json_roundtrip() {
        let _domain: iroha_model_base::domain::DomainId =
            DomainId::try_new("wonderland", "universal").expect("domain id");
        let validator_key = KeyPair::try_from_seed(vec![0xC1; 32], Algorithm::Ed25519)
            .expect("derive checked staking JSON rebind validator fixture keypair");
        let peer_key = KeyPair::try_from_seed(vec![0xC2; 32], Algorithm::Ed25519)
            .expect("derive checked staking JSON rebind peer fixture keypair");
        let validator = AccountId::new(validator_key.public_key().clone());
        let peer_id = PeerId::new(peer_key.public_key().clone());
        let consent = PublicLanePeerBindingAuthorization::new(
            crate::NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
                b"staking-json-rebind",
            ))),
            LaneId::new(3),
            validator.clone(),
            peer_id.clone(),
            13,
            PeerId::new(validator_key.public_key().clone()),
        );
        let signature =
            SignatureOf::try_new(peer_key.private_key(), &consent).expect("rebind consent");
        let isi = RebindPublicLaneValidatorPeer::new(LaneId::new(3), validator, peer_id, signature);
        let encoded = to_value(&isi).expect("encode RebindPublicLaneValidatorPeer");
        let decoded: RebindPublicLaneValidatorPeer =
            from_value(encoded.clone()).expect("decode RebindPublicLaneValidatorPeer");
        assert_eq!(decoded, isi);
        let mut missing_consent = encoded;
        let Value::Object(ref mut fields) = missing_consent else {
            panic!("rebind JSON must be an object");
        };
        assert!(fields.remove("peer_signature").is_some());
        assert!(from_value::<RebindPublicLaneValidatorPeer>(missing_consent).is_err());
    }
}
