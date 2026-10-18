//! Exact first-release State governance policy, excluding diagnostic switches.
//!
//! Governance changes transaction admission, public reward and SoraFS policy,
//! and the Parliament schedule. Its actual-layer configuration has runtime-only
//! representation; this typed projection gives each consensus field a stable
//! Norito identity. Telemetry and debug tracing do not enter the State root.

use std::collections::BTreeMap;

use iroha_config::parameters::actual::{
    Governance, RuntimeUpgradeProvenanceMode, SorafsPinApprovalSigner,
};
use iroha_crypto::{Hash, PublicKey};
use iroha_data_model::{
    account::AccountId,
    asset::AssetDefinitionId,
    nexus::UniversalAccountId,
    sorafs::{capacity::ProviderId, pin_registry::StorageClass, pricing::PricingScheduleRecord},
};
use iroha_primitives::numeric::Quantity;
use norito::{Decode, Encode, NoritoSchema};

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:governance-vk-ref:v1")]
struct VerifyingKeyRefV1 {
    backend: String,
    name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:runtime-upgrade-provenance:v1")]
struct RuntimeUpgradeProvenanceV1 {
    mode: u8,
    require_sbom: bool,
    require_slsa: bool,
    trusted_signers: Vec<PublicKey>,
    signature_threshold: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:viral-incentives:v1")]
struct ViralIncentivesV1 {
    incentive_pool_account: AccountId,
    escrow_account: AccountId,
    reward_asset_definition_id: AssetDefinitionId,
    follow_reward_amount: Quantity,
    sender_bonus_amount: Quantity,
    max_daily_claims_per_uaid: u32,
    max_claims_per_binding: u32,
    daily_budget: Quantity,
    halt: bool,
    deny_uaids: Vec<UniversalAccountId>,
    deny_binding_digests: Vec<Hash>,
    promo_starts_at_ms: Option<u64>,
    promo_ends_at_ms: Option<u64>,
    campaign_cap: Quantity,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:sorafs-pin-approval-signer:v1")]
struct SorafsPinApprovalSignerV1 {
    signer_id: String,
    public_key: PublicKey,
    valid_from_block_height: u64,
    revoked_at_block_height: Option<u64>,
}

impl From<&SorafsPinApprovalSigner> for SorafsPinApprovalSignerV1 {
    fn from(signer: &SorafsPinApprovalSigner) -> Self {
        Self {
            signer_id: signer.signer_id.clone(),
            public_key: signer.public_key.clone(),
            valid_from_block_height: signer.valid_from_block_height,
            revoked_at_block_height: signer.revoked_at_block_height,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:sorafs-pin-policy:v1")]
struct SorafsPinPolicyV1 {
    min_replicas_floor: u16,
    max_replicas_ceiling: Option<u16>,
    max_retention_epoch: Option<u64>,
    allowed_storage_classes: Option<Vec<StorageClass>>,
    require_council_signatures: bool,
    approval_quorum: u16,
    approval_signers: Vec<SorafsPinApprovalSignerV1>,
    max_global_manifests: u64,
    max_global_bytes: u64,
    max_manifests_per_authority: u64,
    max_bytes_per_authority: u64,
    max_lineage_depth: u32,
    max_successor_fanout: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:sorafs-penalty-policy:v1")]
struct SorafsPenaltyPolicyV1 {
    utilisation_floor_bps: u16,
    uptime_floor_bps: u16,
    por_success_floor_bps: u16,
    strike_threshold: u32,
    penalty_bond_bps: u16,
    cooldown_windows: u32,
    max_pdp_failures: u32,
    max_potr_breaches: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:sorafs-telemetry-policy:v1")]
struct SorafsTelemetryPolicyV1 {
    require_submitter: bool,
    require_nonce: bool,
    max_window_gap_secs: u64,
    max_window_gap_nanos: u32,
    reject_zero_capacity: bool,
    submitters: Vec<AccountId>,
    per_provider_submitters: BTreeMap<ProviderId, Vec<AccountId>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:parliament-timed-ovn:v1")]
struct ParliamentTimedOvnV1 {
    registration_phase_blocks: u64,
    survivor_freeze_phase_blocks: u64,
    commitment_phase_blocks: u64,
    release_delay_blocks: u64,
    opening_phase_blocks: u64,
    max_ballot_retries: u32,
    max_corpus_entries: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:parliament-tle-key-lifecycle:v1")]
struct ParliamentTleKeyLifecycleV1 {
    session_lifetime_blocks: u64,
    max_fresh_ballots_per_session: u32,
}

/// Consensus-governed values in the active State policy.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:governance:v1")]
pub(super) struct GovernanceAuthorityV1 {
    vk_ballot: Option<VerifyingKeyRefV1>,
    vk_tally: Option<VerifyingKeyRefV1>,
    voting_asset_id: AssetDefinitionId,
    citizenship_asset_id: AssetDefinitionId,
    citizenship_bond_amount: Quantity,
    citizenship_escrow_account: AccountId,
    min_bond_amount: Quantity,
    bond_escrow_account: AccountId,
    slash_receiver_account: AccountId,
    slash_double_vote_bps: u16,
    slash_invalid_proof_bps: u16,
    slash_ineligible_proof_bps: u16,
    alias_teu_minimum: Quantity,
    jdg_signature_schemes: Vec<u16>,
    runtime_upgrade_provenance: RuntimeUpgradeProvenanceV1,
    viral_incentives: ViralIncentivesV1,
    sorafs_pin_policy: SorafsPinPolicyV1,
    sorafs_pin_fee_asset_id: AssetDefinitionId,
    sorafs_pin_fee_treasury_account: AccountId,
    sorafs_pricing: PricingScheduleRecord,
    sorafs_penalty: SorafsPenaltyPolicyV1,
    sorafs_telemetry: SorafsTelemetryPolicyV1,
    sorafs_provider_owners: BTreeMap<ProviderId, AccountId>,
    conviction_step_blocks: u64,
    max_conviction: u64,
    min_enactment_delay: u64,
    window_span: u64,
    max_active_referenda: u32,
    max_lock_owners_per_referendum: u32,
    plain_voting_enabled: bool,
    approval_threshold_q_num: u64,
    approval_threshold_q_den: u64,
    min_turnout: u128,
    parliament_alternate_size: u64,
    parliament_sortition_pulse_delay_blocks: u64,
    parliament_invitation_phase_blocks: u64,
    parliament_public_finding_phase_blocks: u64,
    parliament_timed_ovn: ParliamentTimedOvnV1,
    parliament_tle_key_lifecycle: ParliamentTleKeyLifecycleV1,
    parliament_tle_partial_release_signer_provider_handle: Option<String>,
    parliament_tle_partial_release_signer_provider_revision: Option<u64>,
    parliament_tle_partial_release_signer_provider_policy_digest: Option<[u8; 32]>,
    rules_committee_size: u64,
    agenda_council_size: u64,
    interest_panel_size: u64,
    review_panel_size: u64,
    coordination_council_size: u64,
    policy_jury_size: u64,
    confirmation_jury_size: u64,
    oversight_committee_size: u64,
    mpc_committee_size: u64,
    fma_committee_size: u64,
}

impl GovernanceAuthorityV1 {
    /// Project every consensus-governed value without ambient configuration.
    pub(super) fn from_actual(config: &Governance) -> Self {
        let vk = |key: &iroha_config::parameters::actual::VerifyingKeyRef| VerifyingKeyRefV1 {
            backend: key.backend.clone(),
            name: key.name.clone(),
        };
        let provenance = &config.runtime_upgrade_provenance;
        let viral = &config.viral_incentives;
        let pin = &config.sorafs_pin_policy;
        let penalty = &config.sorafs_penalty;
        let telemetry = &config.sorafs_telemetry;
        let timed = config.parliament_timed_ovn;
        let tle = config.parliament_tle_key_lifecycle;
        Self {
            vk_ballot: config.vk_ballot.as_ref().map(vk),
            vk_tally: config.vk_tally.as_ref().map(vk),
            voting_asset_id: config.voting_asset_id.clone(),
            citizenship_asset_id: config.citizenship_asset_id.clone(),
            citizenship_bond_amount: config.citizenship_bond_amount.clone(),
            citizenship_escrow_account: config.citizenship_escrow_account.clone(),
            min_bond_amount: config.min_bond_amount.clone(),
            bond_escrow_account: config.bond_escrow_account.clone(),
            slash_receiver_account: config.slash_receiver_account.clone(),
            slash_double_vote_bps: config.slash_double_vote_bps,
            slash_invalid_proof_bps: config.slash_invalid_proof_bps,
            slash_ineligible_proof_bps: config.slash_ineligible_proof_bps,
            alias_teu_minimum: config.alias_teu_minimum.clone(),
            jdg_signature_schemes: config
                .jdg_signature_schemes
                .iter()
                .map(|scheme| scheme.scheme_id())
                .collect(),
            runtime_upgrade_provenance: RuntimeUpgradeProvenanceV1 {
                mode: match provenance.mode {
                    RuntimeUpgradeProvenanceMode::Optional => 0,
                    RuntimeUpgradeProvenanceMode::Required => 1,
                },
                require_sbom: provenance.require_sbom,
                require_slsa: provenance.require_slsa,
                trusted_signers: provenance.trusted_signers.iter().cloned().collect(),
                signature_threshold: u64::try_from(provenance.signature_threshold)
                    .expect("supported usize fits u64"),
            },
            viral_incentives: ViralIncentivesV1 {
                incentive_pool_account: viral.incentive_pool_account.clone(),
                escrow_account: viral.escrow_account.clone(),
                reward_asset_definition_id: viral.reward_asset_definition_id.clone(),
                follow_reward_amount: viral.follow_reward_amount.clone(),
                sender_bonus_amount: viral.sender_bonus_amount.clone(),
                max_daily_claims_per_uaid: viral.max_daily_claims_per_uaid,
                max_claims_per_binding: viral.max_claims_per_binding,
                daily_budget: viral.daily_budget.clone(),
                halt: viral.halt,
                deny_uaids: viral.deny_uaids.clone(),
                deny_binding_digests: viral.deny_binding_digests.clone(),
                promo_starts_at_ms: viral.promo_starts_at_ms,
                promo_ends_at_ms: viral.promo_ends_at_ms,
                campaign_cap: viral.campaign_cap.clone(),
            },
            sorafs_pin_policy: SorafsPinPolicyV1 {
                min_replicas_floor: pin.min_replicas_floor,
                max_replicas_ceiling: pin.max_replicas_ceiling,
                max_retention_epoch: pin.max_retention_epoch,
                allowed_storage_classes: pin
                    .allowed_storage_classes
                    .as_ref()
                    .map(|classes| classes.iter().cloned().collect()),
                require_council_signatures: pin.require_council_signatures,
                approval_quorum: pin.approval_quorum,
                approval_signers: pin.approval_signers.iter().map(Into::into).collect(),
                max_global_manifests: pin.max_global_manifests,
                max_global_bytes: pin.max_global_bytes,
                max_manifests_per_authority: pin.max_manifests_per_authority,
                max_bytes_per_authority: pin.max_bytes_per_authority,
                max_lineage_depth: pin.max_lineage_depth,
                max_successor_fanout: pin.max_successor_fanout,
            },
            sorafs_pin_fee_asset_id: config.sorafs_pin_fee_asset_id.clone(),
            sorafs_pin_fee_treasury_account: config.sorafs_pin_fee_treasury_account.clone(),
            sorafs_pricing: config.sorafs_pricing.clone(),
            sorafs_penalty: SorafsPenaltyPolicyV1 {
                utilisation_floor_bps: penalty.utilisation_floor_bps,
                uptime_floor_bps: penalty.uptime_floor_bps,
                por_success_floor_bps: penalty.por_success_floor_bps,
                strike_threshold: penalty.strike_threshold,
                penalty_bond_bps: penalty.penalty_bond_bps,
                cooldown_windows: penalty.cooldown_windows,
                max_pdp_failures: penalty.max_pdp_failures,
                max_potr_breaches: penalty.max_potr_breaches,
            },
            sorafs_telemetry: SorafsTelemetryPolicyV1 {
                require_submitter: telemetry.require_submitter,
                require_nonce: telemetry.require_nonce,
                max_window_gap_secs: telemetry.max_window_gap.as_secs(),
                max_window_gap_nanos: telemetry.max_window_gap.subsec_nanos(),
                reject_zero_capacity: telemetry.reject_zero_capacity,
                submitters: telemetry.submitters.clone(),
                per_provider_submitters: telemetry.per_provider_submitters.clone(),
            },
            sorafs_provider_owners: config.sorafs_provider_owners.clone(),
            conviction_step_blocks: config.conviction_step_blocks,
            max_conviction: config.max_conviction,
            min_enactment_delay: config.min_enactment_delay,
            window_span: config.window_span,
            max_active_referenda: config.max_active_referenda.get(),
            max_lock_owners_per_referendum: config.max_lock_owners_per_referendum.get(),
            plain_voting_enabled: config.plain_voting_enabled,
            approval_threshold_q_num: config.approval_threshold_q_num,
            approval_threshold_q_den: config.approval_threshold_q_den,
            min_turnout: config.min_turnout,
            parliament_alternate_size: u64::try_from(config.parliament_alternate_size)
                .expect("supported usize fits u64"),
            parliament_sortition_pulse_delay_blocks: config.parliament_sortition_pulse_delay_blocks,
            parliament_invitation_phase_blocks: config.parliament_invitation_phase_blocks,
            parliament_public_finding_phase_blocks: config.parliament_public_finding_phase_blocks,
            parliament_timed_ovn: ParliamentTimedOvnV1 {
                registration_phase_blocks: timed.registration_phase_blocks,
                survivor_freeze_phase_blocks: timed.survivor_freeze_phase_blocks,
                commitment_phase_blocks: timed.commitment_phase_blocks,
                release_delay_blocks: timed.release_delay_blocks,
                opening_phase_blocks: timed.opening_phase_blocks,
                max_ballot_retries: timed.max_ballot_retries,
                max_corpus_entries: timed.max_corpus_entries,
            },
            parliament_tle_key_lifecycle: ParliamentTleKeyLifecycleV1 {
                session_lifetime_blocks: tle.session_lifetime_blocks,
                max_fresh_ballots_per_session: tle.max_fresh_ballots_per_session,
            },
            parliament_tle_partial_release_signer_provider_handle: config
                .parliament_tle_partial_release_signer_provider_handle
                .clone(),
            parliament_tle_partial_release_signer_provider_revision: config
                .parliament_tle_partial_release_signer_provider_revision,
            parliament_tle_partial_release_signer_provider_policy_digest: config
                .parliament_tle_partial_release_signer_provider_policy_digest,
            rules_committee_size: u64::try_from(config.rules_committee_size)
                .expect("supported usize fits u64"),
            agenda_council_size: u64::try_from(config.agenda_council_size)
                .expect("supported usize fits u64"),
            interest_panel_size: u64::try_from(config.interest_panel_size)
                .expect("supported usize fits u64"),
            review_panel_size: u64::try_from(config.review_panel_size)
                .expect("supported usize fits u64"),
            coordination_council_size: u64::try_from(config.coordination_council_size)
                .expect("supported usize fits u64"),
            policy_jury_size: u64::try_from(config.policy_jury_size)
                .expect("supported usize fits u64"),
            confirmation_jury_size: u64::try_from(config.confirmation_jury_size)
                .expect("supported usize fits u64"),
            oversight_committee_size: u64::try_from(config.oversight_committee_size)
                .expect("supported usize fits u64"),
            mpc_committee_size: u64::try_from(config.mpc_committee_size)
                .expect("supported usize fits u64"),
            fma_committee_size: u64::try_from(config.fma_committee_size)
                .expect("supported usize fits u64"),
        }
    }
}

/// Stream every original governance term, preserving sequence and map order.
pub(super) fn borrowed(config: &Governance) -> impl norito::SerializePayload + '_ {
    use super::policy_borrowed::{Ref, Seq, record};
    fn vk(
        key: &iroha_config::parameters::actual::VerifyingKeyRef,
    ) -> impl norito::SerializePayload + '_ {
        record!(Ref(&key.backend), Ref(&key.name))
    }
    fn pin_signer(signer: &SorafsPinApprovalSigner) -> impl norito::SerializePayload + '_ {
        record!(
            Ref(&signer.signer_id),
            Ref(&signer.public_key),
            signer.valid_from_block_height,
            signer.revoked_at_block_height
        )
    }

    let provenance = &config.runtime_upgrade_provenance;
    let viral = &config.viral_incentives;
    let pin = &config.sorafs_pin_policy;
    let penalty = &config.sorafs_penalty;
    let telemetry = &config.sorafs_telemetry;
    let timed = config.parliament_timed_ovn;
    let tle = config.parliament_tle_key_lifecycle;
    record!(
        config.vk_ballot.as_ref().map(vk),
        config.vk_tally.as_ref().map(vk),
        Ref(&config.voting_asset_id),
        Ref(&config.citizenship_asset_id),
        Ref(&config.citizenship_bond_amount),
        Ref(&config.citizenship_escrow_account),
        Ref(&config.min_bond_amount),
        Ref(&config.bond_escrow_account),
        Ref(&config.slash_receiver_account),
        config.slash_double_vote_bps,
        config.slash_invalid_proof_bps,
        config.slash_ineligible_proof_bps,
        Ref(&config.alias_teu_minimum),
        Seq(config
            .jdg_signature_schemes
            .iter()
            .map(|scheme| scheme.scheme_id())),
        record!(
            match provenance.mode {
                RuntimeUpgradeProvenanceMode::Optional => 0_u8,
                RuntimeUpgradeProvenanceMode::Required => 1_u8,
            },
            provenance.require_sbom,
            provenance.require_slsa,
            Seq(provenance.trusted_signers.iter().map(Ref)),
            u64::try_from(provenance.signature_threshold).expect("supported usize fits u64")
        ),
        record!(
            Ref(&viral.incentive_pool_account),
            Ref(&viral.escrow_account),
            Ref(&viral.reward_asset_definition_id),
            Ref(&viral.follow_reward_amount),
            Ref(&viral.sender_bonus_amount),
            viral.max_daily_claims_per_uaid,
            viral.max_claims_per_binding,
            Ref(&viral.daily_budget),
            viral.halt,
            Ref(&viral.deny_uaids),
            Ref(&viral.deny_binding_digests),
            viral.promo_starts_at_ms,
            viral.promo_ends_at_ms,
            Ref(&viral.campaign_cap)
        ),
        record!(
            pin.min_replicas_floor,
            pin.max_replicas_ceiling,
            pin.max_retention_epoch,
            pin.allowed_storage_classes
                .as_ref()
                .map(|classes| Seq(classes.iter().map(Ref))),
            pin.require_council_signatures,
            pin.approval_quorum,
            Seq(pin.approval_signers.iter().map(pin_signer)),
            pin.max_global_manifests,
            pin.max_global_bytes,
            pin.max_manifests_per_authority,
            pin.max_bytes_per_authority,
            pin.max_lineage_depth,
            pin.max_successor_fanout
        ),
        Ref(&config.sorafs_pin_fee_asset_id),
        Ref(&config.sorafs_pin_fee_treasury_account),
        Ref(&config.sorafs_pricing),
        record!(
            penalty.utilisation_floor_bps,
            penalty.uptime_floor_bps,
            penalty.por_success_floor_bps,
            penalty.strike_threshold,
            penalty.penalty_bond_bps,
            penalty.cooldown_windows,
            penalty.max_pdp_failures,
            penalty.max_potr_breaches
        ),
        record!(
            telemetry.require_submitter,
            telemetry.require_nonce,
            telemetry.max_window_gap.as_secs(),
            telemetry.max_window_gap.subsec_nanos(),
            telemetry.reject_zero_capacity,
            Ref(&telemetry.submitters),
            Ref(&telemetry.per_provider_submitters)
        ),
        Ref(&config.sorafs_provider_owners),
        config.conviction_step_blocks,
        config.max_conviction,
        config.min_enactment_delay,
        config.window_span,
        config.max_active_referenda.get(),
        config.max_lock_owners_per_referendum.get(),
        config.plain_voting_enabled,
        config.approval_threshold_q_num,
        config.approval_threshold_q_den,
        config.min_turnout,
        u64::try_from(config.parliament_alternate_size).expect("supported usize fits u64"),
        config.parliament_sortition_pulse_delay_blocks,
        config.parliament_invitation_phase_blocks,
        config.parliament_public_finding_phase_blocks,
        record!(
            timed.registration_phase_blocks,
            timed.survivor_freeze_phase_blocks,
            timed.commitment_phase_blocks,
            timed.release_delay_blocks,
            timed.opening_phase_blocks,
            timed.max_ballot_retries,
            timed.max_corpus_entries
        ),
        record!(
            tle.session_lifetime_blocks,
            tle.max_fresh_ballots_per_session
        ),
        Ref(&config.parliament_tle_partial_release_signer_provider_handle),
        config.parliament_tle_partial_release_signer_provider_revision,
        config.parliament_tle_partial_release_signer_provider_policy_digest,
        u64::try_from(config.rules_committee_size).expect("supported usize fits u64"),
        u64::try_from(config.agenda_council_size).expect("supported usize fits u64"),
        u64::try_from(config.interest_panel_size).expect("supported usize fits u64"),
        u64::try_from(config.review_panel_size).expect("supported usize fits u64"),
        u64::try_from(config.coordination_council_size).expect("supported usize fits u64"),
        u64::try_from(config.policy_jury_size).expect("supported usize fits u64"),
        u64::try_from(config.confirmation_jury_size).expect("supported usize fits u64"),
        u64::try_from(config.oversight_committee_size).expect("supported usize fits u64"),
        u64::try_from(config.mpc_committee_size).expect("supported usize fits u64"),
        u64::try_from(config.fma_committee_size).expect("supported usize fits u64")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};

    fn frame(config: &Governance) -> Vec<u8> {
        super::super::policy_borrowed::assert_same_payload(
            &borrowed(config),
            &GovernanceAuthorityV1::from_actual(config),
        );
        norito::encode_canonical(&GovernanceAuthorityV1::from_actual(config)).unwrap()
    }

    #[test]
    fn governance_authority_roundtrips_with_explicit_v1_identity() {
        let projected = GovernanceAuthorityV1::from_actual(&Governance::default());
        assert_eq!(
            GovernanceAuthorityV1::nominal_name(),
            "iroha:state:governance:v1"
        );
        let encoded = norito::encode_canonical(&projected).unwrap();
        assert_eq!(
            norito::decode_canonical::<GovernanceAuthorityV1>(&encoded).unwrap(),
            projected
        );
        let _ambient = norito::core::DecodeFlagsGuard::enter(0);
        assert_eq!(norito::encode_canonical(&projected).unwrap(), encoded);
    }

    #[test]
    fn governed_admission_reward_storage_and_parliament_fields_change_projection() {
        let baseline = Governance::default();
        let encoded = frame(&baseline);
        let mut changed = baseline.clone();
        changed.slash_double_vote_bps += 1;
        assert_ne!(frame(&changed), encoded);
        let mut changed = baseline.clone();
        changed.runtime_upgrade_provenance.require_sbom =
            !changed.runtime_upgrade_provenance.require_sbom;
        assert_ne!(frame(&changed), encoded);
        let mut changed = baseline.clone();
        changed.viral_incentives.halt = !changed.viral_incentives.halt;
        assert_ne!(frame(&changed), encoded);
        let mut changed = baseline.clone();
        changed.sorafs_pin_policy.min_replicas_floor += 1;
        assert_ne!(frame(&changed), encoded);
        let mut changed = baseline.clone();
        changed
            .sorafs_pin_policy
            .approval_signers
            .push(SorafsPinApprovalSigner {
                signer_id: "governance-projection-fixture".to_owned(),
                public_key: KeyPair::from_seed(
                    b"governance-projection-signer".to_vec(),
                    Algorithm::Ed25519,
                )
                .public_key()
                .clone(),
                valid_from_block_height: 3,
                revoked_at_block_height: Some(30),
            });
        let projected = GovernanceAuthorityV1::from_actual(&changed);
        assert_eq!(
            projected.sorafs_pin_policy.approval_signers[0].valid_from_block_height,
            3
        );
        assert_eq!(
            projected.sorafs_pin_policy.approval_signers[0].revoked_at_block_height,
            Some(30)
        );
        assert_ne!(frame(&changed), encoded);
        let mut changed = baseline.clone();
        changed.sorafs_telemetry.require_nonce = !changed.sorafs_telemetry.require_nonce;
        assert_ne!(frame(&changed), encoded);
        let mut changed = baseline.clone();
        changed.parliament_timed_ovn.release_delay_blocks += 1;
        assert_ne!(frame(&changed), encoded);
        let mut changed = baseline.clone();
        changed.parliament_tle_key_lifecycle.session_lifetime_blocks += 1;
        assert_ne!(frame(&changed), encoded);
    }

    #[test]
    fn diagnostic_governance_switches_are_not_consensus_authority() {
        let baseline = Governance::default();
        let mut changed = baseline.clone();
        changed.alias_frontier_telemetry = !changed.alias_frontier_telemetry;
        changed.debug_trace_pipeline = !changed.debug_trace_pipeline;
        assert_eq!(frame(&changed), frame(&baseline));
    }
}
