//! Canonical effective Nexus policy for the future complete State root.
//!
//! The checked State view projects the configured baseline through the persisted
//! runtime and protected World catalog before selecting decision-policy fields.
//! This value retains the exact V1 policy bytes, including the configured
//! baseline lane catalog and loaded compliance/manifest identities. Runtime
//! progress and committed catalog additions have separate owners.
//! TODO: fund preimage allocation and bind this value to atomic State root
//! publication and authenticated recovery.

use super::lane_manifest_policy::StateAuthorityCaptureError;
use crate::state::{State, StateViewError, is_stable_state_view_generation};
use iroha_config::parameters::actual::{
    Nexus, NexusConsensusPolicyDigestError, nexus_consensus_policy_preimage_with_runtime_policies,
};
#[cfg(test)]
use iroha_crypto::Hash;
use norito::{Decode, Encode, NoritoSchema};

#[cfg(test)]
const NEXUS_POLICY_DOMAIN_V1: &[u8] = b"iroha:nexus:consensus-policy:v1\0";

/// Exact locally configured Nexus consensus policy, excluding dynamic runtime state.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:nexus:v1")]
pub(super) struct NexusStaticAuthorityV1 {
    version: u16,
    bare_policy_preimage: Vec<u8>,
}

impl NexusStaticAuthorityV1 {
    const VERSION: u16 = 1;

    /// Capture the exact source bytes used by the current policy digest.
    ///
    /// # Errors
    /// Rejects invalid static ratios or enabled compliance without its loaded
    /// policy identity. Complete root resource admission is a separate gate.
    pub(super) fn from_actual(
        nexus: &Nexus,
        compliance_policy_digest: Option<[u8; 32]>,
        lane_manifest_policy_digest: Option<[u8; 32]>,
    ) -> Result<Self, NexusConsensusPolicyDigestError> {
        Ok(Self {
            version: Self::VERSION,
            bare_policy_preimage: nexus_consensus_policy_preimage_with_runtime_policies(
                nexus,
                compliance_policy_digest,
                lane_manifest_policy_digest,
            )?,
        })
    }

    /// Recompute the existing consensus policy identity from this exact value.
    #[cfg(test)]
    fn policy_digest(&self) -> [u8; 32] {
        Hash::new_from_chunks(&[NEXUS_POLICY_DOMAIN_V1, &self.bare_policy_preimage]).into()
    }
}

/// Capture the actual effective Nexus authority from one stable State generation.
///
/// The State view validates canonical runtime ownership against the protected
/// World catalog and installed manifest baseline. The manifest and compliance
/// identities are checked again after encoding because those process-local
/// installation handles can be replaced outside a World MV transaction.
/// Physical contention retains its exact State view error; `None` retries a
/// concurrent policy installation without inventing a physical release source.
/// This does not publish a finalized State root or authorize snapshot recovery.
pub(super) fn canonical_preimage_once(
    state: &State,
) -> Result<Option<Vec<u8>>, StateAuthorityCaptureError> {
    let publication_release = state.view_publication_release();
    let generation = state.state_view_generation();
    if generation & 1 != 0 {
        return Err(StateViewError::Busy(publication_release).into());
    }
    let attempt = (|| -> Result<Option<Vec<u8>>, StateAuthorityCaptureError> {
        let installed = state.lane_manifests.read().clone();
        installed.validate_materialized_source_projection()?;
        let manifest_digest = installed.baseline_consensus_policy_digest();
        let compliance = state.lane_compliance_engine();
        let compliance_digest = compliance
            .as_deref()
            .map(crate::compliance::LaneComplianceEngine::consensus_policy_digest);
        let view = state.try_view_once()?;
        if view.lane_manifests.baseline_consensus_policy_digest() != manifest_digest {
            return Ok(None);
        }
        let authority = NexusStaticAuthorityV1::from_actual(
            &view.nexus,
            compliance_digest,
            Some(manifest_digest),
        )
        .map_err(|error| format!("effective Nexus policy is invalid: {error}"))?;
        let encoded = norito::encode_canonical(&authority)
            .map_err(|error| format!("effective Nexus policy cannot be encoded: {error}"))?;
        drop(view);
        let Some(current) = state
            .try_nexus_snapshot_once()
            .map_err(StateViewError::Runtime)?
        else {
            return Ok(None);
        };
        let current_authority =
            NexusStaticAuthorityV1::from_actual(&current, compliance_digest, Some(manifest_digest))
                .map_err(|error| format!("current Nexus policy is invalid: {error}"))?;
        let installed_now = state.lane_manifests.read().clone();
        installed_now.validate_materialized_source_projection()?;
        if authority != current_authority
            || installed_now.baseline_consensus_policy_digest() != manifest_digest
            || state
                .lane_compliance_engine()
                .as_deref()
                .map(crate::compliance::LaneComplianceEngine::consensus_policy_digest)
                != compliance_digest
        {
            return Ok(None);
        }
        Ok(Some(encoded))
    })();
    if !is_stable_state_view_generation(generation, state.state_view_generation()) {
        return Err(StateViewError::Busy(publication_release).into());
    }
    attempt
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        governance::manifest::LaneManifestRegistry, kura::Kura, query::store::LiveQueryStore,
        state::World,
    };
    use iroha_config::parameters::actual::nexus_consensus_policy_digest_with_runtime_policies;
    use iroha_data_model::nexus::{LaneCatalog, LaneConfig};
    use iroha_model_base::topology::LaneId;
    use std::{num::NonZeroU32, path::PathBuf, sync::Arc, time::Duration};

    fn materialized_state() -> State {
        let state = State::new_for_testing(
            World::new(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let nexus = state.nexus_snapshot();
        let manifests = Arc::new(LaneManifestRegistry::from_config(
            &nexus.lane_catalog,
            &nexus.governance,
            &nexus.registry,
        ));
        state
            .install_materialized_lane_manifests_for_catalog(
                &manifests,
                &nexus.lane_catalog,
                &nexus.governance,
            )
            .expect("install frozen manifest authority");
        state
    }

    fn authority(nexus: &Nexus) -> NexusStaticAuthorityV1 {
        NexusStaticAuthorityV1::from_actual(nexus, None, Some([0xA5; 32]))
            .expect("valid static Nexus policy")
    }

    #[test]
    fn static_nexus_policy_roundtrips_and_matches_existing_digest() {
        let policy = authority(&Nexus::default());
        assert_eq!(
            NexusStaticAuthorityV1::nominal_name(),
            "iroha:state:nexus:v1"
        );
        assert_eq!(
            policy.policy_digest(),
            nexus_consensus_policy_digest_with_runtime_policies(
                &Nexus::default(),
                None,
                Some([0xA5; 32])
            )
            .unwrap()
        );
        let encoded = norito::encode_canonical(&policy).expect("canonical State value");
        assert_eq!(
            norito::decode_canonical::<NexusStaticAuthorityV1>(&encoded)
                .expect("decode State value"),
            policy
        );
        let _ambient = norito::core::DecodeFlagsGuard::enter(0);
        assert_eq!(
            norito::encode_canonical(&policy).expect("ambient-independent value"),
            encoded
        );
    }

    #[test]
    fn static_nexus_policy_binds_baseline_fee_routing_and_loaded_sources() {
        let baseline = Nexus::default();
        let original = authority(&baseline);
        let mut changed = baseline.clone();
        changed.configured_lane_catalog = LaneCatalog::new(
            NonZeroU32::new(2).unwrap(),
            vec![
                LaneConfig::default(),
                LaneConfig {
                    id: LaneId::new(1),
                    alias: "second".into(),
                    ..LaneConfig::default()
                },
            ],
        )
        .unwrap();
        assert_ne!(authority(&changed), original, "configured lane baseline");
        let mut changed = baseline.clone();
        changed.fees.per_byte_fee = 123_456_u32.into();
        assert_ne!(authority(&changed), original, "fee policy");
        let mut changed = baseline.clone();
        changed.routing_policy.default_lane = LaneId::new(1);
        assert_ne!(authority(&changed), original, "routing policy");
        let mut changed = baseline.clone();
        changed.atomic_private_settlement.activation_height = Some(10);
        assert_ne!(authority(&changed), original, "atomic settlement policy");
        let changed = NexusStaticAuthorityV1::from_actual(&baseline, None, Some([0xA6; 32]))
            .expect("changed manifest policy identity");
        assert_ne!(changed, original, "loaded manifest authority");
        let mut compliance = baseline;
        compliance.compliance.enabled = true;
        let left =
            NexusStaticAuthorityV1::from_actual(&compliance, Some([0x11; 32]), Some([0xA5; 32]))
                .expect("bound compliance policy");
        let right =
            NexusStaticAuthorityV1::from_actual(&compliance, Some([0x12; 32]), Some([0xA5; 32]))
                .expect("changed compliance policy");
        assert_ne!(left, right, "loaded compliance authority");
    }

    #[test]
    fn static_nexus_policy_excludes_runtime_progress_and_local_paths() {
        let baseline = Nexus::default();
        let original = authority(&baseline);
        let mut changed = baseline.clone();
        changed.lane_catalog = LaneCatalog::new(
            NonZeroU32::new(2).unwrap(),
            vec![
                LaneConfig::default(),
                LaneConfig {
                    id: LaneId::new(1),
                    alias: "runtime".into(),
                    ..LaneConfig::default()
                },
            ],
        )
        .unwrap();
        changed.autoscale.last_transition_height = 17;
        changed.registry.manifest_directory = Some(PathBuf::from("/node/a/manifests"));
        changed.registry.poll_interval = Duration::from_secs(9);
        changed.storage.budget_enforce_interval_blocks = 27;
        assert_eq!(authority(&changed), original);
    }

    #[test]
    fn static_nexus_policy_rejects_invalid_ratio_and_missing_compliance_identity() {
        let mut nexus = Nexus::default();
        nexus.autoscale.scale_out_latency_ratio = f64::NAN;
        assert!(NexusStaticAuthorityV1::from_actual(&nexus, None, None).is_err());
        let mut nexus = Nexus::default();
        nexus.compliance.enabled = true;
        assert_eq!(
            NexusStaticAuthorityV1::from_actual(&nexus, None, None),
            Err(NexusConsensusPolicyDigestError::MissingCompliancePolicyDigest)
        );
    }

    #[test]
    fn actual_effective_nexus_authority_captures_fee_policy_and_loaded_manifest() {
        let state = materialized_state();
        let digest = state
            .lane_manifests
            .read()
            .baseline_consensus_policy_digest();
        let expected =
            NexusStaticAuthorityV1::from_actual(&state.nexus_snapshot(), None, Some(digest))
                .unwrap();
        let encoded = canonical_preimage_once(&state)
            .expect("valid State authority")
            .expect("stable generation");
        assert_eq!(
            norito::decode_canonical::<NexusStaticAuthorityV1>(&encoded).unwrap(),
            expected
        );
        state.nexus.write().fees.base_fee = 123_u32.into();
        let changed = canonical_preimage_once(&state)
            .expect("updated State authority")
            .expect("stable generation");
        assert_eq!(changed, encoded, "local cache is not monetary authority");
        let mut policy = state.nexus_snapshot().fees;
        policy.base_fee = 123_u32.into();
        let mut parameters = state.world.parameters.block();
        parameters
            .set_parameter(iroha_data_model::parameter::Parameter::Custom(
                policy.into_custom_parameter().unwrap(),
            ))
            .unwrap();
        parameters.commit();
        let committed = canonical_preimage_once(&state).unwrap().unwrap();
        assert_ne!(
            committed, encoded,
            "actual committed monetary terms change authority"
        );
    }

    #[test]
    fn actual_nexus_capture_rejects_unowned_runtime_and_incomplete_sources() {
        let state = materialized_state();
        state.nexus.write().configured_dataspace_catalog =
            iroha_data_model::nexus::DataSpaceCatalog::new(Vec::new()).unwrap();
        let error = canonical_preimage_once(&state).unwrap_err();
        assert!(
            matches!(
                error,
                StateAuthorityCaptureError::View(StateViewError::Runtime(_))
            ),
            "{error}"
        );

        let state = materialized_state();
        state.install_lane_manifests_for_testing(&Arc::new(LaneManifestRegistry::from_statuses(
            std::collections::BTreeMap::default(),
        )));
        let error = canonical_preimage_once(&state).unwrap_err();
        assert!(
            error.to_string().contains("materialized frozen source"),
            "{error}"
        );

        let state = materialized_state();
        state.nexus.write().compliance.enabled = true;
        let error = canonical_preimage_once(&state).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("effective Nexus policy is invalid"),
            "{error}"
        );
    }
}
