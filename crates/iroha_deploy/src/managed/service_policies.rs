//! Immutable generated network and provider policies; dispatch authorization is retained separately.
//! These exact public choices alone never authorize current native use or serving.

use super::native_operation::{encode, invalid};
use super::service_authority::ServiceAuthority;
use super::{ManagedCustodyEnrollmentInterval, Result};
use crate::localnet::service_authorities::{
    NetworkServiceAuthorityRole as NetworkRole, StreamTokenAuthorityRole as Role,
};
use iroha_crypto::Hash;
use iroha_data_model::{
    asset::AssetDefinitionId,
    sorafs::{
        capacity::ProviderId,
        pin_registry::{
            ProviderIngestCompletionAuthorityV1, ProviderIngestCompletionSignerPolicyV1,
        },
        reputation::{
            REPUTATION_JOURNAL_AUTHORITY_POLICY_VERSION_V1, ReputationJournalAuthorityPolicyV1,
            derive_stream_token_gateway_id_v1,
            stream_token_delivery::StreamTokenReputationDeliveryTemplateV1,
        },
        reserve::{RESERVE_AUTHORITY_POLICY_VERSION_V1, ReserveAuthorityPolicyV1, ReservePolicyV1},
        stream_token_gateway::{
            StreamTokenGatewayAdmissionQualificationV1, native::StreamTokenGatewayPolicyV1,
        },
    },
    transaction::{FeeChargeKind, FeeChargeLimit, FeePaymentIntent},
};
use iroha_primitives::numeric::{Quantity, XorQuantity};
use sorafs_manifest::signer::{
    custody::{SignerCustodyAuthorityV1, SignerCustodyBindingV1},
    custody_control::SignerCustodyPolicyV1,
    protocol::{SignerKeyAlgorithmV1, SignerPurposeBindingV1, SignerRoleV1},
};
use std::collections::BTreeSet;

const MAX_BYTES: usize = 384 * 1024;
const DAY_MS: u64 = 24 * 60 * 60 * 1_000;

#[derive(Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::service_policies::GeneratedNetworkPolicies")]
pub(super) struct GeneratedNetworkPolicies {
    pub runtime_fee_payment: FeePaymentIntent,
    pub reserve: ReserveAuthorityPolicyV1,
    pub reputation: ReputationJournalAuthorityPolicyV1,
}

#[derive(Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::service_policies::GeneratedProviderPolicies")]
pub(super) struct GeneratedProviderPolicies {
    pub provider_id: ProviderId,
    pub slot: u8,
    pub custody: SignerCustodyPolicyV1,
    pub provider_ingest: ProviderIngestCompletionAuthorityV1,
    pub gateway: StreamTokenGatewayPolicyV1,
    pub observer_authority: SignerCustodyAuthorityV1,
}
impl GeneratedProviderPolicies {
    /// Select one concrete initial enrollment under the separately retained authorization.
    /// This is public intent only; the custody owner still signs and verifies the native body.
    pub(super) fn initial_enrollment(
        &self,
        selected_at_unix_ms: u64,
        deadline_unix_ms: u64,
    ) -> Result<ManagedCustodyEnrollmentInterval> {
        let expires = selected_at_unix_ms
            .checked_add(self.custody.max_validity_ms)
            .ok_or_else(|| invalid("original custody interval overflow"))?
            .min(self.custody.active_until_unix_ms);
        if selected_at_unix_ms < self.custody.active_from_unix_ms
            || selected_at_unix_ms >= self.custody.active_until_unix_ms
            || deadline_unix_ms <= selected_at_unix_ms
            || deadline_unix_ms >= expires
            || deadline_unix_ms == u64::MAX
        {
            return Err(invalid(
                "original enrollment authorization lies outside original custody interval",
            ));
        }
        Ok(ManagedCustodyEnrollmentInterval {
            issued_at_unix_ms: selected_at_unix_ms,
            expires_at_unix_ms: expires,
            deadline_unix_ms,
        })
    }
}

/// One immutable original semantic selection, with no transaction UTC or replaceable I/O clock.
#[derive(Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::service_policies::GeneratedServicePolicies")]
pub(super) struct GeneratedServicePolicies {
    pub network: GeneratedNetworkPolicies,
    pub providers: [GeneratedProviderPolicies; 3],
}
impl GeneratedServicePolicies {
    pub(super) fn provider(&self, provider: ProviderId) -> Result<&GeneratedProviderPolicies> {
        self.providers
            .iter()
            .find(|selected| selected.provider_id == provider)
            .ok_or_else(|| invalid("provider is absent from original generated policy selection"))
    }
    /// Exact labels in native gateway-ID order for the one network reputation Set.
    pub(super) fn gateway_labels(&self) -> Vec<String> {
        let mut gateways: Vec<_> = self
            .providers
            .iter()
            .map(|p| {
                (
                    p.gateway.qualification.gateway_id,
                    p.gateway.compliance_gateway_id.clone(),
                )
            })
            .collect();
        gateways.sort_by_key(|(id, _)| *id);
        gateways.into_iter().map(|(_, label)| label).collect()
    }
    /// Derive only from the authenticated whole original profile, never today's UTC/deadline.
    pub(super) fn select(authority: &ServiceAuthority) -> Result<Self> {
        authority.validate_profile()?;
        let plans = authority.provider_plans()?;
        let reserve = ReserveAuthorityPolicyV1 {
            version: RESERVE_AUTHORITY_POLICY_VERSION_V1,
            revision: 1,
            predecessor_policy_digest: None,
            economics: ReservePolicyV1::default(),
            asset_definition: AssetDefinitionId::parse_address_literal(
                crate::genesis::profile::TAIRA_XOR_ASSET_DEFINITION_ID,
            )
            .map_err(|_| invalid("invalid generated reserve asset"))?,
            custody_account: authority.manifest.network.reserve_accounts.custody.clone(),
            treasury_account: authority.manifest.network.reserve_accounts.treasury.clone(),
            operations_authority: authority
                .network_role(NetworkRole::ReserveOperations)?
                .clone(),
            decision_authority: authority.config.account.clone(),
            grace_period_days: 7,
            default_after_days: 30,
            max_provider_debt: XorQuantity::try_from_micro(1_000_000_000)
                .map_err(std::io::Error::other)?,
            max_pending_movements_per_provider: 4,
            max_open_appeals_per_provider: 2,
        };
        let runtime_fee_payment = FeePaymentIntent::authority(
            vec![FeeChargeLimit::new(
                FeeChargeKind::Nexus,
                reserve.asset_definition.clone(),
                Quantity::from(1_u64),
            )],
            None,
        );
        let identity = |service: &str, administrator: &str| SignerCustodyAuthorityV1 {
            service_id: service.into(),
            administrator_id: administrator.into(),
            key_revision: 1,
            policy_revision: 1,
            policy_digest: [0; 32],
        };
        let mut providers = Vec::with_capacity(3);
        for (slot, plan) in plans.iter().enumerate() {
            if usize::from(plan.slot()) != slot || plan.peer_index() != slot {
                return Err(invalid(
                    "generated provider plans changed original slot order",
                ));
            }
            let inventory = authority.manifest.provider(plan.provider_id())?;
            let role = |role| -> Result<&iroha_data_model::account::AccountId> {
                Ok(&inventory.authority(role)?.account)
            };
            let key = |selected| {
                role(selected)?
                    .try_signatory()
                    .cloned()
                    .ok_or_else(|| invalid("generated service role is not a direct key"))
            };
            let material = plan.admission_material();
            let start = material
                .issued_at
                .checked_mul(1_000)
                .ok_or_else(|| invalid("original provider start overflows milliseconds"))?;
            let end = material
                .retention_epoch
                .checked_mul(1_000)
                .ok_or_else(|| invalid("original provider end overflows milliseconds"))?;
            let custody = SignerCustodyPolicyV1 {
                binding: SignerCustodyBindingV1 {
                    chain_id: authority.config.chain.to_string(),
                    network_id: *authority.config.network_id.as_bytes(),
                    runtime_handle: "software://managed/stream-token-runtime".into(),
                    key_handle: "software://managed/stream-token-key".into(),
                    service_id: "managed-stream-signer".into(),
                    administrator_id: "managed-stream-signing-custodian".into(),
                    role: SignerRoleV1::StreamToken,
                    purpose: SignerPurposeBindingV1::StreamToken {
                        provider_id: *plan.provider_id().as_bytes(),
                    },
                    algorithm: SignerKeyAlgorithmV1::Ed25519,
                    public_key: key(Role::TokenSigner)?,
                    key_revision: 1,
                    policy_revision: 1,
                    policy_digest: [0; 32],
                },
                attester_authority: identity(
                    "managed-custody-attester",
                    "managed-attestation-custodian",
                ),
                attester_public_key: key(Role::CustodyAttester)?,
                active_from_unix_ms: start,
                active_until_unix_ms: end,
                max_validity_ms: DAY_MS,
                max_anchor_age_ms: 300_000,
            };
            // Labels are scoped by the canonical native network identity, never selected by a peer.
            let compliance = authority.gateway_compliance_plan(plan.provider_id())?;
            let label = compliance.gateway_label();
            let gateway_id = derive_stream_token_gateway_id_v1(&authority.config.network_id, label)
                .map_err(|_| invalid("invalid generated gateway label"))?;
            let mut gateway = StreamTokenGatewayPolicyV1 {
                network_id: authority.config.network_id,
                compliance_gateway_id: label.into(),
                qualification: StreamTokenGatewayAdmissionQualificationV1 {
                    gateway_id,
                    revision: 1,
                    policy_digest: [0; 32],
                    max_pending: 64,
                    max_tracked_tokens: 128,
                    lease_ttl_ms: 30_000,
                },
                operators: BTreeSet::from([role(Role::GatewayOperator)?.clone()]),
                observers: BTreeSet::from([role(Role::GatewayObserver)?.clone()]),
                valid_from_unix_ms: start,
                valid_until_unix_ms: end,
                max_observation_age_ms: 30_000,
                admission_enabled: true,
            };
            gateway.qualification.policy_digest = gateway
                .calculate_policy_digest()
                .map_err(|_| invalid("invalid generated gateway policy"))?;
            providers.push(GeneratedProviderPolicies {
                provider_id: plan.provider_id(),
                slot: plan.slot(),
                custody,
                provider_ingest: ProviderIngestCompletionAuthorityV1::new(
                    role(Role::IssuerOperator)?.clone(),
                    role(Role::ProviderIngest)?.clone(),
                    ProviderIngestCompletionSignerPolicyV1 {
                        policy_id: [0; 32],
                        revision: 1,
                        predecessor_digest: None,
                        policy_digest: [0; 32],
                    },
                ),
                gateway,
                observer_authority: identity(
                    "managed-state-observer",
                    "managed-observation-custodian",
                ),
            });
        }
        let providers: [GeneratedProviderPolicies; 3] = providers
            .try_into()
            .map_err(|_| invalid("generated provider cardinality changed"))?;
        let mut allowed_gateways: Vec<_> = providers
            .iter()
            .map(|p| p.gateway.qualification.gateway_id)
            .collect();
        allowed_gateways.sort();
        let recorder = authority.network_role(NetworkRole::ReputationRecorder)?;
        let reputation = ReputationJournalAuthorityPolicyV1 {
            version: REPUTATION_JOURNAL_AUTHORITY_POLICY_VERSION_V1,
            revision: 1,
            predecessor_policy_digest: None,
            por_recorder_authority: recorder.clone(),
            dispute_recorder_authority: recorder.clone(),
            token_recorder_authority: recorder.clone(),
            stream_token_delivery: StreamTokenReputationDeliveryTemplateV1 {
                allowed_gateways,
                fee_payment: runtime_fee_payment.clone(),
                time_to_live_ms: 60_000,
                height_ttl: 128,
            },
            max_source_age_ms: 3_600_000,
        };
        let mut selected = Self {
            network: GeneratedNetworkPolicies {
                runtime_fee_payment,
                reserve,
                reputation,
            },
            providers,
        };
        // Five self-commitments per provider are still zero. Bind the complete network/provider
        // graph and exact original genesis, but no enrollment body, clock or dispatch deadline.
        let bytes = encode(&selected, MAX_BYTES)?;
        for provider in &mut selected.providers {
            let commitment = |purpose: &[u8]| {
                *Hash::new_from_chunks(&[
                    b"iroha:managed-service-policy:v1\0",
                    purpose,
                    authority.genesis.genesis.hash().as_ref(),
                    provider.provider_id.as_bytes(),
                    &bytes,
                ])
                .as_ref()
            };
            provider.custody.binding.policy_digest = commitment(b"stream-token-signer");
            provider.custody.attester_authority.policy_digest = commitment(b"custody-attester");
            provider.observer_authority.policy_digest = commitment(b"state-observer");
            provider.provider_ingest.signer_policy.policy_id =
                commitment(b"provider-ingest-policy-id");
            provider.provider_ingest.signer_policy.policy_digest =
                commitment(b"provider-ingest-policy");
            if !provider.provider_ingest.is_valid() {
                return Err(invalid("invalid generated provider ingest authority"));
            }
            provider
                .custody
                .validate()
                .map_err(|_| invalid("invalid generated custody policy"))?;
            provider
                .gateway
                .validate()
                .map_err(|_| invalid("invalid generated gateway policy"))?;
        }
        selected
            .network
            .reserve
            .validate()
            .map_err(|_| invalid("invalid generated reserve policy"))?;
        selected
            .network
            .reputation
            .validate()
            .map_err(|_| invalid("invalid generated recorder policy"))?;
        authority.validate_profile()?;
        Ok(selected)
    }
    /// Compare complete original semantic intent; decoded bytes grant no current authority.
    pub(super) fn validate(&self, authority: &ServiceAuthority) -> Result<()> {
        let bytes = encode(self, MAX_BYTES)?;
        if bytes != encode(&Self::select(authority)?, MAX_BYTES)? {
            return Err(invalid("original generated service policies changed"));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "service_policies/tests.rs"]
mod tests;
