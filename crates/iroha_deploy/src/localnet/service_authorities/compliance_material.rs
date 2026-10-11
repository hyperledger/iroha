//! Original generated compliance trust and private signing material; no serving authority.
//!
//! Signed genesis commits the bounded network-independent template. The opaque retained owner
//! binds its actual genesis-derived network after validation, avoiding a genesis-hash cycle.
use super::*;
use iroha_data_model::{
    block::SignedBlock, role::RoleId, sorafs::reputation::derive_stream_token_gateway_id_v1,
};
use sorafs_manifest::gateway_compliance::{
    GatewayComplianceTrustPolicyV1, GatewayComplianceTrustedSignerV1,
    gateway_compliance_feed_transport_policy_digest,
};

mod publication;

const OPERATOR_ROLE: &str = "sorafs_gateway_compliance_operator";
fn gateway_label(slot: u8) -> String {
    format!("managed-provider-gateway-{slot}")
}
const PLAN_MAX_BYTES: usize = 16 * 1024;
const PLAN_LIMITS: norito::DecodeLimits = norito::DecodeLimits::new(
    PLAN_MAX_BYTES,
    PLAN_MAX_BYTES,
    PLAN_MAX_BYTES * 2,
    256 * 1024,
    32,
);
const CATALOG_KEYS: [&str; 3] = [
    "compliance-catalog-0.key",
    "compliance-catalog-1.key",
    "compliance-catalog-2.key",
];
const ACK_KEYS: [&str; 1] = ["compliance-gateway.key"];
const CATALOG_IDS: [&str; 3] = [
    "managed-compliance-catalog-0",
    "managed-compliance-catalog-1",
    "managed-compliance-catalog-2",
];

pub(super) fn filenames() -> impl Iterator<Item = &'static str> {
    CATALOG_KEYS.into_iter().chain(ACK_KEYS)
}

#[derive(Clone, Debug, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::localnet::service_authorities::GatewayCompliancePlanV1")]
struct GatewayCompliancePlanV1 {
    creation_time_ms: u64,
    slot: u8,
    provider_id: ProviderId,
    manager: AccountId,
    gateway_label: String,
    issued_at_unix: u64,
    expires_at_unix: u64,
    trust_template: GatewayComplianceTrustPolicyV1,
    empty_feed_transport_digest: [u8; 32],
}

/// Original generated compliance intent authenticated against the entire signed profile.
///
/// No public decoder or constructor turns template bytes into this value. The trust policy is
/// scoped to the actual original network. Its sole acknowledgement identity is the one generated
/// serving gateway (its fixed original peer); catalog governance remains two of three. It proves neither current
/// operator permission nor a
/// promoted catalog, gateway reload, acknowledgement, runtime admission or service readiness.
#[derive(Debug)]
pub struct RetainedGatewayCompliancePlan {
    network_id: NetworkId,
    original: GatewayCompliancePlanV1,
    original_commitment: Hash,
    trust_policy: GatewayComplianceTrustPolicyV1,
    gateway_id: [u8; 32],
}
impl RetainedGatewayCompliancePlan {
    /// Actual network derived from the original authenticated signed genesis.
    #[must_use]
    pub fn network_id(&self) -> NetworkId {
        self.network_id
    }
    /// Original provider scope; current native provider evidence remains separate.
    #[must_use]
    pub fn provider_id(&self) -> ProviderId {
        self.original.provider_id
    }
    /// Original manager assigned the native compliance operator role at genesis.
    #[must_use]
    pub fn manager(&self) -> &AccountId {
        &self.original.manager
    }
    /// Exact local label used by the native gateway policy and compliance controller.
    #[must_use]
    pub fn gateway_label(&self) -> &str {
        &self.original.gateway_label
    }
    /// Native gateway identity derived from this original network and exact label.
    #[must_use]
    pub fn gateway_id(&self) -> [u8; 32] {
        self.gateway_id
    }
    /// Canonical original trust policy bound to this actual network and plan commitment.
    #[must_use]
    pub fn trust_policy(&self) -> &GatewayComplianceTrustPolicyV1 {
        &self.trust_policy
    }
    /// Maximum lifetime of one generated catalog, shared with its sole signing owner.
    #[must_use]
    pub fn catalog_validity_seconds(&self) -> u64 {
        publication::GENERATED_CATALOG_VALIDITY_SECONDS
    }
    /// Original bounded plan hash committed in manager metadata by signed genesis.
    #[must_use]
    pub fn original_commitment(&self) -> Hash {
        self.original_commitment
    }
    /// Exact canonical empty-host transport policy; every external feed is denied.
    #[must_use]
    pub fn empty_feed_transport_digest(&self) -> [u8; 32] {
        self.original.empty_feed_transport_digest
    }
    /// Inclusive beginning of original material validity, in Unix seconds.
    #[must_use]
    pub fn issued_at_unix(&self) -> u64 {
        self.original.issued_at_unix
    }
    /// Exclusive end of original material validity, in Unix seconds; never renewed on reopen.
    #[must_use]
    pub fn expires_at_unix(&self) -> u64 {
        self.original.expires_at_unix
    }
}

fn encode<T: norito::NoritoSerialize>(value: &T) -> Result<Vec<u8>> {
    let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    norito::core::to_bytes_bounded(value, PLAN_MAX_BYTES).map_err(Into::into)
}
fn decode(bytes: &[u8]) -> Result<GatewayCompliancePlanV1> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= PLAN_MAX_BYTES,
        "retained compliance plan exceeds bound"
    );
    norito::decode_canonical_with_limits(bytes, PLAN_LIMITS).map_err(Into::into)
}
fn template_policy_id(provider: ProviderId, creation_time_ms: u64) -> [u8; 32] {
    *Hash::new_from_chunks(&[
        b"iroha:localnet:compliance-template:v1\0",
        provider.as_bytes(),
        &creation_time_ms.to_le_bytes(),
    ])
    .as_ref()
}
fn public32(key: &iroha_crypto::PublicKey) -> Result<[u8; 32]> {
    ensure!(
        key.algorithm() == iroha_crypto::Algorithm::Ed25519,
        "compliance credential algorithm differs"
    );
    key.to_bytes()
        .1
        .try_into()
        .map_err(|_| eyre!("invalid compliance Ed25519 public key"))
}
fn operator_role() -> RoleId {
    OPERATOR_ROLE
        .parse()
        .expect("static compliance operator role")
}

pub(super) struct GeneratedCompliance {
    plan: GatewayCompliancePlanV1,
}
impl GeneratedCompliance {
    pub(super) fn generate(
        directory: &Path,
        seed: Option<&[u8]>,
        slot: u8,
        provider: ProviderId,
        manager: &AccountId,
        creation_time_ms: u64,
        unique: &mut BTreeSet<iroha_crypto::PublicKey>,
    ) -> Result<Self> {
        let mut signers = Vec::with_capacity(4);
        ensure!(
            usize::from(slot) < PROVIDER_COUNT,
            "compliance provider slot exceeds original topology"
        );
        let selected_gateway = gateway_label(slot);
        for (name, id) in filenames().zip(
            CATALOG_IDS
                .into_iter()
                .chain(std::iter::once(selected_gateway.as_str())),
        ) {
            let label = format!("native-service-provider/{slot}/compliance/{name}");
            let identity = localnet_ephemeral_identity(seed, label.as_bytes())?;
            ensure!(
                unique.insert(identity.public_key.clone()),
                "compliance credentials must be distinct"
            );
            write_private_key_sidecar(&directory.join(name), identity.private_key.as_str())?;
            signers.push(GatewayComplianceTrustedSignerV1 {
                signer_id: id.into(),
                public_key: public32(&identity.public_key)?,
            });
        }
        let issued_at_unix = creation_time_ms / 1_000;
        let expires_at_unix = issued_at_unix
            .checked_add(provider_material::VALIDITY_SECONDS)
            .ok_or_else(|| eyre!("compliance validity overflow"))?;
        let plan = GatewayCompliancePlanV1 {
            creation_time_ms,
            slot,
            provider_id: provider,
            manager: manager.clone(),
            gateway_label: selected_gateway,
            issued_at_unix,
            expires_at_unix,
            trust_template: GatewayComplianceTrustPolicyV1 {
                policy_id: template_policy_id(provider, creation_time_ms),
                catalog_threshold: 2,
                gateway_ack_threshold: 1,
                catalog_signers: signers[..3].to_vec(),
                gateway_signers: signers[3..].to_vec(),
                revoked_catalog_signer_ids: Vec::new(),
                revoked_gateway_signer_ids: Vec::new(),
            },
            empty_feed_transport_digest: gateway_compliance_feed_transport_policy_digest(
                &std::collections::BTreeMap::new(),
            )?,
        };
        plan.validate(slot, provider, manager, creation_time_ms)?;
        Ok(Self { plan })
    }
    pub(super) fn bytes(&self) -> Result<Vec<u8>> {
        encode(&self.plan)
    }
}
pub(super) fn append_operator_role(
    genesis: RawGenesisTransaction,
    manager: &AccountId,
) -> Result<RawGenesisTransaction> {
    genesis
        .into_builder()
        .append_instruction(Register::role(Role::new(operator_role(), manager.clone())))
        .build_raw()
}
impl GatewayCompliancePlanV1 {
    fn validate(
        &self,
        slot: u8,
        provider: ProviderId,
        manager: &AccountId,
        creation_time_ms: u64,
    ) -> Result<()> {
        encode(self)?;
        self.trust_template.validate()?;
        ensure!(
            creation_time_ms > 0
                && creation_time_ms < u64::MAX
                && self.creation_time_ms == creation_time_ms
                && usize::from(slot) < PROVIDER_COUNT
                && self.slot == slot
                && self.provider_id == provider
                && &self.manager == manager
                && self.gateway_label == gateway_label(slot)
                && self.issued_at_unix == creation_time_ms / 1_000
                && self.issued_at_unix > 0
                && self
                    .issued_at_unix
                    .checked_add(provider_material::VALIDITY_SECONDS)
                    == Some(self.expires_at_unix)
                && self.expires_at_unix < u64::MAX
                && self.trust_template.policy_id == template_policy_id(provider, creation_time_ms)
                && self.trust_template.catalog_threshold == 2
                && self.trust_template.gateway_ack_threshold == 1
                && self.trust_template.catalog_signers.len() == 3
                && self.trust_template.gateway_signers.len() == 1
                && self.trust_template.revoked_catalog_signer_ids.is_empty()
                && self.trust_template.revoked_gateway_signer_ids.is_empty()
                && self
                    .trust_template
                    .catalog_signers
                    .iter()
                    .map(|s| s.signer_id.as_str())
                    .eq(CATALOG_IDS)
                && self
                    .trust_template
                    .gateway_signers
                    .iter()
                    .map(|s| s.signer_id.as_str())
                    .eq(std::iter::once(self.gateway_label.as_str()))
                && self.empty_feed_transport_digest
                    == gateway_compliance_feed_transport_policy_digest(
                        &std::collections::BTreeMap::new()
                    )?,
            "retained generated compliance selections differ"
        );
        Ok(())
    }
    fn bind(self, network_id: NetworkId) -> Result<RetainedGatewayCompliancePlan> {
        let commitment = Hash::new(encode(&self)?);
        let mut trust_policy = self.trust_template.clone();
        trust_policy.policy_id = *Hash::new_from_chunks(&[
            b"iroha:localnet:gateway-compliance-trust:v1\0",
            network_id.as_bytes(),
            commitment.as_ref(),
        ])
        .as_ref();
        trust_policy.validate()?;
        let gateway_id = derive_stream_token_gateway_id_v1(&network_id, &self.gateway_label)?;
        Ok(RetainedGatewayCompliancePlan {
            network_id,
            original: self,
            original_commitment: commitment,
            trust_policy,
            gateway_id,
        })
    }
}

pub(super) fn validate_retained(
    directory: &capture::CapturedDirectory,
    manifest: &StreamTokenAuthorityManifest,
    selected: &ProviderServiceInventory,
    creation_time_ms: u64,
    unique: &mut BTreeSet<iroha_crypto::PublicKey>,
) -> Result<()> {
    let plan = decode(&selected.compliance_plan)?;
    plan.validate(
        selected.slot,
        selected.provider_id,
        &manifest.manager,
        creation_time_ms,
    )?;
    for (name, signer) in filenames().zip(
        plan.trust_template
            .catalog_signers
            .iter()
            .chain(&plan.trust_template.gateway_signers),
    ) {
        let key = read_service_private_key(directory, name)?;
        ensure!(
            public32(key.public_key())? == signer.public_key
                && unique.insert(key.public_key().clone()),
            "retained compliance credential differs"
        );
    }
    directory.revalidate()?;
    Ok(())
}

pub(super) fn validate_operator_role(block: &SignedBlock, manager: &AccountId) -> Result<()> {
    let role = operator_role();
    let mut roles = 0;
    for transaction in block.external_transactions() {
        for instruction in transaction.instructions().explicit_instructions() {
            if let Some(RegisterBox::Role(register)) =
                instruction.as_any().downcast_ref::<RegisterBox>()
                && register.object.inner.id == role
            {
                ensure!(
                    register.object.grant_to() == manager
                        && register.object.inner.permissions().len() == 0
                        && register.object.inner.permission_epochs.is_empty(),
                    "original compliance operator role differs"
                );
                roles += 1;
            }
            if let Some(grant) = instruction.as_any().downcast_ref::<GrantBox>() {
                ensure!(
                    !matches!(grant,GrantBox::Role(value) if value.object()==&role)
                        && !matches!(grant,GrantBox::RolePermission(value) if value.destination()==&role),
                    "original compliance role changed"
                );
            }
            if let Some(revoke) = instruction
                .as_any()
                .downcast_ref::<iroha_data_model::isi::RevokeBox>()
            {
                ensure!(
                    !matches!(revoke,iroha_data_model::isi::RevokeBox::Role(value) if value.object()==&role)
                        && !matches!(revoke,iroha_data_model::isi::RevokeBox::RolePermission(value) if value.destination()==&role),
                    "original compliance role changed"
                );
            }
            if let Some(iroha_data_model::isi::UnregisterBox::Role(remove)) =
                instruction
                    .as_any()
                    .downcast_ref::<iroha_data_model::isi::UnregisterBox>()
            {
                ensure!(remove.object() != &role, "original compliance role removed");
            }
        }
    }
    ensure!(
        roles == 1,
        "original compliance operator role is absent or repeated"
    );
    Ok(())
}

pub(super) fn retained(
    manifest: &StreamTokenAuthorityManifest,
    provider: ProviderId,
) -> Result<RetainedGatewayCompliancePlan> {
    decode(&manifest.provider(provider)?.compliance_plan)?.bind(manifest.network_id)
}
pub(super) fn validate_standard(block: &SignedBlock) -> Result<()> {
    for transaction in block.external_transactions() {
        for instruction in transaction.instructions().explicit_instructions() {
            if let Some(RegisterBox::Role(register)) =
                instruction.as_any().downcast_ref::<RegisterBox>()
            {
                ensure!(
                    register.object.inner.id != operator_role(),
                    "Standard profile contains a generated compliance role"
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
