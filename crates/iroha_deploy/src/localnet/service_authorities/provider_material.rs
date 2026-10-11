//! Original generated provider material, authenticated by the sole signed-genesis profile.
//!
//! These retained selections establish neither current backing nor runtime readiness. Public
//! HTTPS serving and the closed profile-bound archive transport must be installed before enabling
//! services; generating a certificate never changes machine trust or starts a listener.

use super::*;
use iroha_data_model::sorafs::{
    pin_registry::StorageClass,
    pricing::PricingScheduleRecord,
    provider_admission::governance::InitialProviderAdmissionV1,
    reserve::{ReserveDuration, ReserveProviderTermsV1, ReserveTier},
};
use sorafs_manifest::{
    capacity::{CapacityDeclarationV1, CapacityMetadataEntry, ChunkerCommitmentV1},
    deal::XorQuantity,
    provider_admission::{
        EndpointAdmissionV1, EndpointAttestationKind, EndpointAttestationV1,
        ProviderAdmissionGenesisMaterialV1, ProviderAdmissionProposalV1, ProviderVrfPublicKeyV1,
    },
    provider_advert::{
        AdvertEndpoint, AvailabilityTier, CapabilityTlv, CapabilityType, EndpointKind,
        PathDiversityPolicy, ProviderAdvertBodyV1, ProviderCapabilityRangeV1, QosHints,
        RendezvousTopic, StakePointer, account_read::RegisteredAccountReadV1,
    },
};
use std::net::TcpListener;

mod advert;
mod tls_identity;

const PLAN_MAX_BYTES: usize = 64 * 1024;
const PLAN_LIMITS: norito::DecodeLimits = norito::DecodeLimits::new(
    PLAN_MAX_BYTES,
    PLAN_MAX_BYTES,
    PLAN_MAX_BYTES * 2,
    2 * 1024 * 1024,
    48,
);
const PROFILE: &str = "sorafs.sf1@1.0.0";
pub(super) const VALIDITY_SECONDS: u64 = 30 * 86_400;
const ADVERT_KEY: &str = "provider-advert.key";
const VRF_KEY: &str = "provider-por-vrf.key";
pub(super) const MAX_TLS_BYTES: usize = tls_identity::MAX_DER;
pub(super) fn credential_filenames() -> impl Iterator<Item = &'static str> {
    [ADVERT_KEY, VRF_KEY].into_iter()
}
pub(super) fn tls_filenames() -> impl Iterator<Item = &'static str> {
    tls_identity::FILES.into_iter()
}
pub(super) fn filenames() -> impl Iterator<Item = &'static str> {
    credential_filenames().chain(tls_filenames())
}

#[derive(Clone, Debug, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::localnet::service_authorities::ProviderServicePlanV1")]
struct ProviderServicePlanV1 {
    reserve_terms: ReserveProviderTermsV1,
    attestation_journal_policy_digest: [u8; 32],
    declaration: CapacityDeclarationV1,
    material: ProviderAdmissionGenesisMaterialV1,
}

/// Exact original generated provider selections, authenticated by retained signed genesis.
///
/// No public decoder or constructor turns copied plan bytes into this value. This is original
/// local intent, not a fresh admission, reserve, credit, capacity, or transport capability.
#[derive(Clone, Debug)]
pub struct RetainedProviderServicePlan {
    network_id: NetworkId,
    slot: u8,
    original_profile_commitment: Hash,
    pricing: PricingScheduleRecord,
    plan: ProviderServicePlanV1,
    origin: String,
}
impl RetainedProviderServicePlan {
    /// Network of the exact original signed genesis.
    #[must_use]
    pub fn network_id(&self) -> NetworkId {
        self.network_id
    }
    /// Original provider whose owner is the generated issuer operator.
    #[must_use]
    pub fn provider_id(&self) -> ProviderId {
        self.plan.reserve_terms.provider_id
    }
    /// Fixed original provider slot, authenticated with the entire generated profile.
    #[must_use]
    pub fn slot(&self) -> u8 {
        self.slot
    }
    /// Original validator process selected to host this provider.
    #[must_use]
    pub fn peer_index(&self) -> usize {
        usize::from(self.slot)
    }
    /// One network-independent whole-profile commitment authenticated by signed genesis.
    #[must_use]
    pub fn original_profile_commitment(&self) -> Hash {
        self.original_profile_commitment
    }
    /// Original underwriting terms; current native policy still owns the quote and backing.
    #[must_use]
    pub fn reserve_terms(&self) -> &ReserveProviderTermsV1 {
        &self.plan.reserve_terms
    }
    /// Exact pricing explicitly initialized in signed genesis, to compare with a fresh read.
    #[must_use]
    pub fn pricing(&self) -> &PricingScheduleRecord {
        &self.pricing
    }
    /// Exact fixed generated journal policy authenticated by its original canonical digest.
    /// This is local durability intent, not current approval authority or an external rollback seal.
    #[must_use]
    pub fn attestation_journal_policy(
        &self,
    ) -> sorafs_node::provider_attestation_journal::MusubiProviderAttestationJournalPolicyV1 {
        sorafs_node::provider_attestation_journal::MusubiProviderAttestationJournalPolicyV1::default(
        )
    }
    /// Complete original declaration, including the admitted stake pointer and finite interval.
    #[must_use]
    pub fn declaration(&self) -> &CapacityDeclarationV1 {
        &self.plan.declaration
    }
    /// Native network-independent initial material authenticated by the original genesis.
    #[must_use]
    pub fn admission_material(&self) -> &ProviderAdmissionGenesisMaterialV1 {
        &self.plan.material
    }
    /// Exact original HTTPS origin. This alone grants no access to loopback or private addresses.
    #[must_use]
    pub fn https_origin(&self) -> &str {
        &self.origin
    }
}

pub(super) struct GeneratedProvider {
    plan: ProviderServicePlanV1,
    // Select an actual available port without guessing beside another listener. This reservation
    // lasts through complete generation/signing. The later runtime owner must acquire this exact
    // retained port before activating any service; it cannot silently replace the admitted origin.
    _port: TcpListener,
}

fn tagged_identity(tag: &[u8], provider: ProviderId) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(tag.len() + 32);
    bytes.extend_from_slice(tag);
    bytes.extend_from_slice(provider.as_bytes());
    *Hash::new(bytes).as_ref()
}
fn host(provider: ProviderId) -> String {
    let digest = hex::encode(provider.as_bytes());
    format!("{}.{}.localhost", &digest[..32], &digest[32..])
}
fn public32(public: &iroha_crypto::PublicKey) -> Result<[u8; 32]> {
    ensure!(
        public.algorithm() == iroha_crypto::Algorithm::Ed25519,
        "provider key algorithm differs"
    );
    public
        .to_bytes()
        .1
        .try_into()
        .map_err(|_| eyre!("invalid provider Ed25519 public key"))
}
fn encode<T: norito::NoritoSerialize>(value: &T) -> Result<Vec<u8>> {
    let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let length = norito::core::encoded_frame_len(value)?;
    ensure!(
        length <= PLAN_MAX_BYTES,
        "generated provider plan exceeds bound"
    );
    norito::core::to_bytes_bounded(value, length).map_err(Into::into)
}
fn decode(bytes: &[u8]) -> Result<ProviderServicePlanV1> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= PLAN_MAX_BYTES,
        "retained provider plan exceeds bound"
    );
    norito::decode_canonical_with_limits(bytes, PLAN_LIMITS).map_err(Into::into)
}
fn policy(capabilities: &[CapabilityTlv]) -> Result<RegisteredAccountReadV1> {
    RegisteredAccountReadV1::from_capabilities(capabilities)?
        .ok_or_else(|| eyre!("generated provider lacks exact account-read policy"))
}

impl GeneratedProvider {
    pub(super) fn generate(
        directory: &Path,
        seed: Option<&[u8]>,
        slot: u8,
        provider: ProviderId,
        operator: &AccountId,
        network: &network_material::NetworkServicePlanV1,
        unique: &mut BTreeSet<iroha_crypto::PublicKey>,
        tls_keys: &mut BTreeSet<Hash>,
    ) -> Result<Self> {
        ensure!(
            usize::from(slot) < PROVIDER_COUNT,
            "provider slot exceeds original topology"
        );
        let creation_time_ms = network.creation_time_ms;
        let issued_at = creation_time_ms / 1_000;
        let retention_epoch = issued_at
            .checked_add(VALIDITY_SECONDS)
            .ok_or_else(|| eyre!("provider validity overflow"))?;
        let label = format!("native-service-provider/{slot}/{ADVERT_KEY}");
        let advert = localnet_ephemeral_identity(seed, label.as_bytes())?;
        ensure!(
            unique.insert(advert.public_key.clone()),
            "provider advert key must be distinct"
        );
        write_private_key_sidecar(&directory.join(ADVERT_KEY), advert.private_key.as_str())?;
        let advert = public32(&advert.public_key)?;
        let (vrf_public, vrf_secret, _) = generate_bls_key_pair(
            seed,
            format!("native-service-provider/{slot}/por-vrf").as_bytes(),
        )?;
        ensure!(
            unique.insert(vrf_public.clone()),
            "provider VRF identity must be distinct"
        );
        write_private_key_sidecar(
            &directory.join(VRF_KEY),
            Zeroizing::new(vrf_secret.try_to_multihash_string()?).as_str(),
        )?;
        let vrf = ProviderVrfPublicKeyV1::BlsNormal(
            vrf_public
                .to_bytes()
                .1
                .try_into()
                .map_err(|_| eyre!("invalid provider BLS public key"))?,
        );
        let port = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let account_read = RegisteredAccountReadV1 {
            https_host: host(provider),
            https_port: port.local_addr()?.port(),
            ttl_secs: 60,
            max_streams: 1,
            rate_limit_bytes: 16 * 1024 * 1024,
            requests_per_minute: 60,
        };
        account_read.validate()?;
        let tls = tls_identity::generate(
            directory,
            &account_read.https_host,
            issued_at,
            retention_epoch,
            tls_keys,
        )?;
        // Retain the current registry's exact negotiation handles in every profile projection.
        // The admitted body must already satisfy the advert consumer before genesis is signed.
        let profile_aliases: Vec<String> =
            sorafs_manifest::chunker_registry::lookup_by_handle(PROFILE)
                .ok_or_else(|| eyre!("generated provider chunker profile is absent"))?
                .aliases
                .iter()
                .map(|alias| (*alias).to_owned())
                .collect();
        let pricing = &network.pricing;
        let stake = StakePointer {
            pool_id: tagged_identity(b"iroha.localnet.provider.stake-pool.v1\0", provider),
            stake_amount: XorQuantity::try_from_quantity(pricing.required_collateral(
                StorageClass::Hot,
                1,
                issued_at,
                issued_at,
            )?)?,
        };
        let capabilities = vec![
            CapabilityTlv {
                cap_type: CapabilityType::ToriiGateway,
                payload: Vec::new(),
            },
            CapabilityTlv {
                cap_type: CapabilityType::ChunkRangeFetch,
                payload: ProviderCapabilityRangeV1::default().to_bytes()?,
            },
            account_read.to_capability()?,
        ];
        let endpoint = AdvertEndpoint {
            kind: EndpointKind::Torii,
            host_pattern: account_read.https_host.clone(),
            metadata: Vec::new(),
        };
        let proposal = ProviderAdmissionProposalV1 {
            version: 1,
            provider_id: *provider.as_bytes(),
            profile_id: PROFILE.into(),
            profile_aliases: Some(profile_aliases.clone()),
            stake: stake.clone(),
            capabilities: capabilities.clone(),
            endpoints: vec![EndpointAdmissionV1 {
                endpoint: endpoint.clone(),
                attestation: EndpointAttestationV1 {
                    version: 1,
                    kind: EndpointAttestationKind::Tls,
                    attested_at: issued_at,
                    expires_at: retention_epoch,
                    leaf_certificate: tls.leaf,
                    intermediate_certificates: vec![tls.root],
                    alpn_ids: vec!["http/1.1".into()],
                    report: Vec::new(),
                },
            }],
            advert_key: advert,
            por_vrf_key: vrf,
            // Disposable local material does not assert a real deployment jurisdiction.
            jurisdiction_code: "ZZ".into(),
            contact_uri: None,
            stream_budget: None,
            transport_hints: None,
        };
        let material = ProviderAdmissionGenesisMaterialV1 {
            proposal,
            advert_body: ProviderAdvertBodyV1 {
                provider_id: *provider.as_bytes(),
                profile_id: PROFILE.into(),
                profile_aliases: Some(profile_aliases.clone()),
                stake: stake.clone(),
                qos: QosHints {
                    availability: AvailabilityTier::Hot,
                    max_retrieval_latency_ms: 1_000,
                    max_concurrent_streams: 1,
                },
                capabilities,
                endpoints: vec![endpoint],
                rendezvous_topics: vec![RendezvousTopic {
                    topic: "sorafs.sf1.primary".into(),
                    region: "local".into(),
                }],
                path_policy: PathDiversityPolicy {
                    min_guard_weight: 1,
                    max_same_asn_per_path: 1,
                    max_same_pool_per_path: 1,
                },
                notes: None,
                stream_budget: None,
                transport_hints: None,
            },
            issued_at,
            retention_epoch,
        };
        let plan = ProviderServicePlanV1 {
            reserve_terms: ReserveProviderTermsV1 {
                provider_id: provider,
                provider_account: operator.clone(),
                tier: ReserveTier::TierA,
                storage_class: StorageClass::Hot,
                duration: ReserveDuration::Monthly,
                capacity_gib: 1,
            },
            attestation_journal_policy_digest: native_attestation::policy().digest()?,
            declaration: CapacityDeclarationV1 {
                version: 1,
                provider_id: *provider.as_bytes(),
                stake,
                committed_capacity_gib: 1,
                chunker_commitments: vec![ChunkerCommitmentV1 {
                    profile_id: PROFILE.into(),
                    profile_aliases: Some(profile_aliases),
                    committed_gib: 1,
                    capability_refs: vec![
                        CapabilityType::ToriiGateway,
                        CapabilityType::ChunkRangeFetch,
                    ],
                }],
                lane_commitments: Vec::new(),
                pricing: None,
                valid_from: issued_at,
                valid_until: retention_epoch,
                metadata: vec![
                    CapacityMetadataEntry {
                        key: "sorafs.owner_account_id".into(),
                        value: operator.to_string(),
                    },
                    CapacityMetadataEntry {
                        key: "sorafs.storage_class".into(),
                        value: "hot".into(),
                    },
                ],
            },
            material,
        };
        plan.material.advert_body.validate()?;
        plan.validate(provider, operator, network)?;
        encode(&plan)?;
        Ok(Self { plan, _port: port })
    }
    pub(super) fn attestation_policy_digest(&self) -> [u8; 32] {
        self.plan.attestation_journal_policy_digest
    }
    pub(super) fn bytes(&self) -> Result<Vec<u8>> {
        encode(&self.plan)
    }
    pub(super) fn initializer_entry(&self) -> Result<(ProviderId, InitialProviderAdmissionV1)> {
        Ok((
            self.plan.reserve_terms.provider_id,
            InitialProviderAdmissionV1 {
                owner: self.plan.reserve_terms.provider_account.clone(),
                material: encode(&self.plan.material)?,
            },
        ))
    }
}

impl ProviderServicePlanV1 {
    fn validate(
        &self,
        provider: ProviderId,
        operator: &AccountId,
        network: &network_material::NetworkServicePlanV1,
    ) -> Result<()> {
        encode(self)?;
        self.material.validate()?;
        self.declaration.validate()?;
        network.pricing.validate()?;
        ensure!(
            self.attestation_journal_policy_digest == native_attestation::policy().digest()?,
            "retained native attestation journal policy differs"
        );
        let issued_at = network.creation_time_ms / 1_000;
        let cap = policy(&self.material.proposal.capabilities)?;
        let exact_stake = StakePointer {
            pool_id: tagged_identity(b"iroha.localnet.provider.stake-pool.v1\0", provider),
            stake_amount: XorQuantity::try_from_quantity(network.pricing.required_collateral(
                StorageClass::Hot,
                1,
                issued_at,
                issued_at,
            )?)?,
        };
        ensure!(
            network.creation_time_ms != 0
                && network.creation_time_ms != u64::MAX
                && self.reserve_terms
                    == (ReserveProviderTermsV1 {
                        provider_id: provider,
                        provider_account: operator.clone(),
                        tier: ReserveTier::TierA,
                        storage_class: StorageClass::Hot,
                        duration: ReserveDuration::Monthly,
                        capacity_gib: 1
                    })
                && network.pricing == PricingScheduleRecord::launch_default()
                && self.material.issued_at == issued_at
                && issued_at.checked_add(VALIDITY_SECONDS) == Some(self.material.retention_epoch)
                && self.material.proposal.provider_id == *provider.as_bytes()
                && self.material.proposal.profile_id == PROFILE
                && self.material.proposal.stake == exact_stake
                && cap.https_host == host(provider)
                && self.material.proposal.endpoints.len() == 1
                && self.declaration.provider_id == *provider.as_bytes()
                && self.declaration.stake == exact_stake
                && self.declaration.committed_capacity_gib == 1
                && self.declaration.valid_from == issued_at
                && self.declaration.valid_until == self.material.retention_epoch
                && self.declaration.metadata
                    == vec![
                        CapacityMetadataEntry {
                            key: "sorafs.owner_account_id".into(),
                            value: operator.to_string()
                        },
                        CapacityMetadataEntry {
                            key: "sorafs.storage_class".into(),
                            value: "hot".into()
                        }
                    ],
            "retained generated provider selections differ"
        );
        let endpoint = &self.material.proposal.endpoints[0];
        ensure!(
            endpoint.endpoint.host_pattern == cap.https_host
                && endpoint.attestation.attested_at == issued_at
                && endpoint.attestation.expires_at == self.material.retention_epoch
                && endpoint.attestation.intermediate_certificates.len() == 1,
            "retained provider endpoint differs"
        );
        Ok(())
    }
}

pub(super) fn initialization_entry(
    selected: &ProviderServiceInventory,
) -> Result<(ProviderId, InitialProviderAdmissionV1)> {
    let plan = decode(&selected.provider_plan)?;
    Ok((
        selected.provider_id,
        InitialProviderAdmissionV1 {
            owner: plan.reserve_terms.provider_account,
            material: encode(&plan.material)?,
        },
    ))
}

pub(super) fn validate_retained(
    directory: &capture::CapturedDirectory,
    selected: &ProviderServiceInventory,
    network: &network_material::NetworkServicePlanV1,
    keys: &mut BTreeSet<iroha_crypto::PublicKey>,
    tls_keys: &mut BTreeSet<Hash>,
) -> Result<()> {
    let plan = decode(&selected.provider_plan)?;
    plan.validate(
        selected.provider_id,
        &selected
            .authority(StreamTokenAuthorityRole::IssuerOperator)?
            .account,
        network,
    )?;
    let advert = read_service_private_key(directory, ADVERT_KEY)?;
    ensure!(
        public32(advert.public_key())? == plan.material.proposal.advert_key
            && keys.insert(advert.public_key().clone()),
        "retained advert key differs"
    );
    let vrf = read_service_private_key(directory, VRF_KEY)?;
    ensure!(
        vrf.public_key().algorithm() == iroha_crypto::Algorithm::BlsNormal
            && vrf.public_key().to_bytes().1 == plan.material.proposal.por_vrf_key.as_bytes()
            && keys.insert(vrf.public_key().clone()),
        "retained VRF key differs"
    );
    let endpoint = &plan.material.proposal.endpoints[0];
    tls_identity::validate_retained(
        directory,
        &endpoint.attestation.intermediate_certificates[0],
        &endpoint.attestation.leaf_certificate,
        &endpoint.endpoint.host_pattern,
        plan.material.issued_at,
        tls_keys,
    )?;
    directory.revalidate()?;
    Ok(())
}

pub(super) fn retained(
    manifest: &StreamTokenAuthorityManifest,
    provider: ProviderId,
) -> Result<RetainedProviderServicePlan> {
    let selected = manifest.provider(provider)?;
    let plan = decode(&selected.provider_plan)?;
    let network = network_material::NetworkServicePlanV1::decode(&manifest.network.network_plan)?;
    let origin = policy(&plan.material.proposal.capabilities)?.https_origin()?;
    Ok(RetainedProviderServicePlan {
        network_id: manifest.network_id,
        slot: selected.slot,
        original_profile_commitment: profile_commitment(
            &manifest.manager,
            &manifest.network,
            &manifest.providers,
        )?,
        pricing: network.pricing,
        plan,
        origin,
    })
}

// Node-local listener selection is derived from the exact signed original admission material.
// Each original selected peer serves only its provider. Preparation starts no listener.
struct PeerHttps {
    address: SocketAddr,
    certificate: PathBuf,
    private_key: PathBuf,
    timeout_ms: u64,
}
impl PeerHttps {
    fn original(plan: &ProviderServicePlanV1, root: &Path, slot: u8) -> Result<Self> {
        let port = policy(&plan.material.proposal.capabilities)?.https_port;
        let directory = provider_directory(root, slot)?;
        Ok(Self {
            address: SocketAddr::from(([127, 0, 0, 1], port)),
            certificate: directory.join(tls_identity::LEAF_CERT),
            private_key: directory.join(tls_identity::LEAF_KEY),
            timeout_ms:
                iroha_config::parameters::defaults::torii::transport::https::HANDSHAKE_TIMEOUT_MS,
        })
    }
    fn table(&self) -> Result<toml::Table> {
        Ok(toml::Table::from_iter([
            (
                "address".into(),
                toml::Value::String(self.address.to_literal()),
            ),
            (
                "certificate_chain".into(),
                toml::Value::Array(vec![toml::Value::String(
                    self.certificate
                        .to_str()
                        .ok_or_else(|| eyre!("invalid retained certificate path"))?
                        .to_owned(),
                )]),
            ),
            (
                "private_key".into(),
                toml::Value::String(
                    self.private_key
                        .to_str()
                        .ok_or_else(|| eyre!("invalid retained private key path"))?
                        .to_owned(),
                ),
            ),
            (
                "handshake_timeout_ms".into(),
                toml::Value::Integer(self.timeout_ms.try_into()?),
            ),
        ]))
    }
}
pub(super) fn configure_peer_https(
    selected: Option<(&GeneratedProvider, u8)>,
    table: &mut toml::Table,
    root: &Path,
    index: usize,
) -> Result<()> {
    ensure!(
        index < 4,
        "generated provider peer index exceeds original committee"
    );
    ensure!(
        selected.map(|(_, slot)| usize::from(slot)) == (index < PROVIDER_COUNT).then_some(index),
        "generated provider peer assignment differs"
    );
    let torii = table
        .entry("torii")
        .or_insert_with(|| toml::Value::Table(toml::Table::new()))
        .as_table_mut()
        .ok_or_else(|| eyre!("invalid generated Torii table"))?;
    let transport = torii
        .entry("transport")
        .or_insert_with(|| toml::Value::Table(toml::Table::new()))
        .as_table_mut()
        .ok_or_else(|| eyre!("invalid generated Torii transport table"))?;
    ensure!(
        !transport.contains_key("https"),
        "generated HTTPS listener is already selected"
    );
    if let Some((provider, slot)) = selected {
        transport.insert(
            "https".into(),
            toml::Value::Table(PeerHttps::original(&provider.plan, root, slot)?.table()?),
        );
    }
    Ok(())
}

pub(super) fn validate_peer_https(
    manifest: &StreamTokenAuthorityManifest,
    root: &Path,
    index: usize,
    actual: Option<&iroha_config::parameters::actual::ToriiHttpsTransport>,
) -> Result<()> {
    ensure!(
        index < 4,
        "retained provider peer index exceeds original committee"
    );
    if index >= PROVIDER_COUNT {
        ensure!(
            actual.is_none(),
            "provider HTTPS listener moved to another peer"
        );
        return Ok(());
    }
    let selected = &manifest.providers[index];
    ensure!(
        usize::from(selected.slot) == index,
        "retained provider slot changed"
    );
    let original = PeerHttps::original(&decode(&selected.provider_plan)?, root, selected.slot)?;
    let actual = actual.ok_or_else(|| eyre!("original provider HTTPS listener is absent"))?;
    ensure!(
        actual.address.value() == &original.address
            && actual.certificate_chain.as_slice() == [original.certificate]
            && actual.private_key == original.private_key
            && actual.handshake_timeout == std::time::Duration::from_millis(original.timeout_ms),
        "retained provider HTTPS listener differs from original profile"
    );
    Ok(())
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod listener_tests;
