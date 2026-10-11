//! Retained native token authority prerequisites for managed global genesis.
//!
//! This profile creates funded signers, initial capabilities, two non-signing reserve accounts and
//! three genesis-bound providers with distinct custody and one shared pricing/admission policy.
//! It does not configure custody or gateway policies, enroll a signer, fund native reserves, or
//! enable token services; original profile intent is distinct from current native eligibility.
use super::*;
use crate::managed::{Error, PreparedLocalnet};
use iroha_data_model::{NetworkId, sorafs::capacity::ProviderId};
use iroha_executor_data_model::permission::sorafs::{
    CanCheckSorafsStreamToken, CanCompleteSorafsReplicationOrder, CanDeclareSorafsCapacity,
    CanManageSorafsReputationJournalPolicy, CanManageSorafsStreamTokenCustody,
    CanManageSorafsStreamTokenGateway, CanOperateSorafsRepair, CanOperateSorafsStreamToken,
    CanRecordSorafsProofOutcome, CanRecordSorafsReputationJournal, CanSetSorafsReservePolicy,
    CanUpsertSorafsProviderCredit,
};
use norito::{JsonDeserialize, JsonSerialize};

mod capture;
mod compliance_material;
pub use compliance_material::RetainedGatewayCompliancePlan;
mod native_attestation;
pub(super) mod publication_client;
pub use publication_client::RetainedPublicationClientConfig;
mod publication_material;
pub use publication_material::RetainedPublicationServicePlan;
mod network_material;
mod provider_material;
pub use provider_material::RetainedProviderServicePlan;

const DIRECTORY: &str = "stream-token-authorities";
const MANIFEST: &str = "authorities.json";
const MAX_MANIFEST: usize = 512 * 1024;
const MAX_PROFILE_BYTES: usize = 256 * 1024;
const MATERIAL_METADATA: &str = "localnet_service_material_v1";
const PROVIDER_COUNT: usize = 3;
const NETWORK_DIRECTORY: &str = "network";
const PROVIDERS_DIRECTORY: &str = "providers";
const MAX_ROLE_CREDENTIAL_BYTES: usize = 256;
const PROFILE_METADATA: &str = "localnet_service_profile_v1";
const ROLE_METADATA: &str = "localnet_stream_token_authority_role_v1";

pub(super) fn append_profile(
    genesis: RawGenesisTransaction,
    profile: LocalnetServiceProfile,
    manager: &AccountId,
) -> Result<RawGenesisTransaction> {
    genesis
        .into_builder()
        .append_instruction(SetKeyValue::account(
            manager.clone(),
            PROFILE_METADATA
                .parse()
                .expect("static profile metadata key"),
            Json::new(profile),
        ))
        .build_raw()
}

fn role_metadata(role: impl norito::json::JsonSerialize) -> Metadata {
    let mut metadata = Metadata::default();
    metadata.insert(
        ROLE_METADATA
            .parse()
            .expect("static authority metadata key"),
        Json::new(role),
    );
    metadata
}

/// Closed preparation profile, retained exactly with the signed genesis identity.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(
    tag = "profile",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum LocalnetServiceProfile {
    /// Minimal preparation without token authorities, used by private roots and explicit generators.
    #[default]
    Standard,
    /// Prepare native identities, signed-genesis admission and retained TLS; services stay disabled.
    StreamTokenAuthorities,
}

/// One distinct generated provider service credential purpose.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    JsonSerialize,
    JsonDeserialize,
    norito::Encode,
    norito::Decode,
    norito::NoritoSchema,
)]
#[norito(
    tag = "role",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[norito_schema(name = "iroha_deploy::localnet::service_authorities::StreamTokenAuthorityRole")]
pub enum StreamTokenAuthorityRole {
    /// Provider owner and issuer operation transaction signer.
    IssuerOperator,
    /// Independent issuer Check transaction signer.
    IssuerObserver,
    /// Purpose-bound token body signer; never the operation transaction signer.
    TokenSigner,
    /// Independent signer-custody attester.
    CustodyAttester,
    /// Gateway admission and acknowledgement transaction signer.
    GatewayOperator,
    /// Independent gateway Check transaction signer.
    GatewayObserver,
    /// Exact provider-scoped proof-outcome transaction signer.
    ProofOutcome,
    /// Exact provider-scoped repair transaction signer.
    Repair,
    /// Orderbook transaction signer; current native matcher policy remains required.
    OrderbookMatcher,
    /// Dedicated provider-scoped ingest completion and source-fetch signer.
    ProviderIngest,
}
impl StreamTokenAuthorityRole {
    /// Fixed basename beneath the selected original provider directory; never caller-controlled.
    #[must_use]
    pub const fn credential_filename(self) -> &'static str {
        match self {
            Self::IssuerOperator => "issuer-operator.key",
            Self::IssuerObserver => "issuer-observer.key",
            Self::TokenSigner => "token-signer.key",
            Self::CustodyAttester => "custody-attester.key",
            Self::GatewayOperator => "gateway-operator.key",
            Self::GatewayObserver => "gateway-observer.key",
            Self::ProofOutcome => "proof-outcome.key",
            Self::Repair => "repair.key",
            Self::OrderbookMatcher => "orderbook-matcher.key",
            Self::ProviderIngest => "provider-ingest.key",
        }
    }
    const fn transacts(self) -> bool {
        !matches!(self, Self::TokenSigner | Self::CustodyAttester)
    }
}
const ROLES: [StreamTokenAuthorityRole; 10] = [
    StreamTokenAuthorityRole::IssuerOperator,
    StreamTokenAuthorityRole::IssuerObserver,
    StreamTokenAuthorityRole::TokenSigner,
    StreamTokenAuthorityRole::CustodyAttester,
    StreamTokenAuthorityRole::GatewayOperator,
    StreamTokenAuthorityRole::GatewayObserver,
    StreamTokenAuthorityRole::ProofOutcome,
    StreamTokenAuthorityRole::Repair,
    StreamTokenAuthorityRole::OrderbookMatcher,
    StreamTokenAuthorityRole::ProviderIngest,
];

/// Public account and fixed credential purpose; contains no secret bytes or configurable path.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    JsonSerialize,
    JsonDeserialize,
    norito::Encode,
    norito::Decode,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_deploy::localnet::service_authorities::StreamTokenAuthority")]
pub struct StreamTokenAuthority {
    /// Purpose whose fixed filename is exposed by [`StreamTokenAuthorityRole::credential_filename`].
    pub role: StreamTokenAuthorityRole,
    /// Registered universal single-key account for this purpose.
    pub account: AccountId,
}

/// Distinct protocol-only reserve accounts; neither has a generated signing credential.
///
/// Initial registration gives them no funds or permission. An ordinary governed reserve policy
/// must select them before native reserve movements can use them.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    JsonSerialize,
    JsonDeserialize,
    norito::Encode,
    norito::Decode,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_deploy::localnet::service_authorities::StreamTokenReserveAccounts")]
pub struct StreamTokenReserveAccounts {
    /// Pooled native reserve custody, initially unfunded.
    pub custody: AccountId,
    /// Native reserve treasury, initially unfunded and distinct from custody.
    pub treasury: AccountId,
}

#[derive(Clone, Copy, JsonSerialize)]
#[norito(tag = "role", content = "value", rename_all = "snake_case")]
enum ReserveAccountRole {
    ReserveCustody,
    ReserveTreasury,
}

// These identities belong to the one network reserve policy. No signing scalar is generated.
fn reserve_accounts(operations: &AccountId) -> Result<StreamTokenReserveAccounts> {
    let selection = norito::encode_canonical(operations)?;
    Ok(StreamTokenReserveAccounts {
        custody: AccountId::new(iroha_crypto::derive_non_signing_ed25519_public_key(
            b"iroha:localnet:stream-token-reserve-custody:v1",
            &[&selection],
        )),
        treasury: AccountId::new(iroha_crypto::derive_non_signing_ed25519_public_key(
            b"iroha:localnet:stream-token-reserve-treasury:v1",
            &[&selection],
        )),
    })
}

/// Closed network-wide signing roles, independent from every provider owner.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    JsonSerialize,
    JsonDeserialize,
    norito::Encode,
    norito::Decode,
    norito::NoritoSchema,
)]
#[norito(
    tag = "role",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[norito_schema(name = "iroha_deploy::localnet::service_authorities::NetworkServiceAuthorityRole")]
pub enum NetworkServiceAuthorityRole {
    /// Exact native reserve operations account, shared by all provider partitions.
    ReserveOperations,
    /// Exact native reputation journal recorder, shared by all selected gateways.
    ReputationRecorder,
    /// Ordinary funded pin and publisher-source signer, separate from receipt and manager roles.
    MusubiPin,
}
impl NetworkServiceAuthorityRole {
    /// Fixed basename under the original network credential directory.
    #[must_use]
    pub const fn credential_filename(self) -> &'static str {
        match self {
            Self::ReserveOperations => "reserve-operations.key",
            Self::ReputationRecorder => "reputation-recorder.key",
            Self::MusubiPin => "musubi-pin.key",
        }
    }
}
const NETWORK_ROLES: [NetworkServiceAuthorityRole; 3] = [
    NetworkServiceAuthorityRole::ReserveOperations,
    NetworkServiceAuthorityRole::ReputationRecorder,
    NetworkServiceAuthorityRole::MusubiPin,
];
/// One original public network role and registered universal account.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    JsonSerialize,
    JsonDeserialize,
    norito::Encode,
    norito::Decode,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_deploy::localnet::service_authorities::NetworkServiceAuthority")]
pub struct NetworkServiceAuthority {
    /// Fixed signing purpose.
    pub role: NetworkServiceAuthorityRole,
    /// Original single-key account, distinct from every provider credential.
    pub account: AccountId,
}
/// Original network singletons, before any ordinary policy activation.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    JsonSerialize,
    JsonDeserialize,
    norito::Encode,
    norito::Decode,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_deploy::localnet::service_authorities::NetworkServiceInventory")]
pub struct NetworkServiceInventory {
    /// Exactly three original accounts in canonical network-role order.
    pub authorities: Vec<NetworkServiceAuthority>,
    /// Shared non-signing custody and treasury for the sole native reserve policy.
    pub reserve_accounts: StreamTokenReserveAccounts,
    /// Canonical original timestamp, pricing and single provider-admission council.
    pub network_plan: Vec<u8>,
    /// Canonical fixed publication host/session, limits and original private listener port.
    pub publication_plan: Vec<u8>,
}
impl NetworkServiceInventory {
    /// Select public original intent; this does not establish current permission or policy.
    /// # Errors
    /// Refuses a missing, reordered or incomplete network-role inventory.
    pub fn authority(
        &self,
        role: NetworkServiceAuthorityRole,
    ) -> crate::managed::Result<&NetworkServiceAuthority> {
        if self.authorities.len() != NETWORK_ROLES.len()
            || self
                .authorities
                .iter()
                .map(|entry| &entry.account)
                .collect::<BTreeSet<_>>()
                .len()
                != NETWORK_ROLES.len()
            || self
                .authorities
                .iter()
                .zip(NETWORK_ROLES)
                .any(|(entry, expected)| entry.role != expected)
        {
            return Err(Error::Invalid(
                "original network service roles differ".into(),
            ));
        }
        self.authorities
            .iter()
            .find(|entry| entry.role == role)
            .ok_or_else(|| Error::Invalid("original network service role is absent".into()))
    }
}
/// One provider's original plan and fixed credential inventory, bound by signed genesis.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    JsonSerialize,
    JsonDeserialize,
    norito::Encode,
    norito::Decode,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_deploy::localnet::service_authorities::ProviderServiceInventory")]
pub struct ProviderServiceInventory {
    /// Fixed slot, equal to its original validator peer index (zero, one or two).
    pub slot: u8,
    /// Exact native provider identity, never inferred from an endpoint.
    pub provider_id: ProviderId,
    /// Exactly ten original accounts in canonical provider-role order.
    pub authorities: Vec<StreamTokenAuthority>,
    /// Canonical bounded provider material and original underwriting/declaration.
    pub provider_plan: Vec<u8>,
    /// Canonical original compliance trust for this provider's one actual gateway.
    pub compliance_plan: Vec<u8>,
}
impl ProviderServiceInventory {
    /// Select only the exact original provider role after full profile authentication.
    /// # Errors
    /// Refuses a missing, reordered or incomplete role inventory or invalid slot.
    pub fn authority(
        &self,
        role: StreamTokenAuthorityRole,
    ) -> crate::managed::Result<&StreamTokenAuthority> {
        if usize::from(self.slot) >= PROVIDER_COUNT
            || self.authorities.len() != ROLES.len()
            || self
                .authorities
                .iter()
                .map(|entry| &entry.account)
                .collect::<BTreeSet<_>>()
                .len()
                != ROLES.len()
            || self
                .authorities
                .iter()
                .zip(ROLES)
                .any(|(entry, expected)| entry.role != expected)
        {
            return Err(Error::Invalid(
                "original provider service roles differ".into(),
            ));
        }
        self.authorities
            .iter()
            .find(|entry| entry.role == role)
            .ok_or_else(|| Error::Invalid("original provider service role is absent".into()))
    }
    pub(crate) fn native_transaction_signer_authorities<'a>(
        &'a self,
        network: &'a NetworkServiceInventory,
    ) -> crate::managed::Result<NativeTransactionSignerAuthorities<'a>> {
        Ok(NativeTransactionSignerAuthorities {
            proof_outcome: self.authority(StreamTokenAuthorityRole::ProofOutcome)?,
            repair: self.authority(StreamTokenAuthorityRole::Repair)?,
            reserve: network.authority(NetworkServiceAuthorityRole::ReserveOperations)?,
            orderbook: self.authority(StreamTokenAuthorityRole::OrderbookMatcher)?,
        })
    }
}
/// Borrowed original native roles; full profile and current native eligibility remain required.
pub(crate) struct NativeTransactionSignerAuthorities<'a> {
    pub(crate) proof_outcome: &'a StreamTokenAuthority,
    pub(crate) repair: &'a StreamTokenAuthority,
    pub(crate) reserve: &'a NetworkServiceAuthority,
    pub(crate) orderbook: &'a StreamTokenAuthority,
}
/// Exact signed-genesis-bound public inventory; never proof of current service eligibility.
#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct StreamTokenAuthorityManifest {
    /// Network derived from the exact retained signed genesis.
    pub network_id: NetworkId,
    /// Existing retained ledger manager and reserve decision signer.
    pub manager: AccountId,
    /// One network-wide inventory, pricing/council and reserve account selection.
    pub network: NetworkServiceInventory,
    /// Exactly three provider inventories in fixed original peer order.
    #[norito(json = "provider_inventories_json")]
    pub providers: [ProviderServiceInventory; PROVIDER_COUNT],
}
// JSON keeps the same closed array layout as the canonical aggregate commitment. This adapter
// borrows the original inventories during both writes and does not widen the public array type.
mod provider_inventories_json {
    use norito::json::{
        self, BoundedJsonError, JsonDeserialize, JsonSerialize, JsonWriteSink, Parser,
    };

    use super::{PROVIDER_COUNT, ProviderServiceInventory};

    pub(super) fn serialize(value: &[ProviderServiceInventory; PROVIDER_COUNT], out: &mut String) {
        out.push('[');
        for (index, provider) in value.iter().enumerate() {
            if index != 0 {
                out.push(',');
            }
            provider.json_serialize(out);
        }
        out.push(']');
    }

    pub(super) fn serialize_bounded(
        value: &[ProviderServiceInventory; PROVIDER_COUNT],
        out: &mut dyn JsonWriteSink,
    ) -> Result<(), BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push('[')?;
            for (index, provider) in value.iter().enumerate() {
                if index != 0 {
                    out.push(',')?;
                }
                provider.json_serialize_to(out)?;
            }
            out.push(']')?;
            Ok(())
        })();
        out.end_container();
        result?;
        Ok(())
    }

    pub(super) fn deserialize(
        parser: &mut Parser<'_>,
    ) -> Result<[ProviderServiceInventory; PROVIDER_COUNT], json::Error> {
        // Prove the fixed boundary without constructing inventories or traversing a fourth body.
        // Only then run the original array depth/sequence/resource guard before owned decoding.
        let mut boundary = *parser;
        boundary.expect(b'[')?;
        for index in 0..PROVIDER_COUNT {
            if index != 0 {
                boundary.expect(b',')?;
            }
            boundary.skip_value_lexical()?;
        }
        boundary.expect(b']')?;
        parser.preflight_array_entries()?;

        parser.expect(b'[')?;
        let first = ProviderServiceInventory::json_deserialize(parser)?;
        parser.expect(b',')?;
        let second = ProviderServiceInventory::json_deserialize(parser)?;
        parser.expect(b',')?;
        let third = ProviderServiceInventory::json_deserialize(parser)?;
        parser.expect(b']')?;
        Ok([first, second, third])
    }
}

impl StreamTokenAuthorityManifest {
    /// Select exact public original provider intent, without manufacturing native authority.
    /// # Errors
    /// Refuses an unknown provider or changed fixed slot ordering.
    pub fn provider(
        &self,
        provider: ProviderId,
    ) -> crate::managed::Result<&ProviderServiceInventory> {
        if self
            .providers
            .iter()
            .map(|entry| entry.provider_id)
            .collect::<BTreeSet<_>>()
            .len()
            != PROVIDER_COUNT
            || self
                .providers
                .iter()
                .enumerate()
                .any(|(index, entry)| usize::from(entry.slot) != index)
        {
            return Err(Error::Invalid("original provider slots differ".into()));
        }
        self.providers
            .iter()
            .find(|entry| entry.provider_id == provider)
            .ok_or_else(|| Error::Invalid("original provider is absent".into()))
    }
}

// Sole canonical aggregate commitment layout. The encoder below borrows this exact layout;
// there is no alternate persisted profile or compatibility decoder.
#[derive(norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::localnet::service_authorities::ServiceProfileCommitmentV1")]
struct ServiceProfileCommitmentV1 {
    manager: AccountId,
    network: NetworkServiceInventory,
    providers: [ProviderServiceInventory; PROVIDER_COUNT],
}
struct ProfileValue<'a, T>(&'a T);
impl<T: norito::core::SerializePayload> norito::core::SerializePayload for ProfileValue<'_, T> {
    fn serialize(
        &self,
        out: &mut norito::core::Encoder<'_>,
    ) -> std::result::Result<(), norito::Error> {
        norito::core::SerializePayload::serialize(self.0, out)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        norito::core::SerializePayload::encoded_len_hint(self.0)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        norito::core::SerializePayload::encoded_len_exact(self.0)
    }
}
#[derive(norito::derive::NoritoSerialize)]
struct ServiceProfileCommitmentRef<'a> {
    manager: ProfileValue<'a, AccountId>,
    network: ProfileValue<'a, NetworkServiceInventory>,
    providers: ProfileValue<'a, [ProviderServiceInventory; PROVIDER_COUNT]>,
}
impl norito::NoritoSchema for ServiceProfileCommitmentRef<'_> {
    fn nominal_name() -> String {
        <ServiceProfileCommitmentV1 as norito::NoritoSchema>::nominal_name()
    }
    fn frame_name() -> String {
        <ServiceProfileCommitmentV1 as norito::NoritoSchema>::frame_name()
    }
}
fn profile_commitment(
    manager: &AccountId,
    network: &NetworkServiceInventory,
    providers: &[ProviderServiceInventory; PROVIDER_COUNT],
) -> Result<Hash> {
    let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let bytes = norito::core::to_bytes_bounded(
        &ServiceProfileCommitmentRef {
            manager: ProfileValue(manager),
            network: ProfileValue(network),
            providers: ProfileValue(providers),
        },
        MAX_PROFILE_BYTES,
    )?;
    Ok(Hash::new(bytes))
}
fn provider_directory(root: &Path, slot: u8) -> Result<PathBuf> {
    ensure!(
        usize::from(slot) < PROVIDER_COUNT,
        "provider slot exceeds original topology"
    );
    Ok(root
        .join(LOCALNET_RUNTIME_DIRECTORY)
        .join(DIRECTORY)
        .join(PROVIDERS_DIRECTORY)
        .join(slot.to_string()))
}
fn open_provider_directory(
    root: &iroha_fs::PrivateDirectory,
    slot: u8,
) -> crate::managed::Result<iroha_fs::PrivateDirectory> {
    if usize::from(slot) >= PROVIDER_COUNT {
        return Err(Error::Invalid("invalid original provider slot".into()));
    }
    Ok(root
        .open_child(PROVIDERS_DIRECTORY)?
        .open_child(slot.to_string())?)
}
struct GeneratedProviderAuthorities {
    slot: u8,
    authorities: Vec<(StreamTokenAuthorityRole, LocalnetClientIdentity)>,
    provider_id: ProviderId,
    provider: provider_material::GeneratedProvider,
    compliance: compliance_material::GeneratedCompliance,
}
pub(super) struct GeneratedAuthorities {
    authorities: Vec<(NetworkServiceAuthorityRole, LocalnetClientIdentity)>,
    network: network_material::NetworkServicePlanV1,
    publication: publication_material::GeneratedPublication,
    providers: [GeneratedProviderAuthorities; PROVIDER_COUNT],
}

pub(super) fn validate_selection(opts: &LocalnetOptions, managed: bool, taira: bool) -> Result<()> {
    if opts.service_profile == LocalnetServiceProfile::StreamTokenAuthorities {
        ensure!(
            managed
                && !taira
                && opts.sora_profile.is_none()
                && opts.peers.get() == 4
                && opts.consensus_mode == SumeragiConsensusMode::Permissioned,
            "native service authorities require the stock managed global four-validator profile"
        );
    }
    Ok(())
}

// ProviderId is protocol-assigned opaque bytes, not an account address. This is only the local
// generator's stable scope allocation, not a new network-wide key-to-provider identity rule.
fn provider_scope(operator: &iroha_crypto::PublicKey) -> Result<ProviderId> {
    let key = norito::encode_canonical(operator)?;
    let mut material = b"iroha.localnet.stream-token-provider.v1\0".to_vec();
    material.extend_from_slice(&key);
    Ok(ProviderId::new(*Hash::new(material).as_ref()))
}

pub(super) fn generate(
    profile: LocalnetServiceProfile,
    root: &Path,
    seed: Option<&[u8]>,
    manager: &LocalnetClientIdentity,
    http: &LocalnetClientIdentity,
    onboarding: &LocalnetClientIdentity,
) -> Result<Option<GeneratedAuthorities>> {
    if profile == LocalnetServiceProfile::Standard {
        return Ok(None);
    }
    let directory = root.join(LOCALNET_RUNTIME_DIRECTORY).join(DIRECTORY);
    custody::prepare_empty_private_directory(&directory)?;
    let network_directory = directory.join(NETWORK_DIRECTORY);
    let providers_directory = directory.join(PROVIDERS_DIRECTORY);
    custody::prepare_empty_private_directory(&network_directory)?;
    custody::prepare_empty_private_directory(&providers_directory)?;
    let mut unique = BTreeSet::from([
        manager.public_key.clone(),
        http.public_key.clone(),
        onboarding.public_key.clone(),
    ]);
    let mut authorities = Vec::with_capacity(NETWORK_ROLES.len());
    for role in NETWORK_ROLES {
        let label = format!("native-service-network/{}", role.credential_filename());
        let identity = localnet_ephemeral_identity(seed, label.as_bytes())?;
        ensure!(
            unique.insert(identity.public_key.clone()),
            "network service credentials must be distinct"
        );
        write_private_key_sidecar(
            &network_directory.join(role.credential_filename()),
            identity.private_key.as_str(),
        )?;
        authorities.push((role, identity));
    }
    let reserves = reserve_accounts(&authorities[0].1.account_id)?;
    for account in [&reserves.custody, &reserves.treasury] {
        ensure!(
            unique.insert(
                account
                    .try_signatory()
                    .expect("derived single-key account")
                    .clone()
            ),
            "reserve accounts must be distinct from every signer"
        );
    }
    let network = network_material::NetworkServicePlanV1::generate(
        &network_directory,
        seed,
        &authorities[0].1.account_id,
        &mut unique,
    )?;
    let mut tls_keys = BTreeSet::new();
    let mut providers = Vec::with_capacity(PROVIDER_COUNT);
    for slot in 0..PROVIDER_COUNT {
        let slot = u8::try_from(slot)?;
        let selected_directory = provider_directory(root, slot)?;
        custody::prepare_empty_private_directory(&selected_directory)?;
        let mut selected = Vec::with_capacity(ROLES.len());
        for role in ROLES {
            let label = format!(
                "native-service-provider/{slot}/{}",
                role.credential_filename()
            );
            let identity = localnet_ephemeral_identity(seed, label.as_bytes())?;
            ensure!(
                unique.insert(identity.public_key.clone()),
                "provider credentials must be distinct"
            );
            write_private_key_sidecar(
                &selected_directory.join(role.credential_filename()),
                identity.private_key.as_str(),
            )?;
            selected.push((role, identity));
        }
        let provider_id = provider_scope(&selected[0].1.public_key)?;
        let provider = provider_material::GeneratedProvider::generate(
            &selected_directory,
            seed,
            slot,
            provider_id,
            &selected[0].1.account_id,
            &network,
            &mut unique,
            &mut tls_keys,
        )?;
        let compliance = compliance_material::GeneratedCompliance::generate(
            &selected_directory,
            seed,
            slot,
            provider_id,
            &manager.account_id,
            network.creation_time_ms,
            &mut unique,
        )?;
        providers.push(GeneratedProviderAuthorities {
            slot,
            authorities: selected,
            provider_id,
            provider,
            compliance,
        });
    }
    let providers: [GeneratedProviderAuthorities; PROVIDER_COUNT] = providers
        .try_into()
        .map_err(|_| eyre!("generated provider count differs"))?;
    let publication = publication_material::GeneratedPublication::generate(
        &authorities,
        &providers,
        network.creation_time_ms,
    )?;
    Ok(Some(GeneratedAuthorities {
        authorities,
        network,
        publication,
        providers,
    }))
}

fn grants(
    manager: &AccountId,
    network: &NetworkServiceInventory,
    providers: &[ProviderServiceInventory; PROVIDER_COUNT],
) -> Result<Vec<(AccountId, Permission)>> {
    let mut grants = vec![
        (manager.clone(), CanSetSorafsReservePolicy.into()),
        (manager.clone(), CanUpsertSorafsProviderCredit.into()),
        (manager.clone(), CanManageSorafsStreamTokenGateway.into()),
        (
            manager.clone(),
            CanManageSorafsReputationJournalPolicy.into(),
        ),
        (
            network
                .authority(NetworkServiceAuthorityRole::ReputationRecorder)?
                .account
                .clone(),
            CanRecordSorafsReputationJournal.into(),
        ),
    ];
    for provider in providers {
        let provider_id = provider.provider_id;
        let account = |role| provider.authority(role).map(|entry| entry.account.clone());
        grants.extend([
            (
                manager.clone(),
                CanManageSorafsStreamTokenCustody { provider_id }.into(),
            ),
            (
                account(StreamTokenAuthorityRole::IssuerOperator)?,
                CanOperateSorafsStreamToken { provider_id }.into(),
            ),
            (
                account(StreamTokenAuthorityRole::IssuerOperator)?,
                CanDeclareSorafsCapacity.into(),
            ),
            (
                account(StreamTokenAuthorityRole::IssuerObserver)?,
                CanCheckSorafsStreamToken { provider_id }.into(),
            ),
            (
                account(StreamTokenAuthorityRole::ProofOutcome)?,
                CanRecordSorafsProofOutcome { provider_id }.into(),
            ),
            (
                account(StreamTokenAuthorityRole::Repair)?,
                CanOperateSorafsRepair { provider_id }.into(),
            ),
            (
                account(StreamTokenAuthorityRole::ProviderIngest)?,
                CanCompleteSorafsReplicationOrder { provider_id }.into(),
            ),
        ]);
    }
    Ok(grants)
}
impl GeneratedAuthorities {
    pub(super) fn configure_peer(
        &self,
        rendered: &str,
        chain_discriminant: Option<u16>,
        root: &Path,
        peer_index: usize,
    ) -> Result<Zeroizing<String>> {
        ensure!(
            peer_index < 4,
            "provider peer index exceeds original committee"
        );
        let mut table = crate::secret_toml::Table::new(crate::secret_toml::parse_table(
            rendered,
            "generated service authority config",
        )?);
        let gov = table
            .entry("gov")
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
            .ok_or_else(|| eyre!("generated governance config is not a table"))?;
        ensure!(
            !gov.contains_key("sorafs_provider_owners"),
            "generated provider owner seed is already present"
        );
        let mut owners = toml::Table::new();
        for provider in &self.providers {
            owners.insert(
                hex::encode(provider.provider_id.as_bytes()),
                toml::Value::String(account_id_runtime_literal(
                    &provider.authorities[0].1.account_id,
                    chain_discriminant,
                )),
            );
        }
        gov.insert("sorafs_provider_owners".into(), toml::Value::Table(owners));
        provider_material::configure_peer_https(
            self.providers
                .get(peer_index)
                .map(|entry| (&entry.provider, entry.slot)),
            &mut table,
            root,
            peer_index,
        )?;
        toml::to_string(&*table)
            .map(Zeroizing::new)
            .map_err(|_| eyre!("cannot encode service authority config"))
    }
    fn inventories(
        &self,
    ) -> Result<(
        NetworkServiceInventory,
        [ProviderServiceInventory; PROVIDER_COUNT],
    )> {
        let network = NetworkServiceInventory {
            authorities: self
                .authorities
                .iter()
                .map(|(role, identity)| NetworkServiceAuthority {
                    role: *role,
                    account: identity.account_id.clone(),
                })
                .collect(),
            reserve_accounts: reserve_accounts(&self.authorities[0].1.account_id)?,
            network_plan: self.network.bytes()?,
            publication_plan: self.publication.bytes()?,
        };
        let providers = self
            .providers
            .iter()
            .map(|entry| {
                Ok(ProviderServiceInventory {
                    slot: entry.slot,
                    provider_id: entry.provider_id,
                    authorities: entry
                        .authorities
                        .iter()
                        .map(|(role, identity)| StreamTokenAuthority {
                            role: *role,
                            account: identity.account_id.clone(),
                        })
                        .collect(),
                    provider_plan: entry.provider.bytes()?,
                    compliance_plan: entry.compliance.bytes()?,
                })
            })
            .collect::<Result<Vec<_>>>()?
            .try_into()
            .map_err(|_| eyre!("generated provider count differs"))?;
        Ok((network, providers))
    }
    fn manifest(
        &self,
        network_id: NetworkId,
        manager: &AccountId,
    ) -> Result<StreamTokenAuthorityManifest> {
        let (network, providers) = self.inventories()?;
        Ok(StreamTokenAuthorityManifest {
            network_id,
            manager: manager.clone(),
            network,
            providers,
        })
    }
    pub(super) fn creation_time_ms(&self) -> u64 {
        self.network.creation_time_ms
    }
    pub(super) fn append_genesis(
        &self,
        genesis: RawGenesisTransaction,
        manager: &AccountId,
        genesis_authority: &AccountId,
    ) -> Result<RawGenesisTransaction> {
        use iroha_data_model::isi::sorafs::{
            InitializeSorafsProviderAdmissionV1, SetPricingSchedule,
        };
        use iroha_executor_data_model::permission::sorafs::CanSetSorafsPricing;
        let (network, providers) = self.inventories()?;
        let mut accounts = self
            .authorities
            .iter()
            .map(|(role, identity)| {
                Account::new(identity.account_id.clone()).with_metadata(role_metadata(*role))
            })
            .collect::<Vec<_>>();
        for provider in &self.providers {
            accounts.extend(provider.authorities.iter().map(|(role, identity)| {
                Account::new(identity.account_id.clone()).with_metadata(role_metadata(*role))
            }));
        }
        accounts.extend([
            Account::new(network.reserve_accounts.custody.clone())
                .with_metadata(role_metadata(ReserveAccountRole::ReserveCustody)),
            Account::new(network.reserve_accounts.treasury.clone())
                .with_metadata(role_metadata(ReserveAccountRole::ReserveTreasury)),
        ]);
        let genesis = append_localnet_service_accounts(genesis, &accounts)?;
        let mut builder = genesis.into_builder();
        for (_, identity) in &self.authorities {
            builder = builder.append_instruction(Mint::asset_quantity(
                LOCALNET_ALIAS_SETUP_PAYER_BALANCE,
                AssetId::new(
                    localnet_xor_asset_definition_id(),
                    identity.account_id.clone(),
                ),
            ));
        }
        for provider in &self.providers {
            let issuer_endowment = provider
                .provider
                .initial_issuer_endowment(&self.network.pricing)?;
            for (role, identity) in &provider.authorities {
                if role.transacts() {
                    let amount = if *role == StreamTokenAuthorityRole::IssuerOperator {
                        issuer_endowment.clone()
                    } else {
                        Quantity::from(LOCALNET_ALIAS_SETUP_PAYER_BALANCE)
                    };
                    builder = builder.append_instruction(Mint::asset_quantity(
                        amount,
                        AssetId::new(
                            localnet_xor_asset_definition_id(),
                            identity.account_id.clone(),
                        ),
                    ));
                }
            }
        }
        for (account, permission) in grants(manager, &network, &providers)? {
            builder = builder.append_instruction(Grant::account_permission(permission, account));
        }
        let mut admissions = self
            .providers
            .iter()
            .map(|entry| entry.provider.initializer_entry())
            .collect::<Result<Vec<_>>>()?;
        admissions.sort_by_key(|entry| entry.0);
        let genesis = builder
            .append_instruction(Grant::account_permission(
                Permission::from(CanSetSorafsPricing),
                genesis_authority.clone(),
            ))
            .append_instruction(SetPricingSchedule::new(self.network.pricing.clone()))
            .append_instruction(Revoke::account_permission(
                Permission::from(CanSetSorafsPricing),
                genesis_authority.clone(),
            ))
            .append_instruction(InitializeSorafsProviderAdmissionV1 {
                council: self.network.council.clone(),
                providers: admissions.into_iter().map(|(_, entry)| entry).collect(),
            })
            .append_instruction(SetKeyValue::account(
                manager.clone(),
                MATERIAL_METADATA
                    .parse()
                    .expect("static service material key"),
                Json::new(profile_commitment(manager, &network, &providers)?),
            ))
            .build_raw()?;
        compliance_material::append_operator_role(genesis, manager)
    }
    pub(super) fn publish(
        &self,
        root: &Path,
        genesis: HashOf<BlockHeader>,
        manager: &AccountId,
    ) -> Result<()> {
        let manifest = self.manifest(NetworkId::from_genesis_hash(genesis), manager)?;
        let bytes = norito::json::to_vec(&manifest)?;
        ensure!(
            bytes.len() <= MAX_MANIFEST,
            "authority manifest exceeds byte bound"
        );
        custody::write(
            root.join(LOCALNET_RUNTIME_DIRECTORY)
                .join(DIRECTORY)
                .join(MANIFEST),
            bytes,
        )
    }
}

impl PreparedLocalnet {
    /// Recover the exact original singleton publication intent after full profile validation.
    ///
    /// This does not open custody, install a listener or grant current native authority.
    /// Standard/private profiles contain no publication selection.
    /// # Errors
    /// Refuses changed original genesis, roles, TLS material, session, ports or limits.
    pub fn publication_service_plan(
        &self,
    ) -> crate::managed::Result<Option<RetainedPublicationServicePlan>> {
        validate_retained(self)?
            .map(|manifest| publication_material::retained(self, &manifest))
            .transpose()
            .map_err(|_| Error::Invalid("retained generated publication plan differs".into()))
    }

    /// Recover original compliance selections bound to the actual authenticated network.
    ///
    /// This provides original trust, not a current catalog, operator permission or serving state.
    /// Its finite material interval is never renewed. Standard profiles return no plan.
    /// # Errors
    /// Refuses any original profile, trust, credential, role or genesis commitment substitution.
    pub fn gateway_compliance_plan(
        &self,
        provider: ProviderId,
    ) -> crate::managed::Result<Option<RetainedGatewayCompliancePlan>> {
        validate_retained(self)?
            .map(|manifest| compliance_material::retained(&manifest, provider))
            .transpose()
            .map_err(|_| Error::Invalid("retained generated compliance plan differs".into()))
    }

    /// Recover exact original provider selections authenticated by the entire retained profile.
    ///
    /// Current pricing, admission, backing and service readiness need their native evidence owners.
    /// # Errors
    /// Refuses substituted genesis, bounded plan, credentials, certificates, roles or configuration.
    pub fn provider_service_plan(
        &self,
        provider: ProviderId,
    ) -> crate::managed::Result<Option<RetainedProviderServicePlan>> {
        validate_retained(self)?
            .map(|manifest| provider_material::retained(&manifest, provider))
            .transpose()
            .map_err(|_| Error::Invalid("retained generated provider plan differs".into()))
    }
    /// Recover all three exact original provider plans in fixed peer order.
    /// # Errors
    /// Refuses any full-profile substitution; Standard profiles return no plans.
    pub fn provider_service_plans(
        &self,
    ) -> crate::managed::Result<Option<[RetainedProviderServicePlan; PROVIDER_COUNT]>> {
        let Some(manifest) = validate_retained(self)? else {
            return Ok(None);
        };
        let plans = manifest
            .providers
            .iter()
            .map(|entry| provider_material::retained(&manifest, entry.provider_id))
            .collect::<Result<Vec<_>>>()
            .map_err(|_| Error::Invalid("retained generated provider plans differ".into()))?;
        plans
            .try_into()
            .map(Some)
            .map_err(|_| Error::Invalid("retained provider count differs".into()))
    }
    /// Load exact retained authority prerequisites without claiming current eligibility.
    ///
    /// # Errors
    /// Rejects wrong profile/root/genesis, substituted accounts or credentials, invalid grants,
    /// malformed bounded inventory or token services enabled outside a future provisioning owner.
    pub fn stream_token_authorities(
        &self,
    ) -> crate::managed::Result<Option<StreamTokenAuthorityManifest>> {
        validate_retained(self)
    }
}

// Each private caller passes the scalar from its same-block canonical authentication.
// Profile validation keeps its original order without reconstructing completed metadata;
// the original signed block remains mandatory and no positive result is cached.
pub(super) fn validate_signed_profile(
    prepared: &PreparedLocalnet,
    block: &iroha_data_model::block::SignedBlock,
    metadata: &iroha_data_model::parameter::system::ConsensusHandshakeMetadata,
) -> crate::managed::Result<std::collections::BTreeMap<AccountId, Json>> {
    let invalid = || Error::Invalid("retained signed localnet service profile differs".into());
    block
        .validate_output_merkle_cache()
        .map_err(|_| invalid())?;
    if !block.output_results().all(|result| result.as_ref().is_ok())
        || NetworkId::from_genesis_hash(block.hash()).to_string() != prepared.context.network_id
    {
        return Err(invalid());
    }
    #[cfg(all(test, sumeragi_deploy_mutation = "DEP7"))]
    let metadata = {
        let _ = metadata;
        iroha_data_model::sumeragi_finality::signed_genesis_consensus_metadata(block)
            .map_err(|_| invalid())?
    };
    if metadata.sumeragi_context.root_scope.dataspace_id().as_u64() != prepared.context.dataspace_id
        || (metadata.sumeragi_context.root_scope == SumeragiRootScope::Global
            && prepared.context.dataspace_alias != "universal")
    {
        return Err(invalid());
    }
    // The retained literal owns its address rendering. A parent SDK operation may have
    // installed a different ambient prefix; it cannot reinterpret this domainless identity.
    let discriminant = iroha_data_model::account::address::AccountAddress::i105_discriminant(
        &prepared.context.account_id,
    )
    .map_err(|_| invalid())?;
    let _address_profile = ChainDiscriminantGuard::enter(discriminant);
    let manager = AccountId::parse_encoded(&prepared.context.account_id).map_err(|_| invalid())?;
    let expected_profile = Json::try_new(prepared.service_profile).map_err(|_| invalid())?;
    let mut found_profile = false;
    let mut registered_roles = std::collections::BTreeMap::new();
    let role_key: iroha_model_base::name::Name = ROLE_METADATA
        .parse()
        .expect("static authority metadata key");
    for transaction in block.external_transactions() {
        for instruction in transaction.instructions().explicit_instructions() {
            if let Some(iroha_data_model::isi::SetKeyValueBox::Account(set)) =
                instruction
                    .as_any()
                    .downcast_ref::<iroha_data_model::isi::SetKeyValueBox>()
                && set.key().as_ref() == PROFILE_METADATA
            {
                if found_profile || set.object() != &manager || set.value() != &expected_profile {
                    return Err(invalid());
                }
                found_profile = true;
            }
            if prepared.service_profile == LocalnetServiceProfile::Standard
                && let Some(iroha_data_model::isi::SetKeyValueBox::Account(set)) = instruction
                    .as_any()
                    .downcast_ref::<iroha_data_model::isi::SetKeyValueBox>()
                && set.key().as_ref() == MATERIAL_METADATA
            {
                return Err(invalid());
            }
            if let Some(RegisterBox::Account(register)) =
                instruction.as_any().downcast_ref::<RegisterBox>()
                && let Some(role) = register.object.metadata.get(&role_key)
                && registered_roles
                    .insert(register.object.id.clone(), role.clone())
                    .is_some()
            {
                return Err(invalid());
            }
        }
    }
    if !found_profile {
        return Err(invalid());
    }
    if prepared.service_profile == LocalnetServiceProfile::Standard {
        compliance_material::validate_standard(block).map_err(|_| invalid())?;
        if !registered_roles.is_empty() {
            return Err(invalid());
        }
        let directory = prepared
            .context
            .client_config
            .parent()
            .ok_or_else(invalid)?
            .join(LOCALNET_RUNTIME_DIRECTORY)
            .join(DIRECTORY);
        match fs::symlink_metadata(&directory) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err(invalid()),
        }
    }
    Ok(registered_roles)
}

// Private storage implementations share one syntax decoder. No public source can implement this
// trait; captured bytes and live role access preserve their own native admission boundaries.
trait ServiceKeySource {
    fn service_key(&self, filename: &str) -> crate::managed::Result<KeyPair>;
}
impl ServiceKeySource for iroha_fs::PrivateDirectory {
    fn service_key(&self, filename: &str) -> crate::managed::Result<KeyPair> {
        let invalid = || Error::Invalid("invalid original service role credential".into());
        let bytes = self
            .read(filename, MAX_ROLE_CREDENTIAL_BYTES)
            .map_err(|_| invalid())?;
        let key = decode_service_private_key(&bytes)?;
        self.revalidate().map_err(|_| invalid())?;
        Ok(key)
    }
}
fn read_service_private_key(
    directory: &impl ServiceKeySource,
    filename: &str,
) -> crate::managed::Result<KeyPair> {
    directory.service_key(filename)
}
fn decode_service_private_key(bytes: &[u8]) -> crate::managed::Result<KeyPair> {
    let invalid = || Error::Invalid("invalid original service role credential".into());
    let text = bytes
        .strip_suffix(b"\n")
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .ok_or_else(invalid)?;
    let secret = Zeroizing::new(text.to_owned());
    let exposed: ExposedPrivateKey = secret.parse().map_err(|_| invalid())?;
    if Zeroizing::new(exposed.try_to_multihash_string().map_err(|_| invalid())?).as_str() != text {
        return Err(invalid());
    }
    KeyPair::from_private_key(exposed.0).map_err(|_| invalid())
}

fn read_role_key(
    directory: &impl ServiceKeySource,
    authority: &StreamTokenAuthority,
) -> crate::managed::Result<KeyPair> {
    let key = read_service_private_key(directory, authority.role.credential_filename())?;
    if key.public_key().algorithm() != iroha_crypto::Algorithm::Ed25519
        || AccountId::new(key.public_key().clone()) != authority.account
    {
        return Err(Error::Invalid(
            "invalid original service role credential".into(),
        ));
    }
    Ok(key)
}

// Closed key readers retain native custody after the caller authenticates the complete profile.
fn read_selected_role_key(
    prepared: &PreparedLocalnet,
    manifest: &StreamTokenAuthorityManifest,
    provider: ProviderId,
    role: StreamTokenAuthorityRole,
) -> crate::managed::Result<KeyPair> {
    let selected = manifest.provider(provider)?;
    let root = prepared
        .context
        .client_config
        .parent()
        .ok_or_else(|| Error::Invalid("original generation is absent".into()))?;
    let generation = iroha_fs::PrivateDirectory::open_exact(root)?;
    let runtime = generation
        .open_child(LOCALNET_RUNTIME_DIRECTORY)?
        .open_child(DIRECTORY)?;
    let directory = open_provider_directory(&runtime, selected.slot)?;
    read_role_key(&directory, selected.authority(role)?)
}
pub(crate) fn issuer_operator_key(
    prepared: &PreparedLocalnet,
    manifest: &StreamTokenAuthorityManifest,
    provider: ProviderId,
) -> crate::managed::Result<KeyPair> {
    read_selected_role_key(
        prepared,
        manifest,
        provider,
        StreamTokenAuthorityRole::IssuerOperator,
    )
}
pub(crate) fn custody_attester_key(
    prepared: &PreparedLocalnet,
    manifest: &StreamTokenAuthorityManifest,
    provider: ProviderId,
) -> crate::managed::Result<KeyPair> {
    read_selected_role_key(
        prepared,
        manifest,
        provider,
        StreamTokenAuthorityRole::CustodyAttester,
    )
}
fn read_network_role_key(
    directory: &impl ServiceKeySource,
    authority: &NetworkServiceAuthority,
) -> crate::managed::Result<KeyPair> {
    let key = read_service_private_key(directory, authority.role.credential_filename())?;
    if key.public_key().algorithm() != iroha_crypto::Algorithm::Ed25519
        || AccountId::new(key.public_key().clone()) != authority.account
    {
        return Err(Error::Invalid(
            "invalid original network role credential".into(),
        ));
    }
    Ok(key)
}
pub(crate) fn reserve_operations_key(
    prepared: &PreparedLocalnet,
    manifest: &StreamTokenAuthorityManifest,
) -> crate::managed::Result<KeyPair> {
    let root = prepared
        .context
        .client_config
        .parent()
        .ok_or_else(|| Error::Invalid("original generation is absent".into()))?;
    let generation = iroha_fs::PrivateDirectory::open_exact(root)?;
    let directory = generation
        .open_child(LOCALNET_RUNTIME_DIRECTORY)?
        .open_child(DIRECTORY)?
        .open_child(NETWORK_DIRECTORY)?;
    read_network_role_key(
        &directory,
        manifest
            .network
            .authority(NetworkServiceAuthorityRole::ReserveOperations)?,
    )
}
fn require_entries(
    directory: &iroha_fs::PrivateDirectory,
    expected: impl IntoIterator<Item = std::ffi::OsString>,
) -> crate::managed::Result<()> {
    let expected = expected.into_iter().collect::<BTreeSet<_>>();
    if directory
        .entries(expected.len())?
        .into_iter()
        .collect::<BTreeSet<_>>()
        != expected
    {
        return Err(Error::Invalid(
            "original service directory inventory differs".into(),
        ));
    }
    directory.revalidate()?;
    Ok(())
}

/// Private original intent plus its complete native byte custody. No positive current-state cache.
pub(crate) struct RetainedServiceProfile {
    image: capture::CapturedProfile,
    prepared: PreparedLocalnet,
    manifest: StreamTokenAuthorityManifest,
    plans: [RetainedProviderServicePlan; PROVIDER_COUNT],
    // Public original client intent retained by the same one-time canonical parse.
    chain: String,
    address_discriminant: u16,
}

/// Typed original constructor outputs retained by one canonical profile validation.
pub(crate) struct ValidatedServiceProfile {
    pub(crate) retained: RetainedServiceProfile,
    pub(crate) config: iroha::config::Config,
    pub(crate) genesis: crate::verify::finality::GenesisAnchor,
    pub(crate) peer_ids: [iroha_model_base::peer::PeerId; 4],
}
#[cfg(test)]
pub(crate) fn count_profile_images<T>(action: impl FnOnce() -> T) -> (T, usize) {
    capture::count_revalidations(action)
}

impl RetainedServiceProfile {
    pub(crate) fn manifest(&self) -> &StreamTokenAuthorityManifest {
        &self.manifest
    }
    pub(crate) fn runtime(&self) -> &iroha_fs::PrivateDirectory {
        self.image.runtime()
    }
    pub(crate) fn revalidate(
        &self,
        prepared: &PreparedLocalnet,
        manifest: &StreamTokenAuthorityManifest,
    ) -> crate::managed::Result<()> {
        if prepared != &self.prepared || manifest != &self.manifest {
            return Err(Error::Invalid(
                "original service authority profile changed".into(),
            ));
        }
        self.image.revalidate()
    }
    // These are original public intents only. ServiceAuthority validates full custody before use.
    pub(crate) fn original_plans(&self) -> &[RetainedProviderServicePlan; PROVIDER_COUNT] {
        &self.plans
    }
    pub(crate) fn original_compliance_plan(
        &self,
        provider: ProviderId,
    ) -> crate::managed::Result<RetainedGatewayCompliancePlan> {
        compliance_material::retained(&self.manifest, provider)
            .map_err(|_| Error::Invalid("retained generated compliance plan differs".into()))
    }
    pub(crate) fn original_publication_plan(
        &self,
    ) -> crate::managed::Result<RetainedPublicationServicePlan> {
        let generation = self
            .prepared
            .context
            .client_config
            .parent()
            .ok_or_else(|| Error::Invalid("original publication generation is absent".into()))?;
        publication_material::retained_from_parts(
            &self.manifest,
            &self.chain,
            self.address_discriminant,
            generation,
        )
        .map_err(|_| Error::Invalid("retained generated publication plan differs".into()))
    }
    pub(crate) fn original_plan(
        &self,
        provider: ProviderId,
    ) -> crate::managed::Result<RetainedProviderServicePlan> {
        self.plans
            .iter()
            .find(|plan| plan.provider_id() == provider)
            .cloned()
            .ok_or_else(|| Error::Invalid("selected service provider plan is absent".into()))
    }
}

#[cfg(test)]
pub(crate) fn count_profile_validations<T>(action: impl FnOnce() -> T) -> (T, usize) {
    capture::count_semantic_validations(action)
}

// Exact original role allocation: one canonical XOR mint of the owner-derived quantity.
// Requiring a matching mint alone would permit a second oversized mint to hide the mismatch.
fn validate_genesis_funding<'a>(
    expected: &std::collections::BTreeMap<AccountId, Quantity>,
    reserves: &StreamTokenReserveAccounts,
    instructions: impl IntoIterator<Item = &'a InstructionBox>,
) -> crate::managed::Result<()> {
    let invalid = || Error::Invalid("invalid original service genesis funding".into());
    let mut funded = BTreeSet::new();
    for instruction in instructions {
        if let Some(MintBox::Asset(mint)) = instruction.as_any().downcast_ref::<MintBox>() {
            let account = mint.destination().account();
            if account == &reserves.custody || account == &reserves.treasury {
                return Err(invalid());
            }
            if let Some(amount) = expected.get(account) {
                if mint.destination()
                    != &AssetId::new(localnet_xor_asset_definition_id(), account.clone())
                    || mint.object() != amount
                    || !funded.insert(account.clone())
                {
                    return Err(invalid());
                }
            }
        }
    }
    if funded.len() != expected.len() {
        return Err(invalid());
    }
    Ok(())
}

pub(crate) fn validate_retained(
    prepared: &PreparedLocalnet,
) -> crate::managed::Result<Option<StreamTokenAuthorityManifest>> {
    capture_retained(prepared).map(|profile| profile.map(|profile| profile.retained.manifest))
}

pub(crate) fn capture_retained(
    prepared: &PreparedLocalnet,
) -> crate::managed::Result<Option<ValidatedServiceProfile>> {
    let invalid =
        || Error::Invalid("retained stream-token authority prerequisites are invalid".into());
    let root = prepared
        .context
        .client_config
        .parent()
        .ok_or_else(invalid)?;
    if prepared.context.client_config.file_name() != Some(std::ffi::OsStr::new("client.toml"))
        || prepared.peers.len() != 4
        || prepared
            .peers
            .iter()
            .enumerate()
            .any(|(index, peer)| peer.config_path != root.join(format!("peer{index}.toml")))
    {
        return Err(invalid());
    }
    init_instruction_registry();
    let generation = iroha_fs::PrivateDirectory::open_exact(root)?;
    if prepared.service_profile == LocalnetServiceProfile::Standard {
        let bytes = generation.read("genesis.signed.nrt", SIGNED_GENESIS_MAX_BYTES_V1)?;
        let block =
            iroha_data_model::block::decode_framed_signed_block(&bytes).map_err(|_| invalid())?;
        let metadata = iroha_data_model::sumeragi_finality::authenticated_genesis(&block)
            .map_err(|_| invalid())?
            .metadata();
        validate_signed_profile(prepared, &block, &metadata)?;
        generation.revalidate()?;
        return Ok(None);
    }
    let image = capture::CapturedProfile::open(generation)?;
    #[cfg(test)]
    capture::record_semantic_validation();
    let block = iroha_data_model::block::decode_framed_signed_block(
        image
            .generation()
            .read("genesis.signed.nrt", SIGNED_GENESIS_MAX_BYTES_V1)?,
    )
    .map_err(|_| invalid())?;
    let authenticated = iroha_data_model::sumeragi_finality::authenticated_genesis(&block)
        .map_err(|_| invalid())?;
    let metadata = authenticated.metadata();
    let epoch = authenticated.into_parts().0;
    let registered_roles = validate_signed_profile(prepared, &block, &metadata)?;
    if prepared.context.dataspace_id != 0
        || prepared.context.dataspace_alias != "universal"
        || registered_roles.len() != NETWORK_ROLES.len() + PROVIDER_COUNT * ROLES.len() + 2
    {
        return Err(invalid());
    }
    let (client, _) = iroha::config::Config::load_bytes_with_musubi_publication_and_file_source(
        &prepared.context.client_config,
        image.client_bytes()?,
        &image,
    )
    .map_err(|_| Error::Invalid("managed client configuration is invalid".into()))?;
    prepared.context.validate_client_config(&client)?;
    let _address_profile = ChainDiscriminantGuard::enter(client.account_chain_discriminant);
    let retained = image.authority();
    let network_directory = image.network();
    let bytes = retained.read(MANIFEST, MAX_MANIFEST)?;
    let manifest: StreamTokenAuthorityManifest =
        norito::json::from_slice(bytes).map_err(|_| invalid())?;
    if manifest.network_id.to_string() != prepared.context.network_id
        || manifest.manager != client.account
        || manifest.network_id != client.network_id
    {
        return Err(invalid());
    }
    let operations = &manifest
        .network
        .authority(NetworkServiceAuthorityRole::ReserveOperations)?
        .account;
    let network = network_material::NetworkServicePlanV1::decode(&manifest.network.network_plan)
        .map_err(|_| invalid())?;
    network.validate(operations).map_err(|_| invalid())?;
    network
        .council
        .bind(*manifest.network_id.as_bytes())
        .map_err(|_| invalid())?;
    if manifest.network.reserve_accounts != reserve_accounts(operations).map_err(|_| invalid())? {
        return Err(invalid());
    }
    let mut unique_accounts = BTreeSet::from([manifest.manager.clone()]);
    let mut tls_keys = BTreeSet::new();
    let mut keys = BTreeSet::from([manifest
        .manager
        .try_signatory()
        .ok_or_else(invalid)?
        .clone()]);
    for (account, role) in [
        (
            &manifest.network.reserve_accounts.custody,
            ReserveAccountRole::ReserveCustody,
        ),
        (
            &manifest.network.reserve_accounts.treasury,
            ReserveAccountRole::ReserveTreasury,
        ),
    ] {
        if !unique_accounts.insert(account.clone())
            || !keys.insert(account.try_signatory().ok_or_else(invalid)?.clone())
            || registered_roles.get(account) != Some(&Json::new(role))
        {
            return Err(invalid());
        }
    }
    let mut expected_funding = std::collections::BTreeMap::new();
    for role in NETWORK_ROLES {
        let authority = manifest.network.authority(role)?;
        if !unique_accounts.insert(authority.account.clone())
            || !keys.insert(
                authority
                    .account
                    .try_signatory()
                    .ok_or_else(invalid)?
                    .clone(),
            )
            || registered_roles.get(&authority.account) != Some(&Json::new(role))
        {
            return Err(invalid());
        }
        read_network_role_key(network_directory, authority)?;
        expected_funding.insert(
            authority.account.clone(),
            Quantity::from(LOCALNET_ALIAS_SETUP_PAYER_BALANCE),
        );
    }
    network
        .validate_keys(network_directory, &mut keys)
        .map_err(|_| invalid())?;
    let mut provider_ids = BTreeSet::new();
    for (slot, provider) in manifest.providers.iter().enumerate() {
        if usize::from(provider.slot) != slot || !provider_ids.insert(provider.provider_id) {
            return Err(invalid());
        }
        let directory = image.provider(provider.slot)?;
        for role in ROLES {
            let authority = provider.authority(role)?;
            if !unique_accounts.insert(authority.account.clone())
                || !keys.insert(
                    authority
                        .account
                        .try_signatory()
                        .ok_or_else(invalid)?
                        .clone(),
                )
                || registered_roles.get(&authority.account) != Some(&Json::new(role))
            {
                return Err(invalid());
            }
            read_role_key(directory, authority)?;
            if role.transacts() {
                expected_funding.insert(
                    authority.account.clone(),
                    Quantity::from(LOCALNET_ALIAS_SETUP_PAYER_BALANCE),
                );
            }
        }
        if provider_scope(
            provider
                .authority(StreamTokenAuthorityRole::IssuerOperator)?
                .account
                .try_signatory()
                .ok_or_else(invalid)?,
        )
        .map_err(|_| invalid())?
            != provider.provider_id
        {
            return Err(invalid());
        }
        let issuer_endowment = provider_material::validate_retained(
            directory,
            provider,
            &network,
            &mut keys,
            &mut tls_keys,
        )
        .map_err(|_| invalid())?;
        expected_funding.insert(
            provider
                .authority(StreamTokenAuthorityRole::IssuerOperator)?
                .account
                .clone(),
            issuer_endowment,
        );
        compliance_material::validate_retained(
            directory,
            &manifest,
            provider,
            network.creation_time_ms,
            &mut keys,
        )
        .map_err(|_| invalid())?;
    }
    publication_material::validate_retained(&manifest, &network).map_err(|_| invalid())?;
    if metadata.sumeragi_context.root_scope != SumeragiRootScope::Global
        || NetworkId::from_genesis_hash(block.hash()) != manifest.network_id
    {
        return Err(invalid());
    }
    validate_genesis_material(&manifest, &network, &block).map_err(|_| invalid())?;
    compliance_material::validate_operator_role(&block, &manifest.manager)
        .map_err(|_| invalid())?;
    let mut accounts = BTreeSet::new();
    let mut remaining =
        grants(&manifest.manager, &manifest.network, &manifest.providers).map_err(|_| invalid())?;
    for transaction in block.external_transactions() {
        for instruction in transaction.instructions().explicit_instructions() {
            if let Some(RegisterBox::Account(register)) =
                instruction.as_any().downcast_ref::<RegisterBox>()
            {
                accounts.insert(register.object.id.clone());
            }
            if let Some(GrantBox::Permission(grant)) =
                instruction.as_any().downcast_ref::<GrantBox>()
            {
                remaining.retain(|(account, permission)| {
                    grant.destination() != account || grant.object() != permission
                });
                if matches!(
                    grant.object().name().as_ref(),
                    "CanOperateSorafsStreamTokenGateway" | "CanCheckSorafsStreamTokenGateway"
                ) {
                    return Err(invalid());
                }
            }
        }
    }
    validate_genesis_funding(
        &expected_funding,
        &manifest.network.reserve_accounts,
        block
            .external_transactions()
            .flat_map(|transaction| transaction.instructions().explicit_instructions()),
    )
    .map_err(|_| invalid())?;
    if !remaining.is_empty() || !unique_accounts.is_subset(&accounts) {
        return Err(invalid());
    }
    let owners = manifest
        .providers
        .iter()
        .map(|provider| {
            Ok((
                provider.provider_id,
                provider
                    .authority(StreamTokenAuthorityRole::IssuerOperator)?
                    .account
                    .clone(),
            ))
        })
        .collect::<crate::managed::Result<std::collections::BTreeMap<_, _>>>()?;
    if epoch.network_id != client.network_id {
        return Err(invalid());
    }
    let expected: BTreeSet<_> = epoch
        .committee
        .iter()
        .map(|member| member.validator.clone())
        .collect();
    let mut peer_ids = Vec::with_capacity(4);
    for (index, peer) in prepared.peers.iter().enumerate() {
        let config = image.parse_peer(&peer.config_path, &format!("peer{index}.toml"))?;
        let peer_id =
            iroha_model_base::peer::PeerId::new(config.common.key_pair.public_key().clone());
        if !expected.contains(&peer_id) {
            return Err(invalid());
        }
        peer_ids.push(peer_id);
        provider_material::validate_peer_https(
            &manifest,
            root,
            index,
            config.torii.transport.https.as_ref(),
        )
        .map_err(|_| invalid())?;
        if config.musubi_publication.installation.is_some()
            || config.genesis.expected_hash != block.hash()
            || config.gov.sorafs_provider_owners != owners
            || configured_execution_policy(&config).map_err(|_| invalid())?
                != Hash::prehashed(metadata.sumeragi_context.execution_policy_hash)
            || config.torii.sorafs_storage.native_transaction_signers
                != actual::SorafsNativeTransactionSignerBindings::default()
            || config.torii.sorafs_storage.stream_tokens.enabled
            || config.torii.sorafs_storage.stream_tokens.signer.is_some()
            || config
                .torii
                .sorafs_storage
                .stream_tokens
                .admission_native
                .is_some()
        {
            return Err(invalid());
        }
    }
    if peer_ids.len() != expected.len()
        || peer_ids.iter().cloned().collect::<BTreeSet<_>>() != expected
    {
        return Err(invalid());
    }
    let validators = epoch
        .committee
        .iter()
        .map(
            |member| iroha_data_model::sumeragi_finality::FinalityValidator {
                public_key: member.validator.public_key().clone(),
                proof_of_possession: member.proof_of_possession.clone(),
            },
        )
        .collect();
    let plans = manifest
        .providers
        .iter()
        .map(|provider| provider_material::retained(&manifest, provider.provider_id))
        .collect::<Result<Vec<_>>>()
        .map_err(|_| invalid())?
        .try_into()
        .map_err(|_| invalid())?;
    image.revalidate()?;
    Ok(Some(ValidatedServiceProfile {
        retained: RetainedServiceProfile {
            image,
            prepared: prepared.clone(),
            manifest,
            plans,
            chain: client.chain.to_string(),
            address_discriminant: client.account_chain_discriminant,
        },
        genesis: crate::verify::finality::GenesisAnchor {
            network_id: client.network_id,
            chain_id: client.chain.to_string(),
            genesis: block,
            validators,
        },
        config: client,
        peer_ids: peer_ids.try_into().map_err(|_| invalid())?,
    }))
}

fn validate_genesis_material(
    manifest: &StreamTokenAuthorityManifest,
    network: &network_material::NetworkServicePlanV1,
    block: &iroha_data_model::block::SignedBlock,
) -> Result<()> {
    use iroha_data_model::isi::sorafs::{InitializeSorafsProviderAdmissionV1, SetPricingSchedule};
    let first = block
        .external_transactions()
        .next()
        .ok_or_else(|| eyre!("empty original genesis"))?;
    ensure!(
        u64::try_from(first.creation_time().as_millis())? == network.creation_time_ms,
        "service interval differs from original genesis time"
    );
    let mut providers = manifest
        .providers
        .iter()
        .map(provider_material::initialization_entry)
        .collect::<Result<Vec<_>>>()?;
    providers.sort_by_key(|entry| entry.0);
    let initializer = InitializeSorafsProviderAdmissionV1 {
        council: network.council.clone(),
        providers: providers.into_iter().map(|(_, entry)| entry).collect(),
    };
    let commitment = Json::new(profile_commitment(
        &manifest.manager,
        &manifest.network,
        &manifest.providers,
    )?);
    let mut counts = (0, 0, 0);
    for transaction in block.external_transactions() {
        for instruction in transaction.instructions().explicit_instructions() {
            if let Some(value) = instruction
                .as_any()
                .downcast_ref::<InitializeSorafsProviderAdmissionV1>()
            {
                ensure!(
                    *value == initializer,
                    "original aggregate provider initialization differs"
                );
                counts.0 += 1;
            }
            if let Some(value) = instruction.as_any().downcast_ref::<SetPricingSchedule>() {
                ensure!(
                    value.schedule == network.pricing,
                    "original shared pricing differs"
                );
                counts.1 += 1;
            }
            if let Some(iroha_data_model::isi::SetKeyValueBox::Account(value)) = instruction
                .as_any()
                .downcast_ref::<iroha_data_model::isi::SetKeyValueBox>()
                && value.key().as_ref() == MATERIAL_METADATA
            {
                ensure!(
                    value.object() == &manifest.manager && value.value() == &commitment,
                    "original service material commitment differs"
                );
                counts.2 += 1;
            }
            if let Some(iroha_data_model::isi::RemoveKeyValueBox::Account(value)) = instruction
                .as_any()
                .downcast_ref::<iroha_data_model::isi::RemoveKeyValueBox>()
            {
                ensure!(
                    value.key().as_ref() != MATERIAL_METADATA,
                    "original service material commitment was removed"
                );
            }
        }
    }
    ensure!(
        counts == (1, 1, 1),
        "aggregate service initialization is incomplete or repeated"
    );
    Ok(())
}

// Reuse the canonical runtime policy owners; no native genesis execution or cached authority is
// needed on a retained reopen. The closed profile has no external compliance policy source.
pub(crate) fn configured_execution_policy(config: &actual::Root) -> Result<Hash> {
    ensure!(
        !config.nexus.compliance.enabled,
        "service authority profile cannot select an external compliance policy"
    );
    let manifests = iroha_core::governance::manifest::LaneManifestRegistry::from_config(
        &config.nexus.lane_catalog,
        &config.nexus.governance,
        &config.nexus.registry,
    );
    manifests
        .validate_active_coverage_for_catalog(&config.nexus.lane_catalog)
        .map_err(|_| eyre!("service authority lane policies are invalid"))?;
    let nexus = actual::nexus_consensus_policy_digest_with_runtime_policies(
        &config.nexus,
        None,
        Some(manifests.baseline_consensus_policy_digest()),
    )
    .map_err(|_| eyre!("service authority Nexus policy is invalid"))?;
    Ok(Hash::prehashed(actual::execution_policy_digest_v1(
        &config.pipeline,
        &config.oracle,
        &config.crypto,
        &config.fraud_monitoring,
        &config.gov,
        &config.content,
        &config.settlement,
        nexus,
        iroha_core::state::compute_zk_consensus_policy_hash(&config.zk),
    )))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod credentials_tests;

#[cfg(test)]
mod funding_tests;
#[cfg(test)]
mod native_roles_tests;

#[cfg(test)]
mod topology_tests;

#[cfg(test)]
mod manifest_codec_tests {
    use super::*;

    // Codec inputs only; these generated public accounts do not constitute an admitted profile.
    fn account(seed: u8) -> AccountId {
        AccountId::new(iroha_crypto::derive_non_signing_ed25519_public_key(
            b"iroha:localnet:service-manifest-codec-test:v1",
            &[&[seed]],
        ))
    }

    fn manifest() -> StreamTokenAuthorityManifest {
        StreamTokenAuthorityManifest {
            network_id: NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
                iroha_data_model::block::BlockHeader,
            >::from_untyped_unchecked(
                Hash::new([0xA5; Hash::LENGTH])
            )),
            manager: account(0),
            network: NetworkServiceInventory {
                authorities: NETWORK_ROLES
                    .into_iter()
                    .enumerate()
                    .map(|(index, role)| NetworkServiceAuthority {
                        role,
                        account: account(u8::try_from(index + 1).unwrap()),
                    })
                    .collect(),
                reserve_accounts: StreamTokenReserveAccounts {
                    custody: account(u8::try_from(NETWORK_ROLES.len() + 1).unwrap()),
                    treasury: account(u8::try_from(NETWORK_ROLES.len() + 2).unwrap()),
                },
                network_plan: vec![1, 2, 3],
                // Canonical opaque codec input only, not an admitted PublicationPlanV1.
                publication_plan: norito::encode_canonical(&NetworkServiceAuthorityRole::MusubiPin)
                    .unwrap(),
            },
            providers: std::array::from_fn(|slot| ProviderServiceInventory {
                slot: u8::try_from(slot).unwrap(),
                provider_id: ProviderId::new([u8::try_from(slot + 1).unwrap(); 32]),
                authorities: ROLES
                    .into_iter()
                    .enumerate()
                    .map(|(index, role)| StreamTokenAuthority {
                        role,
                        account: account(
                            u8::try_from(NETWORK_ROLES.len() + 3 + slot * ROLES.len() + index)
                                .unwrap(),
                        ),
                    })
                    .collect(),
                provider_plan: vec![u8::try_from(slot).unwrap(), 0x11],
                compliance_plan: vec![0x22, u8::try_from(slot).unwrap()],
            }),
        }
    }

    fn assert_identity<T: norito::NoritoSchema>(expected: &'static str) {
        assert_eq!(T::nominal_name(), expected);
        assert_eq!(T::frame_name(), expected);
        assert_eq!(T::static_nominal_name(), Some(expected));
        assert_eq!(T::static_frame_name(), Some(expected));
    }

    #[test]
    fn authority_inventory_schema_names_are_exact_canonical_identities() {
        assert_identity::<StreamTokenAuthorityRole>(
            "iroha_deploy::localnet::service_authorities::StreamTokenAuthorityRole",
        );
        assert_identity::<StreamTokenAuthority>(
            "iroha_deploy::localnet::service_authorities::StreamTokenAuthority",
        );
        assert_identity::<StreamTokenReserveAccounts>(
            "iroha_deploy::localnet::service_authorities::StreamTokenReserveAccounts",
        );
        assert_identity::<NetworkServiceAuthorityRole>(
            "iroha_deploy::localnet::service_authorities::NetworkServiceAuthorityRole",
        );
        assert_identity::<NetworkServiceAuthority>(
            "iroha_deploy::localnet::service_authorities::NetworkServiceAuthority",
        );
        assert_identity::<NetworkServiceInventory>(
            "iroha_deploy::localnet::service_authorities::NetworkServiceInventory",
        );
        assert_identity::<ProviderServiceInventory>(
            "iroha_deploy::localnet::service_authorities::ProviderServiceInventory",
        );
    }

    #[test]
    fn manifest_provider_json_preserves_original_order_and_exact_bounded_bytes() {
        let original = manifest();
        let accounts: BTreeSet<_> = std::iter::once(&original.manager)
            .chain(
                original
                    .network
                    .authorities
                    .iter()
                    .map(|role| &role.account),
            )
            .chain([
                &original.network.reserve_accounts.custody,
                &original.network.reserve_accounts.treasury,
            ])
            .chain(
                original
                    .providers
                    .iter()
                    .flat_map(|provider| provider.authorities.iter().map(|role| &role.account)),
            )
            .collect();
        assert_eq!(
            accounts.len(),
            1 + NETWORK_ROLES.len() + 2 + PROVIDER_COUNT * ROLES.len()
        );
        let ordinary = norito::json::to_json(&original).unwrap();
        let decoded: StreamTokenAuthorityManifest = norito::json::from_json(&ordinary).unwrap();
        assert_eq!(decoded, original);
        for (slot, provider) in decoded.providers.iter().enumerate() {
            assert_eq!(usize::from(provider.slot), slot);
            assert_eq!(provider, &original.providers[slot]);
        }
        assert_eq!(
            norito::json::to_json_bounded(&original, ordinary.len()).unwrap(),
            ordinary
        );
        assert!(matches!(
            norito::json::to_json_bounded(&original, ordinary.len() - 1),
            Err(norito::json::BoundedJsonError::BodyTooLarge)
        ));
    }

    #[test]
    fn manifest_provider_json_refuses_incomplete_or_extended_fixed_inventory() {
        let original = manifest();
        let provider = norito::json::to_value(&original.providers[0]).unwrap();
        for count in [0, 1, 2, 4] {
            let mut hostile = norito::json::to_value(&original).unwrap();
            let providers = hostile
                .as_object_mut()
                .and_then(|object| object.get_mut("providers"))
                .and_then(norito::json::Value::as_array_mut)
                .unwrap();
            providers.clear();
            providers.extend(std::iter::repeat_n(provider.clone(), count));
            assert!(
                norito::json::from_value::<StreamTokenAuthorityManifest>(hostile).is_err(),
                "accepted {count} original provider inventories"
            );
        }
    }

    #[test]
    fn manifest_provider_json_keeps_strict_fields_and_original_slot_validation() {
        let original = manifest();
        let mut hostile = norito::json::to_value(&original).unwrap();
        let providers = hostile
            .as_object_mut()
            .and_then(|object| object.get_mut("providers"))
            .and_then(norito::json::Value::as_array_mut)
            .unwrap();
        providers[0]
            .as_object_mut()
            .unwrap()
            .insert("extra".to_owned(), norito::json::Value::Bool(true));
        assert!(norito::json::from_value::<StreamTokenAuthorityManifest>(hostile).is_err());

        let mut reordered = original;
        reordered.providers.swap(0, 1);
        let decoded: StreamTokenAuthorityManifest =
            norito::json::from_json(&norito::json::to_json(&reordered).unwrap()).unwrap();
        assert!(decoded.provider(decoded.providers[0].provider_id).is_err());
    }

    #[test]
    fn fixed_provider_array_rejects_fourth_before_parsing_or_constructing_its_body() {
        let original = manifest();
        let mut prefix = String::new();
        provider_inventories_json::serialize(&original.providers, &mut prefix);
        assert_eq!(prefix.pop(), Some(']'));
        let fourth_comma = prefix.len();
        for fourth in [
            "{invalid-json".to_owned(),
            format!("\"{}\"", "x".repeat(MAX_MANIFEST + 1)),
        ] {
            let hostile = format!("{prefix},{fourth}]");
            let mut parser = norito::json::Parser::new(&hostile);
            let error = provider_inventories_json::deserialize(&mut parser).unwrap_err();
            assert!(matches!(
                error,
                norito::json::Error::UnexpectedCharacter {
                    found: norito::json::UnexpectedToken::Char(','),
                    byte,
                    ..
                } if byte == fourth_comma
            ));
            assert_eq!(
                parser.position(),
                0,
                "constructed a typed inventory before refusal"
            );
        }
    }

    #[test]
    fn fixed_provider_array_keeps_depth_and_resource_guards_before_inventory_decode() {
        for limits in [
            norito::DecodeLimits::new(2, usize::MAX, usize::MAX, usize::MAX, 32),
            norito::DecodeLimits::new(usize::MAX, usize::MAX, 2, usize::MAX, 32),
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 2, 32),
        ] {
            let mut parser = norito::json::Parser::new("[{},{},{}]");
            let error = norito::with_decode_limits_scope(limits, || {
                provider_inventories_json::deserialize(&mut parser)
            })
            .unwrap_err();
            assert!(
                error.is_decode_resource_limit(),
                "lost the original array guard"
            );
            assert_eq!(parser.position(), 0);
        }

        let depth = norito::json::MAX_JSON_VALUE_NESTING_DEPTH;
        let hostile = format!("[{}0{},{{}},{{}}]", "[".repeat(depth), "]".repeat(depth));
        let mut parser = norito::json::Parser::new(&hostile);
        assert!(matches!(
            provider_inventories_json::deserialize(&mut parser),
            Err(norito::json::Error::NestingDepthExceeded { .. })
        ));
        assert_eq!(parser.position(), 0);
    }

    #[test]
    fn original_fixed_provider_inventory_keeps_original_array_and_refusal_depth() {
        let original = manifest();
        let mut expected = String::new();
        provider_inventories_json::serialize(&original.providers, &mut expected);
        crate::service_checked_writer_test_support::audit(&expected, |sink| {
            provider_inventories_json::serialize_bounded(&original.providers, sink)
        });
        assert_eq!(original.providers.len(), PROVIDER_COUNT);
        for (slot, provider) in original.providers.iter().enumerate() {
            assert_eq!(usize::from(provider.slot), slot);
        }
    }
}
