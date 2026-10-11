//! Exact signed application/runtime originals selected by immutable Native build trust.

use super::*;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use iroha_crypto::{Algorithm, PublicKey, Signature};
use iroha_data_model::{
    NetworkId,
    asset::AssetDefinitionId,
    sumeragi_finality::{FinalityValidator, SumeragiFinalityVerifier, authenticated_genesis},
};
use norito::json::{Map, Value};
use std::str::FromStr as _;

include!(concat!(
    env!("OUT_DIR"),
    "/kagemusha_wallet_runtime_trust.rs"
));

#[cfg(test)]
const DOMAIN: &[u8] = b"cbsi.iroha-application-release.v1\0";
const APP_FIELDS: &[&str] = &[
    "artifacts",
    "protocol",
    "schema",
    "source",
    "toolchain_closure",
];

mod bpng;
mod cbsi;
mod session;
mod universal;
pub(crate) use session::Session;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "The immutable native build selects one configured deployment authority; unselected variants remain for other builds."
)]
enum RuntimeAuthority {
    BpngTairaV7,
    CbsiReleaseV1,
    ApplicationReleaseV1,
}

#[derive(Clone, Copy)]
pub(super) struct FinancialSelection {
    pub pack_identity: BlobV1,
    pub catalog_identity: BlobV1,
    pub producer_catalog_digest: [u8; 32],
    pub transport_identity: BlobV1,
}

impl FinancialSelection {
    pub(super) fn original(&self) -> Result<Vec<u8>> {
        // Compare an original to the genuine producer's exact canonical DATA frame.
        // This expected frame is never published, used as proof or given ownership.
        let blob = |value: BlobV1| norito::json!({"bytes":(value.bytes), "sha256":(hex::encode(value.sha256))});
        let value = norito::json!({"schema":("iroha.kagemusha.wallet-financial-originals.v1"),
            "verifierPack":(blob(self.pack_identity)), "producerInventory":(blob(self.catalog_identity)),
            "transport":(blob(self.transport_identity)), "producerCatalogDigest":(hex::encode(self.producer_catalog_digest))});
        let mut bytes = norito::json::to_json_bounded(&value, ENVELOPE_MAX - 1)
            .map_err(|_| invalid())?
            .into_bytes();
        bytes.push(b'\n');
        Ok(bytes)
    }
}

/// Construction is private to installed Native policy; offered originals cannot choose a key.
struct RuntimeTrust {
    authority: RuntimeAuthority,
    key: PublicKey,
}
impl RuntimeTrust {
    fn installed() -> Result<Self> {
        let (authority, key) =
            INSTALLED_RUNTIME_TRUST.ok_or(Failure::code(ARTIFACTS_UNAVAILABLE))?;
        Ok(Self {
            authority,
            key: PublicKey::from_bytes(Algorithm::Ed25519, &key).map_err(|_| invalid())?,
        })
    }
    #[cfg(test)]
    fn test(key: PublicKey) -> Self {
        Self {
            authority: RuntimeAuthority::CbsiReleaseV1,
            key,
        }
    }
}

struct RetainedBaseOriginals {
    _app_manifest: Box<[u8]>,
    _envelope: Box<[u8]>,
    _wallet_runtime: Box<[u8]>,
    _signed_genesis: Box<[u8]>,
}

/// Each variant retains only authority actually present in its independently signed release.
/// The BPNG runtime does not invent a CBSI service scope or a foreign catalog pin.
enum ApplicationBinding {
    ApplicationReleaseV1 {
        _registration: Box<
            iroha_core_zk::kagemusha_wallet_registration_v1::FinalizedKagemushaWalletRegistrationV1,
        >,
        _source: Box<[u8]>,
    },
    CbsiReleaseV1 {
        service_release_scope: [u8; 32],
        scheme_id: [u8; 32],
        manifest_digest: [u8; 32],
        producer_catalog_digest: [u8; 32],
        transport: BlobV1,
    },
    BpngTairaV7 {
        _wallet_runtime_sha256: [u8; 32],
    },
}

/// Authenticated application/root and shared financial selection, independent of any asset.
/// Construction stays inside signed release intake; it grants no enrollment or wallet authority.
pub(super) struct AuthenticatedBase {
    _originals: RetainedBaseOriginals,
    pub financial: Option<FinancialSelection>,
    pub scheme: KagemushaWalletSchemeV1,
    pub artifact_certificate: Vec<u8>,
    pub artifact_manifest: Vec<u8>,
    pub installation: InstallationV1,
    pub genesis: Arc<SumeragiFinalityVerifier>,
}

pub(super) struct Selection {
    pub(super) base: Arc<AuthenticatedBase>,
    application: ApplicationBinding,
    pub asset: KagemushaWalletAssetScopeV1,
    pub asset_original: Vec<u8>,
    pub android_app_policy: [u8; 32],
    android_enrollment: (
        KagemushaWalletAppPolicyV1,
        KagemushaWalletEnrollmentPolicyV1,
    ),
    apple_enrollment: (
        KagemushaWalletAppPolicyV1,
        KagemushaWalletEnrollmentPolicyV1,
    ),
    enrollment_certificate: KagemushaWalletSignerCertificateV1,
    fi_sessions: Vec<session::FiAuthority>,
    bpng_session: Option<session::BpngAuthority>,
    pub apple_app_policy: [u8; 32],
}

fn invalid() -> Failure {
    Failure::code(INVALID)
}
pub(super) fn bounded(bytes: &[u8], maximum: usize) -> Result<&[u8]> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(invalid());
    }
    Ok(bytes)
}
fn safe_numbers(value: &Value) -> Result<()> {
    match value {
        Value::Number(number) => {
            if !number
                .as_i64()
                .is_some_and(|v| (-9_007_199_254_740_991..=9_007_199_254_740_991).contains(&v))
                && number.as_u64().is_none_or(|v| v > 9_007_199_254_740_991)
            {
                return Err(invalid());
            }
        }
        Value::Array(values) => {
            for v in values {
                safe_numbers(v)?;
            }
        }
        Value::Object(values) => {
            for (key, v) in values {
                // The maintained schema uses ASCII property names. This keeps Native's sorted
                // writer identical to the maintained ECMAScript canonical writer.
                if !key.is_ascii() {
                    return Err(invalid());
                }
                safe_numbers(v)?;
            }
        }
        _ => {}
    }
    Ok(())
}
pub(super) fn json(bytes: &[u8], maximum: usize, canonical: bool) -> Result<Value> {
    bounded(bytes, maximum)?;
    let limits = norito::json::JsonPreflightLimits::new(
        maximum, 65_536, maximum, maximum, maximum, 16_384, 32_768, 32_768, 65_536, 32,
    );
    json_limits(bytes, maximum, canonical, limits)
}

pub(super) fn json_limits(
    bytes: &[u8],
    maximum: usize,
    canonical: bool,
    limits: norito::json::JsonPreflightLimits,
) -> Result<Value> {
    bounded(bytes, maximum)?;
    norito::json::preflight_slice(bytes, limits).map_err(|_| invalid())?;
    let value = norito::json::from_slice(bytes).map_err(|_| invalid())?;
    safe_numbers(&value)?;
    if canonical {
        let mut original = norito::json::to_json_bounded(&value, maximum.saturating_sub(1))
            .map_err(|_| invalid())?
            .into_bytes();
        original.push(b'\n');
        if original != bytes {
            return Err(invalid());
        }
    }
    Ok(value)
}
fn object(value: &Value) -> Result<&Map> {
    value.as_object().ok_or(invalid())
}
pub(super) fn exact<'a>(value: &'a Value, fields: &[&str]) -> Result<&'a Map> {
    let value = object(value)?;
    if value.len() != fields.len() || fields.iter().any(|key| !value.contains_key(*key)) {
        return Err(invalid());
    }
    Ok(value)
}
fn field<'a>(map: &'a Map, key: &str) -> Result<&'a Value> {
    map.get(key).ok_or(invalid())
}
pub(super) fn text<'a>(map: &'a Map, key: &str) -> Result<&'a str> {
    field(map, key)?.as_str().ok_or(invalid())
}
pub(super) fn sha(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
    {
        return Err(invalid());
    }
    let value: [u8; 32] = hex::decode(value)
        .map_err(|_| invalid())?
        .try_into()
        .map_err(|_| invalid())?;
    if value == [0; 32] {
        return Err(invalid());
    }
    Ok(value)
}
fn raw(map: &Map, key: &str, maximum: usize) -> Result<Vec<u8>> {
    let value = text(map, key)?;
    if value.is_empty() || value.len() > maximum.div_ceil(3) * 4 {
        return Err(invalid());
    }
    let bytes = STANDARD.decode(value).map_err(|_| invalid())?;
    bounded(&bytes, maximum)?;
    if STANDARD.encode(&bytes) != value {
        return Err(invalid());
    }
    Ok(bytes)
}
/// The Apple App Attestation root pin of an Apple policy. Android policies pin roots by SPKI
/// in their root set and select no root DER original.
pub(super) fn apple_root_pin(policy: &KagemushaWalletEnrollmentPolicyV1) -> Result<[u8; 32]> {
    match &policy.platform {
        KagemushaWalletEnrollmentPlatformV1::Apple {
            attestation_root_sha256,
        } => Ok(*attestation_root_sha256),
        KagemushaWalletEnrollmentPlatformV1::Android { .. } => Err(invalid()),
    }
}
/// Unknown and unqualified vendor adapter identifiers fail configuration (policy spec).
pub(super) fn require_qualified_adapters(
    platform: &KagemushaWalletEnrollmentPlatformV1,
) -> Result<()> {
    iroha_core_zk::kagemusha_wallet_enrollment_v1::issuer_worker::require_qualified_android_adapters_v1(
        platform,
    )
    .map_err(|_| invalid())
}
fn signed_app(trust: &RuntimeTrust, manifest: &[u8], envelope: &[u8]) -> Result<Value> {
    bounded(manifest, APP_MANIFEST_MAX)?;
    let (schema, domain, signature_field, encoding) = match trust.authority {
        RuntimeAuthority::ApplicationReleaseV1 => (
            "iroha.kagemusha.wallet-application-release-signature.v1",
            "iroha.kagemusha.wallet-application-release.v1",
            "signatureBase64",
            &STANDARD,
        ),
        RuntimeAuthority::CbsiReleaseV1 => (
            "cbsi.iroha-application-release-signature.v1",
            "cbsi.iroha-application-release.v1",
            "signatureBase64",
            &STANDARD,
        ),
        RuntimeAuthority::BpngTairaV7 => (
            "bpng.taira-app-runtime-manifest-signature.v7",
            "bpng:taira-app-runtime-manifest:v7",
            "signatureBase64Url",
            &URL_SAFE_NO_PAD,
        ),
    };
    let signature = json(envelope, ENVELOPE_MAX, true)?;
    let signature = exact(
        &signature,
        &[
            "schema",
            "algorithm",
            "domain",
            "keyId",
            "manifestSha256",
            signature_field,
        ],
    )?;
    let (_, public) = trust.key.to_bytes();
    if text(signature, "schema")? != schema
        || text(signature, "algorithm")? != "ed25519"
        || text(signature, "domain")? != domain
        || text(signature, "keyId")? != format!("sha256:{}", hex::encode(BlobV1::of(public).sha256))
        || sha(text(signature, "manifestSha256")?)? != BlobV1::of(manifest).sha256
    {
        return Err(invalid());
    }
    let encoded = text(signature, signature_field)?;
    if encoded.len() != encoding.encode([0_u8; 64]).len() {
        return Err(invalid());
    }
    let bytes = encoding.decode(encoded).map_err(|_| invalid())?;
    if bytes.len() != 64 || encoding.encode(&bytes) != encoded {
        return Err(invalid());
    }
    let mut message = Vec::with_capacity(domain.len() + 1 + manifest.len());
    message.extend_from_slice(domain.as_bytes());
    message.push(0);
    message.extend_from_slice(manifest);
    Signature::from_bytes(&bytes)
        .verify(&trust.key, &message)
        .map_err(|_| invalid())?;
    let manifest = match trust.authority {
        RuntimeAuthority::ApplicationReleaseV1 => {
            let document = json(manifest, APP_MANIFEST_MAX, true)?;
            universal::application(&document)?;
            document
        }
        RuntimeAuthority::CbsiReleaseV1 => {
            let document = cbsi::signed_document(manifest)?;
            cbsi::application(&document)?;
            document
        }
        RuntimeAuthority::BpngTairaV7 => {
            let document = json(manifest, APP_MANIFEST_MAX, true)?;
            bpng::application(&document)?;
            document
        }
    };
    Ok(manifest)
}

impl std::ops::Deref for Selection {
    type Target = AuthenticatedBase;
    fn deref(&self) -> &Self::Target {
        &self.base
    }
}
impl AuthenticatedBase {
    pub(super) fn require_producer_selection(
        &self,
        installed: &InstalledVerifierPackV1,
    ) -> Result<()> {
        let financial = self.financial.as_ref().ok_or_else(invalid)?;
        if installed.originals().producer_catalog_digest != financial.producer_catalog_digest {
            return Err(invalid());
        }
        Ok(())
    }
    pub(super) fn require_transport_selection(&self, bytes: &[u8]) -> Result<()> {
        let financial = self.financial.as_ref().ok_or_else(invalid)?;
        if BlobV1::of(bytes) != financial.transport_identity {
            return Err(invalid());
        }
        Ok(())
    }
}

impl Selection {
    pub(super) fn authenticated_base(&self) -> Result<Arc<AuthenticatedBase>> {
        if let ApplicationBinding::CbsiReleaseV1 {
            scheme_id,
            manifest_digest,
            producer_catalog_digest,
            transport,
            ..
        } = &self.application
        {
            let financial = self.financial.as_ref().ok_or_else(invalid)?;
            if self.installation.scheme_id != *scheme_id
                || self.installation.manifest_digest != *manifest_digest
                || financial.producer_catalog_digest != *producer_catalog_digest
                || financial.transport_identity != *transport
            {
                return Err(invalid());
            }
        }
        Ok(Arc::clone(&self.base))
    }
    pub(super) fn installed(input: &RuntimeOriginals<'_>) -> Result<Self> {
        Self::load(&RuntimeTrust::installed()?, input)
    }
    fn load(trust: &RuntimeTrust, input: &RuntimeOriginals<'_>) -> Result<Self> {
        input.validate_bounds()?;
        let document = signed_app(trust, input.app_manifest, input.envelope)?;
        if trust.authority == RuntimeAuthority::ApplicationReleaseV1 {
            return universal::load(&document, input);
        }
        if !input.registration_source.is_empty() {
            return Err(invalid());
        }
        let (app, application, financial) = match trust.authority {
            RuntimeAuthority::ApplicationReleaseV1 => return Err(invalid()),
            RuntimeAuthority::CbsiReleaseV1 => {
                let selected = cbsi::current(&document, input)?;
                (
                    selected.app,
                    ApplicationBinding::CbsiReleaseV1 {
                        service_release_scope: selected.service_release_scope,
                        scheme_id: selected.scheme_id,
                        manifest_digest: selected.artifact_manifest_digest,
                        producer_catalog_digest: selected.producer_catalog_digest,
                        transport: selected.transport,
                    },
                    Some(FinancialSelection {
                        pack_identity: selected.pack,
                        catalog_identity: selected.catalog,
                        producer_catalog_digest: selected.producer_catalog_digest,
                        transport_identity: selected.transport,
                    }),
                )
            }
            RuntimeAuthority::BpngTairaV7 => {
                let app = bpng::application(&document)?;
                let (digest, financial) = bpng::require_runtime(app, input)?;
                (
                    app,
                    ApplicationBinding::BpngTairaV7 {
                        _wallet_runtime_sha256: digest,
                    },
                    financial,
                )
            }
        };
        // The exact signed inventory row binds the whole public runtime original.
        let runtime = json(input.wallet_runtime, WALLET_RUNTIME_MAX, false)?;
        let mut runtime_fields = vec![
            "schema",
            "version",
            "scheme_id",
            "scheme_original_base64",
            "asset_original_base64",
            "enrollment_certificate_original_base64",
            "artifact_signer_certificate_original_base64",
            "artifact_manifest_original_base64",
            "regulatory_policy_original_base64",
            "challenge_lifetime_ms",
            "android",
            "apple",
        ];
        let runtime_schema = match trust.authority {
            RuntimeAuthority::ApplicationReleaseV1 => return Err(invalid()),
            RuntimeAuthority::CbsiReleaseV1 => "cbsi.kagemusha.wallet-runtime.v1",
            RuntimeAuthority::BpngTairaV7 => {
                runtime_fields.extend([
                    "enrollment_session",
                    "python_path",
                    "python_sha256",
                    "openssl_path",
                    "openssl_sha256",
                ]);
                "bpng.current-wallet-core-runtime.v1"
            }
        };
        let runtime = exact(&runtime, &runtime_fields)?;
        if text(runtime, "schema")? != runtime_schema
            || field(runtime, "version")?.as_u64() != Some(1)
        {
            return Err(invalid());
        }
        if trust.authority == RuntimeAuthority::BpngTairaV7 {
            bpng::runtime_tools(runtime)?;
        }
        if !field(runtime, "challenge_lifetime_ms")?
            .as_u64()
            .is_some_and(|v| (1..=600_000).contains(&v))
        {
            return Err(invalid());
        }
        let scheme = KagemushaWalletSchemeV1::decode_canonical(
            &raw(
                runtime,
                "scheme_original_base64",
                KAGEMUSHA_WALLET_SCHEME_MAX_BYTES_V1,
            )?,
            &sha(text(runtime, "scheme_id")?)?,
        )
        .map_err(|_| invalid())?;
        if let ApplicationBinding::CbsiReleaseV1 { scheme_id, .. } = &application
            && scheme.scheme_id() != *scheme_id
        {
            return Err(invalid());
        }
        let artifact_certificate = raw(
            runtime,
            "artifact_signer_certificate_original_base64",
            KAGEMUSHA_WALLET_CERTIFICATE_MAX_BYTES_V1,
        )?;
        let signer =
            KagemushaWalletSignerCertificateV1::decode_canonical(&artifact_certificate, &scheme)
                .map_err(|_| invalid())?;
        signer
            .verify_role(&scheme, KagemushaWalletSignerRoleV1::Artifact)
            .map_err(|_| invalid())?;
        let artifact_manifest = raw(
            runtime,
            "artifact_manifest_original_base64",
            KAGEMUSHA_WALLET_ARTIFACT_MANIFEST_MAX_BYTES_V1,
        )?;
        let manifest =
            KagemushaWalletArtifactManifestV1::decode_canonical(&artifact_manifest, &scheme)
                .map_err(|_| invalid())?;
        manifest.verify(&scheme, &signer).map_err(|_| invalid())?;
        if let ApplicationBinding::CbsiReleaseV1 {
            manifest_digest, ..
        } = &application
            && manifest.manifest_digest() != *manifest_digest
        {
            return Err(invalid());
        }
        let asset_original = raw(
            runtime,
            "asset_original_base64",
            iroha_core_zk::kagemusha_wallet_intake_v1::ASSET_SCOPE_ORIGINAL_MAX_BYTES_V1,
        )?;
        let asset: KagemushaWalletAssetScopeV1 = norito::decode_canonical_with_limits(
            &asset_original,
            norito::canonical_decode_limits(asset_original.len()),
        )
        .map_err(|_| invalid())?;
        asset.validate().map_err(|_| invalid())?;
        let enrollment_certificate = KagemushaWalletSignerCertificateV1::decode_canonical(
            &raw(
                runtime,
                "enrollment_certificate_original_base64",
                KAGEMUSHA_WALLET_CERTIFICATE_MAX_BYTES_V1,
            )?,
            &scheme,
        )
        .map_err(|_| invalid())?;
        enrollment_certificate
            .verify_role(&scheme, KagemushaWalletSignerRoleV1::Enrollment)
            .map_err(|_| invalid())?;
        let policy_bytes = raw(runtime, "regulatory_policy_original_base64", 4096)?;
        let regulatory_policy: KagemushaWalletRegulatoryPolicyV1 =
            norito::decode_canonical_with_limits(
                &policy_bytes,
                norito::canonical_decode_limits(policy_bytes.len()),
            )
            .map_err(|_| invalid())?;
        regulatory_policy.validate().map_err(|_| invalid())?;
        let platform_policy = |name| -> Result<(
            KagemushaWalletAppPolicyV1,
            KagemushaWalletEnrollmentPolicyV1,
        )> {
            let mut fields = vec![
                "app_policy_hex",
                "enrollment_policy_hex",
                "app_policy_original_base64",
                "enrollment_policy_original_base64",
            ];
            if trust.authority == RuntimeAuthority::BpngTairaV7 {
                fields.push("verifier_configuration_path");
                // Android roots are pinned by SPKI in the policy and a KeyMint chain carries
                // its own root; only the Apple App Attestation root is a selected DER original.
                if name == "apple" {
                    fields.push("attestation_root_der_base64");
                }
            }
            let platform = exact(field(runtime, name)?, &fields)?;
            if trust.authority == RuntimeAuthority::BpngTairaV7
                && text(platform, "verifier_configuration_path")?
                    != format!("srv/etc/kagemusha/wallet-e1-{name}.json")
            {
                return Err(invalid());
            }
            let app_digest = sha(text(platform, "app_policy_hex")?)?;
            let enrollment_digest = sha(text(platform, "enrollment_policy_hex")?)?;
            let app = KagemushaWalletAppPolicyV1::decode_canonical(
                &raw(platform, "app_policy_original_base64", 1024)?,
                &scheme.scheme_id(),
            )
            .map_err(|_| invalid())?;
            let original = raw(platform, "enrollment_policy_original_base64", 1024)?;
            let enrollment =
                KagemushaWalletEnrollmentPolicyV1::decode_canonical(&original, &scheme.scheme_id())
                    .map_err(|_| invalid())?;
            enrollment.validate_for_app(&app).map_err(|_| invalid())?;
            // A policy naming an unimplemented or unqualified vendor adapter fails
            // configuration here, before any session or challenge can select it.
            require_qualified_adapters(&enrollment.platform)?;
            if trust.authority == RuntimeAuthority::BpngTairaV7 && name == "apple" {
                let root = raw(platform, "attestation_root_der_base64", 16_384)?;
                if BlobV1::of(&root).sha256 != apple_root_pin(&enrollment)? {
                    return Err(invalid());
                }
            }
            if app.policy_digest().map_err(|_| invalid())? != app_digest
                || enrollment.policy_digest().map_err(|_| invalid())? != enrollment_digest
                || enrollment.asset_digest != asset.asset_digest()
                || enrollment.regulatory_policy != regulatory_policy
                || Some(enrollment.challenge_lifetime_ms)
                    != field(runtime, "challenge_lifetime_ms")?.as_u64()
                || !matches!(
                    (name, &enrollment.platform),
                    (
                        "android",
                        KagemushaWalletEnrollmentPlatformV1::Android { .. }
                    ) | ("apple", KagemushaWalletEnrollmentPlatformV1::Apple { .. })
                )
            {
                return Err(invalid());
            }
            Ok((app, enrollment))
        };
        let android = platform_policy("android")?;
        let apple = platform_policy("apple")?;
        let ledger = exact(
            field(app, "ledger")?,
            &[
                "toriiUrl",
                "networkId",
                "networkPrefix",
                "chainId",
                "irohaSourceCommit",
                "irohaBuildSha256",
            ],
        )?;
        let mut consensus_fields = vec![
            "mode",
            "protocolVersion",
            "networkId",
            "genesisBlockHash",
            "signedGenesisSha256",
            "genesisPublicKey",
            "validators",
            "checkpointSha256",
            "checkpointHeight",
            "checkpointContextId",
        ];
        // BPNG carries no finality-verifier pin: Native verifies finality itself from the
        // authenticated genesis roster, and Core's finality path reads no such pin. The CBSI
        // release format keeps its signed field as unread DATA.
        if trust.authority == RuntimeAuthority::CbsiReleaseV1 {
            consensus_fields.push("finalityVerifierSha256");
        }
        let consensus = exact(field(app, "consensus")?, &consensus_fields)?;
        sha(text(consensus, "signedGenesisSha256")?)?;
        sha(text(consensus, "genesisBlockHash")?)?;
        if trust.authority == RuntimeAuthority::BpngTairaV7 {
            bpng::checkpoint(consensus)?;
        } else {
            sha(text(consensus, "finalityVerifierSha256")?)?;
            sha(text(consensus, "checkpointSha256")?)?;
            sha(text(consensus, "checkpointContextId")?)?;
            if field(consensus, "checkpointHeight")?
                .as_u64()
                .is_none_or(|value| value > 9_007_199_254_740_991)
            {
                return Err(invalid());
            }
        }
        let original = bounded(input.signed_genesis, GENESIS_MAX)?;
        if BlobV1::of(original).sha256 != sha(text(consensus, "signedGenesisSha256")?)?
            || text(consensus, "networkId")? != text(ledger, "networkId")?
            || field(consensus, "protocolVersion")?.as_u64() != Some(1)
        {
            return Err(invalid());
        }
        let genesis = iroha_genesis::decode_signed_genesis(original).map_err(|_| invalid())?;
        if *genesis.hash().as_ref() != sha(text(consensus, "genesisBlockHash")?)? {
            return Err(invalid());
        }
        let network = NetworkId::from_genesis_hash(genesis.hash());
        if network.to_string() != text(ledger, "networkId")?
            || *network.as_bytes() != scheme.network_id
        {
            return Err(invalid());
        }
        let public =
            PublicKey::from_str(text(consensus, "genesisPublicKey")?).map_err(|_| invalid())?;
        if public.algorithm() != Algorithm::Ed25519
            || genesis
                .external_transactions()
                .next()
                .and_then(|t| t.authority().try_signatory())
                != Some(&public)
        {
            return Err(invalid());
        }
        // This actual native reader verifies the full original block/transaction signatures,
        // commitments, PoPs and every signed initial-epoch/schedule parameter.
        let epoch = authenticated_genesis(&genesis)
            .map(|genesis| genesis.into_parts().0)
            .map_err(|_| invalid())?;
        // Each independently selected application format owns its exact mode label.
        // The BPNG v7 renderer signs short labels; CBSI signs protocol tags.
        let mode = match (trust.authority, epoch.mode.is_permissioned()) {
            (RuntimeAuthority::BpngTairaV7, true) => "permissioned",
            (RuntimeAuthority::BpngTairaV7, false) => "npos",
            (_, true) => "iroha3-consensus::permissioned-sumeragi@v1",
            (_, false) => "iroha3-consensus::npos-sumeragi@v1",
        };
        if text(consensus, "mode")? != mode {
            return Err(invalid());
        }
        let validators = field(consensus, "validators")?
            .as_array()
            .ok_or(invalid())?;
        if validators.len() != epoch.committee.len()
            || !(4..=31).contains(&validators.len())
            || validators.len() % 3 != 1
        {
            return Err(invalid());
        }
        let mut roster = Vec::with_capacity(validators.len());
        for (selected, member) in validators.iter().zip(&epoch.committee) {
            let selected = exact(
                selected,
                &[
                    "peerId",
                    "directToriiUrl",
                    "nodeFingerprint",
                    "buildFingerprint",
                    "configFingerprint",
                ],
            )?;
            if PublicKey::from_str(text(selected, "peerId")?).map_err(|_| invalid())?
                != *member.validator.public_key()
            {
                return Err(invalid());
            }
            let route = text(selected, "directToriiUrl")?;
            if route.is_empty() || route.len() > 2048 || route.contains('\0') {
                return Err(invalid());
            }
            for name in ["nodeFingerprint", "buildFingerprint", "configFingerprint"] {
                sha(text(selected, name)?)?;
            }
            roster.push(FinalityValidator {
                public_key: member.validator.public_key().clone(),
                proof_of_possession: member.proof_of_possession.clone(),
            });
        }
        let native = SumeragiFinalityVerifier::new(&genesis, text(ledger, "chainId")?, roster)
            .map_err(|_| invalid())?;
        let selected_asset = match trust.authority {
            RuntimeAuthority::ApplicationReleaseV1 => return Err(invalid()),
            RuntimeAuthority::CbsiReleaseV1 => exact(
                field(app, "asset")?,
                &["assetAlias", "assetDefinitionId", "scale"],
            )?,
            RuntimeAuthority::BpngTairaV7 => bpng::asset(app)?,
        };
        if AssetDefinitionId::from_str(text(selected_asset, "assetDefinitionId")?)
            .map_err(|_| invalid())?
            != asset.asset
            || field(selected_asset, "scale")?.as_u64() != Some(u64::from(asset.scale))
        {
            return Err(invalid());
        }
        let fi_sessions = match &application {
            ApplicationBinding::CbsiReleaseV1 {
                service_release_scope,
                ..
            } => session::authorities(
                field(app, "fiSessionEnrollment")?,
                service_release_scope,
                &apple.1,
            )?,
            ApplicationBinding::BpngTairaV7 { .. } => Vec::new(),
            ApplicationBinding::ApplicationReleaseV1 { .. } => return Err(invalid()),
        };
        let bpng_session = match &application {
            ApplicationBinding::BpngTairaV7 { .. } => Some(session::bpng_authority(
                field(runtime, "enrollment_session")?,
                input.app_manifest,
                raw(
                    object(field(runtime, "apple")?)?,
                    "attestation_root_der_base64",
                    16_384,
                )?,
            )?),
            ApplicationBinding::CbsiReleaseV1 { .. } => None,
            ApplicationBinding::ApplicationReleaseV1 { .. } => return Err(invalid()),
        };
        Ok(Self {
            fi_sessions,
            bpng_session,
            enrollment_certificate,
            application,
            base: Arc::new(AuthenticatedBase {
                financial,
                _originals: RetainedBaseOriginals {
                    _app_manifest: input.app_manifest.into(),
                    _envelope: input.envelope.into(),
                    _wallet_runtime: input.wallet_runtime.into(),
                    _signed_genesis: input.signed_genesis.into(),
                },
                scheme,
                artifact_certificate,
                artifact_manifest,
                installation: InstallationV1 {
                    scheme_id: scheme.scheme_id(),
                    manifest_digest: manifest.manifest_digest(),
                },
                genesis: Arc::new(native),
            }),
            asset,
            asset_original,
            android_app_policy: android.0.policy_digest().map_err(|_| invalid())?,
            apple_app_policy: apple.0.policy_digest().map_err(|_| invalid())?,
            android_enrollment: android,
            apple_enrollment: apple,
        })
    }
}

#[cfg(test)]
mod tests;
