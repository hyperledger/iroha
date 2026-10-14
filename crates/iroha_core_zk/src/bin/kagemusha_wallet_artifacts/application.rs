//! Offline application DATA preparation. Only an independently admitted signature grants trust.
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use iroha_core_zk::kagemusha_wallet_artifacts_v1::{
    VERIFIER_PACK_MAX_BYTES_V1,
    producer_inventory::{CATALOG_MAX_BYTES_V1, EncodedTransportV1},
};
use norito::json::Value;

pub(super) const RUNTIME_MAX: usize = 128 << 10;
const APP_MAX: usize = 8 << 20;
const ENVELOPE_MAX: usize = 2048;
const DOMAIN: &str = "iroha.kagemusha.wallet-application-release.v1";

#[derive(JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct AndroidRoot {
    family: String,
    /// Independently selected actual root's DER SPKI, never a device attestation verdict.
    spki: OriginalInput,
}
#[derive(JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct Android {
    package_name: String,
    minimum_package_version: u64,
    signing_certificates_der: Vec<OriginalInput>,
    roots: Vec<AndroidRoot>,
    patch_floor_yyyymm: u32,
}
#[derive(JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct Apple {
    app_id: String,
    attestation_root_der: OriginalInput,
}
#[derive(JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct Controls {
    permitted_controls: u32,
    blacklist_max_age_ms: u64,
    time_anchor_max_response_ms: u64,
    challenge_lifetime_ms: u64,
    attestation_lease_lifetime_ms: u64,
}
/// Public session authority inputs. No token, secret or hardware verdict belongs here.
#[derive(JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub(super) struct Authority {
    pub(super) issuer: String,
    pub(super) audience: String,
    pub(super) request_origin: String,
    pub(super) verification_key_ed25519_hex: String,
    pub(super) release_original: OriginalInput,
    pub(super) enrollment_challenge_path: String,
    pub(super) roles: Vec<String>,
    pub(super) required_role: String,
}
#[derive(JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct Prepare {
    schema: String,
    native_bridge_abi_version: u32,
    chain_id: String,
    network_id_hex: String,
    genesis_public_key: String,
    signed_genesis: OriginalInput,
    scheme_id_hex: String,
    scheme: OriginalInput,
    enrollment_certificate: OriginalInput,
    artifact_certificate: OriginalInput,
    artifact_manifest: OriginalInput,
    verifier_pack: OriginalInput,
    producer_inventory: OriginalInput,
    transport: OriginalInput,
    android: Android,
    apple: Apple,
    controls: Controls,
    sessions: Vec<Authority>,
    output_parent: String,
    output_name: String,
}

pub(super) fn text_valid(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
pub(super) fn origin_valid(origin: &str) -> bool {
    let Some(authority) = origin.strip_prefix("https://") else {
        return false;
    };
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, suffix)) = rest.split_once(']') else {
            return false;
        };
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
        let port = if suffix.is_empty() {
            None
        } else {
            let Some(port) = suffix.strip_prefix(':') else {
                return false;
            };
            Some(port)
        };
        (host, port)
    } else {
        let (host, port) = authority
            .split_once(':')
            .map_or((authority, None), |(h, p)| (h, Some(p)));
        if host.is_empty()
            || host.len() > 253
            || host.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        {
            return false;
        }
        (host, port)
    };
    !host.is_empty()
        && port.is_none_or(|p| {
            !p.is_empty()
                && p.bytes().all(|b| b.is_ascii_digit())
                && p.parse::<u16>().is_ok_and(|p| p > 0)
        })
}
pub(super) fn path_valid(path: &str) -> bool {
    text_valid(path, 1024)
        && path.starts_with('/')
        && !path.starts_with("//")
        && !path.contains(['?', '#', '\\'])
        && !path.split('/').any(|v| matches!(v, "." | ".."))
}
pub(super) fn canonical(value: &Value, maximum: usize) -> io::Result<Vec<u8>> {
    let mut bytes = checked(
        json::to_json_bounded(value, maximum.saturating_sub(1)),
        "JSON bound",
    )?
    .into_bytes();
    bytes.push(b'\n');
    Ok(bytes)
}
pub(super) fn parse(bytes: &[u8], maximum: usize, require_canonical: bool) -> io::Result<Value> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(invalid("JSON bound"));
    }
    checked(
        json::preflight_slice(
            bytes,
            json::JsonPreflightLimits::new(
                maximum, 65_536, maximum, maximum, maximum, 16_384, 32_768, 32_768, 65_536, 32,
            ),
        ),
        "JSON complexity",
    )?;
    let value: Value = checked(json::from_slice(bytes), "JSON schema")?;
    if require_canonical && canonical(&value, maximum)? != bytes {
        return Err(invalid("canonical JSON required"));
    }
    Ok(value)
}
pub(super) fn input(
    input: &OriginalInput,
    maximum: usize,
    held: &mut Vec<Original>,
) -> io::Result<Vec<u8>> {
    let original = Original::open(&input.path, maximum, Some(digest(&input.sha256)?))?;
    let bytes = original.bytes.clone();
    held.push(original);
    Ok(bytes)
}
pub(super) fn recheck(held: &[Original]) -> io::Result<()> {
    for original in held {
        original.recheck()?;
    }
    Ok(())
}
pub(super) fn output(parent: &str, name: &str) -> io::Result<PrivateDirectory> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(invalid("single fresh output name required"));
    }
    let parent = PrivateDirectory::open_exact(parent)?;
    // A pre-existing output is never overwritten, resumed, or mistaken for this invocation.
    let directory = parent.create_child(name)?;
    directory.sync()?;
    parent.sync()?;
    parent.revalidate()?;
    Ok(directory)
}
fn roles_valid(roles: &[String], required: &str) -> bool {
    let unique: std::collections::BTreeSet<_> = roles.iter().collect();
    (1..=16).contains(&roles.len())
        && unique.len() == roles.len()
        && roles.iter().all(|r| {
            !r.is_empty() && r.len() <= 128 && r.is_ascii() && !r.chars().any(char::is_control)
        })
        && text_valid(required, 128)
        && roles.iter().any(|r| r == required)
}
fn authority(
    row: &Authority,
    android: &str,
    apple: &str,
    held: &mut Vec<Original>,
) -> io::Result<Value> {
    if !text_valid(&row.issuer, 512)
        || !text_valid(&row.audience, 512)
        || !text_valid(&row.request_origin, 2048)
        || !origin_valid(&row.request_origin)
        || !path_valid(&row.enrollment_challenge_path)
        || !roles_valid(&row.roles, &row.required_role)
    {
        return Err(invalid("session authority scope"));
    }
    let public = digest(&row.verification_key_ed25519_hex)?;
    checked(
        PublicKey::from_bytes(Algorithm::Ed25519, &public),
        "session Ed25519 public key",
    )?;
    let release = input(&row.release_original, 16_384, held)?;
    Ok(
        norito::json!({"issuer":(row.issuer), "audience":(row.audience),
        "requestOrigin":(row.request_origin), "verificationKeyEd25519Base64":(STANDARD.encode(public)),
        "releaseOriginalBase64":(STANDARD.encode(release)), "androidClientApp":(android),
        "appleClientApp":(apple), "enrollmentChallengePath":(row.enrollment_challenge_path),
        "roles":(row.roles), "requiredRole":(row.required_role)}),
    )
}
fn policy(
    app: &KagemushaWalletAppPolicyV1,
    platform: KagemushaWalletEnrollmentPlatformV1,
    controls: &Controls,
) -> io::Result<Vec<u8>> {
    let template = KagemushaWalletEnrollmentPolicyTemplateV1 {
        version: 1,
        scheme_id: app.scheme_id,
        app_policy: checked(app.policy_digest(), "app policy")?,
        platform,
        regulatory_policy: KagemushaWalletRegulatoryPolicyV1 {
            permitted_controls: controls.permitted_controls,
            blacklist_max_age_ms: controls.blacklist_max_age_ms,
            time_anchor_max_response_ms: controls.time_anchor_max_response_ms,
        },
        challenge_lifetime_ms: controls.challenge_lifetime_ms,
        attestation_lease_lifetime_ms: controls.attestation_lease_lifetime_ms,
    };
    checked(template.validate_for_app(app), "platform template mismatch")?;
    checked(template.encode_canonical(), "canonical enrollment template")
}
fn platform_data(
    request: &Prepare,
    scheme_id: [u8; 32],
    held: &mut Vec<Original>,
) -> io::Result<(Value, Value, Vec<(String, Vec<u8>)>)> {
    if !(1..=4).contains(&request.android.signing_certificates_der.len())
        || !(1..=8).contains(&request.android.roots.len())
    {
        return Err(invalid("Android signer/root bounds"));
    }
    let mut signers = Vec::new();
    for original in &request.android.signing_certificates_der {
        signers.push(BlobV1::of(&input(original, 16_384, held)?).sha256);
    }
    signers.sort();
    let android = KagemushaWalletAppPolicyV1 {
        version: 1,
        scheme_id,
        identity: KagemushaWalletAppIdentityV1::Android {
            package_name: request.android.package_name.clone(),
            minimum_package_version: request.android.minimum_package_version,
            signer_set: signers,
        },
    };
    let apple = KagemushaWalletAppPolicyV1 {
        version: 1,
        scheme_id,
        identity: KagemushaWalletAppIdentityV1::Apple {
            app_id: request.apple.app_id.clone(),
        },
    };
    let mut roots = Vec::new();
    for root in &request.android.roots {
        let family = match root.family.as_str() {
            "google-rsa" => KagemushaWalletAndroidRootFamilyV1::GoogleRsa,
            "google-ca1" => KagemushaWalletAndroidRootFamilyV1::GoogleCa1,
            _ => return Err(invalid("unqualified Android root family")),
        };
        roots.push(KagemushaWalletAndroidRootV1 {
            family,
            spki_sha256: BlobV1::of(&input(&root.spki, 16_384, held)?).sha256,
            revocation_source: KagemushaWalletRevocationSourceV1::GoogleAttestationStatus,
        });
    }
    roots.sort_by_key(|root| root.spki_sha256);
    let apple_root = input(&request.apple.attestation_root_der, 16_384, held)?;
    let android_app = checked(android.encode_canonical(), "Android app policy")?;
    let apple_app = checked(apple.encode_canonical(), "Apple app policy")?;
    let android_template = policy(
        &android,
        KagemushaWalletEnrollmentPlatformV1::Android {
            root_set: roots,
            patch_floor_yyyymm: request.android.patch_floor_yyyymm,
        },
        &request.controls,
    )?;
    let apple_template = policy(
        &apple,
        KagemushaWalletEnrollmentPlatformV1::Apple {
            attestation_root_sha256: BlobV1::of(&apple_root).sha256,
        },
        &request.controls,
    )?;
    let a = norito::json!({"app_policy_original_base64":(STANDARD.encode(&android_app)),
        "enrollment_template_original_base64":(STANDARD.encode(&android_template))});
    let b = norito::json!({"app_policy_original_base64":(STANDARD.encode(&apple_app)),
        "enrollment_template_original_base64":(STANDARD.encode(&apple_template)),"attestation_root_der_base64":(STANDARD.encode(&apple_root))});
    Ok((
        a,
        b,
        vec![
            ("android-app-policy.norito".into(), android_app),
            ("apple-app-policy.norito".into(), apple_app),
            (
                "android-enrollment-template.norito".into(),
                android_template,
            ),
            ("apple-enrollment-template.norito".into(), apple_template),
            ("apple-attestation-root.der".into(), apple_root),
        ],
    ))
}
fn transport_closure(
    inventory: &iroha_core_zk::kagemusha_wallet_artifacts_v1::producer_inventory::ProducerInventoryV1,
    transport: &EncodedTransportV1,
) -> io::Result<()> {
    let mut expected = BTreeMap::new();
    for original in &inventory.originals {
        for blob in [
            original.descriptor,
            original.verifying_key,
            original.proving_key,
        ] {
            if expected
                .insert(blob.sha256, blob.bytes)
                .is_some_and(|prior| prior != blob.bytes)
            {
                return Err(invalid("catalog original extent conflict"));
            }
        }
    }
    if expected.len() != transport.originals().len()
        || transport
            .originals()
            .iter()
            .any(|row| expected.get(&row.original.sha256) != Some(&row.original.bytes))
    {
        return Err(invalid(
            "encoded transport differs from exact catalog closure",
        ));
    }
    Ok(())
}
fn blob(bytes: &[u8]) -> Value {
    norito::json!({"bytes":(bytes.len()),"sha256":(hex::encode(BlobV1::of(bytes).sha256))})
}
pub(super) fn signing_message(manifest: &[u8]) -> Vec<u8> {
    let mut message = DOMAIN.as_bytes().to_vec();
    message.push(0);
    message.extend_from_slice(manifest);
    message
}
pub(super) fn prepare(path: &str) -> io::Result<()> {
    let source = Original::open(path, REQUEST_MAX, None)?;
    parse(&source.bytes, REQUEST_MAX, false)?;
    let request: Prepare = checked(
        json::from_slice(&source.bytes),
        "closed application request",
    )?;
    if request.schema != "iroha.kagemusha.wallet-application-preparation.v1"
        || request.native_bridge_abi_version == 0
        || !text_valid(&request.chain_id, 1024)
        || !(1..=64).contains(&request.sessions.len())
    {
        return Err(invalid("application preparation scope"));
    }
    let mut held = vec![source];
    let genesis_bytes = input(&request.signed_genesis, GENESIS_MAX, &mut held)?;
    native_finality(
        &request.chain_id,
        &request.network_id_hex,
        &request.genesis_public_key,
        &genesis_bytes,
    )?;
    let genesis = checked(decode_framed_signed_block(&genesis_bytes), "signed genesis")?;
    let network = NetworkId::from_genesis_hash(genesis.hash());
    let scheme_bytes = input(
        &request.scheme,
        KAGEMUSHA_WALLET_SCHEME_MAX_BYTES_V1,
        &mut held,
    )?;
    let scheme_id = digest(&request.scheme_id_hex)?;
    let scheme = checked(
        KagemushaWalletSchemeV1::decode_canonical(&scheme_bytes, &scheme_id),
        "scheme original",
    )?;
    if scheme.network_id != *network.as_bytes() {
        return Err(invalid("scheme/genesis network mismatch"));
    }
    let enrollment_bytes = input(
        &request.enrollment_certificate,
        KAGEMUSHA_WALLET_CERTIFICATE_MAX_BYTES_V1,
        &mut held,
    )?;
    let artifact_bytes = input(
        &request.artifact_certificate,
        KAGEMUSHA_WALLET_CERTIFICATE_MAX_BYTES_V1,
        &mut held,
    )?;
    let manifest_bytes = input(
        &request.artifact_manifest,
        KAGEMUSHA_WALLET_ARTIFACT_MANIFEST_MAX_BYTES_V1,
        &mut held,
    )?;
    let enrollment = checked(
        KagemushaWalletSignerCertificateV1::decode_canonical(&enrollment_bytes, &scheme),
        "enrollment certificate",
    )?;
    checked(
        enrollment.verify_role(&scheme, KagemushaWalletSignerRoleV1::Enrollment),
        "enrollment role",
    )?;
    let artifact = checked(
        KagemushaWalletSignerCertificateV1::decode_canonical(&artifact_bytes, &scheme),
        "artifact certificate",
    )?;
    checked(
        artifact.verify_role(&scheme, KagemushaWalletSignerRoleV1::Artifact),
        "artifact role",
    )?;
    let manifest = checked(
        KagemushaWalletArtifactManifestV1::decode_canonical(&manifest_bytes, &scheme),
        "artifact manifest",
    )?;
    checked(
        manifest.verify(&scheme, &artifact),
        "artifact manifest signature",
    )?;
    let pack = input(
        &request.verifier_pack,
        VERIFIER_PACK_MAX_BYTES_V1,
        &mut held,
    )?;
    let catalog = input(&request.producer_inventory, CATALOG_MAX_BYTES_V1, &mut held)?;
    // Native ApplicationRelease currently caps this original at the catalog bound.
    let transport = input(&request.transport, CATALOG_MAX_BYTES_V1, &mut held)?;
    let installed = checked(
        InstalledVerifierPackV1::load(
            &pack,
            InstallationV1 {
                scheme_id,
                manifest_digest: manifest.manifest_digest(),
            },
        ),
        "signed verifier pack",
    )?;
    let inventory = checked(
        installed.authenticate_producer_inventory(&catalog),
        "signed producer inventory",
    )?;
    let encoded = EncodedTransportV1::from_json(&transport)?;
    transport_closure(inventory.inventory(), &encoded)?;
    // The signed pack is the maintained owner of this exact catalog commitment.
    let catalog_digest = inventory
        .inventory()
        .digest()
        .map_err(|_| invalid("catalog digest"))?;
    let financial = norito::json!({"verifierPack":(blob(&pack)),"producerInventory":(blob(&catalog)),
        "producerCatalogDigest":(hex::encode(catalog_digest)),"transport":(blob(&transport))});
    let (android, apple, policies) = platform_data(&request, scheme_id, &mut held)?;
    let mut rows = Vec::new();
    let mut identities = std::collections::BTreeSet::new();
    for row in &request.sessions {
        if !identities.insert((&row.issuer, &row.audience)) {
            return Err(invalid("duplicate session authority"));
        }
        rows.push(authority(
            row,
            &request.android.package_name,
            &request.apple.app_id,
            &mut held,
        )?);
    }
    let runtime = canonical(
        &norito::json!({"schema":("iroha.kagemusha.wallet-runtime.v1"),"version":(1),"scheme_id":(hex::encode(scheme_id)),
        "scheme_original_base64":(STANDARD.encode(scheme_bytes)),"enrollment_certificate_original_base64":(STANDARD.encode(enrollment_bytes)),
        "artifact_signer_certificate_original_base64":(STANDARD.encode(artifact_bytes)),"artifact_manifest_original_base64":(STANDARD.encode(manifest_bytes)),
        "android":(android),"apple":(apple),"sessions":(rows)}),
        RUNTIME_MAX,
    )?;
    let release = canonical(
        &norito::json!({"schema":(DOMAIN),"nativeBridgeAbiVersion":(request.native_bridge_abi_version),
        "runtimeSha256":(hex::encode(BlobV1::of(&runtime).sha256)),"signedGenesisSha256":(hex::encode(BlobV1::of(&genesis_bytes).sha256)),
        "genesisBlockHash":(hex::encode(genesis.hash().as_ref())),"genesisPublicKey":(request.genesis_public_key),
        "chainId":(request.chain_id),"networkId":(network.to_string()),"financialOriginals":(financial)}),
        RUNTIME_MAX,
    )?;
    recheck(&held)?;
    let out = output(&request.output_parent, &request.output_name)?;
    for (name, bytes) in policies {
        publish(&out, &name, &bytes)?;
    }
    publish(&out, "wallet-runtime.json", &runtime)?;
    publish(&out, "application-release.json", &release)?;
    publish(
        &out,
        "application-release.signing-input",
        &signing_message(&release),
    )?;
    recheck(&held)?;
    out.revalidate()?;
    // Completion is last: partial output never claims approval, installation or hardware admission.
    publish(
        &out,
        "preparation-complete.json",
        &canonical(
            &norito::json!({"schema":("iroha.kagemusha.wallet-application-prepared.v1"),
        "runtimeSha256":(hex::encode(BlobV1::of(&runtime).sha256)),"manifestSha256":(hex::encode(BlobV1::of(&release).sha256))}),
            4096,
        )?,
    )
}

#[derive(JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct Finish {
    schema: String,
    manifest: OriginalInput,
    signature: OriginalInput,
    independent_release_public_key_hex: String,
    output_parent: String,
    output_name: String,
}
fn release_document(bytes: &[u8]) -> io::Result<Value> {
    let value = parse(bytes, APP_MAX, true)?;
    let map = value.as_object().ok_or_else(|| invalid("release object"))?;
    let fields = [
        "schema",
        "nativeBridgeAbiVersion",
        "runtimeSha256",
        "signedGenesisSha256",
        "genesisBlockHash",
        "genesisPublicKey",
        "chainId",
        "networkId",
        "financialOriginals",
    ];
    if map.len() != fields.len() || fields.iter().any(|key| !map.contains_key(*key)) {
        return Err(invalid("closed release fields"));
    }
    let text = |key| {
        map.get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("release text"))
    };
    if text("schema")? != DOMAIN
        || !text_valid(text("chainId")?, 1024)
        || map
            .get("nativeBridgeAbiVersion")
            .and_then(Value::as_u64)
            .is_none_or(|v| v == 0 || v > u64::from(u32::MAX))
    {
        return Err(invalid("release schema/ABI/chain"));
    }
    for key in ["runtimeSha256", "signedGenesisSha256", "genesisBlockHash"] {
        digest(text(key)?)?;
    }
    let public = checked(
        PublicKey::from_str(text("genesisPublicKey")?),
        "release genesis key",
    )?;
    let network = checked(NetworkId::from_str(text("networkId")?), "release network")?;
    if public.algorithm() != Algorithm::Ed25519
        || public.to_string() != text("genesisPublicKey")?
        || network.to_string() != text("networkId")?
    {
        return Err(invalid("release canonical public identities"));
    }
    let financial = map
        .get("financialOriginals")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("financial originals"))?;
    if financial.len() != 4
        || ![
            "verifierPack",
            "producerInventory",
            "producerCatalogDigest",
            "transport",
        ]
        .iter()
        .all(|k| financial.contains_key(*k))
    {
        return Err(invalid("closed financial originals"));
    }
    digest(
        financial
            .get("producerCatalogDigest")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("catalog digest"))?,
    )?;
    for (name, maximum) in [
        ("verifierPack", VERIFIER_PACK_MAX_BYTES_V1),
        ("producerInventory", CATALOG_MAX_BYTES_V1),
        ("transport", CATALOG_MAX_BYTES_V1),
    ] {
        let blob = financial
            .get(name)
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("financial blob"))?;
        if blob.len() != 2
            || blob
                .get("bytes")
                .and_then(Value::as_u64)
                .is_none_or(|n| n == 0 || n > maximum as u64)
        {
            return Err(invalid("financial blob extent"));
        }
        digest(
            blob.get("sha256")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("financial hash"))?,
        )?;
    }
    Ok(value)
}
fn envelope(manifest: &[u8], signature: &[u8], public: [u8; 32]) -> io::Result<Vec<u8>> {
    let document = release_document(manifest)?;
    if document.get("schema").and_then(Value::as_str) != Some(DOMAIN) || signature.len() != 64 {
        return Err(invalid("application signature scope"));
    }
    let key = checked(
        PublicKey::from_bytes(Algorithm::Ed25519, &public),
        "release public key",
    )?;
    checked(
        iroha_crypto::Signature::from_bytes(signature).verify(&key, &signing_message(manifest)),
        "release signature rejected",
    )?;
    canonical(
        &norito::json!({"schema":("iroha.kagemusha.wallet-application-release-signature.v1"),"algorithm":("ed25519"),"domain":(DOMAIN),
        "keyId":(format!("sha256:{}",hex::encode(BlobV1::of(&public).sha256))),"manifestSha256":(hex::encode(BlobV1::of(manifest).sha256)),
        "signatureBase64":(STANDARD.encode(signature))}),
        ENVELOPE_MAX,
    )
}
pub(super) fn finish(path: &str) -> io::Result<()> {
    let source = Original::open(path, REQUEST_MAX, None)?;
    parse(&source.bytes, REQUEST_MAX, false)?;
    let request: Finish = checked(
        json::from_slice(&source.bytes),
        "closed signature finish request",
    )?;
    if request.schema != "iroha.kagemusha.wallet-application-signature-assembly.v1" {
        return Err(invalid("signature assembly schema"));
    }
    let mut held = vec![source];
    let manifest = input(&request.manifest, APP_MAX, &mut held)?;
    let signature = input(&request.signature, 64, &mut held)?;
    let bytes = envelope(
        &manifest,
        &signature,
        digest(&request.independent_release_public_key_hex)?,
    )?;
    recheck(&held)?;
    let out = output(&request.output_parent, &request.output_name)?;
    publish(&out, "application-release-signature.json", &bytes)?;
    recheck(&held)?;
    out.revalidate()
}

#[cfg(test)]
#[path = "application/tests.rs"]
mod tests;
