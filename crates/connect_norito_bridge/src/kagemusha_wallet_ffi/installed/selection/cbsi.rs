//! Exact signed CBSI release selection; complete Native graph admission remains mandatory.

use super::*;
use std::collections::BTreeMap;

const MAX_ASSETS: usize = 7 + 3 * (4096 + 65_536);
pub(super) const REQUIRED: [&str; 7] = [
    "kagemusha/genesis-manifest.json",
    "kagemusha/network-configuration.toml",
    "kagemusha/producer-inventory.norito",
    "kagemusha/signed-genesis.norito",
    "kagemusha/transport.json",
    "kagemusha/verifier-pack.norito",
    "kagemusha/wallet-runtime.json",
];

pub(super) struct Selected<'a> {
    pub app: &'a Map,
    pub service_release_scope: [u8; 32],
    pub scheme_id: [u8; 32],
    pub artifact_manifest_digest: [u8; 32],
    pub producer_catalog_digest: [u8; 32],
    pub transport: BlobV1,
    pub pack: BlobV1,
    pub catalog: BlobV1,
}

pub(super) fn signed_document(bytes: &[u8]) -> Result<Value> {
    // The whole signed application release contains the finite complete original
    // union. Its original bytes remain capped at 8 MiB; the public inventory ceiling
    // cannot be reused as an uncapped JSON allocation allowance.
    let limits = norito::json::JsonPreflightLimits::new(
        APP_MANIFEST_MAX,
        MAX_ASSETS * 4 + 32_768,
        16_384,
        16_384,
        APP_MANIFEST_MAX,
        MAX_ASSETS,
        MAX_ASSETS + 32_768,
        MAX_ASSETS * 3 + 32_768,
        MAX_ASSETS * 4 + 32_768,
        32,
    );
    json_limits(bytes, APP_MANIFEST_MAX, true, limits)
}

fn mobile(document: &Value) -> Result<&Map> {
    let body = exact(document, APP_FIELDS)?;
    if text(body, "schema")? != "cbsi.iroha-application-release.v1" {
        return Err(invalid());
    }
    let artifacts = exact(
        field(body, "artifacts")?,
        &[
            "javascript_browser",
            "android_sdk",
            "apple_xcframework",
            "kagemusha_mobile",
        ],
    )?;
    let mobile = exact(
        field(artifacts, "kagemusha_mobile")?,
        &[
            "mode",
            "service_release_scope",
            "scheme_id",
            "artifact_manifest_digest",
            "producer_catalog_digest",
            "native_installation",
            "trust_assets",
        ],
    )?;
    if text(mobile, "mode")? != "enabled" {
        return Err(invalid());
    }
    Ok(mobile)
}

pub(super) fn application(document: &Value) -> Result<&Map> {
    let app = exact(
        field(mobile(document)?, "native_installation")?,
        &[
            "schema",
            "ledger",
            "consensus",
            "asset",
            "fiSessionEnrollment",
        ],
    )?;
    if text(app, "schema")? != "cbsi.kagemusha.native-installation.v1" {
        return Err(invalid());
    }
    Ok(app)
}

fn oid(value: &str) -> Result<()> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid());
    }
    Ok(())
}

fn source(document: &Map, app: &Map) -> Result<()> {
    let source = exact(
        field(document, "source")?,
        &[
            "commit",
            "tree",
            "cargo_lock_sha256",
            "cargo_lock_size_bytes",
            "javascript_tree",
            "iroha_js_tree",
            "iroha_js_host_tree",
            "android_source_fingerprint_sha256",
            "apple_source_fingerprint_sha256",
        ],
    )?;
    for name in [
        "commit",
        "tree",
        "javascript_tree",
        "iroha_js_tree",
        "iroha_js_host_tree",
    ] {
        oid(text(source, name)?)?;
    }
    for name in [
        "cargo_lock_sha256",
        "android_source_fingerprint_sha256",
        "apple_source_fingerprint_sha256",
    ] {
        sha(text(source, name)?)?;
    }
    if !field(source, "cargo_lock_size_bytes")?
        .as_u64()
        .is_some_and(|value| (1..=256 * 1024 * 1024).contains(&value))
    {
        return Err(invalid());
    }
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
    if text(ledger, "irohaSourceCommit")? != text(source, "commit")?
        || text(ledger, "toriiUrl")? != "https://bokolo.soramitsu.io"
        || text(ledger, "chainId")? != "fc56984b-2be7-431d-840e-21514d1883f0"
        || field(ledger, "networkPrefix")?.as_u64() != Some(369)
    {
        return Err(invalid());
    }
    sha(text(ledger, "irohaBuildSha256")?)?;
    let expected = norito::json!({"kagemusha_wallet_version":(1),"kagemusha_text_prefix":("kgm1:"),"kagemusha_wallet_types":{"scheme":("KagemushaWalletSchemeV1"),"signer_certificate":("KagemushaWalletSignerCertificateV1"),"artifact_manifest":("KagemushaWalletArtifactManifestV1"),"verifier_pack":("VerifierPackV1"),"producer_inventory":("ProducerInventoryV1")},"native_bridge_abi_version":(crate::CONNECT_NORITO_BRIDGE_ABI_VERSION),"native_prebuilt_provenance_schemas":{"android":("iroha.android-native-build-provenance.v1"),"apple":("cbsi.iroha-apple-xcframework-release.v1")}});
    if field(document, "protocol")? != &expected {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn current<'a>(
    document: &'a Value,
    input: &RuntimeOriginals<'_>,
) -> Result<Selected<'a>> {
    input.validate_bounds()?;
    let body = object(document)?;
    let mobile = mobile(document)?;
    let app = application(document)?;
    source(body, app)?;
    let offered = field(mobile, "trust_assets")?.as_array().ok_or(invalid())?;
    if !(8..=MAX_ASSETS).contains(&offered.len()) {
        return Err(invalid());
    }
    let mut rows = BTreeMap::new();
    let mut previous = None;
    let mut original = false;
    for value in offered {
        let row = exact(value, &["file_name", "sha256", "size_bytes"])?;
        let name = text(row, "file_name")?;
        let digest = sha(text(row, "sha256")?)?;
        let bytes = field(row, "size_bytes")?
            .as_u64()
            .filter(|value| (1..=1 << 30).contains(value))
            .ok_or(invalid())?;
        if previous.is_some_and(|previous: &str| previous >= name) {
            return Err(invalid());
        }
        previous = Some(name);
        if !REQUIRED.contains(&name) {
            if name != format!("kagemusha/originals/{}", hex::encode(digest)) {
                return Err(invalid());
            }
            original = true;
        }
        rows.insert(
            name,
            BlobV1 {
                bytes,
                sha256: digest,
            },
        );
    }
    if !original || REQUIRED.iter().any(|name| !rows.contains_key(name)) {
        return Err(invalid());
    }
    for (name, bytes) in [
        ("kagemusha/wallet-runtime.json", input.wallet_runtime),
        ("kagemusha/verifier-pack.norito", input.verifier_pack),
        (
            "kagemusha/producer-inventory.norito",
            input.producer_inventory,
        ),
        ("kagemusha/signed-genesis.norito", input.signed_genesis),
    ] {
        if rows.get(name) != Some(&BlobV1::of(bytes)) {
            return Err(invalid());
        }
    }
    let transport = rows["kagemusha/transport.json"];
    if transport.bytes > 32 * 1024 * 1024 {
        return Err(invalid());
    }
    let asset = exact(
        field(app, "asset")?,
        &["assetAlias", "assetDefinitionId", "scale"],
    )?;
    if text(asset, "assetAlias")? != "sbd#cbsi"
        || text(asset, "assetDefinitionId")? != "7ZepsJTHCVLKsrFFNZGSRGZgvBhv"
        || field(asset, "scale")?.as_u64() != Some(2)
    {
        return Err(invalid());
    }
    Ok(Selected {
        app,
        service_release_scope: sha(text(mobile, "service_release_scope")?)?,
        scheme_id: sha(text(mobile, "scheme_id")?)?,
        artifact_manifest_digest: sha(text(mobile, "artifact_manifest_digest")?)?,
        producer_catalog_digest: sha(text(mobile, "producer_catalog_digest")?)?,
        transport,
        pack: rows["kagemusha/verifier-pack.norito"],
        catalog: rows["kagemusha/producer-inventory.norito"],
    })
}
