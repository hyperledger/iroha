//! Native projection of the whole authenticated BPNG v7 application original.
//!
//! Core's service admission stays with Core. This module binds
//! only the fields consumed by this installation owner; all other signed fields
//! remain retained DATA and cannot grant a monetary or service capability.

use super::*;
use std::collections::BTreeSet;

// The cutover removed `firstDeviceAuthentication` (Google sign-up key, OAuth client and Play
// Integrity project), the retail OTP `authentication` policy and the retail stage anchor
// authority (Core verifies native checkpoint-rooted finality). They are refused, not ignored.
const APP_FIELDS: &[&str] = &[
    "schema",
    "environment",
    "generatedAt",
    "ledger",
    "consensus",
    "digitalKina",
    "routing",
    "feeSponsor",
    "contracts",
    "authorities",
    "services",
    "kasumi",
    "mibankCentralPaymentAdapter",
    "enrollment",
    "walletRuntime",
    "evidence",
];
pub(super) const VALIDATOR_BASES: [&str; 4] = [
    "https://taira.sora.org:9441",
    "https://taira.sora.org:9442",
    "https://taira.sora.org:9443",
    "https://taira.sora.org:9444",
];

pub(super) fn application(document: &Value) -> Result<&Map> {
    // The retired retailPolicy field is forbidden, including null or signed offers.
    let app = exact(document, APP_FIELDS)?;
    if text(app, "schema")? != "bpng.taira-app-runtime-manifest.v7"
        || text(app, "environment")? != "taira-testnet"
    {
        return Err(invalid());
    }
    // Validate the closed outer envelope while leaving unrelated Core policies as
    // authenticated originals, not a second interpretation of Core authority.
    for name in [
        "feeSponsor",
        "kasumi",
        "mibankCentralPaymentAdapter",
        "enrollment",
        "evidence",
    ] {
        object(field(app, name)?)?;
    }
    for name in ["contracts", "authorities"] {
        if field(app, name)?.as_array().is_none() {
            return Err(invalid());
        }
    }
    let timestamp = text(app, "generatedAt")?.as_bytes();
    if timestamp.len() != 20
        || timestamp.iter().enumerate().any(|(i, b)| match i {
            4 | 7 => *b != b'-',
            10 => *b != b'T',
            13 | 16 => *b != b':',
            19 => *b != b'Z',
            _ => !b.is_ascii_digit(),
        })
    {
        return Err(invalid());
    }
    let decimal = |start: usize, end: usize| {
        timestamp[start..end]
            .iter()
            .fold(0u32, |value, digit| value * 10 + u32::from(digit - b'0'))
    };
    let year = decimal(0, 4);
    let month = decimal(5, 7);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => return Err(invalid()),
    };
    if !(1..=days).contains(&decimal(8, 10))
        || decimal(11, 13) > 23
        || decimal(14, 16) > 59
        || decimal(17, 19) > 59
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
    let commit = text(ledger, "irohaSourceCommit")?;
    if text(ledger, "toriiUrl")? != "https://taira.sora.org"
        || field(ledger, "networkPrefix")?.as_u64() != Some(369)
        || text(ledger, "chainId")? != "fc56984b-2be7-431d-840e-21514d1883f0"
        || commit.len() != 40
        || commit.bytes().all(|byte| byte == b'0')
        || !commit
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid());
    }
    sha(text(ledger, "irohaBuildSha256")?)?;
    asset(app)?;
    services(app)?;
    let consensus = object(field(app, "consensus")?)?;
    let validators = field(consensus, "validators")?
        .as_array()
        .ok_or(invalid())?;
    if validators.len() != VALIDATOR_BASES.len() {
        return Err(invalid());
    }
    let mut peers = BTreeSet::new();
    let mut nodes = BTreeSet::new();
    for (row, base) in validators.iter().zip(VALIDATOR_BASES) {
        let row = exact(
            row,
            &[
                "peerId",
                "directToriiUrl",
                "nodeFingerprint",
                "buildFingerprint",
                "configFingerprint",
            ],
        )?;
        if text(row, "directToriiUrl")? != base
            || !peers.insert(text(row, "peerId")?)
            || !nodes.insert(sha(text(row, "nodeFingerprint")?)?)
        {
            return Err(invalid());
        }
        for name in ["buildFingerprint", "configFingerprint"] {
            sha(text(row, name)?)?;
        }
    }
    Ok(app)
}

pub(super) fn asset(app: &Map) -> Result<&Map> {
    let asset = exact(
        field(app, "digitalKina")?,
        &[
            "assetAlias",
            "assetDefinitionId",
            "scale",
            "owningDomain",
            "owningDataspace",
            "balanceScopePolicy",
            "physicalLaneId",
            "physicalLaneAlias",
            "physicalDataspaceId",
            "physicalDataspaceAlias",
            "registrationTransactionHash",
        ],
    )?;
    if text(asset, "assetAlias")? != "kina#bpng"
        || field(asset, "scale")?.as_u64() != Some(2)
        || field(asset, "owningDomain")? != &Value::Null
        || text(asset, "owningDataspace")? != "8648377547929788715"
        || !matches!(
            text(asset, "balanceScopePolicy")?,
            "Global" | "DataspaceRestricted"
        )
        || !field(asset, "physicalLaneId")?
            .as_u64()
            .is_some_and(|id| (1..=u32::MAX as u64).contains(&id) && id != 3)
        || text(asset, "physicalLaneAlias")? != "bpng"
        || text(asset, "physicalDataspaceId")? != "8648377547929788715"
        || text(asset, "physicalDataspaceAlias")? != "bpng"
    {
        return Err(invalid());
    }
    // The signed release selects the current registered asset. Selection::load
    // additionally binds it to the exact canonical Native asset original.
    AssetDefinitionId::from_str(text(asset, "assetDefinitionId")?).map_err(|_| invalid())?;
    if field(asset, "owningDataspace")? != field(asset, "physicalDataspaceId")? {
        return Err(invalid());
    }
    sha(text(asset, "registrationTransactionHash")?)?;
    let routing = exact(
        field(app, "routing")?,
        &[
            "physicalLaneId",
            "physicalLaneAlias",
            "physicalDataspaceId",
            "physicalDataspaceAlias",
            "bpngAliasScope",
            "mibankAliasScope",
        ],
    )?;
    for name in [
        "physicalLaneId",
        "physicalLaneAlias",
        "physicalDataspaceId",
        "physicalDataspaceAlias",
    ] {
        if field(asset, name)? != field(routing, name)? {
            return Err(invalid());
        }
    }
    if text(routing, "bpngAliasScope")? != "bpng"
        || text(routing, "mibankAliasScope")? != "mibank.bpng"
    {
        return Err(invalid());
    }
    Ok(asset)
}

fn services(app: &Map) -> Result<()> {
    let expected = [
        ("bpngPortalUrl", "https://bpng.soramitsu.io"),
        ("mibankPortalUrl", "https://mibank.soramitsu.io"),
        ("coreApiUrl", "https://bpng-core.soramitsu.io"),
        ("operatorApiUrl", "https://bpng-core.soramitsu.io/operator"),
        ("mibankCoreApiUrl", "https://bpng-core.soramitsu.io/mibank"),
        (
            "mibankOperatorApiUrl",
            "https://bpng-core.soramitsu.io/mibank/operator",
        ),
        ("kycVaultUrl", "https://mibank-kyc.soramitsu.io"),
        ("explorerUrl", "https://explorer-bpng.soramitsu.io"),
    ];
    let services = exact(field(app, "services")?, &expected.map(|(name, _)| name))?;
    for (name, value) in expected {
        if text(services, name)? != value {
            return Err(invalid());
        }
    }
    Ok(())
}

fn blob(value: &Value, maximum: usize) -> Result<BlobV1> {
    let value = exact(value, &["bytes", "sha256"])?;
    let bytes = field(value, "bytes")?
        .as_u64()
        .filter(|bytes| (1..=maximum as u64).contains(bytes))
        .ok_or(invalid())?;
    Ok(BlobV1 {
        bytes,
        sha256: sha(text(value, "sha256")?)?,
    })
}
fn financial(value: &Value, input: &RuntimeOriginals<'_>) -> Result<Option<FinancialSelection>> {
    if matches!(value, Value::Null) {
        if !input.verifier_pack.is_empty()
            || !input.producer_inventory.is_empty()
            || !input.originals_root.is_empty()
        {
            return Err(invalid());
        }
        return Ok(None);
    }
    if input.verifier_pack.is_empty()
        || input.producer_inventory.is_empty()
        || input.originals_root.is_empty()
    {
        return Err(invalid()); // Signed full selection cannot be downgraded to initial absence.
    }
    let record = exact(
        value,
        &[
            "schema",
            "verifierPack",
            "producerInventory",
            "transport",
            "producerCatalogDigest",
        ],
    )?;
    if text(record, "schema")? != "iroha.kagemusha.wallet-financial-originals.v1" {
        return Err(invalid());
    }
    let pack = blob(field(record, "verifierPack")?, VERIFIER_PACK_MAX_BYTES_V1)?;
    let catalog = blob(field(record, "producerInventory")?, CATALOG_MAX_BYTES_V1)?;
    let transport = blob(field(record, "transport")?, 32 * 1024 * 1024)?;
    if !input.verifier_pack.is_empty()
        && (pack != BlobV1::of(input.verifier_pack)
            || catalog != BlobV1::of(input.producer_inventory))
    {
        return Err(invalid());
    }
    Ok(Some(FinancialSelection {
        pack_identity: pack,
        catalog_identity: catalog,
        producer_catalog_digest: sha(text(record, "producerCatalogDigest")?)?,
        transport_identity: transport,
    }))
}
pub(super) fn require_runtime(
    app: &Map,
    input: &RuntimeOriginals<'_>,
) -> Result<([u8; 32], Option<FinancialSelection>)> {
    let pin = exact(
        field(app, "walletRuntime")?,
        &["schema", "currentRuntimeSha256", "financialOriginals"],
    )?;
    let digest = sha(text(pin, "currentRuntimeSha256")?)?;
    if text(pin, "schema")? != "bpng.current-wallet-runtime-pin.v1"
        || BlobV1::of(input.wallet_runtime).sha256 != digest
    {
        return Err(invalid());
    }
    Ok((digest, financial(field(pin, "financialOriginals")?, input)?))
}

pub(super) fn runtime_tools(runtime: &Map) -> Result<()> {
    // These exact public paths are signed Core configuration DATA. Native neither
    // executes them nor treats them as a verifier or producer capability.
    for name in ["python_path", "openssl_path"] {
        let path = text(runtime, name)?;
        if !path.starts_with('/')
            || path.contains('\0')
            || path[1..]
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err(invalid());
        }
    }
    for name in ["python_sha256", "openssl_sha256"] {
        sha(text(runtime, name)?)?;
    }
    Ok(())
}

pub(super) fn checkpoint(consensus: &Map) -> Result<()> {
    if [
        "checkpointSha256",
        "checkpointHeight",
        "checkpointContextId",
    ]
    .iter()
    .all(|name| consensus.get(*name) == Some(&Value::Null))
    {
        return Ok(());
    }
    sha(text(consensus, "checkpointSha256")?)?;
    let context = sha(text(consensus, "checkpointContextId")?)?;
    if !field(consensus, "checkpointHeight")?
        .as_u64()
        .is_some_and(|h| (2..=9_007_199_254_740_991).contains(&h))
        || context[31] & 1 != 1
        || (context[..31] == [0; 31] && context[31] == 1)
    {
        return Err(invalid());
    }
    Ok(())
}
