//! Register an authenticated scheme before physical enrollment needs its ledger authority.
//!
//! This stage keeps the same four peers and publishes genuine registration originals. It
//! does not issue a credential, select eligibility, or claim that any phone has enrolled.
use super::*;
use iroha_core_zk::kagemusha_wallet_registration_v1::{
    RegistrationSelectionV1, publish_registration_source_v1,
};
use iroha_fs::PrivateDirectory;
use std::io::Cursor;

/// In-memory result retained by the sole network owner across enrollment work.
pub(super) struct Registered {
    pub(super) scheme: KagemushaWalletSchemeV1,
    asset: KagemushaWalletAssetScopeV1,
    pub(super) manifest: [u8; 32],
    pub(super) height: u64,
    setup_sha: String,
    pub(super) summary: Vec<u8>,
}
impl Registered {
    pub(super) fn require_target(
        &self,
        setup_sha: &str,
        scheme_id: [u8; 32],
        manifest: [u8; 32],
        asset: &KagemushaWalletAssetScopeV1,
    ) -> Result<()> {
        ensure!(
            setup_sha == self.setup_sha
                && scheme_id == self.scheme.scheme_id()
                && manifest == self.manifest
                && *asset == self.asset,
            "funding target differs from this live owner's authenticated registration"
        );
        Ok(())
    }
}

pub(super) fn run(
    network: &Network,
    root: &Path,
    command: &norito::json::Value,
    setup_sha: &str,
) -> Result<Registered> {
    let setup: norito::json::Value =
        norito::json::from_slice(&read(&root.join("setup/setup.json"), 16 << 10, setup_sha)?)?;
    let predecessor = setup["live_height"]
        .as_u64()
        .ok_or_else(|| eyre!("certified live setup height"))?;
    ensure!(
        predecessor >= 2 && committed_height(network)? == predecessor,
        "setup predecessor changed"
    );
    prefix(network, predecessor)?;
    let asset: KagemushaWalletAssetScopeV1 = canonical(&original(
        &root.join("setup"),
        &setup,
        "originals",
        "asset.norito",
        4096,
    )?)?;
    let scheme_id = digest(&command["scheme_id"])?;
    let manifest = digest(&command["manifest_digest"])?;
    let (_, pack) = selected(command, "verifier_pack", VERIFIER_PACK_MAX_BYTES_V1)?;
    let pack_sha = hash(&pack);
    let admitted = InstalledVerifierPackV1::load(
        &pack,
        InstallationV1 {
            scheme_id,
            manifest_digest: manifest,
        },
    )?;
    let scheme = *admitted.verifier().scheme();
    ensure!(
        scheme.network_id == *network.network_id().as_bytes(),
        "foreign pack network"
    );
    drop(admitted);
    let output = root.join("registration");
    private_directory(&output)?;
    let register = KagemushaWalletLedgerV1::new(
        scheme_id,
        Action::Register {
            scheme: scheme.to_canonical_bytes()?,
            asset: norito::encode_canonical(&asset)?,
            reserve: account(95),
            balance_scope: AssetBalanceScope::Global,
        },
    );
    let install = KagemushaWalletLedgerV1::new(
        scheme_id,
        Action::InstallVerifierPack {
            asset: asset.asset_digest(),
            manifest_digest: manifest,
            pack,
        },
    );
    let (transaction, height) = submit(
        network,
        95,
        vec![register.into(), install.into()],
        &output,
        "register-install-signed.norito",
    )?;
    ensure!(
        height
            == predecessor
                .checked_add(1)
                .ok_or_else(|| eyre!("height overflow"))?,
        "registration must immediately follow its authenticated setup predecessor"
    );
    let snapshots = balances(network, [SUPPLY, 0, 0, 0])?;
    let history = prefix(network, height)?;
    let genesis = native(network)?;
    let mut verifier = native(network)?;
    let mut committed = None;
    let mut proofs = Vec::with_capacity(history.len());
    let mut originals = Vec::new();
    for proof in history {
        let block = verifier.verify(&proof)?;
        if block.height() == height {
            committed = Some(committed_transaction(&block, network, &transaction)?);
        }
        let bytes = norito::encode_canonical(&proof)?;
        originals.push(publish(
            &output,
            &format!("native-proof-{}.norito", proof.height()),
            &bytes,
        )?);
        proofs.push(bytes);
    }
    let committed = committed.ok_or_else(|| eyre!("registration original missing"))?;
    let committed_bytes = norito::encode_canonical(&committed)?;
    originals.push(publish(&output, "committed.norito", &committed_bytes)?);
    originals.push(publish(
        &output,
        "scheme.norito",
        &scheme.to_canonical_bytes()?,
    )?);
    originals.push(publish(
        &output,
        "asset.norito",
        &norito::encode_canonical(&asset)?,
    )?);
    let parent = PrivateDirectory::open_exact(&output)?;
    let (source, finalized) = publish_registration_source_v1(
        &parent,
        "package",
        RegistrationSelectionV1 {
            genesis: &genesis,
            scheme: &scheme,
            asset_digest: asset.asset_digest(),
            instruction_index: 0,
        },
        Cursor::new(committed_bytes),
        proofs.into_iter().map(|bytes| Ok(Cursor::new(bytes))),
        || false,
    )?;
    ensure!(
        finalized.height() == height
            && finalized.asset() == &asset
            && finalized.scheme() == &scheme
            && finalized.reserve() == &account(95)
            && finalized.transaction_hash() == *transaction.hash().as_ref(),
        "published registration must authenticate this exact original"
    );
    let source_bytes = source.encode_canonical()?;
    let summary = norito::json::to_vec(&norito::json!({
        "schema": "iroha.kagemusha.network-registered.v1",
        "setup_sha256": setup_sha,
        "scheme_id": (hex::encode(scheme_id)),
        "manifest_digest": (hex::encode(manifest)),
        "verifier_pack_sha256": pack_sha,
        "registration_source_sha256": (hash(&source_bytes)),
        "registration_source_path": (output.join("package/registration-source.norito").display().to_string()),
        "registration_transaction_hash_hex": (hex::encode(transaction.hash().as_ref())),
        "predecessor_height": predecessor, "certified_height": height,
        "originals": originals,
        "balances": snapshots,
        "scope": "Same four real validators; genuine direct registration and installed verifier pack. No credential, device enrollment, activation, Load or payment has occurred."
    }))?;
    publish(root, "registered.json", &summary)?;
    File::open(root)?.sync_all()?;
    Ok(Registered {
        scheme,
        asset,
        manifest,
        height,
        setup_sha: setup_sha.to_owned(),
        summary,
    })
}

#[test]
fn funding_target_requires_same_owner_setup_scheme_manifest_and_asset() -> Result<()> {
    // Pure DATA join control. This constructs no ledger, finality, installation or credential.
    let key = p256::ecdsa::SigningKey::from_bytes((&[7; 32]).into()).unwrap();
    let scheme = KagemushaWalletSchemeV1 {
        version: 1,
        network_id: *Hash::new(b"registration stage join").as_ref(),
        scheme_root_key: KagemushaDevicePublicKeyV1::from_sec1_bytes(
            key.verifying_key().to_encoded_point(false).as_bytes(),
        )?,
        relation_id: [9; 32],
        provider_contract: kagemusha_wallet_provider_contract_v1(),
    };
    let asset = KagemushaWalletAssetScopeV1 {
        version: 1,
        asset: definition_id(),
        asset_incarnation: *Hash::new(b"registration stage asset").as_ref(),
        scale: SCALE,
    };
    let registered = Registered {
        scheme,
        asset: asset.clone(),
        manifest: [11; 32],
        height: 6,
        setup_sha: hash(b"selected setup"),
        summary: Vec::new(),
    };
    registered.require_target(&registered.setup_sha, scheme.scheme_id(), [11; 32], &asset)?;
    ensure!(
        registered
            .require_target(&hash(b"foreign"), scheme.scheme_id(), [11; 32], &asset)
            .is_err(),
        "foreign setup"
    );
    ensure!(
        registered
            .require_target(&registered.setup_sha, [12; 32], [11; 32], &asset)
            .is_err(),
        "foreign scheme"
    );
    ensure!(
        registered
            .require_target(&registered.setup_sha, scheme.scheme_id(), [12; 32], &asset)
            .is_err(),
        "foreign manifest"
    );
    let mut changed = asset;
    changed.scale += 1;
    ensure!(
        registered
            .require_target(
                &registered.setup_sha,
                scheme.scheme_id(),
                [11; 32],
                &changed
            )
            .is_err(),
        "foreign asset scope"
    );
    Ok(())
}
