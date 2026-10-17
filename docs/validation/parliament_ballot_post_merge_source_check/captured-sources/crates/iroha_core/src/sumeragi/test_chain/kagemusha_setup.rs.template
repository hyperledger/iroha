//! Genuine node execution inputs for KAGEMUSHA monetary acceptance.
//!
//! Only standard fresh-node genesis domain/account state is seeded. Payer/reserve accounts,
//! the asset incarnation, its supply and its exact management permission are created by the
//! original signed genesis instructions. The fixture signs the four-seat committee's votes;
//! this is component evidence, not a running four-validator network or device qualification.

mod funding;
mod registration;

use super::*;
use iroha_data_model::{
    asset::{AssetBalancePolicy, AssetDefinition, AssetDefinitionId, AssetId},
    isi::{Grant, Mint, Register},
    kagemusha::KagemushaWalletAssetScopeV1,
    permission::Permission,
    sumeragi_finality::{FinalityValidator, SumeragiFinalityProof, SumeragiFinalityVerifier},
};
use iroha_executor_data_model::permission::asset_definition::CanManageKagemushaWallet;
use iroha_primitives::numeric::{Numeric, NumericSpec, Quantity};
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Write as _,
    path::Path,
};

const CHAIN: &str = "kagemusha-native-monetary-acceptance-v1";
const SCALE: u32 = 2;
const SUPPLY: u128 = 1_000;
const SETUP_SCHEMA: &str = "iroha.kagemusha.executed-ledger-setup.v1";

/// The actual registered sources and still-live executed chain.
pub(crate) struct ExecutedKagemushaSetup {
    /// Original executed, certified component chain; no injected ledger rows.
    pub(crate) chain: CertifiedTestChain,
    /// Canonical manifest of the same signed genesis.
    pub(crate) manifest: iroha_genesis::RawGenesisTransaction,
    /// Registered account retained by the native A owner.
    pub(crate) account: AccountId,
    /// Independently registered B and C accounts, without initial value.
    pub(crate) recipients: [AccountId; 2],
    /// Registered reserve account, initially empty.
    pub(crate) reserve: AccountId,
    /// Actual incarnation and numeric scale queried after execution.
    pub(crate) asset: KagemushaWalletAssetScopeV1,
}

fn key(seed: u8) -> KeyPair {
    KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
}

fn definition_id() -> AssetDefinitionId {
    AssetDefinitionId::from_uuid_bytes([
        0x2f, 0x17, 0xc7, 0x24, 0x66, 0xf8, 0x4a, 0x4b, 0xb8, 0xa8, 0xe2, 0x48, 0x84, 0xfd, 0xcd,
        0x2f,
    ])
    .unwrap()
}

fn prepare() -> PreparedTestChainConfig {
    let genesis_key = key(0xCE);
    let genesis_account = AccountId::new(genesis_key.public_key().clone());
    let payer = AccountId::new(key(41).public_key().clone());
    let reserve = AccountId::new(key(95).public_key().clone());
    let definition = definition_id();
    let permission: Permission = CanManageKagemushaWallet {
        asset_definition: definition.clone(),
    }
    .into();
    let instructions = vec![
        Register::account(Account::new(payer.clone())).into(),
        Register::account(Account::new(AccountId::new(key(42).public_key().clone()))).into(),
        Register::account(Account::new(AccountId::new(key(43).public_key().clone()))).into(),
        Register::account(Account::new(reserve.clone())).into(),
        Register::asset_definition(AssetDefinition::new(
            definition.clone(),
            "KAGEMUSHA monetary acceptance",
            NumericSpec::fractional(SCALE),
            AssetBalancePolicy::Global,
            None,
        ))
        .into(),
        Mint::asset_quantity(
            Quantity::from_canonical_numeric(Numeric::new(SUPPLY, SCALE)).unwrap(),
            AssetId::of(definition, payer),
        )
        .into(),
        Grant::account_permission(permission, reserve).into(),
    ];
    let chain_id = ChainId::from(CHAIN);
    let validators = fixture_validators();
    let (genesis, manifest) = build_genesis(
        &chain_id,
        &genesis_key,
        &validators,
        instructions,
        Vec::new(),
        SumeragiConsensusMode::Permissioned,
        iroha_data_model::block::consensus::SumeragiRootScope::Global,
        1_000,
        NonZeroU64::MIN,
    )
    .unwrap();
    // This matches irohad's fresh bootstrap, including no fixture clock account or money.
    let world = World::with(
        [Domain::new(iroha_genesis::GENESIS_DOMAIN_ID.clone()).build(&genesis_account)],
        [Account::new(genesis_account.clone()).build(&genesis_account)],
        [],
    );
    let (genesis, manifest, state, kura) = prepare_configured_genesis(
        world,
        &chain_id,
        &genesis_key,
        &validators,
        genesis,
        manifest,
        SumeragiConsensusMode::Permissioned,
        1_000,
        &iroha_config::parameters::actual::Pipeline::default(),
        &iroha_config::parameters::actual::FraudMonitoring::default(),
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();
    let view = state.view();
    assert!(
        view.world()
            .account(&AccountId::new(key(41).public_key().clone()))
            .is_err()
    );
    assert!(
        view.world()
            .account(&AccountId::new(key(95).public_key().clone()))
            .is_err()
    );
    assert!(view.world().asset_definition(&definition_id()).is_err());
    assert!(
        view.world()
            .axt_asset_incarnations()
            .get(&definition_id())
            .is_none()
    );
    assert!(
        view.world()
            .kagemusha_wallet_ledger()
            .iter()
            .next()
            .is_none()
    );
    drop(view);
    let genesis = iroha_genesis::validate_prepared_genesis_bundle(
        &genesis.encode_wire().unwrap(),
        &manifest,
        genesis_key.public_key(),
        genesis.hash(),
    )
    .unwrap();
    PreparedTestChainConfig {
        genesis,
        manifest,
        state,
        kura,
        validator_keys: fixture_keys(),
        clock: genesis_key,
        lane_blocks: Arc::new(crate::sumeragi::lanes::merge::NoLanes),
    }
}

/// Execute original registration and certify its successor, retaining the exact sources.
pub(crate) fn start() -> ExecutedKagemushaSetup {
    let prepared = prepare();
    let manifest = prepared.manifest.clone();
    let mut chain = CertifiedTestChain::from_prepared(prepared).unwrap();
    assert!(
        chain
            .committed(1)
            .block()
            .output_results()
            .all(|result| result.is_ok())
    );
    let account = AccountId::new(key(41).public_key().clone());
    let reserve = AccountId::new(key(95).public_key().clone());
    let recipients = [42, 43].map(|seed| AccountId::new(key(seed).public_key().clone()));
    let view = chain.state().view();
    let world = view.world();
    assert!(world.account(&account).is_ok());
    assert!(world.account(&reserve).is_ok());
    for recipient in &recipients {
        assert!(world.account(recipient).is_ok());
        assert_ne!(recipient, &account);
        assert!(
            world
                .assets()
                .get(&AssetId::of(definition_id(), recipient.clone()))
                .is_none()
        );
    }
    let definition = world.asset_definition(&definition_id()).unwrap();
    assert_eq!(definition.spec().scale(), Some(SCALE));
    assert_eq!(
        definition.balance_scope_policy(),
        AssetBalancePolicy::Global
    );
    let asset = KagemushaWalletAssetScopeV1::new(
        definition_id(),
        world
            .axt_asset_incarnations()
            .get(&definition_id())
            .unwrap(),
        SCALE,
    )
    .unwrap();
    assert_eq!(
        world
            .assets()
            .get(&AssetId::of(asset.asset.clone(), account.clone()))
            .unwrap()
            .as_ref(),
        &Quantity::from_canonical_numeric(Numeric::new(SUPPLY, SCALE)).unwrap(),
    );
    assert!(
        world
            .assets()
            .get(&AssetId::of(asset.asset.clone(), reserve.clone()))
            .is_none()
    );
    assert!(world.kagemusha_wallet_ledger().iter().next().is_none());
    drop(view);
    // commit_at builds a real signed Log transaction: no empty-block production.
    chain.commit_at(2_000, Vec::new());
    assert!(
        chain
            .committed(2)
            .block()
            .output_results()
            .all(|result| result.is_ok())
    );
    ExecutedKagemushaSetup {
        chain,
        manifest,
        account,
        recipients,
        reserve,
        asset,
    }
}

fn native(setup: &ExecutedKagemushaSetup) -> SumeragiFinalityVerifier {
    let roster = setup
        .chain
        .validators()
        .iter()
        .map(|(peer, pop)| FinalityValidator {
            public_key: peer.public_key().clone(),
            proof_of_possession: pop.clone(),
        })
        .collect();
    SumeragiFinalityVerifier::new(setup.chain.genesis(), CHAIN, roster).unwrap()
}

fn registration_proofs(setup: &ExecutedKagemushaSetup) -> [SumeragiFinalityProof; 2] {
    let mut verifier = native(setup);
    [1, 2].map(|height| {
        let proof =
            crate::sumeragi::finality::build_proof(&setup.chain.state().view(), height).unwrap();
        let decision = verifier.verify(&proof).unwrap();
        assert_eq!(decision.result(), setup.chain.committed(height).result());
        proof
    })
}

fn source_capture(setup: &ExecutedKagemushaSetup) -> norito::json::Value {
    let verifier = native(setup);
    let initial = verifier.initial_epoch();
    let parameters = verifier.initial_chain_parameters().unwrap();
    norito::json!({
        "version": 1,
        "scope": "Source-only actual canonical genesis; no Load receipt, proof or deployment authority.",
        "chain_id": CHAIN,
        "signed_genesis_wire_hex": (hex::encode(setup.chain.genesis().encode_wire().unwrap())),
        "history_anchor": {
            "network_hex": (hex::encode(initial.network_id.as_bytes())),
            "instance_hex": (hex::encode(verifier.instance().0)),
            "initial_context_hex": (hex::encode(initial.context_id().unwrap())),
            "initial_epoch": (initial.authorization.epoch),
            "parameters": (vec![parameters.block_time_ms, parameters.payload_retry_interval_ms,
                parameters.exec_budget_ms, parameters.apply_budget_ms,
                u64::from(parameters.max_block_bytes), parameters.epoch_length_blocks]),
        },
    })
}

fn publish(root: &Path, name: &str, bytes: &[u8]) -> norito::json::Value {
    assert!(!bytes.is_empty() && bytes.len() <= 16 << 20);
    let path = root.join(name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    norito::json!({"name": name, "bytes": (bytes.len()), "sha256": (hex::encode(Sha256::digest(bytes)))})
}

fn export(setup: &ExecutedKagemushaSetup, root: &Path) {
    assert!(
        !root.exists(),
        "exclusive output, never overwrite an earlier setup"
    );
    fs::create_dir(root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let proofs = registration_proofs(setup);
    let originals = vec![
        publish(
            root,
            "signed-genesis.wire",
            &setup.chain.genesis().encode_wire().unwrap(),
        ),
        publish(
            root,
            "genesis-manifest.json",
            norito::json::to_json(&setup.manifest).unwrap().as_bytes(),
        ),
        publish(
            root,
            "account.norito",
            &norito::encode_canonical(&setup.account).unwrap(),
        ),
        publish(
            root,
            "account-b.norito",
            &norito::encode_canonical(&setup.recipients[0]).unwrap(),
        ),
        publish(
            root,
            "account-c.norito",
            &norito::encode_canonical(&setup.recipients[1]).unwrap(),
        ),
        publish(
            root,
            "reserve.norito",
            &norito::encode_canonical(&setup.reserve).unwrap(),
        ),
        publish(
            root,
            "asset.norito",
            &norito::encode_canonical(&setup.asset).unwrap(),
        ),
        publish(
            root,
            "registration-proof.norito",
            &norito::encode_canonical(&proofs).unwrap(),
        ),
        publish(
            root,
            "capture.json",
            norito::json::to_json(&source_capture(setup))
                .unwrap()
                .as_bytes(),
        ),
    ];
    let manifest = norito::json!({
        "schema": SETUP_SCHEMA,
        "chain_id": CHAIN,
        "network_hex": (hex::encode(setup.chain.network_id().as_bytes())),
        "instance_hex": (hex::encode(setup.chain.instance().0)),
        "registration_height": 1,
        "certified_height": 2,
        "initial_supply_atomic_units": (SUPPLY.to_string()),
        "asset_digest_hex": (hex::encode(setup.asset.asset_digest())),
        "scope": "Original signed genesis executed by startup and H2 by StateExecutor; fixture signs exactly three of four validator votes. No native wallet, Load, settlement, network-round or phone qualification.",
        "originals": originals,
    });
    publish(
        root,
        "setup.json",
        norito::json::to_json(&manifest).unwrap().as_bytes(),
    );
    File::open(root).unwrap().sync_all().unwrap();
    File::open(root.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
}

#[test]
fn asset_account_supply_and_permission_come_from_original_genesis_execution() {
    let setup = start();
    let same = start();
    assert_eq!(
        setup.chain.genesis().encode_wire().unwrap(),
        same.chain.genesis().encode_wire().unwrap()
    );
    assert_eq!(setup.asset, same.asset);
    assert_eq!(
        setup.chain.committed(2).commitment(),
        same.chain.committed(2).commitment()
    );
    let proofs = registration_proofs(&setup);
    assert!(
        native(&setup).verify(&proofs[1]).is_err(),
        "H2 cannot skip H1"
    );
    let mut verified = native(&setup);
    for proof in &proofs {
        verified.verify(proof).unwrap();
    }
    assert_eq!(
        verified
            .verify_retained_decision(&proofs[1])
            .unwrap()
            .result(),
        setup.chain.committed(2).result()
    );
    assert!(
        verified.verify(&proofs[1]).is_err(),
        "no second prefix insertion"
    );
    let view = setup.chain.state().view();
    let permission: Permission = CanManageKagemushaWallet {
        asset_definition: setup.asset.asset.clone(),
    }
    .into();
    assert!(
        view.world()
            .account_permissions()
            .get(&setup.reserve)
            .unwrap()
            .contains(&permission)
    );
    assert!(
        view.world()
            .kagemusha_wallet_ledger()
            .iter()
            .next()
            .is_none()
    );
}

#[test]
fn executed_setup_export_retains_exact_originals_and_refuses_overwrite() {
    let setup = start();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("setup");
    export(&setup, &root);
    let manifest: norito::json::Value =
        norito::json::from_slice(&fs::read(root.join("setup.json")).unwrap()).unwrap();
    for original in manifest["originals"].as_array().unwrap() {
        let bytes = fs::read(root.join(original["name"].as_str().unwrap())).unwrap();
        assert_eq!(original["bytes"].as_u64().unwrap(), bytes.len() as u64);
        assert_eq!(
            original["sha256"].as_str().unwrap(),
            hex::encode(Sha256::digest(&bytes))
        );
    }
    let before = fs::read(root.join("setup.json")).unwrap();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| export(&setup, &root))).is_err()
    );
    assert_eq!(fs::read(root.join("setup.json")).unwrap(), before);
}

#[test]
#[ignore = "explicit source-qualified executed ledger setup export; no synthetic Load or native activation"]
fn export_executed_kagemusha_ledger_setup() {
    let path =
        std::env::var_os("KAGEMUSHA_EXECUTED_LEDGER_SETUP_OUTPUT").expect("exclusive output path");
    let setup = start();
    export(&setup, Path::new(&path));
}
