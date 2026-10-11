//! Source-only KAGEMUSHA setup from four real Sumeragi validators.
//!
//! TODO: Run the exported setup through the complete signed catalog, genuine Load,
//! A → B → C exchange and network Unload before claiming monetary acceptance.
use super::*;
use eyre::{ensure, eyre};
use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::{
    asset::{AssetBalancePolicy, AssetDefinition},
    isi::{Grant, Log, Mint, RegisterBox},
    kagemusha::KagemushaWalletAssetScopeV1,
    nexus::AxtAssetIncarnationV1,
    permission::Permission,
    sumeragi_finality::{FinalityValidator, SumeragiFinalityProof, SumeragiFinalityVerifier},
    transaction::SignedTransaction,
};
use iroha_executor_data_model::permission::asset_definition::CanManageKagemushaWallet;
use iroha_model_base::peer::PeerId;
use iroha_primitives::numeric::{Numeric, NumericSpec};
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Write as _,
    num::NonZeroU64,
    path::Path,
};

const SCALE: u32 = 2;
const SUPPLY: u128 = 1_000;
const ROLE_FEE_UNITS: u32 = 1_000;

fn key(seed: u8) -> KeyPair {
    KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
}
fn account(seed: u8) -> AccountId {
    AccountId::new(key(seed).public_key().clone())
}
fn definition_id() -> AssetDefinitionId {
    AssetDefinitionId::from_uuid_bytes([
        0x2f, 0x17, 0xc7, 0x24, 0x66, 0xf8, 0x4a, 0x4b, 0xb8, 0xa8, 0xe2, 0x48, 0x84, 0xfd, 0xcd,
        0x2f,
    ])
    .unwrap()
}
fn definition() -> iroha_data_model::asset::NewAssetDefinition {
    AssetDefinition::new(
        definition_id(),
        "KAGEMUSHA real network acceptance",
        NumericSpec::fractional(SCALE),
        AssetBalancePolicy::Global,
        None,
    )
}
fn quantity() -> Quantity {
    Quantity::from_canonical_numeric(Numeric::new(SUPPLY, SCALE)).unwrap()
}
fn permission() -> Permission {
    CanManageKagemushaWallet {
        asset_definition: definition_id(),
    }
    .into()
}
fn network_builder() -> NetworkBuilder {
    let mut network = builder()
        .with_base_seed("kagemusha-real-monetary-v1")
        .with_config_layer(|layer| {
            layer.write("chain", "kagemusha-real-monetary-acceptance-v1");
        });
    for seed in [41, 42, 43, 95] {
        network = network.with_genesis_instruction(Register::account(Account::new(account(seed))));
    }
    // Isolate registration so its exact signed execution has lifecycle ordinal zero.
    // The derived incarnation below refuses a normalized transaction that adds instructions.
    network
        .next_genesis_transaction()
        .with_genesis_instruction(Register::asset_definition(definition()))
        .next_genesis_transaction()
        .with_genesis_instruction(Mint::asset_quantity(
            quantity(),
            AssetId::of(definition_id(), account(41)),
        ))
        .with_genesis_instruction(Grant::account_permission(permission(), account(95)))
}

fn registration_call<'a>(
    transactions: impl Iterator<Item = &'a SignedTransaction>,
) -> Result<&'a SignedTransaction> {
    let mut selected = None;
    for transaction in transactions {
        let Executable::Instructions(instructions) = transaction.instructions() else {
            continue;
        };
        let matches = instructions.iter().filter(|instruction| {
            instruction.as_any().downcast_ref::<RegisterBox>().is_some_and(|register| {
                matches!(register, RegisterBox::AssetDefinition(register) if register.object.id == definition_id())
            })
        }).count();
        if matches == 0 {
            continue;
        }
        ensure!(
            matches == 1 && instructions.len() == 1,
            "asset registration must have its own exact execution and ordinal zero"
        );
        ensure!(selected.is_none(), "asset registration must be unique");
        selected = Some(transaction);
    }
    selected.ok_or_else(|| eyre!("asset registration is missing"))
}

fn publish(root: &Path, name: &str, bytes: &[u8]) -> Result<norito::json::Value> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= 16 << 20,
        "bounded original required"
    );
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(root.join(name))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(
        norito::json!({"name": name, "bytes": (bytes.len()), "sha256": (hex::encode(Sha256::digest(bytes))) }),
    )
}

fn export(network: &Network, root: &Path) -> Result<()> {
    ensure!(
        network.peers().len() == 4,
        "exactly four actual peers required"
    );
    let provisioned = network.native_genesis_provisioning_bundle()?;
    let manifest: iroha_genesis::RawGenesisTransaction =
        norito::json::from_slice(&provisioned.manifest_json)?;
    let genesis = iroha_genesis::validate_prepared_genesis_bundle(
        &provisioned.signed_wire,
        &manifest,
        &provisioned.public_key,
        provisioned.block_hash,
    )?;
    ensure!(
        genesis.canonical_wire() == provisioned.signed_wire,
        "signed genesis changed"
    );
    ensure!(
        iroha_data_model::NetworkId::from_genesis_hash(genesis.expected_hash())
            == network.network_id(),
        "foreign genesis network"
    );
    ensure!(
        genesis.consensus_metadata().sumeragi_context.da_layout
            == iroha_sumeragi::availability::recommended_data_availability_layout(),
        "mandatory RS16 layout differs"
    );
    let roster = genesis
        .validator_pops()
        .iter()
        .map(|(public_key, proof_of_possession)| FinalityValidator {
            public_key: public_key.clone(),
            proof_of_possession: proof_of_possession.clone(),
        })
        .collect::<Vec<_>>();
    let members = roster
        .iter()
        .map(|validator| PeerId::new(validator.public_key.clone()))
        .collect::<std::collections::BTreeSet<_>>();
    ensure!(
        roster.len() == 4 && members == network.peers().iter().map(NetworkPeer::id).collect(),
        "signed roster differs from four running peers"
    );
    let execution_identity = Hash::from(
        registration_call(genesis.block().external_transactions())?.hash_as_entrypoint(),
    );
    let incarnation = AxtAssetIncarnationV1::derive(
        &network.network_id(),
        &definition_id(),
        &genesis.block().header().hash(),
        &execution_identity,
        0,
    );
    let asset = KagemushaWalletAssetScopeV1::new(definition_id(), &incarnation, SCALE)?;
    let chain = network.chain_id().to_string();
    let mut verifier = SumeragiFinalityVerifier::new(genesis.block(), &chain, roster.clone())?;
    let initial = verifier.initial_epoch();
    let parameters = verifier.initial_chain_parameters()?;
    let capture = norito::json!({
        "version": 1, "scope": "Source-only actual four-validator canonical genesis; no Load receipt or catalog grant.",
        "chain_id": (chain.clone()), "signed_genesis_wire_hex": (hex::encode(&provisioned.signed_wire)),
        "history_anchor": {
            "network_hex": (hex::encode(initial.network_id.as_bytes())),
            "instance_hex": (hex::encode(verifier.instance().0)),
            "initial_context_hex": (hex::encode(initial.context_id().map_err(|error| eyre!(error))?)),
            "initial_epoch": (initial.authorization.epoch),
            "parameters": (vec![parameters.block_time_ms, parameters.payload_retry_interval_ms,
                parameters.exec_budget_ms, parameters.apply_budget_ms, u64::from(parameters.max_block_bytes), parameters.epoch_length_blocks]),
        },
    });
    let mut selected = Vec::new();
    for peer in network.peers() {
        ensure!(peer.is_running(), "each seat must be a live node process");
        let client = peer.client();
        let native = client
            .client()
            .clone()
            .with_request_deadline(Instant::now() + Duration::from_secs(120));
        let mut peer_verifier =
            SumeragiFinalityVerifier::new(genesis.block(), &chain, roster.clone())?;
        let mut prefix = Vec::new();
        for height in 1..=2 {
            let proof = native.get_sumeragi_finality_proof(NonZeroU64::new(height).unwrap())?;
            let decision = peer_verifier.verify(&proof)?;
            ensure!(
                proof.committee.len() == 4
                    && proof
                        .committee
                        .iter()
                        .map(|validator| PeerId::new(validator.public_key.clone()))
                        .collect::<std::collections::BTreeSet<_>>()
                        == members,
                "native proof roster differs"
            );
            ensure!(
                decision
                    .block()
                    .output_results()
                    .all(|result| result.is_ok()),
                "setup execution failed"
            );
            if height == 2 {
                let certificate = decision
                    .block()
                    .commit_certificate()
                    .ok_or_else(|| eyre!("successor lacks embedded certificate"))?;
                let qc: iroha_sumeragi::message::Qc =
                    norito::decode_canonical(certificate.commit_qc())?;
                ensure!(
                    qc.signers.count_ones() == 3,
                    "exact quorum must be three equal votes"
                );
            }
            if !selected.is_empty() {
                let prior =
                    verifier.verify_retained_decision(&selected[usize::try_from(height - 1)?])?;
                ensure!(
                    decision.header() == prior.header()
                        && decision.commitment() == prior.commitment(),
                    "peers disagree on certified execution"
                );
            }
            prefix.push(proof);
        }
        if selected.is_empty() {
            for proof in &prefix {
                verifier.verify(proof)?;
            }
            selected = prefix;
        }
        let definitions = native.query(FindAssetDefinitions::new()).execute_all()?;
        let registered = definitions
            .iter()
            .find(|candidate| candidate.id() == &definition_id())
            .ok_or_else(|| eyre!("asset absent on peer"))?;
        ensure!(
            registered.spec().scale() == Some(SCALE)
                && registered.balance_scope_policy() == AssetBalancePolicy::Global,
            "registered scale or Universal Dataspace routing policy differs"
        );
        ensure!(
            registered.total_quantity() == &quantity(),
            "registered total supply differs"
        );
        let assets = native.query(FindAssets::new()).execute_all()?;
        let fee_asset: AssetDefinitionId =
            iroha_config::parameters::defaults::nexus::fees::fee_asset_id().parse()?;
        let fee_quantity =
            Quantity::from_canonical_numeric(Numeric::new(u128::from(ROLE_FEE_UNITS), 0))?;
        for seed in [41, 42, 43, 95] {
            let bucket = AssetId::of(fee_asset.clone(), account(seed));
            let balance = assets.iter().find(|asset| asset.id() == &bucket);
            ensure!(
                balance.is_some_and(|asset| asset.value() == &fee_quantity),
                "ordinary fee funding differs for role {seed}"
            );
        }
        let balances = assets
            .iter()
            .filter(|asset| asset.id().definition() == &definition_id())
            .collect::<Vec<_>>();
        ensure!(
            balances.len() == 1
                && balances[0].id() == &AssetId::of(definition_id(), account(41))
                && balances[0].value() == &quantity(),
            "supply must exist only in A's universal asset bucket"
        );
        let permissions = native
            .query(FindPermissionsByAccountId::new(account(95)))
            .execute_all()?;
        ensure!(
            permissions.contains(&permission()),
            "reserve permission missing"
        );
        let accounts = native.query(FindAccounts::new()).execute_all()?;
        ensure!(
            [41, 42, 43, 95].iter().all(|seed| accounts
                .iter()
                .any(|registered| registered.id() == &account(*seed))),
            "registered role account missing"
        );
    }
    let proofs: [SumeragiFinalityProof; 2] = selected
        .try_into()
        .map_err(|_| eyre!("exact two-block prefix required"))?;
    // No replacement of earlier outputs, including partial or failed attempts.
    fs::create_dir(root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    }
    let mut originals = vec![
        publish(root, "signed-genesis.wire", &provisioned.signed_wire)?,
        publish(root, "genesis-manifest.json", &provisioned.manifest_json)?,
        publish(root, "asset.norito", &norito::encode_canonical(&asset)?)?,
        publish(
            root,
            "registration-proof.norito",
            &norito::encode_canonical(&proofs)?,
        )?,
        publish(root, "capture.json", &norito::json::to_vec(&capture)?)?,
    ];
    for (name, seed) in [
        ("account.norito", 41),
        ("account-b.norito", 42),
        ("account-c.norito", 43),
        ("reserve.norito", 95),
    ] {
        originals.push(publish(
            root,
            name,
            &norito::encode_canonical(&account(seed))?,
        )?);
    }
    let setup = norito::json!({
        "schema": "iroha.kagemusha.executed-ledger-setup.v1", "chain_id": chain,
        "network_hex": (hex::encode(network.network_id().as_bytes())),
        "instance_hex": (hex::encode(verifier.instance().0)),
        "registration_height": 1, "certified_height": 2,
        "initial_supply_atomic_units": (SUPPLY.to_string()), "asset_digest_hex": (hex::encode(asset.asset_digest())),
        "scope": "Four running validators independently returned admitted H1/H2, exact three-vote QC and matching executed balances. Source-only setup; no offline wallet or monetary completion qualification.",
        "originals": originals,
    });
    publish(root, "setup.json", &norito::json::to_vec(&setup)?)?;
    File::open(root)?.sync_all()?;
    File::open(
        root.parent()
            .ok_or_else(|| eyre!("output parent required"))?,
    )?
    .sync_all()?;
    Ok(())
}

fn fund_fee_successor(network: &Network) -> Result<()> {
    // The automatic fee definition is registered at the end of genesis. Use
    // one ordinary ALICE-signed H2 transaction to fund the already registered
    // role accounts, preserving the selected genesis and fee policy.
    let fee_asset: AssetDefinitionId =
        iroha_config::parameters::defaults::nexus::fees::fee_asset_id().parse()?;
    let mut successor: Vec<InstructionBox> =
        vec![Log::new(Level::INFO, "KAGEMUSHA monetary setup successor".to_owned()).into()];
    for seed in [41, 42, 43, 95] {
        successor.push(
            Transfer::asset_quantity(
                AssetId::of(fee_asset.clone(), iroha_test_samples::ALICE_ID.clone()),
                ROLE_FEE_UNITS,
                account(seed),
            )
            .into(),
        );
    }
    network.client().submit_all(
        successor,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    wait_for_committed(network, 2, network.sync_timeout(), &[])
}

#[test]
#[ignore = "explicit four-validator source setup; complete proof catalog and monetary round remain separate"]
fn export_four_validator_kagemusha_setup() -> Result<()> {
    init_instruction_registry();
    let output = std::env::var_os("KAGEMUSHA_REAL_NETWORK_SETUP_OUTPUT")
        .ok_or_else(|| eyre!("exclusive setup output path required"))?;
    let output = Path::new(&output);
    ensure!(!output.exists(), "never replace prior setup evidence");
    let (network, rt) = sandbox::start_network_blocking_or_skip(
        network_builder(),
        stringify!(export_four_validator_kagemusha_setup),
    )?
    .ok_or_else(|| eyre!("four-validator qualification cannot skip network startup"))?;
    let result = (|| -> Result<()> {
        wait_for_committed(&network, 1, network.sync_timeout(), &[])?;
        fund_fee_successor(&network)?;
        export(&network, output)
    })();
    rt.block_on(async { network.shutdown().await });
    result
}

#[test]
fn registration_incarnation_requires_one_isolated_signed_creation() {
    let transaction = |instructions: Vec<InstructionBox>| {
        TransactionBuilder::new(
            iroha_data_model::NetworkId::from_genesis_hash(
                iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(
                    b"kagemusha-network-registration-check",
                )),
            ),
            account(41),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions(instructions)
        .sign(key(41).private_key())
    };
    let valid = transaction(vec![Register::asset_definition(definition()).into()]);
    assert_eq!(
        Hash::from(
            registration_call(std::iter::once(&valid))
                .unwrap()
                .hash_as_entrypoint()
        ),
        Hash::from(valid.hash_as_entrypoint())
    );
    assert!(registration_call(std::iter::empty()).is_err());
    assert!(registration_call([&valid, &valid].into_iter()).is_err());
    let mixed = transaction(vec![
        Register::asset_definition(definition()).into(),
        Log::new(Level::INFO, "extra".to_owned()).into(),
    ]);
    assert!(registration_call(std::iter::once(&mixed)).is_err());
}

#[path = "kagemusha_network_setup/continuation.rs"]
mod continuation;
