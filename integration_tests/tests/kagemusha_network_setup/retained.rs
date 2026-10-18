//! One retained engineering genesis and its real four-seat native provisioning owner.
//!
//! This adapter reproduces the signed engineering policy. It never generates genesis,
//! funds imaginary ALICE/XOR accounts, changes a catalog, or substitutes a node launcher.
use super::*;
use iroha_test_network::{NativeGenesisProvisioningBundle, RetainedNetworkGenesis};

#[path = "retained/provisioning.rs"]
mod provisioning;
pub(super) use provisioning::provision;

const GENESIS_SHA256: &str = "a290b3daecddb94af0c5a3ccf7a849707c8eaa49d2117b6938c39864902240c4";
const MANIFEST_SHA256: &str = "eccbbc36b58a6ebbd2b4a6a84c9dc0e6ddb66ffc99b2f651ee96524f26cf900d";

fn require_selection(value: &norito::json::Value) -> Result<()> {
    let fields = value
        .as_object()
        .ok_or_else(|| eyre!("retained selection object"))?;
    ensure!(
        fields
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>()
            == ["schema", "signed_genesis", "manifest"]
                .into_iter()
                .collect(),
        "closed retained selection"
    );
    ensure!(
        value["schema"].as_str() == Some("iroha.kagemusha.retained-four-validator-inputs.v1"),
        "retained input schema"
    );
    for (field, expected) in [
        ("signed_genesis", GENESIS_SHA256),
        ("manifest", MANIFEST_SHA256),
    ] {
        let selected = value[field]
            .as_object()
            .ok_or_else(|| eyre!("selected original"))?;
        ensure!(
            selected
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>()
                == ["path", "sha256"].into_iter().collect(),
            "closed original selection"
        );
        ensure!(
            value[field]["sha256"].as_str() == Some(expected),
            "different engineering genesis/manifest"
        );
        ensure!(
            value[field]["path"]
                .as_str()
                .is_some_and(|path| path.len() <= 4096 && Path::new(path).is_absolute()),
            "absolute bounded original path"
        );
    }
    Ok(())
}

pub(super) fn network_builder() -> Result<NetworkBuilder> {
    let path = std::env::var_os("KAGEMUSHA_RETAINED_NETWORK_INPUTS")
        .ok_or_else(|| eyre!("explicit retained public input selection required"))?;
    let bytes = continuation::read_original(Path::new(&path), 16 << 10, None)?;
    let selected: norito::json::Value = norito::json::from_slice(&bytes)?;
    require_selection(&selected)?;
    let (_, wire) = continuation::selected(
        &selected,
        "signed_genesis",
        iroha_genesis::SIGNED_GENESIS_MAX_BYTES_V1,
    )?;
    let (_, manifest_json) = continuation::selected(&selected, "manifest", 16 << 20)?;
    let manifest: iroha_genesis::RawGenesisTransaction = norito::json::from_slice(&manifest_json)?;
    let block = iroha_genesis::decode_signed_genesis(&wire)?;
    let genesis_key = key(0xCE); // Existing kagemusha_setup engineering owner, never a production credential.
    let validated = iroha_genesis::validate_prepared_genesis_bundle(
        &wire,
        &manifest,
        genesis_key.public_key(),
        block.hash(),
    )?;
    ensure!(
        validated.block().is_resultless_proposal(),
        "selected original must remain the canonical resultless proposal"
    );
    let registration = registration_call(validated.block().external_transactions())?;
    ensure!(
        (
            registration.instruction_index,
            registration.lifecycle_ordinal
        ) == (4, 0),
        "selected engineering creation differs"
    );
    let input = RetainedNetworkGenesis::new(
        NativeGenesisProvisioningBundle {
            signed_wire: wire,
            manifest_sha256: iroha_crypto::sha256(&manifest_json),
            manifest_json,
            public_key: genesis_key.public_key().clone(),
            block_hash: block.hash(),
            chain_discriminant: manifest.chain_discriminant(),
        },
        iroha_core::sumeragi::test_chain::fixture_keys(),
    )?;
    Ok(
        NetworkBuilder::from_retained_genesis(input).with_config_layer(|layer| {
            // The original kagemusha_setup calls fixture_bootstrap_state(None): defaults
            // with all fee rates zero. These exact strings also enter the signed policy.
            // Native staging verifies the full policy; these are not protocol overrides.
            layer
                .write(
                    ["nexus", "storage", "local_budget_bytes"],
                    TEST_NEXUS_LOCAL_STORAGE_BUDGET_BYTES,
                )
                .write(["gov", "citizenship_bond_amount"], "0")
                .write(["nexus", "fees", "base_fee"], "0")
                .write(["nexus", "fees", "per_byte_fee"], "0")
                .write(["nexus", "fees", "per_instruction_fee"], "0")
                .write(["nexus", "fees", "per_gas_unit_fee"], "0")
                .write(
                    ["nexus", "fees", "fee_sink_account_id"],
                    iroha_config::parameters::defaults::nexus::fees::FEE_SINK_ACCOUNT_ID,
                )
                .write(
                    ["nexus", "staking", "stake_escrow_account_id"],
                    iroha_config::parameters::defaults::nexus::staking::STAKE_ESCROW_ACCOUNT_ID,
                )
                .write(
                    ["nexus", "staking", "slash_sink_account_id"],
                    iroha_config::parameters::defaults::nexus::staking::SLASH_SINK_ACCOUNT_ID,
                );
        }),
    )
}

#[test]
fn retained_selection_refuses_other_genesis_missing_roles_and_unknown_fields() {
    let selected = norito::json!({"schema":"iroha.kagemusha.retained-four-validator-inputs.v1", "signed_genesis":{"path":"/private/genesis.nrt", "sha256":GENESIS_SHA256}, "manifest":{"path":"/private/genesis.json", "sha256":MANIFEST_SHA256}});
    require_selection(&selected).unwrap();
    for field in ["signed_genesis", "manifest"] {
        let mut changed = selected.clone();
        changed.as_object_mut().unwrap().remove(field);
        assert!(require_selection(&changed).is_err());
        let mut changed = selected.clone();
        changed
            .as_object_mut()
            .unwrap()
            .get_mut(field)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("sha256".into(), "00".repeat(32).into());
        assert!(require_selection(&changed).is_err());
    }
    let mut changed = selected;
    changed
        .as_object_mut()
        .unwrap()
        .insert("skip_dkg".into(), true.into());
    assert!(require_selection(&changed).is_err());
}
