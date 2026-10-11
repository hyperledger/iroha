//! Managed call selection and immutable private fee-asset regressions.

use super::*;
use iroha_data_model::{account::AccountId, block::consensus::SumeragiRootScope};
use iroha_model_base::topology::DataSpaceId;

fn selected_config(root: &Path) -> (ManagedStore, ManagedContext, iroha::config::Config) {
    let store = ManagedStore::open(root).unwrap();
    let networks = PrivateDirectory::open(store.root().join("networks")).unwrap();
    let directory = networks.create_child("local").unwrap();
    let ports = LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "local",
        &directory.path().join(generation::DIRECTORY),
        &ports,
        crate::localnet::LocalnetServiceProfile::Standard,
        None,
    )
    .unwrap();
    let config = prepared.context.load_client_config().unwrap();
    (store, prepared.context, config)
}

#[test]
fn call_address_slot_binds_original_network_signer_context_and_dataspace() {
    let _resources = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let (store, selected, config) = selected_config(&temporary.path().join("state"));
    let address = ContractAddress::derive(
        &config.network_id,
        &config.account,
        1,
        DataSpaceId::new(selected.dataspace_id),
    )
    .unwrap();
    let original = call_slot(store.root(), &selected, &address);
    let mut other = selected.clone();
    other.name = "other".into();
    assert_ne!(original, call_slot(store.root(), &other, &address));
    other = selected.clone();
    other.network_id = iroha_data_model::NetworkId::from_genesis_hash(
        iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(b"other network")),
    )
    .to_string();
    assert_ne!(original, call_slot(store.root(), &other, &address));
    other = selected.clone();
    let pair = iroha_crypto::KeyPair::random();
    other.account_id = AccountId::new(pair.public_key().clone()).to_string();
    assert_ne!(original, call_slot(store.root(), &other, &address));
    let other_address =
        ContractAddress::derive(&config.network_id, &config.account, 1, DataSpaceId::new(7))
            .unwrap();
    assert_ne!(original, call_slot(store.root(), &selected, &other_address));
}

#[test]
fn private_call_cap_uses_native_child_currency_and_never_parent_fee_asset() {
    let _resources = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let store = ManagedStore::open(&temporary.path().join("state")).unwrap();
    let networks = PrivateDirectory::open(store.root().join("networks")).unwrap();
    let directory = networks.create_child("private").unwrap();
    let bundle = directory.create_child(generation::DIRECTORY).unwrap();
    let spec = crate::managed::tests::private_spec();
    let ports = LocalnetPorts::reserve().unwrap();
    let prepared =
        crate::localnet::prepare_private_root("private", bundle.path(), &ports, &spec).unwrap();
    let pin = store::pin_binary(&std::env::current_exe().unwrap()).unwrap();
    let retained = RetainedLocalnet {
        root_kind: RootKind::Private { spec: spec.clone() },
        prepared,
        launcher: pin.clone(),
        daemon: pin,
        startup_timeout_ms: 30_000,
    };
    bundle
        .write_atomic(
            MANIFEST,
            &encode(&retained).unwrap(),
            PublishMode::CreateNew,
        )
        .unwrap();
    let target = store
        .capture_deployment(&retained.prepared.context)
        .unwrap();
    assert_eq!(
        target.execution.root_scope,
        SumeragiRootScope::Dataspace {
            parent_network_id: spec.parent_network_id,
            dataspace_id: spec.dataspace_id
        }
    );
    assert_eq!(
        target.fee_asset().unwrap(),
        crate::localnet::private_fee_policy(&spec)
            .unwrap()
            .asset_definition_id
    );
    assert_ne!(
        target.fee_asset().unwrap(),
        crate::localnet::localnet_xor_asset_definition_id()
    );
}

#[test]
fn call_journal_name_rejects_changed_or_escaped_operation_hash() {
    let id = blake3::hash(b"original call").to_hex().to_string();
    journal_id(&id).unwrap();
    for invalid in [
        id.to_uppercase(),
        format!("../{id}"),
        format!("{id}/plan.json"),
        "0".repeat(63),
        "g".repeat(64),
    ] {
        assert!(journal_id(&invalid).is_err());
    }
}

#[test]
fn view_readback_binds_success_address_artifact_and_exact_selector() {
    let _resources = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let (_, _, config) = selected_config(&temporary.path().join("state"));
    let _profile = ChainDiscriminantGuard::enter(config.account_chain_discriminant);
    let address = ContractAddress::derive(
        &config.network_id,
        &config.account,
        1,
        DataSpaceId::UNIVERSAL,
    )
    .unwrap();
    let hash = iroha_crypto::Hash::new(b"verified artifact");
    let response = Value::Object(norito::json::Map::from([
        ("ok".into(), Value::Bool(true)),
        (
            "contract_address".into(),
            norito::json::to_value(&address).unwrap(),
        ),
        (
            "code_hash_hex".into(),
            Value::String(hex::encode(hash.as_ref())),
        ),
        ("entrypoint".into(), Value::String("current".into())),
        ("result".into(), Value::String("7".into())),
    ]));
    validate_view_response(&response, &address, hash, "current").unwrap();
    for (field, replacement) in [
        ("ok", Value::Bool(false)),
        ("contract_address", Value::String("changed address".into())),
        (
            "code_hash_hex",
            Value::String(hex::encode(
                iroha_crypto::Hash::new(b"other artifact").as_ref(),
            )),
        ),
        ("entrypoint", Value::String("other".into())),
    ] {
        let mut changed = response.clone();
        changed
            .as_object_mut()
            .unwrap()
            .insert(field.into(), replacement);
        assert!(validate_view_response(&changed, &address, hash, "current").is_err());
    }
}

#[test]
fn native_call_error_keeps_original_hash_cause_and_exact_recovery_journal() {
    let journal = Path::new("/owner-private state/calls/original");
    let native = iroha_contract_deploy::call::ContractCallPending {
        stage: "entrypoint-grant".into(),
        hash: "original-signed-hash".into(),
        source: color_eyre::eyre::eyre!("exact transaction finality deadline elapsed"),
    };
    let error = journal_failure(journal, color_eyre::eyre::Report::new(native));
    let display = error.to_string();
    assert!(display.contains("original-signed-hash"));
    assert!(display.contains("exact transaction finality deadline elapsed"));
    assert!(display.contains(journal.to_str().unwrap()));
    let Error::ContractCall {
        journal: retained,
        source,
    } = error
    else {
        panic!("typed native call cause");
    };
    assert_eq!(retained, journal);
    assert!(
        source
            .downcast_ref::<iroha_contract_deploy::call::ContractCallPending>()
            .is_some()
    );
}
