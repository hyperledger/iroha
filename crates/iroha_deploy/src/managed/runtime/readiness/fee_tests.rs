//! Original generated fee-asset binding and actual positively charged readiness Log execution.
//! These components start no worker or native IPC and make no four-process readiness claim.

use super::*;
use crate::{
    localnet::{LocalnetServiceProfile, PrivateRootSpec},
    managed::{
        LocalnetPorts,
        native_operation::test_support::native_fixture::{NativeFixture, balance},
        service_authority::{NetworkPurpose, ServiceAuthority},
    },
};
use iroha_crypto::Hash;
use iroha_data_model::{
    NetworkId,
    asset::AssetId,
    sns::{DATASPACE_ALIAS_SUFFIX_ID, NameSelectorV1},
    transaction::FeeChargeKind,
};
use iroha_fs::{PrivateDirectory, PublishMode};
use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::numeric::Quantity;

#[test]
fn all_generated_profiles_select_their_original_bounded_asset_without_services_or_http() {
    let _guard = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let mut assets = Vec::new();
    for (index, profile) in [
        LocalnetServiceProfile::Standard,
        LocalnetServiceProfile::StreamTokenAuthorities,
    ]
    .into_iter()
    .enumerate()
    {
        let ports = LocalnetPorts::reserve().unwrap();
        let prepared = crate::localnet::prepare_localnet_at(
            "readiness-fee",
            &temporary.path().join(format!("global{index}")),
            &ports,
            profile,
            None,
        )
        .unwrap();
        let client = prepared.context.load_client_config().unwrap();
        let selected = fees::select(&prepared, &client).unwrap();
        assert_eq!(selected.payment.charge_limits().len(), 1);
        let limit = &selected.payment.charge_limits()[0];
        assert_eq!(limit.kind, FeeChargeKind::Nexus);
        assert_eq!(limit.max_amount, Quantity::from(1u64));
        assert!(selected.payment.gas_limit().is_none());
        assets.push(limit.asset_definition_id.clone());
    }
    assert_eq!(assets[0], assets[1]);
    let alias = "readinessprivate";
    let spec = PrivateRootSpec {
        parent_network_id: NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"readiness parent structural selection",
        ))),
        dataspace_id: DataSpaceId::from_hash(
            &NameSelectorV1::new(DATASPACE_ALIAS_SUFFIX_ID, alias)
                .unwrap()
                .name_hash(),
        ),
        dataspace_alias: alias.into(),
    };
    let ports = LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_private_root(
        "readiness-private",
        &temporary.path().join("private"),
        &ports,
        &spec,
    )
    .unwrap();
    let selected =
        fees::select(&prepared, &prepared.context.load_client_config().unwrap()).unwrap();
    assert_eq!(selected.payment.charge_limits().len(), 1);
    let limit = &selected.payment.charge_limits()[0];
    assert_eq!(limit.kind, FeeChargeKind::Nexus);
    assert_eq!(limit.max_amount, Quantity::from(1u64));
    assert_ne!(limit.asset_definition_id, assets[0]);
}

#[test]
fn fee_policy_or_peer_identity_substitution_refuses_despite_unchanged_expected_hash() {
    let _guard = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    for (index, profile) in [
        LocalnetServiceProfile::Standard,
        LocalnetServiceProfile::StreamTokenAuthorities,
    ]
    .into_iter()
    .enumerate()
    {
        let ports = LocalnetPorts::reserve().unwrap();
        let prepared = crate::localnet::prepare_localnet_at(
            "readiness-substitution",
            &temporary.path().join(format!("generation{index}")),
            &ports,
            profile,
            None,
        )
        .unwrap();
        let client = prepared.context.load_client_config().unwrap();
        let root =
            PrivateDirectory::open_exact(prepared.context.client_config.parent().unwrap()).unwrap();
        let original = root.read("peer3.toml", 1024 * 1024).unwrap();
        let selected = fees::select(&prepared, &client).unwrap();
        let original_text = std::str::from_utf8(&original).unwrap();
        let original_config = crate::localnet::parse_localnet_peer_config(
            original_text,
            Some(&prepared.peers[3].config_path),
        )
        .unwrap();
        assert!(original_config.nexus.fees.per_instruction_fee > Quantity::zero());
        assert_eq!(original_config.genesis.expected_hash, selected.genesis_hash);
        let original_policy =
            crate::localnet::service_authorities::configured_execution_policy(&original_config)
                .unwrap();
        let mut table = crate::secret_toml::Table::new(
            crate::secret_toml::parse_table(original_text, "readiness mutation control").unwrap(),
        );
        // Standard omits the default fee table; the explicit profile already supplies it.
        // Both must refuse a valid changed schedule rather than a malformed configuration.
        table
            .get_mut("nexus")
            .unwrap()
            .as_table_mut()
            .unwrap()
            .entry("fees".to_owned())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
            .unwrap()
            .insert(
                "per_instruction_fee".into(),
                toml::Value::String("0".into()),
            );
        let altered = toml::to_string(&*table).unwrap();
        let altered_config = crate::localnet::parse_localnet_peer_config(
            &altered,
            Some(&prepared.peers[3].config_path),
        )
        .unwrap();
        assert_eq!(
            altered_config.nexus.fees.per_instruction_fee,
            Quantity::zero()
        );
        assert_ne!(
            altered_config.nexus.fees.per_instruction_fee,
            original_config.nexus.fees.per_instruction_fee
        );
        assert_eq!(
            altered_config.genesis.expected_hash,
            original_config.genesis.expected_hash
        );
        assert_ne!(
            crate::localnet::service_authorities::configured_execution_policy(&altered_config)
                .unwrap(),
            original_policy
        );
        root.write_atomic("peer3.toml", altered.as_bytes(), PublishMode::Replace)
            .unwrap();
        assert!(fees::select(&prepared, &client).is_err());
        root.write_atomic("peer3.toml", &original, PublishMode::Replace)
            .unwrap();
        let restored = fees::select(&prepared, &client).unwrap();
        let mut wrong = prepared.clone();
        wrong.peers[3] = prepared.peers[2].clone();
        assert!(fees::select(&wrong, &client).is_err());
        let mut foreign = client.clone();
        foreign.network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
            Hash::new(b"other readiness network"),
        ));
        assert!(fees::select(&prepared, &foreign).is_err());
        assert_eq!(
            restored.payment.charge_limits()[0].max_amount,
            Quantity::from(1u64)
        );
    }
}

#[test]
fn original_bounded_readiness_log_executes_with_a_real_positive_native_fee() {
    let _guard = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let ports = LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "readiness-native-fee",
        &temporary.path().join("generation"),
        &ports,
        LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let authority =
        ServiceAuthority::open_network(&prepared, NetworkPurpose::InitialReservePolicy).unwrap();
    let mut fixture = NativeFixture::from_generated(&prepared, &authority);
    let selected = fees::select(&prepared, &authority.config).unwrap();
    let asset = AssetId::new(
        selected.payment.charge_limits()[0]
            .asset_definition_id
            .clone(),
        authority.config.account.clone(),
    );
    let before = balance(fixture.chain.state(), &asset);
    let client = iroha::client::Client::builder(authority.config.clone())
        .build()
        .unwrap();
    let account = client.account_client().unwrap();
    let signed = smoke_transaction(&account, selected.payment.clone()).unwrap();
    assert_eq!(signed.fee_payment_intent(), &selected.payment);
    let exact_wire = signed.encode_wire_v1().unwrap();
    assert_eq!(fixture.chain.commit(vec![signed]), vec![true]);
    let tip = fixture.chain.committed(2);
    assert_eq!(tip.block().network_entrypoint_count(), 1);
    assert_eq!(
        tip.block()
            .external_transactions()
            .next()
            .unwrap()
            .encode_wire_v1()
            .unwrap(),
        exact_wire
    );
    assert!(tip.block().network_output_at(0).unwrap().1.result.is_ok());
    let after = balance(fixture.chain.state(), &asset);
    assert!(
        before > after,
        "a positive native fee must actually be paid"
    );
    let paid = before.checked_sub(&after).unwrap();
    assert!(paid <= Quantity::from(1u64));
}
