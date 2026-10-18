//! Raw genesis templates retain the exact mandatory signed root scope.

use iroha_data_model::block::consensus::{SumeragiGenesisContextParameters, SumeragiRootScope};
use norito::json::{self, Value};

#[test]
fn global_genesis_root_scope_uses_the_canonical_tagged_json_shape() {
    let encoded = json::to_value(&SumeragiGenesisContextParameters::recommended()).unwrap();
    let scope = encoded.get("root_scope").unwrap();
    assert_eq!(scope, &norito::json!({"kind": "global", "value": null}));
    assert_eq!(
        json::from_value::<SumeragiRootScope>(scope.clone()).unwrap(),
        SumeragiRootScope::Global
    );
}

#[test]
fn checked_in_genesis_templates_require_an_explicit_global_root_scope() {
    let templates = [
        (
            "default",
            include_str!("../../../../defaults/genesis.template.json"),
        ),
        (
            "nexus",
            include_str!("../../../../defaults/nexus/genesis.template.json"),
        ),
        (
            "kagami-dev",
            include_str!("../../../../defaults/kagami/iroha3-dev/genesis.template.json"),
        ),
        (
            "kagami-nexus",
            include_str!("../../../../defaults/kagami/iroha3-nexus/genesis.template.json"),
        ),
        (
            "soranexus-nexus",
            include_str!("../../../../configs/soranexus/nexus/genesis.template.json"),
        ),
        (
            "soranexus-taira",
            include_str!("../../../../configs/soranexus/taira/genesis.template.json"),
        ),
        (
            "taira-nevo",
            include_str!(
                "../../../iroha_kagami/tests/fixtures/taira_nevo_v2/unsigned-genesis.template.json"
            ),
        ),
    ];
    for (name, template) in templates {
        let value: Value = json::from_str(template).unwrap();
        let _chain = iroha_data_model::account::address::ChainDiscriminantGuard::enter(
            u16::try_from(value.get("chain_discriminant").unwrap().as_u64().unwrap()).unwrap(),
        );
        let fee_parameters = value
            .get("transactions")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|transaction| transaction.get("parameters"))
            .filter_map(|parameters| parameters.get("custom"))
            .filter_map(|custom| custom.get("root_fees_v1"))
            .collect::<Vec<_>>();
        assert_eq!(
            fee_parameters.len(),
            1,
            "{name}: exactly one explicit fee authoring recipe"
        );
        let fee_parameter: iroha_data_model::parameter::CustomParameter =
            json::from_value(fee_parameters[0].clone())
                .unwrap_or_else(|error| panic!("{name}: {error}"));
        let fees = iroha_data_model::block::consensus::RootFeePolicy::from_custom_parameter(
            &fee_parameter,
        )
        .unwrap_or_else(|error| panic!("{name}: {error}"));
        fees.validate_for_scope(&SumeragiRootScope::Global).unwrap();
        assert_eq!(
            iroha_data_model::block::consensus::RootFeePolicy::from_custom_parameter(
                &fees.clone().into_custom_parameter().unwrap()
            )
            .unwrap(),
            fees,
            "{name}: retain every authored fee field through the canonical parameter codec"
        );
        let mut context = value.get("sumeragi_context").unwrap().clone();
        let parsed: SumeragiGenesisContextParameters =
            json::from_value(context.clone()).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(parsed.root_scope, SumeragiRootScope::Global, "{name}");
        parsed
            .validate()
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        context.as_object_mut().unwrap().remove("root_scope");
        assert!(
            json::from_value::<SumeragiGenesisContextParameters>(context).is_err(),
            "{name}: omitted signed root scope must not acquire an implicit global identity"
        );
    }
}
