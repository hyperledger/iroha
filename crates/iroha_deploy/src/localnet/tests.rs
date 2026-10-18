//! Localnet generation regression tests.
use super::*;
use iroha_config::{
    base::toml::TomlSource, kura::FsyncMode, logger::Directives, parameters::actual,
};
use iroha_data_model::{
    block::decode_framed_signed_block,
    isi::{GrantBox, MintBox, SetParameter, TransferBox},
    parameter::{
        Parameter,
        system::{Parameters, SumeragiConsensusMode, SumeragiNposParameters, consensus_metadata},
    },
    sumeragi::PROTOCOL_VERSION,
    transaction::Executable,
};
use iroha_executor_data_model::permission::account::CanDelegateAccountAliasResolution;
use norito::{json, literal};

include!("tests/part_01.rs");
include!("tests/part_02.rs");

#[test]
fn localnet_root_fees_bind_generated_custody_and_preserve_explicit_default_terms() {
    use iroha_data_model::block::consensus::{RootFeePolicy, SumeragiRootScope};
    let key = KeyPair::try_from_seed(vec![0x62; 32], iroha_crypto::Algorithm::Ed25519).unwrap();
    let gas = AccountId::new(key.public_key().clone());
    let defaults = iroha_config::parameters::defaults::nexus::fees::genesis_policy();
    let mut expected = defaults.clone();
    expected.fee_asset_id = localnet_xor_asset_definition_id();
    assert_eq!(localnet_root_fee_policy(false, &gas), expected);
    assert_ne!(expected.fee_sink_account_id, gas);
    assert_ne!(expected.sponsor_vault_custody_account_id, gas);
    expected.fee_sink_account_id = gas.clone();
    expected.sponsor_vault_custody_account_id = gas.clone();
    let generated = localnet_root_fee_policy(true, &gas);
    assert_eq!(generated, expected);
    generated
        .validate_for_scope(&SumeragiRootScope::Global)
        .unwrap();
    let mut parameters = Parameters::default();
    parameters.set_parameter(Parameter::Custom(
        generated.clone().into_custom_parameter().unwrap(),
    ));
    assert_eq!(
        RootFeePolicy::from_parameters(&parameters).unwrap(),
        Some(generated)
    );
}
