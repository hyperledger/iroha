//! Original signed fixture custody for the two retained Parliament reader cases.
//! These test-only keys and ledger fixtures grant no live service or monetary authority.
use super::*;
pub(super) fn signed_fee_registry_root_fixture() -> (
    crate::sumeragi::test_chain::CertifiedTestChain,
    AccountId,
    Vec<u8>,
    Hash,
) {
    let deployer = AccountId::new(key_pair(55).public_key().clone());
    let config = crate::sumeragi::test_chain::TestChainConfig::new(
        validation_fee_payout_world(&deployer),
        1_000,
    );
    signed_fee_registry_root_fixture_with_config(config)
}

pub(super) fn signed_fee_registry_root_fixture_with_config(
    mut config: crate::sumeragi::test_chain::TestChainConfig,
) -> (
    crate::sumeragi::test_chain::CertifiedTestChain,
    AccountId,
    Vec<u8>,
    Hash,
) {
    let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
    use crate::sumeragi::test_chain::CertifiedTestChain;
    use iroha_data_model::{
        isi::smart_contract_code::{RegisterSmartContractBytes, RegisterSmartContractCode},
        smart_contract::ContractArtifactId,
    };
    use iroha_model_base::topology::DataSpaceId;
    let signer = key_pair(55);
    let authority = AccountId::new(signer.public_key().clone());
    let (code, manifest) = minimal_bound_contract_artifact();
    let code_hash = manifest
        .code_hash
        .expect("verified artifact has a code hash");
    let artifact_id = ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash);
    config.genesis_key = signer.clone();
    config.genesis_instructions.push(
        RegisterSmartContractBytes {
            artifact_id,
            code: code.clone(),
        }
        .into(),
    );
    config.genesis_instructions.push(
        RegisterSmartContractCode {
            artifact_id,
            manifest: manifest
                .try_signed(
                    manifest_signing.context(),
                    manifest_signing.max_frame_bytes(),
                    &signer,
                )
                .expect("sign bounded fixture manifest"),
        }
        .into(),
    );
    for scope in [
        iroha_executor_data_model::permission::account::AccountAliasPermissionScope::Dataspace(
            DataSpaceId::UNIVERSAL,
        ),
        iroha_executor_data_model::permission::account::AccountAliasPermissionScope::Domain(
            DomainId::try_new("contracts", "universal").unwrap(),
        ),
    ] {
        let permission: iroha_data_model::permission::Permission =
            iroha_executor_data_model::permission::account::CanManageAccountAlias { scope }.into();
        config.genesis_instructions.push(
            iroha_data_model::isi::Grant::account_permission(permission, authority.clone()).into(),
        );
    }
    let chain = CertifiedTestChain::start(config).expect("original signed root genesis");
    (chain, authority, code, code_hash)
}

fn signed_fee_registry_fixture() -> (
    crate::sumeragi::test_chain::CertifiedTestChain,
    ValidationFeeTreasuryPayoutBindingV1,
    crate::executor::ContractRuntimeExecutionContext,
    Vec<u8>,
) {
    use iroha_data_model::{
        isi::smart_contract_code::CommitContractDeployment,
        smart_contract::{ContractAddress, ContractAlias},
    };
    let (mut chain, authority, code, code_hash) = signed_fee_registry_root_fixture();
    let signer = key_pair(55);
    let address =
        ContractAddress::derive(&chain.network_id(), &authority, 0, DataSpaceId::UNIVERSAL)
            .unwrap();
    let alias =
        ContractAlias::from_components("original-payout", Some("contracts"), "universal").unwrap();
    let deploy = chain.sign(
        &signer,
        [CommitContractDeployment {
            expected_deploy_nonce: 0,
            contract_address: address.clone(),
            code_hash,
            contract_alias: alias.clone(),
            lease_expiry_ms: None,
            expected_previous_contract_address: None,
        }
        .into()],
        2_000,
    );
    assert_eq!(
        chain.commit(vec![deploy]),
        vec![true],
        "actual signed deployment must publish successfully: {:?}",
        chain.committed(2).block().execution_outputs()
    );
    let binding = treasury_payout_binding(address.clone(), &code);
    let runtime = crate::executor::ContractRuntimeExecutionContext {
        contract_address: address,
        contract_subject: binding.treasury_account_id.clone(),
        contract_alias: Some(alias),
        entrypoint: binding.entrypoint.to_string(),
    };
    (chain, binding, runtime, code)
}

/// Two genuinely signed deployments used by the Parliament reader regression.
pub(crate) fn signed_payout_lifecycle_registry_fixture() -> (
    crate::sumeragi::test_chain::CertifiedTestChain,
    ValidationFeeTreasuryPayoutBindingV1,
) {
    use iroha_data_model::{
        isi::smart_contract_code::CommitContractDeployment,
        smart_contract::{ContractAddress, ContractAlias},
    };
    let (mut chain, mut binding, _, code) = signed_fee_registry_fixture();
    let signer = key_pair(55);
    let authority = AccountId::new(signer.public_key().clone());
    let pool = ContractAddress::derive(
        &chain.network_id(),
        &authority,
        1,
        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
    )
    .unwrap();
    let deploy = chain.sign(
        &signer,
        [CommitContractDeployment {
            expected_deploy_nonce: 1,
            contract_address: pool.clone(),
            code_hash: ivm::contract_code_hash(&code),
            contract_alias: ContractAlias::from_components(
                "original-pool",
                Some("contracts"),
                "universal",
            )
            .unwrap(),
            lease_expiry_ms: None,
            expected_previous_contract_address: None,
        }
        .into()],
        3_000,
    );
    assert_eq!(chain.commit(vec![deploy]), vec![true]);
    binding.pool_contract_address = pool.clone();
    binding.pool_code_hash = ivm::contract_code_hash(&code).into();
    binding.pool_vault_account_id = pool.subject_id();
    assert_eq!(binding.invariant_error(), None);
    (chain, binding)
}

/// Own a signed root and a bounded, genuinely certified prefix before exact-due dispatch.
pub(crate) fn with_original_validation_fee_payout_state_at_height(
    height: u64,
    configure: impl FnOnce(crate::state::State) -> crate::sumeragi::test_chain::TestChainConfig,
    test: impl FnOnce(&mut StateTransaction<'_, '_>, &AccountId, &[u8], Hash),
) {
    // The sole caller uses the finite exact-due certificate height, currently 60.
    // The bound must fail before any chain work if another caller passes an unbounded height.
    assert!(
        (2..=128).contains(&height),
        "bounded signed payout fixture height"
    );
    let deployer = AccountId::new(key_pair(55).public_key().clone());
    // Preserve the caller's component configuration before authenticating a root.
    // This component's testing NetworkId is never used as original root evidence.
    let component = crate::state::State::new_with_chain_and_network_id_for_testing(
        validation_fee_payout_world(&deployer),
        crate::kura::Kura::blank_kura_for_testing(),
        crate::query::store::LiveQueryStore::start_test(),
        "generic-testnet".parse().expect("chain id"),
        validation_fee_test_network_id(),
    );
    let config = configure(component);
    let (mut chain, deployer, code, code_hash) =
        signed_fee_registry_root_fixture_with_config(config);
    while chain.height() < height - 1 {
        let next_height = chain.height() + 1;
        // commit_at adds an actual signed clock Log transaction; this is never an empty block.
        chain.commit_at(next_height * 1_000, Vec::new());
    }
    assert_eq!(
        chain.height(),
        height - 1,
        "exact signed predecessor prefix"
    );
    let state = std::sync::Arc::clone(chain.state());
    let header = BlockHeader::new(
        std::num::NonZeroU64::new(height).expect("bounded height is nonzero"),
        state.view().latest_block_hash(),
        None,
        height * 1_000,
        0,
    );
    let mut block = state.block(header);
    let mut transaction = block.transaction();
    test(&mut transaction, &deployer, &code, code_hash);
}
