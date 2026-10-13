//! Original signed fixture custody for the two retained Parliament reader cases.
//! These test-only keys and ledger fixtures grant no live service or monetary authority.
use super::*;

/// Sign fixture work with the exact fee intent derived from its original policy.
pub(crate) fn sign_payout_fixture_work(
    chain: &crate::sumeragi::test_chain::CertifiedTestChain,
    signer: &KeyPair,
    instructions: impl IntoIterator<Item = iroha_data_model::isi::InstructionBox>,
    created_ms: u64,
) -> iroha_data_model::transaction::SignedTransaction {
    use crate::state::StateReadOnly as _;
    use iroha_data_model::transaction::{FeePaymentIntent, TransactionBuilder};

    let mut builder = TransactionBuilder::new(
        chain.network_id(),
        AccountId::new(signer.public_key().clone()),
        FeePaymentIntent::authority(Vec::new(), None),
    );
    builder.set_creation_time(std::time::Duration::from_millis(created_ms));
    let builder = builder.with_instructions(instructions);
    let draft = builder.clone().sign(signer.private_key());
    let view = chain.state().view();
    let route_dataspace = match crate::sumeragi::lanes::routing::committed_root_scope(view.world())
    {
        Some(iroha_data_model::block::consensus::SumeragiRootScope::Dataspace {
            dataspace_id,
            ..
        }) => Some(dataspace_id),
        _ => None,
    };
    let fees = &view.nexus().fees;
    if route_dataspace.is_none()
        && [
            &fees.base_fee,
            &fees.per_byte_fee,
            &fees.per_instruction_fee,
            &fees.per_gas_unit_fee,
        ]
        .into_iter()
        .all(|amount| amount.is_zero())
        && view.pipeline().gas.accepted_assets.is_empty()
    {
        // Ordinary component fixtures have no configured fee component. They do
        // not need to resolve an otherwise unused fee currency. Private roots
        // always quote their signed policy, even when local rates are zero.
        return draft;
    }
    let quote = crate::executor::quote_nexus_fee_admission_draft(
        view.world(),
        view.nexus(),
        view.pipeline(),
        draft.payload(),
        created_ms,
        chain.height().checked_add(1).unwrap(),
        route_dataspace,
    )
    .expect("original payout fixture work has funded exact fee consent");
    builder
        .with_fee_payment_intent(quote.recommended_intent)
        .sign(signer.private_key())
}

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
    use crate::sumeragi::test_chain::CertifiedTestChain;
    use iroha_data_model::{
        isi::smart_contract_code::{RegisterSmartContractBytes, RegisterSmartContractCode},
        smart_contract::ContractArtifactId,
    };
    use iroha_model_base::topology::DataSpaceId;

    let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
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

fn signed_fee_registry_fixture(
    config: crate::sumeragi::test_chain::TestChainConfig,
) -> (
    crate::sumeragi::test_chain::CertifiedTestChain,
    ValidationFeeTreasuryPayoutBindingV1,
    Vec<u8>,
) {
    use iroha_data_model::{
        isi::smart_contract_code::CommitContractDeployment,
        smart_contract::{ContractAddress, ContractAlias},
    };
    let (mut chain, authority, code, code_hash) =
        signed_fee_registry_root_fixture_with_config(config);
    let signer = key_pair(55);
    let address =
        ContractAddress::derive(&chain.network_id(), &authority, 0, DataSpaceId::UNIVERSAL)
            .unwrap();
    let alias =
        ContractAlias::from_components("original-payout", Some("contracts"), "universal").unwrap();
    let deploy = sign_payout_fixture_work(
        &chain,
        &signer,
        [CommitContractDeployment {
            expected_deploy_nonce: 0,
            contract_address: address.clone(),
            code_hash,
            contract_alias: alias,
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
    let binding = treasury_payout_binding(address, &code);
    (chain, binding, code)
}

/// Two genuinely signed deployments used by the Parliament reader regression.
pub(crate) fn signed_payout_lifecycle_registry_fixture() -> (
    crate::sumeragi::test_chain::CertifiedTestChain,
    ValidationFeeTreasuryPayoutBindingV1,
) {
    let deployer = AccountId::new(key_pair(55).public_key().clone());
    let config = crate::sumeragi::test_chain::TestChainConfig::new(
        validation_fee_payout_world(&deployer),
        1_000,
    );
    signed_payout_lifecycle_registry_fixture_with_config(config)
}

/// Execute the same two signed deployments with the caller's original genesis policy.
pub(crate) fn signed_payout_lifecycle_registry_fixture_with_config(
    config: crate::sumeragi::test_chain::TestChainConfig,
) -> (
    crate::sumeragi::test_chain::CertifiedTestChain,
    ValidationFeeTreasuryPayoutBindingV1,
) {
    use iroha_data_model::{
        isi::smart_contract_code::CommitContractDeployment,
        smart_contract::{ContractAddress, ContractAlias},
    };
    let (mut chain, mut binding, code) = signed_fee_registry_fixture(config);
    let signer = key_pair(55);
    let authority = AccountId::new(signer.public_key().clone());
    let pool = ContractAddress::derive(
        &chain.network_id(),
        &authority,
        1,
        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
    )
    .unwrap();
    let deploy = sign_payout_fixture_work(
        &chain,
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

/// Sign bounded fixture work with limits quoted from its original committed State.
/// Global and private fixtures both pay their configured first-release Nexus schedule.
pub(crate) fn sign_paid_fixture(
    chain: &crate::sumeragi::test_chain::CertifiedTestChain,
    key: &KeyPair,
    instructions: impl IntoIterator<Item = iroha_data_model::isi::InstructionBox>,
    created_ms: u64,
) -> iroha_data_model::transaction::SignedTransaction {
    use iroha_data_model::{
        block::consensus::SumeragiRootScope,
        transaction::{FeePaymentIntent, TransactionBuilder},
    };
    let mut builder = TransactionBuilder::new(
        chain.network_id(),
        AccountId::new(key.public_key().clone()),
        FeePaymentIntent::authority(Vec::new(), None),
    );
    builder.set_creation_time(std::time::Duration::from_millis(created_ms));
    let builder = builder.with_instructions(instructions);
    let draft = builder.clone().sign(key.private_key());
    let view = chain.state().view();
    let route = match chain.root_scope() {
        SumeragiRootScope::Global => DataSpaceId::UNIVERSAL,
        SumeragiRootScope::Dataspace { dataspace_id, .. } => dataspace_id,
    };
    let quote = crate::executor::quote_nexus_fee_admission_draft(
        view.world(),
        view.nexus(),
        view.pipeline(),
        &view.zk().gas,
        draft.payload(),
        created_ms,
        crate::smartcontracts::isi::sccp::hold::committed_time_ms(&view)
            .expect("original committed fixture clock"),
        chain.height() + 1,
        Some(route),
    )
    .expect("fixture work must afford its actual signed fee intent");
    drop(view);
    builder
        .with_fee_payment_intent(quote.recommended_intent)
        .sign(key.private_key())
}
