//! Execute the SoraSwap wrapper through the real host and production DLMM bin math.
#[path = "runtime_rewards_tests.rs"]
pub(crate) mod reward_tests;
use super::*;
use crate::{
    executor::ContractEntrypointAuthorizationSnapshot, smartcontracts::ivm::host::CoreHostImpl,
};
use iroha_data_model::{IntoKeyValue, smart_contract::ContractAddress};
use iroha_model_base::{name::Name, topology::DataSpaceId};

const WRAPPER_BLOCK_GAS_LIMIT: u64 = 4_000_000;

// Keep genesis construction outside the frame that invokes the signed callback.
// Every phase still runs on the ordinary test thread with its default stack.
#[inline(never)]
fn wrapper_chain() -> (crate::sumeragi::test_chain::CertifiedTestChain, AccountId) {
    let deployer = account(55);
    // Use the actual default block policy from the signed original genesis.
    // The production wrapper, nested DLMM and byte charge must fit it unchanged.
    let config = crate::sumeragi::test_chain::TestChainConfig::new(
        validation_fee_payout_world(&deployer),
        1_000,
    );
    let (chain, deployer, _, _) =
        signed_original_fixtures::signed_fee_registry_root_fixture_with_config(config);
    (chain, deployer)
}

fn with_wrapper_block(test: impl FnOnce(&mut crate::state::StateBlock<'_>, &AccountId)) {
    let (chain, deployer) = wrapper_chain();
    let state = chain.state();
    let header = BlockHeader::new(
        std::num::NonZeroU64::new(10).unwrap(),
        state.view().latest_block_hash(),
        None,
        2_000,
        0,
    );
    let mut block = state.block(header);
    assert_eq!(block.gas_limit_per_block, WRAPPER_BLOCK_GAS_LIMIT);
    test(&mut block, &deployer);
}

struct WrapperFixture {
    pool: ContractAddress,
    wrapper: ContractAddress,
    reward_pool: AccountId,
    xor: AssetDefinitionId,
    expected_output: Quantity,
    minimum_output: &'static str,
    pool_hash: Hash,
    pool_artifact_bytes: usize,
    pool_full_wire_hash: Hash,
    wrapper_code: Vec<u8>,
    wrapper_hash: Hash,
    treasury_sbd: AssetId,
}

struct WrapperPreview {
    ordered: Vec<(AccountId, InstructionBox)>,
    trigger_id: iroha_data_model::trigger::TriggerId,
    treasury_xor: AssetId,
    gas_used: u64,
}

// Retire the setup transaction and compiler frames before entering the callback.
#[inline(never)]
fn install_wrapper_fixture(
    block: &mut crate::state::StateBlock<'_>,
    deployer: &AccountId,
    production_pool: bool,
) -> WrapperFixture {
    let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
    let mut setup = block.transaction_for_callback_testing();
    let stx = &mut setup;
    let derive = |nonce| {
        ContractAddress::derive(&stx.network_id, deployer, nonce, DataSpaceId::UNIVERSAL).unwrap()
    };
    let pool = derive(200);
    let wrapper = derive(201);
    let reward_pool = account(8);
    let sbd = fee_asset();
    let xor = xor_asset();
    let expected_output: Quantity = if production_pool {
        "9.960039960".parse().unwrap()
    } else {
        Quantity::from(20u64)
    };
    let minimum_output = if production_pool { "9.9" } else { "19.8" };
    validate_network_xor_asset(&stx.world, &xor).unwrap();
    // The first case isolates the effect plan with a fixed liquid quote.
    // The second uses the entire current production DLMM unchanged. Real nested
    // frames, argument decoding, output validation and transfers run unchanged.
    let pool_source = r#"
seiyaku FullFillPool { permission SwapQuotePublic;
  error enum PoolError { Minimum = 1, }
  kotoage fn swap_exact_in_quote_public(quantity amount_in, quantity min_out) authorize(SwapQuotePublic) -> quantity {
    let quantity output = 20;
    require(output >= min_out, PoolError::Minimum);
    ledger::asset::transfer(source: context::authority(), destination: context::seiyaku_subject(), asset_definition: AssetDefinitionId::parse("@@SBD@@"), amount: amount_in, dataspace: DataSpaceId::parse("0"));
    ledger::asset::transfer(source: context::seiyaku_subject(), destination: context::authority(), asset_definition: AssetDefinitionId::parse("@@XOR@@"), amount: output, dataspace: DataSpaceId::parse("0"));
    return output;
  }
}
"#.replace("@@SBD@@", &sbd.to_string()).replace("@@XOR@@", &xor.to_string());
    let pool_source = if production_pool {
        include_str!("fixtures/dlmm_pool.ko").to_owned()
    } else {
        pool_source
    };
    // Production SoraSwap template with the current typed contract import;
    // its reviewed custody inputs and the two asset identities are rendered
    // for this isolated ledger. The import binds the exact compiled pool below.
    let wrapper_source = include_str!("fixtures/autonomous_payout.ko.template")
        .replace(
            "@@PAYOUT_VAULT_ACCOUNT_ID@@",
            &wrapper.subject_id().to_string(),
        )
        .replace("@@POOL_VAULT_ACCOUNT_ID@@", &pool.subject_id().to_string())
        .replace("@@REWARD_POOL_ACCOUNT_ID@@", &reward_pool.to_string())
        .replace("@@POOL_CONTRACT_ADDRESS@@", &pool.to_string())
        .replace("7ZepsJTHCVLKsrFFNZGSRGZgvBhv", &sbd.to_string())
        .replace("6TEAJqbb8oEPmLncoNiMRbLEK6tw", &xor.to_string());
    let install = |stx: &mut StateTransaction<'_, '_>,
                   address: &ContractAddress,
                   source: &str,
                   imported_pool: Option<&[u8]>| {
        let (code, report) = if let Some(pool) = imported_pool {
            use kotodama_lang::linker::{
                SourceContractArtifact, SourceLinkRequest, SourceModuleUnit,
            };
            let output = kotodama_lang::driver::BuildDriver::new(
                kotodama_lang::session::CompilerSession::default(),
                "validation-fee-production-wrapper",
            )
            .compile_project(
                SourceLinkRequest {
                    root: SourceModuleUnit {
                        source_name: "autonomous_payout.ko".into(),
                        source: source.into(),
                    },
                    artifacts: vec![SourceContractArtifact {
                        source_name: "dlmm_pool.to".into(),
                        artifact: pool.to_vec(),
                    }],
                    sources: Vec::new(),
                    imports: Vec::new(),
                    packages: Vec::new(),
                },
                "autonomous_payout.ko",
            )
            .expect("compile wrapper against exact production pool interface");
            (output.artifact, output.report)
        } else {
            let (code, _, report) = kotodama_lang::compiler::Compiler::new()
                .compile_source_with_manifest_and_report(source)
                .expect("compile real contract frames");
            (code, report)
        };
        let metadata = ivm::ProgramMetadata::parse(&code).unwrap();
        let literal_bytes = metadata
            .literal_section
            .map_or(0, |section| section.code_offset - section.start);
        eprintln!(
            "payout gas artifact: contract={address}, code_hash={}, bytes={}, nested_artifact_gas={}, \
             header={}, interface_and_debug={}, literals={}, code={}, mode={}, max_cycles={}",
            report.artifact_hash,
            code.len(),
            ivm::gas::CONSERVATIVE_SYSCALL_INPUT_MULTIPLIER * code.len() as u64,
            metadata.header_len,
            metadata.code_offset - metadata.header_len - literal_bytes,
            literal_bytes,
            code.len() - metadata.code_offset,
            metadata.metadata.mode,
            metadata.metadata.max_cycles,
        );
        for function in &report.budget_report {
            eprintln!(
                "payout gas function: contract={address}, name={}, bytes={}, frame_bytes={}",
                function.function_name, function.bytecode_bytes, function.frame_bytes,
            );
        }
        let verified = ivm::verify_contract_artifact(&code).unwrap();
        let hash = crate::smartcontracts::code::register_code_bytes(
            deployer,
            DataSpaceId::UNIVERSAL,
            code.clone(),
            stx,
        )
        .unwrap();
        crate::smartcontracts::code::register_manifest(
            deployer,
            DataSpaceId::UNIVERSAL,
            verified
                .manifest
                .try_signed(
                    manifest_signing.context(),
                    manifest_signing.max_frame_bytes(),
                    &key_pair(55),
                )
                .expect("sign bounded fixture manifest"),
            stx,
        )
        .unwrap();
        stx.world
            .bind_inactive_contract_subject_for_testing(address.clone(), deployer.clone());
        crate::smartcontracts::code::activate_instance(deployer, address.clone(), 1, hash, stx)
            .unwrap();
        (code, hash)
    };
    let (pool_code, pool_hash) = install(stx, &pool, &pool_source, None);
    let (wrapper_code, wrapper_hash) = install(stx, &wrapper, &wrapper_source, Some(&pool_code));
    for address in [&pool, &wrapper] {
        stx.world.add_account_permission(
            &wrapper.subject_id(),
            iroha_executor_data_model::permission::smart_contract::CanUseContractPermission {
                contract: address.clone(),
                permission: if address == &pool {
                    "SwapQuotePublic"
                } else {
                    "Payout"
                }
                .parse()
                .unwrap(),
            }
            .into(),
        );
    }
    let treasury_sbd = AssetId::new(sbd.clone(), wrapper.subject_id());
    stx.world.add_account_permission(
        &pool.subject_id(),
        iroha_executor_data_model::permission::asset::CanTransferAsset {
            asset: treasury_sbd.clone(),
        }
        .into(),
    );
    let pool_funding = if production_pool {
        vec![
            (AssetId::new(xor.clone(), deployer.clone()), 1000u64),
            (AssetId::new(sbd.clone(), deployer.clone()), 1000u64),
        ]
    } else {
        vec![(AssetId::new(xor.clone(), pool.subject_id()), 20u64)]
    };
    for (id, amount) in std::iter::once((treasury_sbd.clone(), 10u64)).chain(pool_funding) {
        let (id, value) = Asset::new(id, Quantity::from(amount)).into_key_value();
        stx.world.assets.insert(id, value);
    }
    if production_pool {
        for entrypoint in ["hajimari", "seed_bin"] {
            stx.world.add_account_permission(deployer,
                if entrypoint == "hajimari" {
                    iroha_executor_data_model::permission::smart_contract::CanInvokeContractEntrypoint {
                        contract: pool.clone(), entrypoint: entrypoint.to_owned(),
                    }.into()
                } else {
                    iroha_executor_data_model::permission::smart_contract::CanUseContractPermission {
                        contract: pool.clone(), permission: "OperatePool".parse().unwrap(),
                    }.into()
                });
        }
        for asset in [&xor, &sbd] {
            stx.world.add_account_permission(
                &pool.subject_id(),
                iroha_executor_data_model::permission::asset::CanTransferAsset {
                    asset: AssetId::new(asset.clone(), deployer.clone()),
                }
                .into(),
            );
        }
    }
    setup.apply();
    if production_pool {
        super::runtime_dlmm_tests::execute_signed_pool(
            block,
            &pool,
            &pool_code,
            &key_pair(55),
            "hajimari",
            Json::from(norito::json!({
                "base_asset": (xor.to_string()), "quote_asset": (sbd.to_string()),
                "vault_account": (pool.subject_id().to_string()), "fee_pips": "3000",
                "bin_step": "1", "active_bin": "1000", "impact_cap_bps": "10000",
                "min_reserve_base": "0", "min_reserve_quote": "0", "max_bins_per_swap": "32",
                "bin_liquidity_cap": "0",
            })),
        )
        .expect("signed initialization of the actual nested production pool");
        super::runtime_dlmm_tests::execute_signed_pool(
            block,
            &pool,
            &pool_code,
            &key_pair(55),
            "seed_bin",
            Json::from(norito::json!({
                "position_id": "wrapper-liquidity", "bin_id": "1000",
                "base_amount": "1000", "quote_amount": "1000",
            })),
        )
        .expect("signed funding of the actual nested production pool");
    }
    WrapperFixture {
        pool,
        wrapper,
        reward_pool,
        xor,
        expected_output,
        minimum_output,
        pool_hash,
        pool_artifact_bytes: pool_code.len(),
        pool_full_wire_hash: Hash::new(&pool_code),
        wrapper_code,
        wrapper_hash,
        treasury_sbd,
    }
}

// One actual host/authorization/plan-validation path for the maintained gate
// and the explicit diagnostic. Its caller owns the transaction and alone may
// publish it; this preview never executes queued transfers or applies overlays.
struct WrapperEffectsPreview {
    ordered: Vec<(AccountId, InstructionBox)>,
    treasury_xor: AssetId,
    gas_used: u64,
}

#[inline(never)]
fn preview_wrapper_effects(
    stx: &mut StateTransaction<'_, '_>,
    fixture: &WrapperFixture,
    preview_vm_gas_limit: u64,
) -> WrapperEffectsPreview {
    let pool = fixture.pool.clone();
    let wrapper = fixture.wrapper.clone();
    let reward_pool = fixture.reward_pool.clone();
    let xor = fixture.xor.clone();
    let minimum_output = fixture.minimum_output;
    let pool_hash = fixture.pool_hash;
    let wrapper_code = fixture.wrapper_code.clone();
    let wrapper_hash = fixture.wrapper_hash;
    let treasury_xor = AssetId::new(xor.clone(), wrapper.subject_id());
    assert!(
        stx.world.assets.get(&treasury_xor).is_none(),
        "zero initial XOR uses the canonical absent-asset representation"
    );
    let scope = hex::encode(Hash::new(wrapper.to_string().as_bytes()).as_ref());
    for (index, amount) in [(0i128, "10"), (1, minimum_output)] {
        let base: Name = "ValidationFeeConversion".parse().unwrap();
        let encoded = encode_fixture_int_map_key(index);
        let relative = ivm::host::canonical_state_map_path(&base, &encoded).unwrap();
        stx.world.smart_contract_state.insert(
            format!("sc/{scope}/{relative}").parse().unwrap(),
            encode_conversion_quantity_state_value(&amount.parse().unwrap()).unwrap(),
        );
    }
    let context = crate::executor::ContractRuntimeExecutionContext {
        contract_address: wrapper.clone(),
        contract_subject: wrapper.subject_id(),
        contract_alias: None,
        entrypoint: "autonomous_validation_fee_tick".to_owned(),
    };
    let prepared =
        ivm::prepare_contract(std::sync::Arc::<[u8]>::from(wrapper_code.clone())).unwrap();
    let mut host = CoreHostImpl::new(wrapper.subject_id());
    host.set_query_state(stx);
    host.set_durable_state_snapshot_from_world(&stx.world);
    host.set_contract_runtime_context(Some(context.clone()));
    host.set_contract_entrypoint_authorization(Some(ContractEntrypointAuthorizationSnapshot::new(
        wrapper.subject_id(),
        context.entrypoint.clone(),
        iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Permission(
            "Payout".parse().unwrap(),
        ),
        &crate::smartcontracts::code::BoundContractIdentity {
            lifecycle_revision: 1,
            contract_address: wrapper.clone(),
            contract_alias: None,
            contract_alias_binding: None,
            code_hash: wrapper_hash,
        },
    )));
    let mut vm = ivm::IVM::new(preview_vm_gas_limit);
    vm.load_program(&wrapper_code).unwrap();
    vm.set_program_counter(prepared.entrypoint_pc(&context.entrypoint).unwrap())
        .unwrap();
    vm.run_with_host(&mut host)
        .expect("real wrapper and nested pool execute");
    let preview_gas_used = preview_vm_gas_limit - vm.remaining_gas();
    let artifacts = host.into_execution_artifacts(Some(context)).unwrap();
    let ordered = artifacts.queued_instructions_with_authority();
    assert_eq!(
        ordered
            .iter()
            .map(|(authority, _)| authority.clone())
            .collect::<Vec<_>>(),
        vec![pool.subject_id(), pool.subject_id(), wrapper.subject_id()]
    );
    let mut binding = treasury_payout_binding(wrapper.clone(), &wrapper_code);
    binding.pool_contract_address = pool.clone();
    binding.pool_vault_account_id = pool.subject_id();
    binding.pool_code_hash = pool_hash.into();
    binding.reward_pool_account_id = reward_pool.clone();
    let terms = ValidationFeePayoutTerms {
        debit_ds: "10".parse().unwrap(),
        min_xor_out: minimum_output.parse().unwrap(),
        xor_scale: 9,
    };
    assert!(
        validate_treasury_payout_effect_plan(
            &artifacts.queued_instructions_by_authority(),
            &ordered,
            &binding,
            &terms
        )
        .unwrap()
    );
    // The artifact check is a read-only preview. The maintained gate then
    // invokes its callback through an authorized signed ExecuteTrigger;
    // the explicit gas diagnostic drops every effect and its transaction.
    // Neither preview claims scheduled or active retail-policy qualification.
    drop(artifacts);
    WrapperEffectsPreview {
        ordered,
        treasury_xor,
        gas_used: preview_gas_used,
    }
}

// The preview host and VM must finish before the signed root invokes the real VM.
#[inline(never)]
fn prepare_wrapper_callback(
    block: &mut crate::state::StateBlock<'_>,
    deployer: &AccountId,
    fixture: &WrapperFixture,
) -> WrapperPreview {
    let wrapper = fixture.wrapper.clone();
    let wrapper_hash = fixture.wrapper_hash;
    let mut setup = block.transaction_for_callback_testing();
    let WrapperEffectsPreview {
        ordered,
        treasury_xor,
        gas_used: preview_gas_used,
    } = preview_wrapper_effects(&mut setup, fixture, WRAPPER_BLOCK_GAS_LIMIT);
    eprintln!("payout gas execution: contract={wrapper}, total_gas={preview_gas_used}");
    assert!(
        preview_gas_used > 0 && preview_gas_used < WRAPPER_BLOCK_GAS_LIMIT,
        "the real nested frame execution must fit the original default block policy"
    );
    let stx = &mut setup;
    let trigger_id: iroha_data_model::trigger::TriggerId = "wrapper_effect_budget".parse().unwrap();
    let action = Action::new(
        Executable::ContractCall(ContractInvocation {
            contract_address: wrapper.clone(),
            expected_code_hash: wrapper_hash,
            entrypoint: "autonomous_validation_fee_tick".to_owned(),
            arguments: None,
        }),
        Repeats::Exactly(1),
        wrapper.subject_id(),
        iroha_data_model::events::execute_trigger::ExecuteTriggerEventFilter::new()
            .for_trigger(trigger_id.clone())
            .under_authority(wrapper.subject_id()),
    )
    .unwrap();
    crate::smartcontracts::isi::triggers::isi::register_trigger_internal(
        &wrapper.subject_id(),
        stx,
        Trigger::new(trigger_id.clone(), action),
        None,
    )
    .unwrap();
    stx.world.add_account_permission(
        deployer,
        iroha_executor_data_model::permission::trigger::CanExecuteTrigger {
            trigger: trigger_id.clone(),
        }
        .into(),
    );
    setup.apply();
    WrapperPreview {
        ordered,
        trigger_id,
        treasury_xor,
        gas_used: preview_gas_used,
    }
}

#[test]
fn compiled_fee_wrapper_preserves_nested_pool_authorities_and_actual_output() {
    for production_pool in [false, true] {
        with_wrapper_block(|block, deployer| {
            let fixture = install_wrapper_fixture(block, deployer, production_pool);
            let WrapperPreview {
                ordered,
                trigger_id,
                treasury_xor,
                gas_used: preview_gas_used,
            } = prepare_wrapper_callback(block, deployer, &fixture);
            let callbacks = super::runtime_dlmm_tests::execute_signed_body(
                block,
                &key_pair(55),
                Executable::Instructions(
                    vec![iroha_data_model::isi::ExecuteTrigger::new(trigger_id.clone()).into()]
                        .into(),
                ),
            )
            .unwrap_or_else(|error| {
                panic!(
                    "signed trigger executes the original nested frame authorizations: \
                     production_pool={production_pool}, preview_gas={preview_gas_used}, \
                     block_gas_limit={}, block_gas_used={}, error={error:?}",
                    block.gas_limit_per_block, block.gas_used_in_block,
                )
            });
            assert_eq!(
                callbacks.len(),
                1,
                "one original callback is completed exactly once"
            );
            assert_eq!(callbacks[0].id, trigger_id);
            assert_eq!(
                callbacks[0].instructions.0.as_ref(),
                ordered
                    .iter()
                    .map(|(_, instruction)| instruction.clone())
                    .collect::<Vec<_>>()
                    .as_slice(),
                "actual signed callback effects reproduce the exact reviewed preview",
            );
            let snapshot = block.transaction();
            let stx = &snapshot;
            assert!(
                stx.world
                    .triggers
                    .by_call_triggers()
                    .get(&trigger_id)
                    .is_none(),
                "the actual one-shot callback completed"
            );
            let paid = AssetId::new(fixture.xor, fixture.reward_pool);
            assert_eq!(
                stx.world.assets.get(&paid).unwrap().as_ref(),
                &fixture.expected_output
            );
            assert!(stx.world.assets.get(&fixture.treasury_sbd).is_none());
            assert!(
                stx.world.assets.get(&treasury_xor).is_none(),
                "all actual pool output is atomically forwarded to reward custody"
            );
        });
    }
}

// Compare complete ledger balances and every durable contract-state byte after
// dropping the diagnostic's unapplied transaction, rather than assuming rollback.
fn wrapper_ledger_snapshot(
    block: &crate::state::StateBlock<'_>,
) -> (Vec<(AssetId, Quantity)>, Vec<(StatePath, Vec<u8>)>) {
    (
        block
            .world
            .assets
            .iter()
            .map(|(id, value)| (id.clone(), value.as_ref().clone()))
            .collect(),
        block
            .world
            .smart_contract_state
            .iter()
            .map(|(path, bytes)| (path.clone(), bytes.clone()))
            .collect(),
    )
}

#[test]
#[ignore = "Explicit native gas diagnostic with finite8M preview; never a default4M callback qualification"]
fn measure_complete_native_production_wrapper_gas_without_publishing_preview() {
    const DIAGNOSTIC_PREVIEW_VM_GAS_LIMIT: u64 = 8_000_000;
    with_wrapper_block(|block, deployer| {
        let fixture = install_wrapper_fixture(block, deployer, true);
        assert_eq!(block.gas_limit_per_block, WRAPPER_BLOCK_GAS_LIMIT);
        let default_block_gas_limit = block.gas_limit_per_block;
        let fragments_before = block.committed_fragment_count();
        let block_gas_before = block.gas_used_in_block;
        let ledger_before = wrapper_ledger_snapshot(block);
        let mut preview = block.transaction_for_callback_testing();
        let WrapperEffectsPreview {
            ordered,
            treasury_xor,
            gas_used,
        } = preview_wrapper_effects(&mut preview, &fixture, DIAGNOSTIC_PREVIEW_VM_GAS_LIMIT);
        assert!(gas_used > 0 && gas_used < DIAGNOSTIC_PREVIEW_VM_GAS_LIMIT);
        let input = direct_conversion_transfer(&ordered[0].1).unwrap();
        let output = direct_conversion_transfer(&ordered[1].1).unwrap();
        let reserve = direct_conversion_transfer(&ordered[2].1).unwrap();
        assert_eq!(input.object, Quantity::from(10u64));
        assert_eq!(output.object, fixture.expected_output);
        assert_eq!(reserve.object, fixture.expected_output);
        assert_eq!(output.source.definition, fixture.xor);
        assert_eq!(reserve.source, treasury_xor);
        let artifact_byte_gas = ivm::gas::CONSERVATIVE_SYSCALL_INPUT_MULTIPLIER
            .checked_mul(u64::try_from(fixture.pool_artifact_bytes).unwrap())
            .unwrap();
        let non_artifact_gas = gas_used.checked_sub(artifact_byte_gas).unwrap();
        let ordered_transfer_legs = ordered.len();
        let native_sbd_input = input.object.clone();
        let native_xor_output = output.object.clone();
        let native_xor_reward_reserve = reserve.object.clone();
        // Neither queued effects nor the preview overlay are committed or used
        // to register a callback. The actual signed/default4M gate stays separate.
        drop(ordered);
        drop(preview);
        assert_eq!(wrapper_ledger_snapshot(block), ledger_before);
        assert_eq!(block.committed_fragment_count(), fragments_before);
        assert_eq!(block.gas_used_in_block, block_gas_before);
        assert_eq!(block.gas_limit_per_block, WRAPPER_BLOCK_GAS_LIMIT);
        eprintln!(
            "payout native diagnostic: default_block_gas={}, diagnostic_preview_vm_gas={}, \
             pool_code_hash={}, pool_full_wire_hash={}, pool_artifact_bytes={}, \
             wrapper_code_hash={}, wrapper_full_wire_hash={}, wrapper_artifact_bytes={}, \
             nested_artifact_byte_gas={}, complete_native_preview_gas={}, \
             native_preview_non_artifact_gas={}, native_preview_excess_over_default={}, \
             ordered_transfer_legs={}, native_sbd_input={}, native_xor_output={}, \
             native_xor_reward_reserve={}, scope=unapplied-preview-only",
            default_block_gas_limit,
            DIAGNOSTIC_PREVIEW_VM_GAS_LIMIT,
            fixture.pool_hash,
            fixture.pool_full_wire_hash,
            fixture.pool_artifact_bytes,
            fixture.wrapper_hash,
            Hash::new(&fixture.wrapper_code),
            fixture.wrapper_code.len(),
            artifact_byte_gas,
            gas_used,
            non_artifact_gas,
            gas_used.saturating_sub(WRAPPER_BLOCK_GAS_LIMIT),
            ordered_transfer_legs,
            native_sbd_input,
            native_xor_output,
            native_xor_reward_reserve,
        );
    });
}
