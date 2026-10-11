//! Genuine native interval source/authority, finite work and retirement controls.

use super::*;
use crate::{
    state::{StateReadOnly, World},
    sumeragi::{
        certified_chain::relation_counts,
        test_chain::{CertifiedTestChain, Signers, TestChainConfig},
    },
};
use norito::core::DecodeBudgetContext;

fn test_budget(frames: iroha_allocation::AllocationBudget) -> NativeFinalityProofBudget {
    NativeFinalityProofBudget::new(
        frames,
        iroha_allocation::AllocationBudget::new(33_312_848),
        norito::DecodeLimits::new(
            2_562_487,
            MAX_FINALITY_BLOCK_BYTES,
            33_312_848,
            33_312_848,
            norito::core::MAX_VALUE_NESTING_DEPTH,
        ),
    )
}

fn limits(from: u64, to: u64) -> NativeFinalityProofIntervalLimits {
    NativeFinalityProofIntervalLimits::new(
        NonZeroU64::new(from).unwrap(),
        NonZeroU64::new(to).unwrap(),
        NonZeroUsize::new(MAX_FINALITY_BLOCK_BYTES).unwrap(),
        NonZeroUsize::new(usize::MAX).unwrap(),
        Instant::now() + std::time::Duration::from_secs(900),
    )
    .unwrap()
}
fn context() -> DecodeBudgetContext {
    DecodeBudgetContext::new(norito::DecodeLimits::new(
        1024 * 1024,
        MAX_FINALITY_BLOCK_BYTES,
        8 * 1024 * 1024,
        usize::MAX,
        128,
    ))
}
#[inline(never)]
fn with_chain(check: fn(&CertifiedTestChain)) {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 10_000)).unwrap();
    while chain.height() < 4 {
        chain.commit(Vec::new());
    }
    check(&chain);
}

#[test]
fn finite_interval_long_prefix_fits_one_original_request_working_set() {
    with_long_chain(check_long_prefix);
}

#[inline(never)]
fn with_long_chain(check: fn(&CertifiedTestChain)) {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 10_000)).unwrap();
    while chain.height() < 96 {
        chain.commit(Vec::new());
    }
    check(&chain);
}

#[inline(never)]
fn check_long_prefix(chain: &CertifiedTestChain) {
    // Original bodyless Torii reservation remains W=48,000,000. Its source
    // and graph corridors are independent, fixed at every historical height.
    let frames = iroha_allocation::AllocationBudget::new(2_562_487);
    let owner = test_budget(frames.clone());
    let result = chain.state().read_finality_proof_interval(
        &owner,
        &limits(chain.height(), chain.height()),
        &AtomicBool::new(false),
    );
    if let Err(error) = &result {
        panic!(
            "one bounded finality output at height {} must not exhaust memory by charging retired ancestors: {error:?}; retained physical={}",
            chain.height(),
            frames.reserved_bytes(),
        );
    }
    let interval = result.unwrap();
    assert_eq!(interval.len(), 1);
    assert_eq!(
        interval.proof(0).unwrap().block_header.height().get(),
        chain.height()
    );
    interval.proof(0).unwrap().decode_checked().unwrap();
    drop(interval);
    assert_eq!(frames.reserved_bytes(), 0);
}

#[test]
#[ignore = "requires an explicitly selected public canonical history snapshot"]
fn finite_interval_public_snapshot_budget_diagnostic() {
    use iroha_data_model::block::{SharedSignedBlock, decode_framed_signed_block};
    let directory = std::path::PathBuf::from(
        std::env::var_os("FINALITY_DIAGNOSTIC_BLOCKS").expect("public canonical frames directory"),
    );
    let chain_id: ChainId = std::env::var("FINALITY_DIAGNOSTIC_CHAIN_ID")
        .expect("configured public chain ID")
        .parse()
        .unwrap();
    let kura = Kura::blank_kura_for_testing();
    let shells = iroha_allocation::AllocationBudget::new(16 * 1024 * 1024);
    let mut hashes = Vec::new();
    for height in 1u64.. {
        let path = directory.join(format!("{height:020}.norito"));
        if !path.exists() {
            break;
        }
        let original = std::fs::read(path).unwrap();
        let block = decode_framed_signed_block(&original).unwrap();
        assert_eq!(block.header().height().get(), height);
        hashes.push(block.hash());
        let block = SharedSignedBlock::reserve(&shells)
            .unwrap()
            .initialize(block);
        kura.store_block(block).unwrap();
    }
    assert!(!hashes.is_empty());
    let network = NetworkId::from_genesis_hash(hashes[0]);
    let source = NativeFinalityProofSource::new(&chain_id, &network, &hashes, &kura);
    for (from, to) in [
        (1, 1),
        (2, 2),
        (45, 45),
        (46, 46),
        (hashes.len() as u64, hashes.len() as u64),
        (1, hashes.len() as u64),
    ] {
        let frames = iroha_allocation::AllocationBudget::new(2_562_487);
        let graphs = iroha_allocation::AllocationBudget::new(33_312_848);
        let owner = NativeFinalityProofBudget::new(
            frames.clone(),
            graphs.clone(),
            norito::DecodeLimits::new(
                2_562_487,
                MAX_FINALITY_BLOCK_BYTES,
                33_312_848,
                33_312_848,
                norito::core::MAX_VALUE_NESTING_DEPTH,
            ),
        );
        let interval =
            build_proof_interval(&source, &owner, &limits(from, to), &AtomicBool::new(false))
                .unwrap_or_else(|error| {
                    panic!("public canonical interval{from}..={to}: {error:?}")
                });
        assert_eq!(interval.len(), usize::try_from(to - from + 1).unwrap());
        assert_eq!(
            graphs.reserved_bytes(),
            0,
            "all verifier graphs retired before returning exact proof destinations"
        );
        for index in 0..interval.len() {
            let proof = interval.proof(index).unwrap();
            assert_eq!(
                proof.block_header.hash(),
                hashes[usize::try_from(from).unwrap() - 1 + index]
            );
            proof.decode_checked().unwrap();
        }
        eprintln!(
            "interval={from}..={to} verified={} frame_peak={} graph_peak={} graph_retained={}",
            interval.len(),
            frames.peak_reserved_bytes(),
            graphs.peak_reserved_bytes(),
            graphs.reserved_bytes()
        );
        drop(interval);
        assert_eq!(frames.reserved_bytes(), 0);
    }
}

#[test]
#[ignore = "requires an explicitly selected real public verifier pack"]
fn finite_interval_real_verifier_install_fits_original_request_working_set() {
    use crate::state::WorldReadOnly as _;
    use iroha_core_zk::kagemusha_wallet_artifacts_v1::{
        InstallationV1, InstalledVerifierPackV1, VerifierPackV1,
    };
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{
        account::{Account, AccountId},
        asset::{AssetBalancePolicy, AssetBalanceScope, AssetDefinition, AssetDefinitionId},
        isi::{
            Grant, Register,
            kagemusha_wallet::{KagemushaWalletLedgerActionV1, KagemushaWalletLedgerV1},
        },
        kagemusha::{
            KagemushaDevicePublicKeyV1, KagemushaWalletArtifactManifestV1,
            KagemushaWalletAssetScopeV1, KagemushaWalletSchemeV1,
            KagemushaWalletSignerCertificateBodyV1, KagemushaWalletSignerCertificateV1,
            KagemushaWalletSignerOutputV1, KagemushaWalletSignerRoleV1,
        },
        permission::Permission,
    };
    use iroha_executor_data_model::permission::asset_definition::CanManageKagemushaWallet;
    use iroha_primitives::numeric::NumericSpec;
    use mv::storage::StorageReadOnly as _;
    use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};

    let original = std::fs::read(
        std::env::var_os("FINALITY_DIAGNOSTIC_VERIFIER_PACK").expect("public verifier pack"),
    )
    .unwrap();
    assert!(
        original.len() >= 650_000,
        "exercise the actual large install payload"
    );
    let pack_bytes = original.len();
    let mut pack = VerifierPackV1::decode_canonical(&original).unwrap();
    let mut scheme: KagemushaWalletSchemeV1 = norito::decode_canonical_with_limits(
        &pack.scheme,
        norito::canonical_decode_limits(pack.scheme.len()),
    )
    .unwrap();
    let old_manifest =
        KagemushaWalletArtifactManifestV1::decode_canonical(&pack.manifest, &scheme).unwrap();
    InstalledVerifierPackV1::load(
        &original,
        InstallationV1 {
            scheme_id: scheme.scheme_id(),
            manifest_digest: old_manifest.manifest_digest(),
        },
    )
    .expect("authenticate the exact public verifier originals before re-signing test authority");

    let mut config = TestChainConfig::new(World::new(), 10_000);
    let key = KeyPair::from_seed(vec![95; 32], Algorithm::Ed25519);
    let reserve = AccountId::new(key.public_key().clone());
    let definition = AssetDefinitionId::from_uuid_bytes([
        0x2f, 0x17, 0xc7, 0x24, 0x66, 0xf8, 0x4a, 0x4b, 0xb8, 0xa8, 0xe2, 0x48, 0x84, 0xfd, 0xcd,
        0x2f,
    ])
    .unwrap();
    let permission: Permission = CanManageKagemushaWallet {
        asset_definition: definition.clone(),
    }
    .into();
    config.genesis_instructions = vec![
        Register::account(Account::new(reserve.clone())).into(),
        Register::asset_definition(AssetDefinition::new(
            definition.clone(),
            "Finality native verifier install",
            NumericSpec::fractional(2),
            AssetBalancePolicy::Global,
            None,
        ))
        .into(),
        Grant::account_permission(permission, reserve.clone()).into(),
    ];
    let mut chain = CertifiedTestChain::start(config).unwrap();
    let asset = {
        let view = chain.state().view();
        KagemushaWalletAssetScopeV1::new(
            definition.clone(),
            view.world()
                .axt_asset_incarnations()
                .get(&definition)
                .unwrap(),
            2,
        )
        .unwrap()
    };

    // Only the authority frames are re-signed for this local certified chain.
    // Every descriptor, VK, allowlist and catalog commitment remains exact;
    // these public fixture keys confer no deployed authority or source admission.
    let root = SigningKey::from_bytes((&[0x11; 32]).into()).unwrap();
    let artifact = SigningKey::from_bytes((&[0x18; 32]).into()).unwrap();
    let public = |key: &SigningKey| {
        KagemushaDevicePublicKeyV1::from_sec1_bytes(
            key.verifying_key().to_encoded_point(false).as_bytes(),
        )
        .unwrap()
    };
    let sign = |key: &SigningKey, message: &[u8]| {
        let signature: Signature = key.sign(message);
        KagemushaWalletSignerOutputV1::Raw(signature.to_bytes().into())
    };
    scheme.network_id = *chain.network_id().as_bytes();
    scheme.scheme_root_key = public(&root);
    let certificate_body = KagemushaWalletSignerCertificateBodyV1 {
        version: 1,
        scheme_id: scheme.scheme_id(),
        role: KagemushaWalletSignerRoleV1::Artifact,
        key: public(&artifact),
        serial: 1,
    };
    let certificate = KagemushaWalletSignerCertificateV1::sign(
        certificate_body,
        &scheme,
        sign(&root, &certificate_body.signing_message()),
    )
    .unwrap();
    let mut manifest_body = old_manifest.body;
    manifest_body.network_id = scheme.network_id;
    manifest_body.signer_certificate = certificate.certificate_digest();
    let manifest = KagemushaWalletArtifactManifestV1::sign(
        manifest_body,
        &certificate,
        sign(&artifact, &manifest_body.signing_message()),
    )
    .unwrap();
    pack.scheme = scheme.to_canonical_bytes().unwrap();
    pack.signer_certificate = certificate.to_canonical_bytes().unwrap();
    pack.manifest = manifest.to_canonical_bytes().unwrap();
    let pack = pack.to_canonical_bytes().unwrap();
    assert_eq!(
        pack.len(),
        pack_bytes,
        "preserve the full real pack geometry"
    );
    InstalledVerifierPackV1::load(
        &pack,
        InstallationV1 {
            scheme_id: scheme.scheme_id(),
            manifest_digest: manifest.manifest_digest(),
        },
    )
    .expect("authenticate the genuinely signed local test installation");
    let register = KagemushaWalletLedgerV1::new(
        scheme.scheme_id(),
        KagemushaWalletLedgerActionV1::Register {
            scheme: scheme.to_canonical_bytes().unwrap(),
            asset: norito::encode_canonical(&asset).unwrap(),
            reserve,
            balance_scope: AssetBalanceScope::Global,
        },
    );
    let install = KagemushaWalletLedgerV1::new(
        scheme.scheme_id(),
        KagemushaWalletLedgerActionV1::InstallVerifierPack {
            asset: asset.asset_digest(),
            manifest_digest: manifest.manifest_digest(),
            pack,
        },
    );
    // Routing for Install reads the committed registration, so retain the same
    // two-transaction sequence used by deployment instead of a same-tx shortcut.
    let transaction = chain.sign(&key, [register.into()], 10_001);
    assert_eq!(chain.commit(vec![transaction]), [true]);
    assert_eq!(chain.height(), 2);
    let transaction = chain.sign(&key, [install.into()], 10_002);
    assert_eq!(chain.commit(vec![transaction]), [true]);
    assert_eq!(chain.height(), 3);
    assert!(
        chain
            .committed(3)
            .block()
            .output_results()
            .all(|result| result.is_ok())
    );
    let install_wire = chain.committed(3).block().encode_wire().unwrap();
    assert!(install_wire.len() > pack_bytes);
    chain.commit(Vec::new());
    // Exact original bodyless Torii geometry. These choices come from the same
    // fixed aggregate pool; a larger per-request reservation reduces concurrency.
    for (working, frame_bytes, graph_bytes, allocated, target_succeeds, gap_succeeds) in [
        (48_000_000, 2_562_487, 33_312_848, 35_875_335, false, false),
        (
            128_000_000,
            7_895_820,
            102_646_182,
            110_542_002,
            true,
            false,
        ),
        (
            192_000_000,
            12_162_487,
            158_112_848,
            170_275_335,
            true,
            true,
        ),
    ] {
        for height in [3, 4] {
            let frames = iroha_allocation::AllocationBudget::new(frame_bytes);
            let graphs = iroha_allocation::AllocationBudget::new(graph_bytes);
            let owner = NativeFinalityProofBudget::new(
                frames.clone(),
                graphs.clone(),
                norito::DecodeLimits::new(
                    frame_bytes,
                    frame_bytes,
                    allocated,
                    allocated,
                    norito::core::MAX_VALUE_NESTING_DEPTH,
                ),
            );
            let result = chain.state().read_finality_proof_interval(
                &owner,
                &limits(height, height),
                &AtomicBool::new(false),
            );
            if !(if height == 3 {
                target_succeeds
            } else {
                gap_succeeds
            }) {
                let expected = crate::execution_attempt::ExecutionDeferred::from(
                    ivm::error::ExecutionDeferral::ActiveMemoryCapacity,
                );
                assert!(
                    matches!(result, Err(crate::state::FinalityProofIntervalReadError::Proof(
                        NativeFinalityProofIntervalError::Deferred(ref local)))
                        if local == &expected)
                );
                assert_eq!(frames.reserved_bytes(), 0);
                assert_eq!(graphs.reserved_bytes(), 0);
                continue;
            }
            let interval = result.unwrap_or_else(|error| {
                panic!("real install target {height} original W={working}: {error:?}")
            });
            let proof = interval.proof(0).unwrap();
            assert_eq!(proof.block_header.height().get(), height);
            if height == 3 {
                assert_eq!(proof.block_wire, install_wire);
            }
            proof.decode_checked().unwrap();
            eprintln!(
                "real_install pack_bytes={pack_bytes} block_bytes={} target={height} W={working} frame_peak={} graph_peak={}",
                install_wire.len(),
                frames.peak_reserved_bytes(),
                graphs.peak_reserved_bytes()
            );
            assert_eq!(graphs.reserved_bytes(), 0);
            drop(interval);
            assert_eq!(frames.reserved_bytes(), 0);
        }
    }
}

#[test]
fn finite_interval_rejects_earlier_real_qc_changed_after_verification_before_publication() {
    with_chain(check_late_qc_change);
}
#[inline(never)]
fn check_late_qc_change(chain: &CertifiedTestChain) {
    let view = chain.state().view();
    let source = NativeFinalityProofSource::new(
        view.chain_id(),
        view.network_id(),
        view.block_hashes(),
        view.kura(),
    );
    // Refund assertions concern this request's original frame corridor, not
    // unrelated State/Kura cache ownership that can retire during the read.
    let budget = iroha_allocation::AllocationBudget::new(2_562_487);
    let owner = test_budget(budget.clone());
    let qc = chain
        .committed(2)
        .block()
        .commit_certificate()
        .unwrap()
        .commit_qc()
        .to_vec();
    let publication = chain
        .kura()
        .get_block(std::num::NonZeroUsize::new(2).unwrap(), &budget)
        .unwrap()
        .unwrap();
    let reserved = budget.reserved_bytes();
    let cancelled = AtomicBool::new(false);
    let result = build_interval(&source, &owner, &limits(3, 4), &cancelled, || {
        chain.corrupt_local_quorum_for_test(2, Signers::BelowQuorum);
    });
    assert!(
        matches!(result, Err(NativeFinalityProofIntervalError::Source { .. })),
        "completed interval cannot publish after an earlier real QC's source changes"
    );
    assert_eq!(budget.reserved_bytes(), reserved);
    assert!(super::super::build_proof(&view, 4).is_err());
    chain
        .kura()
        .corrupt_commit_certificate_for_testing(std::num::NonZeroUsize::new(2).unwrap(), Some(qc))
        .unwrap();
    let retained = build_proof_interval(&source, &owner, &limits(3, 4), &cancelled).unwrap();
    assert_eq!(
        retained.proof(1).unwrap(),
        &super::super::build_proof(&view, 4).unwrap()
    );
    assert!(budget.reserved_bytes() > reserved);
    drop(retained);
    assert_eq!(budget.reserved_bytes(), reserved);
    drop(publication);
}

#[cfg(unix)]
#[test]
fn finite_interval_rejects_same_bytes_replaced_original_journal_before_publication() {
    with_chain(check_late_source_replacement);
}
#[cfg(unix)]
#[inline(never)]
fn check_late_source_replacement(chain: &CertifiedTestChain) {
    let view = chain.state().view();
    let source = NativeFinalityProofSource::new(
        view.chain_id(),
        view.network_id(),
        view.block_hashes(),
        view.kura(),
    );
    // Observe only this request's pool: replacing canonical storage may also
    // retire unrelated node-cache backing from the execution pool.
    let budget = iroha_allocation::AllocationBudget::new(2_562_487);
    let owner = test_budget(budget.clone());
    let reserved = budget.reserved_bytes();
    let path = Kura::canonical_storage_path(&chain.kura().store_root()).join("blocks.data");
    let saved = path.with_extension("finite-proof-original");
    struct Restore<'a> {
        path: &'a std::path::Path,
        saved: &'a std::path::Path,
    }
    impl Drop for Restore<'_> {
        fn drop(&mut self) {
            if self.saved.exists() {
                std::fs::remove_file(self.path).unwrap();
                std::fs::rename(self.saved, self.path).unwrap();
            }
        }
    }
    let restore = Restore {
        path: &path,
        saved: &saved,
    };
    let cancelled = AtomicBool::new(false);
    let result = build_interval(&source, &owner, &limits(3, 4), &cancelled, || {
        std::fs::rename(&path, &saved).unwrap();
        std::fs::copy(&saved, &path).unwrap();
        assert_eq!(
            std::fs::read(&path).unwrap(),
            std::fs::read(&saved).unwrap()
        );
    });
    drop(restore);
    assert!(
        matches!(
            result,
            Err(NativeFinalityProofIntervalError::Source { .. })
                | Err(NativeFinalityProofIntervalError::Native(
                    NativeFinalityProofRefusal::NotInView { .. }
                ))
        ),
        "same bytes in a replacement namespace are not the original journal"
    );
    assert_eq!(budget.reserved_bytes(), reserved);
    let retried = build_proof_interval(&source, &owner, &limits(3, 4), &cancelled).unwrap();
    drop(retried);
    assert_eq!(budget.reserved_bytes(), reserved);
}

#[test]
fn finite_interval_keeps_original_malformed_target_before_bad_gap_order() {
    with_chain(check_first_target_order);
}
#[inline(never)]
fn check_first_target_order(chain: &CertifiedTestChain) {
    let view = chain.state().view();
    let source = NativeFinalityProofSource::new(
        view.chain_id(),
        view.network_id(),
        view.block_hashes(),
        view.kura(),
    );
    let owner = test_budget(view.execution_budget());
    chain.corrupt_local_quorum_for_test(2, Signers::BelowQuorum);
    chain
        .kura()
        .corrupt_commit_result_for_testing(std::num::NonZeroUsize::new(4).unwrap(), vec![0])
        .unwrap();
    let expected = super::super::build_proof(&view, 4).unwrap_err();
    let actual = build_proof_interval(&source, &owner, &limits(4, 4), &AtomicBool::new(false));
    assert!(matches!(
        &actual,
        Err(NativeFinalityProofIntervalError::Native(
            NativeFinalityProofRefusal::Malformed { height: 4 }
        ))
    ));
    let super::super::ProofError::Chain(expected) = expected else {
        panic!("ordinary native reader must reject the same malformed target")
    };
    let Err(NativeFinalityProofIntervalError::Native(actual)) = actual else {
        unreachable!()
    };
    assert_eq!(actual, NativeFinalityProofRefusal::from(expected));
}

#[test]
fn finite_interval_retained_native_refusal_outlives_refunded_graph_workspace() {
    // A returned refusal has no heap graph to retain after the physical phase.
    assert!(!std::mem::needs_drop::<NativeFinalityProofRefusal>());
    let frames = iroha_allocation::AllocationBudget::new(2_000_000);
    let graphs = iroha_allocation::AllocationBudget::new(2_000_000);
    let owner = NativeFinalityProofBudget::new(
        frames,
        graphs.clone(),
        norito::DecodeLimits::new(2_000_000, 2_000_000, 2_000_000, 2_000_000, 32),
    );
    let mut retained = Vec::new();
    for height in 1..=100 {
        let workspace = owner.workspace().unwrap();
        let error = workspace
            .stage(|| {
                norito::core::reserve_decode_allocation(128).unwrap();
                Err::<(), NativeFinalityProofIntervalError>(
                    ExecutionAttemptError::Rejected(ChainReadError::Malformed {
                        height,
                        reason: "x".repeat(128),
                    })
                    .into(),
                )
            })
            .unwrap_err();
        drop(workspace);
        assert_eq!(graphs.reserved_bytes(), 0);
        let NativeFinalityProofIntervalError::Native(refusal) = error else {
            unreachable!()
        };
        assert_eq!(refusal, NativeFinalityProofRefusal::Malformed { height });
        retained.push(refusal);
    }
    assert_eq!(retained.len(), 100);
    assert_eq!(graphs.reserved_bytes(), 0);
}

#[test]
fn finite_interval_signed_genesis_large_metadata_diagnostic_retires_with_workspace() {
    use iroha_data_model::{
        block::{SharedSignedBlock, SignedBlock},
        isi::{InstructionBox, SetParameter},
        parameter::{CustomParameter, Parameter, system::consensus_metadata},
        sumeragi_finality::{GenesisReadError, authenticated_genesis},
        transaction::{Executable, TransactionBuilder},
    };
    use iroha_primitives::json::{Json, MAX_JSON_BYTES};

    let config = TestChainConfig::new(World::new(), 10_000);
    let signer = config.genesis_key.clone();
    let chain_id = config.chain_id.clone();
    let chain = CertifiedTestChain::start(config).unwrap();
    let mut replacements = 0;
    let mut diagnostic_len = 0;
    let transactions = chain
        .genesis()
        .external_transactions()
        .map(|source| {
            let Executable::Instructions(instructions) = source.instructions() else {
                panic!("genuine genesis must contain explicit instructions");
            };
            let instructions: Vec<InstructionBox> = instructions
                .iter()
                .map(|instruction| {
                    if let Some(set) = instruction.as_any().downcast_ref::<SetParameter>()
                        && let Parameter::Custom(custom) = set.inner()
                        && custom.id() == &consensus_metadata::handshake_meta_id()
                    {
                        replacements += 1;
                        let norito::json::Value::Object(mut metadata) =
                            norito::json::parse_value(custom.payload().get()).unwrap()
                        else {
                            panic!("signed consensus metadata must be an object");
                        };
                        let norito::json::Value::String(mode) = metadata.remove("mode").unwrap()
                        else {
                            panic!("signed consensus mode must be a string");
                        };
                        diagnostic_len = MAX_JSON_BYTES - custom.payload().get().len() + mode.len();
                        metadata.insert(
                            "mode".into(),
                            norito::json::Value::String("x".repeat(diagnostic_len)),
                        );
                        let payload = Json::new(norito::json::Value::Object(metadata));
                        assert_eq!(payload.get().len(), MAX_JSON_BYTES);
                        return SetParameter::new(Parameter::Custom(CustomParameter::new(
                            consensus_metadata::handshake_meta_id(),
                            payload,
                        )))
                        .into();
                    }
                    instruction.clone()
                })
                .collect();
            let mut builder = TransactionBuilder::new_genesis(
                source.authority().clone(),
                source.fee_payment_intent().clone(),
            );
            builder.set_creation_time(source.creation_time());
            builder
                .with_instructions(instructions)
                .sign(signer.private_key())
        })
        .collect();
    assert_eq!(replacements, 1);
    assert!(diagnostic_len > MAX_JSON_BYTES - 4096);
    // Recompute the proposal commitments and both transaction/block signatures.
    // The native constructor must reach the actual metadata decoder, not reject
    // an unsigned body substitution or a mismatched configured network first.
    let genesis = SignedBlock::try_genesis(transactions, signer.private_key(), None, None).unwrap();
    genesis.validate_proposal_commitments().unwrap();
    assert!(
        genesis
            .external_transactions()
            .all(|transaction| transaction.verify_signature().is_ok())
    );
    genesis
        .signatures()
        .next()
        .unwrap()
        .signature()
        .verify_hash(signer.public_key(), genesis.hash())
        .unwrap();
    match authenticated_genesis(&genesis).unwrap_err() {
        GenesisReadError::Json(norito::json::Error::UnknownField { field }) => {
            assert_eq!(field.len(), diagnostic_len);
        }
        _ => panic!("genuine signatures must reach the long invalid consensus mode"),
    }

    let network = NetworkId::from_genesis_hash(genesis.hash());
    let hashes = [genesis.hash()];
    let kura = Kura::blank_kura_for_testing();
    let source_shells = iroha_allocation::AllocationBudget::new(16 * 1024 * 1024);
    kura.store_block(
        SharedSignedBlock::reserve(&source_shells)
            .unwrap()
            .initialize(genesis),
    )
    .unwrap();
    let source = NativeFinalityProofSource::new(&chain_id, &network, &hashes, &kura);
    // An explicit original W=256 MB test reservation leaves room for the
    // maximal JSON source's nested canonical decoder before exercising its
    // diagnostic corridor. This does not change production's 192 MB setting or
    // widen an inherited owner. Reuse these same pools after every failure.
    let frames = iroha_allocation::AllocationBudget::new(16_429_154);
    let graphs = iroha_allocation::AllocationBudget::new(213_579_514);
    let owner = NativeFinalityProofBudget::new(
        frames.clone(),
        graphs.clone(),
        norito::DecodeLimits::new(
            16_429_154,
            16_429_154,
            230_008_668,
            230_008_668,
            norito::core::MAX_VALUE_NESTING_DEPTH,
        ),
    );
    let mut retained = Vec::new();
    for _ in 0..3 {
        let Err(NativeFinalityProofIntervalError::Native(refusal)) =
            build_proof_interval(&source, &owner, &limits(1, 1), &AtomicBool::new(false))
        else {
            panic!("the funded constructor must preserve native malformed-genesis refusal");
        };
        assert_eq!(refusal, NativeFinalityProofRefusal::ForeignGenesis);
        assert_eq!(frames.reserved_bytes(), 0);
        assert_eq!(graphs.reserved_bytes(), 0);
        retained.push(refusal);
    }
    assert_eq!(retained.len(), 3);
}

#[test]
fn finite_interval_stop_retires_real_original_cursor_without_next_native_read() {
    with_chain(check_stop);
}
#[inline(never)]
fn check_stop(chain: &CertifiedTestChain) {
    let view = chain.state().view();
    let source = NativeFinalityProofSource::new(
        view.chain_id(),
        view.network_id(),
        view.block_hashes(),
        view.kura(),
    );
    let budget = iroha_allocation::AllocationBudget::new(2_562_487);
    let original = context();
    let owner = test_budget(budget.clone());
    let reserved = budget.reserved_bytes();
    chain.kura().reset_canonical_query_reads_for_test();
    let cancelled = AtomicBool::new(true);
    let result = build_proof_interval(&source, &owner, &limits(3, 4), &cancelled);
    assert!(
        matches!(result, Err(NativeFinalityProofIntervalError::Cancelled)),
        "finite interval must stop before any native read under original cancellation"
    );
    assert_eq!(chain.kura().canonical_query_reads_for_test(), (0, 0));
    assert_eq!(original.consumed_allocated_bytes(), 0);
    cancelled.store(false, Ordering::Release);
    let mut expired = limits(3, 4);
    expired.deadline = Instant::now();
    assert!(matches!(
        build_proof_interval(&source, &owner, &expired, &cancelled),
        Err(NativeFinalityProofIntervalError::Deadline)
    ));
    assert_eq!(chain.kura().canonical_query_reads_for_test(), (0, 0));
    let result = original.with(|| {
        build_interval(&source, &owner, &limits(3, 4), &cancelled, || {
            cancelled.store(true, Ordering::Release)
        })
    });
    assert!(matches!(
        result,
        Err(NativeFinalityProofIntervalError::Cancelled)
    ));
    assert_eq!(budget.reserved_bytes(), reserved);
    let consumed = original.consumed_allocated_bytes();
    assert!(consumed > 0);
    cancelled.store(false, Ordering::Release);
    let (retained, counts) = relation_counts::measure(|| {
        original.with(|| build_proof_interval(&source, &owner, &limits(3, 4), &cancelled))
    });
    let retained = retained.unwrap();
    assert_eq!(counts.qcs, [2, 3, 4]);
    assert!(original.consumed_allocated_bytes() > consumed);
    drop(retained);
    assert_eq!(budget.reserved_bytes(), reserved);
}
