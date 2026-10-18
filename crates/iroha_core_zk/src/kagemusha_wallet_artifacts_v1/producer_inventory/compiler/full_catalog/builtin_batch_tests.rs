//! Complete built-in batch reuse against the closed engineering profile.
//!
//! This admits only public sources and creates no monetary custody or signatures.

use super::*;
use crate::kagemusha_wallet_artifacts_v1::producer_inventory as inventory;

#[test]
#[ignore = "real compiled engineering profile and signed originals; no monetary custody"]
fn builtin_complete_batch_reuse_preserves_every_role_and_original() {
    let output =
        PathBuf::from(std::env::var_os("KAGEMUSHA_BUILTIN_BATCH_ACCEPTANCE_OUTPUT").unwrap());
    let PinnedEngineeringInputs {
        installed,
        authenticated,
        native,
        catalog,
        ..
    } = pinned_engineering_inputs(&output);
    let actual_profile =
        inventory::builtin::profile_bytes(authenticated.inventory(), installed.verifier().scheme())
            .unwrap();
    let profile =
        iroha_plonk::keys::BuiltinSourceProfileV1::match_actual(&actual_profile, None).unwrap();
    let mut originals =
        DirectoryOriginalsV1::open_existing(catalog.join("originals"), PROVING_KEY_MAX_BYTES_V1)
            .unwrap();
    let config = ReadConfig {
        maximum_bytes: PROVING_KEY_MAX_BYTES_V1,
        maximum_rows: 1 << 16,
        coset_cache: CosetCachePolicy::OnDemand,
        msm_budget: MemoryBudget::DEFAULT,
    };
    let qualified = authenticated
        .qualify_wallet_builtin(&installed, &native, &mut originals, config)
        .unwrap();
    let signature_controls = inventory::q::assert_builtin_signature_reuse_controls(
        &qualified,
        &installed,
        &mut originals,
        config,
        &profile,
    );
    let receive_controls = inventory::operation::assert_builtin_receive_alias_controls(
        &qualified,
        &installed,
        &mut originals,
        config,
        &profile,
    );
    // Twenty current signature references plus every existing refusal/retry case.
    assert_eq!(signature_controls, 57);
    // Nine A/eight W sources per Receive variant, including all original roles.
    assert_eq!(receive_controls, 163);
    let sigma_rebuilds = builtin_sigma_rebuilds(&qualified, &mut originals, config);
    assert_eq!(sigma_rebuilds, 11);
    let (distinct, memo_off) =
        descriptor_memo_controls(&qualified, &installed, &mut originals, config, profile);
    println!(
        "BUILTIN_BATCH_ACCEPTED routes=22 programs=16 signature_controls={signature_controls} receive_controls={receive_controls} sigma_rebuilds={sigma_rebuilds} route_descriptor_decodes={distinct} memo_off_descriptor_decodes={memo_off} every_role_revalidated=true monetary_custody=false"
    );
}

// Phones open through the closed registry, so each sigma seal here was minted by
// `from_builtin_member`. Every use still rereads its three signed originals and
// rebuilds exactly the signed PK from that seal (B2). Returns the sigmas rebuilt.
fn builtin_sigma_rebuilds(
    qualified: &QualifiedWalletSourcesV1,
    originals: &mut DirectoryOriginalsV1,
    config: ReadConfig,
) -> usize {
    let inventory = qualified.inventory();
    let mut counted = Counted {
        source: originals,
        reads: 0,
    };
    for selector in 0..inventory.sigma.len() {
        let before = counted.reads;
        let owner = qualified
            .import_sigma(u8::try_from(selector).unwrap(), &mut counted, config)
            .unwrap();
        assert_eq!(
            counted.reads - before,
            3,
            "each sigma use revalidates its descriptor, VK and PK"
        );
        let original = qualified
            .authenticated_inventory()
            .read_original(
                inventory.sigma[selector],
                &mut counted,
                config.maximum_bytes,
            )
            .unwrap();
        assert_eq!(
            owner.proving_key().artifact_bytes_v2().unwrap(),
            original.proving_key,
            "built-in sigma {selector} rebuilds exactly its signed original"
        );
    }
    inventory.sigma.len()
}

// The routes stage decodes each distinct descriptor content once (B1). A second
// batch with the memo on and a third with it off return the same routes, and
// memo off decodes once per metadata read. Returns (distinct, memo-off decodes).
fn descriptor_memo_controls(
    qualified: &QualifiedWalletSourcesV1,
    installed: &InstalledVerifierPackV1,
    originals: &mut DirectoryOriginalsV1,
    config: ReadConfig,
    profile: iroha_plonk::keys::BuiltinSourceProfileV1,
) -> (u64, u64) {
    use iroha_kagemusha_proof::a_relation::schedule::compiled::compiled_routes;
    use iroha_plonk_recursion::obligation::ledger::Variant;
    let graph = qualified.inventory();
    // Distinct descriptor content addresses (length and digest) among Omega and
    // every route's A and W members.
    let mut distinct = vec![graph.member(graph.omega).unwrap().descriptor];
    let mut reads = 0_u64;
    let mut receive_programs = std::collections::BTreeSet::new();
    for (route, program) in compiled_routes().iter().zip(&graph.routes) {
        let record = &graph.operations[usize::try_from(*program).unwrap()];
        for member in record.a.iter().chain(&record.w) {
            let descriptor = graph.member(*member).unwrap().descriptor;
            if !distinct.contains(&descriptor) {
                distinct.push(descriptor);
            }
        }
        // Metadata reads per route: Bootstrap its one unsplit A, then that A again
        // as its terminal; a Receive alias only its Omega; any other route Omega
        // and every A and W.
        reads += match route.variant {
            Variant::Bootstrap => 2,
            Variant::Receive | Variant::ReceiveRenewed if !receive_programs.insert(*program) => 1,
            _ => u64::try_from(1 + record.a.len() + record.w.len()).unwrap(),
        };
    }
    let distinct = u64::try_from(distinct.len()).unwrap();
    assert_eq!(
        qualified
            .qualification_metrics()
            .routes
            .work
            .descriptor_decodes,
        distinct
    );
    let compiled = compiled_routes();
    let q: Vec<_> = (0..graph.operations.len())
        .map(|program| {
            let route = graph
                .routes
                .iter()
                .position(|index| usize::try_from(*index).unwrap() == program)
                .unwrap();
            qualified.q(compiled[route]).unwrap().clone()
        })
        .collect();
    let authenticated = installed
        .authenticate_producer_inventory(&graph.to_canonical_bytes().unwrap())
        .unwrap();
    let mut batch = |descriptors: &inventory::DescriptorMemo| {
        let before = inventory::OpeningWorkV1::current_thread();
        let routes = authenticated
            .qualify_operation_routes_with_admission(
                installed,
                &q,
                &mut *originals,
                config,
                |_| {},
                inventory::builtin::Admission::Builtin(&profile),
                descriptors,
            )
            .unwrap();
        let decodes = inventory::OpeningWorkV1::current_thread()
            .since(before)
            .descriptor_decodes;
        (routes, decodes)
    };
    let (on, on_decodes) = batch(&inventory::DescriptorMemo::default());
    let (off, off_decodes) = batch(&inventory::DescriptorMemo::with_capacity(0));
    assert_eq!(on_decodes, distinct);
    assert_eq!(off_decodes, reads);
    assert!(off_decodes > on_decodes);
    assert_eq!(on.len(), off.len());
    for (on, off) in on.iter().zip(off.iter()) {
        assert_eq!(on.identity(), off.identity());
        assert_eq!(on.stage_memory_bytes(), off.stage_memory_bytes());
        assert_eq!(on.terminal().binding(), off.terminal().binding());
        assert_eq!(
            on.terminal().key().to_bytes(),
            off.terminal().key().to_bytes()
        );
        assert_eq!(
            on.candidate_omega().is_some(),
            off.candidate_omega().is_some()
        );
        if let (Some(on), Some(off)) = (on.candidate_omega(), off.candidate_omega()) {
            assert_eq!(on.binding(), off.binding());
            assert_eq!(on.key().to_bytes(), off.key().to_bytes());
        }
        let record = &graph.operations[usize::try_from(on.identity().2).unwrap()];
        for (stage, member) in record.a.iter().copied().enumerate() {
            let left = on.bind_a(stage, member, None).unwrap();
            let right = off.bind_a(stage, member, None).unwrap();
            assert_eq!(left.binding(), right.binding());
            assert_eq!(
                left.verifying_key().to_bytes(),
                right.verifying_key().to_bytes()
            );
        }
        for (stage, member) in record.w.iter().copied().enumerate() {
            let left = on.bind_w(stage, member, None).unwrap();
            let right = off.bind_w(stage, member, None).unwrap();
            assert_eq!(left.binding(), right.binding());
            assert_eq!(
                left.verifying_key().to_bytes(),
                right.verifying_key().to_bytes()
            );
        }
    }
    (distinct, off_decodes)
}
