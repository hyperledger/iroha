//! Actual closed-profile wrapper regression using pinned engineering originals.
//!
//! This creates no wallet, key custody, signature, payment or deployment grant.

use super::*;
use crate::kagemusha_wallet_artifacts_v1::producer_inventory as inventory;
use iroha_kagemusha_proof::q_signature::{
    QSignaturePlan, SignatureKey,
    native::{QSignatureError, QSignatureProver},
};
use iroha_plonk::keys::{
    BuiltinSourceProfileV1, RebuildError, keygen_pk_from_vk_v2,
    pk::artifact::Error as ArtifactError,
};

#[test]
#[ignore = "real compiled engineering profile and pinned signed originals; source rebuild only, no monetary custody"]
fn builtin_signature_wrapper_binds_originals_and_rejects_foreign_actual_source() {
    let output =
        PathBuf::from(std::env::var_os("KAGEMUSHA_BUILTIN_WRAPPER_ACCEPTANCE_OUTPUT").unwrap());
    let PinnedEngineeringInputs {
        installed,
        authenticated,
        native,
        catalog,
        ..
    } = pinned_engineering_inputs(&output);
    authenticated.qualify_finality(&installed, &native).unwrap();
    let actual_profile =
        inventory::builtin::profile_bytes(authenticated.inventory(), installed.verifier().scheme())
            .unwrap();
    let profile = BuiltinSourceProfileV1::match_actual(&actual_profile, None).unwrap();
    let mut changed_profile = actual_profile.clone();
    *changed_profile.last_mut().unwrap() ^= 1;
    assert!(BuiltinSourceProfileV1::match_actual(&changed_profile, None).is_err());
    let admission = inventory::builtin::Admission::Builtin(&profile);
    let mut originals =
        DirectoryOriginalsV1::open_existing(catalog.join("originals"), PROVING_KEY_MAX_BYTES_V1)
            .unwrap();
    let config = ReadConfig {
        maximum_bytes: PROVING_KEY_MAX_BYTES_V1,
        maximum_rows: 1 << 16,
        coset_cache: CosetCachePolicy::OnDemand,
        msm_budget: MemoryBudget::DEFAULT,
    };
    let sigmas = authenticated
        .qualify_sigmas_with_admission(
            &mut originals,
            config,
            installed.verifier().vesta_parameters(12).unwrap(),
            installed.verifier().vesta_parameters(14).unwrap(),
            admission,
        )
        .unwrap();
    let program = authenticated
        .inventory()
        .operations
        .iter()
        .position(|record| inventory::variant(record.variant).unwrap() == Variant::Bootstrap)
        .unwrap();
    let program_index = u32::try_from(program).unwrap();
    let qualified = authenticated
        .qualify_q_program_with_admission(
            &installed,
            &sigmas,
            program_index,
            &mut originals,
            config,
            admission,
        )
        .unwrap();
    let plan = qualified.signatures()[0].clone();
    let record = &authenticated.inventory().operations[program];
    // Lean Bootstrap has no sigma Q: the hard 2V1F signature leaf is its only Q.
    assert_eq!(record.q.len(), 1);
    let original = authenticated
        .read_original(record.q[0], &mut originals, config.maximum_bytes)
        .unwrap();
    let params = installed.verifier().pallas_parameters().as_ref().clone();
    let member = profile.member(&[2, program_index, 0]).unwrap();
    assert!(profile.member(&[2, program_index, 1]).is_err());
    assert!(profile.member(&[2, program_index, u32::MAX]).is_err());
    let admit = |plan, member, descriptor: &[u8], vk: &[u8], pk: &[u8], cancellation| {
        QSignatureProver::from_builtin_original_artifact_cancellable(
            plan,
            params.clone(),
            descriptor,
            vk,
            pk,
            config,
            member,
            cancellation,
        )
    };
    // A real member from the same complete profile, but another program's Q
    // relation (Load's one-slot own-receipt leaf), cannot be used as authority
    // for this signature source's originals.
    let load = authenticated
        .inventory()
        .operations
        .iter()
        .position(|record| inventory::variant(record.variant).unwrap() == Variant::Load)
        .unwrap();
    assert_ne!(record.q[0], authenticated.inventory().operations[load].q[0]);
    assert!(
        admit(
            plan.clone(),
            profile
                .member(&[2, u32::try_from(load).unwrap(), 0])
                .unwrap(),
            &original.descriptor,
            &original.verifying_key,
            &original.proving_key,
            None,
        )
        .is_err()
    );
    for role in 0..3 {
        let mut descriptor = original.descriptor.clone();
        let mut vk = original.verifying_key.clone();
        let mut pk = original.proving_key.clone();
        let changed = match role {
            0 => &mut descriptor,
            1 => &mut vk,
            _ => &mut pk,
        };
        *changed.last_mut().unwrap() ^= 1;
        assert!(admit(plan.clone(), member, &descriptor, &vk, &pk, None).is_err());
    }
    let cancellation = iroha_pasta::CancellationToken::new();
    cancellation.cancel();
    assert!(
        admit(
            plan.clone(),
            member,
            &original.descriptor,
            &original.verifying_key,
            &original.proving_key,
            Some(&cancellation),
        )
        .is_err_and(|error| error.is_cancelled())
    );
    let owner = admit(
        plan.clone(),
        member,
        &original.descriptor,
        &original.verifying_key,
        &original.proving_key,
        None,
    )
    .unwrap();
    let strict = QSignatureProver::from_original_artifact(
        plan.clone(),
        params.clone(),
        &original.descriptor,
        &original.verifying_key,
        &original.proving_key,
        config,
    )
    .unwrap();
    assert_eq!(owner.binding(), strict.binding());
    assert_eq!(
        owner.verifying_key().to_bytes(),
        strict.verifying_key().to_bytes()
    );
    let metadata = owner.into_metadata();
    let rebuilt = keygen_pk_from_vk_v2(
        &params,
        &plan.source_circuit().unwrap(),
        &metadata.view(),
        CosetCachePolicy::OnDemand,
    )
    .unwrap();
    assert_eq!(rebuilt.artifact_bytes_v2().unwrap(), original.proving_key);
    drop(rebuilt);

    let mut slots = plan.slots().to_vec();
    let fixed = slots
        .iter_mut()
        .find(|slot| matches!(slot.key, SignatureKey::Fixed(_)))
        .unwrap();
    let SignatureKey::Fixed(root) = fixed.key else {
        unreachable!("selected a fixed slot")
    };
    fixed.key = SignatureKey::Fixed(root.neg());
    let foreign = QSignaturePlan::new(slots).unwrap();
    assert_eq!(foreign.instance_length(), plan.instance_length());
    // Membership certifies its own pinned relation, not arbitrary same-schema
    // caller plans. Exercise the precise source rebuild used by prove(), without
    // an invalid signature rejecting first and masking this authority boundary.
    let foreign_owner = admit(
        foreign.clone(),
        member,
        &original.descriptor,
        &original.verifying_key,
        &original.proving_key,
        None,
    )
    .unwrap();
    let foreign_metadata = foreign_owner.into_metadata();
    assert!(matches!(
        keygen_pk_from_vk_v2(
            &params,
            &foreign.source_circuit().unwrap(),
            &foreign_metadata.view(),
            CosetCachePolicy::OnDemand,
        ),
        Err(RebuildError::Source)
    ));
    // The ordinary public importer remains strictly circuit-bound even if this
    // binary contains the matching original's compiled member.
    assert!(matches!(
        QSignatureProver::from_original_artifact(
            foreign,
            params.clone(),
            &original.descriptor,
            &original.verifying_key,
            &original.proving_key,
            config,
        ),
        Err(QSignatureError::Artifact(ArtifactError::Source))
    ));
    println!(
        "BUILTIN_WRAPPER_ACCEPTED engineering=true program={program_index} original_roles=3 strict_parity=true exact_rebuild=true foreign_source_rejected=true monetary_custody=false"
    );
}
