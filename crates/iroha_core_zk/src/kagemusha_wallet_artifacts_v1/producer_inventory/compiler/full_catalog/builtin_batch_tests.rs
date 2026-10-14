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
    assert_eq!(signature_controls, 94);
    assert_eq!(receive_controls, 175);
    println!(
        "BUILTIN_BATCH_ACCEPTED routes=52 programs=32 signature_controls={signature_controls} receive_controls={receive_controls} every_role_revalidated=true monetary_custody=false"
    );
}
