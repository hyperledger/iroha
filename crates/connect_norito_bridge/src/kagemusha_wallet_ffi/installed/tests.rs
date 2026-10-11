//! Mandatory base and closed financial original bounds; DATA cannot install a runtime.
use super::*;
fn base() -> RuntimeOriginals<'static> {
    RuntimeOriginals {
        app_manifest: b"app",
        envelope: b"envelope",
        wallet_runtime: b"runtime",
        verifier_pack: b"pack",
        producer_inventory: b"catalog",
        signed_genesis: b"genesis",
        originals_root: b"root",
        registration_source: b"",
    }
}
#[test]
fn missing_base_or_partial_financial_original_refuses_before_platform_acquisition() {
    base().validate_bounds().unwrap();
    for field in 0..7 {
        let mut input = base();
        match field {
            0 => input.app_manifest = b"",
            1 => input.envelope = b"",
            2 => input.wallet_runtime = b"",
            3 => input.verifier_pack = b"",
            4 => input.producer_inventory = b"",
            5 => input.signed_genesis = b"",
            _ => input.originals_root = b"",
        }
        assert_eq!(input.validate_bounds(), Err(Failure::code(INVALID)));
        assert!(PreparedInstallation::load(input).is_err());
    }
}
#[test]
fn complete_financial_absence_is_bounded_data_and_partial_offers_refuse() {
    for mask in 0..8 {
        let mut input = base();
        if mask & 1 == 0 {
            input.verifier_pack = b"";
        }
        if mask & 2 == 0 {
            input.producer_inventory = b"";
        }
        if mask & 4 == 0 {
            input.originals_root = b"";
        }
        assert_eq!(
            input.validate_bounds(),
            if mask == 0 || mask == 7 {
                Ok(())
            } else {
                Err(Failure::code(INVALID))
            }
        );
        // Complete presence is still DATA, never authentication or runtime authority.
        assert!(PreparedInstallation::load(input).is_err());
    }
}
#[test]
fn original_extents_are_refused_before_decode_or_platform_acquisition() {
    for (field, bound) in RUNTIME_BOUNDS.into_iter().enumerate() {
        let oversized = vec![1; bound + 1];
        let mut input = base();
        match field {
            0 => input.app_manifest = &oversized,
            1 => input.envelope = &oversized,
            2 => input.wallet_runtime = &oversized,
            3 => input.verifier_pack = &oversized,
            4 => input.producer_inventory = &oversized,
            5 => input.signed_genesis = &oversized,
            6 => input.originals_root = &oversized,
            _ => input.registration_source = &oversized,
        }
        assert_eq!(input.validate_bounds(), Err(Failure::code(INVALID)));
    }
    assert_eq!(read_config().maximum_bytes, PROVING_KEY_MAX_BYTES_V1);
    assert_eq!(read_config().maximum_rows, 1 << 16);
}

#[test]
fn financial_offer_classification_never_grants_an_owner() {
    let mut absent = base();
    absent.verifier_pack = b"";
    absent.producer_inventory = b"";
    absent.originals_root = b"";
    absent.validate_bounds().unwrap();
    assert_eq!(
        financial_offer(&absent),
        Err(Failure::code(ARTIFACTS_UNAVAILABLE))
    );
    absent.verifier_pack = b"pack";
    assert_eq!(absent.validate_bounds(), Err(Failure::code(INVALID)));
    assert_eq!(financial_offer(&absent), Err(Failure::code(INVALID)));
    assert_eq!(financial_offer(&base()), Ok(()));
}

#[test]
fn wallet_artifact_import_retains_its_bounded_process_scratch() {
    assert_eq!(read_config().maximum_bytes, PROVING_KEY_MAX_BYTES_V1);
    assert_eq!(read_config().maximum_rows, 1 << 16);
    assert_eq!(
        iroha_pasta::msm::SharedMemoryBudget::process_default().limit_bytes(),
        64 << 20
    );
}

#[test]
fn registration_original_extends_exact_c_layout_without_role_aliases() {
    use std::mem::{offset_of, size_of};
    let word = size_of::<usize>();
    assert_eq!(size_of::<WalletRuntimeOriginals>(), 16 * word);
    assert_eq!(
        offset_of!(WalletRuntimeOriginals, originals_root),
        12 * word
    );
    assert_eq!(
        offset_of!(WalletRuntimeOriginals, originals_root_length),
        13 * word
    );
    assert_eq!(
        offset_of!(WalletRuntimeOriginals, registration_source),
        14 * word
    );
    assert_eq!(
        offset_of!(WalletRuntimeOriginals, registration_source_length),
        15 * word
    );
}
