//! Parent optional records retain native errors, bounded canonical decode and original custody.

use super::*;
use crate::operations::setup_test_support::service;
use std::sync::atomic::Ordering;

#[test]
fn namespace_parent_optional_read_keeps_absence_active_decode_refusal_and_original_retry() {
    let (service, transport) = service();
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("parent");
    let selected =
        super::super::tests::request(&service.config, current_unix_ms().unwrap()).selection;
    let fee = FeePaymentIntent::authority(Vec::new(), None);
    service
        .initialize_musubi_namespace_binding_parent(&path, &selected, &fee)
        .unwrap();
    let parent = service
        .open_musubi_namespace_binding_parent(&path, &selected, &fee)
        .unwrap();
    assert!(parent.read::<Child>("child-0001").unwrap().is_none());
    assert!(parent.read::<Child>("../invalid").is_err());
    let original = Child {
        request_sha256: "original native request".into(),
    };
    let bytes = encode_bounded(&original, MAX_PARENT_BYTES).unwrap();
    parent
        .directory
        .write_atomic("child-0001", &bytes, PublishMode::CreateNew)
        .unwrap();
    let zero =
        norito::DecodeLimits::new(MAX_PARENT_BYTES, MAX_PARENT_BYTES, MAX_PARENT_BYTES, 0, 32);
    assert!(
        norito::core::with_decode_limits_scope(zero, || parent.read::<Child>("child-0001"))
            .is_err()
    );
    let wide = norito::DecodeLimits::new(
        MAX_PARENT_BYTES,
        MAX_PARENT_BYTES,
        MAX_PARENT_BYTES,
        1024 * 1024,
        32,
    );
    let retried =
        norito::core::with_decode_limits_scope(wide, || parent.read::<Child>("child-0001"))
            .unwrap()
            .unwrap();
    assert_eq!(retried.request_sha256, original.request_sha256);
    assert_eq!(
        parent
            .directory
            .read("child-0001", MAX_PARENT_BYTES)
            .unwrap()
            .as_slice(),
        bytes
    );
    #[cfg(unix)]
    {
        let displaced = temporary.path().join("displaced");
        std::fs::rename(&path, &displaced).unwrap();
        assert!(parent.read::<Child>("missing").is_err());
        std::fs::rename(&displaced, &path).unwrap();
    }
    assert!(parent.read::<Child>("missing").unwrap().is_none());
    assert_eq!(
        parent
            .read::<Child>("child-0001")
            .unwrap()
            .unwrap()
            .request_sha256,
        original.request_sha256
    );
    assert_eq!(transport.quotes.load(Ordering::SeqCst), 0);
    assert_eq!(transport.submissions.load(Ordering::SeqCst), 0);
}
