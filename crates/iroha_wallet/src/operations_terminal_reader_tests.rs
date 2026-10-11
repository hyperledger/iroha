//! Real custody retirement, fresh native reads and inherited decoder controls.
use super::*;
use crate::operations::{CustodyPreparationReader, preparation::count_request_verifications};
use std::{ffi::OsStr, fs};

fn result(
    value: Result<VerifiedNativePreparation>,
) -> Result<(NativePreparationPhase, String), String> {
    value
        .map(|value| {
            assert!(value.signed_transaction().is_none());
            assert!(value.unprepared_status().is_none());
            (value.phase(), value.request_sha256().unwrap().to_owned())
        })
        .map_err(|error| error.to_string())
}

fn retained_bytes(path: &Path) -> (Vec<u8>, Vec<u8>) {
    (
        fs::read(path.join("preparation.json")).unwrap(),
        fs::read(path.join("retired.json")).unwrap(),
    )
}

#[test]
fn terminal_reader_reuses_actual_retired_records_without_retaining_a_lock_or_verdict() {
    let (service, transport) = service();
    let now = current_unix_ms().unwrap();
    let configure = configure(&service.config, now);
    let enroll = enroll(&service.config, now);
    let root = tempfile::tempdir().unwrap();
    let parent = iroha_fs::PrivateDirectory::open(root.path()).unwrap();
    let configured = root.path().join("configure");
    let enrolled = root.path().join("enroll");
    service
        .retain_stream_token_custody_configure_request(&configure, &configured)
        .unwrap();
    service
        .retire_stream_token_custody_configure_unprepared(&configured, &configure)
        .unwrap();
    service
        .retain_stream_token_custody_enroll_request(&enroll, &enrolled)
        .unwrap();
    service
        .retire_stream_token_custody_enroll_unprepared(&enrolled, &enroll)
        .unwrap();
    let before = [retained_bytes(&configured), retained_bytes(&enrolled)];
    let mut reader = CustodyPreparationReader::new(&service);
    for (name, is_enroll) in [("configure", false), ("enroll", true)] {
        let inspect = |reader: &mut CustodyPreparationReader<'_>| {
            if is_enroll {
                reader.inspect_enroll_in_parent(&parent, OsStr::new(name), &enroll)
            } else {
                reader.inspect_configure_in_parent(&parent, OsStr::new(name), &configure)
            }
        };
        let (first, full) = count_request_verifications(|| result(inspect(&mut reader)));
        assert_eq!(full, 1, "new journal must authenticate its actual Request");
        assert_eq!(first.as_ref().unwrap().0, NativePreparationPhase::Retired);
        // Native ownership can be reacquired between observations: no descriptor or lock is
        // retained by the memo. A competing held owner still refuses the next observation.
        let held = Journal::open(&root.path().join(name)).unwrap();
        assert!(inspect(&mut reader).is_err());
        drop(held);
        let (after_lock, full) = count_request_verifications(|| result(inspect(&mut reader)));
        assert_eq!(after_lock, first);
        assert_eq!(full, 1, "refusal clears the sole entry");
        let (repeated, full) = count_request_verifications(|| result(inspect(&mut reader)));
        assert_eq!(repeated, first);
        assert_eq!(full, 0, "exact bytes reuse the actual immutable Request");
        let baseline = if is_enroll {
            service.inspect_stream_token_custody_enroll_preparation_in_parent(
                &parent,
                OsStr::new(name),
                &enroll,
            )
        } else {
            service.inspect_stream_token_custody_configure_preparation_in_parent(
                &parent,
                OsStr::new(name),
                &configure,
            )
        };
        assert_eq!(result(baseline), first);
    }
    let mut changed = enroll.clone();
    changed.options.fee_payment =
        FeePaymentIntent::authority(Vec::new(), std::num::NonZeroU64::new(7));
    let error = reader
        .inspect_enroll_in_parent(&parent, OsStr::new("enroll"), &changed)
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "custody journal differs from original request or fee authorization"
    );
    let (_, full) = count_request_verifications(|| {
        reader
            .inspect_enroll_in_parent(&parent, OsStr::new("enroll"), &enroll)
            .unwrap()
    });
    assert_eq!(
        full, 1,
        "a changed newly supplied expectation invalidates reuse"
    );
    assert_eq!(
        [retained_bytes(&configured), retained_bytes(&enrolled)],
        before
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
}

#[test]
fn terminal_reader_reads_mutations_lazily_and_preserves_original_error_authority() {
    let (service, transport) = service();
    let request = configure(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    let parent = iroha_fs::PrivateDirectory::open(root.path()).unwrap();
    let path = root.path().join("original");
    service
        .retain_stream_token_custody_configure_request(&request, &path)
        .unwrap();
    service
        .retire_stream_token_custody_configure_unprepared(&path, &request)
        .unwrap();
    let original = retained_bytes(&path);
    let directory = iroha_fs::PrivateDirectory::open(&path).unwrap();
    let mut reader = CustodyPreparationReader::new(&service);
    let inspect = |reader: &mut CustodyPreparationReader<'_>| {
        reader.inspect_configure_in_parent(&parent, OsStr::new("original"), &request)
    };
    let expected = result(inspect(&mut reader));
    assert!(expected.is_ok());

    // Malformed current retirement must be freshly decoded on the second actual call.
    directory
        .write_atomic("retired.json", b"{", iroha_fs::PublishMode::Replace)
        .unwrap();
    let ordinary = result(
        service.inspect_stream_token_custody_configure_preparation_in_parent(
            &parent,
            OsStr::new("original"),
            &request,
        ),
    );
    let observed = result(inspect(&mut reader));
    assert!(observed.is_err());
    assert_eq!(observed, ordinary);
    directory
        .write_atomic("retired.json", &original.1, iroha_fs::PublishMode::Replace)
        .unwrap();
    assert_eq!(result(inspect(&mut reader)), expected);

    // A validly encoded changed Request fails its identity gate before opening an oversized
    // later Payload. This checks the original semantic error priority, not only byte equality.
    let source = std::str::from_utf8(&original.0).unwrap();
    let schema = "\"iroha.wallet.native-preparation.v1\"";
    assert_eq!(source.matches(schema).count(), 1);
    let changed = source.replacen(schema, "\"changed\"", 1).into_bytes();
    directory
        .write_atomic("preparation.json", &changed, iroha_fs::PublishMode::Replace)
        .unwrap();
    directory
        .write_atomic("payload.json", b"{}", iroha_fs::PublishMode::CreateNew)
        .unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(path.join("payload.json"))
        .unwrap()
        .set_len((iroha_operation_journal::MAX_JOURNAL_BYTES + 1) as u64)
        .unwrap();
    let ordinary = result(
        service.inspect_stream_token_custody_configure_preparation_in_parent(
            &parent,
            OsStr::new("original"),
            &request,
        ),
    );
    let observed = result(inspect(&mut reader));
    assert_eq!(observed, ordinary);
    assert_eq!(
        observed.unwrap_err(),
        "preparation differs from the original wallet identity or finite authorization"
    );
    directory
        .write_atomic(
            "preparation.json",
            &original.0,
            iroha_fs::PublishMode::Replace,
        )
        .unwrap();
    fs::remove_file(path.join("payload.json")).unwrap();
    let (again, full) = count_request_verifications(|| result(inspect(&mut reader)));
    assert_eq!(again, expected);
    assert_eq!(full, 1);
    // Adding a later fixed record cannot be hidden by an unchanged terminal memo.
    directory
        .write_atomic("operation.json", b"{}", iroha_fs::PublishMode::CreateNew)
        .unwrap();
    assert!(inspect(&mut reader).is_err());
    fs::remove_file(path.join("operation.json")).unwrap();
    assert_eq!(result(inspect(&mut reader)), expected);
    assert_eq!(retained_bytes(&path), original);
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
}

#[test]
fn terminal_reader_preserves_inherited_decoder_recipe_and_does_not_cache_partial_phases() {
    let (service, transport) = service();
    let request = enroll(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    let parent = iroha_fs::PrivateDirectory::open(root.path()).unwrap();
    let path = root.path().join("original");
    let mut reader = CustodyPreparationReader::new(&service);
    assert_eq!(
        reader
            .inspect_enroll_in_parent(&parent, OsStr::new("original"), &request)
            .unwrap()
            .phase(),
        NativePreparationPhase::Missing
    );
    assert!(!path.exists());
    service
        .retain_stream_token_custody_enroll_request(&request, &path)
        .unwrap();
    for _ in 0..2 {
        let (phase, count) = count_request_verifications(|| {
            reader
                .inspect_enroll_in_parent(&parent, OsStr::new("original"), &request)
                .unwrap()
                .phase()
        });
        assert_eq!(phase, NativePreparationPhase::RequestOnly);
        assert_eq!(count, 1);
    }
    service
        .retire_stream_token_custody_enroll_unprepared(&path, &request)
        .unwrap();
    let expected =
        result(reader.inspect_enroll_in_parent(&parent, OsStr::new("original"), &request));
    assert!(expected.is_ok());
    for allocation in [0, 1, 128 * 1024 * 1024] {
        // Prime outside the inherited owner; installing it later must revoke eligibility.
        assert_eq!(
            result(reader.inspect_enroll_in_parent(&parent, OsStr::new("original"), &request)),
            expected
        );
        let limits =
            || norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocation, 64);
        let ordinary = norito::core::with_decode_limits_measured(limits(), || {
            result(
                service.inspect_stream_token_custody_enroll_preparation_in_parent(
                    &parent,
                    OsStr::new("original"),
                    &request,
                ),
            )
        });
        let observed = norito::core::with_decode_limits_measured(limits(), || {
            result(reader.inspect_enroll_in_parent(&parent, OsStr::new("original"), &request))
        });
        assert_eq!(ordinary.0, observed.0);
        if allocation <= 1 {
            assert!(observed.0.is_err());
            assert_eq!(ordinary.1, observed.1);
        } else {
            assert_eq!(observed.0, expected);
            for usage in [ordinary.1, observed.1] {
                assert!(usage.total_allocated_bytes() > 1);
                assert!(usage.total_allocated_bytes() <= allocation);
            }
        }
        let (again, count) = count_request_verifications(|| {
            result(reader.inspect_enroll_in_parent(&parent, OsStr::new("original"), &request))
        });
        assert_eq!(again, expected);
        assert_eq!(
            count, 1,
            "inherited decoder cannot leave reusable observations"
        );
    }
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
}
