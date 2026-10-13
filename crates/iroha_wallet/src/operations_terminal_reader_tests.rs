//! Real custody retirement, fresh native reads and inherited decoder controls.
use super::super::count_plan_read_work;
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

#[test]
fn terminal_plan_timestamp_reuse_keeps_fresh_locks_and_expected_plan_comparisons() {
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
        let (first, work) = count_plan_read_work(|| result(inspect(&mut reader)));
        assert_eq!(first.as_ref().unwrap().0, NativePreparationPhase::Retired);
        assert_eq!(work, (1, 1), "new source decodes and compares its Plan");
        let (repeated, work) = count_plan_read_work(|| result(inspect(&mut reader)));
        assert_eq!(repeated, first);
        assert_eq!(work, (0, 1), "fresh expected Plan is never reused");
        let held = Journal::open(&root.path().join(name)).unwrap();
        let (locked, work) = count_plan_read_work(|| result(inspect(&mut reader)));
        assert!(locked.is_err(), "each callback must acquire the real lock");
        assert_eq!(work, (0, 0));
        drop(held);
        let (restored, work) = count_plan_read_work(|| result(inspect(&mut reader)));
        assert_eq!(restored, first);
        assert_eq!(work, (1, 1), "lock refusal must clear Plan metadata");
    }

    for change in 0..3 {
        let (primed, _) = count_plan_read_work(|| {
            result(reader.inspect_enroll_in_parent(&parent, OsStr::new("enroll"), &enroll))
        });
        assert!(primed.is_ok());
        let mut changed = enroll.clone();
        match change {
            0 => changed.deadline_unix_ms -= 1,
            1 => {
                changed.options.fee_payment =
                    FeePaymentIntent::authority(Vec::new(), std::num::NonZeroU64::new(7));
            }
            _ => changed.enrollment[0] ^= 1,
        }
        let ordinary = result(
            service.inspect_stream_token_custody_enroll_preparation_in_parent(
                &parent,
                OsStr::new("enroll"),
                &changed,
            ),
        );
        let (observed, work) = count_plan_read_work(|| {
            result(reader.inspect_enroll_in_parent(&parent, OsStr::new("enroll"), &changed))
        });
        assert!(observed.is_err());
        assert_eq!(observed, ordinary);
        assert_eq!(work, (0, 1), "unchanged source still compares new terms");
        let (restored, work) = count_plan_read_work(|| {
            result(reader.inspect_enroll_in_parent(&parent, OsStr::new("enroll"), &enroll))
        });
        assert_eq!(restored, primed);
        assert_eq!(work, (1, 1), "expectation refusal must clear metadata");
    }
    assert_eq!(
        [retained_bytes(&configured), retained_bytes(&enrolled)],
        before
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
}

#[test]
fn terminal_plan_timestamp_is_replaced_with_changed_request_bytes() {
    let (service, transport) = service();
    let request = configure(&service.config, current_unix_ms().unwrap());
    let mut changed = request.clone();
    changed.deadline_unix_ms -= 1_000;
    let root = tempfile::tempdir().unwrap();
    let parent = iroha_fs::PrivateDirectory::open(root.path()).unwrap();
    let original_path = root.path().join("original");
    let changed_path = root.path().join("changed");
    for (path, expected) in [(&original_path, &request), (&changed_path, &changed)] {
        service
            .retain_stream_token_custody_configure_request(expected, path)
            .unwrap();
        service
            .retire_stream_token_custody_configure_unprepared(path, expected)
            .unwrap();
    }
    let original = retained_bytes(&original_path);
    let replacement = retained_bytes(&changed_path);
    assert_ne!(original.0, replacement.0);
    let directory = iroha_fs::PrivateDirectory::open(&original_path).unwrap();
    let mut reader = CustodyPreparationReader::new(&service);
    let initial =
        result(reader.inspect_configure_in_parent(&parent, OsStr::new("original"), &request));
    assert!(initial.is_ok());

    // Replace both genuine records while the earlier timestamp is still eligible.
    // Counting the new decode makes this sensitive even if two producer clocks coincide.
    directory
        .write_atomic(
            "preparation.json",
            &replacement.0,
            iroha_fs::PublishMode::Replace,
        )
        .unwrap();
    directory
        .write_atomic(
            "retired.json",
            &replacement.1,
            iroha_fs::PublishMode::Replace,
        )
        .unwrap();
    let ((changed_source, verifications), work) = count_plan_read_work(|| {
        count_request_verifications(|| {
            result(reader.inspect_configure_in_parent(&parent, OsStr::new("original"), &changed))
        })
    });
    assert!(changed_source.is_ok());
    assert_ne!(changed_source, initial);
    assert_eq!(verifications, 1);
    assert_eq!(
        work,
        (1, 1),
        "changed request must discard old Plan metadata"
    );
    directory
        .write_atomic(
            "preparation.json",
            &original.0,
            iroha_fs::PublishMode::Replace,
        )
        .unwrap();
    directory
        .write_atomic("retired.json", &original.1, iroha_fs::PublishMode::Replace)
        .unwrap();
    assert_eq!(
        result(reader.inspect_configure_in_parent(&parent, OsStr::new("original"), &request)),
        initial
    );

    // Both records come from the canonical retain/retire producers. A changed Request
    // cannot lend the earlier timestamp, nor suppress the later retirement mismatch.
    directory
        .write_atomic(
            "preparation.json",
            &replacement.0,
            iroha_fs::PublishMode::Replace,
        )
        .unwrap();
    let ordinary = result(
        service.inspect_stream_token_custody_configure_preparation_in_parent(
            &parent,
            OsStr::new("original"),
            &changed,
        ),
    );
    let ((observed, verifications), work) = count_plan_read_work(|| {
        count_request_verifications(|| {
            result(reader.inspect_configure_in_parent(&parent, OsStr::new("original"), &changed))
        })
    });
    assert!(observed.is_err());
    assert_eq!(observed, ordinary);
    assert_eq!(verifications, 1);
    assert_eq!(
        work,
        (0, 0),
        "retirement error precedes expectation admission"
    );
    directory
        .write_atomic(
            "retired.json",
            &replacement.1,
            iroha_fs::PublishMode::Replace,
        )
        .unwrap();
    let ((updated, verifications), work) = count_plan_read_work(|| {
        count_request_verifications(|| {
            result(reader.inspect_configure_in_parent(&parent, OsStr::new("original"), &changed))
        })
    });
    assert!(updated.is_ok());
    assert_ne!(updated, initial);
    assert_eq!(verifications, 1);
    assert_eq!(work, (1, 1));
    let (repeated, work) = count_plan_read_work(|| {
        result(reader.inspect_configure_in_parent(&parent, OsStr::new("original"), &changed))
    });
    assert_eq!(repeated, updated);
    assert_eq!(work, (0, 1));

    // A different native journal cannot borrow metadata even with these exact same bytes.
    let ((foreign, verifications), work) = count_plan_read_work(|| {
        count_request_verifications(|| {
            result(reader.inspect_configure_in_parent(&parent, OsStr::new("changed"), &changed))
        })
    });
    assert_eq!(foreign, updated);
    assert_eq!(verifications, 1);
    assert_eq!(work, (1, 1));
    directory
        .write_atomic(
            "preparation.json",
            &original.0,
            iroha_fs::PublishMode::Replace,
        )
        .unwrap();
    directory
        .write_atomic("retired.json", &original.1, iroha_fs::PublishMode::Replace)
        .unwrap();
    assert_eq!(
        result(reader.inspect_configure_in_parent(&parent, OsStr::new("original"), &request)),
        initial
    );
    assert_eq!(retained_bytes(&original_path), original);
    assert_eq!(retained_bytes(&changed_path), replacement);
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
}

#[test]
fn terminal_plan_timestamp_preserves_inherited_and_late_decoder_work() {
    let (service, transport) = service();
    let request = enroll(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    let parent = iroha_fs::PrivateDirectory::open(root.path()).unwrap();
    let path = root.path().join("original");
    service
        .retain_stream_token_custody_enroll_request(&request, &path)
        .unwrap();
    service
        .retire_stream_token_custody_enroll_unprepared(&path, &request)
        .unwrap();
    let original = retained_bytes(&path);
    let mut reader = CustodyPreparationReader::new(&service);
    for late in [false, true] {
        for allocation in [0, 1, 128 * 1024 * 1024] {
            if late {
                reader
                    .inspect_enroll_in_parent(&parent, OsStr::new("original"), &request)
                    .unwrap();
                let (_, work) = count_plan_read_work(|| {
                    reader
                        .inspect_enroll_in_parent(&parent, OsStr::new("original"), &request)
                        .unwrap()
                });
                assert_eq!(work, (0, 1), "timestamp was reusable before late admission");
            }
            let limits =
                || norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocation, 64);
            let ordinary = norito::core::with_decode_limits_measured(limits(), || {
                count_plan_read_work(|| {
                    result(
                        service.inspect_stream_token_custody_enroll_preparation_in_parent(
                            &parent,
                            OsStr::new("original"),
                            &request,
                        ),
                    )
                })
            });
            let observed = norito::core::with_decode_limits_measured(limits(), || {
                count_plan_read_work(|| {
                    if late {
                        result(reader.inspect_enroll_in_parent(
                            &parent,
                            OsStr::new("original"),
                            &request,
                        ))
                    } else {
                        let mut inherited = CustodyPreparationReader::new(&service);
                        result(inherited.inspect_enroll_in_parent(
                            &parent,
                            OsStr::new("original"),
                            &request,
                        ))
                    }
                })
            });
            assert_eq!(
                ordinary.0, observed.0,
                "outcome and original Plan work must match"
            );
            if allocation <= 1 {
                assert!(observed.0.0.is_err());
                assert_eq!(ordinary.1, observed.1);
            } else {
                assert_eq!(
                    observed.0.0.as_ref().unwrap().0,
                    NativePreparationPhase::Retired
                );
                assert_eq!(observed.0.1, (1, 1));
                for usage in [ordinary.1, observed.1] {
                    assert!(usage.total_allocated_bytes() > 1);
                    assert!(usage.total_allocated_bytes() <= allocation);
                }
            }
            if late {
                let (again, work) = count_plan_read_work(|| {
                    result(reader.inspect_enroll_in_parent(
                        &parent,
                        OsStr::new("original"),
                        &request,
                    ))
                });
                assert!(again.is_ok());
                assert_eq!(work, (1, 1), "late active owner cannot retain metadata");
            }
        }
    }
    assert_eq!(retained_bytes(&path), original);
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
}
