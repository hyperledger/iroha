//! Native private reads verify opt-in measurement boundaries without changing custody results.

use super::tests::Fixture;
use super::*;
use finish_timing::{Capture, Phase, Stats};

struct Records {
    _temporary: tempfile::TempDir,
    ordinary: PrivateDirectory,
    fixture: Fixture,
    images: Vec<Vec<u8>>,
}
impl Records {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let ordinary = PrivateDirectory::open_or_create(temporary.path().join("records")).unwrap();
        let valid = encode(&vec![3_u64, 5, 8], MAX_RECORD_BYTES).unwrap();
        let oversized = vec![0; MAX_RECORD_BYTES + 1];
        for (name, bytes) in [
            ("valid.nrt", valid.as_slice()),
            ("malformed.nrt", &[0][..]),
            ("oversized.nrt", oversized.as_slice()),
        ] {
            ordinary
                .write_atomic(name, bytes, PublishMode::CreateNew)
                .unwrap();
        }
        let fixture = Fixture::new();
        fixture.reserve();
        let original = fixture
            .operation
            .read(metadata::FILE, metadata::MAX_IMAGE_BYTES)
            .unwrap();
        // These deliberately generic child bytes exercise codec instrumentation only. They
        // never enter a native authorization parser or establish a valid dispatch history.
        let images = [
            Some(valid.as_slice()),
            None,
            Some(&[0][..]),
            Some(oversized.as_slice()),
        ]
        .into_iter()
        .map(|bytes| {
            metadata::test_changed_image(&original, Some(1), "authorization.nrt", bytes).unwrap()
        })
        .collect();
        Self {
            _temporary: temporary,
            ordinary,
            fixture,
            images,
        }
    }
    fn select(&self, index: usize, scoped: bool) {
        if scoped {
            self.fixture
                .operation
                .write_atomic(metadata::FILE, &self.images[index], PublishMode::Replace)
                .unwrap();
        }
    }
    fn read(&self, index: usize, scoped: bool) -> Result<Option<Vec<u64>>> {
        if scoped {
            self.fixture.operation.read_scope(|reader| {
                metadata::load_in_scope(reader).and_then(|image| image.read(Some(1), 0))
            })
        } else {
            read_record(
                &self.ordinary,
                ["valid.nrt", "missing.nrt", "malformed.nrt", "oversized.nrt"][index],
            )
        }
    }
    fn all(&self, scoped: bool) -> Vec<std::result::Result<Option<Vec<u64>>, String>> {
        (0..4)
            .map(|index| {
                self.select(index, scoped);
                self.read(index, scoped).map_err(|error| error.to_string())
            })
            .collect()
    }
}

fn inventory(
    directory: &PrivateDirectory,
    maximum: usize,
    scoped: bool,
) -> Result<Vec<std::ffi::OsString>> {
    if scoped {
        directory.read_tree_scope(|tree| directory_entries_in_tree(directory, maximum, Some(tree)))
    } else {
        directory_entries_in_tree(directory, maximum, None)
    }
}

fn require_read_samples(stats: &Stats, scoped: bool, reads: u64, decodes: u64) {
    let (read, decode) = if scoped {
        (
            Phase::AttemptScopedRecordRead,
            Phase::AttemptScopedRecordDecode,
        )
    } else {
        (Phase::AttemptRecordRead, Phase::AttemptRecordDecode)
    };
    let (read_calls, read_us) = stats.sample(read);
    let (decode_calls, decode_us) = stats.sample(decode);
    assert_eq!(read_calls, reads);
    assert_eq!(decode_calls, decodes);
    if !scoped {
        assert!(
            read_us >= decode_us,
            "epoch codec work remains inside its record read"
        );
    }
    // A canonical image's physical read closes before the independently measured lazy
    // logical decode, so their durations have no containment relationship.
}

#[test]
fn record_and_inventory_samples_preserve_present_absent_and_refused_native_results() {
    let _resources = crate::managed::native_test_guard();
    let records = Records::new();
    let directory = &records.ordinary;
    let ordinary = records.all(false);
    let scoped = records.all(true);
    assert_eq!(&ordinary[..3], &scoped[..3]);
    assert_eq!(
        scoped[3],
        Err("dispatch custody record exceeds its bound".into())
    );
    assert_eq!(ordinary[0], Ok(Some(vec![3, 5, 8])));
    assert_eq!(ordinary[1], Ok(None));
    assert_eq!(
        ordinary[2],
        Err("invalid canonical dispatch custody record".into())
    );
    assert!(ordinary[3].is_err());
    let inventory_results = [false, true].map(|scoped| {
        [3, 0]
            .map(|maximum| inventory(directory, maximum, scoped).map_err(|error| error.to_string()))
    });
    assert!(inventory_results[0][0].is_ok());
    assert!(inventory_results[0][1].is_err());
    assert_eq!(inventory_results[0], inventory_results[1]);

    let capture = Capture::start();
    assert_eq!(records.all(false), ordinary);
    assert_eq!(records.all(true), scoped);
    for (scoped, expected) in [false, true].into_iter().zip(inventory_results) {
        assert_eq!(
            [3, 0]
                .map(|maximum| inventory(directory, maximum, scoped)
                    .map_err(|error| error.to_string())),
            expected
        );
    }
    let stats = capture.finish();
    // A malformed present leaf invokes the codec; absence and oversized native refusal do not.
    require_read_samples(&stats, false, 4, 2);
    require_read_samples(&stats, true, 4, 2);
    assert_eq!(stats.sample(Phase::AttemptInventory).0, 2);
    assert_eq!(stats.sample(Phase::AttemptScopedInventory).0, 2);

    // Readers remain inert after the original collector drops, including ordinary refusals.
    assert_eq!(records.all(false), ordinary);
    assert_eq!(records.all(true), scoped);
    let capture = Capture::start();
    let stats = capture.finish();
    require_read_samples(&stats, false, 0, 0);
    require_read_samples(&stats, true, 0, 0);
    assert_eq!(stats.sample(Phase::AttemptInventory), (0, 0));
    assert_eq!(stats.sample(Phase::AttemptScopedInventory), (0, 0));
}

#[test]
fn record_samples_preserve_active_decode_result_charge_and_refusal() {
    let _resources = crate::managed::native_test_guard();
    let records = Records::new();
    let limits = |allocation| {
        norito::DecodeLimits::new(
            MAX_RECORD_BYTES,
            MAX_RECORD_BYTES,
            MAX_RECORD_BYTES,
            allocation,
            32,
        )
    };
    let run = |scoped, allocation| {
        records.select(0, scoped);
        norito::core::with_decode_limits_measured(limits(allocation), || {
            records.read(0, scoped).map_err(|error| error.to_string())
        })
    };
    records.select(0, true);
    let capture = Capture::start();
    let (indexed, envelope_usage) =
        norito::core::with_decode_limits_measured(limits(usize::MAX), || {
            records
                .fixture
                .operation
                .read_scope(|reader| metadata::load_in_scope(reader).map(|_| ()))
        });
    indexed.unwrap();
    let stats = capture.finish();
    require_read_samples(&stats, true, 1, 0);
    require_read_samples(&stats, false, 0, 0);
    let envelope = envelope_usage.total_allocated_bytes();
    assert!(
        envelope > 1,
        "the actual canonical envelope owns a finite decode charge"
    );
    for scoped in [false, true] {
        let original = run(scoped, usize::MAX);
        assert_eq!(original.0, Ok(Some(vec![3, 5, 8])));
        let exact = original.1.total_allocated_bytes();
        assert!(exact > 1);
        let allocations = if scoped {
            assert!(
                exact > envelope,
                "the lazy logical child owns its own charge"
            );
            vec![0, 1, envelope - 1, envelope, exact - 1, exact, usize::MAX]
        } else {
            vec![0, 1, exact - 1, exact, usize::MAX]
        };
        for allocation in allocations {
            let expected = run(scoped, allocation);
            let capture = Capture::start();
            let actual = run(scoped, allocation);
            let stats = capture.finish();
            assert_eq!(actual, expected);
            let envelope_refused = scoped && allocation < envelope;
            require_read_samples(&stats, scoped, 1, u64::from(!envelope_refused));
            require_read_samples(&stats, !scoped, 0, 0);
            assert!(actual.1.total_allocated_bytes() <= allocation);
            if allocation < exact {
                assert_eq!(
                    actual.0,
                    Err(if envelope_refused {
                        "invalid canonical operation metadata image"
                    } else {
                        "invalid canonical dispatch custody record"
                    }
                    .into()),
                );
            } else {
                assert_eq!(actual.0, Ok(Some(vec![3, 5, 8])));
                assert_eq!(actual.1.total_allocated_bytes(), exact);
            }
        }
    }
}

#[test]
fn record_sample_closes_before_outer_source_exit_overrides_codec_refusal() {
    let _resources = crate::managed::native_test_guard();
    for measured in [false, true] {
        let records = Records::new();
        records.select(2, true);
        let directory = &records.fixture.operation;
        let capture = measured.then(Capture::start);
        let result: Result<Option<Vec<u64>>> = directory.read_scope(|reader| {
            let result = metadata::load_in_scope(reader).and_then(|image| image.read(Some(1), 0));
            assert!(
                matches!(&result, Err(crate::managed::Error::Invalid(message))
                if message == "invalid canonical dispatch custody record")
            );
            // The adversarial test changes the real source only after the original leaf read.
            // Its native directory exit must still override the already observed codec error.
            std::fs::rename(
                directory.path(),
                records.fixture.temporary.path().join("original-records"),
            )?;
            result
        });
        assert!(matches!(result, Err(crate::managed::Error::Io(_))));
        if let Some(capture) = capture {
            let stats = capture.finish();
            require_read_samples(&stats, true, 1, 1);
            require_read_samples(&stats, false, 0, 0);
        }
    }
}
