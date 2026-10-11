//! Native private reads verify opt-in measurement boundaries without changing custody results.

use super::*;
use finish_timing::{Capture, Phase, Stats};

fn directory() -> (tempfile::TempDir, PrivateDirectory) {
    let temporary = tempfile::tempdir().unwrap();
    let directory = PrivateDirectory::open_or_create(temporary.path().join("records")).unwrap();
    directory
        .write_atomic(
            "valid.nrt",
            &encode(&vec![3_u64, 5, 8], MAX_RECORD_BYTES).unwrap(),
            PublishMode::CreateNew,
        )
        .unwrap();
    directory
        .write_atomic("malformed.nrt", &[0], PublishMode::CreateNew)
        .unwrap();
    directory
        .write_atomic(
            "oversized.nrt",
            &vec![0; MAX_RECORD_BYTES + 1],
            PublishMode::CreateNew,
        )
        .unwrap();
    (temporary, directory)
}

fn read(directory: &PrivateDirectory, name: &str, scoped: bool) -> Result<Option<Vec<u64>>> {
    if scoped {
        directory.read_scope(|reader| read_record_in_scope(reader, name))
    } else {
        read_record(directory, name)
    }
}

fn records(
    directory: &PrivateDirectory,
    scoped: bool,
) -> Vec<std::result::Result<Option<Vec<u64>>, String>> {
    ["valid.nrt", "missing.nrt", "malformed.nrt", "oversized.nrt"]
        .into_iter()
        .map(|name| read(directory, name, scoped).map_err(|error| error.to_string()))
        .collect()
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
    assert!(
        read_us >= decode_us,
        "codec work is nested within its record read"
    );
}

#[test]
fn record_and_inventory_samples_preserve_present_absent_and_refused_native_results() {
    let (_temporary, directory) = directory();
    let ordinary = records(&directory, false);
    let scoped = records(&directory, true);
    assert_eq!(ordinary, scoped);
    assert_eq!(ordinary[0], Ok(Some(vec![3, 5, 8])));
    assert_eq!(ordinary[1], Ok(None));
    assert_eq!(
        ordinary[2],
        Err("invalid canonical dispatch custody record".into())
    );
    assert!(ordinary[3].is_err());
    let inventory_results = [false, true].map(|scoped| {
        [3, 0].map(|maximum| {
            inventory(&directory, maximum, scoped).map_err(|error| error.to_string())
        })
    });
    assert!(inventory_results[0][0].is_ok());
    assert!(inventory_results[0][1].is_err());
    assert_eq!(inventory_results[0], inventory_results[1]);

    let capture = Capture::start();
    assert_eq!(records(&directory, false), ordinary);
    assert_eq!(records(&directory, true), scoped);
    for (scoped, expected) in [false, true].into_iter().zip(inventory_results) {
        assert_eq!(
            [3, 0]
                .map(|maximum| inventory(&directory, maximum, scoped)
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
    assert_eq!(records(&directory, false), ordinary);
    assert_eq!(records(&directory, true), scoped);
    let capture = Capture::start();
    let stats = capture.finish();
    require_read_samples(&stats, false, 0, 0);
    require_read_samples(&stats, true, 0, 0);
    assert_eq!(stats.sample(Phase::AttemptInventory), (0, 0));
    assert_eq!(stats.sample(Phase::AttemptScopedInventory), (0, 0));
}

#[test]
fn record_samples_preserve_active_decode_result_charge_and_refusal() {
    let (_temporary, directory) = directory();
    let run = |scoped, allocation| {
        let limits = norito::DecodeLimits::new(
            MAX_RECORD_BYTES,
            MAX_RECORD_BYTES,
            MAX_RECORD_BYTES,
            allocation,
            32,
        );
        norito::core::with_decode_limits_measured(limits, || {
            read(&directory, "valid.nrt", scoped).map_err(|error| error.to_string())
        })
    };
    for scoped in [false, true] {
        let original = run(scoped, usize::MAX);
        assert_eq!(original.0, Ok(Some(vec![3, 5, 8])));
        let exact = original.1.total_allocated_bytes();
        assert!(exact > 1);
        for allocation in [1, exact - 1, exact, usize::MAX] {
            let expected = run(scoped, allocation);
            let capture = Capture::start();
            let actual = run(scoped, allocation);
            let stats = capture.finish();
            assert_eq!(actual, expected);
            require_read_samples(&stats, scoped, 1, 1);
            require_read_samples(&stats, !scoped, 0, 0);
            if allocation == 1 {
                assert_eq!(
                    actual.0,
                    Err("invalid canonical dispatch custody record".into())
                );
            }
            if allocation >= exact {
                assert!(actual.0.is_ok());
            }
        }
    }
}

#[test]
fn record_sample_closes_before_outer_source_exit_overrides_codec_refusal() {
    for measured in [false, true] {
        let (temporary, directory) = directory();
        let capture = measured.then(Capture::start);
        let result: Result<Option<Vec<u64>>> = directory.read_scope(|reader| {
            let result = read_record_in_scope(reader, "malformed.nrt");
            assert!(
                matches!(&result, Err(crate::managed::Error::Invalid(message))
                if message == "invalid canonical dispatch custody record")
            );
            // The adversarial test changes the real source only after the original leaf read.
            // Its native directory exit must still override the already observed codec error.
            std::fs::rename(directory.path(), temporary.path().join("original-records"))?;
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
