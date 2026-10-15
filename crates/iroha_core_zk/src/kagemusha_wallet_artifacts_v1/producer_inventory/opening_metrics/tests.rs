//! Observation-only opening records: lap arithmetic, the log line and pinned work counts.

use std::{io::Write as _, time::Duration};

use iroha_fs::PrivateDirectory;

use super::*;
use crate::kagemusha_wallet_artifacts_v1::producer_inventory::{
    BlobV1, EncodedDirectoryOriginalsV1, EncodedOriginalV1, EncodedTransportV1, Error,
    OriginalSourceV1,
};

fn work(raw: u64, decodes: u64) -> OpeningWorkV1 {
    OpeningWorkV1 {
        raw_bytes_hashed: raw,
        zstd_decodes: decodes,
        ..OpeningWorkV1::default()
    }
}

#[test]
fn laps_partition_thread_work_and_total_includes_restarted_intervals() {
    let mut metrics = OpeningMetricsV1::start();
    record_raw_hashed(5);
    record_zstd_decode();
    metrics.lap("first");
    record_raw_hashed(7);
    // Owned by another record (for example a qualified graph), so not lapped here.
    metrics.restart();
    record_zstd_decode();
    record_zstd_decode();
    metrics.lap("second");
    metrics.finish();
    let names: Vec<_> = metrics.phases().iter().map(|(name, _)| *name).collect();
    assert_eq!(names, ["first", "second", "total"]);
    assert_eq!(metrics.phase("first").unwrap().work, work(5, 1));
    assert_eq!(metrics.phase("second").unwrap().work, work(0, 2));
    assert_eq!(metrics.phase("total").unwrap().work, work(12, 3));
    let total = metrics.phase("total").unwrap().elapsed;
    assert!(metrics.phase("first").unwrap().elapsed <= total);
    assert!(metrics.phase("missing").is_none());
}

#[test]
fn qualification_rows_follow_graph_order_without_touching_the_lap_clock() {
    let stage = |micros| OpeningPhaseV1 {
        elapsed: Duration::from_micros(micros),
        work: work(micros, 0),
    };
    let mut metrics = OpeningMetricsV1::start();
    metrics.qualification(&QualificationMetricsV1 {
        binding: stage(1),
        sigma: stage(2),
        q: stage(3),
        routes: stage(4),
        omega: stage(5),
    });
    let rows: Vec<_> = metrics
        .phases()
        .iter()
        .map(|(name, value)| (*name, value.work.raw_bytes_hashed))
        .collect();
    assert_eq!(
        rows,
        [
            ("binding", 1),
            ("sigma", 2),
            ("q", 3),
            ("routes", 4),
            ("omega", 5)
        ]
    );
    record_raw_hashed(9);
    metrics.lap("closing");
    assert_eq!(metrics.phase("closing").unwrap().work, work(9, 0));
}

#[test]
fn log_line_carries_only_fixed_names_whole_microseconds_and_counts() {
    let mut metrics = OpeningMetricsV1::start();
    metrics.record(
        "snapshot_capture",
        OpeningPhaseV1 {
            elapsed: Duration::from_nanos(2_999),
            work: OpeningWorkV1 {
                originals_opened: 1,
                stored_files_opened: 2,
                stored_bytes_hashed: 3,
                raw_bytes_hashed: 4,
                zstd_decodes: 5,
                descriptor_decodes: 6,
                ancestry_walks: 7,
                ancestry_opens: 8,
            },
        },
    );
    metrics.record("closing", OpeningPhaseV1::default());
    assert_eq!(
        metrics.to_json(),
        concat!(
            r#"{"schema":"iroha.kagemusha.opening-metrics.v1","phases":["#,
            r#"{"phase":"snapshot_capture","micros":2,"originalsOpened":1,"storedFilesOpened":2,"#,
            r#""storedBytesHashed":3,"rawBytesHashed":4,"zstdDecodes":5,"descriptorDecodes":6,"#,
            r#""ancestryWalks":7,"ancestryOpens":8},"#,
            r#"{"phase":"closing","micros":0,"originalsOpened":0,"storedFilesOpened":0,"#,
            r#""storedBytesHashed":0,"rawBytesHashed":0,"zstdDecodes":0,"descriptorDecodes":0,"#,
            r#""ancestryWalks":0,"ancestryOpens":0}]}"#
        )
    );
    let value: norito::json::Value =
        norito::json::from_slice(metrics.to_json().as_bytes()).unwrap();
    let object = value.as_object().unwrap();
    assert_eq!(
        object.get("schema").and_then(norito::json::Value::as_str),
        Some(OPENING_METRICS_SCHEMA_V1)
    );
    assert_eq!(
        object
            .get("phases")
            .and_then(norito::json::Value::as_array)
            .map(Vec::len),
        Some(2)
    );
}

#[test]
fn counts_stay_on_the_recording_thread() {
    let before = OpeningWorkV1::current_thread();
    std::thread::spawn(|| {
        let start = OpeningWorkV1::current_thread();
        record_original_opened();
        record_stored_file_opened();
        record_stored_hashed(3);
        assert_eq!(
            OpeningWorkV1::current_thread().since(start),
            OpeningWorkV1 {
                originals_opened: 1,
                stored_files_opened: 1,
                stored_bytes_hashed: 3,
                ..OpeningWorkV1::default()
            }
        );
    })
    .join()
    .unwrap();
    assert_eq!(OpeningWorkV1::current_thread(), before);
    assert_eq!(
        OpeningWorkV1::default().since(work(1, 1)),
        OpeningWorkV1::default()
    );
}

fn encoded(raws: &[&[u8]]) -> (tempfile::TempDir, EncodedDirectoryOriginalsV1, Vec<u64>) {
    let temp = tempfile::tempdir().unwrap();
    let root =
        PrivateDirectory::open_or_create(temp.path().canonicalize().unwrap().join("data")).unwrap();
    let mut transport_rows = Vec::new();
    let mut stored_lengths = Vec::new();
    for raw in raws {
        let stored = zstd::stream::encode_all(*raw, 1).unwrap();
        let row = EncodedOriginalV1 {
            original: BlobV1::of(raw),
            stored: BlobV1::of(&stored),
        };
        let mut file = root
            .create_retained_private(hex::encode(row.original.sha256), stored.len())
            .unwrap();
        file.write_all(&stored).unwrap();
        file.seal_read_only().unwrap();
        stored_lengths.push(stored.len() as u64);
        transport_rows.push(row);
    }
    transport_rows.sort_by_key(|row| row.original.sha256);
    let source = EncodedDirectoryOriginalsV1::open_existing(
        root.path(),
        &EncodedTransportV1::new(transport_rows).unwrap(),
    )
    .unwrap();
    (temp, source, stored_lengths)
}

// Pins the current admission-transaction work so later read-transaction and
// decode-once changes show their effect as exact count changes.
#[test]
fn encoded_snapshot_work_is_pinned_for_capture_reads_and_closing() {
    let raws: &[&[u8]] = &[
        b"first exact public original",
        b"second, longer exact original",
    ];
    let (_temp, source, stored) = encoded(raws);
    let stored: u64 = stored.iter().sum();
    let raw: u64 = raws.iter().map(|raw| raw.len() as u64).sum();
    let count = raws.len() as u64;
    let mut metrics = OpeningMetricsV1::start();
    source
        .with_snapshot::<_, Error>(|snapshot| {
            metrics.lap("snapshot_capture");
            for raw in raws {
                let bytes = super::super::read(snapshot, BlobV1::of(raw), 1 << 20)?;
                assert_eq!(bytes, *raw);
            }
            metrics.lap("reads");
            Ok(())
        })
        .unwrap();
    metrics.lap("closing");
    let capture = metrics.phase("snapshot_capture").unwrap().work;
    let reads = metrics.phase("reads").unwrap().work;
    let closing = metrics.phase("closing").unwrap().work;
    // Capture opens every file once, hashes stored bytes as read and again while
    // authenticating each decoded frame, and hashes every raw byte once.
    assert_eq!(
        OpeningWorkV1 {
            ancestry_walks: 0,
            ancestry_opens: 0,
            ..capture
        },
        OpeningWorkV1 {
            stored_files_opened: count,
            stored_bytes_hashed: 2 * stored,
            raw_bytes_hashed: raw,
            zstd_decodes: count,
            ..OpeningWorkV1::default()
        }
    );
    assert!(capture.ancestry_walks >= count && capture.ancestry_opens > capture.ancestry_walks);
    // Each bounded read decodes its frame again from memory, re-hashes the stored
    // bytes, and hashes raw bytes in both the decoder and the bounded reader.
    // Reads from the private snapshot touch no file or ancestry.
    assert_eq!(
        reads,
        OpeningWorkV1 {
            originals_opened: count,
            stored_bytes_hashed: stored,
            raw_bytes_hashed: 2 * raw,
            zstd_decodes: count,
            ..OpeningWorkV1::default()
        }
    );
    // Closing reopens every observed file to compare its retained snapshot; it hashes nothing.
    assert_eq!(
        OpeningWorkV1 {
            ancestry_walks: 0,
            ancestry_opens: 0,
            ..closing
        },
        OpeningWorkV1 {
            stored_files_opened: count,
            ..OpeningWorkV1::default()
        }
    );
    assert!(closing.ancestry_walks >= count + 2);
}

#[test]
fn failed_reads_change_no_verdict_and_record_only_started_work() {
    struct Missing;
    impl OriginalSourceV1 for Missing {
        fn open(&mut self, _: [u8; 32]) -> Result<Box<dyn std::io::Read + '_>, Error> {
            Err(Error::Unavailable)
        }
    }
    let before = OpeningWorkV1::current_thread();
    let blob = BlobV1::of(b"absent original");
    assert!(matches!(
        super::super::read(&mut Missing, blob, 1 << 10),
        Err(Error::Unavailable)
    ));
    assert_eq!(
        OpeningWorkV1::current_thread().since(before),
        OpeningWorkV1 {
            originals_opened: 1,
            ..OpeningWorkV1::default()
        }
    );
}
