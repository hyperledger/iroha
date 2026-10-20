//! Decodes the golden camera captures in `fixtures/petal/petal_captures_v1.json`.
//!
//! Every conforming decoder must read the lanes named in `must_decode`, must
//! never report wrong data for any lane, must report the recorded inferred
//! corner, must follow each tracking pair from its first frame into its second,
//! must recover the `must_merge` lanes of every merge set from the merge of its
//! captures, must never let a session offer a lane of a mixed set, and must
//! reject the negatives.
#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]

use std::io::Read as _;
use std::path::PathBuf;

use flate2::read::ZlibDecoder;
use iroha_petal::decode::{DecodeOptions, LaneResult, decode, merge_tiles, tile_evidence, track};
use iroha_petal::image::Luma;
use iroha_petal::lanes::{Lane, decode_lane};
use iroha_petal::session::{ScanLimits, ScanSession, ScanStats};
use iroha_petal::stream::{AssemblerLimits, StreamAssembler};
use norito::json::{self, Value};

fn base64_decode(text: &str) -> Vec<u8> {
    let value = |c: u8| -> u32 {
        match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'a'..=b'z' => u32::from(c - b'a') + 26,
            b'0'..=b'9' => u32::from(c - b'0') + 52,
            b'+' => 62,
            b'/' => 63,
            _ => panic!("bad base64"),
        }
    };
    let mut out = Vec::new();
    for chunk in text.as_bytes().chunks(4) {
        let mut n = 0u32;
        let mut real = 0;
        for &c in chunk {
            n <<= 6;
            if c != b'=' {
                n |= value(c);
                real += 1;
            }
        }
        n <<= 6 * (4 - chunk.len()) as u32;
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&bytes[..real - 1]);
    }
    out
}

fn luma_of(entry: &Value) -> Luma {
    luma_at(entry, "luma_zlib_base64")
}

fn luma_at(entry: &Value, key: &str) -> Luma {
    let compressed = base64_decode(entry.get(key).and_then(Value::as_str).expect("luma"));
    let mut data = Vec::new();
    ZlibDecoder::new(compressed.as_slice())
        .read_to_end(&mut data)
        .expect("inflate");
    let width = entry.get("width").and_then(Value::as_u64).expect("width") as usize;
    let height = entry.get("height").and_then(Value::as_u64).expect("height") as usize;
    Luma::from_raw(width, height, data).expect("luma size")
}

fn load() -> Value {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../fixtures/petal/petal_captures_v1.json");
    json::from_str(&std::fs::read_to_string(path).expect("fixture file")).expect("fixture json")
}

fn hex_field(entry: &Value, key: &str) -> Vec<u8> {
    hex::decode(entry.get(key).and_then(Value::as_str).expect("hex field")).expect("hex")
}

#[test]
fn golden_captures_decode_as_recorded() {
    let doc = load();
    let mut assembler = StreamAssembler::new(AssemblerLimits::default());
    for capture in doc
        .get("captures")
        .and_then(Value::as_array)
        .expect("captures")
    {
        let name = capture.get("name").and_then(Value::as_str).unwrap();
        let image = luma_of(capture);
        let decoded =
            decode(&image, &DecodeOptions::default()).unwrap_or_else(|e| panic!("{name}: {e}"));
        let expected_mirror = capture.get("mirrored").and_then(Value::as_bool).unwrap();
        assert_eq!(decoded.mirrored, expected_mirror, "{name}: mirror flag");
        let lanes = [
            ('P', &decoded.p, hex_field(capture, "p_data")),
            ('K', &decoded.k, hex_field(capture, "k_data")),
            ('D', &decoded.d, hex_field(capture, "d_data")),
        ];
        let must = capture.get("must_decode").and_then(Value::as_str).unwrap();
        for (letter, lane, expected) in lanes {
            match lane {
                Some(result) => assert_eq!(result.data, expected, "{name}: lane {letter} data"),
                None => assert!(
                    !must.contains(letter),
                    "{name}: required lane {letter} was not decoded"
                ),
            }
        }
        let inferred = capture.get("inferred_corner").and_then(Value::as_u64);
        assert_eq!(
            decoded.inferred_corner.map(u64::from),
            inferred,
            "{name}: inferred corner"
        );
        decoded.feed(&mut assembler);
    }
    // captures of different frames of the same stream accumulate in one assembler
    assert!(assembler.progress().atoms_received > 10);
}

#[test]
fn golden_tracks_follow_the_pose_into_the_next_frame() {
    let doc = load();
    let options = DecodeOptions::default();
    for pair in doc.get("tracks").and_then(Value::as_array).expect("tracks") {
        let name = pair.get("name").and_then(Value::as_str).unwrap();
        let previous = decode(&luma_at(pair, "from_luma_zlib_base64"), &options)
            .unwrap_or_else(|e| panic!("{name}: first frame: {e}"));
        let followed = track(&luma_at(pair, "to_luma_zlib_base64"), &previous, &options)
            .unwrap_or_else(|| panic!("{name}: tracking lost the code"));
        let must = pair.get("must_track").and_then(Value::as_str).unwrap();
        for (letter, lane, expected) in [
            ('P', &followed.p, hex_field(pair, "p_data")),
            ('K', &followed.k, hex_field(pair, "k_data")),
            ('D', &followed.d, hex_field(pair, "d_data")),
        ] {
            match lane {
                Some(result) => assert_eq!(result.data, expected, "{name}: lane {letter} data"),
                None => assert!(!must.contains(letter), "{name}: lane {letter} lost"),
            }
        }
        let inferred = pair.get("inferred_corner").and_then(Value::as_u64);
        assert_eq!(
            followed.inferred_corner.map(u64::from),
            inferred,
            "{name}: inferred corner"
        );
    }
}

/// Decodes every capture of a merge set as recorded and pushes it through a fresh session
/// (30 fps); returns the merge of their tile evidence, the lanes the session merged and its
/// counters.
fn merge_set(set: &Value) -> ((Option<LaneResult>, Option<LaneResult>), String, ScanStats) {
    let name = set.get("name").and_then(Value::as_str).unwrap();
    let options = DecodeOptions::default();
    let mut evidence = Vec::new();
    let mut session = ScanSession::new(ScanLimits::default());
    let mut merged = String::new();
    let captures = set
        .get("captures")
        .and_then(Value::as_array)
        .expect("captures");
    for (i, capture) in captures.iter().enumerate() {
        let mut entry = capture.clone();
        for key in ["width", "height"] {
            if let (Some(map), Some(value)) = (entry.as_object_mut(), set.get(key)) {
                map.insert(key.to_string(), value.clone());
            }
        }
        let image = luma_of(&entry);
        let decoded =
            decode(&image, &options).unwrap_or_else(|e| panic!("{name} capture {i}: {e}"));
        let mut read = String::new();
        for (letter, lane, expected) in [
            ('P', &decoded.p, hex_field(set, "p_data")),
            ('K', &decoded.k, hex_field(set, "k_data")),
            ('D', &decoded.d, hex_field(set, "d_data")),
        ] {
            if let Some(result) = lane {
                assert_eq!(
                    result.data, expected,
                    "{name} capture {i}: lane {letter} data"
                );
                read.push(letter);
            }
        }
        let must = capture.get("must_decode").and_then(Value::as_str).unwrap();
        assert!(
            must.chars().all(|letter| read.contains(letter)),
            "{name} capture {i}: read {read:?}, must read {must:?}"
        );
        let reference = capture
            .get("reference_decoded")
            .and_then(Value::as_str)
            .unwrap();
        assert_eq!(read, reference, "{name} capture {i}: lanes read alone");
        evidence.push(tile_evidence(&image, &decoded, &options).expect("tile evidence"));
        merged.push_str(&session.push(&image, 33 * i as u64).merged);
    }
    (merge_tiles(&evidence, &options), merged, session.stats())
}

#[test]
fn golden_merge_sets_recover_lanes_no_capture_reads_alone() {
    let doc = load();
    for set in doc.get("merges").and_then(Value::as_array).expect("merges") {
        let name = set.get("name").and_then(Value::as_str).unwrap();
        let ((p, k), session_merged, stats) = merge_set(set);
        let mut merged = String::new();
        for (letter, lane, expected) in [
            ('P', &p, hex_field(set, "p_data")),
            ('K', &k, hex_field(set, "k_data")),
        ] {
            if let Some(result) = lane {
                assert_eq!(result.data, expected, "{name}: merged lane {letter} data");
                merged.push(letter);
            }
        }
        let reference = set.get("reference_merged").and_then(Value::as_str).unwrap();
        assert_eq!(merged, reference, "{name}: merged lanes");
        let must = set.get("must_merge").and_then(Value::as_str).unwrap();
        for letter in must.chars() {
            assert!(
                session_merged.contains(letter),
                "{name}: the session did not recover lane {letter} (merged {session_merged:?})"
            );
        }
        assert!(stats.merges > 0, "{name}: no merge");
    }
}

#[test]
fn golden_mixed_sets_never_offer_the_other_frames_lanes() {
    let doc = load();
    for set in doc
        .get("mixed_merges")
        .and_then(Value::as_array)
        .expect("mixed merges")
    {
        let name = set.get("name").and_then(Value::as_str).unwrap();
        let ((p, k), session_merged, stats) = merge_set(set);
        // the merge itself reads the tile field, which shows another frame than the rings
        let mut merged = String::new();
        for (letter, lane, expected) in [
            ('P', &p, hex_field(set, "p_data")),
            ('K', &k, hex_field(set, "k_data")),
        ] {
            if let Some(result) = lane {
                assert_eq!(result.data, expected, "{name}: merged lane {letter} data");
                assert_ne!(
                    result.data[1..3],
                    hex_field(set, "d_data")[1..3],
                    "{name}: lane {letter} names the rings' frame"
                );
                merged.push(letter);
            }
        }
        let reference = set.get("reference_merged").and_then(Value::as_str).unwrap();
        assert_eq!(merged, reference, "{name}: merged lanes");
        assert!(stats.merges > 0, "{name}: no merge was tried");
        assert_eq!(
            session_merged, "",
            "{name}: the session offered another frame's lanes"
        );
        assert_eq!((stats.merged_p, stats.merged_k), (0, 0), "{name}");
    }
}

#[test]
fn negative_captures_are_rejected() {
    let doc = load();
    for negative in doc
        .get("negatives")
        .and_then(Value::as_array)
        .expect("negatives")
    {
        assert!(decode(&luma_of(negative), &DecodeOptions::default()).is_err());
    }
}

#[test]
fn recorded_lane_data_is_a_valid_codeword_of_its_stream() {
    let doc = load();
    for capture in doc
        .get("captures")
        .and_then(Value::as_array)
        .expect("captures")
    {
        let data = hex_field(capture, "p_data");
        let word = iroha_petal::lanes::encode_lane(Lane::P, &data);
        assert_eq!(decode_lane(Lane::P, &word, &[]).unwrap(), data);
    }
}
