//! Writes the cross-SDK golden camera captures to `fixtures/petal/petal_captures_v1.json`.
//!
//! Each capture is a degraded 8-bit luma plane (zlib + base64) of one frame of
//! the `one-pass` stream in `petal_stream_v1.json`, together with the decode
//! result every conforming decoder must reach.
//!
//! `cargo run --release -p iroha_petal --example gen_captures -- <output path>`
#[path = "support/count.rs"]
mod count;
#[path = "support/floor.rs"]
mod floor;

use count::count_as_f64;
use floor::floor_u64;

use std::fmt::Write as _;
use std::io::Write as _;

use flate2::Compression;
use flate2::write::ZlibEncoder;
use iroha_petal::decode::{DecodeOptions, DecodedFrame, decode, track};
use iroha_petal::image::Luma;
use iroha_petal::render::{RenderOptions, render};
use iroha_petal::sim::{CaptureConfig, capture, fit_to_frame};
use iroha_petal::stream::StreamEncoder;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn mirror(image: &Luma) -> Luma {
    let mut data = Vec::with_capacity(image.data.len());
    for row in image.data.chunks(image.width) {
        data.extend(row.iter().rev());
    }
    Luma {
        width: image.width,
        height: image.height,
        data,
    }
}

struct Case {
    name: &'static str,
    frame: u16,
    config: Option<CaptureConfig>,
    mirrored: bool,
    /// Columns (as fractions of the width) that are dimmed to `factor` after capture.
    shadow: Option<(f64, f64, f64)>,
    /// Canonical corner whose blossom is painted over before capture (a thumb).
    hide: Option<u8>,
    /// Whether the pose is fitted into the frame; `false` lets a corner leave it.
    fit: bool,
    must: &'static str,
    note: &'static str,
}

/// Renders frame `frame` of the stream and photographs it as `case` says.
fn shoot(encoder: &StreamEncoder, frame: u16, case: &Case) -> Luma {
    let size = if case.config.is_none() { 512 } else { 768 };
    let mut source = render(
        &encoder.cells(frame),
        &RenderOptions {
            size,
            supersample: 3,
            ..RenderOptions::default()
        },
    );
    if let Some(corner) = case.hide {
        let scale = count_as_f64(size) / 1024.0;
        let (cx, cy) = iroha_petal::layout::FINDER_CENTERS[usize::from(corner)];
        let (cx, cy) = (f64::from(cx) * scale, f64::from(cy) * scale);
        let radius = 80.0 * scale;
        for y in 0..size {
            for x in 0..size {
                let (dx, dy) = (count_as_f64(x) + 0.5 - cx, count_as_f64(y) + 0.5 - cy);
                if dx.hypot(dy) <= radius {
                    source.data[(y * size + x) * 3..(y * size + x) * 3 + 3].fill(0);
                }
            }
        }
    }
    let mut luma = case.config.map_or_else(
        || source.to_luma(),
        |config| {
            if case.fit {
                capture(&source, &fit_to_frame(&config, 4.0))
            } else {
                capture(&source, &config)
            }
        },
    );
    if case.mirrored {
        luma = mirror(&luma);
    }
    if let Some((from, to, factor)) = case.shadow {
        apply_shadow(&mut luma, from, to, factor);
    }
    luma
}

/// Apply the original floating-point shadow boundaries with checked integer narrowing.
fn apply_shadow(luma: &mut Luma, from: f64, to: f64, factor: f64) {
    assert!(
        from.is_finite()
            && to.is_finite()
            && (0.0..=1.0).contains(&from)
            && (from..=1.0).contains(&to)
    );
    assert!(factor.is_finite() && (0.0..=1.0).contains(&factor));
    let start =
        usize::try_from(floor_u64(count_as_f64(luma.width) * from).expect("shadow start fits u64"))
            .expect("shadow start fits usize");
    let end =
        usize::try_from(floor_u64(count_as_f64(luma.width) * to).expect("shadow end fits u64"))
            .expect("shadow end fits usize");
    for row in luma.data.chunks_mut(luma.width) {
        for value in &mut row[start..end] {
            let rounded =
                floor_u64((f64::from(*value) * factor).round()).expect("shadow sample is finite");
            *value = u8::try_from(rounded).expect("dimmed sample fits u8");
        }
    }
}

/// Lane letters of a decoded frame, asserting every lane carries the right data.
fn lanes(name: &str, frame: &DecodedFrame, truth: &(Vec<u8>, Vec<u8>, Vec<u8>)) -> String {
    let mut flags = String::new();
    for (letter, lane, data) in [
        ('P', &frame.p, &truth.0),
        ('K', &frame.k, &truth.1),
        ('D', &frame.d, &truth.2),
    ] {
        if let Some(result) = lane {
            assert_eq!(
                &result.data, data,
                "{name}: lane {letter} decoded to wrong data"
            );
            flags.push(letter);
        }
    }
    flags
}

fn zlib64(luma: &Luma) -> String {
    let mut zlib = ZlibEncoder::new(Vec::new(), Compression::best());
    zlib.write_all(&luma.data).expect("compress");
    base64(&zlib.finish().expect("finish"))
}

fn main() {
    let path = std::env::args().nth(1).expect("output path");
    // the stream every capture displays: identical to `one-pass` in petal_stream_v1.json
    let mut rng = iroha_petal::prng::Xorshift32::new(2);
    let payload: Vec<u8> = (0..700).map(|_| rng.next_byte()).collect();
    let encoder = StreamEncoder::new(&payload, 2).expect("stream");
    let base = |w: usize, h: usize| CaptureConfig {
        width: w,
        height: h,
        ..CaptureConfig::modern()
    };
    let cases = vec![
        Case {
            name: "clean-512",
            frame: 5,
            config: None,
            mirrored: false,
            shadow: None,
            hide: None,
            fit: true,
            must: "PKD",
            note: "ideal render, no camera",
        },
        Case {
            name: "modern-720p-rotated",
            frame: 6,
            config: Some(CaptureConfig {
                noise: 2.0,
                rotation_deg: 37.0,
                tilt_x_deg: 6.0,
                tilt_y_deg: -5.0,
                shift: (0.01, -0.02),
                seed: 11,
                ..base(1280, 720)
            }),
            mirrored: false,
            shadow: None,
            hide: None,
            fit: true,
            must: "PKD",
            note: "sharp 720p, 37 degree rotation, mild tilt",
        },
        Case {
            name: "legacy-540p-tilted",
            frame: 9,
            config: Some(CaptureConfig {
                rotation_deg: 200.0,
                seed: 12,
                ..CaptureConfig {
                    width: 960,
                    height: 540,
                    ..CaptureConfig::legacy()
                }
            }),
            mirrored: false,
            shadow: None,
            hide: None,
            fit: true,
            must: "PD",
            note: "older phone: soft, noisy, barrel distortion, glare gradient; lane K optional",
        },
        Case {
            name: "soft-480p-blur1.9",
            frame: 10,
            config: Some(CaptureConfig {
                width: 640,
                height: 480,
                blur_sigma: 1.9,
                noise: 5.0,
                rotation_deg: 110.0,
                tilt_x_deg: -8.0,
                tilt_y_deg: 10.0,
                ambient: 0.05,
                seed: 13,
                ..CaptureConfig::modern()
            }),
            mirrored: false,
            shadow: None,
            hide: None,
            fit: true,
            must: "PD",
            note: "out of focus 480p; lane K must not be reported unless correct",
        },
        Case {
            name: "small-480p",
            frame: 12,
            config: Some(CaptureConfig {
                width: 640,
                height: 480,
                fill: 0.75,
                blur_sigma: 1.6,
                noise: 5.0,
                rotation_deg: 285.0,
                seed: 14,
                ..CaptureConfig::modern()
            }),
            mirrored: false,
            shadow: None,
            hide: None,
            fit: true,
            must: "PD",
            note: "low-end preview resolution and soft focus; lane K must not be reported unless correct",
        },
        Case {
            name: "selfie-mirrored-540p",
            frame: 13,
            config: Some(CaptureConfig {
                noise: 2.0,
                rotation_deg: 15.0,
                tilt_x_deg: -4.0,
                seed: 15,
                ..base(960, 540)
            }),
            mirrored: true,
            shadow: None,
            hide: None,
            fit: true,
            must: "PD",
            note: "horizontally mirrored preview (front camera)",
        },
        Case {
            name: "overexposed-540p",
            frame: 9,
            config: Some(CaptureConfig {
                exposure: 3.0,
                noise: 2.0,
                rotation_deg: 28.0,
                tilt_x_deg: 5.0,
                tilt_y_deg: -4.0,
                shift: (0.01, -0.01),
                seed: 2,
                ..base(960, 540)
            }),
            mirrored: false,
            shadow: None,
            hide: None,
            fit: true,
            must: "PKD",
            note: "auto-exposure blows the tiles out three-fold; only the normalised tile read gets P and K",
        },
        Case {
            name: "veiled-720p",
            frame: 6,
            config: Some(CaptureConfig {
                ambient: 0.5,
                rotation_deg: 250.0,
                seed: 7,
                ..CaptureConfig::legacy()
            }),
            mirrored: false,
            shadow: None,
            hide: None,
            fit: true,
            must: "PKD",
            note: "older phone in a bright room: reflections lift the black level by half the lit level",
        },
        Case {
            name: "shadow-band-540p",
            frame: 10,
            config: Some(CaptureConfig {
                noise: 2.0,
                rotation_deg: 8.0,
                seed: 16,
                ..base(960, 540)
            }),
            mirrored: false,
            shadow: Some((0.35, 0.6, 0.3)),
            hide: None,
            fit: true,
            must: "PK",
            note: "a band across the middle of the code in shadow (30 % light); finder levels cannot describe it",
        },
        Case {
            name: "hidden-corner-540p",
            frame: 14,
            config: Some(CaptureConfig {
                noise: 2.0,
                rotation_deg: 160.0,
                tilt_x_deg: 5.0,
                tilt_y_deg: -4.0,
                seed: 17,
                ..base(960, 540)
            }),
            mirrored: false,
            shadow: None,
            hide: Some(3),
            fit: true,
            must: "PKD",
            note: "a thumb covers the bottom-left blossom; the fourth corner is inferred from the other three",
        },
        Case {
            name: "cut-corner-720p",
            frame: 15,
            config: Some(CaptureConfig {
                fill: 0.7,
                rotation_deg: 45.0,
                shift: (0.02, 0.12),
                seed: 18,
                ..base(1280, 720)
            }),
            mirrored: false,
            shadow: None,
            hide: None,
            fit: false,
            must: "PD",
            note: "held too close: one corner of the code is outside the frame and is inferred",
        },
    ];
    let mut entries = Vec::new();
    for case in &cases {
        let luma = shoot(&encoder, case.frame, case);
        let decoded = decode(&luma, &DecodeOptions::default());
        let truth = encoder.lane_data(case.frame);
        let flags = decoded
            .as_ref()
            .map_or_else(|_| String::new(), |frame| lanes(case.name, frame, &truth));
        for required in case.must.chars() {
            assert!(
                flags.contains(required),
                "{}: reference decoder lost required lane {required} (got {flags:?})",
                case.name
            );
        }
        let inferred = decoded.as_ref().ok().and_then(|f| f.inferred_corner);
        if case.hide.is_some() {
            assert_eq!(inferred, case.hide, "{}: inferred corner", case.name);
        }
        let margin = |lane: &Option<iroha_petal::decode::LaneResult>| {
            lane.as_ref().map_or_else(
                || "-".to_string(),
                |r| format!("{}e{}", r.corrected, r.erasures),
            )
        };
        let (p, k, d) = decoded.as_ref().map_or_else(
            |_| ("-".into(), "-".into(), "-".into()),
            |f| (margin(&f.p), margin(&f.k), margin(&f.d)),
        );
        println!(
            "{:<24} reference decoder reads lanes {flags:?} inferred {inferred:?} (corrected/erased P {p} K {k} D {d})",
            case.name
        );
        entries.push(format!(
            "    {{\n      \"name\": \"{}\", \"note\": \"{}\", \"stream\": \"one-pass\", \"frame\": {}, \"width\": {}, \"height\": {}, \"mirrored\": {},\n      \"must_decode\": \"{}\", \"reference_decoded\": \"{flags}\", \"inferred_corner\": {},\n      \"p_data\": \"{}\", \"k_data\": \"{}\", \"d_data\": \"{}\",\n      \"luma_zlib_base64\": \"{}\"\n    }}",
            case.name,
            case.note,
            case.frame,
            luma.width,
            luma.height,
            case.mirrored,
            case.must,
            inferred.map_or_else(|| "null".to_string(), |c| c.to_string()),
            hex(&truth.0),
            hex(&truth.1),
            hex(&truth.2),
            zlib64(&luma)
        ));
    }
    // tracking pairs: decode `from`, then follow its pose into `to`
    let steady = CaptureConfig {
        noise: 2.0,
        rotation_deg: 31.0,
        tilt_x_deg: 4.0,
        seed: 21,
        ..base(960, 540)
    };
    let pairs = [
        (
            "steady-hand-540p",
            "the next analysed frame after a small hand movement; tracking reuses the pose",
            16u16,
            Case {
                name: "steady-hand-from",
                frame: 0,
                config: Some(steady),
                mirrored: false,
                shadow: None,
                hide: None,
                fit: true,
                must: "",
                note: "",
            },
            Case {
                name: "steady-hand-to",
                frame: 0,
                config: Some(CaptureConfig {
                    rotation_deg: 32.0,
                    shift: (0.008, -0.006),
                    seed: 22,
                    ..steady
                }),
                mirrored: false,
                shadow: None,
                hide: None,
                fit: true,
                must: "",
                note: "",
            },
            "PKD",
            None,
        ),
        (
            "thumb-arrives-540p",
            "a thumb covers the top-right blossom between two frames; tracking infers it",
            18u16,
            Case {
                name: "thumb-from",
                frame: 0,
                config: Some(steady),
                mirrored: false,
                shadow: None,
                hide: None,
                fit: true,
                must: "",
                note: "",
            },
            Case {
                name: "thumb-to",
                frame: 0,
                config: Some(CaptureConfig {
                    shift: (-0.006, 0.004),
                    seed: 23,
                    ..steady
                }),
                mirrored: false,
                shadow: None,
                hide: Some(1),
                fit: true,
                must: "",
                note: "",
            },
            "PKD",
            Some(1u8),
        ),
    ];
    let mut tracks = Vec::new();
    for (name, note, frame, from_case, to_case, must, inferred) in &pairs {
        let from = shoot(&encoder, *frame, from_case);
        let to = shoot(&encoder, *frame + 1, to_case);
        let previous = decode(&from, &DecodeOptions::default()).expect("the first frame decodes");
        let followed = track(&to, &previous, &DecodeOptions::default()).expect("tracking holds");
        let truth = encoder.lane_data(*frame + 1);
        let flags = lanes(name, &followed, &truth);
        for required in must.chars() {
            assert!(
                flags.contains(required),
                "{name}: tracking lost lane {required}"
            );
        }
        assert_eq!(
            followed.inferred_corner, *inferred,
            "{name}: inferred corner"
        );
        println!(
            "{name:<24} tracking reads lanes {flags:?} inferred {:?}",
            followed.inferred_corner
        );
        tracks.push(format!(
            "    {{\n      \"name\": \"{name}\", \"note\": \"{note}\", \"stream\": \"one-pass\", \"from_frame\": {}, \"to_frame\": {}, \"width\": {}, \"height\": {},\n      \"must_track\": \"{must}\", \"reference_tracked\": \"{flags}\", \"inferred_corner\": {},\n      \"p_data\": \"{}\", \"k_data\": \"{}\", \"d_data\": \"{}\",\n      \"from_luma_zlib_base64\": \"{}\",\n      \"to_luma_zlib_base64\": \"{}\"\n    }}",
            frame,
            frame + 1,
            to.width,
            to.height,
            followed
                .inferred_corner
                .map_or_else(|| "null".to_string(), |c| c.to_string()),
            hex(&truth.0),
            hex(&truth.1),
            hex(&truth.2),
            zlib64(&from),
            zlib64(&to)
        ));
    }
    // negative captures
    let noise: Vec<u8> = {
        let mut rng = iroha_petal::prng::Xorshift32::new(5);
        (0..320 * 240).map(|_| rng.next_byte()).collect()
    };
    let mut negatives = Vec::new();
    for (name, data) in [
        ("blank-320x240", vec![0u8; 320 * 240]),
        ("noise-320x240", noise),
    ] {
        assert!(
            decode(
                &Luma {
                    width: 320,
                    height: 240,
                    data: data.clone()
                },
                &DecodeOptions::default()
            )
            .is_err()
        );
        let mut zlib = ZlibEncoder::new(Vec::new(), Compression::best());
        zlib.write_all(&data).expect("compress");
        negatives.push(format!(
            "    {{\"name\": \"{name}\", \"width\": 320, \"height\": 240, \"luma_zlib_base64\": \"{}\"}}",
            base64(&zlib.finish().expect("finish"))
        ));
    }
    let out = format!(
        "{{\n  \"fixture_version\": 1,\n  \"format\": \"petal-captures-v1\",\n  \"payload_hex\": \"{}\",\n  \"payload_kind\": 2,\n  \"captures\": [\n{}\n  ],\n  \"tracks\": [\n{}\n  ],\n  \"negatives\": [\n{}\n  ]\n}}\n",
        hex(&payload),
        entries.join(",\n"),
        tracks.join(",\n"),
        negatives.join(",\n")
    );
    std::fs::write(&path, out).expect("write fixture");
    println!("wrote {path}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shadow_preserves_golden_columns_and_half_up_rounding() {
        let mut image = Luma {
            width: 960,
            height: 1,
            data: vec![255; 960],
        };
        apply_shadow(&mut image, 0.35, 0.6, 0.3);
        assert!(image.data[..336].iter().all(|&value| value == 255));
        assert!(image.data[336..576].iter().all(|&value| value == 77));
        assert!(image.data[576..].iter().all(|&value| value == 255));
        let mut image = Luma {
            width: 4,
            height: 1,
            data: vec![0, 1, 3, 255],
        };
        apply_shadow(&mut image, 0.0, 1.0, 0.5);
        assert_eq!(image.data, [0, 1, 2, 128]);
    }

    #[test]
    fn shadow_refuses_nonfinite_reversed_and_out_of_range_bounds() {
        for (from, to, factor) in [
            (f64::NAN, 1.0, 0.3),
            (-0.1, 1.0, 0.3),
            (0.7, 0.6, 0.3),
            (0.0, 1.1, 0.3),
            (0.0, 1.0, f64::NAN),
            (0.0, 1.0, 1.1),
        ] {
            assert!(
                std::panic::catch_unwind(|| {
                    apply_shadow(
                        &mut Luma {
                            width: 2,
                            height: 1,
                            data: vec![255; 2],
                        },
                        from,
                        to,
                        factor,
                    );
                })
                .is_err()
            );
        }
    }
}
