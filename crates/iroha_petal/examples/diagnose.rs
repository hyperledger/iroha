//! Per-cell error rates of the decoder under a simulated camera.
//!
//! `cargo run --release -p iroha_petal --example diagnose -- blur=1.4 noise=5 fill=0.8 w=1280 h=720 tilt=10 trials=20`
use iroha_petal::decode::{DecodeOptions, decode, decode_at, observed_cells};
use iroha_petal::layout::{SlotRole, TILE_COUNT, slot_roles};
use iroha_petal::render::{RenderOptions, render};
use iroha_petal::sim::{CaptureConfig, camera_homography, capture, fit_to_frame};
use iroha_petal::stream::StreamEncoder;

fn main() {
    let mut config = CaptureConfig {
        width: 1280,
        height: 720,
        fill: 0.8,
        blur_sigma: 1.2,
        noise: 5.0,
        ..CaptureConfig::modern()
    };
    let mut trials = 12usize;
    let mut tilt = 8.0f64;
    for arg in std::env::args().skip(1) {
        let (k, v) = arg.split_once('=').expect("key=value");
        let f: f64 = v.parse().expect("number");
        match k {
            "blur" => config.blur_sigma = f,
            "noise" => config.noise = f,
            "fill" => config.fill = f,
            "w" => config.width = f as usize,
            "h" => config.height = f as usize,
            "tilt" => tilt = f,
            "trials" => trials = f as usize,
            "k1" => config.lens_k1 = f,
            "ambient" => config.ambient = f,
            "gradient" => config.gradient = f,
            "bloom" => config.bloom = f,
            "sharpen" => config.sharpen = f,
            "exposure" => config.exposure = f,
            _ => panic!("unknown key {k}"),
        }
    }
    let payload: Vec<u8> = (0..900u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8)
        .collect();
    let encoder = StreamEncoder::new(&payload, 2).unwrap();
    let options = DecodeOptions::default();
    let roles = slot_roles();
    let mask = 0xFFFFu32;
    let mut glyph_seen = [0usize; 2];
    let mut totals = [[0usize; 4]; 2]; // [estimated, oracle] x [polarity err, glyph err, dot err, lane-K ok]
    let mut counted = [0usize; 2];
    for trial in 0..trials {
        let frame = (trial * 977 % 60000) as u16;
        let truth = encoder.cells(frame);
        let source = render(
            &truth,
            &RenderOptions {
                size: 768,
                supersample: 2,
                ..RenderOptions::default()
            },
        );
        let mut c = config;
        c.seed = trial as u64 + 1;
        c.rotation_deg = (trial as f64 * 47.0) % 360.0;
        c.tilt_x_deg = tilt * ((trial % 5) as f64 - 2.0) / 2.0;
        c.tilt_y_deg = tilt * (((trial + 2) % 5) as f64 - 2.0) / 2.0;
        let c = fit_to_frame(&c, 4.0);
        let image = capture(&source, &c);
        let estimated = decode(&image, &options).ok();
        let oracle = decode_at(&image, camera_homography(&c), &options);
        for (slot, decoded) in [(0, estimated), (1, oracle)] {
            let Some(decoded) = decoded else { continue };
            let Some(observed) = observed_cells(&image, &decoded, &options) else {
                continue;
            };
            let mut p_err = 0;
            let mut g_err = 0;
            for t in 0..TILE_COUNT {
                if observed.light[t] != truth.light[t] {
                    p_err += 1;
                } else if mask >> truth.glyph[t] & 1 == 1 {
                    glyph_seen[slot] += 1;
                    if observed.glyph[t] != truth.glyph[t] {
                        g_err += 1;
                    }
                }
            }
            let dot_err = (0..roles.len())
                .filter(|&i| {
                    matches!(roles[i], SlotRole::Data(_)) && observed.dots[i] != truth.dots[i]
                })
                .count();
            let t = &mut totals[slot];
            t[0] += p_err;
            t[1] += g_err;
            t[2] += dot_err;
            t[3] += usize::from(decoded.k.is_some());
            counted[slot] += 1;
        }
    }
    for (slot, name) in [(0, "finder-based"), (1, "oracle pose ")] {
        let n = counted[slot].max(1) as f64;
        println!(
            "{name}: n={} tile-polarity err {:.2}%  glyph err {:.2}%  dot err {:.2}%  lane K ok {:.0}%",
            counted[slot],
            100.0 * totals[slot][0] as f64 / n / TILE_COUNT as f64,
            100.0 * totals[slot][1] as f64 / glyph_seen[slot].max(1) as f64,
            100.0 * totals[slot][2] as f64 / n / 240.0,
            100.0 * totals[slot][3] as f64 / n
        );
    }
}
