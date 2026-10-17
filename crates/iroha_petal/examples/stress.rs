//! Stress matrix: how the decoder fares when the camera or the light is not nominal.
//!
//! Every row changes one thing about the camera model of `sim.rs` (veiling light, glare, an
//! over-exposing auto-exposure, an uneven light field, hand shake) or about the light itself
//! (banding from display PWM or exposure beating, applied in linear light after capture) and
//! counts, over random poses, the frames in which each lane decodes.
//!
//! `cargo run --release -p iroha_petal --example stress -- [trials] [filter]`
use std::sync::atomic::{AtomicUsize, Ordering};

use iroha_petal::decode::{DecodeOptions, decode};
use iroha_petal::image::Luma;
use iroha_petal::render::{RenderOptions, render};
use iroha_petal::sim::{CaptureConfig, capture, fit_to_frame};
use iroha_petal::stream::StreamEncoder;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> f64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        ((self.0 >> 11) as f64) / (1u64 << 53) as f64
    }
    fn range(&mut self, lo: f64, hi: f64) -> f64 {
        lo + (hi - lo) * self.next()
    }
}

fn srgb_decode(v: f64) -> f64 {
    if v <= 0.04045 {
        v / 12.92
    } else {
        ((v + 0.055) / 1.055).powf(2.4)
    }
}

fn srgb_encode(v: f64) -> f64 {
    if v <= 0.003_130_8 {
        v * 12.92
    } else {
        1.055 * v.powf(1.0 / 2.4) - 0.055
    }
}

/// What a row does to the capture.
#[derive(Clone, Copy)]
enum Stress {
    /// Reflections add this fraction of the lit level everywhere.
    Ambient(f64),
    /// A Gaussian glare of this peak (fraction of the lit level) and sigma (pixels).
    Glare(f64, f64),
    /// The auto-exposure gain is this many times too high.
    Exposure(f64),
    /// Peak-to-peak illumination gradient (fraction of the lit level).
    Gradient(f64),
    /// Horizontal bands of this depth (fraction of the light) and period (pixels).
    Banding(f64, f64),
    /// Linear motion blur of this length in pixels, in a random direction.
    Shake(f64),
    /// One corner blossom covered (a thumb) or glared out (a white disc), before capture.
    Corner(u8),
    /// The code pushed so far that one corner blossom is outside the frame.
    CutCorner,
}

fn stress_rows() -> Vec<(String, Stress)> {
    let mut rows = Vec::new();
    for a in [0.2, 0.35, 0.5] {
        rows.push((format!("veiling light {a:.2}"), Stress::Ambient(a)));
    }
    for e in [0.5, 1.5, 2.0, 3.0] {
        rows.push((format!("exposure x{e:.1}"), Stress::Exposure(e)));
    }
    for g in [0.5, 1.0] {
        rows.push((format!("gradient {g:.1}"), Stress::Gradient(g)));
    }
    for (g, s) in [(0.5, 120.0), (1.0, 120.0), (0.8, 40.0)] {
        rows.push((format!("glare {g:.1} sigma {s:.0}"), Stress::Glare(g, s)));
    }
    for (d, p) in [(0.3, 30.0), (0.5, 30.0), (0.5, 80.0)] {
        rows.push((
            format!("banding {d:.1} period {p:.0}"),
            Stress::Banding(d, p),
        ));
    }
    for px in [2.0, 4.0, 9.0, 14.0] {
        rows.push((format!("hand shake {px:.0} px"), Stress::Shake(px)));
    }
    rows.push(("thumb over a blossom".into(), Stress::Corner(0)));
    rows.push(("glare on a blossom".into(), Stress::Corner(255)));
    rows.push(("corner outside frame".into(), Stress::CutCorner));
    rows
}

fn band(image: &mut Luma, depth: f64, period: f64, rng: &mut Rng) {
    let angle = std::f64::consts::FRAC_PI_2 + rng.range(-0.05, 0.05);
    let phase = rng.range(0.0, std::f64::consts::TAU);
    let (c, s) = (angle.cos(), angle.sin());
    for y in 0..image.height {
        for x in 0..image.width {
            let t = (x as f64 * c + y as f64 * s) / period * std::f64::consts::TAU + phase;
            let gain = 1.0 - depth * (0.5 + 0.5 * t.sin());
            let linear = srgb_decode(f64::from(image.data[y * image.width + x]) / 255.0) * gain;
            image.data[y * image.width + x] =
                (srgb_encode(linear) * 255.0).round().clamp(0.0, 255.0) as u8;
        }
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let trials: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or(30);
    let filter = args.next();
    let payload: Vec<u8> = (0..900u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8)
        .collect();
    let encoder = StreamEncoder::new(&payload, 2).expect("payload");
    let cameras: [(&str, CaptureConfig, f64); 3] = [
        ("modern 720p", CaptureConfig::modern(), 15.0),
        ("legacy 720p", CaptureConfig::legacy(), 15.0),
        ("worst 480p", CaptureConfig::worst(), 22.0),
    ];
    let threads = std::thread::available_parallelism().map_or(4, usize::from);
    println!(
        "{:<26} {:<12} {:>5} {:>5} {:>5} {:>5}",
        "condition", "camera", "any%", "P%", "K%", "D%"
    );
    for (name, stress) in stress_rows() {
        if filter.as_ref().is_some_and(|f| !name.contains(f.as_str())) {
            continue;
        }
        for (camera, base, tilt) in &cameras {
            let next = AtomicUsize::new(0);
            let tally = std::sync::Mutex::new([0usize; 4]);
            std::thread::scope(|scope| {
                for _ in 0..threads {
                    scope.spawn(|| {
                        loop {
                            let trial = next.fetch_add(1, Ordering::SeqCst);
                            if trial >= trials {
                                break;
                            }
                            let mut rng =
                                Rng(0xABCD ^ (trial as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
                            let frame = (rng.next() * 60000.0) as u16;
                            let mut source = render(
                                &encoder.cells(frame),
                                &RenderOptions {
                                    size: 768,
                                    supersample: 2,
                                    ..RenderOptions::default()
                                },
                            );
                            let corner = trial % 4;
                            if let Stress::Corner(value) = stress {
                                let (cx, cy) = iroha_petal::layout::FINDER_CENTERS[corner];
                                let (cx, cy) = (f64::from(cx) * 0.75, f64::from(cy) * 0.75);
                                let radius = if value == 0 { 60.0 } else { 71.0 };
                                for y in 0..768 {
                                    for x in 0..768 {
                                        let (dx, dy) = (x as f64 + 0.5 - cx, y as f64 + 0.5 - cy);
                                        if dx.hypot(dy) <= radius {
                                            source.data[(y * 768 + x) * 3..(y * 768 + x) * 3 + 3]
                                                .fill(value);
                                        }
                                    }
                                }
                            }
                            let mut config = *base;
                            config.seed = trial as u64 + 1;
                            config.rotation_deg = rng.range(0.0, 360.0);
                            config.tilt_x_deg = rng.range(-tilt, *tilt);
                            config.tilt_y_deg = rng.range(-tilt, *tilt);
                            config.shift = (rng.range(-0.04, 0.04), rng.range(-0.04, 0.04));
                            config.gradient_deg = rng.range(0.0, 360.0);
                            let mut banding = None;
                            match stress {
                                Stress::Ambient(a) => config.ambient = a,
                                Stress::Glare(g, s) => {
                                    config.glare = g;
                                    config.glare_sigma = s;
                                    config.glare_at = (rng.range(0.2, 0.8), rng.range(0.2, 0.8));
                                }
                                Stress::Exposure(e) => config.exposure = e,
                                Stress::Gradient(g) => config.gradient = g,
                                Stress::Banding(d, p) => banding = Some((d, p)),
                                Stress::Shake(px) => {
                                    config.motion_px = px;
                                    config.motion_deg = rng.range(0.0, 180.0);
                                }
                                Stress::Corner(_) => {}
                                Stress::CutCorner => {
                                    // a code turned by about 45 degrees and shifted along the
                                    // short side loses exactly one corner blossom
                                    config.fill = 0.7;
                                    config.rotation_deg = 45.0 + rng.range(-8.0, 8.0);
                                    config.shift = (
                                        rng.range(-0.03, 0.03),
                                        if corner.is_multiple_of(2) {
                                            0.12
                                        } else {
                                            -0.12
                                        },
                                    );
                                }
                            }
                            let config = if matches!(stress, Stress::CutCorner) {
                                config
                            } else {
                                fit_to_frame(&config, 4.0)
                            };
                            let mut image = capture(&source, &config);
                            if let Some((depth, period)) = banding {
                                band(&mut image, depth, period, &mut rng);
                            }
                            if let Ok(f) = decode(&image, &DecodeOptions::default()) {
                                let (p, k, d) = (f.p.is_some(), f.k.is_some(), f.d.is_some());
                                let mut t = tally.lock().expect("tally");
                                t[0] += usize::from(p || k || d);
                                t[1] += usize::from(p);
                                t[2] += usize::from(k);
                                t[3] += usize::from(d);
                            }
                        }
                    });
                }
            });
            let t = tally.into_inner().expect("tally");
            let pct = |n: usize| 100.0 * n as f64 / trials as f64;
            println!(
                "{:<26} {:<12} {:>5.0} {:>5.0} {:>5.0} {:>5.0}",
                name,
                camera,
                pct(t[0]),
                pct(t[1]),
                pct(t[2]),
                pct(t[3])
            );
        }
    }
}
