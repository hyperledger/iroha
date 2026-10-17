//! Monte-Carlo qualification of the decoder against simulated cameras.
//!
//! `cargo run --release -p iroha_petal --example qualify -- [trials] [filter] [--verbose]`
//!
//! `--verbose` prints one line per trial (pose and the lanes that decoded).
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use iroha_petal::decode::{DecodeOptions, decode};
use iroha_petal::locate::locate;
use iroha_petal::render::{RenderOptions, render};
use iroha_petal::sim::{CaptureConfig, capture, fit_to_frame, pixels_per_unit};
use iroha_petal::stream::StreamEncoder;

#[derive(Clone)]
struct Scenario {
    name: String,
    base: CaptureConfig,
    rotate_any: bool,
    tilt_max: f64,
}

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

fn scenarios() -> Vec<Scenario> {
    let mut out = Vec::new();
    let mut add = |name: String, base: CaptureConfig, rotate_any: bool, tilt_max: f64| {
        out.push(Scenario {
            name,
            base,
            rotate_any,
            tilt_max,
        });
    };
    let flat = |w: usize, h: usize, fill: f64, blur: f64, noise: f64| CaptureConfig {
        width: w,
        height: h,
        fill,
        blur_sigma: blur,
        noise,
        ..CaptureConfig::modern()
    };
    add("modern 720p".into(), CaptureConfig::modern(), true, 15.0);
    add("legacy 720p".into(), CaptureConfig::legacy(), true, 15.0);
    add("worst 480p".into(), CaptureConfig::worst(), true, 22.0);
    for fill in [0.5, 0.6, 0.7, 0.8, 0.9] {
        add(
            format!("480p fill {fill:.1} blur1.2 noise5"),
            flat(640, 480, fill, 1.2, 5.0),
            true,
            12.0,
        );
    }
    for blur in [0.7, 1.0, 1.4, 1.8, 2.2] {
        add(
            format!("720p blur {blur:.1} noise5"),
            flat(1280, 720, 0.8, blur, 5.0),
            true,
            12.0,
        );
    }
    for blur in [2.6, 3.2, 4.0] {
        add(
            format!("720p defocus {blur:.1} noise5"),
            flat(1280, 720, 0.8, blur, 5.0),
            true,
            12.0,
        );
    }
    for blur in [2.0, 2.6, 3.2] {
        add(
            format!("480p defocus {blur:.1} noise5"),
            flat(640, 480, 0.8, blur, 5.0),
            true,
            12.0,
        );
    }
    for noise in [3.0, 6.0, 9.0, 13.0] {
        add(
            format!("720p noise {noise:.0} blur1.2"),
            flat(1280, 720, 0.8, 1.2, noise),
            true,
            12.0,
        );
    }
    for tilt in [0.0, 15.0, 25.0, 35.0, 45.0] {
        add(
            format!("720p tilt<={tilt:.0} blur1.2"),
            flat(1280, 720, 0.8, 1.2, 5.0),
            true,
            tilt,
        );
    }
    out
}

fn main() {
    let verbose = std::env::args().any(|a| a == "--verbose");
    let mut args = std::env::args().skip(1).filter(|a| a != "--verbose");
    let trials: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or(24);
    let filter = args.next();
    let payload: Vec<u8> = (0..900u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8)
        .collect();
    let encoder = StreamEncoder::new(&payload, 2).expect("payload");
    let threads = std::thread::available_parallelism().map_or(4, usize::from);
    println!(
        "{:<34} {:>6} {:>6} {:>6} {:>6} {:>7} {:>8}",
        "scenario", "any%", "P%", "K%", "D%", "ms/dec", "px/tile"
    );
    for scenario in scenarios() {
        if filter
            .as_ref()
            .is_some_and(|f| !scenario.name.contains(f.as_str()))
        {
            continue;
        }
        let next = AtomicUsize::new(0);
        let results = std::sync::Mutex::new(Vec::new());
        let scale_sum = std::sync::Mutex::new(Vec::new());
        let started = Instant::now();
        std::thread::scope(|scope| {
            for _ in 0..threads {
                scope.spawn(|| {
                    loop {
                        let trial = next.fetch_add(1, Ordering::SeqCst);
                        if trial >= trials {
                            break;
                        }
                        let mut rng =
                            Rng(0x1234_5678 ^ (trial as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
                        let frame = (rng.next() * 60000.0) as u16;
                        let source = render(
                            &encoder.cells(frame),
                            &RenderOptions {
                                size: 768,
                                supersample: 2,
                                ..RenderOptions::default()
                            },
                        );
                        let mut config = scenario.base;
                        config.seed = trial as u64 + 1;
                        if scenario.rotate_any {
                            config.rotation_deg = rng.range(0.0, 360.0);
                        }
                        config.tilt_x_deg = rng.range(-scenario.tilt_max, scenario.tilt_max);
                        config.tilt_y_deg = rng.range(-scenario.tilt_max, scenario.tilt_max);
                        config.shift = (rng.range(-0.04, 0.04), rng.range(-0.04, 0.04));
                        config.gradient_deg = rng.range(0.0, 360.0);
                        let config = fit_to_frame(&config, 4.0);
                        scale_sum.lock().unwrap().push(pixels_per_unit(&config));
                        let image = capture(&source, &config);
                        let located = locate(&image).is_some();
                        let t0 = Instant::now();
                        let outcome = decode(&image, &DecodeOptions::default());
                        let ms = t0.elapsed().as_secs_f64() * 1000.0;
                        let (p, k, d) = match &outcome {
                            Ok(f) => (f.p.is_some(), f.k.is_some(), f.d.is_some()),
                            Err(_) => (false, false, false),
                        };
                        if verbose {
                            println!(
                                "  trial {trial}: rot {:.0} tilt ({:.0},{:.0}) -> {:?}",
                                config.rotation_deg,
                                config.tilt_x_deg,
                                config.tilt_y_deg,
                                outcome.as_ref().map(|f| (
                                    f.p.is_some(),
                                    f.k.is_some(),
                                    f.d.is_some(),
                                    f.rotation,
                                    f.mirrored
                                ))
                            );
                        }
                        results.lock().unwrap().push((p, k, d, ms, located));
                    }
                });
            }
        });
        let results = results.into_inner().unwrap();
        let scales = scale_sum.into_inner().unwrap();
        let mean_scale = scales.iter().sum::<f64>() / scales.len().max(1) as f64;
        let n = results.len() as f64;
        let pct = |f: &dyn Fn(&(bool, bool, bool, f64, bool)) -> bool| {
            100.0 * results.iter().filter(|r| f(r)).count() as f64 / n
        };
        println!(
            "{:<34} {:>6.0} {:>6.0} {:>6.0} {:>6.0} {:>7.0} {:>6.1}px  loc {:>3.0}%  ({:.0}s)",
            scenario.name,
            pct(&|r| r.0 || r.1 || r.2),
            pct(&|r| r.0),
            pct(&|r| r.1),
            pct(&|r| r.2),
            results.iter().map(|r| r.3).sum::<f64>() / n,
            mean_scale * 29.0,
            pct(&|r| r.4),
            started.elapsed().as_secs_f64()
        );
    }
}
