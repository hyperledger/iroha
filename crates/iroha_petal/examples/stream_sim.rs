//! End-to-end stream simulation: a screen animating Petal frames, a phone
//! camera watching it (frame blending and rolling-shutter tearing included).
//!
//! `cargo run --release -p iroha_petal --example stream_sim -- [trials] [payload bytes] [display fps] [camera filter]`
use std::sync::atomic::{AtomicUsize, Ordering};

use iroha_petal::prng::Xorshift32;
use iroha_petal::qualify::{CameraModel, StreamTrial, TrialOutcome, run_stream_trial};

fn main() {
    let mut args = std::env::args().skip(1);
    let trials: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or(8);
    let payload_len: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or(2048);
    let fps: f64 = args.next().and_then(|a| a.parse().ok()).unwrap_or(8.0);
    let filter = args.next();
    println!("payload {payload_len} B, display {fps} fps, camera 30 fps, exposure 1/60 s");
    println!(
        "{:<10} {:>6} {:>8} {:>8} {:>8} {:>7} {:>9} {:>7}",
        "camera", "done%", "mean s", "p50 s", "p90 s", "false", "ms/frame", "K%"
    );
    let threads = std::thread::available_parallelism().map_or(4, usize::from);
    for name in CameraModel::NAMES {
        if filter.as_ref().is_some_and(|f| !name.contains(f.as_str())) {
            continue;
        }
        let camera = CameraModel::named(name).expect("known camera");
        let next = AtomicUsize::new(0);
        let outcomes = std::sync::Mutex::new(Vec::<TrialOutcome>::new());
        std::thread::scope(|scope| {
            for _ in 0..threads {
                scope.spawn(|| {
                    loop {
                        let trial = next.fetch_add(1, Ordering::SeqCst);
                        if trial >= trials {
                            break;
                        }
                        let mut rng = Xorshift32::new(0xABCD_0000 + trial as u32 * 7919);
                        let payload: Vec<u8> = (0..payload_len).map(|_| rng.next_byte()).collect();
                        let spec = StreamTrial {
                            display_fps: fps,
                            ..StreamTrial::typical(camera, trial as u64 + 1)
                        };
                        let outcome = run_stream_trial(&payload, 1, &spec);
                        outcomes.lock().unwrap().push(outcome);
                    }
                });
            }
        });
        let outcomes = outcomes.into_inner().unwrap();
        let mut times: Vec<f64> = outcomes
            .iter()
            .filter(|o| o.payload_matches)
            .filter_map(|o| o.completed_at_s)
            .collect();
        times.sort_by(f64::total_cmp);
        let n = outcomes.len() as f64;
        let wrong = outcomes
            .iter()
            .filter(|o| o.completed_at_s.is_some() && !o.payload_matches)
            .count();
        let pick = |q: f64| {
            times
                .get(((times.len() as f64 - 1.0) * q) as usize)
                .copied()
                .unwrap_or(f64::NAN)
        };
        let frames: u32 = outcomes.iter().map(|o| o.frames).sum();
        let k_frames: u32 = outcomes.iter().map(|o| o.lanes[1]).sum();
        println!(
            "{:<10} {:>6.0} {:>8.1} {:>8.1} {:>8.1} {:>7} {:>9.1} {:>6.0}%",
            name,
            100.0 * times.len() as f64 / n,
            times.iter().sum::<f64>() / times.len().max(1) as f64,
            pick(0.5),
            pick(0.9),
            wrong,
            outcomes.iter().map(|o| o.mean_decode_ms).sum::<f64>() / n,
            100.0 * f64::from(k_frames) / f64::from(frames.max(1))
        );
    }
}
