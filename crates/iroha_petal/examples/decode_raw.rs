//! Decodes a directory of raw 8-bit luma frames (`meta.txt` = `width height count`).
//!
//! `cargo run --release -p iroha_petal --example decode_raw -- <dir> [camera: none|modern|legacy|worst] [expected payload file]`
//!
//! With a camera name each frame is first "filmed" by the camera simulator, so a
//! screen-recorded (H.264) stream can be tested as if a phone were pointed at it.
use iroha_petal::image::{Luma, Rgb};
use iroha_petal::session::{ScanLimits, ScanSession};
use iroha_petal::sim::{CaptureConfig, capture, fit_to_frame};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let dir = args.first().expect("directory");
    let camera = args.get(1).map_or("none", String::as_str);
    let meta = std::fs::read_to_string(format!("{dir}/meta.txt")).expect("meta.txt");
    let nums: Vec<usize> = meta
        .split_whitespace()
        .map(|v| v.parse().expect("number"))
        .collect();
    let (width, height, count) = (nums[0], nums[1], nums[2]);
    let expected = args
        .get(2)
        .map(|p| std::fs::read(p).expect("expected payload"));
    let config = match camera {
        "modern" => Some(CaptureConfig::modern()),
        "legacy" => Some(CaptureConfig::legacy()),
        "worst" => Some(CaptureConfig::worst()),
        _ => None,
    };
    let config = config.map(|c| fit_to_frame(&c, 4.0));
    let mut session = ScanSession::new(ScanLimits::default());
    let fps = 24.0;
    let started = std::time::Instant::now();
    for index in 0..count {
        let raw = std::fs::read(format!("{dir}/frame_{index:04}.y8")).expect("frame");
        let luma = Luma::from_raw(width, height, raw).expect("frame size");
        let luma = match &config {
            Some(config) => {
                let rgb = Rgb {
                    width,
                    height,
                    data: luma.data.iter().flat_map(|&v| [v, v, v]).collect(),
                };
                let mut c = *config;
                c.seed = index as u64 + 1;
                capture(&rgb, &c)
            }
            None => luma,
        };
        let outcome = session.push(&luma, (index as f64 / fps * 1000.0) as u64);
        if let Some(done) = outcome.completed {
            let ok = expected.as_ref().is_none_or(|e| *e == done.payload);
            println!(
                "COMPLETE after {} video frames ({:.2} s of video): {} bytes, kind {}, payload {}",
                index + 1,
                (index + 1) as f64 / fps,
                done.payload.len(),
                done.meta.kind,
                if ok { "matches expected" } else { "DIFFERS" }
            );
            println!(
                "stats {:?}, decode wall time {:.1} s",
                session.stats(),
                started.elapsed().as_secs_f64()
            );
            return;
        }
    }
    println!(
        "NOT complete after {count} frames; progress {:?}; stats {:?}",
        session.progress(),
        session.stats()
    );
}
