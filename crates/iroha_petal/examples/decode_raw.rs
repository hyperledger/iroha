//! Decodes a directory of raw 8-bit luma frames (`meta.txt` = `width height count`).
//!
//! `cargo run --release -p iroha_petal --example decode_raw -- <dir> [camera: none|modern|legacy|worst] [expected payload file]`
//!
//! With a camera name each frame is first "filmed" by the camera simulator, so a
//! screen-recorded (H.264) stream can be tested as if a phone were pointed at it.
use iroha_petal::image::{Luma, Rgb};
use iroha_petal::session::{ScanLimits, ScanSession};
use iroha_petal::sim::{CaptureConfig, capture, fit_to_frame};

/// Elapsed video time at the example's fixed 24 frames per second.
fn frame_time(frame: usize) -> std::time::Duration {
    const FPS: u64 = 24;
    let frame = u64::try_from(frame).expect("frame number fits u64");
    let seconds = frame / FPS;
    let nanos = (frame % FPS) * 1_000_000_000 / FPS;
    std::time::Duration::new(
        seconds,
        u32::try_from(nanos).expect("fractional frame is less than one second"),
    )
}

/// One-based deterministic camera seed, refusing an unrepresentable frame.
fn frame_seed(frame: usize) -> Option<u64> {
    u64::try_from(frame).ok()?.checked_add(1)
}

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
                c.seed = frame_seed(index).expect("frame seed fits u64");
                capture(&rgb, &c)
            }
            None => luma,
        };
        let timestamp_ms = u64::try_from(frame_time(index).as_millis())
            .expect("frame timestamp fits u64 milliseconds");
        let outcome = session.push(&luma, timestamp_ms);
        if let Some(done) = outcome.completed {
            let ok = expected.as_ref().is_none_or(|e| *e == done.payload);
            println!(
                "COMPLETE after {} video frames ({:.2} s of video): {} bytes, kind {}, payload {}",
                index + 1,
                frame_time(index + 1).as_secs_f64(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_time_uses_exact_24_fps_boundaries() {
        for (frame, milliseconds) in [
            (0, 0),
            (1, 41),
            (2, 83),
            (3, 125),
            (23, 958),
            (24, 1_000),
            (25, 1_041),
            (48, 2_000),
        ] {
            assert_eq!(frame_time(frame).as_millis(), milliseconds);
        }
        assert_eq!(frame_time(24), std::time::Duration::from_secs(1));
        assert_eq!(frame_time(1).subsec_nanos(), 41_666_666);
        assert!(frame_time(25) > frame_time(24));
    }

    #[test]
    fn camera_seed_is_one_based_and_checked() {
        assert_eq!(frame_seed(0), Some(1));
        assert_eq!(frame_seed(23), Some(24));
        #[cfg(target_pointer_width = "64")]
        {
            assert_eq!(frame_seed(usize::MAX - 1), Some(u64::MAX));
            assert_eq!(frame_seed(usize::MAX), None);
        }
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn frame_time_keeps_large_integer_precision_and_refuses_timestamp_overflow() {
        let frame = (1_usize << 53) + 1;
        let expected = (frame as u128) * 1_000 / 24;
        assert_eq!(frame_time(frame).as_millis(), expected);
        assert_eq!(
            u64::try_from(frame_time(frame).as_millis()).unwrap(),
            u64::try_from(expected).unwrap(),
        );
        assert!(u64::try_from(frame_time(usize::MAX).as_millis()).is_err());
    }
}
