//! Renders consecutive frames of a stream as PNG files.
//!
//! `cargo run --release -p iroha_petal --example render_stream -- <payload bytes> <frames> <size> <out dir> [first frame] [payload file]`
use iroha_petal::png;
use iroha_petal::prng::Xorshift32;
use iroha_petal::render::{RenderOptions, render};
use iroha_petal::stream::StreamEncoder;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let len: usize = args.first().and_then(|a| a.parse().ok()).unwrap_or(2048);
    let frames: u16 = args.get(1).and_then(|a| a.parse().ok()).unwrap_or(48);
    let size: usize = args.get(2).and_then(|a| a.parse().ok()).unwrap_or(1024);
    let out = args.get(3).cloned().unwrap_or_else(|| ".".into());
    let first: u16 = args.get(4).and_then(|a| a.parse().ok()).unwrap_or(0);
    let payload: Vec<u8> = args.get(5).map_or_else(
        || {
            let mut rng = Xorshift32::new(0x1234_5678);
            (0..len).map(|_| rng.next_byte()).collect()
        },
        |path| std::fs::read(path).expect("payload file"),
    );
    std::fs::create_dir_all(&out).expect("output dir");
    std::fs::write(format!("{out}/payload.bin"), &payload).expect("payload");
    let encoder = StreamEncoder::new(&payload, 2).expect("stream");
    println!(
        "payload {} B, {} source atoms, {} systematic frames",
        payload.len(),
        encoder.meta().source_atoms(),
        encoder.systematic_frames()
    );
    for index in 0..frames {
        let frame = first.wrapping_add(index);
        let image = render(
            &encoder.cells(frame),
            &RenderOptions {
                size,
                supersample: 3,
                ..RenderOptions::default()
            },
        );
        std::fs::write(
            format!("{out}/frame_{index:04}.png"),
            png::encode(image.width, image.height, 3, &image.data),
        )
        .expect("png");
    }
    println!("wrote {frames} frames to {out}");
}
