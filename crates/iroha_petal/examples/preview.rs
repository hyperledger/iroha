//! Renders a sample Petal frame to PNG for visual inspection.
use iroha_petal::png;
use iroha_petal::render::{RenderOptions, render};
use iroha_petal::stream::StreamEncoder;

fn main() {
    let out = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "petal_preview.png".into());
    let payload: Vec<u8> = (0..400u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let encoder = StreamEncoder::new(&payload, 1).expect("payload");
    let cells = encoder.cells(3);
    let image = render(&cells, &RenderOptions::default());
    std::fs::write(&out, png::encode(image.width, image.height, 3, &image.data))
        .expect("write png");
    println!("wrote {out}");
}
