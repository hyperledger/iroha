//! Renders a sample Petal frame to PNG for visual inspection.
use iroha_petal::png;
use iroha_petal::render::{RenderOptions, render};
use iroha_petal::stream::StreamEncoder;

/// The original modular payload pattern, selecting its low byte explicitly.
fn payload() -> Vec<u8> {
    (0..400_u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13).to_le_bytes()[0])
        .collect()
}

fn main() {
    let out = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "petal_preview.png".into());
    let payload = payload();
    let encoder = StreamEncoder::new(&payload, 1).expect("payload");
    let cells = encoder.cells(3);
    let image = render(&cells, &RenderOptions::default());
    std::fs::write(&out, png::encode(image.width, image.height, 3, &image.data))
        .expect("write png");
    println!("wrote {out}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_keeps_the_original_low_byte_pattern() {
        let bytes = payload();
        assert_eq!(bytes.len(), 400);
        for (index, byte) in bytes.into_iter().enumerate() {
            let word = u32::try_from(index).unwrap().wrapping_mul(2_654_435_761);
            assert_eq!(byte, u8::try_from((word >> 13) & 0xFF).unwrap());
        }
    }
}
