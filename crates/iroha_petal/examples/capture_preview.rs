//! Renders a frame and writes simulated camera captures for visual inspection.
use iroha_petal::png;
use iroha_petal::render::{RenderOptions, render};
use iroha_petal::sim::{CaptureConfig, capture};
use iroha_petal::stream::StreamEncoder;

/// The original modular payload pattern, selecting its low byte explicitly.
fn payload() -> Vec<u8> {
    (0..400_u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13).to_le_bytes()[0])
        .collect()
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| ".".into());
    let payload = payload();
    let encoder = StreamEncoder::new(&payload, 1).expect("payload");
    let frame = render(&encoder.cells(3), &RenderOptions::default());
    for (name, config) in [
        ("modern", CaptureConfig::modern()),
        ("legacy", CaptureConfig::legacy()),
        ("worst", CaptureConfig::worst()),
    ] {
        let luma = capture(&frame, &config);
        let path = format!("{dir}/capture_{name}.png");
        std::fs::write(&path, png::encode(luma.width, luma.height, 1, &luma.data)).expect("write");
        println!("wrote {path} ({}x{})", luma.width, luma.height);
    }
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
