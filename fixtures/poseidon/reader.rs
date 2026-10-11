//! Strict dependency-free reader for the independently captured RP56 test banks.

/// Decode one canonical 32-byte, lowercase little-endian hex field string.
pub fn field_bytes(text: &str) -> [u8; 32] {
    assert_eq!(text.len(), 64, "reference field width");
    assert!(
        text.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    std::array::from_fn(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
}

/// Decode exactly 64 round rows followed by a square MDS matrix.
pub fn parameters<const W: usize>(text: &str) -> ([[[u8; 32]; W]; 64], [[[u8; 32]; W]; W]) {
    assert!(text.ends_with('\n'), "reference has a final newline");
    assert!(
        !text.contains('\r'),
        "reference uses canonical LF separators"
    );
    let fields: Vec<_> = text.lines().map(field_bytes).collect();
    assert_eq!(fields.len(), 64 * W + W * W, "reference bank shape");
    (
        std::array::from_fn(|r| std::array::from_fn(|c| fields[r * W + c])),
        std::array::from_fn(|r| std::array::from_fn(|c| fields[64 * W + r * W + c])),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_preserves_high_bytes_and_bank_order() {
        let fields: Vec<_> = (0_u16..201)
            .map(|value| {
                let mut bytes = [0; 32];
                bytes[..2].copy_from_slice(&value.to_le_bytes());
                bytes[31] = 1;
                bytes
            })
            .collect();
        let text: String = fields
            .iter()
            .map(|bytes| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>() + "\n")
            .collect();
        let (rounds, mds) = parameters::<3>(&text);
        assert_eq!(rounds[0][0], fields[0]);
        assert_eq!(rounds[63][2], fields[191]);
        assert_eq!(mds[0][0], fields[192]);
        assert_eq!(mds[2][2], fields[200]);
        for invalid in ["00".to_owned(), "GG".repeat(32), "AA".repeat(32)] {
            assert!(std::panic::catch_unwind(|| field_bytes(&invalid)).is_err());
        }
        for invalid in [
            text.trim_end().to_owned(),
            text.replace('\n', "\r\n"),
            text.clone() + &"00".repeat(32) + "\n",
            text.lines().skip(1).collect::<Vec<_>>().join("\n") + "\n",
        ] {
            assert!(std::panic::catch_unwind(|| parameters::<3>(&invalid)).is_err());
        }
    }
}
