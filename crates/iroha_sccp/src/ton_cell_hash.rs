//! Shared allocation-free TON representation writer for constructed and native cells.

use sha2::{Digest as _, Sha256};

/// Visit the exact descriptor/data/depth/hash order after the caller selected its native level.
pub fn write_representation(
    descriptors: [u8; 2],
    augmented_data: &[u8],
    children: &[(u16, [u8; 32])],
    mut write: impl FnMut(&[u8]),
) {
    write(&descriptors);
    write(augmented_data);
    for (depth, _) in children {
        write(&depth.to_be_bytes());
    }
    for (_, hash) in children {
        write(hash);
    }
}

/// Hash the same representation without allocating an intermediate byte vector.
pub fn representation_hash(
    descriptors: [u8; 2],
    augmented_data: &[u8],
    children: &[(u16, [u8; 32])],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    write_representation(descriptors, augmented_data, children, |bytes| {
        hash.update(bytes)
    });
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn representation_orders_all_depths_before_hashes_and_retains_native_descriptors() {
        let children = [(0x0123, [0x11; 32]), (0x0456, [0x22; 32])];
        let mut actual = Vec::new();
        write_representation([0x2a, 0x01], &[0xb0], &children, |bytes| {
            actual.extend_from_slice(bytes)
        });
        let mut expected = vec![0x2a, 0x01, 0xb0, 0x01, 0x23, 0x04, 0x56];
        expected.extend_from_slice(&[0x11; 32]);
        expected.extend_from_slice(&[0x22; 32]);
        assert_eq!(actual, expected);
        assert_eq!(
            representation_hash([0x2a, 0x01], &[0xb0], &children),
            <[u8; 32]>::from(Sha256::digest(&expected))
        );
        assert_eq!(
            representation_hash([0, 0], &[], &[]),
            <[u8; 32]>::from(Sha256::digest([0, 0]))
        );
    }
}
