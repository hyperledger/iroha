//! Packed activation views, exact native comparisons and strict padding checks.

use super::*;

#[test]
fn packed_views_preserve_row_order_bounds_and_borrow_original_bytes() {
    for rows in [2_usize, 4, 8, 64, 2048] {
        let width = rows.div_ceil(8);
        let native: Vec<Vec<bool>> = (0..3)
            .map(|selector| (0..rows).map(|row| row % 3 == selector).collect())
            .collect();
        let bytes: Vec<u8> = native
            .iter()
            .flat_map(|rows| rows.chunks(8))
            .map(|chunk| {
                chunk
                    .iter()
                    .enumerate()
                    .fold(0, |byte, (bit, enabled)| byte | (u8::from(*enabled) << bit))
            })
            .collect();
        assert_eq!(validate_cancellable(&bytes, rows, None), Ok(()));
        let view = SelectorBitmaps::new(&bytes, rows);
        assert_eq!(view.len(), 3);
        assert!(!view.is_empty());
        assert_eq!(view.iter().len(), 3);
        assert!(view.get(3).is_none());
        assert!(view.get(usize::MAX).is_none());
        for (index, bitmap) in view.iter().enumerate() {
            assert_eq!(view.get(index), Some(bitmap));
            assert_eq!(bitmap.len(), rows);
            assert!(!bitmap.is_empty());
            assert_eq!(bitmap.iter().len(), rows);
            assert_eq!(bitmap.iter().collect::<Vec<_>>(), native[index]);
            assert_eq!(
                bitmap.iter().rev().collect::<Vec<_>>(),
                native[index].iter().copied().rev().collect::<Vec<_>>()
            );
            assert_eq!(
                bitmap.packed_bytes().as_ptr(),
                bytes[index * width..].as_ptr()
            );
            for (row, expected) in native[index].iter().enumerate() {
                assert_eq!(bitmap.get(row), Some(*expected));
            }
            assert_eq!(bitmap.get(rows), None);
            assert_eq!(bitmap.get(usize::MAX), None);
        }
        assert_eq!(view.iter().next_back(), view.get(2));
        assert_eq!(view.matches_rows_cancellable(&native, None), Ok(true));
        assert_eq!(decode_cancellable(&bytes, rows, None).unwrap(), native);
        for selector in 0..3 {
            for row in [0, rows - 1] {
                let mut changed = native.clone();
                changed[selector][row] ^= true;
                assert_eq!(view.matches_rows_cancellable(&changed, None), Ok(false));
            }
        }
        assert_eq!(view.matches_rows_cancellable(&native[..2], None), Ok(false));
        let mut short = native.clone();
        short[1].pop();
        assert_eq!(view.matches_rows_cancellable(&short, None), Ok(false));
        let mut long = native.clone();
        long[2].push(false);
        assert_eq!(view.matches_rows_cancellable(&long, None), Ok(false));
    }
    let empty = SelectorBitmaps::new(&[], 64);
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);
    assert_eq!(empty.iter().count(), 0);
    assert_eq!(empty.get(0), None);
    assert_eq!(empty.matches_rows_cancellable(&[], None), Ok(true));
}

#[test]
fn padding_is_rejected_before_an_activation_view_can_escape() {
    for rows in [2, 4] {
        for selector in 0..3 {
            for padding in rows..8 {
                let mut bytes = vec![1_u8; 3];
                bytes[selector] |= 1 << padding;
                assert_eq!(
                    validate_cancellable(&bytes, rows, None).unwrap_err(),
                    super::super::VkError::BitmapPadding { selector }
                );
            }
        }
    }
}

#[test]
fn packed_comparison_and_plan_decode_preserve_cancellation_and_retry() {
    let bytes = vec![0x55_u8; 256];
    let view = SelectorBitmaps::new(&bytes, 2048);
    let native = vec![view.get(0).unwrap().iter().collect()];
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert!(
        view.matches_rows_cancellable(&native, Some(&cancelled))
            .is_err()
    );
    assert!(
        view.matches_rows_cancellable(&[], Some(&cancelled))
            .is_err()
    );
    assert_eq!(
        validate_cancellable(&bytes, 2048, Some(&cancelled)).unwrap_err(),
        super::super::VkError::Cancelled
    );
    let fresh = CancellationToken::new();
    assert_eq!(
        view.matches_rows_cancellable(&native, Some(&fresh)),
        Ok(true)
    );
    assert_eq!(
        decode_cancellable(&bytes, 2048, Some(&fresh)).unwrap(),
        native
    );
}

#[test]
fn packed_validation_rejects_incomplete_extent_and_zero_rows() {
    assert_eq!(
        validate_cancellable(&[0], 64, None),
        Err(super::super::VkError::Shape)
    );
    assert_eq!(
        validate_cancellable(&[], 0, None),
        Err(super::super::VkError::Shape)
    );
    assert_eq!(validate_cancellable(&[], 64, None), Ok(()));
}
