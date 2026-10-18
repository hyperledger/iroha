//! The packed reader and independent native-row constructor admit identical keys.

use super::*;
use iroha_pasta::CancellationToken;

fn packed_reader_parity<C: PastaCurve>() {
    let params = PinnedParams::<C>::derive(6).unwrap();
    for compressed in [false, true] {
        let mut config = KeygenConfigV2::pipa_r(vec![crate::cs::InstanceType::Field]);
        config.compress_selectors = compressed;
        let (binding, original) = keygen_vk_with_binding_v2(&params, &CIRCUIT, &config).unwrap();
        let bytes = original.to_bytes();
        let read = VerifyingKey::<C>::read(bytes, &binding).unwrap();
        assert_eq!(read, original);
        assert_eq!(read.to_bytes(), bytes);
        for short in [&bytes[..0], &bytes[..bytes.len() - 1]] {
            assert!(matches!(
                VerifyingKey::<C>::read(short, &binding),
                Err(VkError::Length { .. })
            ));
        }
        let mut extra = bytes.to_vec();
        extra.push(0);
        assert!(matches!(
            VerifyingKey::<C>::read(&extra, &binding),
            Err(VkError::Length { .. })
        ));
        let token = CancellationToken::new();
        token.cancel();
        assert_eq!(
            VerifyingKey::<C>::read_cancellable(bytes, &binding, Some(&token)),
            Err(VkError::Cancelled)
        );
        if !compressed {
            continue;
        }
        let native: Vec<Vec<bool>> = original
            .selectors()
            .iter()
            .map(|row| row.iter().collect())
            .collect();
        let offset = vk::VK_HEADER_BYTES
            + 32 * (original.fixed_commitments().len() + original.permutation_commitments().len());
        let width = binding.n().div_ceil(8);
        let descriptor = binding.descriptor();
        assert_eq!(
            descriptor.check_packed_selector_plan_cancellable(&bytes[offset..], None),
            Ok(())
        );
        for extent in [&bytes[offset..bytes.len() - 1], &[]] {
            assert!(
                descriptor
                    .check_packed_selector_plan_cancellable(extent, None)
                    .is_err()
            );
        }
        assert!(
            descriptor
                .check_packed_selector_plan_cancellable(&bytes[offset..], Some(&token))
                .unwrap_err()
                .is_cancelled()
        );
        let mut accepted = 0;
        let mut refused = 0;
        for selector in 0..native.len() {
            for row in [0, 1, 7, 8, 31, 32, 63] {
                let mut changed_native = native.clone();
                changed_native[selector][row] ^= true;
                let mut changed = bytes.to_vec();
                changed[offset + selector * width + row / 8] ^= 1 << (row % 8);
                let expected = VerifyingKey::<C>::from_parts(
                    &binding,
                    original.fixed_commitments().to_vec(),
                    original.permutation_commitments().to_vec(),
                    changed_native.clone(),
                );
                let actual = VerifyingKey::<C>::read(&changed, &binding);
                assert_eq!(actual, expected, "selector={selector}, row={row}");
                assert_eq!(
                    descriptor.check_packed_selector_plan_cancellable(&changed[offset..], None),
                    descriptor.check_selector_plan(&changed_native)
                );
                match actual {
                    Ok(key) => {
                        accepted += 1;
                        assert_eq!(key.to_bytes(), changed);
                        assert_ne!(key.transcript_repr(), original.transcript_repr());
                    }
                    Err(VkError::SelectorPlan) => refused += 1,
                    other => panic!("unexpected reader result: {other:?}"),
                }
            }
        }
        assert!(accepted > 0 && refused > 0);
        // A declaration that changes member/root order is rejected equally by both paths.
        let mut changed_descriptor = descriptor.clone();
        changed_descriptor.selectors.entries[0].root += 1;
        assert_eq!(
            changed_descriptor.check_packed_selector_plan_cancellable(&bytes[offset..], None),
            changed_descriptor.check_selector_plan(&native)
        );
        assert!(changed_descriptor.check_selector_plan(&native).is_err());
    }
}

#[test]
fn packed_vk_reader_matches_native_constructor_and_rejects_mutations_on_both_curves() {
    packed_reader_parity::<Ep>();
    packed_reader_parity::<Eq>();
}
