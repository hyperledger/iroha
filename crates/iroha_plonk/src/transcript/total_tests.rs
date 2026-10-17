//! Pointwise challenge and scoped full-group generator codec controls.
use super::*;
use ff::{Field, PrimeField};
use iroha_pasta::{Ep, Eq, Fp, Fq, PastaField};

fn divide_power_two(mut limbs: [u64; 4], bits: usize) -> [u64; 4] {
    for _ in 0..bits {
        for index in 0..3 {
            limbs[index] = (limbs[index] >> 1) | (limbs[index + 1] << 63);
        }
        limbs[3] >>= 1;
    }
    limbs
}
fn total_maps<F: PastaField>() {
    let order_minus_one = (-F::ONE).to_canonical_limbs();
    let half = divide_power_two(order_minus_one, 1);
    let quarter = divide_power_two(order_minus_one, 2);
    assert_eq!(F::S, 32);
    assert_eq!(F::from(5).pow_vartime(half), -F::ONE);
    assert_eq!(F::from(25).pow_vartime(quarter), -F::ONE);
    let values = [
        F::ZERO,
        F::ONE,
        -F::ONE,
        F::from(5),
        -F::from(5),
        F::from(u64::MAX),
    ];
    for raw in values.into_iter().chain(
        (1..=crate::cs::constraint_system::MAX_K)
            .map(|k| F::ROOT_OF_UNITY.pow_vartime([1_u64 << (F::S - k)])),
    ) {
        let x = pipa_r::evaluation_challenge(raw);
        let x3 = pipa_r::multiopening_challenge(raw);
        let nonzero = if raw == F::ZERO { F::ONE } else { raw };
        assert_eq!(x, F::from(5) * nonzero.square());
        assert_eq!(x3, F::from(25) * nonzero.square().square());
        assert_eq!(x.pow_vartime(half), -F::ONE);
        assert_eq!(x3.pow_vartime(half), F::ONE);
        assert_eq!(x3.pow_vartime(quarter), -F::ONE);
        assert_ne!(x, F::ZERO);
        assert_ne!(x3, F::ZERO);
        assert_ne!(pipa_r::nonzero_challenge(raw), F::ZERO);
        for k in 1..=crate::cs::constraint_system::MAX_K {
            let n = 1_u64 << k;
            assert_ne!(x.pow_vartime([n]), F::ONE);
            assert_ne!(x3.pow_vartime([n]), F::ONE);
            let root = F::ROOT_OF_UNITY.pow_vartime([1_u64 << (F::S - k)]);
            assert_eq!(root.pow_vartime(quarter), F::ONE);
            for rotation in [F::ONE, root, root.square(), root.invert().unwrap()] {
                assert_ne!(x * rotation, x3);
            }
        }
    }
    assert_eq!(pipa_r::nonzero_challenge(F::ZERO), F::ONE);
    assert_eq!(pipa_r::nonzero_challenge(F::ONE), F::ONE);
    assert_eq!(pipa_r::nonzero_challenge(-F::ONE), -F::ONE);
}
#[test]
fn all_supported_domains_and_rotations_have_total_challenges_both_fields() {
    total_maps::<Fp>();
    total_maps::<Fq>();
}
#[test]
fn field_conversion_precedes_each_named_scalar_map() {
    let fp_modulus = (-Fp::ONE).to_canonical_limbs();
    let mut words = fp_modulus;
    words[0] += 1;
    let fq_word = Fq::from_canonical_limbs(words).unwrap();
    let reduced = pipa_r::challenge_from_base::<Eq>(&fq_word);
    assert_eq!(reduced, Fp::ZERO);
    assert_eq!(pipa_r::evaluation_challenge(reduced), Fp::from(5));
    assert_eq!(pipa_r::multiopening_challenge(reduced), Fp::from(25));
    assert_eq!(pipa_r::nonzero_challenge(reduced), Fp::ONE);
    let fp_word = -Fp::ONE;
    assert_eq!(
        pipa_r::challenge_from_base::<Ep>(&fp_word).to_repr(),
        fp_word.to_repr()
    );
}
fn generator_codec<C: PastaCurve>()
where
    C::Base: PoseidonField,
{
    let identity = C::AffineExt::identity();
    assert_eq!(decode_generator::<C>(&[0; 32]), Ok(identity));
    assert_eq!(
        decode_point::<C>(&[0; 32]),
        Err(TranscriptError::IdentityPoint)
    );
    assert_eq!(
        generator_coordinates::<C>(&identity),
        (C::Base::ZERO, C::Base::ZERO)
    );
    assert_eq!(
        generator_from_coordinates::<C>(C::Base::ZERO, C::Base::ZERO),
        Ok(identity)
    );
    assert!(generator_from_coordinates::<C>(C::Base::ZERO, C::Base::ONE).is_err());
    assert!(decode_generator::<C>(&[255; 32]).is_err());
    let finite = C::generator().to_affine();
    let (x, y) = generator_coordinates::<C>(&finite);
    assert_eq!(generator_from_coordinates::<C>(x, y), Ok(finite));
    assert_eq!(
        decode_generator::<C>(&encode_point::<C>(&finite)),
        Ok(finite)
    );
    let mut writer = TranscriptWriter::<C, _>::new(BasePoseidonHash::with_domain(*b"pipa-as1"));
    assert_eq!(
        writer.write_point(&identity),
        Err(TranscriptError::IdentityPoint)
    );
    let before = writer.squeeze_challenge();
    writer.append_unabsorbed_generator(&identity).unwrap();
    let after = writer.squeeze_challenge();
    let bytes = writer.finish();
    assert_eq!(bytes, [0; 32]);
    let mut reader =
        TranscriptReader::<C, _>::new(BasePoseidonHash::with_domain(*b"pipa-as1"), &bytes);
    assert_eq!(reader.squeeze_challenge(), before);
    assert_eq!(reader.read_unabsorbed_generator(), Ok(identity));
    assert_eq!(reader.squeeze_challenge(), after);
    reader.finish().unwrap();
    let mut reader =
        TranscriptReader::<C, _>::new(BasePoseidonHash::with_domain(*b"pipa-as1"), &bytes);
    assert_eq!(reader.read_point(), Err(TranscriptError::IdentityPoint));
}
#[test]
fn full_group_generator_encoding_is_scoped_and_unabsorbed_both_curves() {
    generator_codec::<Ep>();
    generator_codec::<Eq>();
}
