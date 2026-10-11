//! Cross-implementation encoding KATs: `iroha_pasta`, `pasta_curves` 0.5.2
//! and the `halo2curves` 0.9 Pasta implementation.
//!
//! Scalars and points must encode identically in all three, and every
//! 32-byte string must be accepted or rejected identically, so that keys and
//! commitments produced by one implementation are read the same way by the
//! others. Any divergence is listed explicitly below.
//!
//! Known divergence (pinned so that any change is noticed): `halo2curves` 0.9
//! accepts `x = 0` with the sign bit set (`00..00 80`) as a second encoding of
//! the identity, which `pasta_curves` and `iroha_pasta` reject. Callers that
//! decode with `halo2curves` and must agree with the canonical encoding have to
//! reject that string (or the identity) themselves.

use ff::{Field, PrimeField};
use group::{Curve, Group, GroupEncoding};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{RngCore, SeedableRng};

/// Converts 32 bytes into the scalar representation of `F`.
fn repr_of<F: PrimeField>(bytes: [u8; 32]) -> F::Repr {
    let mut repr = F::Repr::default();
    repr.as_mut().copy_from_slice(&bytes);
    repr
}

/// Decodes `bytes` with all three implementations and returns the
/// re-encodings (or `None` on rejection).
macro_rules! decode3 {
    ($bytes:expr, $mine:ty, $pasta:ty, $h2c:ty) => {{
        let b: [u8; 32] = $bytes;
        let mine = Option::<$mine>::from(<$mine>::from_bytes(&b)).map(|p| p.to_bytes());
        let pasta = Option::<$pasta>::from(<$pasta>::from_bytes(&b)).map(|p| p.to_bytes());
        let mut repr = <$h2c as GroupEncoding>::Repr::default();
        repr.as_mut().copy_from_slice(&b);
        let h2c = Option::<$h2c>::from(<$h2c>::from_bytes(&repr)).map(|p| {
            let mut out = [0u8; 32];
            out.copy_from_slice(p.to_bytes().as_ref());
            out
        });
        (mine, pasta, h2c)
    }};
}

macro_rules! suite {
    ($mine:ty, $mine_proj:ty, $pasta:ty, $h2c:ty, $h2c_proj:ty, $mscalar:ty, $hscalar:ty, $seed:expr) => {{
        let mut rng = ChaCha20Rng::seed_from_u64($seed);
        // Scalars: canonical encodings agree and non-canonical ones are rejected.
        for _ in 0..2000 {
            let s = <$mscalar>::random(&mut rng);
            let h = <$hscalar>::from_repr(repr_of::<$hscalar>(s.to_repr())).unwrap();
            assert_eq!(h.to_repr().as_ref(), &s.to_repr()[..]);
        }
        let mut high = [0xFFu8; 32];
        high[31] = 0x7F;
        assert!(bool::from(<$mscalar>::from_repr(high).is_none()));
        assert!(bool::from(
            <$hscalar>::from_repr(repr_of::<$hscalar>(high)).is_none()
        ));

        // Points: generator, random points and their encodings agree.
        let g = <$mine_proj>::generator().to_affine();
        let hg = <$h2c_proj>::generator().to_affine();
        assert_eq!(g.to_bytes().as_ref(), hg.to_bytes().as_ref());
        for _ in 0..500 {
            let k = <$mscalar>::random(&mut rng);
            let p = (<$mine_proj>::generator() * k).to_affine();
            let hk = <$hscalar>::from_repr(repr_of::<$hscalar>(k.to_repr())).unwrap();
            let hp = (<$h2c_proj>::generator() * hk).to_affine();
            assert_eq!(p.to_bytes().as_ref(), hp.to_bytes().as_ref());
            let (mine, pasta, h2c) = decode3!(p.to_bytes(), $mine, $pasta, $h2c);
            assert_eq!(mine, Some(p.to_bytes()));
            assert_eq!(pasta, mine);
            assert_eq!(h2c, mine);
        }

        // Arbitrary byte strings, including the identity and sign-bit edges.
        let mut cases: Vec<[u8; 32]> = Vec::new();
        cases.push([0u8; 32]);
        let mut x0_sign = [0u8; 32];
        x0_sign[31] = 0x80;
        cases.push(x0_sign);
        cases.push([0xFF; 32]);
        for _ in 0..5000 {
            let mut b = [0u8; 32];
            rng.fill_bytes(&mut b);
            b[31] &= 0xBF; // keep x below 2^254 half the time
            cases.push(b);
        }
        let mut divergent = Vec::new();
        for b in cases {
            let (mine, pasta, h2c) = decode3!(b, $mine, $pasta, $h2c);
            assert_eq!(
                mine, pasta,
                "iroha_pasta and pasta_curves disagree on {b:?}"
            );
            if mine != h2c {
                divergent.push((b, mine.is_some(), h2c.is_some()));
            }
        }
        divergent
    }};
}

/// The one string on which `halo2curves` 0.9 diverges: it decodes to the
/// identity there and is rejected by the canonical implementations.
fn expected_divergence() -> Vec<([u8; 32], bool, bool)> {
    let mut b = [0u8; 32];
    b[31] = 0x80;
    vec![(b, false, true)]
}

#[test]
fn pallas_encodings_agree_across_implementations() {
    let divergent = suite!(
        iroha_pasta::EpAffine,
        iroha_pasta::Ep,
        pasta_curves::EpAffine,
        halo2curves::pasta::PallasAffine,
        halo2curves::pasta::Pallas,
        iroha_pasta::Fq,
        halo2curves::pasta::Fq,
        1
    );
    assert_eq!(divergent, expected_divergence());
    let (_, _, h2c) = decode3!(
        expected_divergence()[0].0,
        iroha_pasta::EpAffine,
        pasta_curves::EpAffine,
        halo2curves::pasta::PallasAffine
    );
    assert_eq!(h2c, Some([0u8; 32]), "halo2curves maps it to the identity");
}

#[test]
fn vesta_encodings_agree_across_implementations() {
    let divergent = suite!(
        iroha_pasta::EqAffine,
        iroha_pasta::Eq,
        pasta_curves::EqAffine,
        halo2curves::pasta::VestaAffine,
        halo2curves::pasta::Vesta,
        iroha_pasta::Fp,
        halo2curves::pasta::Fp,
        2
    );
    assert_eq!(divergent, expected_divergence());
    let (_, _, h2c) = decode3!(
        expected_divergence()[0].0,
        iroha_pasta::EqAffine,
        pasta_curves::EqAffine,
        halo2curves::pasta::VestaAffine
    );
    assert_eq!(h2c, Some([0u8; 32]), "halo2curves maps it to the identity");
}
