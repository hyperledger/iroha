//! Witness-only square roots. Every claimed root is separately constrained.
use super::super::{
    extension::Fp2,
    native::{self, Fp},
};

pub(super) fn mul(a: &Fp2, b: &Fp2) -> Fp2 {
    [
        native::sub(&native::mul(&a[0], &b[0]), &native::mul(&a[1], &b[1])),
        native::add(&native::mul(&a[0], &b[1]), &native::mul(&a[1], &b[0])),
    ]
}
fn sqrt_fp(a: &Fp) -> Option<Fp> {
    const EXPONENT: Fp = [
        0xee7f_bfff_ffff_eaab,
        0x07aa_ffff_ac54_ffff,
        0xd9cc_34a8_3dac_3d89,
        0xd91d_d2e1_3ce1_44af,
        0x92c6_e9ed_90d2_eb35,
        0x0680_447a_8e5f_f9a6,
    ];
    let mut x = native::ONE;
    for limb in EXPONENT.iter().rev() {
        for bit in (0..64).rev() {
            x = native::square(&x);
            if (limb >> bit) & 1 == 1 {
                x = native::mul(&x, a);
            }
        }
    }
    (native::square(&x) == *a).then_some(x)
}
/// A root of a quadratic-extension element, if it has one.
pub(super) fn sqrt(a: &Fp2) -> Option<Fp2> {
    const HALF: Fp = [
        0xdcff_7fff_ffff_d556,
        0x0f55_ffff_58a9_ffff,
        0xb398_6950_7b58_7b12,
        0xb23b_a5c2_79c2_895f,
        0x258d_d3db_21a5_d66b,
        0x0d00_88f5_1cbf_f34d,
    ];

    if a[1] == native::ZERO {
        if let Some(root) = sqrt_fp(&a[0]) {
            return Some([root, native::ZERO]);
        }
        return sqrt_fp(&native::neg(&a[0])).map(|root| [native::ZERO, root]);
    }
    let norm = native::add(&native::square(&a[0]), &native::square(&a[1]));
    let alpha = sqrt_fp(&norm)?;
    let first = native::mul(&native::add(&a[0], &alpha), &HALF);
    let x = if let Some(root) = sqrt_fp(&first) {
        root
    } else {
        sqrt_fp(&native::mul(&native::sub(&a[0], &alpha), &HALF))?
    };
    let y = native::mul(&a[1], &native::invert(&native::add(&x, &x)));
    let root = [x, y];
    (mul(&root, &root) == *a).then_some(root)
}
