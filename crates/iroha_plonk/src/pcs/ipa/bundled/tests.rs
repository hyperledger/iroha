//! Embedded parameter identity, strict refusal and transparent-domain parity.

use super::*;
use crate::pcs::ipa::commit::{Secrecy, commit, commit_lagrange};
use iroha_pasta::{Ep, Eq, msm::MemoryBudget};

fn parity<C: PastaCurve>(k: u32) {
    let derived = PinnedParams::<C>::derive(k).unwrap();
    let selected = PinnedParams::<C>::for_domain(k).unwrap();
    let original = bytes(selected.curve(), k).unwrap();
    assert_eq!(selected.k(), k);
    assert!(
        selected == derived,
        "every generator and domain must be identical"
    );
    assert!(selected.params().to_bytes() == original);
    assert!(derived.params().to_bytes() == original);
    assert_eq!(
        Some(selected.digest()),
        crate::cs::descriptor::pinned_params_digest(selected.curve(), k)
    );
    let values: Vec<_> = (0..17_u64).map(C::ScalarExt::from).collect();
    let blind = C::ScalarExt::from(7);
    for commitment in [commit::<C>, commit_lagrange::<C>] {
        assert_eq!(
            commitment(
                selected.params(),
                &values,
                &blind,
                Secrecy::Public,
                MemoryBudget::DEFAULT
            )
            .unwrap(),
            commitment(
                derived.params(),
                &values,
                &blind,
                Secrecy::Public,
                MemoryBudget::DEFAULT
            )
            .unwrap(),
        );
    }
}

#[test]
fn all_embedded_domains_equal_independent_transparent_derivation() {
    for k in [12, 14, 16] {
        parity::<Eq>(k);
    }
    parity::<Ep>(16);
}

#[test]
fn selected_parameter_corruption_truncation_and_curve_miswire_fail_closed() {
    let original = bytes(CurveV1::Vesta, 12).unwrap();
    let mut changed = original.to_vec();
    changed[4] ^= 1;
    for damaged in [changed.as_slice(), &original[..original.len() - 1]] {
        assert!(matches!(
            decode_selected::<Eq>(12, damaged),
            Err(ParamsTrustError::DigestMismatch {
                curve: CurveV1::Vesta,
                k: 12
            })
        ));
    }
    assert_eq!(
        decode_selected::<Eq>(12, &[]),
        Err(ParamsTrustError::MissingHeader)
    );
    assert!(matches!(
        decode_selected::<Eq>(16, bytes(CurveV1::Pallas, 16).unwrap()),
        Err(ParamsTrustError::DigestMismatch {
            curve: CurveV1::Vesta,
            k: 16
        })
    ));
    assert!(matches!(
        decode_selected::<Ep>(16, bytes(CurveV1::Vesta, 16).unwrap()),
        Err(ParamsTrustError::DigestMismatch {
            curve: CurveV1::Pallas,
            k: 16
        })
    ));
}

#[test]
fn a_valid_representation_for_another_domain_is_rejected_before_decode() {
    assert_eq!(
        decode_selected::<Eq>(14, bytes(CurveV1::Vesta, 12).unwrap()),
        Err(ParamsTrustError::DomainMismatch {
            expected: 14,
            actual: 12
        })
    );
    assert!(
        ParamsTrustError::DomainMismatch {
            expected: 14,
            actual: 12
        }
        .to_string()
        .contains("requested k = 14")
    );
}

#[test]
fn unbundled_domains_keep_explicit_transparent_derivation_and_errors() {
    for curve in [CurveV1::Vesta, CurveV1::Pallas] {
        for k in [3, 6, 13, 15] {
            assert!(bytes(curve, k).is_none());
        }
    }
    for k in [3, 6, 13, 15] {
        assert_eq!(
            PinnedParams::<Eq>::for_domain(k),
            PinnedParams::<Eq>::derive(k)
        );
        assert_eq!(
            PinnedParams::<Ep>::for_domain(k),
            PinnedParams::<Ep>::derive(k)
        );
    }
    assert_eq!(
        PinnedParams::<Eq>::for_domain(u32::MAX),
        PinnedParams::<Eq>::derive(u32::MAX)
    );
    assert_eq!(
        PinnedParams::<Ep>::for_domain(u32::MAX),
        PinnedParams::<Ep>::derive(u32::MAX)
    );
}
