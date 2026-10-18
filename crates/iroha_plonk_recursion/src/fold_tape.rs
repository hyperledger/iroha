//! One consumed private coin tape for each committed-mask fold attempt.
//!
//! Production source owners consume this tape; retained witness verification
//! does not request or reconstruct fresh coins.
use ff::{Field, PrimeField};
use iroha_pasta::{PastaCurve, PastaField};
use zeroize::Zeroizing;

/// Number of independent scalar draws, commitment blind followed by left/right masks.
pub const FOLD_COIN_COUNT: usize = 33;
/// Exact canonical private tape extent; never part of the public accumulator.
pub const FOLD_COIN_BYTES: usize = FOLD_COIN_COUNT * 32;

/// One non-cloneable private tape, cleared when released on any return or unwind.
///
/// The heap allocation is populated in place. There is no seed expansion or public
/// nonce constructor. Sampling policy and fallible OS access belong to the caller.
pub struct FoldTape<C: PastaCurve> {
    coins: Box<[C::ScalarExt; FOLD_COIN_COUNT]>,
}
impl<C: PastaCurve> Drop for FoldTape<C> {
    fn drop(&mut self) {
        for coin in self.coins.iter_mut() {
            clear_field(coin);
        }
    }
}
fn clear_field<F: PastaField>(value: &mut F) {
    value.zeroize();
}
/// Single scalar scratch; clearing uses the admitted Pasta field's own trait owner.
pub struct FieldGuard<F: PastaField>(pub(crate) F);
impl<F: PastaField> Drop for FieldGuard<F> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
impl<C: PastaCurve> core::fmt::Debug for FoldTape<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FoldTape { private: [REDACTED] }")
    }
}
impl<C: PastaCurve> FoldTape<C> {
    /// Fill every scalar once in fixed order. Partial output is wiped on error/unwind.
    ///
    /// # Errors
    /// Returns the first error supplied by the entropy owner, with no retry of the tape.
    pub fn try_fill<E>(
        mut fill: impl FnMut(&mut C::ScalarExt) -> Result<(), E>,
    ) -> Result<Self, E> {
        let mut tape = Self {
            coins: Box::new([C::ScalarExt::ZERO; FOLD_COIN_COUNT]),
        };
        for coin in tape.coins.iter_mut() {
            fill(coin)?;
        }
        Ok(tape)
    }
    /// Borrow the independent commitment blind without transferring its owner.
    pub fn rho(&self) -> &C::ScalarExt {
        &self.coins[0]
    }
    /// Borrow exactly sixteen ordered left/right pairs.
    pub fn masks(&self) -> &[C::ScalarExt; 32] {
        self.coins[1..].try_into().expect("fixed tape extent")
    }
    /// Canonical private checkpoint bytes under a clearing owner.
    pub fn to_private_bytes(&self) -> Zeroizing<Box<[u8]>> {
        let mut bytes = Zeroizing::new(vec![0; FOLD_COIN_BYTES].into_boxed_slice());
        for (coin, destination) in self.coins.iter().zip(bytes.chunks_exact_mut(32)) {
            let encoded = Zeroizing::new(coin.to_repr());
            destination.copy_from_slice(encoded.as_ref());
        }
        bytes
    }
    /// Restore only exact canonical private coins. Zero is valid in every position.
    ///
    /// This decodes syntax only. The checkpoint owner must authenticate source, stage,
    /// schema, proof and resulting frame before using the restored tape.
    /// # Errors
    /// Returns `None` for a wrong extent or any noncanonical scalar; no reduction occurs.
    pub fn from_private_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != FOLD_COIN_BYTES {
            return None;
        }
        let mut tape = Self {
            coins: Box::new([C::ScalarExt::ZERO; FOLD_COIN_COUNT]),
        };
        for (destination, encoded) in tape.coins.iter_mut().zip(bytes.chunks_exact(32)) {
            let mut word = Zeroizing::new([0; 32]);
            word.copy_from_slice(encoded);
            let mut decoded = FieldGuard(C::ScalarExt::ZERO);
            decoded.0 = Option::<C::ScalarExt>::from(C::ScalarExt::from_repr(*word))?;
            *destination = decoded.0;
        }
        Some(tape)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use iroha_pasta::{Ep, Eq};
    fn order<C: PastaCurve>() {
        let mut count = 0_u64;
        let tape = FoldTape::<C>::try_fill::<()>(|coin| {
            *coin = C::ScalarExt::from(count);
            count += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(count, 33);
        assert_eq!(*tape.rho(), C::ScalarExt::ZERO);
        for (position, coin) in tape.masks().iter().enumerate() {
            assert_eq!(*coin, C::ScalarExt::from(position as u64 + 1));
        }
        let encoded = tape.to_private_bytes();
        assert_eq!(encoded.len(), 1056);
        let copy = FoldTape::<C>::from_private_bytes(&encoded).unwrap();
        assert_eq!(copy.rho(), tape.rho());
        assert_eq!(copy.masks(), tape.masks());
        assert_eq!(format!("{tape:?}"), "FoldTape { private: [REDACTED] }");
        assert!(FoldTape::<C>::from_private_bytes(&encoded[..1055]).is_none());
        let mut extra = encoded.to_vec();
        extra.push(0);
        assert!(FoldTape::<C>::from_private_bytes(&extra).is_none());
        for position in 0..33 {
            let mut corrupt = tape.to_private_bytes();
            corrupt[position * 32..(position + 1) * 32].fill(255);
            assert!(FoldTape::<C>::from_private_bytes(&corrupt).is_none());
        }
        let zero = FoldTape::<C>::from_private_bytes(&[0; 1056]).unwrap();
        assert!(zero.coins.iter().all(|x| *x == C::ScalarExt::ZERO));
    }
    fn failure<C: PastaCurve>() {
        for fail_at in 0..33 {
            let mut calls = 0;
            let result = FoldTape::<C>::try_fill(|coin| {
                let position = calls;
                calls += 1;
                *coin = C::ScalarExt::from(77);
                if position == fail_at {
                    Err(position)
                } else {
                    Ok(())
                }
            });
            assert!(matches!(result,Err(position) if position==fail_at));
            assert_eq!(calls, fail_at + 1);
        }
        // Exercises guard unwinding; this test makes no post-free memory assertion.
        let result = std::panic::catch_unwind(|| {
            let _ = FoldTape::<C>::try_fill::<()>(|coin| {
                *coin = C::ScalarExt::from(99);
                panic!("injected entropy panic")
            });
        });
        assert!(result.is_err());
    }
    #[test]
    fn pallas_coin_order_canonical_extent_and_redaction() {
        order::<Ep>();
    }
    #[test]
    fn vesta_coin_order_canonical_extent_and_redaction() {
        order::<Eq>();
    }
    #[test]
    fn pallas_partial_fill_stops_and_unwind_is_guarded() {
        failure::<Ep>();
    }
    #[test]
    fn vesta_partial_fill_stops_and_unwind_is_guarded() {
        failure::<Eq>();
    }
}
