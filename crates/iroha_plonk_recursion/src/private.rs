//! Private recursion buffers over existing protocol implementations.
//!
//! Fixed private outputs clear their owned allocation on return, failure and unwind.
//! The common Pasta sponge and PLONK writer clear their own retained buffers.
//! Copy scalar temporaries, stack/register copies and abort/OOM cleanup are not
//! covered by these owner contracts.
use iroha_pasta::{PastaAffine, PastaCurve, PastaField};
use iroha_plonk::transcript::{TranscriptHash, TranscriptWriter};
use zeroize::Zeroizing;

/// Explicit serialized private witness owner, with redacted diagnostics.
pub struct PrivateWitnessBytes(pub(crate) Zeroizing<Vec<u8>>);
impl PrivateWitnessBytes {
    /// Transfer an existing clearing byte allocation without copying or reallocating.
    /// The supplying owner is responsible for guarding acquisition before this call.
    pub fn from_guarded(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }

    /// Write one exact private payload directly into a fixed clearing allocation.
    /// The closure cannot resize, take or expose an owning Vec. Failure and unwind clear
    /// the allocation; success requires exactly the selected capacity to be written.
    pub fn try_write<E: From<std::io::Error>>(
        capacity: usize,
        write: impl FnOnce(&mut dyn std::io::Write) -> Result<(), E>,
    ) -> Result<Self, E> {
        let mut owned = Zeroizing::new(vec![0; capacity]);
        let mut writer = std::io::Cursor::new(owned.as_mut_slice());
        write(&mut writer)?;
        if writer.position() != capacity as u64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "private payload length differs",
            )
            .into());
        }
        Ok(Self(owned))
    }
    /// Allocate a fixed zero witness specimen, only useful for unknown source synthesis.
    pub fn unknown_fold() -> Self {
        Self(Zeroizing::new(vec![0; crate::FOLD_WITNESS_BYTES]))
    }
}
impl core::ops::Deref for PrivateWitnessBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}
impl core::fmt::Debug for PrivateWitnessBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PrivateWitnessBytes { private: [REDACTED] }")
    }
}

// Call each admitted field's own Zeroize supertrait. This also avoids assuming
// that independently emitted dependency variants share our byte guard's trait.
pub(crate) struct FieldVec<F: PastaField>(pub(crate) Vec<F>);
impl<F: PastaField> FieldVec<F> {
    pub(crate) fn truncate(&mut self, len: usize) {
        if len < self.0.len() {
            for value in &mut self.0[len..] {
                value.zeroize();
            }
            self.0.truncate(len);
        }
    }
}
impl<F: PastaField> core::ops::Deref for FieldVec<F> {
    type Target = Vec<F>;
    fn deref(&self) -> &Vec<F> {
        &self.0
    }
}
impl<F: PastaField> core::ops::DerefMut for FieldVec<F> {
    fn deref_mut(&mut self) -> &mut Vec<F> {
        &mut self.0
    }
}
impl<F: PastaField> Drop for FieldVec<F> {
    fn drop(&mut self) {
        for value in self.0.iter_mut() {
            value.zeroize();
        }
    }
}
pub(crate) struct FieldArray<F: PastaField, const N: usize>(pub(crate) [F; N]);
impl<F: PastaField, const N: usize> Drop for FieldArray<F, N> {
    fn drop(&mut self) {
        for value in &mut self.0 {
            value.zeroize();
        }
    }
}

pub(crate) struct PointGuard<C: PastaCurve>(pub(crate) C);
impl<C: PastaCurve> Drop for PointGuard<C> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
pub(crate) struct AffineGuard<C: PastaCurve>(pub(crate) C::AffineExt);
fn clear_affine<A: PastaAffine>(value: &mut A) {
    value.zeroize();
}
impl<C: PastaCurve> Drop for AffineGuard<C> {
    fn drop(&mut self) {
        clear_affine(&mut self.0);
    }
}
pub(crate) struct AffineVec<C: PastaCurve>(pub(crate) Vec<C::AffineExt>);
impl<C: PastaCurve> AffineVec<C> {
    pub(crate) fn truncate(&mut self, len: usize) {
        if len < self.0.len() {
            for value in &mut self.0[len..] {
                clear_affine(value);
            }
            self.0.truncate(len);
        }
    }
    pub(crate) fn clear(&mut self) {
        self.truncate(0);
    }
}
impl<C: PastaCurve> core::ops::Deref for AffineVec<C> {
    type Target = Vec<C::AffineExt>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<C: PastaCurve> core::ops::DerefMut for AffineVec<C> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl<C: PastaCurve> Drop for AffineVec<C> {
    fn drop(&mut self) {
        self.clear();
    }
}

pub(crate) struct PrivateWriter<C: PastaCurve, H: TranscriptHash<C>> {
    writer: Option<TranscriptWriter<C, H>>,
}
impl<C: PastaCurve, H: TranscriptHash<C>> PrivateWriter<C, H> {
    pub(crate) fn new(hash: H) -> Self {
        Self {
            writer: Some(TranscriptWriter::new(hash)),
        }
    }
    pub(crate) fn writer(&mut self) -> &mut TranscriptWriter<C, H> {
        self.writer
            .as_mut()
            .expect("writer is present until consumed")
    }
    pub(crate) fn finish(mut self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(
            self.writer
                .take()
                .expect("writer is present until consumed")
                .finish(),
        )
    }
}
impl<C: PastaCurve, H: TranscriptHash<C>> Drop for PrivateWriter<C, H> {
    fn drop(&mut self) {
        if let Some(writer) = self.writer.take() {
            drop(Zeroizing::new(writer.finish()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PrivateWitnessBytes;
    #[test]
    fn exact_writer_preserves_bytes_and_refuses_short_or_overflow() {
        let bytes =
            PrivateWitnessBytes::try_write::<std::io::Error>(4, |w| w.write_all(b"tape")).unwrap();
        assert_eq!(&*bytes, b"tape");
        assert!(format!("{bytes:?}").contains("REDACTED"));
        assert_eq!(
            PrivateWitnessBytes::try_write::<std::io::Error>(4, |w| w.write_all(b"tap"))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        assert_eq!(
            PrivateWitnessBytes::try_write::<std::io::Error>(4, |w| w.write_all(b"tapes"))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::WriteZero
        );
    }
    #[test]
    fn guarded_intake_transfers_the_same_allocation() {
        let bytes = zeroize::Zeroizing::new(vec![0xa5_u8; 17]);
        let pointer = bytes.as_ptr();
        let owned = PrivateWitnessBytes::from_guarded(bytes);
        assert_eq!(owned.as_ptr(), pointer);
        assert_eq!(&*owned, &[0xa5; 17]);
    }
    #[test]
    fn writer_propagates_closure_failure_without_output() {
        let failure = PrivateWitnessBytes::try_write::<std::io::Error>(4, |w| {
            w.write_all(b"ta")?;
            Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "controlled failure",
            ))
        })
        .unwrap_err();
        assert_eq!(failure.kind(), std::io::ErrorKind::Interrupted);
        assert_eq!(
            PrivateWitnessBytes::unknown_fold().len(),
            crate::FOLD_WITNESS_BYTES
        );
    }
}
