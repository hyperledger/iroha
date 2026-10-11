//! Fiat-Shamir transcripts (spec section 6).
//!
//! A transcript is a hash state ([`TranscriptHash`]) plus a proof byte
//! stream. [`TranscriptWriter`] absorbs every prover message and appends its
//! encoding; [`TranscriptReader`] decodes each message canonically (spec
//! section 7), absorbs it, and refuses trailing bytes when finished. Both
//! implement [`Transcript`], so prover and verifier code share one absorption
//! order.
//!
//! Two hashes are defined:
//!
//! - [`blake2b::Blake2bHash`]: `BLAKE2b-512` `Halo2-Transcript` with
//!   `Challenge255` (spec 6.1), byte-identical to the vendored
//!   `Blake2bWrite`/`Blake2bRead`;
//! - [`kagemusha_poseidon::PoseidonHash`]: the KAGEMUSHA RP57 Poseidon sponge
//!   with snark-verifier `NativeLoader` semantics (spec 6.2). Production
//!   absorbs points injectively; the `fe_to_fe` oracle absorption exists only
//!   under `cfg(test)`.
//!
//! # Encodings and rejections
//!
//! Every message is 32 bytes. A scalar must be below the scalar-field modulus
//! ([`TranscriptError::NonCanonicalScalar`]); a point must be a canonical
//! compressed encoding of a curve point ([`TranscriptError::InvalidPoint`])
//! other than the identity ([`TranscriptError::IdentityPoint`]). Both hashes
//! also refuse to absorb the identity as a common input, exactly as the
//! vendored transcripts do. A reader that has bytes left when it is finished
//! reports [`TranscriptError::TrailingBytes`].
//!
//! # Prelude
//!
//! [`absorb_prelude`] absorbs `transcript_repr` and the production instance
//! frame (spec 6.3 steps 1 and 2): the tag `pipainst`, the instance-column
//! count and every column length, before any instance data.

use core::{fmt, marker::PhantomData};

use ff::PrimeField;
use group::{GroupEncoding, prime::PrimeCurveAffine};
use iroha_pasta::{PastaCurve, poseidon::PoseidonField};

#[cfg(test)]
use crate::cs::TranscriptV1;
use crate::cs::TranscriptV2;

pub mod blake2b;
pub mod kagemusha_poseidon;
pub mod pipa_r;
pub use pipa_r::{BasePoseidonHash, TranscriptRepr, absorb_prelude_v2};
#[cfg(test)]
mod kat_tests;

pub use blake2b::Blake2bHash;
pub use kagemusha_poseidon::{PointAbsorption, PoseidonHash};

/// Bytes of every proof message (a scalar or a compressed point).
pub const MESSAGE_BYTES: usize = 32;

/// The instance-frame tag absorbed after `transcript_repr` (spec 6.3), read as
/// a little-endian `u64`.
pub const INSTANCE_FRAME_TAG: [u8; 8] = *b"pipainst";

/// A transcript operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TranscriptError {
    /// The proof ended inside or before a message.
    ProofTruncated,
    /// The transcript does not accept a binding from this field/profile.
    ProfileMismatch,
    /// Bytes remain after the last message.
    TrailingBytes {
        /// The number of unread bytes.
        remaining: usize,
    },
    /// A scalar encoding is not below the scalar-field modulus.
    NonCanonicalScalar,
    /// A point encoding is not canonical or names no curve point.
    InvalidPoint,
    /// The identity point was supplied or decoded.
    IdentityPoint,
}

impl fmt::Display for TranscriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProfileMismatch => f.write_str("transcript binding/profile mismatch"),
            Self::ProofTruncated => f.write_str("the proof is truncated"),
            Self::TrailingBytes { remaining } => {
                write!(f, "{remaining} bytes follow the last proof message")
            }
            Self::NonCanonicalScalar => f.write_str("non-canonical scalar encoding"),
            Self::InvalidPoint => f.write_str("invalid point encoding"),
            Self::IdentityPoint => f.write_str("the identity point is not allowed"),
        }
    }
}

impl std::error::Error for TranscriptError {}

/// Decodes a canonical scalar (`< modulus`).
///
/// # Errors
///
/// [`TranscriptError::NonCanonicalScalar`] for values at or above the modulus.
pub fn decode_scalar<F: PrimeField<Repr = [u8; 32]>>(
    bytes: &[u8; MESSAGE_BYTES],
) -> Result<F, TranscriptError> {
    Option::<F>::from(F::from_repr(*bytes)).ok_or(TranscriptError::NonCanonicalScalar)
}

/// Decodes a canonical compressed point that is not the identity.
///
/// # Errors
///
/// [`TranscriptError::IdentityPoint`] for the identity encoding (32 zero
/// bytes); [`TranscriptError::InvalidPoint`] for a non-canonical `x`, an `x`
/// without a curve point, or any other undecodable encoding.
pub fn decode_point<C: PastaCurve>(
    bytes: &[u8; MESSAGE_BYTES],
) -> Result<C::AffineExt, TranscriptError> {
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(TranscriptError::IdentityPoint);
    }
    let point = Option::<C::AffineExt>::from(C::AffineExt::from_bytes(bytes))
        .ok_or(TranscriptError::InvalidPoint)?;
    if bool::from(point.is_identity()) {
        return Err(TranscriptError::IdentityPoint);
    }
    Ok(point)
}

/// The compressed encoding of a point (32 zero bytes for the identity).
#[must_use]
pub fn encode_point<C: PastaCurve>(point: &C::AffineExt) -> [u8; MESSAGE_BYTES] {
    point.to_bytes()
}

/// The hash state of a transcript.
pub trait TranscriptHash<C: PastaCurve>: Clone {
    /// Absorbs a curve point.
    ///
    /// # Errors
    ///
    /// [`TranscriptError::IdentityPoint`] for the identity, which is never
    /// absorbed.
    fn absorb_point(&mut self, point: &C::AffineExt) -> Result<(), TranscriptError>;

    /// Absorbs a scalar.
    fn absorb_scalar(&mut self, scalar: &C::ScalarExt);

    /// Absorbs native base-field context; scalar profiles explicitly reject it.
    ///
    /// # Errors
    /// [`TranscriptError::ProfileMismatch`] when the binding field is unsupported.
    fn absorb_base(&mut self, _value: &C::Base) -> Result<(), TranscriptError> {
        Err(TranscriptError::ProfileMismatch)
    }

    /// Absorbs a VK binding only in its declared field.
    ///
    /// # Errors
    /// [`TranscriptError::ProfileMismatch`] when the binding field is unsupported.
    fn absorb_binding(&mut self, binding: &TranscriptRepr<C>) -> Result<(), TranscriptError> {
        match binding {
            TranscriptRepr::Scalar(value) => {
                self.absorb_scalar(value);
                Ok(())
            }
            TranscriptRepr::Base(_) => Err(TranscriptError::ProfileMismatch),
        }
    }

    /// Squeezes a challenge; the state continues.
    fn squeeze(&mut self) -> C::ScalarExt;
}

/// The transcript view shared by provers and verifiers.
pub trait Transcript<C: PastaCurve> {
    /// Squeezes a challenge.
    fn squeeze_challenge(&mut self) -> C::ScalarExt;

    /// Absorbs a point that both sides know (not written to the proof).
    ///
    /// # Errors
    ///
    /// [`TranscriptError::IdentityPoint`] for the identity.
    fn common_point(&mut self, point: &C::AffineExt) -> Result<(), TranscriptError>;

    /// Absorbs a scalar that both sides know (not written to the proof).
    fn common_scalar(&mut self, scalar: &C::ScalarExt);

    /// Absorbs native base-field context; scalar profiles explicitly reject it.
    ///
    /// # Errors
    /// [`TranscriptError::ProfileMismatch`] when the binding field is unsupported.
    fn common_base(&mut self, _value: &C::Base) -> Result<(), TranscriptError> {
        Err(TranscriptError::ProfileMismatch)
    }
    /// Absorbs a descriptor binding only in its declared field.
    ///
    /// # Errors
    /// [`TranscriptError::ProfileMismatch`] when the binding field is unsupported.
    fn common_binding(&mut self, binding: &TranscriptRepr<C>) -> Result<(), TranscriptError> {
        match binding {
            TranscriptRepr::Scalar(value) => {
                self.common_scalar(value);
                Ok(())
            }
            TranscriptRepr::Base(_) => Err(TranscriptError::ProfileMismatch),
        }
    }
}

/// The prover's transcript: messages are absorbed and written to the proof.
pub trait TranscriptWrite<C: PastaCurve>: Transcript<C> {
    /// Absorbs `point` and appends its compressed encoding.
    ///
    /// # Errors
    ///
    /// [`TranscriptError::IdentityPoint`] for the identity.
    fn write_point(&mut self, point: &C::AffineExt) -> Result<(), TranscriptError>;

    /// Absorbs `scalar` and appends its canonical encoding.
    fn write_scalar(&mut self, scalar: &C::ScalarExt);
}

/// The verifier's transcript: messages are read from the proof, decoded
/// canonically and absorbed.
pub trait TranscriptRead<C: PastaCurve>: Transcript<C> {
    /// Reads, decodes and absorbs a point.
    ///
    /// # Errors
    ///
    /// [`TranscriptError::ProofTruncated`], [`TranscriptError::InvalidPoint`]
    /// or [`TranscriptError::IdentityPoint`].
    fn read_point(&mut self) -> Result<C::AffineExt, TranscriptError>;

    /// Reads, decodes and absorbs a scalar.
    ///
    /// # Errors
    ///
    /// [`TranscriptError::ProofTruncated`] or
    /// [`TranscriptError::NonCanonicalScalar`].
    fn read_scalar(&mut self) -> Result<C::ScalarExt, TranscriptError>;
}

/// A prover transcript writing into an owned proof buffer.
#[derive(Clone, Debug)]
pub struct TranscriptWriter<C: PastaCurve, H> {
    hash: H,
    proof: Vec<u8>,
    _curve: PhantomData<C>,
}

impl<C: PastaCurve, H: TranscriptHash<C>> TranscriptWriter<C, H> {
    /// A writer over a fresh hash state and an empty proof.
    #[must_use]
    pub fn new(hash: H) -> Self {
        Self {
            hash,
            proof: Vec::new(),
            _curve: PhantomData,
        }
    }

    /// The proof bytes written so far.
    #[must_use]
    pub fn proof(&self) -> &[u8] {
        &self.proof
    }

    /// Appends a point that is not absorbed (the `FoldedGenerator` suffix of
    /// spec section 7, row 17).
    ///
    /// # Errors
    ///
    /// [`TranscriptError::IdentityPoint`] for the identity.
    pub fn append_unabsorbed_point(&mut self, point: &C::AffineExt) -> Result<(), TranscriptError> {
        if bool::from(point.is_identity()) {
            return Err(TranscriptError::IdentityPoint);
        }
        self.proof.extend_from_slice(&encode_point::<C>(point));
        Ok(())
    }

    /// Finishes the transcript and returns the proof bytes.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.proof
    }
}

impl<C: PastaCurve, H: TranscriptHash<C>> Transcript<C> for TranscriptWriter<C, H> {
    fn squeeze_challenge(&mut self) -> C::ScalarExt {
        self.hash.squeeze()
    }

    fn common_point(&mut self, point: &C::AffineExt) -> Result<(), TranscriptError> {
        self.hash.absorb_point(point)
    }

    fn common_scalar(&mut self, scalar: &C::ScalarExt) {
        self.hash.absorb_scalar(scalar);
    }

    fn common_base(&mut self, value: &C::Base) -> Result<(), TranscriptError> {
        self.hash.absorb_base(value)
    }
    fn common_binding(&mut self, binding: &TranscriptRepr<C>) -> Result<(), TranscriptError> {
        self.hash.absorb_binding(binding)
    }
}

impl<C: PastaCurve, H: TranscriptHash<C>> TranscriptWrite<C> for TranscriptWriter<C, H> {
    fn write_point(&mut self, point: &C::AffineExt) -> Result<(), TranscriptError> {
        self.hash.absorb_point(point)?;
        self.proof.extend_from_slice(&encode_point::<C>(point));
        Ok(())
    }

    fn write_scalar(&mut self, scalar: &C::ScalarExt) {
        self.hash.absorb_scalar(scalar);
        self.proof.extend_from_slice(&scalar.to_repr());
    }
}

/// A verifier transcript reading a borrowed proof.
#[derive(Clone, Debug)]
pub struct TranscriptReader<'a, C: PastaCurve, H> {
    hash: H,
    proof: &'a [u8],
    position: usize,
    #[cfg(test)]
    challenges: Option<Vec<C::ScalarExt>>,
    _curve: PhantomData<C>,
}

impl<'a, C: PastaCurve, H: TranscriptHash<C>> TranscriptReader<'a, C, H> {
    /// A reader over a fresh hash state and `proof`.
    #[must_use]
    pub fn new(hash: H, proof: &'a [u8]) -> Self {
        Self {
            hash,
            proof,
            position: 0,
            #[cfg(test)]
            challenges: None,
            _curve: PhantomData,
        }
    }

    /// Record actual squeezes for independent oracle comparisons only.
    #[cfg(test)]
    pub(crate) fn record_challenges(&mut self) {
        self.challenges = Some(Vec::new());
    }

    /// Transfer the recorded public challenge tape before strict completion.
    #[cfg(test)]
    pub(crate) fn take_challenges(&mut self) -> Vec<C::ScalarExt> {
        self.challenges.take().unwrap_or_default()
    }

    /// The number of unread proof bytes.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.proof.len().saturating_sub(self.position)
    }

    /// Takes the next 32-byte message without absorbing it.
    fn next_message(&mut self) -> Result<[u8; MESSAGE_BYTES], TranscriptError> {
        let end = self
            .position
            .checked_add(MESSAGE_BYTES)
            .ok_or(TranscriptError::ProofTruncated)?;
        let bytes = self
            .proof
            .get(self.position..end)
            .ok_or(TranscriptError::ProofTruncated)?;
        let mut message = [0_u8; MESSAGE_BYTES];
        message.copy_from_slice(bytes);
        self.position = end;
        Ok(message)
    }

    /// Reads a point that is not absorbed (the `FoldedGenerator` suffix).
    ///
    /// # Errors
    ///
    /// As [`TranscriptRead::read_point`].
    pub fn read_unabsorbed_point(&mut self) -> Result<C::AffineExt, TranscriptError> {
        let message = self.next_message()?;
        decode_point::<C>(&message)
    }

    /// Finishes reading: every byte must have been consumed.
    ///
    /// # Errors
    ///
    /// [`TranscriptError::TrailingBytes`] when bytes remain.
    pub fn finish(self) -> Result<(), TranscriptError> {
        match self.remaining() {
            0 => Ok(()),
            remaining => Err(TranscriptError::TrailingBytes { remaining }),
        }
    }
}

impl<C: PastaCurve, H: TranscriptHash<C>> Transcript<C> for TranscriptReader<'_, C, H> {
    fn squeeze_challenge(&mut self) -> C::ScalarExt {
        let challenge = self.hash.squeeze();
        #[cfg(test)]
        if let Some(challenges) = &mut self.challenges {
            challenges.push(challenge);
        }
        challenge
    }

    fn common_point(&mut self, point: &C::AffineExt) -> Result<(), TranscriptError> {
        self.hash.absorb_point(point)
    }

    fn common_scalar(&mut self, scalar: &C::ScalarExt) {
        self.hash.absorb_scalar(scalar);
    }

    fn common_base(&mut self, value: &C::Base) -> Result<(), TranscriptError> {
        self.hash.absorb_base(value)
    }
    fn common_binding(&mut self, binding: &TranscriptRepr<C>) -> Result<(), TranscriptError> {
        self.hash.absorb_binding(binding)
    }
}

impl<C: PastaCurve, H: TranscriptHash<C>> TranscriptRead<C> for TranscriptReader<'_, C, H> {
    fn read_point(&mut self) -> Result<C::AffineExt, TranscriptError> {
        let message = self.next_message()?;
        let point = decode_point::<C>(&message)?;
        self.hash.absorb_point(&point)?;
        Ok(point)
    }

    fn read_scalar(&mut self) -> Result<C::ScalarExt, TranscriptError> {
        let message = self.next_message()?;
        let scalar = decode_scalar::<C::ScalarExt>(&message)?;
        self.hash.absorb_scalar(&scalar);
        Ok(scalar)
    }
}

/// The transcript a descriptor selects ([`TranscriptV1`]), as one hash type.
#[derive(Clone, Debug)]
pub enum DescriptorHash<C: PastaCurve>
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    /// `BLAKE2b` `Challenge255` (spec 6.1).
    Blake2b(Blake2bHash<C>),
    /// KAGEMUSHA RP57 Poseidon (spec 6.2).
    Poseidon(PoseidonHash<C>),
    /// PIPA-R base-field RP57 Poseidon.
    BasePoseidon(BasePoseidonHash<C>),
}

impl<C: PastaCurve> DescriptorHash<C>
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    /// The production hash of `transcript` (injective Poseidon point
    /// absorption).
    #[must_use]
    pub fn production(transcript: impl Into<TranscriptV2>) -> Self {
        match transcript.into() {
            TranscriptV2::KagemushaPoseidonRp57Base => Self::BasePoseidon(BasePoseidonHash::new()),
            TranscriptV2::Blake2bChallenge255 => Self::Blake2b(Blake2bHash::new()),
            TranscriptV2::KagemushaPoseidonRp57 => Self::Poseidon(PoseidonHash::new()),
        }
    }

    /// The oracle-mode hash of `transcript` (`fe_to_fe` Poseidon point
    /// absorption, spec 6.4). Unit tests only.
    #[cfg(test)]
    #[doc(hidden)]
    #[must_use]
    pub fn oracle(transcript: TranscriptV1) -> Self {
        match transcript {
            TranscriptV1::Blake2bChallenge255 => Self::Blake2b(Blake2bHash::new()),
            TranscriptV1::KagemushaPoseidonRp57 => Self::Poseidon(PoseidonHash::new_oracle()),
        }
    }
}

impl<C: PastaCurve> TranscriptHash<C> for DescriptorHash<C>
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    fn absorb_point(&mut self, point: &C::AffineExt) -> Result<(), TranscriptError> {
        let result = match self {
            Self::Blake2b(hash) => hash.absorb_point(point),
            Self::Poseidon(hash) => hash.absorb_point(point),
            Self::BasePoseidon(hash) => hash.absorb_point(point),
        };
        #[cfg(test)]
        if result.is_ok() {
            recording::note(crate::protocol::HashOperation::AbsorbPoint);
        }
        result
    }

    fn absorb_scalar(&mut self, scalar: &C::ScalarExt) {
        match self {
            Self::Blake2b(hash) => hash.absorb_scalar(scalar),
            Self::Poseidon(hash) => hash.absorb_scalar(scalar),
            Self::BasePoseidon(hash) => hash.absorb_scalar(scalar),
        }
        #[cfg(test)]
        recording::note(crate::protocol::HashOperation::AbsorbScalar);
    }

    fn absorb_binding(&mut self, binding: &TranscriptRepr<C>) -> Result<(), TranscriptError> {
        match (self, binding) {
            (Self::BasePoseidon(_), TranscriptRepr::Scalar(_)) => {
                Err(TranscriptError::ProfileMismatch)
            }
            (hash @ Self::BasePoseidon(_), TranscriptRepr::Base(value)) => hash.absorb_base(value),
            (_, TranscriptRepr::Base(_)) => Err(TranscriptError::ProfileMismatch),
            (hash, TranscriptRepr::Scalar(value)) => {
                hash.absorb_scalar(value);
                Ok(())
            }
        }
    }

    fn absorb_base(&mut self, value: &C::Base) -> Result<(), TranscriptError> {
        match self {
            Self::BasePoseidon(hash) => {
                hash.absorb_base(value)?;
                #[cfg(test)]
                recording::note(crate::protocol::HashOperation::AbsorbBase);
                Ok(())
            }
            _ => Err(TranscriptError::ProfileMismatch),
        }
    }

    fn squeeze(&mut self) -> C::ScalarExt {
        #[cfg(test)]
        recording::note(crate::protocol::HashOperation::Squeeze);
        match self {
            Self::Blake2b(hash) => hash.squeeze(),
            Self::Poseidon(hash) => hash.squeeze(),
            Self::BasePoseidon(hash) => hash.squeeze(),
        }
    }
}

/// Unit-test recording of the hash operations a [`DescriptorHash`] performs
/// on the current thread, for the transcript-schedule tests (S11). The
/// prover and the verifier touch their transcript only on the calling
/// thread, so a thread-local log sees every operation in order.
#[cfg(test)]
pub(crate) mod recording {
    use core::cell::RefCell;

    use crate::protocol::HashOperation;

    std::thread_local! {
        static LOG: RefCell<Option<Vec<HashOperation>>> = const { RefCell::new(None) };
    }

    /// Appends `operation` while a recording is active.
    pub fn note(operation: HashOperation) {
        LOG.with(|log| {
            if let Some(log) = log.borrow_mut().as_mut() {
                log.push(operation);
            }
        });
    }

    /// Runs `f` and returns its result and the operations it performed.
    pub fn record<R>(f: impl FnOnce() -> R) -> (R, Vec<HashOperation>) {
        LOG.with(|log| *log.borrow_mut() = Some(Vec::new()));
        let result = f();
        let operations = LOG.with(|log| log.borrow_mut().take()).unwrap_or_default();
        (result, operations)
    }

    #[test]
    fn recording_is_scoped_to_the_closure() {
        note(HashOperation::Squeeze);
        let ((), operations) = record(|| {
            note(HashOperation::AbsorbPoint);
            note(HashOperation::Squeeze);
        });
        assert_eq!(
            operations,
            [HashOperation::AbsorbPoint, HashOperation::Squeeze]
        );
        let ((), empty) = record(|| ());
        assert!(empty.is_empty());
    }
}

/// `F::from(u64)` of a count; counts never exceed `u64` on supported targets.
fn count_scalar<F: PrimeField>(count: usize) -> F {
    F::from(u64::try_from(count).unwrap_or(u64::MAX))
}

/// Absorbs the production prelude (spec 6.3 steps 1 and 2):
/// `transcript_repr`, then the instance frame — the tag
/// [`INSTANCE_FRAME_TAG`], the column count and each column length.
pub fn absorb_prelude<C: PastaCurve, T: Transcript<C> + ?Sized>(
    transcript: &mut T,
    transcript_repr: &C::ScalarExt,
    instance_lengths: &[u32],
) {
    transcript.common_scalar(transcript_repr);
    transcript.common_scalar(&C::ScalarExt::from(u64::from_le_bytes(INSTANCE_FRAME_TAG)));
    transcript.common_scalar(&count_scalar(instance_lengths.len()));
    for length in instance_lengths {
        transcript.common_scalar(&C::ScalarExt::from(u64::from(*length)));
    }
}

/// Absorbs the oracle-mode prelude: `transcript_repr` only, no instance frame
/// (spec 6.4). Unit tests only.
#[cfg(test)]
#[doc(hidden)]
pub fn absorb_prelude_oracle<C: PastaCurve, T: Transcript<C> + ?Sized>(
    transcript: &mut T,
    transcript_repr: &C::ScalarExt,
) {
    transcript.common_scalar(transcript_repr);
}

#[cfg(test)]
mod tests {
    use ff::Field;
    use group::{Curve, Group};
    use iroha_pasta::{Ep, EpAffine, Eq, EqAffine, Fp, Fq};

    use super::*;

    type PallasWriter = TranscriptWriter<Ep, Blake2bHash<Ep>>;

    #[test]
    fn scalar_and_point_decoding_are_canonical() {
        let modulus = crate::cs::descriptor::modulus_le_bytes::<Fq>();
        assert_eq!(
            decode_scalar::<Fq>(&modulus),
            Err(TranscriptError::NonCanonicalScalar)
        );
        assert_eq!(decode_scalar::<Fq>(&Fq::ONE.to_repr()), Ok(Fq::ONE));
        assert_eq!(
            decode_point::<Ep>(&[0_u8; 32]),
            Err(TranscriptError::IdentityPoint)
        );
        let mut off_curve = [0_u8; 32];
        off_curve[0] = 2;
        assert_eq!(
            decode_point::<Ep>(&off_curve),
            Err(TranscriptError::InvalidPoint)
        );
        let generator = Ep::generator().to_affine();
        assert_eq!(
            decode_point::<Ep>(&encode_point::<Ep>(&generator)),
            Ok(generator)
        );
        let vesta = Eq::generator().to_affine();
        assert_eq!(decode_point::<Eq>(&encode_point::<Eq>(&vesta)), Ok(vesta));
    }

    #[test]
    fn writer_and_reader_agree_and_reject_trailing_bytes() {
        let point = (Ep::generator() * Fq::from(7)).to_affine();
        let mut writer = PallasWriter::new(Blake2bHash::new());
        writer.common_scalar(&Fq::from(3));
        writer.write_point(&point).expect("finite point");
        let first = writer.squeeze_challenge();
        writer.write_scalar(&Fq::from(9));
        let second = writer.squeeze_challenge();
        writer
            .append_unabsorbed_point(&point)
            .expect("finite point");
        assert_eq!(writer.proof().len(), 3 * MESSAGE_BYTES);
        let mut proof = writer.finish();

        let mut reader = TranscriptReader::<Ep, _>::new(Blake2bHash::new(), &proof);
        reader.common_scalar(&Fq::from(3));
        assert_eq!(reader.read_point(), Ok(point));
        assert_eq!(reader.squeeze_challenge(), first);
        assert_eq!(reader.read_scalar(), Ok(Fq::from(9)));
        assert_eq!(reader.squeeze_challenge(), second);
        assert_eq!(reader.remaining(), MESSAGE_BYTES);
        assert_eq!(reader.read_unabsorbed_point(), Ok(point));
        assert_eq!(reader.finish(), Ok(()));

        proof.push(0);
        let mut reader = TranscriptReader::<Ep, _>::new(Blake2bHash::new(), &proof);
        reader.common_scalar(&Fq::from(3));
        reader.read_point().expect("point");
        reader.read_scalar().expect("scalar");
        reader.read_unabsorbed_point().expect("suffix");
        assert_eq!(
            reader.finish(),
            Err(TranscriptError::TrailingBytes { remaining: 1 })
        );

        let mut short = TranscriptReader::<Ep, _>::new(Blake2bHash::new(), &proof[..31]);
        assert_eq!(short.read_scalar(), Err(TranscriptError::ProofTruncated));
    }

    #[test]
    fn identity_is_never_absorbed_or_appended() {
        let mut writer = PallasWriter::new(Blake2bHash::new());
        assert_eq!(
            writer.write_point(&EpAffine::identity()),
            Err(TranscriptError::IdentityPoint)
        );
        assert_eq!(
            writer.common_point(&EpAffine::identity()),
            Err(TranscriptError::IdentityPoint)
        );
        assert_eq!(
            writer.append_unabsorbed_point(&EpAffine::identity()),
            Err(TranscriptError::IdentityPoint)
        );
        assert!(writer.proof().is_empty());
        let mut poseidon = TranscriptWriter::<Eq, PoseidonHash<Eq>>::new(PoseidonHash::new());
        assert_eq!(
            poseidon.write_point(&EqAffine::identity()),
            Err(TranscriptError::IdentityPoint)
        );
    }

    /// Absorbs a scalar and the Vesta generator, then squeezes.
    fn run_script<H: TranscriptHash<Eq>>(mut state: H) -> Fp {
        state.absorb_scalar(&Fp::from(5));
        state
            .absorb_point(&Eq::generator().to_affine())
            .expect("finite");
        state.squeeze()
    }

    #[test]
    fn descriptor_hash_dispatches_to_the_selected_transcript() {
        let blake = run_script(DescriptorHash::<Eq>::production(
            TranscriptV1::Blake2bChallenge255,
        ));
        let poseidon = run_script(DescriptorHash::<Eq>::production(
            TranscriptV1::KagemushaPoseidonRp57,
        ));
        assert_eq!(blake, run_script(Blake2bHash::<Eq>::new()));
        assert_eq!(poseidon, run_script(PoseidonHash::<Eq>::new()));
        assert_ne!(blake, poseidon);
        // Oracle mode differs from production only in Poseidon point absorption.
        assert_eq!(
            run_script(DescriptorHash::<Eq>::oracle(
                TranscriptV1::Blake2bChallenge255
            )),
            blake
        );
        assert_eq!(
            run_script(DescriptorHash::<Eq>::oracle(
                TranscriptV1::KagemushaPoseidonRp57
            )),
            run_script(PoseidonHash::<Eq>::new_oracle())
        );
    }

    /// DEV-02 (spec section 14): production absorbs the instance frame (tag, column count,
    /// lengths) before any instance data; the vendored transcript has none.
    #[test]
    fn prelude_frames_the_instance_shape() {
        let repr = Fq::from(11);
        let mut framed = PallasWriter::new(Blake2bHash::new());
        absorb_prelude::<Ep, _>(&mut framed, &repr, &[3, 1]);
        let mut manual = PallasWriter::new(Blake2bHash::new());
        manual.common_scalar(&repr);
        manual.common_scalar(&Fq::from(u64::from_le_bytes(*b"pipainst")));
        manual.common_scalar(&Fq::from(2));
        manual.common_scalar(&Fq::from(3));
        manual.common_scalar(&Fq::from(1));
        assert_eq!(framed.squeeze_challenge(), manual.squeeze_challenge());

        // Different shapes give different challenges, even with equal sums.
        let challenge = |lengths: &[u32]| {
            let mut writer = PallasWriter::new(Blake2bHash::new());
            absorb_prelude::<Ep, _>(&mut writer, &repr, lengths);
            writer.squeeze_challenge()
        };
        assert_ne!(challenge(&[3, 1]), challenge(&[1, 3]));
        assert_ne!(challenge(&[4]), challenge(&[3, 1]));
        assert_ne!(challenge(&[]), challenge(&[0]));

        let mut oracle = PallasWriter::new(Blake2bHash::new());
        absorb_prelude_oracle::<Ep, _>(&mut oracle, &repr);
        let mut bare = PallasWriter::new(Blake2bHash::new());
        bare.common_scalar(&repr);
        assert_eq!(oracle.squeeze_challenge(), bare.squeeze_challenge());
    }

    #[test]
    fn count_scalar_matches_from_u64() {
        assert_eq!(count_scalar::<Fp>(0), Fp::ZERO);
        assert_eq!(count_scalar::<Fp>(65_535), Fp::from(65_535));
    }
}
