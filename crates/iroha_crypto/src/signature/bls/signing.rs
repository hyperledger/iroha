//! Fixed-storage producer for the existing contextual BLS signature relation.
//!
//! The exact Basic-suite prefix and one-byte hash DST are shared with the sole
//! verifier. After canonical scalar parsing, random splitting is the existing
//! upstream `(s + x, -x)` equation and uses its unchanged field sampler. The
//! synchronous blst primitives perform hashing and both scalar multiplications
//! with fixed backing. No message concatenation or signature Vec is constructed.
//!
//! The consensus suite (`super::consensus`) reuses the same checked scalar
//! decoding and blinded split, but hashes an allowlisted [`ConsensusDigest`]
//! under `DST_SIG` with no augmentation. That producer takes only a
//! `ConsensusDigest`, so no other caller can sign under `DST_SIG`.

use ark_serialize::{CanonicalDeserialize as _, CanonicalSerialize as _, SerializationError};
use blst::*;
use w3f_bls::EngineBLS as _;
use zeroize::Zeroizing;

use super::consensus::{ConsensusDigest, DST_SIG};
use super::implementation::BlsConfiguration;
use super::normal::NormalConfiguration;
use super::uncached::{HASH_TO_FIELD_DST, NORMAL_PREFIX, SMALL_PREFIX};
use crate::{Algorithm, Error};

/// Original typed failure of contextual BLS signing, before diagnostic formatting.
#[derive(Debug)]
pub enum BlsSigningError<E = rand_core::OsError> {
    /// The original checked scalar decoder rejected the retained private key.
    PrivateKey(SerializationError),
    /// The original entropy provider refused the existing signing split draw.
    Entropy(E),
    /// The entropy provider returned the prohibited all-zero split seed.
    ZeroEntropy,
    /// Fixed scalar serialization failed before signature output publication.
    ScalarEncoding(SerializationError),
}
impl<E: std::fmt::Display> std::fmt::Display for BlsSigningError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PrivateKey(error) => write!(f, "BLS private-key decoding failed: {error}"),
            Self::Entropy(error) => write!(f, "BLS signing split entropy failed: {error}"),
            Self::ZeroEntropy => {
                f.write_str("BLS signing key split seed material must not be all zero")
            }
            Self::ScalarEncoding(error) => write!(f, "BLS scalar encoding failed: {error}"),
        }
    }
}
impl<E: std::error::Error + 'static> std::error::Error for BlsSigningError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PrivateKey(error) | Self::ScalarEncoding(error) => Some(error),
            Self::Entropy(error) => Some(error),
            Self::ZeroEntropy => None,
        }
    }
}
impl<E: std::fmt::Display> BlsSigningError<E> {
    pub(super) fn into_public_error(self) -> Error {
        match self {
            Self::PrivateKey(error) | Self::ScalarEncoding(error) => {
                Error::Signing(error.to_string())
            }
            Self::Entropy(error) => Error::Signing(
                Error::KeyGen(format!(
                    "BLS OS RNG failed during signing key split: {error}"
                ))
                .to_string(),
            ),
            Self::ZeroEntropy => Error::Signing(
                Error::KeyGen("BLS signing key split seed material must not be all zero".into())
                    .to_string(),
            ),
        }
    }
}

#[derive(Debug)]
pub(crate) struct SigningOutput {
    bytes: [u8; 96],
    len: usize,
}
impl SigningOutput {
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

fn scalar<C: BlsConfiguration + ?Sized, E>(
    bytes: &[u8],
) -> Result<Zeroizing<<C::Engine as w3f_bls::EngineBLS>::Scalar>, BlsSigningError<E>> {
    // W3fSecretKey::from_bytes uses this same checked scalar deserializer and
    // then only sets the second share and both mutation points to zero. Keeping
    // the scalar directly lets retained scalar, seed and conversion buffers zeroize
    // on retirement. The existing CompatRng keeps its existing cleanup policy.
    let value = <C::Engine as w3f_bls::EngineBLS>::Scalar::deserialize_compressed(bytes)
        .map_err(BlsSigningError::PrivateKey)?;
    Ok(Zeroizing::new(value))
}

/// One checked private scalar held as two shares whose sum is the original scalar.
struct ScalarShares<S: zeroize::Zeroize> {
    first: Zeroizing<S>,
    second: Zeroizing<S>,
}

type EngineScalar<C> = <<C as BlsConfiguration>::Engine as w3f_bls::EngineBLS>::Scalar;

#[cfg(feature = "rand")]
pub(super) fn sign_with_rng<C, R>(
    bytes: &[u8],
    message: &[u8],
    rng: &mut R,
) -> Result<SigningOutput, BlsSigningError<R::Error>>
where
    C: BlsConfiguration + ?Sized,
    R: rand_core::TryCryptoRng,
{
    let shares = split_with_rng::<C, R>(bytes, rng)?;
    sign_split::<C, R::Error>(&shares.first, &shares.second, message)
}

/// Decode the scalar, then draw the existing random split `(s + x, -x)`.
#[cfg(feature = "rand")]
fn split_with_rng<C, R>(
    bytes: &[u8],
    rng: &mut R,
) -> Result<ScalarShares<EngineScalar<C>>, BlsSigningError<R::Error>>
where
    C: BlsConfiguration + ?Sized,
    R: rand_core::TryCryptoRng,
{
    let mut first = scalar::<C, R::Error>(bytes)?;
    // Exactly one 32-byte draw, in the same order after checked key decoding.
    let mut seed = Zeroizing::new([0u8; 32]);
    #[cfg(test)]
    ENTROPY_DRAWS.with(|draws| {
        if let Some(count) = draws.get() {
            draws.set(Some(count + 1));
        }
    });
    rng.try_fill_bytes(seed.as_mut())
        .map_err(BlsSigningError::Entropy)?;
    if seed.iter().all(|byte| *byte == 0) {
        return Err(BlsSigningError::ZeroEntropy);
    }
    let mut split_rng = crate::rng::rng_from_seed_slice(seed.as_slice());
    let mut second = Zeroizing::new(C::Engine::generate(&mut split_rng));
    *first += *second;
    *second = -*second;
    Ok(ScalarShares { first, second })
}

#[cfg(any(test, not(feature = "rand")))]
pub(super) fn sign_once<C: BlsConfiguration + ?Sized>(
    bytes: &[u8],
    message: &[u8],
) -> Result<SigningOutput, BlsSigningError> {
    let shares = split_once::<C, rand_core::OsError>(bytes)?;
    sign_split::<C, rand_core::OsError>(&shares.first, &shares.second, message)
}

/// Decode the scalar without blinding: the second share is zero.
#[cfg(any(test, not(feature = "rand")))]
fn split_once<C: BlsConfiguration + ?Sized, E>(
    bytes: &[u8],
) -> Result<ScalarShares<EngineScalar<C>>, BlsSigningError<E>> {
    let first = scalar::<C, E>(bytes)?;
    let second = Zeroizing::new(EngineScalar::<C>::from(0u64));
    Ok(ScalarShares { first, second })
}

/// Sign one allowlisted consensus digest: `sk · hash_to_G2(m, DST_SIG)`.
///
/// `bytes` is the retained BLS-normal private-key payload. With `rand`, the
/// scalar is blinded by the same OS-entropy split as the contextual signer;
/// the signature is unique for the key and digest either way.
pub(super) fn sign_consensus(
    bytes: &[u8],
    digest: &ConsensusDigest,
) -> Result<[u8; 96], BlsSigningError> {
    #[cfg(feature = "rand")]
    {
        sign_consensus_with_rng(bytes, digest, &mut rand::rngs::OsRng)
    }
    #[cfg(not(feature = "rand"))]
    {
        sign_consensus_once(bytes, digest)
    }
}

/// Consensus signing with an explicit entropy source for the scalar split.
#[cfg(feature = "rand")]
pub(super) fn sign_consensus_with_rng<R: rand_core::TryCryptoRng>(
    bytes: &[u8],
    digest: &ConsensusDigest,
    rng: &mut R,
) -> Result<[u8; 96], BlsSigningError<R::Error>> {
    let shares = split_with_rng::<NormalConfiguration, R>(bytes, rng)?;
    consensus_split::<R::Error>(&shares, digest)
}

/// Consensus signing without the blinding split.
#[cfg(any(test, not(feature = "rand")))]
pub(super) fn sign_consensus_once(
    bytes: &[u8],
    digest: &ConsensusDigest,
) -> Result<[u8; 96], BlsSigningError> {
    let shares = split_once::<NormalConfiguration, rand_core::OsError>(bytes)?;
    consensus_split::<rand_core::OsError>(&shares, digest)
}

/// No augmentation: the IETF min-pk proof-of-possession suite hashes exactly the message.
const NO_AUGMENTATION: &[u8] = &[];

fn consensus_split<E>(
    shares: &ScalarShares<EngineScalar<NormalConfiguration>>,
    digest: &ConsensusDigest,
) -> Result<[u8; 96], BlsSigningError<E>> {
    let first = encoded_scalar::<NormalConfiguration, E>(&shares.first)?;
    let second = encoded_scalar::<NormalConfiguration, E>(&shares.second)?;
    let message = digest.as_bytes();
    let mut output = [0_u8; 96];
    // SAFETY: every point/output is initialized and exact-size for its primitive.
    // The digest, DST and empty augmentation pointers carry their actual lengths.
    // The synchronous C primitives retain no pointers and allocate no Rust buffers;
    // both scalar multiplications use blst's constant-time signing routine.
    #[allow(unsafe_code)]
    unsafe {
        let mut hash = blst_p2::default();
        let mut left = blst_p2::default();
        let mut right = blst_p2::default();
        let mut sum = blst_p2::default();
        blst_hash_to_g2(
            &raw mut hash,
            message.as_ptr(),
            message.len(),
            DST_SIG.as_ptr(),
            DST_SIG.len(),
            NO_AUGMENTATION.as_ptr(),
            NO_AUGMENTATION.len(),
        );
        blst_sign_pk_in_g1(&raw mut left, &raw const hash, &raw const *first);
        blst_sign_pk_in_g1(&raw mut right, &raw const hash, &raw const *second);
        blst_p2_add_or_double(&raw mut sum, &raw const left, &raw const right);
        blst_p2_compress(output.as_mut_ptr(), &raw const sum);
    }
    Ok(output)
}

fn encoded_scalar<C: BlsConfiguration + ?Sized, E>(
    scalar: &<C::Engine as w3f_bls::EngineBLS>::Scalar,
) -> Result<Zeroizing<blst_scalar>, BlsSigningError<E>> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    scalar
        .serialize_compressed(bytes.as_mut_slice())
        .map_err(BlsSigningError::ScalarEncoding)?;
    let mut output = Zeroizing::new(blst_scalar::default());
    // SAFETY: both initialized fixed scalar buffers live for this synchronous
    // conversion. blst reads exactly 32 little-endian bytes and retains no pointer.
    #[allow(unsafe_code)]
    unsafe {
        blst_scalar_from_lendian(&raw mut *output, bytes.as_ptr());
    }
    Ok(output)
}

fn sign_split<C: BlsConfiguration + ?Sized, E>(
    first: &<C::Engine as w3f_bls::EngineBLS>::Scalar,
    second: &<C::Engine as w3f_bls::EngineBLS>::Scalar,
    message: &[u8],
) -> Result<SigningOutput, BlsSigningError<E>> {
    let first = encoded_scalar::<C, E>(first)?;
    let second = encoded_scalar::<C, E>(second)?;
    let mut output = SigningOutput {
        bytes: [0; 96],
        len: C::Engine::SIGNATURE_SERIALIZED_SIZE,
    };
    // SAFETY: every point/output is initialized and exact-size for its primitive.
    // All borrowed byte pointers carry their actual lengths. The synchronous C
    // primitives retain no pointers, allocate no Rust buffers, and use blst's
    // constant-time signing multiplications for both original split shares.
    #[allow(unsafe_code)]
    unsafe {
        match C::ALGORITHM {
            Algorithm::BlsNormal => {
                let mut hash = blst_p2::default();
                let mut left = blst_p2::default();
                let mut right = blst_p2::default();
                let mut sum = blst_p2::default();
                blst_hash_to_g2(
                    &raw mut hash,
                    message.as_ptr(),
                    message.len(),
                    HASH_TO_FIELD_DST.as_ptr(),
                    HASH_TO_FIELD_DST.len(),
                    NORMAL_PREFIX.as_ptr(),
                    NORMAL_PREFIX.len(),
                );
                blst_sign_pk_in_g1(&raw mut left, &raw const hash, &raw const *first);
                blst_sign_pk_in_g1(&raw mut right, &raw const hash, &raw const *second);
                blst_p2_add_or_double(&raw mut sum, &raw const left, &raw const right);
                blst_p2_compress(output.bytes.as_mut_ptr(), &raw const sum);
            }
            Algorithm::BlsSmall => {
                let mut hash = blst_p1::default();
                let mut left = blst_p1::default();
                let mut right = blst_p1::default();
                let mut sum = blst_p1::default();
                blst_hash_to_g1(
                    &raw mut hash,
                    message.as_ptr(),
                    message.len(),
                    HASH_TO_FIELD_DST.as_ptr(),
                    HASH_TO_FIELD_DST.len(),
                    SMALL_PREFIX.as_ptr(),
                    SMALL_PREFIX.len(),
                );
                blst_sign_pk_in_g2(&raw mut left, &raw const hash, &raw const *first);
                blst_sign_pk_in_g2(&raw mut right, &raw const hash, &raw const *second);
                blst_p1_add_or_double(&raw mut sum, &raw const left, &raw const right);
                blst_p1_compress(output.bytes.as_mut_ptr(), &raw const sum);
            }
            _ => unreachable!(
                "only the two existing private BLS configurations implement this owner"
            ),
        }
    }
    Ok(output)
}

#[cfg(test)]
thread_local! {
    static ENTROPY_DRAWS: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

/// Observe actual entries into the sole entropy draw; used only by custody controls.
#[cfg(test)]
pub(crate) fn observe_entropy_draws<T>(body: impl FnOnce() -> T) -> (T, usize) {
    struct Retire;
    impl Drop for Retire {
        fn drop(&mut self) {
            ENTROPY_DRAWS.with(|count| count.set(None));
        }
    }
    ENTROPY_DRAWS.with(|count| {
        assert!(count.get().is_none(), "entropy observations cannot nest");
        count.set(Some(0));
    });
    let retire = Retire;
    let value = body();
    let count = ENTROPY_DRAWS.with(|count| count.get().unwrap());
    drop(retire);
    (value, count)
}

#[cfg(test)]
mod tests;
