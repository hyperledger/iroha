use super::{normal::NormalConfiguration, small::SmallConfiguration};
use blake2::{Blake2b, digest::consts::U32};
use core::marker::PhantomData;
use hkdf::HkdfExtract;
#[cfg(feature = "rand")]
use rand::rngs::OsRng;
#[cfg(feature = "rand")]
use rand_core::TryCryptoRng;
use sha2::Digest as _;
use sha2::Sha256;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet, VecDeque},
    string::ToString as _,
    sync::Arc,
    vec,
    vec::Vec,
};
use w3f_bls::{
    EngineBLS, PublicKey, SecretKey as W3fSecretKey, SecretKeyVT, SerializableToBytes as _,
    Signature as BlsSignature,
};
use zeroize::{Zeroize as _, Zeroizing};

pub(super) const MESSAGE_CONTEXT: &[u8; 20] = b"for signing messages";
const VERIFY_OK_CACHE_LIMIT: usize = 4096;
const VERIFY_OK_CACHE_INPUT_BYTES_LIMIT: usize = 2 * 1024 * 1024;
#[cfg(feature = "rand")]
const BLS_RNG_SEED_LEN: usize = 32;
#[derive(Debug, PartialEq, Eq)]
struct VerifyOkCacheEntry {
    public_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
}
impl VerifyOkCacheEntry {
    fn matches(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        self.public_key.as_slice() == public_key
            && self.message.as_slice() == message
            && self.signature.as_slice() == signature
    }
    fn input_bytes(&self) -> usize {
        self.public_key
            .len()
            .saturating_add(self.message.len())
            .saturating_add(self.signature.len())
    }
}
/// Bounded cache of successfully verified BLS triples.
///
/// The digest is only an index. Every hit is confirmed against the exact
/// public-key, message, and signature bytes in its collision bucket, so a
/// digest collision can never reuse another verification verdict. Entry count
/// and retained input bytes are both bounded per thread and BLS orientation.
#[doc(hidden)]
pub struct VerifyOkCache {
    entries: BTreeMap<[u8; 32], Vec<Arc<VerifyOkCacheEntry>>>,
    insertion_order: VecDeque<([u8; 32], Arc<VerifyOkCacheEntry>)>,
    retained_input_bytes: usize,
}
impl VerifyOkCache {
    fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            insertion_order: VecDeque::new(),
            retained_input_bytes: 0,
        }
    }
    fn contains_at_digest(
        &self,
        digest: [u8; 32],
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        self.entries.get(&digest).is_some_and(|bucket| {
            bucket
                .iter()
                .any(|entry| entry.matches(public_key, message, signature))
        })
    }
    fn remember_at_digest(
        &mut self,
        digest: [u8; 32],
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) {
        if self.contains_at_digest(digest, public_key, message, signature) {
            return;
        }
        let input_bytes = public_key
            .len()
            .saturating_add(message.len())
            .saturating_add(signature.len());
        if input_bytes > VERIFY_OK_CACHE_INPUT_BYTES_LIMIT {
            return;
        }
        let entry = Arc::new(VerifyOkCacheEntry {
            public_key: public_key.to_vec(),
            message: message.to_vec(),
            signature: signature.to_vec(),
        });
        debug_assert_eq!(entry.input_bytes(), input_bytes);
        while self.insertion_order.len() >= VERIFY_OK_CACHE_LIMIT
            || self.retained_input_bytes.saturating_add(input_bytes)
                > VERIFY_OK_CACHE_INPUT_BYTES_LIMIT
        {
            if !self.evict_oldest() {
                return;
            }
        }
        self.retained_input_bytes = self.retained_input_bytes.saturating_add(input_bytes);
        self.entries
            .entry(digest)
            .or_default()
            .push(Arc::clone(&entry));
        self.insertion_order.push_back((digest, entry));
    }
    fn evict_oldest(&mut self) -> bool {
        let Some((digest, entry)) = self.insertion_order.pop_front() else {
            return false;
        };
        self.retained_input_bytes = self
            .retained_input_bytes
            .saturating_sub(entry.input_bytes());
        let remove_bucket = self.entries.get_mut(&digest).is_some_and(|bucket| {
            if let Some(position) = bucket
                .iter()
                .position(|candidate| Arc::ptr_eq(candidate, &entry))
            {
                bucket.remove(position);
            }
            bucket.is_empty()
        });
        if remove_bucket {
            self.entries.remove(&digest);
        }
        true
    }
}
fn verify_ok_cache_digest(pk_bytes: &[u8], message: &[u8], signature: &[u8]) -> [u8; 32] {
    // Framing makes the index unambiguous; exact collision-bucket matching is
    // still the authority for a positive cache verdict.
    let mut h = Blake2b::<U32>::new();
    h.update(b"iroha:bls:verify_ok_cache:v2");
    h.update(
        u64::try_from(pk_bytes.len())
            .expect("supported slice lengths fit u64")
            .to_le_bytes(),
    );
    h.update(pk_bytes);
    h.update(
        u64::try_from(message.len())
            .expect("supported slice lengths fit u64")
            .to_le_bytes(),
    );
    h.update(message);
    h.update(
        u64::try_from(signature.len())
            .expect("supported slice lengths fit u64")
            .to_le_bytes(),
    );
    h.update(signature);
    h.finalize().into()
}
/// Optional ordinary verification-result retention; never used by admission.
#[doc(hidden)]
pub trait VerifyOkCacheAccess: BlsConfiguration {
    /// Borrow only the exact positive-verdict cache for this orientation.
    fn with_verify_ok_cache<R>(f: impl FnOnce(&mut VerifyOkCache) -> R) -> R;
}
#[cfg(test)]
thread_local! {
    static VERIFY_OK_CACHE_ACCESSES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(super) fn verify_ok_cache_accesses_for_tests() -> usize {
    VERIFY_OK_CACHE_ACCESSES.with(std::cell::Cell::get)
}

thread_local! {
    static VERIFY_OK_CACHE_NORMAL: RefCell<VerifyOkCache> = RefCell::new(VerifyOkCache::new());
    static VERIFY_OK_CACHE_SMALL: RefCell<VerifyOkCache> = RefCell::new(VerifyOkCache::new());
}
impl VerifyOkCacheAccess for NormalConfiguration {
    fn with_verify_ok_cache<R>(f: impl FnOnce(&mut VerifyOkCache) -> R) -> R {
        #[cfg(test)]
        VERIFY_OK_CACHE_ACCESSES.with(|count| count.set(count.get() + 1));
        VERIFY_OK_CACHE_NORMAL.with(|cache| f(&mut cache.borrow_mut()))
    }
}
impl VerifyOkCacheAccess for SmallConfiguration {
    fn with_verify_ok_cache<R>(f: impl FnOnce(&mut VerifyOkCache) -> R) -> R {
        #[cfg(test)]
        VERIFY_OK_CACHE_ACCESSES.with(|count| count.set(count.get() + 1));
        VERIFY_OK_CACHE_SMALL.with(|cache| f(&mut cache.borrow_mut()))
    }
}
/// Zeroizing serialized wrapper around a w3f secret key.
pub struct ManagedSecretKey<C: BlsConfiguration + ?Sized> {
    bytes: Zeroizing<Vec<u8>>,
    _marker: PhantomData<C>,
}
impl<C: BlsConfiguration + ?Sized> Clone for ManagedSecretKey<C> {
    fn clone(&self) -> Self {
        Self {
            bytes: Zeroizing::new(self.bytes.as_slice().to_vec()),
            _marker: PhantomData,
        }
    }
}
impl<C: BlsConfiguration + ?Sized> ManagedSecretKey<C> {
    fn new(secret: &W3fSecretKey<C::Engine>) -> Self {
        Self {
            bytes: Zeroizing::new(secret.into_vartime().to_bytes()),
            _marker: PhantomData,
        }
    }
    fn try_load_secret(&self) -> Result<W3fSecretKey<C::Engine>, ParseError> {
        W3fSecretKey::<C::Engine>::from_bytes(self.bytes.as_slice())
            .map_err(|err| ParseError::Invalid(err.to_string()))
    }
    /// Copy the secret bytes into a buffer that clears itself on drop.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.bytes.as_slice().to_vec())
    }
    /// Borrow the serialized secret for crate-internal use.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
    pub fn try_public_key(&self) -> Result<PublicKey<C::Engine>, ParseError> {
        Ok(self.try_load_secret()?.into_public())
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        if !bytes.is_empty() && bytes.iter().all(|&byte| byte == 0) {
            return Err(ParseError::Invalid(
                "BLS secret key material must not be all zero".to_string(),
            ));
        }
        let secret = W3fSecretKey::<C::Engine>::from_bytes(bytes)
            .map_err(|err| ParseError::Invalid(err.to_string()))?;
        Ok(Self::new(&secret))
    }
    fn try_sign_bytes(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.try_sign_fixed(message)
            .map(|output| output.as_slice().to_vec())
            .map_err(super::signing::BlsSigningError::into_public_error)
    }
    pub(crate) fn try_sign_fixed(
        &self,
        message: &[u8],
    ) -> Result<super::signing::SigningOutput, super::signing::BlsSigningError> {
        #[cfg(feature = "rand")]
        {
            self.try_sign_fixed_with_rng(message, &mut OsRng)
        }
        #[cfg(not(feature = "rand"))]
        {
            super::signing::sign_once::<C>(self.bytes.as_slice(), message)
        }
    }
    #[cfg(feature = "rand")]
    fn try_sign_fixed_with_rng<R>(
        &self,
        message: &[u8],
        rng: &mut R,
    ) -> Result<super::signing::SigningOutput, super::signing::BlsSigningError<R::Error>>
    where
        R: TryCryptoRng,
    {
        super::signing::sign_with_rng::<C, R>(self.bytes.as_slice(), message, rng)
    }
    #[cfg(test)]
    pub(crate) fn from_unchecked_bytes_for_test(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
            _marker: PhantomData,
        }
    }
}
impl<C: BlsConfiguration + ?Sized> zeroize::Zeroize for ManagedSecretKey<C> {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}
use crate::{Algorithm, Error, KeyGenOption, ParseError};
/// One pre-aggregation group: parsed public keys that all signed the paired message.
#[cfg(test)]
type PublicKeyGroup<'a, E> = (&'a [&'a PublicKey<E>], &'a [u8]);
#[cfg(feature = "rand")]
fn checked_entropy_from_rng<R>(
    context: &str,
    len: usize,
    rng: &mut R,
) -> Result<Zeroizing<Vec<u8>>, Error>
where
    R: TryCryptoRng,
{
    let mut seed = Zeroizing::new(vec![0u8; len]);
    rng.try_fill_bytes(seed.as_mut_slice())
        .map_err(|err| Error::KeyGen(format!("BLS OS RNG failed during {context}: {err}")))?;
    ensure_bls_seed_material_not_all_zero(context, seed.as_slice())?;
    Ok(seed)
}
fn bls_seed_material_is_all_zero(seed: &[u8]) -> bool {
    !seed.is_empty() && seed.iter().all(|&byte| byte == 0)
}
fn bls_seed_material_all_zero_error(context: &str) -> Error {
    Error::KeyGen(format!("BLS {context} seed material must not be all zero"))
}
#[cfg(feature = "rand")]
fn ensure_bls_seed_material_not_all_zero(context: &str, seed: &[u8]) -> Result<(), Error> {
    if bls_seed_material_is_all_zero(seed) {
        return Err(bls_seed_material_all_zero_error(context));
    }
    Ok(())
}
fn parse_canonical_bls_signature<E: EngineBLS>(
    signature_bytes: &[u8],
) -> Result<BlsSignature<E>, Error> {
    super::canonical::signature::<E>(signature_bytes)
        .map(|(signature, _)| signature)
        .map_err(|failure| failure.into_parse_error().into())
}
fn ensure_distinct_messages(messages: &[&[u8]]) -> Result<(), Error> {
    let mut seen = BTreeSet::new();
    for &msg in messages {
        if !seen.insert(msg) {
            return Err(Error::BadSignature);
        }
    }
    Ok(())
}
pub trait BlsConfiguration {
    const ALGORITHM: Algorithm;
    type Engine: w3f_bls::EngineBLS;
}
pub struct BlsImpl<C: BlsConfiguration + ?Sized>(PhantomData<C>);
impl<C: BlsConfiguration + ?Sized> BlsImpl<C> {
    /// Return the exact canonical signature length for this BLS orientation.
    pub const fn signature_len() -> usize {
        C::Engine::SIGNATURE_SERIALIZED_SIZE
    }
    #[allow(clippy::similar_names)]
    pub fn try_keypair(
        mut option: KeyGenOption<ManagedSecretKey<C>>,
    ) -> Result<(PublicKey<C::Engine>, ManagedSecretKey<C>), Error> {
        let private_key = match option {
            #[cfg(feature = "rand")]
            KeyGenOption::Random => return Self::random_keypair_from_rng(&mut OsRng),
            KeyGenOption::UseSeed(ref mut seed) => {
                if bls_seed_material_is_all_zero(seed) {
                    seed.zeroize();
                    return Err(bls_seed_material_all_zero_error(
                        "deterministic key generation",
                    ));
                }
                let salt = b"BLS-SIG-KEYGEN-SALT-";
                let secret_key_size = u8::try_from(C::Engine::SECRET_KEY_SIZE)
                    .map_err(|_| Error::KeyGen("BLS secret-key size overflow".into()))?;
                let info = [0u8, secret_key_size];
                let mut extract = HkdfExtract::<Sha256>::new(Some(&salt[..]));
                extract.input_ikm(seed);
                extract.input_ikm(&[0]);
                seed.zeroize();
                let mut okm = Zeroizing::new(vec![0u8; C::Engine::SECRET_KEY_SIZE]);
                let h = extract.finalize().1;
                h.expand(&info[..], okm.as_mut_slice())
                    .map_err(|_| Error::KeyGen("BLS HKDF seed expansion failed".into()))?;
                let deterministic_rng = crate::rng::rng_from_seed_slice(okm.as_slice());
                let secret = SecretKeyVT::<C::Engine>::from_seed(okm.as_slice())
                    .into_split(deterministic_rng);
                ManagedSecretKey::new(&secret)
            }
            KeyGenOption::FromPrivateKey(key) => key,
        };
        let public_key = private_key
            .try_public_key()
            .map_err(|err| Error::KeyGen(err.to_string()))?;
        Ok((public_key, private_key))
    }
    #[cfg(feature = "rand")]
    pub(super) fn random_keypair_from_rng<R>(
        rng: &mut R,
    ) -> Result<(PublicKey<C::Engine>, ManagedSecretKey<C>), Error>
    where
        R: TryCryptoRng,
    {
        let seed = checked_entropy_from_rng("key generation", C::Engine::SECRET_KEY_SIZE, rng)?;
        let split_seed = checked_entropy_from_rng("key split", BLS_RNG_SEED_LEN, rng)?;
        let split_rng = crate::rng::rng_from_seed_slice(split_seed.as_slice());
        let secret = SecretKeyVT::<C::Engine>::from_seed(seed.as_slice()).into_split(split_rng);
        let private_key = ManagedSecretKey::new(&secret);
        let public_key = private_key
            .try_public_key()
            .map_err(|err| Error::KeyGen(err.to_string()))?;
        Ok((public_key, private_key))
    }
    pub fn try_sign(message: &[u8], sk: &ManagedSecretKey<C>) -> Result<Vec<u8>, Error> {
        sk.try_sign_bytes(message)
    }
    pub fn derive_public_key(sk: &ManagedSecretKey<C>) -> Result<PublicKey<C::Engine>, ParseError> {
        sk.try_public_key()
    }
    pub fn verify(
        message: &[u8],
        signature_bytes: &[u8],
        pk: &PublicKey<C::Engine>,
    ) -> Result<(), Error>
    where
        C: VerifyOkCacheAccess,
    {
        // This typed API has always diagnosed all-zero signature material
        // before typed-key identity; keep that order while checking all keys.
        super::canonical::signature_nonzero(signature_bytes)
            .map_err(|failure| Error::from(failure.into_parse_error()))?;
        let pk_bytes = super::canonical::encode(pk)
            .ok_or_else(|| super::canonical::Failure::PublicKeyInvalid.into_parse_error())?;
        let orientation =
            super::uncached::Orientation::for_algorithm(C::ALGORITHM).ok_or(Error::BadSignature)?;
        let key = super::uncached::public_key(orientation, pk_bytes.as_slice())
            .map_err(super::uncached::Rejection::into_error)?;
        let signature = super::uncached::signature(orientation, signature_bytes)
            .map_err(super::uncached::Rejection::into_error)?;
        Self::verify_parsed_inputs(
            message,
            signature_bytes,
            pk_bytes.as_slice(),
            &key,
            &signature,
        )
    }

    /// Verify the generic Signature facade without retaining a decoded key.
    pub(crate) fn verify_bytes(
        message: &[u8],
        signature_bytes: &[u8],
        public_key_bytes: &[u8],
    ) -> Result<(), Error>
    where
        C: VerifyOkCacheAccess,
    {
        let orientation =
            super::uncached::Orientation::for_algorithm(C::ALGORITHM).ok_or(Error::BadSignature)?;
        let (key, signature) =
            super::uncached::prepare_facade(orientation, public_key_bytes, signature_bytes)
                .map_err(super::uncached::Rejection::into_error)?;
        Self::verify_parsed_inputs(message, signature_bytes, public_key_bytes, &key, &signature)
    }

    fn verify_parsed_inputs(
        message: &[u8],
        signature_bytes: &[u8],
        pk_bytes: &[u8],
        key: &super::uncached::PublicKey,
        signature: &super::uncached::Signature,
    ) -> Result<(), Error>
    where
        C: VerifyOkCacheAccess,
    {
        // Canonical and subgroup validation precede every cache lookup.
        let cache_digest = verify_ok_cache_digest(pk_bytes, message, signature_bytes);
        if C::with_verify_ok_cache(|cache| {
            cache.contains_at_digest(cache_digest, pk_bytes, message, signature_bytes)
        }) {
            return Ok(());
        }
        super::uncached::verify_parsed(key, signature, message)
            .map_err(super::uncached::Rejection::into_error)?;
        C::with_verify_ok_cache(|cache| {
            cache.remember_at_digest(cache_digest, pk_bytes, message, signature_bytes);
        });
        Ok(())
    }
    /// Aggregate-style verification for the case where all signers signed the same message.
    /// Performs one deterministic aggregate check after the public wrappers have validated a
    /// proof of possession for every signer.
    /// Rejects aggregates whose combined signature or public key is the identity element.
    pub(crate) fn verify_aggregate_same_message(
        message: &[u8],
        signatures: &[&[u8]],
        public_keys: &[&[u8]],
    ) -> Result<(), Error> {
        use core::ops::AddAssign as _;
        if signatures.is_empty() || signatures.len() != public_keys.len() {
            return Err(Error::BadSignature);
        }
        let identity_pk = PublicKey::<C::Engine>(Default::default()).to_bytes();
        let parse_signature = |bytes: &[u8]| -> Result<BlsSignature<C::Engine>, Error> {
            parse_canonical_bls_signature::<C::Engine>(bytes)
        };
        let identity_sig = BlsSignature::<C::Engine>(Default::default()).to_bytes();
        // Parse and aggregate signatures
        let mut sig_it = signatures.iter();
        let first_sig_bytes = sig_it.next().ok_or(Error::BadSignature)?;
        let first_sig = parse_signature(first_sig_bytes)?;
        let mut agg_sig_group = first_sig.0;
        for s in sig_it {
            let sig = parse_signature(s)?;
            agg_sig_group.add_assign(&sig.0);
        }
        let agg_sig = BlsSignature::<C::Engine>(agg_sig_group);
        if agg_sig.to_bytes() == identity_sig {
            return Err(Error::BadSignature);
        }
        // Parse and aggregate public keys; enforce unique signers.
        let mut seen_pks = BTreeSet::new();
        let mut pk_it = public_keys.iter();
        let first_pk_bytes = pk_it.next().ok_or(Error::BadSignature)?;
        let first_pk = Self::parse_public_key(first_pk_bytes)?;
        if !seen_pks.insert(*first_pk_bytes) {
            return Err(Error::BadSignature);
        }
        let mut agg_pk_group = first_pk.0;
        for pk_bytes in pk_it {
            let pk = Self::parse_public_key(pk_bytes)?;
            if !seen_pks.insert(*pk_bytes) {
                return Err(Error::BadSignature);
            }
            agg_pk_group.add_assign(&pk.0);
        }
        let agg_pk = PublicKey::<C::Engine>(agg_pk_group);
        if agg_pk.to_bytes() == identity_pk {
            return Err(Error::BadSignature);
        }
        let message = w3f_bls::Message::new(MESSAGE_CONTEXT, message);
        if !agg_sig.verify(&message, &agg_pk) {
            return Err(Error::BadSignature);
        }
        Ok(())
    }
    /// Aggregate a sequence of BLS signatures (same-message context) into a single signature.
    /// The caller is responsible for ensuring all signatures are valid and belong to the same
    /// scheme/engine variant. Rejects aggregates that cancel to the identity element.
    pub fn aggregate_signatures(signatures: &[&[u8]]) -> Result<Vec<u8>, Error> {
        use core::ops::AddAssign as _;
        if signatures.is_empty() {
            return Err(Error::BadSignature);
        }
        let identity_sig = BlsSignature::<C::Engine>(Default::default()).to_bytes();
        let parse_signature = |bytes: &[u8]| -> Result<BlsSignature<C::Engine>, Error> {
            parse_canonical_bls_signature::<C::Engine>(bytes)
        };
        let mut sig_it = signatures.iter();
        let first_sig_bytes = sig_it.next().ok_or(Error::BadSignature)?;
        let first_sig = parse_signature(first_sig_bytes)?;
        let mut agg_sig_group = first_sig.0;
        for s in sig_it {
            let sig = parse_signature(s)?;
            agg_sig_group.add_assign(&sig.0);
        }
        let agg_sig = BlsSignature::<C::Engine>(agg_sig_group);
        let agg_sig_bytes = agg_sig.to_bytes();
        if agg_sig_bytes == identity_sig {
            return Err(Error::BadSignature);
        }
        Ok(agg_sig_bytes)
    }
    /// Verify a pre-aggregated signature for the case where all signers signed the same message.
    /// Public keys are aggregated inside this function and a single pairing check is performed.
    pub(crate) fn verify_preaggregated_same_message(
        message: &[u8],
        aggregated_signature: &[u8],
        public_keys: &[&[u8]],
    ) -> Result<(), Error> {
        use core::ops::AddAssign as _;
        if public_keys.is_empty() {
            return Err(Error::BadSignature);
        }
        let sig = parse_canonical_bls_signature::<C::Engine>(aggregated_signature)?;
        let identity_pk = PublicKey::<C::Engine>(Default::default()).to_bytes();
        // Aggregate public keys; enforce unique signers.
        let mut seen_pks = BTreeSet::new();
        let mut pk_it = public_keys.iter();
        let first_pk_bytes = pk_it.next().ok_or(Error::BadSignature)?;
        let first_pk = Self::parse_public_key(first_pk_bytes)?;
        if !seen_pks.insert(*first_pk_bytes) {
            return Err(Error::BadSignature);
        }
        let mut agg_pk_group = first_pk.0;
        for pk_bytes in pk_it {
            let pk = Self::parse_public_key(pk_bytes)?;
            if !seen_pks.insert(*pk_bytes) {
                return Err(Error::BadSignature);
            }
            agg_pk_group.add_assign(&pk.0);
        }
        let agg_pk = PublicKey::<C::Engine>(agg_pk_group);
        if agg_pk.to_bytes() == identity_pk {
            return Err(Error::BadSignature);
        }
        let message = w3f_bls::Message::new(MESSAGE_CONTEXT, message);
        if !sig.verify(&message, &agg_pk) {
            return Err(Error::BadSignature);
        }
        Ok(())
    }
    /// Verify one pre-aggregated signature over several distinct messages, each signed by a
    /// group of already parsed public keys: the keys of every group are summed and one
    /// multi-pairing checks `e(σ, g) = Π_i e(apk_i, H(m_i))`.
    ///
    /// The caller guarantees that every key's proof of possession verified (the keys of one
    /// group sign the same message, so aggregation is rogue-key safe only with `PoPs`), that
    /// the messages are distinct and that no key repeats inside a group. Rejects an empty
    /// group list, an empty group and a group whose key sum is the identity element.
    #[cfg(test)]
    pub(crate) fn verify_preaggregated_multi_message(
        groups: &[PublicKeyGroup<'_, C::Engine>],
        aggregated_signature: &[u8],
    ) -> Result<(), Error> {
        use core::ops::AddAssign as _;
        if groups.is_empty() {
            return Err(Error::BadSignature);
        }
        let signature = parse_canonical_bls_signature::<C::Engine>(aggregated_signature)?;
        let identity_pk = PublicKey::<C::Engine>(Default::default()).to_bytes();
        let mut inputs = Vec::with_capacity(groups.len());
        for (keys, message) in groups {
            let (first, rest) = keys.split_first().ok_or(Error::BadSignature)?;
            let mut sum = first.0;
            for key in rest {
                sum.add_assign(&key.0);
            }
            let aggregate = PublicKey::<C::Engine>(sum);
            if aggregate.to_bytes() == identity_pk {
                return Err(Error::BadSignature);
            }
            let message = w3f_bls::Message::new(MESSAGE_CONTEXT, message);
            inputs.push((
                <C::Engine as EngineBLS>::prepare_public_key(aggregate.0),
                <C::Engine as EngineBLS>::prepare_signature(
                    message.hash_to_signature_curve::<C::Engine>(),
                ),
            ));
        }
        let prepared_signature = <C::Engine as EngineBLS>::prepare_signature(signature.0);
        if !<C::Engine as EngineBLS>::verify_prepared(prepared_signature, &inputs) {
            return Err(Error::BadSignature);
        }
        Ok(())
    }
    pub fn parse_public_key(payload: &[u8]) -> Result<PublicKey<C::Engine>, ParseError> {
        super::canonical::public_key::<C::Engine>(payload)
            .map(|(key, _)| key)
            .map_err(super::canonical::Failure::into_parse_error)
    }
    /// Validate with the same canonical point relation without formatting a diagnostic.
    pub(crate) fn validate_public_key_for_decode(
        payload: &[u8],
    ) -> Result<(), super::canonical::Failure> {
        super::canonical::public_key::<C::Engine>(payload).map(drop)
    }
    pub fn parse_private_key(payload: &[u8]) -> Result<ManagedSecretKey<C>, ParseError> {
        let key = ManagedSecretKey::from_bytes(payload)?;
        let identity = PublicKey::<C::Engine>(Default::default());
        if key.try_public_key()?.to_bytes() == identity.to_bytes() {
            return Err(ParseError::Invalid("BLS secret key is zero".to_string()));
        }
        Ok(key)
    }
}
impl<C: BlsConfiguration + VerifyOkCacheAccess + ?Sized> BlsImpl<C> {
    /// Verify each signature against its paired distinct message and public key.
    ///
    /// A sum-only aggregate verdict is insufficient for a slice API because it
    /// does not prove that each supplied signature is valid on its own.
    pub fn verify_aggregate_multi_message(
        messages: &[&[u8]],
        signatures: &[&[u8]],
        public_keys: &[&[u8]],
    ) -> Result<(), Error> {
        if !(messages.len() == signatures.len() && signatures.len() == public_keys.len())
            || messages.is_empty()
        {
            return Err(Error::BadSignature);
        }
        ensure_distinct_messages(messages)?;
        for ((message, signature_bytes), public_key_bytes) in messages
            .iter()
            .zip(signatures.iter())
            .zip(public_keys.iter())
        {
            let public_key = Self::parse_public_key(public_key_bytes)?;
            Self::verify(message, signature_bytes, &public_key)?;
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "rand")]
    use rand_core::{TryCryptoRng, TryRngCore};
    const SEEDED_KEYGEN_REFERENCE_SEED: &[u8] = b"iroha-bls-seeded-keygen-reference";
    #[test]
    fn verify_ok_cache_confirms_exact_triple_inside_collision_bucket() {
        let mut cache = VerifyOkCache::new();
        let forced_digest = [0xA5; 32];
        let public_key = b"public-key";
        let message = b"m";
        let signature = b"signature";
        let spliced_message = b"ms";
        let spliced_signature = b"ignature";
        cache.remember_at_digest(forced_digest, public_key, message, signature);
        assert!(cache.contains_at_digest(forced_digest, public_key, message, signature));
        assert!(
            !cache.contains_at_digest(
                forced_digest,
                public_key,
                spliced_message,
                spliced_signature,
            ),
            "a shared digest must not make a different byte triple a cache hit"
        );
        assert!(
            !cache.contains_at_digest(forced_digest, b"other-key", message, signature),
            "the exact public key is part of every cached verdict"
        );
        cache.remember_at_digest(
            forced_digest,
            public_key,
            spliced_message,
            spliced_signature,
        );
        assert!(cache.contains_at_digest(
            forced_digest,
            public_key,
            spliced_message,
            spliced_signature,
        ));
        assert_eq!(cache.insertion_order.len(), 2);
    }
    #[test]
    fn verify_ok_cache_digest_frames_variable_length_fields() {
        let public_key = b"public-key";
        assert_ne!(
            verify_ok_cache_digest(public_key, b"m", b"signature"),
            verify_ok_cache_digest(public_key, b"ms", b"ignature"),
            "moving bytes across message/signature boundaries must change the digest"
        );
    }
    #[test]
    fn verify_ok_cache_does_not_retain_oversized_triples() {
        let mut cache = VerifyOkCache::new();
        let oversized_message = vec![0x42; VERIFY_OK_CACHE_INPUT_BYTES_LIMIT];
        cache.remember_at_digest([0x5A; 32], b"pk", &oversized_message, b"signature");
        assert!(cache.entries.is_empty());
        assert!(cache.insertion_order.is_empty());
        assert_eq!(cache.retained_input_bytes, 0);
    }
    #[test]
    fn verify_ok_cache_evicts_the_exact_oldest_entry() {
        let mut cache = VerifyOkCache::new();
        let first_digest = [0x11; 32];
        let second_digest = [0x22; 32];
        cache.remember_at_digest(first_digest, b"pk-1", b"message-1", b"signature-1");
        cache.remember_at_digest(second_digest, b"pk-2", b"message-2", b"signature-2");
        let retained_before = cache.retained_input_bytes;
        assert!(cache.evict_oldest());
        assert!(!cache.contains_at_digest(first_digest, b"pk-1", b"message-1", b"signature-1"));
        assert!(cache.contains_at_digest(second_digest, b"pk-2", b"message-2", b"signature-2"));
        assert!(cache.retained_input_bytes < retained_before);
    }
    #[cfg(feature = "rand")]
    struct FillSequenceTryRng {
        fills: [u8; 2],
        next_fill: usize,
    }
    #[cfg(feature = "rand")]
    impl TryRngCore for FillSequenceTryRng {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(u32::from_le_bytes([self.fills[self.next_fill.min(1)]; 4]))
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(u64::from_le_bytes([self.fills[self.next_fill.min(1)]; 8]))
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
            let fill = self.fills[self.next_fill.min(1)];
            self.next_fill = self.next_fill.saturating_add(1);
            dest.fill(fill);
            Ok(())
        }
    }
    #[cfg(feature = "rand")]
    impl TryCryptoRng for FillSequenceTryRng {}
    fn reference_seeded_keypair<C: BlsConfiguration>() -> (PublicKey<C::Engine>, ManagedSecretKey<C>)
    {
        let salt = b"BLS-SIG-KEYGEN-SALT-";
        let secret_key_size =
            u8::try_from(C::Engine::SECRET_KEY_SIZE).expect("BLS secret-key size fits u8");
        let info = [0u8, secret_key_size];
        let mut seed = SEEDED_KEYGEN_REFERENCE_SEED.to_vec();
        let mut ikm = vec![0u8; seed.len() + 1];
        ikm[..seed.len()].copy_from_slice(&seed);
        seed.zeroize();
        let mut okm = vec![0u8; C::Engine::SECRET_KEY_SIZE];
        let h = hkdf::Hkdf::<Sha256>::new(Some(&salt[..]), &ikm);
        h.expand(&info, &mut okm)
            .expect("reference BLS HKDF expands");
        ikm.zeroize();
        let deterministic_rng = crate::rng::rng_from_seed_slice(&okm);
        let secret = SecretKeyVT::<C::Engine>::from_seed(&okm).into_split(deterministic_rng);
        okm.zeroize();
        let private = ManagedSecretKey::new(&secret);
        let public = private
            .try_public_key()
            .expect("reference public key derives");
        (public, private)
    }
    fn assert_seeded_keypair_matches_reference_ikm<C: BlsConfiguration>() {
        let (public, private) =
            BlsImpl::<C>::try_keypair(KeyGenOption::UseSeed(SEEDED_KEYGEN_REFERENCE_SEED.to_vec()))
                .expect("streaming BLS keypair derives");
        let (reference_public, reference_private) = reference_seeded_keypair::<C>();
        assert_eq!(public.to_bytes(), reference_public.to_bytes());
        assert_eq!(private.to_bytes(), reference_private.to_bytes());
    }
    fn assert_managed_secret_clone_preserves_bytes<C: BlsConfiguration>() {
        let (public, private) = BlsImpl::<C>::try_keypair(KeyGenOption::UseSeed(
            b"iroha-bls-managed-secret-clone".to_vec(),
        ))
        .expect("BLS keypair derives");
        let clone = private.clone();
        assert_eq!(private.to_bytes(), clone.to_bytes());
        assert_eq!(private.to_bytes().as_slice(), clone.to_bytes().as_slice());
        assert_eq!(
            public.to_bytes(),
            clone
                .try_public_key()
                .expect("clone public key derives")
                .to_bytes()
        );
    }
    fn assert_managed_secret_from_bytes_rejects_all_zero_material<C: BlsConfiguration>() {
        let err = match ManagedSecretKey::<C>::from_bytes(&[0u8; 32]) {
            Ok(_) => panic!("all-zero BLS managed secret material must fail"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("all zero"),
            "unexpected all-zero BLS managed secret error: {err:?}"
        );
    }
    #[test]
    fn seeded_keygen_hkdf_extract_streaming_matches_reference_ikm() {
        assert_seeded_keypair_matches_reference_ikm::<NormalConfiguration>();
        assert_seeded_keypair_matches_reference_ikm::<SmallConfiguration>();
    }
    #[test]
    fn managed_secret_clone_preserves_bytes() {
        assert_managed_secret_clone_preserves_bytes::<NormalConfiguration>();
        assert_managed_secret_clone_preserves_bytes::<SmallConfiguration>();
    }
    #[test]
    fn managed_secret_from_bytes_rejects_all_zero_material() {
        assert_managed_secret_from_bytes_rejects_all_zero_material::<NormalConfiguration>();
        assert_managed_secret_from_bytes_rejects_all_zero_material::<SmallConfiguration>();
    }
    #[test]
    fn managed_secret_zeroize_destroys_key_material() {
        let (_public, mut private) = BlsImpl::<NormalConfiguration>::try_keypair(
            KeyGenOption::UseSeed(b"iroha-bls-managed-secret-zeroize".to_vec()),
        )
        .expect("BLS keypair derives");
        private.zeroize();
        assert!(private.as_bytes().iter().all(|&byte| byte == 0));
        assert!(private.try_public_key().is_err());
        assert!(BlsImpl::<NormalConfiguration>::try_sign(b"must not sign", &private).is_err());
    }
    #[cfg(feature = "rand")]
    #[test]
    fn random_keypair_from_rng_rejects_all_zero_split_seed() {
        let mut rng = FillSequenceTryRng {
            fills: [0x42, 0],
            next_fill: 0,
        };
        match BlsImpl::<NormalConfiguration>::random_keypair_from_rng(&mut rng) {
            Err(Error::KeyGen(message)) => {
                assert!(message.contains("key split"));
                assert!(message.contains("all zero"));
            }
            Err(err) => panic!("expected all-zero split-seed KeyGen error, got {err:?}"),
            Ok(_) => panic!("all-zero BLS key-split seed material must fail"),
        }
    }
    #[cfg(feature = "rand")]
    #[test]
    fn try_sign_bytes_with_rng_rejects_all_zero_split_seed() {
        let (_public, private) = BlsImpl::<NormalConfiguration>::try_keypair(
            KeyGenOption::UseSeed(b"iroha-bls-signing-split-seed".to_vec()),
        )
        .expect("seeded BLS keypair derives");
        let mut rng = FillSequenceTryRng {
            fills: [0, 0],
            next_fill: 0,
        };
        match private
            .try_sign_fixed_with_rng(b"iroha-bls-message", &mut rng)
            .map_err(super::super::signing::BlsSigningError::into_public_error)
        {
            Err(Error::Signing(message)) => {
                assert!(message.contains("signing key split"));
                assert!(message.contains("all zero"));
            }
            Err(err) => panic!("expected all-zero signing seed error, got {err:?}"),
            Ok(_) => panic!("all-zero BLS signing split seed material must fail"),
        }
    }
}
