//! Consensus BLS signing suite (`specs/sumeragi.md` §1 item 6, `specs/sccp.md` §3.8).
//!
//! Sumeragi signatures of kinds `0x01`–`0x05` and the RS16 availability statements are made
//! and checked only through this module. A signature is `σ = sk · hash_to_G2(m, DST_SIG)`
//! over `m = SHA-256(P)`, where `P` is a preimage admitted by
//! [`ConsensusDigest::from_preimage`] and [`DST_SIG`] is the IETF min-pk
//! proof-of-possession ciphersuite tag (RFC 9380 `hash_to_curve`, `expand_message_xmd`
//! with SHA-256, no augmentation). Keys are BLS-normal: 48-byte compressed G1 public keys
//! and 96-byte compressed G2 signatures.
//!
//! Domain separation:
//! - No other API of this crate signs under `DST_SIG`. Every other BLS-normal signature,
//!   including the generic [`crate::Signature`] API and the consensus-key proof of
//!   possession, keeps the w3f transcript (one-byte hash-to-field DST `[1]` and the
//!   `BLS_SIG_..._NUL_for signing messages` prefix), so a signature from another context
//!   never verifies here and a consensus signature never verifies there. The only other
//!   user of the same tag is the Ethereum sync-committee verifier
//!   ([`crate::ETHEREUM_BLS_POP_DST`]): a separate verify-only API over Ethereum keys that
//!   shares only hash-to-curve with this module and produces no signature.
//! - A [`ConsensusDigest`] can be built only from an allowlisted preimage, so the signer
//!   refuses every other message. Kind `0x06` (`att_preimage`) is not allowlisted.
//!
//! Rogue keys: [`verify_fast_aggregate`] and [`verify_aggregate_multi`] take
//! [`BlsNormalPopVerifiedKey`], whose w3f proof of possession (unchanged) was verified at
//! admission; [`verify_fast_aggregate_committed`] takes keys committed by an authenticated
//! committee root and applies [`key_validate`] to each.
//!
//! Custody: every verifier runs on one `blst` pairing context. The free functions allocate
//! an unfunded context per call; [`ConsensusAggregateScratch`] is the same relation on a
//! context whose exact backing the caller admits first (the consensus counterpart of
//! [`crate::BlsNormalAggregateScratch`]), and its verification allocates nothing.
//!
//! `TODO:` unify every other BLS signature on RFC 9380 suites in a later release.
//! `TODO(WP-C1):` route the production Sumeragi `Signer`/`Crypto` implementations
//! (`KeyPairSigner`, `BlsCrypto`, `ProofCrypto`, and the signers delegating to them) through
//! this module; until then they still sign and verify consensus messages with the w3f
//! transcript (`specs/sumeragi.md` §1 item 6, planned case SC4). `BlsCrypto`'s request-funded
//! `BlsNormalAggregateScratch` becomes a [`ConsensusAggregateScratch`] admitted the same way.

use core::borrow::Borrow;

use blst::{Pairing, blst_fp12, blst_p2_affine};
use blstrs::{G1Affine, G1Projective, G2Affine, G2Projective};
use group::{Curve as _, Group as _, prime::PrimeCurveAffine as _};
use sha2::{Digest as _, Sha256};

use crate::{BlsNormalPopVerifiedKey, Error, PrivateKey, PrivateKeyInner};

/// IETF min-pk proof-of-possession ciphersuite tag, reserved to this module (43 bytes).
pub const DST_SIG: &[u8; 43] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Length of a compressed consensus public key (G1).
pub const PUBLIC_KEY_LEN: usize = 48;
/// Length of a compressed consensus signature or aggregate signature (G2).
pub const SIGNATURE_LEN: usize = 96;

/// `TAG_SIG` of `specs/sumeragi.md` §3.1.
const TAG_SIG: &[u8] = b"sumeragi/sig";
/// Statement tag of the RS16 availability manifest and rows (`specs/sumeragi.md` §12.8).
const TAG_AVAILABILITY_SIGN: &[u8] = b"sumeragi/availability/sign";
/// `TAG_SIG ‖ kind ‖ I ‖ be64(epoch) ‖ epoch_context`.
const SIG_PREFIX_LEN: usize = TAG_SIG.len() + 1 + 32 + 8 + 32;
/// Offset of the `enc(hq)` discriminant in a timeout preimage.
const TIMEOUT_HQ_OFFSET: usize = SIG_PREFIX_LEN + 8 + 8;

/// One row of the consensus allowlist (`specs/sumeragi.md` §1 item 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ConsensusContext {
    /// `prop_preimage`: `TAG_SIG ‖ 0x01`, 165 bytes.
    Proposal,
    /// `vote_preimage(0x02, …)`: `TAG_SIG ‖ 0x02`, 165 bytes.
    Prepare,
    /// `vote_preimage(0x03, …)`: `TAG_SIG ‖ 0x03`, 165 bytes (frozen, `specs/sumeragi.md` §3.3.1).
    Commit,
    /// `tmo_preimage(…, None)`: `TAG_SIG ‖ 0x04`, 102 bytes with byte 101 = `0x00`.
    TimeoutWithoutHighQc,
    /// `tmo_preimage(…, Some(hq))`: `TAG_SIG ‖ 0x04`, 110 bytes with byte 101 = `0x01`.
    TimeoutWithHighQc,
    /// `echo_preimage`: `TAG_SIG ‖ 0x05`, 101 bytes.
    Echo,
    /// RS16 `statement(0)`: `"sumeragi/availability/sign" ‖ 0x00`, 179 bytes.
    AvailabilityManifest,
    /// RS16 `statement(1) ‖ be32(i) ‖ be32(len) ‖ row_hash`: `… ‖ 0x01`, 219 bytes.
    AvailabilityRow,
}

impl ConsensusContext {
    /// Every allowlist row, in table order.
    pub const ALL: [Self; 8] = [
        Self::Proposal,
        Self::Prepare,
        Self::Commit,
        Self::TimeoutWithoutHighQc,
        Self::TimeoutWithHighQc,
        Self::Echo,
        Self::AvailabilityManifest,
        Self::AvailabilityRow,
    ];

    /// The row that `preimage` matches exactly, or `None` if it is not allowlisted.
    #[must_use]
    pub fn of_preimage(preimage: &[u8]) -> Option<Self> {
        if let Some(rest) = preimage.strip_prefix(TAG_SIG) {
            let context = match (rest.first().copied()?, preimage.len()) {
                (0x01, 165) => Self::Proposal,
                (0x02, 165) => Self::Prepare,
                (0x03, 165) => Self::Commit,
                (0x04, 102) if preimage[TIMEOUT_HQ_OFFSET] == 0x00 => Self::TimeoutWithoutHighQc,
                (0x04, 110) if preimage[TIMEOUT_HQ_OFFSET] == 0x01 => Self::TimeoutWithHighQc,
                (0x05, 101) => Self::Echo,
                _ => return None,
            };
            return Some(context);
        }
        let rest = preimage.strip_prefix(TAG_AVAILABILITY_SIGN)?;
        match (rest.first().copied()?, preimage.len()) {
            (0x00, 179) => Some(Self::AvailabilityManifest),
            (0x01, 219) => Some(Self::AvailabilityRow),
            _ => None,
        }
    }

    /// The exact preimage length of this row.
    #[must_use]
    pub const fn preimage_len(self) -> usize {
        match self {
            Self::Proposal | Self::Prepare | Self::Commit => 165,
            Self::TimeoutWithoutHighQc => 102,
            Self::TimeoutWithHighQc => 110,
            Self::Echo => 101,
            Self::AvailabilityManifest => 179,
            Self::AvailabilityRow => 219,
        }
    }
}

/// `m = SHA-256(P)` of an allowlisted consensus preimage `P`.
///
/// The only constructor is [`ConsensusDigest::from_preimage`], so holding a digest proves
/// that its preimage matched one allowlist row exactly; [`sign`] cannot be asked to sign any
/// other message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConsensusDigest([u8; 32]);

impl ConsensusDigest {
    /// `Some(SHA-256(preimage))` iff `preimage` matches one allowlist row exactly
    /// ([`ConsensusContext::of_preimage`]); `None` otherwise.
    #[must_use]
    pub fn from_preimage(preimage: &[u8]) -> Option<Self> {
        ConsensusContext::of_preimage(preimage).map(|_| Self(Sha256::digest(preimage).into()))
    }

    /// The 32-byte message `m` that is hashed to G2 under [`DST_SIG`].
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// An arbitrary 32-byte message, for the standard-suite vectors only.
    #[cfg(test)]
    pub(crate) const fn from_raw_for_test(message: [u8; 32]) -> Self {
        Self(message)
    }
}

/// Sign an allowlisted consensus digest with a BLS-normal private key.
///
/// The signature is unique for the key and digest (the scalar is blinded internally, which
/// does not change the result).
///
/// # Errors
/// [`Error::Signing`] if `private_key` is not BLS-normal or its scalar cannot be decoded,
/// or if the signing entropy source fails.
pub fn sign(private_key: &PrivateKey, digest: &ConsensusDigest) -> Result<[u8; 96], Error> {
    use crate::secrecy::ExposeSecret as _;
    match private_key.0.expose_secret() {
        PrivateKeyInner::BlsNormal(secret) => {
            super::signing::sign_consensus(secret.as_bytes(), digest)
                .map_err(super::signing::BlsSigningError::into_public_error)
        }
        _ => Err(Error::Signing(
            "consensus signatures require a BLS-normal private key".to_owned(),
        )),
    }
}

/// Sign the consensus preimage `preimage` (`sign(sk, SHA-256(P))`).
///
/// # Errors
/// [`Error::Signing`] if `preimage` is not allowlisted, and every error of [`sign`].
pub fn sign_preimage(private_key: &PrivateKey, preimage: &[u8]) -> Result<[u8; 96], Error> {
    let digest = ConsensusDigest::from_preimage(preimage).ok_or_else(|| {
        Error::Signing("preimage is not an allowlisted consensus signing context".to_owned())
    })?;
    sign(private_key, &digest)
}

/// `KeyValidate`: the encoding is canonical, on the curve, in the G1 subgroup and not the
/// identity.
#[must_use]
pub fn key_validate(public_key: &[u8; 48]) -> bool {
    parse_public_key(public_key).is_some()
}

/// Verify one consensus signature by a PoP-admitted key.
#[must_use]
pub fn verify(
    public_key: &BlsNormalPopVerifiedKey,
    digest: &ConsensusDigest,
    signature: &[u8; 96],
) -> bool {
    verify_fast_aggregate(&[public_key], digest, signature)
}

/// `FastAggregateVerify` over PoP-admitted keys.
///
/// Accepts iff `keys` is non-empty and holds no repeated key, `apk = Σ PK_i ≠ O`, the
/// aggregate is a canonical, in-subgroup, non-identity point and
/// `e(apk, H(m)) = e(g1, σ)`.
#[must_use]
pub fn verify_fast_aggregate(
    keys: &[&BlsNormalPopVerifiedKey],
    digest: &ConsensusDigest,
    aggregate: &[u8; 96],
) -> bool {
    unfunded_scratch().verify_fast_aggregate(keys.iter().copied(), digest, aggregate)
}

/// `AggregateVerify` over groups: each group of PoP-admitted keys signed its own digest
/// (timeout certificates group their signers by the high-QC view).
///
/// Accepts iff there is at least one group, every group is non-empty with no repeated key and
/// a non-identity key sum, the digests are pairwise distinct, the aggregate is a canonical,
/// in-subgroup, non-identity point and `e(g1, σ) = Π_g e(apk_g, H(m_g))`. The same key may
/// appear in different groups.
#[must_use]
pub fn verify_aggregate_multi(
    groups: &[(&[&BlsNormalPopVerifiedKey], ConsensusDigest)],
    aggregate: &[u8; 96],
) -> bool {
    unfunded_scratch().verify_aggregate_multi(
        groups
            .iter()
            .map(|(keys, digest)| (keys.iter().copied(), *digest)),
        aggregate,
    )
}

/// `FastAggregateVerify` over keys committed by an authenticated committee root (destination
/// emulation, Taira forgery evidence): steps 7–9 of the `specs/sccp.md` §3.8 destination
/// verification relation exactly.
///
/// Accepts iff `keys` is non-empty, every key passes [`key_validate`], `apk = Σ PK_i ≠ O`,
/// the aggregate is a canonical, in-subgroup, non-identity point and `e(apk, H(m)) =
/// e(g1, σ)`. The caller MUST take `keys` from an authenticated committee root; that root's
/// strict key ordering is what excludes repeated keys and rogue keys. Steps 1–6 stay with the
/// caller: `n ∈ {4, 7, …, 31}`, no signer bit at or above `n`, `popcount(signers) = q = n − f`
/// exactly, `keys` selected by the LSB-first bitmap in canonical order, and `digest` built from
/// the kind-`0x03` Commit preimage.
#[must_use]
pub fn verify_fast_aggregate_committed(
    keys: &[[u8; 48]],
    digest: &ConsensusDigest,
    aggregate: &[u8; 96],
) -> bool {
    unfunded_scratch().verify_fast_aggregate_committed(keys, digest, aggregate)
}

/// Reusable consensus-suite verifier with one explicitly admitted `blst` pairing context.
///
/// The consensus counterpart of [`crate::BlsNormalAggregateScratch`], with the relations of
/// [`verify_fast_aggregate`], [`verify_aggregate_multi`] and
/// [`verify_fast_aggregate_committed`] (those functions run on an unfunded instance). The
/// caller admits the exact pairing backing before it is allocated and keeps the returned
/// owner for the verifier's lifetime; the backing is released before that owner. Verification
/// borrows the keys and allocates no heap memory, and each call resets the context, so a
/// rejected input never affects a later verdict.
#[derive(Debug)]
#[must_use = "dropping the verifier releases its pairing backing and custody token"]
pub struct ConsensusAggregateScratch<O = ()> {
    // Declaration order is intentional: release the backing before its funding.
    pairing: Pairing,
    _owner: O,
}

impl<O> ConsensusAggregateScratch<O> {
    /// Exact heap backing bytes of the `blst` pairing context.
    #[must_use]
    pub fn backing_bytes() -> usize {
        crate::BlsNormalAggregateScratch::<()>::backing_bytes()
    }

    /// Admit the exact backing before allocating it and retain the returned owner.
    ///
    /// # Errors
    /// Returns the caller's unchanged refusal; nothing is allocated then.
    pub fn new<E>(admit: impl FnOnce(usize) -> Result<O, E>) -> Result<Self, E> {
        let owner = admit(Self::backing_bytes())?;
        Ok(Self {
            pairing: Pairing::new(true, DST_SIG),
            _owner: owner,
        })
    }

    /// [`verify_fast_aggregate`] on this context. `keys` must replay the same keys in the
    /// same order when cloned; it is rescanned for repeated keys.
    #[must_use]
    pub fn verify_fast_aggregate<'a, K>(
        &mut self,
        keys: K,
        digest: &ConsensusDigest,
        aggregate: &[u8; 96],
    ) -> bool
    where
        K: Iterator<Item = &'a BlsNormalPopVerifiedKey> + Clone,
    {
        if keys.clone().next().is_none() || has_repeated_key(&keys) {
            return false;
        }
        let apk = keys.fold(G1Projective::identity(), |sum, key| sum + key.point);
        self.relation(core::iter::once((apk, *digest)), aggregate)
    }

    /// [`verify_aggregate_multi`] on this context. `groups` and each key iterator must replay
    /// the same items in the same order when cloned; they are rescanned for repeated digests
    /// and keys.
    #[must_use]
    pub fn verify_aggregate_multi<'a, G, K>(&mut self, groups: G, aggregate: &[u8; 96]) -> bool
    where
        G: Iterator<Item = (K, ConsensusDigest)> + Clone,
        K: Iterator<Item = &'a BlsNormalPopVerifiedKey> + Clone,
    {
        if groups.clone().next().is_none() {
            return false;
        }
        for (index, (keys, digest)) in groups.clone().enumerate() {
            if keys.clone().next().is_none()
                || has_repeated_key(&keys)
                || groups.clone().take(index).any(|(_, prior)| prior == digest)
            {
                return false;
            }
        }
        self.relation(
            groups.map(|(keys, digest)| {
                let apk = keys.fold(G1Projective::identity(), |sum, key| sum + key.point);
                (apk, digest)
            }),
            aggregate,
        )
    }

    /// [`verify_fast_aggregate_committed`] on this context.
    #[must_use]
    pub fn verify_fast_aggregate_committed(
        &mut self,
        keys: &[[u8; 48]],
        digest: &ConsensusDigest,
        aggregate: &[u8; 96],
    ) -> bool {
        if keys.is_empty() {
            return false;
        }
        let mut apk = G1Projective::identity();
        for key in keys {
            let Some(point) = parse_public_key(key) else {
                return false;
            };
            apk += point;
        }
        self.relation(core::iter::once((apk, *digest)), aggregate)
    }

    /// `e(g1, σ) = Π e(apk_i, H(m_i))` over at least one term, every `apk_i ≠ O` and a
    /// canonical, in-subgroup, non-identity `σ`.
    fn relation(
        &mut self,
        terms: impl Iterator<Item = (G1Projective, ConsensusDigest)>,
        aggregate: &[u8; 96],
    ) -> bool {
        self.pairing.init(true, DST_SIG);
        let Some(signature) = parse_signature(aggregate) else {
            return false;
        };
        let mut any = false;
        for (apk, digest) in terms {
            if bool::from(apk.is_identity()) {
                return false;
            }
            let apk = apk.to_affine();
            let message = message_point(&digest);
            self.pairing.raw_aggregate(message.as_ref(), apk.as_ref());
            any = true;
        }
        if !any {
            return false;
        }
        self.pairing.commit();
        let mut signature_pairing = blst_fp12::default();
        let signature: &blst_p2_affine = signature.as_ref();
        Pairing::aggregated(&mut signature_pairing, signature);
        self.pairing.finalverify(Some(&signature_pairing))
    }
}

/// A verifier on a pairing context whose backing nobody funds (the free functions).
fn unfunded_scratch() -> ConsensusAggregateScratch {
    ConsensusAggregateScratch::new(|_| Ok::<_, core::convert::Infallible>(()))
        .unwrap_or_else(|never| match never {})
}

/// Sum consensus signature shares into one aggregate signature.
///
/// # Errors
/// [`Error::BadSignature`] if there is no share, a share is not a canonical, in-subgroup,
/// non-identity point, or the sum is the identity.
pub fn aggregate(
    shares: impl IntoIterator<Item = impl Borrow<[u8; 96]>>,
) -> Result<[u8; 96], Error> {
    let mut count = 0_usize;
    let mut sum = G2Projective::identity();
    for share in shares {
        sum += parse_signature(share.borrow()).ok_or(Error::BadSignature)?;
        count += 1;
    }
    if count == 0 || bool::from(sum.is_identity()) {
        return Err(Error::BadSignature);
    }
    Ok(sum.to_affine().to_compressed())
}

/// `hash_to_curve_G2(m, DST_SIG)` of RFC 9380 (`BLS12381G2_XMD:SHA-256_SSWU_RO_`).
fn message_point(digest: &ConsensusDigest) -> G2Affine {
    G2Projective::hash_to_curve(digest.as_bytes(), DST_SIG, &[]).to_affine()
}

/// A canonical, in-subgroup, non-identity compressed G1 point.
fn parse_public_key(bytes: &[u8; 48]) -> Option<G1Affine> {
    let point = G1Affine::from_compressed(bytes).into_option()?;
    (!bool::from(point.is_identity()) && point.to_compressed() == *bytes).then_some(point)
}

/// A canonical, in-subgroup, non-identity compressed G2 point.
fn parse_signature(bytes: &[u8; 96]) -> Option<G2Affine> {
    let point = G2Affine::from_compressed(bytes).into_option()?;
    (!bool::from(point.is_identity()) && point.to_compressed() == *bytes).then_some(point)
}

/// Whether two entries hold the same public key (an allocation-free quadratic rescan over
/// committee-sized inputs, as in `BlsNormalAggregateScratch`).
fn has_repeated_key<'a, K>(keys: &K) -> bool
where
    K: Iterator<Item = &'a BlsNormalPopVerifiedKey> + Clone,
{
    keys.clone()
        .enumerate()
        .any(|(index, key)| keys.clone().take(index).any(|prior| prior == key))
}

#[cfg(test)]
mod tests;
