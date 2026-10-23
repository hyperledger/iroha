//! Offline dealer-assisted custody of a BGV secret key, not threshold decryption.
//!
//! A trusted dealer consumes the complete key and samples independent Shamir
//! polynomials over every main and special prime. The declared threshold and
//! roster have no relationship to consensus quorum rules. Context and a fresh
//! sharing-instance identifier prevent accidental mixing of epochs or dealer
//! invocations. Each participant receives at most one opaque share from this
//! in-memory dealer. All secret buffers use the existing clearing owners.
//!
//! There is no share codec, untrusted import, decryption contribution, public
//! reconstruction, or network integration. Selection checks cover metadata
//! only; they are not algebraic proofs. Test fixtures alone expose share words
//! for independent interpolation. No BGV profile is qualified by this module.
// TODO(C.4): reviewed malicious-party-secure key generation, authenticated durable
// custody, masked ciphertext-bound contributions and zero-knowledge share verification.
use std::sync::Arc;

use super::{
    BgvError, BgvProfile, SecretKey,
    coins::{COIN_STATE_BYTES, CoinPurpose, Coins, EntropySource, OsEntropy, small_residue},
    fault::{self, FaultPoint},
    poly::RnsPoly,
};
use thiserror::Error;

/// Domain separator for the public threshold context.
pub const THRESHOLD_CONTEXT_DOMAIN: &str = "iroha_fhe bgv v1 offline threshold context";

/// A refusal by the offline key-sharing component.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ThresholdError {
    /// Threshold is zero or greater than the participant count.
    #[error("threshold must be in 1..=participant count")]
    InvalidThreshold,
    /// The roster is empty, too long, unsorted, or has zero/duplicate coordinates.
    #[error("participant coordinates must be nonzero, distinct and strictly ascending")]
    InvalidRoster,
    /// A participant coordinate is not below every RNS prime.
    #[error("participant coordinate is outside an RNS prime field")]
    CoordinateOutOfField,
    /// The supplied profile or key belongs to another profile.
    #[error("threshold context or key belongs to another profile")]
    ProfileMismatch,
    /// Secret-buffer size arithmetic overflowed.
    #[error("threshold secret-buffer size overflow")]
    SizeOverflow,
    /// The caller's secret-buffer ceiling is insufficient.
    #[error("threshold requires {required} secret-buffer bytes, limit is {limit}")]
    SecretBufferLimit {
        /// Peak secret-buffer bytes accounted for by this component.
        required: usize,
        /// Caller-supplied limit.
        limit: usize,
    },
    /// A coordinate is absent from the declared roster.
    #[error("participant is absent from the threshold roster")]
    UnknownParticipant,
    /// This in-memory dealer has already issued this participant's share.
    #[error("participant share has already been issued")]
    AlreadyIssued,
    /// Fewer than the declared threshold were selected.
    #[error("selection has fewer than the declared threshold")]
    InsufficientShares,
    /// A selection contains more shares than participants.
    #[error("selection exceeds the participant count")]
    TooManyShares,
    /// The same participant occurs twice in a selection.
    #[error("selection repeats a participant")]
    DuplicateParticipant,
    /// A selected share has another application context, epoch, threshold or roster.
    #[error("share belongs to another threshold context")]
    ContextMismatch,
    /// A selected share was issued by another dealer invocation.
    #[error("share belongs to another sharing instance")]
    InstanceMismatch,
    /// Sampling failed; no fallback entropy is used.
    #[error(transparent)]
    Bgv(#[from] BgvError),
}

/// Public, immutable declaration of one offline sharing context.
///
/// `key_context` identifies the application/key purpose; it is caller-provided
/// metadata, not proof of a registered public key. `epoch` is equally explicit:
/// this component neither chooses nor advances an application's epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThresholdContext {
    profile: [u8; 32],
    key_context: [u8; 32],
    epoch: u64,
    threshold: u16,
    participants: Vec<u16>,
    identity: [u8; 32],
}

impl ThresholdContext {
    /// Validate a declared `threshold` of the listed participants.
    ///
    /// Coordinates are nonzero field elements in strictly ascending order.
    /// A threshold of one is permitted and provides no threshold secrecy.
    ///
    /// # Errors
    /// Invalid threshold, roster, or coordinates outside any profile prime.
    pub fn new(
        profile: &BgvProfile,
        key_context: [u8; 32],
        epoch: u64,
        threshold: u16,
        participants: Vec<u16>,
    ) -> Result<Self, ThresholdError> {
        if participants.is_empty()
            || participants.len() > usize::from(u16::MAX)
            || participants[0] == 0
            || participants.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(ThresholdError::InvalidRoster);
        }
        if threshold == 0 || usize::from(threshold) > participants.len() {
            return Err(ThresholdError::InvalidThreshold);
        }
        let largest = u64::from(participants[participants.len() - 1]);
        let parameters = profile.parameters();
        if parameters
            .main_primes
            .iter()
            .chain(&parameters.special_primes)
            .any(|&prime| largest >= prime)
        {
            return Err(ThresholdError::CoordinateOutOfField);
        }
        // Only public data enters this hasher; no additional secret-state owner.
        let mut hasher = blake3::Hasher::new_derive_key(THRESHOLD_CONTEXT_DOMAIN);
        hasher.update(&[1]);
        hasher.update(profile.identity());
        hasher.update(&key_context);
        hasher.update(&epoch.to_le_bytes());
        hasher.update(&threshold.to_le_bytes());
        hasher.update(
            &u16::try_from(participants.len())
                .map_err(|_| ThresholdError::InvalidRoster)?
                .to_le_bytes(),
        );
        for participant in &participants {
            hasher.update(&participant.to_le_bytes());
        }
        Ok(Self {
            profile: *profile.identity(),
            key_context,
            epoch,
            threshold,
            participants,
            identity: *hasher.finalize().as_bytes(),
        })
    }

    /// Digest of the exact profile, key context, epoch, threshold and roster.
    #[must_use]
    pub const fn identity(&self) -> &[u8; 32] {
        &self.identity
    }

    /// The application-provided key context; not a public-key validation result.
    #[must_use]
    pub const fn key_context(&self) -> &[u8; 32] {
        &self.key_context
    }

    /// The explicitly declared epoch.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The explicitly declared reconstruction threshold.
    #[must_use]
    pub const fn threshold(&self) -> u16 {
        self.threshold
    }

    /// The ascending, distinct field coordinates of all participants.
    #[must_use]
    pub fn participants(&self) -> &[u16] {
        &self.participants
    }

    /// Check selection metadata against this context and a retained instance ID.
    ///
    /// This does not inspect secret words or prove a decryption relation. It
    /// accepts any distinct subset of size at least the declared threshold,
    /// including a superset. Repeated calls are not durable replay protection.
    ///
    /// # Errors
    /// Insufficient/excessive shares, another context/instance, or a missing or
    /// repeated participant. No selected share is consumed on refusal.
    pub fn validate_selection_metadata(
        &self,
        instance: &[u8; 32],
        shares: &[&SecretKeyShare],
    ) -> Result<(), ThresholdError> {
        if shares.len() < usize::from(self.threshold) {
            return Err(ThresholdError::InsufficientShares);
        }
        if shares.len() > self.participants.len() {
            return Err(ThresholdError::TooManyShares);
        }
        let mut seen = std::collections::BTreeSet::new();
        for share in shares {
            if self.identity() != share.context.identity() {
                return Err(ThresholdError::ContextMismatch);
            }
            if instance != &share.instance {
                return Err(ThresholdError::InstanceMismatch);
            }
            if self.participants.binary_search(&share.participant).is_err() {
                return Err(ThresholdError::UnknownParticipant);
            }
            if !seen.insert(share.participant) {
                return Err(ThresholdError::DuplicateParticipant);
            }
        }
        Ok(())
    }
}

/// One participant's opaque, non-Clone secret share; its word buffer clears on drop.
///
/// Shares have no production export/import or reconstruction interface.
///
/// ```compile_fail
/// use iroha_fhe::bgv::threshold::SecretKeyShare;
/// fn duplicate(share: &SecretKeyShare) -> SecretKeyShare {
///     (*share).clone()
/// }
/// ```
pub struct SecretKeyShare {
    context: Arc<ThresholdContext>,
    instance: [u8; 32],
    participant: u16,
    words: RnsPoly,
}

impl std::fmt::Debug for SecretKeyShare {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecretKeyShare")
            .field("context", self.context.identity())
            .field("instance", &self.instance)
            .field("participant", &self.participant)
            .finish_non_exhaustive()
    }
}

impl SecretKeyShare {
    /// Public context under which this share was issued.
    #[must_use]
    pub fn context(&self) -> &ThresholdContext {
        &self.context
    }

    /// Fresh identifier of the dealer invocation, not a decryption session.
    #[must_use]
    pub const fn instance(&self) -> &[u8; 32] {
        &self.instance
    }

    /// This participant's field coordinate.
    #[must_use]
    pub const fn participant(&self) -> u16 {
        self.participant
    }

    /// Bytes in this share's clearing word buffer, excluding public metadata.
    #[must_use]
    pub fn secret_buffer_bytes(&self) -> usize {
        std::mem::size_of_val(self.words.words())
    }

    #[cfg(any(test, feature = "bgv-test-fixtures"))]
    pub(super) fn words_for_fixture(&self) -> &[u64] {
        self.words.words()
    }
}

/// Material retained only until the dealer is dropped or issues the final share.
struct DealerMaterial {
    key: SecretKey,
    /// Nonconstant coefficients, in increasing polynomial degree.
    polynomials: Vec<RnsPoly>,
}

/// An offline trusted dealer; never a distributed key-generation protocol.
///
/// The complete key is consumed and stays here until drop or final issuance.
/// Neither this owner nor the issued shares implement `Clone`. An incomplete
/// dealer must be dropped explicitly when its offline custody operation ends.
///
/// ```compile_fail
/// use iroha_fhe::bgv::threshold::DealerKeyShares;
/// fn duplicate<'a>(dealer: &DealerKeyShares<'a>) -> DealerKeyShares<'a> {
///     (*dealer).clone()
/// }
/// ```
pub struct DealerKeyShares<'profile> {
    profile: &'profile BgvProfile,
    context: Arc<ThresholdContext>,
    instance: [u8; 32],
    issued: Vec<bool>,
    remaining: usize,
    material: Option<DealerMaterial>,
}

impl std::fmt::Debug for DealerKeyShares<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DealerKeyShares")
            .field("context", self.context.identity())
            .field("instance", &self.instance)
            .field("remaining", &self.remaining())
            .finish_non_exhaustive()
    }
}

impl<'profile> DealerKeyShares<'profile> {
    /// Peak bytes of secret heap buffers retained by the dealer plus one issuance.
    ///
    /// Counts the consumed key's coefficients and evaluation form, `t-1`
    /// sampled polynomials, and the larger of the coin block or one issued
    /// share. Caller-retained shares, public metadata, allocator overhead,
    /// stack/register copies and profile storage are excluded. This is not a
    /// process-memory estimate. Size depends only on public inputs.
    ///
    /// # Errors
    /// Another profile or checked size overflow.
    pub fn required_secret_bytes(
        profile: &BgvProfile,
        context: &ThresholdContext,
    ) -> Result<usize, ThresholdError> {
        if profile.identity() != &context.profile {
            return Err(ThresholdError::ProfileMismatch);
        }
        let parameters = profile.parameters();
        let limbs = parameters.main_primes.len() + parameters.special_primes.len();
        let coefficients = profile
            .degree()
            .checked_mul(size_of::<i64>())
            .ok_or(ThresholdError::SizeOverflow)?;
        let poly = profile
            .degree()
            .checked_mul(limbs)
            .and_then(|words| words.checked_mul(size_of::<u64>()))
            .ok_or(ThresholdError::SizeOverflow)?;
        poly.checked_mul(usize::from(context.threshold))
            .and_then(|bytes| bytes.checked_add(coefficients))
            .and_then(|bytes| bytes.checked_add(poly.max(COIN_STATE_BYTES)))
            .ok_or(ThresholdError::SizeOverflow)
    }

    /// Consume a complete key and create an offline dealer using OS entropy.
    ///
    /// The secret-buffer ceiling is checked before new secret allocations or
    /// entropy use. On refusal the consumed key is dropped and cleared.
    ///
    /// # Errors
    /// Profile mismatch, insufficient secret-buffer limit, or failed/stuck entropy.
    pub fn split(
        profile: &'profile BgvProfile,
        context: ThresholdContext,
        key: SecretKey,
        max_secret_bytes: usize,
    ) -> Result<Self, ThresholdError> {
        Self::split_with(profile, context, key, max_secret_bytes, &mut OsEntropy)
    }

    pub(super) fn split_with(
        profile: &'profile BgvProfile,
        context: ThresholdContext,
        key: SecretKey,
        max_secret_bytes: usize,
        entropy: &mut dyn EntropySource,
    ) -> Result<Self, ThresholdError> {
        let required = Self::required_secret_bytes(profile, &context)?;
        if key.profile_identity() != profile.identity() {
            return Err(ThresholdError::ProfileMismatch);
        }
        if required > max_secret_bytes {
            return Err(ThresholdError::SecretBufferLimit {
                required,
                limit: max_secret_bytes,
            });
        }
        let mut coins = Coins::draw(entropy)?;
        let mut instance = [0_u8; 32];
        coins
            .stream(context.identity(), CoinPurpose::ThresholdInstance, 0, 0)
            .bytes(&mut instance);
        let parameters = profile.parameters();
        // This vector contains public moduli only.
        let primes: Vec<u64> = parameters
            .main_primes
            .iter()
            .chain(&parameters.special_primes)
            .copied()
            .collect();
        let mut polynomials = Vec::with_capacity(usize::from(context.threshold - 1));
        for power in 1..context.threshold {
            let mut poly = RnsPoly::zero(primes.len(), profile.degree());
            coins
                .stream(
                    context.identity(),
                    CoinPurpose::ThresholdPolynomial,
                    u32::from(power),
                    0,
                )
                .uniform(&primes, profile.degree(), poly.words_mut());
            polynomials.push(poly);
            if power == 1 {
                fault::reached(FaultPoint::ThresholdAfterFirstPolynomial);
            }
        }
        Ok(Self {
            profile,
            issued: vec![false; context.participants.len()],
            remaining: context.participants.len(),
            context: Arc::new(context),
            instance,
            material: Some(DealerMaterial { key, polynomials }),
        })
    }

    /// Public context retained even after dealer material has been cleared.
    #[must_use]
    pub fn context(&self) -> &ThresholdContext {
        &self.context
    }

    /// Fresh identifier to retain with an offline selection of shares.
    #[must_use]
    pub const fn instance(&self) -> &[u8; 32] {
        &self.instance
    }

    /// Number of declared participants whose shares have not been issued.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.remaining
    }

    /// Issue one share, rejecting an unknown participant or repeated issuance.
    ///
    /// Every coefficient uses the same public Horner schedule and the existing
    /// constant-time modular owner. The last successful issuance drops all
    /// dealer secret material before returning. Returned share owners still
    /// contain secrets and must be dropped by their respective custody owners.
    ///
    /// # Errors
    /// Unknown participant or a participant whose share was already issued.
    pub fn take_share(&mut self, participant: u16) -> Result<SecretKeyShare, ThresholdError> {
        let index = self
            .context
            .participants
            .binary_search(&participant)
            .map_err(|_| ThresholdError::UnknownParticipant)?;
        if self.issued[index] {
            return Err(ThresholdError::AlreadyIssued);
        }
        let material = self
            .material
            .as_ref()
            .ok_or(ThresholdError::AlreadyIssued)?;
        let limbs = self.profile.top_level() + 1 + self.profile.special_count();
        let mut words = RnsPoly::zero(limbs, self.profile.degree());
        for limb in 0..limbs {
            let plan = self.profile.full_plan(limb);
            let fixed: crate::constant_time::FixedModulus = plan.fixed();
            for (coefficient, value) in words.limb_mut(limb).iter_mut().enumerate() {
                for poly in material.polynomials.iter().rev() {
                    *value = fixed.add_canonical(
                        fixed.multiply(*value, u64::from(participant)),
                        poly.limb(limb)[coefficient],
                    );
                }
                *value = fixed.add_canonical(
                    fixed.multiply(*value, u64::from(participant)),
                    small_residue(material.key.coefficients()[coefficient], plan.prime()),
                );
            }
        }
        fault::reached(FaultPoint::ThresholdBeforeShareRelease);
        self.issued[index] = true;
        self.remaining -= 1;
        if self.remaining == 0 {
            drop(self.material.take());
        }
        Ok(SecretKeyShare {
            context: Arc::clone(&self.context),
            instance: self.instance,
            participant,
            words,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::{
        BgvParameters,
        fixtures::{self, FixtureEntropy},
    };

    fn profile() -> BgvProfile {
        BgvProfile::new(BgvParameters::derive(4, 257, (40, 2), (41, 1), 1).expect("parameters"))
            .expect("profile")
    }

    #[test]
    fn metadata_checks_refuse_forged_participants_but_do_not_claim_algebraic_proofs() {
        let profile = profile();
        let context =
            ThresholdContext::new(&profile, [1; 32], 1, 2, vec![1, 2, 3]).expect("context");
        let secret =
            fixtures::secret_key(&profile, &mut FixtureEntropy::new([7; 64])).expect("key");
        let limit = DealerKeyShares::required_secret_bytes(&profile, &context).expect("limit");
        let mut dealer = fixtures::threshold_dealer(
            &profile,
            context.clone(),
            secret,
            limit,
            &mut FixtureEntropy::new([8; 64]),
        )
        .expect("dealer");
        let a = dealer.take_share(1).expect("a");
        let mut b = dealer.take_share(2).expect("b");
        b.participant = 4;
        assert_eq!(
            context.validate_selection_metadata(dealer.instance(), &[&a, &b]),
            Err(ThresholdError::UnknownParticipant)
        );
        b.participant = 2;
        // A malicious canonical residue is not an honest polynomial evaluation.
        // Metadata-only checks cannot detect that; production has no import or
        // mutator capable of creating this deliberately forged internal object.
        let prime = profile.parameters().main_primes[0];
        let original = b.words.words()[0];
        b.words.words_mut()[0] = (original + 1) % prime;
        assert_ne!(b.words.words()[0], original);
        context
            .validate_selection_metadata(dealer.instance(), &[&a, &b])
            .expect("metadata only");
    }
}
