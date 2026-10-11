//! Same-owner, one-dispatch Apple vendor effects with immutable returned-original custody.
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};

pub(super) struct LiveClock {
    pub started: KagemushaWalletMonotonicReadingV1,
    pub observed_at_ms: u64,
    pub expires_at_ms: u64,
}
const BOUNDS: [usize; 3] = [4096, 65_536, 4096];

impl<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1> EnrollmentOwnerV1<F, P> {
    fn apple_slot(&self) -> Result<KagemushaWalletSlotIdV1, Error> {
        if !matches!(
            self.config.policy.platform,
            KagemushaWalletEnrollmentPlatformV1::Apple { .. }
        ) {
            return Err(Error::Phase);
        }
        let (scope, slot) = self.selected.as_ref().ok_or(Error::Phase)?;
        self.require_selected_prekey(scope, slot)?;
        Ok(*slot)
    }
    fn apple_record(&self, stage: u8, result: bool) -> Result<[u8; 32], Error> {
        if !(1..=3).contains(&stage) {
            return Err(Error::Phase);
        }
        let (scope, _) = self.selected.as_ref().ok_or(Error::Phase)?;
        let mut body = scope.challenge.challenge_digest().to_vec();
        body.push(stage);
        Ok(kagemusha_wallet_provider_digest_v1(
            if result {
                "apple-enrollment-returned-original"
            } else {
                "apple-enrollment-dispatch"
            },
            &body,
        ))
    }
    pub(super) fn require_apple_live(&self) -> Result<(), Error> {
        self.apple_slot()?;
        let clock = self.apple_clock.as_ref().ok_or(Error::Phase)?;
        super::super::prekey::require_elapsed(
            &clock.started,
            &self.provider.monotonic_reading()?,
            clock.observed_at_ms,
            clock.expires_at_ms,
        )
        .map_err(Error::Original)
    }
    /// Flush any actual vendor return before releasing or rebinding this same provider owner.
    /// Unavailable publication retains its original bytes; cleanup must retry the same owner.
    pub fn flush_apple_returned(&mut self) -> Result<(), Error> {
        if let Some((stage, bytes)) = &self.apple_returned {
            let slot = self.apple_slot()?;
            let dispatch = self.apple_record(*stage, false)?;
            if self
                .provider
                .with_archive(&slot, |archive| archive.read_record(&dispatch, 1))?
                .as_deref()
                != Some(&[*stage])
            {
                return Err(Error::Original("Apple effect was not dispatched"));
            }
            let key = self.apple_record(*stage, true)?;
            self.provider
                .with_archive(&slot, |archive| archive.write_record(&key, bytes))?;
            self.apple_returned = None;
        }
        Ok(())
    }
    /// Recover exact vendor originals, flushing a returned value whose publication was unavailable.
    /// Missing originals convey no right to repeat an already-dispatched vendor effect.
    pub fn apple_collection_originals(&mut self) -> Result<[Vec<u8>; 3], Error> {
        self.flush_apple_returned()?;
        let slot = self.apple_slot()?;
        let mut originals: [Vec<u8>; 3] = std::array::from_fn(|_| Vec::new());
        for stage in 1..=3 {
            let key = self.apple_record(stage, true)?;
            originals[usize::from(stage - 1)] = self
                .provider
                .with_archive(&slot, |archive| {
                    archive.read_record(&key, BOUNDS[usize::from(stage - 1)])
                })?
                .unwrap_or_default();
        }
        if (originals[0].is_empty() && (!originals[1].is_empty() || !originals[2].is_empty()))
            || (originals[1].is_empty() && !originals[2].is_empty())
        {
            return Err(Error::Original("Apple collection original order"));
        }
        Ok(originals)
    }
    /// Final same-boot deadline check after all vendor returns are durably retained.
    pub fn complete_apple_collection(&mut self) -> Result<(), Error> {
        let originals = self.apple_collection_originals()?;
        let key = STANDARD
            .decode(&originals[0])
            .map_err(|_| Error::Original("Apple key identifier"))?;
        if key.len() != 32
            || key.iter().all(|byte| *byte == 0)
            || STANDARD.encode(&key).as_bytes() != originals[0]
            || originals[1].is_empty()
            || originals[2].is_empty()
        {
            return Err(Error::Original("Apple collection incomplete"));
        }
        self.require_apple_live()
    }
    /// Consume one live authorization and durably claim exactly one vendor dispatch.
    /// An uncertain previous dispatch is never turned into a fresh key or repeated assertion.
    pub fn begin_apple_effect(&mut self, stage: u8) -> Result<(), Error> {
        self.require_apple_live()?;
        let originals = self.apple_collection_originals()?;
        let index = usize::from(stage.checked_sub(1).ok_or(Error::Phase)?);
        if index >= 3
            || !originals[index].is_empty()
            || originals[..index].iter().any(Vec::is_empty)
        {
            return Err(Error::Phase);
        }
        if !matches!(self.progress()?, EnrollmentProgressV1::Evidence { .. }) {
            return Err(Error::Phase);
        }
        let slot = self.apple_slot()?;
        let key = self.apple_record(stage, false)?;
        if self
            .provider
            .with_archive(&slot, |archive| archive.read_record(&key, 1))?
            .is_some()
        {
            return Err(Error::Original("Apple vendor dispatch remains uncertain"));
        }
        self.provider
            .with_archive(&slot, |archive| archive.write_record(&key, &[stage]))?;
        // Sleep-inclusive same-boot elapsed check immediately before the foreign vendor effect.
        self.require_apple_live()
    }
    /// Retain the actual vendor return BEFORE any clock/current-owner guard or publication.
    /// Storage refusal keeps the returned bytes inside this same owner for an exact retry.
    pub fn retain_apple_effect(&mut self, stage: u8, original: &[u8]) -> Result<(), Error> {
        let index = usize::from(stage.checked_sub(1).ok_or(Error::Phase)?);
        if index >= 3 || original.is_empty() || original.len() > BOUNDS[index] {
            return Err(Error::Original("Apple vendor return bound"));
        }
        match &self.apple_returned {
            Some((held_stage, held)) if *held_stage != stage || held != original => {
                return Err(Error::Phase);
            }
            Some(_) => {}
            None => self.apple_returned = Some((stage, original.to_vec())),
        }
        let slot = self.apple_slot()?;
        let key = self.apple_record(stage, false)?;
        if self
            .provider
            .with_archive(&slot, |archive| archive.read_record(&key, 1))?
            .as_deref()
            != Some(&[stage])
        {
            return Err(Error::Original("Apple effect was not dispatched"));
        }
        self.flush_apple_returned()
    }
    pub(super) fn require_apple_originals(
        &mut self,
        key: &[u8; 32],
        attestation: &[u8],
        assertion: &[u8],
    ) -> Result<(), Error> {
        let originals = self.apple_collection_originals()?;
        if originals[0] != STANDARD.encode(key).as_bytes()
            || originals[1] != attestation
            || originals[2] != assertion
        {
            return Err(Error::Original(
                "Apple evidence differs from retained vendor returns",
            ));
        }
        self.require_apple_live()
    }
}
