//! Shared fail-closed health wrappers for privacy-prover entropy.
//!
//! The wrapper samples the source in canonical 64-byte blocks, rejects a catastrophic initial
//! constant or short-period stream, and serves every API through one bounded reservoir. Honest
//! source bytes are therefore invariant under caller chunking. A failed or unwinding refill
//! zeroizes the caller buffer and permanently poisons the wrapper before witness-dependent proving.
use rand::{TryCryptoRng, TryRngCore};
use rand_core_06::{CryptoRng, RngCore};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};
const HEALTH_PREFIX_BYTES_V1: usize = 64;
const HEALTH_HALF_BYTES_V1: usize = HEALTH_PREFIX_BYTES_V1 / 2;
const PROHIBITED_PERIODS_V1: [usize; 6] = [1, 2, 4, 8, 16, 32];
/// Canonical producer policy committed by every curve-engine manifest.
pub const CURVE_PROVER_RANDOMNESS_POLICY_V1: &[u8] = b"prover-rng:fixed64-reservoir:fallible-refill:reject-initial-constant-half+periods-1,2,4,8,16,32:retain-tail-max63:zeroize+poison-on-error-or-unwind:v1";
/// Canonical rand 0.9 `TryCryptoRng` producer and seed-bridge policy.
pub const TRY_CRYPTO_PROVER_RANDOMNESS_POLICY_V1: &[u8] = b"prover-rng-api=rand0.9-TryCryptoRng:fixed64-reservoir:fallible-refill:reject-initial-constant-half+periods-1,2,4,8,16,32:retain-reservoir-tail-max63+initial-block64-until-phase-transition:zeroize+poison-on-error-or-unwind:seed-bridge=sha256-domain+all64+exact-initial64+fresh-fixed64:partition=initial64-replay+fresh64-seed:v1";
const TRY_CRYPTO_DERIVED_SEED_DOMAIN_V1: &[u8] =
    b"iroha:privacy:try-crypto-prover:derived-entropy-seed:v1";
/// Failure while preflighting one cryptographic prover random source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ProverRandomnessErrorV1 {
    /// The source returned an error, including after partially filling the prefix.
    #[error("cryptographic prover randomness is unavailable")]
    Unavailable,
    /// The prefix was constant or repeated with a prohibited short period.
    #[error("cryptographic prover randomness failed its health check")]
    Unhealthy,
}
/// Failure while preflighting or deriving rand 0.9 prover entropy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[doc(hidden)]
pub enum TryCryptoProverRandomnessErrorV1 {
    /// The source failed, including after partially filling a destination.
    #[error("fallible cryptographic prover randomness is unavailable")]
    Unavailable,
    /// The source emitted a constant or prohibited short-period pattern.
    #[error("fallible cryptographic prover randomness failed its health check")]
    Unhealthy,
}
fn is_constant(bytes: &[u8]) -> bool {
    bytes
        .first()
        .is_some_and(|first| bytes.iter().all(|byte| byte == first))
}
fn repeats_with_period(bytes: &[u8], period: usize) -> bool {
    period < bytes.len()
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| *byte == bytes[index % period])
}
fn prefix_is_unhealthy_v1(prefix: &[u8; HEALTH_PREFIX_BYTES_V1]) -> bool {
    let (left, right) = prefix.split_at(HEALTH_HALF_BYTES_V1);
    is_constant(left)
        || is_constant(right)
        || PROHIBITED_PERIODS_V1
            .into_iter()
            .any(|period| repeats_with_period(prefix, period))
}
fn drain_reservoir_v1(
    reservoir: &mut [u8; HEALTH_PREFIX_BYTES_V1],
    cursor: &mut usize,
    destination: &mut [u8],
    offset: usize,
) -> usize {
    let copied = (HEALTH_PREFIX_BYTES_V1 - *cursor).min(destination.len() - offset);
    let end = *cursor + copied;
    destination[offset..offset + copied].copy_from_slice(&reservoir[*cursor..end]);
    reservoir[*cursor..end].zeroize();
    *cursor = end;
    copied
}
struct DestinationZeroizeGuardV1<'a> {
    destination: &'a mut [u8],
    armed: bool,
}
impl<'a> DestinationZeroizeGuardV1<'a> {
    fn new(destination: &'a mut [u8]) -> Self {
        Self {
            destination,
            armed: true,
        }
    }
    fn disarm(&mut self) {
        self.armed = false;
    }
}
impl Drop for DestinationZeroizeGuardV1<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.destination.zeroize();
        }
    }
}
fn core_unavailable_error_v1() -> rand_core_06::Error {
    rand_core_06::Error::new(ProverRandomnessErrorV1::Unavailable)
}
/// A cryptographic RNG health-checked through canonical source blocks.
pub struct HealthCheckedCryptoRngV1<'a, R> {
    source: &'a mut R,
    reservoir: Zeroizing<[u8; HEALTH_PREFIX_BYTES_V1]>,
    cursor: usize,
    poisoned: bool,
}
impl<'a, R> HealthCheckedCryptoRngV1<'a, R>
where
    R: CryptoRng + RngCore,
{
    /// Sample and health-check the exact first canonical source block.
    pub(crate) fn new(source: &'a mut R) -> Result<Self, ProverRandomnessErrorV1> {
        let mut reservoir = Zeroizing::new([0_u8; HEALTH_PREFIX_BYTES_V1]);
        source
            .try_fill_bytes(&mut *reservoir)
            .map_err(|_| ProverRandomnessErrorV1::Unavailable)?;
        if prefix_is_unhealthy_v1(&reservoir) {
            return Err(ProverRandomnessErrorV1::Unhealthy);
        }
        Ok(Self {
            source,
            reservoir,
            cursor: 0,
            poisoned: false,
        })
    }
    fn try_refill_v1(&mut self, destination: &mut [u8]) -> Result<(), rand_core_06::Error> {
        self.reservoir.zeroize();
        self.cursor = HEALTH_PREFIX_BYTES_V1;
        self.poisoned = true;
        let mut next = Zeroizing::new([0_u8; HEALTH_PREFIX_BYTES_V1]);
        let result;
        {
            let mut guard = DestinationZeroizeGuardV1::new(destination);
            result = self.source.try_fill_bytes(next.as_mut());
            if result.is_ok() {
                guard.disarm();
            }
        }
        if result.is_err() {
            return Err(core_unavailable_error_v1());
        }
        self.reservoir.copy_from_slice(next.as_slice());
        self.cursor = 0;
        self.poisoned = false;
        Ok(())
    }
    fn try_fill_canonical_v1(&mut self, destination: &mut [u8]) -> Result<(), rand_core_06::Error> {
        if self.poisoned {
            destination.zeroize();
            return Err(core_unavailable_error_v1());
        }
        let mut offset = 0;
        while offset < destination.len() {
            if self.cursor == HEALTH_PREFIX_BYTES_V1 {
                self.try_refill_v1(destination)?;
            }
            offset +=
                drain_reservoir_v1(&mut self.reservoir, &mut self.cursor, destination, offset);
        }
        Ok(())
    }
}
impl<R> RngCore for HealthCheckedCryptoRngV1<'_, R>
where
    R: CryptoRng + RngCore,
{
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0_u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }
    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0_u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }
    fn fill_bytes(&mut self, destination: &mut [u8]) {
        self.try_fill_canonical_v1(destination)
            .expect("cryptographic prover randomness became unavailable");
    }
    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), rand_core_06::Error> {
        self.try_fill_canonical_v1(destination)
    }
}
impl<R> CryptoRng for HealthCheckedCryptoRngV1<'_, R> where R: CryptoRng + RngCore {}
/// A rand 0.9 cryptographic RNG health-checked through canonical source blocks.
pub struct HealthCheckedTryCryptoRngV1<'a, R: ?Sized> {
    source: &'a mut R,
    reservoir: Zeroizing<[u8; HEALTH_PREFIX_BYTES_V1]>,
    initial_block: Zeroizing<[u8; HEALTH_PREFIX_BYTES_V1]>,
    cursor: usize,
    source_blocks: u64,
    emitted_bytes: u64,
    poisoned: bool,
}
impl<'a, R> HealthCheckedTryCryptoRngV1<'a, R>
where
    R: TryCryptoRng + ?Sized,
{
    /// Sample and health-check the exact first canonical source block.
    pub(crate) fn new(source: &'a mut R) -> Result<Self, TryCryptoProverRandomnessErrorV1> {
        let mut reservoir = Zeroizing::new([0_u8; HEALTH_PREFIX_BYTES_V1]);
        source
            .try_fill_bytes(reservoir.as_mut())
            .map_err(|_| TryCryptoProverRandomnessErrorV1::Unavailable)?;
        if prefix_is_unhealthy_v1(&reservoir) {
            return Err(TryCryptoProverRandomnessErrorV1::Unhealthy);
        }
        let initial_block = Zeroizing::new(*reservoir);
        Ok(Self {
            source,
            reservoir,
            initial_block,
            cursor: 0,
            source_blocks: 1,
            emitted_bytes: 0,
            poisoned: false,
        })
    }
    fn poison(&mut self, destination: &mut [u8]) {
        self.reservoir.zeroize();
        self.initial_block.zeroize();
        self.cursor = HEALTH_PREFIX_BYTES_V1;
        self.poisoned = true;
        destination.zeroize();
    }
    fn try_refill_v1(
        &mut self,
        destination: &mut [u8],
    ) -> Result<(), TryCryptoProverRandomnessErrorV1> {
        self.reservoir.zeroize();
        self.initial_block.zeroize();
        self.cursor = HEALTH_PREFIX_BYTES_V1;
        self.source_blocks = self.source_blocks.saturating_add(1);
        self.poisoned = true;
        let mut next = Zeroizing::new([0_u8; HEALTH_PREFIX_BYTES_V1]);
        let result;
        {
            let mut guard = DestinationZeroizeGuardV1::new(destination);
            result = self.source.try_fill_bytes(next.as_mut());
            if result.is_ok() {
                guard.disarm();
            }
        }
        if result.is_err() {
            return Err(TryCryptoProverRandomnessErrorV1::Unavailable);
        }
        self.reservoir.copy_from_slice(next.as_slice());
        self.cursor = 0;
        self.poisoned = false;
        Ok(())
    }
    fn try_fill_canonical_v1(
        &mut self,
        destination: &mut [u8],
    ) -> Result<(), TryCryptoProverRandomnessErrorV1> {
        if self.poisoned {
            destination.zeroize();
            return Err(TryCryptoProverRandomnessErrorV1::Unavailable);
        }
        let mut offset = 0;
        while offset < destination.len() {
            if self.cursor == HEALTH_PREFIX_BYTES_V1 {
                self.try_refill_v1(destination)?;
            }
            let copied =
                drain_reservoir_v1(&mut self.reservoir, &mut self.cursor, destination, offset);
            offset += copied;
            self.emitted_bytes = self
                .emitted_bytes
                .saturating_add(u64::try_from(copied).unwrap_or(u64::MAX));
        }
        Ok(())
    }
    /// Draw a separately health-checked seed after exactly block one is spent.
    ///
    /// The fresh block must not repeat the initial prover prefix. This catches
    /// a source that cycles between otherwise non-periodic 64-byte blocks.
    pub(crate) fn derive_independent_seed_v1(
        &mut self,
        purpose: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, TryCryptoProverRandomnessErrorV1> {
        if self.poisoned {
            return Err(TryCryptoProverRandomnessErrorV1::Unavailable);
        }
        if self.cursor != HEALTH_PREFIX_BYTES_V1
            || self.source_blocks != 1
            || self.emitted_bytes != HEALTH_PREFIX_BYTES_V1 as u64
        {
            return Err(TryCryptoProverRandomnessErrorV1::Unhealthy);
        }
        let initial_block = Zeroizing::new(*self.initial_block);
        self.initial_block.zeroize();
        self.reservoir.zeroize();
        self.cursor = HEALTH_PREFIX_BYTES_V1;
        self.source_blocks = 2;
        self.poisoned = true;
        let mut entropy = Zeroizing::new([0_u8; HEALTH_PREFIX_BYTES_V1]);
        if self.source.try_fill_bytes(entropy.as_mut()).is_err() {
            self.poison(entropy.as_mut());
            return Err(TryCryptoProverRandomnessErrorV1::Unavailable);
        }
        if prefix_is_unhealthy_v1(&entropy) || entropy.as_slice() == initial_block.as_slice() {
            self.poison(entropy.as_mut());
            return Err(TryCryptoProverRandomnessErrorV1::Unhealthy);
        }
        match derive_try_crypto_seed_from_block_v1(&entropy, purpose) {
            Ok(seed) => {
                self.poisoned = false;
                Ok(seed)
            }
            Err(error) => {
                self.poison(entropy.as_mut());
                Err(error)
            }
        }
    }
    /// Reserve a fresh independent seed and replay block one to a prover.
    pub(crate) fn partition_initial_block_with_independent_seed_v1(
        mut self,
        purpose: &[u8],
    ) -> Result<
        (PartitionedProverTryCryptoRngV1<'a, R>, Zeroizing<[u8; 32]>),
        TryCryptoProverRandomnessErrorV1,
    > {
        if self.poisoned || self.cursor != 0 || self.source_blocks != 1 || self.emitted_bytes != 0 {
            return Err(TryCryptoProverRandomnessErrorV1::Unhealthy);
        }
        let retained_initial_block = Zeroizing::new(*self.initial_block);
        let mut consumed_initial_block = Zeroizing::new([0_u8; HEALTH_PREFIX_BYTES_V1]);
        self.try_fill_canonical_v1(consumed_initial_block.as_mut())?;
        if consumed_initial_block.as_slice() != retained_initial_block.as_slice() {
            self.poison(consumed_initial_block.as_mut());
            return Err(TryCryptoProverRandomnessErrorV1::Unhealthy);
        }
        let independent_seed = self.derive_independent_seed_v1(purpose)?;
        self.reservoir
            .copy_from_slice(retained_initial_block.as_slice());
        self.cursor = 0;
        self.emitted_bytes = 0;
        Ok((PartitionedProverTryCryptoRngV1(self), independent_seed))
    }
}
impl<R> TryRngCore for HealthCheckedTryCryptoRngV1<'_, R>
where
    R: TryCryptoRng + ?Sized,
{
    type Error = TryCryptoProverRandomnessErrorV1;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0_u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0_u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }
    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        self.try_fill_canonical_v1(destination)
    }
}
impl<R> TryCryptoRng for HealthCheckedTryCryptoRngV1<'_, R> where R: TryCryptoRng + ?Sized {}
/// One-way prover phase after block two is reserved for an independent seed.
pub struct PartitionedProverTryCryptoRngV1<'a, R: ?Sized>(HealthCheckedTryCryptoRngV1<'a, R>);
impl<R> TryRngCore for PartitionedProverTryCryptoRngV1<'_, R>
where
    R: TryCryptoRng + ?Sized,
{
    type Error = TryCryptoProverRandomnessErrorV1;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0_u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0_u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }
    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        self.0.try_fill_bytes(destination)
    }
}
impl<R> TryCryptoRng for PartitionedProverTryCryptoRngV1<'_, R> where R: TryCryptoRng + ?Sized {}
/// Draw and domain-derive one 32-byte seed from an independent healthy block.
///
/// Every sampled byte influences the result. Both the source block and
/// derived seed are zeroized on every exit path.
pub fn derive_healthy_try_crypto_seed_v1<R: TryCryptoRng + ?Sized>(
    rng: &mut R,
    purpose: &[u8],
) -> Result<Zeroizing<[u8; 32]>, TryCryptoProverRandomnessErrorV1> {
    let mut entropy = Zeroizing::new([0_u8; HEALTH_PREFIX_BYTES_V1]);
    rng.try_fill_bytes(entropy.as_mut())
        .map_err(|_| TryCryptoProverRandomnessErrorV1::Unavailable)?;
    if prefix_is_unhealthy_v1(&entropy) {
        return Err(TryCryptoProverRandomnessErrorV1::Unhealthy);
    }
    derive_try_crypto_seed_from_block_v1(&entropy, purpose)
}
fn derive_try_crypto_seed_from_block_v1(
    entropy: &[u8; HEALTH_PREFIX_BYTES_V1],
    purpose: &[u8],
) -> Result<Zeroizing<[u8; 32]>, TryCryptoProverRandomnessErrorV1> {
    let mut hash = Sha256::new();
    hash.update(TRY_CRYPTO_DERIVED_SEED_DOMAIN_V1);
    hash.update(
        u64::try_from(purpose.len())
            .map_err(|_| TryCryptoProverRandomnessErrorV1::Unhealthy)?
            .to_be_bytes(),
    );
    hash.update(purpose);
    hash.update(entropy);
    let mut seed = Zeroizing::new(<[u8; 32]>::from(hash.finalize()));
    if seed.iter().all(|byte| *byte == 0) {
        seed.zeroize();
        return Err(TryCryptoProverRandomnessErrorV1::Unhealthy);
    }
    Ok(seed)
}
#[cfg(test)]
mod tests {
    use super::*;
    use rand_08::{SeedableRng as _, rngs::StdRng};
    #[derive(Clone, Copy)]
    enum Mode {
        Constant,
        ConstantLeftHalf,
        ConstantRightHalf,
        Period(usize),
        PartialFailure,
    }
    struct AdversarialRng(Mode);
    impl RngCore for AdversarialRng {
        fn next_u32(&mut self) -> u32 {
            0
        }
        fn next_u64(&mut self) -> u64 {
            0
        }
        fn fill_bytes(&mut self, destination: &mut [u8]) {
            self.try_fill_bytes(destination)
                .expect("infallible adversarial mode")
        }
        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), rand_core_06::Error> {
            match self.0 {
                Mode::Constant => destination.fill(0x5A),
                Mode::ConstantLeftHalf => {
                    for (index, byte) in destination.iter_mut().enumerate() {
                        *byte = if index < HEALTH_HALF_BYTES_V1 {
                            0x5A
                        } else {
                            (index as u8).wrapping_mul(41).wrapping_add(3)
                        };
                    }
                }
                Mode::ConstantRightHalf => {
                    for (index, byte) in destination.iter_mut().enumerate() {
                        *byte = if index < HEALTH_HALF_BYTES_V1 {
                            (index as u8).wrapping_mul(41).wrapping_add(3)
                        } else {
                            0xA5
                        };
                    }
                }
                Mode::Period(period) => {
                    for (index, byte) in destination.iter_mut().enumerate() {
                        *byte = ((index % period) as u8).wrapping_mul(41).wrapping_add(3);
                    }
                }
                Mode::PartialFailure => {
                    let partial = destination.len() / 2;
                    destination
                        .iter_mut()
                        .take(partial)
                        .enumerate()
                        .for_each(|(index, byte)| *byte = index as u8);
                    return Err(rand_core_06::Error::new(
                        "injected partial prover entropy failure",
                    ));
                }
            }
            Ok(())
        }
    }
    impl CryptoRng for AdversarialRng {}
    #[derive(Debug)]
    struct RecordingError;
    impl core::fmt::Display for RecordingError {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter.write_str("injected canonical-block failure")
        }
    }
    impl std::error::Error for RecordingError {}
    struct RecordingStream {
        cursor: usize,
        requests: Vec<usize>,
        fail_on_request: Option<usize>,
        panic_on_request: Option<usize>,
    }
    impl RecordingStream {
        fn new(fail_on_request: Option<usize>) -> Self {
            Self {
                cursor: 0,
                requests: Vec::new(),
                fail_on_request,
                panic_on_request: None,
            }
        }
        fn panicking_on(request: usize) -> Self {
            Self {
                cursor: 0,
                requests: Vec::new(),
                fail_on_request: None,
                panic_on_request: Some(request),
            }
        }
        fn byte(index: usize) -> u8 {
            let mixed = (index as u64)
                .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                .rotate_left((index % 61) as u32)
                ^ 0xA5C3_6D91_E27B_4F08;
            (mixed ^ (mixed >> 17) ^ (mixed >> 43)) as u8
        }
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), RecordingError> {
            self.requests.push(destination.len());
            let panicking = self.panic_on_request == Some(self.requests.len());
            let failing = self.fail_on_request == Some(self.requests.len());
            let written = if failing || panicking {
                destination.len().min(17)
            } else {
                destination.len()
            };
            for byte in destination.iter_mut().take(written) {
                *byte = Self::byte(self.cursor);
                self.cursor += 1;
            }
            if panicking {
                panic!("injected canonical-block panic");
            }
            if failing { Err(RecordingError) } else { Ok(()) }
        }
    }
    struct CoreRecordingRng(RecordingStream);
    impl RngCore for CoreRecordingRng {
        fn next_u32(&mut self) -> u32 {
            let mut bytes = [0; 4];
            self.fill_bytes(&mut bytes);
            u32::from_le_bytes(bytes)
        }
        fn next_u64(&mut self) -> u64 {
            let mut bytes = [0; 8];
            self.fill_bytes(&mut bytes);
            u64::from_le_bytes(bytes)
        }
        fn fill_bytes(&mut self, destination: &mut [u8]) {
            self.try_fill_bytes(destination).expect("recording source")
        }
        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), rand_core_06::Error> {
            self.0.fill(destination).map_err(rand_core_06::Error::new)
        }
    }
    impl CryptoRng for CoreRecordingRng {}
    struct TryRecordingRng(RecordingStream);
    impl TryRngCore for TryRecordingRng {
        type Error = RecordingError;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            let mut bytes = [0; 4];
            self.try_fill_bytes(&mut bytes)?;
            Ok(u32::from_le_bytes(bytes))
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut bytes = [0; 8];
            self.try_fill_bytes(&mut bytes)?;
            Ok(u64::from_le_bytes(bytes))
        }
        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
            self.0.fill(destination)
        }
    }
    impl TryCryptoRng for TryRecordingRng {}
    #[test]
    fn healthy_wrapper_preserves_the_exact_source_stream_across_chunking() {
        let mut direct = StdRng::from_seed([0x39; 32]);
        let mut wrapped_source = StdRng::from_seed([0x39; 32]);
        let mut expected = [0_u8; 257];
        direct.fill_bytes(&mut expected);
        let mut wrapped =
            HealthCheckedCryptoRngV1::new(&mut wrapped_source).expect("healthy source");
        let mut actual = [0_u8; 257];
        wrapped.try_fill_bytes(&mut actual[..13]).expect("prefix");
        wrapped
            .try_fill_bytes(&mut actual[13..191])
            .expect("prefix and source");
        wrapped
            .try_fill_bytes(&mut actual[191..])
            .expect("source suffix");
        assert_eq!(actual, expected);
    }
    #[test]
    fn curve_reservoir_is_partition_invariant_bounded_and_uses_only_fixed_blocks() {
        const TOTALS: [usize; 23] = [
            0, 1, 3, 4, 7, 8, 13, 31, 32, 63, 64, 65, 127, 128, 129, 190, 191, 192, 193, 255, 256,
            257, 4097,
        ];
        for total in TOTALS {
            for chunk in [1, 3, 13, 63, 64, 65, 178, 257, usize::MAX] {
                let mut source = CoreRecordingRng(RecordingStream::new(None));
                let mut checked =
                    HealthCheckedCryptoRngV1::new(&mut source).expect("healthy source");
                let mut actual = vec![0; total];
                let mut offset = 0;
                while offset < total {
                    let end = offset.saturating_add(chunk).min(total);
                    checked
                        .try_fill_bytes(&mut actual[offset..end])
                        .expect("canonical reservoir");
                    let requests = checked.source.0.requests.len();
                    checked.try_fill_bytes(&mut []).expect("empty request");
                    assert_eq!(checked.source.0.requests.len(), requests);
                    offset = end;
                }
                assert_eq!(
                    actual,
                    (0..total).map(RecordingStream::byte).collect::<Vec<_>>()
                );
                assert!(checked.source.0.requests.iter().all(|length| *length == 64));
                assert_eq!(
                    checked.source.0.requests.len(),
                    total.div_ceil(HEALTH_PREFIX_BYTES_V1).max(1)
                );
                assert!(
                    checked.reservoir[..checked.cursor]
                        .iter()
                        .all(|byte| *byte == 0)
                );
            }
        }
    }
    #[test]
    fn curve_refill_failure_zeroizes_poisoned_output_and_never_reenters_source() {
        let mut source = CoreRecordingRng(RecordingStream::new(Some(2)));
        let mut checked = HealthCheckedCryptoRngV1::new(&mut source).expect("healthy first block");
        let mut destination = [0xA5; 65];
        assert!(checked.try_fill_bytes(&mut destination).is_err());
        assert_eq!(destination, [0; 65]);
        assert!(checked.poisoned);
        assert_eq!(*checked.reservoir, [0; HEALTH_PREFIX_BYTES_V1]);
        assert_eq!(checked.source.0.requests, [64, 64]);
        destination.fill(0x5A);
        assert!(checked.try_fill_bytes(&mut destination).is_err());
        assert_eq!(destination, [0; 65]);
        assert_eq!(checked.source.0.requests, [64, 64]);
    }
    #[test]
    fn refill_panics_zeroize_and_permanently_poison_both_wrappers() {
        let mut core_source = CoreRecordingRng(RecordingStream::panicking_on(2));
        let mut core =
            HealthCheckedCryptoRngV1::new(&mut core_source).expect("healthy first block");
        let mut core_destination = [0xA5; 65];
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                core.try_fill_bytes(&mut core_destination).ok();
            }))
            .is_err()
        );
        assert_eq!(core_destination, [0; 65]);
        assert!(core.poisoned);
        assert_eq!(*core.reservoir, [0; HEALTH_PREFIX_BYTES_V1]);
        assert_eq!(core.source.0.requests, [64, 64]);
        core_destination.fill(0x5A);
        assert!(core.try_fill_bytes(&mut core_destination).is_err());
        assert_eq!(core_destination, [0; 65]);
        assert_eq!(core.source.0.requests, [64, 64]);
        let mut try_source = TryRecordingRng(RecordingStream::panicking_on(2));
        let mut checked =
            HealthCheckedTryCryptoRngV1::new(&mut try_source).expect("healthy first block");
        let mut try_destination = [0xA5; 65];
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                checked.try_fill_bytes(&mut try_destination).ok();
            }))
            .is_err()
        );
        assert_eq!(try_destination, [0; 65]);
        assert!(checked.poisoned);
        assert_eq!(*checked.reservoir, [0; HEALTH_PREFIX_BYTES_V1]);
        assert_eq!(*checked.initial_block, [0; HEALTH_PREFIX_BYTES_V1]);
        assert_eq!(checked.source.0.requests, [64, 64]);
        try_destination.fill(0x5A);
        assert_eq!(
            checked.try_fill_bytes(&mut try_destination),
            Err(TryCryptoProverRandomnessErrorV1::Unavailable)
        );
        assert_eq!(try_destination, [0; 65]);
        assert_eq!(checked.source.0.requests, [64, 64]);
    }
    #[test]
    fn every_curve_and_try_entrypoint_consumes_the_same_canonical_stream() {
        let expected = (0..203).map(RecordingStream::byte).collect::<Vec<_>>();
        let mut core_source = CoreRecordingRng(RecordingStream::new(None));
        let mut core = HealthCheckedCryptoRngV1::new(&mut core_source).expect("healthy source");
        assert_eq!(
            core.next_u32(),
            u32::from_le_bytes(expected[0..4].try_into().unwrap())
        );
        assert_eq!(
            core.next_u64(),
            u64::from_le_bytes(expected[4..12].try_into().unwrap())
        );
        let mut core_tail = [0; 191];
        core.fill_bytes(&mut core_tail[..13]);
        core.try_fill_bytes(&mut core_tail[13..])
            .expect("fallible tail");
        assert_eq!(core_tail, expected[12..]);
        let mut try_source = TryRecordingRng(RecordingStream::new(None));
        let mut checked =
            HealthCheckedTryCryptoRngV1::new(&mut try_source).expect("healthy source");
        assert_eq!(
            checked.try_next_u32().expect("u32"),
            u32::from_le_bytes(expected[0..4].try_into().unwrap())
        );
        assert_eq!(
            checked.try_next_u64().expect("u64"),
            u64::from_le_bytes(expected[4..12].try_into().unwrap())
        );
        let mut try_tail = [0; 191];
        checked.try_fill_bytes(&mut try_tail).expect("try tail");
        assert_eq!(try_tail, expected[12..]);
    }
    #[test]
    fn constant_short_period_and_partial_failure_are_rejected() {
        for mode in [
            Mode::Constant,
            Mode::ConstantLeftHalf,
            Mode::ConstantRightHalf,
            Mode::Period(1),
            Mode::Period(2),
            Mode::Period(4),
            Mode::Period(8),
            Mode::Period(16),
            Mode::Period(32),
        ] {
            assert!(matches!(
                HealthCheckedCryptoRngV1::new(&mut AdversarialRng(mode)),
                Err(ProverRandomnessErrorV1::Unhealthy)
            ));
        }
        assert!(matches!(
            HealthCheckedCryptoRngV1::new(&mut AdversarialRng(Mode::PartialFailure)),
            Err(ProverRandomnessErrorV1::Unavailable)
        ));
    }
    mod try_crypto {
        use super::super::*;
        use super::{RecordingStream, TryRecordingRng};
        use rand::{RngCore as _, SeedableRng as _, TryCryptoRng, TryRngCore, rngs::StdRng};
        #[derive(Clone, Copy)]
        enum TryMode {
            Constant,
            ConstantLeftHalf,
            ConstantRightHalf,
            Period(usize),
            PartialFailure,
        }
        #[derive(Debug)]
        struct InjectedTryEntropyError;
        impl core::fmt::Display for InjectedTryEntropyError {
            fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                formatter.write_str("injected fallible prover entropy failure")
            }
        }
        struct TryAdversarialRng(TryMode);
        impl TryRngCore for TryAdversarialRng {
            type Error = InjectedTryEntropyError;
            fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                Err(InjectedTryEntropyError)
            }
            fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                Err(InjectedTryEntropyError)
            }
            fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
                match self.0 {
                    TryMode::Constant => destination.fill(0x5A),
                    TryMode::ConstantLeftHalf => {
                        for (index, byte) in destination.iter_mut().enumerate() {
                            *byte = if index < HEALTH_HALF_BYTES_V1 {
                                0x5A
                            } else {
                                (index as u8).wrapping_mul(41).wrapping_add(3)
                            };
                        }
                    }
                    TryMode::ConstantRightHalf => {
                        for (index, byte) in destination.iter_mut().enumerate() {
                            *byte = if index < HEALTH_HALF_BYTES_V1 {
                                (index as u8).wrapping_mul(41).wrapping_add(3)
                            } else {
                                0xA5
                            };
                        }
                    }
                    TryMode::Period(period) => {
                        for (index, byte) in destination.iter_mut().enumerate() {
                            *byte = ((index % period) as u8).wrapping_mul(41).wrapping_add(3);
                        }
                    }
                    TryMode::PartialFailure => {
                        for (index, byte) in destination.iter_mut().take(17).enumerate() {
                            *byte = index as u8;
                        }
                        return Err(InjectedTryEntropyError);
                    }
                }
                Ok(())
            }
        }
        impl TryCryptoRng for TryAdversarialRng {}
        struct RepeatedHealthyBlockRng {
            cursor: usize,
        }
        impl TryRngCore for RepeatedHealthyBlockRng {
            type Error = InjectedTryEntropyError;
            fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                Err(InjectedTryEntropyError)
            }
            fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                Err(InjectedTryEntropyError)
            }
            fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
                for byte in destination {
                    *byte = ((self.cursor % HEALTH_PREFIX_BYTES_V1) as u8)
                        .wrapping_mul(73)
                        .wrapping_add(11);
                    self.cursor += 1;
                }
                Ok(())
            }
        }
        impl TryCryptoRng for RepeatedHealthyBlockRng {}
        struct AdversarialSecondBlockRng {
            mode: TryMode,
            fills: usize,
        }
        impl TryRngCore for AdversarialSecondBlockRng {
            type Error = InjectedTryEntropyError;
            fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                Err(InjectedTryEntropyError)
            }
            fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                Err(InjectedTryEntropyError)
            }
            fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
                let fill = self.fills;
                self.fills = self.fills.saturating_add(1);
                if fill == 0 {
                    for (index, byte) in destination.iter_mut().enumerate() {
                        *byte = (index as u8).wrapping_mul(73).wrapping_add(11);
                    }
                    return Ok(());
                }
                TryAdversarialRng(self.mode).try_fill_bytes(destination)
            }
        }
        impl TryCryptoRng for AdversarialSecondBlockRng {}
        fn consume_checked_prefix_v1<R: TryCryptoRng + ?Sized>(
            checked: &mut HealthCheckedTryCryptoRngV1<'_, R>,
        ) {
            let mut replay = Zeroizing::new([0_u8; HEALTH_PREFIX_BYTES_V1]);
            checked
                .try_fill_bytes(replay.as_mut())
                .expect("replay initial block");
        }
        #[test]
        fn healthy_wrapper_preserves_the_exact_try_crypto_stream() {
            let mut direct = StdRng::from_seed([0x39; 32]);
            let mut wrapped_source = StdRng::from_seed([0x39; 32]);
            let mut expected = [0_u8; 257];
            direct.fill_bytes(&mut expected);
            let mut wrapped =
                HealthCheckedTryCryptoRngV1::new(&mut wrapped_source).expect("healthy source");
            let mut actual = [0_u8; 257];
            wrapped.try_fill_bytes(&mut actual[..13]).expect("prefix");
            wrapped
                .try_fill_bytes(&mut actual[13..191])
                .expect("prefix and source");
            wrapped
                .try_fill_bytes(&mut actual[191..])
                .expect("source suffix");
            assert_eq!(actual, expected);
        }
        #[test]
        fn try_reservoir_is_partition_invariant_bounded_and_uses_only_fixed_blocks() {
            const TOTALS: [usize; 23] = [
                0, 1, 3, 4, 7, 8, 13, 31, 32, 63, 64, 65, 127, 128, 129, 190, 191, 192, 193, 255,
                256, 257, 4097,
            ];
            for total in TOTALS {
                for chunk in [1, 3, 13, 63, 64, 65, 178, 257, usize::MAX] {
                    let mut source = TryRecordingRng(RecordingStream::new(None));
                    let mut checked =
                        HealthCheckedTryCryptoRngV1::new(&mut source).expect("healthy source");
                    let mut actual = vec![0; total];
                    let mut offset = 0;
                    while offset < total {
                        let end = offset.saturating_add(chunk).min(total);
                        checked
                            .try_fill_bytes(&mut actual[offset..end])
                            .expect("canonical reservoir");
                        let requests = checked.source.0.requests.len();
                        checked.try_fill_bytes(&mut []).expect("empty request");
                        assert_eq!(checked.source.0.requests.len(), requests);
                        offset = end;
                    }
                    assert_eq!(
                        actual,
                        (0..total).map(RecordingStream::byte).collect::<Vec<_>>()
                    );
                    assert!(checked.source.0.requests.iter().all(|length| *length == 64));
                    assert_eq!(
                        checked.source.0.requests.len(),
                        total.div_ceil(HEALTH_PREFIX_BYTES_V1).max(1)
                    );
                    assert!(
                        checked.reservoir[..checked.cursor]
                            .iter()
                            .all(|byte| *byte == 0)
                    );
                }
            }
        }
        #[test]
        fn try_refill_failure_zeroizes_poisoned_output_and_never_reenters_source() {
            let mut source = TryRecordingRng(RecordingStream::new(Some(2)));
            let mut checked =
                HealthCheckedTryCryptoRngV1::new(&mut source).expect("healthy first block");
            let mut destination = [0xA5; 65];
            assert_eq!(
                checked.try_fill_bytes(&mut destination),
                Err(TryCryptoProverRandomnessErrorV1::Unavailable)
            );
            assert_eq!(destination, [0; 65]);
            assert!(checked.poisoned);
            assert_eq!(*checked.reservoir, [0; HEALTH_PREFIX_BYTES_V1]);
            assert_eq!(*checked.initial_block, [0; HEALTH_PREFIX_BYTES_V1]);
            assert_eq!(checked.source.0.requests, [64, 64]);
            destination.fill(0x5A);
            assert_eq!(
                checked.try_fill_bytes(&mut destination),
                Err(TryCryptoProverRandomnessErrorV1::Unavailable)
            );
            assert_eq!(destination, [0; 65]);
            assert_eq!(checked.source.0.requests, [64, 64]);
        }
        #[test]
        fn constant_period_one_to_thirty_two_and_partial_try_sources_fail_closed() {
            for mode in [
                TryMode::Constant,
                TryMode::ConstantLeftHalf,
                TryMode::ConstantRightHalf,
                TryMode::Period(1),
                TryMode::Period(2),
                TryMode::Period(4),
                TryMode::Period(8),
                TryMode::Period(16),
                TryMode::Period(32),
            ] {
                assert_eq!(
                    HealthCheckedTryCryptoRngV1::new(&mut TryAdversarialRng(mode)).map(|_| ()),
                    Err(TryCryptoProverRandomnessErrorV1::Unhealthy)
                );
                assert_eq!(
                    derive_healthy_try_crypto_seed_v1(
                        &mut TryAdversarialRng(mode),
                        b"adversarial-test",
                    )
                    .map(|_| ()),
                    Err(TryCryptoProverRandomnessErrorV1::Unhealthy)
                );
            }
            assert_eq!(
                HealthCheckedTryCryptoRngV1::new(&mut TryAdversarialRng(TryMode::PartialFailure,))
                    .map(|_| ()),
                Err(TryCryptoProverRandomnessErrorV1::Unavailable)
            );
            assert_eq!(
                derive_healthy_try_crypto_seed_v1(
                    &mut TryAdversarialRng(TryMode::PartialFailure),
                    b"partial-test",
                )
                .map(|_| ()),
                Err(TryCryptoProverRandomnessErrorV1::Unavailable)
            );
        }
        #[test]
        fn independent_seed_rejects_reused_and_adversarial_second_blocks() {
            let mut repeated_source = RepeatedHealthyBlockRng { cursor: 0 };
            let mut repeated = HealthCheckedTryCryptoRngV1::new(&mut repeated_source)
                .expect("initial block is healthy");
            consume_checked_prefix_v1(&mut repeated);
            assert_eq!(
                repeated
                    .derive_independent_seed_v1(b"independent-test")
                    .map(|_| ()),
                Err(TryCryptoProverRandomnessErrorV1::Unhealthy)
            );
            let mut early_source = AdversarialSecondBlockRng {
                mode: TryMode::Constant,
                fills: 0,
            };
            let mut early = HealthCheckedTryCryptoRngV1::new(&mut early_source)
                .expect("initial block is healthy");
            assert_eq!(
                early
                    .derive_independent_seed_v1(b"early-independent-seed")
                    .map(|_| ()),
                Err(TryCryptoProverRandomnessErrorV1::Unhealthy)
            );
            let mut late_source = TryRecordingRng(RecordingStream::new(None));
            let mut late = HealthCheckedTryCryptoRngV1::new(&mut late_source)
                .expect("initial block is healthy");
            late.try_fill_bytes(&mut [0; HEALTH_PREFIX_BYTES_V1 + 1])
                .expect("consume into the next source block");
            assert_eq!(
                late.derive_independent_seed_v1(b"late-independent-seed")
                    .map(|_| ()),
                Err(TryCryptoProverRandomnessErrorV1::Unhealthy)
            );
            for (mode, expected) in [
                (
                    TryMode::PartialFailure,
                    TryCryptoProverRandomnessErrorV1::Unavailable,
                ),
                (
                    TryMode::Constant,
                    TryCryptoProverRandomnessErrorV1::Unhealthy,
                ),
                (
                    TryMode::Period(8),
                    TryCryptoProverRandomnessErrorV1::Unhealthy,
                ),
                (
                    TryMode::Period(32),
                    TryCryptoProverRandomnessErrorV1::Unhealthy,
                ),
            ] {
                let mut source = AdversarialSecondBlockRng { mode, fills: 0 };
                let mut checked = HealthCheckedTryCryptoRngV1::new(&mut source)
                    .expect("initial block is healthy");
                consume_checked_prefix_v1(&mut checked);
                assert_eq!(
                    checked
                        .derive_independent_seed_v1(b"adversarial-second-block")
                        .map(|_| ()),
                    Err(expected)
                );
            }
        }
        #[test]
        fn independent_seed_panic_zeroizes_poisoned_state_and_never_reenters_source() {
            let mut source = TryRecordingRng(RecordingStream::panicking_on(2));
            let mut checked =
                HealthCheckedTryCryptoRngV1::new(&mut source).expect("healthy first block");
            consume_checked_prefix_v1(&mut checked);
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    checked
                        .derive_independent_seed_v1(b"panicking-independent-seed")
                        .ok();
                }))
                .is_err()
            );
            assert!(checked.poisoned);
            assert_eq!(*checked.reservoir, [0; HEALTH_PREFIX_BYTES_V1]);
            assert_eq!(*checked.initial_block, [0; HEALTH_PREFIX_BYTES_V1]);
            assert_eq!(checked.source.0.requests, [64, 64]);
            let mut destination = [0xA5; 64];
            assert_eq!(
                checked.try_fill_bytes(&mut destination),
                Err(TryCryptoProverRandomnessErrorV1::Unavailable)
            );
            assert_eq!(destination, [0; 64]);
            assert_eq!(checked.source.0.requests, [64, 64]);
        }
        #[test]
        fn partitioned_prover_replays_block_one_and_skips_reserved_block_two() {
            let purpose = b"partitioned-prover-test-v1";
            let mut source = TryRecordingRng(RecordingStream::new(None));
            let checked =
                HealthCheckedTryCryptoRngV1::new(&mut source).expect("healthy first block");
            let (mut prover, seed) = checked
                .partition_initial_block_with_independent_seed_v1(purpose)
                .expect("healthy partition");
            let first_block = (0..64).map(RecordingStream::byte).collect::<Vec<_>>();
            let second_block: [u8; 64] = (64..128)
                .map(RecordingStream::byte)
                .collect::<Vec<_>>()
                .try_into()
                .expect("second canonical block");
            let expected_seed = derive_try_crypto_seed_from_block_v1(&second_block, purpose)
                .expect("expected independent seed");
            assert_eq!(*seed, *expected_seed);
            assert_eq!(prover.0.source.0.requests, [64, 64]);
            let mut actual = [0_u8; 128];
            prover
                .try_fill_bytes(&mut actual)
                .expect("partitioned prover stream");
            let mut expected = first_block;
            expected.extend((128..192).map(RecordingStream::byte));
            assert_eq!(actual.as_slice(), expected.as_slice());
            assert_eq!(prover.0.source.0.requests, [64, 64, 64]);
            assert!(prover.0.initial_block.iter().all(|byte| *byte == 0));
        }
        #[test]
        fn independent_seed_is_deterministic_and_purpose_separated() {
            let mut first_source = StdRng::from_seed([0x63; 32]);
            let mut second_source = StdRng::from_seed([0x63; 32]);
            let mut third_source = StdRng::from_seed([0x63; 32]);
            let mut first =
                HealthCheckedTryCryptoRngV1::new(&mut first_source).expect("healthy source");
            let mut second =
                HealthCheckedTryCryptoRngV1::new(&mut second_source).expect("healthy source");
            let mut third =
                HealthCheckedTryCryptoRngV1::new(&mut third_source).expect("healthy source");
            consume_checked_prefix_v1(&mut first);
            consume_checked_prefix_v1(&mut second);
            consume_checked_prefix_v1(&mut third);
            let first_seed = first
                .derive_independent_seed_v1(b"authorization")
                .expect("healthy independent seed");
            let second_seed = second
                .derive_independent_seed_v1(b"authorization")
                .expect("healthy independent seed");
            let third_seed = third
                .derive_independent_seed_v1(b"wallet-encryption")
                .expect("healthy independent seed");
            assert_eq!(*first_seed, *second_seed);
            assert_ne!(*first_seed, *third_seed);
        }
    }
}
