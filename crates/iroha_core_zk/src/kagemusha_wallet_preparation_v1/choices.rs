//! Bounded durable native nonce and clock choices; no caller-derived randomness or time.

use super::*;
use crate::kagemusha_wallet_advance_v1::{
    KagemushaWalletFsV1, KagemushaWalletPlatformV1, KagemushaWalletProviderErrorV1,
    KagemushaWalletUnavailableV1, kagemusha_wallet_provider_digest_v1 as digest,
};
use crate::kagemusha_wallet_state_v1::{self as state, NativeIntentV1, PreparationSourceV1};
use rand::rand_core::TryRngCore as _;

const MAX_BYTES: usize = 4096;

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_preparation_v1::ObservationV1")]
struct Observation {
    boot: [u8; 32],
    milliseconds: u64,
}

#[derive(Debug, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_preparation_v1::NativeChoicesV1")]
pub(crate) struct NativeChoicesV1 {
    version: u16,
    manifest: [u8; 32],
    source: [u8; 32],
    request: [u8; 32],
    nonce: [u8; 32],
    observation: Option<Observation>,
}

type Result<T> = core::result::Result<T, state::Error>;

fn entropy_unavailable() -> state::Error {
    KagemushaWalletProviderErrorV1::Unavailable(KagemushaWalletUnavailableV1::Platform(0)).into()
}

fn sample_nonce(
    previous: &[u8; 32],
    mut fill: impl FnMut(&mut [u8; 32]) -> Result<()>,
) -> Result<[u8; 32]> {
    for _ in 0..128 {
        let mut nonce = [0; 32];
        fill(&mut nonce)?;
        if nonce != [0; 32] && nonce != *previous && bool::from(Fp::from_repr(nonce).is_some()) {
            return Ok(nonce);
        }
    }
    Err(entropy_unavailable())
}

fn needs_time(request: &NativeIntentV1, source: &PreparationSourceV1<'_>) -> bool {
    request.kind() == KagemushaWalletOperationKindV1::Send
        && source
            .released()
            .frozen
            .capsule
            .successor_state
            .send_requires_time_anchor()
}

fn bindings(
    request: &NativeIntentV1,
    source: &PreparationSourceV1<'_>,
) -> Result<([u8; 32], [u8; 32])> {
    let bytes =
        norito::to_bytes(request).map_err(|_| state::Error::Invalid("native request encoding"))?;
    let source = source
        .released()
        .frozen
        .capsule
        .capsule_digest()
        .map_err(|_| state::Error::Invalid("native source digest"))?;
    Ok((source, digest("native-preparation-choices-request", &bytes)))
}

impl NativeChoicesV1 {
    pub(crate) fn fresh_nonce(previous: &[u8; 32]) -> Result<[u8; 32]> {
        sample_nonce(previous, |bytes| {
            rand::rngs::OsRng
                .try_fill_bytes(bytes)
                .map_err(|_| entropy_unavailable())
        })
    }

    pub(crate) fn fresh<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1>(
        manifest: [u8; 32],
        request: &NativeIntentV1,
        source: &PreparationSourceV1<'_>,
        observations: &state::NativeObservationsV1<F, P>,
    ) -> Result<Self> {
        let (source_digest, request_digest) = bindings(request, source)?;
        let nonce = Self::fresh_nonce(
            &source
                .released()
                .frozen
                .capsule
                .successor_state
                .core
                .state_nonce,
        )?;
        let observation = if needs_time(request, source) {
            let now = observations.time()?;
            Some(Observation {
                boot: now.boot_id,
                milliseconds: now.monotonic_ms,
            })
        } else {
            None
        };
        let value = Self {
            version: 1,
            manifest,
            source: source_digest,
            request: request_digest,
            nonce,
            observation,
        };
        value.require(manifest, request, source)?;
        Ok(value)
    }

    pub(crate) fn decode(
        bytes: &[u8],
        manifest: [u8; 32],
        request: &NativeIntentV1,
        source: &PreparationSourceV1<'_>,
    ) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err(state::Error::WitnessLost("native choices bound"));
        }
        let value: Self = norito::decode_canonical_with_limits(
            bytes,
            norito::canonical_decode_limits(bytes.len()),
        )
        .map_err(|_| state::Error::WitnessLost("native choices canonical frame"))?;
        value.require(manifest, request, source)?;
        Ok(value)
    }

    fn require(
        &self,
        manifest: [u8; 32],
        request: &NativeIntentV1,
        source: &PreparationSourceV1<'_>,
    ) -> Result<()> {
        let (source_digest, request_digest) = bindings(request, source)?;
        self.require_binding(
            manifest,
            source_digest,
            request_digest,
            source
                .released()
                .frozen
                .capsule
                .successor_state
                .core
                .state_nonce,
            needs_time(request, source),
        )
    }

    fn require_binding(
        &self,
        manifest: [u8; 32],
        source: [u8; 32],
        request: [u8; 32],
        previous_nonce: [u8; 32],
        time_required: bool,
    ) -> Result<()> {
        if self.version != 1
            || manifest == [0; 32]
            || self.manifest != manifest
            || source == [0; 32]
            || self.source != source
            || self.request != request
            || self.nonce == [0; 32]
            || self.nonce == previous_nonce
            || !bool::from(Fp::from_repr(self.nonce).is_some())
            || self.observation.is_some() != time_required
            || self.observation.is_some_and(|now| now.boot == [0; 32])
        {
            return Err(state::Error::WitnessLost("native choices source binding"));
        }
        Ok(())
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let bytes =
            norito::to_bytes(self).map_err(|_| state::Error::Invalid("native choices encoding"))?;
        if bytes.len() > MAX_BYTES {
            return Err(state::Error::Invalid("native choices bound"));
        }
        Ok(bytes)
    }
    pub(crate) const fn nonce(&self) -> [u8; 32] {
        self.nonce
    }
    pub(crate) fn time(&self) -> Option<KagemushaWalletMonotonicReadingV1> {
        self.observation
            .map(|now| KagemushaWalletMonotonicReadingV1 {
                boot_id: now.boot,
                monotonic_ms: now.milliseconds,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nonce_sampling_rejects_zero_repeat_and_noncanonical_without_fallback() {
        let previous = Fp::from(7).to_repr();
        let expected = Fp::from(9).to_repr();
        let mut candidates = [[0; 32], previous, [255; 32], expected].into_iter();
        assert_eq!(
            sample_nonce(&previous, |bytes| {
                *bytes = candidates.next().unwrap();
                Ok(())
            })
            .unwrap(),
            expected
        );
        assert!(matches!(
            sample_nonce(&previous, |_| Err(entropy_unavailable())),
            Err(state::Error::Provider(_))
        ));
        let mut attempts = 0;
        assert!(
            sample_nonce(&previous, |_| {
                attempts += 1;
                Ok(())
            })
            .is_err()
        );
        assert_eq!(attempts, 128);
    }
    #[test]
    fn retained_choices_bind_every_source_and_optional_clock_without_resampling() {
        let mut value = NativeChoicesV1 {
            version: 1,
            manifest: [1; 32],
            source: [2; 32],
            request: [3; 32],
            nonce: Fp::from(9).to_repr(),
            observation: None,
        };
        let require = |v: &NativeChoicesV1, timed| {
            v.require_binding([1; 32], [2; 32], [3; 32], Fp::from(7).to_repr(), timed)
        };
        require(&value, false).unwrap();
        assert!(require(&value, true).is_err());
        value.observation = Some(Observation {
            boot: [4; 32],
            milliseconds: u64::MAX,
        });
        require(&value, true).unwrap();
        assert!(require(&value, false).is_err());
        let bytes = value.encode().unwrap();
        let restored: NativeChoicesV1 = norito::decode_canonical(&bytes).unwrap();
        assert_eq!(restored.nonce(), value.nonce());
        assert_eq!(restored.time(), value.time());
        require(&restored, true).unwrap();
        for role in 0..5 {
            let mut wrong: NativeChoicesV1 = norito::decode_canonical(&bytes).unwrap();
            match role {
                0 => wrong.version = 2,
                1 => wrong.manifest = [5; 32],
                2 => wrong.source = [5; 32],
                3 => wrong.request = [5; 32],
                _ => wrong.observation.as_mut().unwrap().boot = [0; 32],
            }
            assert!(require(&wrong, true).is_err());
        }
        value.nonce = [255; 32];
        assert!(require(&value, true).is_err());
    }
}
