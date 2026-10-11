//! Source-selected originals for nonmonetary setup and native direct time exchanges.
//!
//! These indexes grant no monetary authority. Requests are made available to transport only
//! after their exact signed bytes and historical gap are durably selected. Clock tokens are
//! native, single-use and intentionally not serializable: restart requires a new exchange.

use rand::rand_core::TryRngCore as _;

use super::{preparation_custody::IssuedRequestCustodyV1, *};
use crate::kagemusha_wallet_advance_v1::{
    KagemushaWalletFsV1, KagemushaWalletPlatformV1, KagemushaWalletUnavailableV1,
};

const ANCHOR_CUSTODY_MAX_BYTES: usize = KAGEMUSHA_WALLET_TIME_ANCHOR_MAX_BYTES_V1 + 1024;

/// Native single-use request observation. There is no decoder or foreign constructor.
#[allow(
    missing_copy_implementations,
    reason = "direct time observation custody is consumed exactly once"
)]
pub struct DirectTimeExchangeV1 {
    scheme: [u8; 32],
    wallet: [u8; 32],
    nonce: [u8; 32],
    sent: KagemushaWalletMonotonicReadingV1,
    maximum_response_ms: u64,
}

impl DirectTimeExchangeV1 {
    /// The only value sent to the issuer; local clock custody never crosses the boundary.
    #[must_use]
    pub const fn nonce(&self) -> [u8; 32] {
        self.nonce
    }

    fn complete(
        self,
        anchor: KagemushaWalletTimeAnchorV1,
        certificate: &KagemushaWalletSignerCertificateV1,
        scheme: &KagemushaWalletSchemeV1,
        state: &KagemushaWalletStateV1,
        received: KagemushaWalletMonotonicReadingV1,
    ) -> Result<KagemushaWalletAnchoredTimeV1, Error> {
        valid(anchor.verify(scheme, certificate))?;
        if self.scheme != state.core.scheme_id
            || self.scheme != scheme.scheme_id()
            || self.wallet != state.core.wallet_id
            || anchor.body.wallet_id != self.wallet
            || anchor.body.nonce != self.nonce
            || self.sent.boot_id != received.boot_id
        {
            return Err(Error::Invalid("direct time exchange binding"));
        }
        valid(KagemushaWalletAnchoredTimeV1::new(
            anchor,
            received.boot_id,
            self.sent.monotonic_ms,
            received.monotonic_ms,
            self.maximum_response_ms
                .min(state.core.time_anchor_max_response_ms),
        ))
    }
}

pub(super) fn retain_request<A: ObjectStore>(
    store: &mut A,
    index: IndexRoot,
    request: &KagemushaWalletRequestV1,
    gap: Option<&KagemushaWalletBlacklistGapOpeningV1>,
) -> Result<IndexRoot, Error> {
    valid(request.validate())?;
    if (request.body.receiver_blacklist_version != 0) != gap.is_some() {
        return Err(Error::Invalid("issued Request gap presence"));
    }
    if let Some(gap) = gap {
        valid(gap.verify(
            &request.body.receiver_blacklist_root,
            &request.body.payer_account_digest,
        ))?;
    }
    let bytes = archive::encode(request)?;
    if bytes.len() > KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1 {
        return Err(Error::Invalid("issued Request size"));
    }
    let record = IssuedRequestCustodyV1 {
        request: store.write_object(&bytes, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1)?,
        gap: gap
            .map(|opening| {
                store.write_object(
                    &opening.transcript(),
                    KAGEMUSHA_WALLET_BLACKLIST_GAP_OPENING_TRANSCRIPT_BYTES_V1,
                )
            })
            .transpose()?,
    };
    let value = archive::encode(&record)?;
    let key = request.request_digest();
    if let Some(previous) = index.get(store, &key)? {
        if previous != value {
            return Err(Error::WitnessLost("changed issued Request custody"));
        }
        return Ok(index);
    }
    index.set(store, key, &value)
}

fn retain_anchor<A: ObjectStore>(
    store: &mut A,
    index: IndexRoot,
    anchored: &KagemushaWalletAnchoredTimeV1,
) -> Result<IndexRoot, Error> {
    let address = store.write_object(&archive::encode(anchored)?, ANCHOR_CUSTODY_MAX_BYTES)?;
    let key = anchored.anchor.time_anchor_digest();
    if let Some(previous) = index.get(store, &key)? {
        if previous != address {
            return Err(Error::WitnessLost("changed direct time exchange"));
        }
        return Ok(index);
    }
    index.set(store, key, &address)
}

impl<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1, N: NativeProofs>
    Coordinator<AdvanceHandle<F, P>, ProviderArchive<F, P>, N>
{
    /// Capture a fresh nonce and request reading from the exclusive native provider.
    ///
    /// # Errors
    /// Missing selected head or originals, unavailable entropy, native clock or storage.
    pub fn begin_direct_time_exchange(&mut self) -> Result<DirectTimeExchangeV1, Error> {
        let (_, manifest) = self.sync_manifest()?;
        let step = self.indexed_step(&manifest, manifest.indexed.ok_or(Error::NoHead)?)?;
        self.source_custody(&manifest, &step)?;
        let unavailable = || {
            Error::Provider(ProviderError::Unavailable(
                KagemushaWalletUnavailableV1::Platform(0),
            ))
        };
        let mut nonce = [0; 32];
        // This is an unrestricted nonzero 256-bit session nonce, not a state field.
        for _ in 0..128 {
            rand::rngs::OsRng
                .try_fill_bytes(&mut nonce)
                .map_err(|_| unavailable())?;
            if nonce != [0; 32] {
                let sent = self.custody.observations().time()?;
                if sent.boot_id == [0; 32] {
                    return Err(unavailable());
                }
                return Ok(DirectTimeExchangeV1 {
                    scheme: self.scheme_id,
                    wallet: self.wallet_id,
                    nonce,
                    sent,
                    maximum_response_ms: step
                        .frozen
                        .capsule
                        .successor_state
                        .core
                        .time_anchor_max_response_ms,
                });
            }
        }
        Err(unavailable())
    }

    /// Authenticate and durably retain a direct response before ordinary TimeAnchor Refresh.
    /// Refresh alone cannot create this native observation. A lost token requires reanchoring.
    ///
    /// # Errors
    /// Invalid issuer, nonce, wallet, boot or response interval; lost selected witnesses;
    /// or unavailable native clock or durable storage. The token is consumed on every call.
    pub fn finish_direct_time_exchange(
        &mut self,
        exchange: DirectTimeExchangeV1,
        anchor: KagemushaWalletTimeAnchorV1,
        certificate: &KagemushaWalletSignerCertificateV1,
    ) -> Result<(), Error> {
        // Record arrival before storage and signature work can add latency to this sample.
        let received = self.custody.observations().time()?;
        let (root, mut manifest) = self.sync_manifest()?;
        let step = self.indexed_step(&manifest, manifest.indexed.ok_or(Error::NoHead)?)?;
        self.source_custody(&manifest, &step)?;
        let (scheme, _) = self.proofs.ledger_scope()?;
        let anchored = exchange.complete(
            anchor,
            certificate,
            &scheme,
            &step.frozen.capsule.successor_state,
            received,
        )?;
        let anchors = retain_anchor(&mut self.archive, manifest.direct_anchors, &anchored)?;
        if anchors != manifest.direct_anchors {
            manifest.direct_anchors = anchors;
            self.publish_manifest(root, &manifest)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
