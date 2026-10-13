//! Worker-owned encoding and original signing, retaining every completed phase on refusal.
use super::custody::{AvailabilitySource, AvailableBody};
use super::{
    AvailabilityError, AvailabilityFrame, PayloadBytes, content_digest, row_digest, statement,
    verify_manifest,
};
use crate::{
    bytes::ByteAdmissionError,
    crypto::{Crypto, Signer},
    message::BlockHeader,
    types::{Hash32, HeightConfig, SIGNATURE_LEN},
};
use iroha_allocation::{AllocationBudget, ChargedBuffer};
use iroha_primitives::erasure::rs16::compact::{CodecAllocationError, Encoded, encode_funded};

/// Authoring failure. Resource refusal retains the worker's original request and completed phases.
#[derive(Debug)]
pub enum AuthoringError {
    /// Input or signed statement differs from its authenticated source.
    Invalid(AvailabilityError),
    /// Local signing refused; the exact request and completed signatures remain retained.
    SigningFailed {
        /// Manifest or row whose signing was refused.
        kind: crate::api::SigningKind,
        /// Original payload height.
        height: u64,
        /// Original payload view.
        view: u64,
        /// Local backend refusal.
        error: crate::crypto::SigningError,
    },
    /// Original-pool RS16 workspace or codeword could not be acquired.
    Codec(CodecAllocationError),
    /// Original-pool table backing/shared-control acquisition failed.
    Bytes(ByteAdmissionError),
}
/// Move-only request executed outside the consensus event loop. Its private phase owners retain
/// the original payload, codeword and completed signatures across local allocation refusals.
pub struct PayloadAuthoring {
    header: BlockHeader,
    payload: PayloadBytes,
    encoded: Option<Encoded>,
    pending: Option<ChargedBuffer<u8>>,
    frame: Option<AvailabilityFrame>,
}
/// Original author's completed body plus funded codeword for asynchronous dissemination.
/// Serving later derives the same codeword and reuses the preserved original signatures.
pub struct AuthoredBody {
    /// Immutable exact original body, subject to Core eligibility and durable-body barrier.
    pub body: AvailableBody,
    /// Original funded codeword used to disseminate all exact signed rows.
    pub codeword: Encoded,
}
impl PayloadAuthoring {
    /// Retain the unverified build request; this grants no availability or voting authority.
    pub fn new(header: BlockHeader, payload: PayloadBytes) -> Self {
        Self {
            header,
            payload,
            encoded: None,
            pending: None,
            frame: None,
        }
    }
    /// Complete encoding and original signatures, or return this exact request and its completed
    /// phase allocations. The host runs this outside `Core::handle`; no lazy async work is hidden.
    ///
    /// # Errors
    /// Returns the retained request if its source, signer, payload or funding is invalid,
    /// or encoding, table allocation or signature verification fails.
    #[allow(
        clippy::result_large_err,
        reason = "return original job owners on every refusal"
    )]
    pub fn complete(
        mut self,
        instance: Hash32,
        config: &HeightConfig,
        budget: &AllocationBudget,
        crypto: &dyn Crypto,
        signer: &dyn Signer,
    ) -> Result<AuthoredBody, (Self, AuthoringError)> {
        if let Err(error) = self.prepare(instance, config, budget, crypto, signer) {
            return Err((self, error));
        }
        Ok(AuthoredBody {
            body: AvailableBody::authored(
                AvailabilitySource::new(
                    instance,
                    self.header.height,
                    self.header.hash(crypto),
                    config.clone(),
                )
                .expect("prepared original authority"),
                self.header,
                self.frame.expect("verified exact table"),
                self.payload,
            ),
            codeword: self.encoded.expect("retained exact codeword"),
        })
    }
    fn prepare(
        &mut self,
        instance: Hash32,
        config: &HeightConfig,
        budget: &AllocationBudget,
        crypto: &dyn Crypto,
        signer: &dyn Signer,
    ) -> Result<(), AuthoringError> {
        let invalid = AuthoringError::Invalid;
        if self.header.instance != instance
            || self.header.epoch != config.epoch.id
            || !config.epoch.contains(self.header.height)
            || self.header.payload_len > config.params.max_block_bytes
            || config.committee.get(self.header.proposer) != Some(signer.public_key())
        {
            return Err(invalid(AvailabilityError::Source));
        }
        if !self.payload.admitted_to(budget) {
            return Err(invalid(AvailabilityError::ForeignBudget));
        }
        if self.payload.as_slice().len() != self.header.payload_len as usize
            || crate::preimage::payload_hash(crypto, self.payload.as_slice())
                != self.header.payload_hash
        {
            return Err(invalid(AvailabilityError::Digest));
        }
        let shape = config
            .epoch
            .da_layout
            .shape(u64::from(self.header.payload_len))
            .map_err(|_| invalid(AvailabilityError::Shape))?;
        if self.encoded.is_none() {
            self.encoded = Some(
                encode_funded(shape, self.payload.as_slice(), budget)
                    .map_err(AuthoringError::Codec)?,
            );
        }
        let encoded = self.encoded.as_ref().expect("original codeword retained");
        if encoded.shape() != shape || !encoded.belongs_to(budget) {
            return Err(invalid(AvailabilityError::Source));
        }
        if self.pending.is_none() && self.frame.is_none() {
            let count = shape.chunk_count();
            let mut bytes =
                ChargedBuffer::new(4 + SIGNATURE_LEN + count * (32 + SIGNATURE_LEN), budget)
                    .map_err(|e| AuthoringError::Bytes(ByteAdmissionError::Buffer(e)))?;
            bytes
                .append(
                    &u32::try_from(count)
                        .expect("protocol-bounded row count")
                        .to_be_bytes(),
                )
                .expect("exact table backing");
            for index in 0..count {
                let range = shape.chunk_range(index).expect("bounded row index");
                bytes
                    .append(row_digest(crypto, &encoded.codeword()[range]).as_bytes())
                    .expect("exact table backing");
            }
            self.header.availability_digest = content_digest(crypto, bytes.as_slice());
            self.pending = Some(bytes);
        }
        if let Some(bytes) = self.pending.as_mut() {
            let count = shape.chunk_count();
            let digest_bytes = 4 + count * 32;
            let signatures_written = (bytes.as_slice().len() - digest_bytes) / SIGNATURE_LEN;
            let bh = self.header.hash(crypto);
            for position in signatures_written..=count {
                let (kind, row) = if position == 0 {
                    (crate::api::SigningKind::PayloadManifest, None)
                } else {
                    let index = position - 1;
                    let hash = Hash32(
                        bytes.as_slice()[4 + 32 * index..4 + 32 * (index + 1)]
                            .try_into()
                            .expect("exact table hash"),
                    );
                    let length =
                        u32::try_from(shape.chunk_range(index).expect("bounded index").len())
                            .expect("protocol-bounded row length");
                    (
                        crate::api::SigningKind::PayloadRow,
                        Some((
                            u32::try_from(index).expect("protocol-bounded row index"),
                            length,
                            hash,
                        )),
                    )
                };
                let (message, used) = statement(&self.header, bh, row);
                let signature = match signer.sign(&message[..used]) {
                    Ok(signature) => signature,
                    Err(error) => {
                        // MS59: cache manufactured availability-signature bytes after refusal.
                        #[cfg(sumeragi_mutation = "MS59")]
                        {
                            let _ = (kind, error);
                            crate::types::Signature([0; SIGNATURE_LEN])
                        }
                        #[cfg(not(sumeragi_mutation = "MS59"))]
                        return Err(AuthoringError::SigningFailed {
                            kind,
                            height: self.header.height,
                            view: self.header.origin_view,
                            error,
                        });
                    }
                };
                bytes.append(&signature.0).expect("exact table backing");
            }
        }
        if let Some(bytes) = self.pending.take() {
            match AvailabilityFrame::from_charged(bytes, budget) {
                Ok(frame) => self.frame = Some(frame),
                Err((bytes, error)) => {
                    self.pending = Some(bytes);
                    return Err(AuthoringError::Bytes(error));
                }
            }
        }
        verify_manifest(
            instance,
            config,
            &self.header,
            self.frame.as_ref().expect("original table retained"),
            budget,
            crypto,
        )
        .map_err(invalid)?;
        Ok(())
    }
}
