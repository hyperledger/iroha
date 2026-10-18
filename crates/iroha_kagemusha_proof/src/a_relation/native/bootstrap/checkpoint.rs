//! Canonical terminal A payload bound to the current Bootstrap session and key.
//!
//! The payload preserves the original proof bytes. Its source context is checked
//! against the session, and the proof is then completely reverified by the
//! genuine restore path against the frame and Pallas claim rederived from the
//! session's originals; transported metadata never authorizes a proof. The
//! custody archive separately binds the released capsule, predecessor and
//! checkpoint ordinal. This component supplies neither Omega nor wallet-open
//! authority.

use ff::PrimeField;
use iroha_pasta::msm::MemoryBudget;
use iroha_plonk::Protocol;
use norito::{NoritoDeserialize, NoritoSchema, NoritoSerialize};

use super::{Error, Prover, Session, Terminal};

/// Exact installed terminal A identity and canonical payload length.
///
/// Construction is private and derives from this Prover's installed key. The
/// native installation owner must still authenticate the whole PK/source catalog;
/// this metadata is not a signed artifact admission or a complete fold schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointLayout {
    descriptor_digest: [u8; 32],
    verifying_key_digest: [u8; 32],
    proof_bytes: usize,
    payload_bytes: usize,
}
impl CheckpointLayout {
    /// Exact installed native descriptor identity.
    pub const fn descriptor_digest(&self) -> &[u8; 32] {
        &self.descriptor_digest
    }
    /// Complete descriptor-bound installed key identity in its native base field.
    pub const fn verifying_key_digest(&self) -> &[u8; 32] {
        &self.verifying_key_digest
    }
    /// Exact original proof length derived from the installed Protocol.
    pub const fn proof_bytes(&self) -> usize {
        self.proof_bytes
    }
    /// Exact canonical Norito payload length, including native metadata.
    pub const fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }

    fn new(
        descriptor_digest: [u8; 32],
        verifying_key_digest: [u8; 32],
        proof_bytes: usize,
    ) -> Result<Self, Error> {
        if proof_bytes == 0 || u32::try_from(proof_bytes).is_err() {
            return Err(Error::Artifact);
        }
        // Only a counting specimen: these zero bytes are never parsed as a proof,
        // imported, decided or returned as an admitted checkpoint. Canonical frame
        // length depends on the fixed field/sequence lengths, not their contents.
        let mut proof = Vec::new();
        proof
            .try_reserve_exact(proof_bytes)
            .map_err(|_| Error::Artifact)?;
        proof.resize(proof_bytes, 0);
        let specimen = Payload {
            version: 1,
            descriptor_digest,
            verifying_key_digest,
            source_context: [0; 32],
            proof,
        };
        let payload_bytes = norito::canonical_frame_len(&specimen).map_err(|_| Error::Artifact)?;
        if u32::try_from(payload_bytes).is_err() {
            return Err(Error::Artifact);
        }
        Ok(Self {
            descriptor_digest,
            verifying_key_digest,
            proof_bytes,
            payload_bytes,
        })
    }
}

// No public constructor/decoder accepts this transported metadata as authority.
#[derive(NoritoSerialize, NoritoDeserialize, NoritoSchema)]
#[norito_schema(name = "iroha.kagemusha.native.bootstrap.terminal_checkpoint.v1")]
struct Payload {
    version: u16,
    descriptor_digest: [u8; 32],
    verifying_key_digest: [u8; 32],
    source_context: [u8; 32],
    proof: Vec<u8>,
}
impl Payload {
    fn check(&self, layout: &CheckpointLayout, source_context: [u8; 32]) -> Result<(), Error> {
        if self.version != 1
            || self.descriptor_digest != layout.descriptor_digest
            || self.verifying_key_digest != layout.verifying_key_digest
            || self.source_context != source_context
            || self.proof.len() != layout.proof_bytes
        {
            return Err(Error::Input);
        }
        Ok(())
    }
    fn decode(
        bytes: &[u8],
        layout: &CheckpointLayout,
        source_context: [u8; 32],
    ) -> Result<Self, Error> {
        // Bound the complete frame before any owned Norito sequence allocation.
        if bytes.len() != layout.payload_bytes {
            return Err(Error::Input);
        }
        let payload: Self = norito::decode_canonical_for_admission(
            bytes,
            norito::canonical_decode_limits(layout.payload_bytes),
        )?;
        payload.check(layout, source_context)?;
        Ok(payload)
    }
    fn encode(self, layout: &CheckpointLayout, source_context: [u8; 32]) -> Result<Vec<u8>, Error> {
        self.check(layout, source_context)?;
        let bytes = norito::encode_canonical(&self).map_err(|_| Error::Input)?;
        if bytes.len() != layout.payload_bytes {
            return Err(Error::Input);
        }
        Ok(bytes)
    }
}

impl Prover {
    fn checkpoint_layout(&self) -> Result<CheckpointLayout, Error> {
        CheckpointLayout::new(
            *self.terminal.binding().digest(),
            self.terminal
                .key()
                .kagemusha_digest(self.terminal.binding())
                .map_err(|_| Error::Artifact)?
                .to_repr(),
            Protocol::new(self.terminal.binding().descriptor())
                .map_err(|_| Error::Artifact)?
                .proof_length(),
        )
    }

    /// Derive the single terminal A payload identity/length from the installed key.
    /// Final Omega and whole producer-catalog authentication remain separate.
    ///
    /// # Errors
    /// The installed descriptor/key cannot define a canonical bounded payload.
    pub fn checkpoint_layouts(&self) -> Result<[CheckpointLayout; 1], Error> {
        Ok([self.checkpoint_layout()?])
    }
}

impl Session<'_> {
    /// Canonically retain a genuine terminal A after completely re-verifying its
    /// proof, frame, Pallas claim and own opening under this session's key.
    ///
    /// # Errors
    /// Wrong original length, changed source/key/proof/frame/claim, canonical
    /// encoding or failed full native verification.
    pub fn encode_terminal_checkpoint(
        &self,
        terminal: &Terminal,
        budget: MemoryBudget,
    ) -> Result<Vec<u8>, Error> {
        self.encode_terminal_checkpoint_cancellable(terminal, budget, None)
    }
    /// Execute the same native check with an explicit operation signal.
    /// # Errors
    /// As the ordinary entry point, or cancellation without a partial verdict.
    pub fn encode_terminal_checkpoint_cancellable(
        &self,
        terminal: &Terminal,
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Vec<u8>, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        let layout = self.prover.checkpoint_layout()?;
        if terminal.proof.len() != layout.proof_bytes {
            return Err(Error::Input);
        }
        let checked =
            self.restore_terminal_cancellable(terminal.proof.clone(), budget, cancellation)?;
        if checked.instances != terminal.instances
            || checked.pallas.to_bytes() != terminal.pallas.to_bytes()
            || checked.opening.g() != terminal.opening.g()
            || checked.opening.challenges() != terminal.opening.challenges()
            || checked.opening.source_k() != terminal.opening.source_k()
        {
            return Err(Error::Input);
        }
        let source_context = self.prepared.immutable_context_digest()?.to_repr();
        Payload {
            version: 1,
            descriptor_digest: layout.descriptor_digest,
            verifying_key_digest: layout.verifying_key_digest,
            source_context,
            proof: checked.proof,
        }
        .encode(&layout, source_context)
    }

    /// Restore the terminal A from one exact canonical payload and completely
    /// verify its proof against the frame and Pallas claim rederived from the
    /// retained session inputs.
    ///
    /// # Errors
    /// Truncation/trailing bytes, wrong key/context/length or failed proof/decide.
    pub fn restore_terminal_checkpoint(
        &self,
        bytes: &[u8],
        budget: MemoryBudget,
    ) -> Result<Terminal, Error> {
        self.restore_terminal_checkpoint_cancellable(bytes, budget, None)
    }
    /// Execute the same native check with an explicit operation signal.
    /// # Errors
    /// As the ordinary entry point, or cancellation without a partial verdict.
    pub fn restore_terminal_checkpoint_cancellable(
        &self,
        bytes: &[u8],
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Terminal, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        let layout = self.prover.checkpoint_layout()?;
        let payload = Payload::decode(
            bytes,
            &layout,
            self.prepared.immutable_context_digest()?.to_repr(),
        )?;
        self.restore_terminal_cancellable(payload.proof, budget, cancellation)
    }
}

#[cfg(test)]
#[path = "checkpoint/tests.rs"]
mod tests;
