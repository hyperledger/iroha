//! Canonical A1/W0/A2 payloads bound to the current Bootstrap session and keys.
//!
//! These payloads preserve original proof/accumulator bytes. Their source context
//! is checked against the session and then rederived by its genuine restore path;
//! transported metadata never authorizes a proof. The custody archive separately
//! binds the released capsule, predecessor and checkpoint ordinal. This component
//! supplies neither a complete fold schedule nor Omega or wallet-open authority.

use ff::PrimeField;
use iroha_pasta::msm::MemoryBudget;
use iroha_plonk::Protocol;
use iroha_plonk_recursion::ACCUMULATOR_BYTES;
use norito::{NoritoDeserialize, NoritoSchema, NoritoSerialize};

use super::{Error, FirstCheckpoint, Prover, Session, Terminal, WrapperCheckpoint};

/// The three pre-Omega Bootstrap payload kinds supported by this component.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointKind {
    /// A1's original proof; its public frame is rederived from retained sources.
    First,
    /// W0's original proof and canonical Vesta accumulator.
    Wrapper,
    /// A2 original proof and exact retained fold salt, rederived against W0.
    Terminal,
}
impl CheckpointKind {
    const fn tag(self) -> u8 {
        match self {
            Self::First => 0,
            Self::Wrapper => 1,
            Self::Terminal => 2,
        }
    }
}

/// Exact installed A1/W0/A2 identities and canonical payload lengths.
///
/// Construction is private and derives from this Prover's installed keys. The
/// native installation owner must still authenticate the whole PK/source catalog;
/// this metadata is not a signed artifact admission or a complete fold schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointLayout {
    kind: CheckpointKind,
    descriptor_digest: [u8; 32],
    verifying_key_digest: [u8; 32],
    proof_bytes: usize,
    payload_bytes: usize,
}
impl CheckpointLayout {
    /// The fixed native A1, W0 or A2 payload kind.
    pub const fn kind(&self) -> CheckpointKind {
        self.kind
    }
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
    /// Exact canonical Norito payload length, including native metadata and fold input.
    pub const fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }

    fn new(
        kind: CheckpointKind,
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
        if kind == CheckpointKind::Terminal {
            let specimen = TerminalPayload {
                version: 1,
                descriptor_digest,
                verifying_key_digest,
                source_context: [0; 32],
                fold_salt: [0; 32],
                proof,
            };
            let payload_bytes =
                norito::canonical_frame_len(&specimen).map_err(|_| Error::Artifact)?;
            if u32::try_from(payload_bytes).is_err() {
                return Err(Error::Artifact);
            }
            return Ok(Self {
                kind,
                descriptor_digest,
                verifying_key_digest,
                proof_bytes,
                payload_bytes,
            });
        }
        let specimen = Payload {
            version: 1,
            kind: kind.tag(),
            descriptor_digest,
            verifying_key_digest,
            source_context: [0; 32],
            proof,
            vesta: (kind == CheckpointKind::Wrapper).then_some([0; ACCUMULATOR_BYTES]),
        };
        let payload_bytes = norito::canonical_frame_len(&specimen).map_err(|_| Error::Artifact)?;
        if u32::try_from(payload_bytes).is_err() {
            return Err(Error::Artifact);
        }
        Ok(Self {
            kind,
            descriptor_digest,
            verifying_key_digest,
            proof_bytes,
            payload_bytes,
        })
    }
}

// No public constructor/decoder accepts this transported metadata as authority.
#[derive(NoritoSerialize, NoritoDeserialize, NoritoSchema)]
#[norito_schema(name = "iroha.kagemusha.native.bootstrap.checkpoint.v1")]
struct Payload {
    version: u16,
    kind: u8,
    descriptor_digest: [u8; 32],
    verifying_key_digest: [u8; 32],
    source_context: [u8; 32],
    proof: Vec<u8>,
    vesta: Option<[u8; ACCUMULATOR_BYTES]>,
}
impl Payload {
    fn check(&self, layout: &CheckpointLayout, source_context: [u8; 32]) -> Result<(), Error> {
        if layout.kind == CheckpointKind::Terminal
            || self.version != 1
            || self.kind != layout.kind.tag()
            || self.descriptor_digest != layout.descriptor_digest
            || self.verifying_key_digest != layout.verifying_key_digest
            || self.source_context != source_context
            || self.proof.len() != layout.proof_bytes
            || self.vesta.is_some() != (layout.kind == CheckpointKind::Wrapper)
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
        let payload: Self = norito::decode_canonical_with_limits(
            bytes,
            norito::canonical_decode_limits(layout.payload_bytes),
        )
        .map_err(|_| Error::Input)?;
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

#[derive(NoritoSerialize, NoritoDeserialize, NoritoSchema)]
#[norito_schema(name = "iroha.kagemusha.native.bootstrap.terminal_checkpoint.v1")]
struct TerminalPayload {
    version: u16,
    descriptor_digest: [u8; 32],
    verifying_key_digest: [u8; 32],
    source_context: [u8; 32],
    fold_salt: [u8; 32],
    proof: Vec<u8>,
}
impl TerminalPayload {
    fn check(&self, layout: &CheckpointLayout, context: [u8; 32]) -> Result<(), Error> {
        if layout.kind != CheckpointKind::Terminal
            || self.version != 1
            || self.descriptor_digest != layout.descriptor_digest
            || self.verifying_key_digest != layout.verifying_key_digest
            || self.source_context != context
            || self.proof.len() != layout.proof_bytes
            || Option::<super::Fp>::from(super::Fp::from_repr(self.fold_salt)).is_none()
        {
            return Err(Error::Input);
        }
        Ok(())
    }
    fn encode(self, layout: &CheckpointLayout, context: [u8; 32]) -> Result<Vec<u8>, Error> {
        self.check(layout, context)?;
        let bytes = norito::encode_canonical(&self).map_err(|_| Error::Input)?;
        if bytes.len() != layout.payload_bytes {
            return Err(Error::Input);
        }
        Ok(bytes)
    }
    fn decode(bytes: &[u8], layout: &CheckpointLayout, context: [u8; 32]) -> Result<Self, Error> {
        if bytes.len() != layout.payload_bytes {
            return Err(Error::Input);
        }
        let payload: Self = norito::decode_canonical_with_limits(
            bytes,
            norito::canonical_decode_limits(layout.payload_bytes),
        )
        .map_err(|_| Error::Input)?;
        payload.check(layout, context)?;
        Ok(payload)
    }
}

impl Prover {
    fn checkpoint_layout(&self, kind: CheckpointKind) -> Result<CheckpointLayout, Error> {
        match kind {
            CheckpointKind::First => CheckpointLayout::new(
                kind,
                *self.first.binding().digest(),
                self.first
                    .key()
                    .kagemusha_digest(self.first.binding())
                    .map_err(|_| Error::Artifact)?
                    .to_repr(),
                Protocol::new(self.first.binding().descriptor())
                    .map_err(|_| Error::Artifact)?
                    .proof_length(),
            ),
            CheckpointKind::Wrapper => CheckpointLayout::new(
                kind,
                *self.wrapper.binding().digest(),
                self.wrapper
                    .key()
                    .kagemusha_digest(self.wrapper.binding())
                    .map_err(|_| Error::Artifact)?
                    .to_repr(),
                Protocol::new(self.wrapper.binding().descriptor())
                    .map_err(|_| Error::Artifact)?
                    .proof_length(),
            ),
            CheckpointKind::Terminal => CheckpointLayout::new(
                kind,
                *self.terminal.binding().digest(),
                self.terminal
                    .key()
                    .kagemusha_digest(self.terminal.binding())
                    .map_err(|_| Error::Artifact)?
                    .to_repr(),
                Protocol::new(self.terminal.binding().descriptor())
                    .map_err(|_| Error::Artifact)?
                    .proof_length(),
            ),
        }
    }

    /// Derive the exact A1/W0/A2 payload identities/lengths from the installed keys.
    /// Final Omega and whole producer-catalog authentication remain separate.
    ///
    /// # Errors
    /// An installed descriptor/key cannot define a canonical bounded payload.
    pub fn checkpoint_layouts(&self) -> Result<[CheckpointLayout; 3], Error> {
        Ok([
            self.checkpoint_layout(CheckpointKind::First)?,
            self.checkpoint_layout(CheckpointKind::Wrapper)?,
            self.checkpoint_layout(CheckpointKind::Terminal)?,
        ])
    }
}

impl Session<'_> {
    /// Canonically retain a genuine A1 checkpoint after re-verifying its exact
    /// public/context/claim and proof under this session's installed A1 key.
    ///
    /// # Errors
    /// Wrong original length, source context/key, canonical encoding or proof.
    pub fn encode_first_checkpoint(
        &self,
        checkpoint: &FirstCheckpoint,
        budget: MemoryBudget,
    ) -> Result<Vec<u8>, Error> {
        self.encode_first_checkpoint_cancellable(checkpoint, budget, None)
    }
    /// Execute the same native check with an explicit operation signal.
    /// # Errors
    /// As the ordinary entry point, or cancellation without a partial verdict.
    pub fn encode_first_checkpoint_cancellable(
        &self,
        checkpoint: &FirstCheckpoint,
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Vec<u8>, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        let layout = self.prover.checkpoint_layout(CheckpointKind::First)?;
        if checkpoint.proof.len() != layout.proof_bytes {
            return Err(Error::Input);
        }
        let checked = self.prepared.resume_first_cancellable(
            self.prover.first.key(),
            self.prover.first.binding(),
            checkpoint.clone(),
            budget,
            cancellation,
        )?;
        let source_context = self.prepared.immutable_context_digest()?.to_repr();
        Payload {
            version: 1,
            kind: layout.kind.tag(),
            descriptor_digest: layout.descriptor_digest,
            verifying_key_digest: layout.verifying_key_digest,
            source_context,
            proof: checked.proof,
            vesta: None,
        }
        .encode(&layout, source_context)
    }

    /// Restore one exact canonical A1 payload and completely verify its proof
    /// against public/context/claim rederived from the retained session inputs.
    ///
    /// # Errors
    /// Truncation/trailing bytes, wrong kind/key/context/count, or failed proof.
    pub fn restore_first_checkpoint(
        &self,
        bytes: &[u8],
        budget: MemoryBudget,
    ) -> Result<FirstCheckpoint, Error> {
        self.restore_first_checkpoint_cancellable(bytes, budget, None)
    }
    /// Execute the same native check with an explicit operation signal.
    /// # Errors
    /// As the ordinary entry point, or cancellation without a partial verdict.
    pub fn restore_first_checkpoint_cancellable(
        &self,
        bytes: &[u8],
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<FirstCheckpoint, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        let layout = self.prover.checkpoint_layout(CheckpointKind::First)?;
        let payload = Payload::decode(
            bytes,
            &layout,
            self.prepared.immutable_context_digest()?.to_repr(),
        )?;
        self.restore_first_cancellable(payload.proof, budget, cancellation)
    }

    /// Canonically retain W0's original proof and accumulator after complete
    /// key/context/proof verification and the genuine Vesta decide.
    ///
    /// # Errors
    /// Wrong source, length/key/context, proof or undecidable accumulator.
    pub fn encode_wrapper_checkpoint(
        &self,
        checkpoint: &WrapperCheckpoint,
        budget: MemoryBudget,
    ) -> Result<Vec<u8>, Error> {
        self.encode_wrapper_checkpoint_cancellable(checkpoint, budget, None)
    }
    /// Execute the same native check with an explicit operation signal.
    /// # Errors
    /// As the ordinary entry point, or cancellation without a partial verdict.
    pub fn encode_wrapper_checkpoint_cancellable(
        &self,
        checkpoint: &WrapperCheckpoint,
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Vec<u8>, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        let layout = self.prover.checkpoint_layout(CheckpointKind::Wrapper)?;
        if checkpoint.proof.len() != layout.proof_bytes {
            return Err(Error::Input);
        }
        let checked = self.prepared.resume_wrapper_cancellable(
            &self.prover.w,
            checkpoint.clone(),
            budget,
            cancellation,
        )?;
        let source_context = self.prepared.immutable_context_digest()?.to_repr();
        Payload {
            version: 1,
            kind: layout.kind.tag(),
            descriptor_digest: layout.descriptor_digest,
            verifying_key_digest: layout.verifying_key_digest,
            source_context,
            proof: checked.proof,
            vesta: Some(checked.vesta.to_bytes()),
        }
        .encode(&layout, source_context)
    }

    /// Restore W0 from one exact canonical payload. This recomputes the source
    /// context, verifies the installed W proof and fully decides its Vesta claim.
    ///
    /// # Errors
    /// Wrong canonical frame/kind/key/context/count, proof or accumulator.
    pub fn restore_wrapper_checkpoint(
        &self,
        bytes: &[u8],
        budget: MemoryBudget,
    ) -> Result<WrapperCheckpoint, Error> {
        self.restore_wrapper_checkpoint_cancellable(bytes, budget, None)
    }
    /// Execute the same native check with an explicit operation signal.
    /// # Errors
    /// As the ordinary entry point, or cancellation without a partial verdict.
    pub fn restore_wrapper_checkpoint_cancellable(
        &self,
        bytes: &[u8],
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<WrapperCheckpoint, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        let layout = self.prover.checkpoint_layout(CheckpointKind::Wrapper)?;
        let payload = Payload::decode(
            bytes,
            &layout,
            self.prepared.immutable_context_digest()?.to_repr(),
        )?;
        let vesta = payload.vesta.ok_or(Error::Input)?;
        self.restore_wrapper_cancellable(payload.proof, &vesta, budget, cancellation)
    }

    /// Retain genuine A2 against the original W0, exact source context and canonical fold salt.
    /// # Errors
    /// Changed source/key/proof/frame/claim, malformed salt or failed full native verification.
    pub fn encode_terminal_checkpoint(
        &self,
        wrapper: &WrapperCheckpoint,
        terminal: &Terminal,
        salt: super::Fp,
        budget: MemoryBudget,
    ) -> Result<Vec<u8>, Error> {
        self.encode_terminal_checkpoint_cancellable(wrapper, terminal, salt, budget, None)
    }
    /// Execute the same native check with an explicit operation signal.
    /// # Errors
    /// As the ordinary entry point, or cancellation without a partial verdict.
    pub fn encode_terminal_checkpoint_cancellable(
        &self,
        wrapper: &WrapperCheckpoint,
        terminal: &Terminal,
        salt: super::Fp,
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Vec<u8>, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        let checked = self.restore_terminal_cancellable(
            wrapper,
            terminal.proof.clone(),
            salt,
            budget,
            cancellation,
        )?;
        if checked.instances != terminal.instances
            || checked.pallas.to_bytes() != terminal.pallas.to_bytes()
            || checked.vesta.to_bytes() != terminal.vesta.to_bytes()
            || checked.opening.g() != terminal.opening.g()
            || checked.opening.challenges() != terminal.opening.challenges()
            || checked.opening.source_k() != terminal.opening.source_k()
        {
            return Err(Error::Input);
        }
        let layout = self.prover.checkpoint_layout(CheckpointKind::Terminal)?;
        let context = self.prepared.immutable_context_digest()?.to_repr();
        TerminalPayload {
            version: 1,
            descriptor_digest: layout.descriptor_digest,
            verifying_key_digest: layout.verifying_key_digest,
            source_context: context,
            fold_salt: salt.to_repr(),
            proof: checked.proof,
        }
        .encode(&layout, context)
    }
    /// Restore A2 by replaying its real fold from W0 and fully verifying the original A2.
    /// # Errors
    /// Wrong bounded original/source/key/salt, changed frame or failed proof/decide.
    pub fn restore_terminal_checkpoint(
        &self,
        wrapper: &WrapperCheckpoint,
        bytes: &[u8],
        budget: MemoryBudget,
    ) -> Result<Terminal, Error> {
        self.restore_terminal_checkpoint_cancellable(wrapper, bytes, budget, None)
    }
    /// Execute the same native check with an explicit operation signal.
    /// # Errors
    /// As the ordinary entry point, or cancellation without a partial verdict.
    pub fn restore_terminal_checkpoint_cancellable(
        &self,
        wrapper: &WrapperCheckpoint,
        bytes: &[u8],
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Terminal, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        let layout = self.prover.checkpoint_layout(CheckpointKind::Terminal)?;
        let payload = TerminalPayload::decode(
            bytes,
            &layout,
            self.prepared.immutable_context_digest()?.to_repr(),
        )?;
        let salt = Option::<super::Fp>::from(super::Fp::from_repr(payload.fold_salt))
            .ok_or(Error::Input)?;
        self.restore_terminal_cancellable(wrapper, payload.proof, salt, budget, cancellation)
    }
}

#[cfg(test)]
#[path = "checkpoint/tests.rs"]
mod tests;
