//! Canonical source-bound custody for every fixed Receive A/W stage.
//!
//! Metadata and exact sizes derive from installed native keys. Decoding supplies
//! original bytes only: restoration invokes the genuine session verifier, rederives
//! public frames from the prior opaque checkpoint and checks complete claims.
//! This module does not authenticate a proving catalog or produce final Omega.

use ff::PrimeField;
use iroha_pasta::msm::MemoryBudget;
use iroha_plonk::Protocol;
use iroha_plonk_recursion::ACCUMULATOR_BYTES;
use norito::{NoritoDeserialize, NoritoSchema, NoritoSerialize};

use super::{
    A_STAGE_COUNT, ACheckpoint, Error, Prover, Session, W_STAGE_COUNT, WCheckpoint, context_digest,
};

/// Fixed native stage kind; no transported kind selects a circuit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointKind {
    /// One of the ten original A proof stages.
    A,
    /// One of the nine original W continuations.
    W,
}
impl CheckpointKind {
    const fn tag(self) -> u8 {
        match self {
            Self::A => 0,
            Self::W => 1,
        }
    }
}

/// Exact immutable layout derived from this installed native stage's key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointLayout {
    kind: CheckpointKind,
    stage: u32,
    descriptor_digest: [u8; 32],
    verifying_key_digest: [u8; 32],
    proof_bytes: usize,
    payload_bytes: usize,
}
impl CheckpointLayout {
    /// Fixed native A or W role.
    pub const fn kind(&self) -> CheckpointKind {
        self.kind
    }
    /// Native zero-based ordinal within the fixed role.
    pub const fn stage(&self) -> u32 {
        self.stage
    }
    /// Exact installed native descriptor identity.
    pub const fn descriptor_digest(&self) -> &[u8; 32] {
        &self.descriptor_digest
    }
    /// Complete descriptor-bound installed native key identity.
    pub const fn verifying_key_digest(&self) -> &[u8; 32] {
        &self.verifying_key_digest
    }
    /// Exact original proof length from the installed protocol.
    pub const fn proof_bytes(&self) -> usize {
        self.proof_bytes
    }
    /// Exact canonical Norito payload length, including the carried claim.
    pub const fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }

    fn new(
        kind: CheckpointKind,
        stage: usize,
        descriptor_digest: [u8; 32],
        verifying_key_digest: [u8; 32],
        proof_bytes: usize,
    ) -> Result<Self, Error> {
        let limit = match kind {
            CheckpointKind::A => A_STAGE_COUNT,
            CheckpointKind::W => W_STAGE_COUNT,
        };
        if stage >= limit || proof_bytes == 0 || u32::try_from(proof_bytes).is_err() {
            return Err(Error::Artifact);
        }
        let stage = u32::try_from(stage).map_err(|_| Error::Artifact)?;
        // Counting specimen only. These zero bytes are never treated as a proof,
        // imported, decided or returned as an admitted source checkpoint.
        let mut proof = Vec::new();
        proof
            .try_reserve_exact(proof_bytes)
            .map_err(|_| Error::Artifact)?;
        proof.resize(proof_bytes, 0);
        let specimen = Payload {
            version: 1,
            kind: kind.tag(),
            stage,
            descriptor_digest,
            verifying_key_digest,
            source_context: [0; 32],
            proof,
            accumulator: [0; ACCUMULATOR_BYTES],
        };
        let payload_bytes = norito::canonical_frame_len(&specimen).map_err(|_| Error::Artifact)?;
        if u32::try_from(payload_bytes).is_err() {
            return Err(Error::Artifact);
        }
        Ok(Self {
            kind,
            stage,
            descriptor_digest,
            verifying_key_digest,
            proof_bytes,
            payload_bytes,
        })
    }
}

#[derive(NoritoSerialize, NoritoDeserialize, NoritoSchema)]
#[norito_schema(name = "iroha.kagemusha.native.receive.checkpoint.v1")]
struct Payload {
    version: u16,
    kind: u8,
    stage: u32,
    descriptor_digest: [u8; 32],
    verifying_key_digest: [u8; 32],
    source_context: [u8; 32],
    proof: Vec<u8>,
    accumulator: [u8; ACCUMULATOR_BYTES],
}
impl Payload {
    fn check(&self, layout: &CheckpointLayout) -> Result<(), Error> {
        if self.version != 1
            || self.kind != layout.kind.tag()
            || self.stage != layout.stage
            || self.descriptor_digest != layout.descriptor_digest
            || self.verifying_key_digest != layout.verifying_key_digest
            || self.proof.len() != layout.proof_bytes
        {
            return Err(Error::Input);
        }
        Ok(())
    }
    fn decode(bytes: &[u8], layout: &CheckpointLayout) -> Result<Self, Error> {
        // Bound the entire original before allocating any owned Norito sequence.
        if bytes.len() != layout.payload_bytes {
            return Err(Error::Input);
        }
        let payload: Self = norito::decode_canonical_with_limits(
            bytes,
            norito::canonical_decode_limits(layout.payload_bytes),
        )
        .map_err(|_| Error::Input)?;
        payload.check(layout)?;
        Ok(payload)
    }
    fn encode(self, layout: &CheckpointLayout) -> Result<Vec<u8>, Error> {
        self.check(layout)?;
        let bytes = norito::encode_canonical(&self).map_err(|_| Error::Input)?;
        if bytes.len() != layout.payload_bytes {
            return Err(Error::Input);
        }
        Ok(bytes)
    }
}

impl Prover {
    fn checkpoint_layout(
        &self,
        kind: CheckpointKind,
        stage: usize,
    ) -> Result<CheckpointLayout, Error> {
        match kind {
            CheckpointKind::A => {
                let key = self.a.get(stage).ok_or(Error::Artifact)?;
                CheckpointLayout::new(
                    kind,
                    stage,
                    *key.binding().digest(),
                    key.key()
                        .kagemusha_digest(key.binding())
                        .map_err(|_| Error::Artifact)?
                        .to_repr(),
                    Protocol::new(key.binding().descriptor())
                        .map_err(|_| Error::Artifact)?
                        .proof_length(),
                )
            }
            CheckpointKind::W => {
                let key = self.w.get(stage).ok_or(Error::Artifact)?;
                CheckpointLayout::new(
                    kind,
                    stage,
                    *key.binding().digest(),
                    key.key()
                        .kagemusha_digest(key.binding())
                        .map_err(|_| Error::Artifact)?
                        .to_repr(),
                    Protocol::new(key.binding().descriptor())
                        .map_err(|_| Error::Artifact)?
                        .proof_length(),
                )
            }
        }
    }

    /// Derive every exact A/W custody payload layout in actual execution order.
    /// Final A remains a source for separately installed Omega, never a wallet verdict.
    ///
    /// # Errors
    /// An installed descriptor/key cannot define the fixed canonical payload.
    pub fn checkpoint_layouts(&self) -> Result<Vec<CheckpointLayout>, Error> {
        let mut layouts = Vec::with_capacity(A_STAGE_COUNT + W_STAGE_COUNT);
        for stage in 0..A_STAGE_COUNT {
            layouts.push(self.checkpoint_layout(CheckpointKind::A, stage)?);
            if stage < W_STAGE_COUNT {
                layouts.push(self.checkpoint_layout(CheckpointKind::W, stage)?);
            }
        }
        Ok(layouts)
    }
}

impl Session<'_> {
    /// Retain a genuine A checkpoint after its exact native proof/full claims verify.
    ///
    /// # Errors
    /// Another source/stage/key, changed public/context or failed proof/decide.
    pub fn encode_a_checkpoint(
        &self,
        source: &ACheckpoint,
        budget: MemoryBudget,
    ) -> Result<Vec<u8>, Error> {
        self.encode_a_checkpoint_cancellable(source, budget, None)
    }
    /// Execute the same native check with an explicit operation signal.
    /// # Errors
    /// As the ordinary entry point, or cancellation without a partial verdict.
    pub fn encode_a_checkpoint_cancellable(
        &self,
        source: &ACheckpoint,
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Vec<u8>, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        self.verify_a_cancellable(source, budget, cancellation)?;
        let layout = self
            .prover
            .checkpoint_layout(CheckpointKind::A, source.stage)?;
        Payload {
            version: 1,
            kind: layout.kind.tag(),
            stage: layout.stage,
            descriptor_digest: layout.descriptor_digest,
            verifying_key_digest: layout.verifying_key_digest,
            source_context: context_digest(&source.circuit.source)?.to_repr(),
            proof: source.proof.clone(),
            accumulator: source.circuit.pallas.to_bytes(),
        }
        .encode(&layout)
    }

    /// Restore A1 from one bounded original and this session's retained exact sources.
    ///
    /// # Errors
    /// Wrong fixed layout/context, noncanonical claim or failed full native verification.
    pub fn restore_first_checkpoint(
        &self,
        original: &[u8],
        budget: MemoryBudget,
    ) -> Result<ACheckpoint, Error> {
        self.restore_first_checkpoint_cancellable(original, budget, None)
    }
    /// Execute the same native check with an explicit operation signal.
    /// # Errors
    /// As the ordinary entry point, or cancellation without a partial verdict.
    pub fn restore_first_checkpoint_cancellable(
        &self,
        original: &[u8],
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<ACheckpoint, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        let layout = self.prover.checkpoint_layout(CheckpointKind::A, 0)?;
        let payload = Payload::decode(original, &layout)?;
        let checked = self.restore_first_cancellable(
            payload.proof,
            &payload.accumulator,
            budget,
            cancellation,
        )?;
        if context_digest(&checked.circuit.source)?.to_repr() != payload.source_context {
            return Err(Error::Input);
        }
        Ok(checked)
    }

    /// Restore the exact next A from its verified prior W and bounded original.
    /// No caller provides public frames, result bits or artifact selection.
    ///
    /// # Errors
    /// Wrong source/order/layout/context, noncanonical claim or failed complete verification.
    pub fn restore_a_checkpoint(
        &self,
        prior: &WCheckpoint,
        original: &[u8],
        budget: MemoryBudget,
    ) -> Result<ACheckpoint, Error> {
        self.restore_a_checkpoint_cancellable(prior, original, budget, None)
    }
    /// Execute the same native check with an explicit operation signal.
    /// # Errors
    /// As the ordinary entry point, or cancellation without a partial verdict.
    pub fn restore_a_checkpoint_cancellable(
        &self,
        prior: &WCheckpoint,
        original: &[u8],
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<ACheckpoint, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        self.require_a(&prior.source)?;
        let next = prior.source.stage.checked_add(1).ok_or(Error::Input)?;
        let layout = self.prover.checkpoint_layout(CheckpointKind::A, next)?;
        let payload = Payload::decode(original, &layout)?;
        if context_digest(&prior.source.circuit.source)?.to_repr() != payload.source_context {
            return Err(Error::Input);
        }
        self.restore_a_cancellable(
            prior,
            payload.proof,
            &payload.accumulator,
            budget,
            cancellation,
        )
    }

    /// Retain the original W proof/full deciding claim after its real native restore.
    ///
    /// # Errors
    /// Wrong source/order/layout or failed complete native verification.
    pub fn encode_wrapper_checkpoint(
        &self,
        source: &WCheckpoint,
        budget: MemoryBudget,
    ) -> Result<Vec<u8>, Error> {
        self.encode_wrapper_checkpoint_cancellable(source, budget, None)
    }
    /// Execute the same native check with an explicit operation signal.
    /// # Errors
    /// As the ordinary entry point, or cancellation without a partial verdict.
    pub fn encode_wrapper_checkpoint_cancellable(
        &self,
        source: &WCheckpoint,
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Vec<u8>, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        let checked = self.restore_wrapper_cancellable(
            &source.source,
            source.proof.clone(),
            &source.vesta.to_bytes(),
            budget,
            cancellation,
        )?;
        let layout = self
            .prover
            .checkpoint_layout(CheckpointKind::W, checked.source.stage)?;
        Payload {
            version: 1,
            kind: layout.kind.tag(),
            stage: layout.stage,
            descriptor_digest: layout.descriptor_digest,
            verifying_key_digest: layout.verifying_key_digest,
            source_context: context_digest(&checked.source.circuit.source)?.to_repr(),
            proof: checked.proof,
            accumulator: checked.vesta.to_bytes(),
        }
        .encode(&layout)
    }

    /// Restore a bounded original W only from its exact native source A capability.
    ///
    /// # Errors
    /// Wrong source/order/layout/context, canonical claim or failed native proof/decide.
    pub fn restore_wrapper_checkpoint(
        &self,
        prior: &ACheckpoint,
        original: &[u8],
        budget: MemoryBudget,
    ) -> Result<WCheckpoint, Error> {
        self.restore_wrapper_checkpoint_cancellable(prior, original, budget, None)
    }
    /// Execute the same native check with an explicit operation signal.
    /// # Errors
    /// As the ordinary entry point, or cancellation without a partial verdict.
    pub fn restore_wrapper_checkpoint_cancellable(
        &self,
        prior: &ACheckpoint,
        original: &[u8],
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<WCheckpoint, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        self.require_a(prior)?;
        let layout = self
            .prover
            .checkpoint_layout(CheckpointKind::W, prior.stage)?;
        let payload = Payload::decode(original, &layout)?;
        if context_digest(&prior.circuit.source)?.to_repr() != payload.source_context {
            return Err(Error::Input);
        }
        self.restore_wrapper_cancellable(
            prior,
            payload.proof,
            &payload.accumulator,
            budget,
            cancellation,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counting_layout_preserves_every_fixed_stage_and_rejects_overflow() {
        // Metadata/counting only; no zero proof is restored or admitted here.
        for stage in 0..A_STAGE_COUNT {
            let layout =
                CheckpointLayout::new(CheckpointKind::A, stage, [1; 32], [2; 32], 8480).unwrap();
            assert_eq!(layout.stage(), u32::try_from(stage).unwrap());
            assert_eq!(layout.proof_bytes(), 8480);
            assert!(layout.payload_bytes() > 8480 + ACCUMULATOR_BYTES);
        }
        for stage in 0..W_STAGE_COUNT {
            assert!(
                CheckpointLayout::new(CheckpointKind::W, stage, [1; 32], [2; 32], 4096).is_ok()
            );
        }
        assert!(
            CheckpointLayout::new(CheckpointKind::A, A_STAGE_COUNT, [1; 32], [2; 32], 8480)
                .is_err()
        );
        assert!(
            CheckpointLayout::new(CheckpointKind::W, W_STAGE_COUNT, [1; 32], [2; 32], 4096)
                .is_err()
        );
        assert!(CheckpointLayout::new(CheckpointKind::A, 0, [1; 32], [2; 32], 0).is_err());
        assert!(CheckpointLayout::new(CheckpointKind::A, 0, [1; 32], [2; 32], usize::MAX).is_err());
    }

    #[test]
    fn canonical_payload_metadata_cannot_select_another_stage_key_or_length() {
        // Original codec checks only. These labelled stand-in proof/claim bytes
        // are never passed to Session restore or treated as acceptance evidence.
        let layout = CheckpointLayout::new(CheckpointKind::A, 2, [1; 32], [2; 32], 32).unwrap();
        let payload = || Payload {
            version: 1,
            kind: 0,
            stage: 2,
            descriptor_digest: [1; 32],
            verifying_key_digest: [2; 32],
            source_context: [3; 32],
            proof: vec![0; 32],
            accumulator: [0; ACCUMULATOR_BYTES],
        };
        let original = payload().encode(&layout).unwrap();
        assert!(Payload::decode(&original, &layout).is_ok());
        for mutation in 0..6 {
            let mut changed = payload();
            match mutation {
                0 => changed.version = 2,
                1 => changed.kind = 1,
                2 => changed.stage = 3,
                3 => changed.descriptor_digest[0] ^= 1,
                4 => changed.verifying_key_digest[0] ^= 1,
                _ => {
                    changed.proof.pop();
                }
            }
            assert!(changed.encode(&layout).is_err());
        }
        let mut trailing = original.clone();
        trailing.push(0);
        assert!(Payload::decode(&trailing, &layout).is_err());
        assert!(Payload::decode(&original[..original.len() - 1], &layout).is_err());
    }
}
