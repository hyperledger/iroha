//! Canonical terminal A payload bound to the current Unload/Retiring session and key.
//!
//! The payload preserves the original proof bytes and the exact carried Pallas claim
//! of the terminal fold, which a fresh session cannot recreate. Its source context is
//! checked against the session; restoration then decides that claim in full and
//! completely reverifies the proof against the frame rederived from the session's
//! originals and that claim. Transported metadata never authorizes a proof. The
//! custody archive separately binds the released capsule, predecessor and checkpoint
//! ordinal. This component supplies neither Omega nor wallet-open authority.

use ff::PrimeField;
use iroha_pasta::msm::MemoryBudget;
use iroha_plonk::Protocol;
use iroha_plonk_recursion::ACCUMULATOR_BYTES;
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
    /// Exact canonical Norito payload length, including the carried claim.
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
        // Only a counting specimen: these zero bytes are never parsed as a proof or
        // claim, imported, decided or returned as an admitted checkpoint. Canonical
        // frame length depends on the fixed field/sequence lengths, not their contents.
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
            accumulator: [0; ACCUMULATOR_BYTES],
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
#[norito_schema(name = "iroha.kagemusha.native.consuming.terminal_checkpoint.v1")]
struct Payload {
    version: u16,
    descriptor_digest: [u8; 32],
    verifying_key_digest: [u8; 32],
    source_context: [u8; 32],
    proof: Vec<u8>,
    accumulator: [u8; ACCUMULATOR_BYTES],
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
    /// proof, carried Pallas claim, frame and own opening under this session's key.
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
        let checked = self.restore_terminal_cancellable(
            terminal.proof.clone(),
            &terminal.pallas.to_bytes(),
            budget,
            cancellation,
        )?;
        if checked.instances != terminal.instances
            || checked.predecessor_vesta != terminal.predecessor_vesta
            || checked.opening != terminal.opening
        {
            return Err(Error::Input);
        }
        let source_context = self.prepared.context_digest()?.to_repr();
        Payload {
            version: 1,
            descriptor_digest: layout.descriptor_digest,
            verifying_key_digest: layout.verifying_key_digest,
            source_context,
            proof: checked.proof,
            accumulator: checked.pallas.to_bytes(),
        }
        .encode(&layout, source_context)
    }

    /// Restore the terminal A from one exact canonical payload: decide its carried
    /// Pallas claim in full and completely verify its proof against the frame
    /// rederived from the retained session inputs and that claim.
    ///
    /// # Errors
    /// Truncation/trailing bytes, wrong key/context/length, noncanonical claim or
    /// failed proof/decide.
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
        let payload = Payload::decode(bytes, &layout, self.prepared.context_digest()?.to_repr())?;
        self.restore_terminal_cancellable(payload.proof, &payload.accumulator, budget, cancellation)
    }
}

#[cfg(test)]
mod tests {
    //! Unadmitted DATA controls for the local terminal checkpoint carrier grammar.
    //!
    //! No specimen is a proof, a claim, an installed key, a signed inventory or a
    //! session. Genuine acceptance/round trips use the maintained consuming originals
    //! in the ignored native differential of `tests/a_consuming_recursive.rs`.

    use super::*;

    // A bounded grammar specimen only; it never enters a native restore/prover.
    fn layout() -> CheckpointLayout {
        CheckpointLayout::new([1; 32], [2; 32], 64).unwrap()
    }

    fn data() -> Payload {
        Payload {
            version: 1,
            descriptor_digest: [1; 32],
            verifying_key_digest: [2; 32],
            source_context: [3; 32],
            proof: vec![4; 64],
            accumulator: [5; ACCUMULATOR_BYTES],
        }
    }

    #[test]
    fn unadmitted_bounded_data_round_trips_exact_bytes_under_the_counted_layout() {
        // This checks only the carrier grammar. These nonzero DATA bytes are never
        // passed to Session restore, a proof verifier or an accumulator decide.
        let layout = layout();
        let context = [3; 32];
        let payload = data();
        assert_eq!(
            norito::canonical_frame_len(&payload).unwrap(),
            layout.payload_bytes()
        );
        let bytes = payload.encode(&layout, context).unwrap();
        assert_eq!(bytes.len(), layout.payload_bytes());
        let restored = Payload::decode(&bytes, &layout, context).unwrap();
        assert_eq!(restored.version, 1);
        assert_eq!(restored.descriptor_digest, *layout.descriptor_digest());
        assert_eq!(
            restored.verifying_key_digest,
            *layout.verifying_key_digest()
        );
        assert_eq!(restored.source_context, context);
        assert_eq!(restored.proof, vec![4; layout.proof_bytes()]);
        assert_eq!(restored.accumulator, [5; ACCUMULATOR_BYTES]);
        assert_eq!(restored.encode(&layout, context).unwrap(), bytes);
    }

    #[test]
    fn counting_layout_carries_the_proof_and_the_complete_pallas_claim() {
        // Metadata/counting only; no zero proof or claim is restored or admitted here.
        let layout = CheckpointLayout::new([1; 32], [2; 32], 8480).unwrap();
        assert_eq!(layout.proof_bytes(), 8480);
        assert!(layout.payload_bytes() > 8480 + ACCUMULATOR_BYTES);
    }

    #[test]
    fn unadmitted_data_cannot_substitute_source_installed_key_or_proof_length() {
        let layout = layout();
        let context = [3; 32];
        for mutation in 0..6 {
            let mut payload = data();
            match mutation {
                0 => payload.version = 2,
                1 => payload.descriptor_digest[0] ^= 1,
                2 => payload.verifying_key_digest[0] ^= 1,
                3 => payload.source_context[0] ^= 1,
                4 => {
                    payload.proof.pop();
                }
                _ => payload.proof.push(0),
            }
            // Re-encoding gives the mutated DATA a genuine codec checksum; its
            // altered identity must still be refused before proof verification.
            let bytes = norito::encode_canonical(&payload).unwrap();
            assert!(
                matches!(Payload::decode(&bytes, &layout, context), Err(Error::Input)),
                "mutation {mutation}"
            );
        }
        // The session's own source context is part of the exact accepted identity.
        assert!(matches!(data().encode(&layout, [9; 32]), Err(Error::Input)));
    }

    #[test]
    fn bounded_data_frames_refuse_empty_truncated_trailing_and_noncanonical_input() {
        let layout = layout();
        let context = [3; 32];
        let bytes = norito::encode_canonical(&data()).unwrap();
        let mut extra = bytes.clone();
        extra.push(0);
        for bad in [&[][..], &bytes[..bytes.len() - 1], &extra[..]] {
            assert!(matches!(
                Payload::decode(bad, &layout, context),
                Err(Error::Input)
            ));
        }
        let mut bad_header = bytes;
        bad_header[0] ^= 1;
        assert!(matches!(
            Payload::decode(&bad_header, &layout, context),
            Err(Error::Input)
        ));
    }

    #[test]
    fn impossible_installed_lengths_refuse_before_counting_allocation() {
        for bytes in [0, usize::MAX] {
            assert!(matches!(
                CheckpointLayout::new([1; 32], [2; 32], bytes),
                Err(Error::Artifact)
            ));
        }
    }

    #[test]
    fn checkpoint_read_refusal_preserves_original_and_exact_retry() {
        // Grammar-only originals never enter a proof verifier or monetary owner.
        let layout = layout();
        let context = [3; 32];
        let bytes = data().encode(&layout, context).unwrap();
        for limits in [
            norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 64),
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64),
        ] {
            let error = norito::with_decode_limits_scope(limits, || {
                Payload::decode(&bytes, &layout, context)
            })
            .err()
            .expect("actual enclosing decoder refusal");
            let Error::DecodeResource(ref original) = error else {
                panic!("lost original checkpoint refusal: {error:?}")
            };
            assert_eq!(
                original.kind(),
                norito::core::DecodeLocalRefusalKind::EnclosingLimit
            );
            assert_eq!(error.clone(), error);
            assert!(!error.is_cancelled());
            assert!(std::error::Error::source(&error).is_some());
            assert_eq!(
                Payload::decode(&bytes, &layout, context)
                    .unwrap()
                    .encode(&layout, context)
                    .unwrap(),
                bytes
            );
            // Exact extent is checked before a decoder observer is entered.
            assert!(matches!(
                norito::with_decode_limits_scope(limits, || {
                    Payload::decode(&bytes[..bytes.len() - 1], &layout, context)
                }),
                Err(Error::Input)
            ));
        }
    }

    #[test]
    fn terminal_checkpoint_rejects_every_retired_consuming_layout() {
        // Explicitly retained only as denylist specimens. No old decoder exists: the
        // split A1/W0/A2 carrier tagged each payload with its A or W kind and stage.
        #[derive(NoritoSerialize, NoritoSchema)]
        #[norito_schema(name = "iroha.kagemusha.native.consuming.checkpoint.v1")]
        struct RetiredStageData {
            version: u16,
            kind: u8,
            stage: u32,
            descriptor_digest: [u8; 32],
            verifying_key_digest: [u8; 32],
            source_context: [u8; 32],
            proof: Vec<u8>,
            accumulator: [u8; ACCUMULATOR_BYTES],
        }
        let layout = layout();
        for (kind, stage) in [(0, 0), (1, 0), (0, 1)] {
            let bytes = norito::encode_canonical(&RetiredStageData {
                version: 1,
                kind,
                stage,
                descriptor_digest: [1; 32],
                verifying_key_digest: [2; 32],
                source_context: [3; 32],
                proof: vec![4; 64],
                accumulator: [5; ACCUMULATOR_BYTES],
            })
            .unwrap();
            assert_ne!(
                bytes.len(),
                layout.payload_bytes(),
                "retired layout kind {kind} stage {stage}"
            );
            assert!(
                matches!(Payload::decode(&bytes, &layout, [3; 32]), Err(Error::Input)),
                "retired layout kind {kind} stage {stage}"
            );
        }
    }

    #[test]
    fn guarded_output_refuses_wrong_extent_and_does_not_consume_original() {
        let layout = layout();
        let original = data().encode(&layout, [3; 32]).unwrap();
        for delta in [-1_isize, 1] {
            let mut wrong = layout;
            wrong.payload_bytes = wrong.payload_bytes.checked_add_signed(delta).unwrap();
            assert!(matches!(data().encode(&wrong, [3; 32]), Err(Error::Input)));
        }
        let retried = Payload::decode(&original, &layout, [3; 32])
            .unwrap()
            .encode(&layout, [3; 32])
            .unwrap();
        assert_eq!(retried, original);
    }
}
