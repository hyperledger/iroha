//! Total decoding of a descriptor-sized incoming lineage carrier.
//!
//! This decoder derives every validity bit from one carrier. It does not decide
//! the transported generator claims: the complete operation must keep the
//! original P/V and Omega opening in its fixed incoming obligation slots.
//! Active ingestion retains exact original lengths and byte digests separately
//! from safe padded verifier views. TODO: qualify the complete Receive owner
//! chain, signature/map checks and final catalog before admission.

use iroha_pasta::{Ep, Fp};
use iroha_plonk::frontend::{Error, Region};
use iroha_plonk_gadgets::{
    Bit, GlueChip, Word,
    bytes::{
        PBytes,
        tape::{ByteRun, SegmentSpec},
        variable::ActiveBytes,
    },
};
use iroha_plonk_recursion::{
    ACCUMULATOR_BYTES,
    accumulation_circuit::{FoldInputCells, FoldInputDecodePlan},
    verifier::{VerifierChip, VerifierKeyCells, VerifierPlan},
};

use super::{
    AProofPlan, IncomingLineageCells, IncomingOmegaCells, ProofMessageCells, SigmaBindingCells,
    VestaClaimCells, own::ConsumingProofCells, verify_incoming,
};

#[cfg(test)]
pub(super) mod tests;

/// Fixed incoming program and full-k16 canonical Pallas decoder.
#[derive(Clone, Debug)]
pub struct IncomingTransportPlan {
    omega: VerifierPlan<Ep>,
    pallas: FoldInputDecodePlan<Ep>,
}
impl IncomingTransportPlan {
    /// Descriptor-fixed incoming verifier used by this decoder's exact views.
    pub const fn verifier(&self) -> &VerifierPlan<Ep> {
        &self.omega
    }
    /// Pin the incoming Omega descriptor and accumulator parameter set.
    /// # Errors
    /// The operation has no incoming Omega or its parameters are invalid.
    pub fn new(operation: &AProofPlan) -> Result<Self, Error> {
        if !operation.frame().has_incoming() {
            return Err(Error::Synthesis);
        }
        let omega = operation.omega().ok_or(Error::Synthesis)?.clone();
        let pallas = FoldInputDecodePlan::new(omega.params(), 16).map_err(|_| Error::Synthesis)?;
        Ok(Self { omega, pallas })
    }

    /// Fixed `public320 || proof || accP || accV` payload size, excluding LE32.
    /// # Errors
    /// An impossible descriptor-size overflow.
    pub fn payload_length(&self) -> Result<usize, Error> {
        self.omega
            .proof_length()
            .checked_add(ConsumingProofCells::PUBLIC_BYTES + 2 * ACCUMULATOR_BYTES)
            .ok_or(Error::BoundsFailure)
    }

    /// Fixed views of `public320 || proof || accP || accV` without a prefix.
    /// A larger raw capacity is allowed; its extra original bytes are hashed.
    /// # Errors
    /// Invalid descriptor length or overflow.
    pub fn active_segments(&self) -> Result<Vec<SegmentSpec>, Error> {
        ConsumingProofCells::omega_segments(self.omega.proof_length())?
            .into_iter()
            .filter(|segment| segment.start != 0)
            .map(|segment| {
                Ok(SegmentSpec {
                    start: segment.start.checked_sub(4).ok_or(Error::BoundsFailure)?,
                    ..segment
                })
            })
            .collect()
    }

    /// Totally decode an exact original bounded incoming byte string.
    /// All decoders use fixed views of this same raw tape; the retained active
    /// length is compared with the descriptor length and enters the soft bit.
    /// # Errors
    /// Capacity below the selected fixed view, bad segments or synthesis failure.
    pub fn decode_active(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        raw: &ActiveBytes<Fp>,
        carried_key: &Word<Fp>,
    ) -> Result<IncomingTransportCells, Error> {
        let public = IncomingLineageCells::from_active(
            &mut chip.uint(),
            region,
            raw,
            self.omega.proof_length(),
            carried_key,
        )?;
        self.decode_view(
            chip,
            region,
            public,
            ConsumingProofCells::PUBLIC_BYTES,
            Some(raw.clone()),
        )
    }

    /// Decode every component from one length-prefixed fixed-capacity carrier.
    ///
    /// The two claims receive fixed safe deciding dummies on malformed bytes;
    /// their decoder bits are retained privately and always enter `verify`.
    /// Wrong actual outer length remains a soft failure even though each
    /// embedded proof/claim has a descriptor-fixed slice and no inner prefix.
    /// # Errors
    /// Wrong fixed carrier/segment shape or synthesis failure.
    pub fn decode(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        run: &ByteRun<Fp>,
        carried_key: &Word<Fp>,
    ) -> Result<IncomingTransportCells, Error> {
        let public = IncomingLineageCells::from_run(
            &mut chip.uint(),
            region,
            run,
            self.omega.proof_length(),
            carried_key,
        )?;
        let proof_start = 4 + ConsumingProofCells::PUBLIC_BYTES;
        self.decode_view(chip, region, public, proof_start, None)
    }

    fn decode_view(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        public: IncomingLineageCells,
        proof_start: usize,
        active: Option<ActiveBytes<Fp>>,
    ) -> Result<IncomingTransportCells, Error> {
        let carrier = public.carrier()?;
        let proof = ProofMessageCells::fixed_slice(
            chip,
            region,
            carrier,
            proof_start,
            self.omega.proof_length(),
        )?;
        let pallas_start = proof_start
            .checked_add(self.omega.proof_length())
            .ok_or(Error::BoundsFailure)?;
        let pallas_bytes =
            ProofMessageCells::fixed_slice(chip, region, carrier, pallas_start, ACCUMULATOR_BYTES)?;
        let pallas = FoldInputCells::decode_soft(
            chip,
            region,
            &self.pallas,
            pallas_bytes.messages(),
            pallas_bytes.length(),
        )?;
        let vesta_start = pallas_start
            .checked_add(ACCUMULATOR_BYTES)
            .ok_or(Error::BoundsFailure)?;
        let vesta_bytes =
            ProofMessageCells::fixed_slice(chip, region, carrier, vesta_start, ACCUMULATOR_BYTES)?;
        let (vesta, vesta_valid) = VestaClaimCells::decode_soft(
            chip,
            region,
            vesta_bytes.messages(),
            vesta_bytes.length(),
        )?;
        Ok(IncomingTransportCells {
            descriptor: self.omega.binding().clone(),
            public,
            proof,
            pallas: pallas.value,
            vesta,
            decode_bits: [pallas.valid, vesta_valid],
            active,
        })
    }
}

/// Opaque same-carrier header, proof and normalized incoming obligations.
#[derive(Clone, Debug)]
pub struct IncomingTransportCells {
    descriptor: iroha_plonk::DescriptorBinding,
    public: IncomingLineageCells,
    proof: ProofMessageCells,
    pallas: FoldInputCells<Ep>,
    vesta: VestaClaimCells,
    decode_bits: [Bit<Fp>; 2],
    active: Option<ActiveBytes<Fp>>,
}
impl IncomingTransportCells {
    /// Decoded original prefix and mandatory safe consumer view.
    pub const fn public(&self) -> &IncomingLineageCells {
        &self.public
    }
    /// Exact original proof messages, retained in context even on failure.
    pub const fn proof(&self) -> &ProofMessageCells {
        &self.proof
    }
    /// Original checked P claim or its fixed decoder dummy, before mode selection.
    pub const fn pallas(&self) -> &FoldInputCells<Ep> {
        &self.pallas
    }
    /// Original checked V claim or its fixed decoder dummy, before mode selection.
    pub const fn vesta(&self) -> &VestaClaimCells {
        &self.vesta
    }

    /// Original raw active provenance, never a descriptor-padded substitute.
    /// # Errors
    /// The object came from the fixed-buffer component decoder.
    pub fn active_carrier(&self) -> Result<&ActiveBytes<Fp>, Error> {
        self.active.as_ref().ok_or(Error::Synthesis)
    }

    /// Exact consuming digest of both original active strings and their lengths.
    ///
    /// The original raw tails and lengths remain hashed on all soft failures.
    /// Both carriers must come from the opaque active-byte constructors; a
    /// fixed padded decoder view cannot call this method successfully.
    /// # Errors
    /// Missing active provenance, invalid incoming binding or synthesis failure.
    pub fn proof_digest(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        sigma: &SigmaBindingCells,
    ) -> Result<Word<Fp>, Error> {
        sigma.incoming_statement()?;
        let omega = self.active_carrier()?;
        let sigma = sigma.active_carrier()?;
        let lanes = chip.operation_lanes()?;
        let mut uint = iroha_plonk_gadgets::UintChip::new(lanes.glue, lanes.range);
        let omega = omega.packed().length_prefixed(&mut uint, region)?;
        let sigma = sigma.packed().length_prefixed(&mut uint, region)?;
        omega.concat(&mut uint, region, &sigma)?.digest(
            &mut uint,
            lanes.hash.sponge_mut()?,
            region,
            u64::from_le_bytes(*b"kgwprf_1"),
        )
    }

    /// Soft-verify with all same-carrier decoder verdicts included internally.
    /// The caller cannot supply or replace a decode verdict.
    /// `carried_key` is the trusted operation key, never a proposed incoming
    /// identity. The witness verifier key must match it; a different decoded
    /// identity or proof under another key contributes a false soft verdict.
    /// # Errors
    /// Wrong descriptor/operation class or synthesis failure.
    pub fn verify(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        operation: &AProofPlan,
        key: &VerifierKeyCells<Ep>,
        carried_key: &Word<Fp>,
    ) -> Result<IncomingOmegaCells, Error> {
        if operation.omega().ok_or(Error::Synthesis)?.binding() != &self.descriptor {
            return Err(Error::Synthesis);
        }
        verify_incoming(
            chip,
            region,
            operation,
            key,
            &self.public,
            carried_key,
            &self.pallas,
            &self.vesta,
            &self.decode_bits,
            &self.proof,
        )
    }

    /// Hash the two exact fixed-storage carriers for component diagnostics.
    ///
    /// This binds all sigma chunks to the incoming Q export binding and retains
    /// malformed declared lengths. It hashes every stored byte. Consequently it
    /// is not the external consuming digest when a shorter original payload was
    /// padded for arithmetic; that requires a separate active-prefix ingestion
    /// relation and must be composed before Receive admission.
    /// # Errors
    /// An own/hard sigma binding, missing tape provenance, wrong partition or layout.
    pub fn fixed_buffer_digest(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        sigma: &SigmaBindingCells,
        sigma_run: &ByteRun<Fp>,
    ) -> Result<Word<Fp>, Error> {
        if self.active.is_some() || sigma.active_carrier().is_ok() {
            return Err(Error::Synthesis);
        }
        sigma.incoming_statement()?;
        sigma.step_digest()?;
        if sigma_run.len() != sigma.carrier_length()?
            || sigma_run.primary().len() != sigma.proof_chunks().len()
        {
            return Err(Error::Synthesis);
        }
        for (actual, expected) in sigma_run.primary().iter().zip(sigma.proof_chunks()) {
            GlueChip::assert_equal(region, actual.word(), expected)?;
        }
        let mut tape = PBytes::new();
        for run in [self.public.carrier()?, sigma_run] {
            let mut offset = 0;
            for segment in run.primary() {
                let size = (run.len() - offset).min(31);
                if segment.spec() != SegmentSpec::little(offset, size) {
                    return Err(Error::Synthesis);
                }
                tape.push_bounded_split(
                    &mut chip.uint(),
                    region,
                    &segment.bounded().ok_or(Error::Synthesis)?,
                )?;
                offset += size;
            }
            if offset != run.len() {
                return Err(Error::Synthesis);
            }
        }
        let lanes = chip.operation_lanes()?;
        tape.digest(
            lanes.glue,
            lanes.hash,
            region,
            u64::from_le_bytes(*b"kgwprf_1"),
        )
    }
}
