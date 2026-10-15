//! Shared private fold witness bytes for live circuit owners.
//!
//! Clones share one allocation. Only the final owner release clears that allocation;
//! no clone is a separately erased copy and no output method returns an unguarded Vec.
use iroha_pasta::{Ep, Eq, Fp};
use iroha_plonk::{DescriptorBinding, VerifyingKey, pcs::ipa::PinnedParams};
use iroha_plonk_recursion::{
    AccumulatorT, FoldConfig, FoldInput, FoldPurpose, FoldTape, FoldWitness, PrivateWitnessBytes,
};
use std::{ops::Deref, sync::Arc};

/// One shared clearing allocation, with redacted diagnostics and explicit guarded intake.
#[derive(Clone, Debug)]
pub struct PrivateFoldBytes(Arc<PrivateWitnessBytes>);
impl PrivateFoldBytes {
    /// Retain owned guarded bytes. Shape and proof authority are checked by the consumer.
    pub fn from_owned(bytes: PrivateWitnessBytes) -> Self {
        Self(Arc::new(bytes))
    }
    /// Consume a syntax-checked private witness and retain its guarded serialization.
    pub fn from_fold<C: iroha_pasta::PastaCurve>(fold: FoldWitness<C>) -> Self {
        Self::from_owned(fold.to_private_bytes())
    }
    /// Fixed zero specimen for witnessless source construction; grants no authority.
    pub fn unknown() -> Self {
        Self::from_owned(PrivateWitnessBytes::unknown_fold())
    }
    /// Borrow private witness bytes without allocating or exposing ownership.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}
impl Deref for PrivateFoldBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

/// Fold only the slots and raw challenge derived from the same verified A frame.
/// The enclosing family already authenticated this exact source key and checkpoint.
pub(crate) fn wrapper(
    params: &PinnedParams<Eq>,
    binding: &DescriptorBinding,
    key: &VerifyingKey<Eq>,
    public: &[Vec<Fp>],
    proof: &[u8],
    tape: FoldTape<Eq>,
    config: &FoldConfig,
) -> Result<(FoldWitness<Eq>, AccumulatorT<Eq>), iroha_plonk_recursion::terminal::Error> {
    let plan = iroha_plonk_recursion::terminal::TerminalPlan::new(
        binding.encoded(),
        &[key.to_bytes().to_vec()],
        params.clone(),
    )?;
    plan.read(0, public, proof, config)?.create(tape, config)
}

/// Pad the fixed final Pallas schedule with genuine deciding pinned claims.
pub(crate) fn terminal_inputs(
    params: &PinnedParams<Ep>,
    inputs: &mut Vec<FoldInput<Ep>>,
    config: &FoldConfig,
) -> Result<FoldPurpose, iroha_plonk_recursion::Error> {
    if inputs.len() > 4 {
        return Err(iroha_plonk_recursion::Error::Purpose);
    }
    let trivial = AccumulatorT::trivial_cancellable(
        params,
        config.kernel_budget,
        config.cancellation.as_ref(),
    )?;
    while inputs.len() < 4 {
        inputs.push(trivial.as_input());
    }
    Ok(FoldPurpose::ATerminal)
}

impl norito::SerializePayload for PrivateFoldBytes {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        norito::SerializePayload::serialize(&self.as_slice(), writer)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.len().checked_add(8)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.encoded_len_exact()
    }
}
impl norito::NoritoSchema for PrivateFoldBytes {
    fn nominal_name() -> String {
        "iroha.kagemusha.private_fold_bytes.v1".into()
    }
}
impl<'de> norito::core::DecodeFromSlice<'de> for PrivateFoldBytes {
    fn decode_from_slice(bytes: &'de [u8]) -> Result<(Self, usize), norito::Error> {
        let (borrowed, used) = <&[u8] as norito::core::DecodeFromSlice>::decode_from_slice(bytes)?;
        if borrowed.len() != iroha_plonk_recursion::FOLD_WITNESS_BYTES {
            return Err(norito::Error::LengthMismatch);
        }
        let owned = PrivateWitnessBytes::try_write::<norito::Error>(borrowed.len(), |writer| {
            writer.write_all(borrowed).map_err(Into::into)
        })?;
        Ok((Self::from_owned(owned), used))
    }
}
impl<'de> norito::DeserializePayload<'de> for PrivateFoldBytes {
    fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("private fold byte field")
    }
    fn try_deserialize(archived: &'de norito::core::Archived<Self>) -> Result<Self, norito::Error> {
        let bytes =
            norito::core::payload_slice_from_ptr(core::ptr::from_ref(archived).cast::<u8>())?;
        <Self as norito::core::DecodeFromSlice>::decode_from_slice(bytes).map(|(owned, _)| owned)
    }
}

#[cfg(test)]
mod tests;
