// Sole original native header/body source identity, borrowed before any execution.

/// Fixed source identity minted from an exact native proposal. This is not finality authority:
/// the pristine schedule capture rechecks the instance, epoch and committed parent/result.
/// No native Header/skipped-leader list or body allocation is cloned into this token.
pub(crate) struct NativeHeaderSource<'state> {
    state: &'state State,
    generation: u64,
    header: BlockHeader,
    #[cfg(test)]
    proposal_hash: Hash,
    #[cfg(test)]
    consensus_hash: Hash,
    expected_context: iroha_data_model::consensus::GlobalThresholdBeaconPulseContextV1,
    pulse: Option<iroha_data_model::consensus::FinalizedGlobalThresholdBeaconPulseV1>,
}
impl NativeHeaderSource<'_> {
    #[cfg(test)]
    fn validate_body(&self, block: &SignedBlock) -> Result<(), BlockValidationError> {
        if !block.is_resultless_proposal()
            || block.header() != self.header
            || block
                .canonical_proposal_wire_hash()
                .map_err(|error| ValidBlock::execution_context_error(error.to_string()))?
                != self.proposal_hash
        {
            return Err(ValidBlock::execution_context_error(
                "native source body changed after exact header binding",
            ));
        }
        Ok(())
    }
    /// Exact original carrier header, without reconstructed global context.
    pub(crate) fn header(&self) -> BlockHeader {
        self.header
    }
    /// Exact borrowed State owner of this pending source.
    pub(crate) fn state(&self) -> &State {
        self.state
    }
    /// Original State publication observed before effects.
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
}
impl ValidBlock {
    /// Bind every original proposal byte to its actual native header before expansion or effects.
    /// The returned source does not authorize another body or replace schedule/certificate checks.
    pub(crate) fn native_header_source<'state>(
        block: &SignedBlock,
        state: &'state State,
        native_header: &iroha_sumeragi::message::BlockHeader,
        native_payload: &[u8],
    ) -> Result<NativeHeaderSource<'state>, BlockValidationError> {
        let matches = block
            .matches_resultless_proposal_wire(native_payload)
            .map_err(|error| Self::execution_context_error(error.to_string()))?;
        let payload_hash =
            Hash::new_from_chunks(&[iroha_sumeragi::preimage::TAG_PAY, native_payload]);
        if !matches
            || native_header.height != block.header().height().get()
            || native_header.origin_view != block.header().view_change_index()
            || usize::try_from(native_header.payload_len).ok() != Some(native_payload.len())
            || native_header.payload_hash.0 != <[u8; 32]>::from(payload_hash)
        {
            return Err(Self::execution_context_error(
                "native header differs from its exact original work payload",
            ));
        }
        let pulse = crate::sumeragi::epoch_beacon::control::decode(&native_header.control_witness)
            .map_err(|error| Self::execution_context_error(error.to_string()))?;
        let expected_context = iroha_data_model::consensus::GlobalThresholdBeaconPulseContextV1 {
            instance: native_header.instance.0,
            epoch: native_header.epoch.epoch,
            epoch_context_id: native_header.epoch.context.0,
            parent_consensus_hash: native_header.parent_hash.0,
            parent_result: native_header.parent_result.0,
        };
        let generation = state.state_view_generation();
        let view = state.query_view();
        let authenticated = crate::sumeragi::schedule::authenticate_successor_context(
            &view,
            &block.header(),
            &expected_context,
        );
        let observed_generation = state.state_view_generation();
        if !crate::state::is_stable_state_view_generation(generation, observed_generation) {
            return Err(BlockValidationError::NativeSourceChanged {
                authenticated_generation: generation,
                observed_generation,
            });
        }
        authenticated.map_err(BlockValidationError::from)?;
        Ok(NativeHeaderSource {
            state,
            generation,
            header: block.header(),
            #[cfg(test)]
            proposal_hash: Hash::new(native_payload),
            #[cfg(test)]
            consensus_hash: Hash::prehashed(
                native_header
                    .hash(&crate::sumeragi::crypto::BlsCrypto::new())
                    .0,
            ),
            expected_context,
            pulse,
        })
    }
}
