//! Bounded original-owner consumer of the sole signed-genesis native verifier.

use super::*;
use crate::sumeragi::finality::FinalityDecodeWorkspace;
use iroha_data_model::sumeragi_finality::ScheduledSlot;

fn query_committee_admission(
    bytes: usize,
) -> Result<(), crate::execution_attempt::ExecutionDeferred> {
    state_certificate::query_scratch_admission(bytes)
}

fn epoch_clone_bytes(epoch: &ValidatorEpochContextV1) -> Result<usize, norito::Error> {
    let ValidatorEpochContextV1 {
        version: _,
        network_id: _,
        mode: _,
        authorization: _,
        committee,
        leader_seed: _,
        da_layout: _,
    } = epoch;
    let mut bytes = committee
        .len()
        .checked_mul(std::mem::size_of::<
            iroha_data_model::sumeragi::epoch::ValidatorCommitteeMemberV1,
        >())
        .ok_or(norito::Error::LengthMismatch)?;
    for member in committee {
        bytes = bytes
            .checked_add(
                member
                    .validator
                    .public_key()
                    .retained_allocation_layout()
                    .size(),
            )
            .and_then(|bytes| bytes.checked_add(member.proof_of_possession.len()))
            .ok_or(norito::Error::LengthMismatch)?;
    }
    Ok(bytes)
}

pub(super) fn admit_epoch_clone(
    epoch: &ValidatorEpochContextV1,
    height: u64,
) -> Result<(), ExecutionAttemptError<ChainReadError>> {
    epoch_clone_bytes(epoch)
        .and_then(norito::core::reserve_decode_allocation)
        .map_err(|error| read_decode_error(height, error))
}

pub(super) fn admit_schedule(
    outcome: &schedule::ScheduleOutcome,
    height: u64,
) -> Result<(), ExecutionAttemptError<ChainReadError>> {
    norito::core::reserve_decode_allocation(3 * std::mem::size_of::<ScheduledSlot>())
        .map_err(|error| read_decode_error(height, error))?;
    admit_epoch_clone(&outcome.current, height)?;
    for slot in [&outcome.next, &outcome.after_next] {
        if let ScheduledSlot::Ready(config) = slot {
            admit_epoch_clone(&config.epoch, height)?;
        }
    }
    Ok(())
}

pub(super) fn admit_height_config(
    epoch: &ValidatorEpochContextV1,
    height: u64,
) -> Result<(), ExecutionAttemptError<ChainReadError>> {
    let bytes = core_keys_bytes(epoch.committee.len())
        .and_then(|bytes| {
            bytes.checked_add(std::mem::size_of::<iroha_sumeragi::types::EpochConfig>())
        })
        .ok_or_else(|| read_decode_error(height, norito::Error::LengthMismatch))?;
    norito::core::reserve_decode_allocation(bytes).map_err(|error| read_decode_error(height, error))
}

// Result-collect does not promise an exact-size Vec allocation. Cover the
// complete geometric capacity series, including the minimum nonzero capacity.
fn core_keys_bytes(count: usize) -> Option<usize> {
    count
        .max(4)
        .checked_next_power_of_two()?
        .checked_mul(2)?
        .checked_mul(std::mem::size_of::<iroha_sumeragi::types::PublicKey>())?
        .checked_add(count.checked_mul(48)?)
}

fn admit_genesis_root(
    genesis: &SignedBlock,
    chain_id: &ChainId,
) -> Result<(), ExecutionAttemptError<ChainReadError>> {
    use iroha_data_model::{isi::RegisterBox, transaction::Executable};
    use iroha_model_base::peer::PeerId;
    let mut count = 0usize;
    let mut bytes = 0usize;
    for transaction in genesis.external_transactions() {
        let Executable::Instructions(instructions) = transaction.instructions() else {
            continue;
        };
        for instruction in instructions {
            let Some(RegisterBox::Peer(register)) =
                instruction.as_any().downcast_ref::<RegisterBox>()
            else {
                continue;
            };
            count = count
                .checked_add(1)
                .ok_or_else(|| read_decode_error(1, norito::Error::LengthMismatch))?;
            bytes = bytes
                .checked_add(
                    register
                        .peer
                        .public_key()
                        .retained_allocation_layout()
                        .size(),
                )
                .and_then(|bytes| bytes.checked_add(register.pop.len()))
                .ok_or_else(|| read_decode_error(1, norito::Error::LengthMismatch))?;
        }
    }
    // BTreeMap owns copied keys/proofs. Its exact-size consuming iterator can
    // collect directly; this also covers a full geometric Vec growth series.
    let tree = norito::core::owned_btree_allocation_bytes::<PeerId, Vec<u8>>(count)
        .map_err(|error| read_decode_error(1, error))?;
    let committee = count
        .checked_mul(4)
        .and_then(|count| {
            count.max(4).checked_mul(std::mem::size_of::<
                iroha_data_model::sumeragi::epoch::ValidatorCommitteeMemberV1,
            >())
        })
        .ok_or_else(|| read_decode_error(1, norito::Error::LengthMismatch))?;
    let chain_bytes = chain_id.as_ref().len();
    let instance = iroha_sumeragi::preimage::TAG_INSTANCE
        .len()
        .checked_add(32 + 5)
        .and_then(|bytes| bytes.checked_add(chain_bytes))
        .ok_or_else(|| read_decode_error(1, norito::Error::LengthMismatch))?;
    let bytes = bytes
        .checked_add(tree)
        .and_then(|bytes| bytes.checked_add(committee))
        .and_then(|bytes| bytes.checked_add(chain_bytes))
        .and_then(|bytes| bytes.checked_add(instance))
        .ok_or_else(|| read_decode_error(1, norito::Error::LengthMismatch))?;
    norito::core::reserve_decode_allocation(bytes).map_err(|error| read_decode_error(1, error))
}

impl<'v> CertifiedChain<'v, StateView<'v>> {
    pub(crate) fn from_pinned_history_query(
        chain_id: &'v ChainId,
        network: &'v NetworkId,
        hashes: &'v dyn crate::state::BlockHashRead,
        kura: &'v Kura,
        budget: &iroha_allocation::AllocationBudget,
        maximum_wire_bytes: usize,
    ) -> Result<Self, ExecutionAttemptError<ChainReadError>> {
        let source = ChainSource::Pinned {
            chain_id,
            network,
            hashes: PinnedHashes::Captured(hashes),
            kura,
            budget: budget.clone(),
            maximum_wire_bytes,
        };
        let genesis = source.block(GENESIS_HEIGHT)?;
        admit_genesis_root(&genesis, chain_id)?;
        Self::from_genesis(source, genesis)
    }
}

impl VerifiedAuthority {
    pub(super) fn new_query(
        material: ValidatorEpochContextV1,
        height: u64,
        validation: &mut EpochValidationScope,
    ) -> Result<Self, ExecutionAttemptError<ChainReadError>> {
        use super::super::crypto::QueryCommitteeError;
        let crypto =
            BlsCrypto::for_query_committee(&material.committee, &mut query_committee_admission)
                .map_err(|error| match error {
                    QueryCommitteeError::Resource(error) => ExecutionAttemptError::Deferred(error),
                    QueryCommitteeError::Member { index, error } => {
                        use super::super::crypto::KeyError;
                        let detail = match &error {
                            KeyError::Malformed(text) | KeyError::BadPop(text) => text.len(),
                            KeyError::NotBlsNormal(_) => 0,
                        };
                        let bytes = detail
                            .checked_add(128)
                            .and_then(|bytes| bytes.checked_mul(2));
                        match bytes
                            .ok_or(norito::Error::LengthMismatch)
                            .and_then(norito::core::reserve_decode_allocation)
                        {
                            Ok(()) => ChainReadError::Committee {
                                height,
                                reason: format!("member {index}: {error}"),
                            }
                            .into(),
                            Err(error) => read_decode_error(height, error),
                        }
                    }
                })?;
        // The canonical committee owns one Vec of core keys and each key's bytes.
        let bytes = core_keys_bytes(material.committee.len())
            .ok_or_else(|| read_decode_error(height, norito::Error::LengthMismatch))?;
        norito::core::reserve_decode_allocation(bytes)
            .map_err(|error| read_decode_error(height, error))?;
        let malformed = |reason: String| ChainReadError::Committee { height, reason };
        let epoch = validation
            .core_epoch(&material)
            .map_err(|error| malformed(error.to_string()))?
            .id;
        let keys = material
            .committee
            .iter()
            .map(|member| core_key(member.validator.public_key()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| malformed(error.to_string()))?;
        let committee =
            schedule::global_committee(keys).map_err(|error| malformed(error.to_string()))?;
        Ok(Self {
            material,
            epoch,
            committee,
            crypto,
        })
    }
}

impl<V: StateReadOnly + ?Sized> CertifiedChain<'_, V> {
    /// Project a fully certified target, then move its original receipt into the
    /// prefix. No result/body clone or unchecked authority escapes this consumer.
    pub(crate) fn with_certified_workspace<R, E>(
        &self,
        height: u64,
        progress: &mut impl FnMut() -> Result<(), E>,
        workspace: &FinalityDecodeWorkspace,
        finish: impl FnOnce(&CertifiedBlock) -> Result<R, E>,
    ) -> Result<R, E>
    where
        E: From<ExecutionAttemptError<ChainReadError>>,
    {
        progress()?;
        if self.terminal.is_some() {
            return Err(ExecutionAttemptError::from(ChainReadError::NotInView { height }).into());
        }
        let target = workspace.target_context()?;
        let block = target.with(|| self.source.block(height))?;
        progress()?;
        let mut cursor = self.prefix.lock();
        #[cfg(all(test, sumeragi_core_mutation = "HC210"))]
        {
            *cursor = None;
        }
        if cursor
            .as_ref()
            .is_none_or(|prefix| prefix.tip.height >= height)
        {
            // Destroy a prior generation before admitting the replacement stage.
            *cursor = None;
            *cursor = Some(workspace.stage(|| self.genesis_prefix_query())?);
        }
        let prefix = cursor
            .as_mut()
            .expect("authenticated native genesis prefix");
        let committed = target.with(|| {
            read_frame_with_validation(block, height, self.root_scope, &mut prefix.validation)
        })?;
        progress()?;
        let context = self.verification_context();
        while prefix
            .tip
            .height
            .checked_add(1)
            .is_some_and(|next| next < height)
        {
            progress()?;
            let next_height = prefix.tip.height + 1;
            workspace.stage(|| {
                let body = self.source.block(next_height)?;
                progress()?;
                let next = read_frame_with_validation(
                    body,
                    next_height,
                    self.root_scope,
                    &mut prefix.validation,
                )?;
                progress()?;
                let prepared = context.prepare_advance_query(prefix, &next, None)?;
                prefix.tip = next;
                prefix.schedule = prepared.schedule;
                prefix.authority = prepared.authority;
                prefix.proof_source = prepared.proof_source;
                Ok::<_, E>(())
            })?;
        }
        progress()?;
        workspace.stage(|| {
            if height == GENESIS_HEIGHT {
                if committed.core_hash != prefix.tip.core_hash
                    || committed.result != prefix.tip.result
                {
                    return Err(ExecutionAttemptError::from(ChainReadError::ForeignGenesis).into());
                }
                let verified =
                    context.verify_certificate(committed, &prefix.authority, None, None)?;
                progress()?;
                return finish(&verified);
            }
            let prepared = context.prepare_advance_query(prefix, &committed, None)?;
            let verified = prepared.certificate.into_certified(committed);
            progress()?;
            let result = finish(&verified)?;
            prefix.tip = verified.committed;
            prefix.schedule = prepared.schedule;
            prefix.authority = prepared.authority;
            prefix.proof_source = prepared.proof_source;
            Ok(result)
        })
    }

    fn genesis_prefix_query(
        &self,
    ) -> Result<VerifiedPrefix, ExecutionAttemptError<ChainReadError>> {
        let mut validation = EpochValidationScope::new();
        let genesis = self.source.block(GENESIS_HEIGHT)?;
        let tip =
            read_frame_with_validation(genesis, GENESIS_HEIGHT, self.root_scope, &mut validation)?;
        admit_epoch_clone(&self.genesis_epoch, GENESIS_HEIGHT)?;
        let (schedule, authority) =
            genesis_prefix_authority_query(&tip, self.genesis_epoch.clone(), &mut validation)?;
        let proof_source = self
            .proof_source_genesis
            .filter(|expected| {
                tip.block().canonical_wire_identity().ok().as_ref() == Some(expected)
            })
            .map(|(length, wire)| {
                proof_source_append(proof_source_start(), GENESIS_HEIGHT, length, wire)
            });
        Ok(VerifiedPrefix {
            tip,
            schedule,
            authority,
            validation,
            proof_source,
        })
    }
}
