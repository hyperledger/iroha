//! Fresh authentication of durable tape transport under actual native execution authority.

use super::*;
use crate::{
    query::native_receipts::ordinary_writes, sumeragi::certified_chain::AuthenticatedExecutionBlock,
};
use iroha_allocation::{AllocationRefusal, ChargedBufferError};
use iroha_data_model::{
    execution_witness::FASTPQ_ORDINARY_SOURCE_STATEMENTS_WITNESS_KEY_V1 as KEY,
    fastpq::{
        FastpqEffectsDecodeError, FastpqExecutionEffectContextV1, FastpqSourceEffectCoverageV1,
        build_fastpq_ordinary_source_statement_manifest_v1, decode_fastpq_source_manifest_frame_v1,
        execution_effects_digest_v1, validate_fastpq_ordinary_source_statement_manifest_v1,
    },
    sumeragi_finality::NativeLaneStateProof,
};
use norito::core::{self as ncore, PreparedDecodeWorkspace};
use std::sync::Arc;

mod decode;
use decode::{FundedRecord, SourceDestination};

/// Explicit operation bounds. These never change native validity or certified coverage.
#[derive(Clone, Copy)]
pub(crate) struct SourceReadLimits {
    pub(crate) max_entries: u32,
    pub(crate) max_statements: u32,
    pub(crate) max_effects_per_statement: usize,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SourceReadError {
    #[error(transparent)]
    Archive(#[from] NativeContextArchiveError),
    #[error(transparent)]
    Writes(#[from] ordinary_writes::WriteDecodeError),
    #[error(transparent)]
    Lane(#[from] iroha_data_model::sumeragi_finality::NativeLaneStateProofError),
    #[error(transparent)]
    Allocation(#[from] AllocationRefusal),
    #[error(transparent)]
    Buffer(#[from] ChargedBufferError),
    #[error(transparent)]
    Effects(#[from] FastpqEffectsDecodeError),
    #[error(transparent)]
    Decode(#[from] ncore::DecodeAttemptError),
    #[error(transparent)]
    Codec(#[from] norito::Error),
    #[error(transparent)]
    Workspace(#[from] ncore::PreparedDecodeScopeError),
    #[error("FASTPQ source {kind} count {actual} exceeds local allowance {maximum}")]
    Limit {
        kind: &'static str,
        actual: usize,
        maximum: usize,
    },
    #[error("FASTPQ recovered source: {0}")]
    Source(&'static str),
}

/// Freshly verified original facts. This never pretends to restore the previous
/// execution's allocation custody and cannot be constructed by a wire decoder.
pub(crate) struct AuthenticatedRecoveredFastpqSource {
    native: AuthenticatedExecutionBlock,
    contents: SourceContents,
    pool: AllocationBudget,
}
// Empty is available only after complete native D7 authentication. It grants no
// entry inventory and cannot supply any effect tape to the proof producer.
enum SourceContents {
    Complete(FundedRecord),
    Empty(FastpqOrdinarySourceStatementManifestV1),
}
impl AuthenticatedRecoveredFastpqSource {
    pub(crate) fn native(&self) -> &AuthenticatedExecutionBlock {
        &self.native
    }
    pub(crate) fn pool(&self) -> &AllocationBudget {
        &self.pool
    }
    pub(crate) fn manifest(&self) -> &FastpqOrdinarySourceStatementManifestV1 {
        match &self.contents {
            SourceContents::Complete(funded) => &funded.manifest,
            SourceContents::Empty(manifest) => manifest,
        }
    }
    pub(crate) fn leaves(&self) -> &[FastpqOrdinarySourceStatementLeafV1] {
        match &self.contents {
            SourceContents::Complete(funded) => funded.leaves.as_slice(),
            SourceContents::Empty(_) => &[],
        }
    }
    pub(crate) fn entry(
        &self,
        index: usize,
    ) -> Option<(
        &FastpqExecutionEffectsV1,
        &FastpqOrdinarySourceStatementLeafV1,
    )> {
        let SourceContents::Complete(funded) = &self.contents else {
            return None;
        };
        Some((
            funded.tapes.as_slice().get(index)?.canonical(),
            funded.leaves.as_slice().get(index)?,
        ))
    }
}

/// One immutable source selection. Every refusal retains the actual native block,
/// first selected descriptors, partial byte buffers and completed decode stages.
pub(crate) struct NativeFastpqSourceRead {
    kura: Arc<Kura>,
    native: Option<AuthenticatedExecutionBlock>,
    pool: AllocationBudget,
    limits: SourceReadLimits,
    context_read: Option<NativeContextRead>,
    tape_read: Option<NativeContextRead>,
    context_bytes: Option<ChargedBuffer<u8>>,
    tape_bytes: Option<ChargedBuffer<u8>>,
    context_witness: Option<RetainedPayload<ExecWitness>>,
    manifest: Option<FastpqOrdinarySourceStatementManifestV1>,
    workspace: Option<PreparedDecodeWorkspace>,
    destination: Option<SourceDestination>,
    decoded: Option<FundedRecord>,
}
impl NativeFastpqSourceRead {
    pub(crate) fn new(
        kura: Arc<Kura>,
        native: AuthenticatedExecutionBlock,
        pool: AllocationBudget,
        limits: SourceReadLimits,
    ) -> Self {
        Self {
            kura,
            native: Some(native),
            pool,
            limits,
            context_read: None,
            tape_read: None,
            context_bytes: None,
            tape_bytes: None,
            context_witness: None,
            manifest: None,
            workspace: None,
            destination: None,
            decoded: None,
        }
    }
    /// At most one source chunk is read by a poll. `None` is bounded progress, not
    /// an absent manifest, a negative proof or a durable work acknowledgement.
    pub(crate) fn poll(
        &mut self,
    ) -> Result<Option<AuthenticatedRecoveredFastpqSource>, SourceReadError> {
        let native = self
            .native
            .as_ref()
            .ok_or(SourceReadError::Source("source already delivered"))?;
        let height = native.committed().height();
        let carrier = native.committed().block_hash();
        if self.context_read.is_none() {
            self.context_read = Some(
                NativeContextArchive::open_existing(
                    &self.kura,
                    self.pool.clone(),
                    self.kura.native_context_archive_max_bytes(),
                )?
                .read_job(height, carrier),
            );
        }
        if self.context_bytes.is_none() {
            self.context_bytes = self
                .context_read
                .as_mut()
                .expect("retained context")
                .poll()?;
            return Ok(None);
        }
        if self.context_witness.is_none() {
            let projection = ordinary_writes::decode_projection(
                self.context_bytes.as_ref().expect("original context"),
                &self.pool,
            )?;
            if projection.carrier_height != height || projection.carrier_hash != carrier {
                return Err(SourceReadError::Source(
                    "context carrier differs from native execution",
                ));
            }
            self.context_witness = Some(projection.witness);
        }
        if self.workspace.is_none() {
            let mut reservation = self
                .pool
                .try_reserve_layouts(PreparedDecodeWorkspace::allocation_layouts())?;
            self.workspace = Some(PreparedDecodeWorkspace::from_reservation(
                &self.pool,
                &mut reservation,
            )?);
        }
        if self.manifest.is_none() {
            let witness = self
                .context_witness
                .as_ref()
                .expect("funded original projection");
            let path = NativeLaneStateProof::from_witness(witness.get(), &self.pool)?;
            if path != native.committed().commitment().native_lanes {
                return Err(SourceReadError::Source(
                    "complete ordinary writes differ from certified native result",
                ));
            }
            let mut writes = witness
                .get()
                .writes
                .iter()
                .filter(|write| write.key.first() == KEY.first());
            let write = writes
                .next()
                .ok_or(SourceReadError::Source("certified D7 manifest missing"))?;
            if writes.next().is_some() || write.key.as_slice() != KEY {
                return Err(SourceReadError::Source(
                    "D7 manifest key is not unique and exact",
                ));
            }
            let manifest = decode_fastpq_source_manifest_frame_v1(
                &write.value,
                self.workspace.as_mut().expect("original controls"),
            )
            .map_err(|error| match error {
                ncore::PreparedDecodeError::Codec(error) => SourceReadError::Decode(error),
                ncore::PreparedDecodeError::Destination(error) => SourceReadError::Effects(error),
                ncore::PreparedDecodeError::Scope(error) => SourceReadError::Workspace(error),
            })?;
            if manifest.source.height != height
                || manifest.source.network_id
                    != native.committed().commitment().schedule.current.network_id
                || manifest.coverage != FastpqSourceEffectCoverageV1::Complete
                || !validate_fastpq_ordinary_source_statement_manifest_v1(
                    &manifest,
                    manifest.source,
                    self.limits.max_entries,
                    self.limits.max_statements,
                )
            {
                return Err(SourceReadError::Source(
                    "native source is not complete exact FASTPQ execution",
                ));
            }
            self.manifest = Some(manifest);
        }
        if self
            .manifest
            .as_ref()
            .expect("authenticated D7")
            .statement_count
            == 0
        {
            self.context_read
                .as_ref()
                .expect("original context namespace")
                .recheck_namespace()?;
            return Ok(Some(AuthenticatedRecoveredFastpqSource {
                native: self
                    .native
                    .take()
                    .expect("verified original source moves once"),
                contents: SourceContents::Empty(
                    *self.manifest.as_ref().expect("authenticated empty D7"),
                ),
                pool: self.pool.clone(),
            }));
        }
        if self.tape_read.is_none() {
            self.tape_read = Some(
                NativeContextArchive::open_existing_fastpq(&self.kura, self.pool.clone())?
                    .fastpq_source_read_job(height, carrier),
            );
        }
        if self.tape_bytes.is_none() {
            self.tape_bytes = self
                .tape_read
                .as_mut()
                .expect("retained tape read")
                .poll()?;
            return Ok(None);
        }
        if self.decoded.is_none() {
            let destination = self
                .destination
                .get_or_insert_with(|| SourceDestination::new(&self.pool, self.limits));
            destination.decode(
                self.tape_bytes.as_ref().expect("original tape frame"),
                self.workspace.as_mut().expect("original controls"),
            )?;
            self.decoded = Some(destination.take_complete()?);
            // Canonical comparison completed before discarding any source spans.
            self.destination = None;
        }
        if !self
            .decoded
            .as_ref()
            .expect("funded tape graph")
            .belongs_to(&self.pool)
        {
            return Err(SourceReadError::Source(
                "recovered source lost original physical custody",
            ));
        }
        verify_record(
            self.decoded.as_ref().expect("funded tape graph"),
            native,
            self.manifest.as_ref().expect("authenticated D7"),
            self.limits,
        )?;
        self.context_read
            .as_ref()
            .expect("original context namespace")
            .recheck_namespace()?;
        self.tape_read
            .as_ref()
            .expect("original tape namespace")
            .recheck_namespace()?;
        Ok(Some(AuthenticatedRecoveredFastpqSource {
            native: self
                .native
                .take()
                .expect("verified original source moves once"),
            contents: SourceContents::Complete(
                self.decoded.take().expect("verified graph moves once"),
            ),
            pool: self.pool.clone(),
        }))
    }
}

fn verify_record(
    record: &FundedRecord,
    native: &AuthenticatedExecutionBlock,
    expected: &FastpqOrdinarySourceStatementManifestV1,
    limits: SourceReadLimits,
) -> Result<(), SourceReadError> {
    if record.height != native.committed().height()
        || record.carrier != native.committed().block_hash()
        || &record.manifest != expected
        || record.tapes.as_slice().len() != record.leaves.as_slice().len()
    {
        return Err(SourceReadError::Source(
            "tape source, manifest or complete statement inventory differs",
        ));
    }
    let rebuilt = build_fastpq_ordinary_source_statement_manifest_v1(
        expected.source,
        record.entries.as_slice(),
        record.leaves.as_slice(),
        limits.max_entries,
        limits.max_statements,
    )
    .ok_or(SourceReadError::Source(
        "complete entry and leaf inventory is invalid",
    ))?;
    if &rebuilt != expected {
        return Err(SourceReadError::Source(
            "complete inventory differs from certified D7",
        ));
    }
    for (leaf, allocated) in record.leaves.as_slice().iter().zip(record.tapes.as_slice()) {
        let tape = allocated.canonical();
        let entry = record
            .entries
            .as_slice()
            .get(leaf.entry_index as usize)
            .ok_or(SourceReadError::Source("statement has no original entry"))?;
        if tape.context
            != (FastpqExecutionEffectContextV1 {
                source: expected.source,
                entry: *entry,
            })
            || tape.effects.len() != leaf.effect_count as usize
            || tape.effects.len() > limits.max_effects_per_statement
            || execution_effects_digest_v1(tape)?.as_ref() != &leaf.effects_digest
        {
            return Err(SourceReadError::Source(
                "complete effect tape differs from certified leaf",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
