//! Unanchored live-transfer relation diagnostics; never a wire layout or source witness.
use super::*;

/// Local summary of independently supplied transfer preparation inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TransferArchiveDiagnostic {
    /// Supplied diagnostic network/height, without native authority.
    pub(crate) source: FastpqSourceStatementContextV1,
    /// Complete supplied input position count.
    pub(crate) executed_entry_count: u32,
    /// Existing canonical supplied-entry digest, without completeness authority.
    pub(crate) source_entries_digest: Hash,
    /// Nonempty prepared transfer statement count.
    pub(crate) statement_count: u32,
    /// Test-only ordered diagnostic fingerprint; never an ordinary Merkle root.
    pub(crate) diagnostic_digest: Hash,
}
/// One prepared transfer statement observation, not a D7 leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TransferEntryDiagnostic {
    /// Supplied diagnostic source.
    pub(crate) source: FastpqSourceStatementContextV1,
    /// Prepared statement ordinal.
    pub(crate) statement_index: u32,
    /// Original supplied input position.
    pub(crate) entry_index: u32,
    /// Complete transfer occurrence count.
    pub(crate) entry_transcript_count: u32,
    /// Supplied input identity.
    pub(crate) entry_hash: Hash,
    /// Supplied execution kind.
    pub(crate) execution_kind: FastpqSourceExecutionKindV1,
    /// Supplied route.
    pub(crate) route: FastpqSourceRouteV1,
    /// Supplied dataspace.
    pub(crate) dataspace_id: DataSpaceId,
    /// Exact canonical live-transfer statement frame digest.
    pub(crate) statement_digest: [u8; 32],
}
/// Prepare the live transfer relation under explicit fixture construction bounds.
/// Does not emit a source manifest, D7 write, opening, certificate or authority.
pub(crate) fn prepare_transfer_archive_diagnostic(
    source: FastpqSourceStatementContextV1,
    entries: &[FastpqSourceExecutionEntryV1],
    slot: u64,
    perm_root: [u8; 32],
    tx_set_hash: [u8; 32],
    transcripts: &BTreeMap<Hash, Vec<TransferTranscript>>,
    limits: FastpqSourceStatementBuildLimits,
) -> Result<(TransferArchiveDiagnostic, Vec<TransferEntryDiagnostic>), String> {
    if tx_set_hash == [0; 32] {
        return Err(
            crate::fastpq::TranscriptBatchError::MissingTransactionSetCommitment.to_string(),
        );
    }
    let executed_entry_count = u32::try_from(entries.len())
        .map_err(|_| "FASTPQ executed-entry count exceeds u32".to_owned())?;
    if source.height == 0 || executed_entry_count > limits.max_executed_entries {
        return Err("FASTPQ source height or executed-entry count is invalid".into());
    }
    if transcripts.len() > entries.len() {
        return Err("FASTPQ transcript archive contains more bundles than executed entries".into());
    }
    let identities: BTreeSet<_> = entries.iter().map(|entry| entry.entry_hash).collect();
    if identities.len() != entries.len() {
        return Err("FASTPQ execution archive contains duplicate call identities".into());
    }
    // Canonical framing matches the artifact identity digest, independently of ambient codec flags.
    let _canonical = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    if transcripts.keys().any(|key| !identities.contains(key)) {
        return Err("FASTPQ transcript bundle has no executed entry".into());
    }
    measure_fastpq_source_statement_usage(executed_entry_count, transcripts, limits)?;
    let max_rows = limits
        .max_deltas
        .checked_mul(2)
        .ok_or_else(|| "FASTPQ source construction row limit overflows".to_owned())?;
    let public_limits = source_statement_public_limits(limits)?;
    let tree_limits = TransferSmtBuildLimits::for_update_limit(max_rows)
        .ok_or_else(|| "FASTPQ source tree limits overflow".to_owned())?;
    // The complete-bundle preflight above precedes every leaf/tree allocation.
    let mut leaves = Vec::with_capacity(transcripts.len());
    let mut output_bytes_remaining = limits.max_total_statement_bytes;
    for (entry_index, entry) in entries.iter().enumerate() {
        let Some(bundle) = transcripts.get(&entry.entry_hash) else {
            continue;
        };
        let inputs = FastpqPublicInputsTemplate {
            dsid: dataspace_id_bytes(entry.dataspace_id),
            slot,
            old_root: [0; 32],
            new_root: [0; 32],
            perm_root,
        }
        .with_tx_set_hash(tx_set_hash);
        let entry_transcript_count = u32::try_from(bundle.len())
            .map_err(|_| "FASTPQ entry transcript count exceeds u32".to_owned())?;
        let produced = quantity_statement_from_finalized_transcripts_for_testing(
            inputs,
            bundle,
            public_limits,
            tree_limits,
        )
        .map_err(|error| format!("FASTPQ source entry {entry_index} is not finalized: {error}"))?;
        let bytes = norito::core::to_bytes_bounded(
            produced.statement(),
            limits.max_statement_bytes.min(output_bytes_remaining),
        )
        .map_err(|error| {
            format!("FASTPQ canonical source statement exceeds construction budget: {error}")
        })?;
        output_bytes_remaining -= bytes.len();
        leaves.push(TransferEntryDiagnostic {
            source,
            // Every count was checked against u32 before materializing any leaf.
            statement_index: u32::try_from(leaves.len())
                .map_err(|_| "FASTPQ statement index exceeds u32".to_owned())?,
            entry_index: u32::try_from(entry_index)
                .map_err(|_| "FASTPQ entry index exceeds u32".to_owned())?,
            entry_transcript_count,
            entry_hash: entry.entry_hash,
            execution_kind: entry.execution_kind,
            route: entry.route,
            dataspace_id: entry.dataspace_id,
            statement_digest: Hash::new(&bytes).into(),
        });
    }
    let source_entries_digest =
        iroha_data_model::fastpq::fastpq_source_execution_entries_digest_v1(
            entries,
            limits.max_executed_entries,
        )
        .ok_or_else(|| "FASTPQ diagnostic source projection is inconsistent".to_owned())?;
    // A test-only ordered diagnostic digest, deliberately not a Merkle root or a
    // serializable D7 value. No production consumer accepts this summary.
    let diagnostic_digest = Hash::new_from_writer(|writer| {
        writer.write_all(b"iroha:fastpq:unanchored-transfer-diagnostic:v1|")?;
        writer.write_all(
            &u32::try_from(leaves.len())
                .expect("bounded entries")
                .to_le_bytes(),
        )?;
        for leaf in &leaves {
            norito::core::write_canonical_to_writer(&leaf.source, writer)
                .map_err(|_| std::io::ErrorKind::InvalidData)?;
            writer.write_all(&leaf.statement_index.to_le_bytes())?;
            writer.write_all(&leaf.entry_index.to_le_bytes())?;
            writer.write_all(&leaf.entry_transcript_count.to_le_bytes())?;
            let entry = entries[usize::try_from(leaf.entry_index).expect("original position")];
            norito::core::write_canonical_to_writer(&entry, writer)
                .map_err(|_| std::io::ErrorKind::InvalidData)?;
            writer.write_all(&leaf.statement_digest)?;
        }
        Ok(())
    })
    .map_err(|error| format!("FASTPQ diagnostic digest failed: {error}"))?;
    let summary = TransferArchiveDiagnostic {
        source,
        executed_entry_count,
        source_entries_digest,
        statement_count: u32::try_from(leaves.len()).expect("bounded entries"),
        diagnostic_digest,
    };
    Ok((summary, leaves))
}

/// Ordered empty diagnostic fingerprint, independent of source/role fields with no statements.
pub(super) fn empty_diagnostic_digest() -> Hash {
    Hash::new_from_writer(|writer| {
        writer.write_all(b"iroha:fastpq:unanchored-transfer-diagnostic:v1|")?;
        writer.write_all(&0_u32.to_le_bytes())
    })
    .expect("fixed diagnostic input")
}
