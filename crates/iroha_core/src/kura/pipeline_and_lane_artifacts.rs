/// Norito-encoded pipeline recovery metadata sidecar stored alongside block data.
#[derive(Debug, Clone, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::kura::PipelineRecoverySidecar")]
pub struct PipelineRecoverySidecar {
    /// Schema / evolution tag for the pipeline metadata format.
    pub format: PipelineRecoveryFormat,
    /// Block height the metadata belongs to.
    pub height: u64,
    /// Block hash the metadata belongs to.
    pub block_hash: HashOf<BlockHeader>,
    /// Deterministic DAG fingerprint and key count summary.
    pub dag: PipelineDagSnapshot,
    /// Per-transaction access summaries for recovery heuristics.
    pub txs: Vec<PipelineTxSnapshot>,
    /// Optional zero-knowledge proof attachments captured for this block.
    pub proofs: Vec<PipelineProofSnapshot>,
    /// FASTPQ proof artifacts generated asynchronously for committed execution witnesses.
    pub fastpq_proofs: Vec<FastpqProofSnapshot>,
}
impl PipelineRecoverySidecar {
    const FORMAT_LABEL: &'static str = "pipeline.recovery";
    /// Create a new recovery sidecar payload.
    pub fn new(
        height: u64,
        block_hash: HashOf<BlockHeader>,
        dag: PipelineDagSnapshot,
        txs: Vec<PipelineTxSnapshot>,
    ) -> Self {
        Self {
            format: PipelineRecoveryFormat::Current,
            height,
            block_hash,
            dag,
            txs,
            proofs: Vec::new(),
            fastpq_proofs: Vec::new(),
        }
    }
    /// Return the human-readable format tag describing the recovery payload.
    pub fn format_label(&self) -> &'static str {
        match self.format {
            PipelineRecoveryFormat::Current => Self::FORMAT_LABEL,
        }
    }
    /// Convert the sidecar into a JSON value for operator tooling.
    pub fn to_json_value(&self) -> JsonValue {
        let dag = {
            let mut dag = norito::json::Map::new();
            dag.insert(
                "fingerprint".to_string(),
                norito::json::to_value(&hex::encode(self.dag.fingerprint))
                    .expect("serialize fingerprint"),
            );
            dag.insert(
                "key_count".to_string(),
                norito::json::to_value(&self.dag.key_count).expect("serialize key_count"),
            );
            norito::json::Value::Object(dag)
        };
        let txs = self
            .txs
            .iter()
            .map(|tx| {
                let mut entry = norito::json::Map::new();
                entry.insert(
                    "hash".to_string(),
                    norito::json::to_value(&tx.hash.to_string()).expect("serialize tx hash"),
                );
                entry.insert(
                    "read_count".to_string(),
                    norito::json::to_value(&tx.read_count()).expect("serialize read count"),
                );
                entry.insert(
                    "write_count".to_string(),
                    norito::json::to_value(&tx.write_count()).expect("serialize write count"),
                );
                entry.insert(
                    "reads".to_string(),
                    norito::json::to_value(&tx.reads).expect("serialize sampled reads"),
                );
                entry.insert(
                    "writes".to_string(),
                    norito::json::to_value(&tx.writes).expect("serialize sampled writes"),
                );
                norito::json::Value::Object(entry)
            })
            .collect::<Vec<_>>();
        let proofs = self
            .proofs
            .iter()
            .map(|proof| {
                let mut entry = norito::json::Map::new();
                entry.insert(
                    "backend".to_string(),
                    norito::json::to_value(&proof.backend).expect("serialize backend"),
                );
                entry.insert(
                    "proof".to_string(),
                    norito::json::to_value(&BASE64_STANDARD.encode(&proof.proof))
                        .expect("serialize proof"),
                );
                entry.insert(
                    "code_hash".to_string(),
                    norito::json::to_value(&hex::encode(proof.code_hash))
                        .expect("serialize code hash"),
                );
                if let Some(tx_hash) = proof.tx_hash {
                    entry.insert(
                        "tx_hash".to_string(),
                        norito::json::to_value(&hex::encode(tx_hash)).expect("serialize tx hash"),
                    );
                }
                norito::json::Value::Object(entry)
            })
            .collect::<Vec<_>>();
        let fastpq_proofs = self
            .fastpq_proofs
            .iter()
            .map(FastpqProofSnapshot::to_json_value)
            .collect::<Vec<_>>();
        let mut root = norito::json::Map::new();
        root.insert(
            "format".to_string(),
            norito::json::to_value(&self.format_label()).expect("serialize format label"),
        );
        root.insert(
            "height".to_string(),
            norito::json::to_value(&self.height).expect("serialize pipeline height"),
        );
        root.insert(
            "block_hash".to_string(),
            norito::json::to_value(&self.block_hash.to_string())
                .expect("serialize pipeline block hash"),
        );
        root.insert("dag".to_string(), dag);
        root.insert("txs".to_string(), norito::json::Value::Array(txs));
        root.insert("proofs".to_string(), norito::json::Value::Array(proofs));
        root.insert(
            "fastpq_proofs".to_string(),
            norito::json::Value::Array(fastpq_proofs),
        );
        norito::json::Value::Object(root)
    }
    /// Encode the sidecar into a framed Norito buffer.
    ///
    /// # Errors
    ///
    /// Returns an error if framing fails (e.g., compression/header mismatch).
    pub fn encode_framed(&self) -> Result<Vec<u8>, norito::Error> {
        let bytes = norito::encode_canonical(self)?;
        if bytes.len() > MAX_PIPELINE_RECOVERY_SIDECAR_BYTES {
            return Err(norito::Error::Message(
                "pipeline recovery sidecar exceeds its byte limit".to_owned(),
            ));
        }
        Ok(bytes)
    }
}
/// Known metadata format variants for pipeline recovery sidecars.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::kura::PipelineRecoveryFormat")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub enum PipelineRecoveryFormat {
    #[codec(index = 0)]
    /// Sidecars anchored to a specific block hash to avoid reuse across forks.
    Current,
}
/// Deterministic DAG summary embedded in pipeline recovery metadata.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::kura::PipelineDagSnapshot")]
#[derive(Debug, Copy, Clone, Encode, Decode)]
pub struct PipelineDagSnapshot {
    /// Blake2 hash summarising the DAG structure for the block.
    pub fingerprint: [u8; 32],
    /// Number of unique DAG keys observed during block construction.
    pub key_count: u32,
}
/// Transaction access summary persisted for pipeline recovery/replay.
#[derive(Debug, Clone, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::kura::PipelineTxSnapshot")]
pub struct PipelineTxSnapshot {
    /// Transaction hash to correlate with block entries.
    pub hash: HashOf<TransactionEntrypoint>,
    /// Optional sampled state keys read during execution.
    pub reads: Vec<String>,
    /// Optional sampled state keys written during execution.
    pub writes: Vec<String>,
    /// Total number of state keys read during execution.
    pub read_count: u32,
    /// Total number of state keys written during execution.
    pub write_count: u32,
}
impl PipelineTxSnapshot {
    /// Create a compact tx access summary without embedding the full key lists.
    #[must_use]
    pub fn compact(
        hash: HashOf<TransactionEntrypoint>,
        read_count: usize,
        write_count: usize,
    ) -> Self {
        Self {
            hash,
            reads: Vec::new(),
            writes: Vec::new(),
            read_count: u32::try_from(read_count).unwrap_or(u32::MAX),
            write_count: u32::try_from(write_count).unwrap_or(u32::MAX),
        }
    }
    /// Total number of read keys represented by this snapshot.
    #[must_use]
    pub fn read_count(&self) -> u32 {
        self.read_count
    }
    /// Total number of write keys represented by this snapshot.
    #[must_use]
    pub fn write_count(&self) -> u32 {
        self.write_count
    }
}
/// ZK proof artifacts captured alongside pipeline metadata.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::kura::PipelineProofSnapshot")]
#[derive(Debug, Clone, Encode, Decode)]
pub struct PipelineProofSnapshot {
    /// Backend identifier for the proof format.
    pub backend: String,
    /// Raw proof bytes recorded for the trace.
    pub proof: Vec<u8>,
    /// Code hash of the executed program producing the trace.
    pub code_hash: [u8; 32],
    /// Optional transaction hash associated with the trace.
    pub tx_hash: Option<[u8; 32]>,
}
/// Canonical FASTPQ artifact identity recorded after committed execution.
///
/// Recovery sidecars contain metadata only. Complete statements, private witnesses
/// and proof frames remain outside this bounded record; identity fields describe
/// content and never grant proof verification or AXT authorization.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::kura::FastpqProofSnapshot")]
pub struct FastpqProofSnapshot {
    /// Block height the artifact belongs to.
    pub height: u64,
    /// Canonical block hash the artifact belongs to.
    pub block_hash: HashOf<BlockHeader>,
    /// Original finalized transcript bundle's entry hash.
    pub entry_hash: Hash,
    /// Position in the committed execution witness's transcript bundle order.
    pub batch_index: u32,
    /// Complete public transition occurrence count.
    pub transition_count: u32,
    /// Exact public input commitments checked by the artifact verifier.
    pub public_inputs: iroha_data_model::fastpq::FastpqPublicInputs,
    /// Complete canonical public transition ordering commitment.
    pub ordering_hash: [u8; 32],
    /// Recomputed canonical artifact identity and ordered AIR row commitments.
    pub artifact_identity: iroha_data_model::fastpq::FastpqArtifactIdentityDescriptionV1,
}
impl FastpqProofSnapshot {
    /// Retain only exact public metadata and the canonical artifact identity.
    #[must_use]
    pub fn from_statement(
        height: u64,
        block_hash: HashOf<BlockHeader>,
        entry_hash: Hash,
        batch_index: u32,
        statement: &iroha_data_model::fastpq::FastpqPublicTransferStatementV1,
        artifact_identity: iroha_data_model::fastpq::FastpqArtifactIdentityDescriptionV1,
    ) -> Self {
        Self {
            height,
            block_hash,
            entry_hash,
            batch_index,
            transition_count: u32::try_from(statement.transitions.len()).unwrap_or(u32::MAX),
            public_inputs: statement.public_inputs,
            ordering_hash: statement.ordering_hash,
            artifact_identity,
        }
    }
    /// Return whether two records describe the same canonical artifact attachment.
    #[must_use]
    pub fn same_attachment(&self, other: &Self) -> bool {
        self.entry_hash == other.entry_hash
            && self.batch_index == other.batch_index
            && self.artifact_identity.artifact_digest == other.artifact_identity.artifact_digest
    }
    /// Encode recovery metadata using canonical frames independently of ambient flags.
    #[must_use]
    pub fn to_json_value(&self) -> JsonValue {
        let mut entry = norito::json::Map::new();
        for (key, value) in [
            ("entry_hash", self.entry_hash.to_string()),
            (
                "profile_id",
                hex::encode(self.artifact_identity.profile_id.0),
            ),
            (
                "artifact_digest",
                hex::encode(self.artifact_identity.artifact_digest),
            ),
            (
                "public_statement_digest",
                hex::encode(self.artifact_identity.public_statement_digest),
            ),
            ("ordering_hash", hex::encode(self.ordering_hash)),
            (
                "public_inputs",
                BASE64_STANDARD.encode(
                    norito::encode_canonical(&self.public_inputs)
                        .expect("encode FASTPQ public inputs"),
                ),
            ),
            (
                "artifact_identity",
                BASE64_STANDARD.encode(
                    norito::encode_canonical(&self.artifact_identity)
                        .expect("encode FASTPQ artifact identity"),
                ),
            ),
        ] {
            entry.insert(
                key.to_owned(),
                norito::json::to_value(&value).expect("serialize FASTPQ identity"),
            );
        }
        entry.insert(
            "batch_index".to_owned(),
            norito::json::to_value(&self.batch_index).expect("serialize batch index"),
        );
        entry.insert(
            "transition_count".to_owned(),
            norito::json::to_value(&self.transition_count).expect("serialize transition count"),
        );
        entry.insert(
            "artifact_bytes".to_owned(),
            norito::json::to_value(&self.artifact_identity.artifact_bytes)
                .expect("serialize artifact size"),
        );
        norito::json::Value::Object(entry)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SidecarIndexEntry {
    offset: u64,
    len: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SidecarIndexLayout {
    base_height: u64,
    entries_offset: u64,
    entry_count: u64,
    aligned_len: u64,
}
#[derive(Debug, Clone, Copy)]
enum IndexedSidecarRewrite<'a> {
    Newest {
        retention: NonZeroUsize,
        pinned_height: Option<u64>,
    },
    /// Advance the based-index window together with the retained payloads.
    ///
    /// This is reserved for evidence whose configured retention is also its
    /// hard startup scan bound. Generic pipeline sidecars retain zero slots so
    /// every height in the canonical V1 window keeps a stable position.
    #[cfg(test)]
    NewestWindow { retention: NonZeroUsize },
    /// Discard only the authenticated terminal prefix while retaining a
    /// configured diagnostic window and every later (possibly pending) slot.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "TODO: connect terminal-frontier artifact retention; preserve required historical sidecars through bounded rewrites"
        )
    )]
    AfterTerminalFrontier {
        terminal_height: u64,
        retention: NonZeroUsize,
        /// Exact evidence heights that remain live even below the ordinary
        /// diagnostic window.
        required_heights: &'a BTreeSet<u64>,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FastpqProofWriteResult {
    Written,
    Retry,
    Drop,
}
impl SidecarIndexEntry {
    fn to_bytes(self) -> [u8; PIPELINE_INDEX_ENTRY_SIZE] {
        let mut buf = [0u8; PIPELINE_INDEX_ENTRY_SIZE];
        buf[..8].copy_from_slice(&self.offset.to_le_bytes());
        buf[8..].copy_from_slice(&self.len.to_le_bytes());
        buf
    }
    fn from_bytes(bytes: [u8; PIPELINE_INDEX_ENTRY_SIZE]) -> Self {
        let offset = u64::from_le_bytes(bytes[..8].try_into().expect("slice length matches"));
        let len = u64::from_le_bytes(bytes[8..].try_into().expect("slice length matches"));
        Self { offset, len }
    }
}
impl SidecarIndexLayout {
    fn based(base_height: u64, index_len: u64) -> Result<Self, &'static str> {
        if base_height == 0 || base_height == u64::MAX {
            return Err("sidecar base height is invalid");
        }
        let entries_len = index_len
            .checked_sub(INDEXED_SIDECAR_BASE_HEADER_SIZE_U64)
            .ok_or("sidecar base-height header is truncated")?;
        let aligned_entries_len = entries_len - entries_len % PIPELINE_INDEX_ENTRY_SIZE_U64;
        let entry_count = aligned_entries_len / PIPELINE_INDEX_ENTRY_SIZE_U64;
        base_height
            .checked_add(entry_count)
            .ok_or("sidecar base height and entry count overflow")?;
        Ok(Self {
            base_height,
            entries_offset: INDEXED_SIDECAR_BASE_HEADER_SIZE_U64,
            entry_count,
            aligned_len: INDEXED_SIDECAR_BASE_HEADER_SIZE_U64 + aligned_entries_len,
        })
    }
    fn next_height(self) -> Option<u64> {
        self.base_height.checked_add(self.entry_count)
    }
    fn entry_position(self, height: u64) -> Option<u64> {
        let relative = height.checked_sub(self.base_height)?;
        if relative >= self.entry_count {
            return None;
        }
        relative
            .checked_mul(PIPELINE_INDEX_ENTRY_SIZE_U64)
            .and_then(|offset| self.entries_offset.checked_add(offset))
    }
    fn height_range(self) -> Option<core::ops::RangeInclusive<u64>> {
        if self.entry_count == 0 {
            return None;
        }
        let end = self.next_height()?.checked_sub(1)?;
        Some(self.base_height..=end)
    }
    fn base_header(base_height: u64) -> [u8; INDEXED_SIDECAR_BASE_HEADER_SIZE] {
        let mut header = [0u8; INDEXED_SIDECAR_BASE_HEADER_SIZE];
        header[..8].copy_from_slice(&u64::MAX.to_le_bytes());
        header[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        header[16..24].copy_from_slice(&base_height.to_le_bytes());
        header[24..]
            .copy_from_slice(&(base_height ^ INDEXED_SIDECAR_BASE_CHECK_MASK).to_le_bytes());
        header
    }
    fn read_from(
        index: &mut (impl std::io::Read + std::io::Seek),
        index_len: u64,
    ) -> Result<Self, &'static str> {
        if index_len < INDEXED_SIDECAR_BASE_HEADER_SIZE_U64 {
            return Err("sidecar V1 base-height header is truncated");
        }
        let mut first_buf = [0u8; PIPELINE_INDEX_ENTRY_SIZE];
        index
            .seek(SeekFrom::Start(0))
            .and_then(|_| index.read_exact(&mut first_buf))
            .map_err(|_| "failed to read sidecar index prefix")?;
        let first = SidecarIndexEntry::from_bytes(first_buf);
        if first.offset != u64::MAX || first.len != u64::MAX {
            return Err("sidecar V1 base-height marker is missing");
        }
        let mut metadata_buf = [0u8; PIPELINE_INDEX_ENTRY_SIZE];
        index
            .read_exact(&mut metadata_buf)
            .map_err(|_| "failed to read sidecar base-height metadata")?;
        let metadata = SidecarIndexEntry::from_bytes(metadata_buf);
        if metadata.len != metadata.offset ^ INDEXED_SIDECAR_BASE_CHECK_MASK {
            return Err("sidecar base-height checksum mismatch");
        }
        Self::based(metadata.offset, index_len)
    }
}
