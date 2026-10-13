//! ISO 20022 reference-data ingestion and telemetry helpers.
//!
//! This module loads regulated identifier crosswalks (ISIN↔CUSIP, BIC↔LEI, MIC) and securities
//! ledger crosswalks from operator-provided snapshots, captures provenance metadata, and exposes
//! ready-to-query maps for the Torii ISO bridge runtime. Each dataset is tagged with refresh
//! metadata and emits Prometheus metrics so operators can monitor staleness or ingestion failures.
//! Loading is record-streamed under fixed source-byte, record, string, and retained-index budgets
//! so malformed operator snapshots cannot scale startup memory without bound.
use super::profiles::ReferenceDatasetRequirement;
use core::convert::TryFrom;
use eyre::{self, WrapErr as _};
use iroha_config::parameters::actual;
use iroha_logger::{error, info, warn};
use iroha_telemetry::metrics;
use ivm::iso20022::{self, IdentifierKind};
use norito::json::{self, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
/// Maximum encoded size of one first-release reference-data snapshot.
const REFERENCE_DATA_MAX_DATASET_BYTES: usize = 16 * 1024 * 1024;
/// Maximum encoded bytes examined across one six-dataset refresh.
const REFERENCE_DATA_MAX_TOTAL_INPUT_BYTES: usize = 64 * 1024 * 1024;
/// Maximum records retained across one six-dataset refresh.
const REFERENCE_DATA_MAX_TOTAL_RECORDS: usize = 65_536;
/// Conservative retained-memory budget for all crosswalk indexes.
const REFERENCE_DATA_MAX_RETAINED_BYTES: usize = 64 * 1024 * 1024;
/// Maximum decoded bytes accepted for one metadata or record string.
const REFERENCE_DATA_MAX_STRING_BYTES: usize = 4 * 1024;
/// Conservative per-record accounting for tree nodes, vectors, and allocators.
const REFERENCE_DATA_RECORD_OVERHEAD_BYTES: usize = 1024;
/// Multiplier covering normalized keys and reverse-index string copies.
const REFERENCE_DATA_STRING_ACCOUNTING_MULTIPLIER: usize = 4;
#[derive(Debug)]
struct ReferenceDataLoadBudget {
    remaining_input_bytes: usize,
    remaining_records: usize,
    remaining_retained_bytes: usize,
}
impl Default for ReferenceDataLoadBudget {
    fn default() -> Self {
        Self {
            remaining_input_bytes: REFERENCE_DATA_MAX_TOTAL_INPUT_BYTES,
            remaining_records: REFERENCE_DATA_MAX_TOTAL_RECORDS,
            remaining_retained_bytes: REFERENCE_DATA_MAX_RETAINED_BYTES,
        }
    }
}
impl ReferenceDataLoadBudget {
    fn charge_input(&mut self, kind: DatasetKind, bytes: usize) -> eyre::Result<()> {
        if bytes > self.remaining_input_bytes {
            eyre::bail!(
                "{} dataset would exceed the {}-byte aggregate input budget",
                kind.label(),
                REFERENCE_DATA_MAX_TOTAL_INPUT_BYTES
            );
        }
        self.remaining_input_bytes -= bytes;
        Ok(())
    }
    fn charge_record(&mut self, kind: DatasetKind) -> eyre::Result<()> {
        if self.remaining_records == 0 {
            eyre::bail!(
                "{} dataset would exceed the {REFERENCE_DATA_MAX_TOTAL_RECORDS}-record aggregate limit",
                kind.label()
            );
        }
        self.remaining_records -= 1;
        Ok(())
    }
    fn charge_retained_strings<S: AsRef<str>>(
        &mut self,
        kind: DatasetKind,
        strings: impl IntoIterator<Item = S>,
    ) -> eyre::Result<()> {
        let string_bytes = strings.into_iter().try_fold(0usize, |total, value| {
            let value = value.as_ref();
            if value.len() > REFERENCE_DATA_MAX_STRING_BYTES {
                eyre::bail!(
                    "{} dataset string is {} bytes (maximum {})",
                    kind.label(),
                    value.len(),
                    REFERENCE_DATA_MAX_STRING_BYTES
                );
            }
            total
                .checked_add(value.len())
                .ok_or_else(|| eyre::eyre!("{} dataset string-byte total overflowed", kind.label()))
        })?;
        let charge = string_bytes
            .checked_mul(REFERENCE_DATA_STRING_ACCOUNTING_MULTIPLIER)
            .and_then(|bytes| bytes.checked_add(REFERENCE_DATA_RECORD_OVERHEAD_BYTES))
            .ok_or_else(|| {
                eyre::eyre!("{} dataset retained-byte charge overflowed", kind.label())
            })?;
        if charge > self.remaining_retained_bytes {
            eyre::bail!(
                "{} dataset would exceed the {}-byte retained-index budget",
                kind.label(),
                REFERENCE_DATA_MAX_RETAINED_BYTES
            );
        }
        self.remaining_retained_bytes -= charge;
        Ok(())
    }
}
/// Dataset kinds tracked by the ISO bridge reference-data loader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatasetKind {
    /// ANNA / CUSIP crosswalk.
    IsinCusip,
    /// BIC to LEI mapping.
    BicLei,
    /// MIC directory.
    MicDirectory,
    /// Securities settlement venue to ledger-domain mapping.
    CsdVenue,
    /// Securities settlement-account mapping.
    SecuritiesAccount,
    /// Securities cash-leg mapping.
    CashLeg,
}
impl DatasetKind {
    /// Human-readable label used in logs and metrics.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            DatasetKind::IsinCusip => "isin_cusip",
            DatasetKind::BicLei => "bic_lei",
            DatasetKind::MicDirectory => "mic_directory",
            DatasetKind::CsdVenue => "csd_venue",
            DatasetKind::SecuritiesAccount => "securities_account",
            DatasetKind::CashLeg => "cash_leg",
        }
    }
}
/// Snapshot state capturing whether a dataset was ingested successfully.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotState {
    /// Dataset not provided (no path configured).
    Missing,
    /// Dataset loaded and parsed successfully.
    Loaded,
    /// Dataset ingestion failed due to IO/parse errors.
    Failed,
}
impl SnapshotState {
    /// Map the state to a numeric gauge value for telemetry.
    #[must_use]
    pub fn as_gauge(self) -> i64 {
        match self {
            SnapshotState::Missing => 0,
            SnapshotState::Loaded => 1,
            SnapshotState::Failed => -1,
        }
    }
}
/// Errors that occur while validating ISO reference data records.
#[derive(Debug, Error)]
pub enum ReferenceDataError {
    #[error("{kind_label} dataset is not configured", kind_label = .kind.label())]
    /// Reference data required for validation was not configured.
    DatasetUnavailable {
        /// Dataset kind required by the validation.
        kind: DatasetKind,
    },
    #[error("{kind_label} dataset failed to load reference data: {diagnostics}", kind_label = .kind.label(), diagnostics = .diagnostics.as_deref().unwrap_or("unknown error"))]
    /// Reference data loader was unable to ingest the dataset.
    DatasetFailed {
        /// Dataset kind that failed.
        kind: DatasetKind,
        /// Loader diagnostics when available.
        diagnostics: Option<String>,
    },
    #[error("{kind_label} reference `{value}` not found in snapshot", kind_label = .kind.label())]
    /// Lookup for the requested reference value failed.
    NotFound {
        /// Dataset kind used for lookup.
        kind: DatasetKind,
        /// Identifier value that was queried.
        value: String,
    },
    #[error("MIC `{mic}` is inactive (status: {status:?})")]
    /// Market identifier code exists but is not currently active.
    MicInactive {
        /// MIC identifier considered inactive.
        mic: String,
        /// Optional upstream status string.
        status: Option<String>,
    },
    #[error("{kind_label} reference `{value}` lacks required ledger mapping `{mapping}`", kind_label = .kind.label())]
    /// Reference exists but does not carry the ledger mapping required for admission.
    MissingLedgerMapping {
        /// Dataset kind used for lookup.
        kind: DatasetKind,
        /// Identifier value that was queried.
        value: String,
        /// Mapping field that was missing.
        mapping: &'static str,
    },
}
/// Provenance metadata describing a reference-data snapshot.
#[derive(Debug, Clone)]
pub struct SnapshotMetadata {
    /// Upstream dataset version or publication identifier.
    pub version: String,
    /// Upstream data source (e.g., ANNA DSB, GLEIF).
    pub source: String,
    /// Upstream fetch timestamp (RFC3339). Optional when not supplied.
    pub fetched_at: Option<OffsetDateTime>,
    /// Number of records ingested for the dataset.
    pub record_count: usize,
}
impl SnapshotMetadata {
    fn age_seconds(&self) -> Option<u64> {
        self.fetched_at.map(|ts| {
            let now = OffsetDateTime::now_utc();
            let delta = now - ts;
            if delta.is_negative() {
                0
            } else {
                u64::try_from(delta.whole_seconds()).unwrap_or(0)
            }
        })
    }
}
/// Snapshot container describing the state of a particular dataset.
#[derive(Debug, Clone)]
pub struct DatasetSnapshot<T> {
    kind: DatasetKind,
    state: SnapshotState,
    metadata: Option<SnapshotMetadata>,
    records: Option<T>,
    diagnostics: Option<String>,
    configured_path: Option<PathBuf>,
}
impl<T> DatasetSnapshot<T> {
    fn missing(kind: DatasetKind) -> Self {
        Self {
            kind,
            state: SnapshotState::Missing,
            metadata: None,
            records: None,
            diagnostics: None,
            configured_path: None,
        }
    }
    fn failed(kind: DatasetKind, path: &Path, err: &eyre::Report) -> Self {
        Self {
            kind,
            state: SnapshotState::Failed,
            metadata: None,
            records: None,
            diagnostics: Some(err.to_string()),
            configured_path: Some(path.to_path_buf()),
        }
    }
    fn loaded(kind: DatasetKind, path: &Path, metadata: SnapshotMetadata, records: T) -> Self {
        Self {
            kind,
            state: SnapshotState::Loaded,
            metadata: Some(metadata),
            records: Some(records),
            diagnostics: None,
            configured_path: Some(path.to_path_buf()),
        }
    }
    /// Snapshot status.
    #[must_use]
    pub fn state(&self) -> SnapshotState {
        self.state
    }
    /// Snapshot metadata if the dataset loaded successfully.
    #[must_use]
    pub fn metadata(&self) -> Option<&SnapshotMetadata> {
        self.metadata.as_ref()
    }
    /// Loaded records when the dataset is available.
    #[must_use]
    pub fn records(&self) -> Option<&T> {
        self.records.as_ref()
    }
    /// Diagnostics message (error) when loading failed.
    #[must_use]
    pub fn diagnostics(&self) -> Option<&str> {
        self.diagnostics.as_deref()
    }
    /// Configured snapshot path when provided.
    #[must_use]
    pub fn configured_path(&self) -> Option<&Path> {
        self.configured_path.as_deref()
    }
    /// Dataset kind represented by this snapshot.
    #[must_use]
    pub fn kind(&self) -> DatasetKind {
        self.kind
    }
    fn log_status(&self) {
        match self.state {
            SnapshotState::Loaded => {
                if let Some(meta) = &self.metadata {
                    let fetched = meta
                        .fetched_at
                        .map(|ts| ts.format(&Rfc3339).unwrap_or_else(|_| ts.to_string()));
                    let fetched_str = fetched.as_deref().unwrap_or("n/a");
                    info!(
                        dataset = self.kind.label(),
                        version = meta.version.as_str(),
                        source = meta.source.as_str(),
                        records = meta.record_count,
                        fetched_at = fetched_str,
                        "ISO reference dataset loaded"
                    );
                } else {
                    info!(
                        dataset = self.kind.label(),
                        "ISO reference dataset loaded without metadata"
                    );
                }
            }
            SnapshotState::Missing => {
                warn!(
                    dataset = self.kind.label(),
                    "ISO reference dataset not provided; falling back to runtime defaults"
                );
            }
            SnapshotState::Failed => {
                error!(
                    dataset = self.kind.label(),
                    error = self.diagnostics.as_deref().unwrap_or("unknown"),
                    "ISO reference dataset failed to load"
                );
            }
        }
    }
    fn publish_metrics(&self, refresh_interval: Duration) {
        let metrics = metrics::global_or_default();
        let dataset = self.kind.label();
        let status = self.state.as_gauge();
        let (age_seconds, record_count) = match (&self.state, &self.metadata) {
            (SnapshotState::Loaded, Some(meta)) => (meta.age_seconds(), Some(meta.record_count)),
            _ => (None, None),
        };
        metrics.record_iso_reference_dataset(dataset, status, age_seconds, record_count);
        metrics
            .iso_reference_refresh_interval_secs
            .with_label_values(&[dataset])
            .set({
                let secs = refresh_interval.as_secs();
                let clamped = secs.min(i64::MAX as u64);
                i64::try_from(clamped).unwrap_or(i64::MAX)
            });
    }
}
fn load_configured_dataset<T>(
    path: Option<&Path>,
    kind: DatasetKind,
    budget: &mut ReferenceDataLoadBudget,
    loader: impl FnOnce(&Path, &mut ReferenceDataLoadBudget) -> eyre::Result<(SnapshotMetadata, T)>,
) -> DatasetSnapshot<T> {
    let Some(path) = path else {
        return DatasetSnapshot::missing(kind);
    };
    match loader(path, budget) {
        Ok((metadata, records)) => DatasetSnapshot::loaded(kind, path, metadata, records),
        Err(err) => DatasetSnapshot::failed(kind, path, &err),
    }
}
/// In-memory snapshot cache for ISO 20022 reference data.
#[derive(Debug, Clone)]
pub struct ReferenceDataSnapshots {
    /// ISIN ↔ CUSIP crosswalk (ANNA).
    isin_cusip: DatasetSnapshot<InstrumentCrosswalk>,
    /// BIC ↔ LEI mapping (GLEIF).
    bic_lei: DatasetSnapshot<BicLeiCrosswalk>,
    /// MIC directory (SWIFT).
    mic_directory: DatasetSnapshot<MicDirectory>,
    /// CSD venue to ledger-domain crosswalk.
    csd_venue: DatasetSnapshot<CsdVenueDirectory>,
    /// Securities settlement-account crosswalk.
    securities_account: DatasetSnapshot<SecuritiesAccountCrosswalk>,
    /// Securities cash-leg crosswalk.
    cash_leg: DatasetSnapshot<CashLegCrosswalk>,
    /// Configured refresh interval.
    refresh_interval: Duration,
    /// Timestamp when the loader executed.
    loaded_at: OffsetDateTime,
}
impl ReferenceDataSnapshots {
    /// Build snapshots from the provided configuration.
    pub fn from_config(config: &actual::IsoReferenceData) -> Self {
        let now = OffsetDateTime::now_utc();
        let mut budget = ReferenceDataLoadBudget::default();
        let isin_snapshot = load_configured_dataset(
            config.isin_crosswalk_path.as_deref(),
            DatasetKind::IsinCusip,
            &mut budget,
            load_isin_crosswalk,
        );
        let bic_lei_snapshot = load_configured_dataset(
            config.bic_lei_path.as_deref(),
            DatasetKind::BicLei,
            &mut budget,
            load_bic_lei_crosswalk,
        );
        let mic_snapshot = load_configured_dataset(
            config.mic_directory_path.as_deref(),
            DatasetKind::MicDirectory,
            &mut budget,
            load_mic_directory,
        );
        let csd_venue_snapshot = load_configured_dataset(
            config.csd_venue_path.as_deref(),
            DatasetKind::CsdVenue,
            &mut budget,
            load_csd_venue_directory,
        );
        let securities_account_snapshot = load_configured_dataset(
            config.securities_account_path.as_deref(),
            DatasetKind::SecuritiesAccount,
            &mut budget,
            load_securities_account_crosswalk,
        );
        let cash_leg_snapshot = load_configured_dataset(
            config.cash_leg_path.as_deref(),
            DatasetKind::CashLeg,
            &mut budget,
            load_cash_leg_crosswalk,
        );
        let snapshots = Self {
            isin_cusip: isin_snapshot,
            bic_lei: bic_lei_snapshot,
            mic_directory: mic_snapshot,
            csd_venue: csd_venue_snapshot,
            securities_account: securities_account_snapshot,
            cash_leg: cash_leg_snapshot,
            refresh_interval: config.refresh_interval,
            loaded_at: now,
        };
        snapshots.log_statuses();
        snapshots.publish_metrics();
        if let Some(cache_dir) = config.cache_dir.as_deref()
            && let Err(err) = snapshots.persist_cache(cache_dir)
        {
            error!(
                directory = cache_dir.display().to_string().as_str(),
                error = err.to_string().as_str(),
                "failed to cache ISO reference dataset snapshots"
            );
        }
        snapshots
    }
    fn log_statuses(&self) {
        self.isin_cusip.log_status();
        self.bic_lei.log_status();
        self.mic_directory.log_status();
        self.csd_venue.log_status();
        self.securities_account.log_status();
        self.cash_leg.log_status();
    }
    fn publish_metrics(&self) {
        self.isin_cusip.publish_metrics(self.refresh_interval);
        self.bic_lei.publish_metrics(self.refresh_interval);
        self.mic_directory.publish_metrics(self.refresh_interval);
        self.csd_venue.publish_metrics(self.refresh_interval);
        self.securities_account
            .publish_metrics(self.refresh_interval);
        self.cash_leg.publish_metrics(self.refresh_interval);
    }
    fn persist_cache(&self, root: &Path) -> eyre::Result<()> {
        fs::create_dir_all(root).wrap_err_with(|| {
            format!("failed to create ISO cache directory at {}", root.display())
        })?;
        self.persist_dataset(root, self.isin_cusip())?;
        self.persist_dataset(root, self.bic_lei())?;
        self.persist_dataset(root, self.mic_directory())?;
        self.persist_dataset(root, self.csd_venue())?;
        self.persist_dataset(root, self.securities_account())?;
        self.persist_dataset(root, self.cash_leg())?;
        Ok(())
    }
    fn persist_dataset<T>(&self, root: &Path, snapshot: &DatasetSnapshot<T>) -> eyre::Result<()> {
        let dataset_dir = root.join(snapshot.kind().label());
        fs::create_dir_all(&dataset_dir).wrap_err_with(|| {
            format!(
                "failed to create cache directory for dataset {}",
                snapshot.kind().label()
            )
        })?;
        let status_path = dataset_dir.join("status.json");
        match snapshot.state() {
            SnapshotState::Loaded => {
                let meta = snapshot.metadata().ok_or_else(|| {
                    eyre::eyre!(
                        "dataset {} missing metadata despite Loaded state",
                        snapshot.kind().label()
                    )
                })?;
                self.persist_loaded_dataset(&dataset_dir, &status_path, snapshot, meta)?;
            }
            SnapshotState::Missing => {
                Self::persist_missing_dataset(&status_path, snapshot.kind().label())?;
            }
            SnapshotState::Failed => {
                Self::persist_failed_dataset(&status_path, snapshot)?;
            }
        }
        Ok(())
    }
    fn persist_loaded_dataset<T>(
        &self,
        dataset_dir: &Path,
        status_path: &Path,
        snapshot: &DatasetSnapshot<T>,
        meta: &SnapshotMetadata,
    ) -> eyre::Result<()> {
        let version = if meta.version.trim().is_empty() {
            format!("snapshot_{}", self.loaded_at.unix_timestamp())
        } else {
            meta.version.clone()
        };
        let sanitized_version = sanitize_path_component(&version);
        let data_filename = format!("{sanitized_version}.json");
        let metadata_filename = format!("{sanitized_version}.metadata.json");
        let cached_data_path = dataset_dir.join(&data_filename);
        let cached_sha256 = if let Some(source_path) = snapshot.configured_path() {
            if source_path != cached_data_path {
                fs::copy(source_path, &cached_data_path).wrap_err_with(|| {
                    format!(
                        "failed to copy {} to {}",
                        source_path.display(),
                        cached_data_path.display()
                    )
                })?;
            }
            Some(compute_sha256_hex(&cached_data_path)?)
        } else {
            None
        };
        let fetched_at = meta
            .fetched_at
            .map(|ts| ts.format(&Rfc3339).unwrap_or_else(|_| ts.to_string()));
        let mut metadata_map = json::Map::new();
        metadata_map.insert("status".to_owned(), Value::String("loaded".to_owned()));
        metadata_map.insert("version".to_owned(), Value::String(meta.version.clone()));
        metadata_map.insert("source".to_owned(), Value::String(meta.source.clone()));
        metadata_map.insert(
            "fetched_at".to_owned(),
            fetched_at.map_or(Value::Null, Value::String),
        );
        metadata_map.insert(
            "record_count".to_owned(),
            Value::from(meta.record_count as u64),
        );
        metadata_map.insert(
            "original_path".to_owned(),
            snapshot.configured_path().map_or(Value::Null, |path| {
                Value::String(path.display().to_string())
            }),
        );
        metadata_map.insert(
            "cached_path".to_owned(),
            cached_sha256.as_ref().map_or(Value::Null, |_| {
                Value::String(cached_data_path.display().to_string())
            }),
        );
        metadata_map.insert(
            "cached_sha256".to_owned(),
            cached_sha256
                .as_ref()
                .map_or(Value::Null, |sha| Value::String(sha.clone())),
        );
        let metadata_payload = Value::Object(metadata_map);
        fs::write(
            dataset_dir.join(metadata_filename),
            json::to_string_pretty(&metadata_payload)?,
        )
        .wrap_err_with(|| {
            format!(
                "failed to write metadata for dataset {}",
                snapshot.kind().label()
            )
        })?;
        let mut status_map = json::Map::new();
        status_map.insert("status".to_owned(), Value::String("loaded".to_owned()));
        status_map.insert(
            "latest_version".to_owned(),
            Value::String(meta.version.clone()),
        );
        status_map.insert(
            "cached_file".to_owned(),
            cached_sha256
                .as_ref()
                .map_or(Value::Null, |_| Value::String(data_filename)),
        );
        let status_payload = Value::Object(status_map);
        fs::write(status_path, json::to_string_pretty(&status_payload)?).wrap_err_with(|| {
            format!(
                "failed to write status file for dataset {}",
                snapshot.kind().label()
            )
        })?;
        Ok(())
    }
    fn persist_missing_dataset(status_path: &Path, label: &str) -> eyre::Result<()> {
        let mut status_map = json::Map::new();
        status_map.insert("status".to_owned(), Value::String("missing".to_owned()));
        let status_payload = Value::Object(status_map);
        fs::write(status_path, json::to_string_pretty(&status_payload)?)
            .wrap_err_with(|| format!("failed to write status file for dataset {label}"))?;
        Ok(())
    }
    fn persist_failed_dataset<T>(
        status_path: &Path,
        snapshot: &DatasetSnapshot<T>,
    ) -> eyre::Result<()> {
        let mut status_map = json::Map::new();
        status_map.insert("status".to_owned(), Value::String("failed".to_owned()));
        status_map.insert(
            "diagnostics".to_owned(),
            snapshot
                .diagnostics()
                .map_or(Value::Null, |diag| Value::String(diag.to_owned())),
        );
        status_map.insert(
            "path".to_owned(),
            snapshot.configured_path().map_or(Value::Null, |path| {
                Value::String(path.display().to_string())
            }),
        );
        let status_payload = Value::Object(status_map);
        fs::write(status_path, json::to_string_pretty(&status_payload)?).wrap_err_with(|| {
            format!(
                "failed to write status file for dataset {}",
                snapshot.kind().label()
            )
        })?;
        Ok(())
    }
    /// Access the ISIN ↔ CUSIP crosswalk snapshot.
    #[must_use]
    pub fn isin_cusip(&self) -> &DatasetSnapshot<InstrumentCrosswalk> {
        &self.isin_cusip
    }
    /// Access the BIC ↔ LEI crosswalk snapshot.
    #[must_use]
    pub fn bic_lei(&self) -> &DatasetSnapshot<BicLeiCrosswalk> {
        &self.bic_lei
    }
    /// Access the MIC directory snapshot.
    #[must_use]
    pub fn mic_directory(&self) -> &DatasetSnapshot<MicDirectory> {
        &self.mic_directory
    }
    /// Access the CSD venue crosswalk snapshot.
    #[must_use]
    pub fn csd_venue(&self) -> &DatasetSnapshot<CsdVenueDirectory> {
        &self.csd_venue
    }
    /// Access the securities account crosswalk snapshot.
    #[must_use]
    pub fn securities_account(&self) -> &DatasetSnapshot<SecuritiesAccountCrosswalk> {
        &self.securities_account
    }
    /// Access the securities cash-leg crosswalk snapshot.
    #[must_use]
    pub fn cash_leg(&self) -> &DatasetSnapshot<CashLegCrosswalk> {
        &self.cash_leg
    }
    /// Configured refresh interval.
    #[must_use]
    pub fn refresh_interval(&self) -> Duration {
        self.refresh_interval
    }
    /// Timestamp when the snapshots were last loaded.
    #[must_use]
    pub fn loaded_at(&self) -> OffsetDateTime {
        self.loaded_at
    }
    /// Return a deterministic checksum over loaded dataset provenance.
    #[must_use]
    pub fn snapshot_id(&self) -> String {
        let mut root = json::Map::new();
        root.insert(
            "datasets".to_owned(),
            Value::Array(vec![
                dataset_snapshot_value(self.isin_cusip()),
                dataset_snapshot_value(self.bic_lei()),
                dataset_snapshot_value(self.mic_directory()),
                dataset_snapshot_value(self.csd_venue()),
                dataset_snapshot_value(self.securities_account()),
                dataset_snapshot_value(self.cash_leg()),
            ]),
        );
        let rendered = json::to_json(&Value::Object(root)).unwrap_or_default();
        let digest = Sha256::digest(rendered.as_bytes());
        hex_lower(&digest)
    }
    /// Returns true when a required dataset is loaded.
    #[must_use]
    pub fn has_required_dataset(&self, requirement: ReferenceDatasetRequirement) -> bool {
        match requirement {
            ReferenceDatasetRequirement::BicLei => self.bic_lei.state() == SnapshotState::Loaded,
            ReferenceDatasetRequirement::IsinCusip => {
                self.isin_cusip.state() == SnapshotState::Loaded
            }
            ReferenceDatasetRequirement::MicDirectory => {
                self.mic_directory.state() == SnapshotState::Loaded
            }
        }
    }
    fn dataset_records_or_skip<T>(
        snapshot: &DatasetSnapshot<T>,
    ) -> Result<Option<&T>, ReferenceDataError> {
        match snapshot.state() {
            SnapshotState::Loaded => {
                let records = snapshot.records().expect("records present when loaded");
                Ok(Some(records))
            }
            SnapshotState::Missing => Ok(None),
            SnapshotState::Failed => Err(ReferenceDataError::DatasetFailed {
                kind: snapshot.kind,
                diagnostics: snapshot.diagnostics().map(ToOwned::to_owned),
            }),
        }
    }
    fn required_dataset_records<T>(
        snapshot: &DatasetSnapshot<T>,
    ) -> Result<&T, ReferenceDataError> {
        Self::dataset_records_or_skip(snapshot)?.ok_or(ReferenceDataError::DatasetUnavailable {
            kind: snapshot.kind,
        })
    }
    /// Validate that an ISIN appears in the crosswalk snapshot.
    ///
    /// # Errors
    /// Returns [`ReferenceDataError`] if the dataset is unavailable or the ISIN is unknown.
    pub fn validate_isin(&self, isin: &str) -> Result<(), ReferenceDataError> {
        let records = Self::required_dataset_records(&self.isin_cusip)?;
        if records.by_isin(isin).is_some() {
            Ok(())
        } else {
            Err(ReferenceDataError::NotFound {
                kind: DatasetKind::IsinCusip,
                value: normalise_upper_ascii(isin),
            })
        }
    }
    /// Validate that a CUSIP maps to a known ISIN.
    ///
    /// # Errors
    /// Returns [`ReferenceDataError`] if the dataset is unavailable or the CUSIP is unknown.
    pub fn validate_cusip(&self, cusip: &str) -> Result<(), ReferenceDataError> {
        let records = Self::required_dataset_records(&self.isin_cusip)?;
        if records.by_cusip(cusip).is_some() {
            Ok(())
        } else {
            Err(ReferenceDataError::NotFound {
                kind: DatasetKind::IsinCusip,
                value: normalise_upper_ascii(cusip),
            })
        }
    }
    /// Validate that a BIC is registered in the BIC↔LEI dataset.
    ///
    /// # Errors
    /// Returns [`ReferenceDataError`] if the dataset is unavailable or the BIC has no mapping.
    pub fn validate_bic(&self, bic: &str) -> Result<(), ReferenceDataError> {
        let records = Self::required_dataset_records(&self.bic_lei)?;
        if records.lei_by_bic(bic).is_some() {
            Ok(())
        } else {
            Err(ReferenceDataError::NotFound {
                kind: DatasetKind::BicLei,
                value: normalise_upper_ascii(bic),
            })
        }
    }
    /// Validate that a LEI is present in the BIC↔LEI dataset.
    ///
    /// # Errors
    /// Returns [`ReferenceDataError`] if the dataset is unavailable or the LEI is unknown.
    pub fn validate_lei(&self, lei: &str) -> Result<(), ReferenceDataError> {
        let records = Self::required_dataset_records(&self.bic_lei)?;
        if records.bics_by_lei(lei).is_some() {
            Ok(())
        } else {
            Err(ReferenceDataError::NotFound {
                kind: DatasetKind::BicLei,
                value: normalise_upper_ascii(lei),
            })
        }
    }
    /// Validate that a MIC exists and is active in the MIC directory.
    ///
    /// # Errors
    /// Returns [`ReferenceDataError`] if the dataset is unavailable or the MIC is unknown.
    pub fn validate_mic(&self, mic: &str) -> Result<(), ReferenceDataError> {
        let records = Self::required_dataset_records(&self.mic_directory)?;
        records.by_mic(mic).map_or_else(
            || {
                Err(ReferenceDataError::NotFound {
                    kind: DatasetKind::MicDirectory,
                    value: normalise_upper_ascii(mic),
                })
            },
            |record| {
                if mic_is_active(record.status.as_deref()) {
                    Ok(())
                } else {
                    Err(ReferenceDataError::MicInactive {
                        mic: normalise_upper_ascii(mic),
                        status: record.status.clone(),
                    })
                }
            },
        )
    }
    /// Validate that an instrument exists and carries an on-ledger mapping.
    ///
    /// # Errors
    /// Returns [`ReferenceDataError`] if the dataset failed to load, the identifier
    /// is unknown, or the record lacks both `asset_definition_id` and `asset_id`.
    pub fn validate_instrument_ledger_mapping(
        &self,
        instrument: &str,
    ) -> Result<(), ReferenceDataError> {
        let records = Self::required_dataset_records(&self.isin_cusip)?;
        let isin = normalise_upper_ascii(instrument);
        let record = records.by_isin(&isin).or_else(|| records.by_cusip(&isin));
        let Some(record) = record else {
            return Err(ReferenceDataError::NotFound {
                kind: DatasetKind::IsinCusip,
                value: isin,
            });
        };
        if record.asset_definition_id.is_some() || record.asset_id.is_some() {
            Ok(())
        } else {
            Err(ReferenceDataError::MissingLedgerMapping {
                kind: DatasetKind::IsinCusip,
                value: record.isin.clone(),
                mapping: "asset_definition_id_or_asset_id",
            })
        }
    }
    /// Validate that a settlement venue maps to a configured CSD ledger domain.
    ///
    /// # Errors
    /// Returns [`ReferenceDataError`] if the dataset failed to load, the MIC is
    /// unknown, or the row lacks a ledger-domain identifier.
    pub fn validate_csd_venue(&self, mic: &str) -> Result<(), ReferenceDataError> {
        let records = Self::required_dataset_records(&self.csd_venue)?;
        let key = normalise_upper_ascii(mic);
        let Some(record) = records.by_mic(&key) else {
            return Err(ReferenceDataError::NotFound {
                kind: DatasetKind::CsdVenue,
                value: key,
            });
        };
        if record.ledger_domain_id.is_some() {
            Ok(())
        } else {
            Err(ReferenceDataError::MissingLedgerMapping {
                kind: DatasetKind::CsdVenue,
                value: key,
                mapping: "ledger_domain_id",
            })
        }
    }
    /// Validate that a securities settlement account maps to a ledger account.
    ///
    /// # Errors
    /// Returns [`ReferenceDataError`] if the dataset failed to load, the account is
    /// unknown, the optional party BIC conflicts, or the row lacks `account_id`.
    pub fn validate_securities_account(
        &self,
        account: &str,
        bic: Option<&str>,
    ) -> Result<(), ReferenceDataError> {
        let records = Self::required_dataset_records(&self.securities_account)?;
        let key = normalise_upper_ascii(account);
        let Some(record) = records.by_account(&key) else {
            return Err(ReferenceDataError::NotFound {
                kind: DatasetKind::SecuritiesAccount,
                value: key,
            });
        };
        if let (Some(expected), Some(actual)) = (record.bic.as_deref(), bic)
            && expected != normalise_upper_ascii(actual)
        {
            return Err(ReferenceDataError::NotFound {
                kind: DatasetKind::SecuritiesAccount,
                value: format!("{key}:{}", normalise_upper_ascii(actual)),
            });
        }
        if record.account_id.is_some() {
            Ok(())
        } else {
            Err(ReferenceDataError::MissingLedgerMapping {
                kind: DatasetKind::SecuritiesAccount,
                value: key,
                mapping: "account_id",
            })
        }
    }
    /// Validate that a securities cash leg maps to a ledger asset definition.
    ///
    /// # Errors
    /// Returns [`ReferenceDataError`] if the dataset failed to load, no matching
    /// currency/payment-type row exists, or the row lacks `asset_definition_id`.
    pub fn validate_cash_leg(
        &self,
        currency: &str,
        payment_type: Option<&str>,
    ) -> Result<(), ReferenceDataError> {
        let records = Self::required_dataset_records(&self.cash_leg)?;
        let currency_key = normalise_upper_ascii(currency);
        let payment_key = payment_type.map(normalise_upper_ascii);
        let record = records.by_currency_and_payment(&currency_key, payment_key.as_deref());
        let Some(record) = record else {
            return Err(ReferenceDataError::NotFound {
                kind: DatasetKind::CashLeg,
                value: payment_key.map_or_else(
                    || currency_key.clone(),
                    |payment| format!("{currency_key}:{payment}"),
                ),
            });
        };
        if record.asset_definition_id.is_some() {
            Ok(())
        } else {
            Err(ReferenceDataError::MissingLedgerMapping {
                kind: DatasetKind::CashLeg,
                value: currency_key,
                mapping: "asset_definition_id",
            })
        }
    }
}
fn dataset_snapshot_value<T>(snapshot: &DatasetSnapshot<T>) -> Value {
    let mut map = json::Map::new();
    map.insert(
        "kind".to_owned(),
        Value::String(snapshot.kind().label().to_owned()),
    );
    map.insert(
        "state".to_owned(),
        Value::String(
            match snapshot.state() {
                SnapshotState::Missing => "missing",
                SnapshotState::Loaded => "loaded",
                SnapshotState::Failed => "failed",
            }
            .to_owned(),
        ),
    );
    if let Some(meta) = snapshot.metadata() {
        map.insert("version".to_owned(), Value::String(meta.version.clone()));
        map.insert("source".to_owned(), Value::String(meta.source.clone()));
        map.insert(
            "record_count".to_owned(),
            Value::from(meta.record_count as u64),
        );
        map.insert(
            "fetched_at".to_owned(),
            meta.fetched_at
                .map(|ts| ts.format(&Rfc3339).unwrap_or_else(|_| ts.to_string()))
                .map_or(Value::Null, Value::String),
        );
    }
    map.insert(
        "configured_path".to_owned(),
        snapshot.configured_path().map_or(Value::Null, |path| {
            Value::String(path.display().to_string())
        }),
    );
    map.insert(
        "diagnostics".to_owned(),
        snapshot
            .diagnostics()
            .map_or(Value::Null, |diag| Value::String(diag.to_owned())),
    );
    Value::Object(map)
}
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
/// Crosswalk entry describing an instrument record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstrumentRecord {
    /// ISIN identifier (key).
    pub isin: String,
    /// Optional CUSIP identifier.
    pub cusip: Option<String>,
    /// Optional asset definition identifier associated with the instrument.
    pub asset_definition_id: Option<String>,
    /// Optional asset identifier associated with the instrument.
    pub asset_id: Option<String>,
}
/// ISIN ↔ CUSIP crosswalk lookup structure.
#[derive(Debug, Clone, Default)]
pub struct InstrumentCrosswalk {
    by_isin: BTreeMap<String, InstrumentRecord>,
    by_cusip: BTreeMap<String, String>,
}
impl InstrumentCrosswalk {
    fn insert(&mut self, record: InstrumentRecord) -> eyre::Result<()> {
        let isin_key = normalise_upper_ascii(&record.isin);
        if self.by_isin.contains_key(&isin_key) {
            eyre::bail!("duplicate ISIN entry encountered: {isin_key}");
        }
        if let Some(cusip) = record.cusip.as_ref() {
            let cusip_key = normalise_upper_ascii(cusip);
            if let Some(existing) = self.by_cusip.insert(cusip_key.clone(), isin_key.clone()) {
                eyre::bail!(
                    "CUSIP {cusip_key} mapped to multiple ISINs ({existing} vs {isin_key})"
                );
            }
        }
        self.by_isin.insert(isin_key, record);
        Ok(())
    }
    /// Number of instrument records ingested.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_isin.len()
    }
    /// Returns true when no instrument records are loaded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_isin.is_empty()
    }
    /// Lookup by ISIN.
    #[must_use]
    pub fn by_isin(&self, isin: &str) -> Option<&InstrumentRecord> {
        let key = normalise_upper_ascii(isin);
        self.by_isin.get(&key)
    }
    /// Lookup by CUSIP.
    #[must_use]
    pub fn by_cusip(&self, cusip: &str) -> Option<&InstrumentRecord> {
        let key = normalise_upper_ascii(cusip);
        let isin = self.by_cusip.get(&key)?;
        self.by_isin.get(isin)
    }
}
/// BIC ↔ LEI crosswalk lookup structure.
#[derive(Debug, Clone, Default)]
pub struct BicLeiCrosswalk {
    bic_to_lei: BTreeMap<String, String>,
    lei_to_bic: BTreeMap<String, Vec<String>>,
}
impl BicLeiCrosswalk {
    fn insert(&mut self, bic: &str, lei: &str) -> eyre::Result<()> {
        let bic_key = normalise_upper_ascii(bic);
        let lei_key = normalise_upper_ascii(lei);
        if let Some(existing) = self.bic_to_lei.get(&bic_key) {
            eyre::bail!("duplicate BIC entry encountered: {bic_key} (already maps to {existing})");
        }
        self.bic_to_lei.insert(bic_key.clone(), lei_key.clone());
        self.lei_to_bic.entry(lei_key).or_default().push(bic_key);
        Ok(())
    }
    /// Number of BIC ↔ LEI pairs loaded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bic_to_lei.len()
    }
    /// Returns true when the crosswalk contains no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bic_to_lei.is_empty()
    }
    /// Lookup LEI by BIC.
    #[must_use]
    pub fn lei_by_bic(&self, bic: &str) -> Option<&str> {
        let key = normalise_upper_ascii(bic);
        self.bic_to_lei.get(&key).map(String::as_str)
    }
    /// Lookup BICs registered under a given LEI.
    #[must_use]
    pub fn bics_by_lei(&self, lei: &str) -> Option<&[String]> {
        let key = normalise_upper_ascii(lei);
        self.lei_to_bic.get(&key).map(Vec::as_slice)
    }
}
/// MIC directory entry.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MicRecord {
    /// MIC identifier.
    pub mic: String,
    /// Human-readable market name.
    pub market_name: Option<String>,
    /// Country of operation (ISO 3166 code).
    pub country: Option<String>,
    /// Registration or termination status.
    pub status: Option<String>,
}
/// MIC directory lookup.
#[derive(Debug, Clone, Default)]
pub struct MicDirectory {
    by_mic: BTreeMap<String, MicRecord>,
}
impl MicDirectory {
    fn insert(&mut self, record: MicRecord) -> eyre::Result<()> {
        let key = normalise_upper_ascii(&record.mic);
        if self.by_mic.contains_key(&key) {
            eyre::bail!("duplicate MIC entry encountered: {key}");
        }
        self.by_mic.insert(key, record);
        Ok(())
    }
    /// Number of MIC entries loaded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_mic.len()
    }
    /// Returns true when no MIC entries are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_mic.is_empty()
    }
    /// Lookup a MIC entry by identifier.
    #[must_use]
    pub fn by_mic(&self, mic: &str) -> Option<&MicRecord> {
        let key = normalise_upper_ascii(mic);
        self.by_mic.get(&key)
    }
}
/// CSD settlement venue mapping entry.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CsdVenueRecord {
    /// MIC identifier for the settlement venue.
    pub mic: String,
    /// Operator or upstream CSD identifier.
    pub csd_id: Option<String>,
    /// Ledger domain identifier used for CSD-owned state.
    pub ledger_domain_id: Option<String>,
}
/// CSD venue lookup.
#[derive(Debug, Clone, Default)]
pub struct CsdVenueDirectory {
    by_mic: BTreeMap<String, CsdVenueRecord>,
}
impl CsdVenueDirectory {
    fn insert(&mut self, record: CsdVenueRecord) -> eyre::Result<()> {
        let key = normalise_upper_ascii(&record.mic);
        if self.by_mic.contains_key(&key) {
            eyre::bail!("duplicate CSD venue entry encountered: {key}");
        }
        self.by_mic.insert(key, record);
        Ok(())
    }
    /// Number of CSD venue entries loaded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_mic.len()
    }
    /// Returns true when no CSD venue entries are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_mic.is_empty()
    }
    /// Lookup a CSD venue entry by MIC.
    #[must_use]
    pub fn by_mic(&self, mic: &str) -> Option<&CsdVenueRecord> {
        let key = normalise_upper_ascii(mic);
        self.by_mic.get(&key)
    }
}
/// Securities settlement-account mapping entry.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SecuritiesAccountRecord {
    /// External CSD settlement account literal.
    pub settlement_account: String,
    /// Optional party BIC expected for the account.
    pub bic: Option<String>,
    /// On-ledger account identifier.
    pub account_id: Option<String>,
}
/// Securities settlement-account lookup.
#[derive(Debug, Clone, Default)]
pub struct SecuritiesAccountCrosswalk {
    by_account: BTreeMap<String, SecuritiesAccountRecord>,
}
impl SecuritiesAccountCrosswalk {
    fn insert(&mut self, record: SecuritiesAccountRecord) -> eyre::Result<()> {
        let key = normalise_upper_ascii(&record.settlement_account);
        if self.by_account.contains_key(&key) {
            eyre::bail!("duplicate securities account entry encountered: {key}");
        }
        self.by_account.insert(key, record);
        Ok(())
    }
    /// Number of securities account entries loaded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_account.len()
    }
    /// Returns true when no securities account entries are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_account.is_empty()
    }
    /// Lookup a securities settlement account by external account literal.
    #[must_use]
    pub fn by_account(&self, account: &str) -> Option<&SecuritiesAccountRecord> {
        let key = normalise_upper_ascii(account);
        self.by_account.get(&key)
    }
}
/// Securities cash-leg mapping entry.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CashLegRecord {
    /// ISO 4217 currency code.
    pub currency: String,
    /// Optional ISO settlement payment type for the row.
    pub payment_type: Option<String>,
    /// On-ledger asset definition identifier used for the cash leg.
    pub asset_definition_id: Option<String>,
}
/// Securities cash-leg lookup.
#[derive(Debug, Clone, Default)]
pub struct CashLegCrosswalk {
    by_currency_payment: BTreeMap<(String, Option<String>), CashLegRecord>,
}
impl CashLegCrosswalk {
    fn insert(&mut self, record: CashLegRecord) -> eyre::Result<()> {
        let key = (
            normalise_upper_ascii(&record.currency),
            record.payment_type.as_deref().map(normalise_upper_ascii),
        );
        if self.by_currency_payment.contains_key(&key) {
            eyre::bail!(
                "duplicate cash-leg entry encountered: {}:{}",
                key.0,
                key.1.as_deref().unwrap_or("*")
            );
        }
        self.by_currency_payment.insert(key, record);
        Ok(())
    }
    /// Number of cash-leg entries loaded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_currency_payment.len()
    }
    /// Returns true when no cash-leg entries are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_currency_payment.is_empty()
    }
    /// Lookup by currency and optional payment type, falling back to a currency-only row.
    #[must_use]
    pub fn by_currency_and_payment(
        &self,
        currency: &str,
        payment_type: Option<&str>,
    ) -> Option<&CashLegRecord> {
        let currency_key = normalise_upper_ascii(currency);
        let payment_key = payment_type.map(normalise_upper_ascii);
        self.by_currency_payment
            .get(&(currency_key.clone(), payment_key))
            .or_else(|| self.by_currency_payment.get(&(currency_key, None)))
    }
}
fn load_isin_crosswalk(
    path: &Path,
    budget: &mut ReferenceDataLoadBudget,
) -> eyre::Result<(SnapshotMetadata, InstrumentCrosswalk)> {
    load_dataset_streaming(
        path,
        DatasetKind::IsinCusip,
        budget,
        InstrumentCrosswalk::len,
        |crosswalk, entry, budget| {
            let mut obj = take_entry_object(entry, "isin_cusip")?;
            let mut isin = take_required_string(&mut obj, "isin", "isin_cusip")?;
            isin.make_ascii_uppercase();
            if !iso20022::validate_identifier(IdentifierKind::Isin, &isin) {
                eyre::bail!("isin_cusip entry contains invalid ISIN `{isin}`");
            }
            let mut cusip = take_optional_string(&mut obj, "cusip", "isin_cusip")?;
            if let Some(value) = cusip.as_mut() {
                value.make_ascii_uppercase();
                if !iso20022::validate_identifier(IdentifierKind::Cusip, value) {
                    eyre::bail!("isin_cusip entry contains invalid CUSIP `{value}`");
                }
            }
            let asset_definition_id =
                take_optional_string(&mut obj, "asset_definition_id", "isin_cusip")?;
            let asset_id = take_optional_string(&mut obj, "asset_id", "isin_cusip")?;
            budget.charge_retained_strings(
                DatasetKind::IsinCusip,
                std::iter::once(isin.as_str())
                    .chain(cusip.iter().map(String::as_str))
                    .chain(asset_definition_id.iter().map(String::as_str))
                    .chain(asset_id.iter().map(String::as_str)),
            )?;
            crosswalk.insert(InstrumentRecord {
                isin,
                cusip,
                asset_definition_id,
                asset_id,
            })
        },
    )
}
fn load_bic_lei_crosswalk(
    path: &Path,
    budget: &mut ReferenceDataLoadBudget,
) -> eyre::Result<(SnapshotMetadata, BicLeiCrosswalk)> {
    load_dataset_streaming(
        path,
        DatasetKind::BicLei,
        budget,
        BicLeiCrosswalk::len,
        |crosswalk, entry, budget| {
            let mut obj = take_entry_object(entry, "bic_lei")?;
            let mut bic = take_required_string(&mut obj, "bic", "bic_lei")?;
            bic.make_ascii_uppercase();
            if !iso20022::validate_identifier(IdentifierKind::Bic, &bic) {
                eyre::bail!("bic_lei entry contains invalid BIC `{bic}`");
            }
            let mut lei = take_required_string(&mut obj, "lei", "bic_lei")?;
            lei.make_ascii_uppercase();
            if !iso20022::validate_identifier(IdentifierKind::Lei, &lei) {
                eyre::bail!("bic_lei entry contains invalid LEI `{lei}`");
            }
            budget.charge_retained_strings(DatasetKind::BicLei, [bic.as_str(), lei.as_str()])?;
            crosswalk.insert(&bic, &lei)
        },
    )
}
fn load_mic_directory(
    path: &Path,
    budget: &mut ReferenceDataLoadBudget,
) -> eyre::Result<(SnapshotMetadata, MicDirectory)> {
    load_dataset_streaming(
        path,
        DatasetKind::MicDirectory,
        budget,
        MicDirectory::len,
        |directory, entry, budget| {
            let mut obj = take_entry_object(entry, "mic_directory")?;
            let mut mic = take_required_string(&mut obj, "mic", "mic_directory")?;
            mic.make_ascii_uppercase();
            if !iso20022::validate_identifier(IdentifierKind::Mic, &mic) {
                eyre::bail!("mic_directory entry contains invalid MIC `{mic}`");
            }
            let market_name = take_optional_string(&mut obj, "market_name", "mic_directory")?;
            let mut country = take_optional_string(&mut obj, "country", "mic_directory")?;
            if let Some(value) = country.as_mut() {
                value.make_ascii_uppercase();
            }
            let status = take_optional_string(&mut obj, "status", "mic_directory")?;
            budget.charge_retained_strings(
                DatasetKind::MicDirectory,
                std::iter::once(mic.as_str())
                    .chain(market_name.iter().map(String::as_str))
                    .chain(country.iter().map(String::as_str))
                    .chain(status.iter().map(String::as_str)),
            )?;
            directory.insert(MicRecord {
                mic,
                market_name,
                country,
                status,
            })
        },
    )
}
fn load_csd_venue_directory(
    path: &Path,
    budget: &mut ReferenceDataLoadBudget,
) -> eyre::Result<(SnapshotMetadata, CsdVenueDirectory)> {
    load_dataset_streaming(
        path,
        DatasetKind::CsdVenue,
        budget,
        CsdVenueDirectory::len,
        |directory, entry, budget| {
            let mut obj = take_entry_object(entry, "csd_venue")?;
            let mut mic = take_required_string(&mut obj, "mic", "csd_venue")?;
            mic.make_ascii_uppercase();
            if !iso20022::validate_identifier(IdentifierKind::Mic, &mic) {
                eyre::bail!("csd_venue entry contains invalid MIC `{mic}`");
            }
            let csd_id = take_optional_string(&mut obj, "csd_id", "csd_venue")?;
            let ledger_domain_id = take_optional_string(&mut obj, "ledger_domain_id", "csd_venue")?;
            budget.charge_retained_strings(
                DatasetKind::CsdVenue,
                std::iter::once(mic.as_str())
                    .chain(csd_id.iter().map(String::as_str))
                    .chain(ledger_domain_id.iter().map(String::as_str)),
            )?;
            directory.insert(CsdVenueRecord {
                mic,
                csd_id,
                ledger_domain_id,
            })
        },
    )
}
fn load_securities_account_crosswalk(
    path: &Path,
    budget: &mut ReferenceDataLoadBudget,
) -> eyre::Result<(SnapshotMetadata, SecuritiesAccountCrosswalk)> {
    load_dataset_streaming(
        path,
        DatasetKind::SecuritiesAccount,
        budget,
        SecuritiesAccountCrosswalk::len,
        |crosswalk, entry, budget| {
            let mut obj = take_entry_object(entry, "securities_account")?;
            let mut settlement_account = if obj.contains_key("settlement_account") {
                take_required_string(&mut obj, "settlement_account", "securities_account")?
            } else {
                take_required_string(&mut obj, "account", "securities_account")?
            };
            settlement_account.make_ascii_uppercase();
            if settlement_account.is_empty() {
                eyre::bail!("securities_account entry contains empty settlement account");
            }
            let mut bic = take_optional_string(&mut obj, "bic", "securities_account")?;
            if let Some(value) = bic.as_mut() {
                value.make_ascii_uppercase();
                if !iso20022::validate_identifier(IdentifierKind::Bic, value) {
                    eyre::bail!("securities_account entry contains invalid BIC `{value}`");
                }
            }
            let account_id = take_optional_string(&mut obj, "account_id", "securities_account")?;
            budget.charge_retained_strings(
                DatasetKind::SecuritiesAccount,
                std::iter::once(settlement_account.as_str())
                    .chain(bic.iter().map(String::as_str))
                    .chain(account_id.iter().map(String::as_str)),
            )?;
            crosswalk.insert(SecuritiesAccountRecord {
                settlement_account,
                bic,
                account_id,
            })
        },
    )
}
fn load_cash_leg_crosswalk(
    path: &Path,
    budget: &mut ReferenceDataLoadBudget,
) -> eyre::Result<(SnapshotMetadata, CashLegCrosswalk)> {
    load_dataset_streaming(
        path,
        DatasetKind::CashLeg,
        budget,
        CashLegCrosswalk::len,
        |crosswalk, entry, budget| {
            let mut obj = take_entry_object(entry, "cash_leg")?;
            let mut currency = take_required_string(&mut obj, "currency", "cash_leg")?;
            currency.make_ascii_uppercase();
            if !iso20022::validate_identifier(IdentifierKind::Currency, &currency) {
                eyre::bail!("cash_leg entry contains invalid currency `{currency}`");
            }
            let mut payment_type = take_optional_string(&mut obj, "payment_type", "cash_leg")?;
            if let Some(value) = payment_type.as_mut() {
                value.make_ascii_uppercase();
            }
            let asset_definition_id =
                take_optional_string(&mut obj, "asset_definition_id", "cash_leg")?;
            budget.charge_retained_strings(
                DatasetKind::CashLeg,
                std::iter::once(currency.as_str())
                    .chain(payment_type.iter().map(String::as_str))
                    .chain(asset_definition_id.iter().map(String::as_str)),
            )?;
            crosswalk.insert(CashLegRecord {
                currency,
                payment_type,
                asset_definition_id,
            })
        },
    )
}
fn load_dataset_streaming<T: Default>(
    path: &Path,
    kind: DatasetKind,
    budget: &mut ReferenceDataLoadBudget,
    record_count: impl Fn(&T) -> usize,
    mut insert: impl FnMut(&mut T, Value, &mut ReferenceDataLoadBudget) -> eyre::Result<()>,
) -> eyre::Result<(SnapshotMetadata, T)> {
    let raw = read_dataset_json_bounded(path, kind, budget)?;
    let mut parser = json::Parser::new(&raw);
    let mut object = json::MapVisitor::new(&mut parser).wrap_err_with(|| {
        format!(
            "failed to parse {} reference dataset JSON at {}",
            kind.label(),
            path.display()
        )
    })?;
    let mut version = None;
    let mut source = None;
    let mut fetched_at: Option<Option<String>> = None;
    let mut records = None;
    while let Some(key) = object.next_key()? {
        match key.as_str() {
            "version" => {
                if version.is_some() {
                    return Err(json::Error::duplicate_field("version").into());
                }
                let value = object.parse_value::<String>()?;
                validate_string_bytes(kind, "version", &value)?;
                version = Some(value.trim().to_owned());
            }
            "source" => {
                if source.is_some() {
                    return Err(json::Error::duplicate_field("source").into());
                }
                let value = object.parse_value::<String>()?;
                validate_string_bytes(kind, "source", &value)?;
                source = Some(value.trim().to_owned());
            }
            "fetched_at" => {
                if fetched_at.is_some() {
                    return Err(json::Error::duplicate_field("fetched_at").into());
                }
                let value = object.parse_value::<Option<String>>()?;
                if let Some(value) = value.as_deref() {
                    validate_string_bytes(kind, "fetched_at", value)?;
                }
                fetched_at = Some(value);
            }
            "entries" => {
                if records.is_some() {
                    return Err(json::Error::duplicate_field("entries").into());
                }
                let mut loaded = T::default();
                object.parse_value_with_parser(|parser| {
                    let mut sequence = json::SeqVisitor::new(parser)?;
                    while !sequence.is_finished() {
                        budget.charge_record(kind).map_err(json_message)?;
                        let entry = sequence.next_element::<Value>()?.ok_or_else(|| {
                            json::Error::Message(format!(
                                "{} entries array ended unexpectedly",
                                kind.label()
                            ))
                        })?;
                        insert(&mut loaded, entry, budget).map_err(json_message)?;
                    }
                    sequence.finish()
                })?;
                records = Some(loaded);
            }
            _ => object.skip_value()?,
        }
    }
    object.finish()?;
    parser.skip_ws();
    if !parser.eof() {
        eyre::bail!(
            "{} reference dataset contains trailing JSON at byte {}",
            kind.label(),
            parser.position()
        );
    }
    let records =
        records.ok_or_else(|| eyre::eyre!("{} snapshot missing `entries` array", kind.label()))?;
    let version =
        version.ok_or_else(|| eyre::eyre!("{} snapshot missing `version`", kind.label()))?;
    let source = source.ok_or_else(|| eyre::eyre!("{} snapshot missing `source`", kind.label()))?;
    let fetched_at = fetched_at
        .flatten()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .map(|value| {
            OffsetDateTime::parse(&value, &Rfc3339)
                .wrap_err_with(|| format!("invalid RFC3339 timestamp `{value}`"))
        })
        .transpose()?;
    let metadata = SnapshotMetadata {
        version,
        source,
        fetched_at,
        record_count: record_count(&records),
    };
    Ok((metadata, records))
}
fn take_entry_object(entry: Value, dataset: &str) -> eyre::Result<json::Map> {
    match entry {
        Value::Object(obj) => Ok(obj),
        _ => eyre::bail!("{dataset} entry must be an object"),
    }
}
fn take_required_string(
    obj: &mut json::Map,
    field: &'static str,
    dataset: &str,
) -> eyre::Result<String> {
    let value = obj
        .remove(field)
        .ok_or_else(|| eyre::eyre!("{dataset} entry missing `{field}`"))?;
    let Value::String(value) = value else {
        eyre::bail!("{dataset} entry `{field}` must be a string");
    };
    validate_string_bytes_by_label(dataset, field, &value)?;
    Ok(value.trim().to_owned())
}
fn take_optional_string(
    obj: &mut json::Map,
    field: &'static str,
    dataset: &str,
) -> eyre::Result<Option<String>> {
    let Some(value) = obj.remove(field) else {
        return Ok(None);
    };
    match value {
        Value::Null => Ok(None),
        Value::String(value) => {
            validate_string_bytes_by_label(dataset, field, &value)?;
            let trimmed = value.trim();
            Ok((!trimmed.is_empty()).then(|| trimmed.to_owned()))
        }
        _ => eyre::bail!("{dataset} entry `{field}` must be a string or null"),
    }
}
fn validate_string_bytes(kind: DatasetKind, field: &'static str, value: &str) -> eyre::Result<()> {
    validate_string_bytes_by_label(kind.label(), field, value)
}
fn validate_string_bytes_by_label(
    dataset: &str,
    field: &'static str,
    value: &str,
) -> eyre::Result<()> {
    if value.len() > REFERENCE_DATA_MAX_STRING_BYTES {
        eyre::bail!(
            "{dataset} `{field}` is {} bytes (maximum {})",
            value.len(),
            REFERENCE_DATA_MAX_STRING_BYTES
        );
    }
    Ok(())
}
fn json_message(error: impl core::fmt::Display) -> json::Error {
    json::Error::Message(error.to_string())
}
fn read_dataset_json_bounded(
    path: &Path,
    kind: DatasetKind,
    budget: &mut ReferenceDataLoadBudget,
) -> eyre::Result<String> {
    let initial = fs::symlink_metadata(path).wrap_err_with(|| {
        format!(
            "failed to inspect ISO reference dataset at {}",
            path.display()
        )
    })?;
    if !initial.file_type().is_file() {
        eyre::bail!(
            "ISO reference dataset at {} is not a regular file",
            path.display()
        );
    }
    let initial_len = usize::try_from(initial.len())
        .map_err(|_| eyre::eyre!("ISO reference dataset length does not fit this platform"))?;
    if initial_len > REFERENCE_DATA_MAX_DATASET_BYTES {
        eyre::bail!(
            "{} dataset is {initial_len} bytes (maximum {})",
            kind.label(),
            REFERENCE_DATA_MAX_DATASET_BYTES
        );
    }
    if initial_len > budget.remaining_input_bytes {
        eyre::bail!(
            "{} dataset would exceed the {}-byte aggregate input budget",
            kind.label(),
            REFERENCE_DATA_MAX_TOTAL_INPUT_BYTES
        );
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let nofollow = i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits())
            .expect("NOFOLLOW flag bits fit the platform custom-flags type");
        options.custom_flags(nofollow);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = options
        .open(path)
        .wrap_err_with(|| format!("failed to open ISO reference dataset at {}", path.display()))?;
    let opened = file
        .metadata()
        .wrap_err_with(|| format!("failed to inspect opened ISO dataset at {}", path.display()))?;
    if !opened.is_file() || !same_dataset_snapshot(&initial, &opened) {
        eyre::bail!(
            "ISO reference dataset at {} changed while opening",
            path.display()
        );
    }
    let mut raw = Vec::with_capacity(initial_len);
    Read::by_ref(&mut file)
        .take(
            u64::try_from(REFERENCE_DATA_MAX_DATASET_BYTES)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut raw)
        .wrap_err_with(|| format!("failed to read ISO reference dataset at {}", path.display()))?;
    if raw.len() > REFERENCE_DATA_MAX_DATASET_BYTES {
        eyre::bail!(
            "{} dataset grew beyond its {}-byte limit while reading",
            kind.label(),
            REFERENCE_DATA_MAX_DATASET_BYTES
        );
    }
    let after_read = file.metadata().wrap_err_with(|| {
        format!(
            "failed to re-inspect opened ISO dataset at {}",
            path.display()
        )
    })?;
    let current = fs::symlink_metadata(path).wrap_err_with(|| {
        format!(
            "failed to re-inspect ISO reference dataset at {}",
            path.display()
        )
    })?;
    if !current.file_type().is_file()
        || raw.len() != initial_len
        || !same_dataset_snapshot(&opened, &after_read)
        || !same_dataset_snapshot(&after_read, &current)
    {
        eyre::bail!(
            "ISO reference dataset at {} changed while reading",
            path.display()
        );
    }
    budget.charge_input(kind, raw.len())?;
    String::from_utf8(raw).map_err(|_| {
        eyre::eyre!(
            "ISO reference dataset at {} is not valid UTF-8",
            path.display()
        )
    })
}
#[cfg(unix)]
fn same_dataset_snapshot(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}
#[cfg(not(unix))]
fn same_dataset_snapshot(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}
fn mic_is_active(status: Option<&str>) -> bool {
    match status {
        None => true,
        Some(raw) => {
            let upper = raw.trim().to_ascii_uppercase();
            if upper.is_empty() {
                return true;
            }
            if upper.contains('!') {
                return false;
            }
            !upper.contains("DELETED")
                && !upper.contains("EXPIRED")
                && !upper.contains("INACTIVE")
                && !upper.contains("SUSPENDED")
        }
    }
}
fn normalise_upper_ascii(input: &str) -> String {
    input.trim().to_ascii_uppercase()
}
fn sanitize_path_component(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() { "_".to_owned() } else { out }
}
fn compute_sha256_hex(path: &Path) -> eyre::Result<String> {
    let mut file = File::open(path)
        .wrap_err_with(|| format!("failed to open dataset at {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_config::parameters::actual::IsoReferenceData;
    use iroha_telemetry::metrics;
    use std::{
        fs,
        io::Write as _,
        sync::{Mutex, OnceLock},
    };
    use tempfile::{NamedTempFile, TempDir};
    fn iso_reference_test_guard() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .expect("iso reference test lock poisoned")
    }
    fn write_snapshot(contents: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().expect("temp file");
        file.write_all(contents.as_bytes()).expect("write snapshot");
        file
    }
    #[test]
    fn missing_snapshots_default_to_missing_state() {
        let _guard = iso_reference_test_guard();
        let config = IsoReferenceData::default();
        let snapshots = ReferenceDataSnapshots::from_config(&config);
        assert_eq!(snapshots.isin_cusip().state(), SnapshotState::Missing);
        assert_eq!(snapshots.bic_lei().state(), SnapshotState::Missing);
        assert_eq!(snapshots.mic_directory().state(), SnapshotState::Missing);
        assert_eq!(snapshots.csd_venue().state(), SnapshotState::Missing);
        assert_eq!(
            snapshots.securities_account().state(),
            SnapshotState::Missing
        );
        assert_eq!(snapshots.cash_leg().state(), SnapshotState::Missing);
    }
    #[test]
    fn oversized_snapshot_is_rejected_before_json_allocation() {
        let _guard = iso_reference_test_guard();
        let file = NamedTempFile::new().expect("temp file");
        file.as_file()
            .set_len(
                u64::try_from(REFERENCE_DATA_MAX_DATASET_BYTES + 1)
                    .expect("dataset byte limit fits u64"),
            )
            .expect("create oversized sparse dataset");
        let config = IsoReferenceData {
            isin_crosswalk_path: Some(file.path().to_path_buf()),
            ..IsoReferenceData::default()
        };
        let snapshots = ReferenceDataSnapshots::from_config(&config);
        assert_eq!(snapshots.isin_cusip().state(), SnapshotState::Failed);
        assert!(
            snapshots
                .isin_cusip()
                .diagnostics()
                .is_some_and(|diagnostics| diagnostics.contains("maximum"))
        );
    }
    #[test]
    fn aggregate_record_limit_is_checked_before_next_entry_decode() {
        let file = write_snapshot(
            r#"{
                "version":"2024-05-01",
                "source":"bounded test",
                "entries":[{"isin":42}]
            }"#,
        );
        let mut budget = ReferenceDataLoadBudget {
            remaining_records: 0,
            ..Default::default()
        };
        let error = load_isin_crosswalk(file.path(), &mut budget).unwrap_err();
        assert!(error.to_string().contains("aggregate limit"));
    }
    #[test]
    fn retained_index_budget_rejects_first_overflow() {
        let mut budget = ReferenceDataLoadBudget::default();
        let exact_charge =
            REFERENCE_DATA_RECORD_OVERHEAD_BYTES + REFERENCE_DATA_STRING_ACCOUNTING_MULTIPLIER * 3;
        budget.remaining_retained_bytes = exact_charge;
        budget
            .charge_retained_strings(DatasetKind::CashLeg, ["USD"])
            .expect("exact retained budget");
        assert_eq!(budget.remaining_retained_bytes, 0);
        assert!(
            budget
                .charge_retained_strings(DatasetKind::CashLeg, [""])
                .unwrap_err()
                .to_string()
                .contains("retained-index budget")
        );
    }
    #[test]
    fn loads_isin_crosswalk_snapshot() {
        let _guard = iso_reference_test_guard();
        let metrics_handle = metrics::global_or_default();
        let contents = r#"{
            "version":"2024-05-01",
            "source":"ANNA DSB test",
            "fetched_at":"2024-05-01T12:00:00Z",
            "entries":[
                {
                    "isin":"US0378331005",
                    "cusip":"037833100",
                    "asset_definition_id":"usd#test"
                }
            ]
        }"#;
        let file = write_snapshot(contents);
        let config = IsoReferenceData {
            isin_crosswalk_path: Some(file.path().to_path_buf()),
            ..IsoReferenceData::default()
        };
        let snapshots = ReferenceDataSnapshots::from_config(&config);
        let dataset = snapshots.isin_cusip();
        assert_eq!(dataset.state(), SnapshotState::Loaded);
        let metadata = dataset.metadata().expect("metadata present");
        assert_eq!(metadata.version, "2024-05-01");
        assert_eq!(metadata.source, "ANNA DSB test");
        assert_eq!(metadata.record_count, 1);
        let crosswalk = dataset.records().expect("crosswalk loaded");
        let record = crosswalk.by_isin("US0378331005").expect("isin present");
        assert_eq!(record.cusip.as_deref(), Some("037833100"));
        assert_eq!(record.asset_definition_id.as_deref(), Some("usd#test"));
        assert_eq!(
            metrics_handle
                .iso_reference_status
                .with_label_values(&["isin_cusip"])
                .get(),
            1
        );
        assert_eq!(
            metrics_handle
                .iso_reference_records
                .with_label_values(&["isin_cusip"])
                .get(),
            1
        );
        let age = metrics_handle
            .iso_reference_age_seconds
            .with_label_values(&["isin_cusip"])
            .get();
        assert!(age >= 0);
    }
    #[test]
    fn validate_bic_enforces_registered_entries() {
        let _guard = iso_reference_test_guard();
        let bic_snapshot = r#"{
            "version":"2024-05-01",
            "source":"GLEIF sample",
            "entries":[
                {"bic":"DEUTDEFF","lei":"5493001KJTIIGC8Y1R12"}
            ]
        }"#;
        let file = write_snapshot(bic_snapshot);
        let config = IsoReferenceData {
            bic_lei_path: Some(file.path().to_path_buf()),
            ..IsoReferenceData::default()
        };
        let snapshots = ReferenceDataSnapshots::from_config(&config);
        snapshots.validate_bic("DEUTDEFF").expect("validation");
        let err = snapshots.validate_bic("FOOBARXX").unwrap_err();
        assert!(matches!(err, ReferenceDataError::NotFound { .. }));
    }
    #[test]
    fn validation_fails_closed_when_dataset_is_missing() {
        let _guard = iso_reference_test_guard();
        let config = IsoReferenceData::default();
        let snapshots = ReferenceDataSnapshots::from_config(&config);
        for result in [
            snapshots.validate_bic("DEUTDEFF"),
            snapshots.validate_lei("5493001KJTIIGC8Y1R12"),
        ] {
            assert!(matches!(
                result,
                Err(ReferenceDataError::DatasetUnavailable {
                    kind: DatasetKind::BicLei
                })
            ));
        }
        for result in [
            snapshots.validate_isin("US0378331005"),
            snapshots.validate_cusip("037833100"),
        ] {
            assert!(matches!(
                result,
                Err(ReferenceDataError::DatasetUnavailable {
                    kind: DatasetKind::IsinCusip
                })
            ));
        }
        assert!(matches!(
            snapshots.validate_mic("XNAS"),
            Err(ReferenceDataError::DatasetUnavailable {
                kind: DatasetKind::MicDirectory
            })
        ));
    }
    #[test]
    fn persists_loaded_snapshots_to_cache() {
        let _guard = iso_reference_test_guard();
        let contents = r#"{
            "version":"2024-05-01",
            "source":"ANNA test",
            "entries":[{"isin":"US0378331005","cusip":"037833100"}]
        }"#;
        let file = write_snapshot(contents);
        let cache_dir = TempDir::new().expect("cache dir");
        let config = IsoReferenceData {
            isin_crosswalk_path: Some(file.path().to_path_buf()),
            cache_dir: Some(cache_dir.path().to_path_buf()),
            ..IsoReferenceData::default()
        };
        let snapshots = ReferenceDataSnapshots::from_config(&config);
        assert_eq!(snapshots.isin_cusip().state(), SnapshotState::Loaded);
        let dataset_dir = cache_dir.path().join("isin_cusip");
        let status_path = dataset_dir.join("status.json");
        assert!(status_path.exists(), "status file missing");
        let status_value: Value =
            norito::json::from_str(&fs::read_to_string(&status_path).unwrap())
                .expect("status json");
        assert_eq!(
            status_value.get("status").and_then(Value::as_str),
            Some("loaded")
        );
        let cached_file = status_value
            .get("cached_file")
            .and_then(Value::as_str)
            .expect("cached file entry");
        let metadata_path = dataset_dir.join("2024-05-01.metadata.json");
        assert!(metadata_path.exists(), "metadata file missing");
        let metadata_value: Value =
            norito::json::from_str(&fs::read_to_string(&metadata_path).unwrap())
                .expect("metadata json");
        assert_eq!(
            metadata_value.get("version").and_then(Value::as_str),
            Some("2024-05-01")
        );
        let cached_data_path = dataset_dir.join(cached_file);
        assert!(cached_data_path.exists(), "cached dataset missing");
        let expected_sha = compute_sha256_hex(&cached_data_path).expect("sha256");
        assert_eq!(
            metadata_value.get("cached_sha256").and_then(Value::as_str),
            Some(expected_sha.as_str())
        );
        // Metrics are published to a global registry that other tests mutate concurrently,
        // so this test only verifies the cached artifacts.
    }
    #[test]
    fn validate_mic_flags_inactive_entries() {
        let _guard = iso_reference_test_guard();
        let mic_snapshot = r#"{
            "version":"2024-05-01",
            "source":"MIC sample",
            "entries":[
                {"mic":"XNAS","status":"ACTIVE"},
                {"mic":"XTBD","status":"DELETED"}
            ]
        }"#;
        let file = write_snapshot(mic_snapshot);
        let config = IsoReferenceData {
            mic_directory_path: Some(file.path().to_path_buf()),
            ..IsoReferenceData::default()
        };
        let snapshots = ReferenceDataSnapshots::from_config(&config);
        snapshots.validate_mic("XNAS").expect("validation");
        let err = snapshots.validate_mic("XTBD").unwrap_err();
        assert!(matches!(err, ReferenceDataError::MicInactive { .. }));
    }
    #[test]
    fn loads_and_validates_securities_ledger_crosswalk_snapshots() {
        let _guard = iso_reference_test_guard();
        let instrument_snapshot = write_snapshot(
            r#"{
                "version":"2024-05-01",
                "source":"ANNA DSB sample",
                "entries":[{"isin":"US0378331005","cusip":"037833100","asset_definition_id":"usd#securities"}]
            }"#,
        );
        let csd_snapshot = write_snapshot(
            r#"{
                "version":"2024-05-01",
                "source":"CSD sample",
                "entries":[{"mic":"XNAS","csd_id":"DTC","ledger_domain_id":"securities"}]
            }"#,
        );
        let account_snapshot = write_snapshot(
            r#"{
                "version":"2024-05-01",
                "source":"CSD account sample",
                "entries":[{"settlement_account":"DLVRY-ACC","bic":"DEUTDEFF","account_id":"alice@test"}]
            }"#,
        );
        let cash_snapshot = write_snapshot(
            r#"{
                "version":"2024-05-01",
                "source":"CSD cash-leg sample",
                "entries":[{"currency":"USD","payment_type":"APMT","asset_definition_id":"usd#securities"}]
            }"#,
        );
        let config = IsoReferenceData {
            isin_crosswalk_path: Some(instrument_snapshot.path().to_path_buf()),
            csd_venue_path: Some(csd_snapshot.path().to_path_buf()),
            securities_account_path: Some(account_snapshot.path().to_path_buf()),
            cash_leg_path: Some(cash_snapshot.path().to_path_buf()),
            ..IsoReferenceData::default()
        };
        let snapshots = ReferenceDataSnapshots::from_config(&config);
        snapshots
            .validate_instrument_ledger_mapping("037833100")
            .expect("instrument ledger mapping");
        snapshots
            .validate_csd_venue("XNAS")
            .expect("CSD venue mapping");
        snapshots
            .validate_securities_account("DLVRY-ACC", Some("DEUTDEFF"))
            .expect("securities account mapping");
        snapshots
            .validate_cash_leg("USD", Some("APMT"))
            .expect("cash-leg mapping");
    }
    #[test]
    fn securities_ledger_crosswalk_validation_rejects_incomplete_rows() {
        let _guard = iso_reference_test_guard();
        let instrument_snapshot = write_snapshot(
            r#"{
                "version":"2024-05-01",
                "source":"ANNA DSB sample",
                "entries":[{"isin":"US0378331005","cusip":"037833100"}]
            }"#,
        );
        let csd_snapshot = write_snapshot(
            r#"{
                "version":"2024-05-01",
                "source":"CSD sample",
                "entries":[{"mic":"XNAS","csd_id":"DTC"}]
            }"#,
        );
        let account_snapshot = write_snapshot(
            r#"{
                "version":"2024-05-01",
                "source":"CSD account sample",
                "entries":[{"settlement_account":"DLVRY-ACC","bic":"DEUTDEFF"}]
            }"#,
        );
        let cash_snapshot = write_snapshot(
            r#"{
                "version":"2024-05-01",
                "source":"CSD cash-leg sample",
                "entries":[{"currency":"USD","payment_type":"APMT"}]
            }"#,
        );
        let config = IsoReferenceData {
            isin_crosswalk_path: Some(instrument_snapshot.path().to_path_buf()),
            csd_venue_path: Some(csd_snapshot.path().to_path_buf()),
            securities_account_path: Some(account_snapshot.path().to_path_buf()),
            cash_leg_path: Some(cash_snapshot.path().to_path_buf()),
            ..IsoReferenceData::default()
        };
        let snapshots = ReferenceDataSnapshots::from_config(&config);
        assert!(matches!(
            snapshots
                .validate_instrument_ledger_mapping("US0378331005")
                .unwrap_err(),
            ReferenceDataError::MissingLedgerMapping { .. }
        ));
        assert!(matches!(
            snapshots.validate_csd_venue("XNAS").unwrap_err(),
            ReferenceDataError::MissingLedgerMapping { .. }
        ));
        assert!(matches!(
            snapshots
                .validate_securities_account("DLVRY-ACC", Some("DEUTDEFF"))
                .unwrap_err(),
            ReferenceDataError::MissingLedgerMapping { .. }
        ));
        assert!(matches!(
            snapshots
                .validate_cash_leg("USD", Some("APMT"))
                .unwrap_err(),
            ReferenceDataError::MissingLedgerMapping { .. }
        ));
        assert!(matches!(
            snapshots
                .validate_securities_account("DLVRY-ACC", Some("MARKDEFF"))
                .unwrap_err(),
            ReferenceDataError::NotFound { .. }
        ));
    }
}
