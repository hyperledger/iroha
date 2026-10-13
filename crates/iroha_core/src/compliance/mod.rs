//! Lane compliance policy evaluation and loading.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "TODO: consume the lane compliance projection in the complete State root owner"
    )
)]
pub(crate) mod authority;

use crate::{
    interlane::LanePrivacyRegistryHandle,
    secure_file_metadata::{self, SecureMetadata},
};
use iroha_crypto::{Hash, privacy::LaneCommitmentId};
use iroha_data_model::{
    account::AccountId,
    nexus::{
        LaneCatalog, LaneCompliancePolicy, LaneCompliancePolicyId, LaneComplianceRule,
        MAX_ACTIVE_EXECUTION_LANES, ParticipantSelector, UniversalAccountId,
    },
};
use iroha_logger::warn;
use iroha_model_base::domain::DomainId;
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
use norito::codec::{DecodeAll, Encode};
use norito::{DecodeLimits, with_decode_limits};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, Read as _},
    path::{Path, PathBuf},
    sync::{Arc, LazyLock},
};
/// Static engine that evaluates lane compliance policies.
#[derive(Debug)]
pub struct LaneComplianceEngine {
    policies: BTreeMap<LaneId, Arc<LaneCompliancePolicy>>,
    audit_only: bool,
}
static EMPTY_PRIVACY_COMMITMENTS: LazyLock<BTreeSet<LaneCommitmentId>> =
    LazyLock::new(BTreeSet::new);
// Policy metadata can contain canonical `Json`, whose data model independently
// validates its byte and nesting limits. The file ceiling leaves room for the
// surrounding policy structure, while field, aggregate input, and decode-
// allocation limits apply before Norito allocates strings or collections and
// keep the retained startup policy set bounded independently of directory
// layout.
const LANE_COMPLIANCE_POLICY_MAX_BYTES: usize = 2 * 1024 * 1024;
const LANE_COMPLIANCE_POLICY_AGGREGATE_MAX_BYTES: usize = 16 * 1024 * 1024;
const LANE_COMPLIANCE_POLICY_MAX_FIELD_BYTES: usize = iroha_primitives::json::MAX_JSON_BYTES;
const LANE_COMPLIANCE_POLICY_MAX_SEQUENCE_ELEMENTS: usize = 16 * 1024;
const LANE_COMPLIANCE_POLICY_MAX_TOTAL_ELEMENTS: usize = 64 * 1024;
const LANE_COMPLIANCE_POLICY_MAX_DECODE_ALLOCATED_BYTES: usize = 16 * 1024 * 1024;
const LANE_COMPLIANCE_POLICY_MAX_DECODE_DEPTH: usize = 64;
const LANE_COMPLIANCE_POLICY_DECODE_ALLOCATION_MULTIPLIER: usize = 8;
const LANE_COMPLIANCE_POLICY_DECODE_FIXED_ALLOCATION_BYTES: usize = 16 * 1024;
#[derive(Clone, Copy)]
struct LaneComplianceLoadLimits {
    max_files: usize,
    max_file_bytes: usize,
    max_aggregate_bytes: usize,
    max_field_bytes: usize,
    max_sequence_elements: usize,
    max_total_elements: usize,
    max_decode_allocated_bytes: usize,
    max_decode_depth: usize,
}
const LANE_COMPLIANCE_LOAD_LIMITS: LaneComplianceLoadLimits = LaneComplianceLoadLimits {
    max_files: MAX_ACTIVE_EXECUTION_LANES,
    max_file_bytes: LANE_COMPLIANCE_POLICY_MAX_BYTES,
    max_aggregate_bytes: LANE_COMPLIANCE_POLICY_AGGREGATE_MAX_BYTES,
    max_field_bytes: LANE_COMPLIANCE_POLICY_MAX_FIELD_BYTES,
    max_sequence_elements: LANE_COMPLIANCE_POLICY_MAX_SEQUENCE_ELEMENTS,
    max_total_elements: LANE_COMPLIANCE_POLICY_MAX_TOTAL_ELEMENTS,
    max_decode_allocated_bytes: LANE_COMPLIANCE_POLICY_MAX_DECODE_ALLOCATED_BYTES,
    max_decode_depth: LANE_COMPLIANCE_POLICY_MAX_DECODE_DEPTH,
};
impl LaneComplianceEngine {
    #[cfg(any(test, feature = "iroha-core-tests"))]
    /// Construct an engine from explicit policy definitions.
    ///
    /// # Errors
    /// Returns [`LaneComplianceLoadError`] when duplicate lane identifiers are encountered or the
    /// policy count exceeds the protocol-wide active-lane ceiling.
    pub fn from_policies(
        policies: Vec<LaneCompliancePolicy>,
        audit_only: bool,
    ) -> Result<Self, LaneComplianceLoadError> {
        let mut map = BTreeMap::new();
        for policy in policies {
            insert_policy(&mut map, policy, MAX_ACTIVE_EXECUTION_LANES)?;
        }
        Ok(Self {
            policies: map,
            audit_only,
        })
    }
    /// Load Norito-encoded policy bundles from the supplied directory.
    ///
    /// Direct regular files are ingested one at a time under protocol-count, per-file, aggregate,
    /// and Norito decode budgets. Embedded canonical JSON retains its data-model byte and nesting
    /// validation; symbolic links and other special files are rejected without following them.
    ///
    /// # Errors
    /// Returns [`LaneComplianceLoadError`] when the directory cannot be read, a resource bound is
    /// exceeded, a policy cannot be decoded, or no policies are present.
    pub fn from_directory(dir: &Path, audit_only: bool) -> Result<Self, LaneComplianceLoadError> {
        Self::from_directory_with_limits(dir, audit_only, LANE_COMPLIANCE_LOAD_LIMITS)
    }
    fn from_directory_with_limits(
        dir: &Path,
        audit_only: bool,
        limits: LaneComplianceLoadLimits,
    ) -> Result<Self, LaneComplianceLoadError> {
        let directory_metadata = match secure_file_metadata::from_path(dir) {
            Ok(metadata) => metadata,
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                return Err(LaneComplianceLoadError::MissingDirectory(dir.to_path_buf()));
            }
            Err(source) => {
                return Err(LaneComplianceLoadError::ReadDir {
                    path: dir.to_path_buf(),
                    source,
                });
            }
        };
        if policy_metadata_is_symlink_or_reparse(&directory_metadata)
            || !directory_metadata.is_dir()
        {
            return Err(LaneComplianceLoadError::NotADirectory(dir.to_path_buf()));
        }
        let mut policies = BTreeMap::new();
        let mut file_count = 0_usize;
        let mut aggregate_bytes = 0_usize;
        for entry in fs::read_dir(dir).map_err(|source| LaneComplianceLoadError::ReadDir {
            path: dir.to_path_buf(),
            source,
        })? {
            let entry = entry.map_err(|source| LaneComplianceLoadError::ReadDir {
                path: dir.to_path_buf(),
                source,
            })?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|source| LaneComplianceLoadError::Io {
                    path: path.clone(),
                    source,
                })?;
            if file_type.is_dir() {
                continue;
            }
            file_count = file_count.saturating_add(1);
            if file_count > limits.max_files {
                return Err(LaneComplianceLoadError::FileCountExceeded {
                    actual: file_count,
                    maximum: limits.max_files,
                });
            }
            if !file_type.is_file() || file_type.is_symlink() {
                return Err(LaneComplianceLoadError::NotRegularFile(path));
            }
            let bytes = read_bounded_policy_file(&path, limits.max_file_bytes)?;
            let next_aggregate = aggregate_bytes.checked_add(bytes.len()).ok_or(
                LaneComplianceLoadError::AggregateBytesExceeded {
                    actual: usize::MAX,
                    maximum: limits.max_aggregate_bytes,
                },
            )?;
            if next_aggregate > limits.max_aggregate_bytes {
                return Err(LaneComplianceLoadError::AggregateBytesExceeded {
                    actual: next_aggregate,
                    maximum: limits.max_aggregate_bytes,
                });
            }
            aggregate_bytes = next_aggregate;
            let mut slice: &[u8] = &bytes;
            let decode_limits = lane_compliance_decode_limits(bytes.len(), limits);
            let policy = with_decode_limits(decode_limits, || {
                LaneCompliancePolicy::decode_all(&mut slice)
            })
            .map_err(|source| LaneComplianceLoadError::Decode {
                path: path.clone(),
                source,
            })?;
            insert_policy(&mut policies, policy, limits.max_files)?;
        }
        if policies.is_empty() {
            return Err(LaneComplianceLoadError::Empty(dir.to_path_buf()));
        }
        Ok(Self {
            policies,
            audit_only,
        })
    }
    /// Evaluate the policy if known for the given lane.
    #[must_use]
    pub fn evaluate(&self, ctx: &LaneComplianceContext<'_>) -> LaneComplianceEvaluation {
        let Some(policy) = self.policies.get(&ctx.lane_id) else {
            let mode = if self.audit_only {
                "audit_only_allow"
            } else {
                "enforced_deny"
            };
            warn!(
                lane = %ctx.lane_id.as_u32(),
                dataspace = %ctx.dataspace_id.as_u64(),
                authority = %ctx.authority,
                mode,
                "no exact lane compliance policy is configured"
            );
            return LaneComplianceEvaluation::NotConfigured;
        };
        if policy.dataspace_id != ctx.dataspace_id {
            return LaneComplianceEvaluation::Denied(LaneComplianceDecisionRecord::new(
                policy.id,
                ctx.lane_id,
                ctx.dataspace_id,
                ctx.authority.clone(),
                LaneComplianceDecision::Deny,
                Some("lane compliance policy dataspace mismatch".to_string()),
            ));
        }
        if let Some(rule) = Self::match_rule(&policy.deny, ctx) {
            return LaneComplianceEvaluation::Denied(LaneComplianceDecisionRecord::new(
                policy.id,
                ctx.lane_id,
                ctx.dataspace_id,
                ctx.authority.clone(),
                LaneComplianceDecision::Deny,
                rule.reason_code()
                    .map(str::to_string)
                    .or_else(|| Some("lane compliance deny rule matched".to_string())),
            ));
        }
        if policy.allow.is_empty() {
            return LaneComplianceEvaluation::Allowed(LaneComplianceDecisionRecord::new(
                policy.id,
                ctx.lane_id,
                ctx.dataspace_id,
                ctx.authority.clone(),
                LaneComplianceDecision::Allow,
                None,
            ));
        }
        if let Some(rule) = Self::match_rule(&policy.allow, ctx) {
            return LaneComplianceEvaluation::Allowed(LaneComplianceDecisionRecord::new(
                policy.id,
                ctx.lane_id,
                ctx.dataspace_id,
                ctx.authority.clone(),
                LaneComplianceDecision::Allow,
                rule.reason_code().map(str::to_string),
            ));
        }
        LaneComplianceEvaluation::Denied(LaneComplianceDecisionRecord::new(
            policy.id,
            ctx.lane_id,
            ctx.dataspace_id,
            ctx.authority.clone(),
            LaneComplianceDecision::Deny,
            Some("no lane compliance allow rule matched".to_string()),
        ))
    }
    fn match_rule<'a>(
        rules: &'a [LaneComplianceRule],
        ctx: &LaneComplianceContext<'_>,
    ) -> Option<&'a LaneComplianceRule> {
        rules
            .iter()
            .find(|rule| selector_matches(&rule.selector, ctx))
    }
    /// Whether the engine is running in audit-only mode.
    #[must_use]
    pub fn audit_only(&self) -> bool {
        self.audit_only
    }
    /// Return whether an exact policy is loaded for `lane_id`.
    #[must_use]
    pub fn has_policy(&self, lane_id: LaneId, dataspace_id: DataSpaceId) -> bool {
        self.policies
            .get(&lane_id)
            .is_some_and(|policy| policy.dataspace_id == dataspace_id)
    }
    /// Validate exact lane/dataspace policy coverage for every active lane.
    ///
    /// Policies for prospective lanes may remain pre-provisioned, but each currently active lane
    /// must have a policy whose dataspace matches the active catalog exactly.
    ///
    /// # Errors
    ///
    /// Returns [`LaneComplianceCoverageError`] when an active lane has no policy
    /// or its loaded policy targets a different dataspace.
    pub fn validate_active_catalog(
        &self,
        lane_catalog: &LaneCatalog,
    ) -> Result<(), LaneComplianceCoverageError> {
        for lane in lane_catalog.lanes() {
            let Some(policy) = self.policies.get(&lane.id) else {
                return Err(LaneComplianceCoverageError::MissingPolicy {
                    lane_id: lane.id,
                    dataspace_id: lane.dataspace_id,
                });
            };
            if policy.dataspace_id != lane.dataspace_id {
                return Err(LaneComplianceCoverageError::DataspaceMismatch {
                    lane_id: lane.id,
                    expected: lane.dataspace_id,
                    actual: policy.dataspace_id,
                });
            }
        }
        Ok(())
    }
    /// Compute a canonical digest of every loaded compliance policy.
    ///
    /// Policies are stored by lane identifier in a [`BTreeMap`], so their Norito preimage order is
    /// stable regardless of filesystem directory iteration order.
    #[must_use]
    pub fn consensus_policy_digest(&self) -> [u8; 32] {
        const DOMAIN: &[u8] = b"iroha:nexus:lane-compliance-policy-set:v1\0";
        let policies = self
            .policies
            .values()
            .map(|policy| policy.as_ref().clone())
            .collect::<Vec<_>>();
        let encoded = (1_u8, self.audit_only, policies).encode();
        Hash::new_from_chunks(&[DOMAIN, encoded.as_slice()]).into()
    }
}
fn insert_policy(
    policies: &mut BTreeMap<LaneId, Arc<LaneCompliancePolicy>>,
    policy: LaneCompliancePolicy,
    maximum: usize,
) -> Result<(), LaneComplianceLoadError> {
    let lane_id = policy.lane_id;
    if policies.contains_key(&lane_id) {
        return Err(LaneComplianceLoadError::DuplicateLane { lane_id });
    }
    if policies.len() >= maximum {
        return Err(LaneComplianceLoadError::PolicyCapacityExceeded {
            lane_id,
            actual: policies.len().saturating_add(1),
            maximum,
        });
    }
    policies.insert(lane_id, Arc::new(policy));
    Ok(())
}
fn lane_compliance_decode_limits(
    encoded_len: usize,
    limits: LaneComplianceLoadLimits,
) -> DecodeLimits {
    let encoded_element_budget = encoded_len.saturating_mul(8);
    let allocation_budget = encoded_len
        .saturating_mul(LANE_COMPLIANCE_POLICY_DECODE_ALLOCATION_MULTIPLIER)
        .saturating_add(LANE_COMPLIANCE_POLICY_DECODE_FIXED_ALLOCATION_BYTES)
        .min(limits.max_decode_allocated_bytes);
    DecodeLimits::new(
        limits.max_sequence_elements.min(encoded_element_budget),
        limits.max_field_bytes.min(encoded_len),
        limits.max_total_elements.min(encoded_element_budget),
        allocation_budget,
        limits.max_decode_depth,
    )
}
fn read_bounded_policy_file(
    path: &Path,
    maximum: usize,
) -> Result<Vec<u8>, LaneComplianceLoadError> {
    let before =
        secure_file_metadata::from_path(path).map_err(|source| LaneComplianceLoadError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if policy_metadata_is_symlink_or_reparse(&before) || !before.is_file() {
        return Err(LaneComplianceLoadError::NotRegularFile(path.to_path_buf()));
    }
    let maximum_u64 = u64::try_from(maximum).unwrap_or(u64::MAX);
    if before.len() > maximum_u64 {
        return Err(LaneComplianceLoadError::FileBytesExceeded {
            path: path.to_path_buf(),
            actual: before.len(),
            maximum,
        });
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits().cast_signed());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = options
        .open(path)
        .map_err(|source| LaneComplianceLoadError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let opened =
        secure_file_metadata::from_file(&file).map_err(|source| LaneComplianceLoadError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if policy_metadata_is_symlink_or_reparse(&opened) || !opened.is_file() {
        return Err(LaneComplianceLoadError::NotRegularFile(path.to_path_buf()));
    }
    if opened.len() > maximum_u64 {
        return Err(LaneComplianceLoadError::FileBytesExceeded {
            path: path.to_path_buf(),
            actual: opened.len(),
            maximum,
        });
    }
    if !policy_file_metadata_unchanged(&before, &opened) {
        return Err(LaneComplianceLoadError::Io {
            path: path.to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::InvalidData,
                "lane compliance policy identity changed while opening",
            ),
        });
    }
    let capacity = usize::try_from(opened.len())
        .unwrap_or(maximum)
        .min(maximum);
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take(maximum_u64.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| LaneComplianceLoadError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() > maximum {
        return Err(LaneComplianceLoadError::FileBytesExceeded {
            path: path.to_path_buf(),
            actual: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            maximum,
        });
    }
    let opened_after =
        secure_file_metadata::from_file(&file).map_err(|source| LaneComplianceLoadError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let path_after =
        secure_file_metadata::from_path(path).map_err(|source| LaneComplianceLoadError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if policy_metadata_is_symlink_or_reparse(&path_after)
        || !path_after.is_file()
        || !policy_file_metadata_unchanged(&opened, &opened_after)
        || !policy_file_metadata_unchanged(&opened, &path_after)
        || opened_after.len() != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
    {
        return Err(LaneComplianceLoadError::Io {
            path: path.to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::InvalidData,
                "lane compliance policy changed while reading",
            ),
        });
    }
    Ok(bytes)
}
fn policy_metadata_is_symlink_or_reparse(metadata: &SecureMetadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        return metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0;
    }
    #[cfg(not(windows))]
    false
}
#[cfg(unix)]
fn policy_file_metadata_unchanged(left: &SecureMetadata, right: &SecureMetadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}
#[cfg(windows)]
fn policy_file_metadata_unchanged(left: &SecureMetadata, right: &SecureMetadata) -> bool {
    let left_identity = (left.volume_serial_number(), left.file_index());
    left_identity.0.is_some()
        && left_identity.1.is_some()
        && left_identity == (right.volume_serial_number(), right.file_index())
        && left.file_size() == right.file_size()
        && left.last_write_time() == right.last_write_time()
        && left.creation_time() == right.creation_time()
}
#[cfg(not(any(unix, windows)))]
fn policy_file_metadata_unchanged(left: &SecureMetadata, right: &SecureMetadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}
fn selector_matches(selector: &ParticipantSelector, ctx: &LaneComplianceContext<'_>) -> bool {
    if let Some(account) = selector.account.as_ref()
        && account != ctx.authority
    {
        return false;
    }
    if let Some(domain) = selector.domain.as_ref()
        && !ctx
            .authority_domains
            .iter()
            .any(|current| current == domain)
    {
        return false;
    }
    if let Some(prefix) = selector.domain_prefix.as_deref()
        && !ctx
            .authority_domains
            .iter()
            .any(|current| current.to_string().starts_with(prefix))
    {
        return false;
    }
    if let Some(required_uaid) = selector.uaid.as_ref() {
        match ctx.uaid {
            Some(current) if current == required_uaid => {}
            _ => return false,
        }
    }
    if let Some(prefix) = selector.uaid_prefix.as_ref() {
        match ctx.uaid {
            Some(current)
                if current
                    .as_hash()
                    .as_ref()
                    .starts_with(prefix.as_hash().as_ref()) => {}
            _ => return false,
        }
    }
    if let Some(tag) = selector.capability_tag.as_deref() {
        if !ctx
            .capability_tags
            .iter()
            .any(|capability| capability == tag)
        {
            return false;
        }
    }
    if !selector.privacy_commitments_any_of.is_empty() {
        let has_verified = selector
            .privacy_commitments_any_of
            .iter()
            .any(|id| ctx.verified_privacy_commitments.contains(id));
        if !has_verified {
            return false;
        }
    }
    true
}
/// Metadata describing the evaluation context.
#[derive(Debug)]
pub struct LaneComplianceContext<'a> {
    /// Lane assigned to the transaction.
    pub lane_id: LaneId,
    /// Dataspace assigned to the transaction.
    pub dataspace_id: DataSpaceId,
    /// Transaction authority.
    pub authority: &'a AccountId,
    /// Dataspace-qualified account domains attached to the authority via aliases.
    pub authority_domains: &'a [DomainId],
    /// UAID derived for the authority (if known).
    pub uaid: Option<&'a UniversalAccountId>,
    /// Capability tags attached to the transaction or manifest.
    pub capability_tags: &'a [String],
    /// Snapshot of the privacy commitment registry, if available.
    pub lane_privacy_registry: Option<LanePrivacyRegistryHandle>,
    /// Commitments proven by attached lane privacy witnesses.
    pub verified_privacy_commitments: &'a BTreeSet<LaneCommitmentId>,
}
impl<'a> LaneComplianceContext<'a> {
    /// Convenience constructor for contexts without capability tags.
    #[must_use]
    pub fn new(lane_id: LaneId, dataspace_id: DataSpaceId, authority: &'a AccountId) -> Self {
        Self {
            lane_id,
            dataspace_id,
            authority,
            authority_domains: &[],
            uaid: None,
            capability_tags: &[],
            lane_privacy_registry: None,
            verified_privacy_commitments: &EMPTY_PRIVACY_COMMITMENTS,
        }
    }
}
/// Outcome of evaluating a transaction against a lane policy.
#[derive(Debug)]
pub enum LaneComplianceEvaluation {
    /// No policy configured for the lane.
    NotConfigured,
    /// Transaction satisfied the policy.
    Allowed(LaneComplianceDecisionRecord),
    /// Transaction violates the policy.
    Denied(LaneComplianceDecisionRecord),
}
impl LaneComplianceEvaluation {
    /// Access the decision record (if available).
    #[must_use]
    pub fn record(&self) -> Option<&LaneComplianceDecisionRecord> {
        match self {
            Self::Allowed(record) | Self::Denied(record) => Some(record),
            Self::NotConfigured => None,
        }
    }
}
/// Record describing a single decision.
#[derive(Debug, Clone)]
pub struct LaneComplianceDecisionRecord {
    /// Policy identifier evaluated.
    pub policy_id: LaneCompliancePolicyId,
    /// Lane identifier evaluated.
    pub lane_id: LaneId,
    /// Dataspace identifier evaluated.
    pub dataspace_id: DataSpaceId,
    /// Transaction authority.
    pub authority: AccountId,
    /// Decision outcome.
    pub decision: LaneComplianceDecision,
    /// Optional human-readable reason.
    pub reason: Option<String>,
}
impl LaneComplianceDecisionRecord {
    fn new(
        policy_id: LaneCompliancePolicyId,
        lane_id: LaneId,
        dataspace_id: DataSpaceId,
        authority: AccountId,
        decision: LaneComplianceDecision,
        reason: Option<String>,
    ) -> Self {
        Self {
            policy_id,
            lane_id,
            dataspace_id,
            authority,
            decision,
            reason,
        }
    }
}
/// Decision kind emitted by the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneComplianceDecision {
    /// Transaction allowed.
    Allow,
    /// Transaction denied.
    Deny,
}
/// Errors produced when loading lane compliance policies.
#[derive(Debug, thiserror::Error)]
pub enum LaneComplianceLoadError {
    /// Directory is missing.
    #[error("lane compliance policy directory {0:?} does not exist")]
    MissingDirectory(PathBuf),
    /// Path is not a directory.
    #[error("lane compliance policy path {0:?} is not a directory")]
    NotADirectory(PathBuf),
    /// Failed to enumerate entries in the directory.
    #[error("failed to read lane compliance directory {path:?}")]
    ReadDir {
        /// Directory that failed.
        path: PathBuf,
        /// Source error.
        #[source]
        source: std::io::Error,
    },
    /// I/O failure while reading a policy file.
    #[error("failed to read lane compliance policy {path:?}")]
    Io {
        /// Path that failed.
        path: PathBuf,
        /// Source error.
        #[source]
        source: std::io::Error,
    },
    /// Failed to decode a Norito policy bundle.
    #[error("failed to decode lane compliance policy {path:?}")]
    Decode {
        /// Path that failed.
        path: PathBuf,
        /// Source error.
        #[source]
        source: norito::codec::Error,
    },
    /// Directory contained more candidate files than active lanes can exist.
    #[error(
        "lane compliance directory contains at least {actual} policy files, exceeding the protocol maximum {maximum}"
    )]
    FileCountExceeded {
        /// First observed file count beyond the limit.
        actual: usize,
        /// Consensus-wide maximum active lane count.
        maximum: usize,
    },
    /// A policy path did not resolve to a direct regular file.
    #[error("lane compliance policy path {0:?} is not a direct regular file")]
    NotRegularFile(PathBuf),
    /// One policy file exceeded its byte ceiling.
    #[error(
        "lane compliance policy {path:?} has {actual} bytes, exceeding the per-file maximum {maximum}"
    )]
    FileBytesExceeded {
        /// Oversized policy path.
        path: PathBuf,
        /// Observed file or bounded-read length.
        actual: u64,
        /// Maximum accepted bytes for one policy file.
        maximum: usize,
    },
    /// Cumulative policy bytes exceeded the startup ingestion budget.
    #[error(
        "lane compliance policy files contain {actual} aggregate bytes, exceeding the maximum {maximum}"
    )]
    AggregateBytesExceeded {
        /// Cumulative bytes including the file that crossed the limit.
        actual: usize,
        /// Maximum cumulative policy bytes.
        maximum: usize,
    },
    /// Duplicate lane identifier detected.
    #[error("duplicate lane compliance policy for lane {lane_id}")]
    DuplicateLane {
        /// Lane identifier.
        lane_id: LaneId,
    },
    /// Unique policies exceeded the protocol active-lane count.
    #[error(
        "lane compliance policy for lane {lane_id} would raise the policy count to {actual}, exceeding the protocol maximum {maximum}"
    )]
    PolicyCapacityExceeded {
        /// Prospective lane whose insertion crossed the count bound.
        lane_id: LaneId,
        /// Policy count after the rejected insertion.
        actual: usize,
        /// Consensus-wide maximum active lane count.
        maximum: usize,
    },
    /// Directory contained no policies.
    #[error("lane compliance directory {0:?} does not contain any policies")]
    Empty(PathBuf),
}
/// Active-catalog compliance coverage failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LaneComplianceCoverageError {
    /// No policy exists for an active lane.
    #[error("active lane {lane_id} in dataspace {dataspace_id} has no compliance policy")]
    MissingPolicy {
        /// Active lane without a policy.
        lane_id: LaneId,
        /// Dataspace required by the active catalog.
        dataspace_id: DataSpaceId,
    },
    /// The loaded policy targets a different dataspace than the active lane.
    #[error(
        "active lane {lane_id} requires compliance dataspace {expected}, but the loaded policy targets {actual}"
    )]
    DataspaceMismatch {
        /// Active lane with mismatched policy binding.
        lane_id: LaneId,
        /// Dataspace required by the active catalog.
        expected: DataSpaceId,
        /// Dataspace encoded in the loaded policy.
        actual: DataSpaceId,
    },
}
impl LaneComplianceDecisionRecord {
    /// Helper for logging evaluation summaries.
    pub fn log(&self, audit_only: bool) {
        let mode = if audit_only { "audit_only" } else { "enforced" };
        match self.decision {
            LaneComplianceDecision::Allow => {
                if let Some(reason) = &self.reason {
                    warn!(
                        lane = %self.lane_id.as_u32(),
                        dataspace = %self.dataspace_id.as_u64(),
                        mode,
                        authority = %self.authority,
                        reason,
                        policy = ?self.policy_id.as_hash(),
                        "lane compliance allow decision recorded",
                    );
                }
            }
            LaneComplianceDecision::Deny => {
                warn!(
                    lane = %self.lane_id.as_u32(),
                    dataspace = %self.dataspace_id.as_u64(),
                    mode,
                    authority = %self.authority,
                    reason = %self.reason.as_deref().unwrap_or("lane compliance deny rule"),
                    policy = ?self.policy_id.as_hash(),
                    "lane compliance deny decision recorded",
                );
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{governance::manifest::LaneManifestStatus, interlane::LanePrivacyRegistry};
    use iroha_crypto::{
        Algorithm, Hash, KeyPair,
        privacy::{LaneCommitmentId, LanePrivacyCommitment, MerkleCommitment},
    };
    use iroha_data_model::{
        account::AccountId,
        nexus::{AuditControls, JurisdictionSet, LaneStorageProfile, LaneVisibility},
    };
    use iroha_model_base::metadata::Metadata;
    use iroha_model_base::topology::DataSpaceId;
    use std::{collections::BTreeSet, fs, path::PathBuf};
    fn account(name: &str, domain: &str) -> AccountId {
        let seed_literal = format!("{name}::{domain}");
        let mut seed = seed_literal.into_bytes();
        if seed.is_empty() {
            seed.extend_from_slice(b"lane-compliance-account");
        }
        let keypair = KeyPair::try_from_seed(seed, Algorithm::Ed25519)
            .expect("fixture seed must derive a valid keypair");
        AccountId::new(keypair.public_key().clone())
    }
    #[test]
    fn account_fixture_uses_checked_seed_derivation() {
        assert_ne!(account("alice", "wonderland"), account("bob", "wonderland"));
        assert!(
            KeyPair::try_from_seed(vec![0; 32], Algorithm::Ed25519).is_err(),
            "checked Ed25519 seed derivation must reject weak all-zero fixture seeds"
        );
    }
    #[test]
    fn consensus_policy_digest_binds_loaded_policy_content() {
        let alice = account("alice", "wonderland");
        let bob = account("bob", "wonderland");
        let left = LaneComplianceEngine::from_policies(
            vec![sample_policy(
                LaneId::SINGLE,
                std::slice::from_ref(&alice),
                &[],
            )],
            false,
        )
        .expect("left policy engine");
        let right = LaneComplianceEngine::from_policies(
            vec![sample_policy(
                LaneId::SINGLE,
                std::slice::from_ref(&bob),
                &[],
            )],
            false,
        )
        .expect("right policy engine");
        assert_ne!(
            left.consensus_policy_digest(),
            right.consensus_policy_digest()
        );
    }
    fn sample_policy(
        lane_id: LaneId,
        allow: &[AccountId],
        deny: &[AccountId],
    ) -> LaneCompliancePolicy {
        let mut hash_bytes = [0u8; 32];
        hash_bytes[..4].copy_from_slice(&lane_id.as_u32().to_le_bytes());
        LaneCompliancePolicy {
            id: LaneCompliancePolicyId::new(Hash::prehashed(hash_bytes)),
            version: 1,
            lane_id,
            dataspace_id: DataSpaceId::UNIVERSAL,
            jurisdiction: JurisdictionSet::default(),
            deny: deny
                .iter()
                .cloned()
                .map(|account| LaneComplianceRule {
                    selector: ParticipantSelector {
                        account: Some(account),
                        ..ParticipantSelector::default()
                    },
                    reason_code: Some("deny".to_string()),
                    jurisdiction_override: JurisdictionSet::default(),
                })
                .collect(),
            allow: allow
                .iter()
                .cloned()
                .map(|account| LaneComplianceRule {
                    selector: ParticipantSelector {
                        account: Some(account),
                        ..ParticipantSelector::default()
                    },
                    reason_code: Some("allow".to_string()),
                    jurisdiction_override: JurisdictionSet::default(),
                })
                .collect(),
            transfer_limits: Vec::new(),
            audit_controls: AuditControls::default(),
            metadata: Metadata::default(),
        }
    }
    fn test_load_limits(
        max_files: usize,
        max_file_bytes: usize,
        max_aggregate_bytes: usize,
    ) -> LaneComplianceLoadLimits {
        LaneComplianceLoadLimits {
            max_files,
            max_file_bytes,
            max_aggregate_bytes,
            ..LANE_COMPLIANCE_LOAD_LIMITS
        }
    }
    fn write_policy(dir: &Path, name: &str, policy: &LaneCompliancePolicy) -> Vec<u8> {
        let bytes = policy.encode();
        fs::write(dir.join(name), &bytes).expect("write compliance policy");
        bytes
    }
    #[test]
    fn directory_loader_retains_canonical_lane_order() {
        let directory = tempfile::tempdir().expect("policy directory");
        let high = sample_policy(LaneId::new(9), &[], &[]);
        let low = sample_policy(LaneId::new(1), &[], &[]);
        write_policy(directory.path(), "a-high.norito", &high);
        write_policy(directory.path(), "z-low.norito", &low);
        let loaded = LaneComplianceEngine::from_directory(directory.path(), false)
            .expect("directory policies");
        let explicit =
            LaneComplianceEngine::from_policies(vec![high, low], false).expect("explicit policies");
        assert_eq!(
            loaded.policies.keys().copied().collect::<Vec<_>>(),
            vec![LaneId::new(1), LaneId::new(9)]
        );
        assert_eq!(
            loaded.consensus_policy_digest(),
            explicit.consensus_policy_digest(),
            "directory enumeration order must not affect the canonical digest"
        );
    }
    #[test]
    fn directory_loader_enforces_per_file_and_aggregate_byte_boundaries() {
        let directory = tempfile::tempdir().expect("policy directory");
        let first = write_policy(
            directory.path(),
            "lane-0.norito",
            &sample_policy(LaneId::SINGLE, &[], &[]),
        );
        let second = write_policy(
            directory.path(),
            "lane-1.norito",
            &sample_policy(LaneId::new(1), &[], &[]),
        );
        let maximum_file = first.len().max(second.len());
        let aggregate = first
            .len()
            .checked_add(second.len())
            .expect("small fixtures");
        let engine = LaneComplianceEngine::from_directory_with_limits(
            directory.path(),
            false,
            test_load_limits(2, maximum_file, aggregate),
        )
        .expect("exact byte boundaries must load");
        assert_eq!(engine.policies.len(), 2);
        let file_error = LaneComplianceEngine::from_directory_with_limits(
            directory.path(),
            false,
            test_load_limits(2, maximum_file.saturating_sub(1), aggregate),
        )
        .expect_err("per-file limit minus one must fail");
        assert!(matches!(
            file_error,
            LaneComplianceLoadError::FileBytesExceeded { maximum, .. }
                if maximum == maximum_file.saturating_sub(1)
        ));
        let aggregate_error = LaneComplianceEngine::from_directory_with_limits(
            directory.path(),
            false,
            test_load_limits(2, maximum_file, aggregate.saturating_sub(1)),
        )
        .expect_err("aggregate limit minus one must fail before second decode");
        assert!(matches!(
            aggregate_error,
            LaneComplianceLoadError::AggregateBytesExceeded { actual, maximum }
                if actual == aggregate && maximum == aggregate.saturating_sub(1)
        ));
    }
    #[test]
    fn directory_loader_caps_candidate_files_before_reading_overflow() {
        let directory = tempfile::tempdir().expect("policy directory");
        for lane in 0..3_u32 {
            write_policy(
                directory.path(),
                &format!("lane-{lane}.norito"),
                &sample_policy(LaneId::new(lane), &[], &[]),
            );
        }
        let error = LaneComplianceEngine::from_directory_with_limits(
            directory.path(),
            false,
            test_load_limits(2, LANE_COMPLIANCE_POLICY_MAX_BYTES, usize::MAX),
        )
        .expect_err("third candidate must cross the file bound");
        assert!(matches!(
            error,
            LaneComplianceLoadError::FileCountExceeded {
                actual: 3,
                maximum: 2
            }
        ));
        assert_eq!(
            LANE_COMPLIANCE_LOAD_LIMITS.max_files, MAX_ACTIVE_EXECUTION_LANES,
            "production file capacity must follow the protocol active-lane bound"
        );
    }
    #[test]
    fn directory_loader_rejects_duplicate_lane_before_retention() {
        let directory = tempfile::tempdir().expect("policy directory");
        let policy = sample_policy(LaneId::new(77), &[], &[]);
        let bytes = write_policy(directory.path(), "first.norito", &policy);
        write_policy(directory.path(), "second.norito", &policy);
        let error = LaneComplianceEngine::from_directory_with_limits(
            directory.path(),
            false,
            test_load_limits(2, bytes.len(), bytes.len().saturating_mul(2)),
        )
        .expect_err("duplicate lane must fail");
        assert!(matches!(
            error,
            LaneComplianceLoadError::DuplicateLane { lane_id }
                if lane_id == LaneId::new(77)
        ));
    }
    #[test]
    fn policy_count_bound_preserves_sparse_prospective_lane_ids() {
        let sparse = LaneId::new(u32::MAX);
        let engine =
            LaneComplianceEngine::from_policies(vec![sample_policy(sparse, &[], &[])], false)
                .expect("sparse prospective lane ids remain admissible");
        assert!(engine.policies.contains_key(&sparse));
        let mut policies = BTreeMap::new();
        insert_policy(&mut policies, sample_policy(LaneId::new(1), &[], &[]), 2)
            .expect("first policy");
        insert_policy(&mut policies, sample_policy(LaneId::new(2), &[], &[]), 2)
            .expect("second policy");
        let error = insert_policy(&mut policies, sample_policy(LaneId::new(3), &[], &[]), 2)
            .expect_err("third unique policy must cross count bound");
        assert!(matches!(
            error,
            LaneComplianceLoadError::PolicyCapacityExceeded {
                lane_id,
                actual: 3,
                maximum: 2
            } if lane_id == LaneId::new(3)
        ));
        assert_eq!(policies.len(), 2, "overflow policy must not be retained");
    }
    #[test]
    fn directory_loader_applies_norito_resource_limits_before_retention() {
        let directory = tempfile::tempdir().expect("policy directory");
        let alpha = account("alice", "wonderland");
        let beta = account("bob", "wonderland");
        let bytes = write_policy(
            directory.path(),
            "lane.norito",
            &sample_policy(LaneId::SINGLE, &[alpha, beta], &[]),
        );
        let mut limits = test_load_limits(1, bytes.len(), bytes.len());
        limits.max_sequence_elements = 1;
        let error =
            LaneComplianceEngine::from_directory_with_limits(directory.path(), false, limits)
                .expect_err("two-rule policy must exceed one-element decode limit");
        assert!(matches!(error, LaneComplianceLoadError::Decode { .. }));
    }
    #[test]
    fn directory_loader_rejects_oversized_string_field_before_allocation() {
        let directory = tempfile::tempdir().expect("policy directory");
        let mut policy = sample_policy(LaneId::SINGLE, &[], &[]);
        policy.allow.push(LaneComplianceRule {
            selector: ParticipantSelector::default(),
            reason_code: Some("x".repeat(LANE_COMPLIANCE_POLICY_MAX_FIELD_BYTES + 1)),
            jurisdiction_override: JurisdictionSet::default(),
        });
        let bytes = write_policy(directory.path(), "lane.norito", &policy);
        assert!(
            bytes.len() <= LANE_COMPLIANCE_POLICY_MAX_BYTES,
            "fixture must reach the field bound before the file bound"
        );
        let error = LaneComplianceEngine::from_directory(directory.path(), false)
            .expect_err("oversized string field must fail under the Norito field budget");
        assert!(matches!(error, LaneComplianceLoadError::Decode { .. }));
    }
    #[cfg(unix)]
    #[test]
    fn directory_loader_rejects_symlinked_policy_without_following() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().expect("policy directory");
        let target = tempfile::NamedTempFile::new().expect("policy target");
        fs::write(
            target.path(),
            sample_policy(LaneId::SINGLE, &[], &[]).encode(),
        )
        .expect("write policy target");
        let link = directory.path().join("lane.norito");
        symlink(target.path(), &link).expect("create policy symlink");
        let error = LaneComplianceEngine::from_directory(directory.path(), false)
            .expect_err("symlinked policy must fail closed");
        assert!(matches!(
            error,
            LaneComplianceLoadError::NotRegularFile(path) if path == link
        ));
    }
    #[test]
    fn allow_rule_matches() {
        let alpha = account("alice", "wonderland");
        let beta = account("bob", "wonderland");
        let policy = sample_policy(
            LaneId::SINGLE,
            std::slice::from_ref(&alpha),
            std::slice::from_ref(&beta),
        );
        let engine = LaneComplianceEngine::from_policies(vec![policy], false).expect("engine");
        let ctx = LaneComplianceContext {
            lane_id: LaneId::SINGLE,
            dataspace_id: DataSpaceId::UNIVERSAL,
            authority: &alpha,
            authority_domains: &[],
            uaid: None,
            capability_tags: &[],
            lane_privacy_registry: None,
            verified_privacy_commitments: &EMPTY_PRIVACY_COMMITMENTS,
        };
        let evaluation = engine.evaluate(&ctx);
        matches!(evaluation, LaneComplianceEvaluation::Allowed(_))
            .then_some(())
            .expect("allowed");
        let ctx_beta = LaneComplianceContext {
            lane_id: LaneId::SINGLE,
            dataspace_id: DataSpaceId::UNIVERSAL,
            authority: &beta,
            authority_domains: &[],
            uaid: None,
            capability_tags: &[],
            lane_privacy_registry: None,
            verified_privacy_commitments: &EMPTY_PRIVACY_COMMITMENTS,
        };
        let evaluation = engine.evaluate(&ctx_beta);
        matches!(evaluation, LaneComplianceEvaluation::Denied(_))
            .then_some(())
            .expect("denied");
    }
    #[test]
    fn duplicate_lane_rejected() {
        let alpha = account("alice", "wonderland");
        let policy = sample_policy(LaneId::SINGLE, std::slice::from_ref(&alpha), &[]);
        let duplicate = sample_policy(LaneId::SINGLE, &[alpha], &[]);
        let err = LaneComplianceEngine::from_policies(vec![policy, duplicate], false)
            .expect_err("duplicate lane must fail");
        assert!(matches!(
            err,
            LaneComplianceLoadError::DuplicateLane { lane_id } if lane_id == LaneId::SINGLE
        ));
    }
    #[test]
    fn active_catalog_coverage_rejects_missing_and_mismatched_policies() {
        let lane_one = LaneId::new(1);
        let dataspace_one = DataSpaceId::new(7);
        let catalog = iroha_data_model::nexus::LaneCatalog::new(
            nonzero_ext::nonzero!(2_u32),
            vec![
                iroha_data_model::nexus::LaneConfig::default(),
                iroha_data_model::nexus::LaneConfig {
                    id: lane_one,
                    dataspace_id: dataspace_one,
                    alias: "regulated".to_owned(),
                    ..iroha_data_model::nexus::LaneConfig::default()
                },
            ],
        )
        .expect("active lane catalog");
        let default_policy = sample_policy(LaneId::SINGLE, &[], &[]);
        let missing = LaneComplianceEngine::from_policies(vec![default_policy.clone()], false)
            .expect("missing engine");
        assert_eq!(
            missing
                .validate_active_catalog(&catalog)
                .expect_err("active lane without policy must fail"),
            LaneComplianceCoverageError::MissingPolicy {
                lane_id: lane_one,
                dataspace_id: dataspace_one,
            }
        );
        let mismatched_policy = LaneCompliancePolicy {
            lane_id: lane_one,
            dataspace_id: DataSpaceId::new(8),
            ..sample_policy(lane_one, &[], &[])
        };
        let mismatched =
            LaneComplianceEngine::from_policies(vec![default_policy, mismatched_policy], false)
                .expect("mismatched engine");
        assert_eq!(
            mismatched
                .validate_active_catalog(&catalog)
                .expect_err("dataspace mismatch must fail"),
            LaneComplianceCoverageError::DataspaceMismatch {
                lane_id: lane_one,
                expected: dataspace_one,
                actual: DataSpaceId::new(8),
            }
        );
    }
    #[test]
    fn not_configured_evaluation_preserves_enforcement_mode() {
        let authority = account("alice", "wonderland");
        let ctx = LaneComplianceContext::new(LaneId::new(9), DataSpaceId::UNIVERSAL, &authority);
        let enforced = LaneComplianceEngine::from_policies(
            vec![sample_policy(LaneId::SINGLE, &[], &[])],
            false,
        )
        .expect("enforced engine");
        let audit = LaneComplianceEngine::from_policies(
            vec![sample_policy(LaneId::SINGLE, &[], &[])],
            true,
        )
        .expect("audit engine");
        assert!(matches!(
            enforced.evaluate(&ctx),
            LaneComplianceEvaluation::NotConfigured
        ));
        assert!(!enforced.audit_only());
        assert!(matches!(
            audit.evaluate(&ctx),
            LaneComplianceEvaluation::NotConfigured
        ));
        assert!(audit.audit_only());
    }
    #[test]
    fn selector_requires_privacy_commitment() {
        let alpha = account("alice", "wonderland");
        let policy = LaneCompliancePolicy {
            allow: vec![LaneComplianceRule {
                selector: ParticipantSelector {
                    account: Some(alpha.clone()),
                    privacy_commitments_any_of: vec![LaneCommitmentId::new(7)],
                    ..ParticipantSelector::default()
                },
                reason_code: Some("allow".to_string()),
                jurisdiction_override: JurisdictionSet::default(),
            }],
            deny: Vec::new(),
            ..sample_policy(LaneId::SINGLE, &[], &[])
        };
        let engine = LaneComplianceEngine::from_policies(vec![policy], false).expect("engine");
        let statuses = vec![LaneManifestStatus {
            lane: LaneId::SINGLE,
            alias: "confidential".to_string(),
            dataspace: DataSpaceId::UNIVERSAL,
            visibility: LaneVisibility::Public,
            storage: LaneStorageProfile::CommitmentOnly,
            governance: None,
            manifest_path: Some(PathBuf::from("/tmp/privacy.json")),
            governance_rules: None,
            privacy_commitments: vec![LanePrivacyCommitment::merkle(
                LaneCommitmentId::new(7),
                MerkleCommitment::from_root_bytes([0xAA; 32], 8),
            )],
        }];
        let registry = LanePrivacyRegistry::from_statuses(&statuses);
        let ctx = LaneComplianceContext {
            lane_id: LaneId::SINGLE,
            dataspace_id: DataSpaceId::UNIVERSAL,
            authority: &alpha,
            authority_domains: &[],
            uaid: None,
            capability_tags: &[],
            lane_privacy_registry: Some(Arc::new(registry)),
            verified_privacy_commitments: &EMPTY_PRIVACY_COMMITMENTS,
        };
        let mut verified = BTreeSet::new();
        verified.insert(LaneCommitmentId::new(7));
        let ctx_with_proof = LaneComplianceContext {
            verified_privacy_commitments: &verified,
            ..ctx
        };
        assert!(matches!(
            engine.evaluate(&ctx_with_proof),
            LaneComplianceEvaluation::Allowed(_)
        ));
        let empty_verified = BTreeSet::new();
        let ctx_missing_proof = LaneComplianceContext {
            verified_privacy_commitments: &empty_verified,
            ..ctx_with_proof
        };
        assert!(matches!(
            engine.evaluate(&ctx_missing_proof),
            LaneComplianceEvaluation::Denied(_)
        ));
    }
    #[test]
    fn selector_matches_capability_tag() {
        let alpha = account("alice", "wonderland");
        let policy = LaneCompliancePolicy {
            allow: vec![LaneComplianceRule {
                selector: ParticipantSelector {
                    account: Some(alpha.clone()),
                    capability_tag: Some("fx-cleared".to_string()),
                    ..ParticipantSelector::default()
                },
                reason_code: Some("allow".to_string()),
                jurisdiction_override: JurisdictionSet::default(),
            }],
            deny: Vec::new(),
            ..sample_policy(LaneId::SINGLE, &[], &[])
        };
        let engine = LaneComplianceEngine::from_policies(vec![policy], false).expect("engine");
        let ctx_missing_tag = LaneComplianceContext {
            lane_id: LaneId::SINGLE,
            dataspace_id: DataSpaceId::UNIVERSAL,
            authority: &alpha,
            authority_domains: &[],
            uaid: None,
            capability_tags: &[],
            lane_privacy_registry: None,
            verified_privacy_commitments: &EMPTY_PRIVACY_COMMITMENTS,
        };
        assert!(matches!(
            engine.evaluate(&ctx_missing_tag),
            LaneComplianceEvaluation::Denied(_)
        ));
        let tags = vec!["fx-cleared".to_string()];
        let ctx_with_tag = LaneComplianceContext {
            capability_tags: &tags,
            ..ctx_missing_tag
        };
        assert!(matches!(
            engine.evaluate(&ctx_with_tag),
            LaneComplianceEvaluation::Allowed(_)
        ));
    }
    #[test]
    fn selector_matches_authority_domain() {
        let alpha = account("alice", "wonderland");
        let retail_domain =
            iroha_model_base::domain::DomainId::try_new("hbl", "paynet").expect("domain id");
        let other_domain =
            iroha_model_base::domain::DomainId::try_new("ubl", "paynet").expect("domain id");
        let policy = LaneCompliancePolicy {
            allow: vec![LaneComplianceRule {
                selector: ParticipantSelector {
                    domain: Some(retail_domain.clone()),
                    ..ParticipantSelector::default()
                },
                reason_code: Some("fi domain allowed".to_string()),
                jurisdiction_override: JurisdictionSet::default(),
            }],
            deny: Vec::new(),
            ..sample_policy(LaneId::SINGLE, &[], &[])
        };
        let engine = LaneComplianceEngine::from_policies(vec![policy], false).expect("engine");
        let matched_domains = vec![retail_domain];
        let matched_ctx = LaneComplianceContext {
            lane_id: LaneId::SINGLE,
            dataspace_id: DataSpaceId::UNIVERSAL,
            authority: &alpha,
            authority_domains: &matched_domains,
            uaid: None,
            capability_tags: &[],
            lane_privacy_registry: None,
            verified_privacy_commitments: &EMPTY_PRIVACY_COMMITMENTS,
        };
        assert!(matches!(
            engine.evaluate(&matched_ctx),
            LaneComplianceEvaluation::Allowed(_)
        ));
        let mismatched_domains = vec![other_domain];
        let mismatched_ctx = LaneComplianceContext {
            authority_domains: &mismatched_domains,
            ..matched_ctx
        };
        assert!(matches!(
            engine.evaluate(&mismatched_ctx),
            LaneComplianceEvaluation::Denied(_)
        ));
    }
    #[test]
    fn selector_matches_authority_domain_prefix() {
        let alpha = account("alice", "wonderland");
        let retail_domain =
            iroha_model_base::domain::DomainId::try_new("hbl", "paynet").expect("domain id");
        let policy = LaneCompliancePolicy {
            allow: vec![LaneComplianceRule {
                selector: ParticipantSelector {
                    domain_prefix: Some("hbl.".to_string()),
                    ..ParticipantSelector::default()
                },
                reason_code: Some("fi prefix allowed".to_string()),
                jurisdiction_override: JurisdictionSet::default(),
            }],
            deny: Vec::new(),
            ..sample_policy(LaneId::SINGLE, &[], &[])
        };
        let engine = LaneComplianceEngine::from_policies(vec![policy], false).expect("engine");
        let authority_domains = vec![retail_domain];
        let ctx = LaneComplianceContext {
            lane_id: LaneId::SINGLE,
            dataspace_id: DataSpaceId::UNIVERSAL,
            authority: &alpha,
            authority_domains: &authority_domains,
            uaid: None,
            capability_tags: &[],
            lane_privacy_registry: None,
            verified_privacy_commitments: &EMPTY_PRIVACY_COMMITMENTS,
        };
        assert!(matches!(
            engine.evaluate(&ctx),
            LaneComplianceEvaluation::Allowed(_)
        ));
    }
}
