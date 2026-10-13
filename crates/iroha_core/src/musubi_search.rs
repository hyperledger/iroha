//! Rebuildable finalized-event projection for Musubi package discovery.
//!
//! This index is deliberately process-local and absent from [`crate::state::World`].
//! Consensus resolution continues to use the universal sparse resolver index; this
//! projection serves only description, keyword, namespace, and package-name search.
use iroha_data_model::{
    events::data::musubi::MusubiEvent,
    musubi::{
        MUSUBI_MAX_PAGE_SIZE_V1, MUSUBI_MAX_SEARCH_TERM_BYTES_V1, MusubiPackageIdV1,
        MusubiPackageMetadataRecordV1, MusubiPackageRecordV1, MusubiQueryHashV1,
        MusubiReleaseMetadataV1, MusubiSearchCursorV1, MusubiSearchHitV1, MusubiSearchPageV1,
        MusubiSearchQueryV1, MusubiSearchSnapshotV1,
    },
};
use norito::codec::Encode as _;
use std::{
    borrow::Borrow,
    collections::{BTreeMap, BTreeSet},
    fmt,
    ops::Bound::{Excluded, Unbounded},
};
/// Maximum document terms retained after deterministic priority ordering.
pub const MUSUBI_SEARCH_MAX_DOCUMENT_TERMS_V1: usize = 256;
/// Maximum candidate package rows inspected for a multi-term page.
pub const MUSUBI_SEARCH_MAX_CANDIDATE_SCAN_V1: usize = 16_384;
const MUSUBI_SEARCH_QUERY_HASH_DOMAIN_V1: &[u8] = b"iroha.musubi.search-query.v1";
/// Failure while rebuilding or querying the non-consensus search projection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MusubiSearchError {
    /// A finalized event contradicts an earlier event in the same replay.
    InconsistentFinalizedEvent,
    /// The query is empty or exceeds its byte/term bound.
    InvalidQuery,
    /// The requested result page is empty or exceeds its bound.
    InvalidPageSize,
    /// A sparse multi-term intersection exceeded its deterministic scan budget.
    QueryTooBroad,
    /// A supplied search cursor no longer binds the exact projection and query.
    StaleCursor,
    /// No finalized search projection is available yet.
    ProjectionUnavailable,
    /// The process-local projection revision overflowed.
    RevisionOverflow,
}
impl fmt::Display for MusubiSearchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InconsistentFinalizedEvent => {
                "Musubi finalized search event contradicts the rebuilt projection"
            }
            Self::InvalidQuery => "Musubi search query is empty or exceeds its V1 bounds",
            Self::InvalidPageSize => "Musubi search page size is outside its V1 bounds",
            Self::QueryTooBroad => "Musubi search query exceeds its bounded candidate scan",
            Self::StaleCursor => "Musubi search cursor is stale",
            Self::ProjectionUnavailable => "Musubi finalized search projection is unavailable",
            Self::RevisionOverflow => "Musubi search projection revision overflowed",
        })
    }
}
impl std::error::Error for MusubiSearchError {}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct MusubiSearchDocument {
    claimed_namespace: Option<iroha_data_model::musubi::MusubiNamespaceV1>,
    metadata: MusubiReleaseMetadataV1,
    metadata_revision: u64,
    terms: BTreeSet<String>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct MusubiSearchSliceV1 {
    hits: Vec<MusubiSearchHitV1>,
    next_after: Option<MusubiPackageIdV1>,
}
/// Process-local rich-search state rebuildable solely from finalized Musubi events.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MusubiSearchProjectionV1 {
    documents: BTreeMap<MusubiPackageIdV1, MusubiSearchDocument>,
    postings: BTreeMap<String, BTreeSet<MusubiPackageIdV1>>,
}
/// Anchored process-local search index updated only from finalized Musubi events.
///
/// The index and its revision are operator-local discovery state. Dependency resolution cannot
/// access this type and continues to use the universal sparse resolver index exclusively.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MusubiSearchIndexV1 {
    projection: MusubiSearchProjectionV1,
    snapshot: Option<MusubiSearchSnapshotV1>,
}
impl MusubiSearchProjectionV1 {
    /// Rebuild a fresh projection from a canonically ordered finalized event stream.
    ///
    /// # Errors
    /// Returns `InconsistentFinalizedEvent` when an event conflicts with an earlier
    /// namespace claim or metadata revision, or carries invalid metadata.
    pub fn rebuild<I>(events: I) -> Result<Self, MusubiSearchError>
    where
        I: IntoIterator,
        I::Item: Borrow<MusubiEvent>,
    {
        let mut projection = Self::default();
        for event in events {
            projection.apply_finalized(event.borrow())?;
        }
        Ok(projection)
    }
    /// Rebuild from a consistent finalized package/metadata state snapshot.
    ///
    /// This is the bounded recovery path used after process restart or event-stream
    /// lag. Steady-state updates use [`Self::apply_finalized`] and never rescan the
    /// authoritative package directory.
    ///
    /// # Errors
    /// Returns `InconsistentFinalizedEvent` for invalid package/metadata records,
    /// metadata without a package, duplicate metadata, or a package without metadata.
    pub fn rebuild_records<P, M>(packages: P, metadata: M) -> Result<Self, MusubiSearchError>
    where
        P: IntoIterator,
        P::Item: Borrow<MusubiPackageRecordV1>,
        M: IntoIterator,
        M::Item: Borrow<MusubiPackageMetadataRecordV1>,
    {
        let mut projection = Self::default();
        for package in packages {
            let package = package.borrow();
            package
                .validate()
                .map_err(|_| MusubiSearchError::InconsistentFinalizedEvent)?;
            let document = projection
                .documents
                .entry(package.package.clone())
                .or_default();
            document.claimed_namespace = Some(package.claimed_namespace.clone());
        }
        for metadata in metadata {
            let metadata = metadata.borrow();
            metadata
                .validate()
                .map_err(|_| MusubiSearchError::InconsistentFinalizedEvent)?;
            let Some(document) = projection.documents.get_mut(&metadata.package) else {
                return Err(MusubiSearchError::InconsistentFinalizedEvent);
            };
            if document.metadata_revision != 0 {
                return Err(MusubiSearchError::InconsistentFinalizedEvent);
            }
            document.metadata = metadata.metadata.clone();
            document.metadata_revision = metadata.revision;
        }
        if projection
            .documents
            .values()
            .any(|document| document.metadata_revision == 0)
        {
            return Err(MusubiSearchError::InconsistentFinalizedEvent);
        }
        let packages = projection.documents.keys().cloned().collect::<Vec<_>>();
        for package in packages {
            let document = projection
                .documents
                .get_mut(&package)
                .expect("collected Musubi search document exists");
            document.terms = document_terms(&package, document);
            projection.insert_postings(&package);
        }
        Ok(projection)
    }
    /// Apply one event after its containing block is finalized.
    ///
    /// Events unrelated to rich package discovery are intentionally ignored. Exact
    /// dependency resolution must never read this projection.
    ///
    /// # Errors
    /// Returns `InconsistentFinalizedEvent` for conflicting namespace claims, invalid
    /// metadata, a regressing revision, or different metadata at the same revision.
    pub fn apply_finalized(&mut self, event: &MusubiEvent) -> Result<(), MusubiSearchError> {
        self.apply_finalized_changed(event).map(|_| ())
    }
    fn apply_finalized_changed(&mut self, event: &MusubiEvent) -> Result<bool, MusubiSearchError> {
        match event {
            MusubiEvent::PackageClaimed(event) => {
                if let Some(existing) = self.documents.get(&event.package)
                    && existing
                        .claimed_namespace
                        .as_ref()
                        .is_some_and(|namespace| namespace != &event.namespace)
                {
                    return Err(MusubiSearchError::InconsistentFinalizedEvent);
                }
                if self
                    .documents
                    .get(&event.package)
                    .and_then(|document| document.claimed_namespace.as_ref())
                    == Some(&event.namespace)
                {
                    return Ok(false);
                }
                let package = event.package.clone();
                self.remove_postings(&package);
                let document = self.documents.entry(package.clone()).or_default();
                document.claimed_namespace = Some(event.namespace.clone());
                document.terms = document_terms(&package, document);
                self.insert_postings(&package);
                Ok(true)
            }
            MusubiEvent::PackageMetadataChanged(event) => {
                event
                    .validate()
                    .map_err(|_| MusubiSearchError::InconsistentFinalizedEvent)?;
                let package = event.package.clone();
                if let Some(existing) = self.documents.get(&package) {
                    if event.revision < existing.metadata_revision
                        || (event.revision == existing.metadata_revision
                            && event.metadata != existing.metadata)
                    {
                        return Err(MusubiSearchError::InconsistentFinalizedEvent);
                    }
                    if event.revision == existing.metadata_revision {
                        return Ok(false);
                    }
                }
                self.remove_postings(&package);
                let document = self.documents.entry(package.clone()).or_default();
                document.metadata = event.metadata.clone();
                document.metadata_revision = event.revision;
                document.terms = document_terms(&package, document);
                self.insert_postings(&package);
                Ok(true)
            }
            _ => Ok(false),
        }
    }
    /// Search exact normalized terms without scanning the package directory.
    ///
    /// All query terms must match. `after` is the last structural package key from
    /// the preceding page, making pagination independent of process hash ordering.
    fn search(
        &self,
        terms: &BTreeSet<String>,
        after: Option<&MusubiPackageIdV1>,
        limit: usize,
    ) -> Result<MusubiSearchSliceV1, MusubiSearchError> {
        if limit == 0 || limit > MUSUBI_MAX_PAGE_SIZE_V1 {
            return Err(MusubiSearchError::InvalidPageSize);
        }
        let mut posting_sets = Vec::with_capacity(terms.len());
        for term in terms {
            let Some(posting) = self.postings.get(term) else {
                return Ok(MusubiSearchSliceV1 {
                    hits: Vec::new(),
                    next_after: None,
                });
            };
            posting_sets.push(posting);
        }
        posting_sets.sort_by_key(|posting| posting.len());
        let anchor = posting_sets
            .first()
            .expect("validated Musubi search query has at least one term");
        let mut hits = Vec::with_capacity(limit.saturating_add(1));
        let mut scanned = 0_usize;
        let candidates: Box<dyn Iterator<Item = &MusubiPackageIdV1> + '_> = match after {
            Some(after) => Box::new(anchor.range((Excluded(after), Unbounded))),
            None => Box::new(anchor.iter()),
        };
        for package in candidates {
            scanned = scanned.saturating_add(1);
            if posting_sets.len() > 1 && scanned > MUSUBI_SEARCH_MAX_CANDIDATE_SCAN_V1 {
                return Err(MusubiSearchError::QueryTooBroad);
            }
            if !posting_sets[1..]
                .iter()
                .all(|posting| posting.contains(package))
            {
                continue;
            }
            let document = self
                .documents
                .get(package)
                .expect("Musubi search posting references a document");
            let Some(claimed_namespace) = document.claimed_namespace.clone() else {
                continue;
            };
            if document.metadata_revision == 0 {
                continue;
            }
            hits.push(MusubiSearchHitV1 {
                package: package.clone(),
                claimed_namespace,
                description: document.metadata.description.clone(),
                keywords: document.metadata.keywords.clone(),
                metadata_revision: document.metadata_revision,
            });
            if hits.len() > limit {
                break;
            }
        }
        let has_more = hits.len() > limit;
        if has_more {
            hits.pop();
        }
        let next_after = has_more.then(|| {
            hits.last()
                .expect("non-empty bounded Musubi search page")
                .package
                .clone()
        });
        Ok(MusubiSearchSliceV1 { hits, next_after })
    }
    /// Number of currently projected package documents.
    #[must_use]
    pub fn document_count(&self) -> usize {
        self.documents.len()
    }
    fn contains_hit(&self, package: &MusubiPackageIdV1, terms: &BTreeSet<String>) -> bool {
        self.documents.get(package).is_some_and(|document| {
            document.claimed_namespace.is_some()
                && document.metadata_revision != 0
                && terms.iter().all(|term| document.terms.contains(term))
        })
    }
    fn remove_postings(&mut self, package: &MusubiPackageIdV1) {
        let Some(document) = self.documents.get(package) else {
            return;
        };
        let terms = document.terms.iter().cloned().collect::<Vec<_>>();
        for term in terms {
            let remove_term = self.postings.get_mut(&term).is_some_and(|posting| {
                posting.remove(package);
                posting.is_empty()
            });
            if remove_term {
                self.postings.remove(&term);
            }
        }
    }
    fn insert_postings(&mut self, package: &MusubiPackageIdV1) {
        let terms = self
            .documents
            .get(package)
            .expect("Musubi search document exists before indexing")
            .terms
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        for term in terms {
            self.postings
                .entry(term)
                .or_default()
                .insert(package.clone());
        }
    }
}
impl MusubiSearchIndexV1 {
    /// Rebuild an anchored projection from one consistent finalized world-state view.
    ///
    /// # Errors
    /// Returns `InconsistentFinalizedEvent` if the snapshot anchor is invalid or
    /// package and metadata records cannot form a consistent projection.
    pub fn rebuild_records<P, M>(
        packages: P,
        metadata: M,
        snapshot: MusubiSearchSnapshotV1,
    ) -> Result<Self, MusubiSearchError>
    where
        P: IntoIterator,
        P::Item: Borrow<MusubiPackageRecordV1>,
        M: IntoIterator,
        M::Item: Borrow<MusubiPackageMetadataRecordV1>,
    {
        snapshot
            .validate()
            .map_err(|_| MusubiSearchError::InconsistentFinalizedEvent)?;
        Ok(Self {
            projection: MusubiSearchProjectionV1::rebuild_records(packages, metadata)?,
            snapshot: Some(snapshot),
        })
    }
    /// Return the exact finalized projection anchor, if genesis is available.
    #[must_use]
    pub const fn snapshot(&self) -> Option<MusubiSearchSnapshotV1> {
        self.snapshot
    }
    /// Number of currently projected package documents.
    #[must_use]
    pub fn document_count(&self) -> usize {
        self.projection.document_count()
    }
    /// Apply one finalized event and advance the search-specific projection revision.
    ///
    /// `finalized_height` and `finalized_block_hash` must identify the block that emitted the
    /// event. Events unrelated to package discovery do not change the anchor or revision.
    ///
    /// # Errors
    /// Returns `InconsistentFinalizedEvent` for invalid, regressing or mismatched
    /// finality anchors or contradictory event data, and `RevisionOverflow` if
    /// the next projection revision cannot be represented.
    pub fn apply_finalized(
        &mut self,
        event: &MusubiEvent,
        finalized_height: u64,
        finalized_block_hash: [u8; 32],
    ) -> Result<bool, MusubiSearchError> {
        let Some(expected_height) = search_event_height(event) else {
            return Ok(false);
        };
        if finalized_height == 0 || finalized_block_hash.iter().all(|byte| *byte == 0) {
            return Err(MusubiSearchError::InconsistentFinalizedEvent);
        }
        if expected_height != finalized_height {
            return Err(MusubiSearchError::InconsistentFinalizedEvent);
        }
        if self.snapshot.is_some_and(|snapshot| {
            finalized_height < snapshot.finalized_height
                || (finalized_height == snapshot.finalized_height
                    && finalized_block_hash != snapshot.finalized_block_hash)
        }) {
            return Err(MusubiSearchError::InconsistentFinalizedEvent);
        }
        let projection_revision = match self.snapshot {
            Some(snapshot) => snapshot
                .projection_revision
                .checked_add(1)
                .ok_or(MusubiSearchError::RevisionOverflow)?,
            None => 1,
        };
        let changed = self.projection.apply_finalized_changed(event)?;
        if !changed {
            return Ok(false);
        }
        self.snapshot = Some(MusubiSearchSnapshotV1 {
            finalized_height,
            finalized_block_hash,
            projection_revision,
        });
        Ok(true)
    }
    /// Execute one exact-token query against the anchored discovery projection.
    ///
    /// # Errors
    /// Returns an error for an invalid query/page, unavailable projection, stale
    /// cursor, exceeded candidate-scan budget, or an inconsistent resulting page.
    pub fn search(
        &self,
        request: &MusubiSearchQueryV1,
    ) -> Result<MusubiSearchPageV1, MusubiSearchError> {
        request
            .validate()
            .map_err(|_| MusubiSearchError::InvalidQuery)?;
        let snapshot = self
            .snapshot
            .ok_or(MusubiSearchError::ProjectionUnavailable)?;
        let query_hash = search_query_hash(request);
        let terms = request
            .normalized_terms()
            .map_err(|_| MusubiSearchError::InvalidQuery)?
            .into_iter()
            .collect::<BTreeSet<_>>();
        let after = if let Some(cursor) = &request.page.cursor {
            if cursor.snapshot != snapshot
                || cursor.query_hash != query_hash
                || !self.projection.contains_hit(&cursor.last_package, &terms)
            {
                return Err(MusubiSearchError::StaleCursor);
            }
            Some(&cursor.last_package)
        } else {
            None
        };
        let page = self
            .projection
            .search(&terms, after, request.page.effective_limit())?;
        let next_cursor = page.next_after.map(|last_package| MusubiSearchCursorV1 {
            snapshot,
            query_hash,
            last_package,
        });
        let page = MusubiSearchPageV1 {
            query: request.clone(),
            items: page.hits,
            next_cursor,
            snapshot,
        };
        page.validate()
            .map_err(|_| MusubiSearchError::InconsistentFinalizedEvent)?;
        Ok(page)
    }
}
/// Return the finalized height carried by a search-affecting event.
#[must_use]
pub const fn search_event_height(event: &MusubiEvent) -> Option<u64> {
    match event {
        MusubiEvent::PackageClaimed(event) => Some(event.finalized_height),
        MusubiEvent::PackageMetadataChanged(event) => Some(event.changed_at_height),
        _ => None,
    }
}
fn search_query_hash(request: &MusubiSearchQueryV1) -> MusubiQueryHashV1 {
    let mut canonical = request.clone();
    canonical.page.cursor = None;
    let encoded = canonical.encode();
    let mut payload =
        Vec::with_capacity(MUSUBI_SEARCH_QUERY_HASH_DOMAIN_V1.len() + encoded.len() + 16);
    payload.extend_from_slice(
        &u64::try_from(MUSUBI_SEARCH_QUERY_HASH_DOMAIN_V1.len())
            .expect("static Musubi search query domain length fits u64")
            .to_le_bytes(),
    );
    payload.extend_from_slice(MUSUBI_SEARCH_QUERY_HASH_DOMAIN_V1);
    payload.extend_from_slice(
        &u64::try_from(encoded.len())
            .expect("bounded Musubi search query length fits u64")
            .to_le_bytes(),
    );
    payload.extend_from_slice(&encoded);
    MusubiQueryHashV1::new(*iroha_crypto::Hash::new(&payload).as_ref())
}
fn document_terms(
    package: &MusubiPackageIdV1,
    document: &MusubiSearchDocument,
) -> BTreeSet<String> {
    let mut terms = BTreeSet::new();
    insert_exact_and_words(package.name.as_str(), &mut terms);
    if let Some(namespace) = &document.claimed_namespace {
        insert_exact_and_words(namespace.as_str(), &mut terms);
    }
    for keyword in &document.metadata.keywords {
        if terms.len() >= MUSUBI_SEARCH_MAX_DOCUMENT_TERMS_V1 {
            return terms;
        }
        insert_exact_and_words(keyword.to_string().as_str(), &mut terms);
    }
    if let Some(description) = &document.metadata.description {
        insert_components(description.as_str(), &mut terms);
    }
    terms
}
fn insert_components(value: &str, terms: &mut BTreeSet<String>) {
    for component in value.split_whitespace() {
        if terms.len() >= MUSUBI_SEARCH_MAX_DOCUMENT_TERMS_V1 {
            return;
        }
        insert_exact_and_words(component, terms);
    }
}
fn insert_exact_and_words(value: &str, terms: &mut BTreeSet<String>) {
    if value.len() <= MUSUBI_MAX_SEARCH_TERM_BYTES_V1
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        insert_term(value.to_ascii_lowercase(), terms);
    }
    insert_words(value, terms);
}
fn insert_words(value: &str, terms: &mut BTreeSet<String>) {
    for word in value.split(|character: char| !character.is_alphanumeric()) {
        if terms.len() >= MUSUBI_SEARCH_MAX_DOCUMENT_TERMS_V1 {
            return;
        }
        let normalized = word
            .chars()
            .flat_map(char::to_lowercase)
            .collect::<String>();
        insert_term(normalized, terms);
    }
}
fn insert_term(term: String, terms: &mut BTreeSet<String>) {
    if !term.is_empty()
        && term.len() <= MUSUBI_MAX_SEARCH_TERM_BYTES_V1
        && terms.len() < MUSUBI_SEARCH_MAX_DOCUMENT_TERMS_V1
    {
        terms.insert(term);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{
        account::AccountId,
        events::data::musubi::{MusubiEvent, MusubiPackageClaimedEventV1},
        musubi::{
            MusubiNamespaceBindingDigestV1, MusubiPackageMetadataRecordV1,
            MusubiPackageRevisionsV1, MusubiPackageScopeV1, MusubiReleaseMetadataV1,
            MusubiSearchPageRequestV1,
        },
    };
    use iroha_model_base::topology::DataSpaceId;
    fn account(seed: u8) -> AccountId {
        let keypair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("fixture seed derives account");
        AccountId::new(keypair.public_key().clone())
    }
    fn package(name: &str) -> MusubiPackageIdV1 {
        MusubiPackageIdV1::new(
            DataSpaceId::new(9),
            MusubiPackageScopeV1::DataspaceRoot,
            name.parse().expect("package name"),
        )
    }
    fn claimed(package: MusubiPackageIdV1) -> MusubiEvent {
        MusubiEvent::PackageClaimed(MusubiPackageClaimedEventV1 {
            package,
            namespace: "sora".parse().expect("namespace"),
            claimed_by: account(1),
            governance_revision: 1,
            finalized_height: 1,
        })
    }
    fn metadata(
        package: MusubiPackageIdV1,
        revision: u64,
        description: &str,
        keywords: &[&str],
    ) -> MusubiEvent {
        metadata_at(package, revision, revision, description, keywords)
    }
    fn metadata_at(
        package: MusubiPackageIdV1,
        revision: u64,
        height: u64,
        description: &str,
        keywords: &[&str],
    ) -> MusubiEvent {
        MusubiEvent::PackageMetadataChanged(MusubiPackageMetadataRecordV1 {
            package,
            metadata: MusubiReleaseMetadataV1 {
                description: Some(description.parse().expect("description")),
                keywords: keywords
                    .iter()
                    .map(|keyword| keyword.parse().expect("keyword"))
                    .collect(),
                ..MusubiReleaseMetadataV1::default()
            },
            revision,
            changed_by: account(1),
            changed_at_height: height,
        })
    }
    fn query(text: &str, limit: u32) -> MusubiSearchQueryV1 {
        MusubiSearchQueryV1 {
            query: text.to_owned(),
            page: MusubiSearchPageRequestV1 {
                limit,
                cursor: None,
            },
        }
    }
    fn search_projection(projection: &MusubiSearchProjectionV1, text: &str) -> MusubiSearchSliceV1 {
        let request = query(text, 50);
        let terms = request
            .normalized_terms()
            .expect("normalized query")
            .into_iter()
            .collect::<BTreeSet<_>>();
        projection.search(&terms, None, 50).expect("search")
    }
    #[test]
    fn rebuild_and_incremental_application_are_identical() {
        let package = package("proof-kit");
        let events = vec![
            claimed(package.clone()),
            metadata(
                package,
                1,
                "Deterministic zero knowledge verifier",
                &["cryptography", "zero-knowledge"],
            ),
        ];
        let rebuilt = MusubiSearchProjectionV1::rebuild(&events).expect("rebuild projection");
        let mut incremental = MusubiSearchProjectionV1::default();
        for event in &events {
            incremental
                .apply_finalized(event)
                .expect("apply finalized event");
        }
        assert_eq!(rebuilt, incremental);
        let page = search_projection(&rebuilt, "zero-knowledge verifier");
        assert_eq!(page.hits.len(), 1);
        assert_eq!(page.hits[0].package.name.as_str(), "proof-kit");
    }
    #[test]
    fn metadata_replacement_removes_stale_description_tokens() {
        let package = package("codec");
        let events = [
            claimed(package.clone()),
            metadata(package.clone(), 1, "legacy binary codec", &["codec"]),
            metadata(package, 2, "canonical norito encoding", &["serialization"]),
        ];
        let projection = MusubiSearchProjectionV1::rebuild(&events).expect("rebuild projection");
        assert!(search_projection(&projection, "legacy").hits.is_empty());
        let current = search_projection(&projection, "norito");
        assert_eq!(current.hits.len(), 1);
        assert_eq!(current.hits[0].metadata_revision, 2);
    }
    #[test]
    fn hyphenated_description_matches_its_exact_term_and_words() {
        let package = package("proofs");
        let events = [
            claimed(package.clone()),
            metadata(package, 1, "zero-knowledge verifier", &[]),
        ];
        let projection = MusubiSearchProjectionV1::rebuild(&events).expect("rebuild projection");
        assert_eq!(
            search_projection(&projection, "zero-knowledge").hits.len(),
            1
        );
    }
    #[test]
    fn inconsistent_same_revision_metadata_is_rejected() {
        let package = package("codec");
        let events = [
            metadata(package.clone(), 1, "first description", &["codec"]),
            metadata(package, 1, "substituted description", &["codec"]),
        ];
        assert_eq!(
            MusubiSearchProjectionV1::rebuild(&events),
            Err(MusubiSearchError::InconsistentFinalizedEvent)
        );
    }
    #[test]
    fn finalized_state_rebuild_produces_an_anchored_search_page() {
        let package = package("math-kit");
        let owner = account(1);
        let package_record = MusubiPackageRecordV1 {
            package: package.clone(),
            claimed_namespace: "sora".parse().expect("namespace"),
            claimed_namespace_binding: MusubiNamespaceBindingDigestV1::new([1; 32]),
            owners: vec![owner.clone()],
            member_accounts: vec![owner.clone()],
            claimed_at_height: 1,
            revisions: MusubiPackageRevisionsV1 {
                governance: 1,
                metadata: 1,
                archive_locations: 1,
            },
        };
        let metadata_record = MusubiPackageMetadataRecordV1 {
            package,
            metadata: MusubiReleaseMetadataV1 {
                description: Some("Canonical arithmetic helpers".parse().expect("description")),
                keywords: vec!["math".parse().expect("keyword")],
                ..MusubiReleaseMetadataV1::default()
            },
            revision: 1,
            changed_by: owner,
            changed_at_height: 2,
        };
        let snapshot = MusubiSearchSnapshotV1 {
            finalized_height: 3,
            finalized_block_hash: [3; 32],
            projection_revision: 7,
        };
        let index =
            MusubiSearchIndexV1::rebuild_records([&package_record], [&metadata_record], snapshot)
                .expect("rebuild finalized state");
        let page = index.search(&query("arithmetic math", 50)).expect("search");
        assert_eq!(page.snapshot, snapshot);
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].package.name.as_str(), "math-kit");
    }
    #[test]
    fn search_cursor_binds_query_and_projection_revision() {
        let first = package("alpha-kit");
        let second = package("beta-kit");
        let events = [
            claimed(first.clone()),
            metadata(first, 1, "deterministic verifier", &["cryptography"]),
            claimed(second.clone()),
            metadata(second, 1, "deterministic prover", &["cryptography"]),
        ];
        let mut index = MusubiSearchIndexV1 {
            projection: MusubiSearchProjectionV1::rebuild(&events).expect("projection"),
            snapshot: Some(MusubiSearchSnapshotV1 {
                finalized_height: 1,
                finalized_block_hash: [1; 32],
                projection_revision: 4,
            }),
        };
        let first_page = index.search(&query("cryptography", 1)).expect("first page");
        assert_eq!(first_page.items.len(), 1);
        let cursor = first_page.next_cursor.expect("continuation");
        let mut continuation = query("cryptography", 1);
        continuation.page.cursor = Some(cursor.clone());
        let second_page = index.search(&continuation).expect("second page");
        assert_eq!(second_page.items.len(), 1);
        assert!(second_page.next_cursor.is_none());
        let mut changed_query = query("deterministic", 1);
        changed_query.page.cursor = Some(cursor.clone());
        assert_eq!(
            index.search(&changed_query),
            Err(MusubiSearchError::StaleCursor)
        );
        let replacement = metadata(package("alpha-kit"), 2, "fast verifier", &["cryptography"]);
        index
            .apply_finalized(&replacement, 2, [2; 32])
            .expect("finalized metadata update");
        assert_eq!(
            index.search(&continuation),
            Err(MusubiSearchError::StaleCursor)
        );
    }
    #[test]
    fn finalized_anchor_is_monotonic_and_accepts_same_block_events() {
        let package_id = package("same-block");
        let mut index = MusubiSearchIndexV1::default();
        let claim = claimed(package_id.clone());
        assert!(
            index
                .apply_finalized(&claim, 1, [1; 32])
                .expect("apply package claim")
        );
        let metadata = metadata_at(package_id.clone(), 1, 1, "first metadata", &["first"]);
        assert!(
            index
                .apply_finalized(&metadata, 1, [1; 32])
                .expect("apply same-block metadata")
        );
        assert_eq!(
            index.snapshot(),
            Some(MusubiSearchSnapshotV1 {
                finalized_height: 1,
                finalized_block_hash: [1; 32],
                projection_revision: 2,
            })
        );
        assert!(
            !index
                .apply_finalized(&metadata, 1, [1; 32])
                .expect("idempotent duplicate")
        );
        assert_eq!(index.snapshot().expect("snapshot").projection_revision, 2);
        let conflicting_same_height =
            metadata_at(package_id.clone(), 2, 1, "second metadata", &["second"]);
        assert_eq!(
            index.apply_finalized(&conflicting_same_height, 1, [9; 32]),
            Err(MusubiSearchError::InconsistentFinalizedEvent)
        );
        let second = metadata_at(package_id.clone(), 2, 2, "second metadata", &["second"]);
        assert!(
            index
                .apply_finalized(&second, 2, [2; 32])
                .expect("advance finalized anchor")
        );
        let regressed = metadata_at(package_id, 3, 1, "regressed metadata", &["third"]);
        assert_eq!(
            index.apply_finalized(&regressed, 1, [1; 32]),
            Err(MusubiSearchError::InconsistentFinalizedEvent)
        );
        assert_eq!(
            index.snapshot(),
            Some(MusubiSearchSnapshotV1 {
                finalized_height: 2,
                finalized_block_hash: [2; 32],
                projection_revision: 3,
            })
        );
        let mut overflow = index;
        overflow
            .snapshot
            .as_mut()
            .expect("snapshot")
            .projection_revision = u64::MAX;
        let before = overflow.clone();
        let next = metadata_at(package("same-block"), 3, 3, "third metadata", &["third"]);
        assert_eq!(
            overflow.apply_finalized(&next, 3, [3; 32]),
            Err(MusubiSearchError::RevisionOverflow)
        );
        assert_eq!(overflow, before);
    }
}
