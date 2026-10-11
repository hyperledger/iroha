//! Sole local enrollment-body selection, bounded retention and semantic retirement owner.
//!
//! These records prove private local custody only. Native current state, wallet phases and
//! successful original carriers remain at their existing owners. Only a live closed generated
//! authorization can replace an expired body whose complete dispatch history is proven unsigned.

use super::*;
use crate::localnet::service_authorities::RetainedProviderServicePlan;
use crate::managed::native_operation::{
    attempts::{
        BodyDispatchScope, BodyReplacementTarget, EnrollmentReadPass, EnrollmentScopeBinding,
        EnrollmentScopeEvidence, History, HistoryScope, SemanticSuccessor, VerifiedUnsignedClosure,
    },
    require_retained_material,
};
use iroha_fs::OwnerDirectory;
use std::{ffi::OsStr, sync::Arc};

#[path = "body_history/records.rs"]
mod records;
pub(super) use records::UnsignedEnrollment;
use records::*;

/// Private transport seam; each result is still produced by the canonical native verifier.
pub(super) trait EnrollmentReads {
    fn historical(
        &self,
        owner: &ManagedStreamTokenCustody,
        policy: &SignerCustodyPolicyV1,
        checkpoint: &FinalityVerifier,
        deadline: Instant,
    ) -> Result<VerifiedStreamTokenCustodyStateV1>;
}
struct NativeEnrollmentReads;
impl EnrollmentReads for NativeEnrollmentReads {
    fn historical(
        &self,
        owner: &ManagedStreamTokenCustody,
        policy: &SignerCustodyPolicyV1,
        checkpoint: &FinalityVerifier,
        deadline: Instant,
    ) -> Result<VerifiedStreamTokenCustodyStateV1> {
        owner.read_current(&policy.binding, checkpoint, deadline)
    }
}

/// A bounded immutable-record observation, independent of the shared attempt state machine.
struct RecordSnapshot {
    directory: Arc<PrivateDirectory>,
    name: String,
    maximum: usize,
    observed: Option<(usize, [u8; 32])>,
}
impl RecordSnapshot {
    // Bind the bytes actually consumed by the sole decoder, including observed absence.
    // A second read here could silently attach a replacement file to an older decoded value.
    fn from_read(
        directory: Arc<PrivateDirectory>,
        name: &str,
        maximum: usize,
        bytes: Option<&[u8]>,
    ) -> Self {
        Self {
            directory,
            name: name.to_owned(),
            maximum,
            observed: bytes.map(|bytes| (bytes.len(), *Hash::new(bytes).as_ref())),
        }
    }
    fn revalidate(&self) -> Result<()> {
        #[cfg(test)]
        shared_snapshot_tests::record_read();
        // Both readers begin with fresh native directory revalidation. The
        // optional reader also revalidates custody before accepting absence.
        let bytes = if self.observed.is_some() {
            Some(self.directory.read(&self.name, self.maximum)?)
        } else {
            read_optional(&self.directory, &self.name, self.maximum)?.map(zeroize::Zeroizing::new)
        };
        let observed = bytes
            .as_ref()
            .map(|bytes| (bytes.len(), *Hash::new(bytes).as_ref()));
        #[cfg(test)]
        snapshot_root_scope_tests::after_record(self)?;
        if observed != self.observed {
            return Err(invalid("retained enrollment body material changed"));
        }
        Ok(())
    }
    fn revalidate_in_scope(&self, reader: &mut iroha_fs::PrivateReadScope<'_>) -> Result<()> {
        #[cfg(test)]
        shared_snapshot_tests::record_read();
        let observe = |bytes: &[u8]| (bytes.len(), *Hash::new(bytes).as_ref());
        let observed = if self.observed.is_some() {
            Some(reader.read(&self.name, self.maximum, observe)?)
        } else {
            reader.read_optional(&self.name, self.maximum, observe)?
        };
        #[cfg(test)]
        snapshot_root_scope_tests::after_record(self)?;
        if observed != self.observed {
            return Err(invalid("retained enrollment body material changed"));
        }
        Ok(())
    }
}
/// Recheck outer-owned names without freezing the shared attempt state machine.
struct NamesSnapshot {
    directory: Arc<PrivateDirectory>,
    maximum: usize,
    names: Vec<std::ffi::OsString>,
}
impl NamesSnapshot {
    fn from_read(
        directory: Arc<PrivateDirectory>,
        maximum: usize,
        names: Vec<std::ffi::OsString>,
    ) -> Self {
        Self {
            directory,
            maximum,
            names,
        }
    }
    fn revalidate(&self) -> Result<()> {
        // entries brackets the native census with fresh directory revalidation.
        if self.directory.entries(self.maximum)? != self.names {
            return Err(invalid("retained enrollment namespace changed"));
        }
        Ok(())
    }
}
/// Persistent evidence chain shares prior snapshots instead of copying checkpoint frames.
struct Snapshot {
    previous: Option<Arc<Snapshot>>,
    records: Vec<RecordSnapshot>,
    names: Vec<NamesSnapshot>,
    root: Option<Arc<PrivateDirectory>>,
}
/// Borrowed coverage of one exact immutable snapshot chain during a closed read-only pass.
/// Construction and membership stay with the sole snapshot owner; no token is retained.
pub(in crate::managed) struct SnapshotReadPass<'a> {
    head: &'a Snapshot,
}
impl SnapshotReadPass<'_> {
    fn covers(&self, snapshot: &Snapshot) -> bool {
        if norito::core::decode_limits_active() {
            return false;
        }
        let mut next = Some(self.head);
        for _ in 0..usize::from(MAX_BODIES) + 2 {
            let Some(current) = next else { return false };
            if std::ptr::eq(current, snapshot) {
                return true;
            }
            next = current.previous.as_deref();
        }
        false
    }
}
impl Snapshot {
    fn revalidate(&self) -> Result<()> {
        #[cfg(test)]
        let _snapshot_timing = finish_timing::phase(finish_timing::Phase::SnapshotRevalidate);
        match self.tree_root() {
            Some(root) => root
                .read_tree_scope(|tree| self.revalidate_in_tree_with_root(Some(tree), Some(root))),
            None => self.revalidate_in_tree(None),
        }
    }
    // Only the immutable layout produced below opts into a common-ancestry bracket.
    // This selects a read strategy, never source validity or native ancestry eligibility.
    // Rootless, custom and multiple-root chains retain the original full-read path.
    fn tree_root(&self) -> Option<&PrivateDirectory> {
        let mut snapshot = self;
        let mut container: Option<&Arc<PrivateDirectory>> = None;
        let mut bodies = 0usize;
        while let Some(previous) = &snapshot.previous {
            if snapshot.root.is_some() {
                return None;
            }
            if previous.previous.is_none() {
                // The existing container snapshot lies immediately after the sole base root.
                if !snapshot.records.is_empty() || snapshot.names.len() > 1 {
                    return None;
                }
                match snapshot.names.first() {
                    Some(names)
                        if names.maximum == usize::from(MAX_BODIES) * 3
                            && container.is_none_or(|directory| {
                                Arc::ptr_eq(directory, &names.directory)
                            }) => {}
                    None if bodies == 0 => {}
                    _ => return None,
                }
            } else {
                let [reserved, original, activation, unused] = snapshot.records.as_slice() else {
                    return None;
                };
                if reserved.name != "reserved.nrt"
                    || reserved.maximum != MAX_BODY_BYTES
                    || reserved.observed.is_none()
                    || original.name != "original.nrt"
                    || original.maximum != journal::MAX_ORIGINAL_BYTES
                    || activation.maximum != MAX_SELECTION_BYTES
                    || unused.maximum != MAX_SELECTION_BYTES
                    || !activation.name.ends_with("-activation.nrt")
                    || !unused.name.ends_with("-unused.nrt")
                    || !Arc::ptr_eq(&reserved.directory, &original.directory)
                    || !Arc::ptr_eq(&activation.directory, &unused.directory)
                    || Arc::ptr_eq(&reserved.directory, &activation.directory)
                    || container
                        .is_some_and(|directory| !Arc::ptr_eq(directory, &activation.directory))
                    || snapshot.names.len() > 1
                    || snapshot.names.first().is_some_and(|names| {
                        names.maximum != 1 || !Arc::ptr_eq(&names.directory, &reserved.directory)
                    })
                {
                    return None;
                }
                bodies += 1;
                if bodies > usize::from(MAX_BODIES) {
                    return None;
                }
                container = Some(&activation.directory);
            }
            snapshot = previous;
        }
        let root = snapshot.root.as_ref()?;
        let [original, anchor, reference] = snapshot.records.as_slice() else {
            return None;
        };
        if snapshot.names.is_empty()
            && original.name == "original.nrt"
            && original.maximum == MAX_SELECTION_BYTES
            && original.observed.is_some()
            && anchor.name == "anchor.nrt"
            && anchor.maximum == MAX_BODY_BYTES
            && anchor.observed.is_some()
            && reference.name.ends_with("-selection.nrt")
            && reference.maximum == MAX_SELECTION_BYTES
            && Arc::ptr_eq(&original.directory, root)
            && Arc::ptr_eq(&anchor.directory, root)
            && !Arc::ptr_eq(&reference.directory, root)
            && self.previous.is_some()
        {
            Some(root)
        } else {
            None
        }
    }
    // The original traversal and source checks remain one producer. The optional borrowed
    // tree only consolidates common native ancestry across this one complete read pass.
    // Every original independent caller still opens a fresh bracket. Persistent anchor exit
    // refusal wins ordinary body errors; a prefix changed and restored inside may be unseen.
    fn revalidate_in_tree(
        &self,
        tree: Option<&mut iroha_fs::PrivateReadTreeScope<'_>>,
    ) -> Result<()> {
        self.revalidate_in_tree_with_root(tree, None)
    }
    fn revalidate_in_tree_with_root(
        &self,
        mut tree: Option<&mut iroha_fs::PrivateReadTreeScope<'_>>,
        canonical_root: Option<&PrivateDirectory>,
    ) -> Result<()> {
        #[cfg(test)]
        shared_snapshot_tests::snapshot_visit();
        let mut index = 0;
        if let Some(root) = &self.root {
            if tree.is_some()
                && reuse_root_scope()
                && canonical_root.is_some_and(|admitted| std::ptr::eq(admitted, root.as_ref()))
            {
                // This exact base has no predecessor or names snapshot. Its original
                // inventory and two adjacent root records are one read-only transaction;
                // the external selection reference keeps its independent full bracket.
                // The root exit precedes that reference and overrides ordinary inner errors.
                // Interior root changes fully restored within this bracket may be unseen.
                #[cfg(test)]
                snapshot_root_scope_tests::root_scope(true);
                root.read_scope(|reader| {
                    let names = reader.entries(4)?;
                    let inventory = require_allowed_names(&names, &SCOPE_ROOT_NAMES);
                    #[cfg(test)]
                    snapshot_root_scope_tests::after_inventory(root)?;
                    inventory?;
                    for record in &self.records[..2] {
                        record.revalidate_in_scope(reader)?;
                    }
                    Ok::<_, crate::managed::Error>(())
                })?;
                index = 2;
            } else {
                #[cfg(test)]
                snapshot_root_scope_tests::root_scope(false);
                root.revalidate()?;
                let inventory = check_names(root, &SCOPE_ROOT_NAMES, 4);
                #[cfg(test)]
                snapshot_root_scope_tests::after_inventory(root)?;
                inventory?;
            }
        }
        if let Some(previous) = &self.previous {
            previous.revalidate_in_tree_with_root(tree.as_deref_mut(), canonical_root)?;
        }
        while index < self.records.len() {
            let mut end = index + 1;
            while end < self.records.len()
                && Arc::ptr_eq(&self.records[index].directory, &self.records[end].directory)
            {
                end += 1;
            }
            if end == index + 1 {
                self.records[index].revalidate()?;
            } else {
                let read = |reader: &mut iroha_fs::PrivateReadScope<'_>| {
                    for record in &self.records[index..end] {
                        record.revalidate_in_scope(reader)?;
                    }
                    Ok::<_, crate::managed::Error>(())
                };
                // The base root and singleton external reference keep their full checks.
                match (self.root.is_none(), tree.as_deref_mut()) {
                    (true, Some(tree)) => tree.read_scope(&self.records[index].directory, read)?,
                    _ => self.records[index].directory.read_scope(read)?,
                }
            }
            index = end;
        }
        for names in &self.names {
            match tree.as_deref_mut() {
                Some(tree) => tree.read_scope(&names.directory, |reader| {
                    if reader.entries(names.maximum)? != names.names {
                        return Err(invalid("retained enrollment namespace changed"));
                    }
                    Ok::<_, crate::managed::Error>(())
                })?,
                None => names.revalidate()?,
            }
        }
        Ok(())
    }
}
const SCOPE_ROOT_NAMES: [&str; 4] = ["original.nrt", "anchor.nrt", "bodies", "epochs"];

fn reuse_root_scope() -> bool {
    #[cfg(test)]
    if snapshot_root_scope_tests::original_recipe() {
        return false;
    }
    !norito::core::decode_limits_active()
}

fn reuse_scope_ancestry() -> bool {
    #[cfg(test)]
    if scope_ancestry_tests::original_recipe() {
        return false;
    }
    !norito::core::decode_limits_active()
}

/// Only BodyHistory constructs this sealed evidence after its complete bounded outer census.
pub(in crate::managed) struct ScopeEvidence {
    root: Arc<PrivateDirectory>,
    body: Arc<PrivateDirectory>,
    binding: EnrollmentScopeBinding,
    fees: Fees,
    snapshots: Arc<Snapshot>,
    active: bool,
}
impl EnrollmentScopeEvidence for ScopeEvidence {
    fn binding(&self) -> &EnrollmentScopeBinding {
        &self.binding
    }
    fn root(&self) -> &PrivateDirectory {
        &self.root
    }
    fn operation(&self) -> &PrivateDirectory {
        &self.body
    }
    fn fees(&self) -> &Fees {
        &self.fees
    }
    fn revalidate(&self) -> Result<()> {
        self.revalidate_with_snapshot_read_pass(None)
    }
    fn with_snapshot_read_pass(
        &self,
        action: &mut dyn FnMut(Option<&SnapshotReadPass<'_>>) -> Result<()>,
    ) -> Result<()> {
        // Preserve the original source/codec charging recipe under an inherited owner.
        if norito::core::decode_limits_active() {
            return action(None);
        }
        self.revalidate()?;
        let pass = SnapshotReadPass {
            head: &self.snapshots,
        };
        let result = action(Some(&pass));
        // Close every ordinary result. Persistent custody/byte changes outrank inner errors.
        self.revalidate()?;
        result
    }
    fn revalidate_with_snapshot_read_pass(
        &self,
        pass: Option<&SnapshotReadPass<'_>>,
    ) -> Result<()> {
        #[cfg(test)]
        scope_ancestry_tests::record(scope_ancestry_tests::Point::Full);
        self.root.revalidate()?;
        check_names(&self.root, &SCOPE_ROOT_NAMES, 4)?;
        #[cfg(test)]
        scope_ancestry_tests::record(scope_ancestry_tests::Point::Inventory);
        self.body.revalidate()?;
        if pass.is_some_and(|pass| pass.covers(&self.snapshots)) {
            Ok(())
        } else {
            self.snapshots.revalidate()
        }
    }
    fn revalidate_in_tree(
        &self,
        pass: Option<&SnapshotReadPass<'_>>,
        tree: &mut iroha_fs::PrivateReadTreeScope<'_>,
        root_read: Option<&mut attempts::GraphRootReadPass<'_, '_>>,
    ) -> Result<()> {
        if !reuse_scope_ancestry() || !pass.is_some_and(|pass| pass.covers(&self.snapshots)) {
            return self.revalidate_with_snapshot_read_pass(pass);
        }
        #[cfg(test)]
        scope_ancestry_tests::record(scope_ancestry_tests::Point::Tree);
        // A complete graph direction may lend its exact original root reader. The actual
        // inventory and allowed-name comparison still run at every original position.
        // Only root ancestry observations consolidate into that direction's closed entry/exit;
        // foreign owners and a decoder activated after scope entry keep the literal recipe.
        let read_names = |reader: &mut iroha_fs::PrivateReadScope<'_>| {
            let names = reader.entries(4)?;
            #[cfg(test)]
            {
                scope_ancestry_tests::record(scope_ancestry_tests::Point::Inventory);
                scope_ancestry_tests::hit(scope_ancestry_tests::Boundary::InventoryRead)?;
                graph_root_scope_tests::hit(graph_root_scope_tests::Boundary::InventoryRead)?;
            }
            Ok::<_, crate::managed::Error>(names)
        };
        let names = match root_read.filter(|read| read.covers(&self.root)) {
            Some(read) => read.read(read_names),
            None => {
                #[cfg(test)]
                graph_root_scope_tests::record(graph_root_scope_tests::Point::InventoryBracket);
                tree.read_scope(&self.root, read_names)
            }
        }?;
        require_allowed_names(&names, &SCOPE_ROOT_NAMES)?;
        #[cfg(test)]
        scope_ancestry_tests::hit(scope_ancestry_tests::Boundary::RootClosed)?;
        // Strict descendants share only the exact native prefix; nonshared owners retain
        // full checks. The enclosing graph closes the original anchor on every ordinary
        // result. Interior prefix changes restored before those fences may be unseen.
        tree.revalidate_directory(&self.body)?;
        #[cfg(test)]
        scope_ancestry_tests::hit(scope_ancestry_tests::Boundary::BodyClosed)?;
        #[cfg(test)]
        graph_root_scope_tests::hit(graph_root_scope_tests::Boundary::BodyClosed)?;
        Ok(())
    }
    fn covers_semantic_original(&self, pass: &SnapshotReadPass<'_>, semantic: [u8; 32]) -> bool {
        if !pass.covers(&self.snapshots) || self.binding.semantic != semantic {
            return false;
        }
        let [reserved, original, _, _] = self.snapshots.records.as_slice() else {
            return false;
        };
        self.snapshots.root.is_none()
            && self.snapshots.previous.is_some()
            && reserved.name == "reserved.nrt"
            && reserved.maximum == MAX_BODY_BYTES
            && reserved.observed.is_some()
            && Arc::ptr_eq(&reserved.directory, &self.body)
            && original.name == "original.nrt"
            && original.maximum == journal::MAX_ORIGINAL_BYTES
            && Arc::ptr_eq(&original.directory, &self.body)
            && original.observed.is_some_and(|(length, observed)| {
                length > 0 && length <= journal::MAX_ORIGINAL_BYTES && observed == semantic
            })
    }
    fn require_active(&self) -> Result<()> {
        self.revalidate()?;
        if !self.active {
            return Err(ManagedBootstrapFailure::TransitionPending.into());
        }
        Ok(())
    }
}

struct Target {
    purpose: Purpose,
    outer: [u8; 32],
    previous_body: [u8; 32],
    previous_semantic: Option<[u8; 32]>,
    successor: [u8; 32],
    fees: Fees,
    snapshots: Arc<Snapshot>,
}
impl Target {
    fn revalidate(&self) -> Result<()> {
        self.revalidate_with_snapshot_read_pass(None)
    }
    fn revalidate_with_snapshot_read_pass(
        &self,
        pass: Option<&SnapshotReadPass<'_>>,
    ) -> Result<()> {
        self.fees.validate()?;
        if self.outer == [0; 32]
            || self.previous_body == [0; 32]
            || self.successor == [0; 32]
            || self.previous_semantic == Some([0; 32])
        {
            return Err(invalid("enrollment replacement target is incomplete"));
        }
        if pass.is_some_and(|pass| pass.covers(&self.snapshots)) {
            Ok(())
        } else {
            self.snapshots.revalidate()
        }
    }
}
/// Native-validated unsigned selection; the live issuer consumes this target before publication.
pub(in crate::managed) struct PlannedBodyReplacement {
    target: Target,
    reservation: Reservation,
}
/// Exact already-retained successor; terminal History closure can only rejoin this one selection.
pub(in crate::managed) struct ReservedBodySuccessor {
    target: Target,
}
macro_rules! replacement_target {
    ($ty:ty) => {
        impl BodyReplacementTarget for $ty {
            fn purpose(&self) -> Purpose {
                self.target.purpose
            }
            fn outer_intent(&self) -> [u8; 32] {
                self.target.outer
            }
            fn predecessor_body(&self) -> [u8; 32] {
                self.target.previous_body
            }
            fn predecessor_semantic(&self) -> Option<[u8; 32]> {
                self.target.previous_semantic
            }
            fn successor_selection(&self) -> [u8; 32] {
                self.target.successor
            }
            fn fees(&self) -> &Fees {
                &self.target.fees
            }
            fn validate_target(&self) -> Result<()> {
                self.target.revalidate()
            }
            fn validate_target_with_snapshot_read_pass(
                &self,
                pass: Option<&SnapshotReadPass<'_>>,
            ) -> Result<()> {
                self.target.revalidate_with_snapshot_read_pass(pass)
            }
        }
    };
}
replacement_target!(PlannedBodyReplacement);
replacement_target!(ReservedBodySuccessor);
impl SemanticSuccessor for ReservedBodySuccessor {
    fn target(&self) -> &dyn BodyReplacementTarget {
        self
    }
    fn revalidate(&self) -> Result<()> {
        self.target.revalidate()
    }
    fn revalidate_with_snapshot_read_pass(
        &self,
        pass: Option<&SnapshotReadPass<'_>>,
    ) -> Result<()> {
        self.target.revalidate_with_snapshot_read_pass(pass)
    }
}

struct Body {
    directory: Arc<PrivateDirectory>,
    reservation: Reservation,
    original: Option<Original>,
    activation: Option<Activation>,
    unused: Option<UnusedClosure>,
    semantic: Option<[u8; 32]>,
    snapshots: Arc<Snapshot>,
}
struct ActiveHistory {
    index: usize,
    scope: HistoryScope,
    history: History,
}
/// Full bounded local operation census. Fields and all constructors stay custody-private.
pub(super) struct BodyHistory {
    root: Arc<PrivateDirectory>,
    body_root: Option<Arc<PrivateDirectory>>,
    selection: Selection,
    anchor: Anchor,
    root_snapshots: Arc<Snapshot>,
    bodies: Vec<Body>,
    active: Option<ActiveHistory>,
    nearest_closure: Option<VerifiedUnsignedClosure>,
    reference_present: bool,
    purpose: CustodyPurpose,
}

fn body_name(ordinal: u8) -> Result<String> {
    if ordinal == 0 || ordinal > MAX_BODIES {
        return Err(invalid("enrollment body ordinal exceeds bound"));
    }
    Ok(format!("{ordinal:04}"))
}
fn reference_name(purpose: CustodyPurpose) -> Result<String> {
    Ok(format!("{}-selection.nrt", purpose.directory_name()?))
}
fn decode<T: norito::NoritoSerialize + for<'de> norito::NoritoDeserialize<'de>>(
    bytes: &[u8],
    maximum: usize,
) -> Result<T> {
    if bytes.len() > maximum {
        return Err(invalid("enrollment body record exceeds bound"));
    }
    norito::decode_canonical_with_limits(
        bytes,
        norito::DecodeLimits::new(MAX_CHECKPOINT_BYTES, maximum, maximum, 96 * 1024 * 1024, 48),
    )
    .map_err(|_| invalid("invalid canonical enrollment body record"))
}
fn read<T: norito::NoritoSerialize + for<'de> norito::NoritoDeserialize<'de>>(
    directory: &PrivateDirectory,
    name: &str,
    maximum: usize,
) -> Result<T> {
    decode(&directory.read(name, maximum)?, maximum)
}
fn read_observed<T: norito::NoritoSerialize + for<'de> norito::NoritoDeserialize<'de>>(
    directory: &Arc<PrivateDirectory>,
    name: &str,
    maximum: usize,
) -> Result<(T, RecordSnapshot)> {
    let bytes = directory.read(name, maximum)?;
    let value = decode(&bytes, maximum)?;
    let snapshot = RecordSnapshot::from_read(Arc::clone(directory), name, maximum, Some(&bytes));
    Ok((value, snapshot))
}
fn optional_observed<T: norito::NoritoSerialize + for<'de> norito::NoritoDeserialize<'de>>(
    directory: &Arc<PrivateDirectory>,
    name: &str,
    maximum: usize,
) -> Result<(Option<T>, RecordSnapshot)> {
    let bytes = read_optional(directory, name, maximum)?;
    let value = bytes
        .as_ref()
        .map(|bytes| decode(bytes, maximum))
        .transpose()?;
    let snapshot = RecordSnapshot::from_read(
        Arc::clone(directory),
        name,
        maximum,
        bytes.as_ref().map(|bytes| bytes.as_slice()),
    );
    Ok((value, snapshot))
}
fn read_reference(
    owner: &ManagedStreamTokenCustody,
    purpose: CustodyPurpose,
) -> Result<(Option<Reference>, RecordSnapshot)> {
    owner.authority.directory.revalidate()?;
    let directory = owner.authority.directory.retain()?;
    if directory.identity()? != owner.authority.directory.identity()? {
        return Err(invalid("enrollment authority custody changed"));
    }
    optional_observed(
        &Arc::new(directory),
        &reference_name(purpose)?,
        MAX_SELECTION_BYTES,
    )
}
fn private_parent(directory: &PrivateDirectory) -> Result<OwnerDirectory> {
    directory.revalidate()?;
    let parent = OwnerDirectory::open(directory.path())?;
    if parent.identity()? != directory.identity()? {
        return Err(invalid("enrollment parent custody changed"));
    }
    Ok(parent)
}
fn checked_names(
    directory: &PrivateDirectory,
    allowed: &[&str],
    bound: usize,
) -> Result<Vec<std::ffi::OsString>> {
    let names = directory.entries(bound)?;
    require_allowed_names(&names, allowed)?;
    Ok(names)
}
fn require_allowed_names(names: &[std::ffi::OsString], allowed: &[&str]) -> Result<()> {
    if names
        .iter()
        .any(|name| !allowed.iter().any(|allowed| name == OsStr::new(allowed)))
    {
        return Err(invalid("enrollment body contains unknown material"));
    }
    Ok(())
}
fn check_names(directory: &PrivateDirectory, allowed: &[&str], bound: usize) -> Result<()> {
    checked_names(directory, allowed, bound).map(|_| ())
}
fn same<T: norito::NoritoSerialize>(left: &T, right: &T, bound: usize) -> Result<bool> {
    Ok(encode(left, bound)? == encode(right, bound)?)
}
fn write_once<T: norito::NoritoSerialize>(
    directory: &PrivateDirectory,
    name: &str,
    value: &T,
    maximum: usize,
) -> Result<()> {
    let bytes = encode(value, maximum)?;
    if let Some(old) = read_optional(directory, name, maximum)? {
        if old != bytes {
            return Err(invalid("immutable enrollment body selection changed"));
        }
        return Ok(());
    }
    directory.write_atomic(name, &bytes, PublishMode::CreateNew)?;
    if directory.read(name, maximum)?.as_slice() != bytes {
        return Err(invalid(
            "retained enrollment selection changed after publication",
        ));
    }
    Ok(())
}

// Only this module can assemble a pure history read. The attempt pass invokes this
// concrete algorithm, never an arbitrary callback or a caller-supplied effectful action.
pub(in crate::managed) struct ReadOnlyHistoryParser<'a> {
    current: &'a mut BodyHistory,
    owner: &'a ManagedStreamTokenCustody,
    retained: Option<&'a BodyHistory>,
}
impl<'a> ReadOnlyHistoryParser<'a> {
    pub(in crate::managed) fn retained_graph(&self) -> Option<&'a History> {
        self.retained.and_then(BodyHistory::retained_graph)
    }
    pub(in crate::managed) fn epoch_context(
        &self,
    ) -> Result<Option<crate::managed::native_operation::authorization::BodyParserEpochContext>>
    {
        let CustodyPurpose::Renewal(sequence) = self.current.purpose else {
            return Ok(None);
        };
        // With the independent initial census retained, fewer than three Original bodies
        // cannot reduce complete census work. This threshold avoids adding a third census
        // to the two-body case; actual savings also depend on generated-origin count.
        if self
            .current
            .bodies
            .iter()
            .filter(|body| body.original.is_some())
            .count()
            < 3
        {
            return Ok(None);
        }
        Ok(Some(
            crate::managed::native_operation::authorization::BodyParserEpochContext {
                parent: Arc::clone(&self.current.root),
                parent_intent: self.current.selection.digest()?,
                fees: self.current.selection.fees.clone(),
                scope: crate::managed::native_operation::authorization::Scope::Renewal {
                    provider: self.owner.authority.provider_id()?,
                    sequence,
                },
            },
        ))
    }
    pub(in crate::managed) fn read(
        self,
        pass: &EnrollmentReadPass<'_>,
        epochs: &mut crate::managed::native_operation::authorization::EpochReader,
    ) -> Result<()> {
        self.current
            .verify_histories_in_pass(self.owner, self.retained, epochs, Some(pass))
    }
}

/// Only the concrete body-record parser can borrow its freshly authenticated original plan.
/// This value conveys a pure comparison input, never a profile freshness or live authority verdict.
pub(super) struct BodyOriginalPlan<'a> {
    owner: &'a ManagedStreamTokenCustody,
    plan: &'a RetainedProviderServicePlan,
}
impl BodyOriginalPlan<'_> {
    pub(super) fn for_owner(
        &self,
        owner: &ManagedStreamTokenCustody,
    ) -> Option<&RetainedProviderServicePlan> {
        (std::ptr::eq(self.owner, owner) && !norito::core::decode_limits_active())
            .then_some(self.plan)
    }
}

impl BodyHistory {
    pub(super) fn open(
        owner: &ManagedStreamTokenCustody,
        purpose: CustodyPurpose,
    ) -> Result<Option<Self>> {
        // Reuse only the two exact pure epoch contexts within this fresh historical parse.
        // Source, current authority and active decoder admission remain with their owners.
        let mut validation = EpochValidationScope::new();
        let result = Self::open_with_imports(
            owner,
            purpose,
            &mut crate::managed::service_authority::CheckpointImports::new(
                &owner.authority,
                Some(&mut validation),
            ),
        );
        drop(validation);
        result
    }

    pub(super) fn open_with_imports(
        owner: &ManagedStreamTokenCustody,
        purpose: CustodyPurpose,
        imports: &mut crate::managed::service_authority::CheckpointImports<'_, '_>,
    ) -> Result<Option<Self>> {
        sequence(purpose)?;
        owner.authority.directory.revalidate()?;
        let name = purpose.directory_name()?;
        let (reference, reference_snapshot) = read_reference(owner, purpose)?;
        let root = match owner.authority.directory.open_child_optional(&name) {
            Ok(Some(value)) => Arc::new(value),
            Ok(None) if reference.is_none() => {
                reference_snapshot.revalidate()?;
                return Ok(None);
            }
            Ok(None) => return Err(ManagedBootstrapFailure::RetainedMaterial.into()),
            Err(error) => return require_retained_material(Err(error.into())),
        };
        let plan = owner.authority.provider_plan()?;
        require_retained_material(Self::read(
            owner,
            purpose,
            root,
            (reference, reference_snapshot),
            None,
            plan,
            imports,
        ))
        .map(Some)
    }

    // Consuming transitions keep all original Files live until the same parser has rebuilt
    // and authenticated fresh metadata. Only previously absent paths are opened anew.
    pub(super) fn reopen(self, owner: &ManagedStreamTokenCustody) -> Result<Self> {
        #[cfg(test)]
        let _timing = finish_timing::phase(finish_timing::Phase::Reopen);
        self.read_current(owner)
    }

    fn read_current(&self, owner: &ManagedStreamTokenCustody) -> Result<Self> {
        require_retained_material(self.revalidate_handles())?;
        owner.authority.directory.revalidate()?;
        if self.root.path()
            != owner
                .authority
                .directory
                .path()
                .join(self.purpose.directory_name()?)
        {
            return Err(invalid("retained enrollment belongs to another authority"));
        }
        let reference = read_reference(owner, self.purpose)?;
        #[cfg(test)]
        let timing = finish_timing::phase(finish_timing::Phase::ProfileEntry);
        let plan = owner.authority.provider_plan()?;
        #[cfg(test)]
        drop(timing);
        let current = {
            // End this parse's pure workspace before the closing retained-custody fences
            // and before the caller can publish any successor, retirement or signature.
            let mut validation = EpochValidationScope::new();
            let result = Self::read(
                owner,
                self.purpose,
                Arc::clone(&self.root),
                reference,
                Some(self),
                plan,
                &mut crate::managed::service_authority::CheckpointImports::new(
                    &owner.authority,
                    Some(&mut validation),
                ),
            );
            drop(validation);
            require_retained_material(result)?
        };
        require_retained_material(self.revalidate_handles())?;
        require_retained_material(self.require_retained_prefix(&current))?;
        require_retained_material(current.revalidate_handles())?;
        Ok(current)
    }

    fn revalidate_handles(&self) -> Result<()> {
        // Preserve root, container, body, active graph and nearest-closure order. Only
        // identical complete shared native prefixes use this fresh closed bracket;
        // independently reopened or unrelated handles keep the full native fallback.
        self.root.read_tree_scope(|tree| {
            if let Some(container) = &self.body_root {
                tree.revalidate_directory(container)?;
            }
            for body in &self.bodies {
                tree.revalidate_directory(&body.directory)?;
            }
            if let Some(active) = &self.active {
                active
                    .history
                    .revalidate_retained_handles_in_tree(Some(&mut *tree))?;
            }
            if let Some(closure) = &self.nearest_closure {
                closure
                    .retained_history()
                    .revalidate_retained_handles_in_tree(Some(&mut *tree))?;
            }
            Ok(())
        })
    }

    fn require_retained_prefix(&self, current: &Self) -> Result<()> {
        if self.purpose != current.purpose
            || self.root.identity()? != current.root.identity()?
            || !same(&self.selection, &current.selection, MAX_SELECTION_BYTES)?
            || self.anchor.highest > current.anchor.highest
            || self.anchor.active > current.anchor.active
            || self.anchor.active == current.anchor.active
                && self.anchor.completed.is_some()
                && self.anchor.completed != current.anchor.completed
            || self.bodies.len() > current.bodies.len()
            || self.reference_present && !current.reference_present
            || self.body_root.is_some()
                && self
                    .body_root
                    .as_ref()
                    .map(|root| root.identity())
                    .transpose()?
                    != current
                        .body_root
                        .as_ref()
                        .map(|root| root.identity())
                        .transpose()?
        {
            return Err(invalid("retained enrollment prefix was lost or changed"));
        }
        for (before, after) in self.bodies.iter().zip(&current.bodies) {
            if before.directory.identity()? != after.directory.identity()?
                || !same(&before.reservation, &after.reservation, MAX_BODY_BYTES)?
                || before.semantic.is_some() && before.semantic != after.semantic
                || before.activation.is_some()
                    && !same(&before.activation, &after.activation, MAX_SELECTION_BYTES)?
                || before.unused.is_some()
                    && !same(&before.unused, &after.unused, MAX_SELECTION_BYTES)?
            {
                return Err(invalid("retained enrollment body was lost or changed"));
            }
        }
        if let Some(pending) = &self.anchor.pending {
            let retained = current
                .bodies
                .get(usize::from(pending.ordinal) - 1)
                .map(|body| &body.reservation)
                .or_else(|| {
                    current
                        .anchor
                        .pending
                        .as_ref()
                        .filter(|r| r.ordinal == pending.ordinal)
                })
                .ok_or_else(|| invalid("retained enrollment reservation was lost"))?;
            if !same(pending, retained, MAX_BODY_BYTES)? {
                return Err(invalid("retained enrollment reservation changed"));
            }
        }
        Ok(())
    }

    fn read(
        owner: &ManagedStreamTokenCustody,
        purpose: CustodyPurpose,
        root: Arc<PrivateDirectory>,
        reference: (Option<Reference>, RecordSnapshot),
        retained: Option<&Self>,
        plan: RetainedProviderServicePlan,
        imports: &mut crate::managed::service_authority::CheckpointImports<'_, '_>,
    ) -> Result<Self> {
        // Both callers just acquired this exact owner's plan through its full profile
        // producer. Preserve that entry's native error order. The inactive concrete parser
        // owns the original post-inspection profile exit on every ordinary result, including
        // errors before any Original. No source verdict or borrowed plan leaves this call.
        let share_plan = !norito::core::decode_limits_active();
        #[cfg(test)]
        let share_plan = share_plan && !borrowed_plan_tests::original_recipe();
        if !share_plan {
            return Self::read_inner(
                owner, purpose, root, reference, retained, plan, imports, false,
            );
        }
        let result = Self::read_inner(
            owner, purpose, root, reference, retained, plan, imports, true,
        );
        // Any existing inner history/epoch/snapshot exits run before this independent full
        // profile exit. Persistent profile custody refusal outranks an ordinary parse error.
        #[cfg(test)]
        let _timing = finish_timing::phase(finish_timing::Phase::ProfileExit);
        owner.authority.validate_profile()?;
        result
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Keep one canonical parser with original read inputs and explicit profile scope mode"
    )]
    fn read_inner(
        owner: &ManagedStreamTokenCustody,
        purpose: CustodyPurpose,
        root: Arc<PrivateDirectory>,
        reference: (Option<Reference>, RecordSnapshot),
        retained: Option<&Self>,
        plan: RetainedProviderServicePlan,
        imports: &mut crate::managed::service_authority::CheckpointImports<'_, '_>,
        share_plan: bool,
    ) -> Result<Self> {
        #[cfg(test)]
        let records_timing = finish_timing::phase(finish_timing::Phase::ReadRecords);
        let (reference, reference_snapshot) = reference;
        let root_names = checked_names(
            &root,
            &["original.nrt", "anchor.nrt", "bodies", "epochs"],
            4,
        )?;
        // This inventory fences this parse only: later authorized epochs/body publication is legal.
        let root_names = NamesSnapshot::from_read(Arc::clone(&root), 4, root_names);
        let (selection, selection_snapshot): (Selection, _) =
            read_observed(&root, "original.nrt", MAX_SELECTION_BYTES)?;
        // The entry owner just authenticated this complete original profile. Share it only
        // for pure comparisons, never retain it in History or carry it across a callback.
        selection.validate(owner, purpose, &plan)?;
        let outer = selection.digest()?;
        let (anchor, anchor_snapshot): (Anchor, _) =
            read_observed(&root, "anchor.nrt", MAX_BODY_BYTES)?;
        #[cfg(test)]
        parser_snapshot_tests::hit(parser_snapshot_tests::Point::AnchorDecoded, root.path())?;
        if anchor.completed == Some([0; 32])
            || anchor.active.is_none() && anchor.completed.is_some()
            || anchor.outer != outer
            || anchor.highest == 0
            || anchor.highest > MAX_BODIES
            || anchor.active.is_some_and(|n| n == 0 || n > anchor.highest)
            || match (&anchor.pending, anchor.active) {
                (Some(next), previous) => {
                    next.ordinal != anchor.highest
                        || next.ordinal
                            != previous
                                .unwrap_or(0)
                                .checked_add(1)
                                .ok_or_else(|| invalid("body ordinal overflow"))?
                }
                (None, active) => active != Some(anchor.highest),
            }
        {
            return Err(invalid(
                "enrollment body high-water differs from its original selection",
            ));
        }
        if let Some(reference) = &reference {
            if reference.purpose != selection.purpose || reference.outer != outer {
                return Err(invalid(
                    "enrollment operation differs from its external selection reference",
                ));
            }
        } else {
            // Atomic root publication can precede its external reference only before all effects.
            if anchor.highest != 1 || anchor.active.is_some() || root.entries(2)?.len() != 2 {
                return Err(invalid("enrollment lost its original operation reference"));
            }
        }
        let root_records = vec![selection_snapshot, anchor_snapshot, reference_snapshot];
        let root_snapshots = Arc::new(Snapshot {
            previous: None,
            records: root_records,
            names: vec![],
            root: Some(Arc::clone(&root)),
        });
        let body_root = match retained.and_then(|prior| prior.body_root.as_ref()) {
            Some(container) => {
                container.revalidate()?;
                Some(Arc::clone(container))
            }
            None if anchor.active.is_none() => root.open_child_optional("bodies")?.map(Arc::new),
            None => Some(Arc::new(root.open_child("bodies")?)),
        };
        let names = body_root
            .as_ref()
            .map(|value| value.entries(usize::from(MAX_BODIES) * 3))
            .transpose()?
            .unwrap_or_default();
        for name in &names {
            if !(1..=anchor.highest).any(|ordinal| {
                let value = format!("{ordinal:04}");
                name == OsStr::new(&value)
                    || name == OsStr::new(&format!("{value}-activation.nrt"))
                    || name == OsStr::new(&format!("{value}-unused.nrt"))
            }) {
                return Err(invalid(
                    "enrollment body inventory has a gap or unknown name",
                ));
            }
        }
        #[cfg(test)]
        parser_snapshot_tests::hit(
            parser_snapshot_tests::Point::ContainerNamesValidated,
            root.path(),
        )?;
        let mut retained_bytes = 0usize;
        let mut bodies: Vec<Body> = Vec::new();
        let mut snapshots = Arc::new(Snapshot {
            previous: Some(Arc::clone(&root_snapshots)),
            records: vec![],
            names: body_root
                .as_ref()
                .map(|container| {
                    NamesSnapshot::from_read(
                        Arc::clone(container),
                        usize::from(MAX_BODIES) * 3,
                        names.clone(),
                    )
                })
                .into_iter()
                .collect(),
            root: None,
        });
        for ordinal in 1..=anchor.highest {
            let name = body_name(ordinal)?;
            let directory =
                match retained.and_then(|prior| prior.bodies.get(usize::from(ordinal) - 1)) {
                    Some(body) => {
                        body.directory.revalidate()?;
                        Some(Arc::clone(&body.directory))
                    }
                    None => match body_root.as_ref() {
                        Some(root)
                            if anchor
                                .pending
                                .as_ref()
                                .is_some_and(|r| r.ordinal == ordinal) =>
                        {
                            root.open_child_optional(&name)?.map(Arc::new)
                        }
                        Some(root) => Some(Arc::new(root.open_child(&name)?)),
                        None => None,
                    },
                };
            let Some(directory) = directory else {
                break;
            };
            let body_names = checked_names(
                &directory,
                &[
                    "reserved.nrt",
                    "original.nrt",
                    "dispatch.nrt",
                    "attempts",
                    "closing.nrt",
                    "closed.nrt",
                ],
                6,
            )?;
            let raw = directory.read("reserved.nrt", MAX_BODY_BYTES)?;
            add_bytes(&mut retained_bytes, raw.len())?;
            let reservation: Reservation = decode(&raw, MAX_BODY_BYTES)?;
            let reservation_snapshot = RecordSnapshot::from_read(
                Arc::clone(&directory),
                "reserved.nrt",
                MAX_BODY_BYTES,
                Some(&raw),
            );
            drop(raw);
            reservation
                .unsigned
                .validate_with_imports(owner, purpose, || Ok(&plan), imports)?;
            selection.matches_unsigned(&reservation.unsigned)?;
            let previous = bodies.last();
            if reservation.ordinal != ordinal
                || reservation.outer != outer
                || reservation.previous_body
                    != previous.map(|body| body.reservation.digest()).transpose()?
                || reservation.previous_semantic != previous.and_then(|body| body.semantic)
            {
                return Err(invalid("enrollment body predecessor link changed"));
            }
            if let Some(pending) = &anchor.pending
                && pending.ordinal == ordinal
                && !same(pending, &reservation, MAX_BODY_BYTES)?
            {
                return Err(invalid(
                    "pending body differs from exact anchored unsigned selection",
                ));
            }
            let container = body_root
                .as_ref()
                .ok_or_else(|| invalid("body container absent"))?;
            let activation_name = format!("{name}-activation.nrt");
            let unused_name = format!("{name}-unused.nrt");
            let (activation, activation_snapshot): (Option<Activation>, _) =
                optional_observed(container, &activation_name, MAX_SELECTION_BYTES)?;
            let (unused, unused_snapshot): (Option<UnusedClosure>, _) =
                optional_observed(container, &unused_name, MAX_SELECTION_BYTES)?;
            let reservation_digest = reservation.digest()?;
            if activation
                .as_ref()
                .is_some_and(|a| a.reservation != reservation_digest)
            {
                return Err(invalid("body activation differs from original reservation"));
            }
            if ordinal <= anchor.active.unwrap_or(0) && activation.is_none() {
                return Err(invalid("active enrollment body lost its activation"));
            }
            let original = journal::read_body_intent(&directory)?;
            let original_snapshot = RecordSnapshot::from_read(
                Arc::clone(&directory),
                "original.nrt",
                journal::MAX_ORIGINAL_BYTES,
                original.as_ref().map(|(_, bytes)| bytes.as_slice()),
            );
            let original = original.map(|(value, _bytes)| value);
            if let Some(original) = &original {
                add_bytes(
                    &mut retained_bytes,
                    match original_snapshot
                        .observed
                        .filter(|_| reuse_original_encoding())
                    {
                        Some((length, _)) => length,
                        None => {
                            #[cfg(test)]
                            pure_original_tests::recomputed(pure_original_tests::Point::Length);
                            norito::canonical_frame_len(original)
                                .map_err(|_| invalid("cannot size retained enrollment body"))?
                        }
                    },
                )?;
                if activation.is_none() || ordinal > anchor.active.unwrap_or(0) {
                    return Err(invalid("unsigned body has paid material before activation"));
                }
                #[cfg(test)]
                borrowed_plan_tests::hit(ordinal)?;
                if share_plan {
                    // This borrow ends with the canonical pure Original comparison. The local
                    // plan is dropped below before any wallet callback can execute.
                    owner.validate_original_in_body_read(
                        original,
                        purpose,
                        imports,
                        &BodyOriginalPlan { owner, plan: &plan },
                    )?;
                } else {
                    owner.validate_original_with_imports(original, purpose, imports)?;
                }
                reservation.unsigned.matches_original(original)?;
                if unused.is_some() {
                    return Err(invalid("unused body contains a completed Original"));
                }
            } else {
                // Absence is meaningful only under the original reservation. No paid/native files.
                check_names(&directory, &["reserved.nrt"], 1)?;
            }
            let semantic = original
                .as_ref()
                .map(|original| {
                    // The sole canonical decoder already compared this immutable Original's
                    // complete encoding with exactly the bytes bound by this snapshot.
                    if reuse_original_encoding()
                        && let Some((_, semantic)) = original_snapshot.observed
                    {
                        return Ok(semantic);
                    }
                    #[cfg(test)]
                    pure_original_tests::recomputed(pure_original_tests::Point::ReadDigest);
                    original.digest()
                })
                .transpose()?;
            if anchor.active == Some(ordinal) {
                if anchor.completed.is_some() && anchor.completed != semantic {
                    return Err(invalid(
                        "active body lost or changed its completed Original",
                    ));
                }
                if anchor.completed.is_none() && original.is_some() {
                    check_names(&directory, &["reserved.nrt", "original.nrt"], 2)?;
                }
            }
            let records = vec![
                reservation_snapshot,
                original_snapshot,
                activation_snapshot,
                unused_snapshot,
            ];
            let names = if original.is_none() {
                vec![NamesSnapshot::from_read(
                    Arc::clone(&directory),
                    1,
                    body_names,
                )]
            } else {
                vec![]
            };
            snapshots = Arc::new(Snapshot {
                previous: Some(snapshots),
                records,
                names,
                root: None,
            });
            bodies.push(Body {
                directory,
                reservation,
                original,
                activation,
                unused,
                semantic,
                snapshots: Arc::clone(&snapshots),
            });
        }
        if bodies.len() != usize::from(anchor.highest) {
            let pending = anchor
                .pending
                .as_ref()
                .ok_or_else(|| invalid("published enrollment body was lost"))?;
            if bodies.len() + 1 != usize::from(anchor.highest) || pending.ordinal != anchor.highest
            {
                return Err(invalid("enrollment body prefix has a gap"));
            }
            pending
                .unsigned
                .validate_with_imports(owner, purpose, || Ok(&plan), imports)?;
            selection.matches_unsigned(&pending.unsigned)?;
            if pending.outer != outer
                || pending.previous_body
                    != bodies.last().map(|b| b.reservation.digest()).transpose()?
                || pending.previous_semantic != bodies.last().and_then(|b| b.semantic)
            {
                return Err(invalid("reserved missing body changed its predecessor"));
            }
            add_bytes(
                &mut retained_bytes,
                norito::canonical_frame_len(pending)
                    .map_err(|_| invalid("cannot size pending enrollment body"))?,
            )?;
            // No activation/unused record may outlive the missing body it references.
            if names.iter().any(|name| {
                name == OsStr::new(&format!("{:04}-activation.nrt", pending.ordinal))
                    || name == OsStr::new(&format!("{:04}-unused.nrt", pending.ordinal))
            }) {
                return Err(invalid("referenced enrollment body was lost"));
            }
        }
        let mut value = Self {
            root,
            body_root,
            selection,
            anchor,
            root_snapshots,
            bodies,
            active: None,
            nearest_closure: None,
            reference_present: reference.is_some(),
            purpose,
        };
        let mut epochs = crate::managed::native_operation::authorization::EpochReader::default();
        if let CustodyPurpose::Renewal(sequence) = purpose {
            epochs.validate_retained(
                &value.root,
                value.selection.digest()?,
                &value.selection.fees,
                crate::managed::native_operation::authorization::Scope::Renewal {
                    provider: owner.authority.provider_id()?,
                    sequence,
                },
            )?;
        }
        drop(plan);
        #[cfg(test)]
        drop(records_timing);
        value.verify_histories(owner, retained, &mut epochs)?;
        #[cfg(test)]
        parser_snapshot_tests::hit(
            parser_snapshot_tests::Point::HistoriesVerified,
            value.root.path(),
        )?;
        // The final tail includes unsigned bodies, all optional absences and the inventory
        // actually validated. Mutation-time root fences intentionally remain separate.
        snapshots.revalidate()?;
        root_names.revalidate()?;
        // Recheck the complete original image after all record and wallet inspection, before
        // this local historical result can leave the parser. It grants no current authority.
        if !share_plan {
            #[cfg(test)]
            let _timing = finish_timing::phase(finish_timing::Phase::ProfileExit);
            owner.authority.validate_profile()?;
        }
        Ok(value)
    }
}
// Only concrete canonical Originals use this local pure-computation shortcut. All active
// Norito owners retain the original size/encode/hash calls at their original error positions.
fn reuse_original_encoding() -> bool {
    #[cfg(test)]
    if pure_original_tests::original_recipe() {
        return false;
    }
    !norito::core::decode_limits_active()
}
fn reuse_successor_encoding() -> bool {
    #[cfg(test)]
    if target_digest_tests::original_recipe() {
        return false;
    }
    !norito::core::decode_limits_active()
}
fn add_bytes(total: &mut usize, amount: usize) -> Result<()> {
    *total = total
        .checked_add(amount)
        .filter(|n| *n <= MAX_ALL_BODY_BYTES)
        .ok_or_else(|| invalid("enrollment body history exceeds cumulative byte bound"))?;
    Ok(())
}

impl BodyHistory {
    fn successor(&self, index: usize) -> Result<Option<ReservedBodySuccessor>> {
        let previous = &self.bodies[index];
        let next = self
            .bodies
            .get(index + 1)
            .map(|b| &b.reservation)
            .or_else(|| {
                self.anchor
                    .pending
                    .as_ref()
                    .filter(|r| usize::from(r.ordinal) == index + 2)
            });
        let Some(next) = next else {
            return Ok(None);
        };
        let snapshots = self.bodies.get(index + 1).map_or_else(
            || Arc::clone(&previous.snapshots),
            |b| Arc::clone(&b.snapshots),
        );
        Ok(Some(ReservedBodySuccessor {
            target: Target {
                purpose: self.selection.purpose,
                outer: self.selection.digest()?,
                previous_body: previous.reservation.digest()?,
                previous_semantic: previous.semantic,
                successor: next.digest()?,
                fees: self.selection.fees.clone(),
                snapshots,
            },
        }))
    }
    fn retained_graph(&self) -> Option<&History> {
        self.active
            .as_ref()
            .map(|active| &active.history)
            .or_else(|| {
                self.nearest_closure
                    .as_ref()
                    .map(VerifiedUnsignedClosure::retained_history)
            })
    }
    fn verify_histories(
        &mut self,
        owner: &ManagedStreamTokenCustody,
        retained: Option<&Self>,
        epochs: &mut crate::managed::native_operation::authorization::EpochReader,
    ) -> Result<()> {
        #[cfg(test)]
        let _timing = finish_timing::phase(finish_timing::Phase::VerifyHistories);
        if norito::core::decode_limits_active() {
            return self.verify_histories_in_pass(owner, retained, epochs, None);
        }
        let snapshots = self.bodies.last().map_or_else(
            || Arc::clone(&self.root_snapshots),
            |body| Arc::clone(&body.snapshots),
        );
        snapshots.revalidate()?;
        let pass = SnapshotReadPass { head: &snapshots };
        let parser = ReadOnlyHistoryParser {
            current: self,
            owner,
            retained,
        };
        #[cfg(test)]
        let result = if parser_handle_tests::original_recipe() {
            EnrollmentReadPass::run(&pass, |pass| parser.read(pass, epochs))
        } else {
            EnrollmentReadPass::parse(&pass, parser, epochs)
        };
        #[cfg(not(test))]
        let result = EnrollmentReadPass::parse(&pass, parser, epochs);
        // Persistent immutable custody changes override every ordinary parser result.
        snapshots.revalidate()?;
        result
    }
    fn verify_histories_in_pass(
        &mut self,
        owner: &ManagedStreamTokenCustody,
        retained: Option<&Self>,
        epochs: &mut crate::managed::native_operation::authorization::EpochReader,
        pass: Option<&EnrollmentReadPass<'_>>,
    ) -> Result<()> {
        let retained_graph = retained.and_then(Self::retained_graph);
        // Most body reads precede a wallet observation. Construct its HTTP transports only
        // when the canonical History asks to inspect one, sharing it across this read's bodies.
        let mut account = None;
        let mut preceding: Option<VerifiedUnsignedClosure> = None;
        let mut previous_retirement = None;
        #[cfg(test)]
        let parser_root = self.root.path().to_path_buf();
        for index in 0..self.bodies.len() {
            #[cfg(test)]
            parser_handle_tests::hit(parser_handle_tests::Point::BeforeBody(index))?;
            let body = &self.bodies[index];
            if let Some(activation) = &body.activation {
                if activation.preceding_retirement != previous_retirement
                    || index > 0 && previous_retirement.is_none()
                {
                    return Err(invalid(
                        "body activation differs from verified predecessor retirement",
                    ));
                }
            } else if index + 1 != self.bodies.len()
                || self
                    .anchor
                    .pending
                    .as_ref()
                    .is_none_or(|r| r.ordinal != body.reservation.ordinal)
            {
                return Err(invalid(
                    "enrollment body lost activation before successor material",
                ));
            }
            let successor = self.successor(index)?;
            let Some(original) = &body.original else {
                match (&body.unused, &successor) {
                    (Some(unused), Some(successor))
                        if unused.reservation == body.reservation.digest()?
                            && unused.successor == successor.successor_selection() =>
                    {
                        previous_retirement =
                            Some(attempts::semantic_digest(unused, MAX_SELECTION_BYTES)?);
                    }
                    (None, _)
                        if self.anchor.active == Some(body.reservation.ordinal)
                            || self
                                .anchor
                                .pending
                                .as_ref()
                                .is_some_and(|r| r.ordinal == body.reservation.ordinal) =>
                    {
                        // Valid pre-Original state. A later activated body would fail its link.
                        previous_retirement = None;
                    }
                    _ => {
                        return Err(invalid(
                            "unused enrollment body has no exact retirement successor",
                        ));
                    }
                }
                continue;
            };
            // Body has one private producer and its Original is never mutated. This stored
            // semantic was established from that same value before any History inspection.
            // Recheck the active budget at each original call site, not once per parser.
            let digest = || {
                if reuse_original_encoding()
                    && let Some(semantic) = body.semantic
                {
                    return Ok(semantic);
                }
                #[cfg(test)]
                pure_original_tests::recomputed(pure_original_tests::Point::HistoryDigest);
                original.digest()
            };
            // The sole successor producer above already hashed this exact immutable
            // selection and body reservation. Reuse only those local values before any
            // wallet callback; every use rechecks active admission and keeps its fallback.
            let outer_digest = || {
                if reuse_successor_encoding()
                    && let Some(successor) = successor.as_ref()
                {
                    return Ok(successor.target.outer);
                }
                #[cfg(test)]
                target_digest_tests::recomputed(target_digest_tests::Point::Outer);
                self.selection.digest()
            };
            let body_digest = || {
                if reuse_successor_encoding()
                    && let Some(successor) = successor.as_ref()
                {
                    return Ok(successor.target.previous_body);
                }
                #[cfg(test)]
                target_digest_tests::recomputed(target_digest_tests::Point::Body);
                body.reservation.digest()
            };
            let scope = HistoryScope::Enrollment(BodyDispatchScope::verify(
                Arc::new(ScopeEvidence {
                    root: Arc::clone(&self.root),
                    body: Arc::clone(&body.directory),
                    binding: EnrollmentScopeBinding {
                        outer_intent: outer_digest()?,
                        body_selection: body_digest()?,
                        purpose: self.selection.purpose,
                        semantic: digest()?,
                        predecessor_closure: preceding
                            .as_ref()
                            .map(VerifiedUnsignedClosure::digest),
                    },
                    fees: self.selection.fees.clone(),
                    snapshots: Arc::clone(&body.snapshots),
                    active: self.reference_present
                        && self.anchor.pending.is_none()
                        && self.anchor.active == Some(body.reservation.ordinal)
                        && body.reservation.ordinal == self.anchor.highest
                        && self.anchor.completed == body.semantic,
                }),
                preceding.take(),
                pass,
            )?);
            let history = match retained_graph {
                Some(prior) => History::read_retained_with_pass(
                    &body.directory,
                    self.selection.purpose,
                    digest()?,
                    &scope,
                    prior,
                    pass,
                )?,
                None => History::read_with_pass(
                    &body.directory,
                    self.selection.purpose,
                    digest()?,
                    &scope,
                    pass,
                )?,
            };
            history.require_fees(&self.selection.fees)?;
            if let CustodyPurpose::Renewal(sequence) = self.purpose {
                epochs.validate_references(
                    &self.root,
                    outer_digest()?,
                    &self.selection.fees,
                    crate::managed::native_operation::authorization::Scope::Renewal {
                        provider: self.selection.predecessor.provider_id,
                        sequence,
                    },
                    history.origins(),
                )?;
            }
            let inspect = |attempt: &attempts::Attempt| {
                #[cfg(test)]
                let _timing = finish_timing::phase(finish_timing::Phase::ParserWallet);
                let account = match &mut account {
                    Some(account) => account,
                    empty => empty.insert(owner.wallet()?),
                };
                let preparation = original
                    .request(attempt.terms(), attempt.observation()?, Instant::now())?
                    .inspect_in_parent(account, attempt.directory())?;
                #[cfg(test)]
                parser_snapshot_tests::hit(
                    parser_snapshot_tests::Point::WalletInspected,
                    &parser_root,
                )?;
                #[cfg(test)]
                parser_handle_tests::hit(parser_handle_tests::Point::WalletInspected(index))?;
                Ok(preparation)
            };
            if let Some(successor) = successor {
                match history.into_unsigned_closure_with_pass(&successor, inspect, pass)? {
                    attempts::UnsignedClosureVerification::Closed(closure) => {
                        previous_retirement = Some(closure.digest());
                        preceding = Some(closure);
                    }
                    attempts::UnsignedClosureVerification::Pending(history)
                        if self.anchor.active == Some(body.reservation.ordinal)
                            && self.anchor.pending.is_some() =>
                    {
                        previous_retirement = None;
                        self.active = Some(ActiveHistory {
                            index,
                            scope,
                            history,
                        });
                    }
                    attempts::UnsignedClosureVerification::Pending(_) => {
                        return Err(invalid(
                            "successor body precedes complete unsigned History closure",
                        ));
                    }
                }
            } else {
                history.verify_wallets_with_pass(inspect, pass)?;
                self.active = Some(ActiveHistory {
                    index,
                    scope,
                    history,
                });
                previous_retirement = None;
            }
        }
        self.nearest_closure = preceding;
        if pass.is_some() {
            if let Some(active) = &self.active {
                active.history.close_parser_read()?;
            }
        }
        Ok(())
    }
    pub(super) fn validate_renewal_context(
        &self,
        owner: &ManagedStreamTokenCustody,
        deadline: Instant,
        prerequisite: impl FnOnce() -> Result<enrollment::RetainedInitialPrerequisite>,
    ) -> Result<()> {
        self.with_unsigned_renewal_context(|unsigned| {
            owner.validate_unsigned_renewal_context_using(unsigned, deadline, prerequisite)
        })
    }

    pub(super) fn validate_renewal_context_with_imports(
        &self,
        owner: &ManagedStreamTokenCustody,
        deadline: Instant,
        imports: &mut crate::managed::service_authority::CheckpointImports<'_, '_>,
    ) -> Result<()> {
        self.with_unsigned_renewal_context(|unsigned| {
            owner.validate_unsigned_renewal_context_with_imports(unsigned, deadline, imports)
        })
    }

    fn with_unsigned_renewal_context(
        &self,
        validate: impl FnOnce(&UnsignedEnrollment) -> Result<()>,
    ) -> Result<()> {
        if !matches!(self.purpose, CustodyPurpose::Renewal(_)) {
            return Err(invalid("renewal context used for another purpose"));
        }
        let unsigned = self
            .anchor
            .pending
            .as_ref()
            .map(|r| &r.unsigned)
            .or_else(|| self.bodies.last().map(|b| &b.reservation.unsigned))
            .ok_or_else(|| invalid("renewal unsigned selection absent"))?;
        validate(unsigned)
    }
    /// Paid payload/signature phases retain their original recovery path even after body expiry.
    /// This result comes from the sole canonical wallet inspector after the complete history read.
    pub(super) fn preserve_paid_body(&self, owner: &ManagedStreamTokenCustody) -> Result<bool> {
        if self.anchor.pending.is_some() {
            return Ok(false);
        }
        let Some(active) = &self.active else {
            return Ok(false);
        };
        let Some(last) = active.history.last() else {
            return Ok(false);
        };
        if !last.is_committed() {
            return Ok(false);
        }
        let original = self.bodies[active.index]
            .original
            .as_ref()
            .ok_or_else(|| invalid("paid original absent"))?;
        let preparation = original
            .request(last.terms(), last.observation()?, Instant::now())?
            .inspect_in_parent(&owner.wallet()?, last.directory())?;
        Ok(matches!(
            preparation.phase(),
            iroha_wallet::operations::NativePreparationPhase::PayloadRetained
                | iroha_wallet::operations::NativePreparationPhase::Signed
        ))
    }
    pub(super) fn matches_policy(&self, policy: &SignerCustodyPolicyV1) -> Result<()> {
        if control(&self.selection.predecessor)?.policy != *policy {
            return Err(invalid("enrollment operation changed selected policy"));
        }
        Ok(())
    }
    pub(super) fn purpose(&self) -> Purpose {
        self.selection.purpose
    }
    pub(super) fn body_expired(&self) -> Result<bool> {
        let unsigned = self
            .anchor
            .pending
            .as_ref()
            .map(|r| &r.unsigned)
            .or_else(|| self.bodies.last().map(|b| &b.reservation.unsigned))
            .ok_or_else(|| invalid("enrollment unsigned selection absent"))?;
        let now = now_ms()?;
        if now < unsigned.selected_at_unix_ms {
            return Err(invalid("enrollment observed backward UTC"));
        }
        Ok(now >= unsigned.statement.expires_at_unix_ms)
    }
    pub(super) fn has_pending(&self) -> bool {
        self.anchor.pending.is_some()
    }
    pub(super) fn matches_interval(
        &self,
        interval: ManagedCustodyEnrollmentInterval,
    ) -> Result<()> {
        let unsigned = self
            .anchor
            .pending
            .as_ref()
            .map(|r| &r.unsigned)
            .or_else(|| self.bodies.last().map(|b| &b.reservation.unsigned))
            .ok_or_else(|| invalid("enrollment unsigned selection absent"))?;
        if unsigned.statement.issued_at_unix_ms != interval.issued_at_unix_ms
            || unsigned.statement.expires_at_unix_ms != interval.expires_at_unix_ms
        {
            return Err(invalid(
                "explicit enrollment cannot replace original interval",
            ));
        }
        Ok(())
    }
    pub(super) fn root(&self) -> &PrivateDirectory {
        &self.root
    }
    pub(super) fn fees(&self) -> &Fees {
        &self.selection.fees
    }
    pub(super) fn outer_bytes(&self) -> Result<Vec<u8>> {
        encode(&self.selection, MAX_SELECTION_BYTES)
    }
    pub(super) fn original(&self) -> Result<Option<&Original>> {
        Ok(self
            .anchor
            .active
            .and_then(|ordinal| self.bodies.get(usize::from(ordinal - 1)))
            .and_then(|body| body.original.as_ref()))
    }
    #[cfg(test)]
    pub(super) fn current_history(&self) -> Result<&History> {
        self.active
            .as_ref()
            .map(|value| &value.history)
            .ok_or_else(|| ManagedBootstrapFailure::TransitionPending.into())
    }
    pub(super) fn dispatch(&self) -> Result<(&PrivateDirectory, &Original, &HistoryScope)> {
        if self.anchor.pending.is_some() || self.anchor.completed.is_none() {
            return Err(ManagedBootstrapFailure::TransitionPending.into());
        }
        let active = self
            .active
            .as_ref()
            .ok_or(ManagedBootstrapFailure::TransitionPending)?;
        let body = &self.bodies[active.index];
        Ok((
            &body.directory,
            body.original
                .as_ref()
                .ok_or(ManagedBootstrapFailure::TransitionPending)?,
            &active.scope,
        ))
    }
    pub(super) fn into_reparsed_selected(
        self,
        owner: &ManagedStreamTokenCustody,
    ) -> Result<Selected<Original>> {
        self.reopen(owner)?.into_selected()
    }

    // Genuine fixtures sometimes keep an outer history for byte/identity assertions. This
    // uses the same native-handle lending parser, never an independent second open.
    #[cfg(test)]
    pub(super) fn retained_selected(
        &self,
        owner: &ManagedStreamTokenCustody,
    ) -> Result<Selected<Original>> {
        self.read_current(owner)?.into_selected()
    }

    pub(super) fn into_selected(mut self) -> Result<Selected<Original>> {
        if self.anchor.pending.is_some() || self.anchor.completed.is_none() {
            return Err(ManagedBootstrapFailure::TransitionPending.into());
        }
        let active = self
            .active
            .take()
            .ok_or(ManagedBootstrapFailure::TransitionPending)?;
        let original = self.bodies[active.index]
            .original
            .take()
            .ok_or(ManagedBootstrapFailure::TransitionPending)?;
        Selected::from_history(original, active.history)
    }
}

/// A live call owns clocks; no retained record can create this value.
pub(super) enum SigningTurn<'a> {
    Explicit(&'a Terms),
    Generated(&'a dyn DispatchAuthorization),
    RenewalSelection(&'a renewal::GeneratedRenewalTurn),
}
impl SigningTurn<'_> {
    fn check(&self, selection: &Selection, deadline: Instant) -> Result<()> {
        match self {
            Self::Explicit(terms) => {
                if terms.fees != selection.fees {
                    return Err(invalid("original enrollment fees changed"));
                }
                terms.signing_deadline(deadline)?;
            }
            Self::RenewalSelection(turn) => {
                turn.check_selection(selection.purpose, &selection.fees, deadline)?
            }
            Self::Generated(authorization) => {
                if *authorization.fees() != selection.fees {
                    return Err(invalid("generated enrollment fees changed"));
                }
                authorization.check(selection.purpose, deadline)?;
            }
        }
        Ok(())
    }
}
impl BodyHistory {
    pub(super) fn initialize(
        owner: &ManagedStreamTokenCustody,
        purpose: CustodyPurpose,
        unsigned: UnsignedEnrollment,
        fees: &Fees,
        turn: &SigningTurn<'_>,
        deadline: Instant,
    ) -> Result<Self> {
        if Self::open(owner, purpose)?.is_some() {
            return Err(invalid("enrollment operation already selected"));
        }
        let selection = Selection::new(owner, purpose, &unsigned, fees)?;
        turn.check(&selection, deadline)?;
        let reservation = Reservation {
            ordinal: 1,
            outer: selection.digest()?,
            previous_body: None,
            previous_semantic: None,
            unsigned,
        };
        let anchor = Anchor {
            outer: selection.digest()?,
            highest: 1,
            active: None,
            completed: None,
            pending: Some(reservation),
        };
        let original_bytes = encode(&selection, MAX_SELECTION_BYTES)?;
        let anchor_bytes = encode(&anchor, MAX_BODY_BYTES)?;
        let parent = private_parent(&owner.authority.directory)?;
        turn.check(&selection, deadline)?;
        let root = parent.publish_private_child(
            purpose.directory_name()?,
            &[
                ("original.nrt", original_bytes.as_slice()),
                ("anchor.nrt", anchor_bytes.as_slice()),
            ],
        )?;
        owner.authority.directory.revalidate()?;
        root.revalidate()?;
        let value = Self::open(owner, purpose)?
            .ok_or_else(|| invalid("new enrollment operation absent"))?;
        value.retain_reference(owner, turn, deadline)?;
        value.reopen(owner)
    }
    fn retain_reference(
        &self,
        owner: &ManagedStreamTokenCustody,
        turn: &SigningTurn<'_>,
        deadline: Instant,
    ) -> Result<()> {
        self.root_snapshots.revalidate()?;
        turn.check(&self.selection, deadline)?;
        write_once(
            &owner.authority.directory,
            &reference_name(self.purpose)?,
            &Reference {
                purpose: self.selection.purpose,
                outer: self.selection.digest()?,
            },
            MAX_SELECTION_BYTES,
        )
    }
    fn replace_anchor(&self, next: &Anchor) -> Result<()> {
        let reserve = self.anchor.pending.is_none()
            && next.highest
                == self
                    .anchor
                    .highest
                    .checked_add(1)
                    .ok_or(ManagedBootstrapFailure::EpochLimit)?
            && next.active == self.anchor.active
            && next.completed == self.anchor.completed
            && next
                .pending
                .as_ref()
                .is_some_and(|r| r.ordinal == next.highest);
        let activate = self.anchor.pending.is_some()
            && next.highest == self.anchor.highest
            && next.active == Some(next.highest)
            && next.pending.is_none()
            && next.completed.is_none();
        let complete = self.anchor.pending.is_none()
            && next.pending.is_none()
            && self.anchor.active == next.active
            && self.anchor.highest == next.highest
            && self.anchor.completed.is_none()
            && next.completed.is_some_and(|digest| digest != [0; 32]);
        if next.outer != self.anchor.outer || !(reserve || activate || complete) {
            return Err(invalid("illegal enrollment high-water transition"));
        }
        let identity = self.root.identity()?;
        self.root_snapshots.revalidate()?;
        if !same(
            &read::<Anchor>(&self.root, "anchor.nrt", MAX_BODY_BYTES)?,
            &self.anchor,
            MAX_BODY_BYTES,
        )? {
            return Err(invalid("enrollment high-water changed before transition"));
        }
        let bytes = encode(next, MAX_BODY_BYTES)?;
        self.root
            .write_atomic("anchor.nrt", &bytes, PublishMode::Replace)?;
        if self.root.identity()? != identity
            || self.root.read("anchor.nrt", MAX_BODY_BYTES)?.as_slice() != bytes
        {
            return Err(invalid("enrollment high-water changed during transition"));
        }
        Ok(())
    }
    fn verify_fresh_predecessor(
        &self,
        owner: &ManagedStreamTokenCustody,
        current: &VerifiedStreamTokenCustodyStateV1,
    ) -> Result<RetainedProviderServicePlan> {
        let plan = owner.authority.provider_plan()?;
        self.selection.validate(owner, self.purpose, &plan)?;
        let selected = owner.selection(&self.selection.predecessor.binding, current)?;
        if !same(&selected, &self.selection.predecessor, 64 * 1024)? {
            return Err(ManagedBootstrapFailure::EnrollmentPredecessorChanged.into());
        }
        let now = now_ms()?;
        let policy = control(&self.selection.predecessor)?.policy;
        if now < self.selection.provider_from
            || now >= self.selection.provider_until
            || now < policy.active_from_unix_ms
            || now >= policy.active_until_unix_ms
        {
            return Err(ManagedBootstrapFailure::ProfileExpired.into());
        }
        Ok(plan)
    }
    /// Retain exactly one successor after live native qualification and complete unsigned inspection.
    pub(super) fn reserve_successor(
        self,
        owner: &ManagedStreamTokenCustody,
        unsigned: UnsignedEnrollment,
        current: &VerifiedStreamTokenCustodyStateV1,
        authorization: &dyn DispatchAuthorization,
        deadline: Instant,
    ) -> Result<Self> {
        if self.anchor.pending.is_some() {
            return Err(ManagedBootstrapFailure::TransitionPending.into());
        }
        authorization.check(self.selection.purpose, deadline)?;
        let plan = self.verify_fresh_predecessor(owner, current)?;
        unsigned.validate(owner, self.purpose, || Ok(&plan))?;
        drop(plan);
        self.selection.matches_unsigned(&unsigned)?;
        let last = self
            .bodies
            .last()
            .ok_or_else(|| invalid("selected body absent"))?;
        let now = now_ms()?;
        if now < last.reservation.unsigned.selected_at_unix_ms {
            return Err(invalid("body retirement observed backward UTC"));
        }
        if now < last.reservation.unsigned.statement.expires_at_unix_ms {
            return Err(invalid(
                "live enrollment body cannot be semantically replaced",
            ));
        }
        if let Some(active) = &self.active {
            if active.history.cumulative_reserved_count() >= 64 {
                return Err(ManagedBootstrapFailure::EpochLimit.into());
            }
            let original = last
                .original
                .as_ref()
                .ok_or_else(|| invalid("active body Original absent"))?;
            let account = owner.wallet()?;
            let last_digest = active
                .history
                .last()
                .map(attempts::Attempt::digest)
                .transpose()?;
            active.history.verify_wallets(|attempt| {
                let value = original
                    .request(attempt.terms(), attempt.observation()?, deadline)?
                    .inspect_in_parent(&account, attempt.directory())?;
                if Some(attempt.digest()?) == last_digest
                    && !matches!(
                        value.phase(),
                        iroha_wallet::operations::NativePreparationPhase::Missing
                            | iroha_wallet::operations::NativePreparationPhase::RequestOnly
                    )
                {
                    return Err(invalid(
                        "paid or retired material cannot reserve another attester body",
                    ));
                }
                Ok(value)
            })?;
        } else {
            check_names(&last.directory, &["reserved.nrt"], 1)?;
        }
        let ordinal = self
            .anchor
            .highest
            .checked_add(1)
            .filter(|n| *n <= MAX_BODIES)
            .ok_or(ManagedBootstrapFailure::EpochLimit)?;
        let reservation = Reservation {
            ordinal,
            outer: self.selection.digest()?,
            previous_body: Some(last.reservation.digest()?),
            previous_semantic: last.semantic,
            unsigned,
        };
        let planned = PlannedBodyReplacement {
            target: Target {
                purpose: self.selection.purpose,
                outer: self.selection.digest()?,
                previous_body: last.reservation.digest()?,
                previous_semantic: last.semantic,
                successor: reservation.digest()?,
                fees: self.selection.fees.clone(),
                snapshots: Arc::clone(&last.snapshots),
            },
            reservation,
        };
        // The exact typed claim is durable before the first successor write. Uncertain outcomes
        // consume this selection and can never redraw its statement or interval in the same epoch.
        authorization.claim_body_replacement(&planned, deadline)?;
        let next = Anchor {
            outer: self.selection.digest()?,
            highest: ordinal,
            active: self.anchor.active,
            completed: self.anchor.completed,
            pending: Some(planned.reservation),
        };
        authorization.check(self.selection.purpose, deadline)?;
        self.replace_anchor(&next)?;
        self.reopen(owner)
    }

    /// Complete only the anchored prefix; this never selects another interval or native sequence.
    pub(super) fn finish_pending(
        self,
        owner: &ManagedStreamTokenCustody,
        current: &VerifiedStreamTokenCustodyStateV1,
        turn: &SigningTurn<'_>,
        deadline: Instant,
    ) -> Result<Self> {
        self.finish_pending_with_reads(owner, current, turn, deadline, &NativeEnrollmentReads)
    }
    pub(super) fn finish_pending_with_reads(
        mut self,
        owner: &ManagedStreamTokenCustody,
        current: &VerifiedStreamTokenCustodyStateV1,
        turn: &SigningTurn<'_>,
        deadline: Instant,
        reads: &impl EnrollmentReads,
    ) -> Result<Self> {
        #[cfg(test)]
        let _timing = finish_timing::phase(finish_timing::Phase::Finish);
        turn.check(&self.selection, deadline)?;
        self.verify_fresh_predecessor(owner, current)?;
        if !self.reference_present {
            self.retain_reference(owner, turn, deadline)?;
            self = self.reopen(owner)?;
        }
        if let Some(pending) = &self.anchor.pending {
            let bytes = encode(pending, MAX_BODY_BYTES)?;
            let ordinal = pending.ordinal;
            turn.check(&self.selection, deadline)?;
            let body_root = self.root.ensure_child("bodies")?;
            match body_root.open_child_optional(body_name(ordinal)?)? {
                Some(body) => {
                    if body.read("reserved.nrt", MAX_BODY_BYTES)?.as_slice() != bytes {
                        return Err(invalid("retained body reservation changed"));
                    }
                }
                None => {
                    turn.check(&self.selection, deadline)?;
                    private_parent(&body_root)?.publish_private_child(
                        body_name(ordinal)?,
                        &[("reserved.nrt", bytes.as_slice())],
                    )?;
                }
            }
            self = self.reopen(owner)?;
            let previous_retirement = if ordinal == 1 {
                None
            } else {
                let previous = usize::from(ordinal - 2);
                let successor = self
                    .successor(previous)?
                    .ok_or_else(|| invalid("reserved body successor absent"))?;
                let SigningTurn::Generated(authorization) = turn else {
                    return Err(invalid(
                        "explicit enrollment cannot authorize a semantic successor",
                    ));
                };
                authorization.claim_body_replacement(&successor, deadline)?;
                if self.bodies[previous].original.is_some() {
                    if let Some(closure) = self.nearest_closure.as_ref() {
                        if closure.successor_selection() == successor.successor_selection() {
                            Some(closure.digest())
                        } else {
                            return Err(invalid("body closure selected another successor"));
                        }
                    } else {
                        let active = self
                            .active
                            .take()
                            .ok_or(ManagedBootstrapFailure::TransitionPending)?;
                        if active.index != previous {
                            return Err(invalid("closure selected another body"));
                        }
                        let original = self.bodies[previous]
                            .original
                            .as_ref()
                            .ok_or_else(|| invalid("body Original absent"))?;
                        let account = owner.wallet()?;
                        #[cfg(test)]
                        let prepare_timing =
                            finish_timing::phase(finish_timing::Phase::ClosurePrepare);
                        let pending = active.history.prepare_unsigned_closure(
                            &successor,
                            *authorization,
                            deadline,
                            |attempt| {
                                #[cfg(test)]
                                let _timing =
                                    finish_timing::phase(finish_timing::Phase::ClosureWallet);
                                original
                                    .request(attempt.terms(), attempt.observation()?, deadline)?
                                    .inspect_in_parent(&account, attempt.directory())
                            },
                            |attempt| {
                                #[cfg(test)]
                                let _timing =
                                    finish_timing::phase(finish_timing::Phase::WalletRetire);
                                original
                                    .request(attempt.terms(), attempt.observation()?, deadline)?
                                    .retire(&account, &attempt.wallet_path())
                            },
                        )?;
                        #[cfg(test)]
                        drop(prepare_timing);
                        #[cfg(test)]
                        let close_timing =
                            finish_timing::phase(finish_timing::Phase::ClosureFinish);
                        let closed = pending.finish(
                            &successor,
                            *authorization,
                            deadline,
                            |attempt| {
                                #[cfg(test)]
                                let _timing =
                                    finish_timing::phase(finish_timing::Phase::ClosureWallet);
                                original
                                    .request(attempt.terms(), attempt.observation()?, deadline)?
                                    .inspect_in_parent(&account, attempt.directory())
                            },
                            |attempt| {
                                #[cfg(test)]
                                let _timing =
                                    finish_timing::phase(finish_timing::Phase::WalletRetire);
                                original
                                    .request(attempt.terms(), attempt.observation()?, deadline)?
                                    .retire(&account, &attempt.wallet_path())
                            },
                        )?;
                        #[cfg(test)]
                        drop(close_timing);
                        let digest = closed.digest();
                        // Keep the actual closed History and every predecessor File alive for
                        // retained reparsing; a digest cannot lend or authenticate custody.
                        self.nearest_closure = Some(closed);
                        Some(digest)
                    }
                } else {
                    let previous = &self.bodies[previous];
                    check_names(&previous.directory, &["reserved.nrt"], 1)?;
                    if now_ms()? < previous.reservation.unsigned.statement.expires_at_unix_ms {
                        return Err(invalid("unexpired reserved body cannot be retired unused"));
                    }
                    let unused = UnusedClosure {
                        reservation: previous.reservation.digest()?,
                        successor: successor.successor_selection(),
                    };
                    authorization.check(self.selection.purpose, deadline)?;
                    write_once(
                        &body_root,
                        &format!("{:04}-unused.nrt", previous.reservation.ordinal),
                        &unused,
                        MAX_SELECTION_BYTES,
                    )?;
                    Some(attempts::semantic_digest(&unused, MAX_SELECTION_BYTES)?)
                }
            };
            // The first reservation has no predecessor work between the full reparse above
            // and this activation. Reparse again only after predecessor retirement; those
            // lower History/unused records changed and must be authenticated before the CAS.
            if previous_retirement.is_some() {
                self = self.reopen(owner)?;
            }
            let pending = self
                .anchor
                .pending
                .as_ref()
                .ok_or_else(|| invalid("pending enrollment selection absent"))?;
            let activation = Activation {
                reservation: pending.digest()?,
                preceding_retirement: previous_retirement,
            };
            turn.check(&self.selection, deadline)?;
            write_once(
                &body_root,
                &format!("{ordinal:04}-activation.nrt"),
                &activation,
                MAX_SELECTION_BYTES,
            )?;
            turn.check(&self.selection, deadline)?;
            self.replace_anchor(&Anchor {
                outer: self.selection.digest()?,
                highest: ordinal,
                active: Some(ordinal),
                completed: None,
                pending: None,
            })?;
            self = self.reopen(owner)?;
        }
        // An expired unsigned reservation is activated but never signed. A generated caller can
        // retire this exact unused body through the same bounded outer chain; an explicit caller
        // cannot replace it or obtain a dispatch from this return value.
        if self.body_expired()? && self.original()?.is_none() {
            return Ok(self);
        }
        self.sign_retained(owner, current, turn, deadline, reads)
    }

    fn sign_retained(
        self,
        owner: &ManagedStreamTokenCustody,
        current: &VerifiedStreamTokenCustodyStateV1,
        turn: &SigningTurn<'_>,
        deadline: Instant,
        reads: &impl EnrollmentReads,
    ) -> Result<Self> {
        #[cfg(test)]
        let _timing = finish_timing::phase(finish_timing::Phase::SignRetained);
        if matches!(turn, SigningTurn::RenewalSelection(_)) {
            return Err(invalid("renewal selection does not grant attester signing"));
        }
        let index = usize::from(
            self.anchor
                .active
                .ok_or(ManagedBootstrapFailure::TransitionPending)?
                - 1,
        );
        let body = self
            .bodies
            .get(index)
            .ok_or_else(|| invalid("active body absent"))?;
        if let Some(original) = &body.original {
            if self.anchor.completed.is_none() {
                body.snapshots.revalidate()?;
                turn.check(&self.selection, deadline)?;
                self.replace_anchor(&Anchor {
                    completed: Some(original.digest()?),
                    ..self.anchor.clone()
                })?;
                return self.reopen(owner);
            }
            return Ok(self);
        }
        let plan = self.verify_fresh_predecessor(owner, current)?;
        body.reservation
            .unsigned
            .validate(owner, self.purpose, || Ok(&plan))?;
        drop(plan);
        let unsigned = &body.reservation.unsigned;
        let checkpoint = owner.authority.decode_checkpoint(&unsigned.checkpoint)?;
        #[cfg(test)]
        let timing = finish_timing::phase(finish_timing::Phase::HistoricalRead);
        let historical = reads.historical(
            owner,
            &control(&unsigned.selection)?.policy,
            &checkpoint,
            deadline,
        )?;
        #[cfg(test)]
        drop(timing);
        let tip = checkpoint
            .verified_tip()
            .map_err(|_| invalid("unsigned checkpoint invalid"))?;
        if current.height() < checkpoint.checkpoint().height()
            || historical.height() != checkpoint.checkpoint().height()
            || historical.context_id() != tip.context_id()
            || !matches_predecessor(
                &unsigned.selection,
                historical.current().map(|value| value.record()),
            )
        {
            return Err(ManagedBootstrapFailure::EnrollmentPredecessorChanged.into());
        }
        let now = now_ms()?;
        if now < unsigned.selected_at_unix_ms {
            return Err(invalid("attester signing observed backward UTC"));
        }
        if now >= unsigned.statement.expires_at_unix_ms {
            return Err(ManagedBootstrapFailure::EnrollmentExpired.into());
        }
        turn.check(&self.selection, deadline)?;
        body.snapshots.revalidate()?;
        let payload = unsigned
            .statement
            .signing_payload()
            .map_err(|_| invalid("invalid retained attester statement"))?;
        let key = owner.attester()?;
        // This is the sole attester signature boundary: original bytes already exist, and no
        // retained epoch, old wall clock or unsigned local record can substitute a live call.
        turn.check(&self.selection, deadline)?;
        let now = now_ms()?;
        if now < unsigned.selected_at_unix_ms {
            return Err(invalid("attester signing observed backward UTC"));
        }
        if now >= unsigned.statement.expires_at_unix_ms {
            return Err(ManagedBootstrapFailure::EnrollmentExpired.into());
        }
        body.snapshots.revalidate()?;
        let signature = Signature::try_new(key.private_key(), &payload)
            .map_err(|_| invalid("cannot attest retained custody enrollment"))?;
        let record = SignerCustodyRecordV1 {
            statement: unsigned.statement.clone(),
            attestation: signature
                .payload()
                .try_into()
                .map_err(|_| invalid("invalid custody attester signature"))?,
        };
        let original = Original {
            selection: unsigned.selection.clone(),
            checkpoint: unsigned.checkpoint.clone(),
            action: Action::Enroll {
                anchor: unsigned.statement.anchor,
                selected_at_unix_ms: unsigned.selected_at_unix_ms,
                validity: journal::EnrollmentValidity {
                    issued_at_unix_ms: unsigned.statement.issued_at_unix_ms,
                    expires_at_unix_ms: unsigned.statement.expires_at_unix_ms,
                },
                enrollment: encode(&record, 16 * 1024)?,
            },
        };
        owner.validate_original(&original, self.purpose)?;
        unsigned.matches_original(&original)?;
        // Publication uncertainty retains the same deterministic statement/signature; it never
        // changes selected time, evidence, predecessor, role, fee authorization or body ordinal.
        journal::publish_body_intent(&body.directory, &original)?;
        // Preserve signed bytes even when the live call expires during signing/encoding. No
        // dispatch is admitted until the independent completion anchor is durable below.
        turn.check(&self.selection, deadline)?;
        self.root_snapshots.revalidate()?;
        self.replace_anchor(&Anchor {
            completed: Some(original.digest()?),
            ..self.anchor.clone()
        })?;
        self.reopen(owner)
    }
}

impl ManagedStreamTokenCustody {
    pub(super) fn required_enrollment(
        &self,
        purpose: CustodyPurpose,
    ) -> Result<Selected<Original>> {
        self.required_enrollment_with_imports(
            purpose,
            &mut crate::managed::service_authority::CheckpointImports::new(&self.authority, None),
        )
    }

    pub(super) fn required_enrollment_with_imports(
        &self,
        purpose: CustodyPurpose,
        imports: &mut crate::managed::service_authority::CheckpointImports<'_, '_>,
    ) -> Result<Selected<Original>> {
        BodyHistory::open_with_imports(self, purpose, imports)?
            .ok_or(ManagedBootstrapFailure::RetainedMaterial)?
            .into_selected()
    }
}

pub(super) fn selected_policy(
    selection: &StreamTokenCustodySelection,
) -> Result<SignerCustodyPolicyV1> {
    Ok(control(selection)?.policy)
}

#[cfg(test)]
#[path = "body_history/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "body_history/initial_tests.rs"]
mod initial_tests;

#[cfg(test)]
#[path = "body_history/deep_history_tests.rs"]
mod deep_history_tests;

#[cfg(test)]
#[path = "body_history/profile_plan_tests.rs"]
mod profile_plan_tests;

#[cfg(test)]
#[path = "body_history/parser_snapshot_tests.rs"]
mod parser_snapshot_tests;

#[cfg(test)]
#[path = "body_history/snapshot_native_tests.rs"]
mod snapshot_native_tests;

#[cfg(test)]
#[path = "body_history/read_scope_tests.rs"]
mod read_scope_tests;

#[cfg(test)]
#[path = "body_history/tree_snapshot_tests.rs"]
mod tree_snapshot_tests;

#[cfg(test)]
#[path = "body_history/handle_tree_tests.rs"]
mod handle_tree_tests;

#[cfg(test)]
#[path = "body_history/optional_admission_tests.rs"]
mod optional_admission_tests;

#[cfg(test)]
#[path = "body_history/shared_snapshot_tests.rs"]
mod shared_snapshot_tests;

#[cfg(test)]
#[path = "body_history/epoch_scope_tests.rs"]
mod epoch_scope_tests;

#[cfg(test)]
#[path = "body_history/closure_ownership_tests.rs"]
mod closure_ownership_tests;

#[cfg(test)]
#[path = "body_history/parser_handle_tests.rs"]
mod parser_handle_tests;

#[cfg(test)]
#[path = "body_history/epoch_parser_tests.rs"]
mod epoch_parser_tests;

#[cfg(test)]
#[path = "body_history/borrowed_plan_tests.rs"]
mod borrowed_plan_tests;

#[cfg(test)]
#[path = "body_history/finish_timing.rs"]
pub(in crate::managed) mod finish_timing;

#[cfg(test)]
#[path = "body_history/pure_original_tests.rs"]
mod pure_original_tests;

#[cfg(test)]
#[path = "body_history/target_digest_tests.rs"]
mod target_digest_tests;

#[cfg(test)]
#[path = "body_history/operation_scope_tests.rs"]
pub(in crate::managed) mod operation_scope_tests;

#[cfg(test)]
#[path = "body_history/graph_original_tests.rs"]
pub(in crate::managed) mod graph_original_tests;
#[cfg(test)]
#[path = "body_history/graph_root_scope_tests.rs"]
pub(in crate::managed) mod graph_root_scope_tests;

#[cfg(test)]
#[path = "body_history/scope_ancestry_tests.rs"]
mod scope_ancestry_tests;

#[cfg(test)]
#[path = "body_history/snapshot_root_scope_tests.rs"]
mod snapshot_root_scope_tests;
