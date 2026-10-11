//! Sole local enrollment-body selection, bounded retention and semantic retirement owner.
//!
//! These records prove private local custody only. Native current state, wallet phases and
//! successful original carriers remain at their existing owners. Only a live closed generated
//! authorization can replace an expired body whose complete dispatch history is proven unsigned.

use super::*;
use crate::managed::native_operation::{
    attempts::{
        BodyDispatchScope, BodyReplacementTarget, EnrollmentScopeBinding, EnrollmentScopeEvidence,
        History, HistoryScope, SemanticSuccessor, VerifiedUnsignedClosure,
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
    length: usize,
    digest: [u8; 32],
}
impl RecordSnapshot {
    fn new(directory: Arc<PrivateDirectory>, name: &str, maximum: usize) -> Result<Self> {
        let bytes = directory.read(name, maximum)?;
        Ok(Self {
            directory,
            name: name.to_owned(),
            maximum,
            length: bytes.len(),
            digest: *Hash::new(&bytes).as_ref(),
        })
    }
    fn revalidate(&self) -> Result<()> {
        self.directory.revalidate()?;
        let bytes = self.directory.read(&self.name, self.maximum)?;
        if bytes.len() != self.length || *Hash::new(&bytes).as_ref() != self.digest {
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
    fn capture(directory: Arc<PrivateDirectory>, maximum: usize) -> Result<Self> {
        let names = directory.entries(maximum)?;
        Ok(Self {
            directory,
            maximum,
            names,
        })
    }
    fn revalidate(&self) -> Result<()> {
        self.directory.revalidate()?;
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
impl Snapshot {
    fn revalidate(&self) -> Result<()> {
        if let Some(root) = &self.root {
            root.revalidate()?;
            check_names(root, &["original.nrt", "anchor.nrt", "bodies", "epochs"], 4)?;
        }
        if let Some(previous) = &self.previous {
            previous.revalidate()?;
        }
        for record in &self.records {
            record.revalidate()?;
        }
        for names in &self.names {
            names.revalidate()?;
        }
        Ok(())
    }
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
        self.root.revalidate()?;
        check_names(
            &self.root,
            &["original.nrt", "anchor.nrt", "bodies", "epochs"],
            4,
        )?;
        self.body.revalidate()?;
        self.snapshots.revalidate()
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
        self.fees.validate()?;
        if self.outer == [0; 32]
            || self.previous_body == [0; 32]
            || self.successor == [0; 32]
            || self.previous_semantic == Some([0; 32])
        {
            return Err(invalid("enrollment replacement target is incomplete"));
        }
        self.snapshots.revalidate()
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
fn optional<T: norito::NoritoSerialize + for<'de> norito::NoritoDeserialize<'de>>(
    directory: &PrivateDirectory,
    name: &str,
    maximum: usize,
) -> Result<Option<T>> {
    read_optional(directory, name, maximum)?
        .map(|bytes| decode(&bytes, maximum))
        .transpose()
}
fn private_parent(directory: &PrivateDirectory) -> Result<OwnerDirectory> {
    directory.revalidate()?;
    let parent = OwnerDirectory::open(directory.path())?;
    if parent.identity()? != directory.identity()? {
        return Err(invalid("enrollment parent custody changed"));
    }
    Ok(parent)
}
fn check_names(directory: &PrivateDirectory, allowed: &[&str], bound: usize) -> Result<()> {
    let names = directory.entries(bound)?;
    if names
        .iter()
        .any(|name| !allowed.iter().any(|allowed| name == OsStr::new(allowed)))
    {
        return Err(invalid("enrollment body contains unknown material"));
    }
    Ok(())
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

impl BodyHistory {
    pub(super) fn open(
        owner: &ManagedStreamTokenCustody,
        purpose: CustodyPurpose,
    ) -> Result<Option<Self>> {
        sequence(purpose)?;
        owner.authority.directory.revalidate()?;
        let name = purpose.directory_name()?;
        let reference: Option<Reference> = optional(
            &owner.authority.directory,
            &reference_name(purpose)?,
            MAX_SELECTION_BYTES,
        )?;
        let root = match owner.authority.directory.open_child(&name) {
            Ok(value) => Arc::new(value),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && reference.is_none() => {
                return Ok(None);
            }
            Err(error) => return require_retained_material(Err(error.into())),
        };
        owner.authority.validate_profile()?;
        require_retained_material(Self::read(owner, purpose, root, reference, None)).map(Some)
    }

    // Consuming transitions keep all original Files live until the same parser has rebuilt
    // and authenticated fresh metadata. Only previously absent paths are opened anew.
    pub(super) fn reopen(self, owner: &ManagedStreamTokenCustody) -> Result<Self> {
        #[cfg(test)]
        let _timing = crate::custody_timing::Span::enter(crate::custody_timing::Category::Reopen);
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
        let reference = optional(
            &owner.authority.directory,
            &reference_name(self.purpose)?,
            MAX_SELECTION_BYTES,
        )?;
        owner.authority.validate_profile()?;
        let current = require_retained_material(Self::read(
            owner,
            self.purpose,
            Arc::clone(&self.root),
            reference,
            Some(self),
        ))?;
        require_retained_material(self.revalidate_handles())?;
        require_retained_material(self.require_retained_prefix(&current))?;
        require_retained_material(current.revalidate_handles())?;
        Ok(current)
    }

    fn revalidate_handles(&self) -> Result<()> {
        self.root.revalidate()?;
        if let Some(container) = &self.body_root {
            container.revalidate()?;
        }
        for body in &self.bodies {
            body.directory.revalidate()?;
        }
        if let Some(active) = &self.active {
            active.history.revalidate_retained_handles()?;
        }
        if let Some(closure) = &self.nearest_closure {
            closure.retained_history().revalidate_retained_handles()?;
        }
        Ok(())
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
        reference: Option<Reference>,
        retained: Option<&Self>,
    ) -> Result<Self> {
        #[cfg(test)]
        let _timing = crate::custody_timing::Span::enter(crate::custody_timing::Category::Read);
        check_names(
            &root,
            &["original.nrt", "anchor.nrt", "bodies", "epochs"],
            4,
        )?;
        let selection: Selection = read(&root, "original.nrt", MAX_SELECTION_BYTES)?;
        selection.validate(owner, purpose)?;
        let outer = selection.digest()?;
        let anchor: Anchor = read(&root, "anchor.nrt", MAX_BODY_BYTES)?;
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
        let mut root_records = vec![
            RecordSnapshot::new(Arc::clone(&root), "original.nrt", MAX_SELECTION_BYTES)?,
            RecordSnapshot::new(Arc::clone(&root), "anchor.nrt", MAX_BODY_BYTES)?,
        ];
        if reference.is_some() {
            owner.authority.directory.revalidate()?;
            let authority_root = owner.authority.directory.retain()?;
            if authority_root.identity()? != owner.authority.directory.identity()? {
                return Err(invalid("enrollment authority custody changed"));
            }
            root_records.push(RecordSnapshot::new(
                Arc::new(authority_root),
                &reference_name(purpose)?,
                MAX_SELECTION_BYTES,
            )?);
        }
        let root_snapshots = Arc::new(Snapshot {
            previous: None,
            records: root_records,
            names: vec![],
            root: Some(Arc::clone(&root)),
        });
        let body_root = match retained.and_then(|prior| prior.body_root.as_ref()) {
            Some(container) => {
                container.revalidate()?;
                Ok(Arc::clone(container))
            }
            None => root.open_child("bodies").map(Arc::new),
        };
        let body_root = match body_root {
            Ok(value) => Some(value),
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound && anchor.active.is_none() =>
            {
                None
            }
            Err(error) => return Err(error.into()),
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
        let mut retained_bytes = 0usize;
        let mut bodies: Vec<Body> = Vec::new();
        let mut snapshots = Arc::clone(&root_snapshots);
        for ordinal in 1..=anchor.highest {
            let name = body_name(ordinal)?;
            let directory =
                match retained.and_then(|prior| prior.bodies.get(usize::from(ordinal) - 1)) {
                    Some(body) => {
                        body.directory.revalidate()?;
                        Ok(Some(Arc::clone(&body.directory)))
                    }
                    None => body_root
                        .as_ref()
                        .map(|root| root.open_child(&name).map(Arc::new))
                        .transpose(),
                };
            let directory = match directory {
                Ok(Some(value)) => value,
                Ok(None) => break,
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound
                        && anchor
                            .pending
                            .as_ref()
                            .is_some_and(|r| r.ordinal == ordinal) =>
                {
                    break;
                }
                Err(error) => return Err(error.into()),
            };
            check_names(
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
            drop(raw);
            reservation.unsigned.validate(owner, purpose)?;
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
            let activation: Option<Activation> =
                optional(container, &activation_name, MAX_SELECTION_BYTES)?;
            let unused: Option<UnusedClosure> =
                optional(container, &unused_name, MAX_SELECTION_BYTES)?;
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
            if let Some(original) = &original {
                add_bytes(
                    &mut retained_bytes,
                    norito::canonical_frame_len(original)
                        .map_err(|_| invalid("cannot size retained enrollment body"))?,
                )?;
                if activation.is_none() || ordinal > anchor.active.unwrap_or(0) {
                    return Err(invalid("unsigned body has paid material before activation"));
                }
                owner.validate_original(original, purpose)?;
                reservation.unsigned.matches_original(original)?;
                if unused.is_some() {
                    return Err(invalid("unused body contains a completed Original"));
                }
            } else {
                // Absence is meaningful only under the original reservation. No paid/native files.
                check_names(&directory, &["reserved.nrt"], 1)?;
            }
            let semantic = original.as_ref().map(Original::digest).transpose()?;
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
            let mut records = vec![RecordSnapshot::new(
                Arc::clone(&directory),
                "reserved.nrt",
                MAX_BODY_BYTES,
            )?];
            if original.is_some() {
                records.push(RecordSnapshot::new(
                    Arc::clone(&directory),
                    "original.nrt",
                    journal::MAX_ORIGINAL_BYTES,
                )?);
            }
            if activation.is_some() {
                records.push(RecordSnapshot::new(
                    Arc::clone(container),
                    &activation_name,
                    MAX_SELECTION_BYTES,
                )?);
            }
            if unused.is_some() {
                records.push(RecordSnapshot::new(
                    Arc::clone(container),
                    &unused_name,
                    MAX_SELECTION_BYTES,
                )?);
            }
            let mut names = vec![NamesSnapshot::capture(
                Arc::clone(container),
                usize::from(MAX_BODIES) * 3,
            )?];
            if original.is_none() {
                names.push(NamesSnapshot::capture(Arc::clone(&directory), 1)?);
            }
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
            pending.unsigned.validate(owner, purpose)?;
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
        if let CustodyPurpose::Renewal(sequence) = purpose {
            crate::managed::native_operation::authorization::validate_retained(
                &value.root,
                value.selection.digest()?,
                &value.selection.fees,
                crate::managed::native_operation::authorization::Scope::Renewal {
                    provider: owner.authority.provider_id()?,
                    sequence,
                },
            )?;
        }
        value.verify_histories(owner, retained)?;
        value.root_snapshots.revalidate()?;
        Ok(value)
    }
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
    fn verify_histories(
        &mut self,
        owner: &ManagedStreamTokenCustody,
        retained: Option<&Self>,
    ) -> Result<()> {
        let retained_graph = retained.and_then(|prior| {
            prior
                .active
                .as_ref()
                .map(|active| &active.history)
                .or_else(|| {
                    prior
                        .nearest_closure
                        .as_ref()
                        .map(VerifiedUnsignedClosure::retained_history)
                })
        });
        let account = owner.wallet()?;
        let mut preceding: Option<VerifiedUnsignedClosure> = None;
        let mut previous_retirement = None;
        for index in 0..self.bodies.len() {
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
            let scope = HistoryScope::Enrollment(BodyDispatchScope::verify(
                Arc::new(ScopeEvidence {
                    root: Arc::clone(&self.root),
                    body: Arc::clone(&body.directory),
                    binding: EnrollmentScopeBinding {
                        outer_intent: self.selection.digest()?,
                        body_selection: body.reservation.digest()?,
                        purpose: self.selection.purpose,
                        semantic: original.digest()?,
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
            )?);
            let history = match retained_graph {
                Some(prior) => History::read_retained(
                    &body.directory,
                    self.selection.purpose,
                    original.digest()?,
                    &scope,
                    prior,
                )?,
                None => History::read(
                    &body.directory,
                    self.selection.purpose,
                    original.digest()?,
                    &scope,
                )?,
            };
            history.require_fees(&self.selection.fees)?;
            if let CustodyPurpose::Renewal(sequence) = self.purpose {
                crate::managed::native_operation::authorization::validate_references(
                    &self.root,
                    self.selection.digest()?,
                    &self.selection.fees,
                    crate::managed::native_operation::authorization::Scope::Renewal {
                        provider: self.selection.predecessor.provider_id,
                        sequence,
                    },
                    history.origins(),
                )?;
            }
            let inspect = |attempt: &attempts::Attempt| {
                original
                    .request(attempt.terms(), attempt.observation()?, Instant::now())?
                    .inspect(&account, &attempt.wallet_path())
            };
            if let Some(successor) = successor {
                match history.verify_unsigned_closure(&successor, inspect)? {
                    Some(closure) => {
                        previous_retirement = Some(closure.digest());
                        preceding = Some(closure);
                    }
                    None if self.anchor.active == Some(body.reservation.ordinal)
                        && self.anchor.pending.is_some() =>
                    {
                        previous_retirement = None;
                        self.active = Some(ActiveHistory {
                            index,
                            scope,
                            history,
                        });
                    }
                    None => {
                        return Err(invalid(
                            "successor body precedes complete unsigned History closure",
                        ));
                    }
                }
            } else {
                history.verify_wallets(inspect)?;
                self.active = Some(ActiveHistory {
                    index,
                    scope,
                    history,
                });
                previous_retirement = None;
            }
        }
        self.nearest_closure = preceding;
        Ok(())
    }
    pub(super) fn validate_renewal_context(
        &self,
        owner: &ManagedStreamTokenCustody,
        deadline: Instant,
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
        owner.validate_unsigned_renewal_context(unsigned, deadline)
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
            .inspect(&owner.wallet()?, &last.wallet_path())?;
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
        #[cfg(test)]
        let _timing =
            crate::custody_timing::Span::enter(crate::custody_timing::Category::Initialize);
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
    ) -> Result<()> {
        #[cfg(test)]
        let _timing =
            crate::custody_timing::Span::enter(crate::custody_timing::Category::FreshPredecessor);
        self.selection.validate(owner, self.purpose)?;
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
        Ok(())
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
        self.verify_fresh_predecessor(owner, current)?;
        unsigned.validate(owner, self.purpose)?;
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
                    .inspect(&account, &attempt.wallet_path())?;
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
        let _timing = crate::custody_timing::Span::enter(crate::custody_timing::Category::Finish);
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
            match body_root.open_child(body_name(ordinal)?) {
                Ok(body) => {
                    if body.read("reserved.nrt", MAX_BODY_BYTES)?.as_slice() != bytes {
                        return Err(invalid("retained body reservation changed"));
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    turn.check(&self.selection, deadline)?;
                    private_parent(&body_root)?.publish_private_child(
                        body_name(ordinal)?,
                        &[("reserved.nrt", bytes.as_slice())],
                    )?;
                }
                Err(error) => return Err(error.into()),
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
                        let pending = active.history.prepare_unsigned_closure(
                            &successor,
                            *authorization,
                            deadline,
                            |attempt| {
                                original
                                    .request(attempt.terms(), attempt.observation()?, deadline)?
                                    .inspect(&account, &attempt.wallet_path())
                            },
                            |attempt| {
                                original
                                    .request(attempt.terms(), attempt.observation()?, deadline)?
                                    .retire(&account, &attempt.wallet_path())
                            },
                        )?;
                        let closed = pending.finish(
                            &successor,
                            *authorization,
                            deadline,
                            |attempt| {
                                original
                                    .request(attempt.terms(), attempt.observation()?, deadline)?
                                    .inspect(&account, &attempt.wallet_path())
                            },
                            |attempt| {
                                original
                                    .request(attempt.terms(), attempt.observation()?, deadline)?
                                    .retire(&account, &attempt.wallet_path())
                            },
                        )?;
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
        let _timing = crate::custody_timing::Span::enter(crate::custody_timing::Category::Sign);
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
        self.verify_fresh_predecessor(owner, current)?;
        body.reservation.unsigned.validate(owner, self.purpose)?;
        let unsigned = &body.reservation.unsigned;
        let checkpoint = owner.authority.decode_checkpoint(&unsigned.checkpoint)?;
        let historical = reads.historical(
            owner,
            &control(&unsigned.selection)?.policy,
            &checkpoint,
            deadline,
        )?;
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
        BodyHistory::open(self, purpose)?
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
