//! Consuming same-owner publication handoff; cold and uncertain recovery use the sole parser.
//!
//! A receipt names one completed local write under its original native owner. It carries no
//! current authority. Admission constructs a new exact mutable head and independently checks
//! the immutable retained bytes, complete namespace, original profile, epochs and wallets.
//! Only the already parsed records of a terminal unsigned History may be shared into a new
//! scope. The new scope and its active status always come from the newly observed head.

use super::*;

/// Original graph kept alive until publication admission has closed every borrowed handle.
pub(super) struct PublishedHistory {
    active: Option<ActiveHistory>,
    closed: Option<VerifiedUnsignedClosure>,
}
impl PublishedHistory {
    pub(super) fn retained_graph(&self) -> Option<&History> {
        self.active
            .as_ref()
            .map(|active| &active.history)
            .or_else(|| {
                self.closed
                    .as_ref()
                    .map(VerifiedUnsignedClosure::retained_history)
            })
    }
}

/// Sealed provenance of one read-only admission after a successful original-owner write.
/// Attempts can borrow immutable parsed records only while this concrete parser owns it.
pub(in crate::managed) struct PublishedBodyRead<'a> {
    root: &'a PrivateDirectory,
    purpose: Purpose,
    outer: [u8; 32],
    fees: &'a Fees,
}
impl<'a> PublishedBodyRead<'a> {
    pub(super) fn new(current: &'a BodyHistory) -> Result<Self> {
        Ok(Self {
            root: &current.root,
            purpose: current.selection.purpose,
            outer: current.selection.digest()?,
            fees: &current.selection.fees,
        })
    }
    pub(in crate::managed) fn matches(
        &self,
        evidence: &dyn EnrollmentScopeEvidence,
    ) -> Result<bool> {
        Ok(std::ptr::eq(self.root, evidence.root())
            && self.root.identity()? == evidence.root().identity()?
            && self.root.path() == evidence.root().path()
            && self.purpose == evidence.binding().purpose
            && self.outer == evidence.binding().outer_intent
            && self.fees == evidence.fees())
    }
}

/// Minted exclusively after the native anchor writer's exact successful readback.
pub(super) struct PublishedAnchor {
    root: Arc<PrivateDirectory>,
    before: Anchor,
    after: Anchor,
    observed: RecordSnapshot,
}
impl PublishedAnchor {
    pub(super) fn from_readback(
        history: &BodyHistory,
        after: &Anchor,
        readback: &[u8],
    ) -> Result<Self> {
        let decoded: Anchor = decode(readback, MAX_BODY_BYTES)?;
        if !same(&decoded, after, MAX_BODY_BYTES)? {
            return Err(invalid("published enrollment head changed during readback"));
        }
        Ok(Self {
            root: Arc::clone(&history.root),
            before: history.anchor.clone(),
            after: decoded,
            observed: RecordSnapshot::from_read(
                Arc::clone(&history.root),
                "anchor.nrt",
                MAX_BODY_BYTES,
                Some(readback),
            ),
        })
    }
}

// These variants are private to the concrete body owner. They are never decoded from disk,
// manufactured from a height/hash/path, returned by a callback, or accepted by an effect API.
#[expect(
    clippy::large_enum_variant,
    reason = "Publication hands off original retained values; active decode limits preserve the measured full-parser allocation recipe"
)]
pub(super) enum PublishedBodyDelta {
    Anchor(PublishedAnchor),
    Reserved {
        root: Arc<PrivateDirectory>,
        container: Arc<PrivateDirectory>,
        body: Body,
    },
    Closed {
        root: Arc<PrivateDirectory>,
        ordinal: u8,
        closure: VerifiedUnsignedClosure,
    },
    Unused {
        root: Arc<PrivateDirectory>,
        ordinal: u8,
        value: UnusedClosure,
        observed: RecordSnapshot,
    },
    Activated {
        ordinal: u8,
        value: Activation,
        observed: RecordSnapshot,
        anchor: PublishedAnchor,
    },
    Signed {
        ordinal: u8,
        value: Original,
        observed: RecordSnapshot,
        anchor: PublishedAnchor,
    },
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PublicationStep {
    Anchor,
    Reserved,
    Closed,
    Unused,
    Activated,
    Signed,
}

impl PublishedBodyDelta {
    // The original recovery path retained the actual newly closed graph before reparsing.
    // Restore that owner even when an inherited decoder selects recovery.
    fn into_recovery(self, mut history: BodyHistory) -> BodyHistory {
        if let Self::Closed { closure, .. } = self {
            history.nearest_closure = Some(closure);
        }
        history
    }

    #[cfg(test)]
    fn step(&self) -> PublicationStep {
        match self {
            Self::Anchor(_) => PublicationStep::Anchor,
            Self::Reserved { .. } => PublicationStep::Reserved,
            Self::Closed { .. } => PublicationStep::Closed,
            Self::Unused { .. } => PublicationStep::Unused,
            Self::Activated { .. } => PublicationStep::Activated,
            Self::Signed { .. } => PublicationStep::Signed,
        }
    }

    fn revalidate_retained_handles(&self) -> Result<()> {
        match self {
            Self::Closed { closure, .. } => {
                closure.retained_history().revalidate_retained_handles()
            }
            Self::Reserved {
                container, body, ..
            } => {
                container.revalidate()?;
                body.directory.revalidate()?;
                Ok(())
            }
            _ => Ok(()),
        }
    }

    pub(super) fn reserved(
        history: &BodyHistory,
        container: Arc<PrivateDirectory>,
        directory: PrivateDirectory,
        expected: &Reservation,
    ) -> Result<Self> {
        let directory = Arc::new(directory);
        let names = checked_names(&directory, &["reserved.nrt"], 1)?;
        let (reservation, reserved): (Reservation, _) =
            read_observed(&directory, "reserved.nrt", MAX_BODY_BYTES)?;
        if !same(&reservation, expected, MAX_BODY_BYTES)? {
            return Err(invalid(
                "published reservation differs from the exact pending body",
            ));
        }
        let original = journal::read_body_intent(&directory)?;
        let original_record = RecordSnapshot::from_read(
            Arc::clone(&directory),
            "original.nrt",
            journal::MAX_ORIGINAL_BYTES,
            original.as_ref().map(|(_, bytes)| bytes.as_slice()),
        );
        let name = body_name(reservation.ordinal)?;
        let (activation, activation_record) = optional_observed::<Activation>(
            &container,
            &format!("{name}-activation.nrt"),
            MAX_SELECTION_BYTES,
        )?;
        let (unused, unused_record) = optional_observed::<UnusedClosure>(
            &container,
            &format!("{name}-unused.nrt"),
            MAX_SELECTION_BYTES,
        )?;
        if original.is_some() || activation.is_some() || unused.is_some() {
            return Err(invalid(
                "new reservation already contains later body material",
            ));
        }
        let snapshots = Arc::new(Snapshot {
            previous: None,
            records: vec![reserved, original_record, activation_record, unused_record],
            names: vec![NamesSnapshot::from_read(Arc::clone(&directory), 1, names)],
            root: None,
        });
        Ok(Self::Reserved {
            root: Arc::clone(&history.root),
            container,
            body: Body {
                directory,
                reservation,
                original: None,
                activation: None,
                unused: None,
                semantic: None,
                snapshots,
            },
        })
    }

    pub(super) fn closed(
        history: &BodyHistory,
        ordinal: u8,
        closure: VerifiedUnsignedClosure,
    ) -> Self {
        Self::Closed {
            root: Arc::clone(&history.root),
            ordinal,
            closure,
        }
    }

    pub(super) fn unused(
        history: &BodyHistory,
        ordinal: u8,
        expected: &UnusedClosure,
    ) -> Result<Self> {
        let container = history
            .body_root
            .as_ref()
            .ok_or_else(|| invalid("published unused body lost its container"))?;
        let (value, observed): (UnusedClosure, _) = read_observed(
            container,
            &format!("{ordinal:04}-unused.nrt"),
            MAX_SELECTION_BYTES,
        )?;
        if !same(&value, expected, MAX_SELECTION_BYTES)? {
            return Err(invalid("published unused retirement changed"));
        }
        Ok(Self::Unused {
            root: Arc::clone(&history.root),
            ordinal,
            value,
            observed,
        })
    }

    pub(super) fn activated(
        history: &BodyHistory,
        ordinal: u8,
        expected: &Activation,
        anchor: PublishedAnchor,
    ) -> Result<Self> {
        let container = history
            .body_root
            .as_ref()
            .ok_or_else(|| invalid("published activation lost its container"))?;
        let (value, observed): (Activation, _) = read_observed(
            container,
            &format!("{ordinal:04}-activation.nrt"),
            MAX_SELECTION_BYTES,
        )?;
        if !same(&value, expected, MAX_SELECTION_BYTES)? {
            return Err(invalid("published body activation changed"));
        }
        Ok(Self::Activated {
            ordinal,
            value,
            observed,
            anchor,
        })
    }

    pub(super) fn signed(
        history: &BodyHistory,
        ordinal: u8,
        expected: &Original,
        anchor: PublishedAnchor,
    ) -> Result<Self> {
        let index = usize::from(ordinal)
            .checked_sub(1)
            .ok_or_else(|| invalid("published signed body ordinal is zero"))?;
        let body = history
            .bodies
            .get(index)
            .ok_or_else(|| invalid("published signed body absent"))?;
        let (value, bytes) = journal::read_body_intent(&body.directory)?
            .ok_or_else(|| invalid("published signed body Original absent"))?;
        if !same(&value, expected, journal::MAX_ORIGINAL_BYTES)? {
            return Err(invalid("published signed body Original changed"));
        }
        let observed = RecordSnapshot::from_read(
            Arc::clone(&body.directory),
            "original.nrt",
            journal::MAX_ORIGINAL_BYTES,
            Some(&bytes),
        );
        Ok(Self::Signed {
            ordinal,
            value,
            observed,
            anchor,
        })
    }

    fn apply(self, history: &mut BodyHistory) -> Result<()> {
        fn same_root(history: &BodyHistory, root: &Arc<PrivateDirectory>) -> Result<()> {
            if !Arc::ptr_eq(&history.root, root) {
                return Err(invalid(
                    "publication belongs to another retained body owner",
                ));
            }
            root.revalidate()?;
            Ok(())
        }
        fn anchor(history: &mut BodyHistory, publication: PublishedAnchor) -> Result<()> {
            same_root(history, &publication.root)?;
            if !same(&history.anchor, &publication.before, MAX_BODY_BYTES)? {
                return Err(invalid(
                    "publication does not extend its original mutable head",
                ));
            }
            let mut records = history.root_snapshots.records.clone();
            if records.len() != 3 {
                return Err(invalid("original body head layout changed"));
            }
            records[1] = publication.observed;
            history.root_snapshots = Arc::new(Snapshot {
                previous: None,
                records,
                names: vec![],
                root: Some(Arc::clone(&history.root)),
            });
            history.anchor = publication.after;
            Ok(())
        }
        fn leaf(
            history: &mut BodyHistory,
            ordinal: u8,
            position: usize,
            observed: RecordSnapshot,
        ) -> Result<&mut Body> {
            let index = usize::from(ordinal)
                .checked_sub(1)
                .ok_or_else(|| invalid("publication selected body zero"))?;
            let body = history
                .bodies
                .get_mut(index)
                .ok_or_else(|| invalid("publication selected a missing body"))?;
            let mut records = body.snapshots.records.clone();
            if records.len() != 4 {
                return Err(invalid("original body leaf layout changed"));
            }
            records[position] = observed;
            body.snapshots = Arc::new(Snapshot {
                previous: None,
                records,
                names: body.snapshots.names.clone(),
                root: None,
            });
            Ok(body)
        }
        match self {
            Self::Anchor(publication) => anchor(history, publication),
            Self::Reserved {
                root,
                container,
                body,
            } => {
                same_root(history, &root)?;
                let pending = history
                    .anchor
                    .pending
                    .as_ref()
                    .ok_or_else(|| invalid("publication has no original pending body"))?;
                if history.bodies.len() + 1 != usize::from(body.reservation.ordinal)
                    || !same(pending, &body.reservation, MAX_BODY_BYTES)?
                    || history
                        .body_root
                        .as_ref()
                        .is_some_and(|old| !Arc::ptr_eq(old, &container))
                    || body.reservation.ordinal > MAX_BODIES
                {
                    return Err(invalid(
                        "publication changed the bounded original body prefix",
                    ));
                }
                history.body_root = Some(container);
                history.bodies.push(body);
                Ok(())
            }
            Self::Closed {
                root,
                ordinal,
                closure,
            } => {
                same_root(history, &root)?;
                let index = usize::from(ordinal)
                    .checked_sub(1)
                    .ok_or_else(|| invalid("closed publication ordinal is zero"))?;
                let body = history
                    .bodies
                    .get(index)
                    .ok_or_else(|| invalid("closed publication lost its exact body"))?;
                let successor = history
                    .successor(index)?
                    .ok_or_else(|| invalid("closed publication lost its successor"))?;
                if body.semantic != Some(closure.closed_semantic())
                    || closure.purpose() != history.selection.purpose
                    || closure.successor_selection() != successor.successor_selection()
                    || history.active.is_some()
                {
                    return Err(invalid("closed publication selected another original"));
                }
                history.nearest_closure = Some(closure);
                Ok(())
            }
            Self::Unused {
                root,
                ordinal,
                value,
                observed,
            } => {
                same_root(history, &root)?;
                let body = leaf(history, ordinal, 3, observed)?;
                if body.original.is_some()
                    || body.unused.is_some()
                    || value.reservation != body.reservation.digest()?
                {
                    return Err(invalid("unused publication changed a retained body"));
                }
                body.unused = Some(value);
                Ok(())
            }
            Self::Activated {
                ordinal,
                value,
                observed,
                anchor: publication,
            } => {
                if publication.after.active != Some(ordinal)
                    || publication.after.pending.is_some()
                    || publication.after.completed.is_some()
                {
                    return Err(invalid("activation publication changed its exact new head"));
                }
                let body = leaf(history, ordinal, 2, observed)?;
                if body.activation.is_some() || value.reservation != body.reservation.digest()? {
                    return Err(invalid("activation publication changed a retained body"));
                }
                body.activation = Some(value);
                anchor(history, publication)
            }
            Self::Signed {
                ordinal,
                value,
                observed,
                anchor: publication,
            } => {
                let semantic = observed
                    .observed
                    .map(|(_, digest)| digest)
                    .ok_or_else(|| invalid("signed publication lost its Original bytes"))?;
                if publication.after.active != Some(ordinal)
                    || publication.after.completed != Some(semantic)
                    || publication.after.pending.is_some()
                {
                    return Err(invalid(
                        "signed publication changed its exact completed head",
                    ));
                }
                let body = leaf(history, ordinal, 1, observed)?;
                if body.original.is_some() || body.activation.is_none() || body.unused.is_some() {
                    return Err(invalid("signed publication changed a retained body"));
                }
                body.reservation.unsigned.matches_original(&value)?;
                body.semantic = Some(semantic);
                body.original = Some(value);
                // Original publication replaces this body's prior exact absence census.
                body.snapshots = Arc::new(Snapshot {
                    previous: None,
                    records: body.snapshots.records.clone(),
                    names: vec![],
                    root: None,
                });
                anchor(history, publication)
            }
        }
    }
}

impl BodyHistory {
    pub(super) fn reopen_after_publication(
        self,
        owner: &ManagedStreamTokenCustody,
        publication: Option<PublishedBodyDelta>,
    ) -> Result<Self> {
        self.reopen_after_publication_with_wallets(owner, publication, None)
    }

    pub(super) fn reopen_after_publication_with_wallets(
        self,
        owner: &ManagedStreamTokenCustody,
        publication: Option<PublishedBodyDelta>,
        mut wallets: Option<&mut FinishWalletReads<'_>>,
    ) -> Result<Self> {
        let result =
            self.reopen_after_publication_inner(owner, publication, wallets.as_deref_mut());
        if result.is_err()
            && let Some(wallets) = wallets
        {
            wallets.clear();
        }
        result
    }

    fn reopen_after_publication_inner(
        self,
        owner: &ManagedStreamTokenCustody,
        publication: Option<PublishedBodyDelta>,
        mut wallets: Option<&mut FinishWalletReads<'_>>,
    ) -> Result<Self> {
        let Some(publication) = publication else {
            return self.reopen_with_wallets(owner, wallets);
        };
        if norito::core::decode_limits_active() {
            if let Some(wallets) = wallets.as_deref_mut() {
                wallets.clear();
            }
            return publication.into_recovery(self).reopen(owner);
        }
        #[cfg(test)]
        let _timing = finish_timing::phase(finish_timing::Phase::Reopen);
        require_retained_material(self.revalidate_handles())?;
        require_retained_material(publication.revalidate_retained_handles())?;
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
        #[cfg(test)]
        let step = publication.step();
        #[cfg(test)]
        let result = publication_tests::before_admission(step, &self, owner)
            .and_then(|()| self.admit_publication(owner, publication, reference, plan, wallets));
        #[cfg(not(test))]
        let result = self.admit_publication(owner, publication, reference, plan, wallets);
        // Match the canonical producer: original profile exit outranks every ordinary inner
        // result. No transition capability or borrowed profile verdict survives this point.
        #[cfg(test)]
        let _timing = finish_timing::phase(finish_timing::Phase::ProfileExit);
        owner.authority.validate_profile()?;
        let value = require_retained_material(result)?;
        require_retained_material(value.revalidate_handles())?;
        #[cfg(test)]
        publication_tests::after_admission(step, &value, owner)?;
        Ok(value)
    }

    fn admit_publication(
        mut self,
        owner: &ManagedStreamTokenCustody,
        publication: PublishedBodyDelta,
        reference: (Option<Reference>, RecordSnapshot),
        plan: RetainedProviderServicePlan,
        wallets: Option<&mut FinishWalletReads<'_>>,
    ) -> Result<Self> {
        let root_names = NamesSnapshot::from_read(
            Arc::clone(&self.root),
            4,
            checked_names(&self.root, &SCOPE_ROOT_NAMES, 4)?,
        );
        self.root_snapshots
            .records
            .first()
            .ok_or_else(|| invalid("retained selection snapshot absent"))?
            .revalidate()?;
        self.selection.validate(owner, self.purpose, &plan)?;
        let (reference, reference_record) = reference;
        let reference =
            reference.ok_or_else(|| invalid("publication lost its original reference"))?;
        if !self.reference_present
            || reference.purpose != self.selection.purpose
            || reference.outer != self.selection.digest()?
        {
            return Err(invalid(
                "publication changed its external selection reference",
            ));
        }
        publication.apply(&mut self)?;
        let mut root_records = self.root_snapshots.records.clone();
        if root_records.len() != 3 {
            return Err(invalid("retained root snapshot layout changed"));
        }
        root_records[2] = reference_record;
        self.root_snapshots = Arc::new(Snapshot {
            previous: None,
            records: root_records,
            names: vec![],
            root: Some(Arc::clone(&self.root)),
        });
        let mut expected = Vec::new();
        for body in &self.bodies {
            let name = body_name(body.reservation.ordinal)?;
            expected.push(std::ffi::OsString::from(&name));
            if body.activation.is_some() {
                expected.push(format!("{name}-activation.nrt").into());
            }
            if body.unused.is_some() {
                expected.push(format!("{name}-unused.nrt").into());
            }
        }
        expected.sort();
        let observed = self
            .body_root
            .as_ref()
            .map(|root| root.entries(usize::from(MAX_BODIES) * 3))
            .transpose()?
            .unwrap_or_default();
        if observed != expected || self.bodies.len() > usize::from(MAX_BODIES) {
            return Err(invalid("publication changed the exact body namespace"));
        }
        let mut snapshots = Arc::new(Snapshot {
            previous: Some(Arc::clone(&self.root_snapshots)),
            records: vec![],
            names: self
                .body_root
                .as_ref()
                .map(|root| {
                    NamesSnapshot::from_read(
                        Arc::clone(root),
                        usize::from(MAX_BODIES) * 3,
                        observed,
                    )
                })
                .into_iter()
                .collect(),
            root: None,
        });
        let mut retained_bytes = 0usize;
        for body in &mut self.bodies {
            let records = body.snapshots.records.clone();
            let [reservation, original, _, _] = records.as_slice() else {
                return Err(invalid("retained body snapshot layout changed"));
            };
            let reservation_length = reservation
                .observed
                .ok_or_else(|| invalid("retained reservation bytes absent"))?
                .0;
            add_bytes(&mut retained_bytes, reservation_length)?;
            if let Some((length, _)) = original.observed {
                add_bytes(&mut retained_bytes, length)?;
            }
            snapshots = Arc::new(Snapshot {
                previous: Some(snapshots),
                records,
                names: body.snapshots.names.clone(),
                root: None,
            });
            body.snapshots = Arc::clone(&snapshots);
        }
        if self.bodies.len() != usize::from(self.anchor.highest) {
            let pending = self
                .anchor
                .pending
                .as_ref()
                .ok_or_else(|| invalid("published enrollment body was lost"))?;
            if self.bodies.len() + 1 != usize::from(self.anchor.highest)
                || pending.ordinal != self.anchor.highest
            {
                return Err(invalid("publication changed the bounded body prefix"));
            }
            add_bytes(
                &mut retained_bytes,
                norito::canonical_frame_len(pending)
                    .map_err(|_| invalid("cannot size pending enrollment body"))?,
            )?;
        }
        // This source check is independent of every prior observation and every write receipt.
        // It binds unchanged original bytes and exact new head records before any wallet call.
        snapshots.revalidate()?;
        let previous = PublishedHistory {
            active: self.active.take(),
            closed: self.nearest_closure.take(),
        };
        let mut epochs = crate::managed::native_operation::authorization::EpochReader::default();
        if let CustodyPurpose::Renewal(sequence) = self.purpose {
            epochs.validate_retained(
                &self.root,
                self.selection.digest()?,
                &self.selection.fees,
                crate::managed::native_operation::authorization::Scope::Renewal {
                    provider: owner.authority.provider_id()?,
                    sequence,
                },
            )?;
        }
        drop(plan);
        self.verify_histories_from_with_wallets(
            owner,
            None,
            Some(&previous),
            &mut epochs,
            wallets,
        )?;
        snapshots.revalidate()?;
        root_names.revalidate()?;
        if let Some(graph) = previous.retained_graph() {
            graph.revalidate_retained_handles()?;
        }
        Ok(self)
    }
}

#[cfg(test)]
#[path = "publication_tests.rs"]
mod publication_tests;
