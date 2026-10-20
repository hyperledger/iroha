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
        let names = checked_names(&directory, &["reserved.nrt", "operation.nrt"], 2)?;
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
            names: vec![NamesSnapshot::from_reserved_read(
                Arc::clone(&directory),
                names,
            )],
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

// Local preparation is shared with complete publication admission. It contains fresh
// observations for this read only; no epoch or source verdict survives into activation.
struct PreparedPublication {
    root_names: NamesSnapshot,
    snapshots: Arc<Snapshot>,
    epochs: crate::managed::native_operation::authorization::EpochReader,
}

// These are the original native owners, retained independently of the incomplete value
// consumed by C. There is no cached source, authority or validation result. In particular,
// unsigned bodies absent from the retained graph keep their exact directory owners too.
struct ActivationOwners {
    root: Arc<PrivateDirectory>,
    container: Arc<PrivateDirectory>,
    bodies: Vec<Arc<PrivateDirectory>>,
    graph: Option<std::rc::Rc<History>>,
}
impl ActivationOwners {
    fn retain(history: &BodyHistory, publication: &PublishedBodyDelta) -> Result<Self> {
        if history.active.is_some() || history.bodies.len() > usize::from(MAX_BODIES) {
            return Err(invalid(
                "activation staging changed its bounded original owners",
            ));
        }
        let container = history
            .body_root
            .as_ref()
            .ok_or_else(|| invalid("activation staging lost its original body container"))?;
        let mut bodies = Vec::new();
        bodies
            .try_reserve_exact(history.bodies.len())
            .map_err(|_| invalid("cannot retain bounded activation directory owners"))?;
        bodies.extend(
            history
                .bodies
                .iter()
                .map(|body| Arc::clone(&body.directory)),
        );
        let graph = match publication {
            PublishedBodyDelta::Closed { closure, .. } => {
                Some(std::rc::Rc::clone(closure.shared_history()))
            }
            _ => history
                .nearest_closure
                .as_ref()
                .map(|closure| std::rc::Rc::clone(closure.shared_history())),
        };
        Ok(Self {
            root: Arc::clone(&history.root),
            container: Arc::clone(container),
            bodies,
            graph,
        })
    }

    fn revalidate(&self) -> Result<()> {
        #[cfg(test)]
        let _timing = finish_timing::phase(finish_timing::Phase::BodyHandleRevalidate);
        self.root.read_tree_scope(|tree| {
            tree.revalidate_directory(&self.container)?;
            for body in &self.bodies {
                tree.revalidate_directory(body)?;
            }
            if let Some(graph) = &self.graph {
                graph.revalidate_retained_handles_in_tree(Some(&mut *tree))?;
            }
            Ok(())
        })
    }
}

// This incomplete body owner cannot leave publication.rs. Its only consuming production
// method permits the two existing unsigned local writes, then full canonical C admission.
// It cannot dispatch, sign, retire a wallet, renew authority or return a usable BodyHistory.
struct ActivationStaging {
    history: BodyHistory,
    body_root: Arc<PrivateDirectory>,
    ordinal: u8,
    retirement: [u8; 32],
    owners: ActivationOwners,
}
impl ActivationStaging {
    fn eligible(
        history: &BodyHistory,
        body_root: &Arc<PrivateDirectory>,
        publication: &PublishedBodyDelta,
    ) -> bool {
        #[cfg(test)]
        if activation_staging_tests::original_recipe() {
            return false;
        }
        if norito::core::decode_limits_active()
            || history.active.is_some()
            || !history
                .body_root
                .as_ref()
                .is_some_and(|root| Arc::ptr_eq(root, body_root))
            || history
                .bodies
                .last()
                .is_none_or(|body| body.activation.is_some() || body.original.is_some())
        {
            return false;
        }
        match publication {
            PublishedBodyDelta::Closed { root, .. } | PublishedBodyDelta::Unused { root, .. } => {
                Arc::ptr_eq(&history.root, root)
            }
            _ => false,
        }
    }

    fn bind(
        history: &BodyHistory,
        ordinal: u8,
        retirement: [u8; 32],
        publication: &PublishedBodyDelta,
    ) -> Result<()> {
        let pending = history
            .anchor
            .pending
            .as_ref()
            .ok_or_else(|| invalid("activation staging lost its pending reservation"))?;
        if ordinal <= 1
            || pending.ordinal != ordinal
            || history.anchor.highest != ordinal
            || history.bodies.len() != usize::from(ordinal)
        {
            return Err(invalid(
                "activation staging selected another bounded successor",
            ));
        }
        let previous = &history.bodies[usize::from(ordinal) - 2];
        let current = &history.bodies[usize::from(ordinal) - 1];
        let successor = pending.digest()?;
        if current.reservation.digest()? != successor
            || current.activation.is_some()
            || current.original.is_some()
            || current.unused.is_some()
            || previous.reservation.ordinal != ordinal - 1
        {
            return Err(invalid(
                "activation staging changed its exact reserved body",
            ));
        }
        let bound = match publication {
            PublishedBodyDelta::Closed {
                root,
                ordinal: closed,
                closure,
            } => {
                Arc::ptr_eq(&history.root, root)
                    && *closed == ordinal - 1
                    && closure.digest() == retirement
                    && closure.successor_selection() == successor
                    && previous.semantic == Some(closure.closed_semantic())
                    && previous.original.is_some()
                    && closure.purpose() == history.selection.purpose
                    && history.active.is_none()
            }
            PublishedBodyDelta::Unused {
                root,
                ordinal: unused,
                value,
                ..
            } => {
                Arc::ptr_eq(&history.root, root)
                    && *unused == ordinal - 1
                    && previous.original.is_none()
                    && previous.unused.is_none()
                    && value.reservation == previous.reservation.digest()?
                    && value.successor == successor
                    && attempts::semantic_digest(value, MAX_SELECTION_BYTES)? == retirement
            }
            _ => false,
        };
        if !bound {
            return Err(invalid(
                "activation staging changed its exact predecessor retirement",
            ));
        }
        Ok(())
    }

    fn prepare(
        mut history: BodyHistory,
        owner: &ManagedStreamTokenCustody,
        body_root: Arc<PrivateDirectory>,
        ordinal: u8,
        retirement: [u8; 32],
        publication: PublishedBodyDelta,
    ) -> Result<Self> {
        let owners = ActivationOwners::retain(&history, &publication)?;
        let result = (|| {
            let (reference, plan) = history.publication_inputs(owner, &publication)?;
            #[cfg(test)]
            activation_staging_tests::before_prepare(&history, &publication)?;
            Self::bind(&history, ordinal, retirement, &publication)?;
            let prepared = history.prepare_publication(owner, publication, reference, plan)?;
            #[cfg(test)]
            let result = activation_staging_tests::after_prepare(&history, owner);
            #[cfg(not(test))]
            let result = Ok::<_, crate::managed::Error>(());
            // These checks close even an ordinary inner refusal. The fresh complete linked
            // source snapshots are rebuilt by the same producer used by full admission.
            prepared.snapshots.revalidate()?;
            prepared.root_names.revalidate()?;
            result?;
            // Drop the pure read workspace before any activation write or later parser.
            drop(prepared);
            Ok::<_, crate::managed::Error>(())
        })();
        let handles = owners.revalidate();
        // Original profile refusal keeps precedence over ordinary inner/source errors.
        owner.authority.validate_profile()?;
        require_retained_material(handles)?;
        require_retained_material(result)?;
        Ok(Self {
            history,
            body_root,
            ordinal,
            retirement,
            owners,
        })
    }

    fn activate(
        self,
        owner: &ManagedStreamTokenCustody,
        turn: &SigningTurn<'_>,
        deadline: Instant,
        wallets: &mut FinishWalletReads<'_>,
    ) -> Result<BodyHistory> {
        #[cfg(test)]
        if let Some(limits) = activation_staging_tests::take_late_limits() {
            return norito::core::with_decode_limits_scope(limits, || {
                self.activate(owner, turn, deadline, wallets)
            });
        }
        let Self {
            mut history,
            body_root,
            ordinal,
            retirement,
            owners,
        } = self;
        let result = (|| {
            // A resource owner installed after preparation receives the complete original B
            // recovery path. Already prepared bytes grant no allocation or authority exemption.
            if norito::core::decode_limits_active() {
                wallets.clear();
                history = history.reopen(owner)?;
                return history.publish_activation(
                    owner,
                    &body_root,
                    ordinal,
                    Some(retirement),
                    turn,
                    deadline,
                    wallets,
                );
            }
            let publication =
                history.write_activation(&body_root, ordinal, Some(retirement), turn, deadline);
            let handles = owners.revalidate();
            owner.authority.validate_profile()?;
            let publication = require_retained_material(handles).and_then(|()| publication)?;
            // Full C is mandatory before signing, expiry return or any other usable owner.
            // A changed wallet/history may now refuse after unsigned local staging metadata;
            // crash/error recovery also uses this same canonical parser before any authority.
            history.reopen_after_publication_with_wallets(owner, publication, Some(wallets))
        })();
        // C consumes the incomplete BodyHistory even when it refuses. Independently retained
        // original directories and graph close on every ordinary result before they are dropped.
        let handles = owners.revalidate();
        owner.authority.validate_profile()?;
        require_retained_material(handles)?;
        result
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
        let (reference, plan) = self.publication_inputs(owner, &publication)?;
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

    fn publication_inputs(
        &self,
        owner: &ManagedStreamTokenCustody,
        publication: &PublishedBodyDelta,
    ) -> Result<(
        (Option<Reference>, RecordSnapshot),
        RetainedProviderServicePlan,
    )> {
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
        Ok((reference, plan))
    }

    fn admit_publication(
        mut self,
        owner: &ManagedStreamTokenCustody,
        publication: PublishedBodyDelta,
        reference: (Option<Reference>, RecordSnapshot),
        plan: RetainedProviderServicePlan,
        wallets: Option<&mut FinishWalletReads<'_>>,
    ) -> Result<Self> {
        let PreparedPublication {
            root_names,
            snapshots,
            mut epochs,
        } = self.prepare_publication(owner, publication, reference, plan)?;
        let previous = PublishedHistory {
            active: self.active.take(),
            closed: self.nearest_closure.take(),
        };
        self.verify_histories_from_with_wallets(
            owner,
            None,
            Some(&previous),
            &mut epochs,
            wallets,
            Some(&snapshots),
        )?;
        root_names.revalidate()?;
        if let Some(graph) = previous.retained_graph() {
            graph.revalidate_retained_handles()?;
        }
        Ok(self)
    }
    fn prepare_publication(
        &mut self,
        owner: &ManagedStreamTokenCustody,
        publication: PublishedBodyDelta,
        reference: (Option<Reference>, RecordSnapshot),
        plan: RetainedProviderServicePlan,
    ) -> Result<PreparedPublication> {
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
        publication.apply(self)?;
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
        Ok(PreparedPublication {
            root_names,
            snapshots,
            epochs,
        })
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "One concrete activation boundary retains its original owner, turn and deadline"
    )]
    pub(super) fn activate_reserved_body(
        mut self,
        owner: &ManagedStreamTokenCustody,
        body_root: &Arc<PrivateDirectory>,
        ordinal: u8,
        previous_retirement: Option<[u8; 32]>,
        retirement: Option<PublishedBodyDelta>,
        turn: &SigningTurn<'_>,
        deadline: Instant,
        wallets: &mut FinishWalletReads<'_>,
    ) -> Result<Self> {
        if let Some(digest) = previous_retirement {
            match retirement {
                Some(publication)
                    if ActivationStaging::eligible(&self, body_root, &publication) =>
                {
                    let result = ActivationStaging::prepare(
                        self,
                        owner,
                        Arc::clone(body_root),
                        ordinal,
                        digest,
                        publication,
                    )
                    .and_then(|staged| staged.activate(owner, turn, deadline, wallets));
                    if result.is_err() {
                        wallets.clear();
                    }
                    return result;
                }
                publication => {
                    // Existing/crashed, foreign and inherited-decoder prefixes retain full B.
                    self = self.reopen_after_publication_with_wallets(
                        owner,
                        publication,
                        Some(wallets),
                    )?;
                }
            }
        }
        self.publish_activation(
            owner,
            body_root,
            ordinal,
            previous_retirement,
            turn,
            deadline,
            wallets,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "The sole local activation writer preserves all original mutation inputs"
    )]
    fn publish_activation(
        self,
        owner: &ManagedStreamTokenCustody,
        body_root: &Arc<PrivateDirectory>,
        ordinal: u8,
        previous_retirement: Option<[u8; 32]>,
        turn: &SigningTurn<'_>,
        deadline: Instant,
        wallets: &mut FinishWalletReads<'_>,
    ) -> Result<Self> {
        let publication =
            self.write_activation(body_root, ordinal, previous_retirement, turn, deadline)?;
        self.reopen_after_publication_with_wallets(owner, publication, Some(wallets))
    }

    fn write_activation(
        &self,
        body_root: &Arc<PrivateDirectory>,
        ordinal: u8,
        previous_retirement: Option<[u8; 32]>,
        turn: &SigningTurn<'_>,
        deadline: Instant,
    ) -> Result<Option<PublishedBodyDelta>> {
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
            body_root,
            &format!("{ordinal:04}-activation.nrt"),
            &activation,
            MAX_SELECTION_BYTES,
        )?;
        #[cfg(test)]
        activation_staging_tests::after_write(
            activation_staging_tests::Point::ActivationWritten,
            self,
        )?;
        turn.check(&self.selection, deadline)?;
        let anchor = self.replace_anchor(&Anchor {
            outer: self.selection.digest()?,
            highest: ordinal,
            active: Some(ordinal),
            completed: None,
            pending: None,
        })?;
        #[cfg(test)]
        activation_staging_tests::after_write(
            activation_staging_tests::Point::AnchorWritten,
            self,
        )?;
        let publication = if self.bodies[usize::from(ordinal) - 1].activation.is_none() {
            anchor
                .map(|anchor| PublishedBodyDelta::activated(self, ordinal, &activation, anchor))
                .transpose()?
        } else {
            // A pre-existing activation is a recovery prefix, even when its bytes match.
            None
        };
        Ok(publication)
    }
}

#[cfg(test)]
#[path = "publication_tests.rs"]
mod publication_tests;

#[cfg(test)]
#[path = "publication_close_tests.rs"]
mod publication_close_tests;

#[cfg(test)]
#[path = "activation_staging_tests.rs"]
mod activation_staging_tests;
