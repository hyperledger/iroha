//! Caller-owned complete World preparation and exact retry custody.

use super::*;

struct Fields<'target, Admission> {
    mode: BlockMode,
    fields: PreparedWorldFields<'target>,
    retry: Vec<Box<dyn RetainedWorldField>>,
    dataspace_catalog: Option<DataSpaceCatalog>,
    external_event_buf: Option<Vec<EventBox>>,
    shells: Option<WorldJournalShellReservation>,
    admission: Option<Admission>,
}

enum Phase<'target, Admission> {
    Original(DetachedWorld<Admission>),
    Fields(Fields<'target, Admission>),
}

/// An inert World owner installed with every enclosing State participant.
/// Preparation and terminal physical release borrow this same owner; neither
/// a partial field acquisition nor its notification escapes through a callee.
pub(in crate::state) struct WorldPublicationSlot<'target, Admission, Installation> {
    target: &'target World,
    phase: Option<Phase<'target, Admission>>,
    attempted: bool,
    retryable: bool,
    complete: bool,
    released: bool,
    installation: Option<Installation>,
    shell_installation: Option<WorldJournalShellInstallation>,
}

impl<Admission> DetachedWorld<Admission> {
    /// Move the exact World into its caller without probing or allocating.
    pub(in crate::state) fn publication_slot<'target, Installation>(
        self,
        target: &'target World,
    ) -> WorldPublicationSlot<'target, Admission, Installation> {
        WorldPublicationSlot {
            target,
            phase: Some(Phase::Original(self)),
            attempted: false,
            retryable: true,
            complete: false,
            released: false,
            installation: None,
            shell_installation: None,
        }
    }
}

impl<'target, Admission, Installation> WorldPublicationSlot<'target, Admission, Installation> {
    fn original(&self) -> &DetachedWorld<Admission> {
        let Some(Phase::Original(original)) = self.phase.as_ref() else {
            panic!("original unattempted World");
        };
        original
    }

    /// Admit the whole installation, install every inert field, then prepare.
    pub(in crate::state) fn try_prepare<E>(
        &mut self,
        admit: impl FnOnce(&DetachedWorld<Admission>, &World) -> Result<Installation, E>,
    ) -> Result<(), WorldPublicationError<E>> {
        assert!(
            !self.attempted && !self.released,
            "World preparation is one-shot"
        );
        self.attempted = true;
        self.retryable = false;
        self.shell_installation = match self.original().shells.try_install() {
            Ok(lease) => Some(lease),
            Err(error) => {
                self.retryable = true;
                return Err(WorldPublicationError::ShellsNotRetired(error));
            }
        };
        let installation = match admit(self.original(), self.target) {
            Ok(installation) => installation,
            Err(error) => {
                self.retryable = true;
                return Err(WorldPublicationError::Admission(error));
            }
        };
        self.installation = Some(installation);
        // This is the existing admitted prepared Vec. The original stays in the
        // caller while allocating; its allocation becomes the exact retry Vec.
        let fields = PreparedWorldFields(Vec::with_capacity(self.original().fields.len()));
        let Some(Phase::Original(original)) = self.phase.take() else {
            unreachable!("checked original World");
        };
        let DetachedWorld {
            mode,
            fields: retry,
            dataspace_catalog,
            external_event_buf,
            shells,
            admission,
        } = original;
        self.phase = Some(Phase::Fields(Fields {
            mode,
            fields,
            retry,
            dataspace_catalog: Some(dataspace_catalog),
            external_event_buf: Some(external_event_buf),
            shells: Some(shells),
            admission: Some(admission),
        }));
        let Some(Phase::Fields(fields)) = self.phase.as_mut() else {
            unreachable!("installed original World fields");
        };
        fields.retry.reverse();
        while let Some(original) = fields.retry.pop() {
            fields.fields.push(original.publication_slot(self.target));
        }
        // Every shell and its original journal is already in this caller before
        // the first physical acquisition or a native field preparation can panic.
        for field in fields.fields.iter_mut() {
            if let Err(error) = field.try_prepare() {
                self.retryable = true;
                return Err(WorldPublicationError::Field(error));
            }
        }
        self.complete = true;
        self.retryable = true;
        Ok(())
    }

    /// Recover all exact original boxes and the same original Vec allocation.
    /// The retained shells keep every real notification until outer retirement.
    pub(in crate::state) fn recover_original(&mut self) -> DetachedWorld<Admission> {
        assert!(
            self.retryable && !self.released,
            "unwound or released World is not retry authority"
        );
        self.complete = false;
        self.released = true;
        if matches!(self.phase, Some(Phase::Original(_))) {
            let Some(Phase::Original(original)) = self.phase.take() else {
                unreachable!("checked original World phase");
            };
            return original;
        }
        let Some(Phase::Fields(fields)) = self.phase.as_mut() else {
            unreachable!("original World fields");
        };
        assert!(
            fields.retry.is_empty() && fields.retry.capacity() >= fields.fields.len(),
            "original retry allocation"
        );
        // Normal recovery precedes terminal release: these slots still have the
        // original retry authority. Each physical release remains deferred.
        fields.fields.recover_all();
        fields
            .retry
            .extend(fields.fields.iter_mut().map(|field| field.abort()));
        DetachedWorld {
            mode: fields.mode,
            fields: std::mem::take(&mut fields.retry),
            dataspace_catalog: fields.dataspace_catalog.take().expect("original catalog"),
            external_event_buf: fields.external_event_buf.take().expect("original events"),
            shells: fields.shells.take().expect("original shell capacity"),
            admission: fields.admission.take().expect("original capture admission"),
        }
    }

    /// Terminally unlock every physical field while retaining all other owners.
    pub(in crate::state) fn release_writers(&mut self) {
        self.released = true;
        self.retryable = false;
        self.complete = false;
        if let Some(Phase::Fields(fields)) = self.phase.as_mut() {
            fields.fields.release_all();
        }
    }

    /// Move only a complete original participant into the existing publisher.
    pub(in crate::state) fn into_prepared(
        mut self,
    ) -> PreparedWorld<'target, Admission, Installation> {
        assert!(
            self.complete && !self.released,
            "complete original World preparation"
        );
        let Some(Phase::Fields(fields)) = self.phase.take() else {
            unreachable!("checked complete World fields");
        };
        self.released = true;
        PreparedWorld {
            mode: fields.mode,
            fields: fields.fields,
            retry: fields.retry,
            dataspace_catalog: fields.dataspace_catalog.expect("original catalog"),
            external_event_buf: fields.external_event_buf.expect("original events"),
            shells: fields.shells.expect("original shell capacity"),
            shell_installation: self
                .shell_installation
                .take()
                .expect("original shell installation"),
            admission: fields.admission.expect("original capture admission"),
            installation: self.installation.take().expect("original installation"),
        }
    }

    pub(super) fn into_cleanup(mut self) -> AbortedWorld<'target, Installation> {
        assert!(self.released, "original World must be recovered");
        if let Some(Phase::Fields(fields)) = self.phase.as_ref() {
            assert!(
                fields.admission.is_none()
                    && fields.dataspace_catalog.is_none()
                    && fields.external_event_buf.is_none(),
                "complete original recovery before cleanup"
            );
        }
        let fields = match self.phase.take() {
            Some(Phase::Fields(fields)) => fields.fields,
            None => PreparedWorldFields(Vec::new()),
            Some(Phase::Original(_)) => panic!("original World is not cleanup"),
        };
        AbortedWorld {
            _fields: fields,
            _installation: self.installation.take(),
            _shell_installation: self.shell_installation.take(),
        }
    }
}

impl<Admission, Installation> Drop for WorldPublicationSlot<'_, Admission, Installation> {
    fn drop(&mut self) {
        self.release_writers();
    }
}
