//! One native locked deployment slot and its durable exact journal publication cutover.

use super::*;
use iroha_fs::FileSnapshot;
use norito::derive::{JsonDeserialize, JsonSerialize};
use std::{fs::File, io};

const STATE_FILE: &str = "publication.json";
const MAX_STATE_BYTES: usize = 1024;

#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(
    tag = "state",
    content = "publication",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(super) enum Publication {
    Empty,
    Preparing {
        candidate: String,
        previous: Option<String>,
    },
    Active {
        journal: String,
    },
}

impl Publication {
    fn validate(&self) -> Result<()> {
        match self {
            Self::Empty => Ok(()),
            Self::Active { journal } => validate_journal_id(journal),
            Self::Preparing {
                candidate,
                previous,
            } => {
                validate_journal_id(candidate)?;
                if let Some(previous) = previous {
                    validate_journal_id(previous)?;
                    if previous == candidate {
                        bail!("deployment candidate cannot replace itself");
                    }
                }
                Ok(())
            }
        }
    }
}

/// Locked native slot shared by the managed runtime and package command adapter.
pub(crate) struct DeploymentSlot {
    pub(super) writer: PrivateDirectory,
    lock: File,
    lock_snapshot: FileSnapshot,
    binding: Binding,
}

/// Exact inputs already verified by the compiler owner before slot recovery.
pub(crate) struct RetryRequest<'a> {
    pub code_hash: iroha::crypto::Hash,
    pub alias: &'a ContractAlias,
    pub fee_payment: &'a FeePaymentIntent,
    pub prepare_only: bool,
}

/// Original native plan returned by a fresh retry, optionally after exact recovery.
pub(crate) struct RetainedDeployment {
    pub preflight: DeploymentPreflight,
    pub journal: PathBuf,
    pub receipt: Option<DeploymentReceipt>,
    /// The receipt belongs to a deployment that had already completed before this command, so
    /// later calls such as its activation may have run since.
    pub completed_earlier: bool,
}

enum Binding {
    Managed,
    Package(ContractAlias),
}

impl DeploymentSlot {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        Self::open_bound(path, Binding::Managed)
    }

    pub(crate) fn open_package(path: &Path, alias: ContractAlias) -> Result<Self> {
        Self::open_bound(path, Binding::Package(alias))
    }

    fn open_bound(path: &Path, binding: Binding) -> Result<Self> {
        let parent = PrivateDirectory::open_or_create(
            path.parent()
                .ok_or_else(|| eyre!("deployment slot has no parent"))?,
        )?;
        let name = path
            .file_name()
            .ok_or_else(|| eyre!("deployment slot has no name"))?;
        let directory = if let Some(directory) = parent.open_child_optional(name)? {
            directory
        } else {
            let empty = norito::json::to_vec(&Publication::Empty)?;
            match parent
                .publish_private_child(name, &[("deployment.lock", b""), (STATE_FILE, &empty)])
            {
                Ok(directory) => directory,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    parent.open_child(name)?
                }
                Err(error) => return Err(error.into()),
            }
        };
        Self::from_directory(directory, binding)
    }

    pub(crate) fn open_read(path: &Path) -> Result<Self> {
        Self::from_directory(PrivateDirectory::open(path)?, Binding::Managed)
    }

    pub(crate) fn open_package_read(path: &Path, alias: ContractAlias) -> Result<Self> {
        Self::from_directory(PrivateDirectory::open(path)?, Binding::Package(alias))
    }

    fn from_directory(writer: PrivateDirectory, binding: Binding) -> Result<Self> {
        // Existing custody is never repaired: both lock and state arrive in one publication.
        let lock = writer.open_read("deployment.lock")?;
        lock.try_lock()
            .wrap_err("deployment target is already in use")?;
        let lock_snapshot = FileSnapshot::private_journal(&lock)?;
        let slot = Self {
            writer,
            lock,
            lock_snapshot,
            binding,
        };
        slot.read_state()?;
        Ok(slot)
    }

    pub(super) fn revalidate(&self) -> Result<()> {
        self.writer.revalidate()?;
        let named = self.writer.open_read("deployment.lock")?;
        if FileSnapshot::private_journal(&named)? != self.lock_snapshot
            || FileSnapshot::private_journal(&self.lock)? != self.lock_snapshot
        {
            bail!("deployment slot lock changed from its original snapshot");
        }
        self.writer.revalidate()?;
        Ok(())
    }

    pub(super) fn read_state(&self) -> Result<Publication> {
        self.revalidate()?;
        if self.writer.read_optional("active-journal", 64)?.is_some() {
            bail!("retired deployment active-journal layout is not supported");
        }
        let result = (|| {
            let state: Publication =
                norito::json::from_slice(&self.writer.read(STATE_FILE, MAX_STATE_BYTES)?)?;
            state.validate()?;
            Ok(state)
        })();
        self.revalidate()?;
        result
    }

    pub(super) fn write_state(&self, state: &Publication) -> Result<()> {
        state.validate()?;
        self.revalidate()?;
        let bytes = norito::json::to_json_bounded(state, MAX_STATE_BYTES)?;
        let result = self
            .writer
            .write_atomic(STATE_FILE, bytes.as_bytes(), PublishMode::Replace);
        self.revalidate()?;
        result.map_err(Into::into)
    }

    pub(crate) fn current_journal(&self) -> Result<Option<PathBuf>> {
        match self.read_state()? {
            Publication::Empty => Ok(None),
            Publication::Active { journal } => Ok(Some(self.writer.path().join(journal))),
            Publication::Preparing { candidate, .. } => bail!(
                "deployment journal publication requires recovery: {}",
                self.writer.path().join(candidate).display()
            ),
        }
    }

    fn authenticate(
        &self,
        service: &DeploymentService,
        journal: &Path,
    ) -> Result<DeploymentPreflight> {
        self.revalidate()?;
        let retained = service
            .retained_preflight(journal)
            .map_err(|error| journal_failure(error, journal))?;
        self.validate_binding(&retained)?;
        let id = plan_journal_id(&retained)?;
        if self.writer.path().join(&id) != journal {
            bail!("deployment journal differs from its authenticated slot and commit");
        }
        self.revalidate()?;
        Ok(retained)
    }

    fn validate_binding(&self, retained: &DeploymentPreflight) -> Result<()> {
        match &self.binding {
            Binding::Managed => {
                let expected = deployment_slot_name(
                    &retained.network_id,
                    retained.chain_discriminant,
                    &retained.authority,
                    &retained.contract_alias,
                );
                if self
                    .writer
                    .path()
                    .file_name()
                    .and_then(|name| name.to_str())
                    != Some(expected.as_str())
                {
                    bail!("deployment candidate belongs to another managed alias slot");
                }
            }
            Binding::Package(alias) if alias != &retained.contract_alias => {
                bail!("deployment candidate differs from the selected package alias binding")
            }
            Binding::Package(_) => {}
        }
        Ok(())
    }

    /// Complete a durably intended publication, or roll back only native-proven absence.
    /// The native service atomically publishes lock+plan before this coordinator admits Active.
    pub(crate) fn reconcile(&self, service: &DeploymentService) -> Result<Option<PathBuf>> {
        let Publication::Preparing {
            candidate,
            previous,
        } = self.read_state()?
        else {
            return self.current_journal();
        };
        let candidate_path = self.writer.path().join(&candidate);
        match self.writer.open_child_optional(&candidate)? {
            Some(directory) => {
                self.authenticate(service, &candidate_path)?;
                directory.revalidate()?;
                self.write_state(&Publication::Active { journal: candidate })?;
            }
            None => {
                // An absent atomic destination never reached Active, so no slot-owned dispatch
                // was authorized. Preserve all staging siblings and the exact predecessor.
                let restored = match previous {
                    Some(journal) => {
                        self.authenticate(service, &self.writer.path().join(&journal))?;
                        Publication::Active { journal }
                    }
                    None => Publication::Empty,
                };
                self.write_state(&restored)?;
            }
        }
        self.current_journal()
    }

    /// Classify a requested candidate before requiring its path to exist.
    pub(crate) fn admit_resume(&self, service: &DeploymentService, journal: &Path) -> Result<()> {
        if let Publication::Preparing { candidate, .. } = self.read_state()? {
            if self.writer.path().join(&candidate) == journal
                && self.reconcile(service)?.as_deref() != Some(journal)
            {
                bail!(
                    "the original deployment plan was never published; repeat the original deploy command: {}",
                    journal.display()
                );
            }
        }
        Ok(())
    }

    /// Recover the original reviewed plan; historical completion never moves publication backward.
    pub(crate) fn resume(
        &self,
        service: &DeploymentService,
        journal: &Path,
        expected: &DeploymentPreflight,
        progress: &mut dyn FnMut(DeploymentProgress),
    ) -> Result<DeploymentReceipt> {
        self.admit_resume(service, journal)?;
        let retained = self.authenticate(service, journal)?;
        retained.require_same_plan(expected)?;
        let id = plan_journal_id(&retained)?;
        match self.read_state()? {
            Publication::Active { journal: active } if active == id => {
                // Re-establish durable publication after a prior ambiguous directory sync.
                self.write_state(&Publication::Active { journal: id })?;
                self.revalidate()?;
                #[cfg(test)]
                resume_open_test_support::run();
                let result = service
                    .resume(journal, &mut |event| {
                        if let DeploymentProgress::Prepared(actual) = &event {
                            actual.require_same_plan(expected)?;
                        }
                        progress(event);
                        self.revalidate().map_err(DeploymentError::Journal)
                    })
                    .map_err(|error| journal_failure(error, journal));
                self.revalidate()?;
                result
            }
            Publication::Empty => bail!(
                "deployment journal is not admitted by this slot's publication state: {}",
                journal.display()
            ),
            Publication::Active { .. } | Publication::Preparing { .. } => {
                let receipt = service
                    .completed_receipt(journal, expected)
                    .map_err(|error| journal_failure(error, journal))?;
                self.revalidate()?;
                receipt.ok_or_else(|| eyre!("another deployment is active; unfinished recovery cannot replace its journal: {}", journal.display()))
            }
        }
    }

    pub(crate) fn cancel(
        &self,
        service: &DeploymentService,
        journal: &Path,
    ) -> Result<iroha_contract_deploy::DeploymentCancellation> {
        self.admit_resume(service, journal)?;
        let retained = self.authenticate(service, journal)?;
        let id = plan_journal_id(&retained)?;
        if self.read_state()? != (Publication::Active { journal: id }) {
            bail!("only the exact active deployment may be cancelled in this slot");
        }
        self.revalidate()?;
        let cancellation = service
            .cancel(journal, &retained)
            .map_err(|error| journal_failure(error, journal))?;
        self.revalidate()?;
        Ok(cancellation)
    }

    /// Reuse the exact saved plan before either consumer prepares new paid transactions.
    pub(crate) fn recover_matching(
        &self,
        service: &DeploymentService,
        request: RetryRequest<'_>,
        review: &mut dyn FnMut(&DeploymentPreflight) -> Result<()>,
        progress: &mut dyn FnMut(DeploymentProgress),
    ) -> Result<Option<RetainedDeployment>> {
        let Some(journal) = self.reconcile(service)? else {
            return Ok(None);
        };
        let retained = self.authenticate(service, &journal)?;
        let same_input =
            retained.code_hash == request.code_hash && &retained.contract_alias == request.alias;
        let inspect = || {
            self.authenticate(service, &journal)?
                .require_same_plan(&retained)?;
            service
                .inspect_journal(&journal, &retained)
                .map_err(|error| journal_failure(error, &journal))
        };
        let disposition = if same_input {
            after_review(&retained, review, inspect)?
        } else {
            inspect()?
        };
        self.revalidate()?;
        let completed_earlier = matches!(disposition, JournalDisposition::Completed(_));
        let receipt = match disposition {
            JournalDisposition::Pending { .. } if same_input => {
                if retained.fee_quotes.iter().any(|quote| {
                    !request.fee_payment.has_same_payer_and_gas_bound(&quote.intent)
                }) {
                    bail!(
                        "pending deployment uses a different fee payer or gas bound; resume its exact journal: {}",
                        journal.display()
                    );
                }
                if request.prepare_only {
                    None
                } else {
                    Some(self.resume(service, &journal, &retained, progress)?)
                }
            }
            JournalDisposition::Pending { .. } => bail!(
                "an earlier deployment has different unresolved artifact or alias inputs; resume its exact journal: {}",
                journal.display()
            ),
            JournalDisposition::Completed(_) if same_input => Some(service
                .current_completed_receipt(&journal, &retained)
                .map_err(|error| journal_failure(error, &journal))?
                .ok_or_else(|| eyre!(
                    "completed deployment lost its authenticated receipt\nDeployment journal: {}",
                    journal.display()
                ))?),
            JournalDisposition::Completed(_)
            | JournalDisposition::Failed(_)
            | JournalDisposition::Cancelled(_) => return Ok(None),
        };
        self.revalidate()?;
        Ok(Some(RetainedDeployment {
            preflight: retained,
            journal,
            receipt,
            completed_earlier,
        }))
    }

    pub(crate) fn execute(
        &self,
        service: &DeploymentService,
        prepared: &PreparedDeployment,
        journal: &Path,
        progress: &mut dyn FnMut(DeploymentProgress),
    ) -> Result<DeploymentReceipt> {
        self.validate_binding(prepared.preflight())?;
        let id = plan_journal_id(prepared.preflight())?;
        if self.writer.path().join(&id) != journal
            || self.read_state()? != (Publication::Active { journal: id })
        {
            bail!("deployment must retain durable Active publication before dispatch");
        }
        self.revalidate()?;
        let result = service
            .execute(prepared, journal, &mut |event| {
                progress(event);
                self.revalidate().map_err(DeploymentError::Journal)
            })
            .map_err(|error| journal_failure(error, journal));
        self.revalidate()?;
        result
    }

    pub(crate) fn persist(
        &self,
        service: &DeploymentService,
        prepared: &PreparedDeployment,
    ) -> Result<PathBuf> {
        self.validate_binding(prepared.preflight())?;
        let id = plan_journal_id(prepared.preflight())?;
        let journal = self.writer.path().join(&id);
        let previous = match self.read_state()? {
            Publication::Empty => None,
            Publication::Active { journal: current } if current == id => {
                self.authenticate(service, &journal)?;
                service
                    .persist(prepared, &journal)
                    .map_err(|error| journal_failure(error, &journal))?;
                self.write_state(&Publication::Active { journal: id })?;
                return Ok(journal);
            }
            Publication::Active { journal } => Some(journal),
            Publication::Preparing { candidate, .. } => bail!(
                "deployment publication must be reconciled before preparing another plan: {}",
                self.writer.path().join(candidate).display()
            ),
        };
        self.write_state(&Publication::Preparing {
            candidate: id.clone(),
            previous,
        })?;
        service
            .persist(prepared, &journal)
            .map_err(|error| journal_failure(error, &journal))?;
        self.revalidate()?;
        self.write_state(&Publication::Active { journal: id })?;
        Ok(journal)
    }
}

#[cfg(test)]
pub(super) mod resume_open_test_support {
    //! One-shot mutation at the actual authenticate-to-resume journal-open boundary.

    use std::cell::RefCell;

    thread_local! {
        static BEFORE_OPEN: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
    }

    pub(super) fn run() {
        let hook = BEFORE_OPEN.with(|slot| slot.borrow_mut().take());
        if let Some(hook) = hook {
            hook();
        }
    }

    /// Run one scoped boundary mutation, clearing an unused hook on refusal or unwind.
    pub(crate) fn with_before_open<R>(
        hook: impl FnOnce() + 'static,
        action: impl FnOnce() -> R,
    ) -> R {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                BEFORE_OPEN.with(|slot| {
                    slot.borrow_mut().take();
                });
            }
        }
        BEFORE_OPEN.with(|slot| {
            assert!(
                slot.borrow().is_none(),
                "resume-open fixture is already active"
            );
            *slot.borrow_mut() = Some(Box::new(hook));
        });
        let _reset = Reset;
        action()
    }
}
