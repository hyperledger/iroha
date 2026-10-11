//! Private retained generations, context selection, and foreground control operations.

use super::*;
use iroha_fs::{PrivateDirectory, PublishMode};
use std::{
    fs::{self, File},
    io::{Read as _, Seek as _, SeekFrom},
    net::{Ipv4Addr, TcpListener},
    path::Path,
    process::{Command, Stdio},
    thread,
    time::Instant,
};

/// Held loopback reservations for the four Torii and four P2P listeners.
///
/// Keep this value alive until preparation finishes; the native worker acquires the actual
/// listeners immediately after these reservations are released.
pub struct LocalnetPorts {
    /// First of four consecutive Torii ports.
    pub base_api: u16,
    /// First of four consecutive P2P ports.
    pub base_p2p: u16,
    reservations: Vec<TcpListener>,
}

impl LocalnetPorts {
    /// Reserve two disjoint four-port blocks on IPv4 loopback.
    ///
    /// # Errors
    /// Returns an error when the operating system cannot allocate the listeners.
    pub fn reserve() -> Result<Self> {
        let (base_api, mut reservations) = reserve_block(8080)?;
        let (base_p2p, p2p) = reserve_block(1337)?;
        reservations.extend(p2p);
        Ok(Self {
            base_api,
            base_p2p,
            reservations,
        })
    }

    /// Number of sockets still reserved by this preparation.
    #[must_use]
    pub fn reserved_count(&self) -> usize {
        self.reservations.len()
    }
}

fn reserve_block(preferred: u16) -> Result<(u16, Vec<TcpListener>)> {
    for attempt in 0..128 {
        let base = if attempt == 0 {
            preferred
        } else {
            let probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
            probe.local_addr()?.port()
        };
        if base > u16::MAX - 3 {
            continue;
        }
        let mut listeners = Vec::with_capacity(4);
        for offset in 0..4 {
            match TcpListener::bind((Ipv4Addr::LOCALHOST, base + offset)) {
                Ok(listener) => listeners.push(listener),
                Err(_) => break,
            }
        }
        if listeners.len() == 4 {
            return Ok((base, listeners));
        }
    }
    Err(Error::Invalid(
        "cannot reserve four consecutive loopback ports".into(),
    ))
}

/// Owner-private managed contexts and their retained localnet generations.
pub struct ManagedStore {
    root: PrivateDirectory,
    networks: PrivateDirectory,
}

/// Whether successful startup also changes the workspace's default environment.
#[derive(Clone, Copy)]
pub(super) enum StartupSelection {
    Select,
    Preserve,
}

impl StartupSelection {
    pub(super) fn for_requested_context(requested: Option<&str>) -> Self {
        if requested.is_some() {
            Self::Preserve
        } else {
            Self::Select
        }
    }

    pub(super) fn apply(
        self,
        store: &ManagedStore,
        expected: &ManagedContext,
        observe: impl FnOnce() -> Result<ManagedStatus>,
    ) -> Result<ManagedStatus> {
        // Complete generation custody and encoding before the final Ready/deadline check.
        // Only the uninterruptible native selection publication follows admitted readiness.
        let selection = if matches!(self, Self::Select) {
            let (context, bytes) = store.prepare_selection(&expected.name)?;
            if context != *expected {
                return Err(Error::Invalid(
                    "managed generation changed before startup selection".into(),
                ));
            }
            Some(bytes)
        } else {
            None
        };
        let status = observe()?;
        if status.phase == ManagedPhase::Ready
            && let Some(bytes) = selection
        {
            store
                .root
                .write_atomic("active.json", &bytes, PublishMode::Replace)?;
        }
        // Publication errors remain explicit, including uncertain native durability. Never
        // time out or cancel an already admitted startup after publishing its selection,
        // and never roll back a concurrently published workspace choice.
        Ok(status)
    }
}

/// Generation intent is enforced only while holding the named operation lock.
#[derive(Clone, Copy)]
enum GenerationPolicy<'selection> {
    CreateOrRetain,
    RetainOnly(&'selection ManagedContext),
    CreateOnly,
}

impl ManagedStore {
    /// Open or create a private store at an explicit application-selected path.
    ///
    /// # Errors
    /// Fails if custody cannot be established or the directory cannot be created.
    pub fn open(root: &Path) -> Result<Self> {
        let root = PrivateDirectory::open_or_create(root)?;
        let networks = root.ensure_child("networks")?;
        Ok(Self { root, networks })
    }

    /// Canonical private root passed to the worker entry point.
    #[must_use]
    pub fn root(&self) -> &Path {
        self.root.path()
    }

    /// Open the optional owner-private attachments container under the retained store root.
    /// Existing containers must keep private custody; this does not create or repair them.
    pub(super) fn attachments_directory(&self) -> Result<Option<PrivateDirectory>> {
        Ok(self.root.open_child_optional("attachments")?)
    }

    /// Publish a complete attachment through the original retained private store root.
    /// Validate its managed name before creating the private attachments container.
    pub(super) fn publish_attachment(
        &self,
        name: &str,
        files: &[(&str, &[u8])],
    ) -> Result<PrivateDirectory> {
        validate_name(name)?;
        Ok(self
            .root
            .ensure_child("attachments")?
            .publish_private_child(name, files)?)
    }

    pub(super) fn directory(&self, name: &str) -> Result<PrivateDirectory> {
        validate_name(name)?;
        Ok(self.networks.open_child(name)?)
    }

    /// Start or reconnect to a named network, preparing its generation only once.
    ///
    /// Canonical generation runs only for a new context, with private fixed-path seed custody
    /// and reserved loopback ports. Existing identities, configuration and ledger are retained.
    ///
    /// # Errors
    /// Invalid input, competing ownership, preparation, binary changes, startup or readiness failure.
    pub fn up(&self, request: &LocalnetRequest) -> Result<ManagedStatus> {
        self.up_environment(
            request,
            RootKind::Global,
            GenerationPolicy::CreateOrRetain,
            StartupSelection::Select,
            None,
            |_| Ok(()),
        )
    }

    /// Create and select a new global localnet, refusing an existing named generation.
    ///
    /// The name check and generation publication share the operation lock. A context created
    /// concurrently by another frontend cannot turn this request into a restart or private root.
    ///
    /// # Errors
    /// Invalid input, an existing or concurrently owned name, unsafe custody or failed startup.
    pub fn create_localnet(&self, request: &LocalnetRequest) -> Result<ManagedStatus> {
        self.up_environment(
            request,
            RootKind::Global,
            GenerationPolicy::CreateOnly,
            StartupSelection::Select,
            None,
            |_| Ok(()),
        )
    }

    /// Start or reconnect to an independently signed private root under the same native owner.
    ///
    /// The caller authenticates parent admission separately. This operation prepares and starts
    /// only the local child validators; it does not publish parent registration or certificates.
    ///
    /// # Errors
    /// Rejects an invalid or changed private identity, unsafe custody, or failed native readiness.
    pub fn up_private_root(
        &self,
        request: &LocalnetRequest,
        spec: &crate::localnet::PrivateRootSpec,
    ) -> Result<ManagedStatus> {
        self.up_private_root_bound(request, spec, |_| Ok(()))
    }

    pub(super) fn up_private_root_bound(
        &self,
        request: &LocalnetRequest,
        spec: &crate::localnet::PrivateRootSpec,
        retain_context: impl FnOnce(&PreparedLocalnet) -> Result<()>,
    ) -> Result<ManagedStatus> {
        spec.validate()
            .map_err(|_| Error::Invalid("invalid private-root SNS identity".into()))?;
        self.up_environment(
            request,
            RootKind::Private { spec: spec.clone() },
            GenerationPolicy::CreateOrRetain,
            StartupSelection::Select,
            None,
            retain_context,
        )
    }

    /// Prepare only a fresh AMX manifest, or authenticate the original sources of a retained
    /// signed generation. Source creation and generation admission share the operation lock.
    pub(super) fn up_private_root_with_amx_bound(
        &self,
        request: &LocalnetRequest,
        spec: &crate::localnet::PrivateRootSpec,
        selection: &crate::bootstrap::AmxSourceSelection<'_>,
        retain_context: impl FnOnce(&PreparedLocalnet) -> Result<()>,
    ) -> Result<ManagedStatus> {
        spec.validate()
            .map_err(|_| Error::Invalid("invalid private-root SNS identity".into()))?;
        self.up_environment(
            request,
            RootKind::Private { spec: spec.clone() },
            GenerationPolicy::CreateOrRetain,
            StartupSelection::Select,
            Some(selection),
            retain_context,
        )
    }

    /// Restart the generation originally selected by the caller, with its retained root and signer.
    ///
    /// The expected context is compared again while holding the named operation lock. A reset
    /// followed by a same-name replacement cannot silently change the selected signing identity.
    ///
    /// # Errors
    /// Rejects missing or malformed metadata, changed binaries, or failed native readiness.
    pub fn up_retained(
        &self,
        request: &LocalnetRequest,
        expected: &ManagedContext,
    ) -> Result<ManagedStatus> {
        self.up_retained_with_selection(request, expected, StartupSelection::Select)
    }

    pub(super) fn up_retained_with_selection(
        &self,
        request: &LocalnetRequest,
        expected: &ManagedContext,
        selection: StartupSelection,
    ) -> Result<ManagedStatus> {
        let directory = self.directory(&request.name)?;
        let retained = generation::read(&directory)?;
        self.up_environment(
            request,
            retained.root_kind,
            GenerationPolicy::RetainOnly(expected),
            selection,
            None,
            |_| Ok(()),
        )
    }

    fn up_environment(
        &self,
        request: &LocalnetRequest,
        root_kind: RootKind,
        generation_policy: GenerationPolicy<'_>,
        selection: StartupSelection,
        amx: Option<&crate::bootstrap::AmxSourceSelection<'_>>,
        retain_context: impl FnOnce(&PreparedLocalnet) -> Result<()>,
    ) -> Result<ManagedStatus> {
        if matches!(root_kind, RootKind::Private { .. })
            && request.service_profile != crate::localnet::LocalnetServiceProfile::Standard
        {
            return Err(Error::Invalid(
                "service-authority profiles require a global managed root".into(),
            ));
        }
        transport::supported()?;
        validate_name(&request.name)?;
        if request.startup_timeout.is_zero() || request.startup_timeout > WORKER_STARTUP_MAXIMUM {
            return Err(Error::Invalid(
                "startup timeout must be greater than zero and at most ten minutes".into(),
            ));
        }
        let started = Instant::now();
        let startup_deadline_ns = runtime::startup_deadline(started, request.startup_timeout)?;
        let programs = request.admit_programs()?;
        let (launcher, daemon) = programs.pins()?;
        let directory = self.networks.ensure_child(&request.name)?;
        #[cfg(test)]
        selected_generation_tests::before_operation();
        let _operation = acquire(&directory, "operation.lock", &request.name)?;
        let mut reservations = None;
        let previous = generation::read_optional(&directory)?;
        if let (GenerationPolicy::RetainOnly(expected), Some(retained)) =
            (generation_policy, previous.as_ref())
            && retained.prepared.context != *expected
        {
            return Err(Error::Invalid(
                "retained managed generation changed before startup".into(),
            ));
        }
        let amx_sources = amx
            .map(|selection| {
                let RootKind::Private { spec } = &root_kind else {
                    return Err(Error::Invalid(
                        "AMX bootstrap requires the selected private generation".into(),
                    ));
                };
                selection
                    .retain(spec, previous.is_none())
                    .map_err(|error| Error::Invalid(error.to_string()))
            })
            .transpose()?;
        let retained = match previous {
            Some(retained) => {
                if matches!(generation_policy, GenerationPolicy::CreateOnly) {
                    return Err(Error::Invalid(format!(
                        "managed environment `{}` already exists; select or start it explicitly",
                        request.name
                    )));
                }
                if retained.prepared.service_profile != request.service_profile {
                    return Err(Error::Invalid(
                        "managed generation has a different immutable service profile".into(),
                    ));
                }
                if retained.root_kind != root_kind {
                    return Err(Error::Invalid(
                        "managed generation has a different immutable root identity".into(),
                    ));
                }
                validate_prepared(
                    &request.name,
                    directory.path(),
                    &retained.prepared,
                    &root_kind,
                )?;
                if retained.launcher.blake3 != launcher.blake3
                    || retained.daemon.blake3 != daemon.blake3
                {
                    return Err(Error::Invalid("managed generation uses different binary contents; select its original matching installation".into()));
                }
                retained
            }
            None => {
                if matches!(generation_policy, GenerationPolicy::RetainOnly(_)) {
                    return Err(Error::Invalid(
                        "retained managed generation disappeared; refusing to replace its identity"
                            .into(),
                    ));
                }
                let ports = LocalnetPorts::reserve()?;
                let retained = if let Some(sources) = amx_sources.as_ref() {
                    generation::prepare_with_amx(
                        &directory, request, root_kind, launcher, daemon, &ports, sources,
                    )?
                } else {
                    generation::prepare(&directory, request, root_kind, launcher, daemon, &ports)?
                };
                reservations = Some(ports);
                retained
            }
        };
        if let Some(sources) = amx_sources.as_ref() {
            sources
                .require_signed_generation(&retained.prepared)
                .map_err(|error| Error::Invalid(error.to_string()))?;
        }
        // Binding is serialized with this exact validated generation, before spawn and before
        // any reset can acquire operation.lock. No callback may activate parent operations.
        programs.validate()?;
        #[cfg(test)]
        selected_generation_tests::before_startup(&retained.prepared)?;
        retain_context(&retained.prepared)?;
        runtime::startup_remaining_until(started, request.startup_timeout, startup_deadline_ns)?;
        if let Ok(status) = exchange(&directory, "status") {
            let status = observe_startup_status(
                &directory,
                &retained.prepared.context,
                status,
                started,
                request.startup_timeout,
                startup_deadline_ns,
                true,
            )?;
            if status.phase == ManagedPhase::Ready {
                programs.validate()?;
                return selection.apply(self, &retained.prepared.context, || {
                    observe_startup_status(
                        &directory,
                        &retained.prepared.context,
                        status,
                        started,
                        request.startup_timeout,
                        startup_deadline_ns,
                        true,
                    )
                });
            }
            if status.phase == ManagedPhase::Failed {
                return Ok(status);
            }
        } else {
            // A crashed controller's still-running children keep this lock. Never adopt or kill
            // processes merely because their integer PID appears in a previous record.
            let available = acquire(&directory, "runtime.lock", &request.name)?;
            clear_worker_session(&directory)?;
            let launcher = super::program::NativeProgram::matching(&retained.launcher)?;
            let output = directory.open_append("supervisor.log")?;
            let errors = output.try_clone()?;
            let mut command = Command::new(&retained.launcher.path);
            command
                .arg("_managed-worker")
                .arg("--root")
                .arg(self.root())
                .arg("--name")
                .arg(&request.name)
                .stdin(Stdio::from(available.try_clone()?))
                .stdout(output)
                .stderr(errors);
            transport::detach(&mut command);
            directory.write_atomic(
                STATUS,
                &encode(&ManagedStatus {
                    context: retained.prepared.context.clone(),
                    phase: ManagedPhase::Starting,
                    running_peers: 0,
                    failure: None,
                })?,
                PublishMode::Replace,
            )?;
            // Binary verification and durable status publication consume the caller's same
            // startup budget; the worker must not receive the earlier, larger remainder.
            let remaining = runtime::startup_remaining_until(
                started,
                request.startup_timeout,
                startup_deadline_ns,
            )?;
            let milliseconds = runtime::worker_startup_millis(remaining, request.startup_timeout)?;
            command
                .arg("--startup-timeout-ms")
                .arg(milliseconds.to_string())
                .arg("--startup-deadline-ns")
                .arg(startup_deadline_ns.to_string());
            drop(reservations.take());
            programs.validate()?;
            launcher.validate()?;
            // These original native owners remain alive across spawn. This is a source fence,
            // not a claim that pathname execution is atomic with the validation on every OS.
            runtime::startup_remaining_until(
                started,
                request.startup_timeout,
                startup_deadline_ns,
            )?;
            let mut worker = command.spawn()?;
            // The inherited original remains held across process loading and admission.
            drop(available);
            // Reap this exact child eventually without blocking the CLI after successful startup.
            thread::spawn(move || {
                let _ = worker.wait();
            });
        }
        loop {
            match runtime::startup_remaining_until(
                started,
                request.startup_timeout,
                startup_deadline_ns,
            ) {
                Ok(_) => {}
                Err(Error::Timeout(_)) => {
                    return expire_startup(
                        &directory,
                        &retained.prepared.context,
                        request.startup_timeout,
                    );
                }
                Err(error) => return Err(error),
            }
            if let Ok(status) = exchange(&directory, "status") {
                let status = observe_startup_status(
                    &directory,
                    &retained.prepared.context,
                    status,
                    started,
                    request.startup_timeout,
                    startup_deadline_ns,
                    false,
                )?;
                match status.phase {
                    ManagedPhase::Ready => {
                        programs.validate()?;
                        return selection.apply(self, &retained.prepared.context, || {
                            observe_startup_status(
                                &directory,
                                &retained.prepared.context,
                                status,
                                started,
                                request.startup_timeout,
                                startup_deadline_ns,
                                false,
                            )
                        });
                    }
                    ManagedPhase::Failed | ManagedPhase::Stopped => return Ok(status),
                    ManagedPhase::Starting => {}
                }
            } else if let Ok(bytes) = directory.read(STATUS, MAX_METADATA) {
                let status: ManagedStatus = decode(&bytes)?;
                if status.context != retained.prepared.context {
                    return Err(Error::Invalid(
                        "retained status belongs to another managed identity".into(),
                    ));
                }
                if status.phase == ManagedPhase::Failed && !runtime_owned(&directory)? {
                    return Ok(status);
                }
            }
            thread::sleep(POLL);
        }
    }

    /// Query the authenticated live worker, or report a stopped retained generation.
    ///
    /// # Errors
    /// Missing context, custody failure, or live ownership without a reachable control endpoint.
    pub fn status(&self, name: &str) -> Result<ManagedStatus> {
        let directory = self.directory(name)?;
        let retained = generation::read(&directory)?;
        validate_prepared(
            name,
            directory.path(),
            &retained.prepared,
            &retained.root_kind,
        )?;
        if let Ok(status) = exchange(&directory, "status") {
            if status.context != retained.prepared.context {
                return Err(Error::Invalid(
                    "worker status belongs to another managed identity".into(),
                ));
            }
            return Ok(status);
        }
        if runtime_owned(&directory)? {
            return Err(Error::Busy(name.into()));
        }
        retained_status(&directory, retained.prepared.context, true)
    }

    /// Stop exactly this worker's children while retaining all chain and signer material.
    ///
    /// # Errors
    /// Missing context, competing operation, failed custody or unreconciled process ownership.
    pub fn down(&self, name: &str) -> Result<ManagedStatus> {
        self.down_until(name, Instant::now() + STOP_OBSERVATION_MAXIMUM)
    }

    // One observation deadline covers session admission, terminal reply and original-owner exit.
    // Tests inject a short bound here; no user option or task authorization is introduced.
    fn down_until(&self, name: &str, deadline: Instant) -> Result<ManagedStatus> {
        let directory = self.directory(name)?;
        let _operation = acquire(&directory, "operation.lock", name)?;
        let retained = generation::read(&directory)?;
        validate_prepared(
            name,
            directory.path(),
            &retained.prepared,
            &retained.root_kind,
        )?;
        let context = retained.prepared.context.clone();
        let mut stopped = None;
        loop {
            if Instant::now() >= deadline {
                return Err(Error::Busy(name.into()));
            }
            match acquire(&directory, "runtime.lock", name) {
                Ok(_runtime) => {
                    // The inherited spawn gate prevents a delayed child from entering after
                    // this availability proof. Retain it while closing public native custody.
                    let current = generation::read(&directory)?;
                    if encode(&current)? != encode(&retained)? {
                        return Err(Error::Invalid(
                            "managed generation changed during stop".into(),
                        ));
                    }
                    let status = match stopped {
                        Some(status) => status,
                        None => retained_status(&directory, context.clone(), false)?,
                    };
                    directory.revalidate()?;
                    if Instant::now() >= deadline {
                        return Err(Error::Busy(name.into()));
                    }
                    return Ok(status);
                }
                Err(Error::Busy(_)) => {}
                Err(error) => return Err(error),
            }
            if stopped.is_none() {
                if let Some(status) = exchange_optional(&directory, "down", &retained, deadline)? {
                    if status.context != context {
                        return Err(Error::Invalid(
                            "worker stop belongs to another managed identity".into(),
                        ));
                    }
                    if !matches!(status.phase, ManagedPhase::Stopped | ManagedPhase::Failed)
                        || status.running_peers != 0
                    {
                        return Err(Error::Invalid(
                            "worker stop did not prove terminal zero-peer cleanup".into(),
                        ));
                    }
                    stopped = Some(status);
                } else {
                    // Genuine initial session absence is a pre-session owner, never stopped
                    // evidence. Native custody, malformed records and transport errors refuse.
                    #[cfg(test)]
                    pre_session_tests::before_wait();
                }
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(Error::Busy(name.into()));
            }
            thread::sleep(POLL.min(remaining));
        }
    }

    /// Delete a stopped managed generation after the caller has obtained explicit reset intent.
    ///
    /// This is destructive: all chain state and signer material of the named context is removed.
    /// Running or orphan-owned generations are refused, and unrelated contexts are untouched.
    ///
    /// # Errors
    /// Competing operation, active ownership, malformed name, custody failure or deletion failure.
    pub fn reset(&self, name: &str) -> Result<()> {
        let directory = self.directory(name)?;
        let _operation = acquire(&directory, "operation.lock", name)?;
        let _runtime = acquire(&directory, "runtime.lock", name)?;
        directory.revalidate()?;
        transport::clear_stopped_endpoint(&directory)?;
        directory.clear_contents_preserving(&["operation.lock", "runtime.lock"])?;
        // The ownership directory and locked files remain pinned on every platform. Keep
        // selection resolution explicit: a reset selection should report the missing
        // generation, never silently switch transaction signing to another context.
        Ok(())
    }

    /// Select an existing context without exposing its signer or copying its secret config.
    ///
    /// # Errors
    /// The named generation is absent, malformed, or fails private custody checks.
    pub fn select(&self, name: &str) -> Result<ManagedContext> {
        let (context, bytes) = self.prepare_selection(name)?;
        self.root
            .write_atomic("active.json", &bytes, PublishMode::Replace)?;
        Ok(context)
    }

    fn prepare_selection(&self, name: &str) -> Result<(ManagedContext, Vec<u8>)> {
        let context = self.context(Some(name))?;
        Ok((context, encode(&name.to_owned())?))
    }

    /// Load the named context, or the currently selected managed context.
    ///
    /// # Errors
    /// Missing selection, missing generation or malformed retained public metadata.
    pub fn context(&self, name: Option<&str>) -> Result<ManagedContext> {
        let selected: String;
        let name = if let Some(name) = name {
            name
        } else {
            let bytes = self
                .root
                .read_optional("active.json", MAX_METADATA)?
                .ok_or(Error::NoSelection)?;
            selected = decode(&bytes)?;
            &selected
        };
        Ok(self.prepared(name)?.context)
    }

    /// Observe one retained generation's public context, peer endpoints and configuration paths.
    ///
    /// The returned metadata contains no key or token bytes and does not assert process health.
    /// Use [`Self::status`] for authenticated live lifecycle observations.
    ///
    /// # Errors
    /// Missing generation, malformed metadata, escaped paths or unsafe private custody.
    pub fn prepared(&self, name: &str) -> Result<PreparedLocalnet> {
        let directory = self.directory(name)?;
        let retained = generation::read(&directory)?;
        validate_prepared(
            name,
            directory.path(),
            &retained.prepared,
            &retained.root_kind,
        )?;
        Ok(retained.prepared)
    }

    /// List retained contexts in stable name order.
    ///
    /// # Errors
    /// A retained context or its parent cannot be read under private custody.
    pub fn contexts(&self) -> Result<Vec<ManagedContext>> {
        self.networks.revalidate()?;
        let mut names = Vec::new();
        for entry in fs::read_dir(self.networks.path())? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| Error::Invalid("invalid context filename".into()))?;
            validate_name(&name)?;
            if entry.path().join(generation::DIRECTORY).try_exists()? {
                names.push(name);
            }
        }
        names.sort();
        names
            .into_iter()
            .map(|name| self.context(Some(&name)))
            .collect()
    }

    /// Read the bounded tail of one retained peer or supervisor log.
    ///
    /// # Errors
    /// An unknown log, insecure file, or more than one MiB was requested.
    pub fn logs(&self, name: &str, peer: Option<usize>, max_bytes: usize) -> Result<String> {
        if max_bytes == 0 || max_bytes > 1024 * 1024 {
            return Err(Error::Invalid(
                "log tail size must be between 1 byte and one MiB".into(),
            ));
        }
        let directory = self.directory(name)?;
        let retained = generation::read(&directory)?;
        validate_prepared(
            name,
            directory.path(),
            &retained.prepared,
            &retained.root_kind,
        )?;
        let log_name = match peer {
            Some(index) => retained
                .prepared
                .peers
                .get(index)
                .ok_or_else(|| Error::Invalid("localnet peer index must be 0..3".into()))?
                .log_name
                .as_str(),
            None => "supervisor.log",
        };
        let mut file = directory.open_read(log_name)?;
        let length = file.metadata()?.len();
        file.seek(SeekFrom::Start(length.saturating_sub(max_bytes as u64)))?;
        let mut bytes = Vec::new();
        file.take(max_bytes as u64).read_to_end(&mut bytes)?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
}

pub(super) fn random_token() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}

pub(super) fn acquire(directory: &PrivateDirectory, file: &str, name: &str) -> Result<File> {
    let lock = directory.open_ownership_lock(file).map_err(|error| {
        if ownership_contended(&error) {
            Error::Busy(name.into())
        } else {
            error.into()
        }
    })?;
    lock.try_lock().map_err(|error| match error {
        fs::TryLockError::WouldBlock => Error::Busy(name.into()),
        fs::TryLockError::Error(error) => error.into(),
    })?;
    Ok(lock)
}

fn runtime_owned(directory: &PrivateDirectory) -> Result<bool> {
    file_owned(directory, "runtime.lock")
}

fn file_owned(directory: &PrivateDirectory, name: &str) -> Result<bool> {
    let lock = match directory.open_ownership_lock(name) {
        Ok(lock) => lock,
        Err(error) if ownership_contended(&error) => return Ok(true),
        Err(error) => return Err(error.into()),
    };
    match lock.try_lock() {
        Ok(()) => Ok(false),
        Err(fs::TryLockError::WouldBlock) => Ok(true),
        Err(fs::TryLockError::Error(error)) => Err(error.into()),
    }
}

fn ownership_contended(error: &std::io::Error) -> bool {
    // The native ownership opener alone maps Windows writer-share contention to WouldBlock.
    // Inherited duplicates retain that exclusion independently of process-owned LockFileEx.
    cfg!(windows) && error.kind() == std::io::ErrorKind::WouldBlock
}

pub(super) fn pin_binary(path: &Path) -> Result<BinaryPin> {
    super::program::NativeProgram::capture(path)?.pin()
}

#[cfg(test)]
pub(super) fn verify_binary(pin: &BinaryPin) -> Result<()> {
    super::program::NativeProgram::matching(pin)?.validate()?;
    Ok(())
}

pub(super) fn validate_prepared(
    name: &str,
    root: &Path,
    prepared: &PreparedLocalnet,
    root_kind: &RootKind,
) -> Result<()> {
    let generation_root = root.join(generation::DIRECTORY);
    let root = generation_root.as_path();
    if prepared.context.name != name || prepared.peers.len() != 4 {
        return Err(Error::Invalid(
            "prepared localnet must bind its exact name and four validators".into(),
        ));
    }
    match root_kind {
        RootKind::Global
            if prepared.context.dataspace_id != 0
                || prepared.context.dataspace_alias != "universal" =>
        {
            return Err(Error::Invalid(
                "global localnet must bind the universal dataspace".into(),
            ));
        }
        RootKind::Private { spec } => {
            if prepared.service_profile != crate::localnet::LocalnetServiceProfile::Standard {
                return Err(Error::Invalid(
                    "private roots cannot retain a service-authority profile".into(),
                ));
            }
            spec.validate()
                .map_err(|_| Error::Invalid("invalid retained private-root SNS identity".into()))?;
            if prepared.context.dataspace_id != spec.dataspace_id.as_u64()
                || prepared.context.dataspace_alias != spec.dataspace_alias
            {
                return Err(Error::Invalid(
                    "private context differs from its immutable root identity".into(),
                ));
            }
        }
        RootKind::Global => {}
    }
    let mut endpoints = std::collections::BTreeSet::new();
    let mut configs = std::collections::BTreeSet::new();
    let mut logs = std::collections::BTreeSet::new();
    for peer in &prepared.peers {
        let url: url::Url = peer
            .torii_url
            .parse()
            .map_err(|_| Error::Invalid("invalid managed Torii URL".into()))?;
        if url.scheme() != "http"
            || url.host_str() != Some("127.0.0.1")
            || url.port().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
            || !endpoints.insert(peer.torii_url.clone())
        {
            return Err(Error::Invalid(
                "managed Torii endpoints must be distinct bare IPv4 loopback HTTP origins".into(),
            ));
        }
        if !confined_path(root, &peer.config_path)?
            || !configs.insert(peer.config_path.clone())
            || peer.log_name.contains(['/', '\\'])
            || !peer.log_name.ends_with(".log")
            || peer.log_name.starts_with('.')
            || peer.log_name == "supervisor.log"
            || !logs.insert(peer.log_name.clone())
        {
            return Err(Error::Invalid(
                "managed configs and log names must be distinct and confined to the generation"
                    .into(),
            ));
        }
        iroha_fs::read_private(&peer.config_path, MAX_METADATA)?;
    }
    if prepared.context.torii_url != prepared.peers[0].torii_url
        || !confined_path(root, &prepared.context.client_config)?
    {
        return Err(Error::Invalid(
            "client context must belong to this generation and its first validator".into(),
        ));
    }
    iroha_fs::read_private(&prepared.context.client_config, MAX_METADATA)?;
    if let RootKind::Private { spec } = root_kind {
        let generation =
            prepared.context.client_config.parent().ok_or_else(|| {
                Error::Invalid("private context has no generation directory".into())
            })?;
        crate::localnet::verify_private_root(generation, prepared, spec)?;
    } else {
        crate::localnet::service_authorities::validate_retained(prepared)?;
    }
    Ok(())
}

fn confined_path(root: &Path, path: &Path) -> Result<bool> {
    use std::path::Component;
    // Do not normalize a malicious retained path into an allowed one: exact canonical spelling
    // is part of the context binding, and the custody reader subsequently pins every component.
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
        || !path.starts_with(root)
    {
        return Ok(false);
    }
    Ok(path.canonicalize()? == path && root.canonicalize()? == root)
}

pub(super) fn exchange(directory: &PrivateDirectory, action: &str) -> Result<ManagedStatus> {
    let worker: WorkerRecord = decode(&directory.read(WORKER, MAX_METADATA)?)?;
    transport::request(
        directory,
        &ControlRequest {
            token: worker.token,
            action: action.into(),
        },
    )
}

// Only a public status observer may interpret a competing operation lock as a foreground
// handoff. Down already holds that operation lock and proves runtime availability itself.
fn retained_status(
    directory: &PrivateDirectory,
    context: ManagedContext,
    foreground_handoff: bool,
) -> Result<ManagedStatus> {
    match directory.read_optional(STATUS, MAX_METADATA)? {
        Some(bytes) => {
            let mut last: ManagedStatus = decode(&bytes)?;
            if last.context != context {
                return Err(Error::Invalid(
                    "retained status belongs to another context".into(),
                ));
            }
            if last.phase != ManagedPhase::Stopped {
                if foreground_handoff
                    && last.phase == ManagedPhase::Starting
                    && file_owned(directory, "operation.lock")?
                {
                    // The foreground operation publishes Starting before native spawn; its
                    // lock distinguishes that small handoff window from a crashed owner.
                    last.running_peers = 0;
                    return Ok(last);
                }
                if last.phase != ManagedPhase::Failed {
                    last.failure = Some(
                        "the background controller stopped unexpectedly; inspect its retained log"
                            .into(),
                    );
                }
                last.phase = ManagedPhase::Failed;
                last.running_peers = 0;
                return Ok(last);
            }
        }
        None => {}
    }
    Ok(ManagedStatus {
        context,
        phase: ManagedPhase::Stopped,
        running_peers: 0,
        failure: None,
    })
}

// Only the initial native record absence waits for an already-owned worker's session.
// Present metadata uses the same exact decoder and authenticated transport as exchange.
fn exchange_optional(
    directory: &PrivateDirectory,
    action: &str,
    retained: &RetainedLocalnet,
    deadline: Instant,
) -> Result<Option<ManagedStatus>> {
    let context = &retained.prepared.context;
    let Some(bytes) = directory.read_optional(WORKER, MAX_METADATA)? else {
        return Ok(None);
    };
    let worker: WorkerRecord = decode(&bytes)?;
    let original = directory.open_retained_private(WORKER)?;
    let snapshot = original.snapshot()?;
    if directory.read(WORKER, MAX_METADATA)?.as_slice() != bytes.as_slice()
        || original.snapshot()? != snapshot
    {
        return Err(Error::Invalid(
            "worker session changed during admission".into(),
        ));
    }
    #[cfg(test)]
    pre_session_tests::before_request();
    let observed = transport::request_observed_until(
        directory,
        &ControlRequest {
            token: worker.token,
            action: action.into(),
        },
        deadline,
    );
    match observed {
        Ok(status) => Ok(Some(status)),
        Err(transport::RequestFailure::Refused(error)) => Err(error),
        Err(transport::RequestFailure::Unavailable(error)) => {
            let _runtime = match acquire(directory, "runtime.lock", &context.name) {
                Ok(runtime) => runtime,
                Err(Error::Busy(_)) => return Err(error),
                Err(refusal) => return Err(refusal),
            };
            // Only a closed original owner may reconcile an unavailable peer. The admitted
            // session's native object, exact metadata and bytes must remain unchanged.
            if original.snapshot()? != snapshot
                || directory.read(WORKER, MAX_METADATA)?.as_slice() != bytes.as_slice()
            {
                return Err(Error::Invalid("worker session changed during stop".into()));
            }
            let current = generation::read(directory)?;
            if encode(&current)? != encode(retained)? {
                return Err(Error::Invalid(
                    "managed generation changed during stop".into(),
                ));
            }
            let Some(saved) = directory.read_optional(STATUS, MAX_METADATA)? else {
                return Err(error);
            };
            let status: ManagedStatus = decode(&saved)?;
            if status.context != *context {
                return Err(Error::Invalid(
                    "retained cleanup belongs to another managed identity".into(),
                ));
            }
            if !matches!(status.phase, ManagedPhase::Stopped | ManagedPhase::Failed)
                || status.running_peers != 0
            {
                return Err(error);
            }
            if original.snapshot()? != snapshot {
                return Err(Error::Invalid("worker session changed during stop".into()));
            }
            directory.revalidate()?;
            Ok(Some(status))
        }
    }
}

pub(super) fn observe_startup_status(
    directory: &PrivateDirectory,
    context: &ManagedContext,
    status: ManagedStatus,
    started: Instant,
    timeout: Duration,
    startup_deadline_ns: u128,
    initial_observation: bool,
) -> Result<ManagedStatus> {
    if status.context != *context {
        return Err(Error::Invalid(
            "worker status belongs to another managed identity".into(),
        ));
    }
    // IPC consumes the same foreground budget. Do not select a late Ready. An initial
    // observation of a previously ready worker belongs to a prior successful invocation:
    // a slow repeated `up` must not stop that healthy retained network.
    match runtime::startup_remaining_until(started, timeout, startup_deadline_ns) {
        Ok(_) => Ok(status),
        Err(Error::Timeout(_)) => {
            if initial_observation && status.phase == ManagedPhase::Ready {
                return Err(Error::Timeout(timeout));
            }
            expire_startup(directory, context, timeout)
        }
        Err(error) => Err(error),
    }
}

pub(super) fn expire_startup(
    directory: &PrivateDirectory,
    context: &ManagedContext,
    timeout: Duration,
) -> Result<ManagedStatus> {
    if let Ok(status) = exchange(directory, "startup_expired") {
        if status.context != *context {
            return Err(Error::Invalid(
                "startup cancellation belongs to another managed identity".into(),
            ));
        }
        if status.phase == ManagedPhase::Failed && status.running_peers == 0 {
            return Ok(status);
        }
    }
    // A worker already shutting down may not answer. Its own same bounded deadline still
    // publishes the closed failure; never replace that evidence with a fabricated stopped state.
    Err(Error::Timeout(timeout))
}

// Called only while the foreground holds operation.lock and the transferable runtime.lock.
pub(super) fn clear_worker_session(directory: &PrivateDirectory) -> Result<()> {
    directory.remove_private(WORKER)?;
    transport::clear_stopped_endpoint(directory)?;
    directory.revalidate()?;
    Ok(())
}

#[test]
fn ownership_contention_uses_only_the_platform_ownership_opener_class() {
    assert_eq!(
        ownership_contended(&std::io::Error::from(std::io::ErrorKind::WouldBlock)),
        cfg!(windows)
    );
    assert!(!ownership_contended(&std::io::Error::from(
        std::io::ErrorKind::PermissionDenied
    )));
    assert!(!ownership_contended(&std::io::Error::from_raw_os_error(32)));
}

#[cfg(test)]
#[path = "pre_session_down_tests.rs"]
mod pre_session_tests;

#[cfg(test)]
#[path = "selected_generation_tests.rs"]
mod selected_generation_tests;

#[cfg(test)]
#[path = "startup_selection_tests.rs"]
mod startup_selection_tests;
