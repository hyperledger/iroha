//! Directly owned validator handles and background tasks remain fenced until their owner exits.

use super::*;
use crate::localnet::service_authorities::{
    RetainedGatewayCompliancePlan, RetainedProviderServicePlan,
};
use crate::managed::{
    gateway_compliance::LiveGatewayProcess,
    generated_service_runtime::{GeneratedServiceRuntime, GeneratedServiceRuntimeRevision},
    native_operation::{ManagedTransactionFinality, invalid},
    stream_token_custody::RetainedCustodyEnrollment,
};
use iroha_data_model::sorafs::capacity::ProviderId;
use std::sync::Mutex;

/// Exact original and opaque renderer revision retained for every owned launch.
pub(super) struct GeneratedLaunch {
    owner: Arc<GeneratedServiceRuntime>,
    revision: Arc<GeneratedServiceRuntimeRevision>,
    original: PreparedLocalnet,
    active: AtomicBool,
}
impl GeneratedLaunch {
    pub(super) fn new(
        owner: Arc<GeneratedServiceRuntime>,
        revision: GeneratedServiceRuntimeRevision,
        original: &PreparedLocalnet,
    ) -> Result<Arc<Self>> {
        owner.validate_for(original, &revision)?;
        Ok(Arc::new(Self {
            owner,
            revision: Arc::new(revision),
            original: original.clone(),
            active: AtomicBool::new(true),
        }))
    }

    fn validate(&self) -> Result<()> {
        #[cfg(all(test, unix))]
        tests::batch_validation_tests::revision();
        self.require_active()?;
        self.owner.validate_for(&self.original, &self.revision)?;
        self.require_active()
    }

    fn require_active(&self) -> Result<()> {
        if !self.active.load(Ordering::Acquire) {
            return Err(invalid("the original generated launch is stopping"));
        }
        Ok(())
    }

    fn command(&self, daemon: &std::path::Path, index: usize) -> Result<Command> {
        self.validate()?;
        let peer = self.revision.peer(index)?;
        let mut command = Command::new(daemon);
        command
            .arg("--sora")
            .arg("--config")
            .arg(peer.path())
            .arg("--config-blake3")
            .arg(hex::encode(peer.blake3()))
            .current_dir(self.revision.cwd());
        Ok(command)
    }
}

#[derive(Default)]
pub(super) struct PeerProcesses {
    pub(super) children: Vec<Arc<Mutex<Child>>>,
    launch: Option<Arc<GeneratedLaunch>>,
    background: Option<BackgroundTasks>,
}

// Fixed task slots belong to the same owner as the actual child handles. Receivers carry
// outcomes only; they cannot witness thread exit or release the original runtime ownership.
struct BackgroundTasks {
    cancelled: Arc<AtomicBool>,
    activation: Option<thread::JoinHandle<()>>,
    refresh: Option<thread::JoinHandle<()>>,
    attachment: Option<remote::AttachmentWorker>,
    replacement_panicked: bool,
}
impl BackgroundTasks {
    fn join_slot(slot: &mut Option<thread::JoinHandle<()>>, role: &str) -> Result<()> {
        match slot.take() {
            Some(task) => task
                .join()
                .map_err(|_| Error::Invalid(format!("owned {role} task panicked"))),
            None => Ok(()),
        }
    }

    fn join_all(&mut self) -> Result<()> {
        // Retain every result: a panic must neither detach the other tasks nor leave its
        // consumed handle pending for a later cleanup. No child mutex is held here.
        let activation = Self::join_slot(&mut self.activation, "activation").err();
        let refresh = Self::join_slot(&mut self.refresh, "maintenance").err();
        let attachment = self.attachment.take().and_then(|task| task.join().err());
        let earlier = std::mem::take(&mut self.replacement_panicked)
            .then(|| invalid("owned background task panicked before replacement"));
        let failures = [activation, refresh, attachment, earlier];
        let mut failures = failures.into_iter().flatten();
        match failures.next() {
            None => Ok(()),
            Some(first) => {
                let message = failures.fold(first.to_string(), |mut message, error| {
                    message.push_str("; ");
                    message.push_str(&error.to_string());
                    message
                });
                Err(Error::Invalid(message))
            }
        }
    }
}

impl PeerProcesses {
    pub(super) fn with_background(cancelled: Arc<AtomicBool>) -> Self {
        Self {
            children: Vec::new(),
            launch: None,
            background: Some(BackgroundTasks {
                cancelled,
                activation: None,
                refresh: None,
                attachment: None,
                replacement_panicked: false,
            }),
        }
    }

    pub(super) fn spawn_activation(
        &mut self,
        action: impl FnOnce() + Send + 'static,
    ) -> Result<()> {
        let tasks = self
            .background
            .as_mut()
            .ok_or_else(|| invalid("owned background task scope is absent"))?;
        if let Err(error) = BackgroundTasks::join_slot(&mut tasks.activation, "activation") {
            tasks.replacement_panicked = true;
            return Err(error);
        }
        tasks.activation = Some(thread::Builder::new().spawn(action)?);
        Ok(())
    }

    pub(super) fn spawn_refresh(&mut self, action: impl FnOnce() + Send + 'static) -> Result<()> {
        let tasks = self
            .background
            .as_mut()
            .ok_or_else(|| invalid("owned background task scope is absent"))?;
        if let Err(error) = BackgroundTasks::join_slot(&mut tasks.refresh, "maintenance") {
            tasks.replacement_panicked = true;
            return Err(error);
        }
        tasks.refresh = Some(thread::Builder::new().spawn(action)?);
        Ok(())
    }

    pub(super) fn attachment(&self) -> Option<&remote::AttachmentWorker> {
        self.background.as_ref()?.attachment.as_ref()
    }

    pub(super) fn start_attachment(
        &mut self,
        store: &ManagedStore,
        name: &str,
        prepared: &PreparedLocalnet,
    ) -> Result<()> {
        let tasks = self
            .background
            .as_mut()
            .ok_or_else(|| invalid("owned background task scope is absent"))?;
        if tasks
            .attachment
            .as_ref()
            .is_some_and(|task| !task.is_finished())
        {
            return Err(invalid("original attachment task is still active"));
        }
        if let Some(previous) = tasks.attachment.take() {
            if let Err(error) = previous.join() {
                tasks.replacement_panicked = true;
                return Err(error);
            }
        }
        tasks.attachment =
            remote::AttachmentWorker::start(store, name, prepared, Arc::clone(&tasks.cancelled))?;
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn from_children(children: Vec<Child>) -> Self {
        Self {
            children: children
                .into_iter()
                .map(|child| Arc::new(Mutex::new(child)))
                .collect(),
            launch: None,
            background: None,
        }
    }

    pub(super) fn generated(
        &self,
    ) -> Result<Option<(Arc<GeneratedServiceRuntime>, [OwnedGateway; 3])>> {
        self.launch
            .as_ref()
            .map(|launch| {
                self.gateways()
                    .map(|gateways| (Arc::clone(&launch.owner), gateways))
            })
            .transpose()
    }

    pub(super) fn start(
        &mut self,
        directory: &PrivateDirectory,
        retained: &RetainedLocalnet,
        ownership: &File,
        daemon: &super::super::program::NativeProgram,
        launch: Option<Arc<GeneratedLaunch>>,
        budget: &activation::Budget,
    ) -> Result<()> {
        if !self.children.is_empty() || self.launch.is_some() {
            return Err(invalid("the owned generation must stop before restarting"));
        }
        if let Some(launch) = &launch {
            if launch.original != retained.prepared
                || !matches!(retained.root_kind, RootKind::Global)
            {
                return Err(invalid(
                    "generated launch differs from its original global generation",
                ));
            }
            launch.validate()?;
        }
        if daemon.path() != retained.daemon.path.as_path() {
            return Err(invalid("daemon differs from the retained runtime path"));
        }
        if daemon.pin()?.blake3 != retained.daemon.blake3 {
            return Err(invalid("daemon differs from the retained runtime contents"));
        }
        self.launch = launch;
        for (index, peer) in retained.prepared.peers.iter().enumerate() {
            let log = directory.open_append(&peer.log_name)?;
            let mut command = match &self.launch {
                Some(launch) => launch.command(&retained.daemon.path, index)?,
                None => daemon_command(
                    &retained.daemon.path,
                    &peer.config_path,
                    &retained.root_kind,
                )?,
            };
            command
                .stdin(Stdio::from(ownership.try_clone()?))
                .stdout(log.try_clone()?)
                .stderr(log);
            daemon.validate()?;
            self.children
                .push(Arc::new(Mutex::new(spawn_with_launch_fence(
                    directory,
                    index,
                    &mut command,
                    daemon,
                    budget,
                )?)));
        }
        if let Some(launch) = &self.launch {
            launch.validate()?;
        }
        Ok(())
    }

    /// Select only the exact original provider's directly owned child in this launch.
    pub(super) fn gateway(&self, provider: ProviderId) -> Result<OwnedGateway> {
        let launch = self
            .launch
            .as_ref()
            .ok_or_else(|| invalid("generated gateway is absent"))?;
        if self.children.len() != 4 {
            return Err(invalid("generated gateway has no complete owned committee"));
        }
        launch.validate()?;
        let plan = launch
            .owner
            .original_provider_plan(&launch.original, provider)?
            .ok_or_else(|| invalid("original provider plan absent"))?;
        let gateway = OwnedGateway {
            child: self
                .children
                .get(plan.peer_index())
                .ok_or_else(|| invalid("original provider child absent"))?
                .clone(),
            launch: launch.clone(),
            provider,
        };
        gateway.require_running()?;
        Ok(gateway)
    }

    pub(super) fn gateways(&self) -> Result<[OwnedGateway; 3]> {
        let launch = self
            .launch
            .as_ref()
            .ok_or_else(|| invalid("generated launch absent"))?;
        let plans = launch
            .owner
            .original_provider_plans(&launch.original)?
            .ok_or_else(|| invalid("original provider plans absent"))?;
        plans
            .iter()
            .map(|plan| self.gateway(plan.provider_id()))
            .collect::<Result<Vec<_>>>()?
            .try_into()
            .map_err(|_| invalid("owned gateway count differs"))
    }

    pub(super) fn any_exited(&mut self) -> Result<bool> {
        for child in &self.children {
            if child
                .lock()
                .map_err(|_| invalid("owned child lock failed"))?
                .try_wait()?
                .is_some()
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(super) fn stop(&mut self) -> Result<()> {
        // A native child cleanup error must not skip the task drain. Terminal callers set
        // cancellation before stopping; a normal restart preserves the ongoing relay.
        let children = self.stop_children();
        let background = match self.background.as_mut() {
            Some(tasks) if tasks.cancelled.load(Ordering::Acquire) => tasks.join_all(),
            _ => Ok(()),
        };
        match (children, background) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(children), Err(background)) => Err(Error::WorkerFailure {
                failure: children.to_string(),
                cleanup: Some(Box::new(background)),
                publication: None,
            }),
        }
    }

    fn stop_children(&mut self) -> Result<()> {
        // Invalidate background guards before graceful shutdown begins, even if a child has
        // not exited yet. An already dispatched exact request retains its normal recovery.
        if let Some(launch) = &self.launch {
            launch.active.store(false, Ordering::Release);
        }
        // Only these directly owned, unreaped handles are eligible. A background gateway guard
        // borrows the same handles, so reaping immediately invalidates every old observation.
        for child in &self.children {
            let mut child = child
                .lock()
                .map_err(|_| invalid("owned child lock failed"))?;
            if child.try_wait()?.is_some() {
                continue;
            }
            #[cfg(unix)]
            if let Some(pid) = rustix::process::Pid::from_raw(child.id() as i32) {
                let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
            }
            #[cfg(not(unix))]
            child.kill()?;
        }
        let deadline = Instant::now() + OWNED_PEER_STOP_GRACE;
        loop {
            let mut remaining = false;
            for child in &self.children {
                if child
                    .lock()
                    .map_err(|_| invalid("owned child lock failed"))?
                    .try_wait()?
                    .is_none()
                {
                    remaining = true;
                }
            }
            if !remaining || Instant::now() >= deadline {
                break;
            }
            thread::sleep(POLL);
        }
        for child in &self.children {
            let mut child = child
                .lock()
                .map_err(|_| invalid("owned child lock failed"))?;
            if child.try_wait()?.is_none() {
                child.kill()?;
            }
            child.wait()?;
        }
        self.children.clear();
        self.launch = None;
        Ok(())
    }
}

impl Drop for PeerProcesses {
    fn drop(&mut self) {
        if let Some(tasks) = &self.background {
            tasks.cancelled.store(true, Ordering::Release);
        }
        // A panic or ordinary early return still drains tasks before the caller's original
        // runtime.lock can drop. Join failures are returned by explicit stop, never re-panicked.
        let _ = self.stop();
    }
}

pub(super) struct OwnedGateway {
    child: Arc<Mutex<Child>>,
    launch: Arc<GeneratedLaunch>,
    provider: ProviderId,
}
impl OwnedGateway {
    /// One callback-free observation of the three providers of an exact shared launch.
    /// Only the inactive decoder path uses this round. Full aggregate material and interval
    /// validation bracket all original provider projections and direct-child observations;
    /// no validation result survives this call or crosses a startup effect.
    pub(super) fn validate_shared_round(
        prepared: &PreparedLocalnet,
        live: &[Self; 3],
        budget: &activation::Budget,
    ) -> std::result::Result<(), super::progress::Failure> {
        let plans = budget.call(|_| {
            live[0]
                .original_provider_plans(prepared)?
                .ok_or_else(|| invalid("original provider plans absent"))
        })?;
        budget.call(|_| {
            let launch = &live[0].launch;
            if live
                .iter()
                .any(|gateway| !Arc::ptr_eq(launch, &gateway.launch))
            {
                return Err(invalid(
                    "gateway round belongs to different original launches",
                ));
            }
            launch.validate()?;
            #[cfg(all(test, unix))]
            tests::batch_validation_tests::after_entry();
            let result = (|| {
                for (index, (plan, gateway)) in plans.iter().zip(live).enumerate() {
                    if plan.provider_id() != gateway.provider() {
                        return Err(budget.progress.unconfirmed());
                    }
                    budget.call(|_| {
                        gateway.launch.owner.validate_gateway_compliance_pair(
                            prepared,
                            gateway.provider,
                            || {
                                gateway.require_running()?;
                                gateway.require_original(prepared)?;
                                #[cfg(all(test, unix))]
                                tests::batch_validation_tests::before_binding(index);
                                Ok(())
                            },
                        )?;
                        gateway.require_running()
                    })?;
                    #[cfg(all(test, unix))]
                    tests::batch_validation_tests::after_provider(index);
                    #[cfg(not(all(test, unix)))]
                    let _ = index;
                }
                Ok(())
            })();
            // Close on every ordinary result, even cancellation or expiry inside the round.
            // Evaluate all child observations before propagating material or child failures.
            // The enclosing Budget::call then preserves clock/cancellation precedence.
            let material = launch.validate();
            #[cfg(all(test, unix))]
            tests::batch_validation_tests::exit_material(&material);
            let children = live.each_ref().map(|gateway| gateway.require_running());
            material?;
            for child in children {
                child?;
            }
            Ok(result)
        })??;
        budget.check()?;
        Ok(())
    }

    pub(super) fn provider(&self) -> ProviderId {
        self.provider
    }
    /// This gateway's exact original plan, with fresh source checks and no serving authority.
    /// Active decode limits retain the renderer's standalone full-capture recipe.
    pub(super) fn original_provider_plan(
        &self,
        prepared: &PreparedLocalnet,
    ) -> Result<Option<RetainedProviderServicePlan>> {
        self.launch
            .owner
            .original_provider_plan(prepared, self.provider)
    }

    /// Pure original intent; this does not replace the caller's live child/revision checks.
    pub(super) fn original_provider_plans(
        &self,
        prepared: &PreparedLocalnet,
    ) -> Result<Option<[RetainedProviderServicePlan; 3]>> {
        self.launch.owner.original_provider_plans(prepared)
    }

    /// Pure original trust; native ownership and current serving remain independent.
    pub(super) fn original_gateway_compliance_plan(
        &self,
        prepared: &PreparedLocalnet,
    ) -> Result<Option<RetainedGatewayCompliancePlan>> {
        self.launch
            .owner
            .original_gateway_compliance_plan(prepared, self.provider)
    }

    pub(super) fn required_transactions(&self) -> Result<&[ManagedTransactionFinality]> {
        self.require_running()?;
        self.launch.validate()?;
        Ok(self.launch.revision.required_transactions())
    }
    pub(super) fn observation_floor(&self) -> Result<ManagedTransactionFinality> {
        self.require_running()?;
        self.launch.validate()?;
        self.launch.revision.observation_floor()
    }
    /// Borrow only the enrollment retained by this actual launch's opaque renderer revision.
    /// The requested transaction must be exactly the one that the worker confirmed on all peers.
    pub(super) fn selected_enrollment(
        &self,
        required: ManagedTransactionFinality,
    ) -> Result<&RetainedCustodyEnrollment> {
        self.require_running()?;
        self.launch.validate()?;
        if self.launch.revision.observation_floor()? != required {
            return Err(invalid(
                "owned runtime transaction differs from selected observation",
            ));
        }
        let selected = self
            .launch
            .revision
            .selected_enrollment(self.provider)?
            .ok_or_else(|| invalid("owned runtime has no retained enrollment"))?;
        self.require_running()?;
        Ok(selected)
    }

    /// Derive an exact successor of this actual launch, through its retained sole renderer.
    pub(super) fn prepare_successor(
        &self,
        sequence: u64,
        deadline: Instant,
    ) -> Result<(
        Arc<GeneratedServiceRuntime>,
        GeneratedServiceRuntimeRevision,
    )> {
        self.require_running()?;
        self.launch.validate()?;
        let revision = self.launch.owner.prepare_renewed_stream_tokens(
            &self.launch.revision,
            self.provider,
            sequence,
            deadline,
        )?;
        self.require_running()?;
        Ok((Arc::clone(&self.launch.owner), revision))
    }

    fn require_running(&self) -> Result<()> {
        #[cfg(all(test, unix))]
        tests::batch_validation_tests::running(self.provider);
        self.launch.require_active()?;
        if self
            .child
            .lock()
            .map_err(|_| invalid("owned gateway lock failed"))?
            .try_wait()?
            .is_some()
        {
            return Err(invalid("the original generated gateway process exited"));
        }
        self.launch.require_active()
    }
    fn require_original(&self, prepared: &PreparedLocalnet) -> Result<()> {
        if prepared != &self.launch.original {
            return Err(invalid(
                "the observed gateway belongs to another original generation",
            ));
        }
        Ok(())
    }

    fn validate_binding(
        &self,
        prepared: &PreparedLocalnet,
        plan: &RetainedGatewayCompliancePlan,
    ) -> Result<()> {
        let expected = self
            .original_gateway_compliance_plan(prepared)?
            .ok_or_else(|| invalid("original gateway plan absent"))?;
        if expected.network_id() != plan.network_id()
            || expected.original_commitment() != plan.original_commitment()
            || expected.trust_policy() != plan.trust_policy()
            || expected.gateway_id() != plan.gateway_id()
        {
            return Err(invalid("the observed gateway compliance binding differs"));
        }
        Ok(())
    }
}
impl LiveGatewayProcess for OwnedGateway {
    fn validate(
        &mut self,
        prepared: &PreparedLocalnet,
        plan: &RetainedGatewayCompliancePlan,
    ) -> Result<()> {
        self.require_running()?;
        self.require_original(prepared)?;
        self.launch.validate()?;
        self.validate_binding(prepared, plan)?;
        self.require_running()
    }
}

#[cfg(test)]
mod tests;
