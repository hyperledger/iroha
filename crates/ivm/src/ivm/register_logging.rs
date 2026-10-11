//! Register logger admission, invocation identity and host-callback custody.

use super::{HostRegisterLogIsolation, IVM, VMError, zk};
mod event_counts;
pub(crate) use event_counts::RootArguments;

/// One original-funded detached shell admitted before the enclosing effects.
/// Reserved quote and body callbacks borrow this same owner in sequence.
pub(crate) struct PreparedHostRegisterLog {
    isolation: Option<HostRegisterLogIsolation>,
}

impl IVM {
    pub(crate) fn prepare_root_register_events(
        &self,
        route: RootArguments,
    ) -> Result<zk::RegEventBatch, VMError> {
        zk::RegEventBatch::begin(event_counts::root(route, self.native_packets.is_some()))
    }

    pub(super) fn prepare_instruction_register_events(
        &self,
        word: u32,
    ) -> Result<zk::RegEventBatch, VMError> {
        zk::RegEventBatch::begin(event_counts::instruction(
            word,
            self.vector_length,
            self.strict_return_integrity,
            self.native_packets.is_some(),
        )?)
    }

    pub(super) fn prepare_syscall_register_events(
        &self,
        number: u32,
    ) -> Result<zk::RegEventBatch, VMError> {
        zk::RegEventBatch::begin(event_counts::syscall(number))
    }
    /// Original State credit is admitted before any ordinary run state changes.
    /// The detached-error path instead severs foreign aliases without allocation.
    pub(super) fn prepare_invocation_register_log(&mut self) -> Result<(), VMError> {
        if self.host_trace_log_detached || self.host_trace_invocation_log.is_some() {
            self.host_trace_log_detached = false;
            self.host_trace_invocation_log = None;
            self.reg_log = None;
            self.clear_zk_trace_logs();
            self.memory.clear_tracking();
            return Err(VMError::ExecutionDeferred(
                crate::error::ExecutionDeferral::LocalInvariantViolation,
            ));
        }
        let replacement = zk::SharedRegLog::try_new(self.memory.allocation_budget())?;
        if let Some(previous) = &self.reg_log {
            previous.lock().scrub();
        }
        self.reg_log = Some(replacement);
        Ok(())
    }

    pub(super) fn proof_register_log_handle(&self) -> Option<zk::SharedRegLog> {
        if self.host_trace_log_detached
            && let Some(invocation_log) = &self.host_trace_invocation_log
        {
            return Some(invocation_log.clone());
        }
        self.reg_log.clone()
    }
    pub(super) fn clear_zk_trace_logs(&mut self) {
        self.proof_state_epoch = self.proof_state_epoch.wrapping_add(1);
        self.constraints.list.clear();
        self.mem_log.scrub();
        if let Some(log) = &self.reg_log {
            log.lock().scrub();
        }
        if let Some(invocation_log) = &self.host_trace_invocation_log
            && self
                .reg_log
                .as_ref()
                .is_none_or(|log| !zk::SharedRegLog::ptr_eq(invocation_log, log))
        {
            invocation_log.lock().scrub();
        }
        self.trace_log.scrub();
        self.step_log.clear();
        self.pc_trace.clear();
        self.delta_trace.scrub();
    }
    pub(crate) fn prepare_host_register_log(&mut self) -> Result<PreparedHostRegisterLog, VMError> {
        let Some(invocation_log) = zk::event_reg_logger() else {
            return Ok(PreparedHostRegisterLog { isolation: None });
        };
        if self
            .reg_log
            .as_ref()
            .is_none_or(|log| !zk::SharedRegLog::ptr_eq(log, &invocation_log))
            || self.host_trace_log_detached
            || self.host_trace_invocation_log.is_some()
        {
            invocation_log.lock().scrub();
            self.host_trace_log_detached = false;
            if let Some(stale_log) = self.host_trace_invocation_log.take() {
                stale_log.lock().scrub();
            }
            self.clear_zk_trace_logs();
            return Err(VMError::ExecutionDeferred(
                crate::error::ExecutionDeferral::LocalInvariantViolation,
            ));
        }
        let detached_log = zk::SharedRegLog::try_new(self.memory.allocation_budget())?;
        Ok(PreparedHostRegisterLog {
            isolation: Some(HostRegisterLogIsolation {
                invocation_log,
                detached_log,
                proof_state_epoch: self.proof_state_epoch,
                code_hash: self.code_hash,
                zk_mode: self.zk_mode,
            }),
        })
    }

    pub(super) fn isolate_host_register_log(
        &mut self,
        prepared: &PreparedHostRegisterLog,
    ) -> Result<Option<HostRegisterLogIsolation>, VMError> {
        let active = zk::event_reg_logger();
        let Some(isolation) = &prepared.isolation else {
            return if active.is_none() {
                Ok(None)
            } else {
                Err(VMError::ExecutionDeferred(
                    crate::error::ExecutionDeferral::LocalInvariantViolation,
                ))
            };
        };
        if !active
            .as_ref()
            .is_some_and(|active| zk::SharedRegLog::ptr_eq(active, &isolation.invocation_log))
            || self
                .reg_log
                .as_ref()
                .is_none_or(|log| !zk::SharedRegLog::ptr_eq(log, &isolation.invocation_log))
            || self.host_trace_log_detached
            || self.host_trace_invocation_log.is_some()
            || self.proof_state_epoch != isolation.proof_state_epoch
            || self.code_hash != isolation.code_hash
            || self.zk_mode != isolation.zk_mode
        {
            isolation.invocation_log.lock().scrub();
            isolation.detached_log.lock().scrub();
            self.clear_zk_trace_logs();
            return Err(VMError::ExecutionDeferred(
                crate::error::ExecutionDeferral::LocalInvariantViolation,
            ));
        }
        self.reg_log = Some(isolation.detached_log.clone());
        self.host_trace_log_detached = true;
        self.host_trace_invocation_log = Some(isolation.invocation_log.clone());
        Ok(Some(HostRegisterLogIsolation {
            invocation_log: isolation.invocation_log.clone(),
            detached_log: isolation.detached_log.clone(),
            proof_state_epoch: isolation.proof_state_epoch,
            code_hash: isolation.code_hash,
            zk_mode: isolation.zk_mode,
        }))
    }
    pub(super) fn restore_host_register_log(
        &mut self,
        isolation: Option<HostRegisterLogIsolation>,
    ) -> Result<bool, VMError> {
        let Some(isolation) = isolation else {
            return Ok(false);
        };
        if !self.host_trace_log_detached
            || self
                .reg_log
                .as_ref()
                .is_none_or(|log| !zk::SharedRegLog::ptr_eq(log, &isolation.detached_log))
            || !self
                .host_trace_invocation_log
                .as_ref()
                .is_some_and(|active| zk::SharedRegLog::ptr_eq(active, &isolation.invocation_log))
            || self.proof_state_epoch != isolation.proof_state_epoch
            || self.code_hash != isolation.code_hash
            || self.zk_mode != isolation.zk_mode
        {
            isolation.invocation_log.lock().scrub();
            isolation.detached_log.lock().scrub();
            self.host_trace_log_detached = false;
            self.clear_zk_trace_logs();
            self.host_trace_invocation_log = None;
            return Err(VMError::ExecutionDeferred(
                crate::error::ExecutionDeferral::LocalInvariantViolation,
            ));
        }
        isolation.detached_log.lock().scrub();
        self.host_trace_log_detached = false;
        self.host_trace_invocation_log = None;
        self.reg_log = Some(isolation.invocation_log);
        Ok(true)
    }
    pub(super) fn abort_host_register_log_isolation(
        &mut self,
        isolation: Option<HostRegisterLogIsolation>,
    ) {
        // A caught host panic must leave the VM safe for an outer
        // `catch_unwind` caller to inspect or reuse. Restore ownership when it
        // is still valid, then scrub every proof-facing artifact before
        // resuming the original panic.
        let _host_logger_mask = zk::RegLoggerGuard::mask();
        let _ = self.restore_host_register_log(isolation);
        self.host_trace_log_detached = false;
        if let Some(invocation_log) = self.host_trace_invocation_log.take() {
            invocation_log.lock().scrub();
        }
        self.clear_zk_trace_logs();
    }
}

#[cfg(test)]
mod batch_tests;
#[cfg(test)]
mod tests;
