//! The production driver kernel as a host of the `iroha_sumeragi` simulator (§13.5): the world
//! is its hardware. The kernel's operations become the world's device operations — writes
//! (which may fail and are retried by the kernel), executions, the three apply steps, builds,
//! network effects and serving — and their completions come back as worker completions.
//! Nothing here schedules: ordering, parking, retries, the barrier and the ingress are the
//! kernel's. The host also checks O4 on every run: each `Execute` the core emits is answered
//! exactly once while the core lives.

use std::{cell::Cell, collections::BTreeSet, sync::Arc};

use iroha_sumeragi::{
    Core,
    api::{Action, Event},
    message::{TrafficClass, WireMessage},
    sim::{
        crypto::SimCrypto,
        host::{Backlog, Done, Host, Op as SimOp, Start},
    },
    types::{Millis, PublicKey},
};
use parking_lot::Mutex;

use super::super::{
    Completion, DriverConfig, Kernel, KernelStart, Op, Report,
    exec::{ExecDone, ExecOp},
    ingress::{Ingress, IngressLimits},
    persist::Write,
    serve::Served,
};

/// Operation ids of executor operations (write ids are the persistence sequence numbers).
const EXEC_OP: u64 = 1 << 62;

std::thread_local! {
    /// Starts of driver hosts on this test thread.
    pub static STARTS: Cell<u64> = const { Cell::new(0) };
    /// Most effects a driver host of this test thread held behind a pending record.
    pub static PEAK_HELD: Cell<usize> = const { Cell::new(0) };
}

/// The kernel of one replica, hosted by the simulated world.
#[derive(Default)]
pub struct DriverHost {
    kernel: Option<Kernel>,
    /// The write in flight, kept to hand back to the kernel if the device fails it.
    writing: Option<(u64, Write)>,
    next_exec_op: u64,
    /// Local time of the latest call.
    now: Millis,
    /// O4: `Execute` requests of the living core not answered yet.
    unanswered: BTreeSet<u64>,
}

/// The [`HostFactory`](iroha_sumeragi::sim::host::HostFactory) of the conformance runs.
pub fn driver_host(_machine: usize, _instance: usize) -> Box<dyn Host> {
    Box::new(DriverHost::default())
}

impl DriverHost {
    fn kernel(&mut self) -> Option<&mut Kernel> {
        self.kernel.as_mut()
    }

    fn complete_kernel(&mut self, completion: Completion) {
        let now = self.now;
        if let Some(kernel) = self.kernel() {
            kernel.complete(now, completion);
        }
    }

    /// Map one kernel operation to a device operation, or complete it at once when the world
    /// has nothing to do for it.
    fn map(&mut self, op: Op, out: &mut Vec<SimOp>) {
        let exec_op = |host: &mut Self| {
            host.next_exec_op += 1;
            EXEC_OP | host.next_exec_op
        };
        match op {
            Op::Send { to, msg } => {
                out.push(SimOp::Effect(Box::new(Action::Broadcast { to, msg })))
            }
            Op::Serve(request) => {
                // The world serves at once (a local body arrives through `deliver`).
                if let Some(action) = payload_action(request) {
                    out.push(SimOp::Effect(Box::new(action)));
                }
                self.complete_kernel(Completion::Served(Served::default()));
            }
            Op::Report(Report::Evidence(evidence)) => {
                out.push(SimOp::Effect(Box::new(Action::ReportEvidence(evidence))));
            }
            Op::Report(Report::Fault(_) | Report::Halt(_) | Report::FrameLimit(_)) => {}
            Op::Persist { seq, write } => match &write {
                Write::Record(record) => {
                    out.push(SimOp::WriteRecord {
                        op: seq,
                        record: record.clone(),
                    });
                    self.writing = Some((seq, write));
                }
                Write::Body(block) => {
                    out.push(SimOp::WriteBody {
                        op: seq,
                        block: block.clone(),
                    });
                    self.writing = Some((seq, write));
                }
                // The world drops the applied bodies itself.
                Write::Prune(_) => self.complete_kernel(Completion::Persisted {
                    seq,
                    result: Ok(()),
                }),
            },
            Op::Exec(ExecOp::Execute {
                block, certified, ..
            }) => out.push(SimOp::Execute {
                op: exec_op(self),
                block: Box::new((*block).clone()),
                certified,
            }),
            Op::Exec(ExecOp::Discard { height, keep }) => out.push(SimOp::Discard {
                op: exec_op(self),
                height,
                keep,
            }),
            Op::Exec(ExecOp::Prepare(commit)) => out.push(SimOp::Prepare {
                op: exec_op(self),
                block: Box::new(commit.block.clone()),
                qc: Box::new(commit.qc.clone()),
            }),
            Op::Exec(ExecOp::Append(commit)) => out.push(SimOp::Append {
                op: exec_op(self),
                block: Box::new(commit.block.clone()),
                qc: Box::new(commit.qc.clone()),
            }),
            Op::Exec(ExecOp::Commit(commit)) => out.push(SimOp::Commit {
                op: exec_op(self),
                block: Box::new(commit.block.clone()),
                qc: Box::new(commit.qc.clone()),
            }),
            Op::Exec(ExecOp::BuildControlWitness { .. }) => self.complete_kernel(Completion::Exec(
                ExecDone::ControlWitnessBuilt(Ok(iroha_sumeragi::types::ControlWitness::empty())),
            )),
            Op::Exec(ExecOp::DriveApplicationControl(_)) => self.complete_kernel(Completion::Exec(
                ExecDone::ApplicationControlDriven(Ok(None)),
            )),
            Op::Exec(ExecOp::ReceiveApplicationControl {
                occurrence,
                from,
                message,
            }) => self.complete_kernel(Completion::Exec(ExecDone::ApplicationControlReceived {
                occurrence,
                from,
                message,
                result: Ok(()),
            })),
            Op::Exec(ExecOp::Build {
                req,
                max_bytes,
                exec_budget_ms,
                ..
            }) => out.push(SimOp::Build {
                req,
                max_bytes,
                exec_budget_ms,
            }),
            Op::Exec(ExecOp::Reject { block_hash, .. }) => {
                out.push(SimOp::Reject { block_hash });
                self.complete_kernel(Completion::Exec(ExecDone::Rejected));
            }
        }
    }

    /// O4 bookkeeping of an input the core is about to handle.
    fn answered(&mut self, event: &Event) {
        if let Event::Executed { req, .. } = event {
            assert!(
                self.unanswered.remove(req),
                "O4: Execute {req} answered twice or never requested"
            );
        }
    }
}

impl Host for DriverHost {
    fn start(&mut self, start: Start) -> Result<Vec<Action>, Box<dyn std::error::Error>> {
        STARTS.with(|s| s.set(s.get() + 1));
        self.now = start.now;
        let (kernel, actions) = Kernel::start(KernelStart {
            allocation_budget: start.budget,
            local: start.local,
            init: start.init,
            signers: start.signers,
            crypto: start.crypto,
            hasher: Box::new(SimCrypto::new()),
            now: start.now,
            ingress: Arc::new(Mutex::new(Ingress::new(IngressLimits::default()))),
            config: DriverConfig::default(),
        })?;
        self.kernel = Some(kernel);
        self.unanswered = requests(&actions);
        Ok(actions)
    }

    fn crash(&mut self) {
        self.kernel = None;
        self.writing = None;
        self.unanswered.clear();
    }

    fn running(&self) -> bool {
        self.kernel.is_some()
    }

    fn receive(&mut self, from: PublicKey, msg: WireMessage, class: TrafficClass) {
        if let Some(kernel) = self.kernel() {
            kernel.receive(from, msg, class);
        }
    }

    fn deliver(&mut self, event: Event) {
        match event {
            Event::PayloadBuilt { payload, .. } => {
                self.complete_kernel(Completion::Exec(ExecDone::Built(Ok(payload))))
            }
            other => {
                if let Some(kernel) = self.kernel() {
                    kernel.deliver(other);
                }
            }
        }
    }

    fn has_input(&self) -> bool {
        self.kernel.as_ref().is_some_and(Kernel::has_input)
    }

    fn next_input(&mut self, now: Millis) -> Option<Event> {
        self.now = now;
        let event = self.kernel()?.next_input(now)?;
        self.answered(&event);
        Some(event)
    }

    fn handle(&mut self, now: Millis, event: Event) -> Vec<Action> {
        self.now = now;
        let Some(kernel) = self.kernel() else {
            return Vec::new();
        };
        let actions = kernel.handle_observed(now, event);
        for req in requests(&actions) {
            assert!(self.unanswered.insert(req), "request id {req} reused");
        }
        actions
    }

    fn next_wakeup(&self) -> Millis {
        self.kernel
            .as_ref()
            .map_or(Millis::MAX, Kernel::next_wakeup)
    }

    fn persisting(&mut self, _write: u64) {}

    fn gate(&mut self, effect: Action) -> Option<Action> {
        Some(effect)
    }

    fn durable(&mut self, _write: u64) -> Vec<Action> {
        Vec::new()
    }

    fn core(&self) -> Option<&Core> {
        self.kernel.as_ref().map(Kernel::core)
    }

    fn held(&self) -> Vec<Action> {
        self.kernel.as_ref().map_or_else(Vec::new, Kernel::held)
    }

    fn ingress_drops(&self) -> u64 {
        self.kernel.as_ref().map_or(0, Kernel::ingress_drops)
    }

    fn owns_io(&self) -> bool {
        true
    }

    fn backlog(&self) -> Option<Backlog> {
        let backlog = self.kernel.as_ref()?.backlog();
        PEAK_HELD.with(|peak| peak.set(peak.get().max(backlog.held)));
        Some(Backlog {
            held: backlog.held,
            held_bytes: backlog.held_bytes,
            records: backlog.records,
            bodies: backlog.bodies,
            exec_ops: backlog.exec_ops,
            serve: backlog.serve,
        })
    }

    fn poll(&mut self, now: Millis) -> Vec<SimOp> {
        self.now = now;
        let mut out = Vec::new();
        loop {
            let Some(kernel) = self.kernel() else {
                return out;
            };
            let ops = kernel.poll(now);
            if ops.is_empty() {
                return out;
            }
            for op in ops {
                self.map(op, &mut out);
            }
        }
    }

    fn complete(&mut self, now: Millis, done: Done) {
        self.now = now;
        let completion = match done {
            Done::Written { op, ok } if op & EXEC_OP == 0 => {
                let Some((seq, write)) = self.writing.take() else {
                    return;
                };
                assert_eq!(seq, op, "one write in flight");
                let result = if ok { Ok(()) } else { Err(write) };
                Completion::Persisted { seq, result }
            }
            Done::Written { ok, .. } => Completion::Exec(ExecDone::Appended {
                durable: ok,
                deferred: None,
            }),
            Done::Executed { outcome, .. } => Completion::Exec(ExecDone::Executed(outcome)),
            Done::Discarded { .. } => Completion::Exec(ExecDone::Discarded),
            Done::Prepared { result, .. } => Completion::Exec(ExecDone::Prepared(Ok(result))),
            Done::Committed { config, .. } => {
                Completion::Exec(ExecDone::Committed(Ok(Box::new(config))))
            }
        };
        self.complete_kernel(completion);
    }
}

/// The `Execute` request ids among `actions`.
fn requests(actions: &[Action]) -> BTreeSet<u64> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::Execute { req, .. } => Some(*req),
            _ => None,
        })
        .collect()
}

/// The simulated devices run the same actual author/acquisition APIs from Core actions.
fn payload_action(request: super::super::serve::ServeRequest) -> Option<Action> {
    use super::super::{payload_worker::PayloadWork, serve::ServeRequest};
    Some(match request {
        ServeRequest::Blocks {
            to,
            from_height,
            max_count,
            max_bytes,
        } => Action::ServeBlocks {
            to,
            from_height,
            max_count,
            max_bytes,
        },
        ServeRequest::Payload(work) => match *work {
            PayloadWork::Author {
                req,
                config,
                header,
                payload,
            } => Action::AuthorPayload {
                req,
                config,
                header,
                payload,
            },
            PayloadWork::Acquire { source, manifest } => {
                Action::AcquirePayload { source, manifest }
            }
            PayloadWork::Chunk { from, chunk } => Action::ReceivePayloadChunk { from, chunk },
            PayloadWork::Disseminate { peers, body } => Action::DisseminatePayload { peers, body },
            PayloadWork::Fetch { source, peers } => Action::FetchPayload { source, peers },
            PayloadWork::Serve {
                to,
                height,
                block_hash,
            } => Action::ServePayload {
                to,
                height,
                block_hash,
            },
            PayloadWork::Applied(_) | PayloadWork::Retain { .. } | PayloadWork::Poll => {
                return None;
            }
        },
    })
}

/// Device dispatch retains the core's clock-guard exemption on both execution paths.
#[test]
fn execute_device_mapping_preserves_certification() {
    let block = super::block(
        1,
        iroha_sumeragi::types::Hash32([0xa0; 32]),
        iroha_sumeragi::types::Hash32([0xa1; 32]),
        iroha_sumeragi::sim::driver::encode_tx(1, false, 0),
    );
    let block_hash = super::hash(&block);
    let mut host = DriverHost::default();
    for certified in [false, true] {
        let mut out = Vec::new();
        host.map(
            Op::Exec(ExecOp::Execute {
                block: Arc::new(block.clone()),
                block_hash,
                certified,
            }),
            &mut out,
        );
        assert!(matches!(
            out.as_slice(),
            [SimOp::Execute { block: mapped, certified: actual, .. }]
                if *actual == certified && mapped.as_ref() == &block
        ));
    }
}
