//! Real source refusal/deadline probes inside the retained production server owner.
use super::*;
use std::{
    cell::RefCell,
    os::fd::AsRawFd,
    sync::atomic::{AtomicBool, Ordering},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super) enum Mode {
    RefuseObservation,
    ExpireBeforeDispatch,
    ExpireAfterFrame,
    DriftAfterFrame,
    None,
}
#[derive(Debug, PartialEq, Eq)]
struct Identity {
    request: usize,
    request_bytes: Vec<u8>,
    frame: usize,
    frame_bytes: Vec<u8>,
    inbound_permit: Option<(usize, usize)>,
    admission: usize,
    pool: usize,
    permit: usize,
    socket: std::os::fd::RawFd,
    deadline: std::time::Instant,
}
#[derive(Default, Debug)]
pub(in super::super) struct Audit {
    pub(in super::super) refusals: usize,
    pub(in super::super) retry_checks: usize,
    pub(in super::super) reply: Option<(usize, Vec<u8>)>,
    pub(in super::super) record: Option<(usize, Vec<u8>)>,
    pub(in super::super) encoded_frame: Option<(usize, Vec<u8>)>,
    pub(in super::super) deadline: Option<std::time::Instant>,
    pub(in super::super) successful_phases: [usize; 12],
}
struct Probe {
    mode: Mode,
    drift: Arc<AtomicBool>,
    output: Option<Identity>,
    original_reply: Option<(usize, Vec<u8>)>,
    original_record: Option<(usize, Vec<u8>)>,
    original_query: Option<usize>,
    audit: Audit,
    injected: bool,
}
thread_local! { static PROBE: RefCell<Option<Probe>> = const { RefCell::new(None) }; }
pub(in super::super) fn measure<T>(
    mode: Mode,
    drift: Arc<AtomicBool>,
    action: impl FnOnce() -> T,
) -> (T, Audit) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            PROBE.with_borrow_mut(|slot| *slot = None);
        }
    }

    PROBE.with_borrow_mut(|slot| {
        assert!(slot.is_none());
        *slot = Some(Probe {
            mode,
            drift,
            output: None,
            original_reply: None,
            original_record: None,
            original_query: None,
            audit: Audit::default(),
            injected: false,
        });
    });
    let reset = Reset;
    let result = action();
    let probe = PROBE.with_borrow_mut(|slot| slot.take().unwrap());
    drop(reset);
    (result, probe.audit)
}
fn output_identity(output: &Output<'_>) -> Identity {
    Identity {
        request: std::ptr::from_ref(output.request) as usize,
        request_bytes: output.request.payload.clone(),
        frame: output.request_frame.as_ptr() as usize,
        frame_bytes: output.request_frame.to_vec(),
        inbound_permit: output
            .request_frame
            .inbound_permit
            .as_ref()
            .map(|permit| (std::ptr::from_ref(permit) as usize, permit.num_permits())),
        admission: Arc::as_ptr(output.admission) as usize,
        pool: Arc::as_ptr(&output.admission.pool) as usize,
        permit: std::ptr::from_ref(output.operation_permit) as usize,
        socket: output.stream.as_raw_fd(),
        deadline: output.deadline.expires_at(),
    }
}
pub(super) fn retained_output(output: &Output<'_>) {
    PROBE.with_borrow(|slot| {
        if let Some(probe) = slot {
            assert_eq!(
                probe.output.as_ref(),
                Some(&output_identity(output)),
                "same original socket/frame/request/permit after local processing"
            );
        }
    });
}
pub(super) fn output(output: &Output<'_>) {
    PROBE.with_borrow_mut(|slot| {
        let Some(probe) = slot else {
            return;
        };
        assert!(
            probe.output.is_none(),
            "one admitted operation on the original socket"
        );
        let identity = output_identity(output);
        assert!(
            identity.inbound_permit.is_some(),
            "original inbound frame permit remains live"
        );
        probe.output = Some(identity);
        probe.audit.deadline = Some(output.deadline.expires_at());
    });
}
pub(super) fn before_dispatch(deadline: BrokerDeadlineV1) {
    let expire = PROBE.with_borrow(|slot| {
        slot.as_ref()
            .is_some_and(|probe| probe.mode == Mode::ExpireBeforeDispatch)
    });
    if expire && let Ok(remaining) = deadline.remaining() {
        std::thread::sleep(remaining);
    }
}
fn reply(owner: &CompletedReply<'_>) -> (usize, Vec<u8>) {
    let bytes = owner
        .reply
        .current_evidence()
        .map(|(_, bytes)| bytes)
        .or_else(|| owner.reply.completed_observation())
        .unwrap();
    (bytes.as_ptr() as usize, bytes.to_vec())
}
fn assert_original(owner: &CompletedReply<'_>, probe: &Probe) {
    let output = probe.output.as_ref().unwrap();
    assert_eq!(std::ptr::from_ref(owner.request) as usize, output.request);
    assert_eq!(owner.request.payload.as_slice(), output.request_bytes);
    assert_eq!(Arc::as_ptr(&owner.admission) as usize, output.admission);
    assert_eq!(Arc::as_ptr(&owner.admission.pool) as usize, output.pool);
    assert_eq!(owner.deadline.expires_at(), output.deadline);
    assert_eq!(
        std::ptr::from_ref(&owner.query) as usize,
        probe.original_query.unwrap()
    );
    assert_eq!(reply(owner), *probe.original_reply.as_ref().unwrap());
    assert_eq!(
        owner
            .reply
            .current_evidence()
            .map(|(record, _)| (record.as_ptr() as usize, record.to_vec())),
        probe.original_record,
        "same original CurrentCustody record across local stages",
    );
}
pub(super) fn advance(owner: &mut CompletedReply<'_>) -> Result<(), AttemptError> {
    let action = PROBE.with_borrow_mut(|slot| {
        let Some(probe) = slot else {
            return Mode::None;
        };
        if probe.original_reply.is_none() {
            let original = reply(owner);
            probe.audit.reply = Some(original.clone());
            probe.original_reply = Some(original);
            probe.original_record = owner
                .reply
                .current_evidence()
                .map(|(record, _)| (record.as_ptr() as usize, record.to_vec()));
            probe.audit.record = probe.original_record.clone();
            probe.original_query = Some(std::ptr::from_ref(&owner.query) as usize);
        }
        assert_original(owner, probe);
        if owner.phase == Phase::Qualified {
            let frame = owner.frame.as_ref().unwrap();
            probe.audit.encoded_frame = Some((frame.as_ptr() as usize, frame.to_vec()));
        }
        if probe.injected {
            if owner.phase == Phase::Observation && probe.mode == Mode::RefuseObservation {
                probe.audit.retry_checks += 1;
            }
            return Mode::None;
        }
        if owner.phase == Phase::Observation && probe.mode == Mode::RefuseObservation {
            probe.injected = true;
            return probe.mode;
        }
        if owner.phase == Phase::Qualified {
            let frame = owner.frame.as_ref().unwrap();
            probe.audit.encoded_frame = Some((frame.as_ptr() as usize, frame.to_vec()));
            if probe.mode == Mode::DriftAfterFrame {
                probe.drift.store(true, Ordering::SeqCst);
            }
            probe.injected = true;
            return probe.mode;
        }
        Mode::None
    });
    if action == Mode::ExpireAfterFrame
        && let Ok(remaining) = owner.deadline.remaining()
    {
        std::thread::sleep(remaining);
    }
    let previous = owner.phase;
    let result = if action == Mode::RefuseObservation {
        norito::core::with_decode_limits_scope(
            DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
            || owner.advance(),
        )
    } else {
        owner.advance()
    };
    if result.is_ok() {
        PROBE.with_borrow_mut(|slot| {
            if let Some(probe) = slot {
                let index = match previous {
                    Phase::Observation => 0,
                    Phase::Binding => 1,
                    Phase::Record => 2,
                    Phase::Leaf => 3,
                    Phase::Wire => 4,
                    Phase::Result => 5,
                    Phase::Digest => 6,
                    Phase::Response => 7,
                    Phase::Envelope => 8,
                    Phase::FrameBody => 9,
                    Phase::Frame => 10,
                    Phase::Qualified => 11,
                    Phase::Ready => return,
                };
                probe.audit.successful_phases[index] += 1;
                assert_eq!(
                    probe.audit.successful_phases[index], 1,
                    "no successful phase repeats"
                );
            }
        });
    }
    result
}
pub(super) fn refused(owner: &CompletedReply<'_>, error: &AttemptError) {
    PROBE.with_borrow_mut(|slot| {
        let Some(probe) = slot else {
            return;
        };
        assert_original(owner, probe);
        let AttemptError::Evidence(SignerStreamTokenEvidenceAdmissionErrorV1::Codec(original)) =
            error
        else {
            panic!("one real observation decode scope refusal");
        };
        assert_eq!(
            original.kind(),
            norito::core::DecodeAttemptErrorKind::EnclosingLimit
        );
        probe.audit.refusals += 1;
        assert_eq!(probe.audit.refusals, 1);
    });
}
