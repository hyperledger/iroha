//! One actual enclosing decode refusal in the received-frame owner's production step.
use super::*;
use std::{cell::RefCell, os::fd::AsRawFd};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super::super) enum Point {
    Frame,
    Response,
    Reply,
    Observation,
}
impl Point {
    fn matches(self, phase: Phase) -> bool {
        matches!(
            (self, phase),
            (Self::Frame, Phase::Frame)
                | (Self::Response, Phase::Response)
                | (Self::Reply, Phase::Reply)
                | (Self::Observation, Phase::Observation)
        )
    }
}
#[derive(Debug, PartialEq, Eq)]
struct Identity {
    request: usize,
    query: usize,
    frame: usize,
    bytes: Vec<u8>,
    request_bytes: Vec<u8>,
    deadline: std::time::Instant,
    admission: usize,
    pool: usize,
    socket: std::os::fd::RawFd,
    session: [u8; 32],
    retired_next: u64,
    reply: Option<(usize, Vec<u8>)>,
}
impl Identity {
    fn of(owner: &ObservationResponse<'_, '_>) -> Self {
        let exchange = &owner.exchange;
        Self {
            request: std::ptr::from_ref(exchange.request) as usize,
            query: std::ptr::from_ref(owner.expected) as usize,
            frame: exchange.response_frame.as_ptr() as usize,
            bytes: exchange.response_frame.to_vec(),
            request_bytes: exchange.request.payload.clone(),
            deadline: exchange.deadline.expires_at(),
            admission: Arc::as_ptr(&exchange.decode_admission) as usize,
            pool: Arc::as_ptr(&exchange.decode_admission.pool) as usize,
            socket: exchange.connection.stream.as_raw_fd(),
            session: exchange.connection.session_id,
            retired_next: exchange.connection.next_request_id,
            reply: owner.reply.as_ref().map(|reply| {
                let bytes = reply.completed_observation().unwrap();
                (bytes.as_ptr() as usize, bytes.to_vec())
            }),
        }
    }
}
#[derive(Default, Debug)]
pub(in super::super::super) struct Audit {
    pub(in super::super::super) refusals: usize,
    pub(in super::super::super) retry_identity_checks: usize,
    pub(in super::super::super) reply: Option<(usize, Vec<u8>)>,
    pub(in super::super::super) deadline: Option<std::time::Instant>,
}
struct Probe {
    point: Point,
    identity: Option<Identity>,
    audit: Audit,
    expire_on_refusal: bool,
}
thread_local! { static PROBE: RefCell<Option<Probe>> = const { RefCell::new(None) }; }

pub(in super::super::super) fn measure<T>(
    point: Point,
    expire_on_refusal: bool,
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
            point,
            identity: None,
            audit: Audit::default(),
            expire_on_refusal,
        });
    });
    let reset = Reset;
    let value = action();
    let probe = PROBE.with_borrow_mut(|slot| slot.take().unwrap());
    drop(reset);
    (value, probe.audit)
}

pub(super) fn advance(
    owner: &mut ObservationResponse<'_, '_>,
) -> Result<Option<StreamTokenObserverReplyV1>, AttemptError> {
    let inject = PROBE.with_borrow_mut(|slot| {
        let Some(probe) = slot else {
            return false;
        };
        if !probe.point.matches(owner.phase) {
            return false;
        }
        let current = Identity::of(owner);
        if let Some(original) = &probe.identity {
            assert_eq!(
                &current, original,
                "same frame/request/socket/admission/deadline after refusal"
            );
            probe.audit.retry_identity_checks += 1;
            return false;
        }
        probe.audit.deadline = Some(current.deadline);
        probe.audit.reply = current.reply.clone();
        probe.identity = Some(current);
        true
    });
    if inject {
        // This is the real enclosing scope, not a reconstructed error or a new
        // process-pool grant. It retires before the bounded local wait starts.
        norito::core::with_decode_limits_scope(
            DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
            || owner.advance(),
        )
    } else {
        owner.advance()
    }
}

pub(super) fn refused(owner: &ObservationResponse<'_, '_>, error: &AttemptError) {
    let expire = PROBE.with_borrow_mut(|slot| {
        let Some(probe) = slot else {
            return false;
        };
        assert_eq!(Some(&Identity::of(owner)), probe.identity.as_ref());
        let original = match error {
            AttemptError::Canonical(CanonicalAttemptErrorV1::Decode(original)) => original,
            AttemptError::Evidence(SignerStreamTokenEvidenceAdmissionErrorV1::Codec(original)) => {
                original
            }
            _ => panic!("actual enclosing canonical decode must retain its original cause"),
        };
        assert_eq!(
            original.kind(),
            norito::core::DecodeAttemptErrorKind::EnclosingLimit
        );
        probe.audit.refusals += 1;
        assert_eq!(probe.audit.refusals, 1);
        probe.expire_on_refusal
    });
    if expire {
        if let Ok(remaining) = owner.exchange.deadline.remaining() {
            std::thread::sleep(remaining);
        }
        assert!(owner.exchange.deadline.remaining().is_err());
    }
}
