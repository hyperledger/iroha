//! Allocator observations shared by the two native body integration targets.

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    marker::PhantomData,
    panic::{catch_unwind, AssertUnwindSafe},
    pin::Pin,
    ptr,
    sync::Arc,
    task::{Context, Poll, Wake, Waker},
};

#[derive(Clone, Copy)]
struct Observation {
    body_layout: Layout,
    token_layout: Layout,
    body_pointer: usize,
    token_pointer: usize,
    allocation_step: u8,
    allocations: usize,
    release_step: u8,
    refuse_step: u8,
    body_drops: u8,
    token_drops: u8,
    bad_order: bool,
}

thread_local! {
    static OBSERVATION: Cell<Option<Observation>> = const { Cell::new(None) };
}

struct ObservedAllocator;

#[global_allocator]
static ALLOCATOR: ObservedAllocator = ObservedAllocator;

// This isolated fixture delegates each original allocation to System and
// observes only the current test thread's two exact native layouts. Allocator
// hooks never panic, allocate, or call a body's destructor.
unsafe impl GlobalAlloc for ObservedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut tracked_step = 0;
        let mut refuse = false;
        let _ = OBSERVATION.try_with(|cell| {
            if let Some(mut observation) = cell.get() {
                observation.allocations += 1;
                cell.set(Some(observation));
                let expected = match observation.allocation_step {
                    0 => observation.body_layout,
                    1 => observation.token_layout,
                    _ => return,
                };
                if layout == expected {
                    tracked_step = observation.allocation_step + 1;
                    refuse = tracked_step == observation.refuse_step;
                    observation.allocation_step += 1;
                    cell.set(Some(observation));
                }
            }
        });
        if refuse {
            return ptr::null_mut();
        }
        // SAFETY: GlobalAlloc's caller supplied a valid nonzero layout.
        let allocation = unsafe { System.alloc(layout) };
        if tracked_step != 0 {
            let _ = OBSERVATION.try_with(|cell| {
                if let Some(mut observation) = cell.get() {
                    if tracked_step == 1 {
                        observation.body_pointer = allocation as usize;
                    } else {
                        observation.token_pointer = allocation as usize;
                    }
                    cell.set(Some(observation));
                }
            });
        }
        allocation
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: GlobalAlloc's caller supplied the original pointer/layout.
        // Record the observation after the actual native deallocation.
        unsafe { System.dealloc(pointer, layout) };
        let _ = OBSERVATION.try_with(|cell| {
            if let Some(mut observation) = cell.get() {
                if pointer as usize == observation.body_pointer {
                    observation.bad_order |=
                        observation.release_step != 0 || layout != observation.body_layout;
                    observation.release_step = 1;
                } else if pointer as usize == observation.token_pointer {
                    observation.bad_order |=
                        observation.release_step != 1 || layout != observation.token_layout;
                    observation.release_step = 2;
                }
                cell.set(Some(observation));
            }
        });
    }
}

/// A body with a distinct nonzero allocation and intact returned identity.
#[repr(align(256))]
#[derive(Debug)]
pub(super) struct ProbeBody<E> {
    data: Option<Bytes>,
    identity: u64,
    pending: bool,
    panic_on_drop: bool,
    marker: PhantomData<fn() -> E>,
}

impl<E> ProbeBody<E> {
    fn new(data: Option<Bytes>, pending: bool, panic_on_drop: bool) -> Self {
        Self {
            data,
            identity: 0x1357_2468_ace0_bdf9,
            pending,
            panic_on_drop,
            marker: PhantomData,
        }
    }
}

impl<E> Drop for ProbeBody<E> {
    fn drop(&mut self) {
        OBSERVATION.with(|cell| {
            if let Some(mut observation) = cell.get() {
                observation.body_drops += 1;
                observation.bad_order |=
                    observation.release_step != 0 || observation.token_drops != 0;
                cell.set(Some(observation));
            }
        });
        if self.panic_on_drop {
            panic!("intentional body destructor panic");
        }
    }
}

impl<E> Body for ProbeBody<E> {
    type Data = Bytes;
    type Error = E;

    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, E>>> {
        let this = self.get_mut();
        if this.pending {
            Poll::Pending
        } else {
            Poll::Ready(this.data.take().map(|data| Ok(Frame::data(data))))
        }
    }

    fn is_end_stream(&self) -> bool {
        !self.pending && self.data.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        let mut hint = SizeHint::new();
        if !self.pending {
            hint.set_exact(self.data.as_ref().map_or(0, |bytes| bytes.len() as u64));
        }
        hint
    }
}

/// A token with a distinct exact allocation and original returned identity.
#[repr(align(128))]
#[derive(Debug)]
pub(super) struct ProbeToken {
    identity: u64,
    contents: [u8; 17],
}

impl ProbeToken {
    fn new() -> Self {
        Self {
            identity: 0xfedc_ba98_7654_3210,
            contents: [0x5a; 17],
        }
    }
}

impl Drop for ProbeToken {
    fn drop(&mut self) {
        OBSERVATION.with(|cell| {
            if let Some(mut observation) = cell.get() {
                observation.token_drops += 1;
                observation.bad_order |=
                    observation.release_step != 2 || observation.body_drops != 1;
                cell.set(Some(observation));
            }
        });
    }
}

struct NoopWake;

impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

fn start(body_layout: Layout, token_layout: Layout, refuse_step: u8) {
    OBSERVATION.with(|cell| {
        assert!(cell.get().is_none());
        cell.set(Some(Observation {
            body_layout,
            token_layout,
            body_pointer: 0,
            token_pointer: 0,
            allocation_step: 0,
            allocations: 0,
            release_step: 0,
            refuse_step,
            body_drops: 0,
            token_drops: 0,
            bad_order: false,
        }));
    });
}

fn finish() -> Observation {
    OBSERVATION.with(|cell| cell.take().expect("active allocator observation"))
}

/// Exercise data, cancellation, refusal and panic cleanup against actual
/// allocator deallocations for the supplied native constructor.
pub(super) fn verify<B, E, F>(constructor: F, body_layout: Layout, token_layout: Layout)
where
    B: Body<Data = Bytes, Error = E> + Unpin,
    F: Fn(ProbeBody<E>, ProbeToken) -> Result<B, (ProbeBody<E>, ProbeToken)>,
{
    assert_eq!(body_layout, Layout::new::<ProbeBody<E>>());
    assert_eq!(token_layout, Layout::new::<ProbeToken>());
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);

    for (data, pending, panic_on_drop) in [
        (None, false, false),
        (Some(Bytes::new()), false, false),
        (Some(Bytes::from_static(b"native frame")), false, false),
        (None, true, false),
        (None, false, true),
    ] {
        let expected_data = data.clone();
        start(body_layout, token_layout, 0);
        let Ok(mut body) = constructor(
            ProbeBody::new(data, pending, panic_on_drop),
            ProbeToken::new(),
        ) else {
            panic!("native body allocation unexpectedly refused");
        };
        OBSERVATION.with(|cell| {
            assert_eq!(
                cell.get()
                    .expect("active allocator observation")
                    .allocations,
                2
            );
        });
        assert_eq!(body.is_end_stream(), !pending && expected_data.is_none());
        assert_eq!(
            body.size_hint().lower(),
            expected_data.as_ref().map_or(0, |bytes| bytes.len() as u64)
        );
        match Pin::new(&mut body).poll_frame(&mut context) {
            Poll::Pending => assert!(pending),
            Poll::Ready(Some(Ok(frame))) => {
                assert!(!pending);
                let Ok(bytes) = frame.into_data() else {
                    panic!("expected data frame");
                };
                assert_eq!(Some(bytes), expected_data);
            }
            Poll::Ready(None) => assert!(expected_data.is_none() && !pending),
            Poll::Ready(Some(Err(_))) => panic!("unexpected body error"),
        }
        let result = catch_unwind(AssertUnwindSafe(|| drop(body)));
        let observation = finish();
        assert_eq!(result.is_err(), panic_on_drop);
        assert_eq!(observation.allocation_step, 2);
        assert_ne!(observation.body_pointer, 0);
        assert_ne!(observation.token_pointer, 0);
        assert_eq!(observation.release_step, 2);
        assert_eq!(observation.body_drops, 1);
        assert_eq!(observation.token_drops, 1);
        assert!(!observation.bad_order);
    }

    for refuse_step in [1, 2] {
        start(body_layout, token_layout, refuse_step);
        let Err((body, token)) = constructor(
            ProbeBody::new(Some(Bytes::from_static(b"unchanged")), true, false),
            ProbeToken::new(),
        ) else {
            panic!("constructor ignored allocator refusal");
        };
        let observation = finish();
        assert_eq!(observation.allocation_step, refuse_step);
        assert_eq!(observation.body_drops, 0);
        assert_eq!(observation.token_drops, 0);
        assert_eq!(
            observation.release_step,
            if refuse_step == 2 { 1 } else { 0 }
        );
        assert!(!observation.bad_order);
        assert_eq!(body.identity, 0x1357_2468_ace0_bdf9);
        assert_eq!(body.data.as_deref(), Some(&b"unchanged"[..]));
        assert!(body.pending);
        assert!(!body.panic_on_drop);
        assert_eq!(token.identity, 0xfedc_ba98_7654_3210);
        assert_eq!(token.contents, [0x5a; 17]);
        drop((body, token));
    }
}

/// Check that the original constructor still has only its body allocation.
pub(super) fn verify_plain<B, E, F>(constructor: F, body_layout: Layout)
where
    B: Body<Data = Bytes, Error = E> + Unpin,
    F: Fn(ProbeBody<E>) -> B,
{
    start(body_layout, Layout::new::<ProbeToken>(), 0);
    let body = constructor(ProbeBody::new(None, false, false));
    assert!(body.is_end_stream());
    drop(body);
    let observation = finish();
    assert_eq!(observation.allocations, 1);
    assert_eq!(observation.allocation_step, 1);
    assert_eq!(observation.release_step, 1);
    assert_eq!(observation.body_drops, 1);
    assert_eq!(observation.token_drops, 0);
    assert_eq!(observation.token_pointer, 0);
    assert!(!observation.bad_order);
}
