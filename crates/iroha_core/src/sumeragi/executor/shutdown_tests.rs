//! Shutdown owns the real worker through accepted requests and storage release.

use std::{
    cell::RefCell,
    sync::atomic::{AtomicBool, Ordering},
};

use super::*;
use crate::{
    state::World,
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_data_model::{
    Level,
    isi::{InstructionBox, Log},
};

type ExitHook = Box<dyn FnOnce() + Send>;

thread_local! {
    // A hook is consumed by one real spawn on this test thread, never another test.
    static EXIT_HOOK: RefCell<Option<ExitHook>> = const { RefCell::new(None) };
}

pub(super) fn take_exit_hook() -> Option<ExitHook> {
    EXIT_HOOK.with(|hook| hook.borrow_mut().take())
}

struct HookRestore(Option<ExitHook>);

impl Drop for HookRestore {
    fn drop(&mut self) {
        EXIT_HOOK.with(|hook| *hook.borrow_mut() = self.0.take());
    }
}

fn before_worker_release(hook: impl FnOnce() + Send + 'static) -> HookRestore {
    HookRestore(EXIT_HOOK.with(|slot| slot.replace(Some(Box::new(hook)))))
}

// Releasing the gate during unwinding also lets an owned shutdown thread finish.
struct Release(Option<mpsc::Sender<()>>);

impl Release {
    fn now(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

impl Drop for Release {
    fn drop(&mut self) {
        self.now();
    }
}

// Own every spawned shutdown thread even if an observation/assertion fails.
struct ShutdownOwner {
    release: Release,
    thread: Option<JoinHandle<()>>,
}

impl ShutdownOwner {
    fn finish(&mut self) -> std::thread::Result<()> {
        self.release.now();
        self.thread.take().map_or(Ok(()), JoinHandle::join)
    }
}

impl Drop for ShutdownOwner {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

const WAIT: Duration = Duration::from_secs(10);

#[test]
fn chain_drop_waits_for_original_worker_and_removes_temporary_storage() {
    super::super::threads::sumeragi_thread_builder("executor-chain-drop-test")
        .spawn(|| {
            let (at_exit, exit) = mpsc::channel();
            let (release, released) = mpsc::channel();
            let armed = Arc::new(AtomicBool::new(false));
            let worker_armed = Arc::clone(&armed);
            let _restore = before_worker_release(move || {
                if worker_armed.load(Ordering::Acquire) {
                    let _ = at_exit.send(());
                    // A failed fixture/thread spawn cannot leave this test gated forever.
                    let _ = released.recv_timeout(WAIT);
                }
            });
            let config = TestChainConfig::new(World::new(), 1_000);
            let key = config.genesis_key.clone();
            let mut chain = CertifiedTestChain::start(config).expect("actual signed genesis");
            let transaction = chain.sign(
                &key,
                [InstructionBox::from(Log::new(
                    Level::INFO,
                    "shutdown".into(),
                ))],
                1_001,
            );
            assert_eq!(chain.commit_at(2_000, vec![transaction]), [true]);
            assert_eq!(chain.height(), 2);
            let storage = chain.kura().store_root();
            let state = Arc::downgrade(chain.state());
            let kura = Arc::downgrade(chain.kura());
            assert!(storage.is_dir());
            let (done, completed) = mpsc::channel();
            let (begin, begun) = mpsc::channel();
            let owner = super::super::threads::sumeragi_thread_builder("executor-chain-owner-drop")
                .spawn(move || {
                    let _ = begun.recv();
                    drop(chain);
                    let _ = done.send(());
                })
                .unwrap();
            let mut owner = ShutdownOwner {
                release: Release(Some(release)),
                thread: Some(owner),
            };
            // Setup failures drop an unarmed original worker; only this owned drop is gated.
            armed.store(true, Ordering::Release);
            begin.send(()).unwrap();
            exit.recv_timeout(WAIT)
                .expect("original worker observed sender disconnection");
            let returned_before_release = completed.recv_timeout(Duration::from_millis(100));
            let original_still_owned = state.upgrade().is_some() && kura.upgrade().is_some();
            let storage_still_owned = storage.is_dir();
            owner.finish().unwrap();
            if returned_before_release.is_err() {
                completed.recv_timeout(WAIT).expect("joined chain shutdown");
            }
            assert!(
                matches!(
                    returned_before_release,
                    Err(mpsc::RecvTimeoutError::Timeout)
                ),
                "Drop must wait for the original worker, not merely detach its handle"
            );
            assert!(original_still_owned && storage_still_owned);
            assert!(state.upgrade().is_none());
            assert!(kura.upgrade().is_none());
            assert!(
                !storage.exists(),
                "last chain owner releases its actual temporary store"
            );
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn shutdown_drains_accepted_work_and_abandoned_reply_while_world_is_held() {
    publication_tests::with_worker(|chain, worker, _blocks, _events| {
        let executor = StateExecutor::spawn(worker.context.clone()).unwrap();
        let (entered, started) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let release = Release(Some(release));
        executor
            .requests
            .as_ref()
            .unwrap()
            .send(Request::InspectPrepared(
                Hash32::ZERO,
                Box::new(move |original| {
                    assert!(original.is_err(), "no invented prepared execution");
                    entered.send(()).unwrap();
                    let _ = released.recv_timeout(WAIT);
                }),
            ))
            .unwrap();
        started.recv_timeout(WAIT).unwrap();
        let served = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&served);
        let (reply, abandoned) = mpsc::sync_channel(1);
        drop(abandoned);
        // This accepted request remains in the real capacity-one queue at shutdown.
        executor
            .requests
            .as_ref()
            .unwrap()
            .send(Request::InspectPrepared(
                Hash32::ZERO,
                Box::new(move |original| {
                    assert!(original.is_err());
                    observed.store(true, Ordering::Release);
                    assert!(reply.send(()).is_err());
                }),
            ))
            .unwrap();
        let world = chain.state().world.block();
        let (done, completed) = mpsc::channel();
        let owner = super::super::threads::sumeragi_thread_builder("executor-queued-owner-drop")
            .spawn(move || {
                drop(executor);
                done.send(()).unwrap();
            })
            .unwrap();
        let mut owner = ShutdownOwner {
            release,
            thread: Some(owner),
        };
        owner.release.now();
        let finished = completed.recv_timeout(WAIT);
        // Release the actual writer even on a regression before joining the owned thread.
        drop(world);
        owner.finish().unwrap();
        finished.expect("shutdown must not wait for a held World writer or abandoned reply");
        assert!(
            served.load(Ordering::Acquire),
            "accepted work was drained before Drop returned"
        );
    });
}

#[test]
fn worker_panic_does_not_panic_the_owner_destructor() {
    publication_tests::with_worker(|_chain, worker, _blocks, _events| {
        for unwinding in [false, true] {
            let _restore = before_worker_release(|| panic!("test worker exit panic"));
            let executor = StateExecutor::spawn(worker.context.clone()).unwrap();
            let dropped = catch_unwind(AssertUnwindSafe(move || {
                let _owner = executor;
                if unwinding {
                    panic!("original caller unwind");
                }
            }));
            if unwinding {
                assert_eq!(
                    dropped.unwrap_err().downcast_ref::<&str>(),
                    Some(&"original caller unwind"),
                    "worker join must preserve the original caller panic"
                );
            } else {
                assert!(
                    dropped.is_ok(),
                    "worker panic must not panic the owner destructor"
                );
            }
            assert!(
                take_exit_hook().is_none(),
                "this original spawn consumed its hook"
            );
        }
    });
}
