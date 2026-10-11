//! Install the original instruction registry after any concurrent decoder initialization.

use std::sync::{Arc, OnceLock, RwLock};

use super::InstructionRegistry;

/// Retain the supplied original registry regardless of who initializes the slot first.
///
/// Initialization admits only the supplied owner. Once initialization completes, the same
/// poison-aware write lock installs that owner; a competing initializer cannot discard it.
pub(super) fn install(
    slot: &OnceLock<RwLock<Arc<InstructionRegistry>>>,
    registry: Arc<InstructionRegistry>,
) {
    let lock = slot.get_or_init(|| RwLock::new(Arc::clone(&registry)));
    let mut guard = lock
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *guard = registry;
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use super::*;
    use crate::isi::Log;

    struct ReleaseInitialization(Option<mpsc::Sender<()>>);

    impl Drop for ReleaseInitialization {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                // On unwind the initializer still finishes naturally; a failed child cannot
                // strand a scoped sibling behind an unreleased initialization gate.
                let _ = sender.send(());
            }
        }
    }

    fn custom() -> Arc<InstructionRegistry> {
        Arc::new(InstructionRegistry::new().register_with_id::<Log>("test.original.install.log"))
    }

    fn assert_original(
        slot: &OnceLock<RwLock<Arc<InstructionRegistry>>>,
        supplied: &Arc<InstructionRegistry>,
    ) {
        let actual = slot
            .get()
            .expect("completed original install")
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            Arc::ptr_eq(&actual, supplied),
            "supplied registry owner was discarded"
        );
        assert_eq!(
            actual.wire_id(std::any::type_name::<Log>()),
            supplied.wire_id(std::any::type_name::<Log>())
        );
        assert_eq!(actual.len(), supplied.len());
    }

    #[test]
    fn install_retains_the_supplied_original_arc_in_cold_and_initialized_slots() {
        for initialized in [false, true] {
            let slot = OnceLock::new();
            if initialized {
                slot.get_or_init(|| RwLock::new(Arc::new(super::super::registry::default())));
            }
            let supplied = custom();
            install(&slot, Arc::clone(&supplied));
            assert_original(&slot, &supplied);
            assert_eq!(
                slot.get()
                    .unwrap()
                    .read()
                    .unwrap()
                    .wire_id(std::any::type_name::<Log>()),
                Some("test.original.install.log")
            );
        }
    }

    #[test]
    fn explicit_empty_install_removes_defaults_without_replacing_the_original_owner() {
        let slot = OnceLock::new();
        slot.get_or_init(|| RwLock::new(Arc::new(super::super::registry::default())));
        let supplied = Arc::new(InstructionRegistry::new());
        install(&slot, Arc::clone(&supplied));
        assert_original(&slot, &supplied);
        assert!(slot.get().unwrap().read().unwrap().is_empty());
        assert_eq!(
            slot.get()
                .unwrap()
                .read()
                .unwrap()
                .wire_id(std::any::type_name::<Log>()),
            None
        );
    }

    #[test]
    fn supplied_original_registry_survives_concurrent_default_initialization() {
        let slot = OnceLock::new();
        let (entered, initialization_entered) = mpsc::channel();
        let (release, initialization_released) = mpsc::channel();
        let (observed_none, original_observation) = mpsc::channel();
        let supplied = custom();
        std::thread::scope(|scope| {
            let release = ReleaseInitialization(Some(release));
            let slot_ref = &slot;
            let decoder = scope.spawn(move || {
                slot_ref.get_or_init(|| {
                    entered.send(()).expect("decoder entered initialization");
                    initialization_released
                        .recv()
                        .expect("original initialization release");
                    RwLock::new(Arc::new(super::super::registry::default()))
                });
            });
            // Decoder initialization is active before the real install worker begins.
            initialization_entered
                .recv()
                .expect("pending decoder initialization");
            let supplied_ref = &supplied;
            let installer = scope.spawn(move || {
                assert!(
                    slot_ref.get().is_none(),
                    "decoder must still be initializing"
                );
                // This sender belongs solely to the worker: a pre-send panic disconnects recv.
                observed_none
                    .send(())
                    .expect("original uninitialized observation");
                install(slot_ref, Arc::clone(supplied_ref));
            });
            original_observation
                .recv()
                .expect("installer reached the cold frontier");
            drop(release);
            decoder.join().expect("natural decoder completion");
            installer
                .join()
                .expect("natural original registry installation");
        });
        // The decoder wins initialization; the installer must still publish its exact Arc.
        assert_original(&slot, &supplied);
        assert_eq!(
            slot.get()
                .unwrap()
                .read()
                .unwrap()
                .wire_id(std::any::type_name::<Log>()),
            Some("test.original.install.log")
        );
    }

    #[test]
    fn initialization_release_guard_finishes_its_original_channel_during_unwind() {
        let (sender, released) = mpsc::channel();
        let outcome = std::panic::catch_unwind(move || {
            let _release = ReleaseInitialization(Some(sender));
            panic!("original fixture failed before installing its registry");
        });
        assert!(outcome.is_err());
        assert_eq!(released.recv(), Ok(()));
        assert_eq!(released.try_recv(), Err(mpsc::TryRecvError::Disconnected));
    }
}
