//! One-shot physical I/O at the original immutable publication boundary in tests.

use std::{cell::RefCell, io};
type Hook = Box<dyn FnOnce() -> io::Result<()>>;
thread_local! { static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) }; }
pub(crate) struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        HOOK.with(|hook| {
            hook.borrow_mut().take();
        });
    }
}
pub(crate) fn install(hook: impl FnOnce() -> io::Result<()> + 'static) -> Guard {
    HOOK.with(|current| {
        assert!(
            current.borrow().is_none(),
            "one original publication observation per thread"
        );
        *current.borrow_mut() = Some(Box::new(hook));
    });
    Guard
}
pub(super) fn run() -> io::Result<()> {
    let original = HOOK.with(|hook| hook.borrow_mut().take());
    match original {
        Some(hook) => hook(),
        None => Ok(()),
    }
}
