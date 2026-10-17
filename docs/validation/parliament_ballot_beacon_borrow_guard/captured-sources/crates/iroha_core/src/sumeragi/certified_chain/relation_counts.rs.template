//! Thread-local test observations of actual frame and QC relations; never finality authority.

use std::cell::RefCell;

#[derive(Default, Debug)]
pub(crate) struct Counts {
    pub(crate) frames: Vec<u64>,
    pub(crate) qcs: Vec<u64>,
}
thread_local! { static ACTIVE: RefCell<Option<Counts>> = const { RefCell::new(None) }; }

pub(super) fn frame(height: u64) {
    ACTIVE.with_borrow_mut(|active| {
        if let Some(counts) = active {
            counts.frames.push(height);
        }
    });
}
pub(super) fn qc(height: u64) {
    ACTIVE.with_borrow_mut(|active| {
        if let Some(counts) = active {
            counts.qcs.push(height);
        }
    });
}
pub(crate) fn measure<T>(run: impl FnOnce() -> T) -> (T, Counts) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            ACTIVE.with_borrow_mut(|active| *active = None);
        }
    }
    ACTIVE.with_borrow_mut(|active| {
        assert!(active.is_none(), "nested relation observation");
        *active = Some(Counts::default());
    });
    let reset = Reset;
    let result = run();
    let counts = ACTIVE.with_borrow_mut(|active| active.take().unwrap());
    drop(reset);
    (result, counts)
}
