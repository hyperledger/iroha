//! Actual allocation observations for the shared static Musubi rejection owner.

#[path = "../src/state/deserialize_world_musubi_rejection.rs"]
mod rejection;

use rejection::{ProjectionCut, ProjectionRejection, ProjectionTable};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    fmt::Write as _,
};

thread_local! {
    static COUNT: Cell<Option<usize>> = const { Cell::new(None) };
}
struct Allocator;
fn record_allocation() {
    let _ = COUNT.try_with(|count| {
        if let Some(value) = count.get() {
            count.set(Some(value + 1));
        }
    });
}
#[allow(unsafe_code)]
// SAFETY: every allocation delegates its original request to System.
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        // SAFETY: the unmodified request is passed to the system allocator.
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        // SAFETY: the unmodified request is passed to the system allocator.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record_allocation();
        // SAFETY: the original allocation and requested size are forwarded.
        unsafe { System.realloc(pointer, layout, size) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: the original pointer and layout return to the same allocator.
        unsafe { System.dealloc(pointer, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

struct Observation;
impl Drop for Observation {
    fn drop(&mut self) {
        COUNT.with(|count| count.set(None));
    }
}
fn allocations_during<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    COUNT.with(|count| {
        assert!(count.get().is_none(), "observations must not overlap");
        count.set(Some(0));
    });
    let observation = Observation;
    let result = operation();
    let count = COUNT.with(|count| count.get().unwrap());
    drop(observation);
    (result, count)
}

const TABLES: [ProjectionTable; 6] = [
    ProjectionTable::Archives,
    ProjectionTable::ArchiveLocations,
    ProjectionTable::ProviderBundleAttestations,
    ProjectionTable::ArchiveAvailability,
    ProjectionTable::ResolverIndex,
    ProjectionTable::PublicDirectory,
];
const CUTS: [(Option<ProjectionCut>, &str); 5] = [
    (None, ""),
    (Some(ProjectionCut::Current), "current World cut: "),
    (Some(ProjectionCut::Predecessor), "predecessor World cut: "),
    (Some(ProjectionCut::Capture), "capture World cut: "),
    (Some(ProjectionCut::Candidate), "candidate World cut: "),
];
struct Text {
    bytes: [u8; 512],
    len: usize,
}
impl Text {
    fn new() -> Self {
        Self {
            bytes: [0; 512],
            len: 0,
        }
    }
    fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..self.len]).unwrap()
    }
}
impl std::fmt::Write for Text {
    fn write_str(&mut self, value: &str) -> std::fmt::Result {
        let end = self.len.checked_add(value.len()).ok_or(std::fmt::Error)?;
        self.bytes
            .get_mut(self.len..end)
            .ok_or(std::fmt::Error)?
            .copy_from_slice(value.as_bytes());
        self.len = end;
        Ok(())
    }
}

#[test]
fn static_rejections_preserve_all_contexts_and_format_without_allocation() {
    let model_error = iroha_model_base::error::ParseError::new("model reason: λ");
    for table in TABLES {
        for (cut, prefix) in CUTS {
            let expected = format!(
                "JSON error: invalid field `{}`: {prefix}{}",
                table.field(),
                model_error.reason()
            );
            let ((rejection, text), count) = allocations_during(|| {
                let rejection = ProjectionRejection::new(table, model_error.reason());
                let rejection = cut.map_or(rejection, |cut| rejection.with_cut(cut));
                let copied = std::hint::black_box(rejection);
                let mut text = Text::new();
                write!(&mut text, "{copied}").unwrap();
                (copied, text)
            });
            assert_eq!(count, 0, "static owner and borrowed output cannot allocate");
            assert_eq!(text.as_str(), expected);
            assert_eq!(rejection.field(), table.field());
            assert_eq!(rejection.reason(), model_error.reason());
            assert!(std::ptr::eq(rejection.reason(), model_error.reason()));
        }
    }
    assert!(!std::mem::needs_drop::<ProjectionRejection>());
}

#[test]
fn owned_restore_rendering_matches_the_original_json_error_exactly() {
    for table in TABLES {
        for (cut, prefix) in CUTS {
            let rejection = ProjectionRejection::new(table, "exact failure");
            let rejection = cut.map_or(rejection, |cut| rejection.with_cut(cut));
            let expected = norito::json::Error::InvalidField {
                field: table.field().to_owned(),
                message: format!("{prefix}exact failure"),
            };
            let (actual, count) = allocations_during(|| rejection.into_json());
            assert!(
                count >= 2,
                "the existing owned boundary is explicitly outside static custody"
            );
            assert_eq!(actual.to_string(), expected.to_string());
            let norito::json::Error::InvalidField { field, message } = actual else {
                panic!("restore keeps the exact original error shape")
            };
            assert_eq!(field, table.field());
            assert_eq!(message, format!("{prefix}exact failure"));
            assert_eq!(rejection.to_string(), expected.to_string());
        }
    }
}

#[test]
fn allocator_observer_detects_backing_growth_and_recovers_after_unwind() {
    let (value, count) = allocations_during(|| {
        let mut value = Vec::with_capacity(std::hint::black_box(8));
        value.resize(8, 0_u8);
        value.reserve_exact(std::hint::black_box(1024));
        std::hint::black_box(value)
    });
    assert!(count >= 2);
    drop(value);
    let _ = std::panic::catch_unwind(|| allocations_during(|| panic!("observer unwind")));
    let (_rejection, count) = allocations_during(|| {
        std::hint::black_box(ProjectionRejection::new(
            ProjectionTable::Archives,
            "static",
        ))
    });
    assert_eq!(count, 0);
}
