//! Temporary thread-local inclusive timings for the genuine custody body test helper.
//!
//! TODO: Remove this probe and its test-only spans once the unchanged native interval's cost is
//! localized. Counts and durations describe this helper scope only, not whole-runtime latency.

use std::{
    cell::RefCell,
    fmt::Write as _,
    io::Write as _,
    time::{Duration, Instant},
};

const CATEGORY_COUNT: usize = 11;

/// Fixed payload-free labels; no paths, keys, records, errors or caller text enter the report.
#[derive(Clone, Copy)]
pub(crate) enum Category {
    CheckpointImport,
    NativeVerifier,
    VerifiedTip,
    Profile,
    Unsigned,
    Initialize,
    Reopen,
    Read,
    Finish,
    FreshPredecessor,
    Sign,
}
const CATEGORIES: [(Category, &str); CATEGORY_COUNT] = [
    (Category::CheckpointImport, "finality_from_checkpoint"),
    (Category::NativeVerifier, "finality_native"),
    (Category::VerifiedTip, "finality_verified_tip"),
    (Category::Profile, "service_validate_profile"),
    (Category::Unsigned, "unsigned_validate"),
    (Category::Initialize, "body_initialize"),
    (Category::Reopen, "body_reopen"),
    (Category::Read, "body_read"),
    (Category::Finish, "body_finish"),
    (Category::FreshPredecessor, "body_fresh_predecessor"),
    (Category::Sign, "body_sign"),
];

#[derive(Clone, Copy, Default)]
struct Metric {
    calls: u64,
    inclusive: Duration,
}
struct Measurement {
    id: u64,
    started: Instant,
    metrics: [Metric; CATEGORY_COUNT],
}
#[derive(Default)]
struct State {
    next_id: u64,
    active: Option<Measurement>,
}
thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

/// Own one helper's report; a nested helper contributes to the existing outer scope.
pub(crate) struct Scope {
    id: Option<u64>,
}
impl Scope {
    pub(crate) fn enter() -> Self {
        let id = STATE.with(|state| {
            let mut state = state.borrow_mut();
            if state.active.is_some() {
                return None;
            }
            let id = state.next_id.checked_add(1)?;
            state.next_id = id;
            state.active = Some(Measurement {
                id,
                started: Instant::now(),
                metrics: [Metric::default(); CATEGORY_COUNT],
            });
            Some(id)
        });
        Self { id }
    }
    fn finish(&mut self) -> Option<Measurement> {
        let id = self.id.take()?;
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            if state.active.as_ref().is_some_and(|active| active.id == id) {
                state.active.take()
            } else {
                None
            }
        })
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        if let Some(measurement) = self.finish() {
            let report = measurement.render();
            // A failed diagnostic write must not replace the original failure while unwinding.
            let _ = std::io::stderr().lock().write_all(report.as_bytes());
        }
    }
}
impl Measurement {
    fn render(&self) -> String {
        let mut output = String::new();
        let _ = writeln!(
            output,
            "custody-timing helper_scope_ms={:.3}; category times are inclusive, overlap, and must not be summed",
            self.started.elapsed().as_secs_f64() * 1000.0
        );
        for (category, name) in CATEGORIES {
            let metric = self.metrics[category as usize];
            let _ = writeln!(
                output,
                "custody-timing {name}: calls={} inclusive_ms={:.3}",
                metric.calls,
                metric.inclusive.as_secs_f64() * 1000.0
            );
        }
        output
    }
}

/// Attribute inclusive time only while this thread owns the selected helper scope.
pub(crate) struct Span {
    active: Option<(u64, Instant)>,
    category: Category,
}
impl Span {
    pub(crate) fn enter(category: Category) -> Self {
        let active = STATE.with(|state| {
            state
                .borrow()
                .active
                .as_ref()
                .map(|scope| (scope.id, Instant::now()))
        });
        Self { active, category }
    }
}
impl Drop for Span {
    fn drop(&mut self) {
        let Some((id, started)) = self.active else {
            return;
        };
        let elapsed = started.elapsed();
        STATE.with(|state| {
            if let Some(scope) = state.borrow_mut().active.as_mut()
                && scope.id == id
            {
                let metric = &mut scope.metrics[self.category as usize];
                metric.calls = metric.calls.saturating_add(1);
                metric.inclusive = metric.inclusive.saturating_add(elapsed);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inactive_nested_and_previous_scope_spans_cannot_replace_the_owned_report() {
        drop(Span::enter(Category::Profile));
        let mut scope = Scope::enter();
        let stale = Span::enter(Category::Profile);
        {
            let _nested = Scope::enter();
            let _outer_span = Span::enter(Category::Finish);
            let _inner_span = Span::enter(Category::Read);
        }
        let measured = scope.finish().unwrap();
        assert!(scope.finish().is_none());
        assert_eq!(measured.metrics[Category::Finish as usize].calls, 1);
        assert_eq!(measured.metrics[Category::Read as usize].calls, 1);
        assert_eq!(measured.metrics[Category::Profile as usize].calls, 0);
        let report = measured.render();
        assert!(report.contains("inclusive, overlap, and must not be summed"));
        assert_eq!(report.lines().count(), CATEGORY_COUNT + 1);
        let mut next = Scope::enter();
        drop(stale);
        assert_eq!(
            next.finish().unwrap().metrics[Category::Profile as usize].calls,
            0
        );
    }

    #[test]
    fn panic_unwinds_spans_and_releases_the_report_scope_before_the_next_helper() {
        let result = std::panic::catch_unwind(|| {
            let _scope = Scope::enter();
            let _span = Span::enter(Category::Initialize);
            panic!("deliberate local diagnostic unwind");
        });
        assert!(result.is_err());
        assert!(STATE.with(|state| state.borrow().active.is_none()));
        let mut next = Scope::enter();
        drop(Span::enter(Category::Sign));
        let measured = next.finish().unwrap();
        assert_eq!(measured.metrics[Category::Initialize as usize].calls, 0);
        assert_eq!(measured.metrics[Category::Sign as usize].calls, 1);
    }
}
