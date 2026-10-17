//! Test-only execution conditions shared by native proof diagnostics.

/// Require the same disabled-debug-assertions condition as the release-only proof tests.
///
/// # Panics
/// Panics with the caller's diagnostic when debug assertions are compiled in. The guard remains
/// a runtime refusal, so ordinary test discovery and compilation still work in debug builds.
#[cfg(debug_assertions)]
pub fn require_no_debug_assertions(message: &str) {
    panic!("{message}");
}

/// Permit a release-only proof test when debug assertions are compiled out.
#[cfg(not(debug_assertions))]
pub fn require_no_debug_assertions(_message: &str) {}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "release-only profile guard")]
fn debug_profile_refuses_before_the_release_only_work() {
    require_no_debug_assertions("release-only profile guard");
    panic!("the debug guard returned instead of refusing");
}

#[cfg(not(debug_assertions))]
#[test]
fn release_profile_permits_the_release_only_work() {
    require_no_debug_assertions("release-only profile guard");
}
