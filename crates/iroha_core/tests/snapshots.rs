//! Test helpers for fixture-backed event snapshots.

#![allow(dead_code)]
use iroha_data_model::events::prelude::EventBox;
use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
};
/// Serialize events to canonical JSON, filtering out non-deterministic kinds.
pub fn events_json_filtered(events: &[EventBox]) -> String {
    let mut filtered: Vec<_> = events
        .iter()
        .filter(|e| {
            !matches!(
                e,
                EventBox::Time(_) | EventBox::Pipeline(_) | EventBox::PipelineBatch(_)
            )
        })
        .cloned()
        .collect();
    // Sort deterministically by JSON representation so parallel/sequential ordering differences don't churn fixtures.
    filtered.sort_by(|a, b| {
        let aj = norito::json::to_json(a).expect("serialize event");
        let bj = norito::json::to_json(b).expect("serialize event");
        aj.cmp(&bj)
    });
    norito::json::to_json_pretty(&filtered).expect("serialization should succeed")
}
fn fixtures_dir() -> PathBuf {
    // Integration test crate root is the iroha_core crate directory
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("fixtures");
    p
}
fn fixture_path(name: &str) -> PathBuf {
    let mut p = fixtures_dir();
    p.push(format!("{name}.json"));
    p
}
fn write_if_update_requested(path: &Path, content: &str) -> bool {
    let update = env::var("UPDATE_FIXTURES")
        .ok()
        .filter(|v| v == "1" || v.eq_ignore_ascii_case("true"));
    if update.is_some() {
        if let Some(dir) = path.parent() {
            let _ = fs::create_dir_all(dir);
        }
        let mut f = fs::File::create(path).expect("create fixture file");
        f.write_all(content.as_bytes()).expect("write fixture file");
        true
    } else {
        false
    }
}
/// Assert that the given events match the named JSON fixture under `tests/fixtures/`.
///
/// Set `UPDATE_FIXTURES=1` to create or refresh fixtures with the current output.
pub fn assert_events(name: &str, events: &[EventBox]) {
    let actual = events_json_filtered(events);
    let path = fixture_path(name);
    match fs::read_to_string(&path) {
        Ok(expected) => {
            if expected != actual {
                if write_if_update_requested(&path, &actual) {
                    panic!(
                        "fixture updated: {}. Re-run tests without UPDATE_FIXTURES to verify.",
                        path.display()
                    );
                } else {
                    panic!(
                        "event snapshot mismatch for {}. Run with UPDATE_FIXTURES=1 to update.\nPath: {}",
                        name,
                        path.display()
                    );
                }
            }
        }
        Err(_) => {
            if write_if_update_requested(&path, &actual) {
                panic!(
                    "fixture created: {}. Re-run tests without UPDATE_FIXTURES to verify.",
                    path.display()
                );
            } else {
                panic!(
                    "missing fixture for {}. Run with UPDATE_FIXTURES=1 to create.\nPath: {}",
                    name,
                    path.display()
                );
            }
        }
    }
}
