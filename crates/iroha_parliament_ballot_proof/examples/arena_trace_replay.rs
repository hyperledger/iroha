//! Replay diagnostic allocation traces through the actual standalone arena.
//!
//! This exercises allocator topology, not verifier allocation coverage. The
//! interpreter, JSON, trace storage and backing allocation use the ordinary
//! host allocator outside the modeled workspace. No production qualification
//! or native-memory ceiling follows from a successful replay.

#![allow(unsafe_code)]

#[allow(dead_code)]
#[path = "resource_contract/arena.rs"]
mod arena;

use std::{
    alloc::{Layout, alloc_zeroed, dealloc},
    collections::BTreeMap,
    io::Read,
    ptr::NonNull,
};

use norito::json::Value;

type Failure = String;

struct Backing {
    pointer: NonNull<u8>,
    layout: Layout,
}

impl Backing {
    fn new(bytes: usize, alignment: usize) -> Result<Self, Failure> {
        let layout =
            Layout::from_size_align(bytes, alignment).map_err(|error| error.to_string())?;
        // SAFETY: a nonzero validated layout; ownership is retained until Drop.
        let pointer = NonNull::new(unsafe { alloc_zeroed(layout) })
            .ok_or_else(|| "host backing allocation failed".to_owned())?;
        Ok(Self { pointer, layout })
    }
}

impl Drop for Backing {
    fn drop(&mut self) {
        // SAFETY: this is the original allocation/layout, released once after
        // the arena and its raw-pointer ledger are no longer used.
        unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Live {
    pointer: NonNull<u8>,
    layout: Layout,
}

#[derive(norito::json::JsonSerialize)]
struct Observation {
    id: String,
    offset: usize,
    size: usize,
    alignment: usize,
}

#[derive(norito::json::JsonSerialize)]
struct Report {
    allocator_trace_passed: bool,
    complete_workspace_certificate: bool,
    profile_qualified: bool,
    heap_bytes: usize,
    peak_block_bytes: usize,
    peak_requested_bytes: usize,
    live_exit_block_bytes: usize,
    live_exit_requested_bytes: usize,
    allocations_observed: usize,
    allocations_upper_bound: usize,
    restoring_groups_checked: usize,
    allocation_offsets: Vec<Observation>,
}

struct Replay {
    allocator: arena::Arena,
    tree: Box<[u8]>,
    heap: Backing,
    live: BTreeMap<String, Live>,
    offsets: Vec<Observation>,
    logical_allocations: usize,
    groups: usize,
}

fn integer(value: &Value, key: &str) -> Result<usize, Failure> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|number| usize::try_from(number).ok())
        .ok_or_else(|| format!("missing or non-usize integer: {key}"))
}

fn label<'a>(value: &'a Value, key: &str) -> Result<&'a str, Failure> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| format!("missing or empty string: {key}"))
}

impl Replay {
    fn new(bytes: usize, alignment: usize, limit: usize) -> Result<Self, Failure> {
        if !bytes.is_power_of_two()
            || !(arena::MIN_BLOCK..=arena::HEAP_BYTES).contains(&bytes)
            || !alignment.is_power_of_two()
            || alignment > 1024 * 1024
        {
            return Err("unsupported diagnostic heap shape".to_owned());
        }
        let heap = Backing::new(bytes, alignment)?;
        let mut tree = vec![0u8; 2 * (bytes / arena::MIN_BLOCK) - 1].into_boxed_slice();
        // SAFETY: heap and tree are disjoint initialized allocations with the
        // requested lengths/alignment and remain owned for this Replay's life.
        let allocator = unsafe {
            arena::Arena::new(
                heap.pointer.as_ptr(),
                tree.as_mut_ptr(),
                bytes,
                alignment,
                limit,
            )
        };
        Ok(Self {
            allocator,
            tree,
            heap,
            live: BTreeMap::new(),
            offsets: Vec::new(),
            logical_allocations: 0,
            groups: 0,
        })
    }

    fn events(&mut self, values: &[Value], depth: usize) -> Result<(), Failure> {
        if depth > 32 {
            return Err("trace nesting exceeds diagnostic limit".to_owned());
        }
        for value in values {
            match label(value, "op")? {
                "alloc" => {
                    let id = label(value, "id")?;
                    if self.live.contains_key(id) {
                        return Err(format!("already-live ID: {id}"));
                    }
                    let size = integer(value, "size")?;
                    if size == 0 {
                        return Err("zero-sized GlobalAlloc request".to_owned());
                    }
                    let layout = Layout::from_size_align(size, integer(value, "align")?)
                        .map_err(|error| error.to_string())?;
                    let pointer = NonNull::new(self.allocator.allocate(layout))
                        .ok_or_else(|| format!("arena admission failed: {id}"))?;
                    self.offsets.push(Observation {
                        id: id.to_owned(),
                        offset: pointer.as_ptr() as usize - self.heap.pointer.as_ptr() as usize,
                        size,
                        alignment: layout.align(),
                    });
                    self.live.insert(id.to_owned(), Live { pointer, layout });
                    self.logical_allocations = self
                        .logical_allocations
                        .checked_add(1)
                        .ok_or_else(|| "logical count overflow".to_owned())?;
                }
                "free" => {
                    let id = label(value, "id")?;
                    let live = self
                        .live
                        .remove(id)
                        .ok_or_else(|| format!("unknown or freed ID: {id}"))?;
                    // SAFETY: exact pointer/layout from one still-live arena
                    // allocation; removing the entry prevents double release.
                    unsafe { self.allocator.release(live.pointer.as_ptr(), live.layout) };
                }
                "repeat_restoring" => {
                    let minimum = integer(value, "min")?;
                    let maximum = integer(value, "max")?;
                    let body = value
                        .get("body")
                        .and_then(Value::as_array)
                        .ok_or_else(|| "repeat has no body array".to_owned())?;
                    if minimum > maximum {
                        return Err("repeat min exceeds max".to_owned());
                    }
                    if maximum > 0 {
                        let tree = self.tree.clone();
                        let live = self.live.clone();
                        let count = self.logical_allocations;
                        let stats = self.allocator.stats();
                        self.events(body, depth + 1)?;
                        let after = self.allocator.stats();
                        if self.tree != tree
                            || self.live != live
                            || after.live_blocks != stats.live_blocks
                            || after.live_requested != stats.live_requested
                        {
                            return Err("repeat did not restore exact allocator state".to_owned());
                        }
                        let extra = (self.logical_allocations - count)
                            .checked_mul(maximum - 1)
                            .ok_or_else(|| "logical count overflow".to_owned())?;
                        self.logical_allocations = self
                            .logical_allocations
                            .checked_add(extra)
                            .ok_or_else(|| "logical count overflow".to_owned())?;
                    }
                    self.groups += 1;
                }
                other => return Err(format!("unknown operation: {other}")),
            }
        }
        Ok(())
    }

    fn report(self) -> Result<Report, Failure> {
        let stats = self.allocator.stats();
        if !self.live.is_empty() || stats.live_blocks != 0 || stats.live_requested != 0 {
            return Err("trace ended with live allocations".to_owned());
        }
        Ok(Report {
            allocator_trace_passed: true,
            complete_workspace_certificate: false,
            profile_qualified: false,
            heap_bytes: self.heap.layout.size(),
            peak_block_bytes: stats.peak_blocks,
            peak_requested_bytes: stats.peak_requested,
            live_exit_block_bytes: stats.live_blocks,
            live_exit_requested_bytes: stats.live_requested,
            allocations_observed: stats.allocations,
            allocations_upper_bound: self.logical_allocations,
            restoring_groups_checked: self.groups,
            allocation_offsets: self.offsets,
        })
    }
}

fn run(value: &Value) -> Result<Report, Failure> {
    let bytes = value
        .get("heap_bytes")
        .map_or(Ok(arena::HEAP_BYTES), |_| integer(value, "heap_bytes"))?;
    let alignment = value
        .get("alignment")
        .map_or(Ok(16 * 1024), |_| integer(value, "alignment"))?;
    let limit = value
        .get("limit")
        .map_or(Ok(bytes), |_| integer(value, "limit"))?;
    let events = value
        .get("events")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing events array".to_owned())?;
    let mut replay = Replay::new(bytes, alignment, limit)?;
    replay.events(events, 0)?;
    replay.report()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Some(path) = std::env::args_os().nth(1) else {
        return Err("usage: arena_trace_replay TRACE.json (allocator diagnostic only)".into());
    };
    let file = std::fs::File::open(path)?;
    if file.metadata()?.len() > 10 * 1024 * 1024 {
        return Err("diagnostic trace exceeds 10 MiB".into());
    }
    let mut bytes = Vec::new();
    file.take(10 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 10 * 1024 * 1024 {
        return Err("diagnostic trace grew beyond 10 MiB".into());
    }
    let value: Value = norito::json::from_slice(&bytes)?;
    let report = run(&value)?;
    println!("{}", norito::json::to_json(&report)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(text: &str) -> Value {
        norito::json::from_str(text).unwrap()
    }

    #[test]
    fn exact_allocator_offsets_and_cleanup() {
        let report = run(&value(
            r#"{"heap_bytes":1024,"alignment":64,"events":[
            {"op":"alloc","id":"a","size":512,"align":8},
            {"op":"alloc","id":"b","size":64,"align":8},
            {"op":"free","id":"a"},
            {"op":"alloc","id":"c","size":64,"align":8},
            {"op":"free","id":"b"},{"op":"free","id":"c"}]}"#,
        ))
        .unwrap();
        assert_eq!(
            report
                .allocation_offsets
                .iter()
                .map(|r| r.offset)
                .collect::<Vec<_>>(),
            [0, 512, 0]
        );
        assert_eq!(report.peak_block_bytes, 576);
        assert_eq!(report.live_exit_block_bytes, 0);
        assert!(!report.profile_qualified);
    }

    #[test]
    fn restoring_body_checks_actual_metadata_and_counts() {
        let report = run(&value(
            r#"{"heap_bytes":1024,"events":[
            {"op":"repeat_restoring","min":0,"max":1000,"body":[
                {"op":"alloc","id":"x","size":100,"align":8},
                {"op":"free","id":"x"}]}]}"#,
        ))
        .unwrap();
        assert_eq!(report.allocations_observed, 1);
        assert_eq!(report.allocations_upper_bound, 1000);
        assert_eq!(report.restoring_groups_checked, 1);
        assert!(
            run(&value(
                r#"{"heap_bytes":1024,"events":[
            {"op":"repeat_restoring","min":1,"max":2,"body":[
                {"op":"alloc","id":"x","size":100,"align":8}]}]}"#
            ))
            .is_err()
        );
    }

    #[test]
    fn rejects_malformed_shapes_layouts_ids_and_leaks() {
        assert!(Backing::new(1, 3).is_err());
        assert!(Replay::new(63, 64, 63).is_err());
        assert!(integer(&value(r#"{"x":true}"#), "x").is_err());
        assert!(label(&value(r#"{"x":""}"#), "x").is_err());
        for text in [
            r#"{"events":[{"op":"alloc","id":"x","size":0,"align":8}]}"#,
            r#"{"events":[{"op":"alloc","id":"x","size":100,"align":3}]}"#,
            r#"{"events":[{"op":"free","id":"x"}]}"#,
            r#"{"events":[{"op":"alloc","id":"x","size":100,"align":8}]}"#,
            r#"{"events":[{"op":"unknown"}]}"#,
            r#"{"events":[{"op":"repeat_restoring","min":2,"max":1,"body":[]}]}"#,
        ] {
            assert!(run(&value(text)).is_err(), "{text}");
        }
        let mut replay = Replay::new(64, 8, 64).unwrap();
        assert!(replay.events(&[], 33).is_err());
    }
}
