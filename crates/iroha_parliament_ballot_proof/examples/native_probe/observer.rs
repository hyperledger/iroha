//! Setup-only dynamic binding and fixed-ABI reporting for the native observer.

use std::{ffi::CStr, fmt::Write, sync::OnceLock};

use norito::json::JsonSerialize;

type Version = unsafe extern "C" fn() -> u64;
type LockFree = unsafe extern "C" fn() -> libc::c_int;
type Transition = unsafe extern "C" fn(u64, u64) -> libc::c_int;
type SnapshotFn = unsafe extern "C" fn(*mut Snapshot, u64) -> libc::c_int;

struct Api {
    transition: Transition,
    snapshot: SnapshotFn,
    identity: Version,
    state: u64,
}
static API: OnceLock<Api> = OnceLock::new();

/// One named endpoint's observations, not unique allocations or live bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, JsonSerialize)]
pub struct Counter {
    pub calls: u64,
    pub requested_bytes: u64,
    pub failures: u64,
}

/// Exact ABI-v1 C snapshot, sealed before ordinary Rust JSON serialization.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Snapshot {
    pub abi_version: u64,
    pub struct_bytes: u64,
    pub endpoint_count: u64,
    pub phase_count: u64,
    pub final_phase: u64,
    pub inflight: u64,
    pub invalid_flags: u64,
    pub transitions: u64,
    pub phase_before_seal: u64,
    pub counters: [[Counter; 21]; 3],
}

/// Ordinary post-seal JSON representation; unlike the C snapshot, this owns Vecs.
#[derive(JsonSerialize)]
pub struct SnapshotReport {
    pub abi_version: u64,
    pub struct_bytes: u64,
    pub endpoint_count: u64,
    pub phase_count: u64,
    pub final_phase: u64,
    pub inflight: u64,
    pub invalid_flags: u64,
    pub transitions: u64,
    pub phase_before_seal: u64,
    pub counters: Vec<Vec<Counter>>,
}
impl Snapshot {
    /// Allocate report storage only after native observation has been sealed.
    pub fn into_report(self) -> SnapshotReport {
        SnapshotReport {
            abi_version: self.abi_version,
            struct_bytes: self.struct_bytes,
            endpoint_count: self.endpoint_count,
            phase_count: self.phase_count,
            final_phase: self.final_phase,
            inflight: self.inflight,
            invalid_flags: self.invalid_flags,
            transitions: self.transitions,
            phase_before_seal: self.phase_before_seal,
            counters: self.counters.into_iter().map(|row| row.to_vec()).collect(),
        }
    }
}

unsafe fn symbol(name: &CStr) -> Result<*mut libc::c_void, &'static str> {
    // All resolution runs before the marked interval. Missing symbols fail;
    // there is no substitute state or fallback observer.
    let pointer = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
    if pointer.is_null() {
        Err("native observer symbol missing")
    } else {
        Ok(pointer)
    }
}

/// Resolve one shared dylib state before creating the worker or marking phases.
pub fn init() -> Result<(), &'static str> {
    // SAFETY: each exact exported signature is fixed by np_api.h ABI v1.
    let api = unsafe {
        let version: Version = std::mem::transmute(symbol(c"np_version")?);
        let lock_free: LockFree = std::mem::transmute(symbol(c"np_lock_free")?);
        let identity: Version = std::mem::transmute(symbol(c"np_state_identity")?);
        if version() != 1 || lock_free() != 1 || identity() == 0 {
            return Err("unsupported observer ABI or atomics");
        }
        Api {
            transition: std::mem::transmute::<*mut libc::c_void, Transition>(symbol(
                c"np_transition",
            )?),
            snapshot: std::mem::transmute::<*mut libc::c_void, SnapshotFn>(symbol(c"np_snapshot")?),
            identity,
            state: identity(),
        }
    };
    if std::mem::size_of::<Snapshot>() != 1584 {
        return Err("observer snapshot layout mismatch");
    }
    API.set(api).map_err(|_| "repeated observer initialization")
}

/// Conservatively open observation immediately before enabling the routed arena.
pub fn begin() {
    let Some(api) = API.get() else {
        unsafe { libc::_exit(75) }
    };
    // SAFETY: setup verified the ABI and all lifecycle calls are serialized.
    if unsafe { (api.identity)() != api.state || (api.transition)(0, 1) != 1 } {
        unsafe { libc::_exit(75) };
    }
}

/// Close observation after ordinary owned cleanup and arena deactivation.
pub fn end() {
    let Some(api) = API.get() else {
        unsafe { libc::_exit(75) }
    };
    // SAFETY: begin already succeeded, and the worker owns this transition.
    if unsafe { (api.identity)() != api.state || (api.transition)(1, 2) != 1 } {
        unsafe { libc::_exit(75) };
    }
}

/// Seal and validate counters; phase0 is unadmitted, phase1 incomplete, phase2 ordinary.
pub fn snapshot() -> Result<Snapshot, &'static str> {
    let api = API.get().ok_or("observer not initialized")?;
    let mut value = Snapshot::default();
    // SAFETY: value has the exact checked writable C layout and snapshot seals
    // the single shared state before copying counters.
    let result = unsafe { (api.snapshot)(&mut value, std::mem::size_of::<Snapshot>() as u64) };
    if result != 1 || unsafe { (api.identity)() } != api.state || !valid_snapshot(&value) {
        return Err("native observer snapshot invalid");
    }
    Ok(value)
}

fn valid_snapshot(value: &Snapshot) -> bool {
    value.abi_version == 1
        && value.struct_bytes == 1584
        && value.endpoint_count == 21
        && value.phase_count == 3
        && value.final_phase == 3
        && value.inflight == 0
        && value.invalid_flags == 0
        && value.phase_before_seal <= 2
        && value.transitions == [8, 10, 14][value.phase_before_seal as usize]
}

struct FixedWriter<'a> {
    bytes: &'a mut [u8],
    used: usize,
}
impl std::fmt::Write for FixedWriter<'_> {
    fn write_str(&mut self, value: &str) -> std::fmt::Result {
        let end = self.used.checked_add(value.len()).ok_or(std::fmt::Error)?;
        self.bytes
            .get_mut(self.used..end)
            .ok_or(std::fmt::Error)?
            .copy_from_slice(value.as_bytes());
        self.used = end;
        Ok(())
    }
}

fn terminal_json(value: &Snapshot, output: &mut [u8]) -> Result<usize, std::fmt::Error> {
    let mut writer = FixedWriter {
        bytes: output,
        used: 0,
    };
    write!(
        writer,
        "{{\"native_probe_terminal\":true,\"observation_valid\":true,\"complete_workspace_certificate\":false,\"profile_qualified\":false,\"phase_before_seal\":{},\"invalid_flags\":{},\"counters\":[",
        value.phase_before_seal, value.invalid_flags
    )?;
    for (phase, counters) in value.counters.iter().enumerate() {
        write!(writer, "{}[", if phase == 0 { "" } else { "," })?;
        for (index, counter) in counters.iter().enumerate() {
            write!(
                writer,
                "{}[{},{},{}]",
                if index == 0 { "" } else { "," },
                counter.calls,
                counter.requested_bytes,
                counter.failures
            )?;
        }
        writer.write_str("]")?;
    }
    writer.write_str("]}\n")?;
    Ok(writer.used)
}

/// Preserve an OOM's native observations without allocating or changing exit73.
pub fn terminal() {
    let mut bytes = [0u8; 8192];
    let length = snapshot()
        .ok()
        .and_then(|value| terminal_json(&value, &mut bytes).ok());
    let data = length.map_or(
        b"{\"native_probe_terminal\":true,\"observation_valid\":false}\n".as_slice(),
        |length| &bytes[..length],
    );
    let mut written = 0;
    while written < data.len() {
        // SAFETY: fixed initialized bytes stay valid for the synchronous write.
        let count = unsafe {
            libc::write(
                libc::STDERR_FILENO,
                data[written..].as_ptr().cast(),
                data.len() - written,
            )
        };
        if count <= 0 {
            break;
        }
        written += count as usize;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn abi_layout_and_phase_validation_are_exact() {
        assert_eq!(std::mem::size_of::<Snapshot>(), 1584);
        assert_eq!(std::mem::align_of::<Snapshot>(), 8);
        let report = Snapshot::default().into_report();
        assert_eq!(report.counters.len(), 3);
        assert_eq!(report.counters[0].len(), 21);
        assert!(norito::json::to_json(&report).is_ok());
        let mut value = Snapshot {
            abi_version: 1,
            struct_bytes: 1584,
            endpoint_count: 21,
            phase_count: 3,
            final_phase: 3,
            transitions: 8,
            ..Snapshot::default()
        };
        for (phase, mask) in [8, 10, 14].into_iter().enumerate() {
            value.phase_before_seal = phase as u64;
            value.transitions = mask;
            assert!(valid_snapshot(&value));
        }
        value.inflight = 1;
        assert!(!valid_snapshot(&value));
        value.inflight = 0;
        value.phase_before_seal = u64::MAX;
        assert!(!valid_snapshot(&value));
    }
    #[test]
    fn terminal_writer_is_bounded_and_preserves_every_counter() {
        let value = Snapshot {
            counters: [[Counter {
                calls: u64::MAX,
                requested_bytes: u64::MAX,
                failures: u64::MAX,
            }; 21]; 3],
            ..Snapshot::default()
        };
        let mut bytes = [0u8; 8192];
        let length = terminal_json(&value, &mut bytes).unwrap();
        let json: norito::json::Value = norito::json::from_slice(&bytes[..length]).unwrap();
        assert_eq!(
            json.get("profile_qualified")
                .and_then(norito::json::Value::as_bool),
            Some(false)
        );
        assert!(terminal_json(&value, &mut [0u8; 8]).is_err());
        assert_eq!(
            std::str::from_utf8(&bytes[..length])
                .unwrap()
                .matches("18446744073709551615")
                .count(),
            189
        );
    }
}
