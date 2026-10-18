//! Apple sync classes for publications that need ordering at every step and durability only
//! at their commit points (fcntl(2)).
//!
//! `F_FULLFSYNC` asks the drive to flush its cache: everything fsync'd on that device before it
//! is persisted when it returns, and it costs milliseconds. `F_BARRIERFSYNC` is fsync plus a
//! barrier: I/O flushed before it is persisted before any I/O after it, and nothing is known
//! persisted when it returns. Apple SSDs implement the barrier. An ordered sync records its device;
//! [`fence`] flushes each device with ordered syncs since its last fence once.
#![allow(
    unsafe_code,
    reason = "F_BARRIERFSYNC is reached through fcntl, which rustix does not wrap"
)]

use std::{
    collections::BTreeMap,
    fs::File,
    io,
    os::{fd::AsRawFd as _, unix::fs::MetadataExt as _},
    sync::{Mutex, PoisonError},
};

// sys/fcntl.h.
const F_BARRIERFSYNC: i32 = 85;

unsafe extern "C" {
    fn fcntl(descriptor: i32, command: i32, ...) -> i32;
}

/// One device with ordered syncs: a retained descriptor to flush it and its sync epochs.
struct Device {
    file: File,
    directory: bool,
    ordered: u64,
    fenced: u64,
}

static DEVICES: Mutex<BTreeMap<u64, Device>> = Mutex::new(BTreeMap::new());

/// Order `file`'s data and metadata before any later I/O on its device without waiting for
/// media, and record the device for the next [`fence`].
pub(super) fn ordered(file: &File) -> io::Result<()> {
    // SAFETY: the descriptor stays open for the call; F_BARRIERFSYNC reads no argument.
    if unsafe { fcntl(file.as_raw_fd(), F_BARRIERFSYNC) } == -1 {
        return Err(io::Error::last_os_error());
    }
    let metadata = file.metadata()?;
    let mut devices = DEVICES.lock().unwrap_or_else(PoisonError::into_inner);
    match devices.get_mut(&metadata.dev()) {
        Some(device) => {
            device.ordered += 1;
            // Prefer a directory: a retained staged file would keep its unlinked inode alive.
            if !device.directory && metadata.is_dir() {
                device.file = file.try_clone()?;
                device.directory = true;
            }
        }
        None => {
            devices.insert(
                metadata.dev(),
                Device {
                    file: file.try_clone()?,
                    directory: metadata.is_dir(),
                    ordered: 1,
                    fenced: 0,
                },
            );
        }
    }
    Ok(())
}

/// Persist every ordered sync made so far: one `F_FULLFSYNC` per device with ordered syncs since
/// its last fence. Returns the number of devices flushed.
pub(super) fn fence() -> io::Result<u64> {
    let mut pending = Vec::new();
    {
        let devices = DEVICES.lock().unwrap_or_else(PoisonError::into_inner);
        for (id, device) in devices.iter() {
            if device.ordered != device.fenced {
                pending.push((*id, device.file.try_clone()?, device.ordered));
            }
        }
    }
    let mut flushed = 0;
    for (id, file, ordered) in pending {
        // Never hold the registry across the flush: ordered syncs continue meanwhile and stay
        // recorded for the next fence.
        rustix::fs::fcntl_fullfsync(&file)?;
        let mut devices = DEVICES.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(device) = devices.get_mut(&id) {
            device.fenced = device.fenced.max(ordered);
        }
        flushed += 1;
    }
    Ok(flushed)
}
