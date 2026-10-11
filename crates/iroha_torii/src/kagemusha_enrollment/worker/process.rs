//! Fixed descriptor launch using posix_spawn file actions and bounded private socket pipes.
// This narrow POSIX boundary owns descriptors and child status; individual calls document safety.
#![allow(unsafe_code)]

use super::*;
use std::{
    ffi::CString,
    io::{Read as _, Write as _},
    os::{
        fd::{AsRawFd, FromRawFd as _, OwnedFd},
        unix::{fs::OpenOptionsExt as _, net::UnixStream},
    },
    time::{Duration, Instant},
};

pub(super) struct Process {
    pid: libc::pid_t,
    input: UnixStream,
    output: UnixStream,
    reaped: bool,
}
fn duplicate(file: &impl AsRawFd) -> Result<OwnedFd> {
    // All sources live above the fixed destination range; posix_spawn owns its private
    // error-reporting channel and its file-actions implementation handles descriptor moves.
    let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 64) };
    if fd < 0 {
        return Err(Error::Unavailable);
    }
    // SAFETY: fcntl returned a new exclusively owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
fn ready(fd: i32, events: i16, deadline: Instant) -> Result<()> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(Error::Unavailable)?;
        let milliseconds = remaining
            .as_millis()
            .saturating_add(1)
            .min(i32::MAX as u128) as i32;
        let mut descriptor = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        // SAFETY: one initialized pollfd is exclusively borrowed throughout the call.
        let count = unsafe { libc::poll(&mut descriptor, 1, milliseconds) };
        if count < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if count <= 0
            || Instant::now() >= deadline
            || descriptor.revents & (libc::POLLERR | libc::POLLNVAL) != 0
        {
            return Err(Error::Unavailable);
        }
        if descriptor.revents & (events | libc::POLLHUP) != 0 {
            return Ok(());
        }
    }
}
fn write_all(pipe: &mut UnixStream, mut bytes: &[u8], deadline: Instant) -> Result<()> {
    while !bytes.is_empty() {
        ready(pipe.as_raw_fd(), libc::POLLOUT, deadline)?;
        match pipe.write(bytes) {
            Ok(0) => return Err(Error::Unavailable),
            Ok(count) => bytes = &bytes[count..],
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) =>
            {
                ()
            }
            Err(_) => return Err(Error::Unavailable),
        }
    }
    if Instant::now() >= deadline {
        return Err(Error::Unavailable);
    }
    Ok(())
}
fn read_exact(pipe: &mut UnixStream, mut bytes: &mut [u8], deadline: Instant) -> Result<()> {
    while !bytes.is_empty() {
        ready(pipe.as_raw_fd(), libc::POLLIN, deadline)?;
        match pipe.read(bytes) {
            Ok(0) => return Err(Error::Unavailable),
            Ok(count) => bytes = &mut bytes[count..],
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) =>
            {
                ()
            }
            Err(_) => return Err(Error::Unavailable),
        }
    }
    if Instant::now() >= deadline {
        return Err(Error::Unavailable);
    }
    Ok(())
}
struct SpawnActions(libc::posix_spawn_file_actions_t);
impl SpawnActions {
    fn new() -> Result<Self> {
        let mut actions = std::mem::MaybeUninit::uninit();
        // SAFETY: libc initializes the opaque actions object on successful return.
        if unsafe { libc::posix_spawn_file_actions_init(actions.as_mut_ptr()) } != 0 {
            return Err(Error::Unavailable);
        }
        Ok(Self(unsafe { actions.assume_init() }))
    }
    fn duplicate(&mut self, source: &OwnedFd, target: i32) -> Result<()> {
        // SAFETY: actions is initialized and source stays live until spawn returns.
        if unsafe {
            libc::posix_spawn_file_actions_adddup2(&mut self.0, source.as_raw_fd(), target)
        } != 0
        {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
}
impl Drop for SpawnActions {
    fn drop(&mut self) {
        unsafe {
            libc::posix_spawn_file_actions_destroy(&mut self.0);
        }
    }
}
impl Process {
    pub(super) fn spawn(owner: &PrivateVerifier) -> Result<Self> {
        if !cfg!(target_os = "linux") {
            return Err(Error::Unavailable);
        }
        owner.revalidate(&owner.selected)?;
        let directory = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&owner.selected.worker.store_directory)
            .map_err(|_| Error::Unavailable)?;
        if iroha_fs::FileIdentity::of(&directory).map_err(|_| Error::Unavailable)?
            != owner.directory.identity().map_err(|_| Error::Unavailable)?
        {
            return Err(Error::Unavailable);
        }
        let (input, child_input) = UnixStream::pair().map_err(|_| Error::Unavailable)?;
        let (output, child_output) = UnixStream::pair().map_err(|_| Error::Unavailable)?;
        let null = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .map_err(|_| Error::Unavailable)?;
        let descriptors = vec![
            (duplicate(&child_input)?, 0),
            (duplicate(&child_output)?, 1),
            (duplicate(&null)?, 2),
            (duplicate(&directory)?, 17),
            (duplicate(owner.generation.file.file())?, 16),
            (duplicate(owner.python.file.file())?, 18),
            (duplicate(owner.archive.file.file())?, 19),
            (
                duplicate(
                    owner
                        .configuration
                        .as_ref()
                        .ok_or(Error::Selection)?
                        .0
                        .file
                        .file(),
                )?,
                20,
            ),
            (duplicate(owner.openssl.file.file())?, 21),
        ];
        let mut actions = SpawnActions::new()?;
        for (source, target) in &descriptors {
            actions.duplicate(source, *target)?;
        }
        let originals: Vec<CString> = ["/proc/self/fd/18", "-I", "-S", "-B", "/proc/self/fd/19"]
            .iter()
            .map(|value| CString::new(*value).map_err(|_| Error::Invalid))
            .collect::<Result<_>>()?;
        let mut arguments: Vec<*mut libc::c_char> = originals
            .iter()
            .map(|value| value.as_ptr().cast_mut())
            .collect();
        arguments.push(std::ptr::null_mut());
        let environment = [std::ptr::null_mut()];
        let mut pid = 0;
        // SAFETY: every C string, pointer array, action and source descriptor remains live
        // until posix_spawn returns. No application Rust closure runs in the forked child.
        let status = unsafe {
            libc::posix_spawn(
                &mut pid,
                originals[0].as_ptr(),
                &actions.0,
                std::ptr::null(),
                arguments.as_ptr(),
                environment.as_ptr(),
            )
        };
        if status != 0 || pid <= 0 {
            return Err(Error::Unavailable);
        }
        let process = Self {
            pid,
            input,
            output,
            reaped: false,
        };
        process
            .input
            .set_nonblocking(true)
            .map_err(|_| Error::Unavailable)?;
        process
            .output
            .set_nonblocking(true)
            .map_err(|_| Error::Unavailable)?;
        owner.revalidate(&owner.selected)?;
        Ok(process)
    }
    fn running(&mut self) -> Result<()> {
        if self.reaped {
            return Err(Error::Unavailable);
        }
        let mut status = 0;
        // SAFETY: pid is the unreaped child returned by our sole posix_spawn.
        let result = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
        if result == 0 {
            return Ok(());
        }
        if result == self.pid
            || (result < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD))
        {
            self.reaped = true;
        }
        Err(Error::Unavailable)
    }
    pub(super) fn exchange(&mut self, packet: &[u8], timeout: Duration) -> Result<Vec<u8>> {
        if packet.len() < 5
            || packet.len() > MAX_FRAME + 4
            || u32::from_le_bytes(packet[..4].try_into().map_err(|_| Error::Invalid)?) as usize
                != packet.len() - 4
            || timeout.is_zero()
            || timeout > Duration::from_secs(300)
        {
            return Err(Error::Invalid);
        }
        self.running()?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(Error::Unavailable)?;
        write_all(&mut self.input, packet, deadline)?;
        let mut prefix = [0; 4];
        read_exact(&mut self.output, &mut prefix, deadline)?;
        let length = u32::from_le_bytes(prefix) as usize;
        if length == 0 || length > MAX_FRAME {
            return Err(Error::Invalid);
        }
        let mut response = vec![0; length + 4];
        response[..4].copy_from_slice(&prefix);
        read_exact(&mut self.output, &mut response[4..], deadline)?;
        self.running()?;
        if Instant::now() >= deadline {
            return Err(Error::Unavailable);
        }
        Ok(response)
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        // Re-observe actual child ownership. Unknown/reaped children must never be signalled.
        // The node owns its children individually; a process-global wait-any reaper is unsupported.
        let mut before = 0;
        let alive = loop {
            let observed = unsafe { libc::waitpid(self.pid, &mut before, libc::WNOHANG) };
            if observed < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break observed;
        };
        if alive != 0 {
            if alive == self.pid
                || (alive < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD))
            {
                self.reaped = true;
            }
            return;
        }
        unsafe {
            libc::kill(self.pid, libc::SIGKILL);
        }
        let mut status = 0;
        loop {
            let result = unsafe { libc::waitpid(self.pid, &mut status, 0) };
            if result == self.pid {
                self.reaped = true;
                break;
            }
            if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    #[test]
    fn deadline_rejects_even_readable_completed_bytes_after_expiry() {
        let (mut input, mut output) = UnixStream::pair().unwrap();
        input.set_nonblocking(true).unwrap();
        output.set_nonblocking(true).unwrap();
        output.write_all(b"a").unwrap();
        let mut byte = [0; 1];
        assert!(read_exact(&mut input, &mut byte, Instant::now()).is_err());
        assert!(write_all(&mut output, b"x", Instant::now()).is_err());
        read_exact(
            &mut input,
            &mut byte,
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(byte, [b'a']);
    }
    #[test]
    fn fixed_descriptor_actions_retain_sources_and_report_invalid_moves() {
        let (left, _) = UnixStream::pair().unwrap();
        let duplicate = duplicate(&left).unwrap();
        assert!(duplicate.as_raw_fd() >= 64);
        let mut actions = SpawnActions::new().unwrap();
        actions.duplicate(&duplicate, 18).unwrap();
        assert!(actions.duplicate(&duplicate, -1).is_err());
    }
    // This helper chooses only fixed test programs. It exercises the production descriptor,
    // framing and child-lifecycle owners, not the Linux verifier installation/admission path.
    fn child(program: &str, extra_argument: Option<&str>, retained: Option<&File>) -> Process {
        let (input, child_input) = UnixStream::pair().unwrap();
        let (output, child_output) = UnixStream::pair().unwrap();
        let null = File::options().write(true).open("/dev/null").unwrap();
        let mut descriptors = vec![
            (duplicate(&child_input).unwrap(), 0),
            (duplicate(&child_output).unwrap(), 1),
            (duplicate(&null).unwrap(), 2),
        ];
        if let Some(file) = retained {
            descriptors.push((duplicate(file).unwrap(), 16));
        }
        let mut actions = SpawnActions::new().unwrap();
        for (source, target) in &descriptors {
            actions.duplicate(source, *target).unwrap();
        }
        let mut originals = vec![CString::new(program).unwrap()];
        if let Some(argument) = extra_argument {
            originals.push(CString::new(argument).unwrap());
        }
        let mut arguments: Vec<*mut libc::c_char> =
            originals.iter().map(|s| s.as_ptr().cast_mut()).collect();
        arguments.push(std::ptr::null_mut());
        let environment = [std::ptr::null_mut()];
        let mut pid = 0;
        // SAFETY: all pointers and descriptor sources outlive this spawn call.
        assert_eq!(
            unsafe {
                libc::posix_spawn(
                    &mut pid,
                    originals[0].as_ptr(),
                    &actions.0,
                    std::ptr::null(),
                    arguments.as_ptr(),
                    environment.as_ptr(),
                )
            },
            0
        );
        input.set_nonblocking(true).unwrap();
        output.set_nonblocking(true).unwrap();
        Process {
            pid,
            input,
            output,
            reaped: false,
        }
    }
    fn assert_reaped(pid: libc::pid_t) {
        let mut status = 0;
        // SAFETY: this is only the pid created and already joined by the test's owner.
        assert_eq!(
            unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) },
            -1
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }
    #[test]
    fn owned_echo_process_roundtrips_frames_and_releases_inherited_lock_after_join() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/qualification/enrollment-service/process-tests");
        std::fs::create_dir_all(&root).unwrap();
        let temporary = tempfile::tempdir_in(root).unwrap();
        let path = temporary.path().join("generation");
        let generation = File::options()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        generation.try_lock().unwrap();
        let mut process = child("/bin/cat", None, Some(&generation));
        let pid = process.pid;
        drop(generation);
        let independent = File::options().read(true).write(true).open(path).unwrap();
        assert!(independent.try_lock().is_err());
        for payload in [b"exact original".as_slice(), &[0; 4096]] {
            let mut frame = (payload.len() as u32).to_le_bytes().to_vec();
            frame.extend_from_slice(payload);
            assert_eq!(
                process.exchange(&frame, Duration::from_secs(5)).unwrap(),
                frame
            );
        }
        drop(process);
        assert_reaped(pid);
        independent.try_lock().unwrap();
    }
    #[test]
    fn silent_owned_child_times_out_and_drop_joins_it() {
        let mut process = child("/bin/sleep", Some("30"), None);
        let pid = process.pid;
        assert!(matches!(
            process.exchange(&[1, 0, 0, 0, 42], Duration::from_millis(20)),
            Err(Error::Unavailable)
        ));
        drop(process);
        assert_reaped(pid);
    }
}
