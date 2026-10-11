//! Bounded owner-authenticated local control transport.

use super::*;
use iroha_fs::PrivateDirectory;
use std::{
    io::{Read, Write},
    process::Command,
    time::Instant,
};

const IO_TIMEOUT: Duration = Duration::from_secs(2);

fn remaining_io(deadline: Instant) -> std::io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "managed cleanup observation deadline expired; original ownership is unconfirmed",
            )
        })
}

// Availability is observed only at the direct endpoint or stream-I/O boundaries below.
// Native directory custody, peer authentication and decoding remain strict refusals.
pub(crate) enum RequestFailure {
    Unavailable(Error),
    Refused(Error),
}

impl RequestFailure {
    fn into_error(self) -> Error {
        match self {
            Self::Unavailable(error) | Self::Refused(error) => error,
        }
    }

    fn stream(error: Error) -> Self {
        if let Error::Io(native) = &error
            && matches!(
                native.kind(),
                std::io::ErrorKind::NotFound
                    | std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::UnexpectedEof
            )
        {
            return Self::Unavailable(error);
        }
        Self::Refused(error)
    }
}

impl From<Error> for RequestFailure {
    fn from(error: Error) -> Self {
        Self::Refused(error)
    }
}

impl From<std::io::Error> for RequestFailure {
    fn from(error: std::io::Error) -> Self {
        Self::Refused(error.into())
    }
}

fn write_frame(stream: &mut impl Write, bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_METADATA {
        return Err(Error::Invalid(
            "managed control frame exceeds its bound".into(),
        ));
    }
    let length = u32::try_from(bytes.len())
        .map_err(|_| Error::Invalid("managed frame is too long".into()))?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(bytes)?;
    stream.flush()?;
    Ok(())
}

fn read_frame(stream: &mut impl Read) -> Result<Vec<u8>> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_METADATA {
        return Err(Error::Invalid(
            "managed control frame exceeds its bound".into(),
        ));
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}

#[cfg(unix)]
mod native {
    use super::*;
    use std::{
        fs,
        os::unix::{
            ffi::OsStrExt as _,
            fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _},
            net::{UnixListener, UnixStream},
            process::CommandExt as _,
        },
        path::PathBuf,
    };

    pub(crate) fn supported() -> Result<()> {
        Ok(())
    }

    pub(crate) fn detach(command: &mut Command) {
        // The owned supervisor has a separate process group; its stdio is already retained
        // private files. Lifecycle control never signals a guessed process group or PID.
        command.process_group(0);
    }

    fn endpoint(directory: &PrivateDirectory) -> PathBuf {
        directory.path().join("s")
    }

    fn local_endpoint_fits(store: &std::path::Path) -> bool {
        store.join("ipc/s").as_os_str().as_bytes().len() < 104
    }

    fn ipc_directory(store: &PrivateDirectory, create: bool) -> Result<PrivateDirectory> {
        store.revalidate()?;
        // Keep control custody beside the managed state whenever the absolute pathname fits.
        // Leave room for the NUL terminator in macOS's 104-byte sockaddr_un path; this conservative
        // bound also fits Linux. Selection depends only on the canonical store path, so controller
        // and worker always agree and unsafe local custody never selects a different endpoint.
        if local_endpoint_fits(store.path()) {
            return Ok(if create {
                store.ensure_child("ipc")?
            } else {
                store.open_child("ipc")?
            });
        }
        // Long paths use one short owner-private namespace bound to the complete store hash.
        let temporary = if cfg!(target_os = "macos") {
            "/private/tmp"
        } else {
            "/tmp"
        };
        let owner = rustix::process::geteuid().as_raw();
        let digest = blake3::hash(store.path().as_os_str().as_bytes()).to_hex();
        let path = PathBuf::from(temporary)
            .join(format!("iroha-{owner}"))
            .join(digest.as_str());
        Ok(if create {
            PrivateDirectory::open_or_create(path)?
        } else {
            PrivateDirectory::open(path)?
        })
    }

    fn validate_endpoint(directory: &PrivateDirectory) -> Result<(u64, u64)> {
        endpoint_observation(directory).map_err(RequestFailure::into_error)
    }

    fn endpoint_observation(
        directory: &PrivateDirectory,
    ) -> std::result::Result<(u64, u64), RequestFailure> {
        directory.revalidate()?;
        let metadata = match fs::symlink_metadata(endpoint(directory)) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                directory.revalidate()?;
                return Err(RequestFailure::Unavailable(error.into()));
            }
            Err(error) => return Err(error.into()),
        };
        if !metadata.file_type().is_socket()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(Error::Invalid(
                "managed socket must be one direct owner-only socket".into(),
            )
            .into());
        }
        Ok((metadata.dev(), metadata.ino()))
    }

    // The caller holds the managed operation and runtime locks; no owned worker can still use
    // this endpoint. Reject every unexpected object rather than broadening private tree removal.
    pub(crate) fn clear_stopped_endpoint(store: &PrivateDirectory) -> Result<()> {
        let directory = match ipc_directory(store, false) {
            Ok(directory) => directory,
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                store.revalidate()?;
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        match fs::symlink_metadata(endpoint(&directory)) {
            Ok(_) => {
                validate_endpoint(&directory)?;
                fs::remove_file(endpoint(&directory))?;
                directory.sync()?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        directory.revalidate()?;
        store.revalidate()?;
        Ok(())
    }

    fn authenticate_peer(stream: &UnixStream) -> Result<()> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let uid = rustix::net::sockopt::socket_peercred(stream)
            .map_err(std::io::Error::from)?
            .uid
            .as_raw();
        #[cfg(target_os = "macos")]
        let uid = {
            use std::os::fd::AsRawFd as _;
            let mut uid = 0;
            let mut gid = 0;
            #[allow(
                unsafe_code,
                reason = "getpeereid only reads kernel credentials from this live socket and writes two valid local outputs"
            )]
            let result = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
            if result != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            uid
        };
        #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
        let uid = return Err(Error::Invalid(
            "managed peer credential verification is unavailable on this Unix platform".into(),
        ));
        if uid != rustix::process::geteuid().as_raw() {
            return Err(Error::Invalid(
                "managed control peer belongs to another user".into(),
            ));
        }
        Ok(())
    }

    pub(crate) struct Listener {
        listener: UnixListener,
        path: PathBuf,
        identity: (u64, u64),
        _directory: PrivateDirectory,
    }

    impl Listener {
        pub(crate) fn bind(directory: &PrivateDirectory) -> Result<Self> {
            let directory = ipc_directory(directory, true)?;
            directory.revalidate()?;
            let path = endpoint(&directory);
            match fs::symlink_metadata(&path) {
                Ok(_) => {
                    validate_endpoint(&directory)?;
                    fs::remove_file(&path)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            let listener = UnixListener::bind(&path)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
            listener.set_nonblocking(true)?;
            let identity = validate_endpoint(&directory)?;
            Ok(Self {
                listener,
                path,
                identity,
                _directory: directory,
            })
        }

        pub(crate) fn accept(&self) -> Result<Option<Connection>> {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    let admission = (|| -> Result<()> {
                        authenticate_peer(&stream)?;
                        // BSD/macOS accept inherits the listener's nonblocking mode. A client
                        // may not have written its frame yet, so restore blocking I/O before
                        // applying the finite per-connection timeouts below.
                        stream.set_nonblocking(false)?;
                        stream.set_read_timeout(Some(IO_TIMEOUT))?;
                        stream.set_write_timeout(Some(IO_TIMEOUT))?;
                        Ok(())
                    })();
                    // Admission belongs to this accepted connection, not the listener.
                    // In particular, Darwin can reject timeout options after a queued
                    // client closes. Drop every refused stream without yielding it.
                    if admission.is_err() {
                        return Ok(None);
                    }
                    Ok(Some(Connection(stream)))
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
                Err(error) => Err(error.into()),
            }
        }
    }

    impl Drop for Listener {
        fn drop(&mut self) {
            if let Ok(metadata) = fs::symlink_metadata(&self.path)
                && (metadata.dev(), metadata.ino()) == self.identity
            {
                let _ = fs::remove_file(&self.path);
            }
        }
    }

    pub(crate) struct Connection(UnixStream);

    impl Connection {
        pub(crate) fn receive(&mut self) -> Result<ControlRequest> {
            decode(&read_frame(&mut self.0)?)
        }

        pub(crate) fn reply<T: JsonSerialize>(&mut self, status: &T) -> Result<()> {
            write_frame(&mut self.0, &encode(status)?)
        }
    }

    pub(crate) fn request_as<T: JsonDeserialize>(
        directory: &PrivateDirectory,
        request: &ControlRequest,
    ) -> Result<T> {
        request_observed_as(directory, request).map_err(RequestFailure::into_error)
    }

    pub(crate) fn request_observed_as<T: JsonDeserialize>(
        directory: &PrivateDirectory,
        request: &ControlRequest,
    ) -> std::result::Result<T, RequestFailure> {
        let deadline =
            (request.action == "down").then(|| Instant::now() + STOP_OBSERVATION_MAXIMUM);
        request_observed_with_deadline(directory, request, deadline)
    }

    pub(crate) fn request_observed_with_deadline<T: JsonDeserialize>(
        directory: &PrivateDirectory,
        request: &ControlRequest,
        deadline: Option<Instant>,
    ) -> std::result::Result<T, RequestFailure> {
        if let Some(deadline) = deadline {
            remaining_io(deadline)?;
        }
        let directory = ipc_directory(directory, false)?;
        let mut original = None;
        let result = (|| -> std::result::Result<T, RequestFailure> {
            let before = endpoint_observation(&directory)?;
            original = Some(before);
            let mut stream = match deadline {
                Some(deadline) => connect_until(&endpoint(&directory), deadline),
                None => UnixStream::connect(endpoint(&directory)),
            }
            .map_err(|error| RequestFailure::stream(error.into()))?;
            authenticate_peer(&stream)?;
            if deadline.is_none() {
                stream.set_read_timeout(Some(IO_TIMEOUT))?;
                stream.set_write_timeout(Some(IO_TIMEOUT))?;
            }
            if endpoint_observation(&directory)? != before {
                return Err(Error::Invalid(
                    "managed control endpoint changed during connection".into(),
                )
                .into());
            }
            let bytes = encode(request)?;
            let reply = if let Some(deadline) = deadline {
                let mut stream = DeadlineStream::new(stream, deadline)?;
                write_frame(&mut stream, &bytes).map_err(RequestFailure::stream)?;
                read_frame(&mut stream).map_err(RequestFailure::stream)?
            } else {
                write_frame(&mut stream, &bytes).map_err(RequestFailure::stream)?;
                read_frame(&mut stream).map_err(RequestFailure::stream)?
            };
            if let Some(deadline) = deadline {
                remaining_io(deadline)?;
            }
            decode(&reply).map_err(Into::into)
        })();
        let result = if matches!(&result, Err(RequestFailure::Unavailable(_))) {
            // A peer may close its exact socket, but a new or unsafe endpoint is not exit
            // evidence. Retain this original IPC child through every ordinary outcome.
            match endpoint_observation(&directory) {
                Ok(current) if original == Some(current) => result,
                Err(RequestFailure::Unavailable(_)) => result,
                Ok(_) => Err(Error::Invalid(
                    "managed control endpoint changed during unavailable exchange".into(),
                )
                .into()),
                Err(refusal) => Err(refusal),
            }
        } else {
            result
        };
        directory.revalidate()?;
        result
    }

    // A queued local connection can wait when the original owner's accept queue is full.
    // Only the stop observer uses nonblocking admission; ordinary control transport is unchanged.
    fn connect_until(path: &std::path::Path, deadline: Instant) -> std::io::Result<UnixStream> {
        #[cfg(not(target_vendor = "apple"))]
        use rustix::net::SocketFlags;
        use rustix::{
            io::Errno,
            net::{self, AddressFamily, SocketAddrUnix, SocketType},
        };
        let address = SocketAddrUnix::new(path)?;
        loop {
            remaining_io(deadline)?;
            #[cfg(target_vendor = "apple")]
            let socket = {
                // Darwin exposes neither SOCK_NONBLOCK nor SOCK_CLOEXEC at socket creation.
                let socket = net::socket(AddressFamily::UNIX, SocketType::STREAM, None)?;
                rustix::io::fcntl_setfd(&socket, rustix::io::FdFlags::CLOEXEC)?;
                net::sockopt::set_socket_nosigpipe(&socket, true)?;
                socket
            };
            #[cfg(not(target_vendor = "apple"))]
            let socket = net::socket_with(
                AddressFamily::UNIX,
                SocketType::STREAM,
                SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
                None,
            )?;
            let stream = UnixStream::from(socket);
            stream.set_nonblocking(true)?;
            let pending = match net::connect(&stream, &address) {
                Ok(()) => false,
                Err(Errno::INPROGRESS | Errno::ALREADY) => true,
                Err(Errno::AGAIN) => {
                    std::thread::sleep(POLL.min(remaining_io(deadline)?));
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            if pending {
                loop {
                    remaining_io(deadline)?;
                    if let Some(error) = stream.take_error()? {
                        return Err(error);
                    }
                    match stream.peer_addr() {
                        Ok(_) => break,
                        Err(error) if error.kind() == std::io::ErrorKind::NotConnected => {
                            std::thread::sleep(POLL.min(remaining_io(deadline)?));
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
            remaining_io(deadline)?;
            stream.set_nonblocking(false)?;
            return Ok(stream);
        }
    }

    // A peer can close after writing a complete reply. Darwin rejects timeout sockopts on
    // that disconnected socket even while its reply is buffered, so deadline I/O uses
    // an owned nonblocking descriptor and waits only for the original absolute remainder.
    // Darwin may still block a send with MSG_DONTWAIT alone when its buffer is full.
    // connect_until retains its blocking return contract; only this private exchange changes it.
    struct DeadlineStream {
        stream: UnixStream,
        deadline: Instant,
    }

    impl DeadlineStream {
        fn new(stream: UnixStream, deadline: Instant) -> std::io::Result<Self> {
            remaining_io(deadline)?;
            stream.set_nonblocking(true)?;
            remaining_io(deadline)?;
            Ok(Self { stream, deadline })
        }

        fn wait_ready(&self, events: rustix::event::PollFlags) -> std::io::Result<()> {
            use rustix::{
                event::{PollFd, Timespec, poll},
                io::Errno,
            };
            loop {
                let timeout = Timespec::try_from(remaining_io(self.deadline)?).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "managed poll timeout exceeds its native bound",
                    )
                })?;
                let mut descriptors = [PollFd::new(&self.stream, events)];
                match poll(&mut descriptors, Some(&timeout)) {
                    Ok(0) | Err(Errno::INTR) => continue,
                    Ok(_) => {
                        remaining_io(self.deadline)?;
                        // HUP/ERR also wake poll. The next nonblocking receive/send obtains
                        // buffered bytes, EOF or the actual socket error; readiness alone
                        // never proves that a complete authenticated frame arrived.
                        return Ok(());
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }
    }

    impl Read for DeadlineStream {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            use rustix::{
                event::PollFlags,
                io::Errno,
                net::{RecvFlags, recv},
            };
            loop {
                remaining_io(self.deadline)?;
                if bytes.is_empty() {
                    return Ok(0);
                }
                match recv(&self.stream, &mut *bytes, RecvFlags::DONTWAIT) {
                    Ok((_, received)) => {
                        remaining_io(self.deadline)?;
                        return Ok(received);
                    }
                    Err(Errno::AGAIN) => self.wait_ready(PollFlags::IN)?,
                    Err(Errno::INTR) => continue,
                    Err(error) => return Err(error.into()),
                }
            }
        }
    }

    impl Write for DeadlineStream {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            use rustix::{
                event::PollFlags,
                io::Errno,
                net::{SendFlags, send},
            };
            let flags = SendFlags::DONTWAIT;
            // Apple sockets retain SO_NOSIGPIPE from their creator; other native hosts
            // suppress SIGPIPE on each send without changing process-wide signal policy.
            #[cfg(not(any(target_vendor = "apple", target_os = "redox", target_os = "vita")))]
            let flags = flags | SendFlags::NOSIGNAL;
            loop {
                remaining_io(self.deadline)?;
                if bytes.is_empty() {
                    return Ok(0);
                }
                match send(&self.stream, bytes, flags) {
                    Ok(written) => {
                        remaining_io(self.deadline)?;
                        return Ok(written);
                    }
                    Err(Errno::AGAIN) => self.wait_ready(PollFlags::OUT)?,
                    Err(Errno::INTR) => continue,
                    Err(error) => return Err(error.into()),
                }
            }
        }

        fn flush(&mut self) -> std::io::Result<()> {
            // UnixStream has no userspace write buffer to flush.
            remaining_io(self.deadline).map(|_| ())
        }
    }

    #[cfg(test)]
    mod down_deadline_tests {
        use super::*;
        use std::{io, sync::mpsc, thread};

        #[test]
        fn complete_buffered_frame_survives_peer_close_before_header_or_body_read() {
            for header_consumed in [false, true] {
                let (mut reader, mut writer) = UnixStream::pair().unwrap();
                writer.write_all(&4_u32.to_be_bytes()).unwrap();
                writer.write_all(b"done").unwrap();
                drop(writer);
                // Closing precedes even the first bounded read, reproducing Darwin's
                // disconnected-socket sockopt refusal without a scheduling race.
                if header_consumed {
                    let mut header = [0; 4];
                    reader.read_exact(&mut header).unwrap();
                    assert_eq!(u32::from_be_bytes(header), 4);
                }
                let mut bounded =
                    DeadlineStream::new(reader, Instant::now() + Duration::from_secs(1)).unwrap();
                if header_consumed {
                    let mut body = [0; 4];
                    bounded.read_exact(&mut body).unwrap();
                    assert_eq!(&body, b"done");
                } else {
                    assert_eq!(read_frame(&mut bounded).unwrap(), b"done");
                }
            }
        }

        #[test]
        fn truncated_buffered_frame_after_peer_close_is_eof_not_completion() {
            for payload in [vec![], vec![0, 0], vec![0, 0, 0, 4, b'd', b'o']] {
                let (reader, mut writer) = UnixStream::pair().unwrap();
                writer.write_all(&payload).unwrap();
                drop(writer);
                let mut bounded =
                    DeadlineStream::new(reader, Instant::now() + Duration::from_secs(1)).unwrap();
                let error = read_frame(&mut bounded).unwrap_err();
                assert!(
                    matches!(&error, Error::Io(native) if native.kind() == io::ErrorKind::UnexpectedEof)
                );
                assert!(matches!(
                    RequestFailure::stream(error),
                    RequestFailure::Unavailable(_)
                ));
            }
        }

        #[test]
        fn deadline_write_to_closed_peer_returns_socket_error_without_sigpipe() {
            let temporary = tempfile::tempdir().unwrap();
            let path = temporary.path().join("socket");
            let listener = UnixListener::bind(&path).unwrap();
            // Exercise the same socket creation and SIGPIPE policy as an owned stop request.
            let stream = connect_until(&path, Instant::now() + Duration::from_secs(1)).unwrap();
            let (peer, _) = listener.accept().unwrap();
            #[cfg(target_vendor = "apple")]
            assert!(rustix::net::sockopt::socket_nosigpipe(&stream).unwrap());
            drop(peer);
            let mut bounded =
                DeadlineStream::new(stream, Instant::now() + Duration::from_secs(1)).unwrap();
            let error = bounded.write(b"original request").unwrap_err();
            assert!(matches!(
                error.kind(),
                io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
            ));
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn deadline_stream_establishes_nonblocking_mode_before_frame_io() {
            use std::os::fd::AsRawFd as _;

            fn nonblocking(stream: &UnixStream) -> bool {
                #[allow(
                    unsafe_code,
                    reason = "F_GETFL only reads status flags from this live test-owned socket"
                )]
                let flags = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFL) };
                assert_ne!(flags, -1, "{}", io::Error::last_os_error());
                flags & libc::O_NONBLOCK != 0
            }

            let (stream, _peer) = UnixStream::pair().unwrap();
            assert!(!nonblocking(&stream));
            let bounded =
                DeadlineStream::new(stream, Instant::now() + Duration::from_secs(1)).unwrap();
            assert!(nonblocking(&bounded.stream));

            let (stream, _peer) = UnixStream::pair().unwrap();
            let observer = stream.try_clone().unwrap();
            let error = DeadlineStream::new(stream, Instant::now())
                .err()
                .expect("expired admission must refuse before changing socket mode");
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert!(!nonblocking(&observer));
        }

        #[test]
        fn blocked_frame_write_cannot_extend_original_deadline() {
            let (writer, reader) = UnixStream::pair().unwrap();
            rustix::net::sockopt::set_socket_send_buffer_size(&writer, 4096).unwrap();
            let watchdog_peer = reader.try_clone().unwrap();
            let (finished, completion) = mpsc::channel();
            let watchdog = thread::spawn(move || {
                if completion.recv_timeout(Duration::from_secs(2)).is_err() {
                    // Fail closed if a blocking send is reintroduced: shutdown affects the
                    // retained peer too, wakes send, and must produce a failing socket error.
                    watchdog_peer.shutdown(std::net::Shutdown::Both).unwrap();
                }
            });
            let started = Instant::now();
            let result = DeadlineStream::new(writer, started + Duration::from_millis(80))
                .map_err(Error::from)
                .and_then(|mut bounded| write_frame(&mut bounded, &vec![0x5a; 128 * 1024]));
            let elapsed = started.elapsed();
            let _ = finished.send(());
            watchdog.join().unwrap();
            let error = result.unwrap_err();
            assert!(matches!(error, Error::Io(error) if error.kind() == io::ErrorKind::TimedOut));
            assert!(elapsed >= Duration::from_millis(20));
            assert!(elapsed < Duration::from_secs(1));
        }

        #[test]
        fn fragmented_frame_does_not_restart_absolute_deadline() {
            let (reader, mut writer) = UnixStream::pair().unwrap();
            let (start, proceed) = mpsc::channel();
            let worker = thread::spawn(move || {
                proceed.recv_timeout(Duration::from_secs(1)).unwrap();
                writer
                    .set_write_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                writer.write_all(&4_u32.to_be_bytes()).unwrap();
                writer.write_all(b"a").unwrap();
                // Every fragment would fit a renewed relative budget; the whole frame does not.
                for byte in b"bcd" {
                    thread::sleep(Duration::from_millis(100));
                    if writer.write_all(&[*byte]).is_err() {
                        break;
                    }
                }
            });
            let started = Instant::now();
            let deadline = started + Duration::from_millis(180);
            start.send(()).unwrap();
            let mut bounded = DeadlineStream::new(reader, deadline).unwrap();
            let result = read_frame(&mut bounded);
            assert!(
                matches!(result, Err(Error::Io(error)) if matches!(error.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock))
            );
            assert!(started.elapsed() < Duration::from_secs(1));
            drop(bounded);
            worker.join().unwrap();
        }

        #[test]
        fn down_connect_uses_original_deadline_and_returns_blocking_stream() {
            let temporary = tempfile::tempdir().unwrap();
            let path = temporary.path().join("socket");
            let listener = UnixListener::bind(&path).unwrap();
            let stream = connect_until(&path, Instant::now() + Duration::from_secs(1)).unwrap();
            #[cfg(target_vendor = "apple")]
            assert!(rustix::net::sockopt::socket_nosigpipe(&stream).unwrap());
            let (mut accepted, _) = listener.accept().unwrap();
            accepted
                .set_write_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            accepted.write_all(b"x").unwrap();
            let mut stream = stream;
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            assert_eq!(byte, *b"x");
            stream
                .set_read_timeout(Some(Duration::from_millis(50)))
                .unwrap();
            let started = Instant::now();
            assert!(stream.read(&mut byte).is_err());
            assert!(
                started.elapsed() >= Duration::from_millis(20),
                "returned stream remained nonblocking"
            );
            assert_eq!(
                connect_until(&path, Instant::now()).unwrap_err().kind(),
                io::ErrorKind::TimedOut
            );
        }

        #[test]
        fn expired_deadline_refuses_read_write_and_flush_without_io() {
            let (stream, mut other) = UnixStream::pair().unwrap();
            other.set_nonblocking(true).unwrap();
            let mut bounded =
                DeadlineStream::new(stream, Instant::now() + Duration::from_secs(1)).unwrap();
            bounded.deadline = Instant::now();
            assert_eq!(
                bounded.read(&mut [0]).unwrap_err().kind(),
                io::ErrorKind::TimedOut
            );
            assert_eq!(
                bounded.write(b"x").unwrap_err().kind(),
                io::ErrorKind::TimedOut
            );
            assert_eq!(bounded.flush().unwrap_err().kind(), io::ErrorKind::TimedOut);
            assert_eq!(
                other.read(&mut [0]).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn cleanup_availability_distinguishes_absent_socket_from_unsafe_or_missing_parent() {
            let _resources = super::super::super::native_test_guard();
            let temporary = tempfile::tempdir().unwrap();
            let directory =
                PrivateDirectory::open_or_create(temporary.path().join("network")).unwrap();
            let request = ControlRequest {
                token: "d".repeat(64),
                action: "down".into(),
            };
            let listener = Listener::bind(&directory).unwrap();
            drop(listener);
            assert!(matches!(
                request_observed_as::<ManagedStatus>(&directory, &request),
                Err(RequestFailure::Unavailable(Error::Io(error))) if error.kind() == std::io::ErrorKind::NotFound
            ));
            let ipc = ipc_directory(&directory, false).unwrap();
            ipc.write_atomic("s", b"unsafe endpoint", iroha_fs::PublishMode::CreateNew)
                .unwrap();
            assert!(matches!(
                request_observed_as::<ManagedStatus>(&directory, &request),
                Err(RequestFailure::Refused(Error::Invalid(_)))
            ));
            fs::remove_file(endpoint(&ipc)).unwrap();
            let path = ipc.path().to_owned();
            drop(ipc);
            fs::remove_dir(path).unwrap();
            assert!(matches!(
                request_observed_as::<ManagedStatus>(&directory, &request),
                Err(RequestFailure::Refused(Error::Io(error))) if error.kind() == std::io::ErrorKind::NotFound
            ));
            let listener = Listener::bind(&directory).unwrap();
            drop(listener);
            assert!(matches!(
                request_observed_as::<ManagedStatus>(&directory, &request),
                Err(RequestFailure::Unavailable(Error::Io(error))) if error.kind() == std::io::ErrorKind::NotFound
            ));
            directory.revalidate().unwrap();
        }

        // These controls specifically exercise the local ipc child, not the
        // production long-path endpoint. Select a private short OS fixture root
        // without mutating process-wide TMPDIR or weakening socket assertions.
        fn short_store_fixture() -> tempfile::TempDir {
            let root = if cfg!(target_os = "macos") {
                "/private/tmp"
            } else {
                "/tmp"
            };
            tempfile::Builder::new()
                .prefix("iroha-ipc-")
                .tempdir_in(root)
                .expect("create private short local socket fixture")
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn linux_peer_credentials_authenticate_both_owned_socket_pair_ends() {
            let (left, right) = UnixStream::pair().unwrap();
            authenticate_peer(&left).unwrap();
            authenticate_peer(&right).unwrap();
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn linux_peer_credentials_map_non_socket_failure_to_managed_io_error() {
            use std::os::fd::OwnedFd;

            let descriptor = OwnedFd::from(fs::File::open("/dev/null").unwrap());
            let non_socket = UnixStream::from(descriptor);
            let Err(Error::Io(error)) = authenticate_peer(&non_socket) else {
                panic!("a non-socket descriptor must remain an I/O authentication failure");
            };
            assert_eq!(
                error.raw_os_error(),
                Some(rustix::io::Errno::NOTSOCK.raw_os_error())
            );
        }

        #[test]
        fn local_endpoint_selection_counts_bytes_and_reserves_the_nul_terminator() {
            assert!(local_endpoint_fits(std::path::Path::new(&"x".repeat(97))));
            assert!(!local_endpoint_fits(std::path::Path::new(&"x".repeat(98))));
            assert!(local_endpoint_fits(std::path::Path::new(&"é".repeat(48))));
            assert!(!local_endpoint_fits(std::path::Path::new(&"é".repeat(49))));
        }

        #[test]
        fn short_store_keeps_authenticated_socket_inside_its_private_custody() {
            let temporary = short_store_fixture();
            let directory = PrivateDirectory::open_or_create(temporary.path().join("a")).unwrap();
            let expected = directory.path().join("ipc/s");
            assert!(
                expected.as_os_str().as_bytes().len() < 104,
                "fixture needs a short TMPDIR"
            );
            assert!(ipc_directory(&directory, false).is_err());
            assert!(
                !directory.path().join("ipc").exists(),
                "read-only lookup must not create custody"
            );
            let listener = Listener::bind(&directory).unwrap();
            assert_eq!(listener.path, expected);
            let ipc = ipc_directory(&directory, false).unwrap();
            assert_eq!(ipc.path(), directory.path().join("ipc"));
            validate_endpoint(&ipc).unwrap();
            let stream = UnixStream::connect(&listener.path).unwrap();
            authenticate_peer(&stream).unwrap();
            assert!(listener.accept().unwrap().is_some());
            let other = PrivateDirectory::open_or_create(temporary.path().join("b")).unwrap();
            let other_listener = Listener::bind(&other).unwrap();
            assert_ne!(listener.path, other_listener.path);
            drop(listener);
            assert!(!expected.exists());
            validate_endpoint(&ipc_directory(&other, false).unwrap()).unwrap();
        }

        #[test]
        fn unsafe_local_ipc_custody_is_rejected_without_selecting_another_endpoint() {
            let temporary = short_store_fixture();
            let directory = PrivateDirectory::open_or_create(temporary.path().join("a")).unwrap();
            assert!(directory.path().join("ipc/s").as_os_str().as_bytes().len() < 104);
            let target = directory.ensure_child("target").unwrap();
            std::os::unix::fs::symlink(target.path(), directory.path().join("ipc")).unwrap();
            assert!(Listener::bind(&directory).is_err());
            assert!(ipc_directory(&directory, false).is_err());
            assert!(target.entries(0).unwrap().is_empty());
            assert!(
                std::fs::symlink_metadata(directory.path().join("ipc"))
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
        }

        #[test]
        fn stopped_endpoint_cleanup_keeps_other_files_and_rejects_non_sockets() {
            let temporary = short_store_fixture();
            let directory = PrivateDirectory::open_or_create(temporary.path().join("a")).unwrap();
            assert!(directory.path().join("ipc/s").as_os_str().as_bytes().len() < 104);
            clear_stopped_endpoint(&directory).unwrap();
            assert!(!directory.path().join("ipc").exists());
            let ipc = ipc_directory(&directory, true).unwrap();
            ipc.write_atomic("keep", b"original", iroha_fs::PublishMode::CreateNew)
                .unwrap();
            let socket = endpoint(&ipc);
            // Dropping a bare listener leaves its pathname, reproducing a crashed worker.
            let listener = UnixListener::bind(&socket).unwrap();
            fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
            drop(listener);
            clear_stopped_endpoint(&directory).unwrap();
            assert!(!socket.exists());
            assert_eq!(ipc.read("keep", 32).unwrap().as_slice(), b"original");
            ipc.write_atomic("s", b"unexpected", iroha_fs::PublishMode::CreateNew)
                .unwrap();
            assert!(clear_stopped_endpoint(&directory).is_err());
            assert_eq!(ipc.read("s", 32).unwrap().as_slice(), b"unexpected");
        }

        #[test]
        fn long_workspace_uses_a_short_owner_bound_socket_and_cleans_it() {
            let temporary = tempfile::tempdir().unwrap();
            let path = temporary.path().join("x".repeat(80)).join("y".repeat(80));
            let directory = PrivateDirectory::open_or_create(path).unwrap();
            let listener = Listener::bind(&directory).unwrap();
            assert!(listener.path.as_os_str().as_bytes().len() < 104);
            let ipc = ipc_directory(&directory, false).unwrap();
            validate_endpoint(&ipc).unwrap();
            let stream = UnixStream::connect(&listener.path).unwrap();
            authenticate_peer(&stream).unwrap();
            assert!(listener.accept().unwrap().is_some());
            let socket = listener.path.clone();
            drop(listener);
            assert!(!socket.exists());
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn abandoned_control_client_keeps_listener_for_authenticated_retry() {
            let _resources = super::super::super::native_test_guard();
            let temporary = tempfile::tempdir().unwrap();
            let directory =
                PrivateDirectory::open_or_create(temporary.path().join("network")).unwrap();
            let listener = Listener::bind(&directory).unwrap();
            let identity = validate_endpoint(&listener._directory).unwrap();

            // Close a real queued client before the server accepts it. Darwin can still
            // authenticate this stream, but rejects its timeout options with EINVAL.
            drop(UnixStream::connect(&listener.path).unwrap());
            assert!(listener.accept().unwrap().is_none());
            assert_eq!(validate_endpoint(&listener._directory).unwrap(), identity);

            let mut client = UnixStream::connect(&listener.path).unwrap();
            authenticate_peer(&client).unwrap();
            let mut connection = listener.accept().unwrap().unwrap();
            assert_eq!(connection.0.read_timeout().unwrap(), Some(IO_TIMEOUT));
            assert_eq!(connection.0.write_timeout().unwrap(), Some(IO_TIMEOUT));
            let request = ControlRequest {
                token: "d".repeat(64),
                action: "status".into(),
            };
            write_frame(&mut client, &encode(&request).unwrap()).unwrap();
            let actual = connection.receive().unwrap();
            assert_eq!(actual.token, request.token);
            assert_eq!(actual.action, request.action);
            connection.reply(&actual).unwrap();
            let reply: ControlRequest = decode(&read_frame(&mut client).unwrap()).unwrap();
            assert_eq!(reply.token, request.token);
            assert_eq!(reply.action, request.action);
            assert!(listener.accept().unwrap().is_none());
            assert_eq!(validate_endpoint(&listener._directory).unwrap(), identity);
            directory.revalidate().unwrap();
        }

        #[test]
        fn accepted_control_connection_waits_for_delayed_and_partial_frames() {
            let _resources = super::super::super::native_test_guard();
            let temporary = tempfile::tempdir().unwrap();
            let directory =
                PrivateDirectory::open_or_create(temporary.path().join("network")).unwrap();
            let listener = Listener::bind(&directory).unwrap();
            let mut client = UnixStream::connect(&listener.path).unwrap();
            let mut connection = listener.accept().unwrap().unwrap();
            assert_eq!(connection.0.read_timeout().unwrap(), Some(IO_TIMEOUT));
            assert_eq!(connection.0.write_timeout().unwrap(), Some(IO_TIMEOUT));
            // Accept remains a polling operation even though its accepted stream blocks.
            assert!(listener.accept().unwrap().is_none());
            let request = ControlRequest {
                token: "c".repeat(64),
                action: "status".into(),
            };
            let mut frame = Vec::new();
            write_frame(&mut frame, &encode(&request).unwrap()).unwrap();
            let (entered, ready) = std::sync::mpsc::channel();
            let (sender, received) = std::sync::mpsc::channel();
            let reader = std::thread::spawn(move || {
                entered.send(()).unwrap();
                sender.send(connection.receive()).unwrap();
            });
            ready.recv_timeout(IO_TIMEOUT).unwrap();
            let before_frame = received.recv_timeout(Duration::from_millis(50));
            let prefix = client.write_all(&frame[..2]);
            let partial_header = received.recv_timeout(Duration::from_millis(50));
            let remainder = client.write_all(&frame[2..]);
            let complete = received.recv_timeout(IO_TIMEOUT + Duration::from_secs(1));
            // Join before assertions so the pre-fix early WouldBlock path leaves no reader.
            reader.join().unwrap();
            assert!(matches!(
                before_frame,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ));
            assert!(matches!(
                partial_header,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ));
            prefix.unwrap();
            remainder.unwrap();
            let actual = complete.unwrap().unwrap();
            assert_eq!(actual.action, request.action);
            assert_eq!(actual.token, request.token);
        }
    }
}

#[cfg(windows)]
#[path = "transport_windows.rs"]
mod native;

#[cfg(not(any(unix, windows)))]
mod native {
    use super::*;

    pub(crate) fn supported() -> Result<()> {
        Err(Error::Invalid(
            "this build does not yet provide owner-authenticated native managed IPC".into(),
        ))
    }
    pub(crate) fn detach(_: &mut Command) {}
    pub(crate) struct Listener;
    impl Listener {
        pub(crate) fn bind(_: &PrivateDirectory) -> Result<Self> {
            supported()?;
            Ok(Self)
        }
        pub(crate) fn accept(&self) -> Result<Option<Connection>> {
            supported()?;
            Ok(None)
        }
    }
    pub(crate) struct Connection;
    impl Connection {
        pub(crate) fn receive(&mut self) -> Result<ControlRequest> {
            Err(Error::Invalid("native IPC unavailable".into()))
        }
        pub(crate) fn reply<T: JsonSerialize>(&mut self, _: &T) -> Result<()> {
            supported()
        }
    }
    pub(crate) fn request_as<T: JsonDeserialize>(
        _: &PrivateDirectory,
        _: &ControlRequest,
    ) -> Result<T> {
        Err(Error::Invalid("native IPC unavailable".into()))
    }
    pub(crate) fn request_observed_as<T: JsonDeserialize>(
        _: &PrivateDirectory,
        _: &ControlRequest,
    ) -> std::result::Result<T, RequestFailure> {
        Err(Error::Invalid("native IPC unavailable".into()).into())
    }
    pub(crate) fn request_observed_with_deadline<T: JsonDeserialize>(
        _: &PrivateDirectory,
        _: &ControlRequest,
        _: Option<Instant>,
    ) -> std::result::Result<T, RequestFailure> {
        Err(Error::Invalid("native IPC unavailable".into()).into())
    }
}

pub(crate) use native::{Listener, detach, request_as, supported};

/// Remove only a stopped worker's validated Unix socket while both managed ownership locks are held.
/// Named pipes have no filesystem entry and disappear when their original handles close.
pub(crate) fn clear_stopped_endpoint(directory: &PrivateDirectory) -> Result<()> {
    #[cfg(unix)]
    {
        native::clear_stopped_endpoint(directory)
    }
    #[cfg(not(unix))]
    {
        let _ = directory;
        Ok(())
    }
}

pub(crate) fn request(
    directory: &PrivateDirectory,
    request: &ControlRequest,
) -> Result<ManagedStatus> {
    request_as(directory, request)
}

pub(crate) fn request_observed_until(
    directory: &PrivateDirectory,
    request: &ControlRequest,
    deadline: Instant,
) -> std::result::Result<ManagedStatus, RequestFailure> {
    remaining_io(deadline)?;
    native::request_observed_with_deadline(directory, request, Some(deadline))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_control_frame_is_rejected_before_allocating_payload() {
        let bytes = ((MAX_METADATA + 1) as u32).to_be_bytes();
        assert!(read_frame(&mut bytes.as_slice()).is_err());
        assert!(read_frame(&mut [0_u8; 4].as_slice()).is_err());
    }

    #[test]
    fn framed_control_payload_roundtrips_and_truncation_fails() {
        let mut frame = Vec::new();
        write_frame(&mut frame, b"public-status").unwrap();
        assert_eq!(read_frame(&mut frame.as_slice()).unwrap(), b"public-status");
        frame.pop();
        assert!(read_frame(&mut frame.as_slice()).is_err());
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn native_control_roundtrips_typed_attachment_observations() {
        let _resources = super::super::native_test_guard();
        let temporary = tempfile::tempdir().unwrap();
        let directory = PrivateDirectory::open_or_create(temporary.path().join("network")).unwrap();
        let listener = Listener::bind(&directory).unwrap();
        let expected = ManagedAttachmentStatus {
            network: "fixture".into(),
            stage: ManagedAttachmentPhase::Connecting,
            wallet_status: None,
            local_successor: None,
            parent_confirmed: None,
            failure: None,
        };
        let reply = expected.clone();
        let server = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            loop {
                if let Some(mut connection) = listener.accept().unwrap() {
                    assert_eq!(connection.receive().unwrap().action, "attachment_status");
                    connection.reply(&reply).unwrap();
                    return;
                }
                assert!(std::time::Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(1));
            }
        });
        let actual: ManagedAttachmentStatus = request_as(
            &directory,
            &ControlRequest {
                token: "c".repeat(64),
                action: "attachment_status".into(),
            },
        )
        .unwrap();
        assert_eq!(actual, expected);
        server.join().unwrap();
    }
}
