//! Current-user named pipes with bounded overlapped I/O and native peer authentication.

#![allow(
    unsafe_code,
    reason = "Win32 pipe peer-process queries and scoped security attributes require FFI"
)]

use super::*;
use std::{
    io,
    os::windows::{ffi::OsStrExt as _, io::AsRawHandle as _, process::CommandExt as _},
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions},
    runtime::{Builder, Runtime},
};
use windows_sys::Win32::System::{
    Pipes::{GetNamedPipeClientProcessId, GetNamedPipeServerProcessId},
    Threading::{CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW},
};

pub(crate) fn supported() -> Result<()> {
    Ok(())
}

pub(crate) fn detach(command: &mut Command) {
    command.creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
}

fn address(directory: &PrivateDirectory) -> Result<String> {
    directory.revalidate()?;
    let mut hasher = blake3::Hasher::new();
    for code in directory.path().as_os_str().encode_wide() {
        hasher.update(&code.to_le_bytes());
    }
    Ok(format!(
        r"\\.\pipe\iroha-managed-{}",
        hasher.finalize().to_hex()
    ))
}

fn runtime() -> io::Result<Runtime> {
    Builder::new_current_thread().enable_all().build()
}

fn create_pipe(address: &str, first: bool) -> io::Result<NamedPipeServer> {
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first)
        .reject_remote_clients(true);
    iroha_fs::windows::with_owner_security_attributes(|attributes| {
        // SAFETY: the filesystem custody owner retains a valid SECURITY_ATTRIBUTES record and
        // its protected current-user DACL for the complete duration of this callback.
        unsafe { options.create_with_security_attributes_raw(address, attributes) }
    })?
}

fn authenticate_peer(handle: std::os::windows::io::RawHandle, client: bool) -> Result<()> {
    let mut process = 0;
    // SAFETY: callers retain the live pipe handle; the process-id output is a valid local u32.
    let accepted = unsafe {
        if client {
            GetNamedPipeClientProcessId(handle, &mut process)
        } else {
            GetNamedPipeServerProcessId(handle, &mut process)
        }
    };
    if accepted == 0 {
        return Err(io::Error::last_os_error().into());
    }
    if !iroha_fs::windows::is_current_user_process(process)? {
        return Err(Error::Invalid(
            "managed pipe peer belongs to another user".into(),
        ));
    }
    Ok(())
}

pub(crate) struct Listener {
    address: String,
    runtime: Arc<Runtime>,
    pending: Mutex<NamedPipeServer>,
}

impl Listener {
    pub(crate) fn bind(directory: &PrivateDirectory) -> Result<Self> {
        let runtime = Arc::new(runtime()?);
        let address = address(directory)?;
        let pending = {
            let _entered = runtime.enter();
            create_pipe(&address, true)?
        };
        Ok(Self {
            address,
            runtime,
            pending: Mutex::new(pending),
        })
    }

    pub(crate) fn accept(&self) -> Result<Option<Connection>> {
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| Error::Invalid("managed pipe listener is poisoned".into()))?;
        match self.runtime.block_on(async {
            tokio::time::timeout(Duration::from_millis(1), pending.connect()).await
        }) {
            Err(_) => Ok(None),
            Ok(Err(error)) => Err(error.into()),
            Ok(Ok(())) => {
                // Keep the original server instance until its protected replacement exists.
                // Listener creation errors remain fatal; an unauthenticated accepted peer
                // is dropped without closing the listener or returning a Connection.
                let next = {
                    let _entered = self.runtime.enter();
                    create_pipe(&self.address, false)?
                };
                let stream = std::mem::replace(&mut *pending, next);
                if authenticate_peer(stream.as_raw_handle(), true).is_err() {
                    return Ok(None);
                }
                Ok(Some(Connection {
                    stream,
                    runtime: Arc::clone(&self.runtime),
                }))
            }
        }
    }
}

pub(crate) struct Connection {
    stream: NamedPipeServer,
    runtime: Arc<Runtime>,
}

impl Connection {
    pub(crate) fn receive(&mut self) -> Result<ControlRequest> {
        let bytes = self
            .runtime
            .block_on(async {
                tokio::time::timeout(IO_TIMEOUT, read_async(&mut self.stream)).await
            })
            .map_err(|_| Error::Invalid("managed pipe read deadline expired".into()))??;
        decode(&bytes)
    }

    pub(crate) fn reply<T: JsonSerialize>(&mut self, status: &T) -> Result<()> {
        let bytes = encode(status)?;
        self.runtime
            .block_on(async {
                tokio::time::timeout(IO_TIMEOUT, write_async(&mut self.stream, &bytes)).await
            })
            .map_err(|_| Error::Invalid("managed pipe write deadline expired".into()))?
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
    let deadline = (request.action == "down").then(|| Instant::now() + STOP_OBSERVATION_MAXIMUM);
    request_observed_with_deadline(directory, request, deadline)
}

pub(crate) fn request_observed_with_deadline<T: JsonDeserialize>(
    directory: &PrivateDirectory,
    request: &ControlRequest,
    deadline: Option<Instant>,
) -> std::result::Result<T, RequestFailure> {
    let result = (|| -> std::result::Result<T, RequestFailure> {
        if let Some(deadline) = deadline {
            remaining_io(deadline)?;
        }
        let runtime = runtime()?;
        let address = address(directory)?;
        let mut stream = {
            let _entered = runtime.enter();
            ClientOptions::new()
                .open(address)
                .map_err(|error| RequestFailure::stream(error.into()))?
        };
        authenticate_peer(stream.as_raw_handle(), false)?;
        let bytes = encode(request)?;
        let timeout = deadline
            .map(remaining_io)
            .transpose()?
            .unwrap_or(IO_TIMEOUT);
        let reply = runtime
            .block_on(async {
                let exchange = async {
                    write_async(&mut stream, &bytes).await?;
                    read_async(&mut stream).await
                };
                if let Some(deadline) = deadline {
                    tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), exchange)
                        .await
                } else {
                    tokio::time::timeout(timeout, exchange).await
                }
            })
            .map_err(|_| Error::Invalid("managed pipe control deadline expired".into()))?
            .map_err(RequestFailure::stream)?;
        if let Some(deadline) = deadline {
            remaining_io(deadline)?;
        }
        decode(&reply).map_err(Into::into)
    })();
    directory.revalidate()?;
    result
}

async fn read_async(stream: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>> {
    let length = stream.read_u32().await? as usize;
    if length == 0 || length > MAX_METADATA {
        return Err(Error::Invalid(
            "managed control frame exceeds its bound".into(),
        ));
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}

async fn write_async(stream: &mut (impl AsyncWrite + Unpin), bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_METADATA {
        return Err(Error::Invalid(
            "managed control frame exceeds its bound".into(),
        ));
    }
    stream
        .write_u32(
            u32::try_from(bytes.len())
                .map_err(|_| Error::Invalid("managed frame length overflow".into()))?,
        )
        .await?;
    stream.write_all(bytes).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{process::Stdio, time::Instant};
    use tokio::net::windows::named_pipe::NamedPipeClient;

    const CHILD: &str = "managed::transport::native::tests::abandoned_pipe_client_child";
    const CHILD_DIRECTORY: &str = "IROHA_TEST_ABANDONED_PIPE_DIRECTORY";

    #[test]
    fn abandoned_pipe_client_child() {
        let Some(path) = std::env::var_os(CHILD_DIRECTORY) else {
            return;
        };
        let directory = PrivateDirectory::open_exact(std::path::Path::new(&path)).unwrap();
        let runtime = runtime().unwrap();
        let entered = runtime.enter();
        let client = ClientOptions::new()
            .open(address(&directory).unwrap())
            .unwrap();
        drop(client);
        drop(entered);
    }

    fn client(address: &str) -> (Runtime, NamedPipeClient) {
        let runtime = runtime().unwrap();
        let stream = {
            let _entered = runtime.enter();
            ClientOptions::new().open(address).unwrap()
        };
        (runtime, stream)
    }

    fn roundtrip(connection: Connection, runtime: Runtime, mut client: NamedPipeClient) {
        let request = ControlRequest {
            token: "c".repeat(64),
            action: "status".into(),
        };
        let expected_token = request.token.clone();
        let server = std::thread::spawn(move || {
            let mut connection = connection;
            let received = connection.receive().unwrap();
            assert_eq!(received.action, "status");
            assert_eq!(received.token, expected_token);
            connection.reply(&received).unwrap();
        });
        let observed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let bytes = encode(&request).unwrap();
            let reply = runtime
                .block_on(async {
                    tokio::time::timeout(IO_TIMEOUT, async {
                        write_async(&mut client, &bytes).await?;
                        read_async(&mut client).await
                    })
                    .await
                })
                .unwrap()
                .unwrap();
            let reply: ControlRequest = decode(&reply).unwrap();
            assert_eq!(reply.action, request.action);
            assert_eq!(reply.token, request.token);
        }));
        let closed = server.join();
        observed.unwrap();
        closed.unwrap();
    }

    fn accepted(listener: &Listener) -> Connection {
        let deadline = Instant::now() + IO_TIMEOUT;
        loop {
            if let Some(connection) = listener.accept().unwrap() {
                return connection;
            }
            assert!(
                Instant::now() < deadline,
                "fresh pipe client was not admitted"
            );
        }
    }

    #[test]
    fn exited_queued_pipe_peer_does_not_close_listener_and_fresh_client_authenticates() {
        let _resources = super::super::super::native_test_guard();
        let temporary = tempfile::tempdir().unwrap();
        let directory = PrivateDirectory::open_or_create(temporary.path().join("network")).unwrap();
        let listener = Listener::bind(&directory).unwrap();
        assert!(Listener::bind(&directory).is_err());
        let log = directory.open_append("pipe-child.log").unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CHILD, "--nocapture", "--test-threads=1"])
            .env(CHILD_DIRECTORY, directory.path())
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        // The actual client process has closed its kernel endpoint and exited before
        // authentication. No fake credentials or injected authentication result is used.
        let closed = child.wait().unwrap();
        drop(child);
        assert!(closed.success());
        {
            let pending = listener.pending.lock().unwrap();
            listener
                .runtime
                .block_on(async { tokio::time::timeout(IO_TIMEOUT, pending.connect()).await })
                .unwrap()
                .unwrap();
        }
        // Windows may still expose queryable credentials for an exited pipe peer. Do not
        // assume a particular native authentication error: rejection or a closed empty
        // connection is valid, but neither may terminate the listener or accept a request.
        if let Some(mut connection) = listener.accept().unwrap() {
            assert!(connection.receive().is_err());
        }
        assert!(Listener::bind(&directory).is_err());
        let (runtime, stream) = client(&listener.address);
        roundtrip(accepted(&listener), runtime, stream);
        assert!(Listener::bind(&directory).is_err());
        drop(listener);
    }

    #[test]
    fn next_pipe_creation_failure_retains_original_instance_and_allows_exact_retry() {
        let _resources = super::super::super::native_test_guard();
        let temporary = tempfile::tempdir().unwrap();
        let directory = PrivateDirectory::open_or_create(temporary.path().join("network")).unwrap();
        let mut listener = Listener::bind(&directory).unwrap();
        let (runtime, stream) = client(&listener.address);
        let original = listener.pending.lock().unwrap().as_raw_handle();
        let address = listener.address.clone();
        // Exercise the actual native replacement-create error without replacing or
        // closing the original accepted instance, then retry its original address.
        listener.address = "invalid-managed-pipe-address".into();
        assert!(listener.accept().is_err());
        assert_eq!(listener.pending.lock().unwrap().as_raw_handle(), original);
        assert!(Listener::bind(&directory).is_err());
        listener.address = address;
        roundtrip(accepted(&listener), runtime, stream);
        drop(listener);
    }

    #[test]
    fn fragmented_pipe_reply_keeps_the_original_down_deadline() {
        let _resources = super::super::super::native_test_guard();
        let temporary = tempfile::tempdir().unwrap();
        let directory = PrivateDirectory::open_or_create(temporary.path().join("network")).unwrap();
        let listener = Listener::bind(&directory).unwrap();
        let server = std::thread::spawn(move || {
            let mut connection = accepted(&listener);
            assert_eq!(connection.receive().unwrap().action, "down");
            let runtime = Arc::clone(&connection.runtime);
            runtime.block_on(async {
                let _ = tokio::time::timeout(IO_TIMEOUT, async {
                    connection.stream.write_all(&4_u32.to_be_bytes()).await?;
                    connection.stream.write_all(b"a").await?;
                    for byte in b"bcd" {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        connection.stream.write_all(&[*byte]).await?;
                    }
                    Ok::<_, io::Error>(())
                })
                .await;
            });
        });
        let started = Instant::now();
        let result: std::result::Result<ControlRequest, RequestFailure> =
            request_observed_with_deadline(
                &directory,
                &ControlRequest {
                    token: "c".repeat(64),
                    action: "down".into(),
                },
                Some(started + Duration::from_millis(180)),
            );
        assert!(
            matches!(result, Err(RequestFailure::Refused(Error::Invalid(message))) if message == "managed pipe control deadline expired")
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        server.join().unwrap();
    }
}
