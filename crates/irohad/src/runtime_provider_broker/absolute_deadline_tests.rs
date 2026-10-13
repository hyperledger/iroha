//! Deadline exhaustion cannot reopen socket work or retire a queued operation.

use super::*;

fn expired() -> BrokerDeadlineV1 {
    BrokerDeadlineV1 {
        expires_at: Instant::now().checked_sub(Duration::from_secs(1)).unwrap(),
    }
}

#[test]
fn invalid_or_expired_deadlines_reject_even_an_uncontended_lock() {
    assert!(BrokerDeadlineV1::new(Duration::ZERO).is_err());
    assert!(BrokerDeadlineV1::new(Duration::MAX).is_err());
    let state = Mutex::new(String::from("before"));
    assert!(expired().remaining().is_err());
    assert!(expired().lock(&state).is_err());
    assert_eq!(*state.lock().unwrap(), "before");
    let deadline = BrokerDeadlineV1::new(Duration::from_secs(5)).unwrap();
    *deadline.lock(&state).unwrap() = String::from("after");
    assert_eq!(*state.lock().unwrap(), "after");
}

#[test]
fn expired_socket_views_do_not_consume_input_or_emit_output() {
    let (mut local, mut peer) = UnixStream::pair().unwrap();
    peer.write_all(b"retained").unwrap();
    let mut view = DeadlineUnixStreamV1::new(&mut local, expired());
    let mut byte = [0_u8; 1];
    assert_eq!(
        view.read(&mut byte).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(
        view.write(b"forbidden").unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(view.flush().unwrap_err().kind(), io::ErrorKind::TimedOut);
    let mut input = [0_u8; 8];
    local.read_exact(&mut input).unwrap();
    assert_eq!(&input, b"retained");
    peer.set_nonblocking(true).unwrap();
    assert_eq!(
        peer.read(&mut byte).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn one_deadline_survives_distinct_framing_views_without_renewal() {
    let (mut local, mut peer) = UnixStream::pair().unwrap();
    let deadline = BrokerDeadlineV1::new(Duration::from_secs(5)).unwrap();
    let original_endpoint = deadline.expires_at();
    DeadlineUnixStreamV1::new(&mut local, deadline)
        .write_all(b"one")
        .unwrap();
    let mut first = [0_u8; 3];
    peer.read_exact(&mut first).unwrap();
    assert_eq!(&first, b"one");
    peer.write_all(b"two").unwrap();
    let mut second = [0_u8; 3];
    DeadlineUnixStreamV1::new(&mut local, deadline)
        .read_exact(&mut second)
        .unwrap();
    assert_eq!(&second, b"two");
    assert_eq!(deadline.expires_at(), original_endpoint);
}

#[test]
fn occupied_session_admission_ends_without_waiting_for_the_holder() {
    let state = Mutex::new(String::from("held"));
    let held = state.lock().unwrap();
    let began = Instant::now();
    let deadline = BrokerDeadlineV1::new(Duration::from_millis(25)).unwrap();
    assert!(deadline.lock(&state).is_err());
    assert!(began.elapsed() < Duration::from_secs(5));
    assert_eq!(*held, "held");
}

#[test]
fn blocked_socket_read_and_write_share_the_original_expiration() {
    let (mut local, _peer) = UnixStream::pair().unwrap();
    let deadline = BrokerDeadlineV1::new(Duration::from_millis(25)).unwrap();
    let began = Instant::now();
    let mut byte = [0_u8; 1];
    assert_eq!(
        DeadlineUnixStreamV1::new(&mut local, deadline)
            .read_exact(&mut byte)
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert!(began.elapsed() < Duration::from_secs(5));
    assert!(Instant::now() >= deadline.expires_at());
    assert_eq!(
        DeadlineUnixStreamV1::new(&mut local, deadline)
            .write(b"late")
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
}

#[test]
fn closed_peer_response_is_drained_through_exact_eof_before_deadline() {
    let (mut local, mut peer) = UnixStream::pair().unwrap();
    let original_flags = rustix::fs::fcntl_getfl(&local).unwrap();
    local
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    peer.write_all(b"final buffered broker response").unwrap();
    drop(peer);
    let deadline = BrokerDeadlineV1::new(Duration::from_secs(5)).unwrap();
    let mut view = DeadlineUnixStreamV1::new(&mut local, deadline);
    let mut prefix = [0; 5];
    view.read_exact(&mut prefix).unwrap();
    assert_eq!(&prefix, b"final");
    let mut remainder = Vec::new();
    view.read_to_end(&mut remainder).unwrap();
    assert_eq!(remainder, b" buffered broker response");
    assert_eq!(local.read_timeout().unwrap(), Some(Duration::from_secs(2)));
    assert_eq!(rustix::fs::fcntl_getfl(&local).unwrap(), original_flags);
    assert!(deadline.remaining().is_ok());
}

#[test]
fn blocked_write_and_later_drain_never_renew_expired_deadline() {
    let (mut local, mut peer) = UnixStream::pair().unwrap();
    rustix::net::sockopt::set_socket_send_buffer_size(&local, 4096).unwrap();
    let original_flags = rustix::fs::fcntl_getfl(&local).unwrap();
    local
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let fill = [0x63; 4096];
    let mut buffered = 0;
    loop {
        match rustix::net::send(&local, &fill, rustix::net::SendFlags::DONTWAIT) {
            Ok(count) => {
                assert!(count > 0);
                buffered += count;
                assert!(
                    buffered < 16 * 1024 * 1024,
                    "fixture must reach backpressure"
                );
            }
            Err(rustix::io::Errno::INTR) => (),
            Err(rustix::io::Errno::AGAIN) => break,
            Err(error) => panic!("fill socket: {error}"),
        }
    }
    assert!(buffered > 0);
    let deadline = BrokerDeadlineV1::new(Duration::from_millis(25)).unwrap();
    let began = Instant::now();
    assert_eq!(
        DeadlineUnixStreamV1::new(&mut local, deadline)
            .write(b"blocked")
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert!(Instant::now() >= deadline.expires_at());
    assert!(began.elapsed() < Duration::from_secs(5));
    let mut received = vec![0; buffered];
    peer.read_exact(&mut received).unwrap();
    assert!(received.iter().all(|byte| *byte == 0x63));
    assert_eq!(
        DeadlineUnixStreamV1::new(&mut local, deadline)
            .write(b"late")
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(
        rustix::net::recv(&peer, &mut [0; 1], rustix::net::RecvFlags::DONTWAIT).unwrap_err(),
        rustix::io::Errno::AGAIN
    );
    assert_eq!(local.write_timeout().unwrap(), Some(Duration::from_secs(2)));
    assert_eq!(rustix::fs::fcntl_getfl(&local).unwrap(), original_flags);
}

#[test]
fn closed_peer_write_fails_without_changing_descriptor_mode() {
    let (mut local, mut peer) = UnixStream::pair().unwrap();
    let original_flags = rustix::fs::fcntl_getfl(&local).unwrap();
    let deadline = BrokerDeadlineV1::new(Duration::from_secs(5)).unwrap();
    DeadlineUnixStreamV1::new(&mut local, deadline)
        .write_all(b"open")
        .unwrap();
    let mut received = [0; 4];
    peer.read_exact(&mut received).unwrap();
    assert_eq!(&received, b"open");
    #[cfg(target_os = "macos")]
    assert!(rustix::net::sockopt::socket_nosigpipe(&local).unwrap());
    drop(peer);
    assert!(
        DeadlineUnixStreamV1::new(&mut local, deadline)
            .write(b"closed")
            .is_err()
    );
    assert_eq!(rustix::fs::fcntl_getfl(&local).unwrap(), original_flags);
    assert!(deadline.remaining().is_ok());
}

#[test]
fn empty_io_requires_a_live_deadline_without_touching_the_socket() {
    let (mut local, peer) = UnixStream::pair().unwrap();
    let original_flags = rustix::fs::fcntl_getfl(&local).unwrap();
    let deadline = BrokerDeadlineV1::new(Duration::from_secs(5)).unwrap();
    assert_eq!(
        DeadlineUnixStreamV1::new(&mut local, deadline)
            .read(&mut [])
            .unwrap(),
        0
    );
    drop(peer);
    assert_eq!(
        DeadlineUnixStreamV1::new(&mut local, deadline)
            .write(&[])
            .unwrap(),
        0
    );
    assert_eq!(
        DeadlineUnixStreamV1::new(&mut local, expired())
            .read(&mut [])
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(
        DeadlineUnixStreamV1::new(&mut local, expired())
            .write(&[])
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(local.read_timeout().unwrap(), None);
    assert_eq!(local.write_timeout().unwrap(), None);
    assert_eq!(rustix::fs::fcntl_getfl(&local).unwrap(), original_flags);
    assert!(deadline.remaining().is_ok());
}

#[test]
fn response_deadline_drains_a_closed_peers_complete_frame_and_eof() {
    let (mut local, mut peer) = UnixStream::pair().unwrap();
    peer.write_all(b"\x04\x00\x00\x00done").unwrap();
    peer.shutdown(std::net::Shutdown::Write).unwrap();
    drop(peer);
    let deadline = BrokerDeadlineV1::new(Duration::from_secs(1)).unwrap();
    let mut reader = DeadlineUnixStreamV1::new(&mut local, deadline);
    let mut prefix = [0; 4];
    reader.read_exact(&mut prefix).unwrap();
    assert_eq!(u32::from_le_bytes(prefix), 4);
    let mut body = [0; 4];
    reader.read_exact(&mut body).unwrap();
    assert_eq!(&body, b"done");
    assert_eq!(reader.read(&mut [0; 1]).unwrap(), 0);
}

#[test]
fn expired_response_deadline_rejects_closed_peers_buffered_bytes() {
    let (mut local, mut peer) = UnixStream::pair().unwrap();
    peer.write_all(b"late").unwrap();
    drop(peer);
    assert_eq!(
        DeadlineUnixStreamV1::new(&mut local, expired())
            .read(&mut [0; 4])
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    let mut retained = [0; 4];
    local.read_exact(&mut retained).unwrap();
    assert_eq!(&retained, b"late");
}
