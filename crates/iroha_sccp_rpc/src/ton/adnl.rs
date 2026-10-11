//! ADNL-TCP handshake and framing for TON liteservers (spec §7.2, §8).
//!
//! A liteserver is identified by an Ed25519 public key. The client opens a TCP
//! connection and sends one 256-byte handshake packet:
//!
//! ```text
//! key_id(server) ‖ client_public ‖ sha256(params) ‖ AES-256-CTR(k, iv, params)
//! ```
//!
//! - `key_id(server) = sha256(0x4813b4c6 as LE u32 ‖ server_public)`, the
//!   hash of the TL value `pub.ed25519 key:int256`;
//! - `client_public` is the Edwards (Ed25519) encoding of the client's
//!   ephemeral X25519 key: a random clamped scalar `s` times the base point;
//! - `shared = X25519(s, montgomery(server_public))`, where the server's
//!   Ed25519 key is converted to its Montgomery u-coordinate. The server
//!   derives the same secret from its Ed25519 private scalar and the
//!   Montgomery form of `client_public`;
//! - `params` are 160 random bytes; `k = shared[0..16] ‖ sha256(params)[16..32]`
//!   and `iv = sha256(params)[0..4] ‖ shared[20..32]`.
//!
//! `params` then key the two AES-256-CTR session streams: the client receives
//! with key `params[0..32]` and counter block `params[64..80]` and sends with
//! key `params[32..64]` and counter block `params[80..96]` (128-bit big-endian
//! counters, continuous over the whole connection). The server confirms the
//! handshake with one empty packet.
//!
//! Every packet, including its length, is encrypted by the stream of its
//! direction:
//!
//! ```text
//! size: u32 LE (= 32 + payload + 32) ‖ nonce: 32 random bytes ‖ payload ‖ sha256(nonce ‖ payload)
//! ```
//!
//! Payloads are TL: `adnl.message.query` / `adnl.message.answer` carry
//! liteserver queries, and `tcp.ping` / `tcp.pong` keep a connection alive.
//! A packet with a bad length or checksum desynchronizes the streams, so the
//! connection is unusable afterwards and callers must drop it.
//!
//! The ephemeral scalar, the shared secret and `params` live in zeroizing
//! buffers, and the AES key schedules and counters are zeroized when the
//! session drops. I/O is blocking with one deadline per operation: every read
//! and write gets only the time left until it, so a peer that trickles bytes
//! cannot stretch an operation past its deadline. A query may also bound its
//! answer ([`AdnlConnection::query_bounded`]) below the session's packet bound.

use std::{
    fmt,
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};

use aes::{
    Aes256,
    cipher::{KeyIvInit, StreamCipher},
};
use curve25519_dalek::edwards::EdwardsPoint;
use ed25519_dalek::VerifyingKey;
use rand::{RngCore, TryRngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, SharedSecret, StaticSecret};
use zeroize::Zeroizing;

use super::tl::{TlReader, TlWriter};

/// AES-256 in CTR mode with a 128-bit big-endian counter.
type SessionCipher = ctr::Ctr128BE<Aes256>;

/// `pub.ed25519 key:int256 = PublicKey`.
pub const PUB_ED25519: u32 = 0x4813_b4c6;
/// `adnl.message.query query_id:int256 query:bytes = adnl.Message`.
pub const ADNL_MESSAGE_QUERY: u32 = 0xb48b_f97a;
/// `adnl.message.answer query_id:int256 answer:bytes = adnl.Message`.
pub const ADNL_MESSAGE_ANSWER: u32 = 0x0fac_8416;
/// `tcp.ping random_id:long = tcp.Pong`.
pub const TCP_PING: u32 = 0x4d08_2b9a;
/// `tcp.pong random_id:long = tcp.Pong`.
pub const TCP_PONG: u32 = 0xdc69_fb03;

/// Length of the client handshake packet.
pub const HANDSHAKE_PACKET_LEN: usize = 256;
/// Length of the random session parameters inside the handshake.
pub const HANDSHAKE_PARAMS_LEN: usize = 160;
/// Nonce plus checksum around every payload: the smallest `size` a packet
/// announces.
pub const PACKET_OVERHEAD: usize = 64;
/// Default bound on the announced `size` of one packet (16 MiB): above the
/// 2 MiB TON block size limit plus proofs, small enough that a hostile
/// liteserver cannot exhaust memory.
pub const DEFAULT_MAX_PACKET_BYTES: usize = 16 * 1024 * 1024;
/// What an `adnl.message.answer` packet adds around its answer: the packet
/// overhead, the constructor, the query id, and the TL length prefix and
/// padding of the answer bytes.
pub const ANSWER_ENVELOPE_BYTES: usize = PACKET_OVERHEAD + 4 + 32 + 4 + 3;

/// The packet bound that admits answers of at most `max_answer_bytes`.
pub const fn answer_packet_bytes(max_answer_bytes: usize) -> usize {
    max_answer_bytes.saturating_add(ANSWER_ENVELOPE_BYTES)
}

/// Why an ADNL operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdnlError {
    /// The server key is not a valid Ed25519 point, or has small order.
    InvalidServerKey,
    /// The key agreement produced the all-zero secret.
    NonContributory,
    /// The operating system random source failed.
    Randomness(String),
    /// A socket operation failed.
    Io {
        /// Kind of the I/O error.
        kind: io::ErrorKind,
        /// Bounded description.
        detail: String,
    },
    /// The deadline passed.
    Timeout,
    /// The peer closed the connection.
    Closed,
    /// A packet announces less than [`PACKET_OVERHEAD`] bytes.
    PacketTooShort {
        /// Announced size.
        size: usize,
    },
    /// A packet announces more than the configured bound.
    PacketTooLarge {
        /// Announced size.
        size: usize,
        /// The bound.
        limit: usize,
    },
    /// A packet's SHA-256 checksum does not match its nonce and payload.
    Checksum,
    /// A payload to send exceeds the configured bound.
    PayloadTooLarge {
        /// Payload length.
        length: usize,
        /// The bound on the packet size.
        limit: usize,
    },
    /// The peer sent a message that does not fit the protocol state.
    Protocol(String),
}

impl AdnlError {
    fn from_io(error: &io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => Self::Timeout,
            io::ErrorKind::UnexpectedEof => Self::Closed,
            kind => Self::Io {
                kind,
                detail: bounded(&error.to_string()),
            },
        }
    }
}

impl fmt::Display for AdnlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidServerKey => {
                formatter.write_str("the liteserver key is not a usable Ed25519 public key")
            }
            Self::NonContributory => {
                formatter.write_str("the ADNL key agreement produced the all-zero secret")
            }
            Self::Randomness(detail) => write!(formatter, "OS randomness failed: {detail}"),
            Self::Io { kind, detail } => write!(formatter, "socket error ({kind}): {detail}"),
            Self::Timeout => formatter.write_str("deadline exceeded"),
            Self::Closed => formatter.write_str("connection closed by the liteserver"),
            Self::PacketTooShort { size } => {
                write!(
                    formatter,
                    "ADNL packet announces {size} bytes, below the 64-byte minimum"
                )
            }
            Self::PacketTooLarge { size, limit } => write!(
                formatter,
                "ADNL packet announces {size} bytes, above the {limit}-byte bound"
            ),
            Self::Checksum => formatter.write_str("ADNL packet checksum mismatch"),
            Self::PayloadTooLarge { length, limit } => write!(
                formatter,
                "a {length}-byte ADNL payload exceeds the {limit}-byte packet bound"
            ),
            Self::Protocol(detail) => write!(formatter, "ADNL protocol violation: {detail}"),
        }
    }
}

impl std::error::Error for AdnlError {}

/// Bounds and sanitizes a server-supplied or I/O detail.
fn bounded(text: &str) -> String {
    crate::http::sanitize_message(text)
}

/// `sha256(TL pub.ed25519 key)`: the ADNL short id of an Ed25519 key.
pub fn key_id(public_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PUB_ED25519.to_le_bytes());
    hasher.update(public_key);
    hasher.finalize().into()
}

/// The X25519 public key of a liteserver's Ed25519 key: its Montgomery
/// u-coordinate. Keys that do not decompress or have small order are refused.
///
/// # Errors
/// [`AdnlError::InvalidServerKey`].
pub fn server_x25519_key(public_key: &[u8; 32]) -> Result<X25519PublicKey, AdnlError> {
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| AdnlError::InvalidServerKey)?;
    if key.is_weak() {
        return Err(AdnlError::InvalidServerKey);
    }
    Ok(X25519PublicKey::from(key.to_montgomery().to_bytes()))
}

/// Fills `buffer` from the operating system random source.
///
/// # Errors
/// [`AdnlError::Randomness`].
pub fn os_random(buffer: &mut [u8]) -> Result<(), AdnlError> {
    OsRng
        .try_fill_bytes(buffer)
        .map_err(|error| AdnlError::Randomness(bounded(&error.to_string())))
}

/// The client's secret handshake inputs: the ephemeral X25519 key and the
/// session parameters. Both are zeroized on drop.
pub struct HandshakeSecrets {
    ephemeral: StaticSecret,
    params: Zeroizing<[u8; HANDSHAKE_PARAMS_LEN]>,
}

impl fmt::Debug for HandshakeSecrets {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HandshakeSecrets { .. }")
    }
}

impl HandshakeSecrets {
    /// Fresh secrets from the operating system random source.
    ///
    /// # Errors
    /// [`AdnlError::Randomness`].
    pub fn random() -> Result<Self, AdnlError> {
        let mut scalar = Zeroizing::new([0_u8; 32]);
        os_random(scalar.as_mut())?;
        let mut params = Zeroizing::new([0_u8; HANDSHAKE_PARAMS_LEN]);
        os_random(params.as_mut())?;
        Ok(Self {
            ephemeral: StaticSecret::from(*scalar),
            params,
        })
    }

    /// Fixed secrets, for test vectors. The scalar is clamped when used.
    pub fn from_parts(ephemeral_scalar: [u8; 32], params: [u8; HANDSHAKE_PARAMS_LEN]) -> Self {
        Self {
            ephemeral: StaticSecret::from(ephemeral_scalar),
            params: Zeroizing::new(params),
        }
    }

    /// The Edwards (Ed25519) encoding of the ephemeral public key, as the
    /// handshake carries it: the clamped scalar times the Ed25519 base point,
    /// whose Montgomery form is the X25519 public key.
    pub fn client_public(&self) -> [u8; 32] {
        let scalar = Zeroizing::new(self.ephemeral.to_bytes());
        EdwardsPoint::mul_base_clamped(*scalar)
            .compress()
            .to_bytes()
    }

    /// `X25519(ephemeral, montgomery(server))`.
    ///
    /// # Errors
    /// If the server key is unusable or the result is all-zero.
    pub fn shared_secret(&self, server_public: &[u8; 32]) -> Result<SharedSecret, AdnlError> {
        let shared = self
            .ephemeral
            .diffie_hellman(&server_x25519_key(server_public)?);
        if !shared.was_contributory() {
            return Err(AdnlError::NonContributory);
        }
        Ok(shared)
    }
}

/// The two AES-256-CTR streams of one ADNL-TCP session.
pub struct SessionCiphers {
    receive: SessionCipher,
    send: SessionCipher,
}

impl fmt::Debug for SessionCiphers {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionCiphers { .. }")
    }
}

impl SessionCiphers {
    /// The client's streams: it receives with `params[0..32]`/`params[64..80]`
    /// and sends with `params[32..64]`/`params[80..96]`.
    pub fn client(params: &[u8; HANDSHAKE_PARAMS_LEN]) -> Self {
        Self {
            receive: stream_cipher(&params[0..32], &params[64..80]),
            send: stream_cipher(&params[32..64], &params[80..96]),
        }
    }

    /// The server's streams (the client's, swapped).
    pub fn server(params: &[u8; HANDSHAKE_PARAMS_LEN]) -> Self {
        Self {
            receive: stream_cipher(&params[32..64], &params[80..96]),
            send: stream_cipher(&params[0..32], &params[64..80]),
        }
    }

    /// Seals `payload` into one encrypted packet with `nonce`.
    ///
    /// # Errors
    /// [`AdnlError::PayloadTooLarge`] if the packet would exceed
    /// `max_packet_bytes` or `u32::MAX`.
    pub fn seal(
        &mut self,
        nonce: &[u8; 32],
        payload: &[u8],
        max_packet_bytes: usize,
    ) -> Result<Vec<u8>, AdnlError> {
        let mut packet = frame_plaintext(nonce, payload, max_packet_bytes)?;
        self.send.apply_keystream(&mut packet);
        Ok(packet)
    }

    /// Reads, decrypts and checks one packet from `reader` and returns its
    /// payload.
    ///
    /// # Errors
    /// I/O errors, an announced size outside `64..=max_packet_bytes`, or a
    /// checksum mismatch.
    pub fn open<R: Read + ?Sized>(
        &mut self,
        reader: &mut R,
        max_packet_bytes: usize,
    ) -> Result<Vec<u8>, AdnlError> {
        let mut size = [0_u8; 4];
        reader
            .read_exact(&mut size)
            .map_err(|error| AdnlError::from_io(&error))?;
        self.receive.apply_keystream(&mut size);
        let size = usize::try_from(u32::from_le_bytes(size)).unwrap_or(usize::MAX);
        if size < PACKET_OVERHEAD {
            return Err(AdnlError::PacketTooShort { size });
        }
        if size > max_packet_bytes {
            return Err(AdnlError::PacketTooLarge {
                size,
                limit: max_packet_bytes,
            });
        }
        let mut body = vec![0_u8; size];
        reader
            .read_exact(&mut body)
            .map_err(|error| AdnlError::from_io(&error))?;
        self.receive.apply_keystream(&mut body);
        let (content, checksum) = body.split_at(size - 32);
        if Sha256::digest(content).as_slice() != checksum {
            return Err(AdnlError::Checksum);
        }
        body.truncate(size - 32);
        body.drain(..32);
        Ok(body)
    }
}

fn stream_cipher(key: &[u8], iv: &[u8]) -> SessionCipher {
    SessionCipher::new(key.into(), iv.into())
}

/// The plaintext packet `size ‖ nonce ‖ payload ‖ sha256(nonce ‖ payload)`.
///
/// # Errors
/// [`AdnlError::PayloadTooLarge`] above `max_packet_bytes` or `u32::MAX`.
pub fn frame_plaintext(
    nonce: &[u8; 32],
    payload: &[u8],
    max_packet_bytes: usize,
) -> Result<Vec<u8>, AdnlError> {
    let size = payload.len().saturating_add(PACKET_OVERHEAD);
    let size_field = u32::try_from(size)
        .ok()
        .filter(|_| size <= max_packet_bytes)
        .ok_or(AdnlError::PayloadTooLarge {
            length: payload.len(),
            limit: max_packet_bytes,
        })?;
    let mut packet = Vec::with_capacity(4 + size);
    packet.extend_from_slice(&size_field.to_le_bytes());
    packet.extend_from_slice(nonce);
    packet.extend_from_slice(payload);
    let checksum = Sha256::digest(&packet[4..]);
    packet.extend_from_slice(&checksum);
    Ok(packet)
}

/// The client handshake packet and the session streams it establishes.
pub struct ClientHandshake {
    /// The 256-byte packet to send first.
    pub packet: [u8; HANDSHAKE_PACKET_LEN],
    /// The client's session streams.
    pub ciphers: SessionCiphers,
}

impl fmt::Debug for ClientHandshake {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientHandshake")
            .field("key_id", &hex::encode(&self.packet[..32]))
            .finish_non_exhaustive()
    }
}

/// Builds the handshake packet for `server_public` from `secrets`.
///
/// # Errors
/// If the server key is unusable or the key agreement is non-contributory.
pub fn client_handshake(
    server_public: &[u8; 32],
    secrets: &HandshakeSecrets,
) -> Result<ClientHandshake, AdnlError> {
    let shared = secrets.shared_secret(server_public)?;
    let shared = shared.as_bytes();
    let params_hash: [u8; 32] = Sha256::digest(secrets.params.as_ref()).into();
    let mut key = Zeroizing::new([0_u8; 32]);
    key[..16].copy_from_slice(&shared[..16]);
    key[16..].copy_from_slice(&params_hash[16..]);
    let mut iv = Zeroizing::new([0_u8; 16]);
    iv[..4].copy_from_slice(&params_hash[..4]);
    iv[4..].copy_from_slice(&shared[20..]);
    let mut packet = [0_u8; HANDSHAKE_PACKET_LEN];
    packet[..32].copy_from_slice(&key_id(server_public));
    packet[32..64].copy_from_slice(&secrets.client_public());
    packet[64..96].copy_from_slice(&params_hash);
    packet[96..].copy_from_slice(secrets.params.as_ref());
    stream_cipher(key.as_ref(), iv.as_ref()).apply_keystream(&mut packet[96..]);
    Ok(ClientHandshake {
        packet,
        ciphers: SessionCiphers::client(&secrets.params),
    })
}

/// An ADNL message received on a client connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdnlMessage {
    /// An empty packet (the handshake confirmation).
    Empty,
    /// `adnl.message.answer`.
    Answer {
        /// The query the answer belongs to.
        query_id: [u8; 32],
        /// The TL answer.
        answer: Vec<u8>,
    },
    /// `tcp.ping` from the server.
    Ping(i64),
    /// `tcp.pong`.
    Pong(i64),
}

impl AdnlMessage {
    /// Classifies a received payload.
    ///
    /// # Errors
    /// [`AdnlError::Protocol`] for anything else or a malformed message.
    pub fn parse(payload: &[u8]) -> Result<Self, AdnlError> {
        if payload.is_empty() {
            return Ok(Self::Empty);
        }
        let malformed = |error: super::tl::TlError| AdnlError::Protocol(error.to_string());
        let mut reader = TlReader::new(payload);
        let message = match reader.u32().map_err(malformed)? {
            ADNL_MESSAGE_ANSWER => {
                let query_id = reader.int256().map_err(malformed)?;
                let answer = reader.bytes_vec().map_err(malformed)?;
                Self::Answer { query_id, answer }
            }
            TCP_PING => Self::Ping(reader.i64().map_err(malformed)?),
            TCP_PONG => Self::Pong(reader.i64().map_err(malformed)?),
            other => {
                return Err(AdnlError::Protocol(format!(
                    "unexpected message constructor {other:#010x}"
                )));
            }
        };
        reader.finish().map_err(malformed)?;
        Ok(message)
    }
}

/// `adnl.message.query query_id query`.
///
/// # Errors
/// If `query` is too long for TL.
pub fn encode_query(query_id: &[u8; 32], query: &[u8]) -> Result<Vec<u8>, AdnlError> {
    let mut writer = TlWriter::boxed(ADNL_MESSAGE_QUERY);
    writer.int256(query_id);
    writer
        .bytes(query)
        .map_err(|error| AdnlError::Protocol(error.to_string()))?;
    Ok(writer.finish())
}

/// `tcp.ping random_id` or `tcp.pong random_id`.
pub fn encode_ping(constructor: u32, random_id: i64) -> Vec<u8> {
    let mut writer = TlWriter::boxed(constructor);
    writer.i64(random_id);
    writer.finish()
}

/// Socket I/O bounded by one deadline: every read and write gets the time
/// left as its timeout.
struct Deadlined<'a> {
    stream: &'a TcpStream,
    deadline: Instant,
}

impl Deadlined<'_> {
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))
    }
}

impl Read for Deadlined<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let left = self.remaining()?;
        self.stream.set_read_timeout(Some(left))?;
        let mut stream = self.stream;
        stream.read(buffer)
    }
}

impl Write for Deadlined<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let left = self.remaining()?;
        self.stream.set_write_timeout(Some(left))?;
        let mut stream = self.stream;
        stream.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut stream = self.stream;
        stream.flush()
    }
}

/// An established ADNL-TCP client session with one liteserver.
///
/// Any error leaves the session unusable (the cipher streams may be out of
/// step); callers drop it and reconnect.
pub struct AdnlConnection {
    stream: TcpStream,
    ciphers: SessionCiphers,
    max_packet_bytes: usize,
    last_used: Instant,
}

impl fmt::Debug for AdnlConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdnlConnection")
            .field("peer", &self.stream.peer_addr().ok())
            .field("max_packet_bytes", &self.max_packet_bytes)
            .finish_non_exhaustive()
    }
}

impl AdnlConnection {
    /// Connects to `address`, performs the handshake for `server_public` with
    /// fresh secrets, and waits for the server's confirmation, all before
    /// `deadline`.
    ///
    /// # Errors
    /// Connection, randomness, key or handshake failures.
    pub fn connect(
        address: SocketAddr,
        server_public: &[u8; 32],
        deadline: Instant,
        max_packet_bytes: usize,
    ) -> Result<Self, AdnlError> {
        let secrets = HandshakeSecrets::random()?;
        Self::connect_with_secrets(address, server_public, &secrets, deadline, max_packet_bytes)
    }

    /// [`Self::connect`] with caller-provided secrets (test vectors).
    ///
    /// # Errors
    /// As [`Self::connect`].
    pub fn connect_with_secrets(
        address: SocketAddr,
        server_public: &[u8; 32],
        secrets: &HandshakeSecrets,
        deadline: Instant,
        max_packet_bytes: usize,
    ) -> Result<Self, AdnlError> {
        let handshake = client_handshake(server_public, secrets)?;
        let left = deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or(AdnlError::Timeout)?;
        let stream = TcpStream::connect_timeout(&address, left)
            .map_err(|error| AdnlError::from_io(&error))?;
        stream
            .set_nodelay(true)
            .map_err(|error| AdnlError::from_io(&error))?;
        let mut connection = Self {
            stream,
            ciphers: handshake.ciphers,
            max_packet_bytes,
            last_used: Instant::now(),
        };
        Deadlined {
            stream: &connection.stream,
            deadline,
        }
        .write_all(&handshake.packet)
        .map_err(|error| AdnlError::from_io(&error))?;
        match connection.receive(deadline)? {
            AdnlMessage::Empty => Ok(connection),
            other => Err(AdnlError::Protocol(format!(
                "expected the empty handshake confirmation, got {}",
                message_name(&other)
            ))),
        }
    }

    /// Time since the last completed exchange.
    pub fn idle_for(&self) -> Duration {
        self.last_used.elapsed()
    }

    /// The bound on one packet.
    pub fn max_packet_bytes(&self) -> usize {
        self.max_packet_bytes
    }

    /// Sends one payload with a random nonce.
    ///
    /// # Errors
    /// I/O errors, the deadline, or an oversized payload.
    pub fn send(&mut self, payload: &[u8], deadline: Instant) -> Result<(), AdnlError> {
        let mut nonce = [0_u8; 32];
        rand::rng().fill_bytes(&mut nonce);
        let packet = self.ciphers.seal(&nonce, payload, self.max_packet_bytes)?;
        Deadlined {
            stream: &self.stream,
            deadline,
        }
        .write_all(&packet)
        .map_err(|error| AdnlError::from_io(&error))
    }

    /// Receives and classifies one message.
    ///
    /// # Errors
    /// I/O errors, the deadline, framing errors or an unknown message.
    pub fn receive(&mut self, deadline: Instant) -> Result<AdnlMessage, AdnlError> {
        self.receive_within(deadline, self.max_packet_bytes)
    }

    /// Receives one message from a packet of at most `max_packet_bytes`.
    fn receive_within(
        &mut self,
        deadline: Instant,
        max_packet_bytes: usize,
    ) -> Result<AdnlMessage, AdnlError> {
        let payload = self.ciphers.open(
            &mut Deadlined {
                stream: &self.stream,
                deadline,
            },
            max_packet_bytes,
        )?;
        AdnlMessage::parse(&payload)
    }

    /// Sends `query` as `adnl.message.query` with a random query id and
    /// returns the TL answer. Pongs and empty packets in between are skipped
    /// and server pings are answered.
    ///
    /// # Errors
    /// I/O errors, the deadline, framing errors, or an answer to another query.
    pub fn query(&mut self, query: &[u8], deadline: Instant) -> Result<Vec<u8>, AdnlError> {
        self.query_bounded(query, deadline, self.max_packet_bytes)
    }

    /// [`Self::query`] whose answer may be at most `max_answer_bytes` (and
    /// within the session's packet bound): a packet announcing more is
    /// refused before it is read, with [`AdnlError::PacketTooLarge`].
    ///
    /// # Errors
    /// As [`Self::query`].
    pub fn query_bounded(
        &mut self,
        query: &[u8],
        deadline: Instant,
        max_answer_bytes: usize,
    ) -> Result<Vec<u8>, AdnlError> {
        let bound = answer_packet_bytes(max_answer_bytes).min(self.max_packet_bytes);
        let mut query_id = [0_u8; 32];
        rand::rng().fill_bytes(&mut query_id);
        self.send(&encode_query(&query_id, query)?, deadline)?;
        loop {
            match self.receive_within(deadline, bound)? {
                AdnlMessage::Answer {
                    query_id: answered,
                    answer,
                } => {
                    if answered != query_id {
                        return Err(AdnlError::Protocol(
                            "answer to a query that is not pending".to_owned(),
                        ));
                    }
                    self.last_used = Instant::now();
                    return Ok(answer);
                }
                AdnlMessage::Ping(random_id) => {
                    self.send(&encode_ping(TCP_PONG, random_id), deadline)?;
                }
                AdnlMessage::Pong(_) | AdnlMessage::Empty => {}
            }
        }
    }

    /// Sends `tcp.ping` and waits for the matching `tcp.pong`.
    ///
    /// # Errors
    /// I/O errors, the deadline, framing errors, or an unexpected answer.
    pub fn ping(&mut self, deadline: Instant) -> Result<(), AdnlError> {
        let random_id = rand::rng().next_u64().cast_signed();
        self.send(&encode_ping(TCP_PING, random_id), deadline)?;
        loop {
            match self.receive(deadline)? {
                AdnlMessage::Pong(answered) if answered == random_id => {
                    self.last_used = Instant::now();
                    return Ok(());
                }
                AdnlMessage::Pong(_) | AdnlMessage::Empty => {}
                AdnlMessage::Ping(other) => {
                    self.send(&encode_ping(TCP_PONG, other), deadline)?;
                }
                AdnlMessage::Answer { .. } => {
                    return Err(AdnlError::Protocol(
                        "answer to a query that is not pending".to_owned(),
                    ));
                }
            }
        }
    }
}

fn message_name(message: &AdnlMessage) -> &'static str {
    match message {
        AdnlMessage::Empty => "an empty packet",
        AdnlMessage::Answer { .. } => "adnl.message.answer",
        AdnlMessage::Ping(_) => "tcp.ping",
        AdnlMessage::Pong(_) => "tcp.pong",
    }
}

#[cfg(test)]
mod tests {
    use std::{io::Cursor, net::TcpListener, thread};

    use curve25519_dalek::{MontgomeryPoint, edwards::CompressedEdwardsY};

    use super::*;
    use crate::ton::tl::constructor_id;

    fn sha(label: &str) -> [u8; 32] {
        Sha256::digest(label.as_bytes()).into()
    }

    fn params(label: &str) -> [u8; HANDSHAKE_PARAMS_LEN] {
        let mut out = [0_u8; HANDSHAKE_PARAMS_LEN];
        for (index, chunk) in out.chunks_mut(32).enumerate() {
            chunk.copy_from_slice(&sha(&format!("{label} {index}")));
        }
        out
    }

    fn server_key(label: &str) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&sha(label))
    }

    /// The server side of the key agreement, from the Ed25519 private scalar.
    fn server_shared(server: &ed25519_dalek::SigningKey, client_public: &[u8; 32]) -> [u8; 32] {
        let client = CompressedEdwardsY(*client_public)
            .decompress()
            .expect("client point")
            .to_montgomery();
        client.mul_clamped(server.to_scalar_bytes()).to_bytes()
    }

    #[test]
    fn constructor_ids_match_their_schema_lines() {
        assert_eq!(
            constructor_id("pub.ed25519 key:int256 = PublicKey"),
            PUB_ED25519
        );
        assert_eq!(
            constructor_id("adnl.message.query query_id:int256 query:bytes = adnl.Message"),
            ADNL_MESSAGE_QUERY
        );
        assert_eq!(
            constructor_id("adnl.message.answer query_id:int256 answer:bytes = adnl.Message"),
            ADNL_MESSAGE_ANSWER
        );
        assert_eq!(
            constructor_id("tcp.ping random_id:long = tcp.Pong"),
            TCP_PING
        );
        assert_eq!(
            constructor_id("tcp.pong random_id:long = tcp.Pong"),
            TCP_PONG
        );
    }

    #[test]
    fn key_id_hashes_the_boxed_public_key() {
        let key = [9_u8; 32];
        let mut preimage = PUB_ED25519.to_le_bytes().to_vec();
        preimage.extend_from_slice(&key);
        assert_eq!(
            key_id(&key).as_slice(),
            Sha256::digest(&preimage).as_slice()
        );
    }

    #[test]
    fn server_keys_must_be_usable_points() {
        let server = server_key("server");
        assert!(server_x25519_key(&server.verifying_key().to_bytes()).is_ok());
        // The identity and other small-order points are refused.
        let mut identity = [0_u8; 32];
        identity[0] = 1;
        assert!(matches!(
            server_x25519_key(&identity),
            Err(AdnlError::InvalidServerKey)
        ));
        // A y-coordinate without a curve point.
        let invalid = (2_u8..=255)
            .map(|y| {
                let mut bytes = [0_u8; 32];
                bytes[0] = y;
                bytes
            })
            .find(|bytes| CompressedEdwardsY(*bytes).decompress().is_none())
            .expect("some small y is not on the curve");
        assert!(matches!(
            server_x25519_key(&invalid),
            Err(AdnlError::InvalidServerKey)
        ));
        let secrets = HandshakeSecrets::from_parts([1; 32], [2; HANDSHAKE_PARAMS_LEN]);
        assert!(client_handshake(&identity, &secrets).is_err());
    }

    #[test]
    fn both_sides_derive_the_same_secret() {
        let server = server_key("server");
        let secrets = HandshakeSecrets::from_parts(sha("client"), params("params"));
        let client_public = secrets.client_public();
        let shared = secrets
            .shared_secret(&server.verifying_key().to_bytes())
            .expect("shared");
        assert_eq!(*shared.as_bytes(), server_shared(&server, &client_public));
        // The Edwards key sent is the Montgomery key of the same scalar.
        let montgomery = CompressedEdwardsY(client_public)
            .decompress()
            .expect("point")
            .to_montgomery();
        assert_eq!(montgomery, MontgomeryPoint::mul_base_clamped(sha("client")));
        assert!(format!("{secrets:?}").contains(".."));
    }

    #[test]
    fn handshake_packet_layout_and_decryption() {
        let server = server_key("server");
        let server_public = server.verifying_key().to_bytes();
        let session_params = params("params");
        let secrets = HandshakeSecrets::from_parts(sha("client"), session_params);
        let handshake = client_handshake(&server_public, &secrets).expect("handshake");
        let packet = handshake.packet;
        assert_eq!(&packet[..32], &key_id(&server_public));
        assert_eq!(&packet[32..64], &secrets.client_public());
        let params_hash: [u8; 32] = Sha256::digest(session_params).into();
        assert_eq!(&packet[64..96], &params_hash);
        // The server decrypts the parameters with the key and IV it derives.
        let shared = server_shared(&server, &secrets.client_public());
        let mut key = [0_u8; 32];
        key[..16].copy_from_slice(&shared[..16]);
        key[16..].copy_from_slice(&params_hash[16..]);
        let mut iv = [0_u8; 16];
        iv[..4].copy_from_slice(&params_hash[..4]);
        iv[4..].copy_from_slice(&shared[20..]);
        let mut decrypted = packet[96..].to_vec();
        stream_cipher(&key, &iv).apply_keystream(&mut decrypted);
        assert_eq!(decrypted, session_params);
        assert!(format!("{handshake:?}").contains("key_id"));
    }

    #[test]
    fn packets_round_trip_between_client_and_server_streams() {
        let session_params = params("session");
        let mut client = SessionCiphers::client(&session_params);
        let mut server = SessionCiphers::server(&session_params);
        for payload in [&b""[..], b"hello", &[0xAB; 1000]] {
            let sealed = client
                .seal(&sha("nonce"), payload, DEFAULT_MAX_PACKET_BYTES)
                .expect("seal");
            assert_eq!(sealed.len(), 4 + PACKET_OVERHEAD + payload.len());
            let opened = server
                .open(&mut Cursor::new(sealed), DEFAULT_MAX_PACKET_BYTES)
                .expect("open");
            assert_eq!(opened, payload);
            let reply = server
                .seal(&sha("reply"), payload, DEFAULT_MAX_PACKET_BYTES)
                .expect("seal");
            assert_eq!(
                client
                    .open(&mut Cursor::new(reply), DEFAULT_MAX_PACKET_BYTES)
                    .expect("open"),
                payload
            );
        }
        assert!(format!("{client:?}").contains(".."));
    }

    #[test]
    fn answer_packet_bounds_cover_the_answer_envelope() {
        for length in [0, 1, 3, 4, 253, 254, 255, 1_000, 70_000] {
            let answer = vec![7_u8; length];
            let mut writer = TlWriter::boxed(ADNL_MESSAGE_ANSWER);
            writer
                .int256(&[1; 32])
                .bytes(&answer)
                .expect("answer bytes");
            let frame = frame_plaintext(&[2; 32], &writer.finish(), usize::MAX).expect("frame");
            let size = frame.len() - 4;
            assert!(size <= answer_packet_bytes(length), "{length}: {size}");
            assert!(
                size + 7 >= answer_packet_bytes(length),
                "{length}: the bound is tight"
            );
        }
        assert_eq!(answer_packet_bytes(usize::MAX), usize::MAX);
    }

    #[test]
    fn plaintext_frames_carry_size_nonce_and_checksum() {
        let nonce = sha("nonce");
        let frame = frame_plaintext(&nonce, b"abc", DEFAULT_MAX_PACKET_BYTES).expect("frame");
        assert_eq!(&frame[..4], &67_u32.to_le_bytes());
        assert_eq!(&frame[4..36], &nonce);
        assert_eq!(&frame[36..39], b"abc");
        assert_eq!(&frame[39..], Sha256::digest(&frame[4..39]).as_slice());
        assert_eq!(
            frame_plaintext(&nonce, &[0; 10], 70),
            Err(AdnlError::PayloadTooLarge {
                length: 10,
                limit: 70
            })
        );
    }

    #[test]
    fn corrupted_packets_are_rejected() {
        let session_params = params("session");
        let open = |bytes: Vec<u8>, limit: usize| {
            SessionCiphers::server(&session_params).open(&mut Cursor::new(bytes), limit)
        };
        let sealed = SessionCiphers::client(&session_params)
            .seal(&sha("nonce"), b"payload", DEFAULT_MAX_PACKET_BYTES)
            .expect("seal");
        // A flipped payload or checksum bit fails the checksum.
        for position in [4, 40, sealed.len() - 1] {
            let mut corrupted = sealed.clone();
            corrupted[position] ^= 0x01;
            assert_eq!(
                open(corrupted, DEFAULT_MAX_PACKET_BYTES),
                Err(AdnlError::Checksum),
                "{position}"
            );
        }
        // Size fields outside the bounds are refused before reading the body.
        let mut too_short = sealed.clone();
        too_short[0] ^= 0x47 ^ 0x3F; // 71 becomes 63
        assert_eq!(
            open(too_short, DEFAULT_MAX_PACKET_BYTES),
            Err(AdnlError::PacketTooShort { size: 63 })
        );
        assert_eq!(
            open(sealed.clone(), 70),
            Err(AdnlError::PacketTooLarge {
                size: 71,
                limit: 70
            })
        );
        // A truncated packet is a closed connection.
        assert_eq!(
            open(
                sealed[..sealed.len() - 1].to_vec(),
                DEFAULT_MAX_PACKET_BYTES
            ),
            Err(AdnlError::Closed)
        );
        assert_eq!(
            open(Vec::new(), DEFAULT_MAX_PACKET_BYTES),
            Err(AdnlError::Closed)
        );
    }

    #[test]
    fn messages_are_classified() {
        assert_eq!(AdnlMessage::parse(&[]), Ok(AdnlMessage::Empty));
        assert_eq!(
            AdnlMessage::parse(&encode_ping(TCP_PING, -5)),
            Ok(AdnlMessage::Ping(-5))
        );
        assert_eq!(
            AdnlMessage::parse(&encode_ping(TCP_PONG, 7)),
            Ok(AdnlMessage::Pong(7))
        );
        let mut answer = TlWriter::boxed(ADNL_MESSAGE_ANSWER);
        answer.int256(&[3; 32]).bytes(b"tl").expect("bytes");
        assert_eq!(
            AdnlMessage::parse(&answer.finish()),
            Ok(AdnlMessage::Answer {
                query_id: [3; 32],
                answer: b"tl".to_vec()
            })
        );
        let query = encode_query(&[4; 32], b"q").expect("query");
        assert!(matches!(
            AdnlMessage::parse(&query),
            Err(AdnlError::Protocol(_))
        ));
        let mut trailing = encode_ping(TCP_PONG, 1);
        trailing.push(0);
        assert!(AdnlMessage::parse(&trailing).is_err());
        assert!(AdnlMessage::parse(&[1, 2]).is_err());
        for message in [
            AdnlMessage::Empty,
            AdnlMessage::Ping(1),
            AdnlMessage::Pong(1),
            AdnlMessage::Answer {
                query_id: [0; 32],
                answer: Vec::new(),
            },
        ] {
            assert!(!message_name(&message).is_empty());
        }
    }

    #[test]
    fn io_errors_map_to_timeouts_and_closure() {
        assert_eq!(
            AdnlError::from_io(&io::Error::from(io::ErrorKind::WouldBlock)),
            AdnlError::Timeout
        );
        assert_eq!(
            AdnlError::from_io(&io::Error::from(io::ErrorKind::TimedOut)),
            AdnlError::Timeout
        );
        assert_eq!(
            AdnlError::from_io(&io::Error::from(io::ErrorKind::UnexpectedEof)),
            AdnlError::Closed
        );
        let error = AdnlError::from_io(&io::Error::new(
            io::ErrorKind::ConnectionReset,
            "x".repeat(1_000),
        ));
        let AdnlError::Io { kind, detail } = &error else {
            panic!("unexpected {error:?}");
        };
        assert_eq!(*kind, io::ErrorKind::ConnectionReset);
        assert!(detail.chars().count() <= 257);
        for error in [
            AdnlError::InvalidServerKey,
            AdnlError::NonContributory,
            AdnlError::Randomness("x".to_owned()),
            error,
            AdnlError::Timeout,
            AdnlError::Closed,
            AdnlError::PacketTooShort { size: 1 },
            AdnlError::PacketTooLarge { size: 2, limit: 1 },
            AdnlError::Checksum,
            AdnlError::PayloadTooLarge {
                length: 1,
                limit: 1,
            },
            AdnlError::Protocol("x".to_owned()),
        ] {
            assert!(!error.to_string().is_empty());
        }
    }

    #[test]
    fn os_randomness_fills_buffers() {
        let mut first = [0_u8; 32];
        let mut second = [0_u8; 32];
        os_random(&mut first).expect("random");
        os_random(&mut second).expect("random");
        assert_ne!(first, second);
        let secrets = HandshakeSecrets::random().expect("secrets");
        assert_ne!(secrets.client_public(), [0; 32]);
    }

    #[test]
    fn session_state_is_zeroized_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        // The x25519 secrets derive `Zeroize` with `zeroize(drop)`: dropping
        // them wipes the scalar and the shared secret.
        fn assert_zeroize_with_drop<T: zeroize::Zeroize>() {
            assert!(std::mem::needs_drop::<T>());
        }
        assert_zeroize_on_drop::<SessionCipher>();
        assert_zeroize_with_drop::<StaticSecret>();
        assert_zeroize_with_drop::<SharedSecret>();
        assert_zeroize_on_drop::<Zeroizing<[u8; HANDSHAKE_PARAMS_LEN]>>();
    }

    /// Accepts one connection, answers the handshake, then echoes one query
    /// and one ping.
    fn one_shot_server(
        listener: TcpListener,
        server: ed25519_dalek::SigningKey,
        confirm: bool,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut handshake = [0_u8; HANDSHAKE_PACKET_LEN];
            stream.read_exact(&mut handshake).expect("handshake");
            assert_eq!(
                &handshake[..32],
                &key_id(&server.verifying_key().to_bytes())
            );
            let client_public: [u8; 32] = handshake[32..64].try_into().expect("key");
            let shared = server_shared(&server, &client_public);
            let mut key = [0_u8; 32];
            key[..16].copy_from_slice(&shared[..16]);
            key[16..].copy_from_slice(&handshake[80..96]);
            let mut iv = [0_u8; 16];
            iv[..4].copy_from_slice(&handshake[64..68]);
            iv[4..].copy_from_slice(&shared[20..]);
            let mut session_params = [0_u8; HANDSHAKE_PARAMS_LEN];
            session_params.copy_from_slice(&handshake[96..]);
            stream_cipher(&key, &iv).apply_keystream(&mut session_params);
            let mut ciphers = SessionCiphers::server(&session_params);
            if !confirm {
                let pong = ciphers
                    .seal(
                        &[0; 32],
                        &encode_ping(TCP_PONG, 1),
                        DEFAULT_MAX_PACKET_BYTES,
                    )
                    .expect("seal");
                stream.write_all(&pong).expect("write");
                return;
            }
            let empty = ciphers
                .seal(&[1; 32], &[], DEFAULT_MAX_PACKET_BYTES)
                .expect("seal");
            stream.write_all(&empty).expect("write");
            // A query: first ping the client, then answer.
            let query = ciphers
                .open(&mut stream, DEFAULT_MAX_PACKET_BYTES)
                .expect("query");
            let mut reader = TlReader::new(&query);
            reader
                .expect_constructor(ADNL_MESSAGE_QUERY, "query")
                .expect("query");
            let query_id = reader.int256().expect("id");
            let body = reader.bytes_vec().expect("body");
            let ping = ciphers
                .seal(
                    &[2; 32],
                    &encode_ping(TCP_PING, 99),
                    DEFAULT_MAX_PACKET_BYTES,
                )
                .expect("seal");
            stream.write_all(&ping).expect("write");
            let client_reply = ciphers
                .open(&mut stream, DEFAULT_MAX_PACKET_BYTES)
                .expect("pong");
            assert_eq!(client_reply, encode_ping(TCP_PONG, 99));
            let mut answer = TlWriter::boxed(ADNL_MESSAGE_ANSWER);
            answer.int256(&query_id).bytes(&body).expect("bytes");
            let answer = ciphers
                .seal(&[3; 32], &answer.finish(), DEFAULT_MAX_PACKET_BYTES)
                .expect("seal");
            stream.write_all(&answer).expect("write");
            // A probe from the client.
            let probe = ciphers
                .open(&mut stream, DEFAULT_MAX_PACKET_BYTES)
                .expect("ping");
            let AdnlMessage::Ping(random_id) = AdnlMessage::parse(&probe).expect("parse") else {
                panic!("expected a ping");
            };
            let reply = ciphers
                .seal(
                    &[4; 32],
                    &encode_ping(TCP_PONG, random_id),
                    DEFAULT_MAX_PACKET_BYTES,
                )
                .expect("seal");
            stream.write_all(&reply).expect("write");
            // Then stay silent until the client gives up.
            let mut rest = Vec::new();
            let _ = stream.read_to_end(&mut rest);
        })
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(10)
    }

    #[test]
    fn connection_queries_pings_and_times_out() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        let server = server_key("loopback server");
        let public = server.verifying_key().to_bytes();
        let handle = one_shot_server(listener, server, true);
        let mut connection =
            AdnlConnection::connect(address, &public, deadline(), DEFAULT_MAX_PACKET_BYTES)
                .expect("connect");
        assert_eq!(connection.max_packet_bytes(), DEFAULT_MAX_PACKET_BYTES);
        assert!(format!("{connection:?}").contains("AdnlConnection"));
        let answer = connection.query(b"echo me", deadline()).expect("answer");
        assert_eq!(answer, b"echo me");
        assert!(connection.idle_for() < Duration::from_secs(10));
        connection.ping(deadline()).expect("pong");
        let error = connection
            .receive(Instant::now() + Duration::from_millis(50))
            .expect_err("silent server");
        assert_eq!(error, AdnlError::Timeout);
        drop(connection);
        handle.join().expect("server");
    }

    #[test]
    fn handshake_requires_the_empty_confirmation() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        let server = server_key("unconfirmed server");
        let public = server.verifying_key().to_bytes();
        let handle = one_shot_server(listener, server, false);
        let error = AdnlConnection::connect(address, &public, deadline(), DEFAULT_MAX_PACKET_BYTES)
            .expect_err("no confirmation");
        assert!(matches!(error, AdnlError::Protocol(_)), "{error:?}");
        handle.join().expect("server");
        let past = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .expect("past");
        assert_eq!(
            AdnlConnection::connect(address, &public, past, DEFAULT_MAX_PACKET_BYTES)
                .expect_err("deadline"),
            AdnlError::Timeout
        );
    }
}
