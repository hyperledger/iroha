//! Animated QR stream framing for offline payload handoff.
//!
//! The QR stream protocol splits a binary payload into fixed-size chunks, adds optional XOR parity
//! frames, and wraps each chunk in a CRC32-protected frame. The format matches the existing
//! Swift/Android/JS SDK implementations to ensure cross-platform parity for the first release.
use blake2::{
    Blake2bVar,
    digest::{Update, VariableOutput},
};
use std::time::{Duration, Instant};
use thiserror::Error;
/// Magic bytes that start every QR stream frame (`IQ`).
pub const QR_STREAM_MAGIC: [u8; 2] = [0x49, 0x51];
/// Binary encoding flag for payloads.
pub const QR_STREAM_ENCODING_BINARY: u8 = 0;
/// Default chunk size (bytes).
pub const QR_STREAM_DEFAULT_CHUNK_SIZE: u16 = 360;
/// Default parity group size (0 disables parity).
pub const QR_STREAM_DEFAULT_PARITY_GROUP: u8 = 0;
/// Maximum chunk size accepted by the assembler.
pub const QR_STREAM_MAX_CHUNK_SIZE: u16 = 1024;
/// Maximum payload size accepted by the assembler.
pub const QR_STREAM_MAX_PAYLOAD_BYTES: u32 = 2 * 1024 * 1024;
/// Maximum frame count accepted by the assembler.
pub const QR_STREAM_MAX_FRAMES: u16 = 8192;
/// Default timeout for assembling frames (milliseconds).
pub const QR_STREAM_DEFAULT_TIMEOUT_MS: u64 = 120_000;
/// QR stream frame kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QrStreamFrameKind {
    /// Envelope header frame.
    Header = 0,
    /// Data frame carrying a payload chunk.
    Data = 1,
    /// Parity frame carrying XOR parity for a chunk group.
    Parity = 2,
}
impl QrStreamFrameKind {
    fn from_u8(value: u8) -> Result<Self, QrStreamError> {
        match value {
            0 => Ok(Self::Header),
            1 => Ok(Self::Data),
            2 => Ok(Self::Parity),
            _ => Err(QrStreamError::InvalidEnvelope("unknown frame kind")),
        }
    }
}
/// Payload kind tags embedded in the QR stream `IQ` envelope.
///
/// No typed payload family is assigned yet; every `u16` tag reads back as
/// [`QrPayloadKind::Unspecified`] and encoders emit tag `0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum QrPayloadKind {
    /// No specific payload kind.
    Unspecified = 0,
}
impl QrPayloadKind {
    fn from_u16(_value: u16) -> Self {
        Self::Unspecified
    }
}
/// Encoder options controlling chunking and parity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QrStreamOptions {
    /// Chunk size in bytes.
    pub chunk_size: u16,
    /// Parity group size (0 disables parity frames).
    pub parity_group: u8,
    /// Payload kind tag.
    pub payload_kind: QrPayloadKind,
    /// Envelope flags (reserved for future use).
    pub flags: u8,
    /// Encoding marker (binary by default).
    pub encoding: u8,
}
impl Default for QrStreamOptions {
    fn default() -> Self {
        Self {
            chunk_size: QR_STREAM_DEFAULT_CHUNK_SIZE,
            parity_group: QR_STREAM_DEFAULT_PARITY_GROUP,
            payload_kind: QrPayloadKind::Unspecified,
            flags: 0,
            encoding: QR_STREAM_ENCODING_BINARY,
        }
    }
}
/// Limits applied by the frame assembler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QrStreamAssemblerLimits {
    /// Maximum payload size in bytes.
    pub max_payload_bytes: u32,
    /// Maximum total frame count (header + data + parity).
    pub max_frames: u16,
    /// Maximum chunk size in bytes.
    pub max_chunk_bytes: u16,
    /// Timeout window for assembly since first frame.
    pub timeout: Duration,
}
impl Default for QrStreamAssemblerLimits {
    fn default() -> Self {
        Self {
            max_payload_bytes: QR_STREAM_MAX_PAYLOAD_BYTES,
            max_frames: QR_STREAM_MAX_FRAMES,
            max_chunk_bytes: QR_STREAM_MAX_CHUNK_SIZE,
            timeout: Duration::from_millis(QR_STREAM_DEFAULT_TIMEOUT_MS),
        }
    }
}
/// Errors raised while encoding or decoding QR stream frames.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum QrStreamError {
    /// Frame magic bytes did not match.
    #[error("qr stream magic mismatch")]
    InvalidMagic,
    /// Payload or frame length is invalid.
    #[error("invalid qr stream length for {0}")]
    InvalidLength(&'static str),
    /// CRC32 checksum did not match.
    #[error("qr stream frame checksum mismatch")]
    ChecksumMismatch,
    /// Envelope fields are invalid.
    #[error("qr stream envelope invalid: {0}")]
    InvalidEnvelope(&'static str),
    /// Stream id does not match the envelope.
    #[error("qr stream id mismatch")]
    InvalidStreamId,
    /// Assembler limits were exceeded.
    #[error("qr stream exceeds limits: {0}")]
    LimitExceeded(&'static str),
    /// Assembler timed out waiting for frames.
    #[error("qr stream assembly timed out")]
    TimedOut,
}
/// Envelope describing the payload layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QrStreamEnvelope {
    /// Envelope flags (reserved for future use).
    pub flags: u8,
    /// Encoding marker (binary by default).
    pub encoding: u8,
    /// Parity group size (0 disables parity).
    pub parity_group: u8,
    /// Chunk size in bytes.
    pub chunk_size: u16,
    /// Number of data chunks.
    pub data_chunks: u16,
    /// Number of parity chunks.
    pub parity_chunks: u16,
    /// Payload kind tag.
    pub payload_kind: u16,
    /// Total payload length in bytes.
    pub payload_length: u32,
    /// BLAKE2b-256 hash of the payload bytes.
    pub payload_hash: [u8; 32],
}
impl QrStreamEnvelope {
    /// Construct a new envelope and validate the payload hash length.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        flags: u8,
        encoding: u8,
        parity_group: u8,
        chunk_size: u16,
        data_chunks: u16,
        parity_chunks: u16,
        payload_kind: u16,
        payload_length: u32,
        payload_hash: [u8; 32],
    ) -> Self {
        Self {
            flags,
            encoding,
            parity_group,
            chunk_size,
            data_chunks,
            parity_chunks,
            payload_kind,
            payload_length,
            payload_hash,
        }
    }
    /// Derive the stream id from the payload hash.
    #[must_use]
    pub fn stream_id(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out.copy_from_slice(&self.payload_hash[..16]);
        out
    }
    /// Interpret the payload kind tag as a typed enum.
    #[must_use]
    pub fn payload_kind_tag(&self) -> QrPayloadKind {
        QrPayloadKind::from_u16(self.payload_kind)
    }
    /// Encode the envelope into canonical bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(47);
        out.push(self.flags);
        out.push(self.encoding);
        out.push(self.parity_group);
        out.extend_from_slice(&self.chunk_size.to_le_bytes());
        out.extend_from_slice(&self.data_chunks.to_le_bytes());
        out.extend_from_slice(&self.parity_chunks.to_le_bytes());
        out.extend_from_slice(&self.payload_kind.to_le_bytes());
        out.extend_from_slice(&self.payload_length.to_le_bytes());
        out.extend_from_slice(&self.payload_hash);
        out
    }
    /// Decode envelope bytes.
    ///
    /// # Errors
    /// Returns an error when the envelope is truncated.
    pub fn decode(bytes: &[u8]) -> Result<Self, QrStreamError> {
        let min_len = 1 + 1 + 1 + 2 + 2 + 2 + 2 + 4 + 32;
        if bytes.len() < min_len {
            return Err(QrStreamError::InvalidLength("envelope"));
        }
        let mut offset = 0;
        let flags = bytes[offset];
        offset += 1;
        let encoding = bytes[offset];
        offset += 1;
        let parity_group = bytes[offset];
        offset += 1;
        let chunk_size = read_u16_le(bytes, offset)?;
        offset += 2;
        let data_chunks = read_u16_le(bytes, offset)?;
        offset += 2;
        let parity_chunks = read_u16_le(bytes, offset)?;
        offset += 2;
        let payload_kind = read_u16_le(bytes, offset)?;
        offset += 2;
        let payload_length = read_u32_le(bytes, offset)?;
        offset += 4;
        let end = offset + 32;
        if bytes.len() < end {
            return Err(QrStreamError::InvalidLength("payload_hash"));
        }
        let mut payload_hash = [0u8; 32];
        payload_hash.copy_from_slice(&bytes[offset..end]);
        Ok(Self {
            flags,
            encoding,
            parity_group,
            chunk_size,
            data_chunks,
            parity_chunks,
            payload_kind,
            payload_length,
            payload_hash,
        })
    }
}
/// A single QR stream frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QrStreamFrame {
    /// Frame kind (header/data/parity).
    pub kind: QrStreamFrameKind,
    /// Stream identifier derived from the payload hash.
    pub stream_id: [u8; 16],
    /// Zero-based chunk index.
    pub index: u16,
    /// Total frames of this kind.
    pub total: u16,
    /// Frame payload bytes.
    pub payload: Vec<u8>,
}
impl QrStreamFrame {
    /// Encode a frame to bytes with CRC32.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let payload_len =
            u16::try_from(self.payload.len()).expect("qr stream payload length fits u16");
        let mut out = Vec::with_capacity(2 + 1 + 16 + 2 + 2 + 2 + self.payload.len() + 4);
        out.extend_from_slice(&QR_STREAM_MAGIC);
        out.push(self.kind as u8);
        out.extend_from_slice(&self.stream_id);
        out.extend_from_slice(&self.index.to_le_bytes());
        out.extend_from_slice(&self.total.to_le_bytes());
        out.extend_from_slice(&payload_len.to_le_bytes());
        out.extend_from_slice(&self.payload);
        let crc = crc32(&out[2..]);
        out.extend_from_slice(&crc.to_le_bytes());
        out
    }
    /// Decode a frame from bytes.
    ///
    /// # Errors
    /// Returns an error when frame headers are malformed, payload boundaries
    /// are invalid, or CRC validation fails.
    pub fn decode(bytes: &[u8]) -> Result<Self, QrStreamError> {
        let header_len = 2 + 1 + 16 + 2 + 2 + 2;
        if bytes.len() < header_len + 4 {
            return Err(QrStreamError::InvalidLength("frame"));
        }
        if bytes[0] != QR_STREAM_MAGIC[0] || bytes[1] != QR_STREAM_MAGIC[1] {
            return Err(QrStreamError::InvalidMagic);
        }
        let kind = QrStreamFrameKind::from_u8(bytes[2])?;
        let mut stream_id = [0u8; 16];
        stream_id.copy_from_slice(&bytes[3..19]);
        let index = read_u16_le(bytes, 19)?;
        let total = read_u16_le(bytes, 21)?;
        let payload_len = read_u16_le(bytes, 23)? as usize;
        let payload_start = 25;
        let payload_end = payload_start + payload_len;
        if payload_end + 4 > bytes.len() {
            return Err(QrStreamError::InvalidLength("payload"));
        }
        let payload = bytes[payload_start..payload_end].to_vec();
        let expected_crc = read_u32_le(bytes, payload_end)?;
        let computed_crc = crc32(&bytes[2..payload_end]);
        if expected_crc != computed_crc {
            return Err(QrStreamError::ChecksumMismatch);
        }
        Ok(Self {
            kind,
            stream_id,
            index,
            total,
            payload,
        })
    }
}
/// Encoder for QR stream frames.
#[derive(Debug, Clone, Copy)]
pub struct QrStreamEncoder;
impl QrStreamEncoder {
    /// Encode a payload into a list of frames.
    ///
    /// # Errors
    /// Returns an error when payload/options exceed format limits.
    pub fn encode_frames(
        payload: &[u8],
        options: QrStreamOptions,
    ) -> Result<(QrStreamEnvelope, Vec<QrStreamFrame>), QrStreamError> {
        let payload_len_u32 = u32::try_from(payload.len())
            .map_err(|_| QrStreamError::InvalidEnvelope("payload_length"))?;
        if options.chunk_size == 0 {
            return Err(QrStreamError::InvalidEnvelope("chunk_size"));
        }
        let data_chunks_raw = payload_len_u32.div_ceil(u32::from(options.chunk_size));
        if data_chunks_raw > u32::from(u16::MAX) {
            return Err(QrStreamError::InvalidEnvelope("data_chunks"));
        }
        let data_chunks = u16::try_from(data_chunks_raw)
            .map_err(|_| QrStreamError::InvalidEnvelope("data_chunks"))?;
        let parity_group = u32::from(options.parity_group);
        let parity_chunks_raw = if parity_group > 0 {
            u32::from(data_chunks).div_ceil(parity_group)
        } else {
            0
        };
        if parity_chunks_raw > u32::from(u16::MAX) {
            return Err(QrStreamError::InvalidEnvelope("parity_chunks"));
        }
        let parity_chunks = u16::try_from(parity_chunks_raw)
            .map_err(|_| QrStreamError::InvalidEnvelope("parity_chunks"))?;
        let payload_hash = blake2b256(payload);
        let envelope = QrStreamEnvelope::new(
            options.flags,
            options.encoding,
            options.parity_group,
            options.chunk_size,
            data_chunks,
            parity_chunks,
            options.payload_kind as u16,
            payload_len_u32,
            payload_hash,
        );
        let mut frames = Vec::with_capacity(1 + data_chunks as usize + parity_chunks as usize);
        let header = QrStreamFrame {
            kind: QrStreamFrameKind::Header,
            stream_id: envelope.stream_id(),
            index: 0,
            total: 1,
            payload: envelope.encode(),
        };
        frames.push(header);
        let chunk_size = options.chunk_size as usize;
        for idx in 0..data_chunks as usize {
            let start = idx * chunk_size;
            let end = payload.len().min(start + chunk_size);
            let chunk = payload[start..end].to_vec();
            let frame_index =
                u16::try_from(idx).map_err(|_| QrStreamError::InvalidEnvelope("data_chunks"))?;
            frames.push(QrStreamFrame {
                kind: QrStreamFrameKind::Data,
                stream_id: envelope.stream_id(),
                index: frame_index,
                total: data_chunks,
                payload: chunk,
            });
        }
        if options.parity_group > 0 {
            for group_index in 0..parity_chunks as usize {
                let parity = xor_parity(
                    payload,
                    chunk_size,
                    data_chunks as usize,
                    group_index,
                    options.parity_group as usize,
                );
                let frame_index = u16::try_from(group_index)
                    .map_err(|_| QrStreamError::InvalidEnvelope("parity_chunks"))?;
                frames.push(QrStreamFrame {
                    kind: QrStreamFrameKind::Parity,
                    stream_id: envelope.stream_id(),
                    index: frame_index,
                    total: parity_chunks,
                    payload: parity,
                });
            }
        }
        Ok((envelope, frames))
    }
    /// Encode frames directly to bytes.
    ///
    /// # Errors
    /// Returns an error when payload/options exceed format limits.
    pub fn encode_frame_bytes(
        payload: &[u8],
        options: QrStreamOptions,
    ) -> Result<(QrStreamEnvelope, Vec<Vec<u8>>), QrStreamError> {
        let (envelope, frames) = Self::encode_frames(payload, options)?;
        Ok((
            envelope,
            frames.into_iter().map(|frame| frame.encode()).collect(),
        ))
    }
}
/// Decoder / assembler for QR stream frames.
pub struct QrStreamAssembler {
    envelope: Option<QrStreamEnvelope>,
    data_chunks: Vec<Option<Vec<u8>>>,
    parity_chunks: Vec<Option<Vec<u8>>>,
    pending: Vec<QrStreamFrame>,
    recovered: Vec<bool>,
    limits: QrStreamAssemblerLimits,
    started_at: Option<Instant>,
}
impl QrStreamAssembler {
    /// Create a new assembler with explicit limits.
    pub fn new(limits: QrStreamAssemblerLimits) -> Self {
        Self {
            envelope: None,
            data_chunks: Vec::new(),
            parity_chunks: Vec::new(),
            pending: Vec::new(),
            recovered: Vec::new(),
            limits,
            started_at: None,
        }
    }
    /// Ingest raw frame bytes.
    ///
    /// # Errors
    /// Returns an error when frame decoding fails or assembly validation fails.
    pub fn ingest_bytes(&mut self, bytes: &[u8]) -> Result<QrStreamDecodeResult, QrStreamError> {
        let frame = QrStreamFrame::decode(bytes)?;
        self.ingest_frame(frame)
    }
    /// Ingest a decoded frame.
    ///
    /// # Errors
    /// Returns an error when frame validation fails or payload reconstruction
    /// detects an integrity mismatch.
    pub fn ingest_frame(
        &mut self,
        frame: QrStreamFrame,
    ) -> Result<QrStreamDecodeResult, QrStreamError> {
        self.track_timeout()?;
        match frame.kind {
            QrStreamFrameKind::Header => {
                if self
                    .envelope
                    .is_some_and(|envelope| frame.stream_id != envelope.stream_id())
                {
                    return Ok(self.progress());
                }
                let envelope = QrStreamEnvelope::decode(&frame.payload)?;
                if frame.stream_id != envelope.stream_id() {
                    return Err(QrStreamError::InvalidStreamId);
                }
                if let Some(current) = self.envelope {
                    if envelope != current {
                        return Err(QrStreamError::InvalidEnvelope("conflicting header"));
                    }
                } else {
                    self.validate_limits(&envelope)?;
                    let data_chunks = envelope.data_chunks as usize;
                    let parity_chunks = envelope.parity_chunks as usize;
                    self.envelope = Some(envelope);
                    self.data_chunks = vec![None; data_chunks];
                    self.parity_chunks = vec![None; parity_chunks];
                    self.recovered = vec![false; data_chunks];
                    if !self.pending.is_empty() {
                        let pending = std::mem::take(&mut self.pending);
                        for buffered in pending
                            .into_iter()
                            .filter(|f| f.stream_id == frame.stream_id)
                        {
                            self.ingest_frame(buffered)?;
                        }
                    }
                }
            }
            QrStreamFrameKind::Data | QrStreamFrameKind::Parity => {
                let envelope = if let Some(env) = self.envelope.as_ref() {
                    *env
                } else {
                    self.pending.push(frame);
                    return Ok(self.progress());
                };
                if frame.stream_id != envelope.stream_id() {
                    return Ok(self.progress());
                }
                match frame.kind {
                    QrStreamFrameKind::Data => {
                        self.validate_data_frame(&frame, &envelope)?;
                        self.store_data(&frame);
                    }
                    QrStreamFrameKind::Parity => {
                        self.validate_parity_frame(&frame, &envelope)?;
                        self.store_parity(&frame);
                    }
                    QrStreamFrameKind::Header => {}
                }
                self.recover_missing(&envelope);
            }
        }
        if let Some(payload) = self.finalize_if_complete()? {
            return Ok(QrStreamDecodeResult {
                payload: Some(payload),
                received_chunks: self.received_chunks(),
                total_chunks: self.data_chunks.len(),
                recovered_chunks: self.recovered.iter().filter(|v| **v).count(),
            });
        }
        Ok(self.progress())
    }
    fn progress(&self) -> QrStreamDecodeResult {
        QrStreamDecodeResult {
            payload: None,
            received_chunks: self.received_chunks(),
            total_chunks: self.data_chunks.len(),
            recovered_chunks: self.recovered.iter().filter(|v| **v).count(),
        }
    }
    fn received_chunks(&self) -> usize {
        self.data_chunks.iter().filter(|c| c.is_some()).count()
    }
    fn track_timeout(&mut self) -> Result<(), QrStreamError> {
        let now = Instant::now();
        match self.started_at {
            Some(start) => {
                if now.duration_since(start) > self.limits.timeout {
                    return Err(QrStreamError::TimedOut);
                }
            }
            None => {
                self.started_at = Some(now);
            }
        }
        Ok(())
    }
    fn validate_limits(&self, envelope: &QrStreamEnvelope) -> Result<(), QrStreamError> {
        if envelope.payload_length > self.limits.max_payload_bytes {
            return Err(QrStreamError::LimitExceeded("payload_length"));
        }
        if envelope.chunk_size == 0 || envelope.chunk_size > self.limits.max_chunk_bytes {
            return Err(QrStreamError::LimitExceeded("chunk_size"));
        }
        let total_frames = envelope
            .data_chunks
            .saturating_add(envelope.parity_chunks)
            .saturating_add(1);
        if total_frames > self.limits.max_frames {
            return Err(QrStreamError::LimitExceeded("frame_count"));
        }
        Ok(())
    }
    fn validate_data_frame(
        &self,
        frame: &QrStreamFrame,
        envelope: &QrStreamEnvelope,
    ) -> Result<(), QrStreamError> {
        let index = usize::from(frame.index);
        if frame.total != envelope.data_chunks || index >= self.data_chunks.len() {
            return Err(QrStreamError::InvalidEnvelope("data frame shape"));
        }
        let expected_len = expected_chunk_length(
            envelope.payload_length as usize,
            envelope.chunk_size as usize,
            index,
            self.data_chunks.len(),
        );
        if frame.payload.len() != expected_len {
            return Err(QrStreamError::InvalidLength("data chunk"));
        }
        Ok(())
    }
    fn validate_parity_frame(
        &self,
        frame: &QrStreamFrame,
        envelope: &QrStreamEnvelope,
    ) -> Result<(), QrStreamError> {
        let index = usize::from(frame.index);
        if frame.total != envelope.parity_chunks || index >= self.parity_chunks.len() {
            return Err(QrStreamError::InvalidEnvelope("parity frame shape"));
        }
        if frame.payload.len() != usize::from(envelope.chunk_size) {
            return Err(QrStreamError::InvalidLength("parity chunk"));
        }
        Ok(())
    }
    fn store_data(&mut self, frame: &QrStreamFrame) {
        let index = frame.index as usize;
        if index < self.data_chunks.len() && self.data_chunks[index].is_none() {
            self.data_chunks[index] = Some(frame.payload.clone());
        }
    }
    fn store_parity(&mut self, frame: &QrStreamFrame) {
        let index = frame.index as usize;
        if index < self.parity_chunks.len() && self.parity_chunks[index].is_none() {
            self.parity_chunks[index] = Some(frame.payload.clone());
        }
    }
    fn recover_missing(&mut self, envelope: &QrStreamEnvelope) {
        let group_size = envelope.parity_group as usize;
        if group_size == 0 {
            return;
        }
        let chunk_size = envelope.chunk_size as usize;
        for group_index in 0..self.parity_chunks.len() {
            let parity = match self.parity_chunks[group_index].as_ref() {
                Some(p) => p,
                None => continue,
            };
            let start = group_index * group_size;
            let end = (start + group_size).min(self.data_chunks.len());
            if start >= end {
                continue;
            }
            let mut missing = None;
            let mut xor = vec![0u8; chunk_size];
            xor[..parity.len()].copy_from_slice(parity);
            for data_index in start..end {
                if let Some(chunk) = &self.data_chunks[data_index] {
                    let mut padded = vec![0u8; chunk_size];
                    padded[..chunk.len()].copy_from_slice(chunk);
                    for (slot, byte) in xor.iter_mut().zip(padded) {
                        *slot ^= byte;
                    }
                } else if missing.is_none() {
                    missing = Some(data_index);
                } else {
                    missing = None;
                    break;
                }
            }
            if let Some(missing_index) = missing {
                let expected_len = expected_chunk_length(
                    envelope.payload_length as usize,
                    chunk_size,
                    missing_index,
                    self.data_chunks.len(),
                );
                let recovered = xor[..expected_len].to_vec();
                self.data_chunks[missing_index] = Some(recovered);
                self.recovered[missing_index] = true;
            }
        }
    }
    fn finalize_if_complete(&self) -> Result<Option<Vec<u8>>, QrStreamError> {
        let envelope = match &self.envelope {
            Some(env) => env,
            None => return Ok(None),
        };
        if self.data_chunks.iter().any(std::option::Option::is_none) {
            return Ok(None);
        }
        let mut payload = Vec::with_capacity(envelope.payload_length as usize);
        for (index, chunk) in self.data_chunks.iter().enumerate() {
            let chunk = chunk.as_ref().expect("checked above");
            let expected_len = expected_chunk_length(
                envelope.payload_length as usize,
                envelope.chunk_size as usize,
                index,
                self.data_chunks.len(),
            );
            if chunk.len() > expected_len {
                payload.extend_from_slice(&chunk[..expected_len]);
            } else {
                payload.extend_from_slice(chunk);
            }
        }
        if payload.len() != envelope.payload_length as usize {
            payload.truncate(envelope.payload_length as usize);
        }
        let computed = blake2b256(&payload);
        if computed != envelope.payload_hash {
            return Err(QrStreamError::InvalidEnvelope("payload_hash mismatch"));
        }
        Ok(Some(payload))
    }
}
impl Default for QrStreamAssembler {
    fn default() -> Self {
        Self::new(QrStreamAssemblerLimits::default())
    }
}
/// Result produced by the QR stream assembler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QrStreamDecodeResult {
    /// Decoded payload, if complete.
    pub payload: Option<Vec<u8>>,
    /// Number of received data chunks.
    pub received_chunks: usize,
    /// Total expected data chunks.
    pub total_chunks: usize,
    /// Number of chunks reconstructed via parity.
    pub recovered_chunks: usize,
}
impl QrStreamDecodeResult {
    /// Whether the payload has been fully reconstructed.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.payload.is_some()
    }
    /// Progress ratio based on received data chunks.
    #[must_use]
    pub fn progress(&self) -> f64 {
        if self.total_chunks == 0 {
            0.0
        } else {
            let received = u32::try_from(self.received_chunks).expect("chunk count fits u32");
            let total = u32::try_from(self.total_chunks).expect("chunk count fits u32");
            f64::from(received) / f64::from(total)
        }
    }
}
fn expected_chunk_length(
    payload_len: usize,
    chunk_size: usize,
    index: usize,
    total: usize,
) -> usize {
    if total == 0 {
        return 0;
    }
    if index + 1 < total {
        return chunk_size;
    }
    let tail = payload_len.saturating_sub(chunk_size.saturating_mul(total.saturating_sub(1)));
    tail.min(chunk_size)
}
fn xor_parity(
    payload: &[u8],
    chunk_size: usize,
    data_chunks: usize,
    group_index: usize,
    group_size: usize,
) -> Vec<u8> {
    let mut parity = vec![0u8; chunk_size];
    let start = group_index * group_size;
    let end = (start + group_size).min(data_chunks);
    if start >= end {
        return parity;
    }
    for chunk_index in start..end {
        let offset = chunk_index * chunk_size;
        let end = (offset + chunk_size).min(payload.len());
        let chunk = &payload[offset..end];
        for (slot, byte) in parity.iter_mut().zip(chunk.iter().copied()) {
            *slot ^= byte;
        }
    }
    parity
}
fn blake2b256(payload: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("blake2b var init");
    hasher.update(payload);
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    out
}
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in bytes {
        let mut c = (crc ^ u32::from(byte)) & 0xFF;
        for _ in 0..8 {
            if c & 1 == 1 {
                c = 0xEDB8_8320 ^ (c >> 1);
            } else {
                c >>= 1;
            }
        }
        crc = (crc >> 8) ^ c;
    }
    crc ^ 0xFFFF_FFFF
}
fn read_u16_le(bytes: &[u8], offset: usize) -> Result<u16, QrStreamError> {
    if offset + 2 > bytes.len() {
        return Err(QrStreamError::InvalidLength("u16"));
    }
    Ok(u16::from_le_bytes([bytes[offset], bytes[offset + 1]]))
}
fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32, QrStreamError> {
    if offset + 4 > bytes.len() {
        return Err(QrStreamError::InvalidLength("u32"));
    }
    Ok(u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ]))
}
#[cfg(test)]
mod tests {
    use super::*;
    use norito::json::{self, Value};
    use std::fs;
    use std::path::PathBuf;
    #[derive(Debug)]
    struct FixtureFrame {
        kind: QrStreamFrameKind,
        bytes: Vec<u8>,
    }
    #[derive(Debug)]
    struct QrStreamFixture {
        payload: Vec<u8>,
        options: QrStreamOptions,
        envelope: Vec<u8>,
        frames: Vec<FixtureFrame>,
    }
    fn load_fixture(name: &str) -> QrStreamFixture {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("../../fixtures/qr_stream");
        path.push(name);
        let contents = fs::read_to_string(&path).expect("fixture read");
        let value: Value = json::from_str(&contents).expect("fixture json");
        let payload_hex = value
            .get("payload_hex")
            .and_then(|v| v.as_str())
            .expect("payload_hex");
        let payload = hex::decode(payload_hex).expect("payload hex");
        let options_value = value.get("options").expect("options");
        let chunk_size = options_value
            .get("chunk_size")
            .and_then(norito::json::native::Value::as_u64)
            .and_then(|value| u16::try_from(value).ok())
            .expect("chunk_size");
        let parity_group = options_value
            .get("parity_group")
            .and_then(norito::json::native::Value::as_u64)
            .and_then(|value| u8::try_from(value).ok())
            .expect("parity_group");
        let payload_kind = match options_value
            .get("payload_kind")
            .and_then(|v| v.as_str())
            .unwrap_or("unspecified")
        {
            "unspecified" => QrPayloadKind::Unspecified,
            other => panic!("unknown fixture payload kind {other}"),
        };
        let envelope_hex = value
            .get("envelope_hex")
            .and_then(|v| v.as_str())
            .expect("envelope_hex");
        let envelope = hex::decode(envelope_hex).expect("envelope hex");
        let frames_value = value
            .get("frames")
            .and_then(|v| v.as_array())
            .expect("frames");
        let mut frames = Vec::new();
        for frame in frames_value {
            let kind_str = frame
                .get("kind")
                .and_then(|v| v.as_str())
                .expect("frame kind");
            let kind = match kind_str {
                "header" => QrStreamFrameKind::Header,
                "data" => QrStreamFrameKind::Data,
                "parity" => QrStreamFrameKind::Parity,
                _ => panic!("unknown frame kind {kind_str}"),
            };
            let bytes_hex = frame
                .get("bytes_hex")
                .and_then(|v| v.as_str())
                .expect("bytes_hex");
            let bytes = hex::decode(bytes_hex).expect("frame bytes");
            frames.push(FixtureFrame { kind, bytes });
        }
        QrStreamFixture {
            payload,
            options: QrStreamOptions {
                chunk_size,
                parity_group,
                payload_kind,
                ..QrStreamOptions::default()
            },
            envelope,
            frames,
        }
    }
    #[test]
    fn qr_stream_roundtrip_fixture() {
        let fixture = load_fixture("qr_stream_basic.json");
        let (envelope, frames) =
            QrStreamEncoder::encode_frames(&fixture.payload, fixture.options).expect("encode");
        assert_eq!(envelope.encode(), fixture.envelope);
        let encoded: Vec<Vec<u8>> = frames.iter().map(super::QrStreamFrame::encode).collect();
        let fixture_bytes: Vec<Vec<u8>> = fixture.frames.iter().map(|f| f.bytes.clone()).collect();
        assert_eq!(encoded, fixture_bytes);
        let mut assembler = QrStreamAssembler::default();
        let mut result = None;
        for bytes in fixture_bytes {
            let step = assembler.ingest_bytes(&bytes).expect("decode");
            if step.is_complete() {
                result = step.payload;
            }
        }
        assert_eq!(result, Some(fixture.payload));
    }
    #[test]
    fn qr_stream_parity_recovers_missing_frame() {
        let fixture = load_fixture("qr_stream_parity.json");
        let mut assembler = QrStreamAssembler::default();
        let mut result = None;
        let mut dropped = false;
        for frame in &fixture.frames {
            if frame.kind == QrStreamFrameKind::Data && !dropped {
                dropped = true;
                continue;
            }
            let step = assembler.ingest_bytes(&frame.bytes).expect("decode");
            if step.is_complete() {
                result = step.payload;
            }
        }
        assert_eq!(result, Some(fixture.payload));
    }
    #[test]
    fn qr_payload_kind_unknown_maps_to_unspecified() {
        assert_eq!(QrPayloadKind::Unspecified as u16, 0);
        assert_eq!(QrPayloadKind::from_u16(0), QrPayloadKind::Unspecified);
        for retired in 1..=3 {
            assert_eq!(QrPayloadKind::from_u16(retired), QrPayloadKind::Unspecified);
        }
        assert_eq!(QrPayloadKind::from_u16(4), QrPayloadKind::Unspecified);
        assert_eq!(QrPayloadKind::from_u16(5), QrPayloadKind::Unspecified);
        assert_eq!(QrPayloadKind::from_u16(999), QrPayloadKind::Unspecified);
    }
    #[test]
    fn qr_stream_limits_reject_large_payload() {
        let payload = vec![0u8; (QR_STREAM_MAX_PAYLOAD_BYTES as usize) + 1];
        let options = QrStreamOptions::default();
        let (envelope, _) = QrStreamEncoder::encode_frames(&payload, options).expect("encode");
        let mut assembler = QrStreamAssembler::new(QrStreamAssemblerLimits::default());
        let header = QrStreamFrame {
            kind: QrStreamFrameKind::Header,
            stream_id: envelope.stream_id(),
            index: 0,
            total: 1,
            payload: envelope.encode(),
        };
        let result = assembler.ingest_frame(header);
        assert_eq!(
            result.unwrap_err(),
            QrStreamError::LimitExceeded("payload_length")
        );
    }
    #[test]
    fn qr_stream_accepts_out_of_order_and_duplicates() {
        let fixture = load_fixture("qr_stream_basic.json");
        let mut assembler = QrStreamAssembler::default();
        // Feed data frame before header.
        let data = fixture
            .frames
            .iter()
            .find(|f| f.kind == QrStreamFrameKind::Data)
            .unwrap();
        let header = fixture
            .frames
            .iter()
            .find(|f| f.kind == QrStreamFrameKind::Header)
            .unwrap();
        let step = assembler.ingest_bytes(&data.bytes).expect("data");
        assert!(!step.is_complete());
        let _header_step = assembler.ingest_bytes(&header.bytes).expect("header");
        // Duplicate data frame should be ignored.
        let final_result = assembler.ingest_bytes(&data.bytes).expect("dup");
        assert!(final_result.is_complete());
        assert_eq!(final_result.payload, Some(fixture.payload));
    }

    #[test]
    fn qr_stream_rejects_oversized_parity_payload() {
        let payload = b"ab";
        let options = QrStreamOptions {
            chunk_size: 1,
            parity_group: 2,
            ..QrStreamOptions::default()
        };
        let (envelope, frames) = QrStreamEncoder::encode_frames(payload, options).expect("encode");
        let mut assembler = QrStreamAssembler::default();
        assembler
            .ingest_bytes(&frames[0].encode())
            .expect("ingest header");

        let oversized_parity = QrStreamFrame {
            kind: QrStreamFrameKind::Parity,
            stream_id: envelope.stream_id(),
            index: 0,
            total: envelope.parity_chunks,
            payload: vec![0; usize::from(envelope.chunk_size) + 1],
        };
        let error = assembler
            .ingest_bytes(&oversized_parity.encode())
            .expect_err("oversized parity payload must be rejected");
        assert_eq!(error, QrStreamError::InvalidLength("parity chunk"));
    }

    #[test]
    fn qr_stream_duplicate_header_preserves_progress() {
        let payload = b"ab";
        let options = QrStreamOptions {
            chunk_size: 1,
            ..QrStreamOptions::default()
        };
        let (_, frames) = QrStreamEncoder::encode_frames(payload, options).expect("encode");
        let mut assembler = QrStreamAssembler::default();

        assembler
            .ingest_bytes(&frames[0].encode())
            .expect("ingest header");
        assembler
            .ingest_bytes(&frames[1].encode())
            .expect("ingest first data chunk");
        assembler
            .ingest_bytes(&frames[0].encode())
            .expect("ingest repeated header");
        let result = assembler
            .ingest_bytes(&frames[2].encode())
            .expect("ingest second data chunk");

        assert_eq!(result.payload.as_deref(), Some(payload.as_slice()));
    }
}
