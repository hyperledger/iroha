// One canonical frame per append; each reader invocation owns exactly one record.

/// Maximum complete-frame bytes admitted by one offline metrics replay batch.
///
/// The 64 MiB envelope follows the existing default archive scale but includes
/// every record's header and alignment padding; it is not a disk-retention rule.
pub const METRICS_LOG_MAX_READ_BYTES_V1: usize = 64 * 1024 * 1024;
/// Maximum records collected by one offline batch, independently of schema element counts.
///
/// Together with the allocation ceiling this bounds the returned vector even
/// for tiny records. Callers must select a smaller batch policy when appropriate.
pub const METRICS_LOG_MAX_READ_RECORDS_V1: usize = 65_536;
/// Maximum Norito-accounted cumulative allocation requests during one offline replay.
///
/// This 256 MiB envelope includes the fixed reader buffer, all frame buffers,
/// instrumented owned-field decoders (including Metadata's entry vector, children,
/// and conservative B-tree node estimate), and every output-vector growth request.
/// These modeled cumulative charges are neither a per-record allowance nor an
/// exact heap/RSS bound or audit of every allocator request; allocator exhaustion
/// can still abort. Every byte/count combination is not guaranteed to fit.
pub const METRICS_LOG_MAX_READ_ALLOCATION_BYTES_V1: usize = 256 * 1024 * 1024;
const METRICS_LOG_READER_BUFFER_BYTES: usize = 8 * 1024;

/// Explicit resource policy for one all-or-error offline metrics replay batch.
///
/// Every value must be positive and no greater than its corresponding V1 hard
/// ceiling. Validation precedes filesystem access, including the missing-file case.
/// There is no implicit unlimited or compatibility reader.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetricsLogReadLimitsV1 {
    /// Maximum complete records returned by the batch.
    pub max_records: usize,
    /// Maximum sum of full frame bytes, including headers and alignment padding.
    pub max_total_frame_bytes: usize,
    /// Maximum Norito-accounted cumulative requests across the complete read operation.
    pub max_total_allocated_bytes: usize,
}
impl MetricsLogReadLimitsV1 {
    fn validate(self) -> Result<(), MetricsLogError> {
        if !(1..=METRICS_LOG_MAX_READ_RECORDS_V1).contains(&self.max_records)
            || !(1..=METRICS_LOG_MAX_READ_BYTES_V1).contains(&self.max_total_frame_bytes)
            || !(1..=METRICS_LOG_MAX_READ_ALLOCATION_BYTES_V1)
                .contains(&self.max_total_allocated_bytes)
        {
            return Err(MetricsLogError::InvalidReadLimits { limits: self });
        }
        Ok(())
    }
    fn decode_limits(self) -> norito::DecodeLimits {
        norito::DecodeLimits::new(
            self.max_total_frame_bytes * 8,
            self.max_total_frame_bytes,
            self.max_total_frame_bytes * 8,
            self.max_total_allocated_bytes,
            norito::core::MAX_VALUE_NESTING_DEPTH,
        )
    }
}

/// Filesystem failures while preparing the append-only relay metrics log.
///
/// Opening cannot decode or encode records; retaining those unrelated failures here
/// would enlarge every reward-configuration result with a Norito decode graph.
#[derive(Debug, Error)]
pub enum MetricsLogOpenError {
    /// Creating the parent directory failed.
    #[error("failed to create metrics log directory {path:?}: {source}")]
    CreateDir {
        /// Parent directory requested by the log configuration.
        path: PathBuf,
        /// Underlying filesystem failure.
        source: io::Error,
    },
    /// Opening the log file failed.
    #[error("failed to open metrics log at {path:?}: {source}")]
    Open {
        /// Configured log file.
        path: PathBuf,
        /// Underlying filesystem failure.
        source: io::Error,
    },
}
/// Failure to open, append, or replay the canonical relay metrics log.
#[derive(Debug, Error)]
pub enum MetricsLogError {
    /// The caller supplied a zero or over-ceiling batch resource limit.
    #[error("invalid metrics log replay limits: {limits:?}")]
    InvalidReadLimits {
        /// Rejected caller policy; no filesystem access has occurred.
        limits: MetricsLogReadLimitsV1,
    },
    /// Opening the log file failed.
    #[error("failed to open metrics log at {path:?}: {source}")]
    Open {
        /// Configured log file.
        path: PathBuf,
        /// Underlying filesystem failure.
        source: io::Error,
    },
    /// Appending or flushing one complete frame failed.
    #[error("failed to write metrics log at {path:?}: {source}")]
    Write {
        /// Configured log file.
        path: PathBuf,
        /// Underlying filesystem failure.
        source: io::Error,
    },
    /// Canonical encoding of the supplied metrics failed.
    #[error("failed to encode relay metrics entry: {0}")]
    Encode(
        /// Underlying serialization failure.
        #[from]
        norito::Error,
    ),
    /// A log record was malformed, incomplete, noncanonical, or over its decode budget.
    #[error("failed to decode metrics log at {path:?}: {source}")]
    Decode {
        /// Configured log file.
        path: PathBuf,
        /// Underlying frame or resource-admission failure.
        source: norito::Error,
    },
    /// Reading the log stream failed.
    #[error("failed to read metrics log at {path:?}: {source}")]
    Read {
        /// Configured log file.
        path: PathBuf,
        /// Underlying filesystem failure.
        source: io::Error,
    },
}
#[derive(Debug)]
struct MetricsLog {
    path: PathBuf,
    writer: Mutex<File>,
}
impl MetricsLog {
    fn open(path: PathBuf) -> Result<Self, MetricsLogOpenError> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|source| MetricsLogOpenError::CreateDir {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|source| MetricsLogOpenError::Open {
                path: path.clone(),
                source,
            })?;
        Ok(Self {
            path,
            writer: Mutex::new(file),
        })
    }
    fn append(&self, entry: &RelayEpochMetricsV1) -> Result<(), MetricsLogError> {
        let framed = encode_metrics_frame(
            entry,
            norito::core::max_archive_len(),
            METRICS_LOG_MAX_READ_BYTES_V1,
        )?;
        let mut guard = self.writer.lock().expect("metrics log mutex poisoned");
        guard
            .write_all(&framed)
            .map_err(|source| MetricsLogError::Write {
                path: self.path.clone(),
                source,
            })?;
        guard.flush().map_err(|source| MetricsLogError::Write {
            path: self.path.clone(),
            source,
        })?;
        Ok(())
    }
}
/// Read adjacent canonical V1 relay metrics frames under an explicit batch policy.
///
/// EOF is accepted only between complete frames. A partial header or payload,
/// alternate frame, corrupt record, or exhausted limit rejects the entire batch.
/// A missing file returns an empty vector; other opening failures remain errors.
///
/// The positive policy is checked against the documented V1 ceilings before I/O.
/// Norito allocation accounting is cumulative across the fixed reader buffer,
/// instrumented record decodes (including Metadata's vector, children and modeled
/// tree nodes), and geometrically grown output storage. Accounting is not exact
/// heap/RSS, an audit of every allocator request or protection from allocation
/// aborts. Disk retention is separate.
pub fn read_metrics_log(
    path: impl AsRef<Path>,
    limits: MetricsLogReadLimitsV1,
) -> Result<Vec<RelayEpochMetricsV1>, MetricsLogError> {
    limits.validate()?;
    let path = path.as_ref();
    let file = match File::open(path) {
        Ok(file) => file,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => {
            return Err(MetricsLogError::Open {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    norito::with_decode_limits_scope(limits.decode_limits(), || {
        let decode_error = |source| MetricsLogError::Decode {
            path: path.to_path_buf(),
            source,
        };
        norito::core::reserve_decode_allocation(METRICS_LOG_READER_BUFFER_BYTES)
            .map_err(decode_error)?;
        let mut reader = BufReader::with_capacity(METRICS_LOG_READER_BUFFER_BYTES, file);
        let mut entries = Vec::new();
        let mut total_frame_bytes = 0;
        loop {
            if reader
                .fill_buf()
                .map_err(|source| MetricsLogError::Read {
                    path: path.to_path_buf(),
                    source,
                })?
                .is_empty()
            {
                return Ok(entries);
            }
            if entries.len() == limits.max_records {
                return Err(decode_error(norito::Error::SequenceLengthExceeded {
                    length: (entries.len() + 1) as u64,
                    limit: limits.max_records as u64,
                }));
            }
            let entry = read_metrics_frame(
                &mut reader,
                &mut total_frame_bytes,
                limits.max_total_frame_bytes,
            )
            .map_err(decode_error)?;
            reserve_metrics_entry(&mut entries, limits.max_records).map_err(decode_error)?;
            entries.push(entry);
        }
    })
}

// Charge each complete growth request, not just the capacity delta: Norito's
// outer allocation budget is cumulative, including replaced allocations.
fn reserve_metrics_entry(
    entries: &mut Vec<RelayEpochMetricsV1>,
    max_records: usize,
) -> Result<(), norito::Error> {
    if entries.len() < entries.capacity() {
        return Ok(());
    }
    let capacity = entries
        .capacity()
        .checked_mul(2)
        .ok_or(norito::Error::LengthMismatch)?
        .max(16)
        .min(max_records);
    let bytes = capacity
        .checked_mul(std::mem::size_of::<RelayEpochMetricsV1>())
        .ok_or(norito::Error::LengthMismatch)?;
    norito::core::reserve_decode_allocation(bytes)?;
    entries
        .try_reserve_exact(capacity - entries.len())
        .map_err(|_| norito::Error::AllocationFailed {
            bytes: bytes as u64,
        })
}

fn metrics_frame_overhead() -> usize {
    let alignment = norito::core::archived_payload_align::<RelayEpochMetricsV1>();
    norito::core::Header::SIZE + (alignment - norito::core::Header::SIZE % alignment) % alignment
}

// Count a real canonical serialization before allocating its output frame. The
// requested bounds can only narrow the global payload ceiling and full-frame
// replay ceiling, so one emitted record always fits the byte policy's hard limit.
fn encode_metrics_frame(
    entry: &RelayEpochMetricsV1,
    max_payload_bytes: u64,
    max_frame_bytes: usize,
) -> Result<Vec<u8>, norito::Error> {
    let frame_len = norito::canonical_frame_len(entry)?;
    let max_frame_bytes = max_frame_bytes.min(METRICS_LOG_MAX_READ_BYTES_V1);
    if frame_len > max_frame_bytes {
        return Err(norito::Error::ArchiveLengthExceeded {
            length: frame_len as u64,
            limit: max_frame_bytes as u64,
        });
    }
    let payload_len = frame_len
        .checked_sub(metrics_frame_overhead())
        .ok_or(norito::Error::LengthMismatch)?;
    let length = u64::try_from(payload_len).map_err(|_| norito::Error::LengthMismatch)?;
    let limit = max_payload_bytes.min(norito::core::max_archive_len());
    if length > limit {
        return Err(norito::Error::ArchiveLengthExceeded { length, limit });
    }
    let frame = norito::encode_canonical(entry)?;
    if frame.len() != frame_len {
        return Err(norito::Error::LengthMismatch);
    }
    Ok(frame)
}

// `deserialize_stream` requires EOF after one frame, so it cannot read directly from
// a concatenated log. Isolate the declared frame without probing the next record.
fn read_metrics_frame(
    reader: &mut impl Read,
    total_frame_bytes: &mut usize,
    max_total_frame_bytes: usize,
) -> Result<RelayEpochMetricsV1, norito::Error> {
    use norito::core::Header;

    let mut header_bytes = [0_u8; Header::SIZE];
    reader.read_exact(&mut header_bytes)?;
    let header = Header::read(header_bytes.as_slice())?;
    // This nonempty derived record always emits compact field lengths. Its canonical
    // encoder selects neither packed sequences nor field bitsets, regardless of its values.
    if header.compression != norito::Compression::None
        || header.flags != norito::core::default_encode_flags()
    {
        return Err(norito::Error::NonCanonicalEncoding);
    }
    if header.schema != norito::schema::identity::frame_hash::<RelayEpochMetricsV1>() {
        return Err(norito::Error::SchemaMismatch);
    }
    let limit = norito::core::max_archive_len();
    if header.length > limit {
        return Err(norito::Error::ArchiveLengthExceeded {
            length: header.length,
            limit,
        });
    }
    let payload_len =
        usize::try_from(header.length).map_err(|_| norito::Error::ArchiveLengthExceeded {
            length: header.length,
            limit,
        })?;
    let frame_len = metrics_frame_overhead()
        .checked_add(payload_len)
        .ok_or(norito::Error::LengthMismatch)?;
    let next_total = total_frame_bytes
        .checked_add(frame_len)
        .ok_or(norito::Error::LengthMismatch)?;
    if next_total > max_total_frame_bytes {
        return Err(norito::Error::ArchiveLengthExceeded {
            length: next_total as u64,
            limit: max_total_frame_bytes as u64,
        });
    }
    let limits = norito::canonical_decode_limits(frame_len);
    let entry = norito::with_decode_limits_scope(limits, || {
        norito::core::reserve_decode_allocation(frame_len)?;
        let mut frame = Vec::new();
        frame
            .try_reserve_exact(frame_len)
            .map_err(|_| norito::Error::AllocationFailed {
                bytes: frame_len as u64,
            })?;
        frame.extend_from_slice(&header_bytes);
        frame.resize(frame_len, 0);
        reader.read_exact(&mut frame[Header::SIZE..])?;
        norito::decode_canonical_with_limits(&frame, limits)
    })?;
    *total_frame_bytes = next_total;
    Ok(entry)
}
