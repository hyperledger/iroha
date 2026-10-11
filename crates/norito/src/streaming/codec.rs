//! Baseline streaming codec, bundled entropy, and audio implementation.
use super::{
    AudioCodecError, AudioCodecLayoutMismatchInfo, AudioEncoderSampleCountMismatchInfo, AudioFrame,
    AudioLayout, AudioTrackSummary, BundleAcceleration, Bytes, CapabilityFlags, ChunkDescriptor,
    EncryptionSuite, EntropyMode, FecScheme, FeedbackHint, Hash, ManifestV1, Multiaddr,
    NeuralBundle, NoritoJsonValue, PrivacyRoute, ProfileId, RansGroupTableV1, RdoMode,
    SegmentAudio, SegmentHeader, Signature, SignedRansTablesV1, StorageClass, StreamMetadata,
    Timestamp,
    chunk::{
        AudioFrameCadenceMismatchInfo, AudioFrameCadenceOverflowInfo, AudioSampleCountMismatchInfo,
        BlockCountMismatchInfo, ChromaDimensionsNotEvenInfo, ChunkError, CodecError,
        FrameCountOverflowInfo, FrameLengthMismatch, chunk_commitments, derive_nonce_salt,
        merkle_root,
    },
    json, saturating_usize_to_u32, saturating_usize_to_u64,
};
use crate as norito;
use norito_derive::{NoritoDeserialize, NoritoSerialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, VecDeque},
    convert::TryInto,
    fs,
    path::Path,
    sync::{Arc, OnceLock},
};
use thiserror::Error;
use toml::Value as TomlValue;
pub(crate) const BLOCK_SIZE: usize = 8;
pub(crate) const BLOCK_PIXELS: usize = BLOCK_SIZE * BLOCK_SIZE;
pub(crate) const FRAME_HEADER_LEN: usize = 16;
const RLE_EOB: u8 = 0xFF;
const MAX_ZERO_RUN: usize = 254;
const RLE_TOKEN_BITS: u64 = 24;
const RLE_TOKEN_BITS_F: f32 = 24.0;
const RLE_EOB_BITS_F: f32 = 24.0;
const RDO_ENERGY_BUCKETS: [u32; RDO_BUCKET_COUNT - 1] = [64, 256, 1024, 4096];
const NEURAL_FEATURES: usize = 8;
const NEURAL_HIDDEN: usize = 32;
const NEURAL_OUTPUT: usize = 4;
const DEFAULT_NEURAL_SEED: [u8; 32] = *b"nsc-neural-predictor-v1--seed!!!";
#[cfg(not(feature = "streaming-fixed-point-dct"))]
const DCT_FACTORS: [[f64; 8]; 8] = [
    [
        0.3535533905932737,
        0.3535533905932737,
        0.3535533905932737,
        0.3535533905932737,
        0.3535533905932737,
        0.3535533905932737,
        0.3535533905932737,
        0.3535533905932737,
    ],
    [
        0.4903926402016152,
        0.4157348061512726,
        0.2777851165098011,
        0.0975451610080642,
        -0.0975451610080641,
        -0.277785116509801,
        -0.4157348061512727,
        -0.4903926402016152,
    ],
    [
        0.4619397662556434,
        0.1913417161825449,
        -0.1913417161825449,
        -0.4619397662556434,
        -0.4619397662556434,
        -0.1913417161825452,
        0.191341716182545,
        0.4619397662556433,
    ],
    [
        0.4157348061512726,
        -0.0975451610080641,
        -0.4903926402016152,
        -0.2777851165098011,
        0.2777851165098009,
        0.4903926402016152,
        0.0975451610080644,
        -0.4157348061512726,
    ],
    [
        0.3535533905932738,
        -0.3535533905932737,
        -0.3535533905932738,
        0.3535533905932737,
        0.3535533905932738,
        -0.3535533905932733,
        -0.3535533905932736,
        0.3535533905932733,
    ],
    [
        0.2777851165098011,
        -0.4903926402016152,
        0.0975451610080642,
        0.4157348061512727,
        -0.4157348061512726,
        -0.097545161008064,
        0.4903926402016153,
        -0.2777851165098008,
    ],
    [
        0.1913417161825449,
        -0.4619397662556434,
        0.4619397662556433,
        -0.1913417161825449,
        -0.1913417161825453,
        0.4619397662556434,
        -0.4619397662556432,
        0.1913417161825448,
    ],
    [
        0.0975451610080642,
        -0.2777851165098011,
        0.4157348061512727,
        -0.4903926402016153,
        0.4903926402016152,
        -0.4157348061512725,
        0.2777851165098008,
        -0.0975451610080643,
    ],
];
#[cfg(feature = "streaming-fixed-point-dct")]
const DCT_FACTORS_Q15: [[i16; 8]; 8] = [
    [11585, 11585, 11585, 11585, 11585, 11585, 11585, 11585],
    [16069, 13623, 9102, 3196, -3196, -9102, -13623, -16069],
    [15137, 6270, -6270, -15137, -15137, -6270, 6270, 15137],
    [13623, -3196, -16069, -9102, 9102, 16069, 3196, -13623],
    [11585, -11585, -11585, 11585, 11585, -11585, -11585, 11585],
    [9102, -16069, 3196, 13623, -13623, -3196, 16069, -9102],
    [6270, -15137, 15137, -6270, -6270, 15137, -15137, 6270],
    [3196, -9102, 13623, -16069, 16069, -13623, 9102, -3196],
];
#[cfg(feature = "streaming-fixed-point-dct")]
const DCT_Q_BITS: u32 = 15;
#[cfg(feature = "streaming-fixed-point-dct")]
const DCT_SHIFT: u32 = DCT_Q_BITS * 2;
#[cfg(feature = "streaming-fixed-point-dct")]
const DCT_ROUND: i64 = 1 << (DCT_SHIFT - 1);
#[derive(Debug, Error)]
pub enum BundleTableError {
    #[error("failed to read SignedRansTablesV1 artefact: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse SignedRansTablesV1 TOML: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("invalid SignedRansTablesV1 structure: {0}")]
    InvalidStructure(&'static str),
    #[error("invalid SignedRansTablesV1 payload: {0}")]
    Json(#[from] json::Error),
    #[error("checksum mismatch for SignedRansTablesV1 payload")]
    ChecksumMismatch,
    #[error("missing rANS frequency group for bit length {bit_len}")]
    MissingGroup { bit_len: u8 },
    #[error("invalid rANS frequency group for bit length {bit_len}: {reason}")]
    InvalidGroup { bit_len: u8, reason: &'static str },
}
/// Errors returned when decoding bundled rANS streams.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum BundleDecodeError {
    /// Stream too short to contain the serialized ANS state.
    #[error("bundle rANS stream missing serialized state")]
    TruncatedState,
    /// SIMD bundle stream is missing the header or lane length metadata.
    #[error("SIMD bundle stream missing header or lane lengths")]
    InvalidSimdHeader,
    /// Declared stream lengths do not match the payload.
    #[error("bundle rANS stream length mismatch")]
    LengthMismatch,
    /// A bundle record advertises a width outside the authenticated table domain.
    #[error("invalid bundle bit length at index {index}: found {bit_len}, expected 1..={max}")]
    InvalidBitLength {
        /// Position within the bundle record stream.
        index: u32,
        /// Width advertised by the record.
        bit_len: u8,
        /// Maximum width authenticated by the selected tables.
        max: u8,
    },
    /// Table checksum does not match the telemetry-provided checksum.
    #[error("bundle table checksum mismatch: expected {expected:?}, found {found:?}")]
    ChecksumMismatch { expected: Hash, found: Hash },
    /// Ran out of bytes while renormalizing the ANS state.
    #[error("bundle rANS renormalization underflow")]
    RenormalizeUnderflow,
    /// Decoded symbol does not match the recorded bundle bits.
    #[error(
        "bundle symbol mismatch at index {index}: expected {expected:#04x}, found {found:#04x}"
    )]
    SymbolMismatch {
        /// Position within the decoded bundle stream.
        index: u32,
        /// Symbol reconstructed from the bundle record.
        expected: u8,
        /// Symbol produced by the ANS stream.
        found: u8,
    },
}
/// Errors encountered while loading or applying a bundle context remap.
#[derive(Debug, Error)]
pub enum ContextRemapError {
    /// The remap JSON could not be read from disk.
    #[error("failed to read context remap file: {0}")]
    Io(#[from] std::io::Error),
    /// The remap JSON could not be parsed.
    #[error("failed to parse context remap file: {0}")]
    Json(#[from] json::Error),
    /// The remap JSON is missing required fields.
    #[error("context remap is missing required field: {0}")]
    Missing(&'static str),
    /// A context identifier in the remap was outside the supported range.
    #[error("context remap contains an invalid context id {0}")]
    InvalidContext(u64),
}
/// Mapping from raw bundle contexts to a pruned/remapped domain.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct BundleContextRemap {
    mapping: BTreeMap<BundleContextId, BundleContextId>,
    escape_context: BundleContextId,
    remapped: u32,
    dropped: u32,
}
impl BundleContextRemap {
    /// Construct a new remap with the provided mapping table and escape context.
    pub fn new(
        mapping: BTreeMap<BundleContextId, BundleContextId>,
        escape_context: BundleContextId,
        remapped: u32,
        dropped: u32,
    ) -> Self {
        Self {
            mapping,
            escape_context,
            remapped,
            dropped,
        }
    }
    /// Apply the remap to a raw context, returning the mapped or escape context.
    #[must_use]
    pub fn map(&self, context: BundleContextId) -> BundleContextId {
        *self.mapping.get(&context).unwrap_or(&self.escape_context)
    }
    /// Escape context used for unmapped entries.
    #[must_use]
    pub const fn escape_context(&self) -> BundleContextId {
        self.escape_context
    }
    /// Number of contexts explicitly remapped.
    #[must_use]
    pub const fn remapped_count(&self) -> u32 {
        self.remapped
    }
    /// Number of contexts routed to the escape bucket.
    #[must_use]
    pub const fn dropped_count(&self) -> u32 {
        self.dropped
    }
    fn from_report(value: &NoritoJsonValue) -> Result<Self, ContextRemapError> {
        let escape_context = value
            .get("escape_context")
            .and_then(NoritoJsonValue::as_u64)
            .and_then(|raw| u16::try_from(raw).ok())
            .map(BundleContextId::new)
            .unwrap_or_else(|| BundleContextId::new(u16::MAX));
        let mut mapping = BTreeMap::new();
        let mut remapped = 0u32;
        let mut dropped = 0u32;
        let mut ingest_rows =
            |key: &str, dest: Option<BundleContextId>| -> Result<(), ContextRemapError> {
                if let Some(entries) = value.get(key).and_then(NoritoJsonValue::as_array) {
                    for entry in entries {
                        let original = entry
                            .get("original")
                            .and_then(NoritoJsonValue::as_u64)
                            .ok_or(ContextRemapError::Missing("original"))?;
                        let remapped_value = entry
                            .get("remapped")
                            .and_then(NoritoJsonValue::as_u64)
                            .and_then(|raw| u16::try_from(raw).ok())
                            .map(BundleContextId::new)
                            .or(dest);
                        let raw = u16::try_from(original)
                            .map_err(|_| ContextRemapError::InvalidContext(original))?;
                        let target = remapped_value.unwrap_or(BundleContextId::new(raw));
                        mapping.insert(BundleContextId::new(raw), target);
                        if target == escape_context {
                            dropped = dropped.saturating_add(1);
                        } else if target != BundleContextId::new(raw) {
                            remapped = remapped.saturating_add(1);
                        }
                    }
                }
                Ok(())
            };
        ingest_rows("kept", None)?;
        ingest_rows("dropped", Some(escape_context))?;
        Ok(Self::new(mapping, escape_context, remapped, dropped))
    }
}
/// Load a bundle context remap from a JSON file (output of `streaming-context-remap`).
pub fn load_bundle_context_remap_from_json<P: AsRef<Path>>(
    path: P,
) -> Result<Arc<BundleContextRemap>, ContextRemapError> {
    let text = fs::read_to_string(&path)?;
    let value: NoritoJsonValue = json::from_str(&text)?;
    let remap = BundleContextRemap::from_report(&value)?;
    Ok(Arc::new(remap))
}
#[derive(Clone, Debug)]
pub struct BundleAnsTables {
    precision_bits: u8,
    checksum: Hash,
    max_width: u8,
    tables: [SymbolTable; MAX_BUNDLE_WIDTH],
}
#[cfg(feature = "schema-structural")]
impl ::iroha_schema::TypeId for BundleAnsTables {
    fn id() -> String {
        "BundleAnsTables".to_owned()
    }
}
#[cfg(feature = "schema-structural")]
impl ::iroha_schema::IntoSchema for BundleAnsTables {
    fn type_name() -> String {
        "BundleAnsTables".to_owned()
    }
    fn update_schema_map(map: &mut ::iroha_schema::MetaMap) {
        if map.contains_key::<Self>() {
            return;
        }
        map.insert::<Self>(::iroha_schema::Metadata::Struct(
            ::iroha_schema::NamedFieldsMeta {
                declarations: vec![
                    ::iroha_schema::Declaration {
                        name: "precision_bits".to_owned(),
                        ty: core::any::TypeId::of::<u8>(),
                    },
                    ::iroha_schema::Declaration {
                        name: "checksum".to_owned(),
                        ty: core::any::TypeId::of::<Hash>(),
                    },
                    ::iroha_schema::Declaration {
                        name: "max_width".to_owned(),
                        ty: core::any::TypeId::of::<u8>(),
                    },
                ],
            },
        ));
        <u8 as ::iroha_schema::IntoSchema>::update_schema_map(map);
        <Hash as ::iroha_schema::IntoSchema>::update_schema_map(map);
    }
}
impl BundleAnsTables {
    fn uniform(precision_bits: u8) -> Self {
        let tables =
            core::array::from_fn(|idx| build_uniform_symbol_table((idx + 1) as u8, precision_bits));
        let checksum = hash_bundle_tables(&tables, precision_bits);
        Self {
            precision_bits,
            checksum,
            max_width: MAX_BUNDLE_WIDTH as u8,
            tables,
        }
    }
    fn from_signed(signed: &SignedRansTablesV1) -> Result<Self, BundleTableError> {
        verify_signed_tables(signed)?;
        let mut slots: [Option<SymbolTable>; MAX_BUNDLE_WIDTH] = core::array::from_fn(|_| None);
        let precision_bits = signed
            .payload
            .body
            .groups
            .first()
            .map(|g| g.precision_bits)
            .ok_or(BundleTableError::InvalidStructure(
                "SignedRansTablesV1 payload must contain at least one group",
            ))?;
        let mut configured_width = signed.payload.body.bundle_width;
        if configured_width == 0 {
            configured_width = MAX_BUNDLE_WIDTH as u8;
        }
        let configured_width = configured_width.max(2).min(MAX_BUNDLE_WIDTH as u8);
        for group in &signed.payload.body.groups {
            let group_size = usize::from(group.group_size);
            if group_size == 0 || !group_size.is_power_of_two() {
                return Err(BundleTableError::InvalidGroup {
                    bit_len: 0,
                    reason: "group_size must be a power of two",
                });
            }
            let bit_len = group_size.trailing_zeros() as u8;
            if bit_len == 0 || bit_len as usize > MAX_BUNDLE_WIDTH {
                return Err(BundleTableError::InvalidGroup {
                    bit_len,
                    reason: "unsupported bundle width",
                });
            }
            if bit_len > configured_width {
                return Err(BundleTableError::InvalidGroup {
                    bit_len,
                    reason: "group width exceeds declared bundle width",
                });
            }
            if group.precision_bits != precision_bits {
                return Err(BundleTableError::InvalidGroup {
                    bit_len,
                    reason: "precision bits mismatch across groups",
                });
            }
            let table = SymbolTable::from_group(group)?;
            slots[(bit_len - 1) as usize] = Some(table);
        }
        let mut tables: [SymbolTable; MAX_BUNDLE_WIDTH] =
            core::array::from_fn(|idx| build_uniform_symbol_table((idx + 1) as u8, precision_bits));
        for bit_len in 2..=configured_width {
            let idx = (bit_len - 1) as usize;
            tables[idx] = slots[idx]
                .take()
                .ok_or(BundleTableError::MissingGroup { bit_len })?;
        }
        tables[0] = derive_significance_table(&tables[1]);
        Ok(Self {
            precision_bits,
            checksum: signed.payload.checksum_sha256,
            max_width: configured_width,
            tables,
        })
    }
    fn table_for_bits(&self, bit_len: u8) -> &SymbolTable {
        assert!(
            bit_len <= self.max_width,
            "bundle tables missing width {} (max {})",
            bit_len,
            self.max_width
        );
        let clamped = bit_len.clamp(1, self.max_width);
        &self.tables[clamped as usize - 1]
    }
    pub fn precision_bits(&self) -> u8 {
        self.precision_bits
    }
    pub fn checksum(&self) -> Hash {
        self.checksum
    }
    pub fn max_width(&self) -> u8 {
        self.max_width
    }
    #[cfg(test)]
    pub(crate) fn from_signed_for_tests(
        signed: &SignedRansTablesV1,
    ) -> Result<Self, BundleTableError> {
        Self::from_signed(signed)
    }
    #[cfg(test)]
    pub(crate) fn freq_len_for_bits_for_tests(&self, bit_len: u8) -> Option<usize> {
        if bit_len == 0 || bit_len > self.max_width {
            return None;
        }
        Some(self.table_for_bits(bit_len).freq.len())
    }
}
pub fn load_bundle_tables_from_toml<P: AsRef<Path>>(
    path: P,
) -> Result<Arc<BundleAnsTables>, BundleTableError> {
    let contents = fs::read_to_string(path)?;
    parse_bundle_tables_from_toml(&contents)
}
/// Parse supplied signed rANS table TOML through the canonical table validator.
///
/// This function reads no files and does not resolve paths or include other inputs.
///
/// # Errors
/// Refuses malformed TOML, unknown fields, invalid table groups, or a mismatched checksum.
pub fn parse_bundle_tables_from_toml(
    contents: &str,
) -> Result<Arc<BundleAnsTables>, BundleTableError> {
    let toml_value: TomlValue = toml::from_str(contents)?;
    let json_value = toml_to_norito_value(&toml_value)?;
    let signed: SignedRansTablesV1 = json::from_value(json_value)?;
    let tables = BundleAnsTables::from_signed(&signed)?;
    Ok(Arc::new(tables))
}
/// Lazily construct the shared default bundle tables (uniform distribution).
///
/// The returned handle is backed by a `OnceLock`, so multiple callers share the
/// same allocation and precision parameters.
pub fn default_bundle_tables() -> Arc<BundleAnsTables> {
    static DEFAULT: OnceLock<Arc<BundleAnsTables>> = OnceLock::new();
    DEFAULT
        .get_or_init(|| Arc::new(BundleAnsTables::uniform(BUNDLE_ANS_PRECISION_BITS)))
        .clone()
}
fn hash_bundle_tables(tables: &[SymbolTable; MAX_BUNDLE_WIDTH], precision_bits: u8) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([precision_bits]);
    for table in tables {
        hasher.update((table.freq.len() as u32).to_le_bytes());
        for &freq in &table.freq {
            hasher.update(freq.to_le_bytes());
        }
    }
    let digest = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    hash
}
fn verify_signed_tables(signed: &SignedRansTablesV1) -> Result<(), BundleTableError> {
    let checksum = signed
        .payload
        .body
        .checksum_sha256()
        .map_err(|_| BundleTableError::InvalidStructure("failed to encode table body"))?;
    if checksum != signed.payload.checksum_sha256 {
        return Err(BundleTableError::ChecksumMismatch);
    }
    Ok(())
}
fn toml_to_norito_value(value: &TomlValue) -> Result<NoritoJsonValue, BundleTableError> {
    use toml::Value::{Array, Boolean, Datetime, Float, Integer, String as TomlString, Table};
    Ok(match value {
        Boolean(b) => NoritoJsonValue::Bool(*b),
        Integer(i) => {
            if *i >= 0 {
                NoritoJsonValue::Number(json::native::Number::U64(*i as u64))
            } else {
                NoritoJsonValue::Number(json::native::Number::I64(*i))
            }
        }
        Float(f) => NoritoJsonValue::Number(json::native::Number::F64(*f)),
        TomlString(s) => NoritoJsonValue::String(s.clone()),
        Datetime(dt) => NoritoJsonValue::String(dt.to_string()),
        Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(toml_to_norito_value(item)?);
            }
            NoritoJsonValue::Array(out)
        }
        Table(map) => {
            let mut out = BTreeMap::new();
            for (k, v) in map {
                out.insert(k.clone(), toml_to_norito_value(v)?);
            }
            NoritoJsonValue::Object(out)
        }
    })
}
const BASELINE_QUANT_MATRIX: [u8; 64] = [
    16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55, 14, 13, 16, 24, 40, 57, 69, 56,
    14, 17, 22, 29, 51, 87, 80, 62, 18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81, 104, 113,
    92, 49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112, 100, 103, 99,
];
const ZIG_ZAG: [usize; 64] = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20,
    13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59,
    52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub(crate) enum FrameType {
    Intra,
    Predicted,
}
impl FrameType {
    fn as_byte(self) -> u8 {
        match self {
            Self::Intra => 0,
            Self::Predicted => 1,
        }
    }
    pub(crate) fn from_byte(byte: u8) -> Result<Self, CodecError> {
        match byte {
            0 => Ok(Self::Intra),
            1 => Ok(Self::Predicted),
            other => Err(CodecError::UnknownFrameType(other)),
        }
    }
    pub(crate) fn reset_dc(self) -> bool {
        matches!(self, FrameType::Intra)
    }
}
/// Segment encoding parameters for the baseline profile.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct BaselineEncoderConfig {
    pub profile: ProfileId,
    pub encryption_suite: EncryptionSuite,
    pub layer_bitmap: u32,
    pub duration_ns: u32,
    pub storage_class: StorageClass,
    pub feedback_hint: FeedbackHint,
    pub frame_dimensions: FrameDimensions,
    pub frames_per_segment: u16,
    pub frame_duration_ns: u32,
    pub quantizer: u8,
    pub audio: Option<AudioEncoderConfig>,
    pub entropy_mode: EntropyMode,
    pub bundle_width: u8,
    pub bundle_tables: Arc<BundleAnsTables>,
    pub bundle_acceleration: BundleAcceleration,
    pub bundle_context_remap: Option<Arc<BundleContextRemap>>,
    /// Optional prefetch distance (in records) for the bundle ANS encoder. A value
    /// of `0` disables prefetching.
    pub bundle_prefetch_distance: u16,
    pub rdo_mode: RdoMode,
    pub rdo_neural_seed: Option<Hash>,
}
impl Default for BaselineEncoderConfig {
    fn default() -> Self {
        Self {
            profile: ProfileId::BASELINE,
            encryption_suite: EncryptionSuite::X25519ChaCha20Poly1305([0u8; 32]),
            layer_bitmap: 0b1,
            duration_ns: 250_000_000,
            storage_class: StorageClass::Ephemeral,
            feedback_hint: FeedbackHint::default(),
            frame_dimensions: FrameDimensions::new(640, 360),
            frames_per_segment: 1,
            frame_duration_ns: 33_333_333,
            quantizer: 16,
            audio: None,
            entropy_mode: EntropyMode::RansBundled,
            bundle_width: 2,
            bundle_tables: default_bundle_tables(),
            bundle_acceleration: BundleAcceleration::None,
            bundle_context_remap: None,
            bundle_prefetch_distance: 0,
            rdo_mode: RdoMode::None,
            rdo_neural_seed: None,
        }
    }
}
impl BaselineEncoderConfig {
    #[must_use]
    pub fn with_audio(mut self, audio: AudioEncoderConfig) -> Self {
        self.audio = Some(audio);
        self
    }
    #[must_use]
    pub fn with_bundle_tables(mut self, tables: Arc<BundleAnsTables>) -> Self {
        self.bundle_tables = tables;
        self
    }
    #[must_use]
    pub fn with_bundle_acceleration(mut self, accel: BundleAcceleration) -> Self {
        self.bundle_acceleration = accel;
        self
    }
    #[must_use]
    pub fn with_bundle_context_remap(mut self, remap: Arc<BundleContextRemap>) -> Self {
        self.bundle_context_remap = Some(remap);
        self
    }
    #[must_use]
    pub fn with_bundle_prefetch_distance(mut self, distance: u16) -> Self {
        self.bundle_prefetch_distance = distance;
        self
    }
    #[must_use]
    pub fn with_rdo_mode(mut self, mode: RdoMode) -> Self {
        self.rdo_mode = mode;
        self
    }
    #[must_use]
    pub fn with_rdo_neural_seed(mut self, seed: Hash) -> Self {
        self.rdo_neural_seed = Some(seed);
        self
    }
}
/// Parameters required to construct a manifest for a baseline segment.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct BaselineManifestParams {
    pub stream_id: Hash,
    pub protocol_version: u16,
    pub published_at: Timestamp,
    pub da_endpoint: Multiaddr,
    pub privacy_routes: Vec<PrivacyRoute>,
    pub public_metadata: StreamMetadata,
    pub capabilities: CapabilityFlags,
    pub signature: Signature,
    pub fec_suite: FecScheme,
    pub neural_bundle: Option<NeuralBundle>,
    pub transport_capabilities_hash: Hash,
}
impl Default for BaselineManifestParams {
    fn default() -> Self {
        Self {
            stream_id: [0u8; 32],
            protocol_version: 1,
            published_at: 0,
            da_endpoint: Multiaddr::default(),
            privacy_routes: Vec::new(),
            public_metadata: StreamMetadata::default(),
            capabilities: CapabilityFlags::default(),
            signature: [0u8; 64],
            fec_suite: FecScheme::Rs12_10,
            neural_bundle: None,
            transport_capabilities_hash: [0u8; 32],
        }
    }
}
/// Encoded segment artifacts produced by the baseline encoder.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct EncodedSegment {
    pub header: SegmentHeader,
    pub descriptors: Vec<ChunkDescriptor>,
    pub chunks: Vec<Vec<u8>>,
    pub audio: Option<SegmentAudio>,
}
impl EncodedSegment {
    /// Construct a manifest that matches the encoded segment.
    pub fn build_manifest(&self, mut params: BaselineManifestParams) -> ManifestV1 {
        assert!(
            self.header.entropy_mode.is_bundled(),
            "rANS manifests without bundled tables are not supported"
        );
        params.capabilities = params
            .capabilities
            .insert(CapabilityFlags::FEATURE_ENTROPY_BUNDLED);
        let accel_mask = CapabilityFlags::FEATURE_BUNDLE_ACCEL_CPU_SIMD
            | CapabilityFlags::FEATURE_BUNDLE_ACCEL_GPU;
        params.capabilities = params.capabilities.remove(accel_mask);
        let required = self.header.bundle_acceleration.capability_mask();
        if required != 0 {
            params.capabilities = params.capabilities.insert(required);
        }
        ManifestV1 {
            stream_id: params.stream_id,
            protocol_version: params.protocol_version,
            segment_number: self.header.segment_number,
            published_at: params.published_at,
            profile: self.header.profile,
            entropy_mode: self.header.entropy_mode,
            entropy_tables_checksum: self.header.entropy_tables_checksum,
            da_endpoint: params.da_endpoint,
            chunk_root: self.header.chunk_merkle_root,
            content_key_id: self.header.content_key_id,
            nonce_salt: self.header.nonce_salt,
            chunk_descriptors: self.descriptors.clone(),
            transport_capabilities_hash: params.transport_capabilities_hash,
            encryption_suite: self.header.encryption_suite,
            fec_suite: params.fec_suite,
            privacy_routes: params.privacy_routes,
            neural_bundle: params.neural_bundle,
            audio_summary: self.header.audio_summary,
            public_metadata: params.public_metadata,
            capabilities: params.capabilities,
            signature: params.signature,
        }
    }
    /// Verify that a manifest is consistent with the encoded segment.
    pub fn verify_manifest(&self, manifest: &ManifestV1) -> Result<(), ManifestError> {
        verify_segment(
            &self.header,
            &self.descriptors,
            &self.chunks,
            self.audio.as_ref(),
        )
        .map_err(ManifestError::from)?;
        if manifest.segment_number != self.header.segment_number {
            return Err(ManifestError::SegmentNumberMismatch);
        }
        if manifest.profile != self.header.profile {
            return Err(ManifestError::ProfileMismatch);
        }
        if manifest.entropy_mode != self.header.entropy_mode {
            return Err(ManifestError::EntropyModeMismatch);
        }
        if manifest.entropy_mode.is_bundled()
            && manifest.entropy_tables_checksum != self.header.entropy_tables_checksum
        {
            return Err(ManifestError::EntropyTablesMismatch);
        }
        if manifest.encryption_suite != self.header.encryption_suite {
            return Err(ManifestError::EncryptionSuiteMismatch);
        }
        if manifest.content_key_id != self.header.content_key_id {
            return Err(ManifestError::ContentKeyIdMismatch);
        }
        if manifest.nonce_salt != self.header.nonce_salt {
            return Err(ManifestError::NonceSaltMismatch);
        }
        if manifest.chunk_root != self.header.chunk_merkle_root {
            return Err(ManifestError::ChunkRootMismatch);
        }
        if manifest.audio_summary != self.header.audio_summary {
            return Err(ManifestError::AudioSummaryMismatch);
        }
        if manifest.chunk_descriptors.len() != self.descriptors.len() {
            return Err(ManifestError::DescriptorCountMismatch);
        }
        for (idx, (expected, actual)) in self
            .descriptors
            .iter()
            .zip(manifest.chunk_descriptors.iter())
            .enumerate()
        {
            if expected != actual {
                return Err(ManifestError::DescriptorMismatch(saturating_usize_to_u32(
                    idx,
                )));
            }
        }
        let required_bundled = self.header.entropy_mode.is_bundled();
        let found_bundled = manifest
            .capabilities
            .contains(CapabilityFlags::FEATURE_ENTROPY_BUNDLED);
        if required_bundled != found_bundled {
            return Err(ManifestError::CapabilityEntropyFlagMismatch {
                required_bundled,
                found_bundled,
            });
        }
        let accel_mask = CapabilityFlags::FEATURE_BUNDLE_ACCEL_CPU_SIMD
            | CapabilityFlags::FEATURE_BUNDLE_ACCEL_GPU;
        let advertised_mask = manifest.capabilities.bits() & accel_mask;
        let required_mask = if required_bundled {
            self.header.bundle_acceleration.capability_mask()
        } else {
            0
        };
        if advertised_mask != required_mask {
            return Err(ManifestError::CapabilityAccelerationFlagMismatch {
                entropy_mode: manifest.entropy_mode,
                required_mask,
                found_mask: advertised_mask,
            });
        }
        Ok(())
    }
    /// Wrap the encoded segment into a portable bundle for RD/decoder tooling.
    pub fn to_bundle(
        &self,
        frame_dimensions: FrameDimensions,
        frame_duration_ns: u32,
    ) -> SegmentBundle {
        self.to_bundle_with_chroma(frame_dimensions, frame_duration_ns, Vec::new())
    }
    /// Wrap the encoded segment into a portable bundle for RD/decoder tooling, attaching optional chroma sidecars.
    pub fn to_bundle_with_chroma(
        &self,
        frame_dimensions: FrameDimensions,
        frame_duration_ns: u32,
        chroma: Vec<Chroma420Frame>,
    ) -> SegmentBundle {
        SegmentBundle {
            header: self.header.clone(),
            descriptors: self.descriptors.clone(),
            chunks: self.chunks.clone(),
            audio: self.audio.clone(),
            frame_dimensions,
            frame_duration_ns,
            chroma,
        }
    }
}
/// Serialized segment bundle carrying the encoded payloads and decoder metadata.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::codec::SegmentBundle")]
#[derive(Clone, Debug, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct SegmentBundle {
    /// Segment header as persisted alongside chunk data.
    pub header: SegmentHeader,
    /// Chunk descriptors matching the payload ordering.
    pub descriptors: Vec<ChunkDescriptor>,
    /// Raw chunk payloads.
    pub chunks: Vec<Bytes>,
    /// Optional encoded audio track.
    #[norito(skip_serializing_if = "Option::is_none")]
    #[norito(default)]
    pub audio: Option<SegmentAudio>,
    /// Frame geometry required for decode and Y4M reconstruction.
    pub frame_dimensions: FrameDimensions,
    /// Frame duration in nanoseconds.
    pub frame_duration_ns: u32,
    /// Optional 4:2:0 chroma planes matching the decoded frames.
    #[norito(default)]
    #[norito(skip_serializing_if = "Vec::is_empty")]
    pub chroma: Vec<Chroma420Frame>,
}
impl SegmentBundle {
    /// Convert the bundle back into an encoded segment, validating chunk commitments.
    pub fn into_segment(self) -> Result<(EncodedSegment, FrameDimensions, u32), SegmentError> {
        let (segment, dims, duration, _) = self.into_segment_with_chroma()?;
        Ok((segment, dims, duration))
    }
    /// Convert the bundle back into an encoded segment and return the attached chroma frames.
    pub fn into_segment_with_chroma(
        self,
    ) -> Result<(EncodedSegment, FrameDimensions, u32, Vec<Chroma420Frame>), SegmentError> {
        let chroma = self.chroma;
        let segment = EncodedSegment {
            header: self.header,
            descriptors: self.descriptors,
            chunks: self.chunks,
            audio: self.audio,
        };
        verify_segment(
            &segment.header,
            &segment.descriptors,
            &segment.chunks,
            segment.audio.as_ref(),
        )?;
        Ok((
            segment,
            self.frame_dimensions,
            self.frame_duration_ns,
            chroma,
        ))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct ChunkListCountMismatch {
    pub descriptors: u32,
    pub chunks: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct HeaderDescriptorCountMismatch {
    pub header: u16,
    pub actual: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct ChunkCountOverflowInfo {
    pub found: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct DescriptorOffsetDetails {
    pub index: u32,
    pub expected: u32,
    pub actual: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct DescriptorLengthDetails {
    pub index: u32,
    pub descriptor: u32,
    pub chunk: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct AudioSampleRateMismatchInfo {
    pub expected: u32,
    pub found: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct AudioFrameSamplesMismatchInfo {
    pub expected: u16,
    pub found: u16,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct AudioFrameDurationMismatchInfo {
    pub expected: u32,
    pub found: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct AudioFrameCountMismatchInfo {
    pub expected: u16,
    pub found: u16,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct AudioFecMismatchInfo {
    pub expected: u8,
    pub found: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct AudioLayoutMismatchInfo {
    pub expected: AudioLayout,
    pub found: AudioLayout,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct AudioTimestampMismatchInfo {
    pub index: u32,
    pub expected: u64,
    pub found: u64,
}
/// Errors emitted when verifying or decoding NSC segments.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub enum SegmentError {
    #[error(transparent)]
    Chunk(#[from] ChunkError),
    #[error(
            "chunk descriptor count ({descriptors}) does not match chunk list ({chunks})",
            descriptors = .0.descriptors,
            chunks = .0.chunks
        )]
    CountMismatch(ChunkListCountMismatch),
    #[error("chunk count exceeds u16 range: found {found}", found = .0.found)]
    ChunkCountOverflow(ChunkCountOverflowInfo),
    #[error(
            "header chunk count ({header}) does not match descriptor list ({actual})",
            header = .0.header,
            actual = .0.actual
        )]
    HeaderCountMismatch(HeaderDescriptorCountMismatch),
    #[error("chunk commitment mismatch at index {0}")]
    CommitmentMismatch(u32),
    #[error(
            "descriptor offset mismatch at index {index}: expected {expected}, found {actual}",
            index = .0.index,
            expected = .0.expected,
            actual = .0.actual
        )]
    DescriptorOffsetMismatch(DescriptorOffsetDetails),
    #[error(
            "descriptor length mismatch at index {index}: descriptor {descriptor}, chunk {chunk}",
            index = .0.index,
            descriptor = .0.descriptor,
            chunk = .0.chunk
        )]
    DescriptorLengthMismatch(DescriptorLengthDetails),
    #[error("chunk length at index {0} exceeds u32 range")]
    ChunkLengthOverflow(u32),
    #[error("descriptor offsets overflow while accumulating at index {0}")]
    OffsetOverflow(u32),
    #[error("merkle root mismatch")]
    MerkleMismatch,
    #[error("chunk ids must be strictly ascending")]
    UnsortedChunkIds,
    #[error("segment header expects audio track but none was provided")]
    AudioSummaryMissing,
    #[error("segment carried unexpected audio track not advertised by header")]
    AudioSummaryUnexpected,
    #[error("audio sample rate mismatch: expected {expected}, found {found}", expected = .0.expected, found = .0.found)]
    AudioSampleRateMismatch(AudioSampleRateMismatchInfo),
    #[error("audio frame sample count mismatch: expected {expected}, found {found}", expected = .0.expected, found = .0.found)]
    AudioFrameSamplesMismatch(AudioFrameSamplesMismatchInfo),
    #[error("audio frame duration mismatch: expected {expected}, found {found}", expected = .0.expected, found = .0.found)]
    AudioFrameDurationMismatch(AudioFrameDurationMismatchInfo),
    #[error("audio frame count mismatch: expected {expected}, found {found}", expected = .0.expected, found = .0.found)]
    AudioFrameCountMismatch(AudioFrameCountMismatchInfo),
    #[error("audio FEC level mismatch: expected {expected}, found {found}", expected = .0.expected, found = .0.found)]
    AudioFecMismatch(AudioFecMismatchInfo),
    #[error("audio layout mismatch: expected {expected:?}, found {found:?}", expected = .0.expected, found = .0.found)]
    AudioLayoutMismatch(AudioLayoutMismatchInfo),
    #[error("audio timestamp mismatch at index {index}: expected {expected}, found {found}", index = .0.index, expected = .0.expected, found = .0.found)]
    AudioTimestampMismatch(AudioTimestampMismatchInfo),
    #[error("audio timestamp computation overflow at index {0}")]
    AudioTimestampOverflow(u32),
}
/// Errors emitted when validating a manifest against an encoded segment.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::TypeId))]
pub enum ManifestError {
    #[error(transparent)]
    Segment(#[from] SegmentError),
    #[error("segment number mismatch")]
    SegmentNumberMismatch,
    #[error("profile mismatch")]
    ProfileMismatch,
    #[error("entropy mode mismatch")]
    EntropyModeMismatch,
    #[error("entropy tables checksum mismatch")]
    EntropyTablesMismatch,
    #[error("encryption suite mismatch")]
    EncryptionSuiteMismatch,
    #[error("content key id mismatch")]
    ContentKeyIdMismatch,
    #[error("nonce salt mismatch")]
    NonceSaltMismatch,
    #[error("chunk root mismatch")]
    ChunkRootMismatch,
    #[error("audio summary mismatch between manifest and segment")]
    AudioSummaryMismatch,
    #[error("descriptor count mismatch")]
    DescriptorCountMismatch,
    #[error("descriptor mismatch at index {0}")]
    DescriptorMismatch(u32),
    #[error(
        "manifest capabilities advertise FEATURE_ENTROPY_BUNDLED={found_bundled} but encoder requires {required_bundled}"
    )]
    CapabilityEntropyFlagMismatch {
        /// Whether the encoder expects bundled entropy.
        required_bundled: bool,
        /// Whether the manifest set the bundled capability bit.
        found_bundled: bool,
    },
    #[error(
        "manifest capabilities advertise acceleration mask {found_mask:#06x} but entropy mode {entropy_mode:?} requires mask {required_mask:#06x}"
    )]
    CapabilityAccelerationFlagMismatch {
        /// Manifest entropy mode under verification.
        entropy_mode: EntropyMode,
        /// Acceleration flag mask detected in the manifest.
        found_mask: u32,
        /// Acceleration mask required by the encoder configuration.
        required_mask: u32,
    },
}
#[cfg(feature = "schema-structural")]
#[derive(::iroha_schema::IntoSchema)]
#[allow(dead_code)]
struct CapabilityEntropyFlagMismatchInfo {
    required_bundled: bool,
    found_bundled: bool,
}
#[cfg(feature = "schema-structural")]
#[derive(::iroha_schema::IntoSchema)]
#[allow(dead_code)]
struct CapabilityAccelerationFlagMismatchInfo {
    entropy_mode: EntropyMode,
    found_mask: u32,
    required_mask: u32,
}
#[cfg(feature = "schema-structural")]
impl ::iroha_schema::IntoSchema for ManifestError {
    fn type_name() -> String {
        "ManifestError".to_owned()
    }
    fn update_schema_map(map: &mut ::iroha_schema::MetaMap) {
        if map.contains_key::<Self>() {
            return;
        }
        map.insert::<Self>(::iroha_schema::Metadata::Enum(::iroha_schema::EnumMeta {
            variants: vec![
                ::iroha_schema::EnumVariant {
                    tag: "Segment".to_owned(),
                    discriminant: 0,
                    ty: Some(core::any::TypeId::of::<SegmentError>()),
                },
                ::iroha_schema::EnumVariant {
                    tag: "SegmentNumberMismatch".to_owned(),
                    discriminant: 1,
                    ty: None,
                },
                ::iroha_schema::EnumVariant {
                    tag: "ProfileMismatch".to_owned(),
                    discriminant: 2,
                    ty: None,
                },
                ::iroha_schema::EnumVariant {
                    tag: "EntropyModeMismatch".to_owned(),
                    discriminant: 3,
                    ty: None,
                },
                ::iroha_schema::EnumVariant {
                    tag: "EntropyTablesMismatch".to_owned(),
                    discriminant: 4,
                    ty: None,
                },
                ::iroha_schema::EnumVariant {
                    tag: "EncryptionSuiteMismatch".to_owned(),
                    discriminant: 5,
                    ty: None,
                },
                ::iroha_schema::EnumVariant {
                    tag: "ContentKeyIdMismatch".to_owned(),
                    discriminant: 6,
                    ty: None,
                },
                ::iroha_schema::EnumVariant {
                    tag: "NonceSaltMismatch".to_owned(),
                    discriminant: 7,
                    ty: None,
                },
                ::iroha_schema::EnumVariant {
                    tag: "ChunkRootMismatch".to_owned(),
                    discriminant: 8,
                    ty: None,
                },
                ::iroha_schema::EnumVariant {
                    tag: "AudioSummaryMismatch".to_owned(),
                    discriminant: 9,
                    ty: None,
                },
                ::iroha_schema::EnumVariant {
                    tag: "DescriptorCountMismatch".to_owned(),
                    discriminant: 10,
                    ty: None,
                },
                ::iroha_schema::EnumVariant {
                    tag: "DescriptorMismatch".to_owned(),
                    discriminant: 11,
                    ty: Some(core::any::TypeId::of::<u32>()),
                },
                ::iroha_schema::EnumVariant {
                    tag: "CapabilityEntropyFlagMismatch".to_owned(),
                    discriminant: 12,
                    ty: Some(core::any::TypeId::of::<CapabilityEntropyFlagMismatchInfo>()),
                },
                ::iroha_schema::EnumVariant {
                    tag: "CapabilityAccelerationFlagMismatch".to_owned(),
                    discriminant: 13,
                    ty: Some(core::any::TypeId::of::<
                        CapabilityAccelerationFlagMismatchInfo,
                    >()),
                },
            ],
        }));
        <SegmentError as ::iroha_schema::IntoSchema>::update_schema_map(map);
        <u32 as ::iroha_schema::IntoSchema>::update_schema_map(map);
        <CapabilityEntropyFlagMismatchInfo as ::iroha_schema::IntoSchema>::update_schema_map(map);
        <CapabilityAccelerationFlagMismatchInfo as ::iroha_schema::IntoSchema>::update_schema_map(
            map,
        );
    }
}
/// Frame geometry used by the baseline codec (luma-only for now).
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::codec::FrameDimensions")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct FrameDimensions {
    pub width: u16,
    pub height: u16,
}
impl FrameDimensions {
    pub const fn new(width: u16, height: u16) -> Self {
        Self { width, height }
    }
    pub const fn pixel_count(self) -> usize {
        self.width as usize * self.height as usize
    }
    const fn align_component(value: u16) -> u16 {
        if value == 0 {
            0
        } else {
            let value_usize = value as usize;
            let aligned = value_usize.div_ceil(BLOCK_SIZE).saturating_mul(BLOCK_SIZE);
            if aligned > u16::MAX as usize {
                u16::MAX
            } else {
                aligned as u16
            }
        }
    }
    pub const fn align_to_block(self) -> Self {
        Self {
            width: Self::align_component(self.width),
            height: Self::align_component(self.height),
        }
    }
    pub const fn block_aligned(self) -> bool {
        (self.width as usize).is_multiple_of(BLOCK_SIZE)
            && (self.height as usize).is_multiple_of(BLOCK_SIZE)
    }
    pub const fn block_count(self) -> usize {
        (self.width as usize / BLOCK_SIZE) * (self.height as usize / BLOCK_SIZE)
    }
}
/// Raw luma frame used by the baseline encoder.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct RawFrame {
    pub luma: Vec<u8>,
}
impl RawFrame {
    pub fn new(dimensions: FrameDimensions, luma: Vec<u8>) -> Result<Self, CodecError> {
        let expected = dimensions.pixel_count();
        if luma.len() != expected {
            return Err(CodecError::InvalidFrameLength(FrameLengthMismatch {
                expected: saturating_usize_to_u32(expected),
                actual: saturating_usize_to_u32(luma.len()),
            }));
        }
        Ok(Self { luma })
    }
}
/// 4:2:0 chroma planes paired with a luma frame.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::codec::Chroma420Frame")]
#[derive(Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct Chroma420Frame {
    /// U plane in row-major order.
    pub u: Bytes,
    /// V plane in row-major order.
    pub v: Bytes,
}
pub(crate) fn ensure_chroma_even_dimensions(dimensions: FrameDimensions) -> Result<(), CodecError> {
    if !dimensions.width.is_multiple_of(2) || !dimensions.height.is_multiple_of(2) {
        return Err(CodecError::ChromaDimensionsNotEven(
            ChromaDimensionsNotEvenInfo {
                width: dimensions.width,
                height: dimensions.height,
            },
        ));
    }
    Ok(())
}
impl Chroma420Frame {
    /// Construct a chroma frame, validating that both planes match the expected dimensions.
    pub fn new(dimensions: FrameDimensions, u: Bytes, v: Bytes) -> Result<Self, CodecError> {
        ensure_chroma_even_dimensions(dimensions)?;
        let expected = usize::from(dimensions.width / 2) * usize::from(dimensions.height / 2);
        if u.len() != expected || v.len() != expected {
            return Err(CodecError::InvalidFrameLength(FrameLengthMismatch {
                expected: saturating_usize_to_u32(expected),
                actual: saturating_usize_to_u32(u.len().max(v.len())),
            }));
        }
        Ok(Self { u, v })
    }
    /// Build a neutral 4:2:0 chroma frame (U/V filled with 128).
    pub fn neutral(dimensions: FrameDimensions) -> Self {
        debug_assert!(
            dimensions.width.is_multiple_of(2) && dimensions.height.is_multiple_of(2),
            "4:2:0 chroma requires even dimensions"
        );
        let expected = usize::from(dimensions.width / 2) * usize::from(dimensions.height / 2);
        let plane = vec![128u8; expected];
        Self {
            u: plane.clone(),
            v: plane,
        }
    }
}
const AUDIO_SYNC_TOLERANCE_NS: u64 = 10_000_000;
fn checked_frame_count(frame_count: usize) -> Result<u16, CodecError> {
    u16::try_from(frame_count).map_err(|_| {
        CodecError::FrameCountOverflow(FrameCountOverflowInfo {
            max: u32::from(u16::MAX),
            found: saturating_usize_to_u32(frame_count),
        })
    })
}
fn expected_audio_frame_samples(
    sample_rate: u32,
    frame_duration_ns: u32,
) -> Result<u16, CodecError> {
    const NS_PER_SEC: u128 = 1_000_000_000;
    let numerator = u128::from(sample_rate) * u128::from(frame_duration_ns);
    let expected = (numerator + NS_PER_SEC / 2) / NS_PER_SEC;
    if expected > u16::MAX as u128 {
        return Err(CodecError::AudioFrameCadenceOverflow(
            AudioFrameCadenceOverflowInfo {
                expected: expected as u64,
                sample_rate,
                frame_duration_ns,
            },
        ));
    }
    Ok(expected as u16)
}
struct AudioEncoderState {
    encoder: iroha_audio::Encoder,
    sequence: u64,
}
pub struct BaselineEncoder {
    config: BaselineEncoderConfig,
    audio: Option<AudioEncoderState>,
    bundled_telemetry: Option<BundledTelemetry>,
    bundle_tables: Arc<BundleAnsTables>,
    rdo_lambda: f32,
    neural_predictor: Option<NeuralPredictor>,
}
pub(crate) fn pad_frame_luma(
    input: &[u8],
    dims: FrameDimensions,
    aligned: FrameDimensions,
) -> Vec<u8> {
    if dims == aligned {
        return input.to_vec();
    }
    let dst_w = aligned.width as usize;
    let dst_h = aligned.height as usize;
    let mut out = vec![0u8; dst_w * dst_h];
    let src_w = dims.width as usize;
    let src_h = dims.height as usize;
    if src_w == 0 || src_h == 0 {
        return out;
    }
    for y in 0..src_h {
        let src_row = &input[y * src_w..(y + 1) * src_w];
        let dst_row = &mut out[y * dst_w..(y + 1) * dst_w];
        dst_row[..src_w].copy_from_slice(src_row);
        let fill = src_row.last().copied().unwrap_or(0);
        for value in &mut dst_row[src_w..] {
            *value = fill;
        }
    }
    if src_h < dst_h {
        let last_row = out[(src_h - 1) * dst_w..src_h * dst_w].to_vec();
        for y in src_h..dst_h {
            let dst_row = &mut out[y * dst_w..(y + 1) * dst_w];
            dst_row.copy_from_slice(&last_row);
        }
    }
    out
}
pub(crate) fn crop_frame_luma(
    aligned_data: &[u8],
    dims: FrameDimensions,
    aligned: FrameDimensions,
) -> Vec<u8> {
    if dims == aligned {
        return aligned_data.to_vec();
    }
    let dst_w = dims.width as usize;
    let dst_h = dims.height as usize;
    if dst_w == 0 || dst_h == 0 {
        return Vec::new();
    }
    let src_w = aligned.width as usize;
    let mut out = Vec::with_capacity(dst_w * dst_h);
    for y in 0..dst_h {
        let start = y * src_w;
        out.extend_from_slice(&aligned_data[start..start + dst_w]);
    }
    out
}
impl BaselineEncoder {
    pub fn new(config: BaselineEncoderConfig) -> Self {
        assert!(
            config.entropy_mode.is_bundled(),
            "rANS entropy mode without bundled tables is not supported in the streaming baseline encoder"
        );
        assert!(
            config.bundle_width >= 2,
            "bundled rANS requires bundle_width >= 2"
        );
        let bundle_tables = config.bundle_tables.clone();
        let neural_seed = config.rdo_neural_seed.unwrap_or(DEFAULT_NEURAL_SEED);
        let neural_predictor =
            (config.rdo_mode == RdoMode::Neural).then(|| NeuralPredictor::from_seed(neural_seed));
        let rdo_lambda = rdo_lambda_for_mode(config.rdo_mode, config.quantizer);
        Self {
            bundle_tables,
            config,
            audio: None,
            bundled_telemetry: None,
            rdo_lambda,
            neural_predictor,
        }
    }
    /// Latest bundled entropy telemetry (stats + token stream) recorded by the encoder.
    #[must_use]
    pub fn bundled_telemetry(&self) -> Option<&BundledTelemetry> {
        self.bundled_telemetry.as_ref()
    }
    fn ensure_audio_state(
        &mut self,
        audio_cfg: &AudioEncoderConfig,
    ) -> Result<&mut AudioEncoderState, AudioCodecError> {
        if self.audio.is_none() {
            let encoder = iroha_audio::Encoder::new(iroha_audio::EncoderConfig {
                sample_rate: audio_cfg.sample_rate,
                frame_samples: audio_cfg.frame_samples,
                layout: audio_cfg.layout.into(),
                fec_level: audio_cfg.fec_level,
                target_bitrate: audio_cfg.target_bitrate,
                backend: audio_cfg.backend,
            })
            .map_err(AudioCodecError::from_backend)?;
            self.audio = Some(AudioEncoderState {
                encoder,
                sequence: 0,
            });
        }
        Ok(self.audio.as_mut().expect("audio state initialized"))
    }
    fn encode_audio_track(
        &mut self,
        audio_pcm: Option<&[i16]>,
        frame_count: usize,
        timeline_start_ns: u64,
        frame_step: u64,
    ) -> Result<Option<SegmentAudio>, CodecError> {
        let Some(audio_cfg) = self.config.audio else {
            if audio_pcm.is_some() {
                return Err(CodecError::AudioTrackUnexpected);
            }
            return Ok(None);
        };
        if audio_cfg.frame_samples == 0 {
            return Err(CodecError::Audio(AudioCodecError::InvalidSampleCount(
                AudioEncoderSampleCountMismatchInfo {
                    expected: 1,
                    found: 0,
                },
            )));
        }
        let expected_frame_samples =
            expected_audio_frame_samples(audio_cfg.sample_rate, self.config.frame_duration_ns)?;
        if audio_cfg.frame_samples != expected_frame_samples {
            return Err(CodecError::AudioFrameCadenceMismatch(
                AudioFrameCadenceMismatchInfo {
                    expected: expected_frame_samples,
                    found: audio_cfg.frame_samples,
                    sample_rate: audio_cfg.sample_rate,
                    frame_duration_ns: self.config.frame_duration_ns,
                },
            ));
        }
        let samples = audio_pcm.ok_or(CodecError::AudioTrackMissing)?;
        let channels = audio_cfg.channel_count();
        let samples_per_frame = audio_cfg.frame_samples as usize * channels;
        let expected_samples = frame_count
            .checked_mul(samples_per_frame)
            .ok_or(CodecError::AudioSampleCountOverflow)?;
        if samples.len() != expected_samples {
            return Err(CodecError::AudioSampleCountMismatch(
                AudioSampleCountMismatchInfo {
                    expected: saturating_usize_to_u64(expected_samples),
                    found: saturating_usize_to_u64(samples.len()),
                },
            ));
        }
        let state = self
            .ensure_audio_state(&audio_cfg)
            .map_err(CodecError::from)?;
        let mut frames_out = Vec::with_capacity(frame_count);
        for (idx, window) in samples.chunks(samples_per_frame).enumerate() {
            let payload = state
                .encoder
                .encode(window)
                .map_err(AudioCodecError::from_backend)
                .map_err(CodecError::from)?;
            let offset =
                frame_step
                    .checked_mul(idx as u64)
                    .ok_or(CodecError::AudioTimestampOverflow(saturating_usize_to_u32(
                        idx,
                    )))?;
            let timestamp =
                timeline_start_ns
                    .checked_add(offset)
                    .ok_or(CodecError::AudioTimestampOverflow(saturating_usize_to_u32(
                        idx,
                    )))?;
            frames_out.push(AudioFrame {
                sequence: state.sequence,
                timestamp_ns: timestamp,
                fec_level: audio_cfg.fec_level,
                channel_layout: audio_cfg.layout,
                payload,
            });
            state.sequence = state
                .sequence
                .checked_add(1)
                .ok_or(CodecError::AudioSequenceOverflow)?;
        }
        let frames_per_segment =
            u16::try_from(frame_count).map_err(|_| CodecError::AudioFrameCountOverflow)?;
        let summary = AudioTrackSummary {
            sample_rate: audio_cfg.sample_rate,
            frame_samples: audio_cfg.frame_samples,
            frame_duration_ns: self.config.frame_duration_ns,
            frames_per_segment,
            layout: audio_cfg.layout,
            fec_level: audio_cfg.fec_level,
        };
        Ok(Some(SegmentAudio {
            summary,
            frames: frames_out,
        }))
    }
    pub fn encode_segment(
        &mut self,
        segment_number: u64,
        timeline_start_ns: u64,
        content_key_id: u64,
        frames: &[RawFrame],
        audio_pcm: Option<&[i16]>,
    ) -> Result<EncodedSegment, CodecError> {
        self.encode_segment_with_chroma(
            segment_number,
            timeline_start_ns,
            content_key_id,
            frames,
            None,
            audio_pcm,
        )
    }
    pub fn encode_segment_with_chroma(
        &mut self,
        segment_number: u64,
        timeline_start_ns: u64,
        content_key_id: u64,
        frames: &[RawFrame],
        chroma: Option<&[Chroma420Frame]>,
        audio_pcm: Option<&[i16]>,
    ) -> Result<EncodedSegment, CodecError> {
        if frames.is_empty() {
            return Err(CodecError::Segment(SegmentError::Chunk(
                ChunkError::EmptyTree,
            )));
        }
        let frame_count = checked_frame_count(frames.len())?;
        if let Some(chroma_frames) = chroma
            && chroma_frames.len() != frames.len()
        {
            return Err(CodecError::InvalidFrameLength(FrameLengthMismatch {
                expected: saturating_usize_to_u32(frames.len()),
                actual: saturating_usize_to_u32(chroma_frames.len()),
            }));
        }
        if chroma.is_some() {
            ensure_chroma_even_dimensions(self.config.frame_dimensions)?;
        }
        let dims = self.config.frame_dimensions;
        let frame_len = dims.pixel_count();
        let aligned_dims = dims.align_to_block();
        let blocks_per_frame = aligned_dims.block_count();
        let chunk_count_u16: u16 = blocks_per_frame.try_into().map_err(|_| {
            CodecError::BlockCountMismatch(BlockCountMismatchInfo {
                expected: saturating_usize_to_u32(blocks_per_frame),
                found: u32::MAX,
            })
        })?;
        let frame_step = u64::from(self.config.frame_duration_ns);
        let chroma_frames = chroma.unwrap_or(&[]);
        let chroma_dims = FrameDimensions::new(dims.width / 2, dims.height / 2);
        let chroma_aligned = chroma_dims.align_to_block();
        let mut chunks = Vec::with_capacity(frames.len());
        let mut reconstructed_prev: Option<Vec<u8>> = None;
        let mut previous_chroma_u: Option<Vec<u8>> = None;
        let mut previous_chroma_v: Option<Vec<u8>> = None;
        let mut bundler = self.config.entropy_mode.is_bundled().then(|| {
            let width = self
                .config
                .bundle_width
                .min(self.bundle_tables.max_width())
                .max(1);
            BundleStreamRecorder::new(
                width,
                aligned_dims,
                self.config.quantizer,
                self.bundle_tables.clone(),
                self.config.bundle_acceleration,
                self.config.bundle_prefetch_distance,
                self.config.bundle_context_remap.clone(),
            )
        });
        let mut rdo_builder =
            RdoTelemetryBuilder::new(self.config.rdo_mode, self.rdo_lambda, NEURAL_OUTPUT);
        let mut noop_hooks = NoopBundledHooks;
        for (idx, frame) in frames.iter().enumerate() {
            if frame.luma.len() != frame_len {
                return Err(CodecError::InvalidFrameLength(FrameLengthMismatch {
                    expected: saturating_usize_to_u32(frame_len),
                    actual: saturating_usize_to_u32(frame.luma.len()),
                }));
            }
            let padded_storage = if dims == aligned_dims {
                None
            } else {
                Some(pad_frame_luma(&frame.luma, dims, aligned_dims))
            };
            let frame_slice: &[u8] = if let Some(ref buf) = padded_storage {
                buf.as_slice()
            } else {
                frame.luma.as_slice()
            };
            let frame_type = if idx == 0 {
                FrameType::Intra
            } else {
                FrameType::Predicted
            };
            let idx_delta = frame_step
                .checked_mul(idx as u64)
                .ok_or(CodecError::FramePtsOverflow(saturating_usize_to_u32(idx)))?;
            let pts = timeline_start_ns
                .checked_add(idx_delta)
                .ok_or(CodecError::FramePtsOverflow(saturating_usize_to_u32(idx)))?;
            let prev_ref = reconstructed_prev.as_deref();
            let hooks: &mut dyn BundledHooks = bundler
                .as_mut()
                .map(|rec| rec as &mut dyn BundledHooks)
                .unwrap_or(&mut noop_hooks);
            let (payload, recon) = Self::encode_frame_payload(
                frame_slice,
                frame_type,
                prev_ref,
                aligned_dims,
                self.config.quantizer,
                hooks,
                rdo_builder.as_mut(),
                self.neural_predictor.as_ref(),
                self.config.bundle_width,
                self.config.rdo_mode,
            )?;
            let chroma_planes = chroma_frames.get(idx);
            let mut chunk = Vec::with_capacity(
                FRAME_HEADER_LEN
                    + payload.len()
                    + chroma_planes
                        .map(|planes| planes.u.len().saturating_add(planes.v.len()) + 8)
                        .unwrap_or(0),
            );
            chunk.extend_from_slice(&(idx as u32).to_le_bytes());
            chunk.extend_from_slice(&pts.to_le_bytes());
            chunk.push(frame_type.as_byte());
            chunk.push(self.config.quantizer);
            chunk.extend_from_slice(&chunk_count_u16.to_le_bytes());
            chunk.extend_from_slice(&payload);
            if let Some(planes) = chroma_planes {
                let expected_chroma_len = chroma_dims.pixel_count();
                if planes.u.len() != expected_chroma_len || planes.v.len() != expected_chroma_len {
                    return Err(CodecError::InvalidFrameLength(FrameLengthMismatch {
                        expected: saturating_usize_to_u32(expected_chroma_len),
                        actual: saturating_usize_to_u32(planes.u.len().max(planes.v.len())),
                    }));
                }
                let padded_u = if chroma_dims == chroma_aligned {
                    None
                } else {
                    Some(pad_frame_luma(&planes.u, chroma_dims, chroma_aligned))
                };
                let padded_v = if chroma_dims == chroma_aligned {
                    None
                } else {
                    Some(pad_frame_luma(&planes.v, chroma_dims, chroma_aligned))
                };
                let (u_payload, u_recon) = Self::encode_frame_payload(
                    padded_u
                        .as_ref()
                        .map_or_else(|| planes.u.as_slice(), Vec::as_slice),
                    frame_type,
                    previous_chroma_u.as_deref(),
                    chroma_aligned,
                    self.config.quantizer,
                    &mut noop_hooks,
                    None,
                    None,
                    1,
                    RdoMode::None,
                )?;
                let (v_payload, v_recon) = Self::encode_frame_payload(
                    padded_v
                        .as_ref()
                        .map_or_else(|| planes.v.as_slice(), Vec::as_slice),
                    frame_type,
                    previous_chroma_v.as_deref(),
                    chroma_aligned,
                    self.config.quantizer,
                    &mut noop_hooks,
                    None,
                    None,
                    1,
                    RdoMode::None,
                )?;
                previous_chroma_u = Some(u_recon);
                previous_chroma_v = Some(v_recon);
                chunk.extend_from_slice(&(u_payload.len() as u32).to_le_bytes());
                chunk.extend_from_slice(&(v_payload.len() as u32).to_le_bytes());
                chunk.extend_from_slice(&u_payload);
                chunk.extend_from_slice(&v_payload);
            } else {
                previous_chroma_u = None;
                previous_chroma_v = None;
            }
            chunks.push(chunk);
            reconstructed_prev = Some(recon);
        }
        let rdo_report = rdo_builder.and_then(RdoTelemetryBuilder::finish);
        self.bundled_telemetry = bundler.map(|rec| {
            let mut telemetry = rec.finish();
            telemetry.rdo = rdo_report;
            telemetry
        });
        let offsets_and_lengths = compute_offsets(&chunks);
        let chunk_ids: Vec<u16> = (0..frame_count).collect();
        let nonce_salt = derive_nonce_salt(segment_number, frames.len(), &chunks);
        let payload_refs: Vec<(u16, &[u8])> = chunk_ids
            .iter()
            .zip(chunks.iter())
            .map(|(id, payload)| (*id, payload.as_slice()))
            .collect();
        let commitments = chunk_commitments(segment_number, &payload_refs);
        let root = merkle_root(&commitments)
            .map_err(SegmentError::from)
            .map_err(CodecError::from)?;
        let audio =
            self.encode_audio_track(audio_pcm, frames.len(), timeline_start_ns, frame_step)?;
        let descriptors: Vec<ChunkDescriptor> = offsets_and_lengths
            .into_iter()
            .zip(commitments.iter())
            .zip(chunk_ids.iter())
            .map(|((meta, commitment), chunk_id)| ChunkDescriptor {
                chunk_id: *chunk_id,
                offset: meta.offset,
                length: meta.length,
                commitment: *commitment,
                parity: false,
            })
            .collect();
        let entropy_tables_checksum = self
            .config
            .entropy_mode
            .is_bundled()
            .then(|| self.bundle_tables.checksum());
        let header = SegmentHeader {
            segment_number,
            profile: self.config.profile,
            entropy_mode: self.config.entropy_mode,
            entropy_tables_checksum,
            encryption_suite: self.config.encryption_suite,
            layer_bitmap: self.config.layer_bitmap,
            chunk_merkle_root: root,
            chunk_count: frame_count,
            timeline_start_ns,
            duration_ns: if self.config.duration_ns == 0 {
                self.config
                    .frame_duration_ns
                    .saturating_mul(frames.len() as u32)
                    .max(1)
            } else {
                self.config.duration_ns
            },
            feedback_hint: self.config.feedback_hint.clone(),
            content_key_id,
            nonce_salt,
            storage_class: self.config.storage_class,
            audio_summary: audio.as_ref().map(|track| track.summary),
            bundle_acceleration: self.config.bundle_acceleration,
        };
        Ok(EncodedSegment {
            header,
            descriptors,
            chunks,
            audio,
        })
    }
    #[allow(clippy::too_many_arguments)]
    fn encode_frame_payload(
        frame: &[u8],
        frame_type: FrameType,
        prev_frame: Option<&[u8]>,
        dims: FrameDimensions,
        quantizer: u8,
        hooks: &mut dyn BundledHooks,
        mut rdo: Option<&mut RdoTelemetryBuilder>,
        neural_predictor: Option<&NeuralPredictor>,
        bundle_width: u8,
        rdo_mode: RdoMode,
    ) -> Result<(Vec<u8>, Vec<u8>), CodecError> {
        debug_assert_eq!(frame.len(), dims.pixel_count());
        let mut payload = Vec::with_capacity(frame.len() / 2);
        let mut reconstructed = vec![0u8; dims.pixel_count()];
        let mut prev_dc = 0i16;
        if frame_type.reset_dc() {
            prev_dc = 0;
        }
        for block_index in 0..dims.block_count() {
            let (residual, predictor) =
                build_residual_block(frame, prev_frame, dims, block_index, frame_type);
            let coeffs = forward_dct(&residual);
            let mut quantized = quantize_coeffs(&coeffs, quantizer);
            if let Some(builder) = rdo.as_deref_mut() {
                let report = optimize_block_dp(
                    &mut quantized,
                    rdo_mode,
                    builder.lambda_bits,
                    neural_predictor,
                    bundle_width,
                    quantizer,
                    frame_type,
                    block_index,
                );
                builder.record(&report);
            }
            encode_block_rle(
                &quantized,
                &mut prev_dc,
                &mut payload,
                hooks,
                block_index,
                frame_type,
            );
            let dequantized = dequantize_coeffs(&quantized, quantizer);
            let spatial = inverse_dct(&dequantized);
            write_reconstructed_block(&mut reconstructed, &spatial, &predictor, dims, block_index);
        }
        Ok((payload, reconstructed))
    }
}
pub(crate) fn block_origin(dims: FrameDimensions, block_index: usize) -> (usize, usize) {
    let blocks_per_row = dims.width as usize / BLOCK_SIZE;
    let row = block_index / blocks_per_row;
    let col = block_index % blocks_per_row;
    (col * BLOCK_SIZE, row * BLOCK_SIZE)
}
pub(crate) fn build_residual_block(
    frame: &[u8],
    prev_frame: Option<&[u8]>,
    dims: FrameDimensions,
    block_index: usize,
    frame_type: FrameType,
) -> ([i16; BLOCK_PIXELS], [i16; BLOCK_PIXELS]) {
    let mut residual = [0i16; BLOCK_PIXELS];
    let mut predictor = [0i16; BLOCK_PIXELS];
    let (origin_x, origin_y) = block_origin(dims, block_index);
    let stride = dims.width as usize;
    for y in 0..BLOCK_SIZE {
        for x in 0..BLOCK_SIZE {
            let idx = (origin_y + y) * stride + (origin_x + x);
            let pixel = frame[idx] as i16;
            let pred = if let (FrameType::Predicted, Some(prev)) = (frame_type, prev_frame) {
                prev[idx] as i16
            } else {
                0
            };
            predictor[y * BLOCK_SIZE + x] = pred;
            residual[y * BLOCK_SIZE + x] = pixel - pred;
        }
    }
    (residual, predictor)
}
pub(crate) fn predictor_block(
    prev_frame: Option<&[u8]>,
    dims: FrameDimensions,
    block_index: usize,
    frame_type: FrameType,
) -> [i16; BLOCK_PIXELS] {
    if let (FrameType::Predicted, Some(prev)) = (frame_type, prev_frame) {
        let mut predictor = [0i16; BLOCK_PIXELS];
        let (origin_x, origin_y) = block_origin(dims, block_index);
        let stride = dims.width as usize;
        for y in 0..BLOCK_SIZE {
            for x in 0..BLOCK_SIZE {
                let idx = (origin_y + y) * stride + (origin_x + x);
                predictor[y * BLOCK_SIZE + x] = prev[idx] as i16;
            }
        }
        predictor
    } else {
        [0i16; BLOCK_PIXELS]
    }
}
pub(crate) fn write_reconstructed_block(
    reconstructed: &mut [u8],
    spatial: &[i32; BLOCK_PIXELS],
    predictor: &[i16; BLOCK_PIXELS],
    dims: FrameDimensions,
    block_index: usize,
) {
    let (origin_x, origin_y) = block_origin(dims, block_index);
    let stride = dims.width as usize;
    for y in 0..BLOCK_SIZE {
        for x in 0..BLOCK_SIZE {
            let idx = (origin_y + y) * stride + (origin_x + x);
            let sample_idx = y * BLOCK_SIZE + x;
            let predicted = predictor[sample_idx] as i32;
            reconstructed[idx] = clamp_pixel(spatial[sample_idx] + predicted);
        }
    }
}
#[cfg(test)]
mod block_tests {
    use super::*;
    fn linear_frame(dims: FrameDimensions, offset: u8) -> Vec<u8> {
        (0..dims.pixel_count())
            .map(|idx| offset.wrapping_add(idx as u8))
            .collect()
    }
    fn block_pixels(frame: &[u8], dims: FrameDimensions, block_index: usize) -> Vec<u8> {
        let (origin_x, origin_y) = block_origin(dims, block_index);
        let stride = dims.width as usize;
        let mut out = Vec::with_capacity(BLOCK_PIXELS);
        for y in 0..BLOCK_SIZE {
            for x in 0..BLOCK_SIZE {
                let idx = (origin_y + y) * stride + (origin_x + x);
                out.push(frame[idx]);
            }
        }
        out
    }
    #[test]
    fn block_origin_maps_index_to_coordinates() {
        let dims = FrameDimensions::new(16, 16);
        assert_eq!(block_origin(dims, 0), (0, 0));
        assert_eq!(block_origin(dims, 1), (BLOCK_SIZE, 0));
        assert_eq!(block_origin(dims, 2), (0, BLOCK_SIZE));
        assert_eq!(block_origin(dims, 3), (BLOCK_SIZE, BLOCK_SIZE));
    }
    #[test]
    fn build_residual_block_tracks_previous_frame_for_predicted() {
        let dims = FrameDimensions::new(16, 8);
        let prev = linear_frame(dims, 5);
        let current: Vec<u8> = prev.iter().map(|value| value.saturating_add(2)).collect();
        let (residual, predictor) =
            build_residual_block(&current, Some(&prev), dims, 1, FrameType::Predicted);
        assert!(residual.iter().all(|&value| value == 2));
        let expected_block = block_pixels(&prev, dims, 1);
        for (actual, expected) in predictor.iter().zip(expected_block) {
            assert_eq!(*actual, i16::from(expected));
        }
    }
    #[test]
    fn build_residual_block_resets_predictor_for_intra_frames() {
        let dims = FrameDimensions::new(8, 8);
        let current = linear_frame(dims, 10);
        let prev = linear_frame(dims, 3);
        let (residual, predictor) =
            build_residual_block(&current, Some(&prev), dims, 0, FrameType::Intra);
        assert!(predictor.iter().all(|&value| value == 0));
        for (idx, &value) in residual.iter().enumerate() {
            assert_eq!(value, i16::from(current[idx]));
        }
    }
    #[test]
    fn predictor_block_only_uses_previous_frame_for_predicted() {
        let dims = FrameDimensions::new(16, 8);
        let prev = linear_frame(dims, 7);
        let predicted = predictor_block(Some(&prev), dims, 1, FrameType::Predicted);
        let expected_block = block_pixels(&prev, dims, 1);
        for (actual, expected) in predicted.iter().zip(expected_block) {
            assert_eq!(*actual, i16::from(expected));
        }
        let intra = predictor_block(Some(&prev), dims, 1, FrameType::Intra);
        assert!(intra.iter().all(|&value| value == 0));
    }
    #[test]
    fn write_reconstructed_block_clamps_and_combines_samples() {
        let dims = FrameDimensions::new(8, 8);
        let mut reconstructed = vec![0u8; dims.pixel_count()];
        let mut spatial = [20i32; BLOCK_PIXELS];
        spatial[0] = 400;
        spatial[1] = -400;
        let mut predictor = [10i16; BLOCK_PIXELS];
        predictor[2] = 5;
        write_reconstructed_block(&mut reconstructed, &spatial, &predictor, dims, 0);
        assert_eq!(reconstructed[0], 255, "values above 255 must clamp");
        assert_eq!(reconstructed[1], 0, "values below 0 must clamp");
        assert_eq!(reconstructed[2], 25);
        assert_eq!(reconstructed[3], 30);
    }
    #[cfg(feature = "streaming-neural-filter")]
    #[test]
    fn neural_filter_is_deterministic_and_effectful() {
        let dims = FrameDimensions::new(4, 4);
        let mut frame: Vec<u8> = (0..dims.pixel_count())
            .map(|idx| (idx as u8).saturating_mul(3))
            .collect();
        let mut second = frame.clone();
        apply_neural_filter(&mut frame, dims);
        apply_neural_filter(&mut second, dims);
        assert_eq!(frame, second, "neural filter must be deterministic");
        let untouched: Vec<u8> = (0..dims.pixel_count())
            .map(|idx| (idx as u8).saturating_mul(3))
            .collect();
        assert_ne!(frame, untouched, "neural filter should change the frame");
    }
}
/// Deterministic scalar fixed-point DCT used as the cross-hardware reference.
/// Accelerated variants must prove bit-exact parity against this path.
#[cfg(feature = "streaming-fixed-point-dct")]
pub(crate) fn forward_dct(block: &[i16; BLOCK_PIXELS]) -> [i32; BLOCK_PIXELS] {
    let mut out = [0i32; BLOCK_PIXELS];
    for u in 0..8 {
        for v in 0..8 {
            let mut sum: i64 = 0;
            for x in 0..8 {
                for y in 0..8 {
                    let sample = i64::from(block[x * 8 + y]);
                    let factor_u = i64::from(DCT_FACTORS_Q15[u][x]);
                    let factor_v = i64::from(DCT_FACTORS_Q15[v][y]);
                    sum = sum
                        .saturating_add(sample.saturating_mul(factor_u).saturating_mul(factor_v));
                }
            }
            let rounded = if sum >= 0 {
                (sum + DCT_ROUND) >> DCT_SHIFT
            } else {
                (sum - DCT_ROUND) >> DCT_SHIFT
            };
            out[u * 8 + v] = rounded as i32;
        }
    }
    out
}
#[cfg(not(feature = "streaming-fixed-point-dct"))]
pub(crate) fn forward_dct(block: &[i16; BLOCK_PIXELS]) -> [i32; BLOCK_PIXELS] {
    let mut out = [0i32; BLOCK_PIXELS];
    for u in 0..8 {
        for v in 0..8 {
            let mut sum = 0.0;
            for x in 0..8 {
                for y in 0..8 {
                    let sample = block[x * 8 + y] as f64;
                    sum += sample * DCT_FACTORS[u][x] * DCT_FACTORS[v][y];
                }
            }
            out[u * 8 + v] = sum.round() as i32;
        }
    }
    out
}
#[cfg(feature = "streaming-fixed-point-dct")]
pub(crate) fn inverse_dct(coeffs: &[i32; BLOCK_PIXELS]) -> [i32; BLOCK_PIXELS] {
    let mut out = [0i32; BLOCK_PIXELS];
    for x in 0..8 {
        for y in 0..8 {
            let mut sum: i64 = 0;
            for u in 0..8 {
                for v in 0..8 {
                    let coeff = i64::from(coeffs[u * 8 + v]);
                    let factor_u = i64::from(DCT_FACTORS_Q15[u][x]);
                    let factor_v = i64::from(DCT_FACTORS_Q15[v][y]);
                    sum =
                        sum.saturating_add(coeff.saturating_mul(factor_u).saturating_mul(factor_v));
                }
            }
            let rounded = if sum >= 0 {
                (sum + DCT_ROUND) >> DCT_SHIFT
            } else {
                (sum - DCT_ROUND) >> DCT_SHIFT
            };
            out[x * 8 + y] = rounded.clamp(-32768, 32767) as i32;
        }
    }
    out
}
#[cfg(not(feature = "streaming-fixed-point-dct"))]
pub(crate) fn inverse_dct(coeffs: &[i32; BLOCK_PIXELS]) -> [i32; BLOCK_PIXELS] {
    let mut out = [0i32; BLOCK_PIXELS];
    for x in 0..8 {
        for y in 0..8 {
            let mut sum = 0.0;
            for u in 0..8 {
                for v in 0..8 {
                    let coeff = coeffs[u * 8 + v] as f64;
                    sum += coeff * DCT_FACTORS[u][x] * DCT_FACTORS[v][y];
                }
            }
            out[x * 8 + y] = sum.round().clamp(-32768.0, 32767.0) as i32;
        }
    }
    out
}
fn qp_scale(quantizer: u8) -> i32 {
    (quantizer as i32).max(1)
}
pub(crate) fn quantize_coeffs(coeffs: &[i32; BLOCK_PIXELS], quantizer: u8) -> [i16; BLOCK_PIXELS] {
    let mut out = [0i16; BLOCK_PIXELS];
    if quantizer == 0 {
        for (idx, coeff) in coeffs.iter().enumerate() {
            out[idx] = (*coeff).clamp(i16::MIN as i32, i16::MAX as i32) as i16;
        }
        return out;
    }
    let scale = qp_scale(quantizer);
    for (idx, coeff) in coeffs.iter().enumerate() {
        let step = (i32::from(BASELINE_QUANT_MATRIX[idx]).max(1)) * scale;
        let adjusted = if *coeff >= 0 {
            coeff.saturating_add(step / 2)
        } else {
            coeff.saturating_sub(step / 2)
        };
        let quantized = adjusted / step;
        out[idx] = quantized.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
    }
    out
}
pub(crate) fn dequantize_coeffs(
    coeffs: &[i16; BLOCK_PIXELS],
    quantizer: u8,
) -> [i32; BLOCK_PIXELS] {
    let mut out = [0i32; BLOCK_PIXELS];
    if quantizer == 0 {
        for (idx, coeff) in coeffs.iter().enumerate() {
            out[idx] = i32::from(*coeff);
        }
        return out;
    }
    let scale = qp_scale(quantizer);
    for (idx, coeff) in coeffs.iter().enumerate() {
        let step = (i32::from(BASELINE_QUANT_MATRIX[idx]).max(1)) * scale;
        out[idx] = i32::from(*coeff) * step;
    }
    out
}
pub(crate) trait BundledHooks {
    fn record_dc(&mut self, _diff: i16) {}
    fn record_ac(&mut self, _zeros: u8, _value: i16) {}
    fn record_eob(&mut self) {}
    fn record_block_coeffs(
        &mut self,
        _coeffs: &[i16; BLOCK_PIXELS],
        _block_index: usize,
        _frame_type: FrameType,
    ) {
    }
}
#[derive(Default)]
struct NoopBundledHooks;
impl BundledHooks for NoopBundledHooks {}
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::codec::BundledStats")]
#[derive(Clone, Copy, Debug, Default, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct BundledStats {
    pub bundle_width: u8,
    pub bundles_total: u64,
    pub blocks_encoded: u64,
    pub significance_zero: u64,
    pub significance_one: u64,
    pub sign_negative: u64,
    pub sign_positive: u64,
    pub parity_one: u64,
    pub geq2_one: u64,
    pub dc_events: u64,
    pub ac_events: u64,
    pub nonzero_levels: u64,
    pub zero_run_total: u64,
    pub max_zero_run: u8,
    #[norito(default)]
    pub significance_rle: u64,
    pub flush_type_complete: u64,
    pub flush_context_switch: u64,
    pub flush_end_of_block: u64,
}
impl BundledStats {
    fn record_flush(&mut self, reason: BundleFlushReason) {
        match reason {
            BundleFlushReason::TypeComplete => {
                self.flush_type_complete = self.flush_type_complete.saturating_add(1);
            }
            BundleFlushReason::ContextSwitch => {
                self.flush_context_switch = self.flush_context_switch.saturating_add(1);
            }
            BundleFlushReason::EndOfBlock => {
                self.flush_end_of_block = self.flush_end_of_block.saturating_add(1);
            }
        }
    }
}
pub(crate) const RDO_BUCKET_COUNT: usize = 5;
pub(crate) const RDO_MAX_SYMBOLS: usize = 1 << MAX_BUNDLE_WIDTH;
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::codec::RdoTelemetry")]
#[derive(Clone, Debug, Default, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct RdoTelemetry {
    pub mode: RdoMode,
    pub lambda_bits: f32,
    pub blocks_optimized: u64,
    pub energy_histogram: [u64; RDO_BUCKET_COUNT],
    pub before_rate_bits: u64,
    pub after_rate_bits: u64,
    pub distortion_penalty: u64,
    pub neural_class_histogram: Vec<u64>,
}
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::codec::ContextFrequency")]
#[derive(Clone, Copy, Debug, Default, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct ContextFrequency {
    pub context: BundleContextId,
    pub bundles: u64,
    pub total_bits: u64,
    pub symbol_counts: [u64; RDO_MAX_SYMBOLS],
}
/// Summary describing the context remap applied during bundle recording.
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::codec::ContextRemapSummary")]
#[derive(Clone, Copy, Debug, Default, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct ContextRemapSummary {
    pub escape_context: BundleContextId,
    pub remapped: u32,
    pub dropped: u32,
}
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::codec::BundledTelemetry")]
#[derive(Clone, Debug, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct BundledTelemetry {
    pub stats: BundledStats,
    pub tokens: Vec<BundledToken>,
    pub bundles: Vec<BundleRecord>,
    pub context_stats: Vec<BundleContextStats>,
    pub context_frequencies: Vec<ContextFrequency>,
    pub ans_stream: Vec<u8>,
    pub ans_precision_bits: u8,
    pub tables_checksum: Hash,
    #[norito(default)]
    pub acceleration: BundleAcceleration,
    #[norito(default)]
    pub prefetch_distance: u16,
    #[norito(skip_serializing_if = "Option::is_none")]
    #[norito(default)]
    pub context_remap: Option<ContextRemapSummary>,
    #[norito(skip_serializing_if = "Option::is_none")]
    #[norito(default)]
    pub rdo: Option<RdoTelemetry>,
}
impl BundledTelemetry {
    /// Decode the ANS stream into bundle symbols using the supplied tables.
    pub fn decode_symbols(&self, tables: &BundleAnsTables) -> Result<Vec<u8>, BundleDecodeError> {
        if self.tables_checksum != tables.checksum() {
            return Err(BundleDecodeError::ChecksumMismatch {
                expected: self.tables_checksum,
                found: tables.checksum(),
            });
        }
        decode_bundle_stream(&self.ans_stream, &self.bundles, tables)
    }
    /// Verify that the ANS stream reproduces the recorded bundle bits.
    pub fn verify_stream(&self, tables: &BundleAnsTables) -> Result<(), BundleDecodeError> {
        let decoded = self.decode_symbols(tables)?;
        for (idx, (record, decoded_bits)) in self.bundles.iter().zip(decoded.iter()).enumerate() {
            let mask = (1u8 << record.bit_len) - 1;
            let expected = record.bits & mask;
            let found = decoded_bits & mask;
            if expected != found {
                return Err(BundleDecodeError::SymbolMismatch {
                    index: saturating_usize_to_u32(idx),
                    expected,
                    found,
                });
            }
        }
        Ok(())
    }
}
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::codec::BundledToken")]
#[derive(Clone, Copy, Debug, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::TypeId))]
pub enum BundledToken {
    DcDiff(i16),
    Ac { run: u8, value: i16 },
    EndOfBlock,
}
#[cfg(feature = "schema-structural")]
#[derive(::iroha_schema::IntoSchema)]
#[allow(dead_code)]
struct BundledAcTokenSchema {
    run: u8,
    value: i16,
}
#[cfg(feature = "schema-structural")]
impl ::iroha_schema::IntoSchema for BundledToken {
    fn type_name() -> String {
        "BundledToken".to_owned()
    }
    fn update_schema_map(map: &mut ::iroha_schema::MetaMap) {
        if map.contains_key::<Self>() {
            return;
        }
        map.insert::<Self>(::iroha_schema::Metadata::Enum(::iroha_schema::EnumMeta {
            variants: vec![
                ::iroha_schema::EnumVariant {
                    tag: "DcDiff".to_owned(),
                    discriminant: 0,
                    ty: Some(core::any::TypeId::of::<i16>()),
                },
                ::iroha_schema::EnumVariant {
                    tag: "Ac".to_owned(),
                    discriminant: 1,
                    ty: Some(core::any::TypeId::of::<BundledAcTokenSchema>()),
                },
                ::iroha_schema::EnumVariant {
                    tag: "EndOfBlock".to_owned(),
                    discriminant: 2,
                    ty: None,
                },
            ],
        }));
        <i16 as ::iroha_schema::IntoSchema>::update_schema_map(map);
        <BundledAcTokenSchema as ::iroha_schema::IntoSchema>::update_schema_map(map);
    }
}
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::codec::BundleType")]
#[derive(Clone, Copy, Debug, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub enum BundleType {
    SignificanceOnly,
    SignAndMagnitude,
    SignParity,
    SignParityLevel,
    SignificanceRle,
}
impl BundleType {
    const fn as_u8(self) -> u8 {
        match self {
            Self::SignificanceOnly => 0,
            Self::SignAndMagnitude => 1,
            Self::SignParity => 2,
            Self::SignParityLevel => 3,
            Self::SignificanceRle => 4,
        }
    }
}
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::codec::BundleFlushReason")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub enum BundleFlushReason {
    TypeComplete,
    ContextSwitch,
    EndOfBlock,
}
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::codec::BundleContextId")]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    NoritoSerialize,
    NoritoDeserialize,
)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct BundleContextId(pub u16);
impl BundleContextId {
    pub const fn new(raw: u16) -> Self {
        Self(raw)
    }
}
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::codec::BundleRecord")]
#[derive(Clone, Copy, Debug, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct BundleRecord {
    pub bundle_type: BundleType,
    pub context: BundleContextId,
    pub bits: u8,
    pub bit_len: u8,
    pub flush: BundleFlushReason,
}
#[derive(crate::NoritoSchema)]
#[norito_schema(name = "norito::streaming::codec::BundleContextStats")]
#[derive(Clone, Copy, Debug, NoritoSerialize, NoritoDeserialize)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct BundleContextStats {
    pub context: BundleContextId,
    pub bundles_total: u64,
    pub type_significance_only: u64,
    pub type_sign_and_magnitude: u64,
    pub type_sign_parity: u64,
    pub type_sign_parity_level: u64,
    #[norito(default)]
    pub type_significance_rle: u64,
    pub flush_type_complete: u64,
    pub flush_context_switch: u64,
    pub flush_end_of_block: u64,
}
impl BundleContextStats {
    const fn new(context: BundleContextId) -> Self {
        Self {
            context,
            bundles_total: 0,
            type_significance_only: 0,
            type_sign_and_magnitude: 0,
            type_sign_parity: 0,
            type_sign_parity_level: 0,
            type_significance_rle: 0,
            flush_type_complete: 0,
            flush_context_switch: 0,
            flush_end_of_block: 0,
        }
    }
    fn record_bundle(&mut self, bundle_type: BundleType, flush: BundleFlushReason) {
        self.bundles_total = self.bundles_total.saturating_add(1);
        match bundle_type {
            BundleType::SignificanceOnly => {
                self.type_significance_only = self.type_significance_only.saturating_add(1);
            }
            BundleType::SignAndMagnitude => {
                self.type_sign_and_magnitude = self.type_sign_and_magnitude.saturating_add(1);
            }
            BundleType::SignParity => {
                self.type_sign_parity = self.type_sign_parity.saturating_add(1);
            }
            BundleType::SignParityLevel => {
                self.type_sign_parity_level = self.type_sign_parity_level.saturating_add(1);
            }
            BundleType::SignificanceRle => {
                self.type_significance_rle = self.type_significance_rle.saturating_add(1);
            }
        }
        self.record_flush(flush);
    }
    fn record_flush(&mut self, flush: BundleFlushReason) {
        match flush {
            BundleFlushReason::TypeComplete => {
                self.flush_type_complete = self.flush_type_complete.saturating_add(1);
            }
            BundleFlushReason::ContextSwitch => {
                self.flush_context_switch = self.flush_context_switch.saturating_add(1);
            }
            BundleFlushReason::EndOfBlock => {
                self.flush_end_of_block = self.flush_end_of_block.saturating_add(1);
            }
        }
    }
}
#[derive(Clone, Copy)]
struct DpReport {
    energy: u32,
    before_bits: u64,
    after_bits: u64,
    distortion_penalty: u64,
    neural_class: Option<usize>,
}
struct RdoTelemetryBuilder {
    mode: RdoMode,
    lambda_bits: f32,
    energy_histogram: [u64; RDO_BUCKET_COUNT],
    before_bits: u64,
    after_bits: u64,
    distortion_penalty: u64,
    neural_histogram: Vec<u64>,
    blocks: u64,
}
impl RdoTelemetryBuilder {
    fn new(mode: RdoMode, lambda_bits: f32, neural_classes: usize) -> Option<Self> {
        if !mode.is_enabled() {
            return None;
        }
        let mut neural_histogram = Vec::new();
        if matches!(mode, RdoMode::Neural) && neural_classes > 0 {
            neural_histogram.resize(neural_classes, 0);
        }
        Some(Self {
            mode,
            lambda_bits,
            energy_histogram: [0; RDO_BUCKET_COUNT],
            before_bits: 0,
            after_bits: 0,
            distortion_penalty: 0,
            neural_histogram,
            blocks: 0,
        })
    }
    fn record(&mut self, report: &DpReport) {
        let bucket = energy_bucket(report.energy);
        if let Some(slot) = self.energy_histogram.get_mut(bucket) {
            *slot = slot.saturating_add(1);
        }
        self.before_bits = self.before_bits.saturating_add(report.before_bits);
        self.after_bits = self.after_bits.saturating_add(report.after_bits);
        self.distortion_penalty = self
            .distortion_penalty
            .saturating_add(report.distortion_penalty);
        if let Some(class) = report.neural_class
            && let Some(slot) = self.neural_histogram.get_mut(class)
        {
            *slot = slot.saturating_add(1);
        }
        self.blocks = self.blocks.saturating_add(1);
    }
    fn finish(self) -> Option<RdoTelemetry> {
        Some(RdoTelemetry {
            mode: self.mode,
            lambda_bits: self.lambda_bits,
            blocks_optimized: self.blocks,
            energy_histogram: self.energy_histogram,
            before_rate_bits: self.before_bits,
            after_rate_bits: self.after_bits,
            distortion_penalty: self.distortion_penalty,
            neural_class_histogram: self.neural_histogram,
        })
    }
}
const fn energy_bucket(energy: u32) -> usize {
    let mut idx = 0usize;
    while idx < RDO_ENERGY_BUCKETS.len() {
        if energy <= RDO_ENERGY_BUCKETS[idx] {
            return idx;
        }
        idx += 1;
    }
    RDO_BUCKET_COUNT - 1
}
fn rdo_lambda_for_mode(mode: RdoMode, quantizer: u8) -> f32 {
    match mode {
        RdoMode::Perceptual => rdo_lambda_perceptual(quantizer),
        _ => rdo_lambda_for_quantizer(quantizer),
    }
}
fn rdo_lambda_for_quantizer(quantizer: u8) -> f32 {
    match quantizer_to_bucket(quantizer) {
        0 => 0.45,
        1 => 0.75,
        2 => 1.1,
        _ => 1.35,
    }
}
fn rdo_lambda_perceptual(quantizer: u8) -> f32 {
    // Slightly soften lambda at mid/high Q to favour structure (SSIM proxy) while
    // keeping low-Q output close to the rate-focused schedule.
    match quantizer_to_bucket(quantizer) {
        0 => 0.42,
        1 => 0.65,
        2 => 0.95,
        _ => 1.15,
    }
}
fn block_energy(coeffs: &[i16; BLOCK_PIXELS]) -> u32 {
    coeffs
        .iter()
        .enumerate()
        .skip(1)
        .map(|(_, &coeff)| coeff.unsigned_abs())
        .map(u32::from)
        .sum()
}
fn max_zero_run_in_block(coeffs: &[i16; BLOCK_PIXELS]) -> u8 {
    let mut max_run = 0u8;
    let mut run = 0u8;
    for &slot in ZIG_ZAG.iter().skip(1) {
        if coeffs[slot] == 0 {
            run = run.saturating_add(1);
            max_run = max_run.max(run);
        } else {
            run = 0;
        }
    }
    max_run
}
fn estimate_rle_bits(coeffs: &[i16; BLOCK_PIXELS]) -> u64 {
    let mut pos = 1usize;
    let mut bits = 0u64;
    while pos < BLOCK_PIXELS {
        let mut zero_run = 0usize;
        while pos < BLOCK_PIXELS && coeffs[ZIG_ZAG[pos]] == 0 {
            zero_run = zero_run.saturating_add(1);
            pos = pos.saturating_add(1);
        }
        if pos == BLOCK_PIXELS {
            bits = bits.saturating_add(RLE_TOKEN_BITS);
            break;
        }
        while zero_run > MAX_ZERO_RUN {
            bits = bits.saturating_add(RLE_TOKEN_BITS);
            zero_run = zero_run.saturating_sub(MAX_ZERO_RUN);
        }
        bits = bits.saturating_add(RLE_TOKEN_BITS);
        pos = pos.saturating_add(1);
    }
    bits
}
fn token_rate_bits(zero_run: usize) -> f32 {
    let mut tokens = 1u32;
    let mut run = zero_run;
    while run > MAX_ZERO_RUN {
        tokens = tokens.saturating_add(1);
        run = run.saturating_sub(MAX_ZERO_RUN);
    }
    tokens as f32 * RLE_TOKEN_BITS_F
}
#[allow(clippy::too_many_arguments)]
fn optimize_block_dp(
    coeffs: &mut [i16; BLOCK_PIXELS],
    mode: RdoMode,
    lambda_bits: f32,
    predictor: Option<&NeuralPredictor>,
    bundle_width: u8,
    quantizer: u8,
    frame_type: FrameType,
    block_index: usize,
) -> DpReport {
    let original = *coeffs;
    let energy = block_energy(&original);
    if !mode.is_enabled() {
        return DpReport {
            energy,
            before_bits: estimate_rle_bits(&original),
            after_bits: estimate_rle_bits(coeffs),
            distortion_penalty: 0,
            neural_class: None,
        };
    }
    let mut lambda = lambda_bits;
    let mut neural_class = None;
    if matches!(mode, RdoMode::Neural)
        && let Some(net) = predictor
    {
        let features = build_neural_features(
            &original,
            energy,
            bundle_width,
            quantizer,
            frame_type,
            block_index,
        );
        let class_idx = net.predict(&features);
        neural_class = Some(class_idx);
        lambda *= match class_idx {
            0 => 0.85,
            1 => 1.0,
            2 => 1.12,
            _ => 1.28,
        };
    }
    let ac_len = BLOCK_PIXELS - 1;
    let mut best = vec![vec![f32::INFINITY; ac_len + 1]; ac_len + 1];
    let mut keep = vec![vec![false; ac_len + 1]; ac_len];
    for slot in best[ac_len].iter_mut().take(ac_len + 1) {
        *slot = RLE_EOB_BITS_F;
    }
    for idx in (0..ac_len).rev() {
        let coeff = original[ZIG_ZAG[idx + 1]];
        let distortion_zero = f32::from(coeff) * f32::from(coeff);
        for run in 0..=ac_len {
            let next_run = (run + 1).min(ac_len);
            let zero_cost = distortion_zero + best[idx + 1][next_run];
            let keep_cost = if coeff == 0 {
                f32::INFINITY
            } else {
                lambda * token_rate_bits(run) + best[idx + 1][0]
            };
            if keep_cost < zero_cost {
                keep[idx][run] = true;
                best[idx][run] = keep_cost;
            } else {
                best[idx][run] = zero_cost;
            }
        }
    }
    let mut run = 0usize;
    for idx in 0..ac_len {
        let slot = ZIG_ZAG[idx + 1];
        if keep[idx][run] {
            run = 0;
        } else {
            coeffs[slot] = 0;
            run = (run + 1).min(ac_len);
        }
    }
    coeffs[0] = original[0];
    let before_bits = estimate_rle_bits(&original);
    let after_bits = estimate_rle_bits(coeffs);
    let distortion_penalty: u64 = original
        .iter()
        .zip(coeffs.iter())
        .skip(1)
        .map(|(&before, &after)| {
            let diff = i64::from(before) - i64::from(after);
            diff.saturating_mul(diff) as u64
        })
        .sum();
    DpReport {
        energy,
        before_bits,
        after_bits,
        distortion_penalty,
        neural_class,
    }
}
struct TinyPrng(u64);
impl TinyPrng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }
    fn next(&mut self) -> u32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 >> 32) as u32
    }
    fn next_i8(&mut self) -> i8 {
        let raw = self.next();
        let span = 11i16;
        let value = (raw % (2 * span as u32 + 1)) as i16 - span;
        value as i8
    }
    fn next_i16(&mut self) -> i16 {
        let raw = self.next();
        let span = 127i32;
        let value = (raw % (2 * span as u32 + 1)) as i32 - span;
        value as i16
    }
}
#[derive(Clone)]
struct NeuralPredictor {
    weights1: [[i8; NEURAL_FEATURES]; NEURAL_HIDDEN],
    weights2: [[i8; NEURAL_HIDDEN]; NEURAL_OUTPUT],
    bias1: [i16; NEURAL_HIDDEN],
    bias2: [i16; NEURAL_OUTPUT],
    activation_scale: i16,
}
impl NeuralPredictor {
    fn from_seed(seed: [u8; 32]) -> Self {
        let mut seed_bytes = [0u8; 8];
        seed_bytes.copy_from_slice(&seed[..8]);
        let mut prng = TinyPrng::new(u64::from_le_bytes(seed_bytes));
        let mut weights1 = [[0i8; NEURAL_FEATURES]; NEURAL_HIDDEN];
        let mut weights2 = [[0i8; NEURAL_HIDDEN]; NEURAL_OUTPUT];
        let mut bias1 = [0i16; NEURAL_HIDDEN];
        let mut bias2 = [0i16; NEURAL_OUTPUT];
        for row in &mut weights1 {
            for weight in row {
                *weight = prng.next_i8();
            }
        }
        for row in &mut weights2 {
            for weight in row {
                *weight = prng.next_i8();
            }
        }
        for bias in &mut bias1 {
            *bias = prng.next_i16();
        }
        for bias in &mut bias2 {
            *bias = prng.next_i16();
        }
        let activation_scale = (prng.next() % 7 + 9) as i16;
        Self {
            weights1,
            weights2,
            bias1,
            bias2,
            activation_scale,
        }
    }
    fn predict(&self, features: &[i8; NEURAL_FEATURES]) -> usize {
        let mut hidden = [0i16; NEURAL_HIDDEN];
        for (idx, (row, bias)) in self.weights1.iter().zip(self.bias1.iter()).enumerate() {
            let mut acc = i32::from(*bias);
            for (&w, &f) in row.iter().zip(features.iter()) {
                acc = acc.saturating_add(i32::from(w) * i32::from(f));
            }
            let scaled = acc / i32::from(self.activation_scale.max(1));
            let relu = scaled.max(0).min(i32::from(i16::MAX));
            hidden[idx] = relu as i16;
        }
        let mut best = (0usize, i32::MIN);
        for (class, (row, bias)) in self.weights2.iter().zip(self.bias2.iter()).enumerate() {
            let mut acc = i32::from(*bias);
            for (&w, &h) in row.iter().zip(hidden.iter()) {
                acc = acc.saturating_add(i32::from(w) * i32::from(h));
            }
            if acc > best.1 {
                best = (class, acc);
            }
        }
        best.0
    }
}
fn build_neural_features(
    coeffs: &[i16; BLOCK_PIXELS],
    energy: u32,
    bundle_width: u8,
    quantizer: u8,
    frame_type: FrameType,
    block_index: usize,
) -> [i8; NEURAL_FEATURES] {
    let mut features = [0i8; NEURAL_FEATURES];
    features[0] = energy_bucket(energy) as i8;
    features[1] = max_zero_run_in_block(coeffs) as i8;
    features[2] = quantizer_to_bucket(quantizer) as i8;
    features[3] = bundle_width.clamp(1, MAX_BUNDLE_WIDTH as u8) as i8;
    let non_zero = coeffs.iter().skip(1).filter(|&&c| c != 0).count();
    features[4] = non_zero.min(i8::MAX as usize) as i8;
    features[5] = ((block_index as u8) & 0x0F) as i8;
    features[6] = if matches!(frame_type, FrameType::Intra) {
        0
    } else {
        1
    };
    let tail_energy: u32 = coeffs
        .iter()
        .skip(BLOCK_PIXELS.saturating_sub(8))
        .map(|&c| c.unsigned_abs())
        .map(u32::from)
        .sum();
    features[7] = tail_energy.min(127) as i8;
    features
}
#[cfg(test)]
mod rdo_tests {
    use super::*;
    #[test]
    fn dp_optimizer_reduces_rate_on_sparse_block() {
        let mut coeffs = [0i16; BLOCK_PIXELS];
        coeffs[0] = 10;
        coeffs[1] = 2;
        coeffs[5] = -1;
        coeffs[12] = 1;
        let before_bits = estimate_rle_bits(&coeffs);
        let mut working = coeffs;
        let report = optimize_block_dp(
            &mut working,
            RdoMode::DynamicProgramming,
            1.5,
            None,
            3,
            10,
            FrameType::Intra,
            0,
        );
        assert!(
            report.after_bits <= before_bits,
            "RDO must not increase rate"
        );
        assert!(
            report.distortion_penalty > 0,
            "zeroing must record distortion"
        );
        // ensure DC preserved
        assert_eq!(working[0], coeffs[0]);
    }
    #[test]
    fn neural_predictor_is_deterministic() {
        let predictor = NeuralPredictor::from_seed(DEFAULT_NEURAL_SEED);
        let coeffs = [0i16; BLOCK_PIXELS];
        let features = build_neural_features(&coeffs, 0, 2, 8, FrameType::Intra, 1);
        let first = predictor.predict(&features);
        let second = predictor.predict(&features);
        assert_eq!(first, second);
    }
    #[test]
    fn context_frequency_records_symbols() {
        let dims = FrameDimensions::new(8, 8);
        let tables = default_bundle_tables();
        let mut recorder =
            BundleStreamRecorder::new(2, dims, 4, tables, BundleAcceleration::None, 0, None);
        recorder.record_bundle(
            BundleType::SignAndMagnitude,
            BundleContextId::new(7),
            0b11,
            2,
            BundleFlushReason::TypeComplete,
        );
        let telemetry = recorder.finish();
        let entry = telemetry
            .context_frequencies
            .iter()
            .find(|entry| entry.context == BundleContextId::new(7))
            .expect("context frequency recorded");
        assert_eq!(entry.bundles, 1);
        assert_eq!(entry.symbol_counts[3], 1);
    }
    #[test]
    fn context_remap_loader_maps_and_escapes() {
        let path = std::env::temp_dir().join("remap_loader.json");
        let json = r#"
            {
                "escape_context": 65535,
                "kept": [{ "original": 7, "remapped": 1 }],
                "dropped": [{ "original": 9 }]
            }"#;
        std::fs::write(&path, json).expect("write remap json");
        let remap =
            load_bundle_context_remap_from_json(&path).expect("remap should parse correctly");
        assert_eq!(remap.map(BundleContextId::new(7)), BundleContextId::new(1));
        assert_eq!(
            remap.map(BundleContextId::new(9)),
            BundleContextId::new(u16::MAX)
        );
        assert_eq!(remap.remapped_count(), 1);
        assert_eq!(remap.dropped_count(), 1);
        let _ = std::fs::remove_file(&path);
    }
}
struct BundleStreamRecorder {
    stats: BundledStats,
    tokens: Vec<BundledToken>,
    bundles: Vec<BundleRecord>,
    context_stats: BTreeMap<BundleContextId, BundleContextStats>,
    context_frequency: BTreeMap<BundleContextId, ContextFrequency>,
    width: u8,
    blocks_per_row: usize,
    quantizer_bucket: u8,
    tables: Arc<BundleAnsTables>,
    acceleration: BundleAcceleration,
    prefetch_distance: u16,
    pending_blocks: VecDeque<BlockBundleState>,
    current_block: Option<BlockBundleState>,
    last_context: Option<BundleContextId>,
    context_remap: Option<Arc<BundleContextRemap>>,
}
impl BundleStreamRecorder {
    fn new(
        bundle_width: u8,
        dims: FrameDimensions,
        quantizer: u8,
        tables: Arc<BundleAnsTables>,
        acceleration: BundleAcceleration,
        prefetch_distance: u16,
        context_remap: Option<Arc<BundleContextRemap>>,
    ) -> Self {
        Self {
            stats: BundledStats {
                bundle_width,
                ..BundledStats::default()
            },
            tokens: Vec::new(),
            bundles: Vec::new(),
            context_stats: BTreeMap::new(),
            context_frequency: BTreeMap::new(),
            width: bundle_width.clamp(1, 4),
            blocks_per_row: (dims.width as usize / BLOCK_SIZE).max(1),
            quantizer_bucket: quantizer_to_bucket(quantizer),
            tables,
            acceleration,
            prefetch_distance,
            pending_blocks: VecDeque::new(),
            current_block: None,
            last_context: None,
            context_remap,
        }
    }
    fn context_stats_entry(&mut self, context: BundleContextId) -> &mut BundleContextStats {
        self.context_stats
            .entry(context)
            .or_insert_with(|| BundleContextStats::new(context))
    }
    fn map_context(&self, context: BundleContextId) -> BundleContextId {
        if let Some(remap) = self.context_remap.as_ref() {
            remap.map(context)
        } else {
            context
        }
    }
    fn finish(self) -> BundledTelemetry {
        let (ans_stream, used_acceleration) = encode_bundle_stream_with_opts(
            self.tables.as_ref(),
            &self.bundles,
            self.acceleration,
            self.prefetch_distance,
        );
        let remap = self.context_remap.as_ref().map(|map| ContextRemapSummary {
            escape_context: map.escape_context(),
            remapped: map.remapped_count(),
            dropped: map.dropped_count(),
        });
        BundledTelemetry {
            stats: self.stats,
            tokens: self.tokens,
            bundles: self.bundles,
            context_frequencies: self.context_frequency.into_values().collect(),
            ans_stream,
            ans_precision_bits: self.tables.precision_bits(),
            tables_checksum: self.tables.checksum(),
            context_stats: self.context_stats.into_values().collect(),
            acceleration: used_acceleration,
            prefetch_distance: self.prefetch_distance,
            context_remap: remap,
            rdo: None,
        }
    }
    fn record_bundle(
        &mut self,
        bundle_type: BundleType,
        context: BundleContextId,
        bits: u8,
        bit_len: u8,
        flush: BundleFlushReason,
    ) {
        if let Some(previous_context) = self.last_context
            && previous_context != context
        {
            self.stats.record_flush(BundleFlushReason::ContextSwitch);
            self.context_stats_entry(previous_context)
                .record_flush(BundleFlushReason::ContextSwitch);
        }
        self.last_context = Some(context);
        self.stats.bundles_total = self.stats.bundles_total.saturating_add(1);
        self.stats.record_flush(flush);
        if matches!(bundle_type, BundleType::SignificanceRle) {
            self.stats.significance_rle = self.stats.significance_rle.saturating_add(1);
        }
        self.context_stats_entry(context)
            .record_bundle(bundle_type, flush);
        let freq = self
            .context_frequency
            .entry(context)
            .or_insert_with(|| ContextFrequency {
                context,
                ..ContextFrequency::default()
            });
        freq.bundles = freq.bundles.saturating_add(1);
        freq.total_bits = freq.total_bits.saturating_add(u64::from(bit_len));
        let symbol_idx = usize::from(bits) & (RDO_MAX_SYMBOLS - 1);
        freq.symbol_counts[symbol_idx] = freq.symbol_counts[symbol_idx].saturating_add(1);
        self.bundles.push(BundleRecord {
            bundle_type,
            context,
            bits,
            bit_len,
            flush,
        });
    }
    fn accumulate_stats(&mut self, value: i16) {
        let nonzero = value != 0;
        if nonzero {
            self.stats.significance_one = self.stats.significance_one.saturating_add(1);
        } else {
            self.stats.significance_zero = self.stats.significance_zero.saturating_add(1);
        }
        let negative = value < 0;
        if negative {
            self.stats.sign_negative = self.stats.sign_negative.saturating_add(1);
        } else {
            self.stats.sign_positive = self.stats.sign_positive.saturating_add(1);
        }
        if self.width >= 3 && value != 0 {
            let parity = (value.wrapping_abs() as u32 & 1) as u8;
            if parity == 1 {
                self.stats.parity_one = self.stats.parity_one.saturating_add(1);
            }
        }
        if self.width >= 4 && value.abs() >= 2 {
            self.stats.geq2_one = self.stats.geq2_one.saturating_add(1);
        }
    }
    fn record_block(
        &mut self,
        block_index: usize,
        coeffs: &[i16; BLOCK_PIXELS],
        frame_type: FrameType,
    ) {
        let mut prev_level_abs = 0u8;
        let mut slots = Vec::with_capacity(BLOCK_PIXELS - 1);
        for (order, &slot) in ZIG_ZAG.iter().enumerate().skip(1) {
            let coeff = coeffs[slot];
            self.accumulate_stats(coeff);
            let (bundle_type, _, _) = bundle_bits(coeff, self.width);
            let context = self.map_context(self.compute_context(
                bundle_type,
                block_index,
                order,
                slot,
                coeff,
                prev_level_abs,
                frame_type,
                coeffs,
            ));
            slots.push(SlotContext {
                context,
                is_non_zero: coeff != 0,
            });
            prev_level_abs = (coeff.saturating_abs() as u16).min(0xFF) as u8;
        }
        self.pending_blocks
            .push_back(BlockBundleState::new(block_index, slots));
    }
    fn ensure_current_block(&mut self) {
        if self.current_block.is_none()
            && let Some(next) = self.pending_blocks.pop_front()
        {
            self.current_block = Some(next);
        }
    }
    fn peek_slot(&mut self) -> Option<SlotContext> {
        self.ensure_current_block();
        self.current_block
            .as_ref()
            .and_then(BlockBundleState::peek_slot)
    }
    fn pop_slot(&mut self) -> Option<SlotContext> {
        loop {
            self.ensure_current_block();
            match self.current_block.as_mut() {
                Some(block) => {
                    if let Some(slot) = block.next_slot() {
                        return Some(slot);
                    }
                    self.current_block = None;
                }
                None => return None,
            }
        }
    }
    fn flush_pending_zero_slots(&mut self) {
        while let Some(slot) = self.pop_slot() {
            debug_assert!(!slot.is_non_zero);
            let mut run = 1u16;
            while let Some(next) = self.peek_slot() {
                if next.is_non_zero || next.context != slot.context {
                    break;
                }
                self.pop_slot()
                    .expect("peeked slot should still be available");
                run = run.saturating_add(1);
            }
            self.emit_zero_run_bundle(slot.context, run);
        }
    }
    fn record_zero_run(&mut self, zeros: u8) {
        let mut remaining = zeros;
        while remaining > 0 {
            let slot = self
                .pop_slot()
                .expect("zero slot must exist before nonzero run");
            debug_assert!(!slot.is_non_zero);
            let context = slot.context;
            let mut run: u16 = 1;
            while run < u16::from(remaining) {
                if let Some(next) = self.peek_slot() {
                    if next.is_non_zero || next.context != context {
                        break;
                    }
                    self.pop_slot()
                        .expect("peeked slot should still be available");
                    run = run.saturating_add(1);
                    continue;
                }
                break;
            }
            self.emit_zero_run_bundle(context, run);
            remaining = remaining.saturating_sub(run as u8);
        }
    }
    fn emit_zero_run_bundle(&mut self, context: BundleContextId, mut run: u16) {
        while run > 0 {
            let (bits, bit_len, consumed) = bundle_zero_run_symbol(run, self.width);
            self.record_bundle(
                BundleType::SignificanceRle,
                context,
                bits,
                bit_len,
                BundleFlushReason::TypeComplete,
            );
            run = run.saturating_sub(consumed);
        }
    }
    #[allow(clippy::too_many_arguments)]
    fn compute_context(
        &self,
        bundle_type: BundleType,
        block_index: usize,
        zigzag_order: usize,
        coeff_slot: usize,
        coeff: i16,
        prev_level_abs: u8,
        frame_type: FrameType,
        coeffs: &[i16; BLOCK_PIXELS],
    ) -> BundleContextId {
        let block_x = block_index % self.blocks_per_row;
        let block_y = block_index / self.blocks_per_row;
        let block_tile = (((block_x as u32) & 0x7) | (((block_y as u32) & 0x7) << 3)) as u8;
        let neighbor_nz = neighbor_nonzero_count(coeffs, coeff_slot);
        let subband = subband_class(coeff_slot);
        let pos_class = position_class(zigzag_order);
        let prev_bucket = level_bucket(prev_level_abs);
        let frame_class: u8 = if frame_type == FrameType::Intra { 0 } else { 1 };
        let coeff_bucket = (coeff != 0) as u8;
        let mut hash = 0x811C9DC5u32;
        hash = hash_mix(hash, bundle_type.as_u8() as u32);
        hash = hash_mix(hash, subband.into());
        hash = hash_mix(hash, pos_class.into());
        hash = hash_mix(hash, neighbor_nz.into());
        hash = hash_mix(hash, prev_bucket.into());
        hash = hash_mix(hash, self.quantizer_bucket.into());
        hash = hash_mix(hash, frame_class.into());
        hash = hash_mix(hash, block_tile.into());
        hash = hash_mix(hash, coeff_bucket.into());
        hash = hash_mix(hash, (zigzag_order as u32) & 0x3F);
        BundleContextId::new((hash & 0xFFFF) as u16)
    }
}
impl BundledHooks for BundleStreamRecorder {
    fn record_block_coeffs(
        &mut self,
        coeffs: &[i16; BLOCK_PIXELS],
        block_index: usize,
        frame_type: FrameType,
    ) {
        self.record_block(block_index, coeffs, frame_type);
    }
    fn record_dc(&mut self, diff: i16) {
        self.ensure_current_block();
        self.stats.dc_events = self.stats.dc_events.saturating_add(1);
        self.tokens.push(BundledToken::DcDiff(diff));
    }
    fn record_ac(&mut self, zeros: u8, value: i16) {
        self.stats.ac_events = self.stats.ac_events.saturating_add(1);
        self.stats.zero_run_total = self.stats.zero_run_total.saturating_add(u64::from(zeros));
        self.stats.max_zero_run = self.stats.max_zero_run.max(zeros);
        if value != 0 {
            self.stats.nonzero_levels = self.stats.nonzero_levels.saturating_add(1);
        }
        self.record_zero_run(zeros);
        let slot = self
            .pop_slot()
            .expect("non-zero slot must exist after zero run");
        debug_assert!(slot.is_non_zero);
        let (bundle_type, bits, len) = bundle_bits(value, self.width);
        self.record_bundle(
            bundle_type,
            slot.context,
            bits,
            len,
            BundleFlushReason::TypeComplete,
        );
        self.tokens.push(BundledToken::Ac { run: zeros, value });
    }
    fn record_eob(&mut self) {
        self.flush_pending_zero_slots();
        self.stats.blocks_encoded = self.stats.blocks_encoded.saturating_add(1);
        if let Some(last_context) = self.bundles.last().map(|record| record.context) {
            self.context_stats_entry(last_context)
                .record_flush(BundleFlushReason::EndOfBlock);
        }
        self.stats.record_flush(BundleFlushReason::EndOfBlock);
        self.tokens.push(BundledToken::EndOfBlock);
        self.current_block = None;
        self.last_context = None;
    }
}
#[derive(Clone, Copy)]
struct SlotContext {
    context: BundleContextId,
    is_non_zero: bool,
}
struct BlockBundleState {
    #[allow(dead_code)]
    block_index: usize,
    slots: Vec<SlotContext>,
    cursor: usize,
}
impl BlockBundleState {
    fn new(block_index: usize, slots: Vec<SlotContext>) -> Self {
        Self {
            block_index,
            slots,
            cursor: 0,
        }
    }
    fn next_slot(&mut self) -> Option<SlotContext> {
        let slot = self.slots.get(self.cursor).copied();
        if slot.is_some() {
            self.cursor = self.cursor.saturating_add(1);
        }
        slot
    }
    fn peek_slot(&self) -> Option<SlotContext> {
        self.slots.get(self.cursor).copied()
    }
}
const BUNDLE_ANS_PRECISION_BITS: u8 = 12;
const BUNDLE_RANS_BYTE_L: u32 = 1 << 23;
#[derive(Clone, Debug)]
struct SymbolTable {
    freq: Vec<u16>,
    start: Vec<u16>,
    precision_bits: u8,
    decode: Vec<AnsSymbol>,
}
#[derive(Clone, Copy, Debug)]
struct AnsSymbol {
    symbol: u16,
    start: u16,
    freq: u16,
}
pub(super) const MAX_BUNDLE_WIDTH: usize = 4;
impl SymbolTable {
    fn from_group(group: &RansGroupTableV1) -> Result<Self, BundleTableError> {
        let width_bits = match group.width_bits {
            0 => infer_group_width_bits(group.group_size)?,
            bits => bits,
        };
        let expected = 1usize << width_bits;
        if expected == 0 || group.frequencies.len() != expected {
            return Err(BundleTableError::InvalidGroup {
                bit_len: 0,
                reason: "group frequencies length mismatch",
            });
        }
        if group.cumulative.len() != expected + 1 {
            return Err(BundleTableError::InvalidGroup {
                bit_len: 0,
                reason: "group cumulative length mismatch",
            });
        }
        if usize::from(group.group_size) != expected {
            return Err(BundleTableError::InvalidGroup {
                bit_len: 0,
                reason: "group size does not match width bits",
            });
        }
        let total = 1u32.checked_shl(group.precision_bits.into()).ok_or(
            BundleTableError::InvalidGroup {
                bit_len: 0,
                reason: "precision bits overflow",
            },
        )?;
        if *group.cumulative.first().unwrap_or(&1) != 0
            || *group.cumulative.last().unwrap_or(&0) != total
        {
            return Err(BundleTableError::InvalidGroup {
                bit_len: 0,
                reason: "cumulative range mismatch",
            });
        }
        let freq_sum: u32 = group
            .frequencies
            .iter()
            .map(|&value| u32::from(value))
            .sum();
        if freq_sum != total {
            return Err(BundleTableError::InvalidGroup {
                bit_len: 0,
                reason: "frequency sum mismatch",
            });
        }
        let mut start = Vec::with_capacity(expected);
        for &value in group.cumulative.iter().take(expected) {
            start.push(
                u16::try_from(value).map_err(|_| BundleTableError::InvalidGroup {
                    bit_len: 0,
                    reason: "cumulative value exceeds u16 range",
                })?,
            );
        }
        let table =
            SymbolTable::from_frequencies(group.frequencies.clone(), start, group.precision_bits);
        Ok(table)
    }
    fn from_frequencies(freq: Vec<u16>, start: Vec<u16>, precision_bits: u8) -> Self {
        let decode = build_decode_table(&freq, &start, precision_bits);
        Self {
            freq,
            start,
            precision_bits,
            decode,
        }
    }
}
fn infer_group_width_bits(group_size: u16) -> Result<u8, BundleTableError> {
    if group_size == 0 {
        return Err(BundleTableError::InvalidGroup {
            bit_len: 0,
            reason: "group size must be > 0",
        });
    }
    let value = u32::from(group_size);
    if value & (value - 1) != 0 {
        return Err(BundleTableError::InvalidGroup {
            bit_len: 0,
            reason: "group size must be a power of two",
        });
    }
    Ok(value.trailing_zeros() as u8)
}
fn build_uniform_symbol_table(bit_len: u8, precision_bits: u8) -> SymbolTable {
    let alphabet = 1usize << bit_len.max(1);
    let precision = 1usize << precision_bits;
    let base_freq = (precision / alphabet) as u16;
    let mut freq = vec![base_freq; alphabet];
    let mut remainder = precision - base_freq as usize * alphabet;
    let mut idx = 0usize;
    while remainder > 0 {
        freq[idx] = freq[idx].saturating_add(1);
        remainder -= 1;
        idx += 1;
        if idx == alphabet {
            idx = 0;
        }
    }
    let mut start = Vec::with_capacity(alphabet);
    let mut cumulative = 0u32;
    for &value in &freq {
        start.push(cumulative as u16);
        cumulative += u32::from(value);
    }
    SymbolTable::from_frequencies(freq, start, precision_bits)
}
fn derive_significance_table(source: &SymbolTable) -> SymbolTable {
    let mut freq = vec![0u16; 2];
    for (symbol, &value) in source.freq.iter().enumerate() {
        let sig = symbol & 1;
        freq[sig] = freq[sig].saturating_add(value);
    }
    let mut start = Vec::with_capacity(2);
    let mut cumulative = 0u32;
    for &value in &freq {
        start.push(cumulative as u16);
        cumulative += u32::from(value);
    }
    SymbolTable::from_frequencies(freq, start, source.precision_bits)
}
fn build_decode_table(freq: &[u16], start: &[u16], precision_bits: u8) -> Vec<AnsSymbol> {
    let precision = 1usize << precision_bits;
    let mut table = vec![
        AnsSymbol {
            symbol: 0,
            start: 0,
            freq: 1,
        };
        precision
    ];
    for (symbol, (&begin, &frequency)) in start.iter().zip(freq.iter()).enumerate() {
        table
            .iter_mut()
            .skip(begin as usize)
            .take(frequency as usize)
            .for_each(|slot| {
                *slot = AnsSymbol {
                    symbol: symbol as u16,
                    start: begin,
                    freq: frequency,
                };
            });
    }
    table
}
#[inline]
fn prefetch_bundle_record(record: &BundleRecord) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        use core::arch::x86_64::{_MM_HINT_T0, _mm_prefetch};
        _mm_prefetch(record as *const _ as *const i8, _MM_HINT_T0);
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!(
            "prfm pldl1keep, [{0}]",
            in(reg) record,
            options(readonly, nostack, preserves_flags)
        );
    }
}
struct BundleRansEncoder<'a> {
    tables: &'a BundleAnsTables,
    precision_bits: u8,
    state: u32,
    buffer: Vec<u8>,
    table_cache: [Option<&'a SymbolTable>; MAX_BUNDLE_WIDTH + 1],
}
impl<'a> BundleRansEncoder<'a> {
    fn new(tables: &'a BundleAnsTables) -> Self {
        let mut table_cache: [Option<&'a SymbolTable>; MAX_BUNDLE_WIDTH + 1] =
            core::array::from_fn(|_| None);
        for bit_len in 1..=tables.max_width() {
            table_cache[bit_len as usize] = Some(tables.table_for_bits(bit_len));
        }
        Self {
            tables,
            precision_bits: tables.precision_bits(),
            state: BUNDLE_RANS_BYTE_L,
            buffer: Vec::new(),
            table_cache,
        }
    }
    fn encode_record(&mut self, record: &BundleRecord) {
        let table = self
            .table_cache
            .get(record.bit_len as usize)
            .and_then(Option::as_ref)
            .copied()
            .unwrap_or_else(|| self.tables.table_for_bits(record.bit_len));
        let symbol = (record.bits & ((1 << record.bit_len) - 1)) as usize;
        self.encode_symbol(symbol, table);
    }
    fn encode_symbol(&mut self, symbol: usize, table: &SymbolTable) {
        let freq = table.freq[symbol] as u32;
        let start = table.start[symbol] as u32;
        while self.state >= (freq << (32 - self.precision_bits)) {
            self.buffer.push((self.state & 0xFF) as u8);
            self.state >>= 8;
        }
        self.state = ((self.state / freq) << self.precision_bits) + (self.state % freq) + start;
    }
    fn finish(mut self) -> Vec<u8> {
        for _ in 0..4 {
            self.buffer.push((self.state & 0xFF) as u8);
            self.state >>= 8;
        }
        self.buffer
    }
}
struct BundleRansDecoder<'a> {
    tables: &'a BundleAnsTables,
    precision_bits: u8,
    buffer: &'a [u8],
    cursor: usize,
    state: u32,
}
impl<'a> BundleRansDecoder<'a> {
    fn new(buffer: &'a [u8], tables: &'a BundleAnsTables) -> Result<Self, BundleDecodeError> {
        if buffer.len() < 4 {
            return Err(BundleDecodeError::TruncatedState);
        }
        let len = buffer.len();
        let mut state = 0u32;
        for shift in 0..4 {
            state |= u32::from(buffer[len - 4 + shift]) << (shift * 8);
        }
        let cursor = len - 4;
        Ok(Self {
            tables,
            precision_bits: tables.precision_bits(),
            buffer,
            cursor,
            state,
        })
    }
    fn decode_record(&mut self, record: &BundleRecord) -> Result<u8, BundleDecodeError> {
        let table = self.tables.table_for_bits(record.bit_len);
        self.decode_symbol(table).map(|sym| sym as u8)
    }
    fn decode_symbol(&mut self, table: &SymbolTable) -> Result<u16, BundleDecodeError> {
        let mask = (1u32 << self.precision_bits) - 1;
        let idx = (self.state & mask) as usize;
        let sym = table.decode[idx];
        let scaled = self.state >> self.precision_bits;
        self.state = sym.freq as u32 * scaled + (idx as u32 - sym.start as u32);
        self.renormalize()?;
        Ok(sym.symbol)
    }
    fn renormalize(&mut self) -> Result<(), BundleDecodeError> {
        while self.state < BUNDLE_RANS_BYTE_L && self.cursor > 0 {
            self.cursor -= 1;
            self.state = (self.state << 8) | u32::from(self.buffer[self.cursor]);
        }
        if self.state < BUNDLE_RANS_BYTE_L && self.cursor == 0 {
            return Err(BundleDecodeError::RenormalizeUnderflow);
        }
        Ok(())
    }
}
const SIMD_BUNDLE_MAGIC: [u8; 4] = *b"BR4\x01";
#[cfg(test)]
fn encode_bundle_stream(tables: &BundleAnsTables, bundles: &[BundleRecord]) -> Vec<u8> {
    let (stream, _acceleration) =
        encode_bundle_stream_with_opts(tables, bundles, BundleAcceleration::None, 0);
    stream
}
fn encode_bundle_stream_with_opts(
    tables: &BundleAnsTables,
    bundles: &[BundleRecord],
    requested: BundleAcceleration,
    prefetch_distance: u16,
) -> (Vec<u8>, BundleAcceleration) {
    let has_rle = bundles
        .iter()
        .any(|record| matches!(record.bundle_type, BundleType::SignificanceRle));
    if has_rle {
        let mut stream = Vec::with_capacity(bundles.len());
        for record in bundles {
            stream.push(record.bits & ((1u8 << record.bit_len) - 1));
        }
        // RLE bundles are scalar-only until SIMD tables are calibrated.
        return (stream, BundleAcceleration::None);
    }
    if requested == BundleAcceleration::CpuSimd && cpu_simd_supported() {
        let stream = encode_bundle_stream_simd(tables, bundles, prefetch_distance);
        let acceleration = if stream.starts_with(&SIMD_BUNDLE_MAGIC) {
            BundleAcceleration::CpuSimd
        } else {
            BundleAcceleration::None
        };
        (stream, acceleration)
    } else {
        (
            encode_bundle_stream_scalar(tables, bundles, prefetch_distance),
            BundleAcceleration::None,
        )
    }
}
fn encode_bundle_stream_scalar(
    tables: &BundleAnsTables,
    bundles: &[BundleRecord],
    prefetch_distance: u16,
) -> Vec<u8> {
    let mut encoder = BundleRansEncoder::new(tables);
    let distance = prefetch_distance as usize;
    for rev_idx in 0..bundles.len() {
        let idx = bundles.len() - 1 - rev_idx;
        if distance > 0
            && let Some(prefetch_idx) = idx.checked_sub(distance)
        {
            prefetch_bundle_record(&bundles[prefetch_idx]);
        }
        encoder.encode_record(&bundles[idx]);
    }
    encoder.finish()
}
fn encode_bundle_stream_simd(
    tables: &BundleAnsTables,
    bundles: &[BundleRecord],
    prefetch_distance: u16,
) -> Vec<u8> {
    let mut states = [BUNDLE_RANS_BYTE_L; 4];
    let mut buffers: [Vec<u8>; 4] = [Vec::new(), Vec::new(), Vec::new(), Vec::new()];
    let distance = prefetch_distance as usize;
    let precision_bits = tables.precision_bits();
    let mut table_cache: [Option<&SymbolTable>; MAX_BUNDLE_WIDTH + 1] =
        core::array::from_fn(|_| None);
    for bit_len in 1..=tables.max_width() {
        table_cache[bit_len as usize] = Some(tables.table_for_bits(bit_len));
    }
    for rev_idx in 0..bundles.len() {
        let idx = bundles.len() - 1 - rev_idx;
        if distance > 0
            && let Some(prefetch_idx) = idx.checked_sub(distance)
        {
            prefetch_bundle_record(&bundles[prefetch_idx]);
        }
        let lane = rev_idx & 3;
        let record = &bundles[idx];
        let table = table_cache[record.bit_len as usize]
            .unwrap_or_else(|| tables.table_for_bits(record.bit_len));
        let symbol = (record.bits & ((1 << record.bit_len) - 1)) as usize;
        let state = &mut states[lane];
        let buffer = &mut buffers[lane];
        let freq = table.freq[symbol] as u32;
        let start = table.start[symbol] as u32;
        while *state >= (freq << (32 - precision_bits)) {
            buffer.push((*state & 0xFF) as u8);
            *state >>= 8;
        }
        *state = ((*state / freq) << precision_bits) + (*state % freq) + start;
    }
    for (state, buffer) in states.iter_mut().zip(buffers.iter_mut()) {
        for _ in 0..4 {
            buffer.push((*state & 0xFF) as u8);
            *state >>= 8;
        }
    }
    let mut payload_len = SIMD_BUNDLE_MAGIC.len();
    let mut lane_lengths = [0usize; 4];
    let mut overflowed = false;
    for (idx, buf) in buffers.iter().enumerate() {
        lane_lengths[idx] = buf.len();
        if lane_lengths[idx] > u32::MAX as usize {
            overflowed = true;
        }
        payload_len = payload_len.saturating_add(4).saturating_add(buf.len());
    }
    if overflowed {
        // SIMD header stores lane lengths as u32, so fall back to scalar on overflow.
        return encode_bundle_stream_scalar(tables, bundles, prefetch_distance);
    }
    let mut out = Vec::with_capacity(payload_len);
    out.extend_from_slice(&SIMD_BUNDLE_MAGIC);
    for len in lane_lengths {
        let len_u32 = len as u32;
        out.extend_from_slice(&len_u32.to_le_bytes());
    }
    for buf in buffers {
        out.extend_from_slice(&buf);
    }
    out
}
fn cpu_simd_supported() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        return std::arch::is_x86_feature_detected!("avx2");
    }
    #[cfg(target_arch = "aarch64")]
    {
        return std::arch::is_aarch64_feature_detected!("neon");
    }
    #[allow(unreachable_code)]
    false
}
/// Decode a bundled rANS stream back into the raw bundle symbols.
pub fn decode_bundle_stream(
    stream: &[u8],
    bundles: &[BundleRecord],
    tables: &BundleAnsTables,
) -> Result<Vec<u8>, BundleDecodeError> {
    let max_width = tables.max_width();
    for (index, record) in bundles.iter().enumerate() {
        if record.bit_len == 0 || record.bit_len > max_width {
            return Err(BundleDecodeError::InvalidBitLength {
                index: saturating_usize_to_u32(index),
                bit_len: record.bit_len,
                max: max_width,
            });
        }
    }
    if bundles
        .iter()
        .any(|record| matches!(record.bundle_type, BundleType::SignificanceRle))
    {
        return Ok(bundles
            .iter()
            .map(|record| record.bits & ((1u8 << record.bit_len) - 1))
            .collect());
    }
    if stream.starts_with(&SIMD_BUNDLE_MAGIC) {
        return decode_bundle_stream_simd(stream, bundles, tables);
    }
    let mut decoder = BundleRansDecoder::new(stream, tables)?;
    let mut out = Vec::with_capacity(bundles.len());
    for record in bundles {
        out.push(decoder.decode_record(record)?);
    }
    Ok(out)
}
fn decode_bundle_stream_simd(
    stream: &[u8],
    bundles: &[BundleRecord],
    tables: &BundleAnsTables,
) -> Result<Vec<u8>, BundleDecodeError> {
    let header_len = SIMD_BUNDLE_MAGIC.len();
    if stream.len() < header_len + 16 {
        return Err(BundleDecodeError::InvalidSimdHeader);
    }
    let mut cursor = header_len;
    let mut lengths = [0usize; 4];
    for slot in lengths.iter_mut() {
        *slot = read_simd_bundle_lane_len(stream, &mut cursor)?;
    }
    let total_len = lengths
        .iter()
        .try_fold(0usize, |acc, len| acc.checked_add(*len))
        .ok_or(BundleDecodeError::LengthMismatch)?;
    let expected_end = cursor
        .checked_add(total_len)
        .ok_or(BundleDecodeError::LengthMismatch)?;
    if stream.len() != expected_end {
        return Err(BundleDecodeError::LengthMismatch);
    }
    let mut decoders: [Option<BundleRansDecoder<'_>>; 4] = [None, None, None, None];
    let mut lane_cursor = cursor;
    for (idx, len) in lengths.iter().enumerate() {
        let next = lane_cursor
            .checked_add(*len)
            .ok_or(BundleDecodeError::LengthMismatch)?;
        let lane_slice = stream
            .get(lane_cursor..next)
            .ok_or(BundleDecodeError::LengthMismatch)?;
        decoders[idx] = Some(BundleRansDecoder::new(lane_slice, tables)?);
        lane_cursor = next;
    }
    let mut out = Vec::with_capacity(bundles.len());
    for (idx, record) in bundles.iter().enumerate() {
        let lane = (bundles.len() - 1 - idx) & 3;
        let decoder = decoders[lane]
            .as_mut()
            .ok_or(BundleDecodeError::InvalidSimdHeader)?;
        out.push(decoder.decode_record(record)?);
    }
    Ok(out)
}
fn read_simd_bundle_lane_len(
    stream: &[u8],
    cursor: &mut usize,
) -> Result<usize, BundleDecodeError> {
    let end = (*cursor)
        .checked_add(4)
        .ok_or(BundleDecodeError::InvalidSimdHeader)?;
    let slice = stream
        .get(*cursor..end)
        .ok_or(BundleDecodeError::InvalidSimdHeader)?;
    let mut buf = [0u8; 4];
    buf.copy_from_slice(slice);
    *cursor = end;
    Ok(u32::from_le_bytes(buf) as usize)
}
fn bundle_bits(value: i16, width: u8) -> (BundleType, u8, u8) {
    let nonzero = value != 0;
    let mut bits = (nonzero as u8) & 0x1;
    let mut len = 1u8;
    if !nonzero || width <= 1 {
        return (BundleType::SignificanceOnly, bits, len);
    }
    let negative = value < 0;
    bits = (bits << 1) | (negative as u8);
    len += 1;
    if width <= 2 {
        return (BundleType::SignAndMagnitude, bits, len);
    }
    let parity = (value.saturating_abs() as u16 & 1) as u8;
    bits = (bits << 1) | parity;
    len += 1;
    if width <= 3 {
        return (BundleType::SignParity, bits, len);
    }
    let geq2 = (value.saturating_abs() >= 2) as u8;
    bits = (bits << 1) | geq2;
    len += 1;
    (BundleType::SignParityLevel, bits, len)
}
fn bundle_zero_run_symbol(run: u16, width: u8) -> (u8, u8, u16) {
    let bit_len = width.max(2).min(MAX_BUNDLE_WIDTH as u8);
    let max_symbol = (1u16 << bit_len) - 1;
    let consumed = run.min(max_symbol);
    let bits = u8::try_from(consumed).unwrap_or(u8::MAX);
    (bits, bit_len, consumed)
}
fn quantizer_to_bucket(qp: u8) -> u8 {
    match qp {
        0..=12 => 0,
        13..=24 => 1,
        25..=36 => 2,
        _ => 3,
    }
}
fn position_class(order: usize) -> u8 {
    match order {
        0 => 0,
        1..=4 => 1,
        5..=15 => 2,
        16..=31 => 3,
        _ => 4,
    }
}
fn subband_class(slot: usize) -> u8 {
    let row = slot / BLOCK_SIZE;
    let col = slot % BLOCK_SIZE;
    let low_cut = 3;
    match (row <= low_cut, col <= low_cut) {
        (true, true) => 0,
        (true, false) => 1,
        (false, true) => 2,
        (false, false) => 3,
    }
}
fn neighbor_nonzero_count(coeffs: &[i16; BLOCK_PIXELS], slot: usize) -> u8 {
    let row = slot / BLOCK_SIZE;
    let col = slot % BLOCK_SIZE;
    let mut count = 0u8;
    if col > 0 && coeffs[row * BLOCK_SIZE + (col - 1)] != 0 {
        count = count.saturating_add(1);
    }
    if row > 0 && coeffs[(row - 1) * BLOCK_SIZE + col] != 0 {
        count = count.saturating_add(1);
    }
    if row > 0 && col > 0 && coeffs[(row - 1) * BLOCK_SIZE + (col - 1)] != 0 {
        count = count.saturating_add(1);
    }
    if row > 0 && col + 1 < BLOCK_SIZE && coeffs[(row - 1) * BLOCK_SIZE + (col + 1)] != 0 {
        count = count.saturating_add(1);
    }
    count.min(3)
}
fn level_bucket(value: u8) -> u8 {
    match value {
        0 => 0,
        1 => 1,
        2 => 2,
        _ => 3,
    }
}
fn hash_mix(acc: u32, value: u32) -> u32 {
    acc.wrapping_mul(16777619) ^ value
}
pub(crate) fn encode_block_rle(
    coeffs: &[i16; BLOCK_PIXELS],
    prev_dc: &mut i16,
    out: &mut Vec<u8>,
    hooks: &mut dyn BundledHooks,
    block_index: usize,
    frame_type: FrameType,
) {
    hooks.record_block_coeffs(coeffs, block_index, frame_type);
    let dc = coeffs[0];
    let diff = dc.wrapping_sub(*prev_dc);
    out.extend_from_slice(&diff.to_le_bytes());
    hooks.record_dc(diff);
    *prev_dc = dc;
    let mut pos = 1usize;
    while pos < BLOCK_PIXELS {
        let mut zero_run = 0usize;
        while pos < BLOCK_PIXELS && coeffs[ZIG_ZAG[pos]] == 0 {
            zero_run += 1;
            pos += 1;
        }
        if pos == BLOCK_PIXELS {
            out.push(RLE_EOB);
            out.extend_from_slice(&0i16.to_le_bytes());
            hooks.record_eob();
            return;
        }
        while zero_run > MAX_ZERO_RUN {
            out.push(MAX_ZERO_RUN as u8);
            out.extend_from_slice(&0i16.to_le_bytes());
            hooks.record_ac(MAX_ZERO_RUN as u8, 0);
            zero_run -= MAX_ZERO_RUN;
        }
        out.push(zero_run as u8);
        out.extend_from_slice(&coeffs[ZIG_ZAG[pos]].to_le_bytes());
        hooks.record_ac(zero_run as u8, coeffs[ZIG_ZAG[pos]]);
        pos += 1;
    }
    out.push(RLE_EOB);
    out.extend_from_slice(&0i16.to_le_bytes());
    hooks.record_eob();
}
fn take_block_i16_le(
    bytes: &[u8],
    offset: &mut usize,
    block_index: u32,
) -> Result<i16, CodecError> {
    let end = (*offset)
        .checked_add(2)
        .ok_or(CodecError::TruncatedBlock(block_index))?;
    let slice = bytes
        .get(*offset..end)
        .ok_or(CodecError::TruncatedBlock(block_index))?;
    let mut raw = [0u8; 2];
    raw.copy_from_slice(slice);
    *offset = end;
    Ok(i16::from_le_bytes(raw))
}
fn take_rle_record(
    bytes: &[u8],
    offset: &mut usize,
    block_index: u32,
) -> Result<(u8, i16), CodecError> {
    let end = (*offset)
        .checked_add(3)
        .ok_or(CodecError::TruncatedBlock(block_index))?;
    let record = bytes
        .get(*offset..end)
        .ok_or(CodecError::TruncatedBlock(block_index))?;
    let mut raw = [0u8; 2];
    raw.copy_from_slice(&record[1..3]);
    *offset = end;
    Ok((record[0], i16::from_le_bytes(raw)))
}
pub(crate) fn decode_block_rle(
    bytes: &[u8],
    offset: &mut usize,
    prev_dc: &mut i16,
    block_index: u32,
) -> Result<[i16; BLOCK_PIXELS], CodecError> {
    let mut coeffs = [0i16; BLOCK_PIXELS];
    let dc_diff = take_block_i16_le(bytes, offset, block_index)?;
    let dc = prev_dc.wrapping_add(dc_diff);
    coeffs[0] = dc;
    *prev_dc = dc;
    let mut pos = 1usize;
    let mut finished = false;
    while pos < BLOCK_PIXELS {
        let (run, value) = take_rle_record(bytes, offset, block_index)?;
        if run == RLE_EOB {
            finished = true;
            break;
        }
        let advance = run as usize;
        if pos + advance >= BLOCK_PIXELS {
            return Err(CodecError::RleOverflow(block_index));
        }
        pos += advance;
        coeffs[ZIG_ZAG[pos]] = value;
        pos += 1;
    }
    if !finished {
        if pos < BLOCK_PIXELS {
            return Err(CodecError::TruncatedBlock(block_index));
        }
        if *offset + 3 <= bytes.len() && bytes[*offset] == RLE_EOB {
            *offset += 3;
            return Ok(coeffs);
        }
        return Err(CodecError::MissingEndOfBlock(block_index));
    }
    Ok(coeffs)
}
#[inline]
fn clamp_pixel(value: i32) -> u8 {
    value.clamp(0, 255) as u8
}
#[cfg(feature = "streaming-neural-filter")]
pub(super) fn apply_neural_filter(frame: &mut [u8], dims: FrameDimensions) {
    let width = usize::from(dims.width);
    let height = usize::from(dims.height);
    if width == 0 || height == 0 {
        return;
    }
    let len = width
        .checked_mul(height)
        .unwrap_or_default()
        .min(frame.len());
    if len == 0 || frame.len() < len {
        return;
    }
    const KERNEL: [i8; 9] = [1, 2, 1, 2, 4, 2, 1, 2, 1];
    const SHIFT: i32 = 4;
    const BIAS: i32 = 8;
    let mut out = vec![0u8; len];
    for y in 0..height {
        for x in 0..width {
            let mut acc = 0i32;
            for ky in 0..3 {
                for kx in 0..3 {
                    let nx = x.saturating_add(kx).saturating_sub(1).min(width - 1);
                    let ny = y.saturating_add(ky).saturating_sub(1).min(height - 1);
                    let pixel = frame[ny * width + nx] as i32;
                    let weight = KERNEL[ky * 3 + kx] as i32;
                    acc += pixel * weight;
                }
            }
            let value = ((acc + BIAS) >> SHIFT).clamp(0, 255) as u8;
            out[y * width + x] = value;
        }
    }
    frame[..len].copy_from_slice(&out);
}
#[cfg_attr(not(test), allow(dead_code))]
fn layout_channel_count(layout: AudioLayout) -> usize {
    match layout {
        AudioLayout::Mono => 1,
        AudioLayout::Stereo => 2,
        AudioLayout::FirstOrderAmbisonics => 4,
    }
}
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
pub struct AudioEncoderConfig {
    pub sample_rate: u32,
    pub frame_samples: u16,
    pub layout: AudioLayout,
    pub fec_level: u8,
    pub target_bitrate: Option<u32>,
    pub backend: iroha_audio::BackendPreference,
}
impl Default for AudioEncoderConfig {
    fn default() -> Self {
        Self {
            sample_rate: 48_000,
            frame_samples: 240,
            layout: AudioLayout::Stereo,
            fec_level: 0,
            target_bitrate: None,
            backend: iroha_audio::BackendPreference::Auto,
        }
    }
}
impl AudioEncoderConfig {
    #[must_use]
    pub fn channel_count(&self) -> usize {
        self.layout.channel_count()
    }
}
pub struct AudioEncoder {
    config: AudioEncoderConfig,
    backend: iroha_audio::Encoder,
}
impl AudioEncoder {
    pub fn new(config: AudioEncoderConfig) -> Result<Self, AudioCodecError> {
        let backend = iroha_audio::Encoder::new(iroha_audio::EncoderConfig {
            sample_rate: config.sample_rate,
            frame_samples: config.frame_samples,
            layout: config.layout.into(),
            fec_level: config.fec_level,
            target_bitrate: config.target_bitrate,
            backend: config.backend,
        })
        .map_err(AudioCodecError::from_backend)?;
        Ok(Self { config, backend })
    }
    pub fn encode_frame(
        &mut self,
        sequence: u64,
        timestamp_ns: u64,
        pcm: &[i16],
    ) -> Result<AudioFrame, AudioCodecError> {
        let payload = self
            .backend
            .encode(pcm)
            .map_err(AudioCodecError::from_backend)?;
        Ok(AudioFrame {
            sequence,
            timestamp_ns,
            fec_level: self.config.fec_level,
            channel_layout: self.config.layout,
            payload,
        })
    }
}
pub struct AudioDecoder {
    config: AudioEncoderConfig,
    backend: iroha_audio::Decoder,
}
impl AudioDecoder {
    pub fn new(config: AudioEncoderConfig) -> Result<Self, AudioCodecError> {
        let backend = iroha_audio::Decoder::new(iroha_audio::EncoderConfig {
            sample_rate: config.sample_rate,
            frame_samples: config.frame_samples,
            layout: config.layout.into(),
            fec_level: config.fec_level,
            target_bitrate: None,
            backend: iroha_audio::BackendPreference::Auto,
        })
        .map_err(AudioCodecError::from_backend)?;
        Ok(Self { config, backend })
    }
    pub fn decode_frame(&mut self, frame: &AudioFrame) -> Result<Vec<i16>, AudioCodecError> {
        if frame.channel_layout != self.config.layout {
            return Err(AudioCodecError::LayoutMismatch(
                AudioCodecLayoutMismatchInfo {
                    expected: self.config.layout,
                    found: frame.channel_layout,
                },
            ));
        }
        self.backend
            .decode(&frame.payload)
            .map_err(AudioCodecError::from_backend)
    }
}
fn checked_chunk_count(chunk_count: usize) -> Result<u16, SegmentError> {
    u16::try_from(chunk_count).map_err(|_| {
        SegmentError::ChunkCountOverflow(ChunkCountOverflowInfo {
            found: saturating_usize_to_u32(chunk_count),
        })
    })
}
pub fn verify_segment(
    header: &SegmentHeader,
    descriptors: &[ChunkDescriptor],
    chunks: &[Vec<u8>],
    audio: Option<&SegmentAudio>,
) -> Result<(), SegmentError> {
    if descriptors.len() != chunks.len() {
        return Err(SegmentError::CountMismatch(ChunkListCountMismatch {
            descriptors: saturating_usize_to_u32(descriptors.len()),
            chunks: saturating_usize_to_u32(chunks.len()),
        }));
    }
    let descriptor_count = checked_chunk_count(descriptors.len())?;
    if header.chunk_count != descriptor_count {
        return Err(SegmentError::HeaderCountMismatch(
            HeaderDescriptorCountMismatch {
                header: header.chunk_count,
                actual: saturating_usize_to_u32(descriptors.len()),
            },
        ));
    }
    let mut payload_refs = Vec::with_capacity(descriptors.len());
    let mut expected_offset = 0u32;
    let mut last_chunk_id: Option<u16> = None;
    for (idx, (descriptor, chunk)) in descriptors.iter().zip(chunks.iter()).enumerate() {
        if let Some(last) = last_chunk_id
            && descriptor.chunk_id <= last
        {
            return Err(SegmentError::UnsortedChunkIds);
        }
        last_chunk_id = Some(descriptor.chunk_id);
        let chunk_len = u32::try_from(chunk.len())
            .map_err(|_| SegmentError::ChunkLengthOverflow(saturating_usize_to_u32(idx)))?;
        if descriptor.offset != expected_offset {
            return Err(SegmentError::DescriptorOffsetMismatch(
                DescriptorOffsetDetails {
                    index: saturating_usize_to_u32(idx),
                    expected: expected_offset,
                    actual: descriptor.offset,
                },
            ));
        }
        if descriptor.length != chunk_len {
            return Err(SegmentError::DescriptorLengthMismatch(
                DescriptorLengthDetails {
                    index: saturating_usize_to_u32(idx),
                    descriptor: descriptor.length,
                    chunk: saturating_usize_to_u32(chunk.len()),
                },
            ));
        }
        expected_offset = expected_offset
            .checked_add(chunk_len)
            .ok_or(SegmentError::OffsetOverflow(saturating_usize_to_u32(idx)))?;
        payload_refs.push((descriptor.chunk_id, chunk.as_slice()));
    }
    let commitments = chunk_commitments(header.segment_number, &payload_refs);
    for (idx, (descriptor, commitment)) in descriptors.iter().zip(commitments.iter()).enumerate() {
        if &descriptor.commitment != commitment {
            return Err(SegmentError::CommitmentMismatch(saturating_usize_to_u32(
                idx,
            )));
        }
    }
    let root = merkle_root(&commitments)?;
    if header.chunk_merkle_root != root {
        return Err(SegmentError::MerkleMismatch);
    }
    match (header.audio_summary.as_ref(), audio) {
        (Some(summary), Some(track)) => {
            if track.summary.sample_rate != summary.sample_rate {
                return Err(SegmentError::AudioSampleRateMismatch(
                    AudioSampleRateMismatchInfo {
                        expected: summary.sample_rate,
                        found: track.summary.sample_rate,
                    },
                ));
            }
            if track.summary.frame_samples != summary.frame_samples {
                return Err(SegmentError::AudioFrameSamplesMismatch(
                    AudioFrameSamplesMismatchInfo {
                        expected: summary.frame_samples,
                        found: track.summary.frame_samples,
                    },
                ));
            }
            if track.summary.frame_duration_ns != summary.frame_duration_ns {
                return Err(SegmentError::AudioFrameDurationMismatch(
                    AudioFrameDurationMismatchInfo {
                        expected: summary.frame_duration_ns,
                        found: track.summary.frame_duration_ns,
                    },
                ));
            }
            if track.summary.fec_level != summary.fec_level {
                return Err(SegmentError::AudioFecMismatch(AudioFecMismatchInfo {
                    expected: summary.fec_level,
                    found: track.summary.fec_level,
                }));
            }
            if track.summary.layout != summary.layout {
                return Err(SegmentError::AudioLayoutMismatch(AudioLayoutMismatchInfo {
                    expected: summary.layout,
                    found: track.summary.layout,
                }));
            }
            if track.summary.frames_per_segment != summary.frames_per_segment {
                return Err(SegmentError::AudioFrameCountMismatch(
                    AudioFrameCountMismatchInfo {
                        expected: summary.frames_per_segment,
                        found: track.summary.frames_per_segment,
                    },
                ));
            }
            let expected_frames = usize::from(summary.frames_per_segment);
            if track.frames.len() != expected_frames {
                return Err(SegmentError::AudioFrameCountMismatch(
                    AudioFrameCountMismatchInfo {
                        expected: summary.frames_per_segment,
                        found: track.frames.len().try_into().unwrap_or(u16::MAX),
                    },
                ));
            }
            let frame_step = u64::from(summary.frame_duration_ns);
            for (idx, frame) in track.frames.iter().enumerate() {
                if frame.channel_layout != summary.layout {
                    return Err(SegmentError::AudioLayoutMismatch(AudioLayoutMismatchInfo {
                        expected: summary.layout,
                        found: frame.channel_layout,
                    }));
                }
                if frame.fec_level != summary.fec_level {
                    return Err(SegmentError::AudioFecMismatch(AudioFecMismatchInfo {
                        expected: summary.fec_level,
                        found: frame.fec_level,
                    }));
                }
                let idx_u32 = saturating_usize_to_u32(idx);
                let offset = frame_step
                    .checked_mul(idx as u64)
                    .ok_or(SegmentError::AudioTimestampOverflow(idx_u32))?;
                let expected_ts = header
                    .timeline_start_ns
                    .checked_add(offset)
                    .ok_or(SegmentError::AudioTimestampOverflow(idx_u32))?;
                let delta = frame.timestamp_ns.abs_diff(expected_ts);
                if delta > AUDIO_SYNC_TOLERANCE_NS {
                    return Err(SegmentError::AudioTimestampMismatch(
                        AudioTimestampMismatchInfo {
                            index: idx_u32,
                            expected: expected_ts,
                            found: frame.timestamp_ns,
                        },
                    ));
                }
            }
        }
        (Some(_), None) => return Err(SegmentError::AudioSummaryMissing),
        (None, Some(_)) => return Err(SegmentError::AudioSummaryUnexpected),
        (None, None) => {}
    }
    Ok(())
}
#[derive(Clone, Copy)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
struct OffsetMeta {
    offset: u32,
    length: u32,
}
fn compute_offsets(chunks: &[Vec<u8>]) -> Vec<OffsetMeta> {
    let mut offset = 0u32;
    chunks
        .iter()
        .map(|chunk| {
            let len = chunk.len() as u32;
            let meta = OffsetMeta {
                offset,
                length: len,
            };
            offset = offset.saturating_add(len);
            meta
        })
        .collect()
}
#[cfg(test)]
mod tests;
