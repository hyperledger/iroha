//! Source files, byte ranges, and fixed first-release frontend budgets.
use std::{collections::BTreeMap, error::Error, fmt, io, path::Path, sync::Arc};
/// Maximum UTF-8 source size accepted for one Kotodama V1 source file.
pub const MAX_SOURCE_BYTES: usize = 1024 * 1024;
/// Maximum number of non-trivia lexical tokens, including end-of-file.
pub const MAX_TOKENS: usize = 250_000;
/// Maximum combined syntactic and recursive expression nesting accepted by the frontend.
pub const MAX_NESTING_DEPTH: usize = 256;
/// Maximum number of diagnostics retained for one compilation request.
pub const MAX_DIAGNOSTICS: usize = 64;
/// Failure to read one bounded UTF-8 Kotodama source file.
#[derive(Debug)]
pub enum SourceReadError {
    /// Opening or reading the file failed.
    Io(io::Error),
    /// The source exceeded the mandatory V1 byte limit.
    TooLarge {
        /// Maximum accepted source size.
        limit: usize,
    },
    /// The bounded source bytes were not valid UTF-8.
    InvalidUtf8 {
        /// Number of valid bytes before the malformed sequence.
        valid_up_to: usize,
        /// Malformed-sequence length when it was fully present.
        error_len: Option<usize>,
    },
}
impl fmt::Display for SourceReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(formatter),
            Self::TooLarge { limit } => {
                write!(
                    formatter,
                    "Kotodama V1 source exceeds the {limit}-byte limit"
                )
            }
            Self::InvalidUtf8 {
                valid_up_to,
                error_len,
            } => match error_len {
                Some(length) => write!(
                    formatter,
                    "Kotodama source is not valid UTF-8 at byte {valid_up_to} (invalid sequence length {length})"
                ),
                None => write!(
                    formatter,
                    "Kotodama source ends with an incomplete UTF-8 sequence at byte {valid_up_to}"
                ),
            },
        }
    }
}
impl Error for SourceReadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::TooLarge { .. } | Self::InvalidUtf8 { .. } => None,
        }
    }
}
/// Read one UTF-8 Kotodama source without ever buffering beyond the V1 limit.
///
/// Native immutable-file custody is checked before allocation and after the bounded
/// descriptor read. The original length rejects oversized input before buffering, and
/// changed files cannot replace a captured source or evade the mandatory V1 limit.
pub fn read_source_file(path: impl AsRef<Path>) -> Result<String, SourceReadError> {
    let selected = iroha_fs::SelectedRegularFile::capture(path).map_err(SourceReadError::Io)?;
    read_selected_source(&selected)
}

/// Read an already selected native source without resolving another file.
/// The original immutable descriptor survives intervening work; its byte limit and UTF-8
/// diagnostic fields remain the same as [`read_source_file`].
/// # Errors
/// Refuses changed native custody, oversized source and invalid UTF-8.
pub fn read_selected_source(
    selected: &iroha_fs::SelectedRegularFile,
) -> Result<String, SourceReadError> {
    if selected.len().map_err(SourceReadError::Io)? > MAX_SOURCE_BYTES as u64 {
        return Err(SourceReadError::TooLarge {
            limit: MAX_SOURCE_BYTES,
        });
    }
    let bytes = selected
        .read(MAX_SOURCE_BYTES)
        .map_err(SourceReadError::Io)?;
    String::from_utf8(bytes).map_err(|error| {
        let error = error.utf8_error();
        SourceReadError::InvalidUtf8 {
            valid_up_to: error.valid_up_to(),
            error_len: error.error_len(),
        }
    })
}
/// Stable source identifier inside one compilation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceId(pub u32);
/// Half-open UTF-8 byte range.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TextRange {
    /// First included byte offset.
    pub start: u32,
    /// First excluded byte offset.
    pub end: u32,
}
/// Exact source identity and half-open byte range retained across frontend phases.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceRange {
    /// Stable source identity inside the compilation graph.
    pub source: SourceId,
    /// Exact UTF-8 byte range in that source.
    pub range: TextRange,
}
impl SourceRange {
    /// Construct one graph-stable source range.
    #[must_use]
    pub const fn new(source: SourceId, range: TextRange) -> Self {
        Self { source, range }
    }
}
impl TextRange {
    /// Construct a half-open range.
    #[must_use]
    pub const fn new(start: u32, end: u32) -> Self {
        Self { start, end }
    }
    /// Construct an empty range at `offset`.
    #[must_use]
    pub const fn empty(offset: u32) -> Self {
        Self {
            start: offset,
            end: offset,
        }
    }
    /// Return the range length in bytes.
    #[must_use]
    pub const fn len(self) -> u32 {
        self.end.saturating_sub(self.start)
    }
    /// Return whether the range is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.start >= self.end
    }
    /// Return whether `other` is wholly contained in this range.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.start <= other.start && other.end <= self.end
    }
}
/// A byte range associated with a source file.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Span {
    /// Source containing the range.
    pub source: SourceId,
    /// Half-open UTF-8 byte range.
    pub range: TextRange,
}
/// One-based line and Unicode-scalar column.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LineColumn {
    /// One-based line number.
    pub line: usize,
    /// One-based display column.
    pub column: usize,
}
/// Immutable source file with a precomputed line index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceFile {
    id: SourceId,
    package_identity: Option<Arc<str>>,
    name: Arc<str>,
    text: Arc<str>,
    original_len: usize,
    line_starts: Arc<[u32]>,
    // Sparse byte-offset / Unicode-scalar-count pairs bound column lookup work
    // even when an entire contract is written on one line.
    character_checkpoints: Arc<[(u32, u32)]>,
}
impl SourceFile {
    /// Construct a source file without applying frontend budgets.
    ///
    /// Budget enforcement belongs to the syntax pipeline. Oversized callers
    /// retain only enough of a UTF-8 prefix to anchor the budget diagnostic;
    /// [`Self::original_len`] preserves the size used by that diagnostic.
    #[must_use]
    pub fn new(id: SourceId, name: impl Into<Arc<str>>, text: impl AsRef<str>) -> Self {
        Self::new_scoped(id, None::<Arc<str>>, name, text)
    }
    /// Construct a source file owned by one exact locked package.
    ///
    /// Package identity is intentionally separate from the portable logical path: two dependencies
    /// may both contain `src/lib.ko`, while diagnostics and source maps must still identify their
    /// owners without rewriting the source-visible path.
    #[must_use]
    pub fn new_in_package(
        id: SourceId,
        package_identity: impl Into<Arc<str>>,
        name: impl Into<Arc<str>>,
        text: impl AsRef<str>,
    ) -> Self {
        Self::new_scoped(id, Some(package_identity.into()), name, text)
    }
    fn new_scoped(
        id: SourceId,
        package_identity: Option<Arc<str>>,
        name: impl Into<Arc<str>>,
        text: impl AsRef<str>,
    ) -> Self {
        let name = name.into();
        let original = text.as_ref();
        let original_len = original.len();
        let retained = if original_len > MAX_SOURCE_BYTES {
            let mut end = MAX_SOURCE_BYTES.saturating_add(1).min(original_len);
            while end < original_len && !original.is_char_boundary(end) {
                end = end.saturating_add(1);
            }
            &original[..end]
        } else {
            original
        };
        let text: Arc<str> = Arc::from(retained);
        let mut line_starts = vec![0_u32];
        for (offset, byte) in text.bytes().enumerate() {
            if byte == b'\n' {
                let next = offset.saturating_add(1).min(u32::MAX as usize) as u32;
                line_starts.push(next);
            }
        }
        let mut character_checkpoints = vec![(0_u32, 0_u32)];
        for (characters, (offset, _)) in text.char_indices().enumerate() {
            if offset - character_checkpoints.last().expect("initial checkpoint").0 as usize >= 256
            {
                character_checkpoints.push((offset as u32, characters as u32));
            }
        }
        Self {
            id,
            package_identity,
            name,
            text,
            original_len,
            line_starts: line_starts.into(),
            character_checkpoints: character_checkpoints.into(),
        }
    }
    /// Return the stable source identifier.
    #[must_use]
    pub const fn id(&self) -> SourceId {
        self.id
    }
    /// Return the exact locked package identity, when this is a reusable
    /// package source rather than a deployable root or loose editor document.
    #[must_use]
    pub fn package_identity(&self) -> Option<&str> {
        self.package_identity.as_deref()
    }
    /// Return the logical source name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Return the complete accepted source, or the bounded diagnostic prefix
    /// when [`Self::original_len`] exceeds the V1 source limit.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }
    /// Return the byte length supplied by the caller before budget truncation.
    #[must_use]
    pub const fn original_len(&self) -> usize {
        self.original_len
    }
    /// Return the complete source byte range.
    #[must_use]
    pub fn full_range(&self) -> TextRange {
        TextRange::new(0, self.text.len().min(u32::MAX as usize) as u32)
    }
    /// Slice a byte range when it lies on UTF-8 boundaries inside the file.
    #[must_use]
    pub fn slice(&self, range: TextRange) -> Option<&str> {
        self.text.get(range.start as usize..range.end as usize)
    }
    /// Convert a byte offset to a one-based line and Unicode-scalar column.
    #[must_use]
    pub fn line_column(&self, offset: u32) -> LineColumn {
        let bounded = offset.min(self.text.len().min(u32::MAX as usize) as u32);
        let line_index = self
            .line_starts
            .partition_point(|line_start| *line_start <= bounded)
            .saturating_sub(1);
        let line_start = self.line_starts[line_index] as usize;
        let mut byte_offset = bounded as usize;
        while byte_offset > line_start && !self.text.is_char_boundary(byte_offset) {
            byte_offset -= 1;
        }
        let characters_before = |offset: usize| {
            let index = self
                .character_checkpoints
                .partition_point(|(byte, _)| *byte as usize <= offset)
                .saturating_sub(1);
            let (byte, characters) = self.character_checkpoints[index];
            characters as usize + self.text[byte as usize..offset].chars().count()
        };
        let column = characters_before(byte_offset) - characters_before(line_start) + 1;
        LineColumn {
            line: line_index.saturating_add(1),
            column,
        }
    }
}
/// Deterministic source-file collection for one compilation.
#[derive(Clone, Debug, Default)]
pub struct SourceDatabase {
    files: BTreeMap<SourceId, SourceFile>,
    next_id: u32,
}
impl SourceDatabase {
    /// Create an empty source database.
    #[must_use]
    pub fn new() -> Self {
        Self {
            files: BTreeMap::new(),
            next_id: 0,
        }
    }
    /// Insert a source file and return its deterministic insertion-order id.
    pub fn add(&mut self, name: impl Into<Arc<str>>, text: impl AsRef<str>) -> SourceId {
        let id = SourceId(self.next_id);
        self.next_id = self.next_id.saturating_add(1);
        self.files.insert(id, SourceFile::new(id, name, text));
        id
    }
    /// Insert a source file with an explicitly assigned id.
    pub fn insert(&mut self, file: SourceFile) -> Option<SourceFile> {
        self.next_id = self.next_id.max(file.id().0.saturating_add(1));
        self.files.insert(file.id(), file)
    }
    /// Look up a source file.
    #[must_use]
    pub fn get(&self, id: SourceId) -> Option<&SourceFile> {
        self.files.get(&id)
    }
    /// Return the number of source files.
    #[must_use]
    pub fn len(&self) -> usize {
        self.files.len()
    }
    /// Return whether no source files are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}
/// Fixed compiler-resource limits for Kotodama V1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrontendBudget {
    max_source_bytes: usize,
    max_tokens: usize,
    max_nesting: usize,
    max_diagnostics: usize,
}
impl FrontendBudget {
    /// Return the mandatory V1 frontend budget.
    #[must_use]
    pub const fn v1() -> Self {
        Self {
            max_source_bytes: MAX_SOURCE_BYTES,
            max_tokens: MAX_TOKENS,
            max_nesting: MAX_NESTING_DEPTH,
            max_diagnostics: MAX_DIAGNOSTICS,
        }
    }
    /// Maximum source bytes.
    #[must_use]
    pub const fn max_source_bytes(self) -> usize {
        self.max_source_bytes
    }
    /// Maximum non-trivia tokens, including end-of-file.
    #[must_use]
    pub const fn max_tokens(self) -> usize {
        self.max_tokens
    }
    /// Maximum syntax nesting.
    #[must_use]
    pub const fn max_nesting(self) -> usize {
        self.max_nesting
    }
    /// Maximum retained diagnostics.
    #[must_use]
    pub const fn max_diagnostics(self) -> usize {
        self.max_diagnostics
    }
}
impl Default for FrontendBudget {
    fn default() -> Self {
        Self::v1()
    }
}
#[cfg(test)]
mod tests {
    use super::{MAX_SOURCE_BYTES, SourceFile, SourceId, SourceReadError, read_source_file};
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);
    fn with_temp_source(bytes: &[u8], test: impl FnOnce(&std::path::Path)) {
        let nonce = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "kotodama-source-budget-{}-{nonce}.ko",
            std::process::id()
        ));
        fs::write(&path, bytes).expect("write temporary source");
        test(&path);
        fs::remove_file(path).expect("remove temporary source");
    }
    #[test]
    fn sparse_column_index_preserves_unicode_and_interior_byte_offsets() {
        let text = format!("{}\n{}\n", "ab日本😀".repeat(180), "é文字x".repeat(180));
        let source = SourceFile::new(SourceId(0), "unicode.ko", &text);
        for offset in 0..=text.len() + 2 {
            let mut boundary = offset.min(text.len());
            while !text.is_char_boundary(boundary) {
                boundary -= 1;
            }
            let prefix = &text[..boundary];
            let position = source.line_column(offset as u32);
            assert_eq!(
                position.line,
                prefix.bytes().filter(|byte| *byte == b'\n').count() + 1
            );
            assert_eq!(
                position.column,
                prefix.rsplit('\n').next().unwrap().chars().count() + 1
            );
        }
        assert!(source.character_checkpoints.len() < text.len() / 200);
    }

    #[test]
    fn bounded_reader_accepts_exact_limit_and_rejects_one_extra_byte() {
        let exact = vec![b' '; MAX_SOURCE_BYTES];
        with_temp_source(&exact, |path| {
            assert_eq!(
                read_source_file(path).expect("read exact limit").len(),
                exact.len()
            );
        });
        let oversized = vec![b' '; MAX_SOURCE_BYTES + 1];
        with_temp_source(&oversized, |path| {
            let error = read_source_file(path).expect_err("oversized source must fail");
            assert!(matches!(
                error,
                SourceReadError::TooLarge {
                    limit: MAX_SOURCE_BYTES
                }
            ));
        });
    }
    #[test]
    fn bounded_reader_rejects_invalid_utf8() {
        with_temp_source(&[0xff], |path| {
            let error = read_source_file(path).expect_err("invalid UTF-8 must fail");
            assert!(matches!(
                error,
                SourceReadError::InvalidUtf8 {
                    valid_up_to: 0,
                    error_len: Some(1)
                }
            ));
        });
        with_temp_source(&[b'a', 0xc2], |path| {
            let error = read_source_file(path).expect_err("incomplete UTF-8 must fail");
            assert!(matches!(
                error,
                SourceReadError::InvalidUtf8 {
                    valid_up_to: 1,
                    error_len: None
                }
            ));
        });
    }
    #[test]
    fn selected_reader_preserves_exact_utf8_and_byte_limit_diagnostics() {
        with_temp_source(b"seiyaku Selected {}", |path| {
            let selected = iroha_fs::SelectedRegularFile::capture(path).expect("selected source");
            assert_eq!(
                super::read_selected_source(&selected).expect("first read"),
                "seiyaku Selected {}"
            );
            assert_eq!(
                super::read_selected_source(&selected).expect("repeat read"),
                "seiyaku Selected {}"
            );
        });
        with_temp_source(&vec![b' '; MAX_SOURCE_BYTES + 1], |path| {
            let selected =
                iroha_fs::SelectedRegularFile::capture(path).expect("selected oversized source");
            assert!(matches!(
                super::read_selected_source(&selected),
                Err(SourceReadError::TooLarge {
                    limit: MAX_SOURCE_BYTES
                })
            ));
        });
        with_temp_source(&[b'a', 0xc2], |path| {
            let selected =
                iroha_fs::SelectedRegularFile::capture(path).expect("selected invalid source");
            assert!(matches!(
                super::read_selected_source(&selected),
                Err(SourceReadError::InvalidUtf8 {
                    valid_up_to: 1,
                    error_len: None
                })
            ));
        });
    }

    #[cfg(unix)]
    #[test]
    fn selected_reader_refuses_changed_original_source_before_utf8_parsing() {
        with_temp_source(b"seiyaku Selected {}", |path| {
            let selected = iroha_fs::SelectedRegularFile::capture(path).expect("selected source");
            fs::write(path, [0xff]).expect("change original source");
            assert!(matches!(
                super::read_selected_source(&selected),
                Err(SourceReadError::Io(_))
            ));
        });
    }

    #[test]
    fn source_file_retains_only_a_bounded_prefix_of_oversized_input() {
        let source = "é".repeat(MAX_SOURCE_BYTES);
        let file = SourceFile::new(SourceId(7), "oversized.ko", &source);
        assert_eq!(file.original_len(), source.len());
        assert!(file.text().len() > MAX_SOURCE_BYTES);
        assert!(file.text().len() <= MAX_SOURCE_BYTES + 'é'.len_utf8());
        assert!(file.text().is_char_boundary(file.text().len()));
        assert_eq!(file.line_starts.len(), 1);
    }
}
