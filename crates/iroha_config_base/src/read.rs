//! Configuration reader API.
use drop_bomb::DropBomb;
use error_stack::{Report, ResultExt};
use norito::json::JsonDeserializeOwned;
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::identity,
    error::Error as StdError,
    fmt::Debug,
    path::{Path, PathBuf},
};
use thiserror::Error;
type Result<T, E> = core::result::Result<T, Report<[E]>>;
use crate::{
    ParameterId, ParameterOrigin, WithOrigin, attach,
    attach::{MissingParameter, UnknownParameter},
    env::{FromEnvStr, ReadEnv},
    toml::{self, TomlSource},
    util::Emitter,
};
/// Maximum number of `extends` edges plus the root source in one traversal.
///
/// Repeated diamond edges count toward this ceiling even though their already
/// visited target is loaded only once. This also bounds the explicit DFS stack.
pub const MAX_TOML_EXTENDS_SOURCES: usize = 64;
/// Maximum nesting depth of a TOML `extends` graph, with the root at depth zero.
pub const MAX_TOML_EXTENDS_DEPTH: u8 = 32;
/// Maximum aggregate encoded bytes across unique TOML sources in one traversal.
pub const MAX_TOML_EXTENDS_TOTAL_BYTES: u64 = 8 * toml::MAX_TOML_SOURCE_BYTES;
/// A type that implements reading from [`ConfigReader`]
pub trait ReadConfig: Sized {
    /// Returns the [`FinalWrap`] with self and the reader itself, transformed
    /// throughout the process of reading.
    ///
    /// The wrap is guaranteed to unwrap safely if the reader emits
    /// no error upon [`ConfigReader::into_result`].
    fn read(reader: &mut ConfigReader) -> FinalWrap<Self>;
}
/// An umbrella error for various cases related to [`ConfigReader`].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Failed to read configuration from file.
    #[error("Failed to read configuration from file")]
    ReadFile,
    /// The `extends` field is malformed or invalid.
    #[error("Invalid `extends` field")]
    InvalidExtends,
    /// Extending configuration files failed.
    #[error("Failed to extend configurations")]
    CannotExtend,
    /// Failed to parse a specific parameter.
    #[error("Failed to parse parameter `{0}`")]
    ParseParameter(ParameterId),
    /// Errors occurred while reading from a file.
    #[error("Errors occurred while reading from file: `{path}`", path = .0.display())]
    InSourceFile(PathBuf),
    /// Errors occurred while reading from environment variables.
    #[error("Errors occurred while reading from environment variables")]
    InEnvironment,
    /// Some required parameters are missing.
    #[error("Some required parameters are missing")]
    MissingParameters,
    /// Found unrecognised parameters that are not part of the schema.
    #[error("Found unrecognised parameters")]
    UnknownParameters,
}
#[derive(Debug, Error, Copy, Clone, Eq, PartialEq)]
enum ExtendsPathsError {
    #[error("expected a string or an array of strings")]
    InvalidType,
    #[error("array element at index {index} must be a string")]
    InvalidArrayElement { index: usize },
}
#[derive(Debug, Error, Eq, PartialEq)]
enum ExtendsTraversalError {
    #[error("configuration `extends` cycle detected at `{}`", path.display())]
    Cycle { path: PathBuf },
    #[error("configuration `extends` depth {observed} exceeds the maximum {maximum}")]
    DepthLimit { observed: u8, maximum: u8 },
    #[error("configuration `extends` source references {observed} exceed the maximum {maximum}")]
    SourceLimit { observed: usize, maximum: usize },
    #[error("configuration `extends` encoded bytes {observed} exceed the maximum {maximum}")]
    ByteLimit { observed: u64, maximum: u64 },
}
#[derive(Debug)]
struct ExtendsTraversalBudget {
    source_references: usize,
    bytes_read: u64,
}
impl ExtendsTraversalBudget {
    fn new() -> Self {
        Self {
            source_references: 1,
            bytes_read: 0,
        }
    }
    fn check_depth(depth: u8) -> core::result::Result<(), ExtendsTraversalError> {
        if depth > MAX_TOML_EXTENDS_DEPTH {
            return Err(ExtendsTraversalError::DepthLimit {
                observed: depth,
                maximum: MAX_TOML_EXTENDS_DEPTH,
            });
        }
        Ok(())
    }
    fn schedule_sources(
        &mut self,
        additional: usize,
    ) -> core::result::Result<(), ExtendsTraversalError> {
        let observed = self.source_references.saturating_add(additional);
        if observed > MAX_TOML_EXTENDS_SOURCES {
            return Err(ExtendsTraversalError::SourceLimit {
                observed,
                maximum: MAX_TOML_EXTENDS_SOURCES,
            });
        }
        self.source_references = observed;
        Ok(())
    }
    fn record_bytes(&mut self, additional: u64) -> core::result::Result<(), ExtendsTraversalError> {
        let observed = self.bytes_read.saturating_add(additional);
        if observed > MAX_TOML_EXTENDS_TOTAL_BYTES {
            return Err(ExtendsTraversalError::ByteLimit {
                observed,
                maximum: MAX_TOML_EXTENDS_TOTAL_BYTES,
            });
        }
        self.bytes_read = observed;
        Ok(())
    }
    fn remaining_bytes(&self) -> u64 {
        MAX_TOML_EXTENDS_TOTAL_BYTES.saturating_sub(self.bytes_read)
    }
}
fn extends_traversal_report(error: ExtendsTraversalError) -> Report<Error> {
    Report::new(error).change_context(Error::CannotExtend)
}
fn extends_read_report(
    report: Report<toml::FromFileError>,
    path: &Path,
    parent: Option<&PathBuf>,
    depth: u8,
) -> Report<Error> {
    let report = report
        .attach(attach::FilePath::new(path.to_path_buf()))
        .change_context(Error::ReadFile);
    match parent {
        Some(parent_path) => report.attach(attach::ExtendsChain::new(
            parent_path.clone(),
            path.to_path_buf(),
            depth,
        )),
        None => report,
    }
}
fn read_toml_source_with_budget(
    path: &Path,
    parent: Option<&PathBuf>,
    depth: u8,
    expected_identity: &toml::RegularFileIdentity,
    budget: &mut ExtendsTraversalBudget,
) -> Result<TomlSource, Error> {
    let source_limit = toml::MAX_TOML_SOURCE_BYTES.min(budget.remaining_bytes());
    let (source, bytes_read, loaded_identity) =
        match TomlSource::from_file_with_limit(path, source_limit) {
            Ok(loaded) => loaded,
            Err(error) => {
                if let toml::FromFileError::TooLarge { actual, .. } = *error.current_context()
                    && source_limit < toml::MAX_TOML_SOURCE_BYTES
                {
                    return Err(extends_traversal_report(ExtendsTraversalError::ByteLimit {
                        observed: budget.bytes_read.saturating_add(actual),
                        maximum: MAX_TOML_EXTENDS_TOTAL_BYTES,
                    })
                    .into());
                }
                return Err(extends_read_report(error, path, parent, depth).into());
            }
        };
    if &loaded_identity != expected_identity {
        return Err(extends_read_report(
            Report::new(toml::FromFileError::ChangedWhileReading),
            path,
            parent,
            depth,
        )
        .into());
    }
    budget
        .record_bytes(bytes_read)
        .map_err(extends_traversal_report)?;
    Ok(source)
}
fn take_extends_paths(source: &mut TomlSource) -> Result<Vec<PathBuf>, Error> {
    let Some(extends) = source.table_mut().remove("extends") else {
        return Ok(Vec::new());
    };
    let parsed = parse_extends_paths(&extends)
        .map_err(Report::new)
        .attach_with(|| {
            attach::Expected::new(
                r#"a single path ("./file.toml") or an array of paths (["a.toml", "b.toml", "c.toml"])"#,
            )
        })
        .attach_with(|| attach::ActualValue::new(extends))
        .change_context(Error::InvalidExtends)?;
    log::trace!("found `extends`: {parsed:?}");
    Ok(parsed)
}
fn parse_extends_paths(
    value: &::toml::Value,
) -> core::result::Result<Vec<PathBuf>, ExtendsPathsError> {
    match value {
        ::toml::Value::String(path) => Ok(vec![PathBuf::from(path)]),
        ::toml::Value::Array(values) => values
            .iter()
            .enumerate()
            .map(|(index, value)| match value {
                ::toml::Value::String(path) => Ok(PathBuf::from(path)),
                _ => Err(ExtendsPathsError::InvalidArrayElement { index }),
            })
            .collect(),
        _ => Err(ExtendsPathsError::InvalidType),
    }
}
#[derive(Error, Debug)]
#[error("{0}")]
struct EnvError(String);
#[derive(Error, Debug)]
#[error("failed to deserialize config value: {message}")]
struct JsonValueError {
    message: String,
}
fn normalize_json_error_message(raw: &str) -> String {
    raw.strip_prefix("JSON error: ").unwrap_or(raw).to_string()
}
impl From<norito::json::Error> for JsonValueError {
    fn from(error: norito::json::Error) -> Self {
        let message = error.to_string();
        Self {
            message: normalize_json_error_message(&message),
        }
    }
}
impl From<Report<norito::json::Error>> for JsonValueError {
    fn from(report: Report<norito::json::Error>) -> Self {
        let message = report.to_string();
        Self {
            message: normalize_json_error_message(&message),
        }
    }
}
#[expect(clippy::too_long_first_doc_paragraph)]
/// The reader, which provides an API to accumulate config sources, read parameters from them,
/// optionally override with an explicitly supplied environment reader, fall back to default values,
/// and finally construct an
/// exhaustive error report with as many errors, accumulated along the way, as possible.
pub struct ConfigReader {
    /// The namespace this [`ConfigReader`] is handling. All the `ParameterId` handled will be prefixed with it.
    nesting: Vec<String>,
    /// File sources for the config
    sources: Vec<TomlSource>,
    /// Environment variables source for the config
    env: Box<dyn ReadEnv>,
    /// Errors accumulated per each file
    errors_by_source: BTreeMap<PathBuf, Vec<Report<Error>>>,
    /// Errors accumulated from the environment variables
    errors_in_env: Vec<Report<EnvError>>,
    /// A list of all the parameters that have been requested from this reader. Used to report unused (unknown) parameters in the toml file
    existing_parameters: BTreeSet<ParameterId>,
    /// A list of all required parameters that have been requested, but were not found
    missing_parameters: BTreeSet<ParameterId>,
    /// A runtime guard to prevent dropping the [`ConfigReader`] without handing errors
    bomb: DropBomb,
}
impl Debug for ConfigReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ConfigReader")
    }
}
impl Default for ConfigReader {
    fn default() -> Self {
        Self::new()
    }
}
impl ConfigReader {
    /// Constructor
    pub fn new() -> Self {
        Self {
            sources: <_>::default(),
            nesting: <_>::default(),
            errors_by_source: <_>::default(),
            errors_in_env: <_>::default(),
            existing_parameters: <_>::default(),
            missing_parameters: <_>::default(),
            bomb: DropBomb::new("forgot to call `ConfigReader::into_result()`, didn't you?"),
            env: Box::new(crate::env::std_env),
        }
    }
    /// Install an explicit environment reader.
    #[must_use]
    pub fn with_env(mut self, env: impl ReadEnv + 'static) -> Self {
        self.env = Box::new(env);
        self
    }
    /// Disable environment-variable overlays.
    ///
    /// Artifact-backed production readers should use this so the ambient launcher environment
    /// cannot rewrite the supplied configuration.
    #[must_use]
    pub fn without_env(mut self) -> Self {
        self.env = Box::new(crate::env::empty_env);
        self
    }
    /// Add a data source to read parameters from.
    #[must_use]
    pub fn with_toml_source(mut self, source: TomlSource) -> Self {
        self.sources.push(source);
        self
    }
    /// Return whether any loaded TOML source explicitly defines `id`.
    ///
    /// This distinguishes an operator-provided value from a value materialized by [`ReadConfig`]
    /// defaults. Sources loaded through [`Self::read_toml_with_extends`] are included.
    #[must_use]
    pub fn contains_toml_parameter(&self, id: impl Into<ParameterId>) -> bool {
        let id = self.full_id(id);
        self.sources
            .iter()
            .any(|source| source.fetch(&id).is_some())
    }
    /// TOML sources in precedence order: a later source overrides an earlier one.
    #[must_use]
    pub fn toml_sources(&self) -> &[TomlSource] {
        &self.sources
    }
    /// Exclusive access to the loaded TOML sources, in precedence order.
    ///
    /// Layered loaders use this to complete values that the file layout derives (for example
    /// paths under a node data directory) before any parameter is read.
    pub fn toml_sources_mut(&mut self) -> &mut [TomlSource] {
        &mut self.sources
    }
    /// Reads a TOML file and handles its `extends` field, implementing mixins mechanism.
    ///
    /// The traversal is depth-first in declared order. Canonically identical files reached through
    /// a diamond are applied once, while an edge back to an active source is rejected as a cycle.
    /// The traversal is bounded by [`MAX_TOML_EXTENDS_DEPTH`], [`MAX_TOML_EXTENDS_SOURCES`],
    /// [`MAX_TOML_EXTENDS_TOTAL_BYTES`], and [`toml::MAX_TOML_SOURCE_BYTES`]. Source paths must
    /// name stable regular files; symbolic links are rejected.
    ///
    /// # Errors
    ///
    /// If a source cannot be read or parsed, a cycle is found, or a traversal
    /// or encoded-byte ceiling is exceeded.
    pub fn read_toml_with_extends<P: AsRef<Path>>(mut self, path: P) -> Result<Self, Error> {
        #[derive(Debug)]
        enum StackEntry {
            Visit {
                path: PathBuf,
                depth: u8,
                parent: Option<PathBuf>,
            },
            Emit {
                identity: toml::RegularFileIdentity,
                source: TomlSource,
            },
        }
        let result = (|| -> Result<(), Error> {
            let mut stack = vec![StackEntry::Visit {
                path: path.as_ref().to_path_buf(),
                depth: 0,
                parent: None,
            }];
            let mut active = BTreeSet::new();
            let mut visited = BTreeSet::new();
            let mut budget = ExtendsTraversalBudget::new();
            while let Some(entry) = stack.pop() {
                let (path, depth, parent) = match entry {
                    StackEntry::Visit {
                        path,
                        depth,
                        parent,
                    } => (path, depth, parent),
                    StackEntry::Emit { identity, source } => {
                        let removed = active.remove(&identity);
                        debug_assert!(removed, "emitted TOML source must be active");
                        visited.insert(identity);
                        self.sources.push(source);
                        continue;
                    }
                };
                ExtendsTraversalBudget::check_depth(depth).map_err(extends_traversal_report)?;
                let (identity, canonical_path) = toml::canonical_regular_file_identity(&path)
                    .map_err(|error| extends_read_report(error, &path, parent.as_ref(), depth))?;
                if active.contains(&identity) {
                    return Err(extends_traversal_report(ExtendsTraversalError::Cycle {
                        path: canonical_path,
                    })
                    .into());
                }
                if visited.contains(&identity) {
                    continue;
                }
                let mut source = read_toml_source_with_budget(
                    &path,
                    parent.as_ref(),
                    depth,
                    &identity,
                    &mut budget,
                )?;
                let extends_paths = take_extends_paths(&mut source)?;
                budget
                    .schedule_sources(extends_paths.len())
                    .map_err(extends_traversal_report)?;
                active.insert(identity.clone());
                stack.push(StackEntry::Emit { identity, source });
                let child_depth = depth.saturating_add(1);
                let parent_dir = path.parent().unwrap_or_else(|| Path::new(""));
                for extends_path in extends_paths.into_iter().rev() {
                    stack.push(StackEntry::Visit {
                        path: parent_dir.join(extends_path),
                        depth: child_depth,
                        parent: Some(path.clone()),
                    });
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            self.bomb.defuse();
            return Err(error);
        }
        Ok(self)
    }
    /// Instantiate a parameter reading pipeline.
    #[must_use]
    pub fn read_parameter<T>(&mut self, id: impl Into<ParameterId>) -> ReadingParameter<'_, T>
    where
        T: JsonDeserializeOwned,
    {
        let id = self.full_id(id);
        self.collect_parameter(&id);
        ReadingParameter::new(self, id).fetch()
    }
    /// Delegate reading to another implementor of [`ReadConfig`] under a certain namespace.
    /// All parameter IDs in it will be resolved within that namespace.
    #[must_use]
    pub fn read_nested<T: ReadConfig>(&mut self, namespace: impl AsRef<str>) -> FinalWrap<T> {
        self.nesting.push(namespace.as_ref().to_string());
        let value = T::read(self);
        self.nesting.pop();
        value
    }
    /// Finally, complete the reading procedure and emit a collective report
    /// in case if any error occurred along the reading process.
    ///
    /// # Errors
    /// If any occurred while reading of data.
    pub fn into_result(mut self) -> Result<(), Error> {
        self.bomb.defuse();
        let mut emitter = Emitter::new();
        if !self.missing_parameters.is_empty() {
            let mut report = Report::new(Error::MissingParameters);
            for i in self.missing_parameters {
                report = report.attach(MissingParameter::new(i));
            }
            emitter.emit(report);
        }
        // looking for unknown parameters
        for source in &self.sources {
            let unknown_parameters = source.find_unknown(self.existing_parameters.iter());
            if !unknown_parameters.is_empty() {
                let mut report = Report::new(Error::UnknownParameters);
                for i in unknown_parameters {
                    report = report.attach(UnknownParameter::new(i));
                }
                self.errors_by_source
                    .entry(source.path().clone())
                    .or_default()
                    .push(report);
            }
        }
        // emit reports by source
        for (source, reports) in self.errors_by_source {
            let mut local_emitter = Emitter::new();
            for report in reports {
                local_emitter.emit(report);
            }
            let report = local_emitter
                .into_result()
                .expect_err("there should be at least one error");
            emitter.emit(report.change_context(Error::InSourceFile(source)))
        }
        // environment parsing errors
        if !self.errors_in_env.is_empty() {
            let mut local_emitter = Emitter::new();
            for report in self.errors_in_env {
                local_emitter.emit(report);
            }
            let report = local_emitter
                .into_result()
                .expect_err("there should be at least one error");
            emitter.emit(report.change_context(Error::InEnvironment));
        }
        emitter.into_result()
    }
    /// A shorthand to "just read the config and get an error or the value".
    /// # Errors
    /// See [`Self::into_result`]
    pub fn read_and_complete<T: ReadConfig>(mut self) -> Result<T, Error> {
        let value = T::read(&mut self);
        self.into_result()?;
        Ok(value.unwrap())
    }
    fn full_id(&self, id: impl Into<ParameterId>) -> ParameterId {
        self.nesting.iter().chain(id.into().segments.iter()).into()
    }
    fn collect_deserialize_error<C: StdError + Send + Sync + 'static>(
        &mut self,
        source_path: PathBuf,
        path: &ParameterId,
        report: Report<C>,
    ) {
        self.errors_by_source
            .entry(source_path)
            .or_default()
            .push(report.change_context(Error::ParseParameter(path.clone())));
    }
    fn collect_env_error(&mut self, report: Report<EnvError>) {
        self.errors_in_env.push(report)
    }
    fn collect_parameter(&mut self, id: &ParameterId) {
        self.existing_parameters.insert(id.clone());
    }
    fn collect_missing_parameter(&mut self, id: &ParameterId) {
        self.missing_parameters.insert(id.clone());
    }
    fn fetch_parameter<T>(
        &mut self,
        id: &ParameterId,
    ) -> std::result::Result<Option<WithOrigin<T>>, ()>
    where
        T: JsonDeserializeOwned,
    {
        let mut errored = false;
        let mut value = None;
        let mut errors: Vec<(PathBuf, Report<JsonValueError>)> = Vec::new();
        for source in &self.sources {
            if let Some(toml_value) = source.fetch(id) {
                let source_path = source.path().clone();
                let json_value = match toml::value_to_json(toml_value) {
                    Ok(value) => value,
                    Err(error) => {
                        errored = true;
                        value = None;
                        errors.push((
                            source_path.clone(),
                            Report::new(JsonValueError::from(error)),
                        ));
                        continue;
                    }
                };
                let result: std::result::Result<T, _> = T::json_from_value(&json_value);
                match (result, errored) {
                    (Ok(v), false) => {
                        if value.is_none() {
                            log::trace!("parameter `{id}`: found in `{}`", source_path.display());
                        } else {
                            log::trace!(
                                "parameter `{id}`: found in `{}`, overwriting previous value",
                                source_path.display()
                            );
                        }
                        value = Some(WithOrigin::new(
                            v,
                            ParameterOrigin::file(id.clone(), source_path.clone()),
                        ));
                    }
                    // we don't care if there was an error before
                    (Ok(_), true) => {}
                    (Err(error), _) => {
                        errored = true;
                        value = None;
                        errors.push((
                            source_path.clone(),
                            Report::new(JsonValueError::from(error)),
                        ));
                    }
                }
            } else {
                log::trace!(
                    "parameter `{id}`: not found in `{}`",
                    source.path().display()
                )
            }
        }
        for (source_path, report) in errors {
            self.collect_deserialize_error(source_path, id, report);
        }
        if errored { Err(()) } else { Ok(value) }
    }
}
/// A state of reading a certain configuration parameter.
pub struct ReadingParameter<'reader, T> {
    reader: &'reader mut ConfigReader,
    id: ParameterId,
    value: Option<WithOrigin<T>>,
    errored: bool,
}
impl<'reader, T> ReadingParameter<'reader, T> {
    fn new(reader: &'reader mut ConfigReader, id: ParameterId) -> Self {
        Self {
            reader,
            id,
            value: None,
            errored: false,
        }
    }
}
impl<T> ReadingParameter<'_, T>
where
    T: JsonDeserializeOwned,
{
    #[must_use]
    fn fetch(mut self) -> Self {
        match self.reader.fetch_parameter(&self.id) {
            Ok(value) => {
                self.value = value;
            }
            Err(()) => {
                self.errored = true;
            }
        }
        self
    }
}
impl<T> ReadingParameter<'_, T>
where
    T: FromEnvStr,
{
    /// Reads an environment variable and parses the value which is [`FromEnvStr`].
    #[must_use]
    pub fn env(mut self, var: impl AsRef<str>) -> Self {
        let var = var.as_ref();
        if let Some(raw_str) = self.reader.env.read_env(var) {
            match (T::from_env_str(raw_str), self.errored) {
                (Err(error), _) => {
                    self.errored = true;
                    self.reader
                        .collect_env_error(Report::new(error).change_context(EnvError(format!(
                            "Failed to parse parameter `{}` from `{var}`",
                            self.id,
                        ))));
                }
                (Ok(value), false) => {
                    if self.value.is_none() {
                        log::trace!("parameter `{}`: found `{var}` env var", self.id,);
                    } else {
                        log::trace!(
                            "parameter `{}`: found `{var}` env var, overwriting previous value",
                            self.id,
                        );
                    }
                    self.value = Some(WithOrigin::new(
                        value,
                        ParameterOrigin::env(self.id.clone(), var.to_string()),
                    ));
                }
                (Ok(_ignore), true) => {
                    log::trace!(
                        "parameter `{}`: env var `{var}` found, ignore due to previous errors",
                        self.id,
                    );
                }
            }
        } else {
            log::trace!("parameter `{}`: env var `{var}` not found", self.id)
        }
        self
    }
}
impl<T> ReadingParameter<'_, T> {
    /// Finish reading, and if the value is not read so far, it will be reported later on [`ConfigReader::into_result`].
    #[must_use]
    pub fn value_required(self) -> ReadingDone<T> {
        match (self.errored, self.value) {
            (false, Some(value)) => ReadingDone(ReadingDoneValue::Fine(value)),
            (false, None) => {
                self.reader.collect_missing_parameter(&self.id);
                ReadingDone(ReadingDoneValue::Errored)
            }
            (true, _) => ReadingDone(ReadingDoneValue::Errored),
        }
    }
    /// Finish reading, falling back to a default value if it is absent
    #[must_use]
    pub fn value_or_else<F: FnOnce() -> T>(self, fun: F) -> ReadingDone<T> {
        match (self.errored, self.value) {
            (false, Some(value)) => ReadingDone(ReadingDoneValue::Fine(value)),
            (false, None) => {
                log::trace!("parameter `{}`: fallback to default value", self.id);
                ReadingDone(ReadingDoneValue::Fine(WithOrigin::new(
                    fun(),
                    ParameterOrigin::default(self.id.clone()),
                )))
            }
            (true, _) => ReadingDone(ReadingDoneValue::Errored),
        }
    }
    /// Finish reading, allowing value to be not present
    #[must_use]
    pub fn value_optional(self) -> OptionReadingDone<T> {
        match (self.errored, self.value) {
            (false, value) => OptionReadingDone(ReadingDoneValue::Fine(value)),
            (true, _) => OptionReadingDone(ReadingDoneValue::Errored),
        }
    }
}
// Lifetime is elided intentionally (`'_`) to avoid triggering the
// `single-use-lifetimes` lint while still binding the impl to the reader borrow.
impl<T: Default> ReadingParameter<'_, T> {
    /// Equivalent of [`ReadingParameter::value_or_else`] with [`Default::default`].
    #[must_use]
    pub fn value_or_default(self) -> ReadingDone<T> {
        self.value_or_else(Default::default)
    }
}
enum ReadingDoneValue<T> {
    Errored,
    Fine(T),
}
impl<T> ReadingDoneValue<T> {
    fn into_final(self) -> FinalWrap<T> {
        self.into_final_with(identity)
    }
    fn into_final_with<F, U>(self, f: F) -> FinalWrap<U>
    where
        F: FnOnce(T) -> U,
    {
        match self {
            Self::Errored => FinalWrap(FinalWrapInner::Errored),
            Self::Fine(t) => FinalWrap(FinalWrapInner::Value(Box::new(f(t)))),
        }
    }
}
/// A state of reading when the parameter's value is read, and the next step is to finish it via
/// [`ReadingDone::finish`] or [`ReadingDone::finish_with_origin`]
pub struct ReadingDone<T>(ReadingDoneValue<WithOrigin<T>>);
/// Same as [`ReadingDone`], but holding an optional value.
pub struct OptionReadingDone<T>(ReadingDoneValue<Option<WithOrigin<T>>>);
impl<T> ReadingDone<T> {
    /// Finish with the value only.
    #[must_use]
    pub fn finish(self) -> FinalWrap<T> {
        self.0.into_final_with(WithOrigin::into_value)
    }
    /// Finish with the value and its origin
    #[must_use]
    pub fn finish_with_origin(self) -> FinalWrap<WithOrigin<T>> {
        self.0.into_final()
    }
}
impl<T> OptionReadingDone<T> {
    /// Finish with the value only
    #[must_use]
    pub fn finish(self) -> FinalWrap<Option<T>> {
        self.0.into_final_with(|x| x.map(WithOrigin::into_value))
    }
    /// Finish with the value and its origin
    #[must_use]
    pub fn finish_with_origin(self) -> FinalWrap<Option<WithOrigin<T>>> {
        self.0.into_final()
    }
}
/// A value that should be accessed only if overall configuration reading succeeded.
///
/// I.e. it is guaranteed that [`FinalWrap::unwrap`] will not panic after associated
/// [`ConfigReader::into_result`] returns [`Ok`].
/// Wrapper that yields a value only if overall configuration reading succeeds.
///
/// It defers actual computation or unwrap until the caller verifies that
/// `ConfigReader::into_result` returned `Ok`, preventing premature panics while
/// aggregating configuration errors.
pub struct FinalWrap<T>(FinalWrapInner<T>);
/// Exists to not expose enum variants if they were in [`FinalWrap`]
enum FinalWrapInner<T> {
    Errored,
    // Keep deferred wrappers independent of T: derived readers capture one per field.
    Value(Box<T>),
    ValueFn(Box<dyn FnOnce() -> T>),
}
impl<T> FinalWrap<T> {
    /// Pass a closure that will emit the value on [`Self::unwrap`].
    pub fn value_fn<F>(fun: F) -> Self
    where
        F: FnOnce() -> T + 'static,
    {
        Self(FinalWrapInner::ValueFn(Box::new(fun)))
    }
    /// Unwrap the value inside.
    ///
    /// Can be safely called only after the [`ConfigReader::into_result`] returned [Ok].
    ///
    /// # Panics
    /// Might panic if an error occurred while reading of this certain value.
    pub fn unwrap(self) -> T {
        match self.0 {
            FinalWrapInner::Errored => panic!(
                "`FinalWrap::unwrap` is supposed to be called only after `ConfigReader::into_result` returns OK; it is probably a bug"
            ),
            FinalWrapInner::Value(value) => *value,
            FinalWrapInner::ValueFn(fun) => fun(),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT_TEMP_DIR: AtomicU64 = AtomicU64::new(0);
    fn temp_config_dir(label: &str) -> PathBuf {
        let nonce = NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "iroha_config_base_{label}_{}_{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create temporary configuration directory");
        path
    }
    fn report_debug(report: &Report<[Error]>) -> String {
        format!("{report:#?}")
    }
    #[derive(Debug)]
    struct RejectValueFastPath;
    impl norito::json::JsonDeserialize for RejectValueFastPath {
        fn json_deserialize(
            parser: &mut norito::json::Parser<'_>,
        ) -> std::result::Result<Self, norito::json::Error> {
            <bool as norito::json::JsonDeserialize>::json_deserialize(parser).map(|_| Self)
        }
        fn json_from_value(
            _value: &norito::json::Value,
        ) -> std::result::Result<Self, norito::json::Error> {
            Err(norito::json::Error::Message(
                "value conversion rejected".to_owned(),
            ))
        }
    }
    #[test]
    fn toml_sources_expose_precedence_order_and_allow_completion() {
        let mut reader = ConfigReader::new()
            .without_env()
            .with_toml_source(TomlSource::inline(::toml::toml! { first = 1 }))
            .with_toml_source(TomlSource::inline(::toml::toml! { second = 2 }));
        assert_eq!(reader.toml_sources().len(), 2);
        assert!(reader.toml_sources()[0].table().contains_key("first"));
        assert!(reader.toml_sources()[1].table().contains_key("second"));
        reader.toml_sources_mut()[0]
            .table_mut()
            .insert("completed".to_owned(), ::toml::Value::Integer(3));
        assert!(reader.contains_toml_parameter(["completed"]));
        let completed = reader
            .read_parameter::<u64>(["completed"])
            .value_required()
            .finish();
        let _first = reader
            .read_parameter::<u64>(["first"])
            .value_required()
            .finish();
        let _second = reader
            .read_parameter::<u64>(["second"])
            .value_required()
            .finish();
        reader.into_result().expect("completed sources read");
        assert_eq!(completed.unwrap(), 3);
    }
    #[test]
    fn environment_overlays_can_be_disabled() {
        let reader = ConfigReader::new().without_env();
        assert!(reader.env.read_env("PATH").is_none());
        reader.into_result().expect("unused reader is valid");
    }
    #[test]
    fn parse_diagnostics_do_not_echo_raw_values() {
        const TOML_SENTINEL: &str = "toml-secret-sentinel";
        const ENV_SENTINEL: &str = "env-secret-sentinel";
        let mut reader = ConfigReader::new()
            .with_env(crate::env::MockEnv::from([("SECRET_ENV", ENV_SENTINEL)]))
            .with_toml_source(TomlSource::inline(::toml::toml! {
                toml_value = "toml-secret-sentinel"
            }));
        let _toml_value = reader
            .read_parameter::<u64>(["toml_value"])
            .value_required()
            .finish();
        let _env_value = reader
            .read_parameter::<u64>(["env_value"])
            .env("SECRET_ENV")
            .value_required()
            .finish();
        let report = reader
            .into_result()
            .expect_err("both sentinel values must fail parsing");
        let rendered = report_debug(&report);
        assert!(rendered.contains("toml_value"));
        assert!(rendered.contains("SECRET_ENV"));
        assert!(!rendered.contains(TOML_SENTINEL));
        assert!(!rendered.contains(ENV_SENTINEL));
    }
    #[test]
    fn parses_extends_paths_without_a_public_wrapper() {
        assert_eq!(
            parse_extends_paths(&::toml::Value::String("base.toml".to_owned())),
            Ok(vec![PathBuf::from("base.toml")])
        );
        assert_eq!(
            parse_extends_paths(&::toml::Value::Array(vec![
                ::toml::Value::String("first.toml".to_owned()),
                ::toml::Value::String("second.toml".to_owned()),
            ])),
            Ok(vec![
                PathBuf::from("first.toml"),
                PathBuf::from("second.toml")
            ])
        );
        assert_eq!(
            parse_extends_paths(&::toml::Value::Integer(1)),
            Err(ExtendsPathsError::InvalidType)
        );
        assert_eq!(
            parse_extends_paths(&::toml::Value::Array(vec![::toml::Value::Boolean(true,)])),
            Err(ExtendsPathsError::InvalidArrayElement { index: 0 })
        );
    }
    #[test]
    fn parameter_deserialization_uses_one_authoritative_value_path() {
        let mut reader = ConfigReader::new().with_toml_source(TomlSource::inline(::toml::toml! {
            value = true
        }));
        let _value = reader
            .read_parameter::<RejectValueFastPath>(["value"])
            .value_required()
            .finish();
        let report = reader
            .into_result()
            .expect_err("a rejected value conversion must not be retried through text");
        assert!(
            report_debug(&report).contains("value conversion rejected"),
            "unexpected report: {report:#?}"
        );
    }
    #[test]
    fn extends_reader_still_requires_final_validation() {
        let dir = temp_config_dir("extends_drop_bomb");
        let config = dir.join("config.toml");
        fs::write(&config, "value = true\n").expect("write configuration");
        let reader = ConfigReader::new()
            .read_toml_with_extends(config)
            .expect("configuration must load");
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(reader)));
        assert!(panic.is_err(), "dropping before `into_result` must panic");
        fs::remove_dir_all(dir).expect("remove temporary configuration directory");
    }
    #[test]
    fn extends_cycle_is_rejected_before_reloading_active_source() {
        let dir = temp_config_dir("cycle");
        let config = dir.join("config.toml");
        fs::write(&config, "extends = \"./config.toml\"\n").expect("write cyclic configuration");
        let report = ConfigReader::new()
            .read_toml_with_extends(&config)
            .expect_err("self-cycle must be rejected");
        let rendered = report_debug(&report);
        assert!(
            rendered.contains("configuration `extends` cycle detected"),
            "unexpected report: {rendered}"
        );
        fs::remove_dir_all(dir).expect("remove temporary configuration directory");
    }
    #[test]
    fn extends_diamond_loads_canonical_source_once_in_declared_order() {
        let dir = temp_config_dir("diamond");
        fs::write(dir.join("base.toml"), "value = \"base\"\n").expect("write base configuration");
        fs::write(
            dir.join("left.toml"),
            "extends = \"base.toml\"\nvalue = \"left\"\n",
        )
        .expect("write left configuration");
        fs::write(
            dir.join("right.toml"),
            "extends = \"./base.toml\"\nvalue = \"right\"\n",
        )
        .expect("write right configuration");
        fs::write(
            dir.join("top.toml"),
            "extends = [\"left.toml\", \"right.toml\"]\n",
        )
        .expect("write top configuration");
        let mut reader = ConfigReader::new()
            .read_toml_with_extends(dir.join("top.toml"))
            .expect("diamond must load");
        let source_names: Vec<_> = reader
            .sources
            .iter()
            .map(|source| {
                source
                    .path()
                    .file_name()
                    .expect("source has a file name")
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(
            source_names,
            ["base.toml", "left.toml", "right.toml", "top.toml"]
        );
        let value = reader
            .read_parameter::<String>(["value"])
            .value_required()
            .finish();
        reader.into_result().expect("diamond config is valid");
        assert_eq!(value.unwrap(), "right");
        fs::remove_dir_all(dir).expect("remove temporary configuration directory");
    }
    #[test]
    fn extends_source_reference_ceiling_is_checked_before_children_are_opened() {
        let dir = temp_config_dir("source_limit");
        let children = (0..MAX_TOML_EXTENDS_SOURCES)
            .map(|index| format!("\"missing-{index}.toml\""))
            .collect::<Vec<_>>()
            .join(", ");
        fs::write(dir.join("root.toml"), format!("extends = [{children}]\n"))
            .expect("write excessive source fanout");
        let report = ConfigReader::new()
            .read_toml_with_extends(dir.join("root.toml"))
            .expect_err("excessive source fanout must fail");
        let rendered = report_debug(&report);
        let expected = format!(
            "source references {} exceed the maximum {}",
            MAX_TOML_EXTENDS_SOURCES + 1,
            MAX_TOML_EXTENDS_SOURCES
        );
        assert!(
            rendered.contains(&expected),
            "unexpected report: {rendered}"
        );
        fs::remove_dir_all(dir).expect("remove temporary configuration directory");
    }
    #[test]
    fn extends_depth_ceiling_is_enforced_on_the_first_excess_edge() {
        let dir = temp_config_dir("depth_limit");
        for depth in 0..=u16::from(MAX_TOML_EXTENDS_DEPTH) + 1 {
            let body = if depth <= u16::from(MAX_TOML_EXTENDS_DEPTH) {
                format!("extends = \"{}.toml\"\n", depth + 1)
            } else {
                String::new()
            };
            fs::write(dir.join(format!("{depth}.toml")), body)
                .expect("write deep configuration chain");
        }
        let report = ConfigReader::new()
            .read_toml_with_extends(dir.join("0.toml"))
            .expect_err("excessive depth must fail");
        let rendered = report_debug(&report);
        let expected = format!(
            "depth {} exceeds the maximum {}",
            MAX_TOML_EXTENDS_DEPTH + 1,
            MAX_TOML_EXTENDS_DEPTH
        );
        assert!(
            rendered.contains(&expected),
            "unexpected report: {rendered}"
        );
        fs::remove_dir_all(dir).expect("remove temporary configuration directory");
    }
    #[test]
    fn extends_traversal_budget_enforces_exact_boundaries() {
        ExtendsTraversalBudget::check_depth(MAX_TOML_EXTENDS_DEPTH)
            .expect("maximum depth is admitted");
        assert_eq!(
            ExtendsTraversalBudget::check_depth(MAX_TOML_EXTENDS_DEPTH + 1),
            Err(ExtendsTraversalError::DepthLimit {
                observed: MAX_TOML_EXTENDS_DEPTH + 1,
                maximum: MAX_TOML_EXTENDS_DEPTH,
            })
        );
        let mut sources = ExtendsTraversalBudget::new();
        sources
            .schedule_sources(MAX_TOML_EXTENDS_SOURCES - 1)
            .expect("exact source-reference ceiling is admitted");
        assert_eq!(
            sources.schedule_sources(1),
            Err(ExtendsTraversalError::SourceLimit {
                observed: MAX_TOML_EXTENDS_SOURCES + 1,
                maximum: MAX_TOML_EXTENDS_SOURCES,
            })
        );
        let mut bytes = ExtendsTraversalBudget::new();
        bytes
            .record_bytes(MAX_TOML_EXTENDS_TOTAL_BYTES)
            .expect("exact aggregate byte ceiling is admitted");
        assert_eq!(
            bytes.record_bytes(1),
            Err(ExtendsTraversalError::ByteLimit {
                observed: MAX_TOML_EXTENDS_TOTAL_BYTES + 1,
                maximum: MAX_TOML_EXTENDS_TOTAL_BYTES,
            })
        );
    }
    #[test]
    fn detects_explicit_toml_parameter_before_defaults_are_read() {
        let mut reader = ConfigReader::new().with_toml_source(TomlSource::inline(::toml::toml! {
            [sorafs.storage]
            enabled = false
        }));
        assert!(reader.contains_toml_parameter(["sorafs", "storage", "enabled"]));
        assert!(!reader.contains_toml_parameter(["sorafs", "storage", "missing"]));
        let enabled = reader
            .read_parameter::<bool>(["sorafs", "storage", "enabled"])
            .value_required()
            .finish();
        reader.into_result().expect("source must be fully consumed");
        assert!(!enabled.unwrap());
    }
    #[test]
    fn trims_json_error_prefix_in_messages() {
        let base_err = norito::json::Error::TrailingCharacters {
            byte: 1,
            line: 1,
            col: 2,
        };
        let simple = JsonValueError::from(base_err.clone());
        assert_eq!(
            simple.message,
            "trailing characters at byte 1 (line 1, col 2)"
        );
        let report = Report::new(base_err);
        let reported = JsonValueError::from(report);
        assert_eq!(
            reported.message,
            "trailing characters at byte 1 (line 1, col 2)"
        );
    }
}

#[cfg(test)]
mod final_wrap_tests;
