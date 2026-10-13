//! Native fail-closed controller for authenticated release tools.
//!
//! The controller implements `iroha.authenticated-tool-os-isolation.v1` on
//! hosts whose kernel exposes every primitive required by the contract.  The
//! macOS backend uses Seatbelt plus a controller-owned watchdog and resource
//! accounting. Linux is deliberately rejected until the Landlock, seccomp,
//! and delegated-cgroup backend can be qualified on the deployment kernel.

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::{OsStr, OsString},
    fs::{self, Metadata},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    process::{Command, ExitCode},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::Duration,
};

#[cfg(target_os = "macos")]
use std::{
    fs::File,
    os::{
        fd::AsRawFd,
        unix::process::{CommandExt, ExitStatusExt},
    },
    process::{Child, Output, Stdio},
    time::Instant,
};

const CONTRACT: &str = "iroha.authenticated-tool-os-isolation.v1";
const CONTROLLER_ERROR: u8 = 125;
const CONTROLLER_LIMIT: u8 = 124;
const MAX_ARGUMENTS: usize = 512;
const MAX_WRITABLE_FILES: usize = 64;
const MAX_READABLE_PATHS: usize = 256;
const MAX_ARGUMENT_BYTES: usize = 1024 * 1024;
const MAX_PATH_BYTES: usize = 4096;
const MAX_WALL_SECONDS: f64 = 3600.0;
const MONITOR_INTERVAL: Duration = Duration::from_millis(5);
const CLEANUP_GRACE: Duration = Duration::from_millis(250);

#[cfg(target_os = "macos")]
const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

#[derive(Debug)]
struct ControllerError {
    message: String,
    exit: u8,
}

impl ControllerError {
    fn policy(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit: CONTROLLER_ERROR,
        }
    }

    fn limit(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit: CONTROLLER_LIMIT,
        }
    }
}

type Result<T> = std::result::Result<T, ControllerError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Platform {
    Macos,
    Linux,
}

#[derive(Clone, Debug)]
struct WritableFile {
    name: String,
    path: PathBuf,
    maximum_bytes: u64,
}

#[derive(Clone, Debug)]
struct Request {
    platform: Platform,
    expected_user: u32,
    expected_group: u32,
    working_directory: PathBuf,
    readable_files: Vec<PathBuf>,
    readable_directories: Vec<PathBuf>,
    deny_all_writes: bool,
    writable_files: Vec<WritableFile>,
    cumulative_write_limit: u64,
    maximum_live_write_root: u64,
    wall_time: Duration,
    stdout_limit: u64,
    stderr_limit: u64,
    combined_output_limit: Option<u64>,
    tool: Vec<OsString>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    sha256: [u8; 32],
}

#[derive(Clone, Debug)]
struct RootSnapshot {
    directory: FileIdentity,
    entries: BTreeMap<String, FileIdentity>,
}

#[derive(Debug)]
struct ReaderResult {
    bytes: Vec<u8>,
    io_failed: bool,
}

fn main() -> ExitCode {
    match entrypoint(&env::args_os().collect::<Vec<_>>()) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("authenticated-tool-controller: {}", error.message);
            ExitCode::from(error.exit)
        }
    }
}

fn entrypoint(arguments: &[OsString]) -> Result<u8> {
    if arguments.len() < 2 {
        return Err(ControllerError::policy("missing subcommand"));
    }
    match arguments[1].to_str() {
        Some("run-v1") => run(&parse_request(&arguments[2..])?),
        Some("qualify-host-v1") => qualify_host(&arguments[2..]),
        Some("qualification-probe-v1") => qualification_probe(&arguments[2..]),
        _ => Err(ControllerError::policy("unsupported subcommand")),
    }
}

fn parse_request(arguments: &[OsString]) -> Result<Request> {
    if arguments.len() > MAX_ARGUMENTS {
        return Err(ControllerError::policy("request has too many arguments"));
    }
    let argument_bytes = arguments.iter().try_fold(0usize, |total, value| {
        total
            .checked_add(value.as_encoded_bytes().len())
            .ok_or_else(|| ControllerError::policy("request argument size overflow"))
    })?;
    if argument_bytes > MAX_ARGUMENT_BYTES {
        return Err(ControllerError::policy(
            "request arguments exceed their bound",
        ));
    }

    let separator = arguments
        .iter()
        .position(|value| value == "--")
        .ok_or_else(|| ControllerError::policy("request is missing the tool separator"))?;
    if separator + 1 == arguments.len() {
        return Err(ControllerError::policy(
            "request is missing the tool executable",
        ));
    }
    let options = &arguments[..separator];
    let tool = arguments[separator + 1..].to_vec();

    let mut values: BTreeMap<&str, String> = BTreeMap::new();
    let mut flags = BTreeSet::new();
    let mut writable_specs = Vec::new();
    let mut readable_file_specs = Vec::new();
    let mut readable_directory_specs = Vec::new();
    let mut index = 0;
    while index < options.len() {
        let option = options[index]
            .to_str()
            .ok_or_else(|| ControllerError::policy("controller option is not UTF-8"))?;
        match option {
            "--use-attested-runtime-identity"
            | "--no-new-privileges"
            | "--close-inherited-fds"
            | "--forward-tool-exit-status"
            | "--exact-tool-stdio"
            | "--deny-network"
            | "--deny-tool-process-spawn"
            | "--deny-read-outside-allowlist"
            | "--deny-all-writes"
            | "--deny-write-outside-allowlist"
            | "--deny-link-rename-unlink"
            | "--deny-symlink"
            | "--deny-special-files"
            | "--account-unlinked-write-bytes"
            | "--require-empty-process-tree" => {
                if !flags.insert(option) {
                    return Err(ControllerError::policy(format!(
                        "duplicate controller flag {option}"
                    )));
                }
                index += 1;
            }
            "--contract"
            | "--platform"
            | "--expected-runtime-uid"
            | "--expected-runtime-gid"
            | "--working-directory"
            | "--cumulative-write-limit-bytes"
            | "--maximum-live-write-root-bytes"
            | "--wall-time-seconds"
            | "--stdout-limit-bytes"
            | "--stderr-limit-bytes"
            | "--combined-output-limit-bytes" => {
                let value = options.get(index + 1).ok_or_else(|| {
                    ControllerError::policy(format!("missing value for {option}"))
                })?;
                let value = value
                    .to_str()
                    .ok_or_else(|| ControllerError::policy(format!("{option} is not UTF-8")))?;
                if values.insert(option, value.to_owned()).is_some() {
                    return Err(ControllerError::policy(format!(
                        "duplicate controller option {option}"
                    )));
                }
                index += 2;
            }
            "--writable-file" => {
                let value = options
                    .get(index + 1)
                    .ok_or_else(|| ControllerError::policy("missing value for --writable-file"))?;
                writable_specs.push(
                    value
                        .to_str()
                        .ok_or_else(|| ControllerError::policy("--writable-file is not UTF-8"))?
                        .to_owned(),
                );
                index += 2;
            }
            "--readable-file" | "--readable-directory" => {
                let value = options.get(index + 1).ok_or_else(|| {
                    ControllerError::policy(format!("missing value for {option}"))
                })?;
                let value = value
                    .to_str()
                    .ok_or_else(|| ControllerError::policy(format!("{option} is not UTF-8")))?
                    .to_owned();
                if option == "--readable-file" {
                    readable_file_specs.push(value);
                } else {
                    readable_directory_specs.push(value);
                }
                index += 2;
            }
            _ => {
                return Err(ControllerError::policy(format!(
                    "unsupported controller option {option}"
                )));
            }
        }
    }

    for required in [
        "--use-attested-runtime-identity",
        "--no-new-privileges",
        "--close-inherited-fds",
        "--forward-tool-exit-status",
        "--exact-tool-stdio",
        "--deny-network",
        "--deny-tool-process-spawn",
        "--deny-read-outside-allowlist",
        "--account-unlinked-write-bytes",
        "--require-empty-process-tree",
    ] {
        if !flags.contains(required) {
            return Err(ControllerError::policy(format!(
                "request omits mandatory flag {required}"
            )));
        }
    }
    let deny_all_writes = flags.contains("--deny-all-writes");
    let allowlisted_writes = flags.contains("--deny-write-outside-allowlist");
    if deny_all_writes == allowlisted_writes {
        return Err(ControllerError::policy(
            "request must select exactly one write policy",
        ));
    }
    for flag in [
        "--deny-link-rename-unlink",
        "--deny-symlink",
        "--deny-special-files",
    ] {
        if allowlisted_writes && !flags.contains(flag) {
            return Err(ControllerError::policy(format!(
                "allowlisted write request omits mandatory flag {flag}"
            )));
        }
        if deny_all_writes && flags.contains(flag) {
            return Err(ControllerError::policy(format!(
                "deny-all-writes request contains inapplicable flag {flag}"
            )));
        }
    }

    if required_value(&values, "--contract")? != CONTRACT {
        return Err(ControllerError::policy("unsupported isolation contract"));
    }
    let platform = match required_value(&values, "--platform")? {
        "macos" => Platform::Macos,
        "linux" => Platform::Linux,
        _ => return Err(ControllerError::policy("unsupported request platform")),
    };
    let expected_user = parse_u32(
        required_value(&values, "--expected-runtime-uid")?,
        "--expected-runtime-uid",
    )?;
    let expected_group = parse_u32(
        required_value(&values, "--expected-runtime-gid")?,
        "--expected-runtime-gid",
    )?;
    let working_directory =
        canonical_request_directory(Path::new(required_value(&values, "--working-directory")?))?;

    if readable_file_specs.len() + readable_directory_specs.len() > MAX_READABLE_PATHS {
        return Err(ControllerError::policy(
            "read allowlist contains too many paths",
        ));
    }
    let mut readable_paths = BTreeSet::new();
    let readable_files = readable_file_specs
        .into_iter()
        .map(|path| canonical_request_path(Path::new(&path), false))
        .collect::<Result<Vec<_>>>()?;
    let readable_directories = readable_directory_specs
        .into_iter()
        .map(|path| canonical_request_path(Path::new(&path), true))
        .collect::<Result<Vec<_>>>()?;
    for path in readable_files.iter().chain(&readable_directories) {
        if !readable_paths.insert(path.clone()) {
            return Err(ControllerError::policy(
                "read allowlist contains a duplicate path",
            ));
        }
    }

    if writable_specs.len() > MAX_WRITABLE_FILES {
        return Err(ControllerError::policy(
            "write allowlist contains too many files",
        ));
    }
    let mut names = BTreeSet::new();
    let mut writable_files = Vec::with_capacity(writable_specs.len());
    for spec in writable_specs {
        let (name, maximum) = spec
            .rsplit_once(':')
            .ok_or_else(|| ControllerError::policy("invalid --writable-file value"))?;
        if !valid_direct_name(name) || !names.insert(name.to_owned()) {
            return Err(ControllerError::policy(
                "writable file names must be distinct direct child names",
            ));
        }
        let maximum_bytes = parse_u64(maximum, "--writable-file limit")?;
        if maximum_bytes == 0 {
            return Err(ControllerError::policy(
                "writable file limit must be positive",
            ));
        }
        writable_files.push(WritableFile {
            name: name.to_owned(),
            path: working_directory.join(name),
            maximum_bytes,
        });
    }
    if deny_all_writes && !writable_files.is_empty() {
        return Err(ControllerError::policy(
            "deny-all-writes request contains writable files",
        ));
    }
    if allowlisted_writes && writable_files.is_empty() {
        return Err(ControllerError::policy(
            "allowlisted write request contains no writable files",
        ));
    }
    if readable_paths
        .iter()
        .any(|path| writable_files.iter().any(|file| file.path == *path))
    {
        return Err(ControllerError::policy(
            "writable files are implicitly readable and must not be repeated in the read allowlist",
        ));
    }

    let cumulative_write_limit = parse_u64(
        required_value(&values, "--cumulative-write-limit-bytes")?,
        "--cumulative-write-limit-bytes",
    )?;
    let maximum_live_write_root = parse_u64(
        required_value(&values, "--maximum-live-write-root-bytes")?,
        "--maximum-live-write-root-bytes",
    )?;
    if deny_all_writes && (cumulative_write_limit != 0 || maximum_live_write_root != 0) {
        return Err(ControllerError::policy(
            "deny-all-writes request must use zero write quotas",
        ));
    }
    if allowlisted_writes {
        let declared = writable_files.iter().try_fold(0u64, |total, file| {
            total
                .checked_add(file.maximum_bytes)
                .ok_or_else(|| ControllerError::policy("write quota overflow"))
        })?;
        if cumulative_write_limit == 0 || cumulative_write_limit > declared {
            return Err(ControllerError::policy(
                "cumulative write quota exceeds the declared file quota",
            ));
        }
        if maximum_live_write_root < cumulative_write_limit {
            return Err(ControllerError::policy(
                "live write-root quota is smaller than the cumulative quota",
            ));
        }
    }

    let wall_seconds = required_value(&values, "--wall-time-seconds")?
        .parse::<f64>()
        .map_err(|_| ControllerError::policy("invalid --wall-time-seconds"))?;
    if !wall_seconds.is_finite() || wall_seconds <= 0.0 || wall_seconds > MAX_WALL_SECONDS {
        return Err(ControllerError::policy(
            "wall-time limit is outside the supported range",
        ));
    }
    let stdout_limit = positive_limit(&values, "--stdout-limit-bytes")?;
    let stderr_limit = positive_limit(&values, "--stderr-limit-bytes")?;
    let combined_output_limit = values
        .get("--combined-output-limit-bytes")
        .map(|value| parse_u64(value, "--combined-output-limit-bytes"))
        .transpose()?;
    if combined_output_limit == Some(0) {
        return Err(ControllerError::policy(
            "combined output limit must be positive",
        ));
    }

    validate_tool_arguments(&tool)?;
    Ok(Request {
        platform,
        expected_user,
        expected_group,
        working_directory,
        readable_files,
        readable_directories,
        deny_all_writes,
        writable_files,
        cumulative_write_limit,
        maximum_live_write_root,
        wall_time: Duration::from_secs_f64(wall_seconds),
        stdout_limit,
        stderr_limit,
        combined_output_limit,
        tool,
    })
}

fn required_value<'a>(values: &'a BTreeMap<&str, String>, name: &str) -> Result<&'a str> {
    values
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| ControllerError::policy(format!("missing required option {name}")))
}

fn positive_limit(values: &BTreeMap<&str, String>, name: &str) -> Result<u64> {
    let value = parse_u64(required_value(values, name)?, name)?;
    if value == 0 {
        return Err(ControllerError::policy(format!("{name} must be positive")));
    }
    Ok(value)
}

fn parse_u64(value: &str, label: &str) -> Result<u64> {
    if value.is_empty() || (value.len() > 1 && value.starts_with('0')) {
        return Err(ControllerError::policy(format!("invalid {label}")));
    }
    value
        .parse::<u64>()
        .map_err(|_| ControllerError::policy(format!("invalid {label}")))
}

fn parse_u32(value: &str, label: &str) -> Result<u32> {
    let value = parse_u64(value, label)?;
    u32::try_from(value).map_err(|_| ControllerError::policy(format!("invalid {label}")))
}

fn valid_direct_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\0')
}

fn canonical_request_directory(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute()
        || path.as_os_str().as_encoded_bytes().len() > MAX_PATH_BYTES
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(ControllerError::policy(
            "working directory must be one normalized absolute path",
        ));
    }
    let canonical = fs::canonicalize(path)
        .map_err(|_| ControllerError::policy("working directory is unavailable"))?;
    if canonical != path {
        return Err(ControllerError::policy(
            "working directory must be canonical and symlink-free",
        ));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| ControllerError::policy("working directory metadata is unavailable"))?;
    if !metadata.is_dir() {
        return Err(ControllerError::policy(
            "working directory is not a directory",
        ));
    }
    Ok(canonical)
}

fn canonical_request_path(path: &Path, require_directory: bool) -> Result<PathBuf> {
    if !path.is_absolute()
        || path.as_os_str().as_encoded_bytes().len() > MAX_PATH_BYTES
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(ControllerError::policy(
            "readable path must be one normalized absolute path",
        ));
    }
    let canonical = fs::canonicalize(path)
        .map_err(|_| ControllerError::policy("readable path is unavailable"))?;
    if canonical != path {
        return Err(ControllerError::policy(
            "readable path must be canonical and symlink-free",
        ));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| ControllerError::policy("readable path metadata is unavailable"))?;
    if require_directory != metadata.is_dir() || (!require_directory && !metadata.is_file()) {
        return Err(ControllerError::policy(
            "readable path has the wrong filesystem type",
        ));
    }
    Ok(canonical)
}

fn validate_tool_arguments(tool: &[OsString]) -> Result<()> {
    if tool.is_empty() {
        return Err(ControllerError::policy("tool command is empty"));
    }
    for argument in tool {
        if argument.as_encoded_bytes().contains(&0) {
            return Err(ControllerError::policy("tool argument contains NUL"));
        }
    }
    let executable = Path::new(&tool[0]);
    if !executable.is_absolute()
        || executable.as_os_str().as_encoded_bytes().len() > MAX_PATH_BYTES
        || executable
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(ControllerError::policy(
            "tool executable must be one normalized absolute path",
        ));
    }
    Ok(())
}

fn run(request: &Request) -> Result<u8> {
    validate_environment(request)?;
    validate_no_inherited_fds()?;
    validate_runtime_identity(request)?;
    match request.platform {
        Platform::Macos => {
            #[cfg(target_os = "macos")]
            {
                run_macos(request)
            }
            #[cfg(not(target_os = "macos"))]
            {
                Err(ControllerError::policy(
                    "macOS isolation request does not match this host",
                ))
            }
        }
        Platform::Linux => Err(ControllerError::policy(
            "Linux isolation is unavailable: a qualified Landlock, seccomp, and delegated-cgroup backend is required",
        )),
    }
}

fn qualify_host(arguments: &[OsString]) -> Result<u8> {
    if !arguments.is_empty() {
        return Err(ControllerError::policy(
            "host qualification accepts no arguments",
        ));
    }
    #[cfg(target_os = "macos")]
    {
        qualify_macos_host()?;
        println!("authenticated-tool-controller: macOS host qualification passed");
        Ok(0)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(ControllerError::policy(
            "host qualification is unavailable without the macOS backend",
        ))
    }
}

#[cfg(target_os = "macos")]
struct QualificationRoot {
    path: PathBuf,
}

#[cfg(target_os = "macos")]
impl QualificationRoot {
    fn create() -> Result<Self> {
        let temporary = env::var_os("TMPDIR")
            .ok_or_else(|| ControllerError::policy("host qualification TMPDIR is missing"))?;
        let temporary = Path::new(&temporary);
        validate_environment_directory(temporary, "TMPDIR")?;
        let path = temporary.join(format!(
            "iroha-authenticated-tool-host-qualification.{}",
            std::process::id()
        ));
        fs::create_dir(&path)
            .map_err(|_| ControllerError::policy("host qualification root could not be created"))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).map_err(|_| {
            ControllerError::policy("host qualification root could not be made private")
        })?;
        let path = fs::canonicalize(path)
            .map_err(|_| ControllerError::policy("host qualification root is unavailable"))?;
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| ControllerError::policy("host qualification root is unavailable"))?;
        if !metadata.is_dir()
            || metadata.uid() != effective_user()
            || metadata.gid() != effective_group()
            || metadata.permissions().mode() & 0o077 != 0
        {
            let _ = fs::remove_dir_all(&path);
            return Err(ControllerError::policy(
                "host qualification root is not runtime-identity private",
            ));
        }
        Ok(Self { path })
    }

    fn case(&self, name: &str) -> Result<PathBuf> {
        let path = self.path.join(name);
        fs::create_dir(&path)
            .map_err(|_| ControllerError::policy("host qualification case already exists"))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).map_err(|_| {
            ControllerError::policy("host qualification case could not be made private")
        })?;
        Ok(path)
    }
}

#[cfg(target_os = "macos")]
impl Drop for QualificationRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(target_os = "macos")]
fn qualify_macos_host() -> Result<()> {
    validate_no_inherited_fds()?;
    let executable = env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|_| ControllerError::policy("host qualification image is unavailable"))?;
    validate_trusted_path(&executable, false)?;
    validate_trusted_path(Path::new(SANDBOX_EXEC), true)?;
    let executable_identity = file_identity(&executable, true, true)?;
    let root = QualificationRoot::create()?;

    let success_root = root.case("success")?;
    let allowed = success_root.join("allowed");
    let success = run_qualification_request(
        QualificationTarget {
            executable: &executable,
            temporary: &root.path,
            working_directory: &success_root,
        },
        Some(("allowed", 128)),
        &[],
        "2",
        4096,
        &[OsString::from("success"), allowed.clone().into_os_string()],
    )?;
    require_qualification_result(
        &success,
        0,
        b"qualified stdout\n",
        b"qualified stderr\n",
        "allowlisted write/output",
    )?;
    if fs::read(&allowed).ok().as_deref() != Some(b"qualified\n") {
        return Err(ControllerError::policy(
            "host qualification allowlisted write was not exact",
        ));
    }

    let create_new = run_qualification_request(
        QualificationTarget {
            executable: &executable,
            temporary: &root.path,
            working_directory: &success_root,
        },
        Some(("allowed", 128)),
        &[],
        "2",
        4096,
        &[
            OsString::from("create-new"),
            allowed.clone().into_os_string(),
        ],
    )?;
    require_qualification_stderr(
        &create_new,
        CONTROLLER_ERROR,
        b"qualification create-new signer incompatible",
        "create-new denial",
    )?;

    let cumulative_root = root.case("cumulative-quota")?;
    let cumulative_output = cumulative_root.join("allowed");
    let cumulative = run_qualification_request_with_quotas(
        QualificationTarget {
            executable: &executable,
            temporary: &root.path,
            working_directory: &cumulative_root,
        },
        ("allowed", 128),
        (32, 128),
        &[],
        "2",
        4096,
        &[
            OsString::from("write-bytes"),
            cumulative_output.into_os_string(),
            OsString::from("64"),
        ],
    )?;
    require_qualification_stderr(
        &cumulative,
        CONTROLLER_LIMIT,
        b"cumulative write quota was exceeded",
        "cumulative write quota",
    )?;

    let live_root = root.case("live-quota")?;
    write_qualification_file(&live_root.join("protected"), &[b'p'; 100])?;
    let live_output = live_root.join("allowed");
    let live = run_qualification_request_with_quotas(
        QualificationTarget {
            executable: &executable,
            temporary: &root.path,
            working_directory: &live_root,
        },
        ("allowed", 128),
        (128, 128),
        &[],
        "2",
        4096,
        &[
            OsString::from("write-bytes"),
            live_output.into_os_string(),
            OsString::from("64"),
        ],
    )?;
    require_qualification_stderr(
        &live,
        CONTROLLER_LIMIT,
        b"maximum live write-root quota was exceeded",
        "live write-root quota",
    )?;

    let read_root = root.case("read")?;
    let readable = read_root.join("readable");
    let secret = read_root.join("secret");
    write_qualification_file(&readable, b"qualified readable bytes\n")?;
    write_qualification_file(&secret, b"qualified secret bytes\n")?;
    let read = run_qualification_request(
        QualificationTarget {
            executable: &executable,
            temporary: &root.path,
            working_directory: Path::new("/"),
        },
        None,
        &[readable.as_path()],
        "2",
        4096,
        &[OsString::from("read"), readable.clone().into_os_string()],
    )?;
    require_qualification_result(
        &read,
        0,
        b"qualified readable bytes\n",
        b"",
        "exact readable file",
    )?;
    for (path, label) in [
        (secret.as_path(), "same-directory secret read"),
        (Path::new("/etc/passwd"), "ambient system read"),
    ] {
        let denied = run_qualification_request(
            QualificationTarget {
                executable: &executable,
                temporary: &root.path,
                working_directory: Path::new("/"),
            },
            None,
            &[readable.as_path()],
            "2",
            4096,
            &[OsString::from("read"), path.as_os_str().to_owned()],
        )?;
        require_qualification_stderr(
            &denied,
            CONTROLLER_ERROR,
            b"qualification read denied",
            label,
        )?;
        if denied
            .stdout
            .windows(b"qualified secret bytes".len())
            .any(|window| window == b"qualified secret bytes")
        {
            return Err(ControllerError::policy(
                "host qualification disclosed an ambient secret",
            ));
        }
    }

    for (action, diagnostic) in [
        ("network", "qualification network denied"),
        ("spawn", "qualification spawn denied"),
        ("fork", "qualification fork denied"),
        ("setsid", "qualification setsid denied"),
        ("ambient-sysctl", "qualification ambient sysctl denied"),
    ] {
        let denied = run_qualification_request(
            QualificationTarget {
                executable: &executable,
                temporary: &root.path,
                working_directory: Path::new("/"),
            },
            None,
            &[],
            "2",
            4096,
            &[OsString::from(action)],
        )?;
        require_qualification_stderr(&denied, CONTROLLER_ERROR, diagnostic.as_bytes(), action)?;
    }

    for (index, (action, probe)) in [
        (
            "write",
            vec![OsString::from("write"), OsString::from("other")],
        ),
        (
            "unlink",
            vec![OsString::from("unlink"), OsString::from("allowed")],
        ),
        (
            "rename",
            vec![
                OsString::from("rename"),
                OsString::from("allowed"),
                OsString::from("other"),
            ],
        ),
        (
            "hardlink",
            vec![
                OsString::from("hardlink"),
                OsString::from("allowed"),
                OsString::from("other"),
            ],
        ),
        (
            "symlink",
            vec![
                OsString::from("symlink"),
                OsString::from("/private/tmp"),
                OsString::from("other"),
            ],
        ),
        (
            "FIFO",
            vec![OsString::from("fifo"), OsString::from("other")],
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let case = root.case(&format!("filesystem-{index}"))?;
        let rendered = probe
            .into_iter()
            .map(|argument| match argument.to_str() {
                Some("allowed" | "other") => case.join(argument).into_os_string(),
                _ => argument,
            })
            .collect::<Vec<_>>();
        let denied = run_qualification_request(
            QualificationTarget {
                executable: &executable,
                temporary: &root.path,
                working_directory: &case,
            },
            Some(("allowed", 128)),
            &[],
            "2",
            4096,
            &rendered,
        )?;
        require_qualification_stderr(
            &denied,
            CONTROLLER_ERROR,
            format!("qualification {action}").as_bytes(),
            action,
        )?;
        if case.join("other").exists() {
            return Err(ControllerError::policy(format!(
                "host qualification {action} escaped its write allowlist"
            )));
        }
    }

    let overflow = run_qualification_request(
        QualificationTarget {
            executable: &executable,
            temporary: &root.path,
            working_directory: Path::new("/"),
        },
        None,
        &[],
        "2",
        32,
        &[OsString::from("stdout-overflow"), OsString::from("4096")],
    )?;
    require_qualification_stderr(
        &overflow,
        CONTROLLER_LIMIT,
        b"tool output exceeded its bound",
        "output bound",
    )?;
    let timeout = run_qualification_request(
        QualificationTarget {
            executable: &executable,
            temporary: &root.path,
            working_directory: Path::new("/"),
        },
        None,
        &[],
        "0.1",
        4096,
        &[OsString::from("sleep")],
    )?;
    require_qualification_stderr(
        &timeout,
        CONTROLLER_LIMIT,
        b"tool exceeded its wall-time bound",
        "wall-time bound",
    )?;
    let exact_status = run_qualification_request(
        QualificationTarget {
            executable: &executable,
            temporary: &root.path,
            working_directory: Path::new("/"),
        },
        None,
        &[],
        "2",
        4096,
        &[OsString::from("exit"), OsString::from("17")],
    )?;
    require_qualification_result(&exact_status, 17, b"", b"", "exit status")?;
    qualify_watchdog(&executable, &root.path)?;

    if file_identity(&executable, true, true)? != executable_identity {
        return Err(ControllerError::policy(
            "host qualification image changed during qualification",
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn write_qualification_file(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes)
        .and_then(|()| fs::set_permissions(path, fs::Permissions::from_mode(0o600)))
        .map_err(|_| ControllerError::policy("host qualification input could not be created"))
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy)]
struct QualificationTarget<'a> {
    executable: &'a Path,
    temporary: &'a Path,
    working_directory: &'a Path,
}

#[cfg(target_os = "macos")]
fn qualification_command(
    target: QualificationTarget<'_>,
    writable: Option<(&str, u64)>,
    write_quotas: Option<(u64, u64)>,
    readable_files: &[&Path],
    wall_seconds: &str,
    stdout_limit: u64,
    probe: &[OsString],
) -> Command {
    let QualificationTarget {
        executable,
        temporary,
        working_directory,
    } = target;
    let mut arguments = vec![
        OsString::from("run-v1"),
        OsString::from("--contract"),
        OsString::from(CONTRACT),
        OsString::from("--platform"),
        OsString::from("macos"),
        OsString::from("--expected-runtime-uid"),
        OsString::from(effective_user().to_string()),
        OsString::from("--expected-runtime-gid"),
        OsString::from(effective_group().to_string()),
        OsString::from("--working-directory"),
        working_directory.as_os_str().to_owned(),
        OsString::from("--use-attested-runtime-identity"),
        OsString::from("--no-new-privileges"),
        OsString::from("--close-inherited-fds"),
        OsString::from("--forward-tool-exit-status"),
        OsString::from("--exact-tool-stdio"),
        OsString::from("--deny-network"),
        OsString::from("--deny-tool-process-spawn"),
        OsString::from("--deny-read-outside-allowlist"),
    ];
    match writable {
        Some((name, maximum)) => {
            let (cumulative, live) = write_quotas.unwrap_or((maximum, maximum));
            arguments.extend([
                OsString::from("--deny-write-outside-allowlist"),
                OsString::from("--deny-link-rename-unlink"),
                OsString::from("--deny-symlink"),
                OsString::from("--deny-special-files"),
                OsString::from("--account-unlinked-write-bytes"),
                OsString::from("--require-empty-process-tree"),
                OsString::from("--cumulative-write-limit-bytes"),
                OsString::from(cumulative.to_string()),
                OsString::from("--maximum-live-write-root-bytes"),
                OsString::from(live.to_string()),
                OsString::from("--writable-file"),
                OsString::from(format!("{name}:{maximum}")),
            ]);
        }
        None => arguments.extend([
            OsString::from("--deny-all-writes"),
            OsString::from("--account-unlinked-write-bytes"),
            OsString::from("--require-empty-process-tree"),
            OsString::from("--cumulative-write-limit-bytes"),
            OsString::from("0"),
            OsString::from("--maximum-live-write-root-bytes"),
            OsString::from("0"),
        ]),
    }
    for readable in readable_files {
        arguments.push(OsString::from("--readable-file"));
        arguments.push(readable.as_os_str().to_owned());
    }
    arguments.extend([
        OsString::from("--wall-time-seconds"),
        OsString::from(wall_seconds),
        OsString::from("--stdout-limit-bytes"),
        OsString::from(stdout_limit.to_string()),
        OsString::from("--stderr-limit-bytes"),
        OsString::from("4096"),
        OsString::from("--"),
        executable.as_os_str().to_owned(),
        OsString::from("qualification-probe-v1"),
    ]);
    arguments.extend_from_slice(probe);
    let mut command = Command::new(executable);
    command
        .args(arguments)
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("PATH", "/usr/bin:/bin")
        .env("TMPDIR", temporary)
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

#[cfg(target_os = "macos")]
fn run_qualification_request(
    target: QualificationTarget<'_>,
    writable: Option<(&str, u64)>,
    readable_files: &[&Path],
    wall_seconds: &str,
    stdout_limit: u64,
    probe: &[OsString],
) -> Result<Output> {
    let QualificationTarget {
        executable,
        temporary,
        working_directory,
    } = target;
    qualification_command(
        QualificationTarget {
            executable,
            temporary,
            working_directory,
        },
        writable,
        None,
        readable_files,
        wall_seconds,
        stdout_limit,
        probe,
    )
    .output()
    .map_err(|_| ControllerError::policy("host qualification request could not execute"))
}

#[cfg(target_os = "macos")]
fn run_qualification_request_with_quotas(
    target: QualificationTarget<'_>,
    writable: (&str, u64),
    write_quotas: (u64, u64),
    readable_files: &[&Path],
    wall_seconds: &str,
    stdout_limit: u64,
    probe: &[OsString],
) -> Result<Output> {
    let QualificationTarget {
        executable,
        temporary,
        working_directory,
    } = target;
    qualification_command(
        QualificationTarget {
            executable,
            temporary,
            working_directory,
        },
        Some(writable),
        Some(write_quotas),
        readable_files,
        wall_seconds,
        stdout_limit,
        probe,
    )
    .output()
    .map_err(|_| ControllerError::policy("host qualification request could not execute"))
}

#[cfg(target_os = "macos")]
fn require_qualification_result(
    output: &Output,
    status: u8,
    stdout: &[u8],
    stderr: &[u8],
    label: &str,
) -> Result<()> {
    if output.status.code() != Some(i32::from(status))
        || output.stdout != stdout
        || output.stderr != stderr
    {
        return Err(ControllerError::policy(format!(
            "host qualification failed for {label}"
        )));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn require_qualification_stderr(
    output: &Output,
    status: u8,
    diagnostic: &[u8],
    label: &str,
) -> Result<()> {
    if output.status.code() != Some(i32::from(status))
        || !output
            .stderr
            .windows(diagnostic.len())
            .any(|window| window == diagnostic)
    {
        return Err(ControllerError::policy(format!(
            "host qualification failed for {label}"
        )));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn qualify_watchdog(executable: &Path, temporary: &Path) -> Result<()> {
    let mut command = qualification_command(
        QualificationTarget {
            executable,
            temporary,
            working_directory: Path::new("/"),
        },
        None,
        None,
        &[],
        "60",
        4096,
        &[OsString::from("sleep")],
    );
    command.stdout(Stdio::null()).stderr(Stdio::null());
    let mut controller = command
        .spawn()
        .map_err(|_| ControllerError::policy("host watchdog qualification could not start"))?;
    let deadline = Instant::now() + Duration::from_secs(3);
    let children = loop {
        let children = qualification_child_pids(controller.id())?;
        if children.len() >= 2 {
            break children;
        }
        if Instant::now() >= deadline {
            let _ = controller.kill();
            let _ = controller.wait();
            return Err(ControllerError::policy(
                "host watchdog qualification did not create the isolated job",
            ));
        }
        thread::sleep(Duration::from_millis(20));
    };
    controller
        .kill()
        .and_then(|()| controller.wait().map(|_| ()))
        .map_err(|_| ControllerError::policy("host watchdog controller could not be killed"))?;
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let mut remaining = Vec::new();
        for pid in &children {
            if qualification_pid_exists(*pid)? {
                remaining.push(*pid);
            }
        }
        if remaining.is_empty() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(ControllerError::policy(
                "host watchdog left isolated processes after controller death",
            ));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(target_os = "macos")]
fn qualification_child_pids(parent: u32) -> Result<Vec<u32>> {
    let output = Command::new("/bin/ps")
        .args(["-axo", "pid=,ppid="])
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .output()
        .map_err(|_| ControllerError::policy("host watchdog process inventory failed"))?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(ControllerError::policy(
            "host watchdog process inventory failed",
        ));
    }
    let text = std::str::from_utf8(&output.stdout)
        .map_err(|_| ControllerError::policy("host watchdog process inventory is not UTF-8"))?;
    let mut children = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_ascii_whitespace();
        let pid = fields
            .next()
            .ok_or_else(|| ControllerError::policy("host watchdog process inventory is invalid"))?
            .parse::<u32>()
            .map_err(|_| ControllerError::policy("host watchdog process inventory is invalid"))?;
        let parent_id = fields
            .next()
            .ok_or_else(|| ControllerError::policy("host watchdog process inventory is invalid"))?
            .parse::<u32>()
            .map_err(|_| ControllerError::policy("host watchdog process inventory is invalid"))?;
        if fields.next().is_some() {
            return Err(ControllerError::policy(
                "host watchdog process inventory is invalid",
            ));
        }
        if parent_id == parent {
            children.push(pid);
        }
    }
    Ok(children)
}

#[cfg(target_os = "macos")]
fn qualification_pid_exists(pid: u32) -> Result<bool> {
    let pid_text = pid.to_string();
    let output = Command::new("/bin/ps")
        .args(["-p", pid_text.as_str(), "-o", "pid="])
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .output()
        .map_err(|_| ControllerError::policy("host watchdog process lookup failed"))?;
    if !output.stderr.is_empty() {
        return Err(ControllerError::policy(
            "host watchdog process lookup failed",
        ));
    }
    if !output.status.success() {
        return Ok(false);
    }
    let text = std::str::from_utf8(&output.stdout)
        .map_err(|_| ControllerError::policy("host watchdog process lookup is not UTF-8"))?;
    let mut fields = text.split_ascii_whitespace();
    let found = fields
        .next()
        .ok_or_else(|| ControllerError::policy("host watchdog process lookup is empty"))?
        .parse::<u32>()
        .map_err(|_| ControllerError::policy("host watchdog process lookup is invalid"))?;
    if found != pid || fields.next().is_some() {
        return Err(ControllerError::policy(
            "host watchdog process lookup is invalid",
        ));
    }
    Ok(true)
}

fn validate_environment(request: &Request) -> Result<()> {
    let allowed = BTreeSet::from([
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "PYTHONDONTWRITEBYTECODE",
        "TMPDIR",
    ]);
    for (name, value) in env::vars_os() {
        let name = name
            .to_str()
            .ok_or_else(|| ControllerError::policy("environment name is not UTF-8"))?;
        if !allowed.contains(name) {
            return Err(ControllerError::policy(format!(
                "environment contains unsupported variable {name}"
            )));
        }
        if value.as_encoded_bytes().contains(&0) {
            return Err(ControllerError::policy("environment value contains NUL"));
        }
    }
    if env::var_os("PATH").as_deref() != Some(OsStr::new("/usr/bin:/bin")) {
        return Err(ControllerError::policy(
            "environment PATH is not the exact authenticated value",
        ));
    }
    for name in ["LANG", "LC_ALL"] {
        if env::var_os(name).as_deref() != Some(OsStr::new("C")) {
            return Err(ControllerError::policy(format!(
                "environment {name} is not the exact authenticated value"
            )));
        }
    }
    if let Some(value) = env::var_os("PYTHONDONTWRITEBYTECODE")
        && value != "1"
    {
        return Err(ControllerError::policy(
            "environment PYTHONDONTWRITEBYTECODE is not the exact authenticated value",
        ));
    }
    let temporary = env::var_os("TMPDIR")
        .ok_or_else(|| ControllerError::policy("environment TMPDIR is missing"))?;
    validate_environment_directory(Path::new(&temporary), "TMPDIR")?;
    if let Some(home) = env::var_os("HOME") {
        validate_environment_directory(Path::new(&home), "HOME")?;
        if !request.deny_all_writes && Path::new(&home) != request.working_directory {
            return Err(ControllerError::policy(
                "allowlisted-write request HOME differs from its working directory",
            ));
        }
    }
    Ok(())
}

fn validate_environment_directory(path: &Path, name: &str) -> Result<()> {
    if !path.is_absolute()
        || path.as_os_str().as_encoded_bytes().len() > MAX_PATH_BYTES
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(ControllerError::policy(format!(
            "environment {name} is not one normalized absolute directory"
        )));
    }
    let canonical = fs::canonicalize(path)
        .map_err(|_| ControllerError::policy(format!("environment {name} is unavailable")))?;
    if canonical != path {
        return Err(ControllerError::policy(format!(
            "environment {name} is not canonical and symlink-free"
        )));
    }
    let runtime_uid = effective_user();
    for directory in path.ancestors() {
        let metadata = fs::symlink_metadata(directory).map_err(|_| {
            ControllerError::policy(format!("environment {name} custody is unavailable"))
        })?;
        let mode = metadata.permissions().mode();
        let owner = metadata.uid();
        let root_sticky_directory = owner == 0 && mode & 0o1000 != 0;
        if !metadata.is_dir()
            || (owner != 0 && owner != runtime_uid)
            || (mode & 0o022 != 0 && !root_sticky_directory)
        {
            return Err(ControllerError::policy(format!(
                "environment {name} is not runtime/root-custodied"
            )));
        }
    }
    Ok(())
}

#[allow(
    unsafe_code,
    reason = "fcntl is the audited descriptor-closure boundary"
)]
fn validate_no_inherited_fds() -> Result<()> {
    unsafe extern "C" {
        fn fcntl(fd: i32, command: i32, ...) -> i32;
    }
    const F_GETFD: i32 = 1;

    #[cfg(target_os = "macos")]
    let descriptor_directory = Path::new("/dev/fd");
    #[cfg(target_os = "linux")]
    let descriptor_directory = Path::new("/proc/self/fd");
    let iterator = fs::read_dir(descriptor_directory)
        .map_err(|_| ControllerError::policy("inherited descriptor inventory is unavailable"))?;
    let mut descriptors = Vec::new();
    for entry in iterator {
        let entry = entry.map_err(|_| {
            ControllerError::policy("inherited descriptor inventory is unavailable")
        })?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| ControllerError::policy("invalid descriptor inventory entry"))?;
        let descriptor = name
            .parse::<i32>()
            .map_err(|_| ControllerError::policy("invalid descriptor inventory entry"))?;
        if descriptor > 2 {
            descriptors.push(descriptor);
        }
    }
    // The inventory operation itself owns one descriptor. It is closed when
    // `iterator` is dropped at the end of the loop, so probe every observed
    // number again and reject only descriptors that remain live.
    for descriptor in descriptors {
        if unsafe { fcntl(descriptor, F_GETFD) } >= 0 {
            return Err(ControllerError::policy(format!(
                "controller inherited unexpected descriptor {descriptor}"
            )));
        }
        if io::Error::last_os_error().raw_os_error() != Some(9) {
            return Err(ControllerError::policy(
                "inherited descriptor status is unavailable",
            ));
        }
    }
    Ok(())
}

#[allow(
    unsafe_code,
    reason = "Unix credential queries have no safe standard-library wrappers"
)]
fn validate_runtime_identity(request: &Request) -> Result<()> {
    unsafe extern "C" {
        fn getuid() -> u32;
        fn geteuid() -> u32;
        fn getgid() -> u32;
        fn getegid() -> u32;
    }
    let (real_user, effective_user, real_group, effective_group) =
        unsafe { (getuid(), geteuid(), getgid(), getegid()) };
    if real_user != effective_user
        || real_group != effective_group
        || effective_user != request.expected_user
        || effective_group != request.expected_group
    {
        return Err(ControllerError::policy(
            "runtime identity differs from its exact attested credentials",
        ));
    }
    #[cfg(target_os = "macos")]
    {
        unsafe extern "C" {
            fn issetugid() -> i32;
        }
        if unsafe { issetugid() } != 0 {
            return Err(ControllerError::policy(
                "runtime identity originated from a set-id execution",
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_macos(request: &Request) -> Result<u8> {
    let executable = PathBuf::from(&request.tool[0]);
    let executable = fs::canonicalize(&executable)
        .map_err(|_| ControllerError::policy("tool executable is unavailable"))?;
    if executable.as_os_str() != request.tool[0].as_os_str() {
        return Err(ControllerError::policy(
            "tool executable must be canonical and symlink-free",
        ));
    }
    validate_trusted_path(&executable, false)?;
    validate_trusted_path(Path::new(SANDBOX_EXEC), true)?;
    validate_working_directory(request)?;
    prepare_writable_files(request)?;
    let readable_snapshots = validate_readable_inputs(request)?;
    let executable_identity = file_identity(&executable, true, true)?;
    let initial_root = if request.deny_all_writes {
        None
    } else {
        Some(root_snapshot(&request.working_directory)?)
    };
    validate_write_state(request, initial_root.as_ref())?;
    let profile = macos_profile(request, &executable)?;
    validate_sandbox_profile(&profile)?;

    let environment: Vec<(OsString, OsString)> = env::vars_os().collect();
    let mut command = Command::new(SANDBOX_EXEC);
    command
        .arg("-p")
        .arg(profile)
        .arg(&executable)
        .args(&request.tool[1..])
        .current_dir(&request.working_directory)
        .env_clear()
        .envs(environment)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let file_limit = request
        .writable_files
        .iter()
        .map(|file| file.maximum_bytes)
        .max()
        .unwrap_or(0);
    configure_isolated_child(&mut command, file_limit);

    let mut child = command
        .spawn()
        .map_err(|_| ControllerError::policy("failed to execute macOS Seatbelt controller"))?;
    let process_group =
        i32::try_from(child.id()).expect("a macOS child process identifier fits signed pid_t");
    let watchdog = match Watchdog::start(process_group) {
        Ok(watchdog) => watchdog,
        Err(error) => {
            terminate_unwatched_job(&mut child, process_group)?;
            return Err(error);
        }
    };
    let mut job = MacosJob::new(child, process_group, watchdog);
    let stdout = job
        .child
        .stdout
        .take()
        .ok_or_else(|| ControllerError::policy("tool stdout pipe is unavailable"))?;
    let stderr = job
        .child
        .stderr
        .take()
        .ok_or_else(|| ControllerError::policy("tool stderr pipe is unavailable"))?;
    let combined = Arc::new(AtomicU64::new(0));
    let overflow = Arc::new(AtomicBool::new(false));
    let stdout_thread = bounded_reader(
        stdout,
        request.stdout_limit,
        request.combined_output_limit,
        Arc::clone(&combined),
        Arc::clone(&overflow),
    );
    let stderr_thread = bounded_reader(
        stderr,
        request.stderr_limit,
        request.combined_output_limit,
        Arc::clone(&combined),
        Arc::clone(&overflow),
    );

    let started = Instant::now();
    let mut failure: Option<ControllerError> = None;
    let status = loop {
        if overflow.load(Ordering::Acquire) {
            failure = Some(ControllerError::limit("tool output exceeded its bound"));
            terminate_process_group(&mut job.child, process_group)?;
            break job
                .child
                .wait()
                .map_err(|_| ControllerError::policy("failed to reap isolated tool"))?;
        }
        if started.elapsed() >= request.wall_time {
            failure = Some(ControllerError::limit("tool exceeded its wall-time bound"));
            terminate_process_group(&mut job.child, process_group)?;
            break job
                .child
                .wait()
                .map_err(|_| ControllerError::policy("failed to reap isolated tool"))?;
        }
        if !request.deny_all_writes
            && let Err(error) = validate_write_state(request, initial_root.as_ref())
        {
            failure = Some(error);
            terminate_process_group(&mut job.child, process_group)?;
            break job
                .child
                .wait()
                .map_err(|_| ControllerError::policy("failed to reap isolated tool"))?;
        }
        match job
            .child
            .try_wait()
            .map_err(|_| ControllerError::policy("failed to inspect isolated tool"))?
        {
            Some(status) => break status,
            None => thread::sleep(MONITOR_INTERVAL),
        }
    };

    let stdout_result = stdout_thread
        .join()
        .map_err(|_| ControllerError::policy("tool stdout reader failed"))?;
    let stderr_result = stderr_thread
        .join()
        .map_err(|_| ControllerError::policy("tool stderr reader failed"))?;
    if overflow.load(Ordering::Acquire) {
        failure = Some(ControllerError::limit("tool output exceeded its bound"));
    }
    if stdout_result.io_failed || stderr_result.io_failed {
        failure = Some(ControllerError::policy("tool diagnostic pipe failed"));
    }
    io::stdout()
        .write_all(&stdout_result.bytes)
        .and_then(|()| io::stdout().flush())
        .map_err(|_| ControllerError::policy("failed to forward tool stdout"))?;
    io::stderr()
        .write_all(&stderr_result.bytes)
        .and_then(|()| io::stderr().flush())
        .map_err(|_| ControllerError::policy("failed to forward tool stderr"))?;

    ensure_empty_process_group(process_group)?;
    job.finish_watchdog()?;
    if file_identity(&executable, true, true)? != executable_identity {
        return Err(ControllerError::policy(
            "tool executable changed during execution",
        ));
    }
    validate_readable_snapshots(&readable_snapshots)?;
    if !request.deny_all_writes {
        validate_write_state(request, initial_root.as_ref())?;
    }
    if let Some(error) = failure {
        return Err(error);
    }
    if let Some(code) = status.code() {
        return u8::try_from(code)
            .map_err(|_| ControllerError::policy("tool returned an invalid exit status"));
    }
    let signal = status
        .signal()
        .ok_or_else(|| ControllerError::policy("tool termination status is unavailable"))?;
    Ok(u8::try_from(128i32.saturating_add(signal)).unwrap_or(u8::MAX))
}

#[cfg(target_os = "macos")]
fn terminate_unwatched_job(child: &mut Child, process_group: i32) -> Result<()> {
    if terminate_process_group(child, process_group).is_err() {
        child
            .kill()
            .map_err(|_| ControllerError::policy("failed to kill unmonitored isolated tool"))?;
    }
    child
        .wait()
        .map_err(|_| ControllerError::policy("failed to reap unmonitored isolated tool"))?;
    Ok(())
}

#[cfg(target_os = "macos")]
struct MacosJob {
    child: Child,
    process_group: i32,
    watchdog: Option<Watchdog>,
    completed: bool,
}

#[cfg(target_os = "macos")]
impl MacosJob {
    fn new(child: Child, process_group: i32, watchdog: Watchdog) -> Self {
        Self {
            child,
            process_group,
            watchdog: Some(watchdog),
            completed: false,
        }
    }

    fn finish_watchdog(&mut self) -> Result<()> {
        let watchdog = self
            .watchdog
            .take()
            .ok_or_else(|| ControllerError::policy("cleanup watchdog is unavailable"))?;
        watchdog.finish()?;
        self.completed = true;
        Ok(())
    }
}

#[cfg(target_os = "macos")]
impl Drop for MacosJob {
    fn drop(&mut self) {
        if self.completed {
            return;
        }

        // Closing the heartbeat first makes the independent watchdog kill the
        // whole session even if the controller's own cleanup primitives fail.
        drop(self.watchdog.take());
        let _ = terminate_process_group(&mut self.child, self.process_group);
        let _ = self.child.wait();
    }
}

#[cfg(target_os = "macos")]
#[allow(
    unsafe_code,
    reason = "CommandExt::pre_exec is required to install limits before the authenticated exec"
)]
fn configure_isolated_child(command: &mut Command, file_limit: u64) {
    unsafe {
        command.pre_exec(move || prepare_isolated_child(file_limit));
    }
}

#[cfg(target_os = "macos")]
#[allow(
    unsafe_code,
    reason = "setsid/umask/setrlimit are the audited pre-exec isolation boundary"
)]
fn prepare_isolated_child(file_limit: u64) -> io::Result<()> {
    unsafe extern "C" {
        fn setsid() -> i32;
        fn umask(mask: u16) -> u16;
        fn setrlimit(resource: i32, limits: *const ResourceLimit) -> i32;
    }
    #[repr(C)]
    struct ResourceLimit {
        current: u64,
        maximum: u64,
    }
    const RLIMIT_FSIZE: i32 = 1;
    const RLIMIT_CORE: i32 = 4;
    unsafe {
        if setsid() < 0 {
            return Err(io::Error::last_os_error());
        }
        umask(0o077);
        let core = ResourceLimit {
            current: 0,
            maximum: 0,
        };
        if setrlimit(RLIMIT_CORE, &raw const core) != 0 {
            return Err(io::Error::last_os_error());
        }
        if file_limit > 0 {
            let file = ResourceLimit {
                current: file_limit,
                maximum: file_limit,
            };
            if setrlimit(RLIMIT_FSIZE, &raw const file) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn validate_sandbox_profile(profile: &str) -> Result<()> {
    if profile.len() > 256 * 1024 || profile.as_bytes().contains(&0) {
        return Err(ControllerError::policy(
            "generated Seatbelt profile exceeds its bound",
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn macos_profile(request: &Request, executable: &Path) -> Result<String> {
    let executable_literal = seatbelt_literal(executable)?;
    let mut profile = format!(
        "(version 1)\n(deny default)\n(allow sysctl-read (sysctl-name \"hw.memsize\" \"hw.pagesize\" \"hw.pagesize_compat\"))\n(allow process-info* (target self))\n(allow signal (target self))\n(allow process-exec (literal {executable_literal}))\n(deny network*)\n(deny process-fork)\n(deny process-exec (require-not (literal {executable_literal})))\n(deny file-link)\n(deny file-clone)\n"
    );
    let mut readable_ancestors = BTreeSet::new();
    for path in std::iter::once(executable)
        .chain(std::iter::once(request.working_directory.as_path()))
        .chain(request.readable_files.iter().map(PathBuf::as_path))
        .chain(request.readable_directories.iter().map(PathBuf::as_path))
        .chain(
            request
                .writable_files
                .iter()
                .map(|file| file.path.as_path()),
        )
    {
        for ancestor in path.ancestors().skip(1) {
            readable_ancestors.insert(ancestor.to_path_buf());
        }
    }
    readable_ancestors.insert(request.working_directory.clone());
    for runtime_path in [
        "/usr/lib",
        "/System/Library",
        "/System/Volumes/Preboot/Cryptexes/OS/System/Library",
        "/dev/null",
        "/dev/random",
        "/dev/urandom",
    ] {
        for ancestor in Path::new(runtime_path).ancestors().skip(1) {
            readable_ancestors.insert(ancestor.to_path_buf());
        }
    }
    // Darwin requires data access to the filesystem root while resolving an
    // executable. Other ancestors need metadata only; do not grant directory
    // enumeration of operator-private parent directories.
    profile.push_str("(allow file-read-data (literal \"/\"))\n");
    profile.push_str("(allow file-read-metadata");
    for ancestor in readable_ancestors {
        profile.push_str(" (literal ");
        profile.push_str(&seatbelt_literal(&ancestor)?);
        profile.push(')');
    }
    profile.push_str(")\n");
    profile.push_str("(allow file-read*");
    for path in std::iter::once(executable)
        .chain(request.readable_files.iter().map(PathBuf::as_path))
        .chain(request.readable_directories.iter().map(PathBuf::as_path))
        .chain(
            request
                .writable_files
                .iter()
                .map(|file| file.path.as_path()),
        )
    {
        profile.push_str(" (literal ");
        profile.push_str(&seatbelt_literal(path)?);
        profile.push(')');
    }
    profile.push_str(")\n");
    // These immutable Apple runtime roots are the only recursive read grants.
    // They contain executable/runtime support, not operator or signing data.
    for root in [
        "/usr/lib",
        "/System/Library",
        "/System/Volumes/Preboot/Cryptexes/OS/System/Library",
    ] {
        profile.push_str("(allow file-read* (literal ");
        profile.push_str(&seatbelt_literal(Path::new(root))?);
        profile.push_str(") (subpath ");
        profile.push_str(&seatbelt_literal(Path::new(root))?);
        profile.push_str("))\n");
    }
    for device in ["/dev/null", "/dev/random", "/dev/urandom"] {
        profile.push_str("(allow file-read* (literal ");
        profile.push_str(&seatbelt_literal(Path::new(device))?);
        profile.push_str("))\n");
    }
    if request.deny_all_writes {
        profile.push_str("(deny file-write*)\n");
    } else {
        let literals = request
            .writable_files
            .iter()
            .map(|file| seatbelt_literal(&file.path))
            .collect::<Result<Vec<_>>>()?;
        profile.push_str("(deny file-write-unlink)\n");
        profile.push_str("(deny file-write* (require-not (require-any");
        for literal in literals {
            profile.push_str(" (literal ");
            profile.push_str(&literal);
            profile.push(')');
        }
        profile.push_str(")))\n");
        profile.push_str("(deny file-write-create)\n");
        for literal in request
            .writable_files
            .iter()
            .map(|file| seatbelt_literal(&file.path))
            .collect::<Result<Vec<_>>>()?
        {
            profile.push_str("(allow file-write-data (literal ");
            profile.push_str(&literal);
            profile.push_str("))\n");
        }
    }
    Ok(profile)
}

#[cfg(target_os = "macos")]
fn seatbelt_literal(path: &Path) -> Result<String> {
    let text = path
        .to_str()
        .ok_or_else(|| ControllerError::policy("Seatbelt path is not UTF-8"))?;
    if text.len() > MAX_PATH_BYTES || text.chars().any(char::is_control) {
        return Err(ControllerError::policy(
            "Seatbelt path is not representable",
        ));
    }
    let mut escaped = String::with_capacity(text.len() + 2);
    escaped.push('"');
    for character in text.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            _ => escaped.push(character),
        }
    }
    escaped.push('"');
    Ok(escaped)
}

fn validate_working_directory(request: &Request) -> Result<()> {
    if request.working_directory == Path::new("/") {
        if !request.deny_all_writes {
            return Err(ControllerError::policy(
                "filesystem root is valid only for deny-all-writes requests",
            ));
        }
        validate_trusted_path_acl(&request.working_directory)?;
        return Ok(());
    }
    let metadata = fs::metadata(&request.working_directory)
        .map_err(|_| ControllerError::policy("working directory is unavailable"))?;
    if !metadata.is_dir()
        || metadata.uid() != effective_user()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(ControllerError::policy(
            "writable working directory is not runtime-identity private",
        ));
    }
    validate_trusted_path_acl(&request.working_directory)?;
    validate_trusted_parent_chain(&request.working_directory)?;
    Ok(())
}

fn validate_readable_inputs(request: &Request) -> Result<Vec<(PathBuf, FileIdentity)>> {
    let mut snapshots =
        Vec::with_capacity(request.readable_files.len() + request.readable_directories.len());
    for path in &request.readable_files {
        validate_readable_path(path, false)?;
        snapshots.push((path.clone(), file_identity(path, true, false)?));
    }
    for path in &request.readable_directories {
        validate_readable_path(path, true)?;
        snapshots.push((path.clone(), file_identity(path, false, false)?));
    }
    Ok(snapshots)
}

fn validate_readable_path(path: &Path, require_directory: bool) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| ControllerError::policy("readable input metadata is unavailable"))?;
    let runtime_uid = effective_user();
    let type_is_safe = if require_directory {
        metadata.is_dir()
    } else {
        metadata.is_file() && metadata.nlink() == 1
    };
    if !type_is_safe
        || (metadata.uid() != 0 && metadata.uid() != runtime_uid)
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(ControllerError::policy(
            "readable input has unsafe type, link count, ownership, or mode",
        ));
    }
    validate_trusted_path_acl(path)?;
    validate_trusted_parent_chain(path)
}

fn validate_readable_snapshots(snapshots: &[(PathBuf, FileIdentity)]) -> Result<()> {
    for (path, expected) in snapshots {
        let require_regular = expected.mode & 0o170_000 == 0o100_000;
        if file_identity(path, require_regular, false)? != *expected {
            return Err(ControllerError::policy(format!(
                "readable input changed during execution: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn prepare_writable_files(request: &Request) -> Result<()> {
    if request.deny_all_writes {
        return Ok(());
    }
    for writable in &request.writable_files {
        match fs::symlink_metadata(&writable.path) {
            Ok(_) => {
                let identity = file_identity(&writable.path, true, false)?;
                validate_writable_identity(&writable.name, &identity, writable.maximum_bytes)?;
                validate_trusted_path_acl(&writable.path)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                #[cfg(target_os = "macos")]
                const SAFE_CREATE_FLAGS: i32 = 0x0000_0100 | 0x0100_0000; // O_NOFOLLOW | O_CLOEXEC.
                #[cfg(target_os = "linux")]
                const SAFE_CREATE_FLAGS: i32 = 0x0002_0000 | 0x0008_0000; // O_NOFOLLOW | O_CLOEXEC.
                let mut options = fs::OpenOptions::new();
                options
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(SAFE_CREATE_FLAGS);
                let file = options.open(&writable.path).map_err(|_| {
                    ControllerError::policy(format!(
                        "failed to pre-create writable file: {}",
                        writable.name
                    ))
                })?;
                file.set_permissions(fs::Permissions::from_mode(0o600))
                    .map_err(|_| {
                        ControllerError::policy(format!(
                            "failed to make writable file private: {}",
                            writable.name
                        ))
                    })?;
                let identity = file_identity(&writable.path, true, false)?;
                validate_writable_identity(&writable.name, &identity, writable.maximum_bytes)?;
                validate_trusted_path_acl(&writable.path)?;
            }
            Err(_) => {
                return Err(ControllerError::policy(format!(
                    "writable file metadata is unavailable: {}",
                    writable.name
                )));
            }
        }
    }
    Ok(())
}

fn validate_trusted_path(path: &Path, require_root_owner: bool) -> Result<()> {
    let canonical = fs::canonicalize(path)
        .map_err(|_| ControllerError::policy("trusted executable path is unavailable"))?;
    if canonical != path {
        return Err(ControllerError::policy(
            "trusted executable path is not canonical and symlink-free",
        ));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| ControllerError::policy("trusted executable metadata is unavailable"))?;
    let expected_user = if require_root_owner {
        0
    } else {
        effective_user()
    };
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != expected_user
        || !trusted_executable_mode_is_safe(metadata.permissions().mode())
    {
        return Err(ControllerError::policy(
            "trusted executable has unsafe ownership, mode, or identity",
        ));
    }
    validate_trusted_path_acl(path)?;
    validate_trusted_parent_chain(path)?;
    Ok(())
}

fn trusted_executable_mode_is_safe(mode: u32) -> bool {
    mode & 0o6022 == 0 && mode & 0o111 != 0
}

fn validate_trusted_parent_chain(path: &Path) -> Result<()> {
    let runtime_uid = effective_user();
    for parent in path.ancestors().skip(1) {
        let metadata = fs::symlink_metadata(parent).map_err(|_| {
            ControllerError::policy("trusted executable parent metadata is unavailable")
        })?;
        let mode = metadata.permissions().mode();
        let owner = metadata.uid();
        let root_sticky_directory = owner == 0 && mode & 0o1000 != 0;
        if !metadata.is_dir()
            || (owner != 0 && owner != runtime_uid)
            || (mode & 0o022 != 0 && !root_sticky_directory)
        {
            return Err(ControllerError::policy(
                "trusted executable parent chain is not runtime/root-custodied",
            ));
        }
        validate_trusted_path_acl(parent)?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
#[allow(
    unsafe_code,
    reason = "macOS exposes descriptor-bound extended ACL inspection only through libc"
)]
fn validate_trusted_path_acl(path: &Path) -> Result<()> {
    unsafe extern "C" {
        fn acl_get_fd_np(descriptor: i32, acl_type: i32) -> *mut std::ffi::c_void;
        fn acl_get_entry(
            acl: *mut std::ffi::c_void,
            entry_id: i32,
            entry: *mut *mut std::ffi::c_void,
        ) -> i32;
        fn acl_free(object: *mut std::ffi::c_void) -> i32;
    }
    const ACL_TYPE_EXTENDED: i32 = 0x0000_0100;
    const ACL_FIRST_ENTRY: i32 = 0;
    const ENOENT: i32 = 2;

    let file = File::open(path)
        .map_err(|_| ControllerError::policy("trusted path ACL descriptor is unavailable"))?;
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        return if io::Error::last_os_error().raw_os_error() == Some(ENOENT) {
            Ok(())
        } else {
            Err(ControllerError::policy(
                "trusted path extended ACL is unavailable",
            ))
        };
    }
    let mut entry = std::ptr::null_mut();
    let entry_status = unsafe { acl_get_entry(acl, ACL_FIRST_ENTRY, &raw mut entry) };
    let free_status = unsafe { acl_free(acl) };
    if entry_status < 0 || free_status != 0 {
        return Err(ControllerError::policy(
            "trusted path extended ACL inspection failed",
        ));
    }
    if entry_status == 0 {
        return Err(ControllerError::policy("trusted path has an extended ACL"));
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn validate_trusted_path_acl(_path: &Path) -> Result<()> {
    Ok(())
}

fn root_snapshot(root: &Path) -> Result<RootSnapshot> {
    let directory = file_identity(root, false, false)?;
    let mut entries = BTreeMap::new();
    let iterator = fs::read_dir(root)
        .map_err(|_| ControllerError::policy("write-root inventory is unavailable"))?;
    for entry in iterator {
        let entry =
            entry.map_err(|_| ControllerError::policy("write-root inventory is unavailable"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| ControllerError::policy("write-root name is not UTF-8"))?;
        let identity = file_identity(&entry.path(), true, false)?;
        if entries.insert(name, identity).is_some() {
            return Err(ControllerError::policy(
                "write-root inventory contains duplicate names",
            ));
        }
    }
    Ok(RootSnapshot { directory, entries })
}

fn validate_write_state(request: &Request, initial: Option<&RootSnapshot>) -> Result<()> {
    if request.deny_all_writes {
        return Ok(());
    }
    let initial = initial.ok_or_else(|| ControllerError::policy("write snapshot is absent"))?;
    let current = root_snapshot(&request.working_directory)?;
    if directory_stable_fields(&current.directory) != directory_stable_fields(&initial.directory) {
        return Err(ControllerError::limit(
            "write-root directory identity changed during execution",
        ));
    }
    let allowed: BTreeMap<&str, u64> = request
        .writable_files
        .iter()
        .map(|file| (file.name.as_str(), file.maximum_bytes))
        .collect();
    for (name, identity) in &current.entries {
        if let Some(limit) = allowed.get(name.as_str()) {
            validate_writable_identity(name, identity, *limit)?;
        } else if initial.entries.get(name) != Some(identity) {
            return Err(ControllerError::limit(format!(
                "protected write-root entry changed: {name}"
            )));
        }
    }
    for name in initial.entries.keys() {
        if !allowed.contains_key(name.as_str()) && !current.entries.contains_key(name) {
            return Err(ControllerError::limit(format!(
                "protected write-root entry disappeared: {name}"
            )));
        }
    }
    for name in current.entries.keys() {
        if !initial.entries.contains_key(name) && !allowed.contains_key(name.as_str()) {
            return Err(ControllerError::limit(format!(
                "unexpected write-root entry appeared: {name}"
            )));
        }
    }
    let writable_bytes = current
        .entries
        .iter()
        .filter(|(name, _)| allowed.contains_key(name.as_str()))
        .try_fold(0u64, |total, (_, identity)| {
            total
                .checked_add(identity.size)
                .ok_or_else(|| ControllerError::limit("write accounting overflow"))
        })?;
    if writable_bytes > request.cumulative_write_limit {
        return Err(ControllerError::limit(
            "cumulative write quota was exceeded",
        ));
    }
    let live_bytes = current.entries.values().try_fold(0u64, |total, identity| {
        total
            .checked_add(identity.size)
            .ok_or_else(|| ControllerError::limit("live write-root accounting overflow"))
    })?;
    if live_bytes > request.maximum_live_write_root {
        return Err(ControllerError::limit(
            "maximum live write-root quota was exceeded",
        ));
    }
    Ok(())
}

fn directory_stable_fields(identity: &FileIdentity) -> (u64, u64, u32, u32, u32) {
    (
        identity.device,
        identity.inode,
        identity.mode,
        identity.uid,
        identity.gid,
    )
}

fn validate_writable_identity(name: &str, identity: &FileIdentity, limit: u64) -> Result<()> {
    if identity.mode & 0o170_000 != 0o100_000
        || identity.links != 1
        || identity.uid != effective_user()
        || identity.mode & 0o077 != 0
    {
        return Err(ControllerError::limit(format!(
            "writable file has unsafe type, link count, ownership, or mode: {name}"
        )));
    }
    if identity.size > limit {
        return Err(ControllerError::limit(format!(
            "writable file exceeded its declared quota: {name}"
        )));
    }
    Ok(())
}

fn file_identity(path: &Path, require_regular: bool, hash_contents: bool) -> Result<FileIdentity> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        ControllerError::policy(format!("path metadata is unavailable: {}", path.display()))
    })?;
    if require_regular && !metadata.is_file() {
        return Err(ControllerError::policy(format!(
            "path is not a regular file: {}",
            path.display()
        )));
    }
    let sha256 = if hash_contents && metadata.is_file() {
        sha256_file(path)?
    } else {
        [0; 32]
    };
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        links: metadata.nlink(),
        size: metadata.size(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        sha256,
    })
}

fn sha256_file(path: &Path) -> Result<[u8; 32]> {
    #[cfg(target_os = "macos")]
    const SAFE_OPEN_FLAGS: i32 = 0x0000_0100 | 0x0100_0000; // O_NOFOLLOW | O_CLOEXEC.
    #[cfg(target_os = "linux")]
    const SAFE_OPEN_FLAGS: i32 = 0x0002_0000 | 0x0008_0000; // O_NOFOLLOW | O_CLOEXEC.
    let mut options = fs::OpenOptions::new();
    options.read(true).custom_flags(SAFE_OPEN_FLAGS);
    let mut file = options
        .open(path)
        .map_err(|_| ControllerError::policy(format!("cannot authenticate {}", path.display())))?;
    let before = file
        .metadata()
        .map_err(|_| ControllerError::policy("authenticated file metadata is unavailable"))?;
    if !before.is_file() {
        return Err(ControllerError::policy(
            "authenticated path is not a regular file",
        ));
    }
    let mut hash = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| ControllerError::policy("authenticated file read failed"))?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    let after = file
        .metadata()
        .map_err(|_| ControllerError::policy("authenticated file metadata is unavailable"))?;
    if stable_metadata(&before) != stable_metadata(&after) {
        return Err(ControllerError::policy(
            "authenticated file changed while hashing",
        ));
    }
    Ok(hash.finish())
}

fn stable_metadata(metadata: &Metadata) -> (u64, u64, u32, u32, u32, u64, u64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.mode(),
        metadata.uid(),
        metadata.gid(),
        metadata.nlink(),
        metadata.size(),
        metadata.mtime(),
        metadata.mtime_nsec(),
    )
}

fn bounded_reader<R: Read + Send + 'static>(
    mut reader: R,
    stream_limit: u64,
    combined_limit: Option<u64>,
    combined: Arc<AtomicU64>,
    overflow: Arc<AtomicBool>,
) -> thread::JoinHandle<ReaderResult> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 16 * 1024];
        let mut io_failed = false;
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    let previous = combined.fetch_add(count as u64, Ordering::AcqRel);
                    let stream_overflow = (bytes.len() as u64)
                        .checked_add(count as u64)
                        .is_none_or(|total| total > stream_limit);
                    let combined_overflow = combined_limit.is_some_and(|limit| {
                        previous
                            .checked_add(count as u64)
                            .is_none_or(|total| total > limit)
                    });
                    if stream_overflow || combined_overflow {
                        overflow.store(true, Ordering::Release);
                    } else {
                        bytes.extend_from_slice(&buffer[..count]);
                    }
                }
                Err(_) => {
                    io_failed = true;
                    break;
                }
            }
        }
        ReaderResult { bytes, io_failed }
    })
}

#[cfg(target_os = "macos")]
fn terminate_process_group(child: &mut Child, process_group: i32) -> Result<()> {
    if child
        .try_wait()
        .map_err(|_| ControllerError::policy("failed to inspect isolated tool cleanup"))?
        .is_some()
    {
        return Ok(());
    }
    let leader = i32::try_from(child.id())
        .map_err(|_| ControllerError::policy("isolated tool PID does not fit i32"))?;
    send_job_signal(process_group, leader, 15)?;
    let deadline = Instant::now() + CLEANUP_GRACE;
    while Instant::now() < deadline {
        if child
            .try_wait()
            .map_err(|_| ControllerError::policy("failed to inspect isolated tool cleanup"))?
            .is_some()
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(5));
    }
    send_job_signal(process_group, leader, 9)?;
    Ok(())
}

#[cfg(target_os = "macos")]
#[allow(
    unsafe_code,
    reason = "kill is the audited Darwin job-signaling primitive"
)]
fn send_job_signal(process_group: i32, leader: i32, signal: i32) -> Result<()> {
    unsafe extern "C" {
        fn kill(pid: i32, signal: i32) -> i32;
    }
    for target in [-process_group, leader] {
        let result = unsafe { kill(target, signal) };
        if result == 0 {
            continue;
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(3) {
            return Err(ControllerError::policy("failed to signal isolated job"));
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
#[allow(
    unsafe_code,
    reason = "kill(pid, 0) is the audited Darwin process-group liveness query"
)]
fn ensure_empty_process_group(process_group: i32) -> Result<()> {
    unsafe extern "C" {
        fn kill(pid: i32, signal: i32) -> i32;
    }
    if unsafe { kill(-process_group, 0) } == 0 {
        return Err(ControllerError::policy(
            "isolated process group is not empty at return",
        ));
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(3) {
        Ok(())
    } else {
        Err(ControllerError::policy(
            "isolated process-group status is unavailable",
        ))
    }
}

#[cfg(target_os = "macos")]
struct Watchdog {
    write_fd: i32,
    pid: i32,
}

#[cfg(target_os = "macos")]
impl Watchdog {
    #[allow(
        unsafe_code,
        reason = "the watchdog requires audited pipe/fork/signal Unix primitives"
    )]
    fn start(process_group: i32) -> Result<Self> {
        unsafe extern "C" {
            fn pipe(fds: *mut i32) -> i32;
            fn fork() -> i32;
            fn close(fd: i32) -> i32;
            fn read(fd: i32, buffer: *mut u8, count: usize) -> isize;
            fn kill(pid: i32, signal: i32) -> i32;
            fn usleep(microseconds: u32) -> i32;
            fn _exit(status: i32) -> !;
        }
        let mut fds = [-1i32; 2];
        if unsafe { pipe(fds.as_mut_ptr()) } != 0 {
            return Err(ControllerError::policy("failed to create cleanup watchdog"));
        }
        let pid = unsafe { fork() };
        if pid < 0 {
            unsafe {
                close(fds[0]);
                close(fds[1]);
            }
            return Err(ControllerError::policy("failed to start cleanup watchdog"));
        }
        if pid == 0 {
            unsafe {
                close(fds[1]);
                let mut normal = 0u8;
                let read_count = read(fds[0], &raw mut normal, 1);
                close(fds[0]);
                if read_count != 1 || normal != b'N' {
                    kill(-process_group, 15);
                    kill(process_group, 15);
                    usleep(250_000);
                    kill(-process_group, 9);
                    kill(process_group, 9);
                }
                _exit(0);
            }
        }
        unsafe {
            close(fds[0]);
        }
        Ok(Self {
            write_fd: fds[1],
            pid,
        })
    }

    #[allow(
        unsafe_code,
        reason = "the watchdog completion handshake requires audited Unix fd and wait primitives"
    )]
    fn finish(mut self) -> Result<()> {
        unsafe extern "C" {
            fn write(fd: i32, buffer: *const u8, count: usize) -> isize;
            fn close(fd: i32) -> i32;
            fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
        }
        let normal = b'N';
        let wrote = unsafe { write(self.write_fd, &raw const normal, 1) };
        let closed = unsafe { close(self.write_fd) };
        self.write_fd = -1;
        let watchdog_pid = self.pid;
        let mut status = 0;
        let waited = unsafe { waitpid(watchdog_pid, &raw mut status, 0) };
        if waited == watchdog_pid {
            self.pid = -1;
        }
        if wrote != 1 || closed != 0 || waited != watchdog_pid || status != 0 {
            return Err(ControllerError::policy("cleanup watchdog failed"));
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
impl Drop for Watchdog {
    #[allow(
        unsafe_code,
        reason = "Drop closes and reaps the watchdog through audited Unix primitives"
    )]
    fn drop(&mut self) {
        unsafe extern "C" {
            fn close(fd: i32) -> i32;
            fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
        }
        if self.write_fd >= 0 {
            unsafe {
                close(self.write_fd);
            }
            self.write_fd = -1;
        }
        if self.pid >= 0 {
            let mut status = 0;
            unsafe {
                waitpid(self.pid, &raw mut status, 0);
            }
            self.pid = -1;
        }
    }
}

#[allow(unsafe_code, reason = "geteuid has no safe standard-library wrapper")]
fn effective_user() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}

#[allow(unsafe_code, reason = "getegid has no safe standard-library wrapper")]
fn effective_group() -> u32 {
    unsafe extern "C" {
        fn getegid() -> u32;
    }
    unsafe { getegid() }
}

#[allow(
    unsafe_code,
    reason = "the non-production hostile probe intentionally exercises denied raw Unix operations"
)]
fn qualification_probe(arguments: &[OsString]) -> Result<u8> {
    let action = arguments
        .first()
        .and_then(|value| value.to_str())
        .ok_or_else(|| ControllerError::policy("qualification probe action is missing"))?;
    match action {
        "success" => {
            let path = probe_path(arguments, 1)?;
            fs::write(path, b"qualified\n")
                .map_err(|_| ControllerError::policy("qualification write failed"))?;
            println!("qualified stdout");
            eprintln!("qualified stderr");
            Ok(0)
        }
        "write" => {
            let path = probe_path(arguments, 1)?;
            fs::write(path, b"escape\n")
                .map_err(|_| ControllerError::policy("qualification write denied"))?;
            Ok(0)
        }
        "write-bytes" => {
            let path = probe_path(arguments, 1)?;
            let count = arguments
                .get(2)
                .and_then(|value| value.to_str())
                .ok_or_else(|| ControllerError::policy("probe byte count is missing"))?
                .parse::<usize>()
                .map_err(|_| ControllerError::policy("probe byte count is invalid"))?;
            fs::write(path, vec![b'q'; count])
                .map_err(|_| ControllerError::policy("qualification bounded write failed"))?;
            Ok(0)
        }
        "create-new" => {
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(probe_path(arguments, 1)?)
                .map_err(|_| {
                    ControllerError::policy("qualification create-new signer incompatible")
                })?;
            Ok(0)
        }
        "read" => {
            let path = probe_path(arguments, 1)?;
            let bytes =
                fs::read(path).map_err(|_| ControllerError::policy("qualification read denied"))?;
            io::stdout()
                .write_all(&bytes)
                .map_err(|_| ControllerError::policy("qualification read output failed"))?;
            Ok(0)
        }
        "metadata" => {
            fs::metadata(probe_path(arguments, 1)?)
                .map_err(|_| ControllerError::policy("qualification metadata read denied"))?;
            Ok(0)
        }
        "unlink" => {
            fs::remove_file(probe_path(arguments, 1)?)
                .map_err(|_| ControllerError::policy("qualification unlink denied"))?;
            Ok(0)
        }
        "rename" => {
            fs::rename(probe_path(arguments, 1)?, probe_path(arguments, 2)?)
                .map_err(|_| ControllerError::policy("qualification rename denied"))?;
            Ok(0)
        }
        "hardlink" => {
            fs::hard_link(probe_path(arguments, 1)?, probe_path(arguments, 2)?)
                .map_err(|_| ControllerError::policy("qualification hardlink denied"))?;
            Ok(0)
        }
        "symlink" => {
            std::os::unix::fs::symlink(probe_path(arguments, 1)?, probe_path(arguments, 2)?)
                .map_err(|_| ControllerError::policy("qualification symlink denied"))?;
            Ok(0)
        }
        "spawn" => {
            Command::new("/usr/bin/true")
                .status()
                .map_err(|_| ControllerError::policy("qualification spawn denied"))?;
            Ok(0)
        }
        "fork" => {
            unsafe extern "C" {
                fn fork() -> i32;
                fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
                fn _exit(status: i32) -> !;
            }
            let pid = unsafe { fork() };
            if pid < 0 {
                return Err(ControllerError::policy("qualification fork denied"));
            }
            if pid == 0 {
                unsafe { _exit(0) };
            }
            let mut status = 0;
            if unsafe { waitpid(pid, &raw mut status, 0) } != pid || status != 0 {
                return Err(ControllerError::policy("qualification fork child failed"));
            }
            Ok(0)
        }
        "setsid" => {
            unsafe extern "C" {
                fn setsid() -> i32;
            }
            if unsafe { setsid() } < 0 {
                return Err(ControllerError::policy("qualification setsid denied"));
            }
            Ok(0)
        }
        "setuid-root" => {
            unsafe extern "C" {
                fn setuid(uid: u32) -> i32;
            }
            if unsafe { setuid(0) } != 0 {
                return Err(ControllerError::policy(
                    "qualification privilege escalation denied",
                ));
            }
            Ok(0)
        }
        "fifo" => {
            unsafe extern "C" {
                fn mkfifo(path: *const i8, mode: u16) -> i32;
            }
            use std::{ffi::CString, os::unix::ffi::OsStrExt as _};
            let path = probe_path(arguments, 1)?;
            let path = CString::new(path.as_os_str().as_bytes())
                .map_err(|_| ControllerError::policy("qualification FIFO path is invalid"))?;
            if unsafe { mkfifo(path.as_ptr(), 0o600) } != 0 {
                return Err(ControllerError::policy("qualification FIFO denied"));
            }
            Ok(0)
        }
        "network" => {
            std::net::TcpListener::bind("127.0.0.1:0")
                .map_err(|_| ControllerError::policy("qualification network denied"))?;
            Ok(0)
        }
        #[cfg(target_os = "macos")]
        "ambient-sysctl" => {
            use std::ffi::CString;
            unsafe extern "C" {
                fn sysctlbyname(
                    name: *const i8,
                    old_value: *mut std::ffi::c_void,
                    old_length: *mut usize,
                    new_value: *mut std::ffi::c_void,
                    new_length: usize,
                ) -> i32;
            }
            let name = CString::new("kern.hostname").expect("static sysctl name");
            let mut length = 0usize;
            if unsafe {
                sysctlbyname(
                    name.as_ptr(),
                    std::ptr::null_mut(),
                    &raw mut length,
                    std::ptr::null_mut(),
                    0,
                )
            } != 0
            {
                return Err(ControllerError::policy(
                    "qualification ambient sysctl denied",
                ));
            }
            Ok(0)
        }
        "stdout-overflow" => {
            let count = arguments
                .get(1)
                .and_then(|value| value.to_str())
                .ok_or_else(|| ControllerError::policy("probe byte count is missing"))?
                .parse::<usize>()
                .map_err(|_| ControllerError::policy("probe byte count is invalid"))?;
            io::stdout()
                .write_all(&vec![b'x'; count])
                .map_err(|_| ControllerError::policy("probe stdout write failed"))?;
            Ok(0)
        }
        "sleep" => {
            thread::sleep(Duration::from_secs(30));
            Ok(0)
        }
        "exit" => {
            let code = arguments
                .get(1)
                .and_then(|value| value.to_str())
                .ok_or_else(|| ControllerError::policy("probe exit code is missing"))?
                .parse::<u8>()
                .map_err(|_| ControllerError::policy("probe exit code is invalid"))?;
            Ok(code)
        }
        _ => Err(ControllerError::policy(
            "unsupported qualification probe action",
        )),
    }
}

fn probe_path(arguments: &[OsString], index: usize) -> Result<&Path> {
    arguments
        .get(index)
        .map(Path::new)
        .ok_or_else(|| ControllerError::policy("qualification probe path is missing"))
}

struct Sha256 {
    state: [u32; 8],
    block: [u8; 64],
    buffered: usize,
    length: u64,
}

impl Sha256 {
    const K: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];

    const fn new() -> Self {
        Self {
            state: [
                0x6a09_e667,
                0xbb67_ae85,
                0x3c6e_f372,
                0xa54f_f53a,
                0x510e_527f,
                0x9b05_688c,
                0x1f83_d9ab,
                0x5be0_cd19,
            ],
            block: [0; 64],
            buffered: 0,
            length: 0,
        }
    }

    fn update(&mut self, mut bytes: &[u8]) {
        self.length = self.length.wrapping_add(bytes.len() as u64);
        if self.buffered != 0 {
            let count = (64 - self.buffered).min(bytes.len());
            self.block[self.buffered..self.buffered + count].copy_from_slice(&bytes[..count]);
            self.buffered += count;
            bytes = &bytes[count..];
            if self.buffered == 64 {
                let block = self.block;
                self.compress(&block);
                self.buffered = 0;
            } else {
                // Preserve the incomplete block until a later update fills it.
                return;
            }
        }
        while bytes.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&bytes[..64]);
            self.compress(&block);
            bytes = &bytes[64..];
        }
        self.block[..bytes.len()].copy_from_slice(bytes);
        self.buffered = bytes.len();
    }

    fn finish(mut self) -> [u8; 32] {
        let bit_length = self.length.wrapping_mul(8);
        self.block[self.buffered] = 0x80;
        self.buffered += 1;
        if self.buffered > 56 {
            self.block[self.buffered..].fill(0);
            let block = self.block;
            self.compress(&block);
            self.block = [0; 64];
        } else {
            self.block[self.buffered..56].fill(0);
        }
        self.block[56..].copy_from_slice(&bit_length.to_be_bytes());
        let block = self.block;
        self.compress(&block);
        let mut output = [0u8; 32];
        for (chunk, word) in output.chunks_exact_mut(4).zip(self.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        output
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut schedule = [0u32; 64];
        for (index, chunk) in block.chunks_exact(4).enumerate() {
            schedule[index] = u32::from_be_bytes(chunk.try_into().expect("four-byte chunk"));
        }
        for index in 16..64 {
            let s0 = schedule[index - 15].rotate_right(7)
                ^ schedule[index - 15].rotate_right(18)
                ^ (schedule[index - 15] >> 3);
            let s1 = schedule[index - 2].rotate_right(17)
                ^ schedule[index - 2].rotate_right(19)
                ^ (schedule[index - 2] >> 10);
            schedule[index] = schedule[index - 16]
                .wrapping_add(s0)
                .wrapping_add(schedule[index - 7])
                .wrapping_add(s1);
        }
        let mut working = self.state;
        for (&constant, &word) in Self::K.iter().zip(&schedule) {
            let sum1 = working[4].rotate_right(6)
                ^ working[4].rotate_right(11)
                ^ working[4].rotate_right(25);
            let choose = (working[4] & working[5]) ^ ((!working[4]) & working[6]);
            let temporary1 = working[7]
                .wrapping_add(sum1)
                .wrapping_add(choose)
                .wrapping_add(constant)
                .wrapping_add(word);
            let sum0 = working[0].rotate_right(2)
                ^ working[0].rotate_right(13)
                ^ working[0].rotate_right(22);
            let majority =
                (working[0] & working[1]) ^ (working[0] & working[2]) ^ (working[1] & working[2]);
            let temporary2 = sum0.wrapping_add(majority);
            working.rotate_right(1);
            working[4] = working[4].wrapping_add(temporary1);
            working[0] = temporary1.wrapping_add(temporary2);
        }
        for (state, value) in self.state.iter_mut().zip(working) {
            *state = state.wrapping_add(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_request() -> Vec<OsString> {
        [
            "--contract",
            CONTRACT,
            "--platform",
            if cfg!(target_os = "macos") {
                "macos"
            } else {
                "linux"
            },
            "--expected-runtime-uid",
            "0",
            "--expected-runtime-gid",
            "0",
            "--working-directory",
            "/",
            "--use-attested-runtime-identity",
            "--no-new-privileges",
            "--close-inherited-fds",
            "--forward-tool-exit-status",
            "--exact-tool-stdio",
            "--deny-network",
            "--deny-tool-process-spawn",
            "--deny-read-outside-allowlist",
            "--deny-all-writes",
            "--account-unlinked-write-bytes",
            "--require-empty-process-tree",
            "--cumulative-write-limit-bytes",
            "0",
            "--maximum-live-write-root-bytes",
            "0",
            "--wall-time-seconds",
            "1",
            "--stdout-limit-bytes",
            "1",
            "--stderr-limit-bytes",
            "1",
            "--",
            "/usr/bin/true",
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }

    #[test]
    fn sha256_matches_known_vector() {
        let mut sha = Sha256::new();
        sha.update(b"abc");
        assert_eq!(
            sha.finish(),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }

    #[test]
    fn sha256_streaming_matches_reference_across_padding_and_chunk_boundaries() {
        for (message, expected) in [
            (
                b"".to_vec(),
                [
                    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99,
                    0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95,
                    0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
                ],
            ),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".to_vec(),
                [
                    0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c,
                    0x3e, 0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec,
                    0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1,
                ],
            ),
            (
                (0_u8..=255).cycle().take(1280).collect::<Vec<_>>(),
                [
                    0xd4, 0x14, 0xb0, 0x85, 0x82, 0x6e, 0xb0, 0x67, 0x78, 0x48, 0x3b, 0xa3, 0x55,
                    0x64, 0xdc, 0x84, 0x9e, 0x64, 0x33, 0x59, 0xf6, 0x9e, 0xd9, 0x74, 0x78, 0x78,
                    0xba, 0x6e, 0x54, 0x98, 0x5b, 0xed,
                ],
            ),
        ] {
            for width in [1, 7, 63, 64, 65, 129] {
                let mut hash = Sha256::new();
                for chunk in message.chunks(width) {
                    hash.update(chunk);
                }
                assert_eq!(
                    hash.finish(),
                    expected,
                    "length {} chunk {width}",
                    message.len()
                );
            }
        }
    }

    #[test]
    fn parser_accepts_exact_deny_all_contract() {
        let request = parse_request(&base_request()).expect("parse exact request");
        assert!(request.deny_all_writes);
        assert_eq!(request.expected_user, 0);
        assert_eq!(request.expected_group, 0);
        assert_eq!(request.working_directory, Path::new("/"));
        assert!(request.readable_files.is_empty());
        assert!(request.readable_directories.is_empty());
        assert_eq!(request.tool, [OsString::from("/usr/bin/true")]);
    }

    #[test]
    fn parser_rejects_omitted_security_flag() {
        let mut request = base_request();
        let position = request
            .iter()
            .position(|value| value == "--deny-network")
            .expect("flag position");
        request.remove(position);
        let error = parse_request(&request).expect_err("missing flag must reject");
        assert!(error.message.contains("--deny-network"));
    }

    #[test]
    fn parser_rejects_unknown_option() {
        let mut request = base_request();
        request.insert(0, OsString::from("--permit-network"));
        let error = parse_request(&request).expect_err("unknown option must reject");
        assert!(error.message.contains("unsupported controller option"));
    }

    #[test]
    fn host_qualification_rejects_arguments() {
        let error = qualify_host(&[OsString::from("unexpected")])
            .expect_err("host qualification arguments must reject");
        assert!(error.message.contains("accepts no arguments"));
    }

    #[test]
    fn no_new_privileges_requires_a_non_setid_exact_image() {
        assert!(trusted_executable_mode_is_safe(0o100_755));
        for unsafe_mode in [0o104_755, 0o102_755, 0o100_775, 0o100_644] {
            assert!(
                !trusted_executable_mode_is_safe(unsafe_mode),
                "unsafe executable mode {unsafe_mode:o}"
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn seatbelt_profile_denies_network_fork_links_and_all_writes() {
        let request = parse_request(&base_request()).expect("parse request");
        let profile =
            macos_profile(&request, Path::new("/usr/bin/true")).expect("generate profile");
        for rule in [
            "(deny network*)",
            "(deny process-fork)",
            "(deny file-link)",
            "(deny file-clone)",
            "(deny file-write*)",
        ] {
            assert!(profile.contains(rule), "missing {rule}");
        }
        assert!(
            !profile.lines().any(|line| line == "(allow file-read*)"),
            "profile must not grant ambient filesystem reads"
        );
        assert!(profile.contains("(subpath \"/usr/lib\")"));
        assert!(profile.contains("(sysctl-name \"hw.memsize\" \"hw.pagesize\""));
        assert!(!profile.lines().any(|line| line == "(allow sysctl-read)"));
    }
}
