//! CLI-owned filesystem configuration layered beside the reusable SDK configuration.

use eyre::{Result, eyre};
use std::{
    env,
    path::{Path, PathBuf},
};

/// Filesystem paths used only by CLI commands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FilesystemConfig {
    /// SCCP preferences parsed from this same original client source.
    pub(crate) sccp: Option<iroha_sccp_wallet::config::SccpClientConfig>,
    /// Root directory containing Connect queue state.
    pub(crate) connect_queue_root: PathBuf,
    /// Optional canonical request witness used for multisig Soracloud HTTP mutations.
    pub(crate) soracloud_http_witness_file: Option<PathBuf>,
}

impl Default for FilesystemConfig {
    fn default() -> Self {
        Self {
            sccp: None,
            connect_queue_root: default_connect_queue_root(),
            soracloud_http_witness_file: None,
        }
    }
}

/// Return the CLI default Connect queue root.
pub(crate) fn default_connect_queue_root() -> PathBuf {
    let mut base = if cfg!(windows) {
        env::var_os("USERPROFILE").map(PathBuf::from)
    } else {
        env::var_os("HOME").map(PathBuf::from)
    }
    .unwrap_or_else(|| PathBuf::from("."));
    base.push(".iroha");
    base.push("connect");
    base
}

impl FilesystemConfig {
    /// Remove and validate the CLI-owned sections from a complete client TOML table.
    pub(crate) fn take_from(table: &mut toml::Table, source_path: &Path) -> Result<Self> {
        let mut config = Self::default();
        let mut sccp_table = toml::Table::new();
        if let Some(value) = table.get("sccp") {
            sccp_table.insert("sccp".to_owned(), value.clone());
        }
        let mut reader = iroha_config_base::read::ConfigReader::new()
            .without_env()
            .with_toml_source(iroha_config_base::toml::TomlSource::new(
                source_path.to_path_buf(),
                sccp_table,
            ));
        let sccp = reader.read_nested::<iroha::config::sccp::SccpClientConfigUser>("sccp");
        reader
            .into_result()
            .map_err(|error| eyre!("invalid client SCCP configuration: {error:?}"))?;
        let journal = source_path
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .join(iroha::config::sccp::defaults::JOURNAL_DIR_NAME);
        config.sccp = Some(iroha_sccp_wallet::config::SccpClientConfig::from_user(
            sccp.unwrap(),
            &journal,
        )?);
        if let Some(mut connect) = take_section(table, "connect")? {
            if let Some(value) = connect.remove("queue_root") {
                config.connect_queue_root =
                    take_nonempty_path(value, "connect.queue_root", source_path)?;
            }
            reject_unknown_keys("connect", &connect)?;
        }
        if let Some(mut soracloud) = take_section(table, "soracloud")? {
            if let Some(value) = soracloud.remove("http_witness_file") {
                config.soracloud_http_witness_file = Some(take_nonempty_path(
                    value,
                    "soracloud.http_witness_file",
                    source_path,
                )?);
            }
            reject_unknown_keys("soracloud", &soracloud)?;
        }
        Ok(config)
    }
}

/// Load an explicitly inherited configuration without reopening its provenance path or using SDK environment overrides.
pub(crate) fn load_inherited(
    fd: u32,
    source_path: &Path,
) -> Result<(iroha::config::Config, FilesystemConfig)> {
    if !source_path.is_absolute()
        || source_path.components().any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(eyre!(
            "inherited config source path must be absolute and normalized"
        ));
    }
    let bytes = read_inherited_private_file(
        fd,
        iroha_config_base::toml::MAX_TOML_SOURCE_BYTES,
        "inherited client config",
    )?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| eyre!("inherited client config is not UTF-8 TOML"))?;
    let mut table = text
        .parse::<toml::Table>()
        .map_err(|_| eyre!("inherited client config is not valid TOML"))?;
    let filesystem = FilesystemConfig::take_from(&mut table, source_path)
        .map_err(|_| eyre!("inherited client config has invalid CLI filesystem parameters"))?;
    let transaction = table.get("transaction").cloned();
    let sdk_source = zeroize::Zeroizing::new(
        toml::to_string(&table).map_err(|_| eyre!("cannot encode inherited SDK configuration"))?,
    );
    let (mut config, _) = iroha::config::Config::load_bytes_with_musubi_publication(
        source_path,
        sdk_source.as_bytes(),
    )
    .map_err(|_| eyre!("inherited client config failed strict semantic loading"))?;
    if let Some(transaction) = transaction {
        super::apply_transaction_overrides(
            &mut config,
            &toml::Value::Table(toml::Table::from_iter([(
                "transaction".to_owned(),
                transaction,
            )])),
        );
    }
    Ok((config, filesystem))
}

/// Read a bounded owner-private regular inherited descriptor without following a filesystem path.
#[cfg(unix)]
pub(crate) fn read_inherited_private_file(
    fd: u32,
    maximum: u64,
    label: &str,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    use std::os::unix::fs::{FileExt as _, MetadataExt as _};
    if !(3..=65535).contains(&fd) {
        return Err(eyre!(
            "{label} requires an inherited descriptor in 3..=65535"
        ));
    }
    let file = duplicate_inherited_descriptor(fd)?;
    let access =
        rustix::fs::fcntl_getfl(&file).map_err(|_| eyre!("cannot inspect {label} access mode"))?;
    if access & rustix::fs::OFlags::ACCMODE != rustix::fs::OFlags::RDONLY {
        return Err(eyre!("{label} descriptor must be read-only"));
    }
    let before = file
        .metadata()
        .map_err(|_| eyre!("cannot inspect {label}"))?;
    if !before.is_file()
        || before.uid() != rustix::process::geteuid().as_raw()
        || !matches!(before.mode() & 0o7777, 0o400 | 0o600)
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > maximum
    {
        return Err(eyre!(
            "{label} must be a bounded owner-private regular file"
        ));
    }
    let len =
        usize::try_from(before.len()).map_err(|_| eyre!("{label} length is not representable"))?;
    let mut bytes = zeroize::Zeroizing::new(vec![0_u8; len]);
    file.read_exact_at(&mut bytes, 0)
        .map_err(|_| eyre!("cannot read {label}"))?;
    let after = file
        .metadata()
        .map_err(|_| eyre!("cannot revalidate {label}"))?;
    let snapshot = |metadata: &std::fs::Metadata| {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.uid(),
            metadata.mode(),
            metadata.nlink(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        )
    };
    if snapshot(&before) != snapshot(&after)
        || file
            .read_at(&mut [0_u8; 1], before.len())
            .map_err(|_| eyre!("cannot verify {label} boundary"))?
            != 0
    {
        return Err(eyre!("{label} changed while loading"));
    }
    Ok(bytes)
}

/// Descriptor input is a Unix-only CLI capability.
#[cfg(not(unix))]
pub(crate) fn read_inherited_private_file(
    _: u32,
    _: u64,
    _: &str,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    Err(eyre!("inherited client inputs require Unix descriptors"))
}

/// Safely duplicate an explicitly inherited descriptor for a retained CLI input owner.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(
    unsafe_code,
    reason = "fcntl F_DUPFD_CLOEXEC validates an untrusted raw descriptor and atomically duplicates it before constructing an owned File"
)]
pub(crate) fn duplicate_inherited_descriptor(fd: u32) -> Result<std::fs::File> {
    use std::os::fd::FromRawFd as _;
    // Native ABI constants from Linux fcntl.h and the Darwin SDK sys/fcntl.h.
    #[cfg(target_os = "linux")]
    const DUPFD_CLOEXEC: std::ffi::c_int = 1030;
    #[cfg(target_os = "macos")]
    const DUPFD_CLOEXEC: std::ffi::c_int = 67;
    unsafe extern "C" {
        fn fcntl(fd: std::ffi::c_int, command: std::ffi::c_int, ...) -> std::ffi::c_int;
    }
    // SAFETY: this command consumes an integer minimum descriptor and atomically validates
    // the untrusted input. No borrowed descriptor is constructed before validation.
    let copied = unsafe {
        fcntl(
            i32::try_from(fd).map_err(|_| eyre!("invalid inherited descriptor"))?,
            DUPFD_CLOEXEC,
            3 as std::ffi::c_int,
        )
    };
    if copied < 0 {
        return Err(eyre!("cannot duplicate inherited descriptor"));
    }
    // SAFETY: success returns a new CLOEXEC descriptor owned exclusively by this call.
    let retained = unsafe { std::fs::File::from_raw_fd(copied) };
    // The launcher explicitly cleared CLOEXEC on the original to grant this process access.
    // Restore it without closing the caller's descriptor or changing its shared file offset.
    // F_GETFD=1, F_SETFD=2, and FD_CLOEXEC=1 are the native Linux and Darwin fcntl ABIs.
    // SAFETY: these commands take only the validated integer descriptor and integer flags;
    // the kernel rejects a descriptor closed concurrently without constructing a Rust borrow.
    let protected = unsafe {
        let original = i32::try_from(fd).map_err(|_| eyre!("invalid inherited descriptor"))?;
        let flags = fcntl(original, 1);
        flags >= 0 && fcntl(original, 2, flags | 1) == 0
    };
    if !protected {
        return Err(eyre!("cannot protect inherited descriptor lifetime"));
    }
    Ok(retained)
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
pub(crate) fn duplicate_inherited_descriptor(_: u32) -> Result<std::fs::File> {
    Err(eyre!(
        "inherited private inputs require a supported atomic descriptor ABI"
    ))
}

fn take_section(table: &mut toml::Table, name: &str) -> Result<Option<toml::Table>> {
    table
        .remove(name)
        .map(|value| {
            value
                .try_into()
                .map_err(|_| eyre!("`{name}` must be a TOML table"))
        })
        .transpose()
}

fn take_nonempty_path(value: toml::Value, parameter: &str, source_path: &Path) -> Result<PathBuf> {
    let raw = value
        .as_str()
        .ok_or_else(|| eyre!("`{parameter}` must be a string path"))?;
    if raw.is_empty() {
        return Err(eyre!("`{parameter}` must not be empty"));
    }
    let path = PathBuf::from(raw);
    if path.is_absolute() {
        return Ok(path);
    }
    let source_dir = source_path.parent().unwrap_or_else(|| Path::new("."));
    if source_dir.is_absolute() {
        Ok(source_dir.join(path))
    } else {
        Ok(env::current_dir()?.join(source_dir).join(path))
    }
}

fn reject_unknown_keys(section: &str, table: &toml::Table) -> Result<()> {
    if table.is_empty() {
        return Ok(());
    }
    let keys = table.keys().cloned().collect::<Vec<_>>().join(", ");
    Err(eyre!(
        "unknown `{section}` configuration parameter(s): {keys}"
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn sccp_client_configuration_retains_same_source_and_defaults() {
        let source = std::path::Path::new("/config/client.toml");
        let mut table = toml::toml! {
            [sccp]
            poll_interval_ms = 321
            journal_dir = "journal"
            [sccp.endpoints]
            bsc = ["https://bsc.example"]
        };
        let config = super::FilesystemConfig::take_from(&mut table, source).unwrap();
        assert!(
            table.contains_key("sccp"),
            "the ordinary SDK root owns the same subtree"
        );
        let sccp = config.sccp.unwrap();
        assert_eq!(sccp.poll_interval, std::time::Duration::from_millis(321));
        assert_eq!(sccp.journal_dir, std::path::Path::new("/config/journal"));
        assert_eq!(sccp.endpoints.bsc[0].as_str(), "https://bsc.example/");
        let default = super::FilesystemConfig::take_from(&mut toml::Table::new(), source).unwrap();
        assert_eq!(
            default.sccp.unwrap().journal_dir,
            std::path::Path::new("/config/sccp-journal")
        );
        for invalid in [
            "poll_interval_ms = 0",
            "attestation_timeout_ms = 1",
            "[endpoints]\nbsc = [\"http://rpc.example\"]",
        ] {
            let mut table = toml::Table::from_iter([(
                "sccp".into(),
                toml::Value::Table(invalid.parse().unwrap()),
            )]);
            assert!(
                super::FilesystemConfig::take_from(&mut table, source).is_err(),
                "{invalid}"
            );
        }
    }
    use super::*;

    #[cfg(unix)]
    #[test]
    fn inherited_config_loads_exact_descriptor_without_reopening_provenance() {
        use std::os::{fd::AsRawFd as _, unix::fs::PermissionsExt as _};
        let file = tempfile::NamedTempFile::new().expect("private config fixture");
        std::fs::write(
            file.path(),
            format!(
                "{}\n[connect]\nqueue_root = \"queue-state\"\n",
                include_str!("../../../defaults/client.toml")
            ),
        )
        .expect("write public config fixture");
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600))
            .expect("private fixture");
        let retained = std::fs::File::open(file.path()).expect("read-only config descriptor");
        let provenance = file
            .path()
            .parent()
            .expect("fixture parent")
            .join("does-not-exist/client.toml");
        assert!(!provenance.exists());
        let (config, filesystem) = load_inherited(
            u32::try_from(retained.as_raw_fd()).expect("descriptor"),
            &provenance,
        )
        .expect("load retained descriptor on native host");
        assert_eq!(config.torii_api_url.as_str(), "http://127.0.0.1:8080/");
        assert_eq!(
            filesystem.connect_queue_root,
            provenance
                .parent()
                .expect("provenance parent")
                .join("queue-state")
        );
        assert!(
            !provenance.exists(),
            "loader never creates or reopens provenance path"
        );
    }

    #[cfg(unix)]
    #[test]
    fn inherited_private_descriptor_rejects_writable_unsafe_and_nonregular_inputs() {
        use std::io::{Seek as _, SeekFrom};
        use std::os::{fd::AsRawFd as _, unix::fs::PermissionsExt as _};
        let file = tempfile::NamedTempFile::new().expect("private fixture");
        std::fs::write(file.path(), b"fixture").expect("write fixture");
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600))
            .expect("private fixture");
        let writable = u32::try_from(file.as_file().as_raw_fd()).expect("writable descriptor");
        assert!(
            read_inherited_private_file(writable, 64, "test config")
                .expect_err("read-write descriptor rejected")
                .to_string()
                .contains("read-only")
        );
        let mut retained = std::fs::File::open(file.path()).expect("read-only descriptor");
        retained.seek(SeekFrom::Start(2)).expect("caller offset");
        rustix::io::fcntl_setfd(&retained, rustix::io::FdFlags::empty())
            .expect("simulate inherited descriptor");
        let fd = u32::try_from(retained.as_raw_fd()).expect("read-only fd");
        assert_eq!(
            read_inherited_private_file(fd, 64, "test config")
                .expect("positive native FD")
                .as_slice(),
            b"fixture"
        );
        assert_eq!(
            retained.stream_position().expect("preserved caller offset"),
            2
        );
        assert!(
            rustix::io::fcntl_getfd(&retained)
                .expect("original descriptor remains open")
                .contains(rustix::io::FdFlags::CLOEXEC)
        );
        assert!(read_inherited_private_file(fd, 3, "test config").is_err());
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o644))
            .expect("unsafe fixture");
        assert!(read_inherited_private_file(fd, 64, "test config").is_err());
        let directory = std::fs::File::open(file.path().parent().expect("parent"))
            .expect("directory descriptor");
        assert!(
            read_inherited_private_file(
                u32::try_from(directory.as_raw_fd()).expect("fd"),
                64,
                "test config"
            )
            .is_err()
        );
        for invalid in [0, 1, 2, 65536, u32::MAX] {
            assert!(read_inherited_private_file(invalid, 64, "test config").is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn inherited_private_descriptor_rejects_pipe_socket_and_closed_fd() {
        use std::os::fd::AsRawFd as _;
        let (socket, _) = std::os::unix::net::UnixStream::pair().expect("socket fixture");
        assert!(
            read_inherited_private_file(
                u32::try_from(socket.as_raw_fd()).expect("socket fd"),
                64,
                "test input"
            )
            .is_err()
        );
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("pipe fixture");
        let stdout = child.stdout.take().expect("pipe descriptor");
        assert!(
            read_inherited_private_file(
                u32::try_from(stdout.as_raw_fd()).expect("pipe fd"),
                64,
                "test input"
            )
            .is_err()
        );
        child.wait().expect("fixture child reaped");
        // Reserve a high descriptor before closing it so unrelated low-FD test activity cannot reuse it.
        let file = std::fs::File::open("/dev/null").expect("closed-FD fixture");
        let limit = rustix::process::getrlimit(rustix::process::Resource::Nofile)
            .current
            .unwrap_or(65_536)
            .min(65_536);
        let high = i32::try_from(limit.saturating_sub(1)).expect("bounded fixture limit");
        assert!(high >= 3, "test process must permit inherited descriptors");
        let closed = rustix::io::fcntl_dupfd_cloexec(&file, high)
            .expect("reserve high fixture fd within the host limit");
        let number = u32::try_from(closed.as_raw_fd()).expect("high fixture fd");
        drop(closed);
        assert!(read_inherited_private_file(number, 64, "test input").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn inherited_config_errors_never_include_source_values() {
        use std::os::{fd::AsRawFd as _, unix::fs::PermissionsExt as _};
        let file = tempfile::NamedTempFile::new().expect("private fixture");
        std::fs::write(
            file.path(),
            b"private_key = \"unclosed-runtime-secret-fixture",
        )
        .expect("write malformed fixture");
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600))
            .expect("private fixture");
        let retained = std::fs::File::open(file.path()).expect("read-only descriptor");
        let error = load_inherited(
            u32::try_from(retained.as_raw_fd()).expect("fd"),
            Path::new("/private/inherited/client.toml"),
        )
        .expect_err("invalid TOML rejected");
        assert!(!format!("{error:#}").contains("unclosed-runtime-secret-fixture"));
    }

    #[test]
    fn extracts_cli_paths_and_removes_owned_sections() {
        let mut table = toml::toml! {
            chain = "test"
            [connect]
            queue_root = "/var/lib/iroha/connect"
            [soracloud]
            http_witness_file = "/run/iroha/witness.json"
        };
        let config = FilesystemConfig::take_from(&mut table, Path::new("/etc/iroha/client.toml"))
            .expect("valid CLI paths");
        assert_eq!(
            config.connect_queue_root,
            PathBuf::from("/var/lib/iroha/connect")
        );
        assert_eq!(
            config.soracloud_http_witness_file,
            Some(PathBuf::from("/run/iroha/witness.json"))
        );
        assert!(!table.contains_key("connect"));
        assert!(!table.contains_key("soracloud"));
        assert!(table.contains_key("chain"));
    }

    #[test]
    fn rejects_unknown_cli_keys() {
        let mut table = toml::toml! {
            [connect]
            root = "/retired/alias"
        };
        let error = FilesystemConfig::take_from(&mut table, Path::new("/etc/iroha/client.toml"))
            .expect_err("retired CLI aliases must fail closed");
        assert!(error.to_string().contains("unknown `connect`"));
    }

    #[test]
    fn rejects_invalid_cli_paths_and_unknown_keys() {
        let cases = [
            ("[connect]\nqueue_root = \"\"", "must not be empty"),
            ("[connect]\nqueue_root = 7", "must be a string path"),
            ("[soracloud]\nhttp_witness_file = \"\"", "must not be empty"),
            (
                "[soracloud]\nhttp_witness_file = 7",
                "must be a string path",
            ),
            (
                "[soracloud]\nwitness_file = \"retired\"",
                "unknown `soracloud`",
            ),
        ];
        for (source, expected) in cases {
            let mut table = source.parse::<toml::Table>().expect("test TOML");
            let error =
                FilesystemConfig::take_from(&mut table, Path::new("/etc/iroha/client.toml"))
                    .expect_err("invalid CLI filesystem configuration must fail closed");
            assert!(
                error.to_string().contains(expected),
                "expected `{expected}` in `{error}`"
            );
        }
    }

    #[test]
    fn resolves_relative_paths_from_the_toml_source_directory() {
        let mut table = toml::toml! {
            [connect]
            queue_root = "state/connect"
            [soracloud]
            http_witness_file = "auth/witness.norito"
        };
        let config =
            FilesystemConfig::take_from(&mut table, Path::new("/etc/iroha/profiles/operator.toml"))
                .expect("relative CLI paths");
        assert_eq!(
            config.connect_queue_root,
            PathBuf::from("/etc/iroha/profiles/state/connect")
        );
        assert_eq!(
            config.soracloud_http_witness_file,
            Some(PathBuf::from("/etc/iroha/profiles/auth/witness.norito"))
        );
    }
}
