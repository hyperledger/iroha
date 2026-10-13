//! Offline minting, inspection, and revocation tooling for SoraNet admission tokens.
use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};
use norito::json::{self, Value};
use rand::{RngCore, SeedableRng, rng, rngs::StdRng};
use soranet_pq::MlDsaSuite;
use soranet_relay::token_tool::{
    MintRequest, REVOCATION_LIST_MAX_ENTRIES_V1, RevocationList, TokenBundle, encode_token_base64,
    encode_token_hex, inspect_token, mint_token, parse_hex_array, parse_hex_bytes, parse_rfc3339,
    read_revocation_file,
};
use std::{
    fmt,
    fs::{self, File, Metadata as FsMetadata, OpenOptions},
    io::{self, Read as _, Write as _},
    path::{Path, PathBuf},
    process,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
const DEFAULT_TTL_SECS: u64 = 900;
// AdmissionToken v1 encodes a 4-byte magic, fixed body fields, and a u16
// signature length before the signature. This admits every structurally
// representable v1 token while rejecting file-backed data above 65,671 bytes.
const ADMISSION_TOKEN_V1_FIXED_FRAME_BYTES: usize = 4 + 1 + 1 + 8 + 8 + 32 + 32 + 16 + 32 + 2;
const ADMISSION_TOKEN_V1_MAX_FILE_BYTES: usize =
    ADMISSION_TOKEN_V1_FIXED_FRAME_BYTES + u16::MAX as usize;
// ML-DSA-87 is the largest suite supported by this CLI. Keep these literals
// source-coupled to `MlDsaSuite` with the boundary test below so backend width
// changes cannot silently widen file-backed inputs.
const ML_DSA_MAX_PUBLIC_KEY_BYTES_V1: usize = 2_592;
const ML_DSA_MAX_SECRET_KEY_BYTES_V1: usize = 4_896;
const ML_DSA_MAX_PUBLIC_KEY_HEX_BYTES_V1: usize = ML_DSA_MAX_PUBLIC_KEY_BYTES_V1 * 2;
const ML_DSA_MAX_SECRET_KEY_HEX_BYTES_V1: usize = ML_DSA_MAX_SECRET_KEY_BYTES_V1 * 2;
// Key files are single-value operator artifacts. This corridor preserves trim
// semantics for CRLF and modest editor padding without permitting whitespace
// to amplify the exact ML-DSA payload ceiling.
const ML_DSA_KEY_FILE_MAX_SURROUNDING_WHITESPACE_BYTES_V1: usize = 256;
const REVOCATION_LIST_CANONICAL_ENTRY_BYTES: usize = 70;
const REVOCATION_LIST_MAX_CANONICAL_BYTES_V1: usize =
    REVOCATION_LIST_MAX_ENTRIES_V1 * REVOCATION_LIST_CANONICAL_ENTRY_BYTES + 3;
struct SecretBytes(Vec<u8>);
impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted secret bytes>")
    }
}
impl SecretBytes {
    fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    fn as_slice(&self) -> &[u8] {
        &self.0
    }
    fn len(&self) -> usize {
        self.0.len()
    }
    fn clear(&mut self) {
        self.0.resize(self.0.capacity(), 0);
        zeroize::Zeroize::zeroize(self.0.as_mut_slice());
        self.0.clear();
    }
    fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}
impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.clear();
    }
}
#[cfg(any(target_os = "macos", target_os = "ios"))]
const TOKEN_FILE_O_NOFOLLOW_FLAG: i32 = 0x0000_0100;
#[cfg(any(target_os = "linux", target_os = "android"))]
const TOKEN_FILE_O_NOFOLLOW_FLAG: i32 = 0x0002_0000;
#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
const TOKEN_FILE_O_NOFOLLOW_FLAG: i32 = 0x0000_0100;
#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))
))]
compile_error!("SoraNet admission-token file loading requires a defined no-follow flag");
#[cfg(unix)]
type TokenFileIdentity = (u64, u64);
#[cfg(windows)]
type TokenFileIdentity = (Option<u32>, Option<u64>);
#[cfg(not(any(unix, windows)))]
type TokenFileIdentity = ();
#[cfg(unix)]
fn token_file_identity(metadata: &FsMetadata) -> TokenFileIdentity {
    use std::os::unix::fs::MetadataExt as _;
    (metadata.dev(), metadata.ino())
}
#[cfg(windows)]
fn token_file_identity(metadata: &FsMetadata) -> TokenFileIdentity {
    use std::os::windows::fs::MetadataExt as _;
    (metadata.volume_serial_number(), metadata.file_index())
}
#[cfg(not(any(unix, windows)))]
fn token_file_identity(_metadata: &FsMetadata) -> TokenFileIdentity {}
#[cfg(unix)]
const fn token_file_identity_available(_identity: TokenFileIdentity) -> bool {
    true
}
#[cfg(windows)]
const fn token_file_identity_available(identity: TokenFileIdentity) -> bool {
    identity.0.is_some() && identity.1.is_some()
}
#[cfg(not(any(unix, windows)))]
const fn token_file_identity_available(_identity: TokenFileIdentity) -> bool {
    false
}
#[cfg(windows)]
fn token_file_is_reparse_point(metadata: &FsMetadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}
#[cfg(not(windows))]
fn token_file_is_reparse_point(_metadata: &FsMetadata) -> bool {
    false
}
fn validate_token_file_metadata(
    metadata: &FsMetadata,
    artifact: &str,
    expected_private_owner: Option<u32>,
) -> io::Result<()> {
    if metadata.file_type().is_symlink()
        || token_file_is_reparse_point(metadata)
        || !metadata.file_type().is_file()
        || !token_file_identity_available(token_file_identity(metadata))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{artifact} must be a direct regular file with a stable identity"),
        ));
    }
    #[cfg(unix)]
    if let Some(expected_owner) = expected_private_owner {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.uid() != expected_owner || metadata.mode() & 0o077 != 0 || metadata.nlink() != 1
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{artifact} must be owned by the current user, owner-private, and have exactly one link"
                ),
            ));
        }
    }
    Ok(())
}
#[cfg(unix)]
fn current_process_owner_uid() -> io::Result<u32> {
    use std::os::unix::fs::MetadataExt as _;
    Ok(tempfile::tempfile()?.metadata()?.uid())
}
#[cfg(unix)]
fn open_token_file_direct(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(TOKEN_FILE_O_NOFOLLOW_FLAG);
    options.open(path)
}
#[cfg(windows)]
fn open_token_file_direct(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt as _;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    options.open(path)
}
#[cfg(not(any(unix, windows)))]
fn open_token_file_direct(_path: &Path) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "stable direct-file opens are unavailable on this platform",
    ))
}
#[cfg(unix)]
fn token_file_metadata_unchanged(left: &FsMetadata, right: &FsMetadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    token_file_identity(left) == token_file_identity(right)
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
        && left.mode() == right.mode()
}
#[cfg(windows)]
fn token_file_metadata_unchanged(left: &FsMetadata, right: &FsMetadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    token_file_identity_available(token_file_identity(left))
        && token_file_identity(left) == token_file_identity(right)
        && left.file_size() == right.file_size()
        && left.last_write_time() == right.last_write_time()
        && left.creation_time() == right.creation_time()
        && left.file_attributes() == right.file_attributes()
}
#[cfg(not(any(unix, windows)))]
fn token_file_metadata_unchanged(_left: &FsMetadata, _right: &FsMetadata) -> bool {
    false
}
#[cfg(test)]
static TOKEN_FILE_READ_REPLACEMENT: std::sync::Mutex<Option<(PathBuf, PathBuf)>> =
    std::sync::Mutex::new(None);
#[cfg(test)]
fn replace_token_file_for_test(path: &Path) -> io::Result<()> {
    let replacement = {
        let mut hook = TOKEN_FILE_READ_REPLACEMENT
            .lock()
            .expect("token file race hook lock");
        if hook.as_ref().is_some_and(|(expected, _)| expected == path) {
            hook.take().map(|(_, replacement)| replacement)
        } else {
            None
        }
    };
    if let Some(replacement) = replacement {
        fs::rename(replacement, path)?;
    }
    Ok(())
}
/// Read one immutable, owner-private token snapshot at the complete v1 framing ceiling.
fn read_admission_token_file(path: &Path) -> io::Result<SecretBytes> {
    read_owner_private_bounded_direct_file(
        path,
        ADMISSION_TOKEN_V1_MAX_FILE_BYTES,
        "admission token",
    )
    .map(SecretBytes::new)
}
fn read_admission_token_source(path: &Path) -> io::Result<SecretBytes> {
    if path != Path::new("-") {
        return read_admission_token_file(path);
    }
    let stdin = io::stdin();
    read_bounded_secret_bytes(
        stdin.lock(),
        ADMISSION_TOKEN_V1_MAX_FILE_BYTES,
        "admission token",
    )
}
fn read_bounded_secret_bytes(
    mut reader: impl io::Read,
    maximum: usize,
    artifact: &str,
) -> io::Result<SecretBytes> {
    let read_limit = maximum.checked_add(1).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{artifact} read limit overflowed"),
        )
    })?;
    let mut bytes = SecretBytes::new(Vec::new());
    bytes
        .0
        .try_reserve_exact(read_limit)
        .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
    reader
        .by_ref()
        .take(u64::try_from(read_limit).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{artifact} read limit is not representable"),
            )
        })?)
        .read_to_end(&mut bytes.0)?;
    if bytes.len() > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{artifact} exceeds its {maximum}-byte first-release limit"),
        ));
    }
    Ok(bytes)
}
fn read_bounded_direct_file(path: &Path, maximum: usize, artifact: &str) -> io::Result<Vec<u8>> {
    read_bounded_direct_file_with_owner(path, maximum, artifact, None)
}
fn read_owner_private_bounded_direct_file(
    path: &Path,
    maximum: usize,
    artifact: &str,
) -> io::Result<Vec<u8>> {
    #[cfg(unix)]
    {
        let expected_private_owner = Some(current_process_owner_uid()?);
        read_bounded_direct_file_with_owner(path, maximum, artifact, expected_private_owner)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, maximum, artifact);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private key-file ownership checks are unavailable on this platform; use standard input",
        ))
    }
}
fn read_bounded_direct_file_with_owner(
    path: &Path,
    maximum: usize,
    artifact: &str,
    expected_private_owner: Option<u32>,
) -> io::Result<Vec<u8>> {
    let before = fs::symlink_metadata(path)?;
    validate_token_file_metadata(&before, artifact, expected_private_owner)?;
    let maximum_u64 = u64::try_from(maximum).unwrap_or(u64::MAX);
    if before.len() > maximum_u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{artifact} is {} bytes; first-release limit is {maximum} bytes",
                before.len()
            ),
        ));
    }
    #[cfg(test)]
    replace_token_file_for_test(path)?;
    let mut file = open_token_file_direct(path)?;
    let opened = file.metadata()?;
    validate_token_file_metadata(&opened, artifact, expected_private_owner)?;
    if !token_file_metadata_unchanged(&before, &opened) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{artifact} changed between inspection and open"),
        ));
    }
    let expected_len = usize::try_from(opened.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{artifact} length is not representable on this host"),
        )
    })?;
    let mut bytes = SecretBytes::new(Vec::new());
    bytes
        .0
        .try_reserve_exact(expected_len)
        .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
    bytes.0.resize(expected_len, 0);
    file.read_exact(&mut bytes.0).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{artifact} changed length while being read"),
            )
        } else {
            error
        }
    })?;
    let mut growth_probe = SecretBytes::new(vec![0_u8; 1]);
    if file.read(&mut growth_probe.0)? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{artifact} grew while being read or exceeds its {maximum}-byte limit"),
        ));
    }
    let after_file = file.metadata()?;
    let after_path = fs::symlink_metadata(path)?;
    validate_token_file_metadata(&after_file, artifact, expected_private_owner)?;
    validate_token_file_metadata(&after_path, artifact, expected_private_owner)?;
    if !token_file_metadata_unchanged(&opened, &after_file)
        || !token_file_metadata_unchanged(&opened, &after_path)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{artifact} changed while being read"),
        ));
    }
    Ok(bytes.into_vec())
}
#[derive(Parser, Debug)]
#[command(
    name = "soranet-admission-token",
    version,
    about = "Mint, inspect, and manage SoraNet admission tokens"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand, Debug)]
enum Command {
    /// Mint a new admission token signed with an ML-DSA issuer key.
    Mint(MintArgs),
    /// Decode an admission token and print its metadata.
    Inspect(InspectArgs),
    /// Append a token identifier to a Norito JSON revocation list.
    Revoke(RevokeArgs),
    /// Print all token identifiers present in a revocation list.
    ListRevocations(ListArgs),
}
#[derive(Args, Debug)]
struct MintArgs {
    #[arg(long, conflicts_with = "issuer_public_file")]
    issuer_public_hex: Option<String>,
    #[arg(long)]
    issuer_public_file: Option<PathBuf>,
    /// Owner-private hexadecimal issuer-secret file. Use `-` to read standard input.
    #[arg(long)]
    issuer_secret_file: PathBuf,
    #[arg(long)]
    relay_id_hex: String,
    #[arg(long)]
    transcript_hash_hex: String,
    #[arg(long)]
    issued_at: Option<String>,
    #[arg(long, conflicts_with = "ttl_secs")]
    expires_at: Option<String>,
    #[arg(long, conflicts_with = "expires_at")]
    ttl_secs: Option<u64>,
    #[arg(long, default_value_t = 0)]
    flags: u8,
    #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
    format: OutputFormat,
    #[arg(long)]
    output: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = SuiteArg::MlDsa44)]
    suite: SuiteArg,
}
#[derive(Args, Debug)]
struct InspectArgs {
    /// Owner-private binary admission-token file. Use `-` for standard input.
    #[arg(long)]
    input: PathBuf,
}
#[derive(Args, Debug)]
#[command(group(
    ArgGroup::new("revoke_source")
        .required(true)
        .args(&["token_file", "token_id_hex"])
))]
struct RevokeArgs {
    #[arg(long)]
    list: PathBuf,
    /// Owner-private binary admission-token file. Use `-` for standard input.
    #[arg(long)]
    token_file: Option<PathBuf>,
    #[arg(long)]
    token_id_hex: Option<String>,
    #[arg(long)]
    dry_run: bool,
}
#[derive(Args, Debug)]
struct ListArgs {
    #[arg(long)]
    list: PathBuf,
}
#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Json,
    Base64,
    Hex,
}
#[derive(Clone, Copy, Debug, ValueEnum)]
enum SuiteArg {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}
impl From<SuiteArg> for MlDsaSuite {
    fn from(value: SuiteArg) -> Self {
        match value {
            SuiteArg::MlDsa44 => MlDsaSuite::MlDsa44,
            SuiteArg::MlDsa65 => MlDsaSuite::MlDsa65,
            SuiteArg::MlDsa87 => MlDsaSuite::MlDsa87,
        }
    }
}
fn main() {
    if let Err(err) = run() {
        eprintln!("soranet-admission-token: {err}");
        process::exit(1);
    }
}
fn run() -> Result<(), String> {
    let cli = Cli::parse();
    match cli.command {
        Command::Mint(args) => command_mint(args),
        Command::Inspect(args) => command_inspect(args),
        Command::Revoke(args) => command_revoke(args),
        Command::ListRevocations(args) => command_list(args),
    }
}
fn whole_unix_second(time: SystemTime) -> Result<SystemTime, String> {
    let elapsed = time
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("system clock is before the Unix epoch: {err}"))?;
    UNIX_EPOCH
        .checked_add(Duration::from_secs(elapsed.as_secs()))
        .ok_or_else(|| "whole-second token timestamp overflowed SystemTime".to_owned())
}
fn command_mint(args: MintArgs) -> Result<(), String> {
    let issuer_public =
        load_public_hex_source(args.issuer_public_hex, args.issuer_public_file.as_deref())?;
    let relay_id =
        parse_hex_array::<32>(&args.relay_id_hex, "relay_id_hex").map_err(|err| err.to_string())?;
    let transcript_hash = parse_hex_array::<32>(&args.transcript_hash_hex, "transcript_hash_hex")
        .map_err(|err| err.to_string())?;
    let issued_at = match args.issued_at {
        Some(ref value) => parse_rfc3339(value, "issued_at").map_err(|err| err.to_string())?,
        None => whole_unix_second(SystemTime::now())?,
    };
    let expires_at = if let Some(ref value) = args.expires_at {
        parse_rfc3339(value, "expires_at").map_err(|err| err.to_string())?
    } else {
        let ttl = args.ttl_secs.unwrap_or(DEFAULT_TTL_SECS);
        issued_at
            .checked_add(Duration::from_secs(ttl))
            .ok_or_else(|| "expiry timestamp overflowed SystemTime".to_owned())?
    };
    let suite: MlDsaSuite = args.suite.into();
    let issuer_secret = load_secret_hex_source(&args.issuer_secret_file)?;
    let request = MintRequest {
        suite,
        issuer_public_key: &issuer_public,
        issuer_secret_key: issuer_secret.as_slice(),
        relay_id,
        transcript_hash,
        issued_at,
        expires_at,
        flags: args.flags,
    };
    let mut seed = [0u8; 32];
    rng().fill_bytes(&mut seed);
    let mut rng = StdRng::from_seed(seed);
    zeroize::Zeroize::zeroize(&mut seed);
    let bundle = mint_token(&request, &mut rng).map_err(|err| err.to_string())?;
    let output = render_bundle(&bundle, args.format)?;
    write_secret_output(args.output.as_deref(), output.as_slice())
}
fn command_inspect(args: InspectArgs) -> Result<(), String> {
    let bytes = read_admission_token_source(&args.input).map_err(|err| err.to_string())?;
    let bundle = inspect_token(bytes.as_slice()).map_err(|err| err.to_string())?;
    let output = render_token_metadata(&bundle)?;
    write_public_output(&output)
}
fn command_revoke(args: RevokeArgs) -> Result<(), String> {
    let token_id = if let Some(hex) = args.token_id_hex {
        parse_hex_array::<32>(&hex, "token_id_hex").map_err(|err| err.to_string())?
    } else {
        let bytes = if let Some(path) = args.token_file {
            read_admission_token_source(&path).map_err(|err| err.to_string())?
        } else {
            unreachable!("clap enforces revoke source group");
        };
        let bundle = inspect_token(bytes.as_slice()).map_err(|err| err.to_string())?;
        bundle.metadata.token_id
    };
    let inserted = if args.dry_run {
        let mut list = RevocationList::load_or_default(&args.list)
            .map_err(|err| format!("failed to load {}: {err}", args.list.display()))?;
        list.insert(token_id)
            .map_err(|err| format!("failed to preview revocation: {err}"))?
    } else {
        RevocationList::insert_durable(&args.list, token_id).map_err(|err| {
            format!(
                "failed to persist revocation to {}: {err}",
                args.list.display()
            )
        })?
    };
    let mut payload = json::Map::new();
    payload.insert("token_id_hex".into(), Value::from(hex::encode(token_id)));
    payload.insert("inserted".into(), Value::from(inserted));
    payload.insert("dry_run".into(), Value::from(args.dry_run));
    payload.insert(
        "revocation_list_path".into(),
        Value::from(args.list.display().to_string()),
    );
    let mut text = json::to_string_pretty(&Value::Object(payload))
        .map_err(|err| format!("failed to serialise revoke output: {err}"))?;
    text.push('\n');
    write_public_output(&text)
}
fn command_list(args: ListArgs) -> Result<(), String> {
    let ids = read_revocation_file(&args.list)
        .map_err(|err| format!("failed to load {}: {err}", args.list.display()))?;
    let stdout = io::stdout();
    let mut output = stdout.lock();
    write_revocation_list_json(&mut output, &ids)
        .map_err(|err| format!("failed to write revocation list: {err}"))
}
fn write_revocation_list_json<W: io::Write>(writer: &mut W, ids: &[[u8; 32]]) -> io::Result<()> {
    if ids.len() > REVOCATION_LIST_MAX_ENTRIES_V1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "revocation list contains {} entries; first-release limit is {REVOCATION_LIST_MAX_ENTRIES_V1}",
                ids.len()
            ),
        ));
    }
    let expected_len = if ids.is_empty() {
        3
    } else {
        ids.len()
            .checked_mul(REVOCATION_LIST_CANONICAL_ENTRY_BYTES)
            .and_then(|length| length.checked_add(3))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "revocation-list output length overflowed",
                )
            })?
    };
    if expected_len > REVOCATION_LIST_MAX_CANONICAL_BYTES_V1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "revocation-list output exceeds its first-release byte limit",
        ));
    }
    if ids.is_empty() {
        writer.write_all(b"[]\n")?;
        return writer.flush();
    }
    // This fixed hexadecimal schema matches Norito's pretty JSON layout while
    // retaining only one 64-byte stack encoding at a time.
    writer.write_all(b"[")?;
    for (index, id) in ids.iter().enumerate() {
        if index != 0 {
            writer.write_all(b",")?;
        }
        writer.write_all(b"\n  \"")?;
        writer.write_all(&token_id_hex_bytes(id))?;
        writer.write_all(b"\"")?;
    }
    writer.write_all(b"\n]\n")?;
    writer.flush()
}
fn token_id_hex_bytes(id: &[u8; 32]) -> [u8; 64] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = [0_u8; 64];
    for (index, byte) in id.iter().copied().enumerate() {
        encoded[index * 2] = HEX[usize::from(byte >> 4)];
        encoded[index * 2 + 1] = HEX[usize::from(byte & 0x0f)];
    }
    encoded
}
fn render_bundle(bundle: &TokenBundle, format: OutputFormat) -> Result<SecretBytes, String> {
    let text = match format {
        OutputFormat::Json => {
            let mut text = json::to_string_pretty(&bundle.to_json())
                .map_err(|err| format!("failed to serialise JSON: {err}"))?;
            text.push('\n');
            text
        }
        OutputFormat::Base64 => {
            let mut text = encode_token_base64(&bundle.token);
            text.push('\n');
            text
        }
        OutputFormat::Hex => {
            let mut text = encode_token_hex(&bundle.token);
            text.push('\n');
            text
        }
    };
    Ok(SecretBytes::new(text.into_bytes()))
}
fn render_token_metadata(bundle: &TokenBundle) -> Result<String, String> {
    let issued_at = bundle
        .metadata
        .issued_at
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "token issued_at predates the Unix epoch".to_owned())?
        .as_secs();
    let expires_at = bundle
        .metadata
        .expires_at
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "token expires_at predates the Unix epoch".to_owned())?
        .as_secs();
    let mut object = json::Map::new();
    object.insert(
        "token_id_hex".into(),
        Value::from(hex::encode(bundle.metadata.token_id)),
    );
    object.insert(
        "issuer_fingerprint_hex".into(),
        Value::from(hex::encode(bundle.metadata.issuer_fingerprint)),
    );
    object.insert(
        "relay_id_hex".into(),
        Value::from(hex::encode(bundle.metadata.relay_id)),
    );
    object.insert(
        "transcript_hash_hex".into(),
        Value::from(hex::encode(bundle.metadata.transcript_hash)),
    );
    object.insert("issued_at_unix_secs".into(), Value::from(issued_at));
    object.insert("expires_at_unix_secs".into(), Value::from(expires_at));
    object.insert(
        "ttl_secs".into(),
        Value::from(bundle.metadata.ttl().as_secs()),
    );
    object.insert("flags".into(), Value::from(bundle.metadata.flags));
    object.insert(
        "signature_len".into(),
        Value::from(
            u64::try_from(bundle.metadata.signature_len)
                .map_err(|_| "token signature length is not representable".to_owned())?,
        ),
    );
    let mut output = json::to_string_pretty(&Value::Object(object))
        .map_err(|err| format!("failed to serialise token metadata: {err}"))?;
    output.push('\n');
    Ok(output)
}
fn write_secret_output(path: Option<&Path>, data: &[u8]) -> Result<(), String> {
    if let Some(path) = path {
        if let Some(dir) = path.parent()
            && !dir.as_os_str().is_empty()
        {
            fs::create_dir_all(dir)
                .map_err(|err| format!("failed to create {}: {err}", dir.display()))?;
        }
        write_owner_private_new_file(path, data)
            .map_err(|err| format!("failed to write {}: {err}", path.display()))
    } else {
        let stdout = io::stdout();
        let mut output = stdout.lock();
        output
            .write_all(data)
            .and_then(|()| output.flush())
            .map_err(|err| format!("failed to write token to standard output: {err}"))
    }
}
fn write_public_output(data: &str) -> Result<(), String> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    output
        .write_all(data.as_bytes())
        .and_then(|()| output.flush())
        .map_err(|err| format!("failed to write command output: {err}"))
}
#[cfg(unix)]
fn write_owner_private_new_file(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let owner = current_process_owner_uid()?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(TOKEN_FILE_O_NOFOLLOW_FLAG)
        .open(path)?;
    file.write_all(data)?;
    file.sync_all()?;
    let opened = file.metadata()?;
    let path_metadata = fs::symlink_metadata(path)?;
    validate_token_file_metadata(&opened, "admission-token output", Some(owner))?;
    validate_token_file_metadata(&path_metadata, "admission-token output", Some(owner))?;
    if !token_file_metadata_unchanged(&opened, &path_metadata) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "admission-token output path changed while being written",
        ));
    }
    Ok(())
}
#[cfg(not(unix))]
fn write_owner_private_new_file(_path: &Path, _data: &[u8]) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "owner-private admission-token output is unavailable on this platform; use standard output",
    ))
}
#[derive(Clone, Copy)]
struct KeyFileLimits {
    artifact: &'static str,
    maximum_hex_bytes: usize,
}
fn key_file_limits(field: &'static str) -> Result<KeyFileLimits, String> {
    match field {
        "issuer_public_key" => Ok(KeyFileLimits {
            artifact: "issuer public-key file",
            maximum_hex_bytes: ML_DSA_MAX_PUBLIC_KEY_HEX_BYTES_V1,
        }),
        "issuer_secret_key" => Ok(KeyFileLimits {
            artifact: "issuer secret-key file",
            maximum_hex_bytes: ML_DSA_MAX_SECRET_KEY_HEX_BYTES_V1,
        }),
        _ => Err(format!(
            "no bounded file profile is defined for hexadecimal field {field}"
        )),
    }
}
fn load_public_hex_key_file(path: &Path, limits: KeyFileLimits) -> Result<Vec<u8>, String> {
    let maximum_raw_bytes = limits
        .maximum_hex_bytes
        .checked_add(ML_DSA_KEY_FILE_MAX_SURROUNDING_WHITESPACE_BYTES_V1)
        .ok_or_else(|| format!("{} byte limit overflowed", limits.artifact))?;
    let bytes = read_bounded_direct_file(path, maximum_raw_bytes, limits.artifact)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    decode_hex_key_text(&bytes, "issuer_public_key", limits)
}
fn load_secret_hex_key_file(
    path: &Path,
    field: &'static str,
    limits: KeyFileLimits,
) -> Result<SecretBytes, String> {
    let maximum_raw_bytes = limits
        .maximum_hex_bytes
        .checked_add(ML_DSA_KEY_FILE_MAX_SURROUNDING_WHITESPACE_BYTES_V1)
        .ok_or_else(|| format!("{} byte limit overflowed", limits.artifact))?;
    let bytes = SecretBytes::new(
        read_owner_private_bounded_direct_file(path, maximum_raw_bytes, limits.artifact)
            .map_err(|err| format!("failed to read {}: {err}", path.display()))?,
    );
    decode_secret_hex_key_text(bytes.as_slice(), field, limits)
}
fn load_secret_hex_source(path: &Path) -> Result<SecretBytes, String> {
    let field = "issuer_secret_key";
    let limits = key_file_limits(field)?;
    if path != Path::new("-") {
        return load_secret_hex_key_file(path, field, limits);
    }
    let maximum_raw_bytes = limits
        .maximum_hex_bytes
        .checked_add(ML_DSA_KEY_FILE_MAX_SURROUNDING_WHITESPACE_BYTES_V1)
        .ok_or_else(|| format!("{} byte limit overflowed", limits.artifact))?;
    let stdin = io::stdin();
    let mut locked = stdin.lock();
    read_secret_hex_input(&mut locked, maximum_raw_bytes, field, limits)
}
fn read_secret_hex_input(
    mut reader: impl io::Read,
    maximum_raw_bytes: usize,
    field: &'static str,
    limits: KeyFileLimits,
) -> Result<SecretBytes, String> {
    let read_limit = maximum_raw_bytes
        .checked_add(1)
        .ok_or_else(|| format!("{} read limit overflowed", limits.artifact))?;
    let mut bytes = SecretBytes::new(Vec::new());
    bytes
        .0
        .try_reserve_exact(read_limit)
        .map_err(|_| format!("failed to reserve bounded {} input", limits.artifact))?;
    let mut bounded = reader.by_ref().take(
        u64::try_from(read_limit)
            .map_err(|_| format!("{} read limit is not representable", limits.artifact))?,
    );
    bounded.read_to_end(&mut bytes.0).map_err(|error| {
        format!(
            "failed to read {} from standard input: {error}",
            limits.artifact
        )
    })?;
    if bytes.0.len() > maximum_raw_bytes {
        return Err(format!(
            "{} from standard input exceeds its {maximum_raw_bytes}-byte first-release limit",
            limits.artifact
        ));
    }
    decode_secret_hex_key_text(bytes.as_slice(), field, limits)
}
fn decode_hex_key_text(
    bytes: &[u8],
    field: &'static str,
    limits: KeyFileLimits,
) -> Result<Vec<u8>, String> {
    let trimmed = validate_hex_key_text(bytes, limits)?;
    parse_hex_bytes(trimmed, field).map_err(|err| err.to_string())
}
fn decode_secret_hex_key_text(
    bytes: &[u8],
    field: &'static str,
    limits: KeyFileLimits,
) -> Result<SecretBytes, String> {
    let trimmed = validate_hex_key_text(bytes, limits)?;
    if trimmed.len() % 2 != 0 {
        return Err(format!(
            "{field} must contain an even number of hexadecimal characters"
        ));
    }
    let decoded_len = trimmed.len() / 2;
    let mut decoded = SecretBytes::new(Vec::new());
    decoded
        .0
        .try_reserve_exact(decoded_len)
        .map_err(|_| format!("failed to reserve bounded {} output", limits.artifact))?;
    decoded.0.resize(decoded_len, 0);
    hex::decode_to_slice(trimmed, &mut decoded.0)
        .map_err(|error| format!("failed to decode {field} as hexadecimal: {error}"))?;
    if decoded.len() >= 32
        && decoded
            .as_slice()
            .first()
            .is_some_and(|first| decoded.as_slice().iter().all(|byte| byte == first))
    {
        return Err(format!(
            "{field} must not be an all-zero or repeated-byte degenerate key"
        ));
    }
    Ok(decoded)
}
fn validate_hex_key_text(bytes: &[u8], limits: KeyFileLimits) -> Result<&str, String> {
    let text = std::str::from_utf8(bytes).map_err(|err| {
        format!(
            "{} must contain UTF-8 hexadecimal text: {err}",
            limits.artifact
        )
    })?;
    let trimmed = text.trim();
    let surrounding_whitespace_bytes = text.len().saturating_sub(trimmed.len());
    if surrounding_whitespace_bytes > ML_DSA_KEY_FILE_MAX_SURROUNDING_WHITESPACE_BYTES_V1 {
        return Err(format!(
            "{} contains {surrounding_whitespace_bytes} surrounding whitespace bytes; first-release limit is {ML_DSA_KEY_FILE_MAX_SURROUNDING_WHITESPACE_BYTES_V1}",
            limits.artifact
        ));
    }
    if trimmed.len() > limits.maximum_hex_bytes {
        return Err(format!(
            "{} contains {} hexadecimal bytes; supported ML-DSA limit is {}",
            limits.artifact,
            trimmed.len(),
            limits.maximum_hex_bytes
        ));
    }
    Ok(trimmed)
}
fn load_public_hex_source(inline: Option<String>, path: Option<&Path>) -> Result<Vec<u8>, String> {
    let field = "issuer_public_key";
    match (inline, path) {
        (Some(value), None) => parse_hex_bytes(value.trim(), field).map_err(|err| err.to_string()),
        (None, Some(path)) => {
            let limits = key_file_limits(field)?;
            load_public_hex_key_file(path, limits)
        }
        (Some(_), Some(_)) => {
            Err("--issuer-public-hex and --issuer-public-file are mutually exclusive".to_owned())
        }
        (None, None) => {
            Err("--issuer-public-hex or --issuer-public-file must be provided".to_owned())
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    #[cfg(unix)]
    fn make_owner_private(path: &Path) {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("make test file owner-private");
    }
    fn encoded_token_fixture() -> Vec<u8> {
        let mut token = b"SNTK".to_vec();
        token.push(1);
        token.push(0);
        token.extend_from_slice(&1_700_000_000_u64.to_be_bytes());
        token.extend_from_slice(&1_700_000_060_u64.to_be_bytes());
        token.extend_from_slice(&[0x11; 32]);
        token.extend_from_slice(&[0x22; 32]);
        token.extend_from_slice(&[0x33; 16]);
        token.extend_from_slice(&[0x44; 32]);
        token.extend_from_slice(&1_u16.to_be_bytes());
        token.push(0x55);
        token
    }
    #[derive(Default)]
    struct CountingWriter {
        bytes: usize,
    }
    impl io::Write for CountingWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.bytes = self
                .bytes
                .checked_add(buffer.len())
                .ok_or_else(|| io::Error::other("test byte count overflowed"))?;
            Ok(buffer.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn secret_bytes_debug_is_redacted_and_clear_wipes_the_full_allocation() {
        let mut allocation = Vec::with_capacity(64);
        allocation.extend_from_slice(b"issuer-secret");
        let mut secret = SecretBytes::new(allocation);
        assert_eq!(format!("{secret:?}"), "<redacted secret bytes>");

        secret.clear();
        assert!(secret.as_slice().is_empty());
        assert_eq!(secret.0.capacity(), 64);
    }
    #[test]
    fn key_file_limits_match_largest_supported_mldsa_suite() {
        let suites = [
            MlDsaSuite::MlDsa44,
            MlDsaSuite::MlDsa65,
            MlDsaSuite::MlDsa87,
        ];
        assert_eq!(
            suites.iter().copied().map(MlDsaSuite::public_key_len).max(),
            Some(ML_DSA_MAX_PUBLIC_KEY_BYTES_V1)
        );
        assert_eq!(
            suites.iter().copied().map(MlDsaSuite::secret_key_len).max(),
            Some(ML_DSA_MAX_SECRET_KEY_BYTES_V1)
        );
    }
    #[test]
    fn key_files_accept_exact_payload_and_whitespace_limits() {
        let dir = tempdir().expect("tmp");
        let public_path = dir.path().join("issuer-public.hex");
        let mut public_text = "ab".repeat(ML_DSA_MAX_PUBLIC_KEY_BYTES_V1);
        public_text.push_str(&" ".repeat(ML_DSA_KEY_FILE_MAX_SURROUNDING_WHITESPACE_BYTES_V1));
        assert_eq!(
            public_text.len(),
            ML_DSA_MAX_PUBLIC_KEY_HEX_BYTES_V1
                + ML_DSA_KEY_FILE_MAX_SURROUNDING_WHITESPACE_BYTES_V1
        );
        fs::write(&public_path, public_text).expect("write exact public key file");
        assert_eq!(
            load_public_hex_source(None, Some(&public_path))
                .expect("exact public key file must load"),
            vec![0xab; ML_DSA_MAX_PUBLIC_KEY_BYTES_V1]
        );
        #[cfg(unix)]
        {
            let secret_path = dir.path().join("issuer-secret.hex");
            let mut expected_secret = vec![0xcd; ML_DSA_MAX_SECRET_KEY_BYTES_V1];
            expected_secret[0] = 0xce;
            fs::write(&secret_path, hex::encode(&expected_secret))
                .expect("write exact secret key file");
            make_owner_private(&secret_path);
            let secret =
                load_secret_hex_source(&secret_path).expect("exact secret key file must load");
            assert_eq!(secret.as_slice(), expected_secret);
        }
    }
    #[test]
    fn key_files_reject_payload_and_whitespace_plus_one() {
        let dir = tempdir().expect("tmp");
        let oversized_payload = dir.path().join("oversized-payload.hex");
        fs::write(
            &oversized_payload,
            "ab".repeat(ML_DSA_MAX_PUBLIC_KEY_BYTES_V1 + 1),
        )
        .expect("write oversized payload");
        let error = load_public_hex_source(None, Some(&oversized_payload))
            .expect_err("decoded key limit + 1 must fail");
        assert!(error.contains("supported ML-DSA limit"), "{error}");
        #[cfg(unix)]
        {
            let oversized_whitespace = dir.path().join("oversized-whitespace.hex");
            let mut text = "cd".repeat(ML_DSA_MAX_SECRET_KEY_BYTES_V1);
            text.push_str(&" ".repeat(ML_DSA_KEY_FILE_MAX_SURROUNDING_WHITESPACE_BYTES_V1 + 1));
            fs::write(&oversized_whitespace, text).expect("write oversized whitespace");
            make_owner_private(&oversized_whitespace);
            let error = load_secret_hex_source(&oversized_whitespace)
                .expect_err("raw key file limit + 1 must fail");
            assert!(error.contains("first-release limit"), "{error}");
        }
        let excessive_padding = dir.path().join("excessive-padding.hex");
        let mut text = "ef".repeat(MlDsaSuite::MlDsa44.public_key_len());
        text.push_str(&" ".repeat(ML_DSA_KEY_FILE_MAX_SURROUNDING_WHITESPACE_BYTES_V1 + 1));
        fs::write(&excessive_padding, text).expect("write excessive padding");
        let error = load_public_hex_source(None, Some(&excessive_padding))
            .expect_err("surrounding whitespace limit + 1 must fail");
        assert!(error.contains("surrounding whitespace bytes"), "{error}");
    }
    #[cfg(unix)]
    #[test]
    fn key_file_reader_rejects_symlink() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().expect("tmp");
        let target = dir.path().join("issuer-public.hex");
        let link = dir.path().join("issuer-public-link.hex");
        fs::write(&target, "ab".repeat(ML_DSA_MAX_PUBLIC_KEY_BYTES_V1))
            .expect("write public key target");
        symlink(&target, &link).expect("create key symlink");
        let error = load_public_hex_source(None, Some(&link)).expect_err("key symlink must fail");
        assert!(error.contains("direct regular file"), "{error}");
    }
    #[cfg(unix)]
    #[test]
    fn secret_key_file_requires_private_mode_and_single_link() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempdir().expect("tmp");
        let path = dir.path().join("issuer-secret.hex");
        fs::write(&path, b"ab").expect("write secret key");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("make secret-key fixture non-private");
        let error = load_secret_hex_source(&path).expect_err("public mode must fail");
        assert!(error.contains("owner-private"), "{error}");

        make_owner_private(&path);
        let secret = load_secret_hex_source(&path).expect("private secret key must load");
        assert_eq!(secret.as_slice(), [0xab]);

        let second_link = dir.path().join("issuer-secret-copy.hex");
        fs::hard_link(&path, &second_link).expect("create secret-key hard link");
        let error = load_secret_hex_source(&path).expect_err("hard-linked secret must fail");
        assert!(error.contains("exactly one link"), "{error}");
    }
    #[test]
    fn secret_standard_input_is_bounded_and_decoded() {
        let field = "issuer_secret_key";
        let limits = key_file_limits(field).expect("secret limits");
        let maximum =
            limits.maximum_hex_bytes + ML_DSA_KEY_FILE_MAX_SURROUNDING_WHITESPACE_BYTES_V1;
        let secret = read_secret_hex_input(io::Cursor::new(b"ab\n"), maximum, field, limits)
            .expect("bounded secret input must decode");
        assert_eq!(secret.as_slice(), [0xab]);
        let error = read_secret_hex_input(io::Cursor::new("00".repeat(32)), maximum, field, limits)
            .expect_err("degenerate secret input must fail");
        assert!(error.contains("degenerate key"), "{error}");
        let oversized = vec![b' '; maximum + 1];
        let error = read_secret_hex_input(io::Cursor::new(oversized), maximum, field, limits)
            .expect_err("standard input above its corridor must fail");
        assert!(error.contains("first-release limit"), "{error}");
    }
    #[test]
    fn mint_cli_rejects_inline_issuer_secret() {
        let error = Cli::try_parse_from([
            "soranet-admission-token",
            "mint",
            "--issuer-secret-hex",
            "00",
        ])
        .expect_err("issuer secrets must not be accepted on the command line");
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
    }
    #[test]
    fn cli_rejects_bearer_tokens_in_process_arguments() {
        for args in [
            vec![
                "soranet-admission-token",
                "inspect",
                "--token",
                "secret-token",
            ],
            vec![
                "soranet-admission-token",
                "revoke",
                "--list",
                "revocations.json",
                "--token",
                "secret-token",
            ],
        ] {
            let error = Cli::try_parse_from(args)
                .expect_err("bearer tokens must not be accepted on the command line");
            assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
        }
    }
    #[test]
    fn token_standard_input_is_bounded() {
        let exact = vec![0xA5; ADMISSION_TOKEN_V1_MAX_FILE_BYTES];
        let loaded = read_bounded_secret_bytes(
            io::Cursor::new(exact),
            ADMISSION_TOKEN_V1_MAX_FILE_BYTES,
            "admission token",
        )
        .expect("exact token input limit must load");
        assert_eq!(loaded.len(), ADMISSION_TOKEN_V1_MAX_FILE_BYTES);
        let oversized = vec![0xA5; ADMISSION_TOKEN_V1_MAX_FILE_BYTES + 1];
        let error = read_bounded_secret_bytes(
            io::Cursor::new(oversized),
            ADMISSION_TOKEN_V1_MAX_FILE_BYTES,
            "admission token",
        )
        .expect_err("token input limit + 1 must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
    #[test]
    fn generated_token_time_is_canonical_whole_second() {
        let source = UNIX_EPOCH + Duration::from_secs(1_700_000_000) + Duration::from_nanos(999);
        let canonical = whole_unix_second(source).expect("canonical time");
        assert_eq!(
            canonical.duration_since(UNIX_EPOCH).expect("Unix time"),
            Duration::from_secs(1_700_000_000)
        );
    }
    #[test]
    fn inspect_metadata_omits_bearer_token_encodings() {
        let encoded = encoded_token_fixture();
        let bundle = inspect_token(&encoded).expect("inspect fixture token");
        let output = render_token_metadata(&bundle).expect("render metadata");
        assert!(output.contains("token_id_hex"));
        assert!(!output.contains("token_base64"));
        assert!(!output.contains("token_hex"));
        assert!(!output.contains(&hex::encode(encoded)));
    }
    #[cfg(unix)]
    #[test]
    fn token_file_limit_accepts_exact_and_rejects_plus_one() {
        assert_eq!(ADMISSION_TOKEN_V1_MAX_FILE_BYTES, 65_671);
        let dir = tempdir().expect("tmp");
        let exact = dir.path().join("exact.token");
        let exact_file = File::create(&exact).expect("create exact token file");
        exact_file
            .set_len(
                u64::try_from(ADMISSION_TOKEN_V1_MAX_FILE_BYTES)
                    .expect("fixed token limit fits u64"),
            )
            .expect("size exact token file");
        #[cfg(unix)]
        make_owner_private(&exact);
        assert_eq!(
            read_admission_token_file(&exact)
                .expect("exact token file limit must load")
                .len(),
            ADMISSION_TOKEN_V1_MAX_FILE_BYTES
        );
        let plus_one = dir.path().join("plus-one.token");
        let oversized_file = File::create(&plus_one).expect("create oversized token file");
        oversized_file
            .set_len(
                u64::try_from(ADMISSION_TOKEN_V1_MAX_FILE_BYTES + 1)
                    .expect("fixed token limit + 1 fits u64"),
            )
            .expect("size oversized token file");
        #[cfg(unix)]
        make_owner_private(&plus_one);
        let error = read_admission_token_file(&plus_one).expect_err("limit + 1 must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
    #[cfg(unix)]
    #[test]
    fn token_file_reader_rejects_symlink() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().expect("tmp");
        let target = dir.path().join("target.token");
        let link = dir.path().join("link.token");
        fs::write(&target, b"token").expect("write target");
        symlink(&target, &link).expect("create symlink");
        let error = read_admission_token_file(&link).expect_err("symlink must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
    #[cfg(unix)]
    #[test]
    fn token_file_reader_rejects_path_replacement_race() {
        let dir = tempdir().expect("tmp");
        let configured = dir.path().join("configured.token");
        let replacement = dir.path().join("replacement.token");
        fs::write(&configured, b"token").expect("write configured token");
        fs::write(&replacement, b"token").expect("write replacement token");
        make_owner_private(&configured);
        make_owner_private(&replacement);
        *TOKEN_FILE_READ_REPLACEMENT.lock().expect("race hook lock") =
            Some((configured.clone(), replacement));
        let error = read_admission_token_file(&configured).expect_err("path replacement must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
    #[cfg(unix)]
    #[test]
    fn token_file_requires_private_mode_and_single_link() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempdir().expect("tmp");
        let path = dir.path().join("token.bin");
        fs::write(&path, encoded_token_fixture()).expect("write token");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("make token public");
        let error = read_admission_token_file(&path).expect_err("public token file must fail");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        make_owner_private(&path);
        let link = dir.path().join("token-copy.bin");
        fs::hard_link(&path, &link).expect("create token hard link");
        let error = read_admission_token_file(&path).expect_err("hard-linked token must fail");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }
    #[cfg(unix)]
    #[test]
    fn token_output_is_private_and_never_clobbers() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let dir = tempdir().expect("tmp");
        let path = dir.path().join("minted.token");
        write_owner_private_new_file(&path, b"first").expect("create private output");
        let metadata = fs::metadata(&path).expect("output metadata");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        let error = write_owner_private_new_file(&path, b"second")
            .expect_err("existing token output must not be overwritten");
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&path).expect("read output"), b"first");
    }
    #[test]
    fn revocation_output_matches_norito_pretty_layout() {
        let ids = [[0x11; 32], [0x22; 32]];
        let mut output = Vec::new();
        write_revocation_list_json(&mut output, &ids).expect("write revocation output");
        assert_eq!(
            output,
            format!(
                "[\n  \"{}\",\n  \"{}\"\n]\n",
                hex::encode(ids[0]),
                hex::encode(ids[1])
            )
            .into_bytes()
        );
    }
    #[test]
    fn revocation_output_accepts_exact_count_and_rejects_plus_one() {
        let exact = vec![[0x33; 32]; REVOCATION_LIST_MAX_ENTRIES_V1];
        let mut exact_writer = CountingWriter::default();
        write_revocation_list_json(&mut exact_writer, &exact)
            .expect("exact entry count must stream");
        assert_eq!(exact_writer.bytes, REVOCATION_LIST_MAX_CANONICAL_BYTES_V1);
        let plus_one = vec![[0x44; 32]; REVOCATION_LIST_MAX_ENTRIES_V1 + 1];
        let mut rejected_writer = CountingWriter::default();
        let error = write_revocation_list_json(&mut rejected_writer, &plus_one)
            .expect_err("entry count + 1 must fail before output");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(rejected_writer.bytes, 0);
    }
}
