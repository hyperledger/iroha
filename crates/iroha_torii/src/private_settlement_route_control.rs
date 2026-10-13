//! Feature-isolated post-authentication route control for private-settlement tests.
//!
//! The production/default Torii feature graph does not compile this module. The
//! dedicated test-network daemon reads an owner-only command from the same
//! per-peer directory as consensus message control. A matching request is
//! admitted only after normal Torii authentication and semantic validation,
//! then either passes, is rejected as a controlled loss, or is durably
//! acknowledged and held until an explicit healing command arrives.

#[cfg(not(unix))]
compile_error!("private-settlement route control requires Unix file ownership semantics");

use iroha_crypto::Hash;
use norito::json::{Map, Value};
use sha2::{Digest as _, Sha256};
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
    time::Duration,
};

pub const COMMAND_FILE: &str = "private-settlement-route-command.norito.json";
pub const ACK_FILE: &str = "private-settlement-route-ack.norito.json";
const CONTROL_DIR_ENV: &str = "IROHA_TEST_PRIVATE_SETTLEMENT_ROUTE_CONTROL_DIR";
const FORMAT_VERSION: u64 = 1;
const MAX_CONTROL_BYTES: usize = 256 * 1024;
const MAX_REQUEST_DIGESTS: usize = 16_384;
const HOLD_POLL: Duration = Duration::from_millis(20);

/// Authenticated private-settlement HTTP phase controlled by the test daemon.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Restricted provisional upload and availability-share persistence.
    RestrictedDa,
    /// Prepare vote and Prepare-certificate persistence.
    Prepare,
    /// Commit vote and Commit-certificate persistence.
    Commit,
}

impl Phase {
    const fn as_str(self) -> &'static str {
        match self {
            Self::RestrictedDa => "restricted_da",
            Self::Prepare => "prepare",
            Self::Commit => "commit",
        }
    }

    fn parse(value: &str) -> Result<Self, ControlError> {
        match value {
            "restricted_da" => Ok(Self::RestrictedDa),
            "prepare" => Ok(Self::Prepare),
            "commit" => Ok(Self::Commit),
            _ => Err(ControlError::InvalidCommand("phase")),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Loss,
    Hold,
    Pass,
}

impl Action {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Loss => "loss",
            Self::Hold => "hold",
            Self::Pass => "pass",
        }
    }

    fn parse(value: &str) -> Result<Self, ControlError> {
        match value {
            "loss" => Ok(Self::Loss),
            "hold" => Ok(Self::Hold),
            "pass" => Ok(Self::Pass),
            _ => Err(ControlError::InvalidCommand("action")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Command {
    revision: u64,
    phase: Phase,
    action: Action,
    bundle_id: [u8; 32],
    seed: u64,
    drop_first: u64,
    match_limit: u64,
    sha256: String,
}

#[derive(Default)]
struct State {
    command_sha256: String,
    predecessor_command_sha256: Option<String>,
    revision: u64,
    matched: u64,
    passed: u64,
    dropped: u64,
    held: u64,
    released: u64,
    request_digests: Vec<String>,
}

impl State {
    fn select(&mut self, command: &Command) -> Result<(), ControlError> {
        if self.command_sha256 == command.sha256 {
            return Ok(());
        }
        if command.revision <= self.revision {
            return Err(ControlError::StaleRevision);
        }
        *self = Self {
            command_sha256: command.sha256.clone(),
            revision: command.revision,
            ..Self::default()
        };
        Ok(())
    }

    fn record_request(&mut self, digest: String) -> Result<u64, ControlError> {
        if self.request_digests.len() >= MAX_REQUEST_DIGESTS {
            return Err(ControlError::EvidenceCapacity);
        }
        self.matched = self
            .matched
            .checked_add(1)
            .ok_or(ControlError::EvidenceCapacity)?;
        self.request_digests.push(digest);
        Ok(self.matched)
    }

    fn select_healing(
        &mut self,
        held_command: &Command,
        pass_command: &Command,
    ) -> Result<(), ControlError> {
        let prior_matched = self.matched;
        let prior_held = self.held;
        let prior_request_digests = self.request_digests.clone();
        self.select(pass_command)?;
        self.predecessor_command_sha256 = Some(held_command.sha256.clone());
        self.matched = prior_matched;
        self.held = prior_held;
        self.request_digests = prior_request_digests;
        self.released = self
            .released
            .checked_add(1)
            .ok_or(ControlError::EvidenceCapacity)?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum ControlError {
    UnsafeRoot,
    RootChanged,
    Io(std::io::Error),
    InvalidCommand(
        #[cfg_attr(
            not(test),
            expect(
                dead_code,
                reason = "names the rejected command field for test assertions"
            )
        )]
        &'static str,
    ),
    NonCanonicalCommand,
    StaleRevision,
    EvidenceCapacity,
    SupersededHold,
}

impl From<std::io::Error> for ControlError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Route outcome after authenticated test control is evaluated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// Continue into the production handler.
    Pass,
    /// Return a redacted controlled-loss response without mutating state.
    Drop,
}

struct Controller {
    root: PathBuf,
    root_device: u64,
    root_inode: u64,
    root_owner: u32,
    state: Mutex<State>,
}

static CONTROLLER: OnceLock<Result<Option<Controller>, ControlError>> = OnceLock::new();

fn controller() -> Result<Option<&'static Controller>, &'static ControlError> {
    match CONTROLLER.get_or_init(Controller::from_env) {
        Ok(Some(controller)) => Ok(Some(controller)),
        Ok(None) => Ok(None),
        Err(error) => Err(error),
    }
}

impl Controller {
    fn from_env() -> Result<Option<Self>, ControlError> {
        let Some(raw) = env::var_os(CONTROL_DIR_ENV) else {
            return Ok(None);
        };
        let root = PathBuf::from(raw);
        if !root.is_absolute() || root.canonicalize().map_err(ControlError::Io)? != root {
            return Err(ControlError::UnsafeRoot);
        }
        let metadata = validate_root(&root)?;
        Ok(Some(Self {
            root,
            root_device: metadata.dev(),
            root_inode: metadata.ino(),
            root_owner: metadata.uid(),
            state: Mutex::new(State::default()),
        }))
    }

    fn validate_root_identity(&self) -> Result<(), ControlError> {
        let metadata = validate_root(&self.root)?;
        if metadata.dev() != self.root_device
            || metadata.ino() != self.root_inode
            || metadata.uid() != self.root_owner
        {
            return Err(ControlError::RootChanged);
        }
        Ok(())
    }

    fn read_command(&self) -> Result<Option<Command>, ControlError> {
        self.validate_root_identity()?;
        let bytes = match read_bounded_regular_file(
            &self.root.join(COMMAND_FILE),
            MAX_CONTROL_BYTES,
            self.root_owner,
        ) {
            Ok(bytes) => bytes,
            Err(ControlError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        self.validate_root_identity()?;
        parse_command(&bytes).map(Some)
    }

    fn publish_ack(&self, command: &Command) -> Result<(), ControlError> {
        self.validate_root_identity()?;
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let command_digest_matches = state.command_sha256 == command.sha256;
        if !command_digest_matches || state.revision != command.revision {
            return Err(ControlError::StaleRevision);
        }
        let value = object_value([
            ("action", Value::from(command.action.as_str())),
            ("bundle_id", Value::from(hex::encode(command.bundle_id))),
            ("command_sha256", Value::from(command.sha256.clone())),
            ("dropped", Value::from(state.dropped)),
            ("format_version", Value::from(FORMAT_VERSION)),
            ("held", Value::from(state.held)),
            ("matched", Value::from(state.matched)),
            ("passed", Value::from(state.passed)),
            ("phase", Value::from(command.phase.as_str())),
            (
                "predecessor_command_sha256",
                state
                    .predecessor_command_sha256
                    .clone()
                    .map_or(Value::Null, Value::from),
            ),
            ("released", Value::from(state.released)),
            (
                "request_digests",
                Value::Array(
                    state
                        .request_digests
                        .iter()
                        .cloned()
                        .map(Value::from)
                        .collect(),
                ),
            ),
            ("revision", Value::from(command.revision)),
            ("seed", Value::from(command.seed)),
        ]);
        drop(state);
        let bytes = canonical_json(&value)?;
        write_atomic_private_file(&self.root, ACK_FILE, &bytes, self.root_owner)?;
        self.validate_root_identity()?;
        let readback = read_bounded_regular_file(
            &self.root.join(ACK_FILE),
            MAX_CONTROL_BYTES,
            self.root_owner,
        )?;
        if readback != bytes {
            return Err(ControlError::Io(std::io::Error::other(
                "route-control acknowledgement readback differs",
            )));
        }
        Ok(())
    }

    async fn admit(
        &self,
        phase: Phase,
        bundle_id: [u8; 32],
        request_digest: String,
    ) -> Result<Disposition, ControlError> {
        let Some(command) = self.read_command()? else {
            return Ok(Disposition::Pass);
        };
        if command.phase != phase || command.bundle_id != bundle_id {
            return Ok(Disposition::Pass);
        }
        let occurrence = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.select(&command)?;
            state.record_request(request_digest)?
        };
        match command.action {
            Action::Pass => {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state.passed = state.passed.saturating_add(1);
                drop(state);
                self.publish_ack(&command)?;
                Ok(Disposition::Pass)
            }
            Action::Loss => {
                let drop = occurrence <= command.match_limit && occurrence <= command.drop_first;
                {
                    let mut state = self
                        .state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if drop {
                        state.dropped = state.dropped.saturating_add(1);
                    } else {
                        state.passed = state.passed.saturating_add(1);
                    }
                }
                self.publish_ack(&command)?;
                Ok(if drop {
                    Disposition::Drop
                } else {
                    Disposition::Pass
                })
            }
            Action::Hold => {
                {
                    let mut state = self
                        .state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    state.held = state.held.saturating_add(1);
                }
                self.publish_ack(&command)?;
                loop {
                    tokio::time::sleep(HOLD_POLL).await;
                    let Some(next) = self.read_command()? else {
                        continue;
                    };
                    if next.sha256 == command.sha256 {
                        continue;
                    }
                    if next.revision <= command.revision
                        || next.phase != phase
                        || next.bundle_id != bundle_id
                        || next.action != Action::Pass
                    {
                        return Err(ControlError::SupersededHold);
                    }
                    {
                        let mut state = self
                            .state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        state.select_healing(&command, &next)?;
                    }
                    self.publish_ack(&next)?;
                    return Ok(Disposition::Pass);
                }
            }
        }
    }
}

/// Evaluate one request after its ordinary Torii authentication and validation.
pub async fn admit(
    phase: Phase,
    bundle_id: Hash,
    request_bytes: &[u8],
    authenticated_identity: &[u8],
) -> Result<Disposition, &'static str> {
    let Some(controller) = controller().map_err(|_| "private_settlement_control_invalid")? else {
        return Ok(Disposition::Pass);
    };
    let mut digest = Sha256::new();
    digest.update(b"iroha:aps-route-control:request:v1\0");
    digest.update(phase.as_str().as_bytes());
    digest.update(bundle_id.as_ref());
    digest.update(authenticated_identity);
    digest.update(request_bytes);
    controller
        .admit(phase, *bundle_id.as_ref(), hex::encode(digest.finalize()))
        .await
        .map_err(|_| "private_settlement_control_invalid")
}

fn validate_root(root: &Path) -> Result<fs::Metadata, ControlError> {
    let metadata = fs::symlink_metadata(root).map_err(ControlError::Io)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o777 != 0o700
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(ControlError::UnsafeRoot);
    }
    Ok(metadata)
}

fn read_bounded_regular_file(
    path: &Path,
    maximum: usize,
    owner: u32,
) -> Result<Vec<u8>, ControlError> {
    let before = fs::symlink_metadata(path).map_err(ControlError::Io)?;
    if !before.file_type().is_file()
        || before.file_type().is_symlink()
        || before.uid() != owner
        || before.permissions().mode() & 0o777 != 0o600
        || usize::try_from(before.len())
            .ok()
            .is_none_or(|len| len > maximum)
    {
        return Err(ControlError::UnsafeRoot);
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options.open(path).map_err(ControlError::Io)?;
    let opened = file.metadata().map_err(ControlError::Io)?;
    if opened.dev() != before.dev() || opened.ino() != before.ino() {
        return Err(ControlError::RootChanged);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(opened.len()).unwrap_or(maximum));
    Read::take(
        &mut file,
        u64::try_from(maximum + 1).expect("small route-control bound fits u64"),
    )
    .read_to_end(&mut bytes)
    .map_err(ControlError::Io)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(ControlError::InvalidCommand("size"));
    }
    let after = file.metadata().map_err(ControlError::Io)?;
    if after.dev() != opened.dev()
        || after.ino() != opened.ino()
        || after.len() != opened.len()
        || after.mtime_nsec() != opened.mtime_nsec()
        || after.mtime() != opened.mtime()
    {
        return Err(ControlError::RootChanged);
    }
    Ok(bytes)
}

fn write_atomic_private_file(
    root: &Path,
    name: &str,
    bytes: &[u8],
    owner: u32,
) -> Result<(), ControlError> {
    let suffix = format!("{}-{}", std::process::id(), thread_sequence());
    let temporary = root.join(format!(".{name}.tmp-{suffix}"));
    let target = root.join(name);
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options.open(&temporary).map_err(ControlError::Io)?;
    file.write_all(bytes).map_err(ControlError::Io)?;
    file.sync_all().map_err(ControlError::Io)?;
    let metadata = file.metadata().map_err(ControlError::Io)?;
    if metadata.uid() != owner || !metadata.file_type().is_file() {
        return Err(ControlError::UnsafeRoot);
    }
    drop(file);
    fs::rename(&temporary, &target).map_err(ControlError::Io)?;
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(ControlError::Io)?;
    Ok(())
}

fn thread_sequence() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    SEQUENCE.fetch_add(1, Ordering::Relaxed)
}

fn parse_command(bytes: &[u8]) -> Result<Command, ControlError> {
    if bytes.is_empty() || bytes.len() > MAX_CONTROL_BYTES {
        return Err(ControlError::InvalidCommand("size"));
    }
    let value: Value =
        norito::json::from_slice(bytes).map_err(|_| ControlError::InvalidCommand("json"))?;
    if canonical_json(&value)? != bytes {
        return Err(ControlError::NonCanonicalCommand);
    }
    let object = exact_object(
        &value,
        &[
            "action",
            "bundle_id",
            "drop_first",
            "format_version",
            "match_limit",
            "phase",
            "revision",
            "seed",
        ],
    )?;
    if object.get("format_version").and_then(Value::as_u64) != Some(FORMAT_VERSION) {
        return Err(ControlError::InvalidCommand("format_version"));
    }
    let revision = positive_u64(object, "revision")?;
    let phase = Phase::parse(required_str(object, "phase")?)?;
    let action = Action::parse(required_str(object, "action")?)?;
    let seed = object
        .get("seed")
        .and_then(Value::as_u64)
        .ok_or(ControlError::InvalidCommand("seed"))?;
    let drop_first = object
        .get("drop_first")
        .and_then(Value::as_u64)
        .ok_or(ControlError::InvalidCommand("drop_first"))?;
    let match_limit = object
        .get("match_limit")
        .and_then(Value::as_u64)
        .ok_or(ControlError::InvalidCommand("match_limit"))?;
    if match_limit > 10_000 || drop_first > match_limit {
        return Err(ControlError::InvalidCommand("loss_bounds"));
    }
    match action {
        Action::Loss if match_limit > 0 => {}
        Action::Hold if drop_first == 0 && match_limit == 1 => {}
        Action::Pass if drop_first == 0 && match_limit == 0 => {}
        _ => return Err(ControlError::InvalidCommand("action_bounds")),
    }
    let bundle_id = decode_lower_hex_32(required_str(object, "bundle_id")?)
        .ok_or(ControlError::InvalidCommand("bundle_id"))?;
    Ok(Command {
        revision,
        phase,
        action,
        bundle_id,
        seed,
        drop_first,
        match_limit,
        sha256: hex::encode(Sha256::digest(bytes)),
    })
}

fn canonical_json(value: &Value) -> Result<Vec<u8>, ControlError> {
    norito::json::to_json(value)
        .map(String::into_bytes)
        .map_err(|_| ControlError::InvalidCommand("json"))
}

fn object_value<const N: usize>(fields: [(&str, Value); N]) -> Value {
    let mut object = Map::new();
    for (name, value) in fields {
        object.insert(name.to_owned(), value);
    }
    Value::Object(object)
}

fn exact_object<'a>(value: &'a Value, fields: &[&str]) -> Result<&'a Map, ControlError> {
    let object = value
        .as_object()
        .ok_or(ControlError::InvalidCommand("object"))?;
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return Err(ControlError::InvalidCommand("fields"));
    }
    Ok(object)
}

fn required_str<'a>(object: &'a Map, field: &'static str) -> Result<&'a str, ControlError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or(ControlError::InvalidCommand(field))
}

fn positive_u64(object: &Map, field: &'static str) -> Result<u64, ControlError> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .ok_or(ControlError::InvalidCommand(field))
}

fn decode_lower_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    hex::decode(value).ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(action: &str, drop_first: u64, match_limit: u64) -> Vec<u8> {
        canonical_json(&object_value([
            ("action", Value::from(action)),
            ("bundle_id", Value::from("11".repeat(32))),
            ("drop_first", Value::from(drop_first)),
            ("format_version", Value::from(FORMAT_VERSION)),
            ("match_limit", Value::from(match_limit)),
            ("phase", Value::from("restricted_da")),
            ("revision", Value::from(1_u64)),
            ("seed", Value::from(7_u64)),
        ]))
        .expect("encode command")
    }

    fn parsed_command(action: &str, drop_first: u64, match_limit: u64, revision: u64) -> Command {
        let mut value: Value = norito::json::from_slice(&command(action, drop_first, match_limit))
            .expect("decode command fixture");
        value
            .as_object_mut()
            .expect("command object")
            .insert("revision".to_owned(), Value::from(revision));
        parse_command(&canonical_json(&value).expect("encode command fixture"))
            .expect("parse command fixture")
    }

    #[test]
    fn command_parser_binds_exact_loss_budget() {
        let parsed = parse_command(&command("loss", 5, 25)).expect("parse loss command");
        assert_eq!(parsed.revision, 1);
        assert_eq!(parsed.phase, Phase::RestrictedDa);
        assert_eq!(parsed.action, Action::Loss);
        assert_eq!(parsed.drop_first, 5);
        assert_eq!(parsed.match_limit, 25);
        assert_ne!(parsed.sha256, "0".repeat(64));
    }

    #[test]
    fn command_parser_rejects_noncanonical_or_fail_open_shapes() {
        let mut trailing = command("hold", 0, 1);
        trailing.push(b'\n');
        assert!(matches!(
            parse_command(&trailing),
            Err(ControlError::NonCanonicalCommand)
        ));
        assert!(matches!(
            parse_command(&command("loss", 26, 25)),
            Err(ControlError::InvalidCommand("loss_bounds"))
        ));
        assert!(matches!(
            parse_command(&command("pass", 0, 1)),
            Err(ControlError::InvalidCommand("action_bounds"))
        ));
    }

    #[test]
    fn healing_state_retains_all_held_request_evidence() {
        let hold = parsed_command("hold", 0, 1, 1);
        let pass = parsed_command("pass", 0, 0, 2);
        let mut state = State::default();
        state.select(&hold).expect("select hold command");
        state
            .record_request("2".repeat(64))
            .expect("record first hold");
        state
            .record_request("3".repeat(64))
            .expect("record second hold");
        state.held = 2;
        state
            .select_healing(&hold, &pass)
            .expect("release first hold");
        state
            .select_healing(&hold, &pass)
            .expect("release second hold");
        assert_eq!(state.command_sha256, pass.sha256);
        assert_eq!(state.predecessor_command_sha256, Some(hold.sha256));
        assert_eq!(state.matched, 2);
        assert_eq!(state.held, 2);
        assert_eq!(state.released, 2);
        assert_eq!(state.request_digests, ["2".repeat(64), "3".repeat(64)]);
    }

    #[test]
    fn controller_admit_future_is_send() {
        fn assert_send<T: Send>(_: T) {}

        assert_send(admit(
            Phase::Prepare,
            Hash::new(b"send-future-regression"),
            b"request",
            b"authenticated-identity",
        ));
    }
}
