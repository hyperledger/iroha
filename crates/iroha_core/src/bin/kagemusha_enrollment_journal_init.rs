//! Explicit offline initialization of one fresh KAGEMUSHA issuer journal.
//!
//! Requires an existing owner-private parent and independently selected public deployment scope.
//! No node config, signing key, token, network connection or platform evidence is read. Existing
//! or partially initialized children refuse; failures retain all originals without repair.
use iroha_core::kagemusha_wallet_v1::{
    enrollment_issuer::enrollment_issuer_journal_scope_v1, enrollment_journal::EnrollmentJournalV1,
};
use iroha_fs::PrivateDirectory;
use std::{ffi::OsString, path::PathBuf, process::ExitCode};

const HELP: &str = "kagemusha_enrollment_journal_init --parent ABSOLUTE_PRIVATE_DIR --name NEW_CHILD --scope-hex HEX64\n\nOffline provisioning only. The scope is public configuration DATA and must equal torii.kagemusha_enrollment.scope_hex. The parent must already exist and be owner-private. The child must not exist. No reset, overwrite, repair, signing, eligibility or device admission is performed. On any failure, preserve the child and investigate; never remove it to retry.";

#[derive(Debug, PartialEq, Eq)]
struct Options {
    parent: PathBuf,
    name: String,
    scope: [u8; 32],
}
#[derive(Debug, PartialEq, Eq)]
enum Command {
    Help,
    Initialize(Options),
}
#[derive(Debug, PartialEq, Eq)]
enum Failure {
    Arguments,
    Parent,
    Name,
    Scope,
    ParentCustody,
    Initialization,
    Verification,
}
impl Failure {
    fn message(&self) -> &'static str {
        match self {
            Self::Arguments => "exactly --parent, --name and --scope-hex are required; use --help",
            Self::Parent => "parent must be an absolute canonical POSIX path without traversal",
            Self::Name => {
                "name must be one 1..64-byte lowercase alphanumeric/underscore/hyphen component, starting alphanumeric"
            }
            Self::Scope => "scope must be exactly 64 lowercase hex characters and nonzero",
            Self::ParentCustody => {
                "existing parent custody refused; no child initialization was attempted"
            }
            Self::Initialization => {
                "journal initialization refused or uncertain; preserve every existing or partial child and do not retry by deleting it"
            }
            Self::Verification => {
                "initialized journal custody verification failed; retain the child and investigate without reset"
            }
        }
    }
}
fn scope(text: &str) -> Result<[u8; 32], Failure> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Failure::Scope);
    }
    let mut result = [0; 32];
    hex::decode_to_slice(text, &mut result).map_err(|_| Failure::Scope)?;
    if result == [0; 32] {
        return Err(Failure::Scope);
    }
    Ok(result)
}
fn parse(arguments: Vec<OsString>) -> Result<Command, Failure> {
    if arguments.len() == 1 && arguments[0] == "--help" {
        return Ok(Command::Help);
    }
    if arguments.len() != 6 {
        return Err(Failure::Arguments);
    }
    let (mut parent, mut name, mut selected_scope) = (None, None, None);
    for pair in arguments.chunks_exact(2) {
        match pair[0].to_str() {
            Some("--parent") if parent.is_none() => parent = Some(pair[1].clone()),
            Some("--name") if name.is_none() => name = Some(pair[1].clone()),
            Some("--scope-hex") if selected_scope.is_none() => {
                selected_scope = Some(pair[1].clone());
            }
            _ => return Err(Failure::Arguments),
        }
    }
    let parent = parent.ok_or(Failure::Arguments)?;
    let text = parent.to_str().ok_or(Failure::Parent)?;
    if !text.starts_with('/')
        || text.split('/').skip(1).any(|component| {
            component.is_empty()
                || component == "."
                || component == ".."
                || component.chars().any(char::is_control)
        })
    {
        return Err(Failure::Parent);
    }
    let name = name.ok_or(Failure::Arguments)?;
    let name = name.to_str().ok_or(Failure::Name)?;
    let allowed = |byte: u8| byte.is_ascii_digit() || byte.is_ascii_lowercase();
    if name.is_empty()
        || name.len() > 64
        || !allowed(name.as_bytes()[0])
        || !name
            .bytes()
            .all(|byte| allowed(byte) || b"_-".contains(&byte))
    {
        return Err(Failure::Name);
    }
    let selected_scope = selected_scope.ok_or(Failure::Arguments)?;
    let selected_scope = scope(selected_scope.to_str().ok_or(Failure::Scope)?)?;
    Ok(Command::Initialize(Options {
        parent: PathBuf::from(parent),
        name: name.to_owned(),
        scope: selected_scope,
    }))
}
fn initialize(options: &Options) -> Result<(), Failure> {
    // This native scope API is the same one serving startup uses. A public scope does not
    // grant permission, select a signer, or establish the provider's eligibility decision.
    let scope = enrollment_issuer_journal_scope_v1(options.scope).map_err(|_| Failure::Scope)?;
    let parent = PrivateDirectory::open(&options.parent).map_err(|_| Failure::ParentCustody)?;
    let journal = EnrollmentJournalV1::initialize(&parent, &options.name, &scope)
        .map_err(|_| Failure::Initialization)?;
    parent.revalidate().map_err(|_| Failure::Verification)?;
    drop(journal);
    // Reopen through the exact serving reader after releasing our initialization lock.
    // If another owner takes it or readback fails, preserve state and report uncertainty.
    let journal = EnrollmentJournalV1::open(&options.parent.join(&options.name), &scope)
        .map_err(|_| Failure::Verification)?;
    parent.revalidate().map_err(|_| Failure::Verification)?;
    drop(journal);
    Ok(())
}
fn main() -> ExitCode {
    let result = match parse(std::env::args_os().skip(1).collect()) {
        Ok(Command::Help) => {
            println!("{HELP}");
            return ExitCode::SUCCESS;
        }
        Ok(Command::Initialize(options)) => initialize(&options),
        Err(error) => Err(error),
    };
    match result {
        Ok(()) => {
            println!(
                "Fresh KAGEMUSHA issuer journal initialized and reopened; no enrollment authority or qualification is established."
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            // Closed diagnostics never interpolate caller inputs, paths, config or secrets.
            eprintln!("{}", error.message());
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(parent: &str, name: &str, scope: &str) -> Vec<OsString> {
        ["--parent", parent, "--name", name, "--scope-hex", scope]
            .into_iter()
            .map(OsString::from)
            .collect()
    }
    #[test]
    fn explicit_arguments_reject_defaults_duplicates_and_traversal() {
        let pin = "1a".repeat(32);
        assert_eq!(parse(vec!["--help".into()]), Ok(Command::Help));
        assert_eq!(parse(vec![]), Err(Failure::Arguments));
        assert!(matches!(
            parse(arguments("/private/root", "issuer-1", &pin)),
            Ok(Command::Initialize(_))
        ));
        let mut duplicate = arguments("/private/root", "issuer", &pin);
        duplicate[2] = "--parent".into();
        assert_eq!(parse(duplicate), Err(Failure::Arguments));
        for path in [
            "relative",
            "/",
            "/private/../root",
            "/private/./root",
            "/private//root",
            "/private/root/",
        ] {
            assert_eq!(parse(arguments(path, "issuer", &pin)), Err(Failure::Parent));
        }
        for name in [
            "",
            ".",
            "..",
            "issuer/other",
            "../issuer",
            "-issuer",
            "ISSUER",
        ] {
            assert_eq!(
                parse(arguments("/private/root", name, &pin)),
                Err(Failure::Name)
            );
        }
    }
    #[test]
    fn selected_scope_rejects_zero_uppercase_nonhex_and_wrong_length() {
        for value in [
            String::new(),
            "00".repeat(32),
            "AB".repeat(32),
            "gg".repeat(32),
            "a".repeat(63),
            "a".repeat(65),
        ] {
            assert_eq!(scope(&value), Err(Failure::Scope));
        }
        assert_eq!(scope(&"01".repeat(32)), Ok([1; 32]));
    }
    #[cfg(unix)]
    fn private_parent() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt as _;
        let parent = tempfile::tempdir().expect("temporary parent");
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private parent");
        parent
    }
    #[cfg(unix)]
    #[test]
    fn native_initialization_reopens_exact_scope_and_never_replaces_existing_bytes() {
        let parent = private_parent();
        let options = Options {
            parent: parent.path().canonicalize().unwrap(),
            name: "issuer".into(),
            scope: [7; 32],
        };
        initialize(&options).unwrap();
        let path = options.parent.join(&options.name);
        let before = std::fs::read(path.join("scope.norito")).unwrap();
        assert_eq!(initialize(&options), Err(Failure::Initialization));
        assert_eq!(std::fs::read(path.join("scope.norito")).unwrap(), before);
        let wrong_scope = enrollment_issuer_journal_scope_v1([8; 32]).unwrap();
        assert!(EnrollmentJournalV1::open(&path, &wrong_scope).is_err());
        let owner = EnrollmentJournalV1::open(
            &path,
            &enrollment_issuer_journal_scope_v1(options.scope).unwrap(),
        )
        .unwrap();
        assert!(
            EnrollmentJournalV1::open(
                &path,
                &enrollment_issuer_journal_scope_v1(options.scope).unwrap()
            )
            .is_err()
        );
        drop(owner);
    }
    #[cfg(unix)]
    #[test]
    fn missing_unsafe_linked_and_partial_custody_is_preserved_without_repair() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let parent = private_parent();
        let canonical = parent.path().canonicalize().unwrap();
        let mut options = Options {
            parent: canonical.join("missing"),
            name: "issuer".into(),
            scope: [9; 32],
        };
        assert_eq!(initialize(&options), Err(Failure::ParentCustody));
        assert!(!options.parent.exists());
        let unsafe_parent = canonical.join("unsafe");
        std::fs::create_dir(&unsafe_parent).unwrap();
        std::fs::set_permissions(&unsafe_parent, std::fs::Permissions::from_mode(0o755)).unwrap();
        options.parent = unsafe_parent;
        assert_eq!(initialize(&options), Err(Failure::ParentCustody));
        assert!(!options.parent.join("issuer").exists());
        let alias = canonical.join("alias");
        symlink(&canonical, &alias).unwrap();
        options.parent = alias;
        assert_eq!(initialize(&options), Err(Failure::ParentCustody));
        options.parent = canonical;
        let held = PrivateDirectory::open(&options.parent).unwrap();
        let partial = held.create_child("issuer").unwrap();
        partial
            .write_atomic("partial", b"retained", iroha_fs::PublishMode::CreateNew)
            .unwrap();
        drop(partial);
        assert_eq!(initialize(&options), Err(Failure::Initialization));
        assert_eq!(
            std::fs::read(options.parent.join("issuer/partial")).unwrap(),
            b"retained"
        );
        assert!(!options.parent.join("issuer/scope.norito").exists());
    }
}
