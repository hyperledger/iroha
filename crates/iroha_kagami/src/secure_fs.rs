//! Owner-only filesystem primitives for private Kagami artifacts.
#[cfg(any(
    not(unix),
    target_os = "espidf",
    target_os = "horizon",
    target_os = "redox"
))]
use color_eyre::eyre::{Result, eyre};
#[cfg(any(
    not(unix),
    target_os = "espidf",
    target_os = "horizon",
    target_os = "redox"
))]
use std::path::Path;
#[cfg(all(test, unix))]
/// Creates a named pipe for Unix special-file regression tests.
#[allow(
    unsafe_code,
    reason = "POSIX mkfifo requires FFI; this test-only wrapper validates the C path"
)]
pub fn create_fifo_for_test(path: &std::path::Path, mode: libc::mode_t) -> std::io::Result<()> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt as _};

    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "FIFO path contains an interior NUL",
        )
    })?;
    // SAFETY: `path` is a live, NUL-terminated C string and `mode` is passed
    // directly using the platform's `mode_t` type.
    if unsafe { libc::mkfifo(path.as_ptr(), mode) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}
#[cfg(all(
    unix,
    not(any(target_os = "espidf", target_os = "horizon", target_os = "redox"))
))]
mod unix {
    use color_eyre::eyre::{Result, WrapErr as _, eyre};
    use rand::{TryRngCore as _, rngs::OsRng};
    use rustix::fs::{
        AtFlags, Dir, FileType as RustixFileType, Mode, OFlags, fchmod, open, openat, statat,
    };
    use std::{
        collections::BTreeSet,
        ffi::{OsStr, OsString},
        fs::{self, DirBuilder, File, OpenOptions},
        io::{Read, Write},
        os::unix::ffi::OsStrExt as _,
        os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _},
        path::{Component, Path, PathBuf},
    };
    use zeroize::Zeroize as _;
    const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
    const PRIVATE_FILE_MODE: u32 = 0o600;
    const PRIVATE_EXECUTABLE_FILE_MODE: u32 = 0o700;
    const MAX_PRIVATE_FILE_BYTES: u64 = 1024 * 1024;
    const MAX_PRIVATE_ROOT_COMPONENTS: usize = 64;
    const MAX_PRIVATE_TREE_DEPTH: usize = 64;
    const MAX_PRIVATE_TREE_ENTRIES: usize = 16_384;
    #[cfg(test)]
    static PRIVATE_TREE_ENTRY_REPLACEMENT: std::sync::Mutex<Option<(PathBuf, PathBuf)>> =
        std::sync::Mutex::new(None);
    #[cfg(test)]
    static PRIVATE_TREE_ANCESTOR_REPLACEMENT: std::sync::Mutex<
        Option<(PathBuf, PathBuf, PathBuf)>,
    > = std::sync::Mutex::new(None);
    fn absolute(path: &Path) -> Result<PathBuf> {
        if path.is_absolute() {
            Ok(path.to_path_buf())
        } else {
            Ok(std::env::current_dir()
                .wrap_err("resolve current directory")?
                .join(path))
        }
    }
    fn reject_symlink_components(path: &Path) -> Result<()> {
        let mut current = absolute(path)?;
        loop {
            match fs::symlink_metadata(&current) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(eyre!(
                        "private path contains a symbolic link: {}",
                        current.display()
                    ));
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).wrap_err_with(|| {
                        format!("inspect private path component {}", current.display())
                    });
                }
            }
            let Some(parent) = current.parent() else {
                break;
            };
            if parent == current {
                break;
            }
            current = parent.to_path_buf();
        }
        Ok(())
    }
    fn current_uid() -> u32 {
        rustix::process::geteuid().as_raw()
    }
    fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
        left.dev() == right.dev()
            && left.ino() == right.ino()
            && left.mode() == right.mode()
            && left.uid() == right.uid()
            && left.gid() == right.gid()
            && left.nlink() == right.nlink()
            && left.size() == right.size()
            && left.mtime() == right.mtime()
            && left.mtime_nsec() == right.mtime_nsec()
            && left.ctime() == right.ctime()
            && left.ctime_nsec() == right.ctime_nsec()
    }
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct PrivateFileIdentity {
        device: u64,
        inode: u64,
    }
    fn stat_identifier<T>(value: T, field: &str) -> Result<u64>
    where
        u64: TryFrom<T>,
    {
        u64::try_from(value)
            .map_err(|_| eyre!("kernel stat {field} identifier cannot be represented as u64"))
    }
    impl PrivateFileIdentity {
        fn from_metadata(metadata: &fs::Metadata) -> Self {
            Self {
                device: metadata.dev(),
                inode: metadata.ino(),
            }
        }
        fn from_stat(stat: &rustix::fs::Stat) -> Result<Self> {
            Ok(Self {
                device: stat_identifier(stat.st_dev, "device")?,
                inode: stat_identifier(stat.st_ino, "inode")?,
            })
        }
    }
    struct PrivateDirectoryLink {
        parent: File,
        name: OsString,
        child_identity: PrivateFileIdentity,
    }
    struct OpenPrivateTreeRoot {
        root: File,
        root_before: fs::Metadata,
        ancestry: Vec<PrivateDirectoryLink>,
    }
    impl OpenPrivateTreeRoot {
        fn verify_ancestry(&self, path: &Path) -> Result<()> {
            for link in &self.ancestry {
                let observed = statat(&link.parent, &link.name, AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(std::io::Error::from)
                    .wrap_err_with(|| {
                        format!("reinspect private path ancestry for {}", path.display())
                    })?;
                if RustixFileType::from_raw_mode(observed.st_mode) != RustixFileType::Directory
                    || PrivateFileIdentity::from_stat(&observed)? != link.child_identity
                {
                    return Err(eyre!(
                        "private path ancestry changed during hardening: {}",
                        path.display()
                    ));
                }
            }
            Ok(())
        }
    }
    fn validate_private_directory(path: &Path) -> Result<()> {
        reject_symlink_components(path)?;
        let lexical = fs::symlink_metadata(path)
            .wrap_err_with(|| format!("inspect private directory {}", path.display()))?;
        if !lexical.is_dir()
            || lexical.file_type().is_symlink()
            || lexical.uid() != current_uid()
            || lexical.mode() & 0o777 != PRIVATE_DIRECTORY_MODE
        {
            return Err(eyre!(
                "private directory must be owner-held mode 0700: {}",
                path.display()
            ));
        }
        let opened = File::open(path)
            .wrap_err_with(|| format!("open private directory {}", path.display()))?;
        let observed = opened
            .metadata()
            .wrap_err_with(|| format!("inspect opened directory {}", path.display()))?;
        if lexical.dev() != observed.dev() || lexical.ino() != observed.ino() {
            return Err(eyre!(
                "private directory changed while opening: {}",
                path.display()
            ));
        }
        Ok(())
    }
    fn resolve_private_output_directory(path: &Path) -> Result<PathBuf> {
        let name = match path.components().next_back() {
            Some(Component::Normal(name)) => name,
            _ => {
                return Err(eyre!(
                    "private output directory must end in a normal path component: {}",
                    path.display()
                ));
            }
        };
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent = fs::canonicalize(parent).wrap_err_with(|| {
            format!(
                "resolve private output directory parent {}",
                parent.display()
            )
        })?;
        let resolved = parent.join(name);
        reject_symlink_components(&resolved)?;
        Ok(resolved)
    }
    fn harden_empty_private_directory(path: &Path) -> Result<()> {
        let lexical = fs::symlink_metadata(path)
            .wrap_err_with(|| format!("inspect empty private directory {}", path.display()))?;
        if !lexical.is_dir()
            || lexical.file_type().is_symlink()
            || lexical.uid() != current_uid()
            || lexical.mode() & 0o022 != 0
        {
            return Err(eyre!(
                "private output directory must be an owner-held, non-symlink directory with no group/world write access: {}",
                path.display()
            ));
        }
        if fs::read_dir(path)
            .wrap_err_with(|| format!("read private directory {}", path.display()))?
            .next()
            .is_some()
        {
            return Err(eyre!(
                "private output directory must be empty: {}",
                path.display()
            ));
        }
        let opened = File::open(path)
            .wrap_err_with(|| format!("open empty private directory {}", path.display()))?;
        let observed = opened
            .metadata()
            .wrap_err_with(|| format!("inspect opened directory {}", path.display()))?;
        if !observed.is_dir()
            || lexical.dev() != observed.dev()
            || lexical.ino() != observed.ino()
            || observed.uid() != current_uid()
        {
            return Err(eyre!(
                "private output directory changed while opening: {}",
                path.display()
            ));
        }
        fchmod(&opened, Mode::from_raw_mode(PRIVATE_DIRECTORY_MODE as _))
            .map_err(std::io::Error::from)
            .wrap_err_with(|| format!("harden private directory {}", path.display()))?;
        opened
            .sync_all()
            .wrap_err_with(|| format!("sync private directory {}", path.display()))?;
        validate_private_directory(path)?;
        if fs::read_dir(path)
            .wrap_err_with(|| format!("recheck private directory {}", path.display()))?
            .next()
            .is_some()
        {
            return Err(eyre!(
                "private output directory changed while being hardened: {}",
                path.display()
            ));
        }
        Ok(())
    }
    pub fn prepare_empty_private_directory(path: &Path) -> Result<PathBuf> {
        let path = resolve_private_output_directory(path)?;
        if !path.exists() {
            let mut builder = DirBuilder::new();
            builder.mode(PRIVATE_DIRECTORY_MODE);
            builder
                .create(&path)
                .wrap_err_with(|| format!("create private directory {}", path.display()))?;
        }
        harden_empty_private_directory(&path)?;
        Ok(path)
    }
    fn open_private_tree_root(path: &Path) -> Result<OpenPrivateTreeRoot> {
        let raw_path = path.as_os_str().as_bytes();
        if raw_path.is_empty()
            || raw_path
                .split(|byte| *byte == b'/')
                .any(|component| component == b"." || component == b"..")
        {
            return Err(eyre!(
                "private tree path must not be empty or contain `.`/`..`: {}",
                path.display()
            ));
        }
        let anchor = if path.is_absolute() {
            Path::new("/")
        } else {
            Path::new(".")
        };
        let mut current = File::from(
            open(
                anchor,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(std::io::Error::from)
            .wrap_err_with(|| format!("open private path anchor for {}", path.display()))?,
        );
        let mut ancestry = Vec::new();
        for component in path.components() {
            let name = match component {
                Component::RootDir => continue,
                Component::Normal(name) => name,
                Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                    return Err(eyre!(
                        "private tree path contains an ambiguous component: {}",
                        path.display()
                    ));
                }
            };
            if ancestry.len() >= MAX_PRIVATE_ROOT_COMPONENTS {
                return Err(eyre!(
                    "private tree path contains too many components: {}",
                    path.display()
                ));
            }
            let before = statat(&current, name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(std::io::Error::from)
                .wrap_err_with(|| {
                    format!("inspect private path component for {}", path.display())
                })?;
            if RustixFileType::from_raw_mode(before.st_mode) != RustixFileType::Directory {
                return Err(eyre!(
                    "private tree path contains a symbolic link or non-directory component: {}",
                    path.display()
                ));
            }
            let child_identity = PrivateFileIdentity::from_stat(&before)?;
            let child = File::from(
                openat(
                    &current,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(std::io::Error::from)
                .wrap_err_with(|| format!("open private path component for {}", path.display()))?,
            );
            let opened = child.metadata().wrap_err_with(|| {
                format!(
                    "inspect opened private path component for {}",
                    path.display()
                )
            })?;
            let after = statat(&current, name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(std::io::Error::from)
                .wrap_err_with(|| {
                    format!("reinspect private path component for {}", path.display())
                })?;
            if !opened.is_dir()
                || PrivateFileIdentity::from_metadata(&opened) != child_identity
                || RustixFileType::from_raw_mode(after.st_mode) != RustixFileType::Directory
                || PrivateFileIdentity::from_stat(&after)? != child_identity
            {
                return Err(eyre!(
                    "private path component changed while opening: {}",
                    path.display()
                ));
            }
            ancestry.push(PrivateDirectoryLink {
                parent: current,
                name: name.to_os_string(),
                child_identity,
            });
            current = child;
        }
        let root_before = current
            .metadata()
            .wrap_err_with(|| format!("inspect private directory {}", path.display()))?;
        if !root_before.is_dir()
            || root_before.uid() != current_uid()
            || root_before.mode() & 0o777 != PRIVATE_DIRECTORY_MODE
        {
            return Err(eyre!(
                "private directory must be owner-held mode 0700: {}",
                path.display()
            ));
        }
        let opened = OpenPrivateTreeRoot {
            root: current,
            root_before,
            ancestry,
        };
        opened.verify_ancestry(path)?;
        Ok(opened)
    }
    #[cfg(test)]
    fn replace_private_tree_ancestor_for_test(root_path: &Path) {
        let replacement = {
            let mut hook = PRIVATE_TREE_ANCESTOR_REPLACEMENT
                .lock()
                .expect("private tree ancestor replacement hook lock");
            match hook.as_ref() {
                Some((expected, _, _)) if expected == root_path => {
                    hook.take().map(|(_, ancestor, moved)| (ancestor, moved))
                }
                _ => None,
            }
        };
        if let Some((ancestor, moved)) = replacement {
            fs::rename(&ancestor, &moved).expect("move private tree ancestor for replacement test");
            std::os::unix::fs::symlink(&moved, &ancestor)
                .expect("replace private tree ancestor with symlink for test");
        }
    }
    fn verify_hardened_file(
        metadata: &fs::Metadata,
        identity: PrivateFileIdentity,
        expected_mode: u32,
    ) -> bool {
        metadata.is_file()
            && PrivateFileIdentity::from_metadata(metadata) == identity
            && metadata.uid() == current_uid()
            && metadata.nlink() == 1
            && metadata.mode() & 0o777 == expected_mode
    }
    fn verify_hardened_file_stat(
        stat: &rustix::fs::Stat,
        identity: PrivateFileIdentity,
        expected_mode: u32,
    ) -> bool {
        RustixFileType::from_raw_mode(stat.st_mode) == RustixFileType::RegularFile
            && PrivateFileIdentity::from_stat(stat).is_ok_and(|observed| observed == identity)
            && stat.st_uid == current_uid()
            && stat.st_nlink == 1
            && u32::from(stat.st_mode) & 0o777 == expected_mode
    }
    fn verify_hardened_directory(metadata: &fs::Metadata, identity: PrivateFileIdentity) -> bool {
        metadata.is_dir()
            && PrivateFileIdentity::from_metadata(metadata) == identity
            && metadata.uid() == current_uid()
            && metadata.mode() & 0o777 == PRIVATE_DIRECTORY_MODE
    }
    fn verify_hardened_directory_stat(
        stat: &rustix::fs::Stat,
        identity: PrivateFileIdentity,
    ) -> bool {
        RustixFileType::from_raw_mode(stat.st_mode) == RustixFileType::Directory
            && PrivateFileIdentity::from_stat(stat).is_ok_and(|observed| observed == identity)
            && stat.st_uid == current_uid()
            && u32::from(stat.st_mode) & 0o777 == PRIVATE_DIRECTORY_MODE
    }
    #[cfg(test)]
    fn replace_private_tree_entry_for_test(child_path: &Path) {
        let replacement = {
            let mut hook = PRIVATE_TREE_ENTRY_REPLACEMENT
                .lock()
                .expect("private tree replacement hook lock");
            match hook.as_ref() {
                Some((expected, _)) if expected == child_path => {
                    hook.take().map(|(_, replacement)| replacement)
                }
                _ => None,
            }
        };
        if let Some(replacement) = replacement {
            fs::remove_file(child_path).expect("remove private tree entry for replacement test");
            fs::rename(replacement, child_path)
                .expect("replace private tree entry for replacement test");
        }
    }
    #[allow(clippy::too_many_lines)]
    fn harden_private_directory_contents(
        directory: &File,
        display_path: &Path,
        depth: usize,
        entries_seen: &mut usize,
        owner_executable_files: &BTreeSet<PathBuf>,
        seen_owner_executable_files: &mut BTreeSet<PathBuf>,
    ) -> Result<()> {
        if depth > MAX_PRIVATE_TREE_DEPTH {
            return Err(eyre!(
                "private tree exceeds the maximum depth at {}",
                display_path.display()
            ));
        }
        let directory_before = directory
            .metadata()
            .wrap_err_with(|| format!("inspect private tree {}", display_path.display()))?;
        let mut entries = Dir::read_from(directory)
            .map_err(std::io::Error::from)
            .wrap_err_with(|| format!("read private tree {}", display_path.display()))?;
        for entry in &mut entries {
            let entry = entry
                .map_err(std::io::Error::from)
                .wrap_err("read private tree entry")?;
            let name = entry.file_name();
            if matches!(name.to_bytes(), b"." | b"..") {
                continue;
            }
            *entries_seen = entries_seen
                .checked_add(1)
                .ok_or_else(|| eyre!("private tree entry count overflow"))?;
            if *entries_seen > MAX_PRIVATE_TREE_ENTRIES {
                return Err(eyre!("private tree contains too many entries"));
            }
            let child_path = display_path.join(OsStr::from_bytes(name.to_bytes()));
            let before = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(std::io::Error::from)
                .wrap_err_with(|| format!("inspect private tree entry {}", child_path.display()))?;
            if before.st_uid != current_uid() {
                return Err(eyre!(
                    "private tree contains an entry owned by another user: {}",
                    child_path.display()
                ));
            }
            let identity = PrivateFileIdentity::from_stat(&before)?;
            #[cfg(test)]
            replace_private_tree_entry_for_test(&child_path);
            match RustixFileType::from_raw_mode(before.st_mode) {
                RustixFileType::Directory => {
                    let child = File::from(
                        openat(
                            directory,
                            name,
                            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                            Mode::empty(),
                        )
                        .map_err(std::io::Error::from)
                        .wrap_err_with(|| {
                            format!("open private directory {}", child_path.display())
                        })?,
                    );
                    let opened = child.metadata().wrap_err_with(|| {
                        format!("inspect opened private directory {}", child_path.display())
                    })?;
                    if !opened.is_dir()
                        || PrivateFileIdentity::from_metadata(&opened) != identity
                        || opened.uid() != current_uid()
                    {
                        return Err(eyre!(
                            "private directory changed while opening: {}",
                            child_path.display()
                        ));
                    }
                    fchmod(&child, Mode::from_raw_mode(PRIVATE_DIRECTORY_MODE as _))
                        .map_err(std::io::Error::from)
                        .wrap_err_with(|| {
                            format!("harden private directory {}", child_path.display())
                        })?;
                    let hardened = child.metadata().wrap_err_with(|| {
                        format!("reinspect hardened directory {}", child_path.display())
                    })?;
                    let parent_entry = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
                        .map_err(std::io::Error::from)
                        .wrap_err_with(|| {
                            format!("reinspect private directory {}", child_path.display())
                        })?;
                    if !verify_hardened_directory(&hardened, identity)
                        || !verify_hardened_directory_stat(&parent_entry, identity)
                    {
                        return Err(eyre!(
                            "private directory changed while hardening: {}",
                            child_path.display()
                        ));
                    }
                    harden_private_directory_contents(
                        &child,
                        &child_path,
                        depth + 1,
                        entries_seen,
                        owner_executable_files,
                        seen_owner_executable_files,
                    )?;
                    let parent_entry = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
                        .map_err(std::io::Error::from)
                        .wrap_err_with(|| {
                            format!("reinspect private directory {}", child_path.display())
                        })?;
                    if !verify_hardened_directory_stat(&parent_entry, identity) {
                        return Err(eyre!(
                            "private directory changed during traversal: {}",
                            child_path.display()
                        ));
                    }
                }
                RustixFileType::RegularFile if before.st_nlink == 1 => {
                    let expected_mode = if owner_executable_files.contains(&child_path) {
                        PRIVATE_EXECUTABLE_FILE_MODE
                    } else {
                        PRIVATE_FILE_MODE
                    };
                    let child = File::from(
                        openat(
                            directory,
                            name,
                            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                            Mode::empty(),
                        )
                        .map_err(std::io::Error::from)
                        .wrap_err_with(|| format!("open private file {}", child_path.display()))?,
                    );
                    let opened = child.metadata().wrap_err_with(|| {
                        format!("inspect opened private file {}", child_path.display())
                    })?;
                    if !opened.is_file()
                        || PrivateFileIdentity::from_metadata(&opened) != identity
                        || opened.uid() != current_uid()
                        || opened.nlink() != 1
                    {
                        return Err(eyre!(
                            "private file changed while opening: {}",
                            child_path.display()
                        ));
                    }
                    fchmod(&child, Mode::from_raw_mode(expected_mode as _))
                        .map_err(std::io::Error::from)
                        .wrap_err_with(|| {
                            format!("harden private file {}", child_path.display())
                        })?;
                    let hardened = child.metadata().wrap_err_with(|| {
                        format!("reinspect hardened file {}", child_path.display())
                    })?;
                    let parent_entry = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
                        .map_err(std::io::Error::from)
                        .wrap_err_with(|| {
                            format!("reinspect private file {}", child_path.display())
                        })?;
                    if !verify_hardened_file(&hardened, identity, expected_mode)
                        || !verify_hardened_file_stat(&parent_entry, identity, expected_mode)
                    {
                        return Err(eyre!(
                            "private file changed while hardening: {}",
                            child_path.display()
                        ));
                    }
                    if expected_mode == PRIVATE_EXECUTABLE_FILE_MODE {
                        seen_owner_executable_files.insert(child_path);
                    }
                }
                _ => {
                    return Err(eyre!(
                        "private tree contains a special or multi-link entry: {}",
                        child_path.display()
                    ));
                }
            }
        }
        drop(entries);
        directory
            .sync_all()
            .wrap_err_with(|| format!("sync hardened private tree {}", display_path.display()))?;
        let directory_after = directory
            .metadata()
            .wrap_err_with(|| format!("reinspect private tree {}", display_path.display()))?;
        if !same_file(&directory_before, &directory_after) {
            return Err(eyre!(
                "private directory changed during traversal: {}",
                display_path.display()
            ));
        }
        Ok(())
    }
    fn harden_private_tree_inner(
        path: &Path,
        owner_executable_files: &BTreeSet<PathBuf>,
    ) -> Result<()> {
        let opened_root = open_private_tree_root(path)?;
        #[cfg(test)]
        replace_private_tree_ancestor_for_test(path);
        let mut entries_seen = 0;
        let mut seen_owner_executable_files = BTreeSet::new();
        harden_private_directory_contents(
            &opened_root.root,
            path,
            0,
            &mut entries_seen,
            owner_executable_files,
            &mut seen_owner_executable_files,
        )?;
        if let Some(missing) = owner_executable_files
            .difference(&seen_owner_executable_files)
            .next()
        {
            return Err(eyre!(
                "private executable was not found as a regular file in the hardened tree: {}",
                missing.display()
            ));
        }
        let opened_after = opened_root
            .root
            .metadata()
            .wrap_err_with(|| format!("reinspect private directory {}", path.display()))?;
        if !same_file(&opened_root.root_before, &opened_after) {
            return Err(eyre!(
                "private directory changed during hardening: {}",
                path.display()
            ));
        }
        opened_root.verify_ancestry(path)?;
        Ok(())
    }
    #[cfg(test)]
    fn harden_private_tree(path: &Path) -> Result<()> {
        harden_private_tree_inner(path, &BTreeSet::new())
    }
    pub fn harden_private_tree_with_owner_executables(
        path: &Path,
        owner_executable_files: &[&Path],
    ) -> Result<()> {
        let mut validated = BTreeSet::new();
        for candidate in owner_executable_files {
            let relative = candidate.strip_prefix(path).map_err(|_| {
                eyre!(
                    "private executable must be inside the hardened tree: {}",
                    candidate.display()
                )
            })?;
            if relative.as_os_str().is_empty()
                || relative
                    .components()
                    .any(|component| !matches!(component, Component::Normal(_)))
            {
                return Err(eyre!(
                    "private executable path contains an unsafe component: {}",
                    candidate.display()
                ));
            }
            if !validated.insert((*candidate).to_path_buf()) {
                return Err(eyre!(
                    "duplicate private executable path: {}",
                    candidate.display()
                ));
            }
        }
        harden_private_tree_inner(path, &validated)
    }
    fn random_temporary_path(parent: &Path, target_name: &str) -> Result<PathBuf> {
        let mut random = [0_u8; 16];
        OsRng
            .try_fill_bytes(&mut random)
            .wrap_err("obtain OS entropy for private temporary filename")?;
        let suffix = hex::encode(random);
        random.zeroize();
        Ok(parent.join(format!(".{target_name}.tmp.{suffix}")))
    }
    pub fn write_private_file_atomic(path: &Path, raw: &[u8]) -> Result<()> {
        if raw.is_empty() || raw.len() > MAX_PRIVATE_FILE_BYTES as usize {
            return Err(eyre!(
                "private file payload must be within 1..={MAX_PRIVATE_FILE_BYTES} bytes"
            ));
        }
        let parent = path
            .parent()
            .ok_or_else(|| eyre!("private output path has no parent"))?;
        validate_private_directory(parent)?;
        match fs::symlink_metadata(path) {
            Ok(_) => {
                return Err(eyre!(
                    "refusing to overwrite private output: {}",
                    path.display()
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).wrap_err("inspect private output destination"),
        }
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| eyre!("private output filename is not UTF-8"))?;
        let temporary = random_temporary_path(parent, name)?;
        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .mode(PRIVATE_FILE_MODE)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let mut file = options
            .open(&temporary)
            .wrap_err_with(|| format!("create private temporary file {}", temporary.display()))?;
        let result = (|| -> Result<()> {
            let metadata = file.metadata().wrap_err("inspect private temporary file")?;
            if !metadata.is_file()
                || metadata.uid() != current_uid()
                || metadata.mode() & 0o777 != PRIVATE_FILE_MODE
                || metadata.nlink() != 1
            {
                return Err(eyre!("private temporary file has unsafe custody"));
            }
            file.write_all(raw)
                .wrap_err("write private temporary file")?;
            file.sync_all().wrap_err("sync private temporary file")?;
            fs::hard_link(&temporary, path).wrap_err_with(|| {
                format!("atomically publish private output {}", path.display())
            })?;
            fs::remove_file(&temporary).wrap_err("remove private temporary link")?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .wrap_err("sync private output directory")?;
            Ok(())
        })();
        drop(file);
        if temporary.exists() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
    pub fn read_private_file(path: &Path) -> Result<Vec<u8>> {
        reject_symlink_components(path)?;
        let lexical = fs::symlink_metadata(path)
            .wrap_err_with(|| format!("inspect private file {}", path.display()))?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
        let mut file = options
            .open(path)
            .wrap_err_with(|| format!("open private file {}", path.display()))?;
        let before = file.metadata().wrap_err("inspect opened private file")?;
        if lexical.file_type().is_symlink()
            || !before.is_file()
            || !same_file(&lexical, &before)
            || before.uid() != current_uid()
            || before.mode() & 0o777 != PRIVATE_FILE_MODE
            || before.nlink() != 1
            || before.size() == 0
            || before.size() > MAX_PRIVATE_FILE_BYTES
        {
            return Err(eyre!(
                "private file must be owner-held mode 0600, single-link regular data: {}",
                path.display()
            ));
        }
        let expected_len = usize::try_from(before.size())
            .map_err(|_| eyre!("private file length cannot be represented on this platform"))?;
        let mut raw = Vec::new();
        raw.try_reserve_exact(expected_len)
            .wrap_err("reserve private file buffer")?;
        (&mut file)
            .take(MAX_PRIVATE_FILE_BYTES + 1)
            .read_to_end(&mut raw)
            .wrap_err("read private file")?;
        if raw.len() > MAX_PRIVATE_FILE_BYTES as usize {
            raw.zeroize();
            return Err(eyre!(
                "private file grew beyond the {MAX_PRIVATE_FILE_BYTES}-byte limit while being read"
            ));
        }
        let after = file.metadata().wrap_err("reinspect private file")?;
        if !same_file(&before, &after) || raw.len() as u64 != before.size() {
            raw.zeroize();
            return Err(eyre!("private file changed while being read"));
        }
        Ok(raw)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::{
            fs::{PermissionsExt as _, symlink},
            net::UnixListener,
        };
        fn set_mode(path: &Path, mode: u32) {
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set mode");
        }
        fn mode(path: &Path) -> u32 {
            fs::symlink_metadata(path).expect("read metadata").mode() & 0o777
        }
        fn private_root() -> (tempfile::TempDir, PathBuf) {
            let guard = tempfile::tempdir().expect("create private root");
            set_mode(guard.path(), PRIVATE_DIRECTORY_MODE);
            let root = fs::canonicalize(guard.path()).expect("canonicalize private root");
            (guard, root)
        }
        #[test]
        fn private_directory_creation_returns_a_canonical_path_and_rejects_a_final_symlink() {
            let sandbox = tempfile::tempdir().expect("create private-directory sandbox");
            let sandbox_root = fs::canonicalize(sandbox.path()).expect("canonicalize sandbox");
            let actual_parent = sandbox_root.join("actual-parent");
            fs::create_dir(&actual_parent).expect("create actual parent");
            let parent_alias = sandbox_root.join("parent-alias");
            symlink(&actual_parent, &parent_alias).expect("create parent alias");

            let requested = parent_alias.join("custody");
            let canonical = prepare_empty_private_directory(&requested)
                .expect("resolve the existing parent before private-directory creation");
            assert_eq!(canonical, actual_parent.join("custody"));
            assert_eq!(mode(&canonical), PRIVATE_DIRECTORY_MODE);

            let actual_target = sandbox_root.join("actual-target");
            fs::create_dir(&actual_target).expect("create final symlink target");
            set_mode(&actual_target, PRIVATE_DIRECTORY_MODE);
            let final_alias = sandbox_root.join("final-alias");
            symlink(&actual_target, &final_alias).expect("create final directory alias");
            let error = prepare_empty_private_directory(&final_alias)
                .expect_err("the requested final directory must never be a symlink");
            assert!(error.to_string().contains("symbolic link"));

            let error = prepare_empty_private_directory(&actual_parent.join(".."))
                .expect_err("a parent-directory final component must be rejected");
            assert!(error.to_string().contains("normal path component"));
        }
        #[test]
        fn private_directory_hardens_safe_empty_modes_and_rejects_writable_or_nonempty_roots() {
            let sandbox = tempfile::tempdir().expect("create private-directory sandbox");
            let safe = sandbox.path().join("safe-empty");
            fs::create_dir(&safe).expect("create safe empty directory");
            set_mode(&safe, 0o755);
            prepare_empty_private_directory(&safe).expect("harden safe empty directory");
            assert_eq!(mode(&safe), PRIVATE_DIRECTORY_MODE);

            let writable = sandbox.path().join("writable-empty");
            fs::create_dir(&writable).expect("create writable empty directory");
            set_mode(&writable, 0o777);
            let error = prepare_empty_private_directory(&writable)
                .expect_err("group/world-writable directory must fail closed");
            assert!(error.to_string().contains("no group/world write access"));

            let nonempty = sandbox.path().join("nonempty");
            fs::create_dir(&nonempty).expect("create nonempty directory");
            fs::write(nonempty.join("existing"), b"occupied").expect("occupy directory");
            let error = prepare_empty_private_directory(&nonempty)
                .expect_err("nonempty directory must fail closed");
            assert!(error.to_string().contains("must be empty"));
        }
        #[test]
        fn private_file_roundtrip_accepts_exact_size_limit() {
            let (_root_guard, root) = private_root();
            let path = root.join("exact-limit.secret");
            let raw = vec![0xA5; MAX_PRIVATE_FILE_BYTES as usize];
            write_private_file_atomic(&path, &raw).expect("write exact-limit private file");
            let read = read_private_file(&path).expect("read exact-limit private file");
            assert_eq!(read.len(), MAX_PRIVATE_FILE_BYTES as usize);
            assert_eq!(read.first(), Some(&0xA5));
            assert_eq!(read.last(), Some(&0xA5));
        }
        #[test]
        fn private_file_reader_rejects_fifo_without_waiting_for_a_writer() {
            let (_root_guard, root) = private_root();
            let path = root.join("named-pipe.secret");
            crate::secure_fs::create_fifo_for_test(&path, 0o600)
                .expect("create private-input FIFO");
            let error = read_private_file(&path).expect_err("FIFO must not be accepted as a key");
            assert!(error.to_string().contains("single-link regular data"));
        }
        #[test]
        fn private_file_writer_rejects_size_limit_plus_one_before_creation() {
            let (_root_guard, root) = private_root();
            let path = root.join("oversized.secret");
            let raw = vec![0xA5; MAX_PRIVATE_FILE_BYTES as usize + 1];
            let error = write_private_file_atomic(&path, &raw)
                .expect_err("limit plus one must be rejected");
            assert!(error.to_string().contains("within 1..=1048576 bytes"));
            assert!(!path.exists(), "rejection must happen before publication");
        }
        #[test]
        fn harden_private_tree_normalizes_directories_and_every_regular_file_to_private_modes() {
            let (_root_guard, root) = private_root();
            let nested = root.join("nested");
            fs::create_dir(&nested).expect("create nested directory");
            set_mode(&nested, 0o755);
            let executable = root.join("start.sh");
            let regular = nested.join("client.toml");
            fs::write(&executable, b"#!/usr/bin/env bash\nexit 0\n").expect("write script");
            fs::write(&regular, b"private_key = 'secret'\n").expect("write config");
            set_mode(&executable, 0o755);
            set_mode(&regular, 0o644);
            harden_private_tree(&root).expect("harden private tree");
            assert_eq!(mode(&root), PRIVATE_DIRECTORY_MODE);
            assert_eq!(mode(&nested), PRIVATE_DIRECTORY_MODE);
            assert_eq!(mode(&executable), PRIVATE_FILE_MODE);
            assert_eq!(mode(&regular), PRIVATE_FILE_MODE);
            assert_eq!(
                fs::read(&executable).expect("read script"),
                b"#!/usr/bin/env bash\nexit 0\n"
            );
        }
        #[test]
        fn harden_private_tree_preserves_only_explicit_owner_executables() {
            let (_root_guard, root) = private_root();
            let executable = root.join("start.sh");
            let regular = root.join("client.toml");
            fs::write(&executable, b"#!/usr/bin/env bash\nexit 0\n").expect("write script");
            fs::write(&regular, b"private_key = 'secret'\n").expect("write config");
            set_mode(&executable, 0o755);
            set_mode(&regular, 0o644);
            harden_private_tree_with_owner_executables(&root, &[&executable])
                .expect("harden private tree with an owner-executable script");
            assert_eq!(mode(&root), PRIVATE_DIRECTORY_MODE);
            assert_eq!(mode(&executable), PRIVATE_EXECUTABLE_FILE_MODE);
            assert_eq!(mode(&regular), PRIVATE_FILE_MODE);
        }
        #[test]
        fn harden_private_tree_rejects_an_executable_outside_the_private_root() {
            let (_root_guard, root) = private_root();
            let outside = tempfile::NamedTempFile::new().expect("create outside executable");
            let error = harden_private_tree_with_owner_executables(&root, &[outside.path()])
                .expect_err("outside executable must fail closed");
            assert!(
                error
                    .to_string()
                    .contains("private executable must be inside the hardened tree")
            );
        }
        #[test]
        fn harden_private_tree_rejects_a_missing_allowlisted_executable() {
            let (_root_guard, root) = private_root();
            let missing = root.join("missing-start.sh");
            let error = harden_private_tree_with_owner_executables(&root, &[&missing])
                .expect_err("missing executable must fail closed");
            assert!(
                error
                    .to_string()
                    .contains("private executable was not found as a regular file")
            );
        }
        #[test]
        fn harden_private_tree_rejects_duplicate_executable_paths() {
            let (_root_guard, root) = private_root();
            let executable = root.join("start.sh");
            fs::write(&executable, b"#!/usr/bin/env bash\nexit 0\n").expect("write script");
            let error =
                harden_private_tree_with_owner_executables(&root, &[&executable, &executable])
                    .expect_err("duplicate executable must fail closed");
            assert!(
                error
                    .to_string()
                    .contains("duplicate private executable path")
            );
        }
        #[test]
        fn harden_private_tree_rejects_unsafe_executable_path_components() {
            let (_root_guard, root) = private_root();
            let ambiguous = root.join("nested").join("..").join("start.sh");
            let error = harden_private_tree_with_owner_executables(&root, &[&ambiguous])
                .expect_err("ambiguous executable path must fail closed");
            assert!(
                error
                    .to_string()
                    .contains("private executable path contains an unsafe component")
            );
        }
        #[test]
        fn harden_private_tree_rejects_symlinks_without_changing_their_target() {
            let (_root_guard, root) = private_root();
            let outside = tempfile::NamedTempFile::new().expect("create outside file");
            set_mode(outside.path(), 0o640);
            symlink(outside.path(), root.join("linked-secret")).expect("create symlink");
            let error = harden_private_tree(&root).expect_err("symlink must fail closed");
            assert!(error.to_string().contains("special or multi-link entry"));
            assert_eq!(mode(outside.path()), 0o640);
        }
        #[test]
        fn harden_private_tree_rejects_special_files() {
            const CHILD_ROOT: &str = "IROHA_KAGAMI_PRIVATE_TREE_SOCKET_TEST_ROOT";
            if let Some(expected_root) = std::env::var_os(CHILD_ROOT) {
                let root = std::env::current_dir().expect("child fixture directory");
                assert_eq!(root, PathBuf::from(expected_root));
                // Only this child changes cwd. A relative socket address keeps the
                // actual socket fixture below SUN_LEN even with a long TMPDIR.
                let _listener = UnixListener::bind("control.sock").expect("bind Unix socket");
                let error = harden_private_tree(&root).expect_err("socket must fail closed");
                assert!(error.to_string().contains("special or multi-link entry"));
                return;
            }
            let (_root_guard, root) = private_root();
            let root = root.canonicalize().expect("canonical private root");
            let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
                .args([
                    "--exact",
                    "secure_fs::unix::tests::harden_private_tree_rejects_special_files",
                    "--nocapture",
                ])
                .current_dir(&root)
                .env(CHILD_ROOT, &root)
                .output()
                .expect("execute isolated socket fixture");
            assert!(output.status.success(), "socket fixture failed: {output:?}");
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed; 0 ignored"),
                "the child must execute the exact socket assertion: {output:?}"
            );
        }
        #[test]
        fn harden_private_tree_rejects_hard_linked_regular_files() {
            let (_root_guard, root) = private_root();
            let first = root.join("first");
            let second = root.join("second");
            fs::write(&first, b"secret").expect("write first link");
            set_mode(&first, 0o640);
            fs::hard_link(&first, &second).expect("create second hard link");
            let error = harden_private_tree(&root).expect_err("hard links must fail closed");
            assert!(error.to_string().contains("special or multi-link entry"));
            assert_eq!(mode(&first), 0o640);
            assert_eq!(mode(&second), 0o640);
        }
        #[test]
        fn harden_private_tree_rejects_a_regular_file_replaced_after_inspection() {
            let (_root_guard, root) = private_root();
            let victim = root.join("victim");
            fs::write(&victim, b"original").expect("write original entry");
            set_mode(&victim, 0o755);
            let replacements = tempfile::tempdir().expect("create replacement directory");
            let replacement = replacements.path().join("replacement");
            fs::write(&replacement, b"replacement").expect("write replacement entry");
            set_mode(&replacement, 0o640);
            {
                let mut hook = PRIVATE_TREE_ENTRY_REPLACEMENT
                    .lock()
                    .expect("private tree replacement hook lock");
                assert!(hook.is_none(), "replacement hook must start empty");
                *hook = Some((victim.clone(), replacement));
            }
            let error = harden_private_tree(&root)
                .expect_err("descriptor identity mismatch must fail closed");
            assert!(error.to_string().contains("changed while opening"));
            assert_eq!(mode(&victim), 0o640);
            assert_eq!(fs::read(&victim).expect("read replacement"), b"replacement");
        }
        #[test]
        fn harden_private_tree_rejects_an_intermediate_ancestor_replaced_with_a_symlink() {
            let sandbox = tempfile::tempdir().expect("create ancestor replacement sandbox");
            let sandbox_root =
                fs::canonicalize(sandbox.path()).expect("canonicalize replacement sandbox");
            let ancestor = sandbox_root.join("ancestor");
            let moved = sandbox_root.join("moved-ancestor");
            let root = ancestor.join("private");
            fs::create_dir_all(&root).expect("create nested private root");
            set_mode(&root, PRIVATE_DIRECTORY_MODE);
            {
                let mut hook = PRIVATE_TREE_ANCESTOR_REPLACEMENT
                    .lock()
                    .expect("private tree ancestor replacement hook lock");
                assert!(hook.is_none(), "ancestor replacement hook must start empty");
                *hook = Some((root.clone(), ancestor.clone(), moved.clone()));
            }
            let error = harden_private_tree(&root)
                .expect_err("an intermediate ancestor symlink must fail closed");
            assert!(error.to_string().contains("path ancestry changed"));
            assert!(
                fs::symlink_metadata(&ancestor)
                    .expect("inspect replaced ancestor")
                    .file_type()
                    .is_symlink()
            );
            assert!(moved.join("private").is_dir());
        }
        #[test]
        fn harden_private_tree_rejects_a_preexisting_intermediate_ancestor_symlink() {
            let sandbox = tempfile::tempdir().expect("create ancestor symlink sandbox");
            let sandbox_root =
                fs::canonicalize(sandbox.path()).expect("canonicalize symlink sandbox");
            let actual_ancestor = sandbox_root.join("actual-ancestor");
            let actual_root = actual_ancestor.join("private");
            fs::create_dir_all(&actual_root).expect("create actual private root");
            set_mode(&actual_root, PRIVATE_DIRECTORY_MODE);
            let alias = sandbox_root.join("ancestor-alias");
            symlink(&actual_ancestor, &alias).expect("create intermediate ancestor symlink");
            let spelled_root = alias.join("private");
            let error = harden_private_tree(&spelled_root)
                .expect_err("a preexisting intermediate ancestor symlink must fail closed");
            assert!(
                error
                    .to_string()
                    .contains("symbolic link or non-directory component")
            );
            assert_eq!(mode(&actual_root), PRIVATE_DIRECTORY_MODE);
        }
    }
}
#[cfg(all(
    unix,
    not(any(target_os = "espidf", target_os = "horizon", target_os = "redox"))
))]
pub use unix::{
    harden_private_tree_with_owner_executables, prepare_empty_private_directory, read_private_file,
    write_private_file_atomic,
};
#[cfg(any(
    not(unix),
    target_os = "espidf",
    target_os = "horizon",
    target_os = "redox"
))]
fn unsupported<T>() -> Result<T> {
    Err(eyre!(
        "owner-only private artifact operations require a supported Unix platform"
    ))
}
#[cfg(any(
    not(unix),
    target_os = "espidf",
    target_os = "horizon",
    target_os = "redox"
))]
pub fn prepare_empty_private_directory(_path: &Path) -> Result<std::path::PathBuf> {
    unsupported()
}
#[cfg(any(
    not(unix),
    target_os = "espidf",
    target_os = "horizon",
    target_os = "redox"
))]
pub fn harden_private_tree_with_owner_executables(
    _path: &Path,
    _owner_executable_files: &[&Path],
) -> Result<()> {
    unsupported()
}
#[cfg(any(
    not(unix),
    target_os = "espidf",
    target_os = "horizon",
    target_os = "redox"
))]
pub fn write_private_file_atomic(_path: &Path, _raw: &[u8]) -> Result<()> {
    unsupported()
}
#[cfg(any(
    not(unix),
    target_os = "espidf",
    target_os = "horizon",
    target_os = "redox"
))]
pub fn read_private_file(_path: &Path) -> Result<Vec<u8>> {
    unsupported()
}

/// Whether two metadata snapshots describe the same unchanged regular-file inode.
///
/// Unix compares device, inode, mode, ownership, link count, size and both
/// timestamps with nanoseconds. Other platforms fall back to the portable
/// type, length and modification-time subset.
#[cfg(unix)]
pub fn same_file_snapshot(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.mode() == right.mode()
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && left.nlink() == right.nlink()
        && left.size() == right.size()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}
/// Whether two metadata snapshots describe the same unchanged regular-file inode.
#[cfg(not(unix))]
pub(crate) fn same_file_snapshot(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.is_file() == right.is_file()
        && left.is_dir() == right.is_dir()
        && left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
}
/// Whether two metadata snapshots name the same filesystem object.
#[cfg(unix)]
pub fn same_file_identity(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.dev() == right.dev() && left.ino() == right.ino()
}
/// Whether two metadata snapshots name the same filesystem object.
#[cfg(windows)]
pub(crate) fn same_file_identity(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    left.volume_serial_number().is_some()
        && left.file_index().is_some()
        && left.volume_serial_number() == right.volume_serial_number()
        && left.file_index() == right.file_index()
}
/// Platforms without a stable file identity never report an alias.
#[cfg(not(any(unix, windows)))]
pub(crate) fn same_file_identity(_left: &std::fs::Metadata, _right: &std::fs::Metadata) -> bool {
    false
}
/// Whether two snapshots describe the same unchanged single-link regular input file.
#[cfg(unix)]
pub fn same_single_link_input_snapshot(
    left: &std::fs::Metadata,
    right: &std::fs::Metadata,
) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.is_file()
        && right.is_file()
        && left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.mode() == right.mode()
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && left.nlink() == 1
        && right.nlink() == 1
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}
/// Whether two snapshots describe the same unchanged single-link regular input file.
#[cfg(not(unix))]
pub(crate) fn same_single_link_input_snapshot(
    left: &std::fs::Metadata,
    right: &std::fs::Metadata,
) -> bool {
    left.is_file()
        && right.is_file()
        && left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
}
