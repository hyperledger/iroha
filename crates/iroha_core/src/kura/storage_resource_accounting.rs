// Included at Kura module scope. Physical storage observations confer no read/write authority.

/// Observe a caller-owned regular file without reading or allocating its payload.
fn storage_resource_file_bytes(
    path: &Path,
) -> std::result::Result<u64, resource_inventory::Unavailable> {
    storage_resource_file_bytes_with_admission_hooks(path, || {}, |_| {})
}

/// Preserve the production observer while exposing per-call test admission boundaries.
fn storage_resource_file_bytes_with_admission_hooks(
    path: &Path,
    after_admission: impl FnOnce(),
    after_open: impl FnOnce(&std::fs::File),
) -> std::result::Result<u64, resource_inventory::Unavailable> {
    use resource_inventory::Unavailable as Missing;
    let (parent, parent_before) = index_resource_parent_binding(path)?;
    let before = match secure_file_metadata::from_path(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return if index_resource_parent_unchanged(&parent, &parent_before) {
                Ok(0)
            } else {
                Err(Missing::InvalidInventory)
            };
        }
        Err(_) => return Err(Missing::InvalidInventory),
    };
    if !before.is_file()
        || before.file_type().is_symlink()
        || !Kura::sidecar_is_single_link(&before)
    {
        return Err(Missing::InvalidInventory);
    }
    after_admission();
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(i32::from_ne_bytes(
            (rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC)
                .bits()
                .to_ne_bytes(),
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path).map_err(|_| Missing::InvalidInventory)?;
    after_open(&file);
    let opened = secure_file_metadata::from_file(&file).map_err(|_| Missing::InvalidInventory)?;
    let after = secure_file_metadata::from_path(path).map_err(|_| Missing::InvalidInventory)?;
    if !Kura::sidecar_file_metadata_unchanged(&before, &opened)
        || !Kura::sidecar_file_metadata_unchanged(&opened, &after)
        || !index_resource_parent_unchanged(&parent, &parent_before)
    {
        return Err(Missing::InvalidInventory);
    }
    Ok(opened.len())
}
