//! Resolve filesystem devices to whole block devices accepted by cgroup-v2 io.max.
//!
//! Linux rejects partitions in `blkg_conf_open_bdev` with ENODEV. A backing file's
//! `st_dev` identifies its filesystem partition, so the kernel-owned sysfs mapping
//! must identify the whole device before finite I/O limits can be installed.

use std::{collections::BTreeSet, fs, io::Read as _, path::Path};

use eyre::WrapErr as _;

/// Kernel block-device identity used by the cgroup I/O controller.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct InrouCgroupIoDevice {
    pub(super) major: u32,
    pub(super) minor: u32,
}

/// Resolve and deduplicate actual whole devices, without falling back to limits
/// on a partition or accepting a filesystem the block controller cannot govern.
pub(super) fn resolve_inrou_whole_io_devices(
    devices: &BTreeSet<InrouCgroupIoDevice>,
    sysfs_root: &Path,
) -> eyre::Result<BTreeSet<InrouCgroupIoDevice>> {
    if devices.is_empty() {
        eyre::bail!("Inrou IO confinement requires at least one backing device");
    }
    let sysfs_root = fs::canonicalize(sysfs_root).wrap_err("resolve kernel sysfs root")?;
    devices
        .iter()
        .map(|device| resolve_whole_device(*device, &sysfs_root))
        .collect()
}

fn device_path(device: InrouCgroupIoDevice, sysfs_root: &Path) -> eyre::Result<std::path::PathBuf> {
    if device.major == 0 {
        eyre::bail!(
            "Inrou IO device 0:{} is not a governable block device",
            device.minor
        );
    }
    let link = sysfs_root.join(format!("dev/block/{}:{}", device.major, device.minor));
    let resolved = fs::canonicalize(&link)
        .wrap_err_with(|| format!("resolve Inrou IO block-device identity {}", link.display()))?;
    if !resolved.starts_with(sysfs_root.join("devices")) || !resolved.is_dir() {
        eyre::bail!("Inrou IO block-device identity escapes the kernel devices hierarchy");
    }
    if read_device(&resolved.join("dev"))? != device {
        eyre::bail!("Inrou IO sysfs dev attribute differs from its block-device identity");
    }
    Ok(resolved)
}

fn resolve_whole_device(
    device: InrouCgroupIoDevice,
    sysfs_root: &Path,
) -> eyre::Result<InrouCgroupIoDevice> {
    let path = device_path(device, sysfs_root)?;
    let partition = path.join("partition");
    match fs::symlink_metadata(&partition) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(device),
        Err(error) => return Err(error).wrap_err("inspect Inrou IO partition marker"),
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => eyre::bail!("Inrou IO partition marker is not a regular sysfs attribute"),
    }
    let number = read_attribute(&partition)?;
    if number.is_empty()
        || !number.bytes().all(|byte| byte.is_ascii_digit())
        || number
            .parse::<u32>()
            .ok()
            .filter(|value| *value > 0)
            .is_none()
    {
        eyre::bail!("Inrou IO partition marker is not a positive partition number");
    }
    let parent = path
        .parent()
        .ok_or_else(|| eyre::eyre!("Inrou IO partition has no parent"))?;
    if parent
        .join("partition")
        .try_exists()
        .wrap_err("inspect Inrou IO whole-device parent")?
    {
        eyre::bail!("Inrou IO partition parent is also a partition");
    }
    let whole = read_device(&parent.join("dev"))?;
    if whole == device || device_path(whole, sysfs_root)? != parent {
        eyre::bail!("Inrou IO partition parent does not match the kernel whole-device identity");
    }
    Ok(whole)
}

fn read_attribute(path: &Path) -> eyre::Result<String> {
    let mut value = String::new();
    fs::File::open(path)
        .wrap_err_with(|| format!("open Inrou IO sysfs attribute {}", path.display()))?
        .take(65)
        .read_to_string(&mut value)
        .wrap_err_with(|| format!("read Inrou IO sysfs attribute {}", path.display()))?;
    if value.len() > 64 {
        eyre::bail!("Inrou IO sysfs attribute exceeds its bounded numeric representation");
    }
    Ok(value.trim_end_matches('\n').to_owned())
}

fn read_device(path: &Path) -> eyre::Result<InrouCgroupIoDevice> {
    let value = read_attribute(path)?;
    let (major, minor) = value
        .split_once(':')
        .ok_or_else(|| eyre::eyre!("Inrou IO sysfs dev lacks major:minor"))?;
    if major.is_empty()
        || minor.is_empty()
        || !major.bytes().all(|byte| byte.is_ascii_digit())
        || !minor.bytes().all(|byte| byte.is_ascii_digit())
    {
        eyre::bail!("Inrou IO sysfs dev must contain two decimal device identifiers");
    }
    Ok(InrouCgroupIoDevice {
        major: major.parse().wrap_err("parse Inrou IO major device")?,
        minor: minor.parse().wrap_err("parse Inrou IO minor device")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::unix::fs::symlink, path::PathBuf};

    const DISK: InrouCgroupIoDevice = InrouCgroupIoDevice {
        major: 254,
        minor: 0,
    };
    const PART: InrouCgroupIoDevice = InrouCgroupIoDevice {
        major: 254,
        minor: 2,
    };

    fn fixture() -> eyre::Result<(tempfile::TempDir, PathBuf)> {
        let root = tempfile::tempdir()?;
        let disk = root.path().join("devices/pci/virtio/block/vda");
        fs::create_dir_all(disk.join("vda2"))?;
        fs::create_dir_all(root.path().join("dev/block"))?;
        fs::write(disk.join("dev"), "254:0\n")?;
        fs::write(disk.join("vda2/dev"), "254:2\n")?;
        fs::write(disk.join("vda2/partition"), "2\n")?;
        symlink(&disk, root.path().join("dev/block/254:0"))?;
        symlink(disk.join("vda2"), root.path().join("dev/block/254:2"))?;
        Ok((root, disk))
    }

    #[test]
    fn cgroup_io_device_resolves_partition_to_whole_and_deduplicates() -> eyre::Result<()> {
        let (root, _) = fixture()?;
        for devices in [
            BTreeSet::from([PART]),
            BTreeSet::from([DISK]),
            BTreeSet::from([PART, DISK]),
        ] {
            assert_eq!(
                resolve_inrou_whole_io_devices(&devices, root.path())?,
                BTreeSet::from([DISK])
            );
        }
        Ok(())
    }

    #[test]
    fn cgroup_io_device_rejects_missing_pseudo_and_escaping_devices() -> eyre::Result<()> {
        let (root, _) = fixture()?;
        for devices in [
            BTreeSet::new(),
            BTreeSet::from([InrouCgroupIoDevice {
                major: 0,
                minor: 42,
            }]),
            BTreeSet::from([InrouCgroupIoDevice {
                major: 254,
                minor: 99,
            }]),
        ] {
            assert!(resolve_inrou_whole_io_devices(&devices, root.path()).is_err());
        }
        let outside = tempfile::tempdir()?;
        fs::write(outside.path().join("dev"), "254:0\n")?;
        fs::remove_file(root.path().join("dev/block/254:0"))?;
        symlink(outside.path(), root.path().join("dev/block/254:0"))?;
        assert!(resolve_inrou_whole_io_devices(&BTreeSet::from([PART]), root.path()).is_err());
        Ok(())
    }

    #[test]
    fn cgroup_io_device_requires_exact_partition_and_parent_identity() -> eyre::Result<()> {
        let (root, disk) = fixture()?;
        let selected = BTreeSet::from([PART]);
        fs::write(disk.join("vda2/dev"), "254:3\n")?;
        assert!(resolve_inrou_whole_io_devices(&selected, root.path()).is_err());
        fs::write(disk.join("vda2/dev"), "254:2\n")?;
        fs::write(disk.join("dev"), "254:1\n")?;
        assert!(resolve_inrou_whole_io_devices(&selected, root.path()).is_err());
        fs::write(disk.join("dev"), "254:0\n")?;
        fs::write(disk.join("partition"), "1\n")?;
        assert!(resolve_inrou_whole_io_devices(&selected, root.path()).is_err());
        fs::remove_file(disk.join("partition"))?;
        let other = root.path().join("devices/other");
        fs::create_dir(&other)?;
        fs::write(other.join("dev"), "254:0\n")?;
        fs::remove_file(root.path().join("dev/block/254:0"))?;
        symlink(other, root.path().join("dev/block/254:0"))?;
        assert!(resolve_inrou_whole_io_devices(&selected, root.path()).is_err());
        Ok(())
    }

    #[test]
    fn cgroup_io_device_rejects_malformed_and_missing_sysfs_attributes() -> eyre::Result<()> {
        let (root, disk) = fixture()?;
        let selected = BTreeSet::from([PART]);
        for bad in ["0\n", "-1\n", "max\n", "2 3\n", "4294967296\n"] {
            fs::write(disk.join("vda2/partition"), bad)?;
            assert!(resolve_inrou_whole_io_devices(&selected, root.path()).is_err());
        }
        fs::write(disk.join("vda2/partition"), "2\n")?;
        for bad in [
            "0:1\n",
            "254\n",
            "254:-1\n",
            "254:0 extra\n",
            "4294967296:0\n",
        ] {
            fs::write(disk.join("dev"), bad)?;
            assert!(resolve_inrou_whole_io_devices(&selected, root.path()).is_err());
        }
        fs::remove_file(disk.join("dev"))?;
        assert!(resolve_inrou_whole_io_devices(&selected, root.path()).is_err());
        Ok(())
    }
}
