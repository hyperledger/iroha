//! Reopen immutable proving DATA while independently reconstructing every source capability.

use super::*;
use crate::kagemusha_wallet_artifacts_v1::producer_inventory::reopen_pinned_engineering_wallet_sources;

const SELECTION_SCHEMA: &str = "iroha.kagemusha.sealed-proving-originals-selection.v1";

const LOCATOR_SCHEMA: &str = "iroha.kagemusha.sealed-proving-originals-locator.v1";

// This locator is part of the independently hash-pinned target, not a serialized grant.
pub(super) fn locator(path: &Path) -> norito::json::Value {
    assert!(path.is_absolute());
    norito::json!({ "schema": LOCATOR_SCHEMA, "path": (path.to_str().unwrap()) })
}

fn selected_locator<'a>(
    target: &'a norito::json::Value,
    selected_pins: &norito::json::Value,
    qualification: &Path,
) -> Result<&'a Path, &'static str> {
    selected_originals(target, TARGET_SCHEMA, selected_pins, qualification)
}

fn selected_originals<'a>(
    target: &'a norito::json::Value,
    expected_schema: &str,
    selected_pins: &norito::json::Value,
    qualification: &Path,
) -> Result<&'a Path, &'static str> {
    if target["schema"].as_str() != Some(expected_schema) || &target["source_pins"] != selected_pins
    {
        return Err("target differs from independently selected source pins");
    }
    let selected = &target["sealed_originals"];
    if selected["schema"].as_str() != Some(LOCATOR_SCHEMA) {
        return Err("missing or invalid sealed DATA locator");
    }
    let path = Path::new(
        selected["path"]
            .as_str()
            .ok_or("missing sealed DATA path")?,
    );
    if !path.is_absolute() || !path.starts_with(qualification) {
        return Err("sealed DATA must remain inside the selected qualification workspace");
    }
    // No canonicalization, path fallback or new directory is permitted here. The strict
    // original owner subsequently rejects redirects, noncanonical paths and unsafe custody.
    Ok(path)
}

impl Sources {
    // Initial target requires explicit independently pinned DATA, just as later targets do.
    // The locator is never a source grant; complete current admission below is unchanged.
    pub(super) fn admit(output: &Path) -> Self {
        let path = selected_path("KAGEMUSHA_NATIVE_SOURCE_SELECTION");
        let bytes = read_pin(
            &path,
            TARGET_MAX,
            &env_pin("KAGEMUSHA_NATIVE_SOURCE_SELECTION_SHA256"),
        );
        let selected: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
        let originals = selected_originals(
            &selected,
            SELECTION_SCHEMA,
            &source_pins(),
            &qualification_root(),
        )
        .unwrap();
        Self::reopen(output, originals)
    }

    pub(super) fn requalify(output: &Path) -> Self {
        let target_path = selected_path("KAGEMUSHA_NATIVE_LOAD_TARGET");
        let bytes = read_pin(
            &target_path,
            TARGET_MAX,
            &env_pin("KAGEMUSHA_NATIVE_LOAD_TARGET_SHA256"),
        );
        let target: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
        let selected = selected_locator(&target, &source_pins(), &qualification_root()).unwrap();
        Self::reopen(output, selected)
    }

    fn reopen(output: &Path, selected: &Path) -> Self {
        let (installed, qualified, genesis, originals) =
            reopen_pinned_engineering_wallet_sources(output, selected);
        let path = originals.root().unwrap().to_path_buf();
        assert_eq!(path.as_path(), selected);
        drop(originals);
        Self {
            installed,
            qualified,
            genesis: Arc::new(genesis),
            originals: path,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kagemusha_wallet_artifacts_v1::producer_inventory::BlobV1;
    use std::io::Read as _;

    fn pins(changed: Option<&str>) -> norito::json::Value {
        norito::json::to_value(
            &SOURCE_PINS
                .into_iter()
                .map(|name| {
                    (
                        name,
                        hex::encode([if changed == Some(name) { 2 } else { 1 }; 32]),
                    )
                })
                .collect::<std::collections::BTreeMap<_, _>>(),
        )
        .unwrap()
    }

    fn target(location: norito::json::Value, source: norito::json::Value) -> norito::json::Value {
        norito::json!({
            "schema": TARGET_SCHEMA,
            "source_pins": source,
            "sealed_originals": location,
        })
    }

    fn original() -> (tempfile::TempDir, iroha_fs::PrivateDirectory, BlobV1) {
        let temporary = tempfile::tempdir().unwrap();
        let private =
            iroha_fs::PrivateDirectory::open_or_create(temporary.path().join("originals")).unwrap();
        let mut store = DirectoryOriginalsV1::open_existing(private.path(), 1024).unwrap();
        let identity = BlobV1::of(b"one immutable proving DATA original");
        store
            .store_original(identity, b"one immutable proving DATA original")
            .unwrap();
        (temporary, private, identity)
    }

    #[test]
    fn first_target_selection_requires_current_pins_and_distinct_data_schema() {
        let (_temporary, private, identity) = original();
        let expected = pins(None);
        let root = private.path().parent().unwrap();
        let selection = |source| {
            norito::json!({
                "schema": SELECTION_SCHEMA, "source_pins": source,
                "sealed_originals": (locator(private.path())),
            })
        };
        let data = selection(expected.clone());
        let path = selected_originals(&data, SELECTION_SCHEMA, &expected, root).unwrap();
        DirectoryOriginalsV1::open_existing(path, 1024)
            .unwrap()
            .verify_original(identity)
            .unwrap();
        assert!(selected_locator(&data, &expected, root).is_err());
        assert!(
            selected_originals(
                &target(locator(private.path()), expected.clone()),
                SELECTION_SCHEMA,
                &expected,
                root,
            )
            .is_err()
        );
        for changed in SOURCE_PINS {
            assert!(
                selected_originals(
                    &selection(pins(Some(changed))),
                    SELECTION_SCHEMA,
                    &expected,
                    root
                )
                .is_err()
            );
        }
        for selected in [
            norito::json::Value::Null,
            norito::json!({ "schema": SELECTION_SCHEMA, "source_pins": (expected.clone()) }),
            norito::json!({ "schema": SELECTION_SCHEMA, "source_pins": (expected.clone()),
                "sealed_originals": { "schema": LOCATOR_SCHEMA, "path": "relative" } }),
        ] {
            assert!(selected_originals(&selected, SELECTION_SCHEMA, &expected, root).is_err());
        }
    }

    #[test]
    fn independently_selected_locator_reopens_the_same_sealed_inode_without_writes() {
        let (_temporary, private, identity) = original();
        let selected_pins = pins(None);
        let manifest = target(locator(private.path()), selected_pins.clone());
        let path =
            selected_locator(&manifest, &selected_pins, private.path().parent().unwrap()).unwrap();
        let name = hex::encode(identity.sha256);
        let before = private
            .open_retained_read_only(&name, 1024)
            .unwrap()
            .snapshot()
            .unwrap();
        for _ in 0..2 {
            let source = DirectoryOriginalsV1::open_existing(path, 1024).unwrap();
            source.verify_original(identity).unwrap();
            let mut reader = source.open_original(identity.sha256).unwrap();
            let mut actual = Vec::new();
            reader.read_to_end(&mut actual).unwrap();
            assert_eq!(actual, b"one immutable proving DATA original");
            drop(reader);
            drop(source);
            assert_eq!(
                private
                    .open_retained_read_only(&name, 1024)
                    .unwrap()
                    .snapshot()
                    .unwrap(),
                before,
                "fresh native readers retain the same inode, mode, link count and bytes"
            );
        }
        assert_eq!(fs::read_dir(private.path()).unwrap().count(), 1);
    }

    #[test]
    fn locator_refuses_every_foreign_source_pin_and_missing_or_outside_selection() {
        let (_temporary, private, _) = original();
        let selected = pins(None);
        let root = private.path().parent().unwrap();
        for changed in SOURCE_PINS {
            assert!(
                selected_locator(
                    &target(locator(private.path()), pins(Some(changed))),
                    &selected,
                    root,
                )
                .is_err()
            );
        }
        for location in [
            norito::json::Value::Null,
            norito::json!({ "schema": LOCATOR_SCHEMA, "path": "relative/originals" }),
            norito::json!({ "schema": "retired-locator", "path": (private.path().to_str().unwrap()) }),
            locator(root.parent().unwrap()),
        ] {
            assert!(
                selected_locator(&target(location, selected.clone()), &selected, root).is_err()
            );
        }
        let missing = norito::json!({ "schema": TARGET_SCHEMA, "source_pins": (selected.clone()) });
        assert!(selected_locator(&missing, &selected, root).is_err());
        let foreign = norito::json!({ "schema": "foreign-target", "source_pins": (selected.clone()), "sealed_originals": (locator(private.path())) });
        assert!(selected_locator(&foreign, &selected, root).is_err());
    }

    #[test]
    fn valid_locator_cannot_replace_missing_originals_with_an_admission_marker() {
        let temporary = tempfile::tempdir().unwrap();
        let private =
            iroha_fs::PrivateDirectory::open_or_create(temporary.path().join("originals")).unwrap();
        let selected = pins(None);
        let manifest = target(locator(private.path()), selected.clone());
        let path =
            selected_locator(&manifest, &selected, private.path().parent().unwrap()).unwrap();
        fs::write(
            private.path().join("engineering-source-acceptance.norito"),
            b"accepted",
        )
        .unwrap();
        let source = DirectoryOriginalsV1::open_existing(path, 1024).unwrap();
        assert!(
            source
                .verify_original(BlobV1::of(b"absent original"))
                .is_err()
        );
        assert!(
            !private
                .path()
                .join(hex::encode(BlobV1::of(b"absent original").sha256))
                .exists()
        );
    }

    #[cfg(unix)]
    #[test]
    fn selected_locator_does_not_relax_strict_original_custody_or_digest_checks() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        for fault in ["writable", "hardlink", "symlink", "changed"] {
            let (_temporary, private, identity) = original();
            let name = private.path().join(hex::encode(identity.sha256));
            match fault {
                "writable" => {
                    fs::set_permissions(&name, fs::Permissions::from_mode(0o600)).unwrap()
                }
                "hardlink" => fs::hard_link(&name, private.path().join("other-link")).unwrap(),
                "symlink" => {
                    let retained = private.path().join("retained-original");
                    fs::rename(&name, &retained).unwrap();
                    symlink(&retained, &name).unwrap();
                }
                "changed" => {
                    fs::set_permissions(&name, fs::Permissions::from_mode(0o600)).unwrap();
                    fs::write(&name, b"another immutable proving original").unwrap();
                    fs::set_permissions(&name, fs::Permissions::from_mode(0o400)).unwrap();
                }
                _ => unreachable!(),
            }
            let selected = pins(None);
            let manifest = target(locator(private.path()), selected.clone());
            let path =
                selected_locator(&manifest, &selected, private.path().parent().unwrap()).unwrap();
            let source = DirectoryOriginalsV1::open_existing(path, 1024).unwrap();
            assert!(source.verify_original(identity).is_err(), "{fault}");
        }
    }
}
