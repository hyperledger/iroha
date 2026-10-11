//! Native CLI packaging contract tests; no build or validator is started.

use super::*;
use iroha_deploy::bootstrap::InstalledNetworkProfiles;
use std::io::Write as _;

#[test]
fn locked_build_selects_native_client_worker_and_daemon_without_gui_or_feature_changes() {
    for profile in ["debug", "release"] {
        let args = build_args(profile);
        assert_eq!(args[0], "build");
        assert!(args.iter().any(|arg| arg == "--locked"));
        for selected in [
            "iroha_cli",
            "iroha_kagami",
            "irohad",
            "iroha",
            "kagami",
            "iroha3d",
        ] {
            assert!(args.iter().any(|arg| arg == selected));
        }
        for forbidden in ["mochi", "mochi-ui", "--features", "--no-default-features"] {
            assert!(!args.iter().any(|arg| arg == forbidden));
        }
        assert_eq!(
            args.iter().any(|arg| arg == "--release"),
            profile == "release"
        );
    }
    assert!(validate_profile("local-release").is_err());
    assert!(validate_profile("../other").is_err());
}

fn source(root: &Path) -> BTreeMap<String, PathBuf> {
    let source = root.join("source");
    fs::create_dir(&source).unwrap();
    let mut programs = BTreeMap::new();
    // Unit format fixtures exercise admission only; these bytes never start a process.
    for program in PROGRAMS {
        let mut header = [0_u8; 128];
        match (env::consts::OS, env::consts::ARCH) {
            ("macos", arch) => {
                header[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
                let cpu: u32 = if arch == "aarch64" {
                    0x0100_000c
                } else {
                    0x0100_0007
                };
                header[4..8].copy_from_slice(&cpu.to_le_bytes());
                header[12..16].copy_from_slice(&2_u32.to_le_bytes());
            }
            ("linux", arch) => {
                header[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
                header[16..18].copy_from_slice(&2_u16.to_le_bytes());
                let cpu: u16 = if arch == "aarch64" { 183 } else { 62 };
                header[18..20].copy_from_slice(&cpu.to_le_bytes());
                header[24..32].copy_from_slice(&4096_u64.to_le_bytes());
            }
            ("windows", arch) => {
                header[..2].copy_from_slice(b"MZ");
                header[60..64].copy_from_slice(&64_u32.to_le_bytes());
                header[64..68].copy_from_slice(b"PE\0\0");
                let cpu: u16 = if arch == "aarch64" { 0xaa64 } else { 0x8664 };
                header[68..70].copy_from_slice(&cpu.to_le_bytes());
                header[86..88].copy_from_slice(&2_u16.to_le_bytes());
                header[88..90].copy_from_slice(&0x20b_u16.to_le_bytes());
            }
            _ => panic!("unsupported native test host"),
        }
        let path = source.join(format!("{program}{}", env::consts::EXE_SUFFIX));
        fs::write(&path, header).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        programs.insert(program.into(), path);
    }
    programs
}

#[test]
fn complete_cli_package_has_exact_runtime_profile_location_and_sorted_hash_inventory() {
    let temporary = tempfile::tempdir().unwrap();
    let source = source(temporary.path());
    let package = temporary.path().join("native-cli");
    let profiles =
        network_profiles::development(&InstalledNetworkProfiles::new(Vec::new()).unwrap()).unwrap();
    publish(&source, &package, "debug", Some(&profiles)).unwrap();
    let runtime = KagamiBundleLayout::runtime_directory(&package);
    let installed = InstalledRuntime::from_directory(&runtime).unwrap();
    assert_eq!(installed.network_profiles().unwrap().names().len(), 0);
    assert_eq!(
        KagamiBundleLayout::profiles_path(&package).parent(),
        Some(runtime.as_path())
    );
    assert!(!runtime.join("mochi").exists());
    assert!(!package.join("Mochi.app").exists());
    let manifest: Value =
        json::from_slice(&fs::read(package.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["network_profiles"], profiles.provenance());
    let files = manifest.get("files").unwrap().as_array().unwrap();
    assert_eq!(files.len(), 4);
    for program in PROGRAMS {
        assert!(files.iter().any(|file| {
            file.get("path").and_then(Value::as_str)
                == Some(format!("bin/{program}{}", env::consts::EXE_SUFFIX).as_str())
        }));
    }
    let mut previous = "";
    for file in files {
        let path = file.get("path").unwrap().as_str().unwrap();
        assert!(path > previous);
        assert_eq!(
            file.get("sha256").unwrap().as_str().unwrap(),
            digest(&mut RetainedFile::open_regular(package.join(path)).unwrap()).unwrap()
        );
        previous = path;
    }
    assert!(publish(&source, &package, "debug", None).is_err());
}

#[test]
fn cli_development_without_selected_profiles_keeps_installation_authority_absent() {
    let temporary = tempfile::tempdir().unwrap();
    let programs = source(temporary.path());
    let package = temporary.path().join("native-cli");
    publish(&programs, &package, "debug", None).unwrap();
    assert!(!KagamiBundleLayout::profiles_path(&package).exists());
    let runtime =
        InstalledRuntime::from_directory(&KagamiBundleLayout::runtime_directory(&package)).unwrap();
    assert!(runtime.network_profiles().is_err());
    let manifest: Value =
        json::from_slice(&fs::read(package.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["network_profiles"], Value::Null);
    let files = manifest["files"].as_array().unwrap();
    assert_eq!(files.len(), PROGRAMS.len());
    for program in PROGRAMS {
        assert!(files.iter().any(|file| {
            file["path"].as_str()
                == Some(format!("bin/{program}{}", env::consts::EXE_SUFFIX).as_str())
        }));
    }
}

#[test]
fn copying_programs_refuses_occupied_names_without_changing_their_bytes_or_custody() {
    for body in [b"".as_slice(), b"existing unpublished output".as_slice()] {
        let temporary = tempfile::tempdir().unwrap();
        let programs = source(temporary.path());
        let destination = temporary.path().join("occupied-program");
        let mut incumbent = RetainedFile::create_new_private(&destination).unwrap();
        incumbent.file_mut().write_all(body).unwrap();
        let incumbent = incumbent.seal().unwrap();
        drop(incumbent);
        let incumbent = RetainedFile::open_private(&destination).unwrap();
        let identity = incumbent.snapshot().unwrap();
        let mut input = RetainedFile::open_regular(programs.get("iroha").unwrap()).unwrap();
        let snapshot = input.snapshot().unwrap();
        let expected_hash = digest(&mut input).unwrap();
        assert!(copy_program(&mut input, snapshot, &expected_hash, &destination).is_err());
        incumbent.revalidate().unwrap();
        assert_eq!(incumbent.snapshot().unwrap(), identity);
        assert_eq!(fs::read(&destination).unwrap(), body);
        assert_eq!(
            RetainedFile::open_private(&destination)
                .unwrap()
                .snapshot()
                .unwrap(),
            identity
        );
    }
}

#[test]
fn packaging_refuses_missing_or_indirect_programs_before_creating_the_package() {
    for program in PROGRAMS {
        let temporary = tempfile::tempdir().unwrap();
        let source = source(temporary.path());
        let missing = source.get(program).unwrap();
        fs::remove_file(missing).unwrap();
        let package = temporary.path().join("native-cli");
        assert!(publish(&source, &package, "debug", None).is_err());
        assert!(!package.exists());
        #[cfg(unix)]
        {
            let substitute = PROGRAMS.into_iter().find(|name| *name != program).unwrap();
            std::os::unix::fs::symlink(source.get(substitute).unwrap(), missing).unwrap();
            assert!(publish(&source, &package, "debug", None).is_err());
            assert!(!package.exists());
        }
    }
}

#[test]
fn exact_cargo_records_ignore_sdk_library_and_refuse_missing_or_invalid_executables() {
    let record = |name: &str, path: &str, kind: &str| {
        Value::Object(Map::from([
            ("reason".into(), Value::String("compiler-artifact".into())),
            ("executable".into(), Value::String(path.into())),
            (
                "target".into(),
                Value::Object(Map::from([
                    ("name".into(), Value::String(name.into())),
                    (
                        "kind".into(),
                        Value::Array(vec![Value::String(kind.into())]),
                    ),
                ])),
            ),
        ]))
    };
    let read = |records: Vec<Value>| {
        let mut bytes = Vec::new();
        for record in records {
            bytes.extend(json::to_vec(&record).unwrap());
            bytes.push(b'\n');
        }
        collect_programs(io::Cursor::new(bytes))
    };
    let native_path = std::env::temp_dir().join("exact build/native/kagami");
    let daemon_path = std::env::temp_dir().join("other target/native/iroha3d");
    let client_path = std::env::temp_dir().join("client target/native/iroha");
    let native = record("kagami", native_path.to_str().unwrap(), "bin");
    let daemon = record("iroha3d", daemon_path.to_str().unwrap(), "bin");
    let client = record("iroha", client_path.to_str().unwrap(), "bin");
    let sdk_library = Value::Object(Map::from([
        ("reason".into(), Value::String("compiler-artifact".into())),
        ("executable".into(), Value::Null),
        (
            "target".into(),
            Value::Object(Map::from([
                ("name".into(), Value::String("iroha".into())),
                (
                    "kind".into(),
                    Value::Array(vec![Value::String("lib".into())]),
                ),
            ])),
        ),
    ]));
    let programs = read(vec![
        sdk_library.clone(),
        native.clone(),
        daemon.clone(),
        client.clone(),
    ])
    .unwrap();
    assert_eq!(programs.get("kagami").unwrap(), &native_path);
    assert_eq!(programs.get("iroha").unwrap(), &client_path);
    for records in [
        vec![native.clone()],
        vec![native.clone(), daemon.clone()],
        vec![sdk_library, native.clone(), daemon.clone()],
        vec![
            native.clone(),
            daemon.clone(),
            record("iroha", client_path.to_str().unwrap(), "lib"),
        ],
        vec![
            native.clone(),
            daemon.clone(),
            client.clone(),
            client.clone(),
        ],
        vec![
            native.clone(),
            native.clone(),
            daemon.clone(),
            client.clone(),
        ],
        vec![
            native.clone(),
            record("iroha3d", "relative/iroha3d", "bin"),
            client.clone(),
        ],
        vec![
            native.clone(),
            daemon.clone(),
            record("iroha", "relative/iroha", "bin"),
        ],
        vec![
            native.clone(),
            daemon.clone(),
            record("iroha", client_path.to_str().unwrap(), "test"),
        ],
        vec![
            native,
            record("iroha3d", daemon_path.to_str().unwrap(), "test"),
            client,
        ],
    ] {
        assert!(read(records).is_err());
    }
}

#[test]
fn nonexecutables_cross_host_and_multiple_link_inputs_fail_before_visibility() {
    let temporary = tempfile::tempdir().unwrap();
    let programs = source(temporary.path());
    let kagami = programs.get("kagami").unwrap();
    let original = fs::read(kagami).unwrap();
    let package = temporary.path().join("native-cli");
    fs::write(kagami, b"not an executable").unwrap();
    assert!(publish(&programs, &package, "debug", None).is_err());
    assert!(!package.exists());
    fs::write(kagami, &original).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(kagami, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(publish(&programs, &package, "debug", None).is_err());
        assert!(!package.exists());
        fs::set_permissions(kagami, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut cross_host = original.clone();
    cross_host[..4].fill(0);
    fs::write(kagami, cross_host).unwrap();
    assert!(publish(&programs, &package, "debug", None).is_err());
    assert!(!package.exists());
    fs::write(kagami, original).unwrap();
    fs::hard_link(kagami, temporary.path().join("shared-link")).unwrap();
    assert!(publish(&programs, &package, "debug", None).is_err());
    assert!(!package.exists());
}

#[test]
fn complete_staging_and_source_substitution_never_publish_a_partial_installation() {
    let temporary = tempfile::tempdir().unwrap();
    let programs = source(temporary.path());
    let package = temporary.path().join("native-cli");
    assert!(
        publish_checked(
            &programs,
            &package,
            "debug",
            None,
            &mut || {
                assert!(!package.exists());
                Err("injected failure before atomic publication".into())
            },
            &mut |_| Ok(())
        )
        .is_err()
    );
    assert!(!package.exists());
    assert!(
        publish_checked(
            &programs,
            &package,
            "debug",
            None,
            &mut || {
                let kagami = programs.get("kagami").unwrap();
                fs::rename(kagami, temporary.path().join("original-kagami"))?;
                fs::write(kagami, b"substituted source")?;
                Ok(())
            },
            &mut |_| Ok(())
        )
        .is_err()
    );
    assert!(!package.exists());
}

#[test]
fn complete_cli_publication_reopens_exact_native_outputs_after_the_directory_rename() {
    let temporary = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temporary.path()).unwrap();
    let programs = source(&root);
    let package = root.join("native-cli");
    let mut saw_complete_publication = false;
    publish_checked(
        &programs,
        &package,
        "debug",
        None,
        &mut || Ok(()),
        &mut |published| {
            saw_complete_publication = true;
            assert!(published.join("manifest.json").is_file());
            for name in PROGRAMS {
                assert_eq!(
                    fs::read(
                        KagamiBundleLayout::runtime_directory(published)
                            .join(format!("{name}{}", env::consts::EXE_SUFFIX))
                    )?,
                    fs::read(&programs[name])?
                );
            }
            Ok(())
        },
    )
    .unwrap();
    assert!(saw_complete_publication);
    InstalledRuntime::from_directory(&KagamiBundleLayout::runtime_directory(&package)).unwrap();
}

#[test]
fn atomic_cli_publication_refuses_a_new_destination_collision_without_state_loss() {
    let temporary = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temporary.path()).unwrap();
    let programs = source(&root);
    let package = root.join("occupied-native-cli");
    assert!(
        publish_checked(
            &programs,
            &package,
            "debug",
            None,
            &mut || {
                fs::create_dir(&package)?;
                fs::write(
                    package.join("previous-candidate"),
                    b"keep this exact candidate",
                )?;
                Ok(())
            },
            &mut |_| panic!("an occupied name must never reach published validation")
        )
        .is_err()
    );
    assert_eq!(
        fs::read(package.join("previous-candidate")).unwrap(),
        b"keep this exact candidate"
    );
    assert_eq!(fs::read_dir(&package).unwrap().count(), 1);
}

#[test]
fn equal_byte_substitution_after_cli_rename_refuses_a_success_result() {
    let temporary = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temporary.path()).unwrap();
    let programs = source(&root);
    let package = root.join("native-cli");
    let mut substituted = false;
    assert!(
        publish_checked(
            &programs,
            &package,
            "debug",
            None,
            &mut || Ok(()),
            &mut |published| {
                let output = KagamiBundleLayout::runtime_directory(published)
                    .join(format!("kagami{}", env::consts::EXE_SUFFIX));
                let bytes = fs::read(&output)?;
                fs::rename(&output, root.join("original-created-kagami"))?;
                fs::write(&output, bytes)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt as _;
                    fs::set_permissions(&output, fs::Permissions::from_mode(0o700))?;
                }
                substituted = true;
                Ok(())
            }
        )
        .is_err()
    );
    assert!(
        substituted,
        "the regression must reach actual post-rename substitution"
    );
    assert!(package.join("manifest.json").is_file());
}

#[test]
fn staged_program_profile_manifest_or_inventory_drift_refuses_atomic_publication() {
    for relative in [
        format!("bin/iroha{}", env::consts::EXE_SUFFIX),
        format!("bin/kagami{}", env::consts::EXE_SUFFIX),
        format!("bin/iroha3d{}", env::consts::EXE_SUFFIX),
        format!("bin/{}", iroha_deploy::bootstrap::NETWORK_PROFILES_FILENAME),
        "manifest.json".into(),
        "bin/uninventoried-file".into(),
    ] {
        let temporary = tempfile::tempdir().unwrap();
        let programs = source(temporary.path());
        let package = temporary.path().join("native-cli");
        let profiles =
            network_profiles::development(&InstalledNetworkProfiles::new(Vec::new()).unwrap())
                .unwrap();
        assert!(
            publish_checked(
                &programs,
                &package,
                "debug",
                Some(&profiles),
                &mut || {
                    assert!(!package.exists());
                    let staging = fs::read_dir(temporary.path())?
                        .map(|entry| entry.map(|entry| entry.path()))
                        .collect::<Result<Vec<_>, _>>()?
                        .into_iter()
                        .find(|path| {
                            path.file_name().is_some_and(|name| {
                                name.to_string_lossy().starts_with(".kagami-stage-")
                            })
                        })
                        .ok_or("private package staging is absent")?;
                    fs::write(
                        staging.join(&relative),
                        b"changed after completed validation",
                    )?;
                    Ok(())
                },
                &mut |_| Ok(())
            )
            .is_err(),
            "changed {relative} must not publish a stale inventory"
        );
        assert!(!package.exists());
    }
}

#[test]
fn occupied_cli_package_refuses_before_profile_selection_or_build() {
    for directory in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let output = root.path().join("output");
        fs::create_dir(&output).unwrap();
        let package = output.join(format!(
            "kagami-{}-{}-release",
            env::consts::OS,
            env::consts::ARCH,
        ));
        let retained = if directory {
            fs::create_dir(&package).unwrap();
            package.join("retained")
        } else {
            package.clone()
        };
        fs::write(&retained, b"original completed candidate").unwrap();
        let original_type = fs::symlink_metadata(&package).unwrap().file_type();
        for supplied in [None, Some(root.path().join("missing-profile-input"))] {
            // Neither missing release input may mask an already occupied destination.
            // The original source root has no release profile, so this never starts Cargo.
            let error =
                bundle_at(root.path(), &output, "release", supplied.as_deref()).unwrap_err();
            assert!(error.to_string().contains("CLI package already exists"));
            assert_eq!(
                fs::read(&retained).unwrap(),
                b"original completed candidate"
            );
            assert_eq!(
                fs::symlink_metadata(&package).unwrap().file_type(),
                original_type
            );
            assert_eq!(fs::read_dir(&output).unwrap().count(), 1);
            assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
        }
    }
}

#[cfg(unix)]
#[test]
fn broken_cli_package_link_refuses_before_profile_selection_or_build() {
    use std::os::unix::fs::{MetadataExt, symlink};

    let root = tempfile::tempdir().unwrap();
    let output = root.path().join("output");
    fs::create_dir(&output).unwrap();
    let package = output.join(format!(
        "kagami-{}-{}-release",
        env::consts::OS,
        env::consts::ARCH,
    ));
    let missing = root.path().join("uncreated-link-target");
    symlink(&missing, &package).unwrap();
    let original = fs::symlink_metadata(&package).unwrap();
    assert!(!package.try_exists().unwrap());
    let error = bundle_at(root.path(), &output, "release", None).unwrap_err();
    assert!(error.to_string().contains("CLI package already exists"));
    let retained = fs::symlink_metadata(&package).unwrap();
    assert!(retained.file_type().is_symlink());
    assert_eq!(retained.dev(), original.dev());
    assert_eq!(retained.ino(), original.ino());
    assert_eq!(fs::read_link(&package).unwrap(), missing);
    assert!(!missing.exists());
    assert_eq!(fs::read_dir(&output).unwrap().count(), 1);
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
}

#[test]
fn cli_release_selection_refuses_before_build_or_destination_mutation() {
    let root = tempfile::tempdir().unwrap();
    let output = root.path().join("output");
    fs::create_dir(&output).unwrap();
    let retained = output.join("kept");
    fs::write(&retained, b"original package").unwrap();
    let absent = root.path().join("not-created");
    for destination in [&output, &absent] {
        let error = bundle_at(root.path(), destination, "release", None).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("approved release-owned network profiles")
        );
        let error = bundle_at(
            root.path(),
            destination,
            "release",
            Some(Path::new("override.nrt")),
        )
        .unwrap_err();
        assert!(error.to_string().contains("development-only"));
    }
    assert!(!absent.exists());
    assert_eq!(fs::read(&retained).unwrap(), b"original package");
    assert_eq!(fs::read_dir(&output).unwrap().count(), 1);
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);

    // Even the private publication owner cannot relabel development selection as a release.
    // No source program is read or output parent created before this rejection.
    let development =
        network_profiles::development(&InstalledNetworkProfiles::new(Vec::new()).unwrap()).unwrap();
    for selection in [None, Some(&development)] {
        assert!(
            publish(
                &BTreeMap::new(),
                &absent.join("package"),
                "release",
                selection
            )
            .unwrap_err()
            .to_string()
            .contains("release-owned Taira profile")
        );
        assert!(!absent.exists());
    }
}

#[test]
fn cli_development_preserves_exact_selected_image_and_shared_provenance() {
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_deploy::bootstrap::InstalledNetworkProfile;

    let root = tempfile::tempdir().unwrap();
    let programs = source(root.path());
    let supplied = root.path().join("fixture.nrt");
    // Deliberately a fixture network, never a source of official Taira authority.
    let image = InstalledNetworkProfiles::new(vec![
        InstalledNetworkProfile::new(
            "fixture".into(),
            KeyPair::from_seed(vec![29; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
            11,
            "https://fixture.invalid/checkpoint.nrt".into(),
        )
        .unwrap(),
    ])
    .unwrap()
    .encode_installation()
    .unwrap();
    fs::write(&supplied, &image).unwrap();
    let selected = network_profiles::select(root.path(), "debug", Some(&supplied))
        .unwrap()
        .unwrap();
    assert_eq!(selected.bytes(), image.as_slice());
    // A changed source cannot substitute for the retained original selection during publication.
    fs::write(&supplied, b"changed after selection").unwrap();
    let package = root.path().join("native-cli");
    publish(&programs, &package, "debug", Some(&selected)).unwrap();
    let path = KagamiBundleLayout::profiles_path(&package);
    selected.verify_installed(&path).unwrap();
    assert_eq!(fs::read(&path).unwrap(), image);
    let manifest: Value =
        json::from_slice(&fs::read(package.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["network_profiles"], selected.provenance());
    assert_eq!(
        manifest["network_profiles"]["kind"].as_str(),
        Some("explicit_development_input")
    );
    assert_eq!(manifest["network_profiles"]["source_commit"], Value::Null);
    assert_eq!(
        manifest["network_profiles"]["sha256"].as_str(),
        Some(hex::encode(Sha256::digest(&image)).as_str())
    );
    let runtime =
        InstalledRuntime::from_directory(&KagamiBundleLayout::runtime_directory(&package)).unwrap();
    assert_eq!(
        runtime
            .network_profiles()
            .unwrap()
            .names()
            .collect::<Vec<_>>(),
        vec!["fixture"]
    );
    fs::write(&path, b"substituted installed profile").unwrap();
    assert!(selected.verify_installed(&path).is_err());
    fs::remove_file(&path).unwrap();
    assert!(selected.verify_installed(&path).is_err());
    assert!(!path.exists());
}

#[test]
fn exact_cargo_hardlink_inputs_publish_private_single_link_runtime_copies() {
    let temporary = tempfile::tempdir().unwrap();
    let programs = source(temporary.path());
    let mut records = Vec::new();
    for (name, path) in &programs {
        let alias = path.with_extension("cargo-dependency-link");
        fs::hard_link(path, &alias).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(fs::metadata(path).unwrap().nlink(), 2);
        }
        assert!(RetainedFile::open_regular(path).is_err());
        let record = Value::Object(Map::from([
            ("reason".into(), Value::String("compiler-artifact".into())),
            (
                "target".into(),
                Value::Object(Map::from([
                    ("name".into(), Value::String(name.clone())),
                    (
                        "kind".into(),
                        Value::Array(vec![Value::String("bin".into())]),
                    ),
                ])),
            ),
            (
                "executable".into(),
                Value::String(path.to_str().unwrap().into()),
            ),
        ]));
        records.extend(json::to_vec(&record).unwrap());
        records.push(b'\n');
    }
    let actual = collect_programs(io::Cursor::new(records)).unwrap();
    assert_eq!(actual, programs);
    let package = temporary.path().join("cargo-cli");
    // The existing ordinary input route continues to refuse shared source custody.
    assert!(publish(&actual, &package, "debug", None).is_err());
    assert!(!package.exists());
    publish_cargo(&actual, &package, "debug", None).unwrap();
    for (name, path) in &programs {
        let output = package
            .join("bin")
            .join(format!("{name}{}", env::consts::EXE_SUFFIX));
        assert_eq!(fs::read(&output).unwrap(), fs::read(path).unwrap());
        let mut strict_output = RetainedFile::open_regular(&output).unwrap();
        assert_eq!(
            digest(&mut strict_output).unwrap(),
            hex::encode(Sha256::digest(fs::read(path).unwrap()))
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(fs::metadata(&output).unwrap().nlink(), 1);
            assert_eq!(fs::metadata(path).unwrap().nlink(), 2);
        }
        assert!(path.with_extension("cargo-dependency-link").is_file());
    }
    assert!(InstalledRuntime::from_directory(&package.join("bin")).is_ok());
    let manifest: Value =
        json::from_slice(&fs::read(package.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["files"].as_array().unwrap().len(), PROGRAMS.len());
}

#[test]
fn cargo_input_role_requires_exact_absolute_three_program_geometry() {
    let temporary = tempfile::tempdir().unwrap();
    let programs = source(temporary.path());
    for attack in ["missing", "extra", "relative"] {
        let mut malformed = programs.clone();
        match attack {
            "missing" => {
                malformed.remove("kagami");
            }
            "extra" => {
                malformed.insert("other".into(), programs["kagami"].clone());
            }
            "relative" => {
                malformed.insert("kagami".into(), PathBuf::from("kagami"));
            }
            _ => unreachable!(),
        }
        let package = temporary.path().join(attack);
        assert!(publish_cargo(&malformed, &package, "debug", None).is_err());
        assert!(!package.exists());
    }
    publish_cargo(&programs, &temporary.path().join("retry"), "debug", None).unwrap();
}

#[cfg(unix)]
struct AliasMutationInput {
    original: RetainedBuildInput,
    alias: PathBuf,
    replacement: Vec<u8>,
    read_bytes: usize,
    mutated: bool,
}

#[cfg(unix)]
impl Read for AliasMutationInput {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let count = self.original.read(bytes)?;
        self.read_bytes += count;
        if count > 0 && !self.mutated {
            fs::write(&self.alias, &self.replacement)?;
            self.mutated = true;
        }
        Ok(count)
    }
}

#[cfg(unix)]
impl Seek for AliasMutationInput {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.original.seek(position)
    }
}

#[cfg(unix)]
impl NativeInput for AliasMutationInput {
    fn reader(&mut self) -> &mut dyn InputReader {
        self
    }
    fn length(&self) -> io::Result<u64> {
        self.original.len()
    }
    fn snapshot(&self) -> io::Result<FileSnapshot> {
        self.original.snapshot()
    }
    fn revalidate(&self) -> io::Result<()> {
        self.original.revalidate()
    }
}

#[cfg(unix)]
#[test]
fn real_alias_mutation_during_private_copy_refuses_the_original_and_restored_capture_retries() {
    use std::os::unix::fs::MetadataExt;
    let temporary = tempfile::tempdir().unwrap();
    let programs = source(temporary.path());
    let path = &programs["kagami"];
    let identity = fs::metadata(path).unwrap().ino();
    let bytes = fs::read(path).unwrap();
    let alias = path.with_extension("cargo-dependency-link");
    fs::hard_link(path, &alias).unwrap();
    let mut changed = bytes.clone();
    *changed.last_mut().unwrap() ^= 1;
    let mut input = AliasMutationInput {
        original: RetainedBuildInput::open(path).unwrap(),
        alias: alias.clone(),
        replacement: changed.clone(),
        read_bytes: 0,
        mutated: false,
    };
    let before = input.snapshot().unwrap();
    let hash = hex::encode(Sha256::digest(&bytes));
    let destination = temporary.path().join("private-copy");
    assert!(copy_program(&mut input, before, &hash, &destination).is_err());
    assert!(input.mutated);
    assert_eq!(input.read_bytes, bytes.len());
    assert_eq!(fs::read(&alias).unwrap(), changed);
    assert!(input.original.revalidate().is_err());
    assert_eq!(fs::metadata(path).unwrap().ino(), identity);
    drop(input);
    fs::write(&alias, &bytes).unwrap();
    let mut retry = RetainedBuildInput::open(path).unwrap();
    let before = retry.snapshot().unwrap();
    let output = temporary.path().join("retry-copy");
    let (file, _, copied_hash, _) = copy_program(&mut retry, before, &hash, &output).unwrap();
    assert_eq!(copied_hash, hash);
    assert_eq!(fs::read(&output).unwrap(), bytes);
    file.revalidate().unwrap();
    assert_eq!(fs::metadata(&output).unwrap().nlink(), 1);
    assert_eq!(fs::metadata(path).unwrap().nlink(), 2);
}

#[cfg(unix)]
#[test]
fn linked_input_hashing_is_bounded_when_real_alias_growth_occurs_after_read() {
    let temporary = tempfile::tempdir().unwrap();
    let programs = source(temporary.path());
    let path = &programs["kagami"];
    let bytes = fs::read(path).unwrap();
    let alias = path.with_extension("cargo-dependency-link");
    fs::hard_link(path, &alias).unwrap();
    let mut grown = bytes.clone();
    grown.extend_from_slice(&[0; 1024]);
    let mut input = AliasMutationInput {
        original: RetainedBuildInput::open(path).unwrap(),
        alias: alias.clone(),
        replacement: grown,
        read_bytes: 0,
        mutated: false,
    };
    let error = digest(&mut input).unwrap_err();
    assert!(error.to_string().contains("extent changed during hashing"));
    assert!(input.mutated);
    assert_eq!(input.read_bytes, bytes.len() + 1);
    assert!(input.original.revalidate().is_err());
    drop(input);
    fs::write(alias, &bytes).unwrap();
    let mut retry = RetainedBuildInput::open(path).unwrap();
    assert_eq!(
        digest(&mut retry).unwrap(),
        hex::encode(Sha256::digest(bytes))
    );
}

#[cfg(unix)]
#[test]
fn cargo_source_owner_survives_private_copy_until_atomic_publication_checks() {
    use std::os::unix::fs::MetadataExt;
    let temporary = tempfile::tempdir().unwrap();
    let programs = source(temporary.path());
    let path = &programs["kagami"];
    let original = fs::read(path).unwrap();
    let identity = fs::metadata(path).unwrap().ino();
    let alias = path.with_extension("cargo-dependency-link");
    fs::hard_link(path, &alias).unwrap();
    let package = temporary.path().join("cargo-cli");
    let mut mutated_after_copy = false;
    assert!(
        publish_inputs(
            &programs,
            &package,
            "debug",
            None,
            ProgramKind::Cargo,
            &mut || {
                assert!(!package.exists());
                fs::write(&alias, b"changed after complete private copying")?;
                mutated_after_copy = true;
                Ok(())
            },
            &mut |_| panic!("changed source must not reach atomic visibility"),
        )
        .is_err()
    );
    assert!(mutated_after_copy);
    assert!(!package.exists());
    assert_eq!(
        fs::read(&alias).unwrap(),
        b"changed after complete private copying"
    );
    assert_eq!(fs::metadata(path).unwrap().ino(), identity);
    fs::write(&alias, original).unwrap();
    publish_cargo(&programs, &package, "debug", None).unwrap();
    assert_eq!(fs::metadata(path).unwrap().ino(), identity);
    assert_eq!(fs::metadata(path).unwrap().nlink(), 2);
}
