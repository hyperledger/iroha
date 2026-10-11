//! Focused semantic and public receipt tests for exact validator config retirement.
use super::*;

fn fixture(changed: bool) -> (json::Value, json::Value, json::Value) {
    let operation = format!("update-{}", "a".repeat(32));
    let plan = norito::json!({"operation":operation,"commit":("b".repeat(40)),"network_id":"network", "deployment":{"config_root":"/srv/taira","config_release":("c".repeat(40)),"config_filename":"beacon.toml"}});
    let mut prepared_rows = Vec::new();
    let mut installed_rows = Vec::new();
    for (index, role) in super::super::super::VALIDATOR_SLUGS.iter().enumerate() {
        let (source, staged, original) = config_paths(&plan, role).unwrap();
        let before = norito::json!([1, (10 + index), 33152, 0, 0, 1, 100, 1000, 1000]);
        let next = norito::json!([1, (20 + index), 33152, 0, 0, 1, 90, 2000, 2000]);
        let row = norito::json!({"role":(*role),"source_path":(source.to_string_lossy().into_owned()),"staged_path":(staged.to_string_lossy().into_owned()),"original_path":(original.to_string_lossy().into_owned()),"changed":changed,"source_sha256":("d".repeat(64)),"output_sha256":((if changed {"e"}else{"d"}).repeat(64)),"before_stamp":before,"staged_stamp":next});
        let mut installed = row.clone();
        let mut stamp = field(
            &row,
            if changed {
                "staged_stamp"
            } else {
                "before_stamp"
            },
        )
        .unwrap()
        .clone();
        if changed {
            *stamp.get_mut(8usize).unwrap() = norito::json!(3000);
        }
        installed
            .as_object_mut()
            .unwrap()
            .insert("installed_stamp".into(), stamp);
        prepared_rows.push(row);
        installed_rows.push(installed);
    }
    let receipt = |kind: &str, rows: Vec<json::Value>| norito::json!({"schema":(format!("{PREFIX}.{kind}.v1")),"operation":(text(&plan,"operation").unwrap()),"source_commit":(text(&plan,"commit").unwrap()),"network_id":"network","rows":rows});
    let prepared = receipt("prepared", prepared_rows);
    let installed = receipt("installed", installed_rows);
    (plan, prepared, installed)
}

#[test]
fn retirement_preserves_every_other_toml_value() {
    let original = b"private_key = 'untouched'\n[genesis]\nfile = '/private/genesis.signed'\n[sumeragi]\nrecords_dir = '/state/records'\n[zk]\nenable_verifiers = true\n[zk.halo2]\nk = 16\n[zk.stark]\nlimit = 7\n";
    let (projected, changed) = project(original).unwrap();
    assert!(changed);
    let mut expected: toml::Table = toml::from_str(std::str::from_utf8(original).unwrap()).unwrap();
    expected
        .get_mut("zk")
        .unwrap()
        .as_table_mut()
        .unwrap()
        .remove("halo2");
    let actual: toml::Table = toml::from_str(std::str::from_utf8(&projected).unwrap()).unwrap();
    assert_eq!(actual, expected);
    let (again, changed) = project(&projected).unwrap();
    assert!(!changed);
    assert_eq!(again.as_slice(), projected.as_slice());
}

#[test]
fn retirement_noop_preserves_exact_original_bytes() {
    for original in [
        b"# comment\n[zk]\nenable_verifiers = true\n".as_slice(),
        b"[sumeragi]\nrecords_dir = 'state'\n",
    ] {
        let (output, changed) = project(original).unwrap();
        assert!(!changed);
        assert_eq!(output.as_slice(), original);
    }
    let (output, changed) = project(b"[zk.halo2]\n").unwrap();
    assert!(changed);
    let table: toml::Table = toml::from_str(std::str::from_utf8(&output).unwrap()).unwrap();
    assert!(table["zk"].as_table().unwrap().is_empty());
}

#[test]
fn retirement_rejects_inherited_malformed_or_non_table_inputs() {
    for bytes in [
        b"extends = 'elsewhere'\n[zk.halo2]\n".as_slice(),
        b"profile = 'other'\n",
        b"zk = 9",
        b"[zk]\nhalo2 = 'not table'",
        b"bad = [",
        b"",
        &[255u8],
    ] {
        assert!(project(bytes).is_err());
    }
    assert!(project(&vec![b' '; LIMIT as usize + 1]).is_err());
}

#[test]
fn retirement_receipt_accepts_only_bound_inode_transition_and_true_noop() {
    for changed in [false, true] {
        let (plan, prepared, installed) = fixture(changed);
        validate_retirement_records(&prepared, &installed, &plan).unwrap();
        for key in ["operation", "source_commit", "network_id"] {
            let mut foreign = installed.clone();
            *foreign.get_mut(key).unwrap() = norito::json!("foreign");
            assert!(validate_retirement_records(&prepared, &foreign, &plan).is_err());
        }
        let mut foreign = installed.clone();
        *foreign
            .get_mut("rows")
            .unwrap()
            .get_mut(0usize)
            .unwrap()
            .get_mut("installed_stamp")
            .unwrap()
            .get_mut(1usize)
            .unwrap() = norito::json!(999);
        assert!(validate_retirement_records(&prepared, &foreign, &plan).is_err());
        let mut foreign = installed.clone();
        foreign
            .get_mut("rows")
            .unwrap()
            .get_mut(0usize)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), norito::json!(true));
        assert!(validate_retirement_records(&prepared, &foreign, &plan).is_err());
    }
}

#[test]
fn retirement_receipt_rejects_substituted_roles_paths_stamps_and_digests() {
    let (plan, prepared, installed) = fixture(true);
    for key in [
        "role",
        "source_path",
        "staged_path",
        "original_path",
        "source_sha256",
        "output_sha256",
    ] {
        let mut foreign = installed.clone();
        *foreign
            .get_mut("rows")
            .unwrap()
            .get_mut(0usize)
            .unwrap()
            .get_mut(key)
            .unwrap() = norito::json!("foreign");
        assert!(
            validate_retirement_records(&prepared, &foreign, &plan).is_err(),
            "{key}"
        );
    }
    for index in [0usize, 1, 2, 3, 4, 5, 6, 7] {
        let mut foreign = installed.clone();
        *foreign
            .get_mut("rows")
            .unwrap()
            .get_mut(0usize)
            .unwrap()
            .get_mut("installed_stamp")
            .unwrap()
            .get_mut(index)
            .unwrap() = norito::json!(999);
        assert!(
            validate_retirement_records(&prepared, &foreign, &plan).is_err(),
            "{index}"
        );
    }
    let mut foreign = installed.clone();
    foreign
        .get_mut("rows")
        .unwrap()
        .as_array_mut()
        .unwrap()
        .pop();
    assert!(validate_retirement_records(&prepared, &foreign, &plan).is_err());
}

#[test]
fn retirement_rename_allows_only_ctime_change() {
    let a = norito::json!([1, 2, 33152, 0, 0, 1, 100, 1000, 2000]);
    let b = norito::json!([1, 2, 33152, 0, 0, 1, 100, 1000, 3000]);
    assert!(same_renamed_file(&a, &b).unwrap());
    let mut b = b;
    *b.get_mut(7usize).unwrap() = norito::json!(999);
    assert!(!same_renamed_file(&a, &b).unwrap());
}
