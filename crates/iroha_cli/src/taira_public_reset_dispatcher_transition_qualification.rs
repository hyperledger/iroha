//! Join qualified checks or explicit unqualified builds with maintained transfer records.
// The root transaction runs on Linux only; other platforms compile these items solely for their
// unit tests, which do not reach every Linux entry point.
#![cfg_attr(all(test, not(target_os = "linux")), allow(dead_code))]
use super::*;
const NAMES: [&str; 4] = ["iroha3d_taira", "iroha", "sorafs-node", "kagami"];
const PACKAGES: [&str; 4] = ["irohad", "iroha_cli", "sorafs_node", "iroha_kagami"];
const BASE: &str = "commit signer_fingerprint native_check_scope native_incremental native_linker environment_sha256 native_environment_sha256 tree target profile jobs source_unchanged toolchain_unchanged source_snapshot_sha256 source_root source_output_target compiler_tools tools command release_qualified deployed";
fn fields(value: &Value, expected: impl IntoIterator<Item = String>) -> Result<()> {
    let actual = value
        .as_object()
        .ok_or_else(|| eyre!("record is not an object"))?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    need(
        actual == expected.into_iter().collect(),
        "producer record field set differs",
    )
}
pub(super) fn names(value: &Value, expected: &str) -> Result<()> {
    fields(value, expected.split_whitespace().map(str::to_owned))
}
fn number(value: &Value, key: &str) -> Result<u64> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| eyre!("missing unsigned {key}"))
}
fn array<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| eyre!("missing array {key}"))
}

pub(in super::super) fn validate_records(candidate: &Candidate, records: &[Value]) -> Result<()> {
    let [result, request, checks, binary, source, transfer, completed] = records else {
        return Err(eyre!("missing qualification records"));
    };
    fields(
        result,
        BASE.split_whitespace()
            .chain(["artifacts", "timings_seconds", "attempt"])
            .map(str::to_owned),
    )?;
    fields(
        request,
        BASE.split_whitespace()
            .chain(["schema", "repo_root", "target_dir"])
            .map(str::to_owned),
    )?;
    names(checks, "request passed")?;
    need(
        checks.get("request") == Some(request),
        "native checks request differs",
    )?;
    // Regression outcomes are evidence, not deployment authorization. The
    // owner-signed transition and native preflight/apply checks remain required.
    need(
        checks.get("passed").and_then(Value::as_bool).is_some(),
        "native checks outcome must be boolean",
    )?;
    need(
        text(request, "schema")? == "taira.local-preparation.v1",
        "qualification request schema differs",
    )?;
    for key in BASE.split_whitespace() {
        need(
            result.get(key) == request.get(key),
            "qualification base differs",
        )?;
    }
    need(
        linux_elf_machine(&candidate.revision.target).is_some(),
        "unsupported candidate Linux artifact target",
    )?;
    for (key, value) in [
        ("commit", candidate.commit.as_str()),
        ("tree", candidate.tree.as_str()),
        ("signer_fingerprint", candidate.signer_fingerprint.as_str()),
        ("target", candidate.revision.target.as_str()),
        ("profile", "release"),
    ] {
        need(
            text(result, key)? == value,
            "qualification identity differs",
        )?;
    }
    need(
        matches!(
            text(result, "native_check_scope")?,
            "basic" | "full" | "build-only"
        ) && number(result, "jobs")? > 0,
        "qualification scope differs",
    )?;
    for key in ["source_unchanged", "toolchain_unchanged"] {
        flag(result, key, true)?;
    }
    for key in ["release_qualified", "deployed"] {
        flag(result, key, false)?;
    }
    names(
        binary,
        "commit destination artifacts all_hashes_verified activated",
    )?;
    flag(binary, "all_hashes_verified", true)?;
    flag(binary, "activated", false)?;
    need(
        text(binary, "commit")? == candidate.commit,
        "binary revision differs",
    )?;
    names(
        source,
        "commit tree signer_fingerprint source_root clean signature_verified object_inventory_verified history_included runtime_files_transferred runtime_files_included activated sha256 size source_bytes file_count result_sha256",
    )?;
    for key in ["clean", "signature_verified", "object_inventory_verified"] {
        flag(source, key, true)?;
    }
    for key in [
        "history_included",
        "runtime_files_transferred",
        "runtime_files_included",
        "activated",
    ] {
        flag(source, key, false)?;
    }
    need(
        text(source, "commit")? == candidate.commit
            && text(source, "tree")? == candidate.tree
            && text(source, "signer_fingerprint")? == candidate.signer_fingerprint
            && text(source, "result_sha256")? == candidate.preparation.sha256,
        "source transfer identity differs",
    )?;
    let import = format!(
        "{RUNTIME}/release-import-{}-{}",
        candidate.commit, candidate.preparation.sha256
    );
    need(
        candidate.transfer_request.path == format!("{import}/request.json")
            && candidate.transfer_completed.path == format!("{import}/completed.json")
            && candidate.binary_transfer.path
                == format!("{import}/artifacts/verified-manifest.json")
            && candidate.source_transfer.path == format!("{import}/source/verified-manifest.json")
            && text(binary, "destination")? == format!("{import}/artifacts/bin")
            && text(source, "source_root")? == format!("{import}/source/source")
            && candidate.executable.path == format!("{import}/artifacts/bin/iroha"),
        "candidate escaped exact completed import",
    )?;
    names(
        transfer,
        "schema commit tree signer_fingerprint result_sha256 runtime_root rows allocation",
    )?;
    need(
        text(transfer, "schema")? == "taira.release-transfer.v1"
            && text(transfer, "commit")? == candidate.commit
            && text(transfer, "tree")? == candidate.tree
            && text(transfer, "signer_fingerprint")? == candidate.signer_fingerprint
            && text(transfer, "result_sha256")? == candidate.preparation.sha256
            && text(transfer, "runtime_root")? == RUNTIME,
        "transfer request differs",
    )?;
    // The completed record is the maintained producer boundary, not a new qualification claim.
    names(
        completed,
        "schema request_sha256 binary_transfer source_transfer activated",
    )?;
    need(
        text(completed, "schema")? == "taira.release-transfer.completed.v1"
            && text(completed, "request_sha256")? == candidate.transfer_request.sha256,
        "transfer completion does not bind request",
    )?;
    flag(completed, "activated", false)?;
    for (key, pin) in [
        ("binary_transfer", &candidate.binary_transfer),
        ("source_transfer", &candidate.source_transfer),
    ] {
        let reference = completed
            .get(key)
            .ok_or_else(|| eyre!("missing completed receipt"))?;
        names(reference, "path sha256")?;
        need(
            text(reference, "path")? == pin.path && text(reference, "sha256")? == pin.sha256,
            "completed receipt join differs",
        )?;
    }
    let attempt = text(result, "attempt")?;
    need(
        attempt.len() == 15
            && attempt.starts_with("attempts/")
            && attempt[9..].bytes().all(|b| b.is_ascii_digit()),
        "invalid preparation attempt",
    )?;
    for key in [
        "repo_root",
        "target_dir",
        "source_root",
        "source_output_target",
    ] {
        validate_absolute_normal_path(Path::new(text(request, key)?), "preparation origin")?;
    }
    need(
        request.get("source_output_target") == request.get("target_dir"),
        "preparation target origin differs",
    )?;
    let produced = array(result, "artifacts")?;
    let copied = array(binary, "artifacts")?;
    let transport = array(transfer, "rows")?;
    need(
        produced.len() == 4 && copied.len() == 4 && transport.len() == 10,
        "four transferred binary roles required",
    )?;
    let origin = Path::new(text(&produced[0], "path")?)
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .and_then(Path::parent)
        .ok_or_else(|| eyre!("artifact origin missing"))?;
    validate_absolute_normal_path(origin, "preparation output origin")?;
    for index in 0..4 {
        names(&produced[index], "name package path sha256 size")?;
        names(&copied[index], "name sha256 size")?;
        need(
            text(&produced[index], "name")? == NAMES[index]
                && text(&produced[index], "package")? == PACKAGES[index]
                && text(&copied[index], "name")? == NAMES[index]
                && copied[index] == transport[index],
            "binary role order differs",
        )?;
        need(
            Path::new(text(&produced[index], "path")?)
                == origin.join(attempt).join("bin").join(NAMES[index]),
            "artifact origin differs",
        )?;
        for key in ["size", "sha256"] {
            need(
                produced[index].get(key) == copied[index].get(key),
                "qualified/transferred binary differs",
            )?;
        }
        require_lower_sha256(text(&copied[index], "sha256")?, "artifact hash")?;
        need(
            number(&copied[index], "size")? >= 20 && number(&copied[index], "size")? <= MAX_BINARY,
            "binary size differs",
        )?;
    }
    for (index, name) in [(4, "source.pack"), (5, "source-capture.json")] {
        names(&transport[index], "name sha256 size")?;
        need(
            text(&transport[index], "name")? == name
                && number(&transport[index], "size")? > 0
                && number(&transport[index], "size")?
                    <= if index == 4 {
                        4 * 1024 * 1024 * 1024
                    } else {
                        64 * 1024 * 1024
                    },
            "source transport role differs",
        )?;
        require_lower_sha256(text(&transport[index], "sha256")?, "source transport hash")?;
    }
    need(
        source.get("sha256") == transport[4].get("sha256")
            && source.get("size") == transport[4].get("size"),
        "source pack receipt differs",
    )?;
    for (index, name, pin) in [
        (6, "preparation/result.json", &candidate.preparation),
        (7, "preparation/request.json", &candidate.request),
        (8, "preparation/checks.json", &candidate.checks),
        (9, "preparation/capture.json", &candidate.capture),
    ] {
        names(&transport[index], "name sha256 size")?;
        need(
            text(&transport[index], "name")? == name
                && pin.path == format!("{import}/{name}")
                && text(&transport[index], "sha256")? == pin.sha256
                && number(&transport[index], "size")? == pin.size
                && pin.size > 0
                && pin.size <= 16 * 1024 * 1024
                && pin.mode == 0o400,
            "preparation transport proof differs",
        )?;
    }
    need(
        candidate.capture.sha256 == candidate.preparation.sha256
            && candidate.capture.size == candidate.preparation.size,
        "capture transport differs from result",
    )?;
    let allocation = transfer
        .get("allocation")
        .ok_or_else(|| eyre!("allocation missing"))?;
    names(allocation, "bytes files directories")?;
    for key in ["bytes", "files", "directories"] {
        need(
            number(allocation, key)? > 0 && number(allocation, key)? < (1u64 << 50),
            "transfer allocation is invalid",
        )?;
    }
    need(
        number(allocation, "bytes")?
            >= transport
                .iter()
                .map(|row| number(row, "size"))
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .sum::<u64>(),
        "transfer allocation omits payload bytes",
    )?;
    need(
        text(&copied[1], "sha256")? == candidate.executable.sha256
            && number(&copied[1], "size")? == candidate.executable.size
            && candidate.executable.mode == 0o755,
        "candidate CLI differs from qualified import",
    )?;
    Ok(())
}

pub(super) fn admit(candidate: &Candidate) -> Result<Vec<Pin>> {
    validate_lower_hex("candidate commit", &candidate.commit, 40)?;
    validate_lower_hex("candidate tree", &candidate.tree, 40)?;
    need(
        matches!(candidate.signer_fingerprint.len(), 40 | 64)
            && candidate
                .signer_fingerprint
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b)),
        "full signer required",
    )?;
    need(
        crate::compiled_build_identity()?.release_source_commit()? == candidate.commit,
        "candidate is not this compiled CLI",
    )?;
    need(
        std::env::current_exe()? == Path::new(&candidate.executable.path),
        "run exact transferred CLI",
    )?;
    for p in [
        &candidate.preparation,
        &candidate.request,
        &candidate.checks,
        &candidate.capture,
        &candidate.binary_transfer,
        &candidate.source_transfer,
        &candidate.transfer_request,
        &candidate.transfer_completed,
    ] {
        need(p.mode == 0o400, "qualification evidence must be read-only")?;
    }
    let result = read(&candidate.preparation)?;
    need(
        read(&candidate.capture)? == result,
        "capture bytes differ from qualified result",
    )?;
    let records = [
        json::from_slice(&result)?,
        record(&candidate.request)?,
        record(&candidate.checks)?,
        record(&candidate.binary_transfer)?,
        record(&candidate.source_transfer)?,
        record(&candidate.transfer_request)?,
        record(&candidate.transfer_completed)?,
    ];
    validate_records(candidate, &records)?;
    let mut binaries = Vec::new();
    for row in array(&records[3], "artifacts")? {
        let value = Pin {
            path: format!(
                "{}/{}",
                text(&records[3], "destination")?,
                text(row, "name")?
            ),
            sha256: text(row, "sha256")?.into(),
            size: number(row, "size")?,
            mode: 0o755,
        };
        let (mut file, snapshot) = pin(&value, MAX_BINARY)?;
        file.rewind()?;
        let mut magic = [0; 20];
        file.read_exact(&mut magic)?;
        need(
            valid_elf(&magic, &candidate.revision.target),
            "transferred binary ELF differs from candidate target",
        )?;
        ensure_pinned_unchanged(
            Path::new(&value.path),
            "transferred binary",
            &file,
            &snapshot,
        )?;
        binaries.push(value);
    }
    Ok(binaries)
}

// Artifact policy only. Host-pair and revision admission still own execution authority.
fn linux_elf_machine(target: &str) -> Option<u16> {
    match target {
        "aarch64-unknown-linux-gnu" => Some(183),
        "x86_64-unknown-linux-gnu" => Some(62),
        _ => None,
    }
}

pub(in super::super) fn valid_elf(header: &[u8], target: &str) -> bool {
    linux_elf_machine(target).is_some()
        && header.len() >= 20
        && header[..7] == *b"\x7fELF\x02\x01\x01"
        && matches!(u16::from_le_bytes([header[16], header[17]]), 2 | 3)
        && Some(u16::from_le_bytes([header[18], header[19]])) == linux_elf_machine(target)
}
