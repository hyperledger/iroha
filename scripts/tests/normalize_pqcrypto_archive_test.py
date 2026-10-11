"""Exact-byte trust and malformed-input tests for Apple pqcrypto archive normalization."""

from __future__ import annotations

import importlib.util
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "normalize_pqcrypto_archive.py"
SPEC = importlib.util.spec_from_file_location("normalize_pqcrypto_archive", SCRIPT)
assert SPEC and SPEC.loader
NORMALIZER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = NORMALIZER
SPEC.loader.exec_module(NORMALIZER)

MAGIC = b"!<arch>\n"
COMMON_NAMES = tuple(
    f"0123456789abcdef-{name}.o"
    for name in ("aes", "fips202", "sha2", "nistseedexpander", "sp800-185")
)
ARCH_NAMES = {
    "libkeccak2x.a": (
        "fedcba9876543210-fips202x2.o",
        "fedcba9876543210-feat.o",
    ),
    "libkeccak4x.a": ("fedcba9876543210-KeccakP-1600-times4-SIMD256.o",),
}


def raw_member(name: str, payload: bytes, *, bsd: bool = True, timestamp: int = 7) -> bytes:
    """Construct independent standard-ar fixtures, including BSD extended names."""
    name_bytes = name.encode("ascii")
    if bsd:
        header_name = f"#1/{len(name_bytes)}"
        body = name_bytes + payload
    else:
        assert len(name_bytes) <= 15
        header_name = name + "/"
        body = payload
    fields = (
        (header_name, 16),
        (str(timestamp), 12),
        ("12", 6),
        ("34", 6),
        ("100644", 8),
        (str(len(body)), 10),
    )
    header = b"".join(value.encode("ascii").ljust(width, b" ") for value, width in fields)
    assert len(header) == 58
    return header + b"`\n" + body + (b"\n" if len(body) % 2 else b"")


def payload(name: str) -> bytes:
    return b"object-bytes\x00" + name.encode("ascii") + b"\xff"


def reference_fixture(architecture: str = "libkeccak2x.a"):
    names = COMMON_NAMES + ARCH_NAMES[architecture]
    refs = {
        "libpqclean_common.a": MAGIC
        + raw_member("__.SYMDEF SORTED", b"trusted common symbols")
        + b"".join(raw_member(name, payload(name)) for name in COMMON_NAMES),
        architecture: MAGIC
        + b"".join(raw_member(name, payload(name)) for name in ARCH_NAMES[architecture]),
    }
    objects = [raw_member(name, payload(name)) for name in names]
    return refs, names, objects


@pytest.mark.parametrize("architecture", ARCH_NAMES)
def test_removes_only_second_trusted_objects_and_preserves_other_members(architecture):
    refs, names, objects = reference_fixture(architecture)
    unique_before = raw_member("first.o", b"untouched\x00odd", bsd=False, timestamp=11)
    unique_after = raw_member("unrelated-long-object-name.o", b"\x00\xfftail", timestamp=29)
    symbol_index = raw_member("__.SYMDEF SORTED", b"old offsets")
    repeated = [raw_member(name, payload(name), timestamp=99) for name in names]
    original = MAGIC + symbol_index + unique_before + b"".join(objects + repeated) + unique_after

    normalized, removed = NORMALIZER.normalize_archive_bytes(original, refs)

    assert normalized == MAGIC + unique_before + b"".join(objects) + unique_after
    assert len(removed) == len(names)
    assert set(removed) == set(names)
    assert NORMALIZER.normalize_archive_bytes(normalized, refs) == (normalized, [])


@pytest.mark.parametrize("architecture", ARCH_NAMES)
def test_already_normalized_archive_including_symbol_index_is_byte_unchanged(architecture):
    refs, _, objects = reference_fixture(architecture)
    original = MAGIC + raw_member("__.SYMDEF", b"keep these offsets", bsd=False) + b"".join(objects)
    assert NORMALIZER.normalize_archive_bytes(original, refs) == (original, [])


def test_identical_unknown_duplicate_is_rejected():
    refs, _, objects = reference_fixture()
    unrelated = raw_member("other.o", b"identical", bsd=False)
    with pytest.raises(ValueError, match="unknown duplicate"):
        NORMALIZER.normalize_archive_bytes(MAGIC + b"".join(objects) + unrelated * 2, refs)


@pytest.mark.parametrize("changed_copy", ["first", "second", "both"])
def test_trusted_name_never_authorizes_conflicting_payloads(changed_copy):
    refs, names, objects = reference_fixture()
    first = list(objects)
    if changed_copy in ("first", "both"):
        first[0] = raw_member(names[0], b"different object")
    repeated_payload = b"different object" if changed_copy in ("second", "both") else payload(names[0])
    original = MAGIC + b"".join(first) + raw_member(names[0], repeated_payload)
    with pytest.raises(ValueError):
        NORMALIZER.normalize_archive_bytes(original, refs)


def test_three_identical_trusted_copies_are_rejected():
    refs, _, objects = reference_fixture()
    with pytest.raises(ValueError, match="more than twice"):
        NORMALIZER.normalize_archive_bytes(MAGIC + b"".join(objects) + objects[0] * 2, refs)


def test_reference_payload_must_authenticate_both_input_copies():
    refs, names, objects = reference_fixture()
    refs["libpqclean_common.a"] = MAGIC + b"".join(
        raw_member(name, b"wrong reference" if name == names[0] else payload(name))
        for name in COMMON_NAMES
    )
    with pytest.raises(ValueError):
        NORMALIZER.normalize_archive_bytes(MAGIC + b"".join(objects) + objects[0], refs)


@pytest.mark.parametrize("defect", ["missing", "extra", "duplicate", "wrong_prefix"])
def test_reference_archive_inventory_is_exact(defect):
    refs, _, objects = reference_fixture()
    common = [raw_member(name, payload(name)) for name in COMMON_NAMES]
    if defect == "missing":
        common.pop()
    elif defect == "extra":
        common.append(raw_member("unexpected.o", b"extra", bsd=False))
    elif defect == "duplicate":
        common.append(common[0])
    else:
        common[0] = raw_member("wrong-aes.o", payload(COMMON_NAMES[0]))
    refs["libpqclean_common.a"] = MAGIC + b"".join(common)
    with pytest.raises(ValueError):
        NORMALIZER.normalize_archive_bytes(MAGIC + b"".join(objects) + objects[0], refs)


@pytest.mark.parametrize("defect", ["missing_common", "missing_architecture", "unknown", "both_architectures"])
def test_reference_archive_names_are_closed(defect):
    refs, _, objects = reference_fixture()
    if defect == "missing_common":
        del refs["libpqclean_common.a"]
    elif defect == "missing_architecture":
        del refs["libkeccak2x.a"]
    elif defect == "unknown":
        refs["other.a"] = refs["libkeccak2x.a"]
    else:
        other, _, _ = reference_fixture("libkeccak4x.a")
        refs["libkeccak4x.a"] = other["libkeccak4x.a"]
    with pytest.raises(ValueError):
        NORMALIZER.normalize_archive_bytes(MAGIC + b"".join(objects), refs)


def test_every_trusted_member_must_be_present_in_input():
    refs, _, objects = reference_fixture()
    with pytest.raises(ValueError):
        NORMALIZER.normalize_archive_bytes(MAGIC + b"".join(objects[:-1]), refs)


@pytest.mark.parametrize("defect", ["empty", "thin", "truncated_header", "truncated_body", "bad_trailer", "bad_size", "trailing_byte", "gnu_names"])
def test_malformed_input_archives_fail_closed(defect):
    refs, _, objects = reference_fixture()
    good = MAGIC + b"".join(objects)
    cases = {
        "empty": b"",
        "thin": b"!<thin>\n" + good[len(MAGIC):],
        "truncated_header": MAGIC + b"short",
        "truncated_body": good[:-2],
        "bad_trailer": good[:66] + b"??" + good[68:],
        "bad_size": good[:56] + b"not-a-size" + good[66:],
        "trailing_byte": good + b"x",
        "gnu_names": MAGIC + raw_member("/", b"unsupported GNU names", bsd=False) + b"".join(objects),
    }
    with pytest.raises(ValueError, match="archive"):
        NORMALIZER.normalize_archive_bytes(cases[defect], refs)


def test_malformed_reference_archive_fails_even_when_input_needs_no_normalization():
    refs, _, objects = reference_fixture()
    refs["libkeccak2x.a"] = b"not an archive"
    with pytest.raises(ValueError, match="archive"):
        NORMALIZER.normalize_archive_bytes(MAGIC + b"".join(objects), refs)


def cargo_fixture(build_dir: Path, suffix: str = "01234567"):
    refs, names, objects = reference_fixture()
    candidate = build_dir / f"pqcrypto-internals-{suffix}"
    out_dir = candidate / "out"
    out_dir.mkdir(parents=True)
    for name, data in refs.items():
        (out_dir / name).write_bytes(data)
    output = candidate / "output"
    output.write_text(
        f"cargo:rustc-link-search=native={out_dir.resolve()}\n"
        "cargo:rustc-link-lib=static=pqclean_common\n"
        "cargo:rustc-link-lib=static=keccak2x\n",
        encoding="utf-8",
    )
    return refs, names, objects, output



def cargo_context(build_dir: Path, output: Path):
    package = {
        "name": "pqcrypto-internals", "version": "0.2.11",
        "source": "registry+https://github.com/rust-lang/crates.io-index",
        "checksum": "ab" * 32,
    }
    messages = build_dir.parent / (build_dir.name + "-messages.jsonl")
    record = {
        "reason": "build-script-executed",
        "package_id": package["source"] + "#pqcrypto-internals@0.2.11",
        "out_dir": str(output.parent / "out"),
        "linked_libs": ["static=pqclean_common", "static=keccak2x"],
        "linked_paths": ["native=" + str(output.parent / "out")],
    }
    messages.write_text(json.dumps(record) + "\n" + json.dumps({"reason": "build-finished", "success": True}) + "\n")
    return messages, package


def test_cargo_reference_provenance_binds_recorded_search_path_and_file_hashes(tmp_path):
    refs, _, _, output = cargo_fixture(tmp_path)
    messages, package = cargo_context(tmp_path, output)
    actual, provenance = NORMALIZER.cargo_references(tmp_path, "aarch64-apple-ios", messages, package)
    assert actual == refs
    assert provenance["cargo_package_checksum"] == package["checksum"]
    assert provenance["cargo_build_output"] == str(output.resolve())
    assert provenance["cargo_build_output_sha256"] == hashlib.sha256(output.read_bytes()).hexdigest()
    for name, data in refs.items():
        assert provenance[name] == hashlib.sha256(data).hexdigest()


def test_cargo_reference_accepts_upstream_static_and_unqualified_link_directives(tmp_path):
    refs, _, _, output = cargo_fixture(tmp_path)
    messages, package = cargo_context(tmp_path, output)
    rows = [json.loads(line) for line in messages.read_text().splitlines()]
    rows[0]["linked_libs"].extend(["pqclean_common", "keccak2x"])
    messages.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
    output.write_text(output.read_text()
                      + "cargo:rustc-link-lib=pqclean_common\ncargo:rustc-link-lib=keccak2x\n")
    actual, _ = NORMALIZER.cargo_references(tmp_path, "aarch64-apple-ios", messages, package)
    assert actual == refs


@pytest.mark.parametrize("retained", ["none", "common_only", "backend_only", "all"])
def test_authentic_upstream_link_directives_never_prove_archive_member_custody(tmp_path, retained):
    # The current locked build genuinely emits both kinds. Provenance identifies
    # its reference bytes, but does not prove rustc bundled them in a staticlib.
    refs, _, objects, output = cargo_fixture(tmp_path)
    messages, package = cargo_context(tmp_path, output)
    rows = [json.loads(line) for line in messages.read_text().splitlines()]
    rows[0]["linked_libs"].extend(["pqclean_common", "keccak2x"])
    messages.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
    output.write_text(output.read_text()
                      + "cargo:rustc-link-lib=pqclean_common\ncargo:rustc-link-lib=keccak2x\n")
    authenticated, _ = NORMALIZER.cargo_references(
        tmp_path, "aarch64-apple-darwin", messages, package)
    assert authenticated == refs
    selected = {"none": [], "common_only": objects[:len(COMMON_NAMES)],
                "backend_only": objects[len(COMMON_NAMES):], "all": objects}[retained]
    original = MAGIC + raw_member("rust-only.o", b"original compiler object", bsd=False) + b"".join(selected)
    if retained == "all":
        # A complete single copy requires no edit, synthetic injection or duplicate.
        assert NORMALIZER.normalize_archive_bytes(original, authenticated) == (original, [])
    else:
        with pytest.raises(ValueError, match="missing an authenticated reference member"):
            NORMALIZER.normalize_archive_bytes(original, authenticated)


def test_two_matching_cargo_outputs_are_rejected(tmp_path):
    _, _, _, first = cargo_fixture(tmp_path, "0123")
    _, _, _, second = cargo_fixture(tmp_path, "abcd")
    messages, package = cargo_context(tmp_path, first)
    rows = [json.loads(line) for line in messages.read_text().splitlines()]
    other = dict(rows[0], out_dir=str(second.parent / "out"))
    messages.write_text("\n".join(json.dumps(row) for row in [rows[0], other, rows[1]]) + "\n")
    with pytest.raises(ValueError, match="exactly one"):
        NORMALIZER.cargo_references(tmp_path, "aarch64-apple-ios", messages, package)


@pytest.mark.parametrize("field,value", [
    ("name", "other"), ("version", "0.2.12"),
    ("source", "path+file:///vendor/pqcrypto-internals"),
    ("checksum", None), ("checksum", "not-a-checksum"),
])
def test_cargo_reference_requires_locked_registry_identity(tmp_path, field, value):
    _, _, _, output = cargo_fixture(tmp_path)
    messages, package = cargo_context(tmp_path, output)
    package[field] = value
    with pytest.raises(ValueError, match="locked registry"):
        NORMALIZER.cargo_references(tmp_path, "aarch64-apple-ios", messages, package)


@pytest.mark.parametrize("defect", ["different_search_path", "missing_common_link", "wrong_architecture_link"])
def test_cargo_reference_requires_its_exact_recorded_link_directives(tmp_path, defect):
    _, _, _, output = cargo_fixture(tmp_path)
    text = output.read_text()
    if defect == "different_search_path":
        text = text.replace(str(output.parent / "out"), str(tmp_path / "other"))
    elif defect == "missing_common_link":
        text = text.replace("cargo:rustc-link-lib=static=pqclean_common\n", "")
    else:
        text = text.replace("static=keccak2x", "static=keccak4x")
    output.write_text(text)
    messages, package = cargo_context(tmp_path, output)
    with pytest.raises(ValueError, match="link directives"):
        NORMALIZER.cargo_references(tmp_path, "aarch64-apple-ios", messages, package)


def test_cargo_reference_rejects_a_malformed_archive_inventory(tmp_path):
    _, _, _, output = cargo_fixture(tmp_path)
    (output.parent / "out" / "libpqclean_common.a").write_bytes(
        MAGIC + raw_member(COMMON_NAMES[0], payload(COMMON_NAMES[0]))
    )
    messages, package = cargo_context(tmp_path, output)
    with pytest.raises(ValueError, match="reference"):
        NORMALIZER.cargo_references(tmp_path, "aarch64-apple-ios", messages, package)


def test_read_regular_rejects_symbolic_provenance_files(tmp_path):
    source = tmp_path / "original.a"
    source.write_bytes(MAGIC)
    alias = tmp_path / "alias.a"
    alias.symlink_to(source)
    assert NORMALIZER.read_regular(source) == MAGIC
    with pytest.raises(ValueError, match="regular file"):
        NORMALIZER.read_regular(alias)


@pytest.mark.parametrize("version", ["0.2.10", "0.2.12"])
def test_cli_rejects_any_other_locked_pqcrypto_version_without_writing(tmp_path, version):
    _, _, objects, output = cargo_fixture(tmp_path / "build")
    messages, package = cargo_context(tmp_path / "build", output)
    original = MAGIC + b"".join(objects) + objects[0]
    library = tmp_path / "library.a"
    library.write_bytes(original)
    lock = tmp_path / "Cargo.lock"
    lock.write_text(f'[[package]]\nname = "pqcrypto-internals"\nversion = "{version}"\n')
    report = tmp_path / "report.json"
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--library", str(library),
         "--cargo-build-dir", str(tmp_path / "build"), "--target", "aarch64-apple-ios",
         "--cargo-messages", str(messages),
         "--cargo-lock", str(lock), "--report", str(report)],
        capture_output=True, text=True, check=False, timeout=10,
    )
    assert result.returncode == 1
    assert "locked pqcrypto-internals 0.2.11" in result.stderr
    assert library.read_bytes() == original
    assert not report.exists()


def test_cli_records_the_exact_authenticated_input_and_output(tmp_path):
    refs, names, objects, output = cargo_fixture(tmp_path / "build")
    messages, package = cargo_context(tmp_path / "build", output)
    original = MAGIC + b"".join(objects) + objects[0]
    library = tmp_path / "library.a"
    library.write_bytes(original)
    lock = tmp_path / "Cargo.lock"
    lock.write_text("[[package]]\n" + "".join(f'{key} = "{value}"\n' for key, value in package.items()))
    report = tmp_path / "report.json"
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--library", str(library),
         "--cargo-build-dir", str(tmp_path / "build"), "--target", "aarch64-apple-ios",
         "--cargo-messages", str(messages),
         "--cargo-lock", str(lock), "--report", str(report)],
        capture_output=True, text=True, check=False, timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert library.read_bytes() == MAGIC + b"".join(objects)
    record = json.loads(report.read_text())
    assert record["input_sha256"] == hashlib.sha256(original).hexdigest()
    assert record["unindexed_output_sha256"] == hashlib.sha256(library.read_bytes()).hexdigest()
    assert record["removed_identical_members"] == [names[0]]
    for name, data in refs.items():
        assert record["references"][name] == hashlib.sha256(data).hexdigest()


def test_current_cargo_selection_ignores_unselected_warm_cache_without_changing_it(tmp_path):
    _, _, _, old = cargo_fixture(tmp_path, "0123")
    refs, _, _, current = cargo_fixture(tmp_path, "abcd")
    _, _, _, unrelated = cargo_fixture(tmp_path, "ffff")
    # Even an invalid unselected old archive cannot override this invocation's selection.
    old_archive = old.parent / "out/libpqclean_common.a"
    old_archive.write_bytes(b"retained historical archive")
    before = {str(path): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    messages, package = cargo_context(tmp_path, current)
    actual, provenance = NORMALIZER.cargo_references(tmp_path, "aarch64-apple-ios", messages, package)
    assert actual == refs
    assert provenance["cargo_package_checksum"] == package["checksum"]
    assert provenance["cargo_build_output"] == str(current)
    assert provenance["cargo_package_id"] == package["source"] + "#pqcrypto-internals@0.2.11"
    for name, data in before.items():
        assert Path(name).read_bytes() == data
    assert unrelated.exists()


@pytest.mark.parametrize("defect", ["missing", "duplicate", "wrong_registry", "path_package", "wrong_target", "unsuccessful", "unfinished", "malformed_json", "wrong_link"])
def test_current_cargo_selection_rejects_missing_conflicting_or_foreign_records(tmp_path, defect):
    _, _, _, output = cargo_fixture(tmp_path)
    messages, package = cargo_context(tmp_path, output)
    rows = [json.loads(line) for line in messages.read_text().splitlines()]
    if defect == "missing": rows = rows[1:]
    elif defect == "duplicate": rows.insert(0, rows[0].copy())
    elif defect == "wrong_registry": rows[0]["package_id"] = rows[0]["package_id"].replace("crates.io-index", "foreign-index")
    elif defect == "path_package": rows[0]["package_id"] = "path+file:///vendor/pqcrypto-internals#pqcrypto-internals@0.2.11"
    elif defect == "wrong_target": rows[0]["out_dir"] = str(tmp_path.parent / "other-target/release/build/pqcrypto-internals-abcd/out")
    elif defect == "unsuccessful": rows[-1]["success"] = False
    elif defect == "unfinished": rows.pop()
    elif defect == "wrong_link": rows[0]["linked_paths"] = ["native=/other/build"]
    if defect == "malformed_json": messages.write_text("not Cargo JSON\n")
    else: messages.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
    with pytest.raises(ValueError):
        NORMALIZER.cargo_references(tmp_path, "aarch64-apple-ios", messages, package)


def test_current_cargo_selection_rejects_symlinked_output_directory(tmp_path):
    _, _, _, output = cargo_fixture(tmp_path)
    messages, package = cargo_context(tmp_path, output)
    original = output.parent / "out"
    moved = output.parent / "retained-out"
    original.rename(moved)
    original.symlink_to(moved, target_is_directory=True)
    with pytest.raises(ValueError, match="canonical"):
        NORMALIZER.cargo_references(tmp_path, "aarch64-apple-ios", messages, package)


@pytest.mark.parametrize("exit_code", [0, 73])
def test_actual_hermetic_builder_captures_current_messages_and_preserves_cargo_exit(tmp_path, exit_code):
    builder = (SCRIPT.parent / "build_norito_xcframework.sh").read_text()
    function = builder[builder.index("run_hermetic_apple_cargo() {"):builder.index('\nif [[ -n "$CI_ASSEMBLE_APPLE_SLICES" ]]; then', builder.index("run_hermetic_apple_cargo() {"))]
    script = tmp_path / "runner.sh"
    script.write_text("""set -e
STAGE_DIR="$1"
FIXTURE_EXIT="$2"
run_isolated_python() {
  printf '%s\\n' "$@" > "$STAGE_DIR/arguments.txt"
  printf '{"reason":"build-finished","success":true}\\n'
  return "$FIXTURE_EXIT"
}
assert_selected_cargo_lock() { :; }
""" + function + '\nrun_hermetic_apple_cargo apple-macos /sdk build --locked --offline --jobs 1 --target aarch64-apple-darwin\n')
    result = subprocess.run(["/bin/bash", str(script), str(tmp_path), str(exit_code)], capture_output=True, text=True, check=False, timeout=10)
    assert result.returncode == exit_code, result.stderr
    records = tmp_path / "cargo-messages/aarch64-apple-darwin.jsonl"
    assert json.loads(records.read_text()) == {"reason": "build-finished", "success": True}
    assert "--message-format=json-render-diagnostics" in (tmp_path / "arguments.txt").read_text().splitlines()


def test_current_cargo_selection_accepts_real_accelerator_prelude_and_binds_raw_bytes(tmp_path):
    refs, _, _, output = cargo_fixture(tmp_path)
    messages, package = cargo_context(tmp_path, output)
    prelude = "[cargo-fast] CARGO_BUILD_JOBS=cargo-default\n[cargo-fast] linker=system-default\n"
    raw = prelude + messages.read_text()
    messages.write_text(raw)
    actual, provenance = NORMALIZER.cargo_references(tmp_path, "aarch64-apple-ios", messages, package)
    assert actual == refs
    assert provenance["cargo_messages_sha256"] == hashlib.sha256(raw.encode()).hexdigest()
    assert provenance["cargo_build_output"] == str(output)


@pytest.mark.parametrize("defect", ["late_banner", "foreign_banner", "duplicate_member", "non_message", "duplicate_terminal"])
def test_current_cargo_selection_refuses_noise_or_ambiguous_json_even_with_accelerator_prelude(tmp_path, defect):
    _, _, _, output = cargo_fixture(tmp_path)
    messages, package = cargo_context(tmp_path, output)
    rows = messages.read_text().splitlines()
    if defect == "late_banner": rows.insert(1, "[cargo-fast] late diagnostics")
    elif defect == "foreign_banner": rows.insert(0, "[foreign-wrapper] ignored?")
    elif defect == "duplicate_member": rows[0] = rows[0].replace('"reason": "build-script-executed"', '"reason": "foreign", "reason": "build-script-executed"')
    elif defect == "non_message": rows.insert(0, '{}')
    elif defect == "duplicate_terminal": rows.append(rows[-1])
    messages.write_text("[cargo-fast] inert known prelude\n" + "\n".join(rows) + "\n")
    with pytest.raises(ValueError):
        NORMALIZER.cargo_references(tmp_path, "aarch64-apple-ios", messages, package)
