"""Fail-closed coverage for compiled Kotlin ownership and exact JNI linkage.

The module also pins the first-release KAGEMUSHA SDK package surface from
repository sources: Kotlin and Swift keep only the wallet V1 files, and
JavaScript and C# ship no old KAGEMUSHA facade.
"""

from __future__ import annotations

import importlib.util
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "check_kotlin_jni.py"
SPEC = importlib.util.spec_from_file_location("check_kotlin_jni", SCRIPT)
assert SPEC and SPEC.loader
GUARD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GUARD
SPEC.loader.exec_module(GUARD)
JVM = GUARD.JVM
SDK = GUARD.SDK_PACKAGE
PRIVACY = SDK + "privacy/PrivacyNativeBridge"
SIGNER = SDK + "crypto/NativeSignerBridge"
CODEC = SDK + "tx/norito/NoritoJavaCodecAdapter"


def class_bytes(name, methods=(), *, major=52, source="Fixture.kt", extra_utf8=()):
    """Build small declaration fixtures; javac supplies the independent oracle below."""
    pool = []

    def utf8(value):
        raw = value.encode("utf-8", "surrogatepass").replace(b"\0", b"\xc0\x80")
        pool.append(b"\x01" + struct.pack(">H", len(raw)) + raw)
        return len(pool)

    def class_entry(value):
        index = utf8(value)
        pool.append(b"\x07" + struct.pack(">H", index))
        return len(pool)

    owner, parent = class_entry(name), class_entry("java/lang/Object")
    rendered = []
    for method in methods:
        rendered.append(struct.pack(">HHHH", method.flags, utf8(method.name), utf8(method.descriptor), 0))
    attributes = []
    if source is not None:
        attributes.append(struct.pack(">HIH", utf8("SourceFile"), 2, utf8(source)))
    for value in extra_utf8:
        utf8(value)
    return (
        struct.pack(">IHHH", 0xCAFEBABE, 0, major, len(pool) + 1) + b"".join(pool)
        + struct.pack(">HHHHHH", 0x0421, owner, parent, 0, 0, len(rendered))
        + b"".join(rendered) + struct.pack(">H", len(attributes)) + b"".join(attributes)
    )


def native(name, descriptor):
    return JVM.Method(name, descriptor, JVM.ACC_NATIVE | JVM.ACC_STATIC | 2)


def release_methods():
    return {
        CODEC: (JVM.Method("<init>", "(I)V", JVM.ACC_PUBLIC),),
        PRIVACY: (
            native("nativeValidateCompiledProfileCatalog", "([B)I"),
            native("nativeExact12FixtureBundle", "()[B"),
            native("nativeValidateExact12FixtureBundle", "([B)I"),
            native("nativeValidateExact12CapabilityManifestForNetworkV1", "([B[B)I"),
            native("nativeRequireExact12CapabilityTupleForNetworkV1", "([BI[B)Z"),
            native("nativeValidateExact12SubmitProofConstructionForNetworkV1", "([BI[B[B)Z"),
        ),
        SIGNER: (
            JVM.Method("encodeRegisterZkAssetSignedTransaction",
                       "(IL" + SDK + "core/model/NetworkId;I)V", JVM.ACC_PUBLIC | JVM.ACC_STATIC),
            native("nativeEncodeRegisterZkAssetSignedTransaction", "(I[BI)V"),
            native("nativeValidateAccountAddressCanonical", "([B)[B"),
        ),
    }


def build_outputs(tmp_path):
    roots = {module: [tmp_path / module] for module in GUARD.MODULES}
    for module, paths in roots.items():
        owner = SDK + "fixture/" + module.replace("-", "_")
        path = paths[0] / (owner + ".class")
        path.parent.mkdir(parents=True)
        path.write_bytes(class_bytes(owner))
    for owner, methods in release_methods().items():
        path = roots["core-jvm"][0] / (owner + ".class")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(class_bytes(owner, methods))
    return roots


def test_parser_reads_javac_headers_without_loading_classes(tmp_path):
    javac = shutil.which("javac")
    if javac is None:
        pytest.skip("JDK compiler is required for the independent classfile/header oracle")
    source = tmp_path / "NativeOracle.java"
    source.write_text('''package oracle;
public class NativeOracle {
  public static final String UNUSED = "\\u0000\\ud83d\\ude80";
  public native long overloaded(int value);
  public native long overloaded(byte[][] value);
  public static native void under_score(String value);
  public void under_score(int value) {}
  public static class Nested { public native byte[] call(); }
}
''', encoding="utf-8")
    subprocess.run([javac, "--release", "8", "-h", str(tmp_path), "-d", str(tmp_path), str(source)],
                   check=True, capture_output=True, timeout=60)
    outer = JVM.parse_class((tmp_path / "oracle/NativeOracle.class").read_bytes())
    nested = JVM.parse_class((tmp_path / "oracle/NativeOracle$Nested.class").read_bytes())
    assert outer.major == nested.major == 52
    assert outer.source_file == "NativeOracle.java"
    assert not [method for method in outer.methods if method.name == "<init>"][0].native
    operations = GUARD.native_operations(outer) + GUARD.native_operations(nested)
    headers = "\n".join(path.read_text() for path in tmp_path.glob("*.h"))
    assert len(operations) == 4
    for operation in operations:
        assert operation["symbol"] + "\n" in headers
    assert {operation["symbol"] for operation in operations} == {
        "Java_oracle_NativeOracle_overloaded__I",
        "Java_oracle_NativeOracle_overloaded___3_3B",
        "Java_oracle_NativeOracle_under_1score",
        "Java_oracle_NativeOracle_00024Nested_call",
    }
    assert [operation["static"] for operation in operations] == [False, False, True, False]


@pytest.fixture(scope="module")
def compiled_inheritance(tmp_path_factory):
    """Use javac as an independent parent-metadata oracle without loading classes."""
    javac = shutil.which("javac")
    if javac is None:
        pytest.skip("JDK compiler is required for the independent inheritance oracle")
    root = tmp_path_factory.mktemp("classfile-inheritance")
    source = root / "InheritanceOracle.java"
    source.write_text("""package oracle;
interface ApiParent { void interfaceCall(); }
class SuperParent { public void parentCall() {} }
public abstract class InheritanceOracle extends SuperParent implements ApiParent {}
""", encoding="utf-8")
    subprocess.run([javac, "--release", "8", "-d", str(root), str(source)],
                   check=True, capture_output=True, timeout=60)
    return root


def test_parser_preserves_actual_javac_superclass_and_interfaces(compiled_inheritance):
    child = JVM.parse_class((compiled_inheritance / "oracle/InheritanceOracle.class").read_bytes())
    parent = JVM.parse_class((compiled_inheritance / "oracle/SuperParent.class").read_bytes())
    interface = JVM.parse_class((compiled_inheritance / "oracle/ApiParent.class").read_bytes())
    assert child.major == parent.major == interface.major == 52
    assert child.super_name == parent.name == "oracle/SuperParent"
    assert child.interfaces == (interface.name,) == ("oracle/ApiParent",)
    assert parent.methods[-1].name == "parentCall"
    assert interface.methods[-1].name == "interfaceCall"
    assert parent.methods[-1].flags & JVM.ACC_PUBLIC
    assert interface.methods[-1].flags & JVM.ACC_PUBLIC


@pytest.mark.parametrize("parent", [b"oracle/SuperParent", b"oracle/ApiParent"])
def test_parser_rejects_parent_name_path_escape(compiled_inheritance, parent):
    raw = (compiled_inheritance / "oracle/InheritanceOracle.class").read_bytes()
    assert raw.count(parent) == 1
    raw = raw.replace(parent, parent.replace(b"oracle/", b"or..le/"))
    with pytest.raises(JVM.ClassFileError, match="parent class name"):
        JVM.parse_class(raw)


def test_parser_rejects_every_truncation_and_trailing_data():
    raw = class_bytes("sdk/Fixture", [native("call", "([B)J")])
    assert JVM.parse_class(raw).methods[0].descriptor == "([B)J"
    for end in range(len(raw)):
        with pytest.raises(JVM.ClassFileError):
            JVM.parse_class(raw[:end])
    with pytest.raises(JVM.ClassFileError, match="trailing"):
        JVM.parse_class(raw + b"x")
    with pytest.raises(JVM.ClassFileError, match="byte limit"):
        JVM.parse_class(b"x" * (JVM.MAX_CLASS_BYTES + 1))


def test_parser_rejects_ambiguous_native_declarations():
    method = native("call", "()V")
    with pytest.raises(JVM.ClassFileError, match="duplicate method"):
        JVM.parse_class(class_bytes("sdk/F", [method, method]))
    with pytest.raises(JVM.ClassFileError, match="incompatible"):
        JVM.parse_class(class_bytes("sdk/F", [native("<init>", "()V")]))
    with pytest.raises(JVM.ClassFileError, match="incompatible"):
        JVM.parse_class(class_bytes("sdk/F", [JVM.Method("call", "()V", JVM.ACC_NATIVE | JVM.ACC_ABSTRACT)]))
    malformed = bytearray(class_bytes("sdk/F"))
    malformed[10] = 99
    with pytest.raises(JVM.ClassFileError, match="constant-pool tag"):
        JVM.parse_class(bytes(malformed))


@pytest.mark.parametrize("descriptor", ["", "I", "(V)V", "([V)V", "([)V", "()", "()VV", "(L;)V", "(Lx)V", "(Lx//y;)V", "(" + "I" * 256 + ")V", "(" + "[" * 256 + "B)V"])
def test_invalid_method_descriptors_fail(descriptor):
    with pytest.raises(JVM.ClassFileError):
        JVM.method_descriptor(descriptor)


def test_modified_utf8_and_jni_mangling_handle_utf16():
    declaration = JVM.parse_class(class_bytes("sdk/\ud83d\ude80", extra_utf8=("unused\0", "\ud800")))
    assert declaration.name == "sdk/🚀"
    assert GUARD.jni_escape(declaration.name + "$_[;") == "sdk__0d83d_0de80_00024_1_3_2"


@pytest.mark.parametrize("precursor", ["0method", "1class", "2method", "3method", "sdk/0Native", "[Lsdk/2Native;"])
def test_jni_escape_rejects_unresolvable_precursor_names(precursor):
    with pytest.raises(GUARD.AuditError, match="cannot be resolved"):
        GUARD.jni_escape(precursor)
    assert GUARD.jni_escape("_1method") == "_11method"


def test_scan_and_exact_exports_cover_all_modules(tmp_path):
    roots = build_outputs(tmp_path)
    classes, records = GUARD.scan_classes(roots)
    assert len(classes) == len(records) == 6
    assert {record["module"] for record in records} == set(GUARD.MODULES)
    operations = [operation for record in records for operation in record["operations"]]
    exports = [operation["symbol"] for operation in operations]
    GUARD.validate_exports(operations, exports + ["connect_norito_free"])
    with pytest.raises(GUARD.AuditError, match="missing JNI exports"):
        GUARD.validate_exports(operations, exports[1:])
    for unowned in ("Java_org_hyperledger_iroha_android_F_call", "Java_pg_product_F_call", exports[0] + "Stale"):
        with pytest.raises(GUARD.AuditError, match="unowned JNI exports"):
            GUARD.validate_exports(operations, exports + [unowned])
    with pytest.raises(GUARD.AuditError, match="duplicate JNI"):
        GUARD.validate_exports(operations, exports + exports[:1])
    with pytest.raises(GUARD.AuditError, match="colliding"):
        GUARD.validate_exports(operations + operations[:1], exports)


@pytest.mark.parametrize("mutation", ["missing_module", "empty_output", "duplicate_class", "misplaced", "jdk9", "java_native", "wrong_owner", "no_source", "symlink_directory", "fifo"])
def test_scan_rejects_incomplete_or_noncanonical_classes(tmp_path, mutation):
    roots = build_outputs(tmp_path)
    privacy = roots["core-jvm"][0] / (PRIVACY + ".class")
    if mutation == "missing_module":
        del roots["client-android"]
    elif mutation == "empty_output":
        for path in roots["client-android"][0].rglob("*.class"):
            path.unlink()
    elif mutation == "duplicate_class":
        copy = roots["client-android"][0] / (PRIVACY + ".class")
        copy.parent.mkdir(parents=True)
        copy.write_bytes(privacy.read_bytes())
    elif mutation == "misplaced":
        privacy.rename(privacy.with_name("Wrong.class"))
    elif mutation == "jdk9":
        privacy.write_bytes(class_bytes(PRIVACY, release_methods()[PRIVACY], major=53))
    elif mutation == "java_native":
        privacy.write_bytes(class_bytes(PRIVACY, release_methods()[PRIVACY], source="Fixture.java"))
    elif mutation == "no_source":
        privacy.write_bytes(class_bytes(PRIVACY, release_methods()[PRIVACY], source=None))
    elif mutation == "symlink_directory":
        retired = tmp_path / "hidden"
        retired.mkdir()
        (retired / "UnshieldInstruction.class").write_bytes(
            class_bytes(SDK + "core/model/instructions/UnshieldInstruction"))
        link = roots["core-jvm"][0] / (SDK + "core/model/instructions")
        link.parent.mkdir(parents=True)
        link.symlink_to(retired, target_is_directory=True)
    elif mutation == "fifo":
        if not hasattr(os, "mkfifo"):
            pytest.skip("FIFO inputs are Unix-only")
        privacy.unlink()
        os.mkfifo(privacy)
    else:
        owner = "org/hyperledger/iroha/android/Bridge"
        path = roots["core-jvm"][0] / (owner + ".class")
        path.parent.mkdir(parents=True)
        path.write_bytes(class_bytes(owner, [native("call", "()V")]))
    with pytest.raises(GUARD.AuditError):
        GUARD.scan_classes(roots)


@pytest.mark.parametrize("mutation", ["missing_privacy", "managed_validator", "validator_signature", "generic_proof", "retired_signer", "retired_instruction", "implicit_public_network", "implicit_native_network", "implicit_companion_network", "public_native_bytes", "default_codec_context"])
def test_release_api_constraints_replace_reflection(mutation):
    declarations = release_methods()
    if mutation == "missing_privacy":
        del declarations[PRIVACY]
    elif mutation == "default_codec_context":
        declarations[CODEC] += (JVM.Method("<init>", "()V", JVM.ACC_PUBLIC),)
    elif mutation == "managed_validator":
        first, *rest = declarations[PRIVACY]
        declarations[PRIVACY] = (JVM.Method(first.name, first.descriptor, JVM.ACC_STATIC), *rest)
    elif mutation == "validator_signature":
        first, *rest = declarations[PRIVACY]
        declarations[PRIVACY] = (native(first.name, "([B)J"), *rest)
    elif mutation == "generic_proof":
        declarations[PRIVACY + "$Companion"] = (JVM.Method("buildProof", "()[B", JVM.ACC_PUBLIC),)
    elif mutation == "retired_signer":
        declarations[SIGNER] += (native("nativeEncodeShieldSignedTransaction", "()[B"),)
    elif mutation == "retired_instruction":
        declarations[SDK + "core/model/instructions/UnshieldInstruction"] = ()
    elif mutation == "implicit_companion_network":
        declarations[SIGNER + "$Companion"] = (
            JVM.Method("encodeRegisterZkAssetSignedTransaction", "(ILjava/lang/String;I)V", JVM.ACC_PUBLIC),
        )
    else:
        public, private, account = declarations[SIGNER]
        if mutation == "public_native_bytes":
            public = JVM.Method(public.name, "(I[BI)V", public.flags | JVM.ACC_NATIVE)
        elif mutation == "implicit_public_network":
            public = JVM.Method(public.name, "(ILjava/lang/String;I)V", public.flags)
        else:
            private = native(private.name, "(II[B)V")
        declarations[SIGNER] = (public, private, account)
    classes = {owner: JVM.parse_class(class_bytes(owner, methods)) for owner, methods in declarations.items()}
    with pytest.raises(GUARD.AuditError):
        GUARD.validate_release_api(classes)


def test_audit_seals_inputs_without_claiming_runtime_qualification(tmp_path, monkeypatch):
    roots = build_outputs(tmp_path)
    _, records = GUARD.scan_classes(roots)
    exports = [operation["symbol"] for record in records for operation in record["operations"]]
    library = tmp_path / "libbridge.so"
    library.write_bytes(b"test export inventory")
    monkeypatch.setattr(GUARD.ARTIFACT, "inspect_exported_symbols", lambda *args, **kwargs: tuple(exports))
    report = GUARD.audit(roots, library)
    assert report["valid"] and report["native_method_count"] == 8
    assert not report["native_execution_qualified"]
    assert not report["native_signatures_qualified"]
    assert not report["source_build_provenance_qualified"]
    assert report["platform"] == "host" and not report["symbol_inspection"]["tool_pinned"]
    assert len(report["class_inventory_sha256"]) == len(report["library"]["sha256"]) == 64

    def change_class(*args, **kwargs):
        path = roots["core-jvm"][0] / (PRIVACY + ".class")
        path.write_bytes(class_bytes(PRIVACY, release_methods()[PRIVACY], source="Changed.kt"))
        return tuple(exports)

    monkeypatch.setattr(GUARD.ARTIFACT, "inspect_exported_symbols", change_class)
    with pytest.raises(GUARD.AuditError, match="classes changed"):
        GUARD.audit(roots, library)


def pinned_fixture(tmp_path, *, stdout="connect_norito_free\n", stderr="", exit_code=0, child_code="", abi="arm64-v8a"):
    """Use an owned executable oracle and ELF header fixture, never native execution."""
    root = tmp_path.resolve()
    tool = root / "reviewed-symbol-tool"
    tool.write_text("#!" + str(Path(sys.executable).resolve()) + "\nimport os, sys\n"
                    + child_code + "\nsys.stdout.write(" + repr(stdout) + ")\n"
                    + "sys.stderr.write(" + repr(stderr) + ")\nsys.exit(" + str(exit_code) + ")\n")
    tool.chmod(0o700)
    library = root / "libbridge.so"
    elf_class = GUARD.ANDROID_ELF_CLASSES[abi]
    header = bytearray(52 if elf_class == 1 else 64)
    header[:7] = b"\x7fELF" + bytes((elf_class, 1, 1))
    header[16:24] = struct.pack("<HHI", 3, GUARD.ANDROID_MACHINES[abi], 1)
    library.write_bytes(header + b"synthetic symbol inspection fixture")
    library.chmod(0o600)
    return library, {"abi": abi, "tool": tool,
                     "tool_sha256": hashlib.sha256(tool.read_bytes()).hexdigest(),
                     "tool_size_bytes": tool.stat().st_size, "output": root / "original-inspection"}


def test_android_audit_uses_only_pinned_tool_and_retains_originals(tmp_path, monkeypatch):
    roots = build_outputs(tmp_path)
    _, records = GUARD.scan_classes(roots)
    exports = [operation["symbol"] for record in records for operation in record["operations"]]
    library, pin = pinned_fixture(tmp_path, stdout="\n".join(exports + ["connect_norito_free"]) + "\n",
                                  child_code="assert sys.argv[1:5] == ['--dynamic', '--defined-only', '--extern-only', '--format=just-symbols']\n"
                                             "assert os.environ.get('PINNED_TOOL_HOSTILE') is None\n"
                                             "assert os.environ['PATH'] == '/usr/bin:/bin'\n")
    monkeypatch.setenv("PINNED_TOOL_HOSTILE", "must not reach symbol tool")
    monkeypatch.setattr(GUARD.ARTIFACT, "inspect_exported_symbols",
                        lambda *args, **kwargs: pytest.fail("Android must not discover an ambient tool"))
    report = GUARD.audit(roots, library, platform="android", android_abi=pin["abi"],
                         symbol_tool=pin["tool"], symbol_tool_sha256=pin["tool_sha256"],
                         symbol_tool_size_bytes=pin["tool_size_bytes"], inspection_output=pin["output"])
    inspection = report["symbol_inspection"]
    assert inspection["tool_pinned"] and report["platform"] == "android"
    assert inspection["argv"] == [str(pin["tool"]), *GUARD.ANDROID_SYMBOL_ARGUMENTS, str(library)]
    assert inspection["environment"] == GUARD.ANDROID_SYMBOL_ENVIRONMENT
    assert report["native_method_count"] == 8
    assert not any(report[name] for name in ("native_signatures_qualified", "native_execution_qualified", "source_build_provenance_qualified"))
    for name, claim in inspection["originals"].items():
        raw = Path(claim["path"]).read_bytes()
        assert len(raw) == claim["size_bytes"] and hashlib.sha256(raw).hexdigest() == claim["sha256"]
        assert Path(claim["path"]).stat().st_mode & 0o777 == 0o600
    assert pin["output"].stat().st_mode & 0o777 == 0o700
    result = json.loads((pin["output"] / "result.json").read_bytes())
    assert result["exit_code"] == 0 and result["streams_complete"] and result["transport_error"] is None


@pytest.mark.parametrize("mutation", ["sha256", "size", "zero_sha256", "relative_tool", "symlink_tool", "hardlink_tool", "writable_tool", "not_executable", "wrong_abi", "not_elf", "symlink_library", "existing_output", "relative_output"])
def test_android_pins_reject_before_starting_child(tmp_path, mutation):
    library, pin = pinned_fixture(tmp_path)
    if mutation == "sha256":
        pin["tool_sha256"] = "1" * 64
    elif mutation == "size":
        pin["tool_size_bytes"] += 1
    elif mutation == "zero_sha256":
        pin["tool_sha256"] = "0" * 64
    elif mutation == "relative_tool":
        pin["tool"] = Path("symbol-tool")
    elif mutation == "symlink_tool":
        link = tmp_path / "linked-tool"
        link.symlink_to(pin["tool"])
        pin["tool"] = link
    elif mutation == "hardlink_tool":
        (tmp_path / "tool-alias").hardlink_to(pin["tool"])
    elif mutation == "writable_tool":
        pin["tool"].chmod(0o722)
    elif mutation == "not_executable":
        pin["tool"].chmod(0o600)
    elif mutation == "wrong_abi":
        pin["abi"] = "x86_64"
    elif mutation == "not_elf":
        library.write_bytes(b"not an Android library")
    elif mutation == "symlink_library":
        link = tmp_path / "linked-library"
        link.symlink_to(library)
        library = link
    elif mutation == "existing_output":
        pin["output"].mkdir()
        (pin["output"] / "preserved").write_text("original retained")
    else:
        pin["output"] = Path("inspection-output")
    with pytest.raises(GUARD.AuditError):
        GUARD.inspect_pinned_android_symbols(library, **pin)
    assert not (pin["output"] / "invocation.json").exists()
    if mutation == "existing_output":
        assert (pin["output"] / "preserved").read_text() == "original retained"


@pytest.mark.parametrize("mutation", ["tool_bytes", "tool_inode", "library_bytes", "library_inode"])
def test_android_drift_retains_actual_child_originals(tmp_path, mutation):
    if mutation == "tool_bytes":
        code = "with open(sys.argv[0], 'ab') as stream: stream.write(b'changed')"
    elif mutation == "library_bytes":
        code = "with open(sys.argv[-1], 'ab') as stream: stream.write(b'changed')"
    else:
        target = "sys.argv[0]" if mutation == "tool_inode" else "sys.argv[-1]"
        code = "target = " + target + "\nwith open(target, 'rb') as stream: raw = stream.read()\nos.unlink(target)\nwith open(target, 'wb') as stream: stream.write(raw)\nos.chmod(target, 0o700)"
    library, pin = pinned_fixture(tmp_path, child_code=code)
    with pytest.raises(GUARD.AuditError, match="changed during inspection"):
        GUARD.inspect_pinned_android_symbols(library, **pin)
    assert (pin["output"] / "stdout.bin").read_bytes() == b"connect_norito_free\n"
    assert (pin["output"] / "stderr.bin").read_bytes() == b""
    assert json.loads((pin["output"] / "result.json").read_bytes())["exit_code"] == 0
    assert not json.loads((pin["output"] / "input-guards.json").read_bytes())["valid"]


def test_android_parent_symlink_substitution_fails_even_with_same_tool_inode(tmp_path):
    library, pin = pinned_fixture(tmp_path)
    parent = tmp_path.resolve() / "tool-parent"
    parent.mkdir()
    tool = parent / pin["tool"].name
    pin["tool"].rename(tool)
    relocated = tmp_path.resolve() / "relocated-tool-parent"
    original = tool.read_text()
    original = original.replace("\nsys.stdout.write", "\nos.rename(" + repr(str(parent)) + ", " + repr(str(relocated))
                                + ")\nos.symlink(" + repr(str(relocated)) + ", " + repr(str(parent)) + ")\nsys.stdout.write")
    tool.write_text(original)
    pin.update(tool=tool, tool_sha256=hashlib.sha256(tool.read_bytes()).hexdigest(), tool_size_bytes=tool.stat().st_size)
    inode = tool.stat().st_ino
    with pytest.raises(GUARD.AuditError, match="changed during inspection"):
        GUARD.inspect_pinned_android_symbols(library, **pin)
    assert tool.stat().st_ino == inode
    assert (pin["output"] / "stdout.bin").read_bytes() == b"connect_norito_free\n"
    assert not json.loads((pin["output"] / "input-guards.json").read_bytes())["valid"]


@pytest.mark.parametrize("mutation", ["nonzero", "stderr", "empty", "decorated", "non_ascii", "malformed", "stderr_limit", "stdout_limit"])
def test_android_failed_probe_keeps_originals(tmp_path, mutation, monkeypatch):
    arguments = {}
    if mutation == "nonzero":
        arguments["exit_code"] = 7
    elif mutation == "stderr":
        arguments["stderr"] = "actual diagnostic\n"
    elif mutation == "empty":
        arguments["stdout"] = ""
    elif mutation == "decorated":
        arguments["stdout"] = "Java_owner_call@@VERSION\n"
    elif mutation == "non_ascii":
        arguments["child_code"] = "os.write(1, b'\\xff\\n')"
        arguments["stdout"] = ""
    elif mutation == "malformed":
        arguments["stdout"] = "connect_norito_free\n\n"
    else:
        monkeypatch.setattr(GUARD.ARTIFACT, "MAX_PROBE_STDERR_BYTES", 16)
        monkeypatch.setattr(GUARD.ARTIFACT, "MAX_SYMBOL_TOOL_OUTPUT_BYTES", 16)
        arguments["stdout"] = "x\n"
        arguments["stderr" if mutation == "stderr_limit" else "stdout"] = "x" * 100
    library, pin = pinned_fixture(tmp_path, **arguments)
    with pytest.raises(GUARD.AuditError):
        GUARD.inspect_pinned_android_symbols(library, **pin)
    result = json.loads((pin["output"] / "result.json").read_bytes())
    assert (pin["output"] / "stdout.bin").exists() and (pin["output"] / "stderr.bin").exists()
    assert result["streams_complete"] == (not mutation.endswith("_limit"))
    assert (result["transport_error"] is not None) == mutation.endswith("_limit")
    if mutation == "nonzero":
        assert result["exit_code"] == 7
    elif mutation == "stderr":
        assert (pin["output"] / "stderr.bin").read_bytes() == b"actual diagnostic\n"


def test_android_audit_requires_complete_explicit_pin_and_separate_outputs(tmp_path):
    roots = build_outputs(tmp_path)
    library, pin = pinned_fixture(tmp_path)
    with pytest.raises(GUARD.AuditError, match="requires explicit"):
        GUARD.audit(roots, library, platform="android")
    with pytest.raises(GUARD.AuditError, match="only to --platform android"):
        GUARD.audit(roots, library, symbol_tool=pin["tool"])
    with pytest.raises(GUARD.AuditError, match="outside compiled"):
        GUARD.audit(roots, library, platform="android", android_abi=pin["abi"],
                    symbol_tool=pin["tool"], symbol_tool_sha256=pin["tool_sha256"],
                    symbol_tool_size_bytes=pin["tool_size_bytes"],
                    inspection_output=roots["core-jvm"][0] / "inspection")


@pytest.mark.parametrize("abi", ["arm64-v8a", "armeabi-v7a", "x86_64"])
def test_exact_android_elf_class_and_machine_are_required(tmp_path, abi):
    library, pin = pinned_fixture(tmp_path, abi=abi)
    symbols, record = GUARD.inspect_pinned_android_symbols(library, **pin)
    assert symbols == ("connect_norito_free",) and record["android_abi"] == abi
    assert record["tool_pinned"] is True


@pytest.mark.parametrize("mutation", ["class", "machine", "endianness", "kind", "version", "truncated"])
def test_armv7_header_rejections_do_not_start_a_symbol_child(tmp_path, mutation):
    library, pin = pinned_fixture(tmp_path, abi="armeabi-v7a")
    data = bytearray(library.read_bytes())
    if mutation == "class":
        data[4] = 2
    elif mutation == "machine":
        data[18:20] = struct.pack("<H", 183)
    elif mutation == "endianness":
        data[5] = 2
    elif mutation == "kind":
        data[16:18] = struct.pack("<H", 2)
    elif mutation == "version":
        data[20:24] = struct.pack("<I", 0)
    else:
        data = data[:51]
    library.write_bytes(data)
    with pytest.raises(GUARD.AuditError, match="exact ABI ELF class and machine"):
        GUARD.inspect_pinned_android_symbols(library, **pin)
    assert not pin["output"].exists()


@pytest.mark.parametrize("abi", ["arm64-v8a", "x86_64"])
def test_64_bit_android_abi_rejects_elf32_before_child(tmp_path, abi):
    library, pin = pinned_fixture(tmp_path, abi=abi)
    data = bytearray(library.read_bytes())
    data[4] = 1
    library.write_bytes(data)
    with pytest.raises(GUARD.AuditError, match="exact ABI ELF class and machine"):
        GUARD.inspect_pinned_android_symbols(library, **pin)
    assert not pin["output"].exists()


def test_android_x86_64_and_bounded_owned_child_timeout(tmp_path):
    library, pin = pinned_fixture(tmp_path, abi="x86_64")
    symbols, record = GUARD.inspect_pinned_android_symbols(library, **pin)
    assert symbols == ("connect_norito_free",) and record["android_abi"] == "x86_64"
    stdout, stderr, outcome = GUARD._collect_symbol_probe(
        [str(Path(sys.executable).resolve()), "-I", "-S", "-B", "-c", "import time; time.sleep(1)"],
        timeout_seconds=0.05)
    assert stdout == stderr == b""
    assert not outcome["streams_complete"] and outcome["transport_error"]["kind"] == "TimeoutError"
    assert outcome["exit_code"] is not None
    with pytest.raises(GUARD.AuditError, match="deadline"):
        GUARD._collect_symbol_probe(["never-executed"], timeout_seconds=float("nan"))


def test_android_cli_requires_pins_and_preserves_tool_report_alias(tmp_path):
    roots = build_outputs(tmp_path)
    library, pin = pinned_fixture(tmp_path)
    arguments = ["--library", str(library), "--platform", "android"]
    for module, paths in roots.items():
        arguments += ["--classes", module + "=" + str(paths[0])]
    assert GUARD.main(arguments) == 1
    original = pin["tool"].read_bytes()
    arguments += ["--android-abi", pin["abi"], "--symbol-tool", str(pin["tool"]),
                  "--symbol-tool-sha256", pin["tool_sha256"], "--symbol-tool-size-bytes", str(pin["tool_size_bytes"]),
                  "--inspection-output", str(pin["output"]), "--report", str(pin["tool"])]
    assert GUARD.main(arguments) == 1
    assert pin["tool"].read_bytes() == original and not pin["output"].exists()


@pytest.mark.parametrize("mutation", ("missing", "return_type", "instance", "managed", "curve_switch", "bypass", "retired_config"))
def test_complete_account_native_admission_is_required(mutation):
    declarations = release_methods()
    public, private, account = declarations[SIGNER]
    if mutation == "missing":
        declarations[SIGNER] = (public, private)
    elif mutation in {"return_type", "instance", "managed"}:
        descriptor = "([B)Z" if mutation == "return_type" else account.descriptor
        flags = account.flags
        if mutation == "instance":
            flags &= ~JVM.ACC_STATIC
        if mutation == "managed":
            flags &= ~JVM.ACC_NATIVE
        declarations[SIGNER] = (public, private, JVM.Method(account.name, descriptor, flags))
    elif mutation == "retired_config":
        declarations[SDK + "address/CurveSupportConfig"] = ()
    else:
        name = "configureCurveSupport" if mutation == "curve_switch" else "parseEncodedIgnoringCurveSupport"
        declarations[SDK + "address/AccountAddress$Companion"] = (
            JVM.Method(name, "()V", JVM.ACC_PUBLIC),
        )
    classes = {owner: JVM.parse_class(class_bytes(owner, methods)) for owner, methods in declarations.items()}
    with pytest.raises(GUARD.AuditError, match="account"):
        GUARD.validate_release_api(classes)


def test_cli_does_not_overwrite_build_inputs(tmp_path):
    roots = build_outputs(tmp_path)
    library = tmp_path / "libbridge.so"
    library.write_bytes(b"unchanged")
    arguments = ["--library", str(library), "--report", str(library)]
    for module, paths in roots.items():
        arguments += ["--classes", module + "=" + str(paths[0])]
    assert GUARD.main(arguments) == 1
    assert library.read_bytes() == b"unchanged"


def test_report_rejects_input_aliases_and_replaces_its_own_inode(tmp_path):
    library, class_path = tmp_path / "library", tmp_path / "Class.class"
    library.write_bytes(b"native bytes")
    class_path.write_bytes(b"class bytes")
    result = {"library": {"path": str(library)}, "classes": [{"path": str(class_path)}]}
    report = tmp_path / "report.json"
    report.hardlink_to(class_path)
    with pytest.raises(GUARD.AuditError, match="alias"):
        GUARD.write_report(report, result)
    assert class_path.read_bytes() == b"class bytes"
    report.unlink()
    report.symlink_to(library)
    with pytest.raises(GUARD.AuditError, match="symlink"):
        GUARD.write_report(report, result)
    report.unlink()
    report.write_text("old report")
    old_report = tmp_path / "old-report"
    old_report.hardlink_to(report)
    GUARD.write_report(report, result)
    assert json.loads(report.read_text()) == result
    assert old_report.read_text() == "old report"
    assert not list(tmp_path.glob(".report.json.*"))


@pytest.mark.parametrize("index", range(6))
@pytest.mark.parametrize("mutation", ("missing", "return", "managed", "instance"))
def test_privacy_class_contract_rejects_every_native_declaration_drift(index, mutation):
    methods = list(release_methods()[PRIVACY])
    current = methods[index]
    if mutation == "missing":
        del methods[index]
    else:
        descriptor = current.descriptor[:-1] + "J" if mutation == "return" else current.descriptor
        flags = current.flags & ~JVM.ACC_NATIVE if mutation == "managed" else current.flags & ~JVM.ACC_STATIC if mutation == "instance" else current.flags
        methods[index] = JVM.Method(current.name, descriptor, flags)
    with pytest.raises(GUARD.AuditError, match="native declaration"):
        GUARD.validate_privacy_api({PRIVACY: JVM.parse_class(class_bytes(PRIVACY, methods))})


@pytest.mark.parametrize("name", ("nativeValidateExact12CapabilityManifest", "nativeRequireExact12CapabilityTuple", "nativeValidateExact12SubmitProofConstruction", "buildProof", "verifyProof", "nativeBuildProof", "nativeVerifyProof", "PrivacyProofRequest"))
def test_privacy_class_contract_rejects_every_retired_method(name):
    classes = {PRIVACY: JVM.parse_class(class_bytes(PRIVACY, release_methods()[PRIVACY]))}
    classes[PRIVACY + "$Companion"] = JVM.parse_class(class_bytes(PRIVACY + "$Companion", [native(name, "()[B")]))
    with pytest.raises(GUARD.AuditError):
        GUARD.validate_privacy_api(classes)


def test_scoped_privacy_classfile_contract_seals_actual_bytes(tmp_path):
    for suffix in ("", "$Companion"):
        name = PRIVACY + suffix
        path = tmp_path / (name + ".class")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(class_bytes(name, release_methods()[PRIVACY] if not suffix else (), source="PrivacyNativeBridge.kt"))
    report = GUARD.audit_privacy_classfiles(tmp_path)
    assert len(report["classes"]) == 2
    assert report["native_executed"] is False and report["release_qualified"] is False
    (tmp_path / (PRIVACY + "$Companion.class")).unlink()
    with pytest.raises(GUARD.AuditError):
        GUARD.audit_privacy_classfiles(tmp_path)


@pytest.mark.parametrize("owner,source", (
    (SDK + "privacy/PrivacyConfidentialWitnessV1", "PrivacyConfidentialWitness.kt"),
    (SDK + "privacy/PrivacyConfidentialNoteWitnessV1", "PrivacyConfidentialWitness.kt"),
    (SDK + "privacy/NoteWitnessAdapter", "PrivacyConfidentialWitness.kt"),
    (SDK + "privacy/fixtures/RetiredPrivacyConfidentialWitnessCodecs", "RetiredPrivacyConfidentialWitnessFixture.kt"),
    (SDK + "privacy/Relocated", "RetiredPrivacyConfidentialWitnessFixture.kt"),
    ("org/hyperledger/iroha/android/privacy/PrivacyConfidentialWitness", "PrivacyConfidentialWitness.java"),
))
def test_compiled_privacy_contract_rejects_retired_witnesses_and_test_fixtures(tmp_path, owner, source):
    for name, methods, file in (
        (PRIVACY, release_methods()[PRIVACY], "PrivacyNativeBridge.kt"),
        (PRIVACY + "$Companion", (), "PrivacyNativeBridge.kt"),
        (owner, (), source),
    ):
        path = tmp_path / (name + ".class")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(class_bytes(name, methods, source=file))
    with pytest.raises(GUARD.AuditError, match="retired confidential witness or test fixture"):
        GUARD.audit_privacy_classfiles(tmp_path)
    classes = {owner: JVM.parse_class(class_bytes(owner, (), source=source))}
    with pytest.raises(GUARD.AuditError, match="retired confidential witness or test fixture"):
        GUARD.validate_retired_privacy_witness_classes(classes)


def test_compiled_privacy_contract_seals_nonprivacy_main_classes_too(tmp_path):
    for suffix in ("", "$Companion"):
        name = PRIVACY + suffix
        path = tmp_path / (name + ".class")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(class_bytes(name, release_methods()[PRIVACY] if not suffix else (), source="PrivacyNativeBridge.kt"))
    owner = SDK + "privacy/PrivacyProtocolIdV1"
    path = tmp_path / (owner + ".class")
    path.write_bytes(class_bytes(owner, (), source="PrivacyNativeBridge.kt"))
    assert len(GUARD.audit_privacy_classfiles(tmp_path)["classes"]) == 3
    link = path.parent / "hidden"
    link.symlink_to(tmp_path / "absent")
    with pytest.raises(GUARD.AuditError, match="symlink"):
        GUARD.audit_privacy_classfiles(tmp_path)


# First-release KAGEMUSHA eligibility and wallet V1 wire, platform adapters,
# Native owner clients and typed projections. Compiled declaration/export auditing requires exact
# Native ownership for every wallet JNI declaration. These
# source inventories do not execute wallet JNI or prove artifacts are available.
# They need no JDK, native artifact, network or environment variable.
ROOT = Path(__file__).resolve().parents[2]
KOTLIN_OFFLINE_PACKAGE = "org/hyperledger/iroha/sdk/offline"


def kagemusha_named_files(root, directories):
    """Return every regular file whose name starts with KAGEMUSHA, relative to ``root``."""
    return {
        path.relative_to(root).as_posix()
        for directory in directories
        for path in (root / directory).rglob("*")
        if path.is_file() and path.name.lower().startswith("kagemusha")
    }


def test_kotlin_ships_only_the_kagemusha_wallet_v1_surface():
    """Pin current eligibility, ledger wire, P-256 and Android/Native wallet owners."""
    kotlin = ROOT / "kotlin"
    offline = KOTLIN_OFFLINE_PACKAGE
    wallet = "kagemusha-wallet-android/src"
    kept = {
        "core-jvm/src/main/java/org/hyperledger/iroha/sdk/core/model/instructions/"
        "KagemushaWalletIssueLoadInstructionV1.kt",
        "core-jvm/src/test/kotlin/org/hyperledger/iroha/sdk/core/model/instructions/"
        "KagemushaWalletIssueLoadInstructionV1Test.kt",
        "core-jvm/src/main/java/org/hyperledger/iroha/sdk/core/model/instructions/"
        "KagemushaWalletActivateInstructionV1.kt",
        "core-jvm/src/test/kotlin/org/hyperledger/iroha/sdk/core/model/instructions/"
        "KagemushaWalletActivateInstructionV1Test.kt",
        f"core-jvm/src/main/java/{offline}/KagemushaP256Codec.kt",
        f"core-jvm/src/main/java/{offline}/KagemushaWalletWireV1.kt",
        f"core-jvm/src/main/java/{offline}/KagemushaWalletEnrollmentBindingV1.kt",
        f"core-jvm/src/test/kotlin/{offline}/KagemushaWalletEnrollmentBindingV1Test.kt",
        f"core-jvm/src/main/java/{offline}/KagemushaWalletAccountOriginalV1.kt",
        f"core-jvm/src/test/kotlin/{offline}/KagemushaWalletAccountOriginalV1Test.kt",
        f"core-jvm/src/main/java/{offline}/KagemushaEnrollmentEligibilityV1.kt",
        f"core-jvm/src/test/kotlin/{offline}/KagemushaEnrollmentEligibilityV1Test.kt",
        f"core-jvm/src/test/java/{offline}/KagemushaEligibilityJavaTest.java",
        "core-jvm/src/test/kotlin/org/hyperledger/iroha/sdk/client/"
        "KagemushaLedgerOriginalTransportV1Test.kt",
        f"core-jvm/src/test/kotlin/{offline}/KagemushaWalletVectorsV1Test.kt",
        f"{wallet}/androidTest/java/{offline}/wallet/KagemushaWalletAndroidPlatformDeviceV1Test.kt",
        f"{wallet}/main/res/xml/kagemusha_wallet_v1_data_extraction_rules.xml",
        f"{wallet}/main/res/xml/kagemusha_wallet_v1_full_backup_content.xml",
        f"{wallet}/main/java/{offline}/wallet/KagemushaWalletV1.kt",
        f"{wallet}/main/java/{offline}/wallet/KagemushaWalletEnrollmentV1.kt",
        f"{wallet}/main/java/{offline}/wallet/KagemushaWalletLoadOriginalV1.kt",
        f"{wallet}/main/java/{offline}/wallet/KagemushaWalletLedgerV1.kt",
        f"{wallet}/main/java/{offline}/wallet/KagemushaWalletCreditProjectionV1.kt",
        f"{wallet}/main/java/{offline}/wallet/KagemushaWalletRequestFeeSelectionV1.kt",
        f"{wallet}/main/java/{offline}/wallet/KagemushaWalletInstalledRuntimeV1.kt",
        f"{wallet}/main/java/{offline}/wallet/KagemushaWalletInstallationAttemptV1.kt",
        f"{wallet}/main/java/{offline}/wallet/KagemushaWalletEnrollmentV1.kt",
        f"{wallet}/main/java/{offline}/wallet/KagemushaWalletReviewV1.kt",
        f"{wallet}/main/java/{offline}/wallet/KagemushaWalletOpenV1.kt",
        f"{wallet}/main/java/{offline}/wallet/KagemushaWalletSetupV1.kt",
        f"{wallet}/main/java/{offline}/wallet/KagemushaWalletNativeReplyV1.kt",
        f"{wallet}/main/java/{offline}/wallet/KagemushaWalletSnapshotV1.kt",
        f"{wallet}/test/kotlin/{offline}/wallet/KagemushaWalletV1Test.kt",
        f"{wallet}/test/kotlin/{offline}/wallet/KagemushaWalletEnrollmentV1Test.kt",
        f"{wallet}/test/kotlin/{offline}/wallet/KagemushaWalletInstalledRuntimeV1Test.kt",
        f"{wallet}/test/kotlin/{offline}/wallet/KagemushaWalletInstallationAttemptV1Test.kt",
        f"{wallet}/test/kotlin/{offline}/wallet/KagemushaWalletReviewV1Test.kt",
        f"{wallet}/test/kotlin/{offline}/wallet/KagemushaWalletCurrentReviewIntegrationV1Test.kt",
        f"{wallet}/test/kotlin/{offline}/wallet/KagemushaWalletInstalledHolderV1Test.kt",
        f"{wallet}/test/kotlin/{offline}/wallet/KagemushaWalletCleanupQuarantineV1Test.kt",
        f"{wallet}/test/kotlin/{offline}/wallet/KagemushaWalletAdmissionLifetimeV1Test.kt",
        f"{wallet}/test/java/{offline}/wallet/KagemushaWalletLoadOriginalV1Test.kt",
        f"{wallet}/test/kotlin/{offline}/wallet/KagemushaWalletSetupV1Test.kt",
        f"{wallet}/test/kotlin/{offline}/wallet/KagemushaWalletHostNativeV1Test.kt",
        f"{wallet}/test/kotlin/{offline}/wallet/KagemushaWalletSnapshotV1Test.kt",
        f"{wallet}/test/kotlin/{offline}/wallet/KagemushaWalletLedgerV1Test.kt",
        f"{wallet}/test/kotlin/{offline}/wallet/KagemushaWalletCreditProjectionV1Test.kt",
        f"{wallet}/test/kotlin/{offline}/wallet/KagemushaWalletRequestFeeSelectionV1Test.kt",
        f"{wallet}/test/kotlin/{offline}/wallet/KagemushaWalletBoundDeliveryV1Test.kt",
        *(
            f"{wallet}/main/java/{offline}/wallet/KagemushaWalletAndroid{name}V1.kt"
            for name in ("Environment", "KeyStore", "PaymentKey", "Platform", "Results")
        ),
        *(
            f"{wallet}/test/kotlin/{offline}/wallet/KagemushaWalletAndroid{name}.kt"
            for name in ("BackupRulesV1Test", "PaymentKeyV1Test", "PlatformV1Test", "TestFakesV1")
        ),
    }
    modules = tuple(f"{module}/src" for module in GUARD.MODULES)
    assert kagemusha_named_files(kotlin, modules) == kept

    # The retired ServiceLoader providers and the probe package must not return.
    for module in GUARD.MODULES:
        services = kotlin / module / "src/main/resources/META-INF/services"
        if services.exists():
            retired = sorted(
                path.name for path in services.iterdir()
                if path.name.startswith("org.hyperledger.iroha.sdk.offline.")
            )
            assert retired == [], f"{module} ships retired offline SPI resources"
        for source_set in ("main/java", "test/kotlin", "test/java", "androidTest/java"):
            probe = kotlin / module / "src" / source_set / offline / "probe"
            assert not probe.exists(), f"{probe.relative_to(ROOT)} must stay retired"

    # Keep exact wallet V1 platform upcalls, Native owners/results and snapshot holder.
    expected_wallet_kept_names = {
        "KagemushaWalletAndroidPlatformV1",
        "KagemushaWalletAndroidUnavailableV1",
        "KagemushaWalletAndroidKeyProbeV1",
        "KagemushaWalletAndroidKeyGenerationV1",
        "KagemushaWalletAndroidSecurityLevelV1",
        "KagemushaWalletAndroidSignatureV1",
        "KagemushaWalletAndroidRemoveV1",
        "KagemushaWalletAndroidAttestationChainV1",
        "KagemushaWalletAndroidCustodyRootV1",
        "KagemushaWalletNativeReplyV1",
        "KagemushaWalletNativeV1",
        "KagemushaWalletLoadOriginalNativeV1",
        "KagemushaWalletInstalledRuntimeNativeV1",
        "KagemushaWalletReviewReplyV1",
        "KagemushaWalletCallV1",
        "KagemushaWalletSnapshotReplyV1",
    }
    for rules in (
        "client-android/consumer-rules.pro",
        "kagemusha-wallet-android/consumer-rules.pro",
        "core-jvm/src/main/resources/META-INF/proguard/consumer-proguard-rules.pro",
    ):
        lines = (kotlin / rules).read_text(encoding="utf-8").splitlines()
        rule_text = "\n".join(line for line in lines if not line.lstrip().startswith("#"))
        kept_names = set(re.findall(r"\bKagemusha\w*", rule_text))
        expected_names = expected_wallet_kept_names if rules == "kagemusha-wallet-android/consumer-rules.pro" else set()
        assert kept_names == expected_names, (rules, sorted(kept_names))
        kept_classes = {
            name for name in re.findall(r"\bclass\s+([\w.$]+)", rule_text)
            if "Kagemusha" in name
        }
        assert kept_classes == {
            "org.hyperledger.iroha.sdk.offline.wallet." + name for name in expected_names
        }, (rules, sorted(kept_classes))

    # The wallet manifest binds the exclude-only backup and device-transfer rules.
    manifest = (kotlin / wallet / "main/AndroidManifest.xml").read_text(encoding="utf-8")
    for attribute in (
        'android:allowBackup="false"',
        'android:dataExtractionRules="@xml/kagemusha_wallet_v1_data_extraction_rules"',
        'android:fullBackupContent="@xml/kagemusha_wallet_v1_full_backup_content"',
    ):
        assert attribute in manifest


def test_swift_ships_no_old_kagemusha_surface():
    """Pin the wallet V1 wire, Apple platform, Native client and typed snapshot files."""
    swift = ROOT / "IrohaSwift"
    kept = {
        "Sources/IrohaSwift/KagemushaWalletAppleAppAttestV1.swift",
        "Sources/IrohaSwift/KagemushaWalletApplePlatformV1.swift",
        "Sources/IrohaSwift/KagemushaWalletAppleSystemV1.swift",
        "Sources/IrohaSwift/KagemushaWalletWireV1.swift",
        "Sources/IrohaSwift/KagemushaWalletV1.swift",
        "Sources/IrohaSwift/KagemushaWalletEnrollmentV1.swift",
        "Sources/IrohaSwift/KagemushaWalletReviewV1.swift",
        "Sources/IrohaSwift/KagemushaWalletInstalledRuntimeV1.swift",
        "Sources/IrohaSwift/KagemushaWalletInstallationAttemptV1.swift",
        "Sources/IrohaSwift/KagemushaWalletAccountOriginalV1.swift",
        "Sources/IrohaSwift/KagemushaWalletLoadOriginalV1.swift",
        "Sources/IrohaSwift/KagemushaWalletLedgerV1.swift",
        "Sources/IrohaSwift/KagemushaWalletOpenV1.swift",
        "Sources/IrohaSwift/KagemushaWalletSetupV1.swift",
        "Sources/IrohaSwift/KagemushaWalletSnapshotV1.swift",
        "Tests/IrohaSwiftTests/KagemushaWalletApplePlatformV1Tests.swift",
        "Tests/IrohaSwiftTests/KagemushaWalletVectorsV1Tests.swift",
        "Tests/IrohaSwiftTests/KagemushaWalletNativeV1Tests.swift",
        "Tests/IrohaSwiftTests/KagemushaWalletEnrollmentV1Tests.swift",
        "Tests/IrohaSwiftTests/KagemushaWalletReviewV1Tests.swift",
        "Tests/IrohaSwiftTests/KagemushaWalletInstalledRuntimeV1Tests.swift",
        "Tests/IrohaSwiftTests/KagemushaWalletInstallationAttemptV1Tests.swift",
        "Tests/IrohaSwiftTests/KagemushaWalletAccountOriginalV1Tests.swift",
        "Tests/IrohaSwiftTests/KagemushaWalletExchangeBindingV1Tests.swift",
        "Tests/IrohaSwiftTests/KagemushaWalletNativeLeaseV1Tests.swift",
        "Tests/IrohaSwiftTests/KagemushaWalletCurrentReviewIntegrationV1Tests.swift",
        "Tests/IrohaSwiftTests/KagemushaWalletLoadOriginalV1Tests.swift",
        "Tests/IrohaSwiftTests/KagemushaWalletOpenV1Tests.swift",
        "Tests/IrohaSwiftTests/KagemushaWalletSetupV1Tests.swift",
        "Tests/IrohaSwiftTests/KagemushaWalletSnapshotV1Tests.swift",
    }
    assert kagemusha_named_files(swift, ("Sources", "Tests")) == kept
    for relative in (
        "Sources/IrohaSwift/ParticipantEnrollmentHttpCodecV1.swift",
        "Sources/IrohaSwift/AndroidProvisionedProof.swift",
    ):
        assert not (swift / relative).exists(), relative


def test_javascript_ships_no_old_kagemusha_surface():
    js_root = ROOT / "javascript/iroha_js"
    for relative in (
        "kagemusha.d.ts",
        "kagemusha-v1.d.ts",
        "src/kagemusha.js",
        "src/kagemushaV1.js",
        "src/kagemushaToriiV1.js",
        "src/public/kagemusha.js",
    ):
        path = js_root / relative
        assert not (path.exists() or path.is_symlink()), relative
    package = json.loads((js_root / "package.json").read_text(encoding="utf-8"))
    assert "./kagemusha" not in package["exports"]
    assert "kagemusha" not in package["typesVersions"]["*"]
    assert re.search(r"(?i)kagemusha", json.dumps(package)) is None
    for relative in ("src/index.js", "src/browser.js", "index.d.ts", "browser.d.ts"):
        source = (js_root / relative).read_text(encoding="utf-8")
        assert re.search(r"\bKagemusha(?:V1)?\b|\./kagemusha\.js", source) is None, relative


def test_csharp_ships_no_old_kagemusha_surface():
    sdk_root = ROOT / "csharp/src/Hyperledger.Iroha.Sdk"
    assert not (sdk_root / "Kagemusha").exists()
    checked = 0
    for path in sdk_root.rglob("*.cs"):
        relative = path.relative_to(sdk_root)
        if relative.parts[0] in ("bin", "obj"):
            continue
        checked += 1
        source = path.read_text(encoding="utf-8")
        assert re.search(
            r"\bnamespace\s+Hyperledger\.Iroha\.Kagemusha\b|\bconnect_norito_kagemusha_", source,
        ) is None, relative.as_posix()
    assert checked
