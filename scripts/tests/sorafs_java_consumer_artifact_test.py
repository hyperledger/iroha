"""Actual parser/ZIP/report/process controls; synthetic bytes are not qualification."""
from __future__ import annotations

import base64
import io
import json
import os
from pathlib import Path
import stat
import struct
import sys
import warnings
import xml.etree.ElementTree as ET
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import sorafs_java_consumer_artifact as contract
import build_sorafs_java_consumer_artifact as producer


def class_bytes(name: str, source: str, groups=(), *, major=52, flags=1) -> bytes:
    """Construct small classfile parser inputs, never executable qualification."""
    def u2(value): return struct.pack(">H", value)
    def u4(value): return struct.pack(">I", value)
    def utf8(value):
        encoded = value.encode()
        return b"\x01" + u2(len(encoded)) + encoded
    pool = [utf8(name), b"\x07" + u2(1), utf8("java/lang/Object"), b"\x07" + u2(3),
            utf8("SourceFile"), utf8(source), utf8("Code"), utf8("()V")]
    pool.extend(utf8(group) for group in groups)
    result = b"\xca\xfe\xba\xbe" + u2(0) + u2(major) + u2(len(pool) + 1) + b"".join(pool)
    result += u2(0x21) + u2(2) + u2(4) + u2(0) + u2(0) + u2(len(groups))
    for index, _group in enumerate(groups, 9):
        body = u2(0) + u2(1) + u4(1) + b"\xb1" + u2(0) + u2(0)
        result += u2(flags) + u2(index) + u2(8) + u2(1) + u2(7) + u4(len(body)) + body
    return result + u2(1) + u2(5) + u4(2) + u2(6)


def zip_bytes(members):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, raw in members:
            archive.writestr(name, raw)
    return output.getvalue()


def core():
    return {name: class_bytes(name, "SorafsReferenceValidators.kt" if index == 0 else "JsonParser.kt")
            for index, name in enumerate(contract.CORE_OWNERS)}


def packages():
    main = core()
    android = {contract.ANDROID_OWNER: class_bytes(contract.ANDROID_OWNER, "KeySecurityPreference.kt")}
    jar = lambda classes: zip_bytes([(name + ".class", raw) for name, raw in classes.items()])
    return jar(main), zip_bytes([("classes.jar", jar(android)), ("AndroidManifest.xml", b"manifest")])


def report():
    root = ET.Element("testsuite", name=contract.SUITE, tests="25", failures="0", errors="0", skipped="0")
    for name in contract.GROUPS:
        ET.SubElement(root, "testcase", classname=contract.SUITE, name=name, time="0.001")
    return root


def test_actual_archive_classfile_and_report_parsers_accept_complete_synthetic_inputs():
    first, second = packages()
    main, android, raw = contract.package_classes(first, second)
    assert set(main) == set(contract.CORE_OWNERS)
    assert set(android) == {contract.ANDROID_OWNER}
    assert contract.jar_classes(raw, sdk=True) == android
    owner = contract.SUITE.replace(".", "/")
    contract.validate_test_classes({owner: class_bytes(owner, "SorafsReferenceValidatorsJavaConsumerTest.java", contract.GROUPS)})
    assert contract.validate_report(ET.tostring(report())) == contract.GROUPS


@pytest.mark.parametrize("name", ["../bad", "a/../bad", "/absolute", "a//b", "a/./b", "C:/a", "a\\b", "x" * 1025])
def test_archive_rejects_unsafe_member_names(name):
    with pytest.raises(contract.ArtifactError, match="unsafe"):
        contract.archive_members(zip_bytes([(name, b"x")]))


def test_archive_rejects_duplicate_and_symbolic_members():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        raw = zip_bytes([("same", b"x"), ("same", b"y")])
    with pytest.raises(contract.ArtifactError, match="duplicate"):
        contract.archive_members(raw)
    link = zipfile.ZipInfo("link"); link.create_system = 3; link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with pytest.raises(contract.ArtifactError, match="non-regular"):
        contract.archive_members(zip_bytes([(link, b"target")]))


@pytest.mark.parametrize("manifest", [b"Class-Path: external.jar\r\n", b"class-path: ../escape.jar\n", b"Class-Path: x\n more.jar\n"])
def test_archive_cannot_extend_fixed_classpath(manifest):
    with pytest.raises(contract.ArtifactError, match="classpath"):
        contract.archive_members(zip_bytes([("META-INF/MANIFEST.MF", manifest)]))


def test_expansion_inventory_and_archive_byte_limits_precede_use(monkeypatch):
    raw = zip_bytes([("file", b"abcd")])
    monkeypatch.setattr(contract, "MAX_MEMBER_BYTES", 3)
    with pytest.raises(contract.ArtifactError, match="expansion"):
        contract.archive_members(raw)
    with pytest.raises(contract.ArtifactError, match="limits"):
        contract.deterministic_archive({"file": b"abcd"})
    monkeypatch.setattr(contract, "MAX_ARCHIVE_BYTES", len(raw) - 1)
    with pytest.raises(contract.ArtifactError, match="byte limit"):
        contract.archive_members(raw)


def test_dependency_cannot_shadow_sdk_or_test_namespace():
    name = contract.CORE_OWNERS[0]
    with pytest.raises(contract.ArtifactError, match="shadows"):
        contract.jar_classes(zip_bytes([(name + ".class", class_bytes(name, "X.kt"))]), sdk=False)
    name = contract.SUITE.replace(".", "/")
    with pytest.raises(contract.ArtifactError, match="assertion"):
        contract.jar_classes(zip_bytes([(name + ".class", class_bytes(name, "X.java"))]), sdk=True)


@pytest.mark.parametrize("mutation", ["entry", "target", "multi_release"])
def test_sdk_class_identity_and_java8_target_are_exact(mutation):
    name = contract.CORE_OWNERS[0]
    path = name + ".class"
    if mutation == "entry": path = "wrong.class"
    if mutation == "multi_release": path = "META-INF/versions/9/" + path
    with pytest.raises(contract.ArtifactError, match="JDK-8"):
        contract.jar_classes(zip_bytes([(path, class_bytes(name, "X.kt", major=53 if mutation == "target" else 52))]), sdk=True)


@pytest.mark.parametrize("mutation", ["missing", "embedded", "duplicate", "source"])
def test_actual_aar_owner_cannot_be_missing_substituted_or_shadowed(mutation):
    first, second = packages(); members = contract.archive_members(second)
    if mutation == "missing": del members["classes.jar"]
    if mutation == "embedded": members["libs/unreviewed.jar"] = first
    if mutation == "duplicate": members["classes.jar"] = first
    if mutation == "source": members["classes.jar"] = zip_bytes([(contract.ANDROID_OWNER + ".class", class_bytes(contract.ANDROID_OWNER, "Forged.java"))])
    with pytest.raises(contract.ArtifactError): contract.package_classes(first, zip_bytes(list(members.items())))


@pytest.mark.parametrize("missing", contract.GROUPS)
def test_each_java_assertion_group_is_required_in_compiled_owner(missing):
    name = contract.SUITE.replace(".", "/")
    raw = class_bytes(name, "SorafsReferenceValidatorsJavaConsumerTest.java", tuple(g for g in contract.GROUPS if g != missing))
    with pytest.raises(contract.ArtifactError, match="group"):
        contract.validate_test_classes({name: raw})


@pytest.mark.parametrize("missing", contract.GROUPS)
def test_each_java_assertion_group_must_execute(missing):
    value = report();value.remove(next(case for case in value if case.attrib["name"] == missing))
    with pytest.raises(contract.ArtifactError, match="omits"):
        contract.validate_report(ET.tostring(value))


@pytest.mark.parametrize("mutation", ["duplicate", "skip", "failure", "owner", "unknown", "nan", "infinity", "negative", "nested", "zero", "extra_field", "dtd_utf8", "dtd_utf16"])
def test_hostile_or_nonpassing_reports_reject(mutation):
    value = report()
    if mutation == "duplicate": value[1].set("name", value[0].attrib["name"])
    if mutation in ("skip", "failure"): ET.SubElement(value[0], "skipped" if mutation == "skip" else "failure")
    if mutation == "owner": value[0].set("classname", "forged")
    if mutation == "unknown": value[0].set("name", "unrelated")
    if mutation in ("nan", "infinity", "negative"): value[0].set("time", {"nan": "NaN", "infinity": "Infinity", "negative": "-1"}[mutation])
    if mutation == "nested": ET.SubElement(value[0], "testcase")
    if mutation == "zero": value.set("tests", "0")
    if mutation == "extra_field": value[0].set("ignored", "true")
    raw = ET.tostring(value)
    if mutation.startswith("dtd"):
        text = '<!DOCTYPE testsuite [<!ENTITY escaped "anything">]>' + raw.decode()
        raw = text.encode("utf-16" if mutation.endswith("16") else "utf-8")
    with pytest.raises(contract.ArtifactError): contract.validate_report(raw)


def load_log(jars):
    return "\n".join(f"[3ms][info][class,load] {name.replace('/', '.')} source: {path.as_uri()}" for path, classes in jars.items() for name in classes).encode()


def test_loaded_classes_and_native_origin_are_bound_to_real_bytes(tmp_path):
    jars = {tmp_path / "core.jar": core(), tmp_path / "android.jar": {contract.ANDROID_OWNER: class_bytes(contract.ANDROID_OWNER, "KeySecurityPreference.kt")}}
    rows = contract.validate_class_origins(load_log(jars), jars, android=True)
    assert len(rows) == 3 and rows[0]["size"] > 0
    native = tmp_path / "libconnect_norito_bridge.so"
    contract.validate_library_origin(f"[library] Loaded library {native}, handle 0x1\n".encode(), native)


@pytest.mark.parametrize("mutation", ["missing", "outside", "http", "duplicate", "unknown", "host", "query"])
def test_loaded_sdk_class_origin_is_not_a_caller_assertion(tmp_path, mutation):
    jars = {tmp_path / "core.jar": core()}; raw = load_log(jars)
    if mutation == "missing": raw = raw.split(b"\n")[0]
    if mutation == "outside": raw = raw.replace(b"core.jar", b"workspace-classes")
    if mutation == "http": raw = raw.replace(b"file:", b"https:")
    if mutation == "duplicate": raw += b"\n" + raw.split(b"\n")[0]
    if mutation == "unknown": raw = raw.replace(b"JsonParser", b"Unowned")
    if mutation == "host": raw = raw.replace(b"file:///", b"file://remote/")
    if mutation == "query": raw = raw.replace(b"core.jar", b"core.jar?override")
    with pytest.raises(contract.ArtifactError): contract.validate_class_origins(raw, jars, android=False)


@pytest.mark.parametrize("observed", ["", "elsewhere/libconnect_norito_bridge.so", "libconnect_norito_bridge.so\nlibconnect_norito_bridge.so"])
def test_wrong_or_repeated_native_load_does_not_qualify(tmp_path, observed):
    expected = tmp_path / "libconnect_norito_bridge.so"
    raw = "\n".join(f"[library] Loaded library {name}, handle 0x1" for name in observed.splitlines()).encode()
    with pytest.raises(contract.ArtifactError): contract.validate_library_origin(raw, expected)


def test_archive_replays_exact_member_bytes_and_metadata():
    files = {"manifest.json": contract.canonical_json({"cases": list(contract.GROUPS)}), "reports/junit.xml": ET.tostring(report())}
    first = contract.deterministic_archive(files)
    assert first == contract.deterministic_archive(dict(reversed(list(files.items()))))
    assert contract.archive_members(first) == files
    assert contract.identity(first) == {"sha256": __import__("hashlib").sha256(first).hexdigest(), "size": len(first)}


def test_stable_file_and_tree_capture_reject_links_and_growth(tmp_path, monkeypatch):
    target = tmp_path / "raw";target.write_bytes(b"abc")
    assert contract.read_file(target, 3) == b"abc"
    with pytest.raises(ValueError): contract.read_file(target, 2)
    linked = tmp_path / "link";linked.symlink_to(target)
    with pytest.raises(ValueError): contract.read_file(linked, 3)
    with pytest.raises(ValueError): producer.capture_tree(tmp_path, 32)
    linked.unlink();(tmp_path / "empty.log").write_bytes(b"")
    assert producer.capture_tree(tmp_path, 32) == {"empty.log": b"", "raw": b"abc"}
    with pytest.raises(ValueError): producer.capture_tree(tmp_path, 2)


def test_fresh_output_never_replaces_original(tmp_path):
    target = tmp_path / "output";producer.write_fresh(target, b"original")
    with pytest.raises(FileExistsError): producer.write_fresh(target, b"replacement")
    assert target.read_bytes() == b"original"


def test_command_runner_retains_real_exit_output_and_clears_jvm_injection(tmp_path, monkeypatch):
    monkeypatch.setenv("JAVA_TOOL_OPTIONS", "injected")
    log = tmp_path / "output.log"
    producer.run_command([sys.executable, "-c", "import os; assert 'JAVA_TOOL_OPTIONS' not in os.environ; print('ran')"], tmp_path, log, timeout=5)
    assert log.read_bytes() == b"ran\n"


@pytest.mark.parametrize("mode", ["failure", "output", "timeout"])
def test_owned_command_failure_never_becomes_qualification(tmp_path, monkeypatch, mode):
    monkeypatch.setattr(producer, "MAX_LOG_BYTES", 64)
    code = {"failure": "import sys; print('failure'); sys.exit(2)", "output": "print('x'*1024)", "timeout": "import time; time.sleep(5)"}[mode]
    log = tmp_path / "failure.log"
    with pytest.raises(contract.ArtifactError): producer.run_command([sys.executable, "-c", code], tmp_path, log, timeout=0.2 if mode == "timeout" else 5)
    assert log.exists() and not (tmp_path / "java-source-kotlin-consumer.zip").exists()


def test_dependency_manifest_pin_and_exact_inventory(tmp_path):
    source = tmp_path / "dependencies.json"
    source.write_bytes(contract.canonical_json({"schema": "sorafs.java_consumer.dependencies.v1", "jars": []}))
    with pytest.raises(contract.ArtifactError, match="independent pin"): producer.load_dependencies(source.read_bytes(), "0" * 64)
    with pytest.raises(contract.ArtifactError, match="incomplete"): producer.load_dependencies(source.read_bytes(), contract.identity(source.read_bytes())["sha256"])


def test_source_sets_keep_one_actual_java_owner_and_all_assertion_groups():
    source = (ROOT / producer.SOURCE).read_text()
    assert source.count("@Test") == 25
    assert '@Tag("host-native")' in source
    assert 'System.getProperty("iroha.sorafs.fixtureRoot")' in source
    assert 'src/sorafsJavaTest/java' in (ROOT / 'kotlin/core-jvm/build.gradle.kts').read_text()
    assert 'src/sorafsJavaTest/java' in (ROOT / 'kotlin/client-android/build.gradle.kts').read_text()
    assert not (ROOT / producer.SOURCE.replace('/sorafsJavaTest/', '/test/')).exists()


@pytest.mark.parametrize("name", ["org/junit/jupiter/engine/JupiterTestEngine", "org/hyperledger/iroha/qualification/SorafsJavaConsumerQualificationRunner", "kotlin/Forged"])
def test_sdk_package_cannot_replace_dependency_or_qualification_owners(name):
    with pytest.raises(contract.ArtifactError, match="foreign class"):
        contract.jar_classes(zip_bytes([(name + ".class", class_bytes(name, "Forged.kt"))]), sdk=True)


def test_zip_null_truncation_cannot_normalize_member_identity():
    raw = zip_bytes([("abcd", b"payload")]).replace(b"abcd", b"a\0cd")
    with pytest.raises(contract.ArtifactError, match="normalized"):
        contract.archive_members(raw)


def lambda_class_bytes(name, *, bootstrap_owner="java/lang/invoke/LambdaMetafactory", bootstrap_method="metafactory", malformed=None):
    """Synthetic constant-pool control, never executable qualification bytes."""
    def u2(v):return struct.pack(">H",v)
    def utf8(v):
        b=v.encode();return b"\x01"+u2(len(b))+b
    pool=[utf8(name),b"\x07"+u2(1),utf8("java/lang/Object"),b"\x07"+u2(3),utf8("BootstrapMethods"),utf8(bootstrap_owner),b"\x07"+u2(6),utf8(bootstrap_method),utf8("()V"),b"\x0c"+u2(8)+u2(9),b"\x0a"+u2(7)+u2(10),b"\x0f\x06"+u2(11)]
    payload=u2(1)+u2(12)+u2(0)
    if malformed=="handle":payload=u2(1)+u2(7)+u2(0)
    if malformed=="truncated":payload=payload[:-1]
    if malformed=="trailing":payload+=b"x"
    if malformed=="argument":payload=u2(1)+u2(12)+u2(1)+u2(99)
    prefix=b"\xca\xfe\xba\xbe"+u2(0)+u2(52)+u2(len(pool)+1)+b"".join(pool)
    prefix+=u2(0x21)+u2(2)+u2(4)+u2(0)+u2(0)+u2(0)
    attr=u2(5)+struct.pack(">I",len(payload))+payload
    return prefix+u2(2 if malformed=="duplicate" else 1)+attr*(2 if malformed=="duplicate" else 1)


@pytest.mark.parametrize("method", ["metafactory", "altMetafactory"])
def test_actual_classfile_bootstrap_metadata_recognizes_lambda_factory(method):
    assert contract.parse_class(lambda_class_bytes(contract.CORE_OWNERS[0],bootstrap_method=method)).lambda_metafactory
    assert not contract.parse_class(lambda_class_bytes(contract.CORE_OWNERS[0],bootstrap_owner="unrelated/Bootstrap",bootstrap_method=method)).lambda_metafactory
    assert not contract.parse_class(lambda_class_bytes(contract.CORE_OWNERS[0],bootstrap_method="unknown")).lambda_metafactory


@pytest.mark.parametrize("malformed", ["handle", "truncated", "trailing", "argument", "duplicate"])
def test_malformed_bootstrap_metadata_rejects(malformed):
    with pytest.raises(ValueError):contract.parse_class(lambda_class_bytes(contract.CORE_OWNERS[0],malformed=malformed))


def lambda_log(owner):
    name=owner.replace("/", ".")
    return f"[info][class,load] {name}$$Lambda/0x0000000000000001 source: {name}".encode()


def test_runtime_generated_lambda_binds_exact_previously_loaded_bootstrap_owner(tmp_path):
    owner=contract.CORE_OWNERS[0];classes=core();classes[owner]=lambda_class_bytes(owner)
    jars={tmp_path/"core.jar":classes}
    rows=contract.validate_class_origins(load_log(jars)+b"\n"+lambda_log(owner),jars,android=False)
    generated=next(row for row in rows if row.get("runtime_generated"))
    assert generated["enclosing_class"]==owner
    assert generated["enclosing_bytes"]==contract.identity(classes[owner])
    assert "sha256" not in generated


@pytest.mark.parametrize("mutation", ["before_owner", "foreign_origin", "unknown_owner", "bad_name", "no_bootstrap", "duplicate"])
def test_generated_lambda_does_not_exempt_unknown_sdk_code(tmp_path, mutation):
    owner=contract.CORE_OWNERS[0];classes=core()
    if mutation!="no_bootstrap":classes[owner]=lambda_class_bytes(owner)
    jars={tmp_path/"core.jar":classes};generated=lambda_log(owner);loaded=load_log(jars)
    if mutation=="foreign_origin":generated=generated.replace(b"source: org.hyperledger",b"source: unrelated.org.hyperledger")
    if mutation=="unknown_owner":generated=lambda_log(owner+"Unknown")
    if mutation=="bad_name":generated=generated.replace(b"$$Lambda/",b"$CustomGenerated/")
    raw=generated+b"\n"+loaded if mutation=="before_owner" else loaded+b"\n"+generated
    if mutation=="duplicate":raw+=b"\n"+generated
    with pytest.raises(contract.ArtifactError):contract.validate_class_origins(raw,jars,android=False)


def test_tree_inventory_limit_applies_during_enumeration(tmp_path, monkeypatch):
    calls=[]
    class Entry:
        def __init__(self,i):self.path=str(tmp_path/str(i))
        def is_symlink(self):return False
        def is_dir(self,follow_symlinks=False):return False
    class Entries:
        def __enter__(self):return self
        def __exit__(self,*args):return None
        def __iter__(self):
            for i in range(1000000):
                calls.append(i);yield Entry(i)
    monkeypatch.setattr(producer.os,"scandir",lambda path:Entries())
    monkeypatch.setattr(producer,"read_evidence_bytes",lambda path,limit:b"")
    with pytest.raises(contract.ArtifactError,match="excessive"):
        producer.capture_tree(tmp_path,32)
    assert len(calls)==4097


@pytest.mark.parametrize("flags", [0x0009,0x0401])
def test_compiled_groups_must_be_concrete_instance_methods(flags):
    owner=contract.SUITE.replace(".","/")
    raw=class_bytes(owner,"SorafsReferenceValidatorsJavaConsumerTest.java",contract.GROUPS,flags=flags)
    with pytest.raises(contract.ArtifactError):contract.validate_test_classes({owner:raw})


def test_tree_exact_budget_still_allows_empty_logs(tmp_path):
    (tmp_path/"raw").write_bytes(b"abc");(tmp_path/"empty").write_bytes(b"")
    assert producer.capture_tree(tmp_path,3)=={"empty":b"","raw":b"abc"}


def synthetic_producer_inputs(tmp_path, monkeypatch, mutation=None):
    """Unit fault injection only: mock compiler/native verification, never qualify SDK bytes."""
    from argparse import Namespace
    root=tmp_path/"source";root.mkdir();work=tmp_path/"work"
    for name in (producer.SOURCE,producer.RUNNER,producer.PROBE):
        target=root/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((ROOT/name).read_bytes())
    fixtures=root/"fixtures/sorafs_manifest";fixtures.mkdir(parents=True);(fixtures/"fixture").write_bytes(b"fixture")
    first,second=packages();core_path=tmp_path/"core.jar";aar_path=tmp_path/"client.aar";core_path.write_bytes(first);aar_path.write_bytes(second)
    expected_native={"darwin":"libconnect_norito_bridge.dylib","linux":"libconnect_norito_bridge.so","win32":"connect_norito_bridge.dll"}[sys.platform]
    native_path=tmp_path/expected_native;native_path.write_bytes(b"synthetic native")
    native_manifest=tmp_path/"native.json";native_manifest.write_bytes(b"synthetic manifest")
    checks=[]
    def verify(manifest,artifact_path,source_root):
        assert source_root==root and artifact_path.read_bytes()==b"synthetic native";checks.append(artifact_path)
    monkeypatch.setattr(producer,"parse_native_manifest",lambda raw:{"sdk":"c-jni","source_commit":"a"*40,"workspace_source_manifest_sha256":"b"*64})
    monkeypatch.setattr(producer.native,"verify_manifest",verify)
    dependencies=[]
    for i,module in enumerate(sorted(producer.DEPENDENCIES)):
        owner = {"org.junit.jupiter:junit-jupiter-engine": contract.DEPENDENCY_RUNTIME_OWNERS[0], "org.junit.platform:junit-platform-launcher": contract.DEPENDENCY_RUNTIME_OWNERS[1]}.get(module, "dependency/Owner" + str(i))
        path=tmp_path/(str(i)+".jar");raw=zip_bytes([(owner+".class",class_bytes(owner,"Dependency.java"))]);path.write_bytes(raw)
        dependencies.append({"module":module,"version":"1.0","path":str(path),**contract.identity(raw)})
    dependency_path=tmp_path/"dependencies.json";dependency_path.write_bytes(contract.canonical_json({"schema":"sorafs.java_consumer.dependencies.v1","jars":dependencies}))
    jdk=tmp_path/"jdk";jdk.mkdir()
    suffix=".exe" if sys.platform=="win32" else ""
    for relative in ("release","lib/modules","lib/ct.sym","bin/java"+suffix,"bin/javac"+suffix):
        path=jdk/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'JAVA_VERSION="21.0.0"\n' if relative=="release" else b"synthetic JDK")
    commands=[]
    def execute(command,cwd,log,**kwargs):
        commands.append(command);log.write_bytes(b"")
        classes=cwd/"classes";lane=cwd.name
        if command[0].endswith("javac"+suffix):
            assert command[command.index("--release")+1]=="8" and "-proc:none" in command and "-implicit:none" in command
            owner=contract.SUITE.replace(".","/");raw=class_bytes(owner,"SorafsReferenceValidatorsJavaConsumerTest.java",contract.GROUPS)
            if mutation=="compiled_owner":owner="unowned/Source"
            path=classes/(owner+".class");path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
            for name in ("SorafsJavaConsumerQualificationRunner", *(["SorafsAndroidPackageLinkProbe"] if lane == "android-host" else [])):
                if mutation == "missing_runner" and name == "SorafsJavaConsumerQualificationRunner":
                    continue
                if mutation == "missing_probe" and name == "SorafsAndroidPackageLinkProbe":
                    continue
                qualified = "org/hyperledger/iroha/qualification/" + name
                path = classes / (qualified + ".class")
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(class_bytes(qualified, name + ".java"))
        elif command[-1].endswith("SorafsAndroidPackageLinkProbe"):
            log.write_bytes(load_log({work/"packages/android-classes.jar":{contract.ANDROID_OWNER:b""}, classes:{"org/hyperledger/iroha/qualification/SorafsAndroidPackageLinkProbe":b""}})+b"\n")
        else:
            jars={work/"packages/core.jar":core(),classes:{contract.SUITE.replace(".","/"):b"", "org/hyperledger/iroha/qualification/SorafsJavaConsumerQualificationRunner":b""}}
            dependency_jars = contract.dependency_classpath({entry["module"]: Path(entry["path"]).read_bytes() for entry in dependencies}, work)
            log.write_bytes(load_log(jars)+b"\n"+load_log(dependency_jars)+b"\n"+b"[0.1s][info][library] Loaded library "+str(work/"native"/expected_native).encode()+b", handle 0x1\n"+producer.REPORT_PREFIX+base64.b64encode(ET.tostring(report()))+b"\n")
            if lane=="jvm":
                mutations={
                    "original_package":core_path,"private_package":work/"packages/core.jar",
                    "original_source":root/producer.SOURCE,"private_source":work/"sources/SorafsReferenceValidatorsJavaConsumerTest.java",
                    "original_fixture":fixtures/"fixture","private_fixture":work/"snapshot/fixtures/sorafs_manifest/fixture",
                    "compiled_drift":classes/(contract.SUITE.replace(".","/")+".class"),
                    "tool_drift":jdk/"lib/modules",
                    "producer_copy":work/"inputs/tools/sorafs_java_consumer_artifact.py",
                }
                if mutation in mutations:mutations[mutation].write_bytes(b"changed")
    monkeypatch.setattr(producer,"run_command",execute)
    if mutation=="report_after_validation":
        original=producer.validate_report
        def mutate_report(raw):
            result=original(raw);(work/"jvm/junit.xml").write_bytes(b"changed");return result
        monkeypatch.setattr(producer,"validate_report",mutate_report)
    args=Namespace(source_root=root,work_dir=work,core_jar=core_path,client_aar=aar_path,native_artifact=native_path,native_manifest=native_manifest,jdk_home=jdk,dependency_manifest=dependency_path,dependency_manifest_sha256=contract.identity(dependency_path.read_bytes())["sha256"])
    return args,commands,checks


def test_producer_joins_retained_exact_bytes_in_mocked_process_unit_boundary(tmp_path,monkeypatch):
    args,commands,checks=synthetic_producer_inputs(tmp_path,monkeypatch)
    result=producer.produce(args)
    assert len(commands)==5 and len(checks)==4
    assert result["lanes"]==["jvm","android-host"] and result["groups_per_lane"]==25
    members=contract.archive_members(Path(result["artifact"]).read_bytes());manifest=json.loads(members["manifest.json"])
    assert manifest["consumer"]=="java_source_kotlin" and len(manifest["executions"])==2
    for name,expected in manifest["retained"].items():assert contract.identity(members[name])==expected
    for lane in result["lanes"]:assert len(contract.validate_report(members[lane+"/junit.xml"]))==25
    assert members["sources/SorafsReferenceValidatorsJavaConsumerTest.java"]==(ROOT/producer.SOURCE).read_bytes()
    assert not any(key in manifest for key in ("qualified","production_ready","passed"))


@pytest.mark.parametrize("relative", ["target/qualification", "build/qualification", "sources/qualification"])
def test_producer_only_allows_in_tree_outputs_under_target(tmp_path, monkeypatch, relative):
    args, _, _ = synthetic_producer_inputs(tmp_path, monkeypatch)
    args.work_dir = args.source_root / relative
    args.work_dir.parent.mkdir(parents=True)
    def stop_at_capture(*_args):
        raise RuntimeError("reached original input capture")
    monkeypatch.setattr(producer, "read_file", stop_at_capture)
    if relative.startswith("target/"):
        with pytest.raises(RuntimeError, match="reached original input capture"): producer.produce(args)
        assert args.work_dir.is_dir()
    else:
        with pytest.raises(contract.ArtifactError, match="under target/"): producer.produce(args)
        assert not args.work_dir.exists()


@pytest.mark.parametrize("mutation", ["original_package","private_package","original_source","private_source","original_fixture","private_fixture","compiled_drift","tool_drift","producer_copy","report_after_validation","compiled_owner","missing_runner","missing_probe"])
def test_producer_preserves_refusal_instead_of_packaging_drift(tmp_path,monkeypatch,mutation):
    args,_commands,_checks=synthetic_producer_inputs(tmp_path,monkeypatch,mutation)
    with pytest.raises((ValueError,OSError)):producer.produce(args)
    assert not (args.work_dir/"java-source-kotlin-consumer.zip").exists()


def native_manifest_bytes():
    """Real native schema/codec inputs; synthetic artifact bytes never qualify."""
    return producer.native.canonical_manifest_bytes({
        "schema": producer.native.SCHEMA, "sdk": "c-jni", "target": "aarch64-apple-darwin",
        "artifact_sha256": contract.identity(b"synthetic native")["sha256"],
        "artifact_size": len(b"synthetic native"), "bridge_abi_version": 30,
        "source_commit": "a" * 40, "source_tree_clean": True,
        "workspace_source_manifest_sha256": "b" * 64,
        "required_symbols": list(producer.native.REQUIRED_SYMBOLS["c-jni"]),
        "privacy_c_exports": list(producer.native.APPROVED_PRIVACY_C_EXPORTS),
        "privacy_c_exports_inspected": True,
    })


def runtime_output(raw=None):
    value = ET.tostring(report()) if raw is None else raw
    return (b"[0.1s][info][class,load] java.lang.Object source: shared objects file\n"
            b"[0.1s][info][library] Loaded library /native/library, handle 0x1\n"
            + producer.REPORT_PREFIX + base64.b64encode(value) + b"\n")


def test_bounded_runtime_stream_joins_complete_original_bytes():
    raw = runtime_output()
    classes, libraries, xml = producer.consume_runtime_output(raw, report_required=True)
    assert classes in raw and libraries in raw
    assert xml == ET.tostring(report())
    assert contract.validate_report(xml) == contract.GROUPS


@pytest.mark.parametrize("mutation", ["missing", "repeated", "partial", "empty", "malformed_base64", "embedded", "no_classes", "no_library", "report_in_probe", "padbits", "extra_padding"])
def test_bounded_runtime_stream_rejects_lost_or_ambiguous_observations(mutation):
    raw = runtime_output()
    required = True
    if mutation == "missing": raw = raw[:raw.index(producer.REPORT_PREFIX)]
    elif mutation == "repeated": raw += raw[raw.index(producer.REPORT_PREFIX):]
    elif mutation == "partial": raw = raw.rstrip(b"\n")
    elif mutation == "empty": raw = b""
    elif mutation == "malformed_base64": raw = raw[:raw.index(producer.REPORT_PREFIX)] + producer.REPORT_PREFIX + b"?\n"
    elif mutation == "embedded": raw = raw.replace(producer.REPORT_PREFIX, b"noise" + producer.REPORT_PREFIX)
    elif mutation == "no_classes": raw = b"\n".join(raw.split(b"\n")[1:])
    elif mutation == "no_library": raw = b"\n".join(line for line in raw.split(b"\n") if b"[library]" not in line)
    elif mutation == "report_in_probe": required = False
    elif mutation == "padbits": raw = raw[:raw.index(producer.REPORT_PREFIX)] + producer.REPORT_PREFIX + b"Zh==\n"
    elif mutation == "extra_padding": raw = raw[:raw.index(producer.REPORT_PREFIX)] + producer.REPORT_PREFIX + b"YQ===\n"
    with pytest.raises(contract.ArtifactError): producer.consume_runtime_output(raw, report_required=required)


def test_combined_runtime_stream_cap_applies_before_retention(tmp_path, monkeypatch):
    monkeypatch.setattr(producer, "MAX_LOG_BYTES", 1024)
    # All three streams fit separately, but their one actual pipe must refuse.
    chunks = [b"[0.1s][info][class,load] " + b"x" * 400 + b"\n",
              b"[0.1s][info][library] " + b"x" * 400 + b"\n",
              producer.REPORT_PREFIX + base64.b64encode(b"x" * 300) + b"\n"]
    code = "import os; os.write(1, " + repr(b"".join(chunks)) + ")"
    with pytest.raises(contract.ArtifactError, match="output limit"):
        producer.run_command([sys.executable, "-c", code], tmp_path, tmp_path / "combined.log", timeout=5)
    assert (tmp_path / "combined.log").stat().st_size <= 1024
    assert set(path.name for path in tmp_path.iterdir()) == {"combined.log"}


def test_runtime_stream_report_byte_cap_precedes_decode(monkeypatch):
    monkeypatch.setattr(producer, "MAX_REPORT_BYTES", 2)
    with pytest.raises(contract.ArtifactError, match="byte limit"):
        producer.consume_runtime_output(runtime_output(b"long"), report_required=True)


@pytest.mark.parametrize("mutation", ["duplicate", "spacing", "unknown", "bool_integer", "missing", "utf16", "non_json", "empty", "oversized"])
def test_captured_native_parser_preserves_exact_original_native_codec(mutation):
    raw = native_manifest_bytes()
    assert producer.parse_native_manifest(raw)["source_commit"] == "a" * 40
    value = json.loads(raw)
    if mutation == "duplicate": raw = raw.replace(b'{', b'{"sdk":"c-jni",', 1)
    elif mutation == "spacing": raw = json.dumps(value, indent=2).encode()
    elif mutation == "unknown": value["extra"] = 1; raw = contract.canonical_json(value)
    elif mutation == "bool_integer": value["artifact_size"] = True; raw = contract.canonical_json(value)
    elif mutation == "missing": del value["required_symbols"]; raw = contract.canonical_json(value)
    elif mutation == "utf16": raw = raw.decode().encode("utf-16")
    elif mutation == "non_json": raw = raw.replace(b'"artifact_size":16', b'"artifact_size":NaN')
    elif mutation == "empty": raw = b""
    elif mutation == "oversized": raw = b" " * (producer.native.MAX_MANIFEST_BYTES + 1)
    with pytest.raises((ValueError, RuntimeError)): producer.parse_native_manifest(raw)


def test_captured_dependency_pin_refuses_transient_reopened_substitute(tmp_path, monkeypatch):
    args, _commands, _checks = synthetic_producer_inputs(tmp_path, monkeypatch)
    pinned = args.dependency_manifest.read_bytes()
    retained = json.loads(pinned)
    for row in retained["jars"]: row["version"] = "9.9"
    captured = contract.canonical_json(retained)
    args.dependency_manifest.write_bytes(captured)
    original = producer.read_file
    reads = []
    def transient(path, maximum):
        if path == args.dependency_manifest:
            reads.append(path)
            if len(reads) == 2:
                path.write_bytes(pinned)
                try: return original(path, maximum)
                finally: path.write_bytes(captured)
        return original(path, maximum)
    monkeypatch.setattr(producer, "read_file", transient)
    with pytest.raises(contract.ArtifactError, match="independent pin"): producer.produce(args)
    assert len(reads) == 1 and args.dependency_manifest.read_bytes() == captured
    assert not (args.work_dir / "java-source-kotlin-consumer.zip").exists()


def test_captured_native_manifest_never_reopens_for_parsing(tmp_path, monkeypatch):
    parser = producer.parse_native_manifest
    args, _commands, checks = synthetic_producer_inputs(tmp_path, monkeypatch)
    captured = native_manifest_bytes()
    value = json.loads(captured); value["source_commit"] = "c" * 40
    substitute = producer.native.canonical_manifest_bytes(value)
    args.native_manifest.write_bytes(captured)
    parsed = []
    def inspect(raw):
        assert raw == captured
        args.native_manifest.write_bytes(substitute)
        try:
            result = parser(raw); parsed.append(result["source_commit"]); return result
        finally: args.native_manifest.write_bytes(captured)
    def forbidden_reopen(*args): raise AssertionError("a second manifest owner was requested")
    monkeypatch.setattr(producer, "parse_native_manifest", inspect)
    monkeypatch.setattr(producer.native, "load_manifest", forbidden_reopen)
    result = producer.produce(args)
    members = contract.archive_members(Path(result["artifact"]).read_bytes())
    manifest = json.loads(members["manifest.json"])
    assert parsed == ["a" * 40] and len(checks) == 4
    assert manifest["source_commit"] == json.loads(members["inputs/native-abi30.json"])["source_commit"] == "a" * 40


@pytest.mark.parametrize("mutation", ["rotated_origin", "unknown_output", "bad_early_origin", "repeated_report"])
def test_producer_rejects_unobserved_or_rotated_output(tmp_path, monkeypatch, mutation):
    args, commands, _checks = synthetic_producer_inputs(tmp_path, monkeypatch)
    original = producer.run_command
    def execute(command, cwd, log, **kwargs):
        original(command, cwd, log, **kwargs)
        if command[-1].endswith("SorafsJavaConsumerQualificationRunner"):
            assert not any(":file=" in value for value in command)
            if mutation == "rotated_origin": (cwd / "classes.log.0").write_text("bad origin")
            elif mutation == "unknown_output": (cwd / "unobserved").write_text("not observed")
            elif mutation == "bad_early_origin": log.write_bytes(b"[0.1s][info][class,load] org.hyperledger.iroha.sdk.Substituted source: file:///unowned.jar\n" + log.read_bytes())
            elif mutation == "repeated_report": log.write_bytes(log.read_bytes() + producer.REPORT_PREFIX + base64.b64encode(ET.tostring(report())) + b"\n")
    monkeypatch.setattr(producer, "run_command", execute)
    with pytest.raises(contract.ArtifactError): producer.produce(args)
    assert commands and not (args.work_dir / "java-source-kotlin-consumer.zip").exists()


def test_fixed_java_runner_has_no_direct_report_file_or_unbounded_result_records():
    raw = (ROOT / producer.RUNNER).read_text()
    assert "java.nio.file" not in raw and "Files.write" not in raw
    for bound in ("started.size() >= 25", "elapsed.size() >= 25", "{0,255}", "report.length > 16 * 1024", "System.out.checkError()"):
        assert bound in raw


@pytest.mark.parametrize("spaces", [0, 1, 3])
def test_runtime_library_tag_accepts_actual_jdk_column_padding(spaces):
    raw = runtime_output().replace(b"[library]", b"[library" + b" " * spaces + b"]")
    classes, library, report_raw = producer.consume_runtime_output(raw, report_required=True)
    assert classes and report_raw and b"Loaded library" in library
