#!/usr/bin/env python3
"""Publication command/filesystem contracts using explicit synthetic build stubs.

No Gradle/native/remote/cosign execution or release qualification is claimed.
Git source checks run against a temporary genuine fixture repository only.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class PublicationContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="android-publication-contract.")
        self.directory = Path(self.temp.name).resolve()
        self.repo = self.directory / "repo"
        self.artifacts = self.directory / "artifacts"
        self.artifacts.mkdir()
        (self.repo / "scripts").mkdir(parents=True)
        for name in ["publish_android_sdk.sh", "android_publish_snapshot.sh", "mobile_sdk_android_publication.py", "mobile_sdk_android_artifacts.py"]:
            shutil.copy2(ROOT / "scripts" / name, self.repo / "scripts" / name)
        (self.repo / "kotlin").mkdir()
        self.gradle = self.repo / "kotlin/gradlew"
        self.gradle.write_text('''#!/usr/bin/env python3
import hashlib,json,os,pathlib,subprocess,sys,zipfile
args=sys.argv[1:]
root=pathlib.Path(__file__).resolve().parent.parent
artifacts=pathlib.Path(os.environ['MOBILE_SDK_ANDROID_ARTIFACT_DIR'])
version=next(value.split('=',1)[1] for value in args if value.startswith('-PirohaSdkVersion='))
repo=pathlib.Path(next(value.split('=',1)[1] for value in args if value.startswith('-PirohaSdkRepoDir=')))
remote=any('ToRemoteSdkRepository' in value for value in args)
with (artifacts/'calls.jsonl').open('a') as log:
 log.write(json.dumps({'args':args,'remote':remote,'username_present':bool(os.environ.get('IROHA_SDK_MAVEN_USERNAME')),'password_present':bool(os.environ.get('IROHA_SDK_MAVEN_PASSWORD'))})+'\\n')
if remote:
 if os.environ.get('FIXTURE_REMOTE_FAIL')=='1':sys.exit(71)
 sys.exit(0)
commit=subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip()
build=artifacts/'gradle-build/iroha_kotlin_sdk'
for module,dependency in [('core-jvm',''),('client-android','core-jvm'),('kagemusha-wallet-android','client-android')]:
 extension='jar' if module=='core-jvm' else 'aar'
 output=build/module/(f'libs/core-jvm-{version}.jar' if module=='core-jvm' else f'outputs/aar/{module}-release.aar')
 output.parent.mkdir(parents=True,exist_ok=True)
 if module=='core-jvm': output.write_bytes(b'public managed fixture')
 else:
  with zipfile.ZipFile(output,'w') as archive:
   archive.writestr('AndroidManifest.xml','<manifest/>');archive.writestr('classes.jar',b'managed fixture')
   if module=='client-android':
    abis=['arm64-v8a','armeabi-v7a','x86_64']
    if os.environ.get('FIXTURE_OMIT_ARMV7')=='1':abis.remove('armeabi-v7a')
    native_bytes=b'synthetic native fixture'
    libraries={abi:{'aar_path':f'jni/{abi}/libconnect_norito_bridge.so','bytes':len(native_bytes),'sha256':hashlib.sha256(native_bytes).hexdigest()}for abi in abis}
    payload=json.dumps({'schema':'iroha.android-native-build-provenance.v1','build_profile':'release','privacy_production_enabled':True,'cargo_locked':True,'source_tree_dirty':False,'source_commit':commit,'libraries':libraries}).encode()
    provenance=build/module/'generated/nativeProvenance/production/iroha/native-build-provenance-v1.json'
    provenance.parent.mkdir(parents=True,exist_ok=True);provenance.write_bytes(payload)
    archive.writestr('assets/iroha/native-build-provenance-v1.json',payload)
    for abi in abis:
     native=build/module/f'generated/jniLibs/production/{abi}/libconnect_norito_bridge.so'
     native.parent.mkdir(parents=True,exist_ok=True);native.write_bytes(native_bytes)
     archive.writestr(f'jni/{abi}/libconnect_norito_bridge.so',native_bytes)
 deps=(f'<dependencies><dependency><groupId>org.hyperledger.iroha.sdk</groupId><artifactId>{dependency}</artifactId><version>{version}</version></dependency></dependencies>' if dependency else '')
 pom=f'<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion><groupId>org.hyperledger.iroha.sdk</groupId><artifactId>{module}</artifactId><version>{version}</version><packaging>{extension}</packaging>{deps}</project>'
 generated=build/module/'publications/release/pom-default.xml';generated.parent.mkdir(parents=True,exist_ok=True);generated.write_text(pom)
 directory=repo/'org/hyperledger/iroha/sdk'/module/version;directory.mkdir(parents=True)
 published=directory/f'{module}-{version}.{extension}';published.write_bytes(output.read_bytes())
 (directory/f'{module}-{version}.pom').write_text(pom)
 variants=[]
 for usage in ['java-api','java-runtime']:
  attributes={'org.gradle.category':'library','org.gradle.dependency.bundling':'external','org.gradle.libraryelements':extension,'org.gradle.usage':usage}
  if module=='core-jvm':attributes['org.gradle.jvm.version']=8
  dependencies=[{'group':'org.hyperledger.iroha.sdk','module':dependency,'version':{'requires':version}}] if dependency else []
  variants.append({'name':usage,'attributes':attributes,'dependencies':dependencies,'files':[{'name':published.name,'url':published.name,'size':published.stat().st_size,'sha256':hashlib.sha256(published.read_bytes()).hexdigest()}]})
 (directory/f'{module}-{version}.module').write_text(json.dumps({'formatVersion':'1.1','component':{'group':'org.hyperledger.iroha.sdk','module':module,'version':version},'variants':variants}))
if os.environ.get('FIXTURE_CHANGE_SOURCE')=='1':(root/'changed-source.txt').write_text('changed source')
''')
        self.gradle.chmod(0o755)
        (self.repo / "scripts/check_mobile_sdk_artifacts.sh").write_text("#!/bin/bash\nexit 0\n")
        (self.repo / "scripts/android_sbom_provenance.sh").write_text('''#!/usr/bin/env python3
import json,os,pathlib,sys
output=pathlib.Path(os.environ['MOBILE_SDK_SBOM_OUTPUT_DIR']);output.mkdir()
for module in ['core-jvm','client-android','kagemusha-wallet-android']:
 path=output/f'iroha-{module}.cyclonedx.json'
 path.write_text(json.dumps({'bomFormat':'CycloneDX','metadata':{'component':{'group':'org.hyperledger.iroha.sdk','name':module,'version':sys.argv[1]}},'components':[]}))
 path.with_suffix(path.suffix+'.sigstore').write_text('explicit synthetic signature fixture')
''')
        # The production caller explicitly executes SBOM via bash, so retain that
        # exact script process boundary while delegating only this fixture body.
        body = self.repo / "scripts/fixture_sbom.py"
        (self.repo / "scripts/android_sbom_provenance.sh").rename(body)
        (self.repo / "scripts/android_sbom_provenance.sh").write_text('#!/bin/bash\nexec "$MOBILE_SDK_PYTHON_BINARY" -I -S -B "$(dirname "$0")/fixture_sbom.py" "$@"\n')
        self.git(["init", "-q"])
        self.git(["config", "user.name", "Fixture"])
        self.git(["config", "user.email", "fixture@example.invalid"])
        self.git(["add", "."])
        self.git(["commit", "-qm", "synthetic publication command fixture"])

    def tearDown(self):
        self.temp.cleanup()

    def git(self, args):
        return subprocess.run(["git", "-C", str(self.repo), *args], check=True, capture_output=True)

    def run_publisher(self, *args, **updates):
        env = os.environ.copy()
        for name in list(env):
            if name.startswith(("ANDROID_PUBLISH_", "IROHA_SDK_MAVEN_")):
                del env[name]
        env.update(MOBILE_SDK_ANDROID_ARTIFACT_DIR=str(self.artifacts), MOBILE_SDK_PYTHON_BINARY=str(Path(sys.executable).resolve()))
        env.update(updates)
        return subprocess.run(["/bin/bash", str(self.repo / "scripts/publish_android_sdk.sh"), "--version", "1.2.3", *args], env=env, capture_output=True, text=True)

    def test_local_publication_calls_all_canonical_modules_and_keeps_receipt(self):
        result = self.run_publisher()
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in (self.artifacts / "calls.jsonl").read_text().splitlines()]
        self.assertEqual(len(calls), 1)
        for module in ["core-jvm", "client-android", "kagemusha-wallet-android"]:
            self.assertIn(f":{module}:publishReleasePublicationToMobileSdkRepository", calls[0]["args"])
        self.assertFalse(any(value.startswith("-PprivacyProductionEnabled") for value in calls[0]["args"]))
        self.assertEqual(
            [argument for argument in calls[0]["args"] if argument.startswith(":")],
            [f":{module}:publishReleasePublicationToMobileSdkRepository"
             for module in ["core-jvm", "client-android", "kagemusha-wallet-android"]],
        )
        report = json.loads((self.artifacts / "publication-1.2.3/publish_summary.json").read_text())
        self.assertEqual(report["modules"], ["core-jvm", "client-android", "kagemusha-wallet-android"])
        self.assertFalse(report["release_qualification"])
        self.assertEqual(report["version"], "1.2.3")

    def test_prior_two_abi_publication_has_no_receipt(self):
        result = self.run_publisher(FIXTURE_OMIT_ARMV7="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exact three-ABI native provenance", result.stderr)
        self.assertFalse((self.artifacts / "publication-1.2.3").exists())

    def test_sbom_generation_requires_original_canonical_unit_suites(self):
        source = (ROOT / "scripts/android_sbom_provenance.sh").read_text()
        command = source.split('"$SDK_GRADLE_WRAPPER" -p', 1)[1].split("\ncollect_sbom_reports", 1)[0]
        for task in self.required_quality_tasks():
            self.assertIn(task, command)
        self.assertNotIn(":lint", command)
        for module in ["core-jvm", "client-android", "kagemusha-wallet-android"]:
            self.assertIn(f":{module}:cyclonedxDirectBom", command)

    def test_remote_tasks_follow_local_admission_with_environment_only_credentials(self):
        result = self.run_publisher("--repo-url", "https://maven.example.invalid/releases", ANDROID_PUBLISH_REPO_USERNAME="synthetic-user", ANDROID_PUBLISH_REPO_PASSWORD="synthetic-runtime-secret")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in (self.artifacts / "calls.jsonl").read_text().splitlines()]
        self.assertEqual([entry["remote"] for entry in calls], [False, True])
        for module in ["core-jvm", "client-android", "kagemusha-wallet-android"]:
            self.assertIn(f":{module}:publishReleasePublicationToRemoteSdkRepository", calls[1]["args"])
        self.assertTrue(calls[1]["password_present"])
        public = result.stdout + result.stderr + (self.artifacts / "publication-1.2.3/publish_summary.json").read_text() + json.dumps(calls)
        self.assertNotIn("synthetic-runtime-secret", public)
        self.assertNotIn("-PirohaAndroid", public)

    def test_remote_failure_preserves_local_graph_and_does_not_claim_receipt(self):
        result = self.run_publisher("--repo-url", "https://maven.example.invalid/releases", FIXTURE_REMOTE_FAIL="1")
        self.assertEqual(result.returncode, 71)
        self.assertTrue((self.artifacts / "maven").is_dir())
        self.assertFalse((self.artifacts / "publication-1.2.3").exists())

    def test_dirty_or_changed_source_refuses_remote_publication(self):
        result = self.run_publisher("--repo-url", "https://maven.example.invalid/releases", FIXTURE_CHANGE_SOURCE="1")
        self.assertNotEqual(result.returncode, 0)
        calls = [json.loads(line) for line in (self.artifacts / "calls.jsonl").read_text().splitlines()]
        self.assertEqual(len(calls), 1)
        self.assertFalse((self.artifacts / "publication-1.2.3").exists())

    def test_existing_outputs_are_never_replaced(self):
        output = self.artifacts / "maven"
        output.mkdir(); sentinel = output / "keep.txt"; sentinel.write_text("preserve")
        result = self.run_publisher()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(sentinel.read_text(), "preserve")
        self.assertFalse((self.artifacts / "calls.jsonl").exists())

    def test_skip_sbom_and_insecure_or_embedded_credential_url_refuse_before_tasks(self):
        for args in [("--skip-sbom",), ("--repo-url", "http://maven.example.invalid/releases"),
                     ("--repo-url", "https://user:password@maven.example.invalid/releases")]:
            result = self.run_publisher(*args)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((self.artifacts / "calls.jsonl").exists())

    def test_runtime_credential_pair_and_dry_run_do_not_log_secrets_or_build(self):
        result = self.run_publisher("--dry-run", "--repo-url", "https://maven.example.invalid/releases", ANDROID_PUBLISH_REPO_USERNAME="synthetic-user", ANDROID_PUBLISH_REPO_PASSWORD="synthetic-runtime-secret")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("synthetic-runtime-secret", result.stdout + result.stderr)
        self.assertIn(":kagemusha-wallet-android:publishReleasePublicationToRemoteSdkRepository", result.stdout)
        self.assertFalse((self.artifacts / "calls.jsonl").exists())
        self.assertFalse((self.artifacts / "maven").exists())
        incomplete = self.run_publisher("--repo-url", "https://maven.example.invalid/releases", ANDROID_PUBLISH_REPO_USERNAME="synthetic-user")
        self.assertNotEqual(incomplete.returncode, 0)
        self.assertFalse((self.artifacts / "calls.jsonl").exists())

    def test_release_pipeline_keeps_credentials_out_of_public_command_and_owns_outputs(self):
        source = (ROOT / "scripts/run_release_pipeline.py").read_text()
        block = source.split("    if args.publish_android_sdk:", 1)[1].split("    fastpq_grafana_rel:", 1)[0]
        self.assertNotIn('publish_cmd.extend(["--password"', block)
        self.assertNotIn('publish_cmd.extend(["--username"', block)
        self.assertIn('publisher_env["ANDROID_PUBLISH_REPO_PASSWORD"]', block)
        self.assertIn('lambda: run(publish_cmd, env=publisher_env)', block)
        self.assertIn('"--sbom-dir", str(android_sbom_dir)', block)
        self.assertNotIn('REPO_ROOT / "artifacts" / "android"', block)
        self.assertNotIn('"--android-sdk-skip-sbom"', source)

    def test_all_three_gradle_repository_blocks_preserve_jdk8_api_gates(self):
        for module in ["core-jvm", "client-android", "kagemusha-wallet-android"]:
            source = (ROOT / f"kotlin/{module}/build.gradle.kts").read_text()
            self.assertIn('name = "remoteSdk"', source)
            self.assertIn('providers.environmentVariable("IROHA_SDK_MAVEN_PASSWORD")', source)
            self.assertIn('freeCompilerArgs.add("-Xjdk-release=8")', source)
            self.assertIn('name = "mobileSdk"', source)
            self.assertNotIn("irohaAndroidRepo", source)

    @staticmethod
    def required_quality_tasks():
        return [":core-jvm:test", ":client-android:testDebugUnitTest",
                ":client-android:testDebugHostNative",
                ":kagemusha-wallet-android:testDebugUnitTest"]

    def retain_actual_sbom_process_boundary(self):
        # Execute the real SBOM shell and publisher; only Gradle, collection and
        # signing are synthetic. This verifies gating, not SDK/native execution.
        shutil.copy2(ROOT / "scripts/android_sbom_provenance.sh",
                     self.repo / "scripts/android_sbom_provenance.sh")
        body = self.gradle.read_text()
        marker = "repo=pathlib.Path(next(value.split('=',1)[1] for value in args if value.startswith('-PirohaSdkRepoDir=')))"
        boundary = r'''
if any(value.endswith(':cyclonedxDirectBom') for value in args):
 with (artifacts/'calls.jsonl').open('a') as log:
  log.write(json.dumps({'args':args,'phase':'quality','remote':False})+'\n')
 if os.environ.get('FIXTURE_QUALITY_FAIL') in args:sys.exit(74)
 for module in ['core-jvm','client-android','kagemusha-wallet-android']:
  bom=artifacts/'gradle-build/iroha_kotlin_sdk'/module/'reports/bom/bom.json';bom.parent.mkdir(parents=True,exist_ok=True)
  bom.write_text(json.dumps({'bomFormat':'CycloneDX','metadata':{'component':{'group':'org.hyperledger.iroha.sdk','name':module,'version':version}},'components':[]}))
 sys.exit(0)
'''
        self.assertEqual(body.count(marker), 1)
        self.gradle.write_text(body.replace(marker, boundary + marker))
        cosign = self.repo / "scripts/fixture_cosign.py"
        cosign.write_text(r'''
#!/usr/bin/env python3
import os,pathlib,sys
args=sys.argv[1:]
with (pathlib.Path(os.environ['MOBILE_SDK_ANDROID_ARTIFACT_DIR'])/'signing.log').open('a') as log:log.write(args[-1]+'\n')
pathlib.Path(args[args.index('--bundle')+1]).write_text('explicit synthetic signature fixture')
'''.lstrip())
        cosign.chmod(0o700)
        self.git(["add", "."])
        self.git(["commit", "-qm", "retain real SBOM gate with synthetic children"])
        return str(cosign)

    def test_each_required_unit_failure_prevents_signing_and_any_publication(self):
        cosign = self.retain_actual_sbom_process_boundary()
        for task in self.required_quality_tasks():
            with self.subTest(task=task):
                calls_path = self.artifacts / "calls.jsonl"
                calls_path.unlink(missing_ok=True)
                result = self.run_publisher("--repo-url", "https://maven.example.invalid/releases",
                                            COSIGN=cosign, FIXTURE_QUALITY_FAIL=task)
                self.assertEqual(result.returncode, 74, result.stderr)
                calls = [json.loads(line) for line in calls_path.read_text().splitlines()]
                self.assertEqual(len(calls), 1)
                self.assertEqual(calls[0]["phase"], "quality")
                self.assertTrue(all(required in calls[0]["args"]
                                    for required in self.required_quality_tasks()))
                for output in ["maven", "sbom-1.2.3", "publication-1.2.3", "signing.log"]:
                    self.assertFalse((self.artifacts / output).exists(), output)

    def test_actual_sbom_gate_precedes_signing_local_and_remote_publication(self):
        cosign = self.retain_actual_sbom_process_boundary()
        result = self.run_publisher("--repo-url", "https://maven.example.invalid/releases", COSIGN=cosign)
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in (self.artifacts / "calls.jsonl").read_text().splitlines()]
        self.assertEqual(len(calls), 3)
        self.assertEqual(calls[0]["phase"], "quality")
        self.assertEqual([call["remote"] for call in calls], [False, False, True])
        self.assertEqual([arg for arg in calls[0]["args"] if arg.startswith(":")],
                         self.required_quality_tasks() +
                         [f":{module}:cyclonedxDirectBom" for module in
                          ["core-jvm", "client-android", "kagemusha-wallet-android"]])
        self.assertEqual(len((self.artifacts / "signing.log").read_text().splitlines()), 3)
        self.assertTrue((self.artifacts / "publication-1.2.3/publish_summary.json").is_file())

if __name__ == "__main__":
    unittest.main()
