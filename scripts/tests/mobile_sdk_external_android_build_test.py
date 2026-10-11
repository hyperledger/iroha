"""Exercise actual Gradle/Kotlin cache routing without any Android or Native task.

Requires JDK 21, the wrapper's Gradle distribution, and cached Kotlin plugin
dependencies. Set MOBILE_SDK_TEST_GRADLE to that distribution's bin/gradle to
enable these offline integration tests. Test fixtures are disposable source
trees, not authenticated release captures; the maintained settings script is
copied unchanged and every source path, mode and byte is checked after building.
"""

from pathlib import Path
import hashlib
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
GRADLE = os.environ.get("MOBILE_SDK_TEST_GRADLE")
SETTINGS_SCRIPT = ROOT / "gradle/mobile-sdk-external-android-build.settings.gradle.kts"


@unittest.skipUnless(GRADLE, "set MOBILE_SDK_TEST_GRADLE to enable real offline Gradle tests")
class MobileSdkExternalAndroidBuildTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="iroha-external-gradle-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.source = self.base / "source"
        self.sdk = self.source / "kotlin"
        self.app = self.base / "app"
        self.artifacts = self.base / "artifacts"
        for directory in (self.source / ".git", self.source / "gradle",
                          self.sdk / "src/main/kotlin", self.app, self.artifacts):
            directory.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(SETTINGS_SCRIPT, self.source / "gradle" / SETTINGS_SCRIPT.name)
        version = re.search(
            r'^kotlin = "([^"]+)"$',
            (ROOT / "kotlin/gradle/libs.versions.toml").read_text(), re.MULTILINE,
        )[1]
        (self.sdk / "settings.gradle.kts").write_text(
            'pluginManagement { repositories { google(); gradlePluginPortal(); mavenCentral() } }\n'
            'rootProject.name = "sdk_cache_fixture"\n'
            'apply(from = "../gradle/mobile-sdk-external-android-build.settings.gradle.kts")\n'
        )
        (self.sdk / "build.gradle.kts").write_text(
            f'plugins {{ kotlin("jvm") version "{version}" }}\n'
            'repositories { mavenCentral() }\n'
            'tasks.register("cacheProbe") { dependsOn("compileKotlin"); doLast {\n'
            '    println("SDK_PROJECT_CACHE=" + gradle.startParameter.projectCacheDir)\n'
            '    println("SDK_KOTLIN_CACHE=" + findProperty("kotlin.project.persistent.dir"))\n'
            '} }\n'
        )
        (self.sdk / "src/main/kotlin/CacheProbe.kt").write_text('class CacheProbe\n')
        (self.app / "settings.gradle.kts").write_text(
            'rootProject.name = "app_cache_fixture"\n'
            'includeBuild("../source/kotlin") { name = "sdk_cache_fixture" }\n'
        )
        (self.app / "build.gradle.kts").write_text(
            'tasks.register("probe") {\n'
            '    dependsOn(gradle.includedBuild("sdk_cache_fixture").task(":cacheProbe"))\n'
            '}\n'
        )

    def inventory(self):
        return {
            str(path.relative_to(self.source)): (
                stat.S_IMODE(path.stat().st_mode),
                hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None,
            )
            for path in [self.source, *self.source.rglob("*")]
        }

    def run_gradle(self, *, composite, external=True):
        environment = os.environ.copy()
        environment.pop("MOBILE_SDK_ANDROID_ARTIFACT_DIR", None)
        if external:
            environment["MOBILE_SDK_ANDROID_ARTIFACT_DIR"] = str(self.artifacts)
        # Caller properties cannot allow an included build to write its own
        # source. The maintained settings route supersedes this unsafe value.
        selected_kotlin_cache = self.sdk / "caller-selected-kotlin-cache"
        result = subprocess.run(
            [GRADLE, "-p", str(self.app if composite else self.sdk),
             "probe" if composite else "cacheProbe", "--offline", "--console=plain",
             "--no-daemon", "--no-configuration-cache",
             "--project-cache-dir", str(self.base / "caller-project-cache"),
             f"-Pkotlin.project.persistent.dir={selected_kotlin_cache}"],
            env=environment, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    def assert_external_compile(self, composite):
        before = self.inventory()
        output = self.run_gradle(composite=composite)
        self.assertEqual(self.inventory(), before)
        build = self.artifacts / "gradle-build/sdk_cache_fixture"
        self.assertIn(f"SDK_KOTLIN_CACHE={build / 'kotlin-persistent'}", output)
        self.assertTrue((build / "root/classes/kotlin/main/CacheProbe.class").is_file())
        self.assertTrue(any((self.base / "caller-project-cache").rglob("*.bin")))
        self.assertTrue((build / "kotlin-persistent/sessions").is_dir())

    def test_direct_sdk_compile_preserves_all_source_paths_modes_and_bytes(self):
        self.assert_external_compile(composite=False)

    def test_included_sdk_compile_preserves_all_source_paths_modes_and_bytes(self):
        self.assert_external_compile(composite=True)

    def test_without_external_artifact_selection_keeps_caller_and_developer_paths(self):
        output = self.run_gradle(composite=False, external=False)
        self.assertIn(f"SDK_PROJECT_CACHE={self.base / 'caller-project-cache'}", output)
        self.assertIn(f"SDK_KOTLIN_CACHE={self.sdk / 'caller-selected-kotlin-cache'}", output)
        self.assertTrue((self.sdk / "build/classes/kotlin/main/CacheProbe.class").is_file())
        self.assertTrue((self.sdk / "caller-selected-kotlin-cache/sessions").is_dir())
        self.assertEqual(list(self.artifacts.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
