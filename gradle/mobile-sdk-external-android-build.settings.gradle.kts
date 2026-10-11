import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path

/*
 * A reviewed mobile Release supplies one canonical external Android artifact
 * root. Redirect every project in each included Iroha build below that root so
 * a read-only reviewed source mount never receives Gradle or native outputs.
 * Debug/developer builds retain Gradle's normal local build directories when
 * the variable is absent.
 */
fun validateLocalAndroidArtifactDirectory(root: Path, artifacts: Path) {
    val rawPython = System.getenv("MOBILE_SDK_PYTHON_BINARY")
        ?: throw GradleException("Local Android integration requires MOBILE_SDK_PYTHON_BINARY")
    val python = Path.of(rawPython)
    require(python.isAbsolute && python.normalize() == python &&
        python.toRealPath() == python &&
        Files.isRegularFile(python, LinkOption.NOFOLLOW_LINKS) &&
        !Files.isSymbolicLink(python) && Files.isExecutable(python)) {
        "MOBILE_SDK_PYTHON_BINARY must be one canonical regular executable"
    }
    val process = ProcessBuilder(
        python.toString(), "-I", "-S", "-B",
        root.resolve("scripts/mobile_sdk_android_artifacts.py").toString(),
        "--root", root.toString(), "--artifact-dir", artifacts.toString(),
        "--validate-local-root",
    ).directory(root.toFile()).redirectErrorStream(true)
    process.environment().clear()
    process.environment().putAll(mapOf("PATH" to "/usr/bin:/bin", "LANG" to "C.UTF-8"))
    val child = process.start()
    val output = child.inputStream.bufferedReader().use { it.readText() }.trim()
    require(child.waitFor() == 0 && output == artifacts.toString()) {
        "Local Android artifact custody validation failed: $output"
    }
}

val localAndroidIntegrationInput =
    providers.gradleProperty("irohaAndroidLocalIntegration").orNull ?: "false"
require(localAndroidIntegrationInput in setOf("true", "false")) {
    "irohaAndroidLocalIntegration must be exactly true or false"
}
val localAndroidIntegration = localAndroidIntegrationInput == "true"
val mobileSdkAndroidArtifactDirectory =
    providers.environmentVariable("MOBILE_SDK_ANDROID_ARTIFACT_DIR").orNull

require(!localAndroidIntegration || mobileSdkAndroidArtifactDirectory != null) {
    "Local Android integration requires an explicit artifact directory"
}
if (localAndroidIntegration) {
    gradle.taskGraph.whenReady {
        require(allTasks.none { it.name.startsWith("publish", ignoreCase = true) }) {
            "Local Android integration artifacts cannot be published"
        }
    }
}

if (mobileSdkAndroidArtifactDirectory != null) {
    require(mobileSdkAndroidArtifactDirectory.isNotEmpty()) {
        "MOBILE_SDK_ANDROID_ARTIFACT_DIR must not be empty"
    }
    val suppliedRoot = Path.of(mobileSdkAndroidArtifactDirectory)
    require(suppliedRoot.isAbsolute) {
        "MOBILE_SDK_ANDROID_ARTIFACT_DIR must be absolute"
    }
    val normalizedRoot = suppliedRoot.normalize()
    require(normalizedRoot.toString() == mobileSdkAndroidArtifactDirectory) {
        "MOBILE_SDK_ANDROID_ARTIFACT_DIR must be normalized and canonical"
    }
    val canonicalRoot = normalizedRoot.toRealPath()
    require(canonicalRoot == normalizedRoot) {
        "MOBILE_SDK_ANDROID_ARTIFACT_DIR must not traverse symbolic links"
    }
    require(
        Files.isDirectory(canonicalRoot, LinkOption.NOFOLLOW_LINKS) &&
            !Files.isSymbolicLink(canonicalRoot) &&
            Files.isWritable(canonicalRoot),
    ) {
        "MOBILE_SDK_ANDROID_ARTIFACT_DIR must be a writable non-symbolic directory"
    }

    var reviewedSourceRoot = settingsDir.toPath().toRealPath()
    while (
        !Files.exists(reviewedSourceRoot.resolve(".git"), LinkOption.NOFOLLOW_LINKS) &&
        reviewedSourceRoot.parent != null
    ) {
        reviewedSourceRoot = reviewedSourceRoot.parent
    }
    require(Files.exists(reviewedSourceRoot.resolve(".git"), LinkOption.NOFOLLOW_LINKS)) {
        "Unable to locate the reviewed Iroha source root"
    }
    if (localAndroidIntegration) {
        validateLocalAndroidArtifactDirectory(reviewedSourceRoot, canonicalRoot)
    } else {
        require(
            canonicalRoot != reviewedSourceRoot &&
                !canonicalRoot.startsWith(reviewedSourceRoot),
        ) {
            "MOBILE_SDK_ANDROID_ARTIFACT_DIR must be outside the reviewed Iroha source tree"
        }
    }

    val buildNamespace = rootProject.name
    require(Regex("^[A-Za-z0-9._-]+$").matches(buildNamespace)) {
        "Iroha Gradle build namespace is not path-safe: $buildNamespace"
    }
    val externalProjectRoot = canonicalRoot
        .resolve("gradle-build")
        .resolve(buildNamespace)
    gradle.beforeProject {
        // Kotlin also keeps persistent state outside layout.buildDirectory.
        extensions.extraProperties.set(
            "kotlin.project.persistent.dir",
            externalProjectRoot.resolve("kotlin-persistent").toString(),
        )
        val relativeProjectPath = if (path == ":") {
            "root"
        } else {
            path.removePrefix(":").replace(':', '/')
        }
        layout.buildDirectory.set(
            externalProjectRoot.resolve(relativeProjectPath).toFile()
        )
    }
}
