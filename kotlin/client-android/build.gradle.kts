import java.net.URI
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.FileSystemOperations
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputDirectory
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.LocalState
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.process.ExecOperations
import org.gradle.work.DisableCachingByDefault
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.security.MessageDigest
import java.util.Properties
import javax.inject.Inject

plugins {
    alias(libs.plugins.android.library)
    `maven-publish`
}

private object NativeBridgeBuildContract {
    val abis = listOf("arm64-v8a", "x86_64")
    val rustTargets = listOf("aarch64-linux-android", "x86_64-linux-android")
    const val armv7DiagnosticPlatform = "android-armv7-diagnostic"
    fun buildAbis(platform: String): List<String> = when (platform) {
        "android" -> abis
        armv7DiagnosticPlatform -> listOf("armeabi-v7a")
        else -> throw GradleException("Unsupported Android native build profile: $platform")
    }
    fun buildTargets(platform: String): List<String> = when (platform) {
        "android" -> rustTargets
        armv7DiagnosticPlatform -> listOf("armv7-linux-androideabi")
        else -> throw GradleException("Unsupported Android native source-seal profile: $platform")
    }
    const val libraryName = "libconnect_norito_bridge.so"
    const val sourceSealSchema = "iroha.norito-bridge-source-seal.v1"
    const val buildEnvironmentSchema = "iroha.mobile-native-build-environment.v1"
    const val hermeticRunnerSchema = "iroha.mobile-hermetic-command.v1"
    const val pinnedRustToolchain = "1.93.1"
    const val pinnedCargoNdkVersion = "4.1.2"
    const val pinnedPythonSeries = "3.12"
    const val pinnedAndroidNdkBaseRevision = "28.0.12674087"
    const val pinnedAndroidNdkRevision = "28.0.12674087-beta2"
    const val pinnedAndroidNdkReleaseName = "r28-beta2"
    const val pinnedAndroidNdkDescription = "Android NDK"
    const val pinnedAndroidNdkSourcePropertiesSha256 =
        "55368a3554d27b8413b75a4b2e83ea7f6b66fef4068f7a7f71cf2910c6e3357b"
    const val maxAndroidNdkSourcePropertiesBytes = 4096
    val androidCargoEnvironmentAllowlist = listOf(
        "ANDROID_NDK_HOME",
        "ANDROID_NDK_ROOT",
        "CARGO",
        "CARGO_BUILD_JOBS",
        "CARGO_HOME",
        "CARGO_INCREMENTAL",
        "CARGO_NET_OFFLINE",
        "CARGO_TARGET_DIR",
        "HOME",
        "LANG",
        "LC_ALL",
        "NORITO_SKIP_BINDINGS_SYNC",
        "PATH",
        "RUSTC",
        "RUSTDOC",
        "RUSTUP_HOME",
        "TMPDIR",
    )

    data class BuildTools(
        val home: java.io.File,
        val temporaryDirectory: java.io.File,
        val python: java.nio.file.Path,
        val git: java.nio.file.Path,
        val rustup: java.nio.file.Path,
        val cargo: java.nio.file.Path,
        val rustc: java.nio.file.Path,
        val rustdoc: java.nio.file.Path,
        val cargoNdk: java.nio.file.Path,
        val hermeticRunner: java.nio.file.Path,
        val androidNdk: java.nio.file.Path,
        val cargoTargetDirectory: java.nio.file.Path,
        val cargoLock: java.nio.file.Path,
        val cargoRelease: String,
        val cargoCommitHash: String,
        val rustcRelease: String,
        val rustcCommitHash: String,
        val rustdocRelease: String,
        val rustdocCommitHash: String,
        val cargoNdkVersion: String,
        val pythonVersion: String,
        val gitVersion: String,
        val rustupVersion: String,
        val androidNdkRevision: String,
        val androidNdkSourcePropertiesSha256: String,
    )

    data class AndroidNdkIdentity(
        val description: String,
        val revision: String,
        val baseRevision: String,
        val releaseName: String,
        val sourcePropertiesSha256: String,
    )

    fun sha256Hex(payload: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(payload).joinToString("") { byte ->
            "%02x".format(byte.toInt() and 0xff)
        }

    fun sha256Hex(path: java.nio.file.Path): String {
        val digest = MessageDigest.getInstance("SHA-256")
        Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS).use { input ->
            val buffer = ByteArray(1024 * 1024)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                digest.update(buffer, 0, read)
            }
        }
        return digest.digest().joinToString("") { byte ->
            "%02x".format(byte.toInt() and 0xff)
        }
    }

    fun canonicalStripCommands(
        stripExecutablePath: Path,
        libraries: List<File>,
    ): List<List<String>> {
        require(libraries.isNotEmpty()) {
            "Canonical Android stripping requires at least one native library"
        }
        val libraryPaths = libraries.map { library ->
            library.toPath().toAbsolutePath().normalize().toString()
        }
        require(libraryPaths.toSet().size == libraryPaths.size) {
            "Canonical Android stripping requires distinct native library paths"
        }
        return libraryPaths.map { libraryPath ->
            listOf(
                stripExecutablePath.toString(),
                "--strip-unneeded",
                libraryPath,
            )
        }
    }

    private fun readBoundedNonSymbolicRegularFile(
        path: Path,
        label: String,
        maximumBytes: Int,
    ): ByteArray {
        require(maximumBytes > 0) { "$label byte bound must be positive" }
        require(!Files.isSymbolicLink(path)) {
            "$label must be a non-symbolic regular file: $path"
        }
        val before = Files.readAttributes(
            path,
            BasicFileAttributes::class.java,
            LinkOption.NOFOLLOW_LINKS,
        )
        require(before.isRegularFile) {
            "$label must be a non-symbolic regular file: $path"
        }
        require(before.size() in 1..maximumBytes.toLong()) {
            "$label must contain 1..$maximumBytes bytes"
        }
        val payload = Files.newByteChannel(
            path,
            setOf<java.nio.file.OpenOption>(
                StandardOpenOption.READ,
                LinkOption.NOFOLLOW_LINKS,
            ),
        ).use { channel ->
            val buffer = ByteBuffer.allocate(before.size().toInt())
            while (buffer.hasRemaining()) {
                require(channel.read(buffer) > 0) {
                    "$label changed while it was being authenticated"
                }
            }
            require(channel.read(ByteBuffer.allocate(1)) == -1) {
                "$label exceeded its authenticated byte size"
            }
            buffer.array()
        }
        val after = Files.readAttributes(
            path,
            BasicFileAttributes::class.java,
            LinkOption.NOFOLLOW_LINKS,
        )
        require(
            after.isRegularFile &&
                before.fileKey() == after.fileKey() &&
                before.size() == after.size() &&
                before.lastModifiedTime() == after.lastModifiedTime() &&
                payload.size.toLong() == before.size(),
        ) {
            "$label changed while it was being authenticated"
        }
        return payload
    }

    fun parseAndroidNdkSourceProperties(payload: ByteArray): AndroidNdkIdentity {
        require(payload.size in 1..maxAndroidNdkSourcePropertiesBytes) {
            "Android NDK source.properties must contain " +
                "1..$maxAndroidNdkSourcePropertiesBytes bytes"
        }
        val text = try {
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(payload))
                .toString()
        } catch (error: CharacterCodingException) {
            throw GradleException(
                "Android NDK source.properties must be strict UTF-8",
                error,
            )
        }
        require(text.endsWith("\n") && '\r' !in text) {
            "Android NDK source.properties must use canonical LF-terminated lines"
        }
        val linesWithTerminator = text.split('\n')
        require(linesWithTerminator.last().isEmpty()) {
            "Android NDK source.properties must end with exactly one LF"
        }
        val lines = linesWithTerminator.dropLast(1)
        require(lines.isNotEmpty() && lines.none(String::isEmpty)) {
            "Android NDK source.properties must not contain empty lines"
        }
        val parsed = linkedMapOf<String, String>()
        val canonicalLine = Regex("^([A-Za-z][A-Za-z0-9.]*) = ([ -~]+)$")
        lines.forEach { line ->
            val match = canonicalLine.matchEntire(line)
                ?: throw GradleException(
                    "Android NDK source.properties contains a malformed property line",
                )
            val key = match.groupValues[1]
            require(parsed.put(key, match.groupValues[2]) == null) {
                "Android NDK source.properties contains duplicate property $key"
            }
        }
        val expected = linkedMapOf(
            "Pkg.Desc" to pinnedAndroidNdkDescription,
            "Pkg.Revision" to pinnedAndroidNdkRevision,
            "Pkg.BaseRevision" to pinnedAndroidNdkBaseRevision,
            "Pkg.ReleaseName" to pinnedAndroidNdkReleaseName,
        )
        require(parsed.keys.toList() == expected.keys.toList()) {
            "Android NDK source.properties field inventory and order are not exact"
        }
        require(parsed == expected) {
            "Android NDK source.properties identity values are not exact"
        }
        val digest = sha256Hex(payload)
        require(digest == pinnedAndroidNdkSourcePropertiesSha256) {
            "Android NDK source.properties digest is not exact"
        }
        return AndroidNdkIdentity(
            description = parsed.getValue("Pkg.Desc"),
            revision = parsed.getValue("Pkg.Revision"),
            baseRevision = parsed.getValue("Pkg.BaseRevision"),
            releaseName = parsed.getValue("Pkg.ReleaseName"),
            sourcePropertiesSha256 = digest,
        )
    }

    fun loadAndroidNdkIdentity(androidNdkDirectory: Path): AndroidNdkIdentity {
        val supplied = androidNdkDirectory.toAbsolutePath().normalize()
        require(supplied.fileName?.toString() == pinnedAndroidNdkBaseRevision) {
            "Android native builds require exact NDK directory " +
                pinnedAndroidNdkBaseRevision
        }
        require(
            Files.isDirectory(supplied, LinkOption.NOFOLLOW_LINKS) &&
                !Files.isSymbolicLink(supplied),
        ) {
            "Android NDK must be a non-symbolic directory: $supplied"
        }
        val canonical = supplied.toRealPath(LinkOption.NOFOLLOW_LINKS)
        require(canonical == supplied) {
            "Android NDK path must be canonical and must not traverse symbolic links: $supplied"
        }
        val sourceProperties = canonical.resolve("source.properties")
        val payload = readBoundedNonSymbolicRegularFile(
            sourceProperties,
            "Android NDK source.properties",
            maxAndroidNdkSourcePropertiesBytes,
        )
        return parseAndroidNdkSourceProperties(payload)
    }

    private fun requireExecutable(path: java.nio.file.Path, label: String): java.nio.file.Path {
        val resolved = path.toRealPath()
        require(
            Files.isRegularFile(resolved, LinkOption.NOFOLLOW_LINKS) &&
                !Files.isSymbolicLink(resolved) &&
                Files.isExecutable(resolved),
        ) {
            "$label must resolve to a non-symbolic regular executable: $path -> $resolved"
        }
        return resolved
    }

    private fun commandOutput(
        execOperations: ExecOperations,
        workingDirectory: File,
        environment: Map<String, String>,
        command: List<String>,
        label: String,
    ): String {
        val stdout = ByteArrayOutputStream()
        val stderr = ByteArrayOutputStream()
        val result = execOperations.exec {
            workingDir(workingDirectory)
            setEnvironment(environment)
            commandLine(command)
            standardOutput = stdout
            errorOutput = stderr
            isIgnoreExitValue = true
        }
        require(result.exitValue == 0) {
            "$label failed: ${stderr.toString(Charsets.UTF_8.name()).trim()}"
        }
        return stdout.toString(Charsets.UTF_8.name()).trim()
    }

    private fun probePython312(
        execOperations: ExecOperations,
        workingDirectory: File,
        candidate: Path,
    ): Path? {
        val expected = runCatching { requireExecutable(candidate, "Python") }.getOrNull()
            ?: return null
        val stdout = ByteArrayOutputStream()
        val result = execOperations.exec {
            workingDir(workingDirectory)
            setEnvironment(
                mapOf(
                    "HOME" to "/tmp",
                    "PATH" to "/usr/bin:/bin",
                    "TMPDIR" to "/tmp",
                    "LANG" to "C.UTF-8",
                    "LC_ALL" to "C.UTF-8",
                ),
            )
            commandLine(
                candidate.toString(),
                "-I",
                "-S",
                "-c",
                "import os,pathlib,stat,sys; " +
                    "p=pathlib.Path(sys.executable).resolve(strict=True); " +
                    "ok=(sys.version_info[:2] == (3, 12) and sys.flags.isolated " +
                    "and 'SDKROOT' not in os.environ and stat.S_ISREG(p.stat().st_mode) " +
                    "and os.access(p, os.X_OK)); " +
                    "print(p) if ok else sys.exit(1)",
            )
            standardOutput = stdout
            errorOutput = ByteArrayOutputStream()
            isIgnoreExitValue = true
        }
        if (result.exitValue != 0) return null
        val reported = runCatching {
            Path.of(stdout.toString(Charsets.UTF_8.name()).trim())
                .toRealPath(LinkOption.NOFOLLOW_LINKS)
        }.getOrNull() ?: return null
        return reported.takeIf { path ->
            path == expected &&
                Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) &&
                !Files.isSymbolicLink(path) &&
                Files.isExecutable(path)
        }
    }

    private fun trustedPython(
        execOperations: ExecOperations,
        workingDirectory: File,
    ): Path {
        val override = System.getenv("MOBILE_SDK_PYTHON_BINARY").orEmpty()
        if (override.isNotEmpty()) {
            val supplied = runCatching { Path.of(override) }.getOrElse {
                throw GradleException(
                    "MOBILE_SDK_PYTHON_BINARY must be an absolute canonical regular executable",
                    it,
                )
            }
            if (
                !supplied.isAbsolute ||
                supplied.normalize() != supplied ||
                !Files.isRegularFile(supplied, LinkOption.NOFOLLOW_LINKS) ||
                Files.isSymbolicLink(supplied) ||
                !Files.isExecutable(supplied)
            ) {
                throw GradleException(
                    "MOBILE_SDK_PYTHON_BINARY must be an absolute canonical regular executable",
                )
            }
            val canonical = runCatching {
                supplied.toRealPath()
            }.getOrElse {
                throw GradleException(
                    "MOBILE_SDK_PYTHON_BINARY must be an absolute canonical regular executable",
                    it,
                )
            }
            if (canonical != supplied) {
                throw GradleException(
                    "MOBILE_SDK_PYTHON_BINARY must already name its canonical executable",
                )
            }
            return probePython312(execOperations, workingDirectory, canonical)
                ?: throw GradleException(
                    "MOBILE_SDK_PYTHON_BINARY must be an isolated Python " +
                        "$pinnedPythonSeries executable",
                )
        }

        val candidates = listOf(
            "/opt/homebrew/opt/python@3.12/bin/python3.12",
            "/opt/homebrew/bin/python3.12",
            "/usr/local/opt/python@3.12/bin/python3.12",
            "/usr/local/bin/python3.12",
            "/usr/bin/python3.12",
            "/usr/bin/python3",
        )
        for (candidate in candidates) {
            val path = Path.of(candidate)
            if (!Files.isRegularFile(path) || !Files.isExecutable(path)) continue
            probePython312(execOperations, workingDirectory, path)?.let { return it }
        }
        throw GradleException(
            "A trusted absolute Python $pinnedPythonSeries executable is required",
        )
    }

    private fun baseToolEnvironment(
        home: File,
        temporaryDirectory: File,
        path: String,
    ): Map<String, String> = linkedMapOf(
        "HOME" to home.absolutePath,
        "PATH" to path,
        "TMPDIR" to temporaryDirectory.absolutePath,
        "LANG" to "C.UTF-8",
        "LC_ALL" to "C.UTF-8",
        "RUSTUP_HOME" to home.resolve(".rustup").absolutePath,
        "CARGO_HOME" to home.resolve(".cargo").absolutePath,
    )

    fun resolveBuildTools(
        execOperations: ExecOperations,
        irohaRoot: File,
        hermeticRunnerFile: File,
        androidNdkDirectory: File,
        cargoTargetDirectory: File,
    ): BuildTools {
        val python = trustedPython(execOperations, irohaRoot)
        val homeText = commandOutput(
            execOperations,
            irohaRoot,
            mapOf(
                "HOME" to "/tmp",
                "PATH" to "${python.parent}:/usr/bin:/bin",
                "TMPDIR" to "/tmp",
                "LANG" to "C.UTF-8",
                "LC_ALL" to "C.UTF-8",
            ),
            listOf(
                python.toString(),
                "-I",
                "-S",
                "-c",
                "import os,pwd; print(pwd.getpwuid(os.getuid()).pw_dir)",
            ),
            "system account home resolution",
        )
        val home = File(homeText).toPath().toRealPath().toFile()
        val temporaryDirectory = File("/tmp").toPath().toRealPath().toFile()
        val git = requireExecutable(Path.of("/usr/bin/git"), "Git")
        val rustup = requireExecutable(home.resolve(".cargo/bin/rustup").toPath(), "rustup")
        val hermeticRunner = hermeticRunnerFile.toPath().toRealPath()
        require(
            Files.isRegularFile(hermeticRunner, LinkOption.NOFOLLOW_LINKS) &&
                !Files.isSymbolicLink(hermeticRunner),
        ) {
            "Hermetic command runner must be a non-symbolic regular file: $hermeticRunner"
        }
        val rustToolchainFile = irohaRoot.resolve("rust-toolchain.toml")
        require(
            Files.isRegularFile(rustToolchainFile.toPath(), LinkOption.NOFOLLOW_LINKS) &&
                !Files.isSymbolicLink(rustToolchainFile.toPath()),
        ) {
            "rust-toolchain.toml must be a non-symbolic regular file"
        }
        val toolchainMatches = Regex(
            """(?m)^\s*channel\s*=\s*"([^"]+)"\s*$""",
        ).findAll(rustToolchainFile.readText()).map { match -> match.groupValues[1] }.toList()
        require(toolchainMatches == listOf(pinnedRustToolchain)) {
            "Android native builds require exact Rust $pinnedRustToolchain"
        }

        val rustupEnvironment = baseToolEnvironment(
            home,
            temporaryDirectory,
            "${rustup.parent}:/usr/bin:/bin",
        )
        val cargo = requireExecutable(
            Path.of(
                commandOutput(
                    execOperations,
                    irohaRoot,
                    rustupEnvironment,
                    listOf(
                        rustup.toString(),
                        "which",
                        "--toolchain",
                        pinnedRustToolchain,
                        "cargo",
                    ),
                    "pinned Cargo resolution",
                ),
            ),
            "Cargo",
        )
        val rustc = requireExecutable(
            Path.of(
                commandOutput(
                    execOperations,
                    irohaRoot,
                    rustupEnvironment,
                    listOf(
                        rustup.toString(),
                        "which",
                        "--toolchain",
                        pinnedRustToolchain,
                        "rustc",
                    ),
                    "pinned rustc resolution",
                ),
            ),
            "rustc",
        )
        val rustdoc = requireExecutable(
            Path.of(
                commandOutput(
                    execOperations,
                    irohaRoot,
                    rustupEnvironment,
                    listOf(
                        rustup.toString(),
                        "which",
                        "--toolchain",
                        pinnedRustToolchain,
                        "rustdoc",
                    ),
                    "pinned rustdoc resolution",
                ),
            ),
            "rustdoc",
        )
        val cargoNdk = requireExecutable(
            home.resolve(".cargo/bin/cargo-ndk").toPath(),
            "cargo-ndk",
        )
        val canonicalIrohaRoot = irohaRoot.toPath().toRealPath(LinkOption.NOFOLLOW_LINKS)
        require(
            canonicalIrohaRoot == irohaRoot.toPath().toAbsolutePath().normalize() &&
                Files.isDirectory(canonicalIrohaRoot, LinkOption.NOFOLLOW_LINKS) &&
                !Files.isSymbolicLink(canonicalIrohaRoot),
        ) {
            "Iroha root must be one absolute canonical non-symbolic directory"
        }
        val cargoLock = canonicalIrohaRoot.resolve("Cargo.lock")
        require(
            Files.isRegularFile(cargoLock, LinkOption.NOFOLLOW_LINKS) &&
                !Files.isSymbolicLink(cargoLock) &&
                cargoLock.toRealPath(LinkOption.NOFOLLOW_LINKS) == cargoLock,
        ) {
            "Android native builds require the explicit non-symbolic root Cargo.lock: " +
                cargoLock
        }
        val suppliedCargoTarget = cargoTargetDirectory.toPath().toAbsolutePath().normalize()
        val canonicalCargoTarget = suppliedCargoTarget.toRealPath(LinkOption.NOFOLLOW_LINKS)
        require(
            canonicalCargoTarget == suppliedCargoTarget &&
                Files.isDirectory(canonicalCargoTarget, LinkOption.NOFOLLOW_LINKS) &&
                !Files.isSymbolicLink(canonicalCargoTarget),
        ) {
            "Android CARGO_TARGET_DIR must be one absolute canonical non-symbolic directory"
        }
        val suppliedAndroidNdk = androidNdkDirectory.toPath().toAbsolutePath().normalize()
        val androidNdkIdentity = loadAndroidNdkIdentity(suppliedAndroidNdk)
        val androidNdk = suppliedAndroidNdk.toRealPath(LinkOption.NOFOLLOW_LINKS)

        val cargoPath = listOf(
            cargo.parent.toString(),
            rustc.parent.toString(),
            rustdoc.parent.toString(),
            cargoNdk.parent.toString(),
            "/usr/bin",
            "/bin",
        ).distinct().joinToString(File.pathSeparator)
        val cargoEnvironment = baseToolEnvironment(home, temporaryDirectory, cargoPath) +
            mapOf(
                "CARGO" to cargo.toString(),
                "CARGO_BUILD_JOBS" to "1",
                "RUSTC" to rustc.toString(),
                "RUSTDOC" to rustdoc.toString(),
                "CARGO_INCREMENTAL" to "0",
                "CARGO_NET_OFFLINE" to "true",
            )
        val cargoVersion = commandOutput(
            execOperations,
            irohaRoot,
            cargoEnvironment,
            listOf(cargo.toString(), "--version", "--verbose"),
            "Cargo identity",
        )
        val rustcVersion = commandOutput(
            execOperations,
            irohaRoot,
            cargoEnvironment,
            listOf(rustc.toString(), "--version", "--verbose"),
            "rustc identity",
        )
        val rustdocVersion = commandOutput(
            execOperations,
            irohaRoot,
            cargoEnvironment,
            listOf(rustdoc.toString(), "--version", "--verbose"),
            "rustdoc identity",
        )
        fun versionField(document: String, field: String): String =
            document.lineSequence().singleOrNull { line -> line.startsWith("$field: ") }
                ?.substringAfter("$field: ")
                ?.trim()
                ?: throw GradleException("Native tool identity is missing $field")
        val cargoRelease = versionField(cargoVersion, "release")
        val cargoCommitHash = versionField(cargoVersion, "commit-hash")
        val rustcRelease = versionField(rustcVersion, "release")
        val rustcCommitHash = versionField(rustcVersion, "commit-hash")
        val rustdocRelease = versionField(rustdocVersion, "release")
        val rustdocCommitHash = versionField(rustdocVersion, "commit-hash")
        require(
            cargoRelease == pinnedRustToolchain &&
                rustcRelease == pinnedRustToolchain &&
                rustdocRelease == pinnedRustToolchain,
        ) {
            "Cargo/rustc/rustdoc do not match exact Rust $pinnedRustToolchain"
        }
        require(
            Regex("^[0-9a-f]{40}$").matches(cargoCommitHash) &&
                Regex("^[0-9a-f]{40}$").matches(rustcCommitHash) &&
                Regex("^[0-9a-f]{40}$").matches(rustdocCommitHash) &&
                rustdocCommitHash == rustcCommitHash,
        ) {
            "Cargo/rustc/rustdoc commit identity is not canonical and exact"
        }
        val cargoNdkVersionOutput = commandOutput(
            execOperations,
            irohaRoot,
            cargoEnvironment,
            listOf(cargo.toString(), "ndk", "--version"),
            "cargo-ndk identity",
        )
        val cargoNdkVersion = Regex("""^cargo-ndk ([0-9]+(?:\.[0-9]+){1,2})$""")
            .matchEntire(cargoNdkVersionOutput)
            ?.groupValues
            ?.get(1)
            ?: throw GradleException("cargo-ndk returned a non-canonical version")
        require(cargoNdkVersion == pinnedCargoNdkVersion) {
            "Android native builds require exact cargo-ndk $pinnedCargoNdkVersion"
        }

        val pythonEnvironment = mapOf(
            "HOME" to home.absolutePath,
            "PATH" to "${python.parent}:/usr/bin:/bin",
            "TMPDIR" to temporaryDirectory.absolutePath,
            "LANG" to "C.UTF-8",
            "LC_ALL" to "C.UTF-8",
        )
        val pythonVersion = commandOutput(
            execOperations,
            irohaRoot,
            pythonEnvironment,
            listOf(
                python.toString(),
                "-I",
                "-S",
                "-c",
                "import platform; print(platform.python_version())",
            ),
            "Python identity",
        )
        val gitEnvironment = pythonEnvironment + mapOf(
            "GIT_CONFIG_NOSYSTEM" to "1",
            "GIT_CONFIG_GLOBAL" to "/dev/null",
            "GIT_OPTIONAL_LOCKS" to "0",
        )
        val gitVersion = commandOutput(
            execOperations,
            irohaRoot,
            gitEnvironment,
            listOf(git.toString(), "--version"),
            "Git identity",
        ).let { output ->
            Regex("""^git version ([0-9]+(?:\.[0-9]+){1,3}).*$""")
                .matchEntire(output)
                ?.groupValues
                ?.get(1)
                ?: throw GradleException("Git returned a non-canonical version")
        }
        val rustupVersion = commandOutput(
            execOperations,
            irohaRoot,
            rustupEnvironment,
            listOf(rustup.toString(), "--version"),
            "rustup identity",
        ).lineSequence().first().let { output ->
            Regex("""^rustup ([0-9]+(?:\.[0-9]+){1,2}).*$""")
                .matchEntire(output)
                ?.groupValues
                ?.get(1)
                ?: throw GradleException("rustup returned a non-canonical version")
        }
        require(
            Regex("^${Regex.escape(pinnedPythonSeries)}\\.[0-9]+$")
                .matches(pythonVersion),
        ) {
            "Python must report a canonical $pinnedPythonSeries release"
        }

        return BuildTools(
            home = home,
            temporaryDirectory = temporaryDirectory,
            python = python,
            git = git,
            rustup = rustup,
            cargo = cargo,
            rustc = rustc,
            rustdoc = rustdoc,
            cargoNdk = cargoNdk,
            hermeticRunner = hermeticRunner,
            androidNdk = androidNdk,
            cargoTargetDirectory = canonicalCargoTarget,
            cargoLock = cargoLock,
            cargoRelease = cargoRelease,
            cargoCommitHash = cargoCommitHash,
            rustcRelease = rustcRelease,
            rustcCommitHash = rustcCommitHash,
            rustdocRelease = rustdocRelease,
            rustdocCommitHash = rustdocCommitHash,
            cargoNdkVersion = cargoNdkVersion,
            pythonVersion = pythonVersion,
            gitVersion = gitVersion,
            rustupVersion = rustupVersion,
            // Provenance v1 intentionally carries the package/base revision.
            androidNdkRevision = androidNdkIdentity.baseRevision,
            androidNdkSourcePropertiesSha256 =
                androidNdkIdentity.sourcePropertiesSha256,
        )
    }

    fun buildEnvironmentDocument(tools: BuildTools): Map<String, Any> {
        return linkedMapOf(
        "schema" to buildEnvironmentSchema,
        "hermetic_runner_schema" to hermeticRunnerSchema,
        "hermetic_runner_sha256" to sha256Hex(tools.hermeticRunner),
        "environment_profile" to "android-cargo",
        "environment_allowlist" to androidCargoEnvironmentAllowlist,
        "cargo_build_jobs" to 1,
        "rust_toolchain_channel" to pinnedRustToolchain,
        "cargo_release" to tools.cargoRelease,
        "cargo_commit_hash" to tools.cargoCommitHash,
        "cargo_binary_sha256" to sha256Hex(tools.cargo),
        "rustc_release" to tools.rustcRelease,
        "rustc_commit_hash" to tools.rustcCommitHash,
        "rustc_binary_sha256" to sha256Hex(tools.rustc),
        "rustdoc_release" to tools.rustdocRelease,
        "rustdoc_commit_hash" to tools.rustdocCommitHash,
        "rustdoc_binary_sha256" to sha256Hex(tools.rustdoc),
        "cargo_ndk_version" to tools.cargoNdkVersion,
        "cargo_ndk_binary_sha256" to sha256Hex(tools.cargoNdk),
        "python_version" to tools.pythonVersion,
        "python_binary_sha256" to sha256Hex(tools.python),
        "git_version" to tools.gitVersion,
        "git_binary_sha256" to sha256Hex(tools.git),
        "rustup_version" to tools.rustupVersion,
        "rustup_binary_sha256" to sha256Hex(tools.rustup),
        "android_ndk_revision" to tools.androidNdkRevision,
        "android_ndk_source_properties_sha256" to tools.androidNdkSourcePropertiesSha256,
        )
    }

    fun buildEnvironmentBytes(tools: BuildTools): ByteArray =
        (JsonOutput.prettyPrint(JsonOutput.toJson(buildEnvironmentDocument(tools))) + "\n")
            .toByteArray(Charsets.UTF_8)

    private fun sourceSealEnvironment(tools: BuildTools): Map<String, String> =
        linkedMapOf(
            "HOME" to tools.home.absolutePath,
            "PATH" to listOf(
                tools.python.parent.toString(),
                tools.cargo.parent.toString(),
                tools.rustc.parent.toString(),
                tools.rustdoc.parent.toString(),
                tools.git.parent.toString(),
                "/usr/bin",
                "/bin",
            ).distinct().joinToString(File.pathSeparator),
            "TMPDIR" to tools.temporaryDirectory.absolutePath,
            "LANG" to "C.UTF-8",
            "LC_ALL" to "C.UTF-8",
            "NORITO_BRIDGE_SEAL_HOME" to tools.home.absolutePath,
            "NORITO_BRIDGE_SEAL_CARGO_HOME" to tools.home.resolve(".cargo").absolutePath,
            "NORITO_BRIDGE_SEAL_RUSTUP_HOME" to tools.home.resolve(".rustup").absolutePath,
            "NORITO_BRIDGE_SEAL_TMPDIR" to tools.temporaryDirectory.absolutePath,
            "NORITO_BRIDGE_SEAL_CARGO" to tools.cargo.toString(),
            "NORITO_BRIDGE_SEAL_RUSTC" to tools.rustc.toString(),
            "NORITO_BRIDGE_SEAL_RUSTDOC" to tools.rustdoc.toString(),
            "NORITO_BRIDGE_SEAL_CARGO_TARGET_DIR" to
                tools.cargoTargetDirectory.toString(),
        )

    fun requireLibraries(
        root: java.io.File,
        expectedAbis: List<String> = abis,
    ): List<java.io.File> {
        val rootPath = root.toPath()
        require(
            Files.isDirectory(rootPath, LinkOption.NOFOLLOW_LINKS) &&
                !Files.isSymbolicLink(rootPath),
        ) {
            "Android native bridge inventory root must be a non-symbolic directory: $root"
        }
        val expectedRelativePaths = expectedAbis.map { abi -> "$abi/$libraryName" }.toSet()
        val expectedDirectories = expectedAbis.toSet()
        val actualRelativePaths = mutableSetOf<String>()
        val actualDirectories = mutableSetOf<String>()
        Files.walk(rootPath).use { paths ->
            paths.forEach { candidate ->
                if (candidate == rootPath) return@forEach
                require(!Files.isSymbolicLink(candidate)) {
                    "Android native bridge inventory must not contain a symbolic link: $candidate"
                }
                if (Files.isDirectory(candidate, LinkOption.NOFOLLOW_LINKS)) {
                    actualDirectories += rootPath.relativize(candidate).toString()
                        .replace(File.separatorChar, '/')
                    return@forEach
                }
                require(Files.isRegularFile(candidate, LinkOption.NOFOLLOW_LINKS)) {
                    "Android native bridge inventory contains a non-regular entry: $candidate"
                }
                actualRelativePaths += rootPath.relativize(candidate).toString()
                    .replace(File.separatorChar, '/')
            }
        }
        require(actualDirectories == expectedDirectories) {
            "Expected exact Android native bridge directories $expectedDirectories under $root; " +
                "found $actualDirectories"
        }
        require(actualRelativePaths == expectedRelativePaths) {
            "Expected exact Android native bridge inventory $expectedRelativePaths under $root; " +
                "found $actualRelativePaths"
        }
        return expectedAbis.map { abi ->
            root.resolve("$abi/$libraryName").also { library ->
                require(Files.isRegularFile(library.toPath(), LinkOption.NOFOLLOW_LINKS)) {
                    "Android native bridge must be a non-symbolic regular file: $library"
                }
                require(library.length() > 0L) {
                    "Android native bridge must not be empty: $library"
                }
            }
        }
    }

    fun requireRegularFileInside(
        root: java.io.File,
        candidate: java.io.File,
        label: String,
    ) {
        val rootPath = root.toPath().toAbsolutePath().normalize()
        val candidatePath = candidate.toPath().toAbsolutePath().normalize()
        require(candidatePath.startsWith(rootPath)) {
            "$label escapes its allowed root: $candidate"
        }
        var current = candidatePath
        while (true) {
            require(!Files.isSymbolicLink(current)) {
                "$label must not traverse a symbolic link: $current"
            }
            if (current == rootPath) break
            current = requireNotNull(current.parent) {
                "$label has no parent inside its allowed root: $candidate"
            }
        }
        require(Files.isRegularFile(candidatePath, LinkOption.NOFOLLOW_LINKS)) {
            "$label must be a non-symbolic regular file: $candidate"
        }
    }

    fun captureSourceSeal(
        execOperations: ExecOperations,
        irohaRoot: java.io.File,
        sourceSealScript: java.io.File,
        tools: BuildTools,
        platform: String = "android",
    ): ByteArray {
        val stdout = ByteArrayOutputStream()
        val stderr = ByteArrayOutputStream()
        val result = execOperations.exec {
            workingDir(irohaRoot)
            setEnvironment(sourceSealEnvironment(tools))
            commandLine(
                tools.python.toString(),
                "-I",
                "-S",
                sourceSealScript.absolutePath,
                "snapshot",
                "--root",
                irohaRoot.absolutePath,
                "--platform",
                platform,
                "--lockfile-path",
                tools.cargoLock.toString(),
            )
            standardOutput = stdout
            errorOutput = stderr
            isIgnoreExitValue = true
        }
        require(result.exitValue == 0) {
            "Unable to capture Android NoritoBridge source seal: " +
                stderr.toString(Charsets.UTF_8.name()).trim()
        }
        return stdout.toByteArray().also { payload ->
            require(payload.isNotEmpty()) { "Android NoritoBridge source seal is empty" }
        }
    }

    fun assertSourceSeal(
        execOperations: ExecOperations,
        irohaRoot: java.io.File,
        sourceSealScript: java.io.File,
        sourceSealFile: java.io.File,
        phase: String,
        tools: BuildTools,
        platform: String = "android",
    ) {
        val stderr = ByteArrayOutputStream()
        val result = execOperations.exec {
            workingDir(irohaRoot)
            setEnvironment(sourceSealEnvironment(tools))
            commandLine(
                tools.python.toString(),
                "-I",
                "-S",
                sourceSealScript.absolutePath,
                "verify",
                "--root",
                irohaRoot.absolutePath,
                "--platform",
                platform,
                "--snapshot",
                sourceSealFile.absolutePath,
                "--lockfile-path",
                tools.cargoLock.toString(),
            )
            errorOutput = stderr
            isIgnoreExitValue = true
        }
        require(result.exitValue == 0) {
            "Android NoritoBridge source changed during $phase; refusing a mixed-source " +
                "native artifact: ${stderr.toString(Charsets.UTF_8.name()).trim()}"
        }
    }
}

@DisableCachingByDefault(
    because = "Cargo's complete workspace dependency closure is not modeled as a Gradle input",
)
abstract class CompileNativeBridgeTask @Inject constructor(
    private val execOperations: ExecOperations,
    private val fileSystemOperations: FileSystemOperations,
) : DefaultTask() {
    @get:Input
    abstract val sourceSealPlatform: Property<String>

    @get:Input
    abstract val localIntegration: Property<Boolean>

    init {
        sourceSealPlatform.convention("android")
        localIntegration.convention(false)
    }

    @get:Internal
    abstract val irohaDirectory: DirectoryProperty

    @get:LocalState
    abstract val cargoTargetDirectory: DirectoryProperty

    @get:LocalState
    abstract val cargoNdkStagingDirectory: DirectoryProperty

    @get:Internal
    abstract val sourceSealScript: RegularFileProperty

    @get:Internal
    abstract val hermeticRunner: RegularFileProperty

    @get:Internal
    abstract val androidNdkDirectory: DirectoryProperty

    @get:OutputDirectory
    abstract val outputDirectory: DirectoryProperty

    @get:OutputFile
    abstract val sourceSealFile: RegularFileProperty

    @get:OutputFile
    abstract val buildEnvironmentFile: RegularFileProperty

    @TaskAction
    fun compile() {
        val platform = sourceSealPlatform.get()
        val selectedAbis = NativeBridgeBuildContract.buildAbis(platform)
        require(platform == "android" || localIntegration.get()) {
            "Armv7 diagnostics require the owned local Android integration scope"
        }
        val irohaRoot = irohaDirectory.get().asFile
        val sealScript = sourceSealScript.get().asFile
        require(Files.isRegularFile(sealScript.toPath(), LinkOption.NOFOLLOW_LINKS)) {
            "NoritoBridge source-seal script must be a non-symbolic regular file: $sealScript"
        }
        val cargoTargetRoot = cargoTargetDirectory.get().asFile
        require(cargoTargetRoot.mkdirs() || cargoTargetRoot.isDirectory) {
            "Unable to create isolated Cargo target directory: $cargoTargetRoot"
        }
        val tools = NativeBridgeBuildContract.resolveBuildTools(
            execOperations,
            irohaRoot,
            hermeticRunner.get().asFile,
            androidNdkDirectory.get().asFile,
            cargoTargetRoot,
        )
        val sourceSeal = NativeBridgeBuildContract.captureSourceSeal(
            execOperations,
            irohaRoot,
            sealScript,
            tools,
            platform,
        )
        val capturedSeal = JsonSlurper().parse(sourceSeal) as? Map<*, *>
            ?: throw GradleException("Native source seal must be an object")
        require(capturedSeal["platform"] == platform &&
            capturedSeal["targets"] == NativeBridgeBuildContract.buildTargets(platform)) {
            "Native source seal target inventory differs from the selected build profile"
        }
        val buildEnvironment = NativeBridgeBuildContract.buildEnvironmentBytes(tools)
        val outputRoot = outputDirectory.get().asFile
        val stagingRoot = cargoNdkStagingDirectory.get().asFile
        val sealFile = sourceSealFile.get().asFile
        val environmentFile = buildEnvironmentFile.get().asFile
        fileSystemOperations.delete {
            // Gradle's DeleteSpec.delete(...) replaces its target array on
            // every invocation; pass the complete inventory in one call.
            delete(outputRoot, stagingRoot, sealFile, environmentFile)
        }
        require(
            listOf(outputRoot, stagingRoot, sealFile, environmentFile).none { candidate ->
                Files.exists(candidate.toPath(), LinkOption.NOFOLLOW_LINKS)
            },
        ) {
            "Unable to clear stale Android native build outputs before sealing: " +
                listOf(outputRoot, stagingRoot, sealFile, environmentFile)
        }
        require(outputRoot.mkdirs() || outputRoot.isDirectory) {
            "Unable to create cargo-ndk output directory: $outputRoot"
        }
        require(stagingRoot.mkdirs() || stagingRoot.isDirectory) {
            "Unable to create transient cargo-ndk staging directory: $stagingRoot"
        }
        require(sealFile.parentFile.mkdirs() || sealFile.parentFile.isDirectory) {
            "Unable to create Android source-seal directory: ${sealFile.parentFile}"
        }
        require(
            environmentFile.parentFile.mkdirs() || environmentFile.parentFile.isDirectory,
        ) {
            "Unable to create Android build-environment directory: ${environmentFile.parentFile}"
        }
        sealFile.writeBytes(sourceSeal)
        environmentFile.writeBytes(buildEnvironment)
        NativeBridgeBuildContract.assertSourceSeal(
            execOperations,
            irohaRoot,
            sealScript,
            sealFile,
            "build start",
            tools,
            sourceSealPlatform.get(),
        )
        selectedAbis.forEachIndexed { index, abi ->
            val abiStagingRoot = stagingRoot.resolve(abi)
            fileSystemOperations.delete { delete(abiStagingRoot) }
            require(abiStagingRoot.mkdirs() || abiStagingRoot.isDirectory) {
                "Unable to create transient cargo-ndk staging directory for $abi: $abiStagingRoot"
            }
            val cargoPath = listOf(
                tools.cargo.parent.toString(),
                tools.rustc.parent.toString(),
                tools.rustdoc.parent.toString(),
                tools.cargoNdk.parent.toString(),
                "/usr/bin",
                "/bin",
            ).distinct().joinToString(File.pathSeparator)
            val command = buildList {
                addAll(
                    listOf(
                        tools.python.toString(),
                        "-I",
                        "-S",
                        tools.hermeticRunner.toString(),
                        "--profile",
                        "android-cargo",
                        "--set",
                        "ANDROID_NDK_HOME=${tools.androidNdk}",
                        "--set",
                        "ANDROID_NDK_ROOT=${tools.androidNdk}",
                        "--set",
                        "CARGO=${tools.cargo}",
                        "--set",
                        "CARGO_BUILD_JOBS=1",
                        "--set",
                        "CARGO_HOME=${tools.home.resolve(".cargo")}",
                        "--set",
                        "CARGO_INCREMENTAL=0",
                        "--set",
                        "CARGO_NET_OFFLINE=true",
                        "--set",
                        "CARGO_TARGET_DIR=${cargoTargetRoot.absolutePath}",
                        "--set",
                        "HOME=${tools.home.absolutePath}",
                        "--set",
                        "LANG=C.UTF-8",
                        "--set",
                        "LC_ALL=C.UTF-8",
                        "--set",
                        "NORITO_SKIP_BINDINGS_SYNC=1",
                        "--set",
                        "PATH=$cargoPath",
                        "--set",
                        "RUSTC=${tools.rustc}",
                        "--set",
                        "RUSTDOC=${tools.rustdoc}",
                        "--set",
                        "RUSTUP_HOME=${tools.home.resolve(".rustup")}",
                        "--set",
                        "TMPDIR=${tools.temporaryDirectory.absolutePath}",
                        "--",
                        tools.cargo.toString(),
                        "ndk",
                        "-t",
                        abi,
                        "-o",
                        abiStagingRoot.absolutePath,
                    ),
                )
                addAll(
                    listOf(
                        "build",
                        "--locked",
                        "--offline",
                        "--jobs",
                        "1",
                        "--manifest-path",
                        irohaRoot.resolve("Cargo.toml").absolutePath,
                        "--release",
                        "-p",
                        "connect_norito_bridge",
                    ),
                )
                addAll(listOf("--features", "privacy-production-enabled"))
            }
            execOperations.exec {
                workingDir(irohaRoot)
                setEnvironment(
                    mapOf(
                        "HOME" to tools.home.absolutePath,
                        "PATH" to "${tools.python.parent}:/usr/bin:/bin",
                        "TMPDIR" to tools.temporaryDirectory.absolutePath,
                        "LANG" to "C.UTF-8",
                        "LC_ALL" to "C.UTF-8",
                    ),
                )
                commandLine(*command.toTypedArray())
            }.assertNormalExitValue()
            NativeBridgeBuildContract.assertSourceSeal(
                execOperations,
                irohaRoot,
                sealScript,
                sealFile,
                "$abi Cargo build",
                tools,
                sourceSealPlatform.get(),
            )

            // cargo-ndk can copy unrelated cdylib workspace outputs into its
            // destination. Treat that destination as transient and promote
            // only the exact bridge name into the authoritative raw inventory.
            val stagedLibrary = abiStagingRoot.resolve(
                "$abi/${NativeBridgeBuildContract.libraryName}",
            )
            NativeBridgeBuildContract.requireRegularFileInside(
                abiStagingRoot,
                stagedLibrary,
                "cargo-ndk ${NativeBridgeBuildContract.libraryName} for $abi",
            )
            val promotedLibrary = outputRoot.resolve(
                "$abi/${NativeBridgeBuildContract.libraryName}",
            )
            require(promotedLibrary.parentFile.mkdirs() || promotedLibrary.parentFile.isDirectory) {
                "Unable to create promoted raw native ABI directory: ${promotedLibrary.parentFile}"
            }
            NativeBridgeBuildContract.assertSourceSeal(
                execOperations,
                irohaRoot,
                sealScript,
                sealFile,
                "$abi immediate pre-promotion authentication",
                tools,
                sourceSealPlatform.get(),
            )
            Files.copy(
                stagedLibrary.toPath(),
                promotedLibrary.toPath(),
                LinkOption.NOFOLLOW_LINKS,
                StandardCopyOption.COPY_ATTRIBUTES,
                StandardCopyOption.REPLACE_EXISTING,
            )
            NativeBridgeBuildContract.requireLibraries(
                outputRoot,
                selectedAbis.take(index + 1),
            )
            NativeBridgeBuildContract.assertSourceSeal(
                execOperations,
                irohaRoot,
                sealScript,
                sealFile,
                "$abi immediate post-promotion authentication",
                tools,
                sourceSealPlatform.get(),
            )
        }
        NativeBridgeBuildContract.requireLibraries(outputRoot, NativeBridgeBuildContract.buildAbis(sourceSealPlatform.get()))
        NativeBridgeBuildContract.assertSourceSeal(
            execOperations,
            irohaRoot,
            sealScript,
            sealFile,
            "native compile completion",
            tools,
            sourceSealPlatform.get(),
        )
    }

    fun hasReusableSealedOutput(): Boolean = runCatching {
        val outputRoot = outputDirectory.get().asFile
        val sealFile = sourceSealFile.get().asFile
        val environmentFile = buildEnvironmentFile.get().asFile
        val tools = NativeBridgeBuildContract.resolveBuildTools(
            execOperations,
            irohaDirectory.get().asFile,
            hermeticRunner.get().asFile,
            androidNdkDirectory.get().asFile,
            cargoTargetDirectory.get().asFile,
        )
        NativeBridgeBuildContract.requireLibraries(outputRoot, NativeBridgeBuildContract.buildAbis(sourceSealPlatform.get()))
        require(Files.isRegularFile(sealFile.toPath(), LinkOption.NOFOLLOW_LINKS))
        require(Files.isRegularFile(environmentFile.toPath(), LinkOption.NOFOLLOW_LINKS))
        require(
            environmentFile.readBytes().contentEquals(
                NativeBridgeBuildContract.buildEnvironmentBytes(tools),
            ),
        ) {
            "Reusable Android native output was built with a different toolchain environment"
        }
        NativeBridgeBuildContract.assertSourceSeal(
            execOperations,
            irohaDirectory.get().asFile,
            sourceSealScript.get().asFile,
            sealFile,
            "up-to-date authentication",
            tools,
            sourceSealPlatform.get(),
        )
        true
    }.getOrDefault(false)
}

@DisableCachingByDefault(because = "Diagnostic observations authenticate live original outputs")
abstract class InspectArmv7DiagnosticTask @Inject constructor(
    private val execOperations: ExecOperations,
) : DefaultTask() {
    @get:Input abstract val localIntegration: Property<Boolean>
    @get:Internal abstract val irohaDirectory: DirectoryProperty
    @get:Internal abstract val hermeticRunner: RegularFileProperty
    @get:Internal abstract val androidNdkDirectory: DirectoryProperty
    @get:Internal abstract val cargoTargetDirectory: DirectoryProperty
    @get:Internal abstract val sourceSealScript: RegularFileProperty
    @get:Internal abstract val inspectionScript: RegularFileProperty
    @get:InputDirectory
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val rawDirectory: DirectoryProperty
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val sourceSealFile: RegularFileProperty
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val buildEnvironmentFile: RegularFileProperty
    @get:OutputFile abstract val reportFile: RegularFileProperty

    @TaskAction
    fun inspect() {
        require(localIntegration.get()) {
            "Armv7 diagnostics require -PirohaAndroidLocalIntegration=true"
        }
        val root = irohaDirectory.get().asFile
        val tools = NativeBridgeBuildContract.resolveBuildTools(
            execOperations, root, hermeticRunner.get().asFile,
            androidNdkDirectory.get().asFile, cargoTargetDirectory.get().asFile,
        )
        val profile = NativeBridgeBuildContract.armv7DiagnosticPlatform
        val sealFile = sourceSealFile.get().asFile
        val sealScript = sourceSealScript.get().asFile
        val inspectScript = inspectionScript.get().asFile
        NativeBridgeBuildContract.requireRegularFileInside(root, inspectScript, "armv7 inspector")
        val libraries = NativeBridgeBuildContract.requireLibraries(
            rawDirectory.get().asFile, NativeBridgeBuildContract.buildAbis(profile),
        )
        val sealBytes = sealFile.readBytes()
        val seal = JsonSlurper().parse(sealBytes) as? Map<*, *>
            ?: throw GradleException("Armv7 source seal must be an object")
        require(seal["platform"] == profile &&
            seal["targets"] == NativeBridgeBuildContract.buildTargets(profile)) {
            "Armv7 diagnostic source seal has another target profile"
        }
        val environmentBytes = buildEnvironmentFile.get().asFile.readBytes()
        require(environmentBytes.contentEquals(NativeBridgeBuildContract.buildEnvironmentBytes(tools))) {
            "Armv7 diagnostic build environment changed before inspection"
        }
        val prebuiltRoot = tools.androidNdk.resolve("toolchains/llvm/prebuilt").toFile()
        require(Files.isDirectory(prebuiltRoot.toPath(), LinkOption.NOFOLLOW_LINKS) &&
            !Files.isSymbolicLink(prebuiltRoot.toPath())) { "NDK prebuilt root must be original" }
        val inspectors = prebuiltRoot.listFiles().orEmpty().filter { host ->
            Files.isDirectory(host.toPath(), LinkOption.NOFOLLOW_LINKS) &&
                !Files.isSymbolicLink(host.toPath())
        }.map { it.resolve("bin/llvm-nm") }.filter { candidate ->
            Files.isRegularFile(candidate.toPath(), LinkOption.NOFOLLOW_LINKS) &&
                Files.isExecutable(candidate.toPath())
        }
        require(inspectors.size == 1) { "Armv7 diagnostics require one original NDK llvm-nm" }
        val inspector = inspectors.single()
        NativeBridgeBuildContract.requireRegularFileInside(tools.androidNdk.toFile(), inspector, "NDK llvm-nm")
        val output = ByteArrayOutputStream()
        val errors = ByteArrayOutputStream()
        NativeBridgeBuildContract.assertSourceSeal(
            execOperations, root, sealScript, sealFile, "armv7 pre-inspection", tools, profile,
        )
        val result = execOperations.exec {
            workingDir(root)
            setEnvironment(mapOf("PATH" to "/usr/bin:/bin", "LANG" to "C", "LC_ALL" to "C"))
            commandLine(tools.python.toString(), "-I", "-S", inspectScript.absolutePath,
                "--library", libraries.single().absolutePath,
                "--symbol-inspector", inspector.absolutePath)
            standardOutput = output
            errorOutput = errors
            isIgnoreExitValue = true
        }
        require(result.exitValue == 0) {
            "Armv7 diagnostic inspection failed: ${errors.toString(Charsets.UTF_8.name()).trim()}"
        }
        NativeBridgeBuildContract.assertSourceSeal(
            execOperations, root, sealScript, sealFile, "armv7 post-inspection", tools, profile,
        )
        val observation = JsonSlurper().parse(output.toByteArray()) as? Map<*, *>
            ?: throw GradleException("Armv7 inspection must return an object")
        require(observation["schema"] == "iroha.android-armv7-diagnostic.v1" &&
            observation["artifact_scope"] == "android-local-diagnostic" &&
            observation["release_admitted"] == false) {
            "Armv7 inspection must remain explicitly diagnostic"
        }
        val report = linkedMapOf<String, Any>(
            "schema" to "iroha.android-armv7-diagnostic.v1",
            "artifact_scope" to "android-local-diagnostic",
            "release_admitted" to false,
            "privacy_production_enabled" to true,
            "cargo_features" to listOf("privacy-production-enabled"),
            "source_seal" to seal,
            "source_seal_sha256" to NativeBridgeBuildContract.sha256Hex(sealBytes),
            "build_environment" to NativeBridgeBuildContract.buildEnvironmentDocument(tools),
            "build_environment_sha256" to NativeBridgeBuildContract.sha256Hex(environmentBytes),
            "inspection_script_sha256" to NativeBridgeBuildContract.sha256Hex(inspectScript.toPath()),
            "observation" to observation,
        )
        val reportPath = reportFile.get().asFile.toPath()
        require(reportPath.parent.toFile().mkdirs() || Files.isDirectory(reportPath.parent)) {
            "Cannot create armv7 diagnostic report directory"
        }
        require(reportPath.parent.toRealPath() == reportPath.parent &&
            !Files.isSymbolicLink(reportPath.parent)) {
            "Armv7 report directory must remain canonical and original"
        }
        val staged = reportPath.resolveSibling(reportPath.fileName.toString() + ".staged")
        Files.write(staged,
            (JsonOutput.prettyPrint(JsonOutput.toJson(report)) + "\n").toByteArray(Charsets.UTF_8),
            StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
        try {
            NativeBridgeBuildContract.assertSourceSeal(
                execOperations, root, sealScript, sealFile, "armv7 report publication", tools, profile,
            )
            Files.move(staged, reportPath, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        } finally {
            Files.deleteIfExists(staged)
        }
    }
}

@DisableCachingByDefault(
    because = "The manifest records live source-control provenance and must be regenerated",
)
abstract class StripNativeBridgeTask @Inject constructor(
    private val execOperations: ExecOperations,
    private val fileSystemOperations: FileSystemOperations,
) : DefaultTask() {
    @get:Input
    abstract val localIntegration: Property<Boolean>

    @get:InputDirectory
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val inputDirectory: DirectoryProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val sourceSealFile: RegularFileProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val buildEnvironmentFile: RegularFileProperty

    @get:Internal
    abstract val irohaDirectory: DirectoryProperty

    @get:Internal
    abstract val sourceSealScript: RegularFileProperty

    @get:Internal
    abstract val hermeticRunner: RegularFileProperty

    @get:Internal
    abstract val androidNdkDirectory: DirectoryProperty

    @get:Internal
    abstract val cargoTargetDirectory: DirectoryProperty

    @get:OutputDirectory
    abstract val outputDirectory: DirectoryProperty

    @get:OutputDirectory
    abstract val provenanceDirectory: DirectoryProperty

    @TaskAction
    fun strip() {
        val irohaRoot = irohaDirectory.get().asFile
        val sealScript = sourceSealScript.get().asFile
        val sealFile = sourceSealFile.get().asFile
        val environmentFile = buildEnvironmentFile.get().asFile
        val tools = NativeBridgeBuildContract.resolveBuildTools(
            execOperations,
            irohaRoot,
            hermeticRunner.get().asFile,
            androidNdkDirectory.get().asFile,
            cargoTargetDirectory.get().asFile,
        )
        require(Files.isRegularFile(sealFile.toPath(), LinkOption.NOFOLLOW_LINKS)) {
            "Android source seal must be a non-symbolic regular file: $sealFile"
        }
        require(
            Files.isRegularFile(environmentFile.toPath(), LinkOption.NOFOLLOW_LINKS) &&
                !Files.isSymbolicLink(environmentFile.toPath()),
        ) {
            "Android build environment must be a non-symbolic regular file: $environmentFile"
        }
        require(
            environmentFile.readBytes().contentEquals(
                NativeBridgeBuildContract.buildEnvironmentBytes(tools),
            ),
        ) {
            "Android native build environment changed between compile and strip"
        }
        NativeBridgeBuildContract.assertSourceSeal(
            execOperations,
            irohaRoot,
            sealScript,
            sealFile,
            "strip start",
            tools,
        )
        val sourceSeal = JsonSlurper().parse(sealFile) as? Map<*, *>
            ?: throw GradleException("Android source seal root must be a JSON object")
        val expectedSealFields = setOf(
            "platform",
            "schema",
            "source_commit",
            "source_fingerprint_sha256",
            "source_status",
            "source_tree_dirty",
            "targets",
        )
        require(sourceSeal.keys == expectedSealFields) {
            "Android source seal field inventory is not exact: ${sourceSeal.keys}"
        }
        require(sourceSeal["schema"] == NativeBridgeBuildContract.sourceSealSchema) {
            "Android source seal schema is not canonical"
        }
        require(sourceSeal["platform"] == "android") {
            "Android source seal platform is not canonical"
        }
        require(sourceSeal["targets"] == NativeBridgeBuildContract.rustTargets) {
            "Android source seal target inventory is not exact"
        }
        val sourceCommit = sourceSeal["source_commit"] as? String
            ?: throw GradleException("Android source seal commit is not a string")
        require(Regex("^[0-9a-f]{40}$").matches(sourceCommit)) {
            "Iroha source commit is not a canonical 40-character Git object id"
        }
        val sourceTreeDirty = sourceSeal["source_tree_dirty"] as? Boolean
            ?: throw GradleException("Android source seal dirty state is not boolean")
        val sourceStatus = sourceSeal["source_status"] as? String
            ?: throw GradleException("Android source seal status is not a string")
        require(sourceTreeDirty == sourceStatus.isNotEmpty()) {
            "Android source seal dirty state disagrees with its exact status"
        }
        val sourceFingerprint = sourceSeal["source_fingerprint_sha256"] as? String
            ?: throw GradleException("Android source seal fingerprint is not a string")
        require(Regex("^[0-9a-f]{64}$").matches(sourceFingerprint)) {
            "Android source seal fingerprint is not canonical SHA-256"
        }
        val inputRoot = inputDirectory.get().asFile
        val rawLibraries = NativeBridgeBuildContract.requireLibraries(inputRoot)
        val rawIdentityByAbi = rawLibraries.associate { library ->
            library.parentFile.name to Pair(
                library.length(),
                NativeBridgeBuildContract.sha256Hex(library.toPath()),
            )
        }
        val outputRoot = outputDirectory.get().asFile
        val provenanceRoot = provenanceDirectory.get().asFile
        val scopedRoots = listOf(inputRoot, outputRoot, provenanceRoot)
            .map { directory -> directory.toPath().toAbsolutePath().normalize() }
        require(scopedRoots.toSet().size == scopedRoots.size) {
            "Raw, stripped, and provenance output directories must be distinct: $scopedRoots"
        }
        fileSystemOperations.delete {
            delete(outputRoot, provenanceRoot)
        }
        require(
            listOf(outputRoot, provenanceRoot).none { candidate ->
                Files.exists(candidate.toPath(), LinkOption.NOFOLLOW_LINKS)
            },
        ) {
            "Unable to clear stale stripped/provenance outputs before release packaging: " +
                listOf(outputRoot, provenanceRoot)
        }
        require(outputRoot.mkdirs() || outputRoot.isDirectory) {
            "Unable to create stripped native output directory: $outputRoot"
        }

        val outputLibraries = rawLibraries.map { rawLibrary ->
            val relativePath = rawLibrary.relativeTo(inputRoot).invariantSeparatorsPath
            val outputLibrary = outputRoot.resolve(relativePath)
            require(outputLibrary.parentFile.mkdirs() || outputLibrary.parentFile.isDirectory) {
                "Unable to create stripped native ABI directory: ${outputLibrary.parentFile}"
            }
            Files.copy(
                rawLibrary.toPath(),
                outputLibrary.toPath(),
                LinkOption.NOFOLLOW_LINKS,
                StandardCopyOption.REPLACE_EXISTING,
            )
            outputLibrary
        }

        val prebuiltRoot = androidNdkDirectory.get().asFile
            .resolve("toolchains/llvm/prebuilt")
        require(
            Files.isDirectory(prebuiltRoot.toPath(), LinkOption.NOFOLLOW_LINKS) &&
                !Files.isSymbolicLink(prebuiltRoot.toPath()),
        ) {
            "Android NDK LLVM prebuilt root must be a non-symbolic directory: $prebuiltRoot"
        }
        val stripLaunchers = prebuiltRoot.listFiles()
            ?.asSequence()
            ?.filter { hostDirectory ->
                Files.isDirectory(hostDirectory.toPath(), LinkOption.NOFOLLOW_LINKS) &&
                    !Files.isSymbolicLink(hostDirectory.toPath())
            }
            ?.flatMap { hostDirectory ->
                sequenceOf("llvm-strip", "llvm-strip.exe").map { launcherName ->
                    hostDirectory.resolve("bin/$launcherName")
                }
            }
            ?.filter { launcher ->
                Files.exists(launcher.toPath(), LinkOption.NOFOLLOW_LINKS) &&
                    !Files.isDirectory(launcher.toPath(), LinkOption.NOFOLLOW_LINKS)
            }
            ?.toList()
            .orEmpty()
        require(stripLaunchers.size == 1) {
            "Expected one Android NDK llvm-strip launcher under $prebuiltRoot; " +
                "found ${stripLaunchers.size}"
        }
        val stripLauncher = stripLaunchers.single()
        val stripExecutablePath = stripLauncher.toPath().toRealPath()
        val stripHostBinPath = stripLauncher.parentFile.toPath().toRealPath()
        require(
            stripExecutablePath.startsWith(stripHostBinPath) &&
                Files.isRegularFile(stripExecutablePath, LinkOption.NOFOLLOW_LINKS) &&
                Files.isExecutable(stripExecutablePath),
        ) {
            "Android NDK llvm-strip must resolve to an executable regular file inside " +
                "${stripLauncher.parentFile}: $stripLauncher -> $stripExecutablePath"
        }
        NativeBridgeBuildContract.canonicalStripCommands(
            stripExecutablePath,
            outputLibraries,
        ).forEach { stripCommand ->
            execOperations.exec {
                setEnvironment(
                    mapOf(
                        "HOME" to tools.home.absolutePath,
                        "PATH" to "${stripExecutablePath.parent}:/usr/bin:/bin",
                        "TMPDIR" to tools.temporaryDirectory.absolutePath,
                        "LANG" to "C.UTF-8",
                        "LC_ALL" to "C.UTF-8",
                    ),
                )
                commandLine(*stripCommand.toTypedArray())
            }.assertNormalExitValue()
        }
        NativeBridgeBuildContract.requireLibraries(outputRoot)
        val rawLibrariesAfterStrip = NativeBridgeBuildContract.requireLibraries(inputRoot)
            .associateBy { library -> library.parentFile.name }
        rawIdentityByAbi.forEach { (abi, identity) ->
            val rawLibrary = requireNotNull(rawLibrariesAfterStrip[abi])
            require(rawLibrary.length() == identity.first &&
                NativeBridgeBuildContract.sha256Hex(rawLibrary.toPath()) == identity.second
            ) {
                "Canonical stripping modified raw cargo-ndk output for $abi"
            }
        }

        val ndkRevision = tools.androidNdkRevision

        val outputByAbi = outputLibraries.associateBy { library -> library.parentFile.name }
        val libraries = linkedMapOf<String, Any>()
        NativeBridgeBuildContract.abis.forEach { abi ->
            val outputLibrary = requireNotNull(outputByAbi[abi])
            val rawIdentity = requireNotNull(rawIdentityByAbi[abi])
            libraries[abi] = linkedMapOf(
                "aar_path" to "jni/$abi/${NativeBridgeBuildContract.libraryName}",
                "bytes" to outputLibrary.length(),
                "raw_bytes" to rawIdentity.first,
                "raw_sha256" to rawIdentity.second,
                "sha256" to NativeBridgeBuildContract.sha256Hex(outputLibrary.toPath()),
            )
        }
        val cargoFeatures = listOf("privacy-production-enabled")
        val manifest = linkedMapOf<String, Any?>(
            "schema" to "iroha.android-native-build-provenance.v1",
            "native_bridge_abi_version" to 25,
            "build_profile" to "release",
            "cargo_locked" to true,
            "privacy_production_enabled" to true,
            "cargo_features" to cargoFeatures,
            "build_environment" to NativeBridgeBuildContract.buildEnvironmentDocument(tools),
            "source_commit" to sourceCommit,
            "source_tree_dirty" to sourceTreeDirty,
            "source_fingerprint_sha256" to sourceFingerprint,
            "cargo_lock_sha256" to NativeBridgeBuildContract.sha256Hex(tools.cargoLock),
            "android_ndk_revision" to ndkRevision,
            "strip_tool_sha256" to NativeBridgeBuildContract.sha256Hex(stripExecutablePath),
            "libraries" to libraries,
        )
        if (localIntegration.get()) {
            manifest["artifact_scope"] = "local-integration"
        }
        val provenanceFile = provenanceRoot.resolve(
            "iroha/native-build-provenance-v1.json",
        )
        require(provenanceFile.parentFile.mkdirs() || provenanceFile.parentFile.isDirectory) {
            "Unable to create native provenance directory: ${provenanceFile.parentFile}"
        }
        NativeBridgeBuildContract.assertSourceSeal(
            execOperations,
            irohaRoot,
            sealScript,
            sealFile,
            "stripped artifact immediate pre-promotion authentication",
            tools,
        )
        provenanceFile.writeText(JsonOutput.prettyPrint(JsonOutput.toJson(manifest)) + "\n")
        NativeBridgeBuildContract.assertSourceSeal(
            execOperations,
            irohaRoot,
            sealScript,
            sealFile,
            "stripped artifact immediate post-promotion authentication",
            tools,
        )
    }
}

group = "org.hyperledger.iroha.sdk"
version = providers.gradleProperty("irohaSdkVersion")
    .orElse(providers.environmentVariable("IROHA_SDK_VERSION"))
    .orElse("0.1.0")
    .get()

val mobileSdkRepoDir = providers.gradleProperty("irohaSdkRepoDir")
    .orElse(rootProject.layout.buildDirectory.dir("mobile-sdk-maven").map { it.asFile.absolutePath })

android {
    namespace = "org.hyperledger.iroha.sdk.android"
    compileSdk = 35
    ndkVersion = NativeBridgeBuildContract.pinnedAndroidNdkBaseRevision

    defaultConfig {
        minSdk = 24
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
        isCoreLibraryDesugaringEnabled = true
    }

    kotlin {
        jvmToolchain(21)

        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_1_8)
            freeCompilerArgs.add("-Xjdk-release=8")
        }
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }

    sourceSets {
        // Native bridge bytes are generated under build/ and registered with
        // the variant API below. Never package stale, ignored source-tree .so files.
        getByName("main").jniLibs.directories.clear()
        // Reuse the exact Java assertions against the Android consumer classpath.
        getByName("test").java.srcDir(project(":core-jvm").file("src/sorafsJavaTest/java"))
    }

    packaging {
        resources {
            // Each Netty module ships this optional jar index; it is not runtime data.
            excludes.add("META-INF/INDEX.LIST")
            // Module version reports are diagnostic metadata, not protocol behavior.
            excludes.add("META-INF/io.netty.versions.properties")
        }
        jniLibs {
            // The mobile artifact verifier binds the published AAR to the exact
            // generated, canonically stripped bridge bytes and provenance.
            // Prevent AGP from applying a second, potentially different strip.
            keepDebugSymbols.add("**/libconnect_norito_bridge.so")
        }
    }
}

repositories {
    google()
    mavenCentral()
}

publishing {
    repositories {
        maven {
            name = "mobileSdk"
            url = uri(mobileSdkRepoDir.get())
        }
        providers.environmentVariable("IROHA_SDK_MAVEN_URL").orNull?.let { remoteUrl ->
            val endpoint = URI(remoteUrl)
            require(endpoint.scheme == "https" && !endpoint.host.isNullOrBlank() &&
                endpoint.rawUserInfo == null && endpoint.rawQuery == null && endpoint.rawFragment == null) {
                "IROHA_SDK_MAVEN_URL must be an HTTPS repository without embedded credentials"
            }
            val remoteUsername = providers.environmentVariable("IROHA_SDK_MAVEN_USERNAME").orNull
            val remotePassword = providers.environmentVariable("IROHA_SDK_MAVEN_PASSWORD").orNull
            require((remoteUsername == null) == (remotePassword == null) &&
                (remoteUsername == null || remoteUsername.isNotBlank() && remotePassword!!.isNotBlank())) {
                "Remote Maven credentials must be a complete runtime-only pair"
            }
            maven {
                name = "remoteSdk"
                url = endpoint
                isAllowInsecureProtocol = false
                if (remoteUsername != null) {
                    credentials {
                        username = remoteUsername
                        password = remotePassword
                    }
                }
            }
        }
    }
}

dependencies {
    api(project(":core-jvm"))
    implementation(libs.play.services.nearby)
    implementation(libs.play.integrity)
    coreLibraryDesugaring(libs.desugar.jdk.libs)
    testImplementation(kotlin("test"))
    testImplementation(libs.bcprov)
    testImplementation(libs.junit.params)
    testRuntimeOnly(libs.junit.jupiter.engine)
    testRuntimeOnly(libs.junit.platform.launcher)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.junit)
    androidTestImplementation(libs.okhttp)
    androidTestImplementation(libs.bcprov)
    // This library's self-targeted instrumentation APK needs its compiled Android
    // classes at runtime; the AGP test classpath alone does not package them.
    androidTestRuntimeOnly(files(layout.buildDirectory.file(
        "intermediates/compile_library_classes_jar/debug/bundleLibCompileToJarDebug/classes.jar",
    )).builtBy("bundleLibCompileToJarDebug"))
}

tasks.withType<Test>().configureEach {
    enableAssertions = true
    val hostNativeTask = name == "testDebugHostNative"
    useJUnitPlatform {
        if (!hostNativeTask) excludeTags("host-native")
    }
    if (name == "testDebugUnitTest") {
        dependsOn("processDebugManifest")
        systemProperty(
            "iroha.clientAndroid.mergedManifest",
            layout.buildDirectory.file(
                "intermediates/merged_manifest/debug/processDebugManifest/AndroidManifest.xml",
            ).get().asFile.absolutePath,
        )
    }
}

// Reuse the Android variant's compiled consumers and mockable Android classpath.
// Loading a host JNI library is an explicit qualification task, separate from
// managed unit tests and from physical-device/Android-native execution.
afterEvaluate {
    tasks.register<Test>("testDebugHostNative") {
        description = "Run Android Kotlin and Java consumers against an explicitly supplied host JNI bridge."
        group = "verification"
        val managed = tasks.named<Test>("testDebugUnitTest").get()
        testClassesDirs = managed.testClassesDirs
        classpath = managed.classpath
        dependsOn(provider { managed.taskDependencies.getDependencies(managed) })
        useJUnitPlatform { includeTags("host-native") }
        filter {
            includeTestsMatching("org.hyperledger.iroha.sdk.*")
            isFailOnNoMatchingTests = true
        }
        outputs.upToDateWhen { false }
        outputs.doNotCacheIf("Host JNI qualification must execute against the supplied artifact") { true }
        val nativeDirectory = providers.environmentVariable("IROHA_NATIVE_LIBRARY_PATH")
        doFirst {
            val configured = nativeDirectory.orNull
            require(!configured.isNullOrBlank()) {
                "testDebugHostNative requires IROHA_NATIVE_LIBRARY_PATH for the rebuilt host bridge"
            }
            val directory = File(configured)
            require(directory.isAbsolute && directory.isDirectory) {
                "IROHA_NATIVE_LIBRARY_PATH must be an absolute existing directory"
            }
            require(directory.resolve(System.mapLibraryName("connect_norito_bridge")).isFile) {
                "The configured host JNI bridge is missing"
            }
            systemProperty("java.library.path", directory.absolutePath)
        }
    }
}

fun irohaDir(): String {
    val props = Properties()
    val file = rootProject.file("local.properties")
    if (file.exists()) file.inputStream().use { props.load(it) }
    return props.getProperty("iroha.dir") ?: rootProject.file("..").absolutePath
}

// Privacy support is mandatory. This retired selector cannot introduce an off profile.
require(!providers.gradleProperty("privacyProductionEnabled").isPresent) {
    "privacyProductionEnabled has been removed; the native bridge always includes privacy support"
}
val nativeBuildMode = "production"
// Native app and instrumentation packages always include the sealed bridge.
// The ordinary JVM unit-test task graph does not execute these packaging owners.
require(!providers.gradleProperty("irohaDebugNativeBridge").isPresent) {
    "irohaDebugNativeBridge has been removed; every native app variant includes the bridge"
}
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
        python.toString(), "-I", "-S",
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
val mobileSdkAndroidArtifactDirectoryInput =
    providers.environmentVariable("MOBILE_SDK_ANDROID_ARTIFACT_DIR")
val requireAndroidArtifactDirectory =
    tasks.register("requireAndroidArtifactDirectory") {
        group = "verification"
        description =
            "Requires authenticated canonical Android release or local integration output"
        inputs.property(
            "mobileSdkAndroidArtifactDirectory",
            mobileSdkAndroidArtifactDirectoryInput.orElse("<missing>"),
        )
        inputs.property("localAndroidIntegration", localAndroidIntegration)
        doLast {
            val raw = mobileSdkAndroidArtifactDirectoryInput.orNull
                ?: throw GradleException(
                    "Reviewed Android Release builds require " +
                        "MOBILE_SDK_ANDROID_ARTIFACT_DIR.",
                )
            val supplied = Path.of(raw)
            require(supplied.isAbsolute && supplied.normalize().toString() == raw) {
                "MOBILE_SDK_ANDROID_ARTIFACT_DIR must be an absolute normalized path"
            }
            val canonical = supplied.toRealPath()
            require(
                canonical == supplied &&
                    Files.isDirectory(canonical, LinkOption.NOFOLLOW_LINKS) &&
                    !Files.isSymbolicLink(canonical) &&
                    Files.isWritable(canonical),
            ) {
                "MOBILE_SDK_ANDROID_ARTIFACT_DIR must be one canonical writable " +
                    "non-symbolic directory"
            }
            val irohaRoot = file(irohaDir()).toPath().toRealPath()
            if (localAndroidIntegration) {
                validateLocalAndroidArtifactDirectory(irohaRoot, canonical)
            } else {
                require(canonical != irohaRoot && !canonical.startsWith(irohaRoot)) {
                    "MOBILE_SDK_ANDROID_ARTIFACT_DIR must be outside the reviewed Iroha source tree"
                }
            }
            val expectedBuildDirectory = canonical
                .resolve("gradle-build/iroha_kotlin_sdk/client-android")
                .normalize()
            require(
                layout.buildDirectory.get().asFile.toPath().toAbsolutePath().normalize() ==
                    expectedBuildDirectory,
            ) {
                "client-android Release outputs are not redirected to the canonical " +
                    "MOBILE_SDK_ANDROID_ARTIFACT_DIR"
            }
        }
    }
val androidNdkRoot = providers.environmentVariable("ANDROID_NDK_HOME")
    .orElse(providers.environmentVariable("ANDROID_NDK_ROOT"))
    .orElse(androidComponents.sdkComponents.ndkDirectory.map { it.asFile.absolutePath })

tasks.register("verifyAndroidNdkIdentityContract") {
    group = "verification"
    description = "Exercises the strict Android NDK package identity parser"
    doLast {
        check(android.ndkVersion == NativeBridgeBuildContract.pinnedAndroidNdkBaseRevision) {
            "Gradle must select the same NDK installation required by native artifact verification"
        }
        val canonicalText = listOf(
            "Pkg.Desc = Android NDK",
            "Pkg.Revision = 28.0.12674087-beta2",
            "Pkg.BaseRevision = 28.0.12674087",
            "Pkg.ReleaseName = r28-beta2",
        ).joinToString(separator = "\n", postfix = "\n")
        val canonicalBytes = canonicalText.toByteArray(StandardCharsets.UTF_8)

        fun installation(label: String, payload: ByteArray): Path {
            val root = Files.createTempDirectory(temporaryDir.toPath(), "$label-")
            val ndk = Files.createDirectory(
                root.resolve(NativeBridgeBuildContract.pinnedAndroidNdkBaseRevision),
            )
            Files.write(
                ndk.resolve("source.properties"),
                payload,
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE,
            )
            return ndk
        }

        fun requireRejected(label: String, action: () -> Unit) {
            require(runCatching(action).isFailure) {
                "Android NDK identity self-test accepted $label"
            }
        }

        val identity = NativeBridgeBuildContract.loadAndroidNdkIdentity(
            installation("canonical", canonicalBytes),
        )
        require(
            identity.description == NativeBridgeBuildContract.pinnedAndroidNdkDescription &&
                identity.revision == NativeBridgeBuildContract.pinnedAndroidNdkRevision &&
                identity.baseRevision ==
                    NativeBridgeBuildContract.pinnedAndroidNdkBaseRevision &&
                identity.releaseName ==
                    NativeBridgeBuildContract.pinnedAndroidNdkReleaseName &&
                identity.sourcePropertiesSha256 ==
                    NativeBridgeBuildContract.pinnedAndroidNdkSourcePropertiesSha256,
        ) {
            "Canonical Android NDK identity did not round-trip exactly"
        }

        val malformedDocuments = linkedMapOf(
            "duplicate property" to canonicalText.replace(
                "Pkg.ReleaseName = r28-beta2\n",
                "Pkg.Desc = Android NDK\nPkg.ReleaseName = r28-beta2\n",
            ),
            "missing property" to canonicalText.replace(
                "Pkg.ReleaseName = r28-beta2\n",
                "",
            ),
            "malformed delimiter" to canonicalText.replace(
                "Pkg.Desc = Android NDK",
                "Pkg.Desc=Android NDK",
            ),
            "extra property" to canonicalText +
                "Pkg.Extra = forbidden\n",
            "altered whitespace" to canonicalText.replace(
                "Pkg.Desc = Android NDK",
                "Pkg.Desc  = Android NDK",
            ),
            "altered case" to canonicalText.replace(
                "Pkg.Desc",
                "pkg.Desc",
            ),
            "altered preview suffix" to canonicalText.replace(
                "28.0.12674087-beta2",
                "28.0.12674087-beta3",
            ),
            "altered base revision" to canonicalText.replace(
                "Pkg.BaseRevision = 28.0.12674087",
                "Pkg.BaseRevision = 28.0.12674088",
            ),
            "reordered properties" to listOf(
                "Pkg.Revision = 28.0.12674087-beta2",
                "Pkg.Desc = Android NDK",
                "Pkg.BaseRevision = 28.0.12674087",
                "Pkg.ReleaseName = r28-beta2",
            ).joinToString(separator = "\n", postfix = "\n"),
            "CRLF lines" to canonicalText.replace("\n", "\r\n"),
            "missing final LF" to canonicalText.removeSuffix("\n"),
        )
        malformedDocuments.forEach { (label, document) ->
            requireRejected(label) {
                NativeBridgeBuildContract.parseAndroidNdkSourceProperties(
                    document.toByteArray(StandardCharsets.UTF_8),
                )
            }
        }
        requireRejected("non-UTF-8 bytes") {
            NativeBridgeBuildContract.parseAndroidNdkSourceProperties(
                byteArrayOf(0xc3.toByte(), 0x28),
            )
        }
        requireRejected("oversized source.properties") {
            NativeBridgeBuildContract.loadAndroidNdkIdentity(
                installation(
                    "oversized",
                    ByteArray(
                        NativeBridgeBuildContract.maxAndroidNdkSourcePropertiesBytes + 1,
                    ) { 'A'.code.toByte() },
                ),
            )
        }

        val symlinkRoot = Files.createTempDirectory(temporaryDir.toPath(), "symlink-")
        val symlinkNdk = Files.createDirectory(
            symlinkRoot.resolve(
                NativeBridgeBuildContract.pinnedAndroidNdkBaseRevision,
            ),
        )
        val symlinkTarget = symlinkRoot.resolve("actual-source.properties")
        Files.write(
            symlinkTarget,
            canonicalBytes,
            StandardOpenOption.CREATE_NEW,
            StandardOpenOption.WRITE,
        )
        Files.createSymbolicLink(
            symlinkNdk.resolve("source.properties"),
            symlinkTarget,
        )
        requireRejected("symbolic-link source.properties") {
            NativeBridgeBuildContract.loadAndroidNdkIdentity(symlinkNdk)
        }

        val wrongDirectoryRoot =
            Files.createTempDirectory(temporaryDir.toPath(), "wrong-directory-")
        val wrongDirectory = Files.createDirectory(
            wrongDirectoryRoot.resolve("28.0.12674087-beta2"),
        )
        Files.write(
            wrongDirectory.resolve("source.properties"),
            canonicalBytes,
            StandardOpenOption.CREATE_NEW,
            StandardOpenOption.WRITE,
        )
        requireRejected("noncanonical NDK directory name") {
            NativeBridgeBuildContract.loadAndroidNdkIdentity(wrongDirectory)
        }

        val stripProbeRoot =
            Files.createTempDirectory(temporaryDir.toPath(), "strip-invocation-")
        val fakeObjcopy = stripProbeRoot.resolve("llvm-objcopy")
        val fakeObjcopyScript = """
            #!/bin/sh
            set -eu
            if [ "${'$'}#" -ne 2 ] || [ "${'$'}1" != "--strip-unneeded" ]; then
              exit 64
            fi
            case "${'$'}2" in
              *reject*)
                exit 65
                ;;
            esac
            printf 'stripped\n' >> "${'$'}2"
        """.trimIndent() + "\n"
        Files.write(
            fakeObjcopy,
            fakeObjcopyScript.toByteArray(StandardCharsets.UTF_8),
            StandardOpenOption.CREATE_NEW,
            StandardOpenOption.WRITE,
        )
        require(fakeObjcopy.toFile().setExecutable(true, true)) {
            "Unable to make the fake llvm-objcopy executable"
        }
        val fakeStripLauncher = stripProbeRoot.resolve("llvm-strip")
        Files.createSymbolicLink(fakeStripLauncher, fakeObjcopy.fileName)
        val authenticatedStripExecutable = fakeStripLauncher.toRealPath()
        require(authenticatedStripExecutable == fakeObjcopy.toRealPath()) {
            "The fake llvm-strip launcher did not resolve to llvm-objcopy"
        }

        fun runStripProbe(command: List<String>): Pair<Int, String> {
            val process = ProcessBuilder(command)
                .directory(stripProbeRoot.toFile())
                .redirectErrorStream(true)
                .start()
            val output = process.inputStream.bufferedReader(Charsets.UTF_8).use { reader ->
                reader.readText()
            }
            return process.waitFor() to output
        }

        val taggedLibraries = listOf("arm64-v8a", "x86_64").map { abi ->
            val abiDirectory = Files.createDirectory(stripProbeRoot.resolve(abi))
            val library = abiDirectory.resolve(NativeBridgeBuildContract.libraryName)
            Files.write(
                library,
                "$abi-original\n".toByteArray(StandardCharsets.UTF_8),
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE,
            )
            library.toFile()
        }
        val stripCommands = NativeBridgeBuildContract.canonicalStripCommands(
            authenticatedStripExecutable,
            taggedLibraries,
        )
        require(
            stripCommands.size == taggedLibraries.size &&
                stripCommands.all { command ->
                    command.size == 3 &&
                        command[0] == authenticatedStripExecutable.toString() &&
                        command[1] == "--strip-unneeded"
                } &&
                stripCommands.map { command -> command[2] }.toSet().size ==
                    taggedLibraries.size,
        ) {
            "Canonical Android stripping must invoke authenticated llvm-objcopy " +
                "once per distinct ABI library"
        }
        stripCommands.forEach { command ->
            val (status, output) = runStripProbe(command)
            require(status == 0) {
                "Independent Android strip probe failed with status $status: $output"
            }
        }
        taggedLibraries.forEach { library ->
            val abi = library.parentFile.name
            require(library.readText(Charsets.UTF_8) == "$abi-original\nstripped\n") {
                "Independent Android stripping cross-overwrote or skipped $abi"
            }
        }

        val rejectedLibrary = stripProbeRoot.resolve("reject-library.so")
        Files.write(
            rejectedLibrary,
            "must-remain\n".toByteArray(StandardCharsets.UTF_8),
            StandardOpenOption.CREATE_NEW,
            StandardOpenOption.WRITE,
        )
        val rejectedCommand = NativeBridgeBuildContract.canonicalStripCommands(
            authenticatedStripExecutable,
            listOf(rejectedLibrary.toFile()),
        ).single()
        val (rejectedStatus, _) = runStripProbe(rejectedCommand)
        require(rejectedStatus != 0 &&
            rejectedLibrary.toFile().readText(Charsets.UTF_8) == "must-remain\n"
        ) {
            "Android strip probe must fail closed without mutating a rejected ABI library"
        }
    }
}

val compileNativeLibs = tasks.register<CompileNativeBridgeTask>("compileNativeLibs") {
    group = "native"
    description = "Compile connect_norito_bridge .so from Rust source (requires cargo-ndk + Android NDK)"
    irohaDirectory.set(file(irohaDir()))
    cargoTargetDirectory.set(
        layout.buildDirectory.dir("native/cargo-target/$nativeBuildMode"),
    )
    cargoNdkStagingDirectory.set(
        layout.buildDirectory.dir("native/cargo-ndk-staging/$nativeBuildMode"),
    )
    sourceSealScript.set(file(irohaDir()).resolve("scripts/norito_bridge_source_seal.py"))
    hermeticRunner.set(file(irohaDir()).resolve("scripts/run_mobile_hermetic_command.py"))
    androidNdkDirectory.set(
        layout.dir(androidNdkRoot.map { ndkPath -> file(ndkPath) }),
    )
    outputDirectory.set(layout.buildDirectory.dir("native/cargo-ndk/$nativeBuildMode"))
    sourceSealFile.set(
        layout.buildDirectory.file("native/sourceSeal/$nativeBuildMode/source-seal-v1.json"),
    )
    buildEnvironmentFile.set(
        layout.buildDirectory.file(
            "native/buildEnvironment/$nativeBuildMode/build-environment-v1.json",
        ),
    )
    outputs.upToDateWhen { hasReusableSealedOutput() }
    dependsOn(requireAndroidArtifactDirectory)
}

// Explicit development-only armv7 lane. It shares the pinned native recipe but
// never supplies generated JNI directories, AAR contents or admitted provenance.
val compileArmv7DiagnosticRaw = tasks.register<CompileNativeBridgeTask>("compileArmv7DiagnosticRaw") {
    group = "native"
    description = "Compile the sealed armv7 bridge in the owned diagnostic scope"
    // A fixed warm lane must never reuse artifacts from another feature recipe.
    sourceSealPlatform.set(NativeBridgeBuildContract.armv7DiagnosticPlatform)
    sourceSealPlatform.disallowChanges()
    localIntegration.set(localAndroidIntegration)
    irohaDirectory.set(file(irohaDir()))
    cargoTargetDirectory.set(layout.buildDirectory.dir("native/cargo-target/armv7-diagnostic"))
    cargoNdkStagingDirectory.set(layout.buildDirectory.dir("native/cargo-ndk-staging/armv7-diagnostic"))
    sourceSealScript.set(file(irohaDir()).resolve("scripts/norito_bridge_source_seal.py"))
    hermeticRunner.set(file(irohaDir()).resolve("scripts/run_mobile_hermetic_command.py"))
    androidNdkDirectory.set(layout.dir(androidNdkRoot.map { file(it) }))
    outputDirectory.set(layout.buildDirectory.dir("native/armv7-diagnostic/raw"))
    sourceSealFile.set(layout.buildDirectory.file("native/sourceSeal/armv7-diagnostic/source-seal-v1.json"))
    buildEnvironmentFile.set(layout.buildDirectory.file("native/buildEnvironment/armv7-diagnostic/build-environment-v1.json"))
    outputs.upToDateWhen { hasReusableSealedOutput() }
    dependsOn(requireAndroidArtifactDirectory)
}
val compileArmv7Diagnostic = tasks.register<InspectArmv7DiagnosticTask>("compileArmv7Diagnostic") {
    group = "native"
    description = "Build and inspect an armv7 diagnostic; no AAR/JNI or release promotion"
    localIntegration.set(localAndroidIntegration)
    irohaDirectory.set(file(irohaDir()))
    hermeticRunner.set(file(irohaDir()).resolve("scripts/run_mobile_hermetic_command.py"))
    androidNdkDirectory.set(layout.dir(androidNdkRoot.map { file(it) }))
    cargoTargetDirectory.set(compileArmv7DiagnosticRaw.flatMap { it.cargoTargetDirectory })
    sourceSealScript.set(file(irohaDir()).resolve("scripts/norito_bridge_source_seal.py"))
    inspectionScript.set(file(irohaDir()).resolve("scripts/inspect_android_armv7_diagnostic.py"))
    rawDirectory.set(compileArmv7DiagnosticRaw.flatMap { it.outputDirectory })
    sourceSealFile.set(compileArmv7DiagnosticRaw.flatMap { it.sourceSealFile })
    buildEnvironmentFile.set(compileArmv7DiagnosticRaw.flatMap { it.buildEnvironmentFile })
    reportFile.set(layout.buildDirectory.file("native/armv7-diagnostic/diagnostic-manifest.json"))
    outputs.upToDateWhen { false }
    dependsOn(compileArmv7DiagnosticRaw, requireAndroidArtifactDirectory)
}
tasks.register("verifyArmv7DiagnosticContract") {
    group = "verification"
    description = "Check armv7 diagnostic routing without invoking native compilation"
    doLast {
        val diagnostic = NativeBridgeBuildContract.armv7DiagnosticPlatform
        check(NativeBridgeBuildContract.abis == listOf("arm64-v8a", "x86_64"))
        check(NativeBridgeBuildContract.rustTargets == listOf("aarch64-linux-android", "x86_64-linux-android"))
        check(NativeBridgeBuildContract.buildAbis(diagnostic) == listOf("armeabi-v7a"))
        check(NativeBridgeBuildContract.buildTargets(diagnostic) == listOf("armv7-linux-androideabi"))
        val raw = compileArmv7DiagnosticRaw.get()
        check(raw.sourceSealPlatform.get() == diagnostic)
        check(raw.cargoTargetDirectory.get().asFile == layout.buildDirectory.dir("native/cargo-target/armv7-diagnostic").get().asFile)
        check(raw.outputDirectory.get().asFile == layout.buildDirectory.dir("native/armv7-diagnostic/raw").get().asFile)
        check(raw.outputDirectory.get().asFile != compileNativeLibs.get().outputDirectory.get().asFile)
        check(compileArmv7Diagnostic.get().reportFile.get().asFile.name == "diagnostic-manifest.json")
        check(runCatching { NativeBridgeBuildContract.buildAbis("unreviewed") }.isFailure)
    }
}

val stripNativeLibs = tasks.register<StripNativeBridgeTask>("stripNativeLibs") {
    group = "native"
    description = "Canonically strip the compiled Android native bridge libraries"
    localIntegration.set(localAndroidIntegration)
    inputDirectory.set(compileNativeLibs.flatMap { it.outputDirectory })
    sourceSealFile.set(compileNativeLibs.flatMap { it.sourceSealFile })
    buildEnvironmentFile.set(compileNativeLibs.flatMap { it.buildEnvironmentFile })
    irohaDirectory.set(file(irohaDir()))
    sourceSealScript.set(file(irohaDir()).resolve("scripts/norito_bridge_source_seal.py"))
    hermeticRunner.set(file(irohaDir()).resolve("scripts/run_mobile_hermetic_command.py"))
    androidNdkDirectory.set(
        layout.dir(androidNdkRoot.map { ndkPath -> file(ndkPath) }),
    )
    cargoTargetDirectory.set(compileNativeLibs.flatMap { it.cargoTargetDirectory })
    outputDirectory.set(layout.buildDirectory.dir("generated/jniLibs/$nativeBuildMode"))
    provenanceDirectory.set(
        layout.buildDirectory.dir("generated/nativeProvenance/$nativeBuildMode"),
    )
    // Re-run the comparatively cheap strip/provenance phase so every release
    // packaging operation performs a final live source-seal check, even when
    // the expensive per-ABI Cargo output is safely reusable.
    outputs.upToDateWhen { false }
}

// This library's instrumentation APK targets itself. Its compiled Kotlin classes are
// supplied above, but AGP does not copy the library variant's JNI payload into that
// self-targeted APK. Physical native probes must carry the same generated bridge.
android.sourceSets.getByName("androidTest").jniLibs.srcDir(
    layout.buildDirectory.get().asFile.resolve("generated/jniLibs/$nativeBuildMode"),
)
tasks.matching { it.name == "mergeDebugAndroidTestJniLibFolders" }.configureEach {
    dependsOn(stripNativeLibs)
}

// Every app variant uses the same authenticated native build and provenance.
// Ordinary JVM unit-test compilation does not launch Cargo or the Android NDK.

androidComponents.onVariants { variant ->
    requireNotNull(variant.sources.jniLibs) {
        "AGP did not expose jniLibs sources for ${variant.name}"
    }.addGeneratedSourceDirectory(stripNativeLibs, StripNativeBridgeTask::outputDirectory)
    requireNotNull(variant.sources.assets) {
        "AGP did not expose asset sources for ${variant.name}"
    }.addGeneratedSourceDirectory(stripNativeLibs, StripNativeBridgeTask::provenanceDirectory)
}

tasks.register("buildNativeLibs") {
    group = "native"
    description = "Build and canonically strip connect_norito_bridge Android libraries"
    dependsOn(stripNativeLibs)
    dependsOn(requireAndroidArtifactDirectory)
}

tasks.matching {
    name == "assembleRelease" ||
        name == "bundleReleaseAar" ||
        name.startsWith("publishRelease")
}.configureEach {
    dependsOn(requireAndroidArtifactDirectory)
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])
                groupId = "org.hyperledger.iroha.sdk"
                artifactId = "client-android"
            }
        }
    }
}
