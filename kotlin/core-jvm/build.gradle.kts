import java.net.URI
import java.io.File
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
    `maven-publish`
    `java-library`
}

group = "org.hyperledger.iroha.sdk"
version = providers.gradleProperty("irohaSdkVersion")
    .orElse(providers.environmentVariable("IROHA_SDK_VERSION"))
    .orElse("0.1.0")
    .get()

val mobileSdkRepoDir = providers.gradleProperty("irohaSdkRepoDir")
    .orElse(rootProject.layout.buildDirectory.dir("mobile-sdk-maven").map { it.asFile.absolutePath })

repositories {
    mavenCentral()
}

dependencies {
    api(libs.okhttp)
    api(platform(libs.netty.bom))
    api(libs.netty.transport)
    implementation(libs.netty.handler)
    implementation(libs.netty.codec.http)
    testImplementation(libs.mockwebserver)
    implementation(libs.zstd.jni)
    implementation(libs.bcprov)
    implementation(libs.serialization.json)
    testImplementation(kotlin("test"))
    testImplementation(libs.junit.params)
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

kotlin {
    jvmToolchain(21)

    sourceSets.named("test") {
        kotlin.srcDir(rootProject.file("test-support/src"))
    }

    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_1_8)
        freeCompilerArgs.add("-Xjdk-release=8")
    }
}

// One Java assertion owner is compiled against both JVM and Android Kotlin consumers.
sourceSets.test {
    java.srcDir("src/sorafsJavaTest/java")
}

// Java consumers are compiled against JDK 8 APIs, just like the Kotlin API.
tasks.withType<JavaCompile>().configureEach {
    options.release.set(8)
}

tasks.test {
    enableAssertions = true
    useJUnitPlatform {
        excludeTags("cuda-hardware")
    }
    inputs.file(
        rootProject.layout.projectDirectory
            .dir("..")
            .file("fixtures/norito_rpc/atomic_private_settlement_sdk_v1.json"),
    )
    inputs.file(rootProject.layout.projectDirectory.dir("..").file("fixtures/musubi/sdk_v1.json"))
    inputs.file(
        rootProject.layout.projectDirectory
            .dir("..")
            .file("fixtures/musubi/instructions_v1.json"),
    )
    inputs.file(rootProject.layout.projectDirectory.dir("..").file("fixtures/crypto/ed25519_public_key_admission_v1.json"))
    inputs.file(rootProject.layout.projectDirectory.dir("..").file("fixtures/account/multisig_wire_v1.json"))
    inputs.file(rootProject.layout.projectDirectory.dir("..").file("fixtures/multisig/instruction_batch_hash_v1.json"))
    inputs.file(rootProject.layout.projectDirectory.dir("..").file("fixtures/sumeragi/native_status_v1.tsv"))
    inputs.file(rootProject.layout.projectDirectory.dir("..").file("fixtures/sumeragi/native_lanes_v1.tsv"))
    inputs.file(rootProject.layout.projectDirectory.dir("..").file("fixtures/validator_staking/norito_v1.tsv"))
    inputs.file(rootProject.layout.projectDirectory.dir("..").file("fixtures/numeric_v1_golden.json"))
    inputs.file(rootProject.layout.projectDirectory.dir("..").file("fixtures/torii/list_query/vectors.json"))
    inputs.file(rootProject.layout.projectDirectory.dir("..").file("fixtures/kagemusha/wallet_v1_vectors.json"))
    inputs.dir(rootProject.layout.projectDirectory.dir("..").dir("fixtures/petal"))
    inputs.file(
        rootProject.layout.projectDirectory
            .dir("..")
            .file("fixtures/kotodama/entrypoint_argument_record_v1.json"),
    )
    inputs.file(rootProject.layout.projectDirectory.dir("..").file("fixtures/zk/verifying_key_record_v1.json"))
    inputs.file(
        rootProject.layout.projectDirectory
            .dir("..")
            .file("fixtures/privacy/exact12_typed_fixture_bundle_v1.norito.b64"),
    )
    inputs.dir(
        rootProject.layout.projectDirectory
            .dir("..")
            .dir("fixtures/sorafs_manifest/appeal_finance"),
    )
    inputs.dir(
        rootProject.layout.projectDirectory
            .dir("..")
            .dir("fixtures/sorafs_manifest/reference_sdk"),
    )
    // OfflinePackageSurfaceV1Test pins KAGEMUSHA file names and ServiceLoader registrations
    // across the three SDK modules, so their names are test inputs.
    for (module in listOf("core-jvm", "client-android", "kagemusha-wallet-android")) {
        inputs.files(
            rootProject.layout.projectDirectory.dir("$module/src").asFileTree.matching {
                include { element ->
                    element.isDirectory ||
                        element.name.lowercase().startsWith("kagemusha") ||
                        element.path.contains("META-INF/services")
                }
            },
        ).withPropertyName("packageSurface-$module").ignoreEmptyDirectories()
    }

    // Release CI supplies a freshly built, isolated ABI-25 bridge. Local
    // development retains the conventional root target/debug fallback.
    val configuredNativeDir = System.getenv("IROHA_NATIVE_LIBRARY_PATH")
    val hostNativeDir = if (configuredNativeDir.isNullOrBlank()) {
        rootProject.projectDir.parentFile.resolve("target/debug")
    } else {
        file(configuredNativeDir)
    }
    systemProperty("java.library.path", hostNativeDir.absolutePath)
}

// Ordinary native parity may use CPU fallback. It cannot satisfy device evidence.
// TODO: implement JNI per-family completion receipts and mandatory physical controls.
tasks.register("cudaHardwareTest") {
    description = "Report the open Kotlin/JNI CUDA physical qualification gate."
    group = "verification"
    doLast {
        throw GradleException("CUDA JNI qualification is open: per-family completion receipts are not implemented. Ordinary native parity is not device evidence.")
    }
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

    publications {
        create<MavenPublication>("release") {
            from(components["java"])
            groupId = "org.hyperledger.iroha.sdk"
            artifactId = "core-jvm"
        }
    }
}

// Runnable local proof example. A same-source JNI bridge is required; no network is contacted.
tasks.register<JavaExec>("confidentialRedemptionExample") {
    description = "Generate and locally verify one confidential full-redemption proof."
    group = "verification"
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("org.hyperledger.iroha.sdk.examples.ConfidentialRedemptionExample")
    val nativeDirectory = providers.environmentVariable("IROHA_NATIVE_LIBRARY_PATH")
        .orElse(rootProject.projectDir.parentFile.resolve("target/debug").absolutePath)
    systemProperty("java.library.path", nativeDirectory.get())
}
