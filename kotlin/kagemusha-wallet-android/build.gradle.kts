import java.io.File
import java.net.URI
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.library)
    `maven-publish`
}

group = "org.hyperledger.iroha.sdk"
version = providers.gradleProperty("irohaSdkVersion")
    .orElse(providers.environmentVariable("IROHA_SDK_VERSION"))
    .orElse("0.1.0")
    .get()

val mobileSdkRepoDir = providers.gradleProperty("irohaSdkRepoDir")
    .orElse(rootProject.layout.buildDirectory.dir("mobile-sdk-maven").map { it.asFile.absolutePath })

android {
    namespace = "org.hyperledger.iroha.sdk.offline.wallet"
    compileSdk = 35

    defaultConfig {
        minSdk = 26
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    sourceSets {
        getByName("test") {
            kotlin.srcDir(rootProject.file("test-support/src"))
        }
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
    api(project(":client-android"))
    coreLibraryDesugaring(libs.desugar.jdk.libs)
    testImplementation(kotlin("test"))
    testImplementation(libs.coroutines.core.jvm)
    testImplementation(libs.junit.params)
    testRuntimeOnly(libs.junit.jupiter.engine)
    testRuntimeOnly(libs.junit.platform.launcher)
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
}

tasks.withType<Test>().configureEach {
    enableAssertions = true
    val hostNativeTask = name == "testDebugHostNative"
    useJUnitPlatform {
        if (!hostNativeTask) excludeTags("host-native")
    }
    // The wallet custody backup test asserts the processed library manifest, not only its source.
    if (name == "testDebugUnitTest") {
        dependsOn("processDebugManifest")
        systemProperty(
            "iroha.kagemushaWalletAndroid.mergedManifest",
            layout.buildDirectory.file(
                "intermediates/merged_manifest/debug/processDebugManifest/AndroidManifest.xml",
            ).get().asFile.absolutePath,
        )
    }
}

afterEvaluate {
    // Actual host JNI is an explicit component gate, separate from managed adapters and phones.
    tasks.register<Test>("testDebugHostNative") {
        description = "Run wallet consumers against an explicitly supplied current host JNI bridge."
        group = "verification"
        val managed = tasks.named<Test>("testDebugUnitTest").get()
        testClassesDirs = managed.testClassesDirs
        classpath = managed.classpath
        dependsOn(provider { managed.taskDependencies.getDependencies(managed) })
        useJUnitPlatform { includeTags("host-native") }
        filter {
            includeTestsMatching("org.hyperledger.iroha.sdk.offline.wallet.*")
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
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])
                groupId = "org.hyperledger.iroha.sdk"
                artifactId = "kagemusha-wallet-android"
            }
        }
    }
}
