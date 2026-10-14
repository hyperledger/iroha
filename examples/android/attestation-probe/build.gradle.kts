plugins {
    id("com.android.application") version "9.0.1"
}

android {
    namespace = "org.hyperledger.iroha.samples.attestationprobe"
    compileSdk = 35

    defaultConfig {
        applicationId = "org.hyperledger.iroha.samples.attestationprobe"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlin {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_1_8)
        }
    }
}

dependencies {
    testImplementation("junit:junit:4.13.2")
}
