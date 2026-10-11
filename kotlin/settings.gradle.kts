pluginManagement {
    repositories {
        google()
        gradlePluginPortal()
        mavenCentral()
    }
}

plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}
rootProject.name = "iroha_kotlin_sdk"
apply(from = "../gradle/mobile-sdk-external-android-build.settings.gradle.kts")

include(":core-jvm")
include(":tools")
include(":client-android")
include(":kagemusha-wallet-android")
