// The Flutter host for spike S1, laid out like platforms/android (the real
// Mesh host): the Flutter Gradle plugin from the SDK named in
// local.properties, which the CI job writes.
pluginManagement {
    val flutter_sdk =
        run {
            val properties = java.util.Properties()
            file("local.properties").inputStream().use { properties.load(it) }
            properties.getProperty("flutter.sdk") ?: error("flutter.sdk not set in local.properties")
        }

    includeBuild("$flutter_sdk/packages/flutter_tools/gradle")

    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

// The same plugin versions as platforms/android.
plugins {
    id("dev.flutter.flutter-plugin-loader") version "1.0.0"
    id("com.android.application") version "8.11.1" apply false
    id("com.android.library") version "8.11.1" apply false
    id("org.jetbrains.kotlin.android") version "2.2.20" apply false
}

include(":app")
// The confinement half, shared with the Compose host.
include(":common")
project(":common").projectDir = file("../../common")
