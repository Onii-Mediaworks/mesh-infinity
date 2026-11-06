// The Flutter host for spike S1: the confinement half comes from :common,
// this app adds the Flutter UI (../../lib) in the `:ui` process.

plugins {
    id("com.android.application")
    id("kotlin-android")
    // The Flutter Gradle plugin must come after the Android and Kotlin plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

android {
    namespace = "com.oniimediaworks.meshinfinity.uispike.flutter"
    compileSdk = 36
    ndkVersion = flutter.ndkVersion

    defaultConfig {
        applicationId = "com.oniimediaworks.meshinfinity.uispike.flutter"
        // Fibrewall supports API 26 and up.
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.0.1-spike"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        ndk {
            // Fibrewall is 64-bit only.
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    // The test runs against the release build: Dart compiled ahead of time,
    // as Mesh ships it, and no VM service (debug and profile builds open
    // one on a socket, which the confined process may not create).
    testBuildType = "release"
    buildTypes {
        getByName("release") {
            // Signed with the debug key so CI can install it; not shrunk, so
            // the test can reach the app's classes.
            signingConfig = signingConfigs.getByName("debug")
            isMinifyEnabled = false
            isShrinkResources = false
        }
    }

    // The shared instrumented test, which drives whichever UI the host ships.
    sourceSets["androidTest"].java.srcDir("../../../common/src/androidTest/kotlin")

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    packaging {
        // Native libraries extracted to the native-library folder, which the
        // confined process may read (libflutter.so, libapp.so, the sandbox).
        jniLibs.useLegacyPackaging = true
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

flutter {
    source = "../.."
}

dependencies {
    implementation(project(":common"))

    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test:rules:1.6.1")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test.uiautomator:uiautomator:2.3.0")
}
