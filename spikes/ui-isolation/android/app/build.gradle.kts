// The spike app: a stand-in core and its Fibrewall broker in the main
// process, and a Compose UI in the `:ui` process that locks itself down
// before it draws anything.

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.oniimediaworks.meshinfinity.uispike"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.oniimediaworks.meshinfinity.uispike"
        // Fibrewall supports API 26 and up (its NDK floor, android-26).
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.0.1-spike"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        ndk {
            // Fibrewall is 64-bit only (v0.1.4): x86_64 for the emulators,
            // arm64-v8a for real devices.
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
        externalNativeBuild {
            cmake {
                // Fibrewall's own end-to-end test is not part of the app.
                arguments += listOf("-DSBX_TESTS=OFF", "-DANDROID_PLATFORM=android-26")
            }
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    buildFeatures {
        compose = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    packaging {
        // The JNI library must be extracted to the native-library folder,
        // which the confined process is allowed to read.
        jniLibs.useLegacyPackaging = true
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    // Compose, pinned through one bill of materials.
    val compose_bom = platform("androidx.compose:compose-bom:2025.01.01")
    implementation(compose_bom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.10.0")
    implementation("androidx.core:core-ktx:1.15.0")

    // Instrumented tests drive the UI through UiAutomator, which reads the
    // accessibility tree: that is the accessibility check from a confined
    // process.
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test:rules:1.6.1")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test.uiautomator:uiautomator:2.3.0")
}
