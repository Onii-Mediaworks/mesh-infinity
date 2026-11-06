// The confinement half of spike S1, shared by the Compose host (../android)
// and the Flutter host (../flutter/android): the stand-in core's provider,
// the warden's provider and Fibrewall broker, the UI session that locks the
// `:ui` process down, and the escape probes. Each host adds only its UI.

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    // Its own namespace, so it never clashes with a host app's; the Kotlin package is shared.
    namespace = "com.oniimediaworks.meshinfinity.uispike.common"
    compileSdk = 36

    defaultConfig {
        // Fibrewall supports API 26 and up.
        minSdk = 26
        ndk {
            // Fibrewall is 64-bit only.
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
        externalNativeBuild {
            cmake {
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

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    // BundleCompat, for reading descriptors out of provider calls without deprecated APIs.
    implementation("androidx.core:core-ktx:1.15.0")
}
