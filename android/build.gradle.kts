plugins {
    id("com.android.application") version "8.5.0" apply false
    id("org.jetbrains.kotlin.android") version "1.9.22" apply false
}

val buildDirOverride = System.getenv("NETINFINITY_ANDROID_BUILD_DIR")?.takeIf { it.isNotBlank() }
val defaultTempRoot = java.io.File(System.getProperty("java.io.tmpdir"), "netinfinity-android").absolutePath
val buildRoot = buildDirOverride ?: defaultTempRoot

allprojects {
    layout.buildDirectory.set(file("$buildRoot/${project.name}"))
}
