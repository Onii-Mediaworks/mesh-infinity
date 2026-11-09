// Spike S5, Kotlin side: Wire-generated protocol types on the JVM. Wire is
// Kotlin Multiplatform, so the same generated code serves Android, desktop
// and iOS in Phase 2; the JVM is enough to prove the encoding matches.
pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
    }
}

rootProject.name = "mesh_ui_protocol_kotlin"
