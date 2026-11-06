// Phase 0 spike S1 (plans/ui-isolation-and-compose.md §5): a Compose UI in its
// own `:ui` process, confined by Fibrewall, talking to a stand-in core in the
// main process. This project is an experiment on the spike branch only; it is
// never merged and never shipped.

pluginManagement {
    repositories {
        // Android Gradle plugin and AndroidX artifacts.
        google()
        // Kotlin and everything else.
        mavenCentral()
        // Gradle's own plugins.
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    // Every module resolves from the same two repositories.
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "mesh_ui_spike"

// One application module: the core stand-in and the UI live in one APK, as
// they will in Mesh Infinity, and differ only by process.
include(":app")
