// Plugin versions for the spike, declared once and applied in :app.
// AGP 8.13 and Kotlin 2.2.21 match the versions Enginehost builds with today
// (the same Fibrewall-on-Android pattern this spike follows).
plugins {
    id("com.android.application") version "8.13.1" apply false
    id("com.android.library") version "8.13.1" apply false
    id("org.jetbrains.kotlin.android") version "2.2.21" apply false
    // The Compose compiler ships with Kotlin since 2.0; its plugin version
    // must equal the Kotlin version.
    id("org.jetbrains.kotlin.plugin.compose") version "2.2.21" apply false
}
