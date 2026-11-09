// Every module resolves from the same repositories (the Flutter plugin adds
// the engine's own maven repository itself).
allprojects {
    repositories {
        google()
        mavenCentral()
    }
}
