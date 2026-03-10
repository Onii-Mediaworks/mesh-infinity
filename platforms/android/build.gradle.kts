allprojects {
    repositories {
        google()
        mavenCentral()
    }
}

// Resolve relative to rootDir (platforms/android/), not the build directory,
// so the output lands at <repo-root>/build/ rather than platforms/build/.
val newBuildDir: File = rootProject.rootDir.resolve("../../build")
rootProject.layout.buildDirectory.set(newBuildDir)

subprojects {
    project.layout.buildDirectory.set(newBuildDir.resolve(project.name))
}
subprojects {
    project.evaluationDependsOn(":app")
}

tasks.register<Delete>("clean") {
    delete(rootProject.layout.buildDirectory)
}
