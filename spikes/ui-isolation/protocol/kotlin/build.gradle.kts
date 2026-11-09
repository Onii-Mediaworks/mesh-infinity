plugins {
    kotlin("jvm") version "2.2.21"
    // Generates Kotlin types from ../proto at build time.
    id("com.squareup.wire") version "5.2.1"
    application
}

wire {
    sourcePath {
        srcDir("../proto")
    }
    kotlin {}
}

kotlin {
    jvmToolchain(17)
}

application {
    // Reads a framed stream, decodes and re-encodes each envelope, writes it back out.
    mainClass.set("RoundTripKt")
}
