# NIP-41 Kotlin Multiplatform reference

Configured targets: JVM, Android, iOS (arm64 / x64 / simulator-arm64),
macOS arm64, Linux (x64 / arm64).

## Running tests

    ./gradlew :nip41:allTests

This runs every host-runnable test target. On macOS arm64 that's
`jvmTest`, `macosArm64Test`, `iosSimulatorArm64Test`, and `iosX64Test`;
on Linux it's `jvmTest` and `linuxX64Test`. `jvmTest` always works.

Android unit tests are disabled in `build.gradle.kts` because the
Android JNI artifact only ships `.so` files for Android device ABIs
(they don't load on the host JVM). The same Kotlin code is covered by
`jvmTest`. To re-enable, see the `androidComponents { beforeVariants }`
block.

The plain `:nip41:test` aggregate task is a no-op alias (KMP layout
artifact) — it prints `BUILD SUCCESSFUL` without exercising anything.
Use `:nip41:allTests` or a platform-specific test task instead.
