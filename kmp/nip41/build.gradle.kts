plugins {
    kotlin("multiplatform")
    kotlin("plugin.serialization")
    id("com.android.library")
    id("org.jetbrains.dokka")
}

kotlin {
    jvmToolchain(21)
    explicitApi()

    jvm()
    androidTarget()

    iosArm64()
    iosX64()
    iosSimulatorArm64()

    macosArm64()

    linuxX64()
    linuxArm64()

    applyDefaultHierarchyTemplate()

    sourceSets {
        val commonMain by getting {
            dependencies {
                // BIP-340 Schnorr + BIP-341 Taproot tweak (KMP wrapper around libsecp256k1)
                implementation("fr.acinq.secp256k1:secp256k1-kmp:0.23.0")
                // Pure-Kotlin SHA-256 (used for HKDF, tagged hash, event id)
                implementation("org.kotlincrypto.hash:sha2:0.8.0")
                // HMAC-SHA256 primitive used by our local HKDF impl (Hkdf.kt).
                implementation("org.kotlincrypto.macs:hmac-sha2:0.7.0")
                // JSON for Nostr canonical event serialization (NIP-01 compact, no-whitespace)
                implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.11.0")
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test"))
            }
        }
        val jvmMain by getting {
            dependencies {
                // JNI-backed native libsecp256k1 binaries for the JVM target
                implementation("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm:0.23.0")
            }
        }
        val androidMain by getting {
            dependencies {
                // Android AAR with libsecp256k1 .so files bundled for arm64-v8a,
                // armeabi-v7a, x86_64, x86 in the AAR's jniLibs/.
                implementation("fr.acinq.secp256k1:secp256k1-kmp-jni-android:0.23.0")
            }
        }
    }
}

android {
    namespace = "com.appollo41.nip41"
    compileSdk = 36
    defaultConfig {
        minSdk = 21
    }
}

// Module.md provides the narrative landing page rendered at the top of
// the package index in generated docs. Without it, Dokka's index is just
// an alphabetical list of symbols — informative but not orienting.
dokka {
    dokkaSourceSets.configureEach {
        includes.from("Module.md")
    }
}

// Android unit tests run on the host JVM, but `secp256k1-kmp-jni-android`
// only ships .so files for Android device ABIs — they don't load on the host.
// The same Kotlin code is already covered by jvmTest (which uses the JVM JNI
// artifact). Re-enable here if we ever wire up instrumented tests on a device.
androidComponents {
    beforeVariants(selector().all()) { variant ->
        variant.enableUnitTest = false
    }
}
