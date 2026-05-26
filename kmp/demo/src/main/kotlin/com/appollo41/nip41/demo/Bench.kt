package com.appollo41.nip41.demo

import com.appollo41.nip41.deriveIdentityChain
import java.security.MessageDigest
import kotlin.system.measureNanoTime

/**
 * `gradle run -PmainClass=com.appollo41.nip41.demo.BenchKt`
 *
 * Measures how long `deriveIdentityChain(rootSecret, N)` takes for several
 * chain lengths. JIT-warms first, then reports the median of multiple runs.
 *
 * Per-generation cost is roughly: 1 HKDF-SHA256 + 1 scalar multiplication
 * (pubkeyCreate) + 1 point tweak (pubKeyTweakAdd) + 1 seckey tweak. The two
 * point operations dominate; libsecp256k1 makes them fast.
 */
fun main() {
    val rootSecret = MessageDigest.getInstance("SHA-256").digest("bench-root".encodeToByteArray())

    println("Warming JIT…")
    repeat(5) { deriveIdentityChain(rootSecret, 128) }
    println()

    val lengths = intArrayOf(2, 4, 16, 32, 64, 128, 256, 512, 1024)
    val runs = 11

    println("%-6s | %12s | %10s | %14s".format("N", "median (ms)", "min (ms)", "per-gen (µs)"))
    println("-".repeat(56))

    for (n in lengths) {
        val timings = LongArray(runs) {
            measureNanoTime { deriveIdentityChain(rootSecret, n) }
        }.also { it.sort() }
        val medianMs = timings[runs / 2] / 1_000_000.0
        val minMs = timings.first() / 1_000_000.0
        val perGenUs = (timings[runs / 2].toDouble() / n) / 1_000.0
        println("%-6d | %12.2f | %10.2f | %14.1f".format(n, medianMs, minMs, perGenUs))
    }

    println()
    println("Notes:")
    println("  - libsecp256k1 (acinq JNI wrapper) does the heavy lifting.")
    println("  - HKDF/SHA-256 is pure Kotlin (kotlincrypto), negligible at this scale.")
    println("  - Chain is fully deterministic from the root secret.")
}
