package com.appollo41.nip41

/**
 * BIP-340 tagged hash, kept as a top-level convenience so callsites read
 * `taggedHash("nip41/succession", bytes)` instead of `CryptoUtils.taggedHash(...)`.
 *
 * Internal: implementation detail of the chain derivation and verifier.
 * Consumers should not need to compute tagged hashes themselves.
 */
internal fun taggedHash(tag: String, message: ByteArray): ByteArray = CryptoUtils.taggedHash(tag, message)
