package com.appollo41.nip41

import fr.acinq.secp256k1.Hex

/**
 * Hex decode with a precise catch scope: `Hex.decode` throws only
 * `IllegalArgumentException` on malformed input. Returning null on that one
 * exception keeps the fail-closed shape without swallowing `Error` subclasses
 * (OOM, StackOverflowError, LinkageError) that indicate genuine system trouble
 * we'd rather see propagate.
 *
 * Used by every verifier and walk predicate that decodes caller-supplied hex
 * strings (event ids, pubkeys, tag values).
 */
internal fun decodeHexOrNull(s: String): ByteArray? = try {
    Hex.decode(s)
} catch (_: IllegalArgumentException) {
    null
}
