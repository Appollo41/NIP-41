package com.appollo41.nip41

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Pins the public-API surface of the NIP-41 spec-frozen constants.
 *
 * These values are interop-critical: changing a single byte silently
 * fragments compatibility with conforming implementations elsewhere.
 * Treat any test failure here as a load-bearing API break, not a test
 * to update.
 */
class PublicConstantsTest {

    @Test fun hkdfSalt_isSpecValue_inUtf8Bytes() {
        assertTrue(
            NIP41_HKDF_SALT.contentEquals("nip41-key-rotation-v1".encodeToByteArray()),
            "NIP41_HKDF_SALT must equal utf8('nip41-key-rotation-v1') (spec 'Identity chain')",
        )
    }

    @Test fun tweakTag_isSpecValue() {
        assertEquals("nip41/succession", NIP41_TWEAK_TAG)
    }

    @Test fun kinds_areSpecValues() {
        assertEquals(1041, NIP41_KIND_1041)
        assertEquals(1042, NIP41_KIND_1042)
    }

    @Test fun chainLength_isSpecValue() {
        assertEquals(1024, NIP41_CHAIN_LENGTH)
    }

    @Test fun tagNames_areSpecValues() {
        assertEquals("successor", Nip41Tags.SUCCESSOR)
        assertEquals("predecessor", Nip41Tags.PREDECESSOR)
        assertEquals("bridge", Nip41Tags.BRIDGE)
        assertEquals("p", Nip41Tags.P)
        assertEquals("commits", Nip41Tags.COMMITS)
    }
}
