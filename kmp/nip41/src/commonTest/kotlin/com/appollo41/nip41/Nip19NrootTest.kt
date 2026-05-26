package com.appollo41.nip41

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Spec "Portability (root-secret export)": a conformant client MUST be able to
 * export and import the 32-byte root secret as bech32 with HRP `nroot`,
 * following NIP-19.
 *
 * These tests pin both directions and the format guarantees implementations
 * are entitled to assume from each other.
 */
class Nip19NrootTest {

    private val sampleRoot: ByteArray = ByteArray(32) { (it + 1).toByte() } // 0x01,0x02,...,0x20

    // --- happy path ---------------------------------------------------------

    @Test fun encodeNroot_producesNrootPrefix() {
        val encoded = Nip19.encodeNroot(sampleRoot)
        assertTrue(encoded.startsWith("nroot1"), "expected nroot1… prefix, got $encoded")
    }

    @Test fun decodeNroot_roundTripsArbitraryBytes() {
        val encoded = Nip19.encodeNroot(sampleRoot)
        val decoded = Nip19.decodeNroot(encoded)
        assertTrue(
            decoded.contentEquals(sampleRoot),
            "round-trip mismatch; expected 0x${sampleRoot.toHex()} got 0x${decoded.toHex()}",
        )
    }

    @Test fun encodeNroot_isStableAcrossInvocations() {
        // bech32 encoding is deterministic — two encodes of the same input must
        // produce the same string, byte-for-byte. Implementations comparing
        // nroot artifacts MUST be able to rely on this.
        assertEquals(Nip19.encodeNroot(sampleRoot), Nip19.encodeNroot(sampleRoot))
    }

    // --- input validation on encode ---------------------------------------

    @Test fun encodeNroot_rejectsShortPayload() {
        assertFailsWith<IllegalArgumentException> { Nip19.encodeNroot(ByteArray(31)) }
    }

    @Test fun encodeNroot_rejectsLongPayload() {
        assertFailsWith<IllegalArgumentException> { Nip19.encodeNroot(ByteArray(33)) }
    }

    @Test fun encodeNroot_rejectsEmptyPayload() {
        assertFailsWith<IllegalArgumentException> { Nip19.encodeNroot(ByteArray(0)) }
    }

    // --- input validation on decode ---------------------------------------

    @Test fun decodeNroot_rejectsNpubHrp() {
        // Constructing a valid 'npub1…' string and trying to decode it as nroot
        // MUST fail; mixing HRPs across NIP-19 entities is the single biggest
        // foot-gun the bech32 HRP exists to prevent.
        val asNpub = Nip19.encodeNpub(sampleRoot)
        assertFailsWith<IllegalArgumentException> { Nip19.decodeNroot(asNpub) }
    }

    @Test fun decodeNroot_rejectsNsecHrp() {
        val asNsec = Nip19.encodeNsec(sampleRoot)
        assertFailsWith<IllegalArgumentException> { Nip19.decodeNroot(asNsec) }
    }

    @Test fun decodeNroot_rejectsMalformedBech32() {
        assertFailsWith<IllegalArgumentException> { Nip19.decodeNroot("nroot1qqqq") }
    }

    @Test fun decodeNroot_rejectsTotalGarbage() {
        assertFailsWith<IllegalArgumentException> { Nip19.decodeNroot("not even bech32") }
    }

    private fun ByteArray.toHex(): String =
        joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
}
