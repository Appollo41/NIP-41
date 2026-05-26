package com.appollo41.nip41

import fr.acinq.secp256k1.Hex
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails

/**
 * NIP-19 bech32 encoding for `npub` (public key) and `nsec` (private key).
 *
 * Conformance vector for npub is taken from the NIP-19 spec itself:
 *   hex   : 3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d
 *   npub1 : npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6
 *
 * For nsec we lean on round-trip + the bech32 checksum (changing any single
 * char in a valid bech32 string will invalidate the checksum).
 */
class Nip19Test {

    private val specNpubHex = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"
    private val specNpubBech = "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6"

    @Test fun encodeNpub_fromBytes_matchesNip19Vector() {
        assertEquals(specNpubBech, Nip19.encodeNpub(Hex.decode(specNpubHex)))
    }

    @Test fun encodeNpub_fromHex_matchesNip19Vector() {
        assertEquals(specNpubBech, Nip19.encodeNpub(specNpubHex))
    }

    @Test fun decodeNpub_returnsHex_matchesNip19Vector() {
        assertEquals(specNpubHex, Nip19.decodeNpub(specNpubBech))
    }

    @Test fun encodeNpub_rejectsWrongSize() {
        assertFails { Nip19.encodeNpub(ByteArray(31)) }
        assertFails { Nip19.encodeNpub(ByteArray(33)) }
    }

    @Test fun encodeNpub_fromHex_rejectsWrongLength() {
        assertFails { Nip19.encodeNpub("aa".repeat(31)) }
        assertFails { Nip19.encodeNpub("aa".repeat(33)) }
    }

    @Test fun encodeNpub_fromHex_rejectsNonHex() {
        assertFails { Nip19.encodeNpub("z".repeat(64)) }
    }

    @Test fun decodeNpub_rejectsNsecPrefix() {
        // A perfectly valid nsec1... string must not decode as npub.
        val nsec = Nip19.encodeNsec(ByteArray(32).apply { this[31] = 0x42 })
        assertFails { Nip19.decodeNpub(nsec) }
    }

    @Test fun encodeNsec_roundTrips() {
        val key = ByteArray(32) { (it * 7 + 3).toByte() }
        val nsec = Nip19.encodeNsec(key)
        assertEquals(true, nsec.startsWith("nsec1"))
        assertContentEquals(key, Nip19.decodeNsec(nsec))
    }

    @Test fun decodeNpub_rejectsCorruptedChecksum() {
        // Flip one character; bech32 should reject it.
        val bad = specNpubBech.replaceFirst("8", "9") // touches the data section
        assertFails { Nip19.decodeNpub(bad) }
    }

    @Test fun nip41_specNpub0_encodesAndRoundTrips() {
        // The first npub from our NIP-41 test vector: sanity that it bech32s cleanly.
        val gen0 = "af878736425985fd1f32c4b2673281e4a670af12e5b44bac6109913f7535d1c4"
        val encoded = Nip19.encodeNpub(gen0)
        assertEquals(true, encoded.startsWith("npub1"))
        assertEquals(gen0, Nip19.decodeNpub(encoded))
    }
}
