package com.appollo41.nip41

import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Spec "Bridge commitment kind:1042": a single one-time event signed by the
 * legacy key, with one `commits` tag pointing at `npub[0]` of a fresh
 * committed chain.
 *
 * Covers both the construction side (`buildBridgeCommitment`) and the
 * verification side (`verifyKind1042Event`).
 */
class Kind1042EventTest {

    // A 32-byte BIP-340 signing key for the legacy identity, plus its derived
    // x-only pubkey. The exact bytes don't matter, just that they're a valid
    // signing pair we can drive end-to-end through libsecp256k1.
    private val legacyNsec: ByteArray = ByteArray(32).apply { this[31] = 0x42 }
    private val legacyNpubBytes: ByteArray = Secp256k1.pubkeyCreate(legacyNsec).copyOfRange(1, 33)
    private val legacyNpubHex: String = Hex.encode(legacyNpubBytes)

    // A fresh committed chain's npub[0] (the bridge target).
    private val freshChain = deriveIdentityChain(
        CryptoUtils.sha256("nip41-bridge-fresh-root".encodeToByteArray()),
        4,
    )
    private val freshNpub0Hex: String = freshChain.npub[0]

    // --- builder ---------------------------------------------------------

    @Test fun build_setsKind1042() {
        val event = buildBridgeCommitment(legacyNsec, freshNpub0Hex, createdAt = 1716100000L)
        assertEquals(1042, event.kind)
    }

    @Test fun build_setsPubkeyToLegacyKey() {
        val event = buildBridgeCommitment(legacyNsec, freshNpub0Hex, createdAt = 0L)
        assertEquals(legacyNpubHex, event.pubkey)
    }

    @Test fun build_carriesExactlyOneCommitsTag() {
        val event = buildBridgeCommitment(legacyNsec, freshNpub0Hex, createdAt = 0L)
        val commitsTags = event.tags.filter { it.firstOrNull() == "commits" }
        assertEquals(1, commitsTags.size, "exactly one commits tag is required")
        assertEquals(listOf("commits", freshNpub0Hex), commitsTags[0])
    }

    @Test fun build_producesValidEventIdAndSignature() {
        // Verifier covers id+sig together; if either is wrong the event is
        // rejected. Round-tripping through the verifier is the strongest
        // single check.
        val event = buildBridgeCommitment(legacyNsec, freshNpub0Hex, createdAt = 0L)
        val result = verifyKind1042Event(event)
        assertIs<Kind1042Verification.Valid>(result)
        assertEquals(
            freshNpub0Hex,
            result.commits,
            "commits target must round-trip equal to the input npub[0]",
        )
    }

    @Test fun build_rejectsNonHex32CommitsTarget() {
        assertFailsWith<IllegalArgumentException> {
            buildBridgeCommitment(legacyNsec, "aa".repeat(31), createdAt = 0L)
        }
    }

    @Test fun build_rejectsWrongNsecLength() {
        assertFailsWith<IllegalArgumentException> {
            buildBridgeCommitment(ByteArray(31), freshNpub0Hex, createdAt = 0L)
        }
    }

    // --- verifier positive ----------------------------------------------

    @Test fun verify_acceptsHandBuiltEvent_andReturnsCommitsTarget() {
        val event = buildBridgeCommitment(legacyNsec, freshNpub0Hex, createdAt = 1L)
        val result = verifyKind1042Event(event)
        assertIs<Kind1042Verification.Valid>(result)
        assertEquals(freshNpub0Hex, result.commits)
    }

    // --- verifier negative ----------------------------------------------

    @Test fun verify_rejectsWrongKind() {
        val event = buildBridgeCommitment(legacyNsec, freshNpub0Hex, createdAt = 0L)
            .copy(kind = 1041)
        assertIs<Kind1042Verification.Invalid>(verifyKind1042Event(event))
    }

    @Test fun verify_rejectsTamperedContent_idMismatch() {
        val event = buildBridgeCommitment(legacyNsec, freshNpub0Hex, createdAt = 0L)
            .copy(content = "tampered")
        val result = verifyKind1042Event(event)
        assertIs<Kind1042Verification.Invalid>(result)
        assertTrue(result.reason.contains("event id"))
    }

    @Test fun verify_rejectsBadSignature() {
        val event = buildBridgeCommitment(legacyNsec, freshNpub0Hex, createdAt = 0L)
        val flippedSig = event.sig
            .replaceFirst(event.sig[0], if (event.sig[0] == 'a') 'b' else 'a')
        val tampered = event.copy(sig = flippedSig)
        val result = verifyKind1042Event(tampered)
        assertIs<Kind1042Verification.Invalid>(result)
        assertTrue(result.reason.contains("signature"))
    }

    @Test fun verify_rejectsMissingCommitsTag() {
        // Re-sign a kind:1042 event with no commits tag at all.
        val tags = listOf<List<String>>()
        val event = UnsignedNostrEvent(
            pubkey = legacyNpubHex,
            createdAt = 0L,
            kind = 1042,
            tags = tags,
            content = "",
        ).sign(legacyNsec)
        val result = verifyKind1042Event(event)
        assertIs<Kind1042Verification.Invalid>(result)
        assertTrue(result.reason.contains("commits"))
    }

    @Test fun verify_rejectsMultipleCommitsTags() {
        val tags = listOf(
            listOf("commits", freshNpub0Hex),
            listOf("commits", freshChain.npub[1]),
        )
        val event = UnsignedNostrEvent(
            pubkey = legacyNpubHex,
            createdAt = 0L,
            kind = 1042,
            tags = tags,
            content = "",
        ).sign(legacyNsec)
        val result = verifyKind1042Event(event)
        assertIs<Kind1042Verification.Invalid>(result)
        assertTrue(result.reason.contains("commits"))
    }

    @Test fun verify_rejectsCommitsTagWrongArity() {
        val tags = listOf(listOf("commits", freshNpub0Hex, "extra"))
        val event = UnsignedNostrEvent(
            pubkey = legacyNpubHex,
            createdAt = 0L,
            kind = 1042,
            tags = tags,
            content = "",
        ).sign(legacyNsec)
        val result = verifyKind1042Event(event)
        assertIs<Kind1042Verification.Invalid>(result)
        assertTrue(result.reason.contains("commits"))
    }

    @Test fun verify_rejectsCommitsValueNotHex() {
        val tags = listOf(listOf("commits", "not-hex-at-all"))
        val event = UnsignedNostrEvent(
            pubkey = legacyNpubHex,
            createdAt = 0L,
            kind = 1042,
            tags = tags,
            content = "",
        ).sign(legacyNsec)
        assertIs<Kind1042Verification.Invalid>(verifyKind1042Event(event))
    }

    @Test fun verify_rejectsCommitsValueWrongLength() {
        // 31 bytes hex
        val tags = listOf(listOf("commits", "aa".repeat(31)))
        val event = UnsignedNostrEvent(
            pubkey = legacyNpubHex,
            createdAt = 0L,
            kind = 1042,
            tags = tags,
            content = "",
        ).sign(legacyNsec)
        assertIs<Kind1042Verification.Invalid>(verifyKind1042Event(event))
    }
}
