package com.appollo41.nip41

import fr.acinq.secp256k1.Hex
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * NIP-01 event id = SHA-256 of `[0, pubkey, created_at, kind, tags, content]`
 * canonical JSON (compact, no whitespace, raw UTF-8).
 *
 * The byte-exact test that matters is `id == spec id`, because that's what
 * gets signed. We don't pin the exact intermediate JSON string — that would be
 * brittle and just re-test kotlinx-serialization's output format. Instead we
 * test the *consequences*: each field contributes to the id, and special
 * characters round-trip deterministically.
 *
 * Fixture: the spec test vectors' generation-0 -> generation-1 rotation event.
 */
class NostrEventTest {

    private val specRotationEvent = UnsignedNostrEvent(
        pubkey = "dcfd5f479fbc68ae0af338c914826713df5c94fda0534c14ebb62fffbcc5a111",
        createdAt = 1716200000L,
        kind = 1041,
        tags = listOf(
            listOf("p", "af878736425985fd1f32c4b2673281e4a670af12e5b44bac6109913f7535d1c4", "", "predecessor"),
            listOf("p", "dcfd5f479fbc68ae0af338c914826713df5c94fda0534c14ebb62fffbcc5a111", "", "successor"),
            listOf(
                "successor",
                "af878736425985fd1f32c4b2673281e4a670af12e5b44bac6109913f7535d1c4",
                "589ab097fb0dc109d597ab8714b8363b6c96238e735b4f749fad4377aa8871cf",
                "dcfd5f479fbc68ae0af338c914826713df5c94fda0534c14ebb62fffbcc5a111",
            ),
            listOf(
                "successor",
                "dcfd5f479fbc68ae0af338c914826713df5c94fda0534c14ebb62fffbcc5a111",
                "b78bf4bbe86f70f8262a7916a7e414cd3b65eb708db7ce011b9a1133ce693094",
                "06632001932f623c61df08d7dde11900aa6680748f9fc01a8f244fb4b0a70d2a",
            ),
        ),
        content = "optional human-readable note",
    )

    // --- The conformance check: byte-exact event id from the spec ------------

    @Test fun spec_rotationEvent_id_matchesSpec() {
        val expectedId = Hex.decode("53a326f7e153f2b3c5d9aa195b461f9f20c03e32a15d318f4de65fc2ca3574ec")
        assertContentEquals(expectedId, specRotationEvent.eventId())
    }

    // --- Property tests: each field actually contributes to the id ----------

    @Test fun id_changes_whenPubkeyChanges() {
        val mutated = specRotationEvent.copy(
            pubkey = "0000000000000000000000000000000000000000000000000000000000000001",
        )
        assertFalse(specRotationEvent.eventId().contentEquals(mutated.eventId()))
    }

    @Test fun id_changes_whenCreatedAtChanges() {
        val mutated = specRotationEvent.copy(createdAt = specRotationEvent.createdAt + 1)
        assertFalse(specRotationEvent.eventId().contentEquals(mutated.eventId()))
    }

    @Test fun id_changes_whenKindChanges() {
        val mutated = specRotationEvent.copy(kind = 1042)
        assertFalse(specRotationEvent.eventId().contentEquals(mutated.eventId()))
    }

    @Test fun id_changes_whenTagsChange() {
        val mutated = specRotationEvent.copy(
            tags = specRotationEvent.tags + listOf(listOf("extra", "x")),
        )
        assertFalse(specRotationEvent.eventId().contentEquals(mutated.eventId()))
    }

    @Test fun id_changes_whenContentChanges() {
        val mutated = specRotationEvent.copy(content = "hello")
        assertFalse(specRotationEvent.eventId().contentEquals(mutated.eventId()))
    }

    // --- Round-trip determinism for tricky content ---------------------------

    @Test fun id_isDeterministic_forContentWithEscapes() {
        val ev = specRotationEvent.copy(content = "a\"b\\c\nd\te")
        assertContentEquals(ev.eventId(), ev.eventId())
    }

    @Test fun id_isDeterministic_forNonAsciiContent() {
        val ev = specRotationEvent.copy(content = "héllo 🌹 こんにちは")
        assertContentEquals(ev.eventId(), ev.eventId())
    }

    @Test fun canonicalSerialization_keepsNonAsciiAsRawUtf8_notUnicodeEscape() {
        // Python's ensure_ascii=False — non-ASCII characters appear as raw UTF-8.
        // kotlinx-serialization defaults to the same.
        val ev = specRotationEvent.copy(content = "héllo")
        val ser = ev.canonicalSerialization()
        assertTrue(
            ser.contains("héllo"),
            "non-ASCII content must appear as raw UTF-8 in canonical form, not as \\uXXXX escapes",
        )
    }
}
