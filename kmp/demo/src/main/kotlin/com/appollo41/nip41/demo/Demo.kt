package com.appollo41.nip41.demo

import com.appollo41.nip41.Kind1041Verification
import com.appollo41.nip41.NIP41_CHAIN_LENGTH
import com.appollo41.nip41.NIP41_KIND_1041
import com.appollo41.nip41.Nip19
import com.appollo41.nip41.SignedNostrEvent
import com.appollo41.nip41.UnsignedNostrEvent
import com.appollo41.nip41.buildChainBirthEvent
import com.appollo41.nip41.buildRotationEvent
import com.appollo41.nip41.deriveIdentityChain
import com.appollo41.nip41.verifyKind1041Event
import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.security.MessageDigest

/**
 * Runnable walkthrough of NIP-41 against the spec test vector.
 *
 *   gradle :demo:run
 *
 * Outputs the derived chain (A), an ordinary signed note (B), a chain-birth
 * kind:1041 event (C), a rotation kind:1041 event (D), and the event-level
 * verification result on the legitimate event plus a forged-attacker variant
 * (E).
 */
fun main() {
    val pretty = Json {
        prettyPrint = true
        prettyPrintIndent = "  "
    }

    banner("NIP-41 Nostr Identity Chain — KMP reference implementation")

    section("[A] Phase A — Derive the identity chain")
    val rootSecret = sha256("nip-41 test vector root secret v1".encodeToByteArray())
    println("root_secret : ${Hex.encode(rootSecret)}")
    println("                  (32 random bytes in production — passkey PRF or csprng;")
    println("                   here SHA-256 of a fixed string so we reproduce the spec)")
    println()

    val chain = deriveIdentityChain(rootSecret, length = NIP41_CHAIN_LENGTH)
    println("Chain length: ${chain.length}  (= NIP41_CHAIN_LENGTH; covers any realistic identity lifetime)")
    println("Showing the first 4 generations and the terminal; intermediate generations")
    println("are derived identically.")
    println()
    val sample = listOf(0, 1, 2, 3, chain.length - 1)
    for (i in sample) {
        val tag = when (i) {
            0 -> "  (active)"
            chain.length - 1 -> "  (terminal — commits to nothing)"
            else -> ""
        }
        // exportNsec() returns a defensive copy of the signing key. In real
        // code the caller would zero it after use; the demo just prints it.
        val nsecBytes = chain.exportNsec(i)
        println("  Generation $i$tag")
        println("    npub  hex : ${chain.npub[i]}")
        println("    npub  nip19: ${Nip19.encodeNpub(chain.npub[i])}")
        println("    nsec  hex : ${Hex.encode(nsecBytes)}")
        println("    nsec  nip19: ${Nip19.encodeNsec(nsecBytes)}")
        println()
    }

    section("[B] Phase B — Sign an ordinary kind:1 note with the gen-0 key")
    val note = chain.signWith(
        generation = 0,
        event = UnsignedNostrEvent(
            pubkey = chain.npub[0],
            createdAt = 1716200000L,
            kind = 1,
            tags = emptyList(),
            content = "Hello, Nostr — signed by a NIP-41 committed identity. " +
                "A client that has never heard of NIP-41 sees nothing unusual.",
        ),
    )

    println(pretty.encodeToString(SignedNostrEvent.serializer(), note))
    val noteOk = Secp256k1.verifySchnorr(
        Hex.decode(note.sig),
        Hex.decode(note.id),
        Hex.decode(chain.npub[0]),
    )
    println()
    println("BIP-340 verify against npub[0]: ${ok(noteOk)}")

    section("[C] Phase C — Chain-birth kind:1041 event (declares npub[0] as a committed-chain head)")
    val birth = chain.buildChainBirthEvent(createdAt = 1716100000L)
    println(pretty.encodeToString(SignedNostrEvent.serializer(), birth))
    println()
    println("Single self-successor tag opening npub[0]'s commitment to npub[1].")

    section("[D] Phase D — Rotation kind:1041 event (gen 0 -> gen 1)")
    val rotation = chain.buildRotationEvent(
        toGeneration = 1,
        createdAt = 1716200000L,
        content = "optional human-readable note",
    )
    println(pretty.encodeToString(SignedNostrEvent.serializer(), rotation))
    println()
    println("Signed by nsec[1] (the NEW key) — the old, possibly-compromised nsec[0]")
    println("never touches this event.")

    section("[E] Phase E — Verify the rotation event")
    val verified = verifyKind1041Event(rotation)
    println("verifyKind1041Event -> $verified")
    val rotationAccepted = verified is Kind1041Verification.Rotation
    val landsOnGen1 = verified is Kind1041Verification.Rotation &&
        verified.subject == chain.npub[1]
    println("Recognised as Rotation:   ${ok(rotationAccepted)}")
    println("Subject == npub[1]:       ${ok(landsOnGen1)}")

    println()
    println("Negative test — attacker holds a key, signs a forged rotation:")
    val attackerNsec = ByteArray(32).apply { this[31] = 0x42 }
    val attackerNpubBytes = Secp256k1.pubkeyCreate(attackerNsec).copyOfRange(1, 33)
    val attackerNpub = Hex.encode(attackerNpubBytes)
    val forgedTags = listOf(
        listOf("p", chain.npub[0], "", "predecessor"),
        listOf("p", attackerNpub, "", "successor"),
        listOf(
            "successor",
            chain.npub[0],
            chain.internalXonly[0],
            attackerNpub,
        ),
        listOf(
            "successor",
            attackerNpub,
            chain.internalXonly[1],
            chain.npub[2],
        ),
    )
    val forged = UnsignedNostrEvent(
        pubkey = attackerNpub,
        createdAt = 1716200000L,
        kind = NIP41_KIND_1041,
        tags = forgedTags,
        content = "",
    ).sign(attackerNsec)
    val sigValid = Secp256k1.verifySchnorr(
        Hex.decode(forged.sig),
        Hex.decode(forged.id),
        attackerNpubBytes,
    )
    val forgedResult = verifyKind1041Event(forged)
    println("  attacker npub             : $attackerNpub")
    println("  BIP-340 signature valid?  : ${if (sigValid) "yes (they signed it themselves)" else "no"}")
    println("  Event-level verification  : $forgedResult")
    println()
    println("→ The attacker's event has a perfectly valid Schnorr signature, but the")
    println("  successor tag's verify_chain_proof equation doesn't hold. Fail-closed.")

    banner("Done.")
}

private fun banner(title: String) {
    val bar = "=".repeat(78)
    println()
    println(bar)
    println(title)
    println(bar)
}

private fun section(title: String) {
    println()
    println(title)
    println("-".repeat(78))
}

private fun ok(b: Boolean) = if (b) "PASS" else "FAIL"

// Demo is JVM-only; SHA-256 via the JDK standard library keeps the demo
// independent of whatever hash provider the library happens to use.
private fun sha256(data: ByteArray): ByteArray =
    MessageDigest.getInstance("SHA-256").digest(data)
