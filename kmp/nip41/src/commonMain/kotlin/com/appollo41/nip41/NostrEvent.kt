package com.appollo41.nip41

import fr.acinq.secp256k1.Hex
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonArray
import kotlinx.serialization.json.buildJsonArray

/**
 * The Nostr event fields that determine the event id (NIP-01).
 * No `id` or `sig` here; those are derived. See [eventId] and [sign].
 */
@Serializable
public data class UnsignedNostrEvent(
    @SerialName("pubkey") public val pubkey: String,
    @SerialName("created_at") public val createdAt: Long,
    public val kind: Int,
    public val tags: List<List<String>>,
    public val content: String,
) {
    /**
     * NIP-01 canonical serialization:
     * `[0, pubkey, created_at, kind, tags, content]` as compact JSON, no
     * whitespace, raw UTF-8 for non-ASCII. kotlinx-serialization's default
     * `JsonArray.toString()` matches Python's
     * `json.dumps(..., separators=(",",":"), ensure_ascii=False)` byte-for-byte.
     */
    public fun canonicalSerialization(): String = buildJsonArray {
        add(0)
        add(pubkey)
        add(createdAt)
        add(kind)
        addJsonArray {
            tags.forEach { tag ->
                addJsonArray { tag.forEach { add(it) } }
            }
        }
        add(content)
    }.toString()

    /** SHA-256 of the canonical serialization: this is the value the signer signs. */
    public fun eventId(): ByteArray = CryptoUtils.sha256(canonicalSerialization().encodeToByteArray())

    /**
     * Sign this event with [nsec] (32-byte BIP-340 signing key), producing a
     * fully-serialised [SignedNostrEvent].
     *
     * [auxRand32] defaults to all zeros: deterministic signing, which is
     * what makes signatures reproducible against the spec test vectors. In
     * production, pass 32 random bytes for the standard BIP-340 nonce
     * rerandomization guarantees.
     *
     * Both [nsec] and [auxRand32] are read once by the BIP-340 signer and
     * not retained or mutated by this call; the caller may zero either
     * buffer after the call returns.
     *
     * For chain-derived keys, prefer [IdentityChain.signWith], which keeps
     * the signing key inside the chain object.
     */
    public fun sign(nsec: ByteArray, auxRand32: ByteArray = ByteArray(32)): SignedNostrEvent {
        require(nsec.size == 32) { "nsec must be 32 bytes, got ${nsec.size}" }
        require(auxRand32.size == 32) { "auxRand32 must be 32 bytes, got ${auxRand32.size}" }
        val id = eventId()
        val sig = CryptoUtils.signSchnorr(id, nsec, auxRand32)
        return SignedNostrEvent(
            id = Hex.encode(id),
            pubkey = pubkey,
            createdAt = createdAt,
            kind = kind,
            tags = tags,
            content = content,
            sig = Hex.encode(sig),
        )
    }
}

/**
 * A signed Nostr event in wire form.
 */
@Serializable
public data class SignedNostrEvent(
    public val id: String,
    @SerialName("pubkey") public val pubkey: String,
    @SerialName("created_at") public val createdAt: Long,
    public val kind: Int,
    public val tags: List<List<String>>,
    public val content: String,
    public val sig: String,
)
