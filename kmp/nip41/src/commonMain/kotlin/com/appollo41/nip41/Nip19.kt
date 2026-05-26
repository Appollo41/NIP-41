package com.appollo41.nip41

import fr.acinq.secp256k1.Hex

/**
 * NIP-19 bech32 encodings used by NIP-41:
 *  - `npub1…`: 32-byte BIP-340 x-only public key (NIP-19)
 *  - `nsec1…`: 32-byte BIP-340 signing key (NIP-19)
 *  - `nroot1…`: 32-byte NIP-41 root secret (spec "Portability
 *    (root-secret export)"). The root secret derives the entire identity
 *    chain, so it is the cross-client portable artifact a conformant
 *    implementation MUST support.
 *
 * Decoders verify both the HRP and the bech32 checksum.
 *
 * Public-identifier flavors (`npub`) accept and return lowercase 64-char hex
 * strings to match the rest of the library's public surface
 * ([IdentityChain.npub], [Kind1041Verification], etc.) and the Nostr wire
 * shape. Secret-bearing flavors (`nsec`, `nroot`) keep raw [ByteArray] for
 * zeroization.
 */
public object Nip19 {

    public const val HRP_NPUB: String = "npub"
    public const val HRP_NSEC: String = "nsec"
    public const val HRP_NROOT: String = "nroot"

    /** Encode a 32-byte x-only pubkey (as raw bytes) to `npub1…`. */
    public fun encodeNpub(xonlyPubkey: ByteArray): String {
        require(xonlyPubkey.size == 32) { "npub payload must be 32 bytes, got ${xonlyPubkey.size}" }
        return Bech32.encodeBytes(HRP_NPUB, xonlyPubkey, Bech32.Encoding.Bech32)
    }

    /**
     * Encode a 32-byte x-only pubkey (as lowercase 64-char hex, the form
     * carried by [IdentityChain.npub], [SignedNostrEvent.pubkey], and the
     * verification outcomes) to `npub1…`.
     */
    public fun encodeNpub(xonlyPubkeyHex: String): String {
        requireHex32("xonlyPubkeyHex", xonlyPubkeyHex)
        return Bech32.encodeBytes(HRP_NPUB, Hex.decode(xonlyPubkeyHex), Bech32.Encoding.Bech32)
    }

    /**
     * Encode a 32-byte BIP-340 signing key as `nsec1…`.
     *
     * [privateKey] is read once and not retained or mutated; the caller may
     * zero its buffer after this call returns.
     */
    public fun encodeNsec(privateKey: ByteArray): String {
        require(privateKey.size == 32) { "nsec payload must be 32 bytes, got ${privateKey.size}" }
        return Bech32.encodeBytes(HRP_NSEC, privateKey, Bech32.Encoding.Bech32)
    }

    /**
     * Encode a 32-byte NIP-41 root secret as `nroot1…`.
     *
     * [rootSecret] is read once and not retained or mutated; the caller may
     * zero its buffer after this call returns.
     */
    public fun encodeNroot(rootSecret: ByteArray): String {
        require(rootSecret.size == 32) { "nroot payload must be 32 bytes, got ${rootSecret.size}" }
        return Bech32.encodeBytes(HRP_NROOT, rootSecret, Bech32.Encoding.Bech32)
    }

    /**
     * Decode an `npub1…` string and return the x-only pubkey as lowercase
     * 64-char hex, matching the form callers will compare against
     * ([IdentityChain.npub], [SignedNostrEvent.pubkey], verification outcomes).
     */
    public fun decodeNpub(npub1: String): String = Hex.encode(decode(HRP_NPUB, npub1))

    /**
     * Decode an `nsec1…` string and return the raw 32-byte signing key.
     *
     * Returns a fresh buffer the caller owns and is responsible for zeroing
     * when no longer needed. The library retains no reference to it.
     */
    public fun decodeNsec(nsec1: String): ByteArray = decode(HRP_NSEC, nsec1)

    /**
     * Decode an `nroot1…` string and return the raw 32-byte NIP-41 root secret.
     *
     * Returns a fresh buffer the caller owns and is responsible for zeroing
     * when no longer needed. The library retains no reference to it.
     */
    public fun decodeNroot(nroot1: String): ByteArray = decode(HRP_NROOT, nroot1)

    /**
     * Decode a 32-byte payload bech32 entity, verifying both the HRP and the
     * payload length. Anything else throws [IllegalArgumentException],
     * matching the existing `require(…)` contract of the encoders above and
     * keeping the failure mode a single, predictable type.
     */
    private fun decode(expectedHrp: String, s: String): ByteArray {
        val (hrp, bytes, _) = Bech32.decodeBytes(s)
        require(hrp == expectedHrp) { "expected '${expectedHrp}1…' prefix, got '${hrp}1…'" }
        require(bytes.size == 32) { "expected 32-byte payload, got ${bytes.size}" }
        return bytes
    }
}
