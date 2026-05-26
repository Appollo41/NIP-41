"""Independent BIP-340 signature oracle backed by coincurve / libsecp256k1."""

from coincurve import PrivateKey, PublicKeyXOnly


def schnorr_sign(seckey_scalar: int, message32: bytes, aux_rand: bytes | None = None) -> bytes:
    """BIP-340 signature over a 32-byte message, via libsecp256k1.

    aux_rand: None -> coincurve auto-generates fresh randomness (default,
    recommended); pass b"\\x00" * 32 for a deterministic signature.
    """
    pk = PrivateKey(seckey_scalar.to_bytes(32, "big"))
    return pk.sign_schnorr(message32, aux_randomness=aux_rand or b"")


def schnorr_verify(xonly_pubkey: bytes, message32: bytes, signature: bytes) -> bool:
    """Verify a BIP-340 signature via libsecp256k1."""
    try:
        return PublicKeyXOnly(xonly_pubkey).verify(signature, message32)
    except Exception:
        return False
