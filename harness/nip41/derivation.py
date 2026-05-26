"""The identity chain's per-generation internal keys."""

from vendor.bip340_reference import n, G, point_mul
from nip41.hkdf import hkdf_sha256

SALT = b"nip41-key-rotation-v1"
INFO_PREFIX = b"internal-key"


def info_for(i: int, attempt: int) -> bytes:
    """HKDF `info` for generation `i`. attempt 0 = no suffix; k>=1 appends u8(k)."""
    info = INFO_PREFIX + i.to_bytes(4, "big")
    if attempt > 0:
        info += bytes([attempt])
    return info


def internal_scalar(root_secret: bytes, i: int) -> int:
    """Internal private scalar for generation `i`, reduced into 1..n-1."""
    attempt = 0
    while True:
        okm = hkdf_sha256(root_secret, SALT, info_for(i, attempt), 32)
        d = int.from_bytes(okm, "big")
        if 0 < d < n:
            return d
        attempt += 1  # reject-and-rederive (probability ~2**-128)


def internal_key(root_secret: bytes, i: int):
    """Returns (scalar, point) for generation `i`."""
    d = internal_scalar(root_secret, i)
    return d, point_mul(G, d)
