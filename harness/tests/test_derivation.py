from vendor.bip340_reference import n, G, point_mul
from nip41.derivation import internal_scalar, internal_key, info_for

ROOT = bytes.fromhex("11" * 32)


def test_info_encoding_is_pinned():
    # u32be(i), no suffix on attempt 0, u8(k) suffix on retry k
    assert info_for(0, 0) == b"internal-key" + b"\x00\x00\x00\x00"
    assert info_for(5, 0) == b"internal-key" + b"\x00\x00\x00\x05"
    assert info_for(5, 1) == b"internal-key" + b"\x00\x00\x00\x05" + b"\x01"


def test_internal_scalar_is_deterministic_and_in_range():
    for i in (0, 1, 7, 63, 127):
        d = internal_scalar(ROOT, i)
        assert 0 < d < n
        assert internal_scalar(ROOT, i) == d  # deterministic


def test_generations_are_distinct():
    scalars = {internal_scalar(ROOT, i) for i in range(16)}
    assert len(scalars) == 16


def test_internal_key_point_matches_scalar():
    d, P = internal_key(ROOT, 3)
    assert P == point_mul(G, d)
