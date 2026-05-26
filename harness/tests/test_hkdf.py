from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from nip41.hkdf import hkdf_sha256


def test_rfc5869_basic_vector():
    # RFC 5869 Appendix A.1
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    expected = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )
    assert hkdf_sha256(ikm, salt, info, 42) == expected


def test_matches_cryptography_library():
    ikm, salt, info = b"root-secret-bytes-32-long-padxxx", b"some-salt", b"info"
    ours = hkdf_sha256(ikm, salt, info, 32)
    theirs = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)
    assert ours == theirs


def test_rfc5869_vector_a2_long_inputs():
    # RFC 5869 Appendix A.2 — longer inputs, 82-byte output (multi-block expand)
    ikm = bytes(range(0x00, 0x50))
    salt = bytes(range(0x60, 0xB0))
    info = bytes(range(0xB0, 0x100))
    expected = bytes.fromhex(
        "b11e398dc80327a1c8e7f78c596a4934"
        "4f012eda2d4efad8a050cc4c19afa97c"
        "59045a99cac7827271cb41c65e590e09"
        "da3275600c2f09b8367793a9aca3db71"
        "cc30c58179ec3e87c14c01d5c1f3434f"
        "1d87"
    )
    assert hkdf_sha256(ikm, salt, info, 82) == expected


def test_rfc5869_vector_a3_empty_salt_and_info():
    # RFC 5869 Appendix A.3 — empty salt and empty info
    ikm = bytes.fromhex("0b" * 22)
    expected = bytes.fromhex(
        "8da4e775a563c18f715f802a063c5a31"
        "b8a11f5c5ee1879ec3454e5f3c738d2d"
        "9d201395faa4b61a96c8"
    )
    assert hkdf_sha256(ikm, b"", b"", 42) == expected
