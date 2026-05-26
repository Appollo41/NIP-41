import csv
from pathlib import Path

from vendor.bip340_reference import schnorr_sign, schnorr_verify, pubkey_gen

VECTORS = Path(__file__).parent.parent / "vendor" / "bip340_test_vectors.csv"


def _rows():
    with open(VECTORS, newline="") as fh:
        yield from csv.DictReader(fh)


def test_bip340_official_vectors():
    checked = 0
    for row in _rows():
        seckey = bytes.fromhex(row["secret key"]) if row["secret key"] else None
        pubkey = bytes.fromhex(row["public key"])
        aux = bytes.fromhex(row["aux_rand"]) if row["aux_rand"] else None
        msg = bytes.fromhex(row["message"])
        sig = bytes.fromhex(row["signature"])
        expected = row["verification result"].strip().upper() == "TRUE"

        if seckey is not None:
            assert pubkey_gen(seckey) == pubkey, f"pubkey row {row['index']}"
            produced = schnorr_sign(msg, seckey, aux)
            assert produced == sig, f"sign row {row['index']}"

        assert schnorr_verify(msg, pubkey, sig) == expected, f"verify row {row['index']}"
        checked += 1
    assert checked >= 15
