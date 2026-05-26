from vendor.bip340_reference import lift_x, bytes_from_point
from nip41.chain import tweak_scalar, build_chain

ROOT = bytes.fromhex("22" * 32)


def test_terminal_generation_commits_to_nothing():
    N = 8
    chain = build_chain(ROOT, N=N)
    # terminal npub is the plain x-only of its internal key
    assert chain.npub[N - 1] == bytes_from_point(chain.P_internal[N - 1])


def test_every_npub_is_a_valid_xonly_point():
    chain = build_chain(ROOT, N=16)
    for pub in chain.npub:
        assert len(pub) == 32
        assert lift_x(int.from_bytes(pub, "big")) is not None


def test_chain_is_deterministic():
    a = build_chain(ROOT, N=8)
    b = build_chain(ROOT, N=8)
    assert a.npub == b.npub


def test_tweak_scalar_is_below_curve_order():
    from vendor.bip340_reference import n
    N = 8
    chain = build_chain(ROOT, N=N)
    for i in range(N - 1):
        t = tweak_scalar(chain.P_internal[i], chain.npub[i + 1])
        assert 0 <= t < n  # t == 0 is theoretically degenerate but negligible-probability (~2^-256), so lower bound is intentionally non-strict


def test_minimal_chain_of_two():
    chain = build_chain(ROOT, N=2)
    assert len(chain.npub) == 2
    assert chain.npub[0] != chain.npub[1]
