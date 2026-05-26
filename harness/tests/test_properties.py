from hypothesis import given, settings, strategies as st

from vendor.bip340_reference import has_even_y, bytes_from_point, G, n, point_mul
from nip41.chain import build_chain, tweak_scalar
from nip41.signing import signing_key
from nip41.verify import verify_chain_rotation, resolve
from oracles.coincurve_oracle import schnorr_sign, schnorr_verify

root_secrets = st.binary(min_size=32, max_size=32)
chain_lengths = st.integers(min_value=2, max_value=24)


@settings(max_examples=300, deadline=None)
@given(root=root_secrets, N=chain_lengths)
def test_every_generation_signs_and_verifies(root, N):
    chain = build_chain(root, N)
    msg = bytes.fromhex("3c" * 32)
    for i in range(N):
        sk = signing_key(chain, i)
        sig = schnorr_sign(sk, msg)
        assert schnorr_verify(chain.npub[i], msg, sig)


@settings(max_examples=300, deadline=None)
@given(root=root_secrets, N=chain_lengths)
def test_full_chain_resolves_from_generation_zero(root, N):
    chain = build_chain(root, N)
    rotations = {
        chain.npub[i]: (chain.npub[i + 1], bytes_from_point(chain.P_internal[i]))
        for i in range(N - 1)
    }
    assert resolve(chain.npub[0], rotations) == chain.npub[N - 1]


@settings(max_examples=300, deadline=None)
@given(root=root_secrets, N=chain_lengths)
def test_every_honest_rotation_verifies(root, N):
    chain = build_chain(root, N)
    for i in range(N - 1):
        proof = bytes_from_point(chain.P_internal[i])
        assert verify_chain_rotation(chain.npub[i], chain.npub[i + 1], proof)


def test_odd_y_parity_case_is_exercised():
    """Prove the fuzzing actually hits the risky odd-y internal-key case,
    rather than only ever testing even-y points. Also proves the Q-parity
    branch in the signing path is exercised for non-terminal generations."""
    odd = even = 0
    q_odd = q_even = 0
    for b in range(60):
        chain = build_chain(bytes([b]) * 32, N=16)
        N = len(chain.npub)
        for i, P in enumerate(chain.P_internal):
            if has_even_y(P):
                even += 1
            else:
                odd += 1
            # Count Q parity for non-terminal generations
            if i < N - 1:
                d_internal = chain.p_internal[i]
                d_even = d_internal if has_even_y(P) else n - d_internal
                t = tweak_scalar(P, chain.npub[i + 1])
                Q = point_mul(G, (d_even + t) % n)
                if has_even_y(Q):
                    q_even += 1
                else:
                    q_odd += 1
    assert odd > 0 and even > 0, f"P parity not exercised: odd={odd} even={even}"
    assert q_odd > 0 and q_even > 0, f"Q parity not exercised: q_odd={q_odd} q_even={q_even}"
