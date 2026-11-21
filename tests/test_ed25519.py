"""The rules-pack signature check: Ed25519 (RFC 8032) in pure Python, so owltriage needs no crypto library."""
import time

import pytest
from hypothesis import given, settings, strategies as st

from owltriage import ed25519

# RFC 8032, section 7.1, tests 1 and 2
RFC_VECTORS = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
]


@pytest.mark.parametrize("seed, public, message, signature", RFC_VECTORS)
def test_rfc8032_vectors(seed, public, message, signature):
    seed, public, message, signature = (bytes.fromhex(x) for x in (seed, public, message, signature))
    assert ed25519.public_key(seed) == public
    assert ed25519.sign(seed, message) == signature
    assert ed25519.verify(public, message, signature)


def test_any_change_breaks_the_signature():
    seed, public, _, _ = (bytes.fromhex(x) for x in RFC_VECTORS[1])
    message = b"rules pack payload"
    signature = ed25519.sign(seed, message)
    assert ed25519.verify(public, message, signature)
    assert not ed25519.verify(public, message + b" ", signature)
    for i in (0, 31, 32, 63):                                   # R and S halves
        broken = bytearray(signature)
        broken[i] ^= 0x01
        assert not ed25519.verify(public, message, bytes(broken))
    other = ed25519.public_key(bytes(32))
    assert not ed25519.verify(other, message, signature)


def test_malformed_input_is_rejected_without_raising():
    seed, public, _, _ = (bytes.fromhex(x) for x in RFC_VECTORS[0])
    signature = ed25519.sign(seed, b"x")
    assert not ed25519.verify(public[:31], b"x", signature)
    assert not ed25519.verify(public, b"x", signature[:63])
    assert not ed25519.verify(b"\xff" * 32, b"x", signature)   # not a point on the curve
    # S must be below the group order: S + L is the same point but a different (forged) encoding
    s = int.from_bytes(signature[32:], "little") + ed25519.L
    assert s < 2 ** 256
    assert not ed25519.verify(public, b"x", signature[:32] + s.to_bytes(32, "little"))
    with pytest.raises(ValueError):
        ed25519.public_key(b"short")


def test_verifying_is_fast_enough_to_do_on_every_run():
    seed, public, _, _ = (bytes.fromhex(x) for x in RFC_VECTORS[0])
    message = b"p" * 200_000
    signature = ed25519.sign(seed, message)
    start = time.perf_counter()
    assert ed25519.verify(public, message, signature)
    assert time.perf_counter() - start < 1.0


cryptography = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")


@settings(max_examples=40, deadline=None)
@given(seed=st.binary(min_size=32, max_size=32), message=st.binary(max_size=300))
def test_matches_the_cryptography_library(seed, message):
    theirs = cryptography.Ed25519PrivateKey.from_private_bytes(seed)
    signature = theirs.sign(message)
    assert ed25519.sign(seed, message) == signature             # Ed25519 signatures are deterministic
    assert ed25519.verify(ed25519.public_key(seed), message, signature)
    flipped = bytes([signature[0] ^ 0x80]) + signature[1:]
    assert not ed25519.verify(ed25519.public_key(seed), message, flipped)
