"""Ed25519 signatures (RFC 8032), pure Python, used to check signed rules packs.

owltriage only *verifies* at runtime, so it needs no crypto library and installs everywhere.
`sign` exists for tools/rulepack.py, which signs packs on a throw-away CI runner; it is not
constant-time, so do not use it where an attacker can time it.

Follows the RFC 8032 section 6 reference code, with the checks verification must make:
a 32-byte public key that decodes to a curve point, a 64-byte signature whose R decodes and
whose S is below the group order L (otherwise a second, forged encoding would verify).
"""
from __future__ import annotations

import hashlib

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493   # order of the base point
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _sha512_int(data: bytes) -> int:
    return int.from_bytes(hashlib.sha512(data).digest(), "little")


# points in extended coordinates (X, Y, Z, T) with x = X/Z, y = Y/Z, x*y = T/Z
def _add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % P
    b = (p[1] + p[0]) * (q[1] + q[0]) % P
    c = 2 * p[3] * q[3] * D % P
    d = 2 * p[2] * q[2] % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return e * f % P, g * h % P, f * g % P, e * h % P


def _mul(scalar: int, point):
    result = (0, 1, 1, 0)                                    # neutral element
    while scalar > 0:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _equal(p, q) -> bool:
    return (p[0] * q[2] - q[0] * p[2]) % P == 0 and (p[1] * q[2] - q[1] * p[2]) % P == 0


def _recover_x(y: int, sign: int):
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P)
    if x2 % P == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


def _decompress(data: bytes):
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % P)


def _compress(point) -> bytes:
    z_inv = pow(point[2], P - 2, P)
    x, y = point[0] * z_inv % P, point[1] * z_inv % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


_GY = 4 * pow(5, P - 2, P) % P
_GX = _recover_x(_GY, 0)
G = (_GX, _GY, 1, _GX * _GY % P)


def _expand(seed: bytes):
    if len(seed) != 32:
        raise ValueError("an Ed25519 private key is 32 bytes")
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return scalar, digest[32:]


def public_key(seed: bytes) -> bytes:
    return _compress(_mul(_expand(seed)[0], G))


def sign(seed: bytes, message: bytes) -> bytes:
    scalar, prefix = _expand(seed)
    public = _compress(_mul(scalar, G))
    r = _sha512_int(prefix + message) % L
    encoded_r = _compress(_mul(r, G))
    h = _sha512_int(encoded_r + public + message) % L
    return encoded_r + ((r + h * scalar) % L).to_bytes(32, "little")


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """True only for a valid signature; malformed keys or signatures give False, never an exception."""
    if len(public) != 32 or len(signature) != 64:
        return False
    a = _decompress(public)
    r = _decompress(signature[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    h = _sha512_int(signature[:32] + public + message) % L
    return _equal(_mul(s, G), _add(r, _mul(h, a)))
