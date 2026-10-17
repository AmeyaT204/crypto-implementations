"""
External module: the SHA-256 block cipher (SHACAL-2), per FIPS 180-4.

Treated as a black box by this project. Provides:

    f(k, m)   block cipher: 64-byte key k, 32-byte input m -> 32 bytes
"""
# ---------------------------------------------------------------------------
# 32-bit word utilities
# ---------------------------------------------------------------------------
MASK = 0xFFFFFFFF


def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & MASK


def add(*xs):
    return sum(xs) & MASK


def bytes_to_words(b):
    return [int.from_bytes(b[i:i + 4], "big") for i in range(0, len(b), 4)]


def words_to_bytes(ws):
    return b"".join(w.to_bytes(4, "big") for w in ws)


# ---------------------------------------------------------------------------
# Round constants K: cube roots of the first 64 primes
# ---------------------------------------------------------------------------
def _first_primes(n):
    primes, c = [], 2
    while len(primes) < n:
        if all(c % p for p in primes if p * p <= c):
            primes.append(c)
        c += 1
    return primes


def _icbrt(n):
    x = 1 << ((n.bit_length() + 2) // 3)
    while True:
        y = (2 * x + n // (x * x)) // 3
        if y >= x:
            break
        x = y
    while x ** 3 > n:
        x -= 1
    while (x + 1) ** 3 <= n:
        x += 1
    return x


_PRIMES = _first_primes(64)
K = [_icbrt(p << 96) & MASK for p in _PRIMES]


# ---------------------------------------------------------------------------
# Block cipher f
# ---------------------------------------------------------------------------
def _Ch(x, y, z):  return (x & y) ^ ((~x & MASK) & z)
def _Maj(x, y, z): return (x & y) ^ (x & z) ^ (y & z)
def _Sig0(x):      return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
def _Sig1(x):      return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
def _sig0(x):      return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
def _sig1(x):      return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)


def _key_schedule(k):
    W = bytes_to_words(k)
    for t in range(16, 64):
        W.append(add(_sig1(W[t - 2]), W[t - 7], _sig0(W[t - 15]), W[t - 16]))
    return W


def f(k, m):
    """Encrypt the 32-byte block m under the 64-byte key k."""
    assert len(k) == 64 and len(m) == 32
    W = _key_schedule(k)
    a, b, c, d, e, f_, g, h = bytes_to_words(m)
    for t in range(64):
        T1 = add(h, _Sig1(e), _Ch(e, f_, g), K[t], W[t])
        T2 = add(_Sig0(a), _Maj(a, b, c))
        a, b, c, d, e, f_, g, h = add(T1, T2), a, b, c, add(d, T1), e, f_, g
    return words_to_bytes([a, b, c, d, e, f_, g, h])
