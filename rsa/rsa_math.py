"""Number theory for RSA: gcd, inverses, exponentiation, prime generation."""
import secrets

# ---------------------------------------------------------------------------
# Basic modular arithmetic
# ---------------------------------------------------------------------------
def egcd(a, b):
    """Extended Euclid: returns (g, x, y) with a*x + b*y = g = gcd(a, b)."""
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def modinv(a, n):
    """Inverse of a mod n."""
    g, x, _ = egcd(a, n)
    if g != 1:
        raise ValueError("not invertible")
    return x % n


def modexp(base, exp, n):
    """Square-and-multiply: base^exp mod n."""
    result, base = 1, base % n
    while exp > 0:
        if exp & 1:                    # current bit is 1 -> multiply
            result = result * base % n
        base = base * base % n         # square for the next bit
        exp >>= 1
    return result


# ---------------------------------------------------------------------------
# Prime generation
# ---------------------------------------------------------------------------
def _small_primes(limit):
    """All primes below limit (sieve of Eratosthenes)."""
    sieve = [True] * limit
    sieve[0] = sieve[1] = False
    for i in range(2, int(limit ** 0.5) + 1):
        if sieve[i]:
            sieve[i * i::i] = [False] * len(sieve[i * i::i])
    return [i for i, is_p in enumerate(sieve) if is_p]


SMALL_PRIMES = _small_primes(2000)


def miller_rabin(n, rounds=40):
    """True if n is probably prime (error < 4^-rounds), False if composite."""
    if n < 2:
        return False
    for p in SMALL_PRIMES[:10]: # checking divisibility against small primes explicitly
        if n % p == 0:
            return n == p
    # write n - 1 = 2^s * d with d odd
    s, d = 0, n - 1
    while d % 2 == 0:
        s, d = s + 1, d // 2
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2          # random base in [2, n-2]
        x = modexp(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1: # residue is +/- mod n here
                break
        else:
            return False                           # a is a witness: composite
    return True


def random_prime(bits):
    """Random prime of exactly `bits` bits. Returns (prime, candidates_tried)."""
    tried = 0
    while True:
        tried += 1
        n = secrets.randbits(bits)
        n |= (1 << (bits - 1)) | (1 << (bits - 2))   # forcing first two bits to be 
        n |= 1                                        # making n odd
        if any(n % p == 0 for p in SMALL_PRIMES):     # cheap filter first
            continue
        if miller_rabin(n):
            return n, tried


# ---------------------------------------------------------------------------
# Key file helpers (simple "name=hex" lines)
# ---------------------------------------------------------------------------
def save_key(path, **values):
    with open(path, "w") as fh:
        for name, v in values.items():
            fh.write(f"{name}={v:x}\n")


def load_key(path):
    with open(path) as fh:
        return {name: int(v, 16) for name, v in (line.strip().split("=") for line in fh if line.strip())}
