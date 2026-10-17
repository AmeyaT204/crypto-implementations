"""
Davies-Meyer hash: an arbitrary-length hash built from a block cipher.

    f  block cipher (external, sha256_cipher.py)   512-bit key, 256-bit block
    h  compression function (Davies-Meyer)         h(z, M) = f_M(z) XOR z
    H  hash function (Merkle-Damgard)              Katz-Lindell 3rd ed., Theorem 6.4

All chaining values z_0, z_1, ..., z_{l+1} are 256-bit integers.

Run:  python3 davies_meyer_hash.py
"""
from sha256_cipher import f

N = 256                    # output length n, in bits
BLOCK = 64                 # message block length, in bytes (512 bits = f's key size)
IV = 0x0000000000000000000000000000000000000000000000000000000000000000   # z_0 = 0^n


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------
def string_to_bytes(s):
    return s.encode("utf-8")


def bytes_to_hex(b):
    digits = "0123456789abcdef"
    return "".join(digits[byte >> 4] + digits[byte & 0xF] for byte in b)


def string_to_hex(s):
    return bytes_to_hex(string_to_bytes(s))


def int_to_hex(z):
    """256-bit integer -> 64 hex characters (leading zeros kept)."""
    return format(z, "064x")


# ---------------------------------------------------------------------------
# Compression function h: Davies-Meyer
#   z : 256-bit chaining value (integer) -> the INPUT of f
#   M : 64-byte (512-bit) block           -> the KEY of f
#   h(z, M) = f_M(z) XOR z                -> 256-bit integer
# ---------------------------------------------------------------------------
def h(z, M):
    assert 0 <= z < 2 ** N and len(M) == BLOCK
    encrypted = int.from_bytes(f(M, z.to_bytes(32, "big")), "big") # default f returns list of 32 bit integers
    return encrypted ^ z


# ---------------------------------------------------------------------------
# Merkle-Damgard
#   1. pad x with 0s to a multiple of the block length; split into x_1..x_l
#   2. z_0 = IV = 0^n,  z_i = h(z_{i-1}, x_i)
#   3. output z_{l+1} = h(z_l, |x|),  |x| = length of x in bits
# ---------------------------------------------------------------------------
def pad(msg):
    """Pad msg with 0s to a multiple of BLOCK bytes."""
    return msg + b"\x00" * ((-len(msg)) % BLOCK)


def H(msg):
    """Hash any byte string to a 256-bit integer."""
    L = 8 * len(msg)                          # |x|, before padding
    padded = pad(msg)
    z = IV                                    # z_0
    for i in range(0, len(padded), BLOCK):    # z_1 .. z_l
        z = h(z, padded[i:i + BLOCK])
    return h(z, L.to_bytes(BLOCK, "big"))     # z_{l+1}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    text = input("Enter a string: ")
    print("Input (hex):", string_to_hex(text))
    print("Hash  (hex):", int_to_hex(H(string_to_bytes(text))))


if __name__ == "__main__":
    main()
