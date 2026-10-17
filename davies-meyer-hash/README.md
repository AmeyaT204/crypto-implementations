# Davies-Meyer Hash

An arbitrary-length hash function built from a block cipher, in pure Python,
following the textbook constructions (Katz-Lindell, Ch. 6-7):

    f  block cipher            512-bit key, 256-bit block     (external module)
    h  compression function    h(z, M) = f_M(z) XOR z         (Davies-Meyer)
    H  hash function           chain h over blocks, then |x|  (Merkle-Damgard)

## Files

| File | Contents |
|---|---|
| `sha256_cipher.py` | **External module.** The block cipher `f(k, m)` used inside SHA-256 (SHACAL-2, per FIPS 180-4). Used as a black box. |
| `davies_meyer_hash.py` | The construction: `h` (Davies-Meyer), `pad` and `H` (Merkle-Damgard), conversions, and `main`. |
| `test_collisions.py` | Collision search on random inputs. |

## Construction

**Davies-Meyer.** The 512-bit message block M is the cipher's *key*, the
256-bit chaining value z is its *input*, and z is fed forward:

    h(z, M) = f_M(z) XOR z

The feed-forward makes h one-way even though f_M is invertible.

**Merkle-Damgard** (Katz-Lindell 3rd ed., Theorem 6.4):

1. Pad the message x with 0s to a multiple of 512 bits; split into x_1, ..., x_l.
2. z_0 = IV = 0^n, and z_i = h(z_{i-1}, x_i).
3. Output z_{l+1} = h(z_l, |x|), where |x| is the original length of x in bits.

If h is collision-resistant, so is H. The final |x| block is what makes this
work: messages that differ only in trailing zeros pad identically, but have
different lengths.

All chaining values z_0, ..., z_{l+1} are handled as 256-bit integers.

**NOTE:** the hash is unkeyed (no Gen), and since f has
a 512-bit key, h compresses 256 + 512 bits to 256 bits rather than 2n to n.
This does not affect the structure of the construction compared to the standard Davis Meyer.

**Relation to SHA-256:** it uses SHA-256's block cipher, but follows the
textbook construction (XOR feed-forward, zero padding, separate length block,
IV = 0), so outputs differ from SHA-256.

## Run

    python3 davies_meyer_hash.py

Example: `abc` -> `a8b49f51a60c656f795b92a80ad966bd867f27f91a1f2060cb1cd8724d9bfae6`

## Collision test

    python3 test_collisions.py 5000

Hashes 5000 distinct random inputs and counts colliding pairs, for the full
256-bit hash and for the hash truncated to 16, 20, 24 and 32 bits. Truncated
versions collide at roughly the birthday-bound rate n^2 / 2^(t+1); the full
hash shows no collisions.

For learning only: not constant-time, not for protecting real data.
