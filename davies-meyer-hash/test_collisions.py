"""
Collision test: hash many random inputs and look for two with the same hash.

For the full 256-bit hash, no collision should ever appear. To make the
birthday bound visible, the test also repeats the search on the hash
truncated to its first t bits, where collisions are expected after about
2^(t/2) inputs.

Run:  python3 test_collisions.py [number_of_inputs]   (default 5000)
"""
import os
import sys
from itertools import combinations

from davies_meyer_hash import H, int_to_hex


def find_collisions(hashes, bits):
    """Group inputs by their first `bits` bits of hash; return colliding groups."""
    buckets = {}
    for msg, digest in hashes:
        key = digest >> (256 - bits)
        buckets.setdefault(key, []).append(msg)
    return [group for group in buckets.values() if len(group) > 1]


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 5000

    inputs = set()
    while len(inputs) < n:                  # n distinct random inputs
        inputs.add(os.urandom(os.urandom(1)[0] % 100 + 1))

    print(f"Hashing {n} distinct random inputs...")
    hashes = [(msg, H(msg)) for msg in inputs]

    print(f"\n{'bits':>5} {'collisions found':>17} {'expected':>10}")
    for bits in (16, 20, 24, 32, 256):
        groups = find_collisions(hashes, bits)
        pairs = sum(len(g) * (len(g) - 1) // 2 for g in groups)
        expected = n * (n - 1) / 2 / 2 ** bits
        print(f"{bits:>5} {pairs:>17} {expected:>10.3g}")
        if bits == 256:
            full_groups = groups

    print()
    if full_groups:
        print("Full 256-bit collision FOUND (this should never happen):")
        for g in full_groups:
            for m1, m2 in combinations(g, 2):
                print(" ", m1.hex(), "\n ", m2.hex(), "->", int_to_hex(H(m1)))
    else:
        print("No collision found in the full 256-bit hash.")


if __name__ == "__main__":
    main()
