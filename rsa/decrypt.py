"""Decrypt a ciphertext with the private key, using the CRT speedup."""
from rsa_math import load_key, modexp


def decrypt(c, sk):
    """m = c^d mod N, computed mod p and mod q separately, then combined (CRT)."""
    p, q = sk["p"], sk["q"]
    m1 = modexp(c, sk["dp"], p)                  # c^d mod p
    m2 = modexp(c, sk["dq"], q)                  # c^d mod q
    h = sk["qinv"] * (m1 - m2) % p
    return m2 + h * q                            # unique m mod N with both residues


def decrypt_plain(c, sk):
    """m = c^d mod N directly (slower; for comparison)."""
    return modexp(c, sk["d"], sk["N"])


def main():
    sk = load_key("private_key.txt")
    text = input("Ciphertext (hex, blank = read cipher.txt): ").strip()
    if not text:
        text = open("cipher.txt").read().strip()
    m = decrypt(int(text, 16), sk)
    data = m.to_bytes((m.bit_length() + 7) // 8, "big")
    print("Message:", data.decode("utf-8"))


if __name__ == "__main__":
    main()
