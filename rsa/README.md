# RSA from scratch

Textbook RSA in pure Python, with key generation, prime generation and CRT
decryption written from scratch (no crypto libraries, no built-in `pow` for
the core math).

| File | Contents |
|---|---|
| `rsa_math.py` | extended Euclid, modular inverse, square-and-multiply, Miller-Rabin, random prime generation, key file helpers |
| `keygen.py` | generates (N, e) and (d, p, q, CRT values); saves `public_key.txt`, `private_key.txt` |
| `encrypt.py` | reads the public key, encrypts a string: c = m^e mod N on a given input m|
| `decrypt.py` | reads the private key, decrypts with the CRT: m = c^d mod N |

## Run

    python3 keygen.py          # 2048-bit key (or: python3 keygen.py 1024)
    python3 encrypt.py         # type a message; ciphertext saved to cipher.txt
    python3 decrypt.py         # paste ciphertext, or press Enter to read cipher.txt

## Key generation

1. Generate two random 1024-bit primes p != q (see below).
2. N = pq, phi = (p-1)(q-1), e = 65537; retry if gcd(e, phi) != 1.
3. d = e^-1 mod phi (extended Euclid).
4. CRT values: dp = d mod (p-1), dq = d mod (q-1), qinv = q^-1 mod p.

## Prime generation

1. Draw a random 1024-bit number; set its top two bits (so N has exactly
   2048 bits) and its lowest bit (so it is odd).
2. Discard it if divisible by any prime below 2000 (cheap filter).
3. Run Miller-Rabin with 40 random bases (error probability < 2^-80).
4. Repeat until a candidate passes. By the prime number theorem about
   1 in 355 odd 1024-bit numbers is prime.

## Decryption with the CRT

Instead of c^d mod N, compute m1 = c^dp mod p and m2 = c^dq mod q, then
combine: m = m2 + q * (qinv * (m1 - m2) mod p). Exponents and moduli are half
size, so this is roughly 3-4x faster.

## Security

This a Naive RSA encryption under the RSA assumption which only ensures COA security(an eavesdropper who sees
only c cannot recover a random m), but it is deterministic, so it is **not**
CPA-secure: equal messages give equal ciphertexts, and an attacker can test
guesses by encrypting them. Real systems add randomized padding (RSA-OAEP).
