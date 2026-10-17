"""Generate an RSA key pair: public_key.txt (N, e) and private_key.txt."""
import sys
import time

from rsa_math import egcd, modinv, random_prime, save_key

E = 65537


def keygen(bits=2048):
    half = bits // 2
    while True:
        p, tried_p = random_prime(half)
        q, tried_q = random_prime(half)
        phi = (p - 1) * (q - 1)
        if p != q and egcd(E, phi)[0] == 1:          # e must be invertible mod phi
            break
    N = p * q
    d = modinv(E, phi) 
    dp, dq, qinv = d % (p - 1), d % (q - 1), modinv(q, p) # CRT values for fast decryption
    return dict(N=N, e=E, d=d, p=p, q=q, dp=dp, dq=dq, qinv=qinv), (tried_p, tried_q)


def main():
    bits = int(sys.argv[1]) if len(sys.argv) > 1 else 2048
    start = time.time()
    key, (tp, tq) = keygen(bits)
    elapsed = time.time() - start # time taken fir generation

    save_key("public_key.txt", N=key["N"], e=key["e"])
    save_key("private_key.txt", **key) 

    print(f"Generated {key['N'].bit_length()}-bit RSA key in {elapsed:.2f} s")
    print(f"Candidates tried: p {tp}, q {tq}")
    print("Saved public_key.txt (N, e) and private_key.txt (N, e, d, p, q, CRT values)")


if __name__ == "__main__":
    main()
