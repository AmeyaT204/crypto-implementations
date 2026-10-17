"""Encrypt a string with the public key: c = m^e mod N (textbook RSA)."""
from rsa_math import load_key, modexp


def encrypt(message, N, e):
    data = message.encode("utf-8") # turning string to bytes
    k = (N.bit_length() + 7) // 8 # hec=x of message must be less than 2^N
    if len(data) > k - 1:
        raise ValueError(f"message too long: at most {k - 1} bytes for this key")
    m = int.from_bytes(data, "big")              # converting m to integer
    return modexp(m, e, N)


def main():
    pk = load_key("public_key.txt")
    c = encrypt(input("Message: "), pk["N"], pk["e"])
    with open("cipher.txt", "w") as fh:
        fh.write(f"{c:x}\n")
    print("Ciphertext (hex):", f"{c:x}")
    print("Saved to cipher.txt")


if __name__ == "__main__":
    main()
