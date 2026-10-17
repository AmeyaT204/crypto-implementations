"""
End-to-end test of the RSA scheme: keygen -> encrypt -> decrypt.

Run:  python3 test_rsa.py      (or: pytest test_rsa.py)
"""
import secrets

from decrypt import decrypt, decrypt_plain
from encrypt import encrypt
from keygen import keygen


def to_text(m):
    return m.to_bytes((m.bit_length() + 7) // 8, "big").decode("utf-8")


def random_text(max_bytes):
    """Random printable ASCII message of random length."""
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,!?"
    return "".join(secrets.choice(alphabet) for _ in range(secrets.randbelow(max_bytes) + 1))


def test_rsa_scheme():
    key, _ = keygen(2048)
    N, e = key["N"], key["e"]
    max_bytes = (N.bit_length() + 7) // 8 - 1

    messages = ["hello", "", "नमस्ते RSA 🔐", "x" * max_bytes]
    messages += [random_text(max_bytes) for _ in range(50)]

    for msg in messages:
        c = encrypt(msg, N, e)
        m = decrypt(c, key)
        assert m == decrypt_plain(c, key), "CRT and plain decryption disagree"
        assert to_text(m) == msg, f"round trip failed for {msg!r}"

    # too-long message must be rejected
    try:
        encrypt("x" * (max_bytes + 1), N, e)
        raise AssertionError("over-long message was not rejected")
    except ValueError:
        pass

    # a different key must not decrypt it
    other, _ = keygen(2048)
    c = encrypt("secret", N, e)
    try:
        assert to_text(decrypt(c % other["N"], other)) != "secret"
    except UnicodeDecodeError:
        pass                                     # garbage bytes: also a pass

    print(f"passed: RSA scheme ({len(messages)} messages, 1 wrong-key check)")


if __name__ == "__main__":
    test_rsa_scheme()
    print("All end-to-end tests passed.")
