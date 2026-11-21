"""
rsa.py - RSA key generation (SageMath) and RSA-OAEP / hybrid encryption.

Mathematical background (see README for the full treatment)
-----------------------------------------------------------
    n   = p * q                     (p, q large random primes)
    phi = (p - 1)(q - 1)            (Euler's totient of n)
    e   = 65537                     (public exponent, gcd(e, phi) = 1)
    d   = e^(-1) mod phi            (private exponent)

    encrypt:  c = m^e mod n
    decrypt:  m = c^d mod n         (computed faster with the CRT, see below)

Correctness: e*d = 1 + k*phi, and by Euler's theorem m^(e*d) = m (mod n).

Textbook RSA is deterministic and malleable, so it is NEVER used to encrypt
user data here.  Messages are first padded with RSA-OAEP (RFC 8017, SHA-256,
MGF1-SHA-256), which adds randomness and integrity-style redundancy.

Two backends implement the RSA *primitive*; everything else is shared:

  "openssl"  the `cryptography` library (OpenSSL).  Production-grade,
             constant-time-hardened.  Used for the main benchmark.
  "sage"     our own OAEP encoder + SageMath modular arithmetic (GMP).
             Educational; shows the maths; NOT side-channel hardened.

Key generation is always done with SageMath's number theory (own prime search
fed by the OS CSPRNG); the resulting key is then loaded into `cryptography`
which independently re-validates it (p*q = n, d*e = 1 mod p-1 / q-1, ...).
"""

import hashlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from sage.all import Integer, gcd, inverse_mod, prime_range, product

from common import (
    AES_KEY_LEN, NONCE_LEN, TAG_LEN, DecryptionError,
    aead_decrypt, aead_encrypt, csprng_bytes, csprng_randbelow,
)

PUBLIC_EXPONENT = 65537
MIN_RSA_BITS = 2048          # smaller moduli are not considered secure
HASH_LEN = 32                # SHA-256 output length
HYBRID_PROTOCOL_ID = b"RSA-ECC-Comparison/RSA-OAEP-AES256GCM/v1"

# Product of all primes < 2^15: one gcd() removes candidates with a small
# factor far faster than running a modular exponentiation on each of them.
_SMALL_PRIMES_PRODUCT = Integer(product(prime_range(3, 2 ** 15)))

OAEP_PADDING = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


# ==========================================================================
# 1.  Prime generation and key generation (SageMath)
# ==========================================================================


def _miller_rabin_round(n: Integer, a: Integer) -> bool:
    """One Miller-Rabin round: True if n passes for base a ("probably prime")."""
    s = (n - 1).valuation(2)
    d = (n - 1) >> s
    x = a.powermod(d, n)
    if x == 1 or x == n - 1:
        return True
    for _ in range(s - 1):
        x = (x * x) % n
        if x == n - 1:
            return True
    return False


def is_probable_prime(c: Integer, mr_rounds: int = 8) -> bool:
    """Cheap filters first, then BPSW, then Miller-Rabin with random bases."""
    if gcd(c, _SMALL_PRIMES_PRODUCT) != 1:           # small-factor sieve
        return False
    if Integer(2).powermod(c - 1, c) != 1:           # Fermat base 2 (fast reject)
        return False
    if not c.is_pseudoprime():                       # Baillie-PSW
        return False
    for _ in range(mr_rounds):                       # random-base Miller-Rabin
        a = Integer(2 + csprng_randbelow(int(c) - 3))
        if not _miller_rabin_round(c, a):
            return False
    return True


def generate_prime(bits: int, e: int = PUBLIC_EXPONENT) -> Integer:
    """Random `bits`-bit prime p with gcd(p - 1, e) = 1, from the OS CSPRNG.

    The two top bits are forced to 1 so that the product of two such primes
    has exactly 2*bits bits; the bottom bit is forced to 1 (odd).
    Sage's own random_prime() is a simulation PRNG and is deliberately NOT used.
    """
    while True:
        c = Integer(csprng_randbelow(1 << bits)) | (Integer(3) << (bits - 2)) | 1
        if gcd(c - 1, e) != 1:                       # need e invertible mod p-1
            continue
        if is_probable_prime(c):
            return c


class RSAKeyPair:
    """RSA key pair holding both the Sage integers and `cryptography` objects.

    Secrets (d, p, q) are never included in repr()/str().
    """

    def __init__(self, p, q, e: int = PUBLIC_EXPONENT):
        p, q = Integer(p), Integer(q)
        if p < q:
            p, q = q, p
        self.p, self.q, self.e = p, q, Integer(e)
        self.n = p * q                                   # modulus
        self.phi = (p - 1) * (q - 1)                     # Euler totient
        self.d = inverse_mod(self.e, self.phi)           # d = e^-1 mod phi
        self.bits = int(self.n.nbits())
        # CRT parameters (Garner): speed up decryption ~4x.
        self.dp = self.d % (p - 1)
        self.dq = self.d % (q - 1)
        self.qinv = inverse_mod(q, p)

        pub = rsa.RSAPublicNumbers(int(self.e), int(self.n))
        priv = rsa.RSAPrivateNumbers(
            int(p), int(q), int(self.d), int(self.dp), int(self.dq), int(self.qinv), pub
        )
        # private_key() runs OpenSSL's key validation (p*q == n, d*e == 1 ...).
        self.private_key = priv.private_key()
        self.public_key = self.private_key.public_key()

    @classmethod
    def from_cryptography(cls, private_key: rsa.RSAPrivateKey) -> "RSAKeyPair":
        nums = private_key.private_numbers()
        return cls(nums.p, nums.q, nums.public_numbers.e)

    def __repr__(self):
        return f"RSAKeyPair(bits={self.bits}, e={self.e}, <private parameters hidden>)"

    # ---- serialization ---------------------------------------------------
    def public_der(self) -> bytes:
        """X.509 SubjectPublicKeyInfo DER (what is normally transmitted)."""
        return self.public_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    def public_pem(self) -> bytes:
        return self.public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    def public_pkcs1_der(self) -> bytes:
        """Bare PKCS#1 RSAPublicKey {n, e} DER (without the algorithm header)."""
        return self.public_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.PKCS1)

    def private_der(self) -> bytes:
        """Unencrypted PKCS#8 DER.  Contains n, e, d, p, q, dp, dq, qinv."""
        return self.private_key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())

    def private_pem(self) -> bytes:
        return self.private_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())


def generate_rsa_keypair(bits: int = 3072, backend: str = "sage") -> RSAKeyPair:
    """Generate an RSA key pair.

    backend="sage"    : primes found with the Sage-based search above.
    backend="openssl" : OpenSSL's generator (used where Sage's pure search
                        would take minutes, e.g. RSA-15360, and for comparison).
    """
    if bits < MIN_RSA_BITS or bits % 2:
        raise ValueError(f"RSA modulus must be an even number >= {MIN_RSA_BITS} bits")
    if backend == "openssl":
        return RSAKeyPair.from_cryptography(
            rsa.generate_private_key(PUBLIC_EXPONENT, bits))
    if backend != "sage":
        raise ValueError("backend must be 'sage' or 'openssl'")
    while True:
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        # p and q must differ, and not be close (Fermat factoring): |p-q| > 2^(bits/2 - 100)
        if abs(p - q) > (Integer(1) << (bits // 2 - 100)):
            return RSAKeyPair(p, q)


# ==========================================================================
# 2.  RSA-OAEP
# ==========================================================================


def oaep_max_plaintext(bits_or_n) -> int:
    """Largest message RSA-OAEP(SHA-256) can encrypt: k - 2*hLen - 2 bytes."""
    bits = bits_or_n if isinstance(bits_or_n, int) else int(Integer(bits_or_n).nbits())
    k = (bits + 7) // 8
    return k - 2 * HASH_LEN - 2


def _mgf1(seed: bytes, length: int) -> bytes:
    out = b"".join(
        hashlib.sha256(seed + i.to_bytes(4, "big")).digest()
        for i in range((length + HASH_LEN - 1) // HASH_LEN))
    return out[:length]


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def oaep_encode(msg: bytes, k: int, label: bytes = b"") -> bytes:
    """RFC 8017 sec. 7.1.1 EME-OAEP encoding (SHA-256, MGF1-SHA-256).

        DB   = lHash || 00..00 || 01 || M
        seed = random hLen bytes                      <- the randomization
        EM   = 00 || (seed XOR MGF(maskedDB)) || (DB XOR MGF(seed))
    """
    if len(msg) > k - 2 * HASH_LEN - 2:
        raise ValueError("message too long for RSA-OAEP with this key size")
    lhash = hashlib.sha256(label).digest()
    db = lhash + b"\x00" * (k - len(msg) - 2 * HASH_LEN - 2) + b"\x01" + msg
    seed = csprng_bytes(HASH_LEN)
    masked_db = _xor(db, _mgf1(seed, k - HASH_LEN - 1))
    masked_seed = _xor(seed, _mgf1(masked_db, HASH_LEN))
    return b"\x00" + masked_seed + masked_db


def oaep_decode(em: bytes, k: int, label: bytes = b"") -> bytes:
    """EME-OAEP decoding.  Every failure raises the same DecryptionError.

    All checks are folded into one boolean before branching so that failures
    are not distinguishable through the error type (Manger's attack).  Python
    cannot give true constant-time guarantees - another reason the "sage"
    backend is educational only.
    """
    lhash = hashlib.sha256(label).digest()
    y, masked_seed, masked_db = em[0], em[1:1 + HASH_LEN], em[1 + HASH_LEN:]
    seed = _xor(masked_seed, _mgf1(masked_db, HASH_LEN))
    db = _xor(masked_db, _mgf1(seed, k - HASH_LEN - 1))
    ok = (y == 0) & (db[:HASH_LEN] == lhash)
    rest = db[HASH_LEN:]
    idx = rest.find(b"\x01")
    ok &= idx >= 0 and rest[:idx].count(b"\x00") == idx
    if not ok:
        raise DecryptionError("decryption failed")
    return rest[idx + 1:]


def _check_public(pub):
    if not isinstance(pub, (rsa.RSAPublicKey, RSAKeyPair)):
        raise TypeError("expected an RSA public key")
    return pub.public_key if isinstance(pub, RSAKeyPair) else pub


def rsa_oaep_encrypt(pub, msg: bytes, backend: str = "openssl") -> bytes:
    """RSA-OAEP(SHA-256) encrypt `msg` (at most oaep_max_plaintext bytes)."""
    pubkey = _check_public(pub)
    nums = pubkey.public_numbers()
    n_bits = pubkey.key_size
    if len(msg) > oaep_max_plaintext(n_bits):
        raise ValueError(
            f"message of {len(msg)} bytes exceeds the RSA-OAEP limit of "
            f"{oaep_max_plaintext(n_bits)} bytes for RSA-{n_bits}; use hybrid encryption")
    if backend == "openssl":
        return pubkey.encrypt(msg, OAEP_PADDING)
    if backend == "sage":
        k = (n_bits + 7) // 8
        m = Integer(int.from_bytes(oaep_encode(msg, k), "big"))
        c = m.powermod(nums.e, Integer(nums.n))               # c = m^e mod n
        return int(c).to_bytes(k, "big")
    raise ValueError("unknown backend")


def rsa_oaep_decrypt(key: RSAKeyPair, ct: bytes, backend: str = "openssl") -> bytes:
    """RSA-OAEP(SHA-256) decrypt.  Raises DecryptionError on any failure."""
    k = (key.bits + 7) // 8
    if len(ct) != k:
        raise DecryptionError("decryption failed")
    if backend == "openssl":
        try:
            return key.private_key.decrypt(ct, OAEP_PADDING)
        except ValueError:
            raise DecryptionError("decryption failed") from None
    if backend == "sage":
        c = Integer(int.from_bytes(ct, "big"))
        if c >= key.n:
            raise DecryptionError("decryption failed")
        # CRT: m = m_q + q * ((m_p - m_q) * q^-1 mod p),  m_p = c^dp mod p ...
        mp = (c % key.p).powermod(key.dp, key.p)
        mq = (c % key.q).powermod(key.dq, key.q)
        h = (key.qinv * (mp - mq)) % key.p
        m = mq + h * key.q
        return oaep_decode(int(m).to_bytes(k, "big"), k)
    raise ValueError("unknown backend")


# ==========================================================================
# 3.  Hybrid encryption: RSA-OAEP transports a random AES-256 key
# ==========================================================================
#
# Wire format (all fields fixed length except the ciphertext):
#     RSA-OAEP(aes_key)  [k bytes]  ||  nonce [12]  ||  AES-GCM ciphertext  ||  tag [16]
# The encapsulated key is also bound into the GCM associated data, so
# swapping or truncating it makes authentication fail.


def rsa_hybrid_encrypt(pub, plaintext: bytes, backend: str = "openssl") -> bytes:
    pubkey = _check_public(pub)
    aes_key = csprng_bytes(AES_KEY_LEN)
    enc_key = rsa_oaep_encrypt(pubkey, aes_key, backend)
    nonce, ct, tag = aead_encrypt(aes_key, plaintext, HYBRID_PROTOCOL_ID + enc_key)
    return enc_key + nonce + ct + tag


def rsa_hybrid_decrypt(key: RSAKeyPair, blob: bytes, backend: str = "openssl") -> bytes:
    k = (key.bits + 7) // 8
    if len(blob) < k + NONCE_LEN + TAG_LEN:
        raise DecryptionError("decryption failed")
    enc_key, rest = blob[:k], blob[k:]
    nonce, ct, tag = rest[:NONCE_LEN], rest[NONCE_LEN:-TAG_LEN], rest[-TAG_LEN:]
    aes_key = rsa_oaep_decrypt(key, enc_key, backend)
    return aead_decrypt(aes_key, nonce, ct, tag, HYBRID_PROTOCOL_ID + enc_key)


def rsa_hybrid_overhead(bits: int) -> dict:
    """Bytes added on top of the plaintext by the RSA hybrid construction."""
    k = (bits + 7) // 8
    return {"encapsulated_key": k, "nonce": NONCE_LEN, "tag": TAG_LEN,
            "total": k + NONCE_LEN + TAG_LEN}
