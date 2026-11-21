"""RSA tests: key generation, OAEP, hybrid encryption, security properties."""
import pytest
from sage.all import Integer, gcd, is_prime

from common import DecryptionError, NONCE_LEN, TAG_LEN
from conftest import MESSAGES
from rsa import (PUBLIC_EXPONENT, generate_prime, generate_rsa_keypair, is_probable_prime,
                 oaep_decode, oaep_encode, oaep_max_plaintext, rsa_hybrid_decrypt,
                 rsa_hybrid_encrypt, rsa_hybrid_overhead, rsa_oaep_decrypt, rsa_oaep_encrypt)

BACKENDS = ["openssl", "sage"]


def test_keygen_math(rsa_key):
    k = rsa_key
    assert is_prime(k.p) and is_prime(k.q) and k.p != k.q
    assert k.n == k.p * k.q and k.bits == 2048
    assert k.e == 65537 == PUBLIC_EXPONENT
    assert k.phi == (k.p - 1) * (k.q - 1)
    assert (k.e * k.d) % k.phi == 1 and gcd(k.e, k.phi) == 1
    assert (Integer(123456789).powermod(k.e, k.n)).powermod(k.d, k.n) == 123456789


def test_default_key_size_is_3072():
    k = generate_rsa_keypair(3072)
    assert k.bits == 3072


@pytest.mark.parametrize("bits", [512, 1024, 2047, 2049])
def test_small_or_odd_key_sizes_rejected(bits):
    with pytest.raises(ValueError):
        generate_rsa_keypair(bits)


def test_prime_generation_properties():
    p = generate_prime(512)
    assert p.nbits() == 512 and is_prime(p) and gcd(p - 1, 65537) == 1
    assert not is_probable_prime(Integer(561))          # Carmichael number
    assert not is_probable_prime(Integer(2) ** 521 - 3 * 7 * 11)


def test_repr_hides_secrets(rsa_key):
    text = repr(rsa_key) + str(rsa_key)
    assert str(rsa_key.d) not in text and str(rsa_key.p) not in text


@pytest.mark.parametrize("backend", BACKENDS)
def test_oaep_roundtrip_and_max_length(rsa_key, backend):
    mx = oaep_max_plaintext(rsa_key.bits)
    assert mx == 256 - 66 == 190
    for m in (b"", b"hi", b"z" * mx):
        assert rsa_oaep_decrypt(rsa_key, rsa_oaep_encrypt(rsa_key, m, backend), backend) == m
    with pytest.raises(ValueError):
        rsa_oaep_encrypt(rsa_key, b"z" * (mx + 1), backend)


@pytest.mark.parametrize("enc,dec", [("openssl", "sage"), ("sage", "openssl")])
def test_oaep_backends_interoperate(rsa_key, enc, dec):
    m = "cross-backend é".encode()
    assert rsa_oaep_decrypt(rsa_key, rsa_oaep_encrypt(rsa_key, m, enc), dec) == m


@pytest.mark.parametrize("backend", BACKENDS)
def test_oaep_is_randomized(rsa_key, backend):
    c1, c2 = (rsa_oaep_encrypt(rsa_key, b"same", backend) for _ in range(2))
    assert c1 != c2


def test_oaep_encode_decode_and_label():
    em = oaep_encode(b"payload", 256)
    assert len(em) == 256 and em[0] == 0
    assert oaep_decode(em, 256) == b"payload"
    with pytest.raises(DecryptionError):
        oaep_decode(em, 256, label=b"other")


@pytest.mark.parametrize("backend", BACKENDS)
def test_oaep_corruption_rejected(rsa_key, backend):
    ct = bytearray(rsa_oaep_encrypt(rsa_key, b"secret", backend))
    ct[10] ^= 1
    with pytest.raises(DecryptionError):
        rsa_oaep_decrypt(rsa_key, bytes(ct), backend)
    with pytest.raises(DecryptionError):
        rsa_oaep_decrypt(rsa_key, bytes(ct[:-1]), backend)


@pytest.mark.parametrize("backend", BACKENDS)
def test_oaep_wrong_key_fails(rsa_key, rsa_key2, backend):
    ct = rsa_oaep_encrypt(rsa_key, b"secret", backend)
    with pytest.raises(DecryptionError):
        rsa_oaep_decrypt(rsa_key2, ct, backend)


@pytest.mark.parametrize("backend", BACKENDS)
@pytest.mark.parametrize("msg", MESSAGES, ids=lambda m: f"len{len(m)}")
def test_hybrid_roundtrip(rsa_key, backend, msg):
    blob = rsa_hybrid_encrypt(rsa_key, msg, backend)
    assert rsa_hybrid_decrypt(rsa_key, blob, backend) == msg
    assert len(blob) == len(msg) + rsa_hybrid_overhead(rsa_key.bits)["total"]


def test_hybrid_utf8_text(rsa_key):
    text = "Grüße ☃ 你好"
    assert rsa_hybrid_decrypt(rsa_key, rsa_hybrid_encrypt(rsa_key, text.encode())).decode() == text


@pytest.mark.parametrize("backend", BACKENDS)
def test_hybrid_randomized(rsa_key, backend):
    assert rsa_hybrid_encrypt(rsa_key, b"same", backend) != rsa_hybrid_encrypt(rsa_key, b"same", backend)


def test_hybrid_every_region_is_authenticated(rsa_key):
    """Flip one bit in: encapsulated key, nonce, ciphertext body, tag -> all rejected."""
    msg = b"authenticated payload"
    blob = rsa_hybrid_encrypt(rsa_key, msg)
    k = rsa_key.bits // 8
    for pos in (0, k // 2, k, k + NONCE_LEN, len(blob) - TAG_LEN - 1, len(blob) - 1):
        bad = bytearray(blob)
        bad[pos] ^= 0x01
        with pytest.raises(DecryptionError):
            rsa_hybrid_decrypt(rsa_key, bytes(bad))


def test_hybrid_truncated_and_empty_input_rejected(rsa_key):
    blob = rsa_hybrid_encrypt(rsa_key, b"data")
    for bad in (b"", blob[:10], blob[:-1], blob + b"\x00"):
        with pytest.raises(DecryptionError):
            rsa_hybrid_decrypt(rsa_key, bad)


def test_hybrid_wrong_key_fails(rsa_key, rsa_key2):
    with pytest.raises(DecryptionError):
        rsa_hybrid_decrypt(rsa_key2, rsa_hybrid_encrypt(rsa_key, b"x"))


def test_public_key_only_object_is_enough_to_encrypt(rsa_key):
    blob = rsa_hybrid_encrypt(rsa_key.public_key, b"to public key")
    assert rsa_hybrid_decrypt(rsa_key, blob) == b"to public key"


def test_non_key_input_rejected():
    with pytest.raises(TypeError):
        rsa_hybrid_encrypt("not a key", b"x")
