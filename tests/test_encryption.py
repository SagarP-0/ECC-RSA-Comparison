"""End-to-end encryption tests for RSA hybrid and the ECIES-style scheme, side by side."""
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

import ecies
from common import DecryptionError, NONCE_LEN, TAG_LEN
from conftest import MESSAGES
from ecc import ECCKeyPair, InvalidPointError, get_curve
from ecies import ecies_decrypt, ecies_encrypt, ecies_overhead
from rsa import rsa_hybrid_decrypt, rsa_hybrid_encrypt

BACKENDS = ["openssl", "sage"]
IDS = lambda m: f"len{len(m)}"


# ---------------- ECIES-style -------------------------------------------------


@pytest.mark.parametrize("backend", BACKENDS)
@pytest.mark.parametrize("msg", MESSAGES, ids=IDS)
def test_ecies_roundtrip(ecc_key, backend, msg):
    blob = ecies_encrypt("P-256", ecc_key.public_bytes(), msg, backend)
    assert ecies_decrypt(ecc_key, blob, backend) == msg
    assert len(blob) == len(msg) + ecies_overhead("P-256")["total"] == len(msg) + 93


@pytest.mark.parametrize("enc", BACKENDS)
@pytest.mark.parametrize("dec", BACKENDS)
@pytest.mark.parametrize("compressed", [False, True])
def test_ecies_backends_interoperate_and_derive_identical_keys(ecc_key, enc, dec, compressed):
    msg = "cross-check é中".encode()
    blob = ecies_encrypt("P-256", ecc_key.public_bytes(compressed), msg, enc, compressed)
    assert ecies_decrypt(ecc_key, blob, dec) == msg
    assert len(blob) == len(msg) + ecies_overhead("P-256", compressed)["total"]


@pytest.mark.parametrize("curve", ["P-224", "P-256", "P-384", "P-521"])
@pytest.mark.parametrize("backend", BACKENDS)
def test_ecies_all_curves(curve, backend):
    kp = ECCKeyPair.generate(curve)
    blob = ecies_encrypt(curve, kp.public_bytes(), b"curve test", backend)
    assert ecies_decrypt(kp, blob, backend) == b"curve test"


@pytest.mark.parametrize("backend", BACKENDS)
def test_ecies_randomized(ecc_key, backend):
    a = ecies_encrypt("P-256", ecc_key.public_bytes(), b"same", backend)
    b = ecies_encrypt("P-256", ecc_key.public_bytes(), b"same", backend)
    assert a != b
    assert a[:65] != b[:65]                                 # fresh ephemeral key each time
    assert a[65:77] != b[65:77]                             # fresh nonce


def test_ecies_every_region_is_authenticated(ecc_key):
    blob = ecies_encrypt("P-256", ecc_key.public_bytes(), b"authenticated payload")
    # ephemeral point (x and y bytes), nonce, ciphertext, tag
    for pos in (1, 40, 65, 65 + NONCE_LEN, len(blob) - TAG_LEN - 1, len(blob) - 1):
        bad = bytearray(blob)
        bad[pos] ^= 0x01
        with pytest.raises(DecryptionError):
            ecies_decrypt(ecc_key, bytes(bad))
        with pytest.raises(DecryptionError):
            ecies_decrypt(ecc_key, bytes(bad), "sage")


def test_ecies_reencoded_ephemeral_key_breaks_tag(ecc_key):
    """Same R, different encoding (compressed): header is AAD, so it must be rejected."""
    c = get_curve("P-256")
    blob = ecies_encrypt("P-256", ecc_key.public_bytes(), b"payload")
    R = c.decode_point(blob[:65])
    forged = c.encode_point(R, True) + blob[65:]
    with pytest.raises(DecryptionError):
        ecies_decrypt(ecc_key, forged)


def test_ecies_truncated_and_garbage_rejected(ecc_key):
    blob = ecies_encrypt("P-256", ecc_key.public_bytes(), b"data")
    for bad in (b"", b"\x04", blob[:20], blob[:-1], blob + b"\x00", b"\xff" * 93, b"\x00" * 93):
        with pytest.raises(DecryptionError):
            ecies_decrypt(ecc_key, bad)


@pytest.mark.parametrize("backend", BACKENDS)
def test_ecies_wrong_private_key_fails(ecc_key, ecc_key2, backend):
    blob = ecies_encrypt("P-256", ecc_key.public_bytes(), b"secret", backend)
    with pytest.raises(DecryptionError):
        ecies_decrypt(ecc_key2, blob, backend)


def test_ecies_invalid_recipient_public_point_rejected(ecc_key):
    good = ecc_key.public_bytes()
    bad = good[:-1] + bytes([good[-1] ^ 1])
    for backend in BACKENDS:
        with pytest.raises(InvalidPointError):
            ecies_encrypt("P-256", bad, b"x", backend)
        with pytest.raises(InvalidPointError):
            ecies_encrypt("P-256", b"\x04" + b"\x00" * 64, b"x", backend)


def test_ecies_invalid_ephemeral_point_in_ciphertext_rejected(ecc_key):
    """Invalid-curve attack: attacker sends an off-curve R; decryption must refuse, not compute."""
    blob = bytearray(ecies_encrypt("P-256", ecc_key.public_bytes(), b"x"))
    blob[64] ^= 1                                             # y no longer satisfies the curve equation
    for backend in BACKENDS:
        with pytest.raises(DecryptionError):
            ecies_decrypt(ecc_key, bytes(blob), backend)


def test_ecies_kdf_is_context_bound(ecc_key):
    """Different R / Q / curve / protocol context must give different keys; raw ECDH is not the key."""
    c = get_curve("P-256")
    x = b"\x11" * 32
    R1, R2 = ecc_key.public_bytes(), ECCKeyPair.generate("P-256").public_bytes()
    k = ecies.derive_key(c, x, R1, R1)
    assert len(k) == 32 and k != x
    assert k != ecies.derive_key(c, x, R2, R1) and k != ecies.derive_key(c, x, R1, R2)
    assert k != ecies.derive_key(get_curve("P-384"), x, R1, R1)
    assert k == ecies.derive_key(c, x, R1, R1)                # deterministic


def test_ecies_session_key_is_hkdf_of_ecdh_not_raw(ecc_key, monkeypatch):
    """Capture the AES key used: must differ from the raw ECDH x-coordinate."""
    seen = {}
    real = ecies.aead_encrypt
    monkeypatch.setattr(ecies, "aead_encrypt", lambda key, pt, aad: seen.setdefault("k", key) and real(key, pt, aad))
    blob = ecies_encrypt("P-256", ecc_key.public_bytes(), b"x")
    R = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), blob[:65])
    raw = ecc_key.private_key.exchange(ec.ECDH(), R)
    assert seen["k"] != raw and len(seen["k"]) == 32


# ---------------- both systems, same inputs ---------------------------------------


@pytest.mark.parametrize("msg", MESSAGES, ids=IDS)
def test_both_systems_recover_identical_plaintext(rsa_key, ecc_key, msg):
    r = rsa_hybrid_decrypt(rsa_key, rsa_hybrid_encrypt(rsa_key, msg))
    e = ecies_decrypt(ecc_key, ecies_encrypt("P-256", ecc_key.public_bytes(), msg))
    assert r == e == msg


def test_utf8_text_and_binary_handled_by_both(rsa_key, ecc_key):
    text = "Zoë ❤ Да こんにちは"
    binary = bytes(range(256)) * 3
    for m in (text.encode("utf-8"), binary):
        assert rsa_hybrid_decrypt(rsa_key, rsa_hybrid_encrypt(rsa_key, m)) == m
        assert ecies_decrypt(ecc_key, ecies_encrypt("P-256", ecc_key.public_bytes(), m)) == m
    assert ecies_decrypt(ecc_key, ecies_encrypt("P-256", ecc_key.public_bytes(), text.encode())).decode() == text


def test_ciphertext_does_not_contain_plaintext(rsa_key, ecc_key):
    m = b"VERY-RECOGNISABLE-PLAINTEXT-0123456789"
    assert m not in rsa_hybrid_encrypt(rsa_key, m)
    assert m not in ecies_encrypt("P-256", ecc_key.public_bytes(), m)


def test_randomness_comes_from_os_csprng(monkeypatch, rsa_key, ecc_key):
    """AES keys, nonces and OAEP seeds are drawn through common.csprng_bytes (os.urandom)."""
    import common, rsa as rsa_mod
    calls = []
    real = common.os.urandom
    monkeypatch.setattr(common.os, "urandom", lambda n: calls.append(n) or real(n))
    rsa_hybrid_encrypt(rsa_key, b"x", "sage")        # AES key (32) + OAEP seed (32) + nonce (12)
    assert sorted(calls) == [12, 32, 32]
    calls.clear()
    ecies_encrypt("P-256", ecc_key.public_bytes(), b"x", "sage")
    assert 12 in calls                               # nonce; ephemeral scalar uses secrets (also OS CSPRNG)


def test_no_secret_leak_in_benchmark_output(capsys):
    """The benchmark log lines contain only timings, never key material."""
    import benchmark
    from ecc import ECCKeyPair
    from rsa import generate_rsa_keypair
    k = ECCKeyPair.generate("P-256"); r = generate_rsa_keypair(2048)
    benchmark.PROFILES["tiny"] = {"levels": [112], "reps": {112: 2}, "warmup": 1,
                                  "keygen_reps": {"openssl": {112: 2}, "sage": {112: 2}}}
    data = benchmark.run_all("tiny", "/tmp/_rsa_ecc_tiny")
    out = capsys.readouterr()
    text = out.out + out.err + benchmark.format_summary(data)
    for secret in (str(k.d), hex(k.d)[2:], str(r.d), str(r.p), str(r.q)):
        assert secret not in text
    del benchmark.PROFILES["tiny"]
