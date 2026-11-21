"""ECC tests: domain parameters, group law, key generation, validation, serialization."""
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sage.all import Integer

import ecc
from ecc import ECCKeyPair, InvalidPointError, get_curve, validate_private_scalar

CURVES = ["P-224", "P-256", "P-384", "P-521"]


@pytest.mark.parametrize("name", CURVES)
def test_domain_parameters_are_the_standard_ones(name):
    """Sage's parameters must equal OpenSSL's independent definition of the NIST curve,
    and every algebraic invariant must hold."""
    c = get_curve(name)
    assert all(c.verify_domain_parameters().values())
    # cross-check G against OpenSSL: derive_private_key(1) is G itself
    nums = ec.derive_private_key(1, c.crypto_curve).public_key().public_numbers()
    assert (int(c.G.xy()[0]), int(c.G.xy()[1])) == (nums.x, nums.y)
    assert c.a == c.p - 3 and c.h == 1


def test_p256_known_constants():
    c = get_curve("P-256")
    assert c.p == 2**256 - 2**224 + 2**192 + 2**96 - 1
    assert hex(c.n) == "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
    assert hex(int(c.G.xy()[0])) == "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"


def test_p256_full_point_count_equals_n():
    assert get_curve("P-256").verify_domain_parameters(full_order=True)["#E(F_p) == n*h (SEA point counting)"]


def test_group_law_matches_sage(ecc_key):
    c = get_curve("P-256")
    G, Q = c.G, ecc_key.Q
    assert c.point_add(G, Q) == G + Q
    assert c.point_double(Q) == 2 * Q
    assert c.point_add(Q, Q) == 2 * Q                      # doubling via add
    assert c.point_add(Q, -Q) == c.E(0)
    assert c.point_add(c.E(0), Q) == Q and c.point_add(Q, c.E(0)) == Q
    for k in (1, 2, 3, 255, 256, 2**64 + 17, int(c.n) - 1, int(c.n)):
        assert c.scalar_mult(k) == k * G


def test_scalar_mult_group_properties():
    c = get_curve("P-256")
    a, b = 123456789, 987654321
    assert a * c.G + b * c.G == (a + b) * c.G               # distributivity
    assert a * (b * c.G) == (a * b) * c.G                   # ECDH commutativity core
    assert c.n * c.G == c.E(0)


@pytest.mark.parametrize("name", CURVES)
def test_keygen_public_point(name):
    kp = ECCKeyPair.generate(name, "sage")
    c = kp.curve
    assert 1 <= kp.d <= c.n - 1
    assert kp.Q == kp.d * c.G and kp.Q in c.E and c.n * kp.Q == c.E(0)
    # OpenSSL derives the same public point
    assert ECCKeyPair(c, kp.d, "openssl").Q == kp.Q


def test_keygen_uses_os_csprng_not_sage_prng(monkeypatch):
    """The private scalar comes from secrets/os.urandom via common.csprng_randbelow."""
    calls = []
    real = ecc.csprng_randbelow
    monkeypatch.setattr(ecc, "csprng_randbelow", lambda n: calls.append(n) or real(n))
    ECCKeyPair.generate("P-256")
    assert calls == [int(get_curve("P-256").n) - 1]
    # and distinct keys come out
    assert ECCKeyPair.generate("P-256").d != ECCKeyPair.generate("P-256").d


@pytest.mark.parametrize("bad", [0, -1, "5", 1.5, None, True])
def test_invalid_private_scalar_types_and_small_values(bad):
    c = get_curve("P-256")
    with pytest.raises(ValueError):
        validate_private_scalar(c, bad)
    with pytest.raises(ValueError):
        ECCKeyPair(c, bad)


def test_out_of_range_private_scalar_rejected():
    c = get_curve("P-256")
    for bad in (int(c.n), int(c.n) + 1, 2**300):
        with pytest.raises(ValueError):
            ECCKeyPair(c, bad)
    assert validate_private_scalar(c, int(c.n) - 1) == int(c.n) - 1   # boundary accepted
    assert validate_private_scalar(c, 1) == 1


def test_repr_hides_private_scalar(ecc_key):
    assert str(ecc_key.d) not in repr(ecc_key) and hex(ecc_key.d)[2:] not in repr(ecc_key)


def test_unknown_curve_rejected():
    with pytest.raises(ValueError):
        get_curve("secp256k1")


# ---- point encoding / validation -------------------------------------------------


@pytest.mark.parametrize("name", CURVES)
@pytest.mark.parametrize("compressed", [False, True])
def test_point_encoding_roundtrip(name, compressed):
    kp = ECCKeyPair.generate(name)
    raw = kp.public_bytes(compressed)
    assert len(raw) == (1 + kp.curve.coord_len) if compressed else (1 + 2 * kp.curve.coord_len)
    assert kp.curve.decode_point(raw) == kp.Q
    # identical to OpenSSL's own SEC1 encoding
    fmt = serialization.PublicFormat.CompressedPoint if compressed else serialization.PublicFormat.UncompressedPoint
    assert raw == kp.public_key.public_bytes(serialization.Encoding.X962, fmt)


def test_invalid_points_rejected(ecc_key):
    c = get_curve("P-256")
    good = ecc_key.public_bytes(False)
    x, y = good[1:33], good[33:]
    p = int(c.p).to_bytes(32, "big")
    bad_points = {
        "off curve (y+1)": b"\x04" + x + (int.from_bytes(y, "big") ^ 1).to_bytes(32, "big"),
        "all zero coords": b"\x04" + b"\x00" * 64,
        "x >= p": b"\x04" + p + y,
        "y >= p": b"\x04" + x + p,
        "bad prefix": b"\x05" + x + y,
        "infinity encoding": b"\x00",
        "empty": b"",
        "truncated": good[:-1],
        "too long": good + b"\x00",
        "compressed wrong length": b"\x02" + x[:-1],
        "hybrid prefix 06": b"\x06" + x + y,
    }
    # a compressed x with no square root on the curve
    for i in range(2, 200):
        if not (c.field(i) ** 3 + c.field(c.a) * i + c.field(c.b)).is_square():
            bad_points["compressed x with no y"] = b"\x02" + i.to_bytes(32, "big")
            break
    for label, pt in bad_points.items():
        with pytest.raises(InvalidPointError):
            c.decode_point(pt)
        assert label  # (label shown on failure through the loop variable)


def test_point_on_a_different_curve_rejected():
    """Invalid-curve attack input: a valid P-384 point must not decode as P-256."""
    other = ECCKeyPair.generate("P-384").public_bytes(False)
    with pytest.raises(InvalidPointError):
        get_curve("P-256").decode_point(other)
    # a point from the twist-like set: random (x, y) pairs essentially never satisfy the equation
    c = get_curve("P-256")
    with pytest.raises(InvalidPointError):
        c.decode_point(b"\x04" + (5).to_bytes(32, "big") + (7).to_bytes(32, "big"))


def test_cannot_encode_infinity():
    c = get_curve("P-256")
    with pytest.raises(InvalidPointError):
        c.encode_point(c.E(0))


def test_decoded_points_have_prime_order(ecc_key):
    c = get_curve("P-256")
    for comp in (False, True):
        assert c.n * c.decode_point(ecc_key.public_bytes(comp)) == c.E(0)


# ---- serialization -------------------------------------------------------------


def test_serialization_sizes_p256(ecc_key):
    assert len(ecc_key.public_bytes(False)) == 65 and len(ecc_key.public_bytes(True)) == 33
    assert len(ecc_key.public_der(False)) == 91 and len(ecc_key.public_der(True)) == 59
    assert len(ecc_key.private_raw()) == 32
    assert len(ecc_key.private_der()) == 138


def test_spki_matches_openssl_and_is_parseable(ecc_key):
    ossl = ecc_key.public_key.public_bytes(serialization.Encoding.DER,
                                           serialization.PublicFormat.SubjectPublicKeyInfo)
    assert ecc_key.public_der(False) == ossl
    # our hand-built compressed SPKI is accepted by an independent parser
    pub = serialization.load_der_public_key(ecc_key.public_der(True))
    assert pub.public_numbers() == ecc_key.public_key.public_numbers()


@pytest.mark.parametrize("name", CURVES)
def test_spki_all_curves_parse(name):
    kp = ECCKeyPair.generate(name)
    for comp in (False, True):
        pub = serialization.load_der_public_key(kp.public_der(comp))
        assert pub.public_numbers() == kp.public_key.public_numbers()


def test_private_key_roundtrip_through_pkcs8(ecc_key):
    loaded = serialization.load_der_private_key(ecc_key.private_der(), None)
    assert loaded.private_numbers().private_value == ecc_key.d
    loaded_pem = serialization.load_pem_private_key(ecc_key.private_pem(), None)
    assert loaded_pem.private_numbers().private_value == ecc_key.d


def test_toy_ecdlp_baby_step_giant_step():
    E, g, n = ecc.toy_curve(20, seed=7)
    for d in (1, 2, 12345 % n, n - 1):
        assert ecc.bsgs(E, g, d * g, n) == d % n
