"""
ecc.py - elliptic-curve mathematics (SageMath) and key handling for NIST curves.

Curve (short Weierstrass form over a prime field F_p):

        E:  y^2 = x^3 + a*x + b   (mod p),     a = -3 for all NIST prime curves

Points form an abelian group under the chord-and-tangent rule.  Let G be the
base point of prime order n (cofactor h = 1 for every curve used here).

    point addition  P + Q (P != +-Q):  lam = (y2-y1)/(x2-x1)
    point doubling  2P:                lam = (3*x1^2 + a)/(2*y1)
        x3 = lam^2 - x1 - x2,   y3 = lam*(x1 - x3) - y1
    scalar mult.    kG = G + G + ... + G  (k times), by double-and-add.

ECDLP: given Q = dG, recover d.  The best known classical attacks (Pollard rho)
need ~sqrt(n) group operations, so n ~ 2^256 gives ~2^128 work.

The domain parameters below are the real standardized values (FIPS 186-4 /
SEC 2).  They were taken from OpenSSL's built-in curve definitions and are
re-verified at import time by `verify_domain_parameters` in the tests
(p prime, G on curve, n prime, n*G = O, #E = n*h within the Hasse bound).
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sage.all import GF, EllipticCurve, Integer, ZZ, is_prime

from common import csprng_randbelow

__all__ = ["Curve", "get_curve", "ECCKeyPair", "InvalidPointError", "validate_private_scalar", "toy_curve", "bsgs", "NIST_PARAMS"]

NIST_PARAMS = {
    "P-224": dict(
        p=0xffffffffffffffffffffffffffffffff000000000000000000000001,
        a=0xfffffffffffffffffffffffffffffffefffffffffffffffffffffffe,
        b=0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4,
        gx=0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21,
        gy=0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34,
        n=0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d,
        h=1,
    ),
    "P-256": dict(
        p=0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
        a=0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc,
        b=0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
        gx=0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
        gy=0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
        n=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
        h=1,
    ),
    "P-384": dict(
        p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff,
        a=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc,
        b=0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
        gx=0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
        gy=0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f,
        n=0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973,
        h=1,
    ),
    "P-521": dict(
        p=0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
        a=0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc,
        b=0x51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00,
        gx=0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66,
        gy=0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650,
        n=0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409,
        h=1,
    ),
}

_CRYPTO_CURVES = {
    "P-224": ec.SECP224R1, "P-256": ec.SECP256R1,
    "P-384": ec.SECP384R1, "P-521": ec.SECP521R1,
}

# DER-encoded OIDs (tag 06) of the named curves, for hand-built SPKI encoding.
_CURVE_OIDS = {
    "P-224": bytes.fromhex("06052b81040021"),
    "P-256": bytes.fromhex("06082a8648ce3d030107"),
    "P-384": bytes.fromhex("06052b81040022"),
    "P-521": bytes.fromhex("06052b81040023"),
}
_OID_EC_PUBLIC_KEY = bytes.fromhex("06072a8648ce3d0201")


class InvalidPointError(ValueError):
    """An encoded point is malformed, off-curve, or the point at infinity."""


def _der(tag: int, body: bytes) -> bytes:
    n = len(body)
    if n < 128:
        ln = bytes([n])
    else:
        nb = n.to_bytes((n.bit_length() + 7) // 8, "big")
        ln = bytes([0x80 | len(nb)]) + nb
    return bytes([tag]) + ln + body


class Curve:
    """A NIST prime curve realised in SageMath."""

    def __init__(self, name: str):
        if name not in NIST_PARAMS:
            raise ValueError(f"unsupported curve {name!r}; choose from {sorted(NIST_PARAMS)}")
        P = NIST_PARAMS[name]
        self.name = name
        self.p, self.a, self.b = Integer(P["p"]), Integer(P["a"]), Integer(P["b"])
        self.n, self.h = Integer(P["n"]), P["h"]
        self.field = GF(self.p)                                   # finite field F_p
        self.E = EllipticCurve(self.field, [self.a, self.b])      # the curve
        self.G = self.E(P["gx"], P["gy"])                         # base point (raises if off-curve)
        self.coord_len = (int(self.p.nbits()) + 7) // 8           # bytes per coordinate
        self.order_bits = int(self.n.nbits())
        self.crypto_curve = _CRYPTO_CURVES[name]()

    def __repr__(self):
        return f"Curve({self.name})"

    # ------------------------------------------------------------------
    # Group law, implemented explicitly (cross-checked against Sage in tests)
    # ------------------------------------------------------------------
    def point_add(self, P, Q):
        """Affine chord-and-tangent addition including all special cases."""
        O = self.E(0)
        if P == O:
            return Q
        if Q == O:
            return P
        x1, y1 = P.xy()
        x2, y2 = Q.xy()
        if x1 == x2:
            if y1 != y2 or y1 == 0:       # Q = -P (or P of order 2): result is O
                return O
            return self.point_double(P)
        lam = (y2 - y1) / (x2 - x1)       # slope of the chord
        x3 = lam ** 2 - x1 - x2
        y3 = lam * (x1 - x3) - y1
        return self.E(x3, y3)

    def point_double(self, P):
        """Tangent doubling: lam = (3x^2 + a) / 2y."""
        O = self.E(0)
        if P == O:
            return O
        x1, y1 = P.xy()
        if y1 == 0:
            return O
        lam = (3 * x1 ** 2 + self.field(self.a)) / (2 * y1)
        x3 = lam ** 2 - 2 * x1
        y3 = lam * (x1 - x3) - y1
        return self.E(x3, y3)

    def scalar_mult(self, k, P=None):
        """kP via left-to-right double-and-add (explicit version, for teaching).

        Not constant time - the secret-dependent branch leaks the bits of k.
        Real implementations (OpenSSL) use constant-time ladders/windowing.
        """
        P = self.G if P is None else P
        k = int(k)
        R = self.E(0)
        for bit in bin(k)[2:]:
            R = self.point_double(R)
            if bit == "1":
                R = self.point_add(R, P)
        return R

    # ------------------------------------------------------------------
    # Domain-parameter verification
    # ------------------------------------------------------------------
    def verify_domain_parameters(self, full_order: bool = False) -> dict:
        """Check the standardized parameters; returns a dict of check results.

        full_order=True additionally counts all points with Schoof-Elkies-Atkin
        (#E == n*h).  That takes seconds for P-224/P-256 and much longer for
        P-384/P-521, so it is opt-in.
        """
        res = {
            "p is prime": bool(is_prime(self.p)),
            "n is prime": bool(is_prime(self.n)),
            "discriminant 4a^3+27b^2 != 0": bool(
                4 * self.field(self.a) ** 3 + 27 * self.field(self.b) ** 2 != 0),
            "G lies on the curve": bool(self.G in self.E),
            "n*G = O": bool(self.n * self.G == self.E(0)),
            "G != O": bool(self.G != self.E(0)),
            "cofactor h = 1": self.h == 1,
        }
        hasse = abs(self.n * self.h - (self.p + 1)) <= 2 * self.p.sqrt(prec=self.p.nbits() + 8)
        res["Hasse bound holds for n*h"] = bool(hasse)
        if full_order:
            res["#E(F_p) == n*h (SEA point counting)"] = bool(self.E.order() == self.n * self.h)
        return res

    # ------------------------------------------------------------------
    # SEC1 point encoding / decoding with full validation
    # ------------------------------------------------------------------
    def encode_point(self, P, compressed: bool = False) -> bytes:
        """SEC1 encoding: 04||X||Y (uncompressed) or 02/03||X (compressed)."""
        if P == self.E(0):
            raise InvalidPointError("cannot encode the point at infinity")
        x, y = P.xy()
        xb = int(x).to_bytes(self.coord_len, "big")
        if compressed:
            return bytes([2 + (int(y) & 1)]) + xb
        return b"\x04" + xb + int(y).to_bytes(self.coord_len, "big")

    def point_len(self, first_byte: int) -> int:
        """Encoded length implied by the SEC1 prefix byte (0 if unknown)."""
        if first_byte == 4:
            return 1 + 2 * self.coord_len
        if first_byte in (2, 3):
            return 1 + self.coord_len
        return 0

    def decode_point(self, data: bytes):
        """Parse and VALIDATE a SEC1 point.  Raises InvalidPointError.

        Checks: known prefix, exact length, coordinates in [0, p), the point
        satisfies the curve equation, and it is not the point at infinity.
        Since h = 1, every such point automatically has prime order n, so no
        separate subgroup check is needed (verified by n*P = O in the tests).
        Skipping the on-curve check enables invalid-curve attacks.
        """
        data = bytes(data)
        if not data or self.point_len(data[0]) != len(data):
            raise InvalidPointError("bad SEC1 encoding (prefix or length)")
        L = self.coord_len
        x = int.from_bytes(data[1:1 + L], "big")
        if x >= self.p:
            raise InvalidPointError("x coordinate out of range")
        if data[0] == 4:
            y = int.from_bytes(data[1 + L:], "big")
            if y >= self.p:
                raise InvalidPointError("y coordinate out of range")
            fx, fy = self.field(x), self.field(y)
            if fy ** 2 != fx ** 3 + self.field(self.a) * fx + self.field(self.b):
                raise InvalidPointError("point is not on the curve")
            return self.E(fx, fy)
        # compressed: recover y = sqrt(x^3 + ax + b) and pick the parity
        fx = self.field(x)
        rhs = fx ** 3 + self.field(self.a) * fx + self.field(self.b)
        if not rhs.is_square():
            raise InvalidPointError("x is not the x-coordinate of any curve point")
        y = rhs.sqrt()
        if int(y) & 1 != data[0] & 1:
            y = -y
        return self.E(fx, y)

    # ------------------------------------------------------------------
    # DER SubjectPublicKeyInfo for a point (supports compressed points,
    # which `cryptography` does not emit for SPKI)
    # ------------------------------------------------------------------
    def spki_der(self, point_bytes: bytes) -> bytes:
        alg = _der(0x30, _OID_EC_PUBLIC_KEY + _CURVE_OIDS[self.name])
        return _der(0x30, alg + _der(0x03, b"\x00" + point_bytes))


_CURVE_CACHE = {}


def get_curve(name: str) -> Curve:
    """Cached Curve factory (curve construction is done once, not per operation)."""
    if name not in _CURVE_CACHE:
        _CURVE_CACHE[name] = Curve(name)
    return _CURVE_CACHE[name]


# ==========================================================================
# Key pairs
# ==========================================================================


def validate_private_scalar(curve: Curve, d) -> int:
    """Return d as int if it is an integer in [1, n-1]; otherwise ValueError."""
    if isinstance(d, bool) or not isinstance(d, (int, Integer)):
        raise ValueError("private scalar must be an integer")
    d = int(d)
    if not 1 <= d <= int(curve.n) - 1:
        raise ValueError("private scalar out of range [1, n-1]")
    return d


class ECCKeyPair:
    """ECC key pair: private scalar d in [1, n-1], public point Q = d*G."""

    def __init__(self, curve: Curve, d: int, backend: str = "sage"):
        self.curve = curve
        self._d = validate_private_scalar(curve, d)
        if backend == "sage":
            self.Q = curve.G * self._d                        # Q = dG (Sage group law)
        elif backend == "openssl":
            self.Q = None
        else:
            raise ValueError("backend must be 'sage' or 'openssl'")
        self.private_key = ec.derive_private_key(self._d, curve.crypto_curve)
        self.public_key = self.private_key.public_key()
        if self.Q is None:   # take the public point from OpenSSL, decode+validate it in Sage
            raw = self.public_key.public_bytes(
                serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
            self.Q = curve.decode_point(raw)

    @classmethod
    def generate(cls, curve_name: str = "P-256", backend: str = "sage") -> "ECCKeyPair":
        """Uniform private scalar in [1, n-1] from the OS CSPRNG (never Sage's PRNG)."""
        curve = get_curve(curve_name)
        d = 1 + csprng_randbelow(int(curve.n) - 1)
        return cls(curve, d, backend)

    @property
    def d(self) -> int:
        return self._d

    def __repr__(self):
        return f"ECCKeyPair({self.curve.name}, <private scalar hidden>)"

    # ---- serialization ---------------------------------------------------
    def public_bytes(self, compressed: bool = False) -> bytes:
        """Raw SEC1 point (65 bytes uncompressed / 33 compressed for P-256)."""
        return self.curve.encode_point(self.Q, compressed)

    def public_der(self, compressed: bool = False) -> bytes:
        return self.curve.spki_der(self.public_bytes(compressed))

    def public_pem(self) -> bytes:
        return self.public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    def private_raw(self) -> bytes:
        """The scalar d as a fixed-length big-endian integer."""
        return self._d.to_bytes((self.curve.order_bits + 7) // 8, "big")

    def private_der(self) -> bytes:
        """Unencrypted PKCS#8 DER (includes the public key)."""
        return self.private_key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())

    def private_pem(self) -> bytes:
        return self.private_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())


# ==========================================================================
# ECDLP illustration on TOY curves (clearly NOT standardized curves)
# ==========================================================================


def toy_curve(bits: int, seed: int):
    """A small prime-order curve for ECDLP experiments.  For illustration only."""
    from sage.all import random_prime, set_random_seed, randint
    set_random_seed(seed)
    while True:
        p = random_prime(2 ** bits, lbound=2 ** (bits - 1))
        F = GF(p)
        try:
            E = EllipticCurve(F, [randint(1, int(p) - 1), randint(1, int(p) - 1)])
        except ArithmeticError:
            continue
        n = E.order()
        if is_prime(n):
            return E, E.gens()[0], int(n)


def bsgs(E, G, Q, n: int):
    """Baby-step giant-step: solve Q = dG in ~sqrt(n) steps and ~sqrt(n) memory."""
    m = int(Integer(n).sqrt()) + 1
    baby = {}
    R = E(0)
    for j in range(m):                       # baby steps: store jG
        baby[R.xy() if R != E(0) else None] = j
        R = R + G
    step = -(m * G)
    R = Q
    for i in range(m + 1):                   # giant steps: Q - i*mG
        key = R.xy() if R != E(0) else None
        if key in baby:
            return (i * m + baby[key]) % n
        R = R + step
    return None
