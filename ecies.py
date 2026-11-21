"""
ecies.py - an ECIES-STYLE hybrid encryption scheme (ephemeral ECDH + HKDF + AES-256-GCM).

IMPORTANT: this is an ECIES-*style* construction designed for this project.
It is NOT claimed to comply with SEC 1 ECIES, IEEE 1363a, ISO 18033-2 or any
other specification (those fix different KDFs, MAC/DEM choices and encodings).

Exact construction
------------------
Recipient key pair:  d (private scalar), Q = dG.

Encrypt(Q, M):
  1. Validate Q (on curve, not infinity).
  2. r  <- uniform in [1, n-1] from the OS CSPRNG;   R = rG
  3. S  = rQ                                        (ECDH shared point)
  4. Z  = x(S) as a fixed-length big-endian string   (the ECDH output)
  5. K  = HKDF-SHA256( ikm = Z,  salt = none (32 zero bytes),
                       info = lp(PROTOCOL_ID) || lp(curve name)
                              || lp(R, uncompressed) || lp(Q, uncompressed),
                       L = 32 bytes )
  6. nonce <- 12 random bytes
  7. (C, T) = AES-256-GCM_K(nonce, M, aad = PROTOCOL_ID || header)
  Output = header || nonce || C || T      with header = R as SEC1 (65 B for P-256
           uncompressed, 33 B compressed), nonce 12 B, T 16 B.

Decrypt(d, output):
  parse header -> validate R -> S = dR -> same Z, K -> AES-GCM verify+decrypt.

Design notes
  * Raw ECDH output is NEVER used as the key: x(S) is not uniformly random, so
    HKDF-Extract concentrates its entropy and HKDF-Expand derives K.
  * `info` binds the key to the protocol, curve, R and Q (context binding), so
    a key derived for one context cannot be reused in another.
  * The exact transmitted header bytes are authenticated as GCM associated
    data, so re-encoding R (e.g. compressed <-> uncompressed) breaks the tag.
  * K is single-use (fresh r each time), so a random 96-bit nonce is safe.
  * Every failure (bad point, bad tag, short input) raises DecryptionError.

Two backends perform the EC arithmetic; HKDF/AES-GCM are shared:
  "openssl" - `cryptography` (constant-time, fast).   "sage" - SageMath group law.
The wire format is identical, so the backends interoperate (tested).
"""

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from common import (
    AES_KEY_LEN, NONCE_LEN, TAG_LEN, DecryptionError,
    aead_decrypt, aead_encrypt, csprng_randbelow, lp,
)
from ecc import ECCKeyPair, InvalidPointError, get_curve

PROTOCOL_ID = b"RSA-ECC-Comparison/ECIES-style/ECDH-HKDF-SHA256-AES256GCM/v1"


def derive_key(curve, shared_x: bytes, R_bytes: bytes, Q_bytes: bytes) -> bytes:
    """HKDF-SHA256 over the ECDH x-coordinate with full context binding."""
    info = (lp(PROTOCOL_ID) + lp(curve.name.encode()) + lp(R_bytes) + lp(Q_bytes))
    return HKDF(algorithm=hashes.SHA256(), length=AES_KEY_LEN, salt=None, info=info).derive(shared_x)


def _uncompressed(curve, point) -> bytes:
    return curve.encode_point(point, compressed=False)


def _crypto_pub(curve, point_bytes: bytes):
    return ec.EllipticCurvePublicKey.from_encoded_point(curve.crypto_curve, point_bytes)


def ecies_encrypt(curve_name: str, recipient_public: bytes, plaintext: bytes,
                  backend: str = "openssl", compressed: bool = False) -> bytes:
    """Encrypt to a recipient's SEC1-encoded public key.

    Raises InvalidPointError if the recipient public key is not a valid point.
    """
    curve = get_curve(curve_name)
    Q = curve.decode_point(recipient_public)          # full validation, BOTH backends
    Q_unc = _uncompressed(curve, Q)

    if backend == "sage":
        r = 1 + csprng_randbelow(int(curve.n) - 1)    # secret ephemeral scalar
        R = curve.G * r                               # R = rG
        S = Q * r                                     # S = rQ
        if S == curve.E(0):
            raise InvalidPointError("degenerate shared point")
        shared_x = int(S.xy()[0]).to_bytes(curve.coord_len, "big")
        R_hdr = curve.encode_point(R, compressed)
        R_unc = _uncompressed(curve, R)
    elif backend == "openssl":
        eph = ec.generate_private_key(curve.crypto_curve)
        shared_x = eph.exchange(ec.ECDH(), _crypto_pub(curve, Q_unc))
        fmt = (serialization.PublicFormat.CompressedPoint if compressed
               else serialization.PublicFormat.UncompressedPoint)
        R_hdr = eph.public_key().public_bytes(serialization.Encoding.X962, fmt)
        R_unc = eph.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    else:
        raise ValueError("backend must be 'sage' or 'openssl'")

    key = derive_key(curve, shared_x, R_unc, Q_unc)
    nonce, ct, tag = aead_encrypt(key, plaintext, PROTOCOL_ID + R_hdr)
    return R_hdr + nonce + ct + tag


def ecies_decrypt(keypair: ECCKeyPair, blob: bytes, backend: str = "openssl") -> bytes:
    """Decrypt; raises DecryptionError for ANY malformed/forged input."""
    curve = keypair.curve
    try:
        if not blob:
            raise DecryptionError("decryption failed")
        hdr_len = curve.point_len(blob[0])
        if hdr_len == 0 or len(blob) < hdr_len + NONCE_LEN + TAG_LEN:
            raise DecryptionError("decryption failed")
        R_hdr = blob[:hdr_len]
        nonce = blob[hdr_len:hdr_len + NONCE_LEN]
        ct, tag = blob[hdr_len + NONCE_LEN:-TAG_LEN], blob[-TAG_LEN:]

        R = curve.decode_point(R_hdr)                 # validates R (invalid-curve defence)
        R_unc = _uncompressed(curve, R)
        Q_unc = _uncompressed(curve, keypair.Q)
        if backend == "sage":
            S = R * keypair.d                         # S = dR = d(rG) = r(dG) = rQ
            if S == curve.E(0):
                raise DecryptionError("decryption failed")
            shared_x = int(S.xy()[0]).to_bytes(curve.coord_len, "big")
        elif backend == "openssl":
            shared_x = keypair.private_key.exchange(ec.ECDH(), _crypto_pub(curve, R_unc))
        else:
            raise ValueError("backend must be 'sage' or 'openssl'")
    except (InvalidPointError, ValueError, UnsupportedAlgorithm) as exc:
        if isinstance(exc, ValueError) and "backend" in str(exc):
            raise
        raise DecryptionError("decryption failed") from None

    key = derive_key(curve, shared_x, R_unc, Q_unc)
    return aead_decrypt(key, nonce, ct, tag, PROTOCOL_ID + R_hdr)


def ecies_overhead(curve_name: str, compressed: bool = False) -> dict:
    """Bytes added on top of the plaintext by the ECIES-style construction."""
    curve = get_curve(curve_name)
    point = (1 + curve.coord_len) if compressed else (1 + 2 * curve.coord_len)
    return {"encapsulated_key": point, "nonce": NONCE_LEN, "tag": TAG_LEN,
            "total": point + NONCE_LEN + TAG_LEN}
