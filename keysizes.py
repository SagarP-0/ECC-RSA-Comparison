"""
keysizes.py - key-size analysis (mathematical vs serialized vs transmitted).

Three different things are measured and kept apart:

1. MATHEMATICAL size - the bits of the underlying mathematical objects.
     RSA public  = (n, e)            -> bits(n) + bits(e)
     RSA private = d (minimal)       -> bits(d);  full CRT key = d,p,q,dp,dq,qinv
     ECC public  = point (x, y)      -> 2 * field bits (uncompressed),
                                        field bits + 1 sign bit (compressed)
     ECC private = scalar d          -> order bits
2. SERIALIZED size - bytes of a concrete encoding (DER / PEM / raw SEC1).
     RSA public : X.509 SubjectPublicKeyInfo DER (the format actually sent);
                  also bare PKCS#1 {n, e}.
     RSA private: unencrypted PKCS#8 DER (all CRT components).
     ECC public : SPKI DER (uncompressed and compressed) and raw SEC1 point.
     ECC private: PKCS#8 DER (includes the public key) and the raw scalar.
3. TRANSMISSION size - what is sent for another party to encrypt to you:
     the SPKI DER public key (bytes), and its PEM text form.

Reduction = (RSA size - ECC size) / RSA size * 100, computed separately for
public and private keys and for each serialization.
"""

from common import SECURITY_LEVELS
from ecc import ECCKeyPair
from rsa import PUBLIC_EXPONENT, generate_rsa_keypair


def reduction_pct(rsa_size: float, ecc_size: float) -> float:
    return (rsa_size - ecc_size) / rsa_size * 100.0


def measure_level(level: int, rsa_key=None, ecc_key=None, rsa_backend="openssl") -> dict:
    """All size measurements for one security level (keys generated if not given)."""
    sl = SECURITY_LEVELS[level]
    rsa_key = rsa_key or generate_rsa_keypair(sl.rsa_bits, rsa_backend)
    ecc_key = ecc_key or ECCKeyPair.generate(sl.curve)
    cv = ecc_key.curve

    math = {
        "rsa_public_bits": rsa_key.bits + int(PUBLIC_EXPONENT).bit_length(),
        "rsa_modulus_bits": rsa_key.bits,
        "rsa_private_min_bits": int(rsa_key.d.nbits()),                 # d only
        "rsa_private_crt_bits": sum(int(x.nbits()) for x in
                                    (rsa_key.d, rsa_key.p, rsa_key.q, rsa_key.dp, rsa_key.dq, rsa_key.qinv)),
        "ecc_public_uncompressed_bits": 2 * int(cv.p.nbits()),
        "ecc_public_compressed_bits": int(cv.p.nbits()) + 1,
        "ecc_private_bits": cv.order_bits,
    }
    ser = {
        "rsa_public_spki_der": len(rsa_key.public_der()),
        "rsa_public_pkcs1_der": len(rsa_key.public_pkcs1_der()),
        "rsa_public_pem": len(rsa_key.public_pem()),
        "rsa_private_pkcs8_der": len(rsa_key.private_der()),
        "rsa_private_pkcs8_pem": len(rsa_key.private_pem()),
        "ecc_public_spki_der_uncompressed": len(ecc_key.public_der(False)),
        "ecc_public_spki_der_compressed": len(ecc_key.public_der(True)),
        "ecc_public_sec1_uncompressed": len(ecc_key.public_bytes(False)),
        "ecc_public_sec1_compressed": len(ecc_key.public_bytes(True)),
        "ecc_public_pem": len(ecc_key.public_pem()),
        "ecc_private_pkcs8_der": len(ecc_key.private_der()),
        "ecc_private_pkcs8_pem": len(ecc_key.private_pem()),
        "ecc_private_raw_scalar": len(ecc_key.private_raw()),
    }
    # Reductions: each compares like with like (same serialization family).
    red = {
        "public_spki_der_uncompressed": reduction_pct(ser["rsa_public_spki_der"], ser["ecc_public_spki_der_uncompressed"]),
        "public_spki_der_compressed": reduction_pct(ser["rsa_public_spki_der"], ser["ecc_public_spki_der_compressed"]),
        "public_pem": reduction_pct(ser["rsa_public_pem"], ser["ecc_public_pem"]),
        "public_math_uncompressed": reduction_pct(math["rsa_public_bits"], math["ecc_public_uncompressed_bits"]),
        "public_math_compressed": reduction_pct(math["rsa_public_bits"], math["ecc_public_compressed_bits"]),
        "private_pkcs8_der": reduction_pct(ser["rsa_private_pkcs8_der"], ser["ecc_private_pkcs8_der"]),
        "private_math_crt_vs_scalar": reduction_pct(math["rsa_private_crt_bits"], math["ecc_private_bits"]),
        "private_math_d_vs_scalar": reduction_pct(math["rsa_private_min_bits"], math["ecc_private_bits"]),
    }
    return {"level": level, "rsa_bits": sl.rsa_bits, "curve": sl.curve,
            "mathematical_bits": math, "serialized_bytes": ser, "reduction_percent": red}


def measure_all(levels=None, rsa_backend="openssl") -> list:
    return [measure_level(l, rsa_backend=rsa_backend) for l in (levels or sorted(SECURITY_LEVELS))]


def format_table(results: list) -> str:
    """Plain-text table of the headline serialized comparison."""
    hdr = (f"{'Level':>6} {'RSA':>9} {'ECC':>6} | {'RSA pub':>8} {'ECC pub':>8} {'ECC pub':>8} {'red.%':>6} {'red.%':>6}"
           f" | {'RSA priv':>9} {'ECC priv':>9} {'red.%':>6}")
    sub = (f"{'':>6} {'':>9} {'':>6} | {'SPKI':>8} {'unc.':>8} {'comp.':>8} {'unc.':>6} {'comp.':>6}"
           f" | {'PKCS#8':>9} {'PKCS#8':>9} {'':>6}")
    rows = [hdr, sub, "-" * len(hdr)]
    for r in results:
        s, d = r["serialized_bytes"], r["reduction_percent"]
        rows.append(
            f"{r['level']:>6} {'RSA-' + str(r['rsa_bits']):>9} {r['curve']:>6} | "
            f"{s['rsa_public_spki_der']:>8} {s['ecc_public_spki_der_uncompressed']:>8} "
            f"{s['ecc_public_spki_der_compressed']:>8} {d['public_spki_der_uncompressed']:>6.1f} "
            f"{d['public_spki_der_compressed']:>6.1f} | {s['rsa_private_pkcs8_der']:>9} "
            f"{s['ecc_private_pkcs8_der']:>9} {d['private_pkcs8_der']:>6.1f}")
    rows.append("(all sizes in bytes; DER encodings; red.% = (RSA-ECC)/RSA*100)")
    return "\n".join(rows)
