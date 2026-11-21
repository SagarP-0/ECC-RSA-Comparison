"""
benchmark.py - performance benchmarks for RSA-OAEP hybrid vs ECIES-style hybrid.

Methodology (see README for discussion)
---------------------------------------
* Clock: time.perf_counter_ns (monotonic, highest resolution).  Garbage
  collection is disabled inside the timed loop.
* Key generation is benchmarked SEPARATELY from encryption/decryption.
  Keys for the enc/dec benchmarks are created once, outside any timer.
* All imports, curve construction (Sage EllipticCurve / GF) and key
  conversions happen during setup; every timed callable is also executed
  `warmup` times first and those runs are discarded.
* The SAME plaintext bytes are used for RSA and ECC (deterministic, derived
  from SHA-256 in counter mode; plaintexts are not secret).
* Compared constructions:
      RSA : RSA-OAEP(SHA-256) transports a random AES-256 key; AES-256-GCM
      ECC : ephemeral ECDH + HKDF-SHA256 + AES-256-GCM  (ECIES-style)
  and each is run with two interchangeable backends for the public-key step:
      "openssl": cryptography/OpenSSL (primary, production-grade)
      "sage"   : SageMath arithmetic (educational implementation)
  Backends are never mixed in a single comparison row.
* Reported: mean, median, standard deviation (sample), min, max, in
  milliseconds, with the repetition count.  Where fewer than 100 repetitions
  are used (very slow operations such as RSA-15360 key generation) the count
  is recorded so the report can flag it.
* Ciphertext sizes are measured from the actual outputs, not computed.
* Nothing secret (keys, shared secrets) is ever printed.
"""

import gc
import hashlib
import json
import platform
import statistics
import sys
import time
from pathlib import Path

from common import SECURITY_LEVELS
from ecc import ECCKeyPair, get_curve
from ecies import ecies_decrypt, ecies_encrypt
from rsa import (RSAKeyPair, generate_rsa_keypair, rsa_hybrid_decrypt, rsa_hybrid_encrypt)

PLAINTEXT_SIZES = [32, 128, 1024, 10 * 1024, 100 * 1024]   # bytes

# Repetition plans.  "full" meets the >=100 target wherever practical.
PROFILES = {
    "full": {
        "levels": [112, 128, 192, 256],
        # enc/dec repetitions per level
        "reps": {112: 100, 128: 100, 192: 100, 256: 50},
        # key generation repetitions per (backend, level): RSA-7680/15360 are minutes-long
        "keygen_reps": {"openssl": {112: 100, 128: 100, 192: 10, 256: 3},
                        "sage": {112: 100, 128: 30, 192: 0, 256: 0}},
        "warmup": 3,
    },
    "quick": {
        "levels": [112, 128],
        "reps": {112: 20, 128: 20},
        "keygen_reps": {"openssl": {112: 10, 128: 10}, "sage": {112: 5, 128: 3}},
        "warmup": 2,
    },
}


def make_plaintext(size: int) -> bytes:
    """Deterministic pseudo-random bytes: identical for every algorithm/run."""
    out, ctr = bytearray(), 0
    while len(out) < size:
        out += hashlib.sha256(b"benchmark-plaintext" + ctr.to_bytes(4, "big")).digest()
        ctr += 1
    return bytes(out[:size])


def time_callable(fn, reps: int, warmup: int = 3) -> dict:
    """Time `fn()` `reps` times (after `warmup` discarded runs); stats in ms."""
    for _ in range(warmup):
        fn()
    samples = []
    gc.collect()
    gc.disable()
    try:
        for _ in range(reps):
            t0 = time.perf_counter_ns()
            fn()
            samples.append((time.perf_counter_ns() - t0) / 1e6)
    finally:
        gc.enable()
    return {
        "reps": reps,
        "mean_ms": statistics.fmean(samples),
        "median_ms": statistics.median(samples),
        "stdev_ms": statistics.stdev(samples) if len(samples) > 1 else 0.0,
        "min_ms": min(samples),
        "max_ms": max(samples),
    }


def _log(msg):
    print(msg, file=sys.stderr, flush=True)


def benchmark_keygen(profile: dict, sizes_log=_log) -> list:
    rows = []
    for backend in ("openssl", "sage"):
        for level in profile["levels"]:
            reps = profile["keygen_reps"][backend].get(level, 0)
            if reps <= 0:
                continue
            sl = SECURITY_LEVELS[level]
            # Pre-touch Sage curve construction so it is not billed to keygen.
            get_curve(sl.curve)
            rsa_stats = time_callable(lambda: generate_rsa_keypair(sl.rsa_bits, backend),
                                      reps, warmup=1)
            ecc_stats = time_callable(lambda: ECCKeyPair.generate(sl.curve, backend),
                                      max(reps, 100), warmup=3)   # ECC keygen is cheap: >=100 reps
            for algo, label, st in (("RSA", f"RSA-{sl.rsa_bits}", rsa_stats),
                                    ("ECC", sl.curve, ecc_stats)):
                rows.append({"operation": "keygen", "backend": backend, "level": level,
                             "algorithm": algo, "config": label, **st})
            sizes_log(f"keygen {backend} level {level}: RSA {rsa_stats['median_ms']:.1f} ms "
                      f"(n={reps}), ECC {ecc_stats['median_ms']:.3f} ms")
    return rows


def benchmark_encdec(profile: dict, sizes_log=_log) -> list:
    rows = []
    warm = profile["warmup"]
    plaintexts = {s: make_plaintext(s) for s in PLAINTEXT_SIZES}
    for level in profile["levels"]:
        sl = SECURITY_LEVELS[level]
        reps = profile["reps"][level]
        # Keys made once, outside every timer.  (OpenSSL keygen for RSA because
        # Sage's pure search would take minutes at 7680/15360 bits; the key is
        # then wrapped in the same RSAKeyPair class used by both backends.)
        rsa_key = generate_rsa_keypair(sl.rsa_bits, "openssl")
        ecc_key = ECCKeyPair.generate(sl.curve, "sage")
        ecc_pub = ecc_key.public_bytes(False)
        for backend in ("openssl", "sage"):
            for size, pt in plaintexts.items():
                # Pre-generate ciphertexts for the decrypt timers.
                rsa_ct = rsa_hybrid_encrypt(rsa_key, pt, backend)
                ecc_ct = ecies_encrypt(sl.curve, ecc_pub, pt, backend)
                assert rsa_hybrid_decrypt(rsa_key, rsa_ct, backend) == pt
                assert ecies_decrypt(ecc_key, ecc_ct, backend) == pt

                ops = {
                    "RSA": {
                        "encrypt": lambda: rsa_hybrid_encrypt(rsa_key, pt, backend),
                        "decrypt": lambda: rsa_hybrid_decrypt(rsa_key, rsa_ct, backend),
                        "roundtrip": lambda: rsa_hybrid_decrypt(
                            rsa_key, rsa_hybrid_encrypt(rsa_key, pt, backend), backend),
                    },
                    "ECC": {
                        "encrypt": lambda: ecies_encrypt(sl.curve, ecc_pub, pt, backend),
                        "decrypt": lambda: ecies_decrypt(ecc_key, ecc_ct, backend),
                        "roundtrip": lambda: ecies_decrypt(
                            ecc_key, ecies_encrypt(sl.curve, ecc_pub, pt, backend), backend),
                    },
                }
                for algo, label, ct in (("RSA", f"RSA-{sl.rsa_bits}", rsa_ct),
                                        ("ECC", sl.curve, ecc_ct)):
                    for op, fn in ops[algo].items():
                        st = time_callable(fn, reps, warm)
                        rows.append({"operation": op, "backend": backend, "level": level,
                                     "algorithm": algo, "config": label, "plaintext_bytes": size,
                                     "ciphertext_bytes": len(ct),
                                     "overhead_bytes": len(ct) - size, **st})
            sizes_log(f"enc/dec level {level} backend {backend} done "
                      f"({sl.rsa_bits}-bit RSA vs {sl.curve}, {reps} reps)")
    return rows


def run_all(profile_name: str = "full", out_dir: str = "results", sizes_log=_log) -> dict:
    """Run every benchmark and write results/benchmark_results.json."""
    from keysizes import measure_all
    profile = PROFILES[profile_name]
    t0 = time.time()
    data = {
        "meta": {
            "profile": profile_name,
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "processor_count": __import__("os").cpu_count(),
            "plaintext_sizes": PLAINTEXT_SIZES,
            "timestamp_utc": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
            "profile_settings": {k: (v if not isinstance(v, dict) else {str(a): b for a, b in v.items()})
                                 for k, v in profile.items()},
        },
        "key_sizes": measure_all(profile["levels"]),
        "keygen": benchmark_keygen(profile, sizes_log),
        "encdec": benchmark_encdec(profile, sizes_log),
    }
    data["meta"]["elapsed_seconds"] = round(time.time() - t0, 1)
    try:
        import cryptography
        import sage.version
        data["meta"]["cryptography"] = cryptography.__version__
        data["meta"]["sage"] = sage.version.version
    except Exception:
        pass
    Path(out_dir).mkdir(exist_ok=True)
    with open(Path(out_dir) / "benchmark_results.json", "w") as f:
        json.dump(data, f, indent=1)
    return data


def format_summary(data: dict, backend: str = "openssl", size: int = 1024) -> str:
    """Compact text summary (medians) of a results dict."""
    lines = [f"Backend: {backend}   plaintext: {size} bytes   (median ms, n in brackets)",
             f"{'level':>6} {'config':>10} {'keygen':>16} {'encrypt':>16} {'decrypt':>16} {'roundtrip':>16} {'ct bytes':>9}"]
    kg = {(r["backend"], r["level"], r["algorithm"]): r for r in data["keygen"]}
    ed = {(r["backend"], r["level"], r["algorithm"], r["operation"], r["plaintext_bytes"]): r
          for r in data["encdec"]}
    for level in data["meta"]["profile_settings"]["levels"]:
        for algo in ("RSA", "ECC"):
            k = kg.get((backend, level, algo))
            cells = [f"{k['median_ms']:.3f} [{k['reps']}]" if k else "-"]
            ctb = "-"
            cfg = ""
            for op in ("encrypt", "decrypt", "roundtrip"):
                r = ed.get((backend, level, algo, op, size))
                if r:
                    cells.append(f"{r['median_ms']:.3f} [{r['reps']}]")
                    ctb, cfg = r["ciphertext_bytes"], r["config"]
                else:
                    cells.append("-")
            lines.append(f"{level:>6} {cfg:>10} " + " ".join(f"{c:>16}" for c in cells) + f" {ctb:>9}")
    return "\n".join(lines)


def markdown_report(data: dict) -> str:
    """Render all measured results as Markdown tables (used for results/results_summary.md)."""
    from common import SECURITY_LEVELS
    out = []
    meta = data["meta"]
    out.append(f"*Run: {meta['timestamp_utc']} UTC, profile `{meta['profile']}`, Python {meta['python']}, "
               f"SageMath {meta.get('sage', '?')}, cryptography {meta.get('cryptography', '?')}, "
               f"{meta['processor_count']} CPUs, {meta['platform']}; total {meta['elapsed_seconds']} s.*\n")

    # ---- key sizes ----
    out.append("#### Serialized key sizes (bytes) and reduction of ECC relative to RSA\n")
    out.append("| Security | RSA | ECC | RSA public (SPKI DER) | ECC public (SPKI, uncompressed) | ECC public (SPKI, compressed) | Reduction (unc. / comp.) "
               "| RSA private (PKCS#8 DER) | ECC private (PKCS#8 DER) | Reduction | ECC raw scalar |")
    out.append("|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|")
    for k in data["key_sizes"]:
        s, r = k["serialized_bytes"], k["reduction_percent"]
        out.append(f"| {k['level']}-bit | RSA-{k['rsa_bits']} | {k['curve']} | {s['rsa_public_spki_der']} | "
                   f"{s['ecc_public_spki_der_uncompressed']} | {s['ecc_public_spki_der_compressed']} | "
                   f"{r['public_spki_der_uncompressed']:.1f}% / {r['public_spki_der_compressed']:.1f}% | "
                   f"{s['rsa_private_pkcs8_der']} | {s['ecc_private_pkcs8_der']} | {r['private_pkcs8_der']:.1f}% | "
                   f"{s['ecc_private_raw_scalar']} |")
    out.append("\n#### Other serialized forms (bytes)\n")
    out.append("| Security | RSA public PKCS#1 `{n,e}` | RSA public PEM | ECC public PEM | ECC SEC1 point (unc. / comp.) | RSA private PEM | ECC private PEM |")
    out.append("|---|---:|---:|---:|---:|---:|---:|")
    for k in data["key_sizes"]:
        s = k["serialized_bytes"]
        out.append(f"| {k['level']}-bit | {s['rsa_public_pkcs1_der']} | {s['rsa_public_pem']} | {s['ecc_public_pem']} | "
                   f"{s['ecc_public_sec1_uncompressed']} / {s['ecc_public_sec1_compressed']} | "
                   f"{s['rsa_private_pkcs8_pem']} | {s['ecc_private_pkcs8_pem']} |")
    out.append("\n#### Mathematical key sizes (bits)\n")
    out.append("| Security | RSA public (n, e) | RSA private d | RSA private, all CRT parameters | ECC public point (unc. / comp.) | ECC private scalar | "
               "Reduction, public (unc. / comp.) | Reduction, private (d vs scalar) |")
    out.append("|---|---:|---:|---:|---:|---:|---:|---:|")
    for k in data["key_sizes"]:
        m, r = k["mathematical_bits"], k["reduction_percent"]
        out.append(f"| {k['level']}-bit | {m['rsa_public_bits']} | {m['rsa_private_min_bits']} | {m['rsa_private_crt_bits']} | "
                   f"{m['ecc_public_uncompressed_bits']} / {m['ecc_public_compressed_bits']} | {m['ecc_private_bits']} | "
                   f"{r['public_math_uncompressed']:.1f}% / {r['public_math_compressed']:.1f}% | {r['private_math_d_vs_scalar']:.1f}% |")

    kg = {(r["backend"], r["level"], r["algorithm"]): r for r in data["keygen"]}
    ed = {(r["backend"], r["level"], r["algorithm"], r["operation"], r["plaintext_bytes"]): r for r in data["encdec"]}
    levels = meta["profile_settings"]["levels"]

    def cell(r, f="{:.3f}"):
        return (f.format(r["median_ms"]) + f" ± {f.format(r['stdev_ms'])}") if r else "-"

    for backend, title in (("openssl", "OpenSSL backend (`cryptography`) - primary comparison"),
                           ("sage", "SageMath backend (own OAEP / elliptic-curve arithmetic) - educational implementation")):
        out.append(f"\n#### Key generation - {title}\n")
        out.append("| Security | Config | Repetitions | Mean (ms) | Median (ms) | Std. dev. (ms) | Min (ms) | Max (ms) |")
        out.append("|---|---|---:|---:|---:|---:|---:|---:|")
        for level in levels:
            for algo in ("RSA", "ECC"):
                r = kg.get((backend, level, algo))
                if r:
                    out.append(f"| {level}-bit | {r['config']} | {r['reps']} | {r['mean_ms']:.3f} | {r['median_ms']:.3f} | "
                               f"{r['stdev_ms']:.3f} | {r['min_ms']:.3f} | {r['max_ms']:.3f} |")
        for op in ("encrypt", "decrypt", "roundtrip"):
            label = {"encrypt": "Encryption", "decrypt": "Decryption",
                     "roundtrip": "Total encrypt + decrypt (one timed call)"}[op]
            out.append(f"\n#### {label} time, median ± std. dev. (ms) - {title}\n")
            sizes = meta["plaintext_sizes"]
            out.append("| Security | Config | Reps | " + " | ".join(
                {32: "32 B", 128: "128 B", 1024: "1 KB", 10240: "10 KB", 102400: "100 KB"}[s] for s in sizes) + " |")
            out.append("|---|---|---:|" + "---:|" * len(sizes))
            for level in levels:
                for algo in ("RSA", "ECC"):
                    rs = [ed.get((backend, level, algo, op, s)) for s in sizes]
                    if rs[0]:
                        out.append(f"| {level}-bit | {rs[0]['config']} | {rs[0]['reps']} | " +
                                   " | ".join(cell(r) for r in rs) + " |")
    out.append("\n#### Mean encrypt / decrypt / round-trip (ms) at 1 KB, OpenSSL backend\n")
    out.append("| Security | Config | Encrypt mean | Decrypt mean | Round-trip mean | Keygen mean | One-shot total (keygen + round-trip) |")
    out.append("|---|---|---:|---:|---:|---:|---:|")
    for level in levels:
        for algo in ("RSA", "ECC"):
            e, d, t = (ed.get(("openssl", level, algo, op, 1024)) for op in ("encrypt", "decrypt", "roundtrip"))
            k = kg.get(("openssl", level, algo))
            if e and d and t and k:
                out.append(f"| {level}-bit | {e['config']} | {e['mean_ms']:.3f} | {d['mean_ms']:.3f} | {t['mean_ms']:.3f} | "
                           f"{k['mean_ms']:.3f} | {k['mean_ms'] + t['mean_ms']:.3f} |")

    out.append("\n#### Communication overhead (bytes added to the plaintext; measured from actual ciphertexts)\n")
    out.append("| Security | Config | Encapsulated key material | Nonce | Tag | Total overhead | Ciphertext for 32 B | for 1 KB | for 100 KB | Overhead at 32 B | at 1 KB | at 100 KB |")
    out.append("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    from ecies import ecies_overhead
    from rsa import rsa_hybrid_overhead
    for level in levels:
        sl = SECURITY_LEVELS[level]
        for algo in ("RSA", "ECC"):
            ov = rsa_hybrid_overhead(sl.rsa_bits) if algo == "RSA" else ecies_overhead(sl.curve)
            rs = {s: ed.get(("openssl", level, algo, "encrypt", s)) for s in (32, 1024, 102400)}
            out.append(f"| {level}-bit | {rs[32]['config']} | {ov['encapsulated_key']} | {ov['nonce']} | {ov['tag']} | {ov['total']} | "
                       f"{rs[32]['ciphertext_bytes']} | {rs[1024]['ciphertext_bytes']} | {rs[102400]['ciphertext_bytes']} | "
                       f"{rs[32]['overhead_bytes'] / 32 * 100:.0f}% | {rs[1024]['overhead_bytes'] / 1024 * 100:.1f}% | "
                       f"{rs[102400]['overhead_bytes'] / 102400 * 100:.2f}% |")
    return "\n".join(out) + "\n"
