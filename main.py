#!/usr/bin/env python
"""
main.py - command-line interface for the RSA vs ECC comparison project.

Run with a Python that can import SageMath (e.g. the venv from the README, or
`sage -python main.py ...`).

    python main.py                 # default: side-by-side demo, RSA-3072 vs P-256
    python main.py demo [--level 128] [--message "text"]
    python main.py interactive     # menu: choose algorithm, keys, encrypt, decrypt ...
    python main.py math            # ECC mathematics demo (field, curve, G, add, double, kG, ECDLP)
    python main.py keysizes        # key-size analysis table
    python main.py benchmark [--profile quick|full]
    python main.py graphs          # regenerate the 7 PNG graphs from results/
    python main.py all [--profile ...]   # keysizes + benchmark + graphs
"""

import argparse
import base64
import json
import sys
import time
from pathlib import Path

from common import DEFAULT_LEVEL, SECURITY_LEVELS, DecryptionError

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
GRAPHS = ROOT / "graphs"
DEFAULT_MESSAGE = "Elliptic curves give the same security with far smaller keys. ✓ café π"


def hexdump(b: bytes, width: int = 32, max_lines: int = 6) -> str:
    lines = [b[i:i + width].hex(" ") for i in range(0, len(b), width)]
    if len(lines) > max_lines:
        lines = lines[:max_lines] + [f"... ({len(b)} bytes total)"]
    return "\n      ".join(lines)


def ms(t0):
    return (time.perf_counter() - t0) * 1000


# ----------------------------------------------------------------------------
# Demonstrations
# ----------------------------------------------------------------------------


def demo(level: int = DEFAULT_LEVEL, message: str = DEFAULT_MESSAGE, backend: str = "openssl"):
    """Run RSA and ECC on the SAME message and print a side-by-side comparison."""
    from ecc import ECCKeyPair
    from ecies import ecies_decrypt, ecies_encrypt, ecies_overhead
    from keysizes import measure_level
    from rsa import (generate_rsa_keypair, oaep_max_plaintext, rsa_hybrid_decrypt,
                     rsa_hybrid_encrypt, rsa_hybrid_overhead)

    sl = SECURITY_LEVELS[level]
    msg = message.encode("utf-8")
    print(f"=== RSA-{sl.rsa_bits} (RSA-OAEP + AES-256-GCM)  vs  {sl.curve} (ECIES-style) "
          f"- approx. {level}-bit classical security ===")
    print(f"Message ({len(msg)} bytes): {message!r}\n")

    from ecc import get_curve
    get_curve(sl.curve)                      # one-time Sage curve construction is setup, not keygen
    t = time.perf_counter()
    rk = generate_rsa_keypair(sl.rsa_bits, "sage")
    t_rsa_kg = ms(t)
    t = time.perf_counter()
    ek = ECCKeyPair.generate(sl.curve, "sage")
    t_ecc_kg = ms(t)

    rsa_pub_sz = len(rk.public_der())
    ecc_pub = ek.public_bytes(False)

    t = time.perf_counter()
    rct = rsa_hybrid_encrypt(rk, msg, backend)
    t_rsa_enc = ms(t)
    t = time.perf_counter()
    rpt = rsa_hybrid_decrypt(rk, rct, backend)
    t_rsa_dec = ms(t)

    t = time.perf_counter()
    ect = ecies_encrypt(sl.curve, ecc_pub, msg, backend)
    t_ecc_enc = ms(t)
    t = time.perf_counter()
    ept = ecies_decrypt(ek, ect, backend)
    t_ecc_dec = ms(t)

    ks = measure_level(level, rk, ek)
    s = ks["serialized_bytes"]
    ro, eo = rsa_hybrid_overhead(rk.bits), ecies_overhead(sl.curve)
    w = 30
    rows = [
        ("", f"RSA-{sl.rsa_bits}", sl.curve),
        ("Public key, SPKI DER (bytes)", s["rsa_public_spki_der"], s["ecc_public_spki_der_uncompressed"]),
        ("Public key, compressed (bytes)", "n/a", s["ecc_public_spki_der_compressed"]),
        ("Private key, PKCS#8 DER (bytes)", s["rsa_private_pkcs8_der"], s["ecc_private_pkcs8_der"]),
        ("Key generation, one run (ms)*", f"{t_rsa_kg:.1f}", f"{t_ecc_kg:.2f}"),
        ("Encrypt, one run (ms)*", f"{t_rsa_enc:.3f}", f"{t_ecc_enc:.3f}"),
        ("Decrypt, one run (ms)*", f"{t_rsa_dec:.3f}", f"{t_ecc_dec:.3f}"),
        ("Key encapsulation (bytes)", ro["encapsulated_key"], eo["encapsulated_key"]),
        ("Nonce + tag (bytes)", ro["nonce"] + ro["tag"], eo["nonce"] + eo["tag"]),
        ("Total ciphertext (bytes)", len(rct), len(ect)),
        ("Plaintext recovered?", rpt == msg, ept == msg),
    ]
    for label, a, b in rows:
        print(f"  {label:<{w + 2}}{str(a):>14}{str(b):>14}")
    print("  * single un-averaged runs (Sage keygen / selected backend); use `benchmark` for statistics.\n")
    print("RSA ciphertext:")
    print("      " + hexdump(rct))
    print("ECC ciphertext (R || nonce || ct || tag):")
    print("      " + hexdump(ect))
    print(f"\nRSA-OAEP alone can encrypt at most {oaep_max_plaintext(rk.bits)} bytes with RSA-{rk.bits}; "
          "the hybrid scheme removes that limit.")
    red = ks["reduction_percent"]
    print(f"ECC public key is {red['public_spki_der_uncompressed']:.1f}% smaller (uncompressed SPKI) / "
          f"{red['public_spki_der_compressed']:.1f}% smaller (compressed SPKI) than RSA's; "
          f"private key {red['private_pkcs8_der']:.1f}% smaller (PKCS#8).")
    assert rpt == msg and ept == msg
    return True


def math_demo():
    """Walk through the ECC mathematics on the real NIST P-256 parameters."""
    from common import csprng_randbelow
    from ecc import bsgs, get_curve, toy_curve

    c = get_curve("P-256")
    print("=== Elliptic-curve mathematics on NIST P-256 (secp256r1) ===")
    print(f"Finite field  F_p, p = 2^256 - 2^224 + 2^192 + 2^96 - 1\n  p = {hex(c.p)}")
    print(f"Curve         E: y^2 = x^3 + a*x + b over F_p\n  a = p - 3 = -3 (mod p)\n  b = {hex(c.b)}")
    print(f"Base point    G = (\n  {hex(int(c.G.xy()[0]))},\n  {hex(int(c.G.xy()[1]))})")
    print(f"Order of G    n = {hex(c.n)}   ({c.order_bits} bits, prime), cofactor h = {c.h}")
    print("\nVerifying the domain parameters (Sage):")
    for k, v in c.verify_domain_parameters(full_order=True).items():
        print(f"  [{'ok' if v else 'FAIL'}] {k}")

    G = c.G
    print("\nGroup law (explicit affine formulas, cross-checked against Sage's built-in group law):")
    P2 = c.point_double(G)
    print(f"  2G (doubling)   : x = {hex(int(P2.xy()[0]))[:30]}...   matches Sage: {P2 == 2 * G}")
    P3 = c.point_add(P2, G)
    print(f"  3G = 2G + G     : x = {hex(int(P3.xy()[0]))[:30]}...   matches Sage: {P3 == 3 * G}")
    print(f"  G + (-G) = O    : {c.point_add(G, -G) == c.E(0)}   (identity: the point at infinity)")
    k = 1 + csprng_randbelow(int(c.n) - 1)
    t = time.perf_counter()
    kG = c.scalar_mult(k)
    t_dbl = ms(t)
    t = time.perf_counter()
    kG2 = k * G
    t_sage = ms(t)
    print(f"  kG for a random 256-bit k (not printed): double-and-add == Sage k*G: {kG == kG2} "
          f"({t_dbl:.1f} ms explicit vs {t_sage:.2f} ms Sage)")
    print(f"  n*G = O         : {c.n * G == c.E(0)}   ((n+1)G = G: {(c.n + 1) * G == G})")

    print("\nECDLP: given Q = dG, find d.  Best generic attack (BSGS / Pollard rho) costs ~sqrt(n).")
    print("Demonstration on small TOY curves (random prime-order curves - NOT P-256):")
    print(f"  {'bits':>5} {'group order n':>16} {'sqrt(n)':>10} {'BSGS time (s)':>14}")
    for bits in (16, 20, 24, 28, 32):
        E, g, n = toy_curve(bits, seed=bits)
        d = 1 + csprng_randbelow(n - 1)
        t = time.perf_counter()
        found = bsgs(E, g, d * g, n)
        dt = time.perf_counter() - t
        assert found == d
        print(f"  {bits:>5} {n:>16} {int(n ** 0.5):>10} {dt:>14.3f}")
    print(f"  Each +4 bits multiplies the work ~4x (= sqrt(2^4)).  For P-256: sqrt(n) ~ 2^128 steps - infeasible.")


def keysizes_cmd(levels=None, save=True):
    from keysizes import format_table, measure_all
    res = measure_all(levels)
    print(format_table(res))
    print("\nMathematical sizes (bits) for each level:")
    for r in res:
        m = r["mathematical_bits"]
        print(f"  RSA-{r['rsa_bits']:<5}: public (n,e) {m['rsa_public_bits']} b, private d {m['rsa_private_min_bits']} b "
              f"(all CRT parameters {m['rsa_private_crt_bits']} b) | {r['curve']}: public point "
              f"{m['ecc_public_uncompressed_bits']} b (compressed {m['ecc_public_compressed_bits']} b), "
              f"private scalar {m['ecc_private_bits']} b")
    if save:
        RESULTS.mkdir(exist_ok=True)
        (RESULTS / "key_sizes.json").write_text(json.dumps(res, indent=1))
    return res


def benchmark_cmd(profile="full"):
    import benchmark
    from keysizes import format_table
    data = benchmark.run_all(profile, str(RESULTS))
    (RESULTS / "results_summary.md").write_text(benchmark.markdown_report(data))
    for be in ("openssl", "sage"):
        for size in (32, 1024, 102400):
            print(benchmark.format_summary(data, be, size), "\n")
    print(format_table(data["key_sizes"]))
    print(f"\nResults written to {RESULTS / 'benchmark_results.json'} "
          f"({data['meta']['elapsed_seconds']} s)")
    return data


def graphs_cmd():
    import visualization
    f = RESULTS / "benchmark_results.json"
    if not f.exists():
        sys.exit("No results yet - run `python main.py benchmark` first.")
    GRAPHS.mkdir(exist_ok=True)
    for p in visualization.generate_all(str(f), str(GRAPHS)):
        print("wrote", p)


# ----------------------------------------------------------------------------
# Interactive mode
# ----------------------------------------------------------------------------


def interactive():
    from ecc import ECCKeyPair
    from ecies import ecies_decrypt, ecies_encrypt
    from rsa import (generate_rsa_keypair, oaep_max_plaintext, rsa_hybrid_decrypt,
                     rsa_hybrid_encrypt, rsa_oaep_decrypt, rsa_oaep_encrypt)

    state = {"algo": "ECC", "level": DEFAULT_LEVEL, "keys": {}, "ct": None, "pt": None, "mode": "hybrid"}

    def keys():
        return state["keys"].get((state["algo"], state["level"]))

    def menu():
        sl = SECURITY_LEVELS[state["level"]]
        cfg = f"RSA-{sl.rsa_bits}" if state["algo"] == "RSA" else sl.curve
        print(f"\n--- RSA vs ECC  |  algorithm: {cfg}  (level {state['level']}-bit)  "
              f"|  keys: {'yes' if keys() else 'no'} ---")
        print(" 1) Select algorithm (RSA / ECC)      2) Select security level")
        print(" 3) Generate key pair                 4) Show public/private key sizes")
        print(" 5) Enter plaintext + encrypt         6) Show ciphertext")
        print(" 7) Decrypt + verify                  8) Side-by-side comparison demo")
        print(" 9) Run benchmarks (quick)           10) Generate graphs")
        print(" 0) Quit")

    while True:
        menu()
        try:
            c = input("> ").strip()
        except EOFError:
            break
        sl = SECURITY_LEVELS[state["level"]]
        try:
            if c == "0":
                break
            elif c == "1":
                a = input("RSA or ECC? ").strip().upper()
                if a in ("RSA", "ECC"):
                    state["algo"] = a
            elif c == "2":
                l = int(input(f"Level {sorted(SECURITY_LEVELS)}: "))
                if l in SECURITY_LEVELS:
                    state["level"] = l
            elif c == "3":
                t = time.perf_counter()
                if state["algo"] == "RSA":
                    k = generate_rsa_keypair(sl.rsa_bits, "openssl" if sl.rsa_bits > 4096 else "sage")
                else:
                    k = ECCKeyPair.generate(sl.curve)
                state["keys"][(state["algo"], state["level"])] = k
                print(f"Generated {k} in {ms(t):.1f} ms (private key is never displayed)")
            elif c == "4":
                k = keys()
                if not k:
                    print("Generate keys first (option 3).")
                    continue
                if state["algo"] == "RSA":
                    print(f"RSA-{k.bits}: public key SPKI DER {len(k.public_der())} bytes "
                          f"({len(k.public_der()) * 8} bits), PEM {len(k.public_pem())} bytes; "
                          f"private PKCS#8 DER {len(k.private_der())} bytes")
                else:
                    print(f"{k.curve.name}: public SPKI DER {len(k.public_der())} B uncompressed / "
                          f"{len(k.public_der(True))} B compressed; raw point {len(k.public_bytes())} / "
                          f"{len(k.public_bytes(True))} B; private PKCS#8 DER {len(k.private_der())} B "
                          f"(raw scalar {len(k.private_raw())} B)")
            elif c == "5":
                k = keys()
                if not k:
                    print("Generate keys first (option 3).")
                    continue
                msg = input("Plaintext: ").encode("utf-8")
                state["pt"] = msg
                if state["algo"] == "RSA":
                    lim = oaep_max_plaintext(k.bits)
                    if len(msg) <= lim and input(f"Use plain RSA-OAEP (max {lim} B)? [y/N] ").lower() == "y":
                        state["ct"], state["mode"] = rsa_oaep_encrypt(k, msg), "oaep"
                    else:
                        state["ct"], state["mode"] = rsa_hybrid_encrypt(k, msg), "hybrid"
                else:
                    state["ct"] = ecies_encrypt(sl.curve, k.public_bytes(), msg)
                print(f"Encrypted {len(msg)} bytes -> {len(state['ct'])} bytes ({state['mode'] if state['algo'] == 'RSA' else 'ECIES-style'})")
            elif c == "6":
                if not state["ct"]:
                    print("Nothing encrypted yet.")
                    continue
                print("hex:\n      " + hexdump(state["ct"]))
                print("base64:", base64.b64encode(state["ct"]).decode()[:96] + ("..." if len(state["ct"]) > 72 else ""))
            elif c == "7":
                k = keys()
                if not (k and state["ct"]):
                    print("Need keys and a ciphertext (options 3, 5).")
                    continue
                if state["algo"] == "RSA":
                    pt = (rsa_oaep_decrypt(k, state["ct"]) if state["mode"] == "oaep"
                          else rsa_hybrid_decrypt(k, state["ct"]))
                else:
                    pt = ecies_decrypt(k, state["ct"])
                print("Decrypted:", pt.decode("utf-8", "replace"))
                print("Matches original plaintext:", pt == state["pt"])
            elif c == "8":
                demo(state["level"], input("Message (blank = default): ") or DEFAULT_MESSAGE)
            elif c == "9":
                benchmark_cmd("quick")
            elif c == "10":
                graphs_cmd()
            else:
                print("Unknown option.")
        except DecryptionError:
            print("Decryption/authentication FAILED (as designed for invalid or modified data).")
        except (ValueError, KeyboardInterrupt) as e:
            print(f"Error: {e}")


# ----------------------------------------------------------------------------


def main(argv=None):
    ap = argparse.ArgumentParser(description="RSA vs ECC comparison (SageMath)")
    sub = ap.add_subparsers(dest="cmd")
    d = sub.add_parser("demo", help="side-by-side demonstration (default)")
    d.add_argument("--level", type=int, default=DEFAULT_LEVEL, choices=sorted(SECURITY_LEVELS))
    d.add_argument("--message", default=DEFAULT_MESSAGE)
    d.add_argument("--backend", default="openssl", choices=["openssl", "sage"])
    sub.add_parser("interactive", help="interactive menu")
    sub.add_parser("math", help="ECC mathematics demonstration")
    sub.add_parser("keysizes", help="key-size analysis")
    for name in ("benchmark", "all"):
        b = sub.add_parser(name)
        b.add_argument("--profile", choices=["quick", "full"], default="full")
    sub.add_parser("graphs", help="generate PNG graphs from results/")
    a = ap.parse_args(argv)

    cmd = a.cmd or "demo"
    if cmd == "demo":
        demo(getattr(a, "level", DEFAULT_LEVEL), getattr(a, "message", DEFAULT_MESSAGE),
             getattr(a, "backend", "openssl"))
    elif cmd == "interactive":
        interactive()
    elif cmd == "math":
        math_demo()
    elif cmd == "keysizes":
        keysizes_cmd()
    elif cmd == "benchmark":
        benchmark_cmd(a.profile)
    elif cmd == "graphs":
        graphs_cmd()
    elif cmd == "all":
        keysizes_cmd()
        benchmark_cmd(a.profile)
        graphs_cmd()


if __name__ == "__main__":
    main()
