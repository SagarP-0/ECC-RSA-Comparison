"""
visualization.py - matplotlib graphs generated ONLY from measured data.

Input : results/benchmark_results.json (written by benchmark.py)
Output: graphs/*.png  (7 separate figures)

Nothing is hardcoded: every plotted number is read from the results file
(key sizes come from serialized keys that were actually generated; times and
ciphertext sizes come from actual runs).

Colour: RSA = blue, ECC = orange (colour-blind-checked pair); markers and line
styles are a second encoding so the charts also read in greyscale.
Light-theme PNGs with a white background for print/report use.
"""

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")                       # headless rendering
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter

RSA_C, ECC_C = "#2a78d6", "#eb6834"
INK, MUTED, GRID = "#1a1a19", "#6b6a63", "#e4e3dd"
COL = {"RSA": RSA_C, "ECC": ECC_C}
MARK = {"RSA": "o", "ECC": "s"}

plt.rcParams.update({
    "figure.facecolor": "white", "axes.facecolor": "white", "savefig.facecolor": "white",
    "axes.edgecolor": MUTED, "axes.labelcolor": INK, "text.color": INK,
    "xtick.color": MUTED, "ytick.color": MUTED, "axes.grid": True, "grid.color": GRID,
    "grid.linewidth": 0.8, "axes.spines.top": False, "axes.spines.right": False,
    "font.size": 10, "axes.titlesize": 12, "axes.titleweight": "bold", "legend.frameon": False,
})


def _size_fmt(v, _=None):
    if v >= 1024 * 1024:
        return f"{v / 1048576:.3g} MB"
    if v >= 1024:
        return f"{v / 1024:.3g} KB"
    return f"{v:.3g} B"


def _save(fig, path):
    fig.tight_layout()
    fig.savefig(path, dpi=160)
    plt.close(fig)
    return str(path)


def _label_bars(ax, bars, fmt="{:.0f}", pad=3):
    for b in bars:
        ax.annotate(fmt.format(b.get_height()), (b.get_x() + b.get_width() / 2, b.get_height()),
                    ha="center", va="bottom", fontsize=8, color=INK,
                    xytext=(0, pad), textcoords="offset points")


def _grouped_bars(ax, labels, series, ylabel, fmt="{:.0f}"):
    """series: list of (name, color, values) drawn side by side with a surface gap."""
    n = len(series)
    w = 0.8 / n
    for i, (name, color, vals) in enumerate(series):
        xs = [j + (i - (n - 1) / 2) * w for j in range(len(labels))]
        bars = ax.bar(xs, vals, w * 0.92, label=name, color=color, edgecolor="white", linewidth=1.5)
        _label_bars(ax, bars, fmt)
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels)
    ax.set_ylabel(ylabel)
    ax.grid(axis="x", visible=False)


def _level_labels(ks):
    return [f"{k['level']}-bit\nRSA-{k['rsa_bits']} / {k['curve']}" for k in ks]


# --------------------------------------------------------------------------
def plot_public_key_sizes(data, out):
    ks = data["key_sizes"]
    fig, ax = plt.subplots(figsize=(9, 5.2))
    _grouped_bars(ax, _level_labels(ks), [
        ("RSA - SPKI DER", RSA_C, [k["serialized_bytes"]["rsa_public_spki_der"] for k in ks]),
        ("ECC - SPKI DER, uncompressed point", ECC_C, [k["serialized_bytes"]["ecc_public_spki_der_uncompressed"] for k in ks]),
        ("ECC - SPKI DER, compressed point", "#f2a98c", [k["serialized_bytes"]["ecc_public_spki_der_compressed"] for k in ks]),
    ], "Serialized public key size (bytes)")
    ax.set_ylim(0, max(k["serialized_bytes"]["rsa_public_spki_der"] for k in ks) * 1.12)
    ax.set_title("Public key size: RSA vs ECC (X.509 SubjectPublicKeyInfo, DER)")
    ax.set_xlabel("Security level (approx. classical bits) and configuration")
    ax.legend(loc="upper left")
    return _save(fig, out / "1_public_key_sizes.png")


def plot_private_key_sizes(data, out):
    ks = data["key_sizes"]
    fig, ax = plt.subplots(figsize=(9, 5.2))
    _grouped_bars(ax, _level_labels(ks), [
        ("RSA - PKCS#8 DER (d, p, q, CRT params)", RSA_C, [k["serialized_bytes"]["rsa_private_pkcs8_der"] for k in ks]),
        ("ECC - PKCS#8 DER (scalar + public key)", ECC_C, [k["serialized_bytes"]["ecc_private_pkcs8_der"] for k in ks]),
        ("ECC - raw scalar only", "#f2a98c", [k["serialized_bytes"]["ecc_private_raw_scalar"] for k in ks]),
    ], "Serialized private key size (bytes)")
    ax.set_ylim(0, max(k["serialized_bytes"]["rsa_private_pkcs8_der"] for k in ks) * 1.12)
    ax.set_title("Private key size: RSA vs ECC (unencrypted PKCS#8 DER)")
    ax.set_xlabel("Security level (approx. classical bits) and configuration")
    ax.legend(loc="upper left")
    return _save(fig, out / "2_private_key_sizes.png")


def _series(rows, backend, level, algo, op):
    pts = sorted((r["plaintext_bytes"], r) for r in rows
                 if (r["backend"], r["level"], r["algorithm"], r["operation"]) == (backend, level, algo, op))
    return [p[0] for p in pts], [p[1] for p in pts]


def _time_vs_size(data, op, title, fname, out):
    levels = data["meta"]["profile_settings"]["levels"]
    cols = 2
    rows_n = (len(levels) + 1) // 2
    fig, axes = plt.subplots(rows_n, cols, figsize=(11, 5.4 * rows_n), squeeze=False)
    for ax, level in zip(axes.flat, levels):
        for backend, ls, alpha in (("openssl", "-", 1.0), ("sage", "--", 0.8)):
            for algo in ("RSA", "ECC"):
                xs, rs = _series(data["encdec"], backend, level, algo, op)
                if not xs:
                    continue
                med = [r["median_ms"] for r in rs]
                lo = [max(r["median_ms"] - r["stdev_ms"], r["min_ms"]) for r in rs]
                hi = [r["median_ms"] + r["stdev_ms"] for r in rs]
                cfg = rs[0]["config"]
                ax.plot(xs, med, ls, color=COL[algo], marker=MARK[algo], markersize=6, linewidth=2,
                        alpha=alpha, label=f"{cfg} ({'OpenSSL' if backend == 'openssl' else 'SageMath'})")
                ax.fill_between(xs, lo, hi, color=COL[algo], alpha=0.10, linewidth=0)
        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.xaxis.set_major_formatter(FuncFormatter(_size_fmt))
        ax.set_xticks(data["meta"]["plaintext_sizes"])
        ax.tick_params(axis="x", labelsize=8)
        ax.set_title(f"{level}-bit security level")
        ax.set_xlabel("Plaintext size")
        ax.set_ylabel(f"{op.capitalize()} time (ms, median, log)")
        ax.legend(fontsize=8, loc="upper center", bbox_to_anchor=(0.5, -0.2), ncol=2)
    for ax in list(axes.flat)[len(levels):]:
        ax.set_visible(False)
    fig.suptitle(title, fontsize=13, fontweight="bold")
    fig.tight_layout(rect=(0, 0, 1, 0.96), h_pad=3)
    fig.savefig(out / fname, dpi=160)
    plt.close(fig)
    return str(out / fname)


def plot_encryption_time(data, out):
    return _time_vs_size(data, "encrypt",
                         "Hybrid encryption time vs plaintext size (median; band = ±1 std. dev.)",
                         "3_encryption_time.png", out)


def plot_decryption_time(data, out):
    return _time_vs_size(data, "decrypt",
                         "Hybrid decryption time vs plaintext size (median; band = ±1 std. dev.)",
                         "4_decryption_time.png", out)


def plot_keygen_time(data, out):
    kg = data["keygen"]
    backends = [b for b in ("openssl", "sage") if any(r["backend"] == b for r in kg)]
    fig, axes = plt.subplots(1, len(backends), figsize=(6.2 * len(backends), 5.2), squeeze=False)
    for ax, backend in zip(axes[0], backends):
        levels = sorted({r["level"] for r in kg if r["backend"] == backend})
        by = {(r["level"], r["algorithm"]): r for r in kg if r["backend"] == backend}
        for algo, off in (("RSA", -0.08), ("ECC", 0.08)):
            xs = [i + off for i in range(len(levels))]
            ys = [by[(l, algo)]["mean_ms"] for l in levels]
            lo = [min(by[(l, algo)]["stdev_ms"], 0.95 * y) for l, y in zip(levels, ys)]  # keep log axis valid
            hi = [by[(l, algo)]["stdev_ms"] for l in levels]
            ax.errorbar(xs, ys, yerr=[lo, hi], fmt=MARK[algo], color=COL[algo], markersize=9,
                        capsize=4, elinewidth=1.4, label=f"{algo} (mean ± std. dev.)")
            for x, y, l in zip(xs, ys, levels):
                txt = f"{y / 1000:.3g} s" if y >= 1000 else f"{y:.3g} ms"
                above = algo == "RSA"                     # RSA labels above, ECC labels below the marker
                ax.annotate(f"{txt}\n(n={by[(l, algo)]['reps']})", (x, y),
                            xytext=(0, 12 if above else -12), textcoords="offset points",
                            ha="center", va="bottom" if above else "top", fontsize=8)
        ax.set_xticks(range(len(levels)))
        ax.set_xticklabels([f"{l}-bit\n{by[(l, 'RSA')]['config']}\n{by[(l, 'ECC')]['config']}" for l in levels])
        ax.set_xlim(-0.6, len(levels) - 0.4)
        ax.set_ylabel("Key generation time (ms, log scale)")
        ax.set_yscale("log")
        ax.set_ylim(bottom=ax.get_ylim()[0] / 6, top=ax.get_ylim()[1] * 4)
        ax.set_xlabel("Security level and configuration")
        ax.set_title("OpenSSL key generation" if backend == "openssl" else "SageMath key generation")
        pass
    h, l = axes[0][0].get_legend_handles_labels()
    fig.legend(h, l, loc="lower center", ncol=2, fontsize=10)
    fig.suptitle("Key generation time (mean ± std. dev.; repetition counts are in the results file)",
                 fontsize=13, fontweight="bold")
    fig.tight_layout(rect=(0, 0.07, 1, 0.95))
    p = out / "5_keygen_time.png"
    fig.savefig(p, dpi=160)
    plt.close(fig)
    return str(p)


def plot_overhead(data, out):
    levels = data["meta"]["profile_settings"]["levels"]
    ls_for = dict(zip(levels, ["-", "--", ":", "-."]))
    mk_for = dict(zip(levels, ["o", "^", "D", "v"]))
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(13, 5.4))
    for level in levels:
        for algo in ("RSA", "ECC"):
            xs, rs = _series(data["encdec"], "openssl", level, algo, "encrypt")
            ct = [r["ciphertext_bytes"] for r in rs]
            ov = [r["overhead_bytes"] / r["plaintext_bytes"] * 100 for r in rs]
            lab = f"{rs[0]['config']}"
            kw = dict(color=COL[algo], linestyle=ls_for[level], marker=mk_for[level],
                      markersize=5, linewidth=1.8, label=lab)
            a1.plot(xs, ct, **kw)
            a2.plot(xs, ov, **kw)
    xs = data["meta"]["plaintext_sizes"]
    a1.plot(xs, xs, color=MUTED, linewidth=1, linestyle=(0, (1, 3)), label="plaintext size (no overhead)")
    for ax in (a1, a2):
        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.xaxis.set_major_formatter(FuncFormatter(_size_fmt))
        ax.set_xticks(xs)
        ax.set_xlabel("Plaintext size")
    a1.yaxis.set_major_formatter(FuncFormatter(_size_fmt))
    a1.set_ylabel("Total transmitted ciphertext size (log)")
    a1.set_title("Ciphertext size vs plaintext size")
    a2.set_ylabel("Overhead = (ciphertext − plaintext) / plaintext (%, log)")
    a2.set_title("Relative communication overhead")
    a2.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:g}%"))
    a1.legend(fontsize=8, loc="upper left")
    a2.legend(fontsize=8, loc="upper right")
    fig.suptitle("Communication overhead of the hybrid constructions "
                 "(RSA = blue, ECC = orange; line style/marker = security level)",
                 fontsize=12, fontweight="bold")
    fig.tight_layout(rect=(0, 0, 1, 0.95))
    p = out / "6_ciphertext_overhead.png"
    fig.savefig(p, dpi=160)
    plt.close(fig)
    return str(p)


def plot_keysize_across_levels(data, out):
    ks = data["key_sizes"]
    sec = [k["level"] for k in ks]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(12, 5.2))
    a1.plot(sec, [k["mathematical_bits"]["rsa_modulus_bits"] for k in ks], "-o", color=RSA_C,
            linewidth=2, markersize=7, label="RSA modulus n (bits)")
    a1.plot(sec, [k["mathematical_bits"]["ecc_private_bits"] for k in ks], "-s", color=ECC_C,
            linewidth=2, markersize=7, label="ECC group order n / private scalar (bits)")
    for k in ks:
        a1.annotate(f"RSA-{k['rsa_bits']}", (k["level"], k["mathematical_bits"]["rsa_modulus_bits"]),
                    xytext=(0, 8), textcoords="offset points", ha="center", fontsize=8)
        a1.annotate(k["curve"], (k["level"], k["mathematical_bits"]["ecc_private_bits"]),
                    xytext=(0, 9), textcoords="offset points", ha="center", fontsize=8)
    a1.set_xticks(sec)
    a1.set_ylim(-600, max(k["mathematical_bits"]["rsa_modulus_bits"] for k in ks) * 1.08)
    a1.set_xlabel("Approximate classical security level (bits)")
    a1.set_ylabel("Mathematical key parameter size (bits)")
    a1.set_title("Mathematical size grows linearly (ECC) vs super-linearly (RSA)")
    a1.legend(loc="upper left")

    labels = [f"{k['level']}-bit" for k in ks]
    ratio_pub = [k["serialized_bytes"]["rsa_public_spki_der"] / k["serialized_bytes"]["ecc_public_spki_der_compressed"] for k in ks]
    ratio_priv = [k["serialized_bytes"]["rsa_private_pkcs8_der"] / k["serialized_bytes"]["ecc_private_pkcs8_der"] for k in ks]
    _grouped_bars(a2, labels, [
        ("Public key (SPKI DER, ECC compressed)", "#184f95", ratio_pub),
        ("Private key (PKCS#8 DER)", "#6da7ec", ratio_priv),
    ], "Size ratio RSA / ECC (serialized bytes, ×)", fmt="{:.1f}×")
    a2.set_xlabel("Security level")
    a2.set_title("How many times larger the RSA key is")
    a2.legend(loc="upper left")
    fig.suptitle("Key-size comparison across security levels", fontsize=13, fontweight="bold")
    fig.tight_layout(rect=(0, 0, 1, 0.95))
    p = out / "7_keysize_across_levels.png"
    fig.savefig(p, dpi=160)
    plt.close(fig)
    return str(p)


def generate_all(results_file="results/benchmark_results.json", out_dir="graphs"):
    with open(results_file) as f:
        data = json.load(f)
    out = Path(out_dir)
    out.mkdir(exist_ok=True)
    return [fn(data, out) for fn in (
        plot_public_key_sizes, plot_private_key_sizes, plot_encryption_time,
        plot_decryption_time, plot_keygen_time, plot_overhead, plot_keysize_across_levels)]


if __name__ == "__main__":
    for p in generate_all():
        print("wrote", p)
