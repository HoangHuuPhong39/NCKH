"""
Generate publication-quality scientific figures for Paper 1 (Gap G1/G2/G3).
Features:
- Dialectal Refusal Shift across 6 linguistic cohorts (N_eval = 60: N=10 per cohort, N_h=7, N_b=3)
- BPE Token Fertility overlay from Llama-3-8B AutoTokenizer
- Colorblind-safe / Muted Academic Palette (Slate Blue, Sandstone Ochre, Deep Rust)
- Clean anti-collision layout without duplicate titles (caption-managed)
"""

import sys
from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def generate_dialectal_refusal_shift_figure():
    fig_dir = Path("paper/figures")
    fig_dir.mkdir(parents=True, exist_ok=True)

    cohorts = [
        "English\nBaseline",
        "Standard VI\n(NFC)",
        "No Diacritics\n(Unaccented)",
        "Teencode /\nSlang",
        "Code-\nSwitching",
        "Unicode NFD\n(Decomposed)",
    ]

    # Metrics from 60-prompt empirical evaluation (main_benchmark_metrics.csv)
    err = [85.7, 85.7, 0.0, 100.0, 85.7, 0.0]     # State 0: Explicit Refusal Rate
    lsr = [14.3, 14.3, 100.0, 0.0, 14.3, 100.0]   # State 1: Low-Specificity / Ambiguity
    asr = [0.0, 0.0, 0.0, 0.0, 0.0, 0.0]           # State 2: Full Compliance / Actionable Harm

    # Token fertility metrics synchronized with Table 2 (Meta-Llama-3-8B-Instruct AutoTokenizer)
    fertility = [1.207, 1.186, 1.470, 1.197, 1.192, 3.194]

    plt.rcParams.update({
        "font.family": "serif",
        "font.size": 11,
        "axes.labelsize": 11.5,
        "axes.titlesize": 12,
        "xtick.labelsize": 10.5,
        "ytick.labelsize": 10.5,
        "legend.fontsize": 10,
    })

    fig, ax1 = plt.subplots(figsize=(9.2, 4.8), dpi=300)

    x = np.arange(len(cohorts))
    width = 0.52

    color_err = "#2b5c8f"   # Slate Blue (State 0: Explicit Refusal)
    color_lsr = "#d9a05b"   # Sandstone Ochre (State 1: Low-Specificity)
    color_asr = "#8c2d19"   # Deep Rust (State 2: Actionable Jailbreak)
    color_fert = "#8c2d19"  # Deep Rust line for Subword Fertility

    b1 = ax1.bar(x, err, width, label="State 0: Explicit Refusal (ERR %)", color=color_err, edgecolor="black", linewidth=0.6)
    b2 = ax1.bar(x, lsr, width, bottom=err, label="State 1: Low-Specificity Safe Discourse (LSR %)", color=color_lsr, edgecolor="black", linewidth=0.6)
    b3 = ax1.bar(x, asr, width, bottom=np.array(err) + np.array(lsr), label="State 2: Actionable Jailbreak (ASR %)", color=color_asr, edgecolor="black", linewidth=0.6)

    ax1.set_ylabel("Harmful Evaluation Response Rate (%)", color="#1c2d42", fontweight="bold")
    ax1.set_ylim(0, 115)
    ax1.set_xticks(x)
    ax1.set_xticklabels(cohorts, fontweight="medium")
    ax1.grid(axis="y", linestyle="--", alpha=0.35)

    for i in range(len(cohorts)):
        if err[i] > 10:
            if err[i] >= 95:
                y_pos = 52.0
            else:
                y_pos = 46.0
            ax1.text(x[i], y_pos, f"{err[i]:.1f}%", ha="center", va="center", color="white", fontweight="bold", fontsize=9.5)

        if lsr[i] > 10:
            if lsr[i] >= 95:
                if i == 2:      # No Diacritics
                    y_pos = 65.0
                elif i == 5:    # Unicode NFD
                    y_pos = 40.0
                else:
                    y_pos = 65.0
            else:
                y_pos = 92.8
            ax1.text(x[i], y_pos, f"{lsr[i]:.1f}%", ha="center", va="center", color="#1c2d42", fontweight="bold", fontsize=9.0)

    ax2 = ax1.twinx()
    line = ax2.plot(x, fertility, color=color_fert, marker="s", markersize=7.5, linewidth=2.2, linestyle="-", label="BPE Subword Fertility (Tokens / Word)")
    ax2.set_ylabel("BPE Subword Fertility Ratio (Tokens / Word)", color=color_fert, fontweight="bold")
    ax2.set_ylim(0.8, 3.8)
    ax2.tick_params(axis="y", labelcolor=color_fert)

    for i, txt in enumerate(fertility):
        offset = (0, 10)
        ax2.annotate(f"{txt:.2f}×", (x[i], fertility[i]), textcoords="offset points", xytext=offset,
                     ha="center", color=color_fert, fontweight="bold", fontsize=9.5,
                     bbox=dict(boxstyle="round,pad=0.2", facecolor="#FDF6F0", edgecolor=color_fert, alpha=0.9, linewidth=0.8))

    bars_labels = [b1, b2, line[0]]
    labs = [b.get_label() for b in bars_labels]
    ax1.legend(bars_labels, labs, loc="upper left", bbox_to_anchor=(0.02, 0.98), framealpha=0.94, facecolor="white", edgecolor="#cccccc")

    plt.tight_layout()

    pdf_path = fig_dir / "dialectal_refusal_shift.pdf"
    png_path = fig_dir / "dialectal_refusal_shift.png"
    plt.savefig(pdf_path, format="pdf", bbox_inches="tight")
    plt.savefig(png_path, format="png", dpi=300, bbox_inches="tight")
    plt.close()

    print(f"[OK] Generated {pdf_path}")
    print(f"[OK] Generated {png_path}")


if __name__ == "__main__":
    generate_dialectal_refusal_shift_figure()
