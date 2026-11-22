#!/usr/bin/env python3
"""
package_submission.py
Packages all manuscript files from paper/ into paper_submission_bundle.zip
formatted for direct upload to Overleaf, Editorial Manager, or arXiv.
Ensures root-level main.tex and preserves clean relative paths.
"""

import os
import sys
import zipfile
import hashlib
from pathlib import Path

def compute_sha256(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def package_submission():
    repo_root = Path(__file__).resolve().parent.parent
    paper_dir = repo_root / "paper"
    out_zip = repo_root / "paper_submission_bundle.zip"

    if not paper_dir.exists():
        print(f"Error: {paper_dir} does not exist.")
        sys.exit(1)

    required_files = [
        "main.tex",
        "sections/dataset_and_variants_section.tex",
        "sections/judge_validation_section.tex",
        "sections/main_results_section.tex",
        "sections/judge_validation_results_section.tex",
        "tables/main_benchmark_tables.tex",
        "tables/judge_validation_tables.tex",
        "tables/token_fragmentation_table.tex",
        "tables/ablation_and_scaling_table.tex",
        "tables/intervention_results_table.tex",
        "tables/cross_model_comparison_table.tex",
        "figures/cascade_architecture.tex",
        "figures/dialectal_refusal_shift.pdf",
        "submission_docs/highlights.txt",
        "submission_docs/cover_letter.md",
        "submission_docs/reproducibility_and_credit.tex",
    ]

    print("Verifying required submission components in paper/ ...")
    missing = []
    for rel in required_files:
        full_path = paper_dir / rel
        if not full_path.exists():
            missing.append(rel)
        else:
            print(f"  [OK] {rel}")

    if missing:
        print(f"\nError: Missing required files: {missing}")
        sys.exit(1)

    print(f"\nCreating submission bundle: {out_zip} ...")
    with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(paper_dir):
            for file in sorted(files):
                # Skip temporary / editor backup files
                if file.endswith((".aux", ".log", ".out", ".synctex.gz", ".bak", ".tmp")):
                    continue
                full_path = Path(root) / file
                arcname = full_path.relative_to(paper_dir).as_posix()
                zipf.write(full_path, arcname=arcname)
                print(f"  Added: {arcname}")

    zip_size_kb = out_zip.stat().st_size / 1024
    zip_sha = compute_sha256(out_zip)

    print("\n" + "=" * 60)
    print(f"Submission bundle created successfully!")
    print(f"Output File : {out_zip}")
    print(f"File Size   : {zip_size_kb:.2f} KB")
    print(f"SHA-256     : {zip_sha}")
    print("Structure   : Root main.tex + sections/ + tables/ + figures/ + submission_docs/")
    print("Ready for   : Overleaf / Elsevier Editorial System / IEEE Author Portal")
    print("=" * 60)

if __name__ == "__main__":
    package_submission()
