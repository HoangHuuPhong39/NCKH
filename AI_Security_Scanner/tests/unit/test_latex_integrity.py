import re
from pathlib import Path
import json
import pytest

def get_paper_root():
    # Look for paper directory from current file location or cwd
    current = Path(__file__).resolve().parent
    for parent in [current, current.parent, current.parent.parent, current.parent.parent.parent, Path.cwd()]:
        paper_dir = parent / "paper"
        if paper_dir.exists() and (paper_dir / "main.tex").exists():
            return paper_dir
    raise FileNotFoundError("Could not find paper directory with main.tex")

def get_all_tex_contents(paper_dir):
    contents = {}
    for tex_file in paper_dir.rglob("*.tex"):
        with open(tex_file, "r", encoding="utf-8") as f:
            contents[tex_file] = f.read()
    return contents

def test_latex_input_files_exist():
    paper_dir = get_paper_root()
    main_tex = paper_dir / "main.tex"
    with open(main_tex, "r", encoding="utf-8") as f:
        main_content = f.read()

    # Find all \input{...} in main.tex and included files
    input_pattern = re.compile(r"\\input\{([^}]+)\}")
    
    # Check recursive inputs
    to_check = [("main.tex", main_content)]
    checked = set()

    while to_check:
        fname, content = to_check.pop(0)
        checked.add(fname)
        matches = input_pattern.findall(content)
        for rel_path in matches:
            if not rel_path.endswith(".tex"):
                target_path = paper_dir / f"{rel_path}.tex"
            else:
                target_path = paper_dir / rel_path
            assert target_path.exists(), f"Input file missing: {target_path} referenced in {fname}"
            if target_path.name not in checked:
                with open(target_path, "r", encoding="utf-8") as f:
                    to_check.append((target_path.name, f.read()))

def test_latex_citations_resolve():
    paper_dir = get_paper_root()
    tex_contents = get_all_tex_contents(paper_dir)
    
    # Extract all bibitems
    bibitem_pattern = re.compile(r"\\bibitem\{([^}]+)\}")
    all_bibitems = set()
    for content in tex_contents.values():
        all_bibitems.update(bibitem_pattern.findall(content))
    
    assert len(all_bibitems) >= 25, f"Expected at least 25 citations, found {len(all_bibitems)}"

    # Extract all cites: \cite{c1,c2}
    cite_pattern = re.compile(r"\\cite\{([^}]+)\}")
    all_cites = set()
    for fname, content in tex_contents.items():
        for group in cite_pattern.findall(content):
            keys = [k.strip() for k in group.split(",")]
            for k in keys:
                all_cites.add((k, fname.name))

    unresolved = [f"{k} in {fname}" for k, fname in all_cites if k not in all_bibitems]
    assert not unresolved, f"Unresolved citations found: {unresolved}"

def test_latex_labels_and_refs_resolve():
    paper_dir = get_paper_root()
    tex_contents = get_all_tex_contents(paper_dir)

    label_pattern = re.compile(r"\\label\{([^}]+)\}")
    ref_pattern = re.compile(r"\\ref\{([^}]+)\}")

    all_labels = set()
    for content in tex_contents.values():
        all_labels.update(label_pattern.findall(content))

    all_refs = set()
    for fname, content in tex_contents.items():
        for k in ref_pattern.findall(content):
            all_refs.add((k.strip(), fname.name))

    unresolved = [f"{k} in {fname}" for k, fname in all_refs if k not in all_labels]
    assert not unresolved, f"Unresolved \\ref references found: {unresolved}"

def test_latex_figures_exist():
    paper_dir = get_paper_root()
    tex_contents = get_all_tex_contents(paper_dir)

    img_pattern = re.compile(r"\\includegraphics(?:\[[^\]]*\])?\{([^}]+)\}")
    all_imgs = []
    for fname, content in tex_contents.items():
        for img_rel in img_pattern.findall(content):
            all_imgs.append((img_rel.strip(), fname.name))

    for img_rel, src in all_imgs:
        img_path = paper_dir / img_rel
        if not img_path.suffix:
            # Check for pdf or png
            pdf_path = paper_dir / f"{img_rel}.pdf"
            png_path = paper_dir / f"{img_rel}.png"
            assert pdf_path.exists() or png_path.exists(), f"Figure missing: {img_rel} referenced in {src}"
        else:
            assert img_path.exists(), f"Figure missing: {img_path} referenced in {src}"

def test_tables_resizebox_overflow_protection():
    paper_dir = get_paper_root()
    tables_dir = paper_dir / "tables"
    for tex_file in tables_dir.glob("*.tex"):
        with open(tex_file, "r", encoding="utf-8") as f:
            content = f.read()
        if "tabular" in content:
            assert "\\resizebox" in content, f"Table in {tex_file.name} lacks \\resizebox overflow protection"

def test_token_fragmentation_data_consistency():
    metrics_path = Path("experiments/results/token_fragmentation_metrics.json")
    if not metrics_path.exists():
        metrics_path = get_paper_root().parent / "experiments/results/token_fragmentation_metrics.json"
    
    assert metrics_path.exists(), "token_fragmentation_metrics.json must exist"
    with open(metrics_path, "r", encoding="utf-8") as f:
        metrics = json.load(f)

    paper_dir = get_paper_root()
    tex_path = paper_dir / "tables/token_fragmentation_table.tex"
    with open(tex_path, "r", encoding="utf-8") as f:
        tex_content = f.read()

    # Verify each cohort from json is present in the table
    for name in metrics.keys():
        assert name in tex_content, f"Cohort {name} missing from LaTeX token fragmentation table"

def test_submission_bundle_integrity():
    paper_dir = get_paper_root()
    repo_root = paper_dir.parent
    bundle_path = repo_root / "paper_submission_bundle.zip"
    if not bundle_path.exists():
        alt_path = repo_root / "docs_local" / "goi_nop_bai_bao" / "paper_submission_bundle.zip"
        if alt_path.exists():
            bundle_path = alt_path
        else:
            pytest.skip("paper_submission_bundle.zip is gitignored in clean CI checkouts")

    import zipfile
    with zipfile.ZipFile(bundle_path, "r") as z:
        names = z.namelist()
        assert "main.tex" in names, "Root-level main.tex must be present in submission bundle"
        assert "figures/cascade_architecture.tex" in names
        assert "figures/dialectal_refusal_shift.pdf" in names
        assert "tables/ablation_and_scaling_table.tex" in names
        assert "tables/main_benchmark_tables.tex" in names
        assert "tables/judge_validation_tables.tex" in names
        assert "tables/token_fragmentation_table.tex" in names
        assert "submission_docs/highlights.txt" in names
        assert "submission_docs/cover_letter.md" in names
        assert "submission_docs/reproducibility_and_credit.tex" in names

def test_submission_docs_standards():
    paper_dir = get_paper_root()
    highlights_path = paper_dir / "submission_docs/highlights.txt"
    assert highlights_path.exists(), "highlights.txt must exist"

    with open(highlights_path, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    assert len(lines) >= 3 and len(lines) <= 5, f"Elsevier highlights should have 3-5 bullets, got {len(lines)}"
    for i, line in enumerate(lines):
        assert len(line) <= 85, f"Highlight line {i+1} exceeds 85 chars ({len(line)} chars): '{line}'"

    cover_letter_path = paper_dir / "submission_docs/cover_letter.md"
    assert cover_letter_path.exists(), "cover_letter.md must exist"

def test_vietnamese_t5_encoding_and_figure_resize():
    paper_dir = get_paper_root()
    main_tex_path = paper_dir / "main.tex"
    with open(main_tex_path, "r", encoding="utf-8") as f:
        main_content = f.read()

    assert "T5" in main_content, "main.tex must include T5 in fontenc for Vietnamese rendering"
    assert "vietnamese,english" in main_content, "main.tex must include babel with vietnamese,english"
    assert r"\fontencoding{T5}\selectfont" in main_content, "main.tex must select T5 font encoding"
    assert r"\sloppy" in main_content, "main.tex must include \\sloppy to eliminate underfull hbox warnings"
    assert "protrusion=false" in main_content, "main.tex must configure microtype with protrusion=false"
    assert r"\documentclass[11pt]{article}" in main_content, "main.tex must be in single-column 11pt article format"

    # Verify abstract is a single contiguous paragraph
    abstract_match = re.search(r"\\begin\{abstract\}(.*?)\\end\{abstract\}", main_content, re.DOTALL)
    assert abstract_match, "abstract must be present in main.tex"
    abstract_text = abstract_match.group(1).strip()
    assert "\n\n" not in abstract_text, "abstract must be a single seamless paragraph without blank lines"

    cascade_tex_path = paper_dir / "figures/cascade_architecture.tex"
    with open(cascade_tex_path, "r", encoding="utf-8") as f:
        cascade_content = f.read()

    assert r"\resizebox{\textwidth}{!}" in cascade_content, "cascade_architecture.tex must wrap tikzpicture in \\resizebox{\\textwidth}{!}"

    judge_sec_path = paper_dir / "sections/judge_validation_section.tex"
    with open(judge_sec_path, "r", encoding="utf-8") as f:
        judge_sec_content = f.read()

    assert r"\resizebox" in judge_sec_content, "judge_validation_section.tex must wrap long cascade decision equation in \\resizebox"


