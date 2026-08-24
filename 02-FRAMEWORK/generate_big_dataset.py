#!/usr/bin/env python3
"""
Generador de Dataset Grande — Acumula de múltiples runs de red-teaming
"""
import sys
sys.path.insert(0, '.')

import json
from datetime import datetime
from pathlib import Path

from attacks.automated_redteam import RedTeamRunner
from core.adversarial_trainer import AdversarialTrainer, TrainingDataset, HardeningPair
from core.report_generator import ReportGenerator

RUNS = 10
MULTIPLIER = 10
MODEL = "gpt-4o"

print("=" * 70)
print("  🛡️  GovLLM-Sentinel — BIG DATASET GENERATOR")
print(f"  {RUNS} runs × 18 tests × {MULTIPLIER} augmentation")
print("=" * 70)

all_pairs = []
all_stats = {"total_tests": 0, "total_vulnerable": 0}

for i in range(RUNS):
    runner = RedTeamRunner(mode="mock")
    report = runner.run_all_tests(MODEL)
    trainer = AdversarialTrainer()
    ds = trainer.generate_dataset(report, MODEL)
    all_pairs.extend(ds.pairs)
    all_stats["total_tests"] += report.total_tests
    all_stats["total_vulnerable"] += report.total_vulnerable
    vulns = report.total_vulnerable
    print(f"  Run {i+1:2d}/{RUNS}: {report.total_tests} tests, {vulns} vulnerable → {len(ds.pairs)} pairs")

# Deduplicate
seen = set()
unique = []
for p in all_pairs:
    key = (p.attack_category, p.attack_payload[:40])
    if key not in seen:
        seen.add(key)
        unique.append(p)

print(f"\n  Unique pairs: {len(unique)}")

# Create dataset and augment
base_ds = TrainingDataset(
    dataset_id="big-dataset",
    created_at=datetime.now().isoformat(),
    model_target=MODEL,
    pairs=unique,
    stats=all_stats,
)
augmented = trainer.generate_augmented_dataset(base_ds, multiplier=MULTIPLIER)

# Stats
cats = {}
diffs = {}
for p in augmented.pairs:
    cats[p.attack_category] = cats.get(p.attack_category, 0) + 1
    diffs[p.difficulty] = diffs.get(p.difficulty, 0) + 1

print(f"  After ×{MULTIPLIER} augmentation: {len(augmented.pairs)} pairs")
print()
print("  Categories:")
for k, v in sorted(cats.items(), key=lambda x: -x[1]):
    bar = "█" * (v // 2)
    print(f"    {k:20s} {v:3d} {bar}")
print()
print("  Difficulty:")
for k, v in sorted(diffs.items(), key=lambda x: -x[1]):
    print(f"    {k:12s} {v:3d}")

# Export
timestamp = datetime.now().strftime("%Y%m%d")
outdir = f"../datasets/big-{timestamp}"
Path(outdir).mkdir(parents=True, exist_ok=True)

alpaca = trainer.export_alpaca_format(augmented, f"{outdir}/alpaca.json")
chatml = trainer.export_chatml_format(augmented, f"{outdir}/chatml.jsonl")
jsonl = trainer.export_dataset(augmented, f"{outdir}/hardening.jsonl")

# Executive report
gen = ReportGenerator()
html = gen.save_report(
    gen.generate_html_report({
        "scan_id": "big-dataset",
        "pii": {"total_violations": 0, "action": "allow", "violations": [], "scan_duration_ms": 0},
        "compliance": {"total_violations": 0, "action": "allow", "violations": [], "scan_duration_ms": 0},
        "alignment": {"overall_score": 85, "overall_compliant": True, "violations": []},
        "overall_action": "allow",
    }, MODEL),
    f"{outdir}/report.html"
)

print(f"\n{'=' * 70}")
print(f"  📊 BIG DATASET READY")
print(f"{'=' * 70}")
print(f"  Total pairs:     {len(augmented.pairs)}")
print(f"  Categories:      {len(cats)}")
print(f"  Red-team runs:   {RUNS}")
print(f"  Total tests:     {all_stats['total_tests']}")
print(f"  Vuln found:      {all_stats['total_vulnerable']}")
print()
print(f"  Files:")
print(f"    {alpaca}")
print(f"    {chatml}")
print(f"    {jsonl}")
print(f"    {html}")
print(f"{'=' * 70}")
