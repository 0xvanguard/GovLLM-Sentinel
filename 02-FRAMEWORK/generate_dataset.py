#!/usr/bin/env python3
"""
GovLLM-Sentinel — Generador de Dataset de Adversarial Training

Ejecuta la batería completa de red-teaming y genera datasets
de hardening en múltiples formatos para fine-tuning.

Formatos de exportación:
- JSONL (estándar)
- Alpaca (LLaMA-Factory, Axolotl, unsloth)
- ChatML (OpenAI fine-tuning)

Uso:
    python generate_dataset.py
    python generate_dataset.py --model "gpt-4o" --multiplier 5
"""
import sys
sys.path.insert(0, '.')

import argparse
from datetime import datetime

from attacks.automated_redteam import RedTeamRunner
from core.adversarial_trainer import AdversarialTrainer
from core.report_generator import ReportGenerator


def main():
    parser = argparse.ArgumentParser(description="Generar dataset de adversarial training")
    parser.add_argument("--model", default="target-model", help="Nombre del modelo target")
    parser.add_argument("--multiplier", type=int, default=3, help="Augmentación del dataset")
    parser.add_argument("--output", default="../datasets", help="Directorio de salida")
    args = parser.parse_args()

    print("=" * 70)
    print("  🛡️  GovLLM-Sentinel — ADVERSARIAL TRAINING DATASET GENERATOR")
    print("=" * 70)

    # ── FASE 1: Red-Teaming ──────────────────────────────────────
    print(f"\n{'─' * 70}")
    print("  FASE 1: Ejecutando batería de red-teaming...")
    print(f"{'─' * 70}")

    runner = RedTeamRunner(mode="mock")
    report = runner.run_all_tests(args.model)

    print(f"  Modelo: {report.model_name}")
    print(f"  Tests ejecutados: {report.total_tests}")
    print(f"  Vulnerables: {report.total_vulnerable}")
    print(f"  Resistentes: {report.total_resistant}")
    print(f"  Score: {report.overall_resistance}%")
    print(f"  Grade: {report.security_grade}")

    # ── FASE 2: Generar Dataset Base ─────────────────────────────
    print(f"\n{'─' * 70}")
    print("  FASE 2: Generando dataset de hardening...")
    print(f"{'─' * 70}")

    trainer = AdversarialTrainer()
    dataset = trainer.generate_dataset(report, args.model)

    print(f"  Dataset ID: {dataset.dataset_id}")
    print(f"  Pares generados: {len(dataset.pairs)}")
    print(f"  Categorías: {list(dataset.stats.get('categories', {}).keys())}")

    # ── FASE 3: Augmentar Dataset ────────────────────────────────
    print(f"\n{'─' * 70}")
    print(f"  FASE 3: Augmentando dataset (×{args.multiplier})...")
    print(f"{'─' * 70}")

    augmented = trainer.generate_augmented_dataset(dataset, multiplier=args.multiplier)

    print(f"  Pares base: {len(dataset.pairs)}")
    print(f"  Pares augmentados: {len(augmented.pairs)}")
    print(f"  Total final: {len(augmented.pairs)}")

    # ── FASE 4: Exportar en 3 formatos ───────────────────────────
    print(f"\n{'─' * 70}")
    print("  FASE 4: Exportando datasets...")
    print(f"{'─' * 70}")

    timestamp = datetime.now().strftime("%Y%m%d")
    outdir = f"{args.output}/hardening-{timestamp}"

    # JSONL
    jsonl_path = trainer.export_dataset(augmented, f"{outdir}/hardening-dataset.jsonl")
    print(f"  ✅ JSONL:       {jsonl_path}")

    # Alpaca
    alpaca_path = trainer.export_alpaca_format(augmented, f"{outdir}/alpaca-dataset.json")
    print(f"  ✅ Alpaca:      {alpaca_path}")

    # ChatML
    chatml_path = trainer.export_chatml_format(augmented, f"{outdir}/chatml-dataset.jsonl")
    print(f"  ✅ ChatML:      {chatml_path}")

    # ── FASE 5: Reporte Ejecutivo ────────────────────────────────
    print(f"\n{'─' * 70}")
    print("  FASE 5: Generando reporte ejecutivo...")
    print(f"{'─' * 70}")

    gen = ReportGenerator()
    scan_data = {
        "scan_id": dataset.dataset_id,
        "pii": {"total_violations": 0, "action": "allow", "violations": [], "scan_duration_ms": 0},
        "compliance": {"total_violations": 0, "action": "allow", "violations": [], "scan_duration_ms": 0},
        "alignment": {"overall_score": report.overall_resistance, "overall_compliant": True, "violations": []},
        "overall_action": "allow",
    }
    html = gen.generate_html_report(scan_data, report.model_name)
    report_path = gen.save_report(html, f"{outdir}/reporte-ejecutivo.html")
    print(f"  ✅ Reporte:     {report_path}")

    # ── RESUMEN ──────────────────────────────────────────────────
    print(f"\n{'=' * 70}")
    print("  📊 RESUMEN DEL DATASET")
    print(f"{'=' * 70}")
    print(f"  Modelo target:    {args.model}")
    print(f"  Pares totales:    {len(augmented.pairs)}")
    print(f"  Augmentación:     ×{args.multiplier}")
    print(f"  Formatos:         JSONL, Alpaca, ChatML")
    print(f"  Directorio:       {outdir}/")
    print(f"{'=' * 70}")
    print()
    print("  Para usar con LLaMA-Factory:")
    print(f"    datasets:\n      - file_name: {alpaca_path}")
    print()
    print("  Para usar con OpenAI fine-tuning:")
    print(f"    openai fine_tuning.create --training_file {chatml_path}")
    print()

    # Mostrar muestra del dataset
    if augmented.pairs:
        print("  📋 MUESTRA DEL DATASET (3 pares):")
        print(f"{'─' * 70}")
        for i, pair in enumerate(augmented.pairs[:3], 1):
            print(f"  [{i}] Category: {pair.attack_category}")
            print(f"      Attack:   {pair.attack_payload[:60]}...")
            print(f"      Response: {pair.safe_response[:60]}...")
            print(f"      Defense:  {pair.expected_defense[:60]}...")
            print()


if __name__ == "__main__":
    main()
