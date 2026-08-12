"""
Run entropy analysis and classifier evaluation on collected or synthetic data.

Usage:
  python scripts/analyze.py                     # synthetic data
  python scripts/analyze.py --db fingerprints.db
  python scripts/analyze.py --n 2000 --seed 7
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def _load_from_db(db_path: str) -> list[dict]:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from server.database import Fingerprint, Base

    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    db = Session()
    rows = db.query(Fingerprint).all()
    db.close()

    def _row(fp):
        return {col.name: getattr(fp, col.name) for col in fp.__table__.columns}

    return [_row(r) for r in rows]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db",    default=None,  help="Path to SQLite database (default: use synthetic data)")
    ap.add_argument("--n",     type=int, default=1000, help="Number of synthetic fingerprints")
    ap.add_argument("--seed",  type=int, default=42)
    ap.add_argument("--json",  action="store_true", help="Output entropy results as JSON")
    ap.add_argument("--no-classifier", action="store_true", help="Skip classifier training")
    args = ap.parse_args()

    if args.db:
        print(f"Loading fingerprints from {args.db}…")
        rows = _load_from_db(args.db)
    else:
        print(f"Generating {args.n:,} synthetic fingerprints (seed={args.seed})…")
        from scripts.generate_synthetic import generate
        rows = generate(n=args.n, seed=args.seed)

    print(f"Loaded {len(rows):,} fingerprints.\n")

    from analysis.entropy import entropy_summary
    summary = entropy_summary(rows)

    if args.json:
        print(json.dumps(summary, indent=2))
        return

    print("=" * 60)
    print(f"  Entropy Analysis — {summary['n_fingerprints']:,} fingerprints")
    print("=" * 60)
    print(f"  Total bits:      {summary['total_bits']:.2f}")
    if summary["anonymity_set_upper"] == float("inf"):
        print(f"  Anonymity set:   > 2^50 (effectively unique)")
    else:
        print(f"  Anonymity set:   ~{summary['anonymity_set_upper']:,.0f}")
    print()
    print(f"  {'Group':<12} {'Bits':>8}")
    print(f"  {'-'*22}")
    for group, bits in summary["group_totals"].items():
        bar = "█" * int(bits * 3)
        print(f"  {group:<12} {bits:>8.3f}  {bar}")
    print()
    print(f"  {'Feature':<36} {'Bits':>7}  {'Unique':>7}  {'Coverage':>9}")
    print(f"  {'-'*62}")
    for f in summary["features"][:20]:
        print(f"  {f['feature']:<36} {f['entropy_bits']:>7.4f}  {f['n_unique']:>7}  {f['coverage']:>8.1%}")
    print()

    if not args.no_classifier:
        from sklearn.model_selection import train_test_split
        from analysis.classifier import FingerprintClassifier

        print("=" * 60)
        print("  Classifier: predict Browser/OS from non-UA signals")
        print("=" * 60)
        train, test = train_test_split(rows, test_size=0.2, random_state=42)
        clf = FingerprintClassifier()
        print(f"  Training on {len(train):,} samples…")
        clf.fit(train)
        results = clf.evaluate(test)
        report = results["classification_report"]
        print(f"\n  Overall accuracy: {report['accuracy']:.4f}\n")
        print(f"  {'Class':<22} {'Precision':>10} {'Recall':>8} {'F1':>8} {'n':>6}")
        print(f"  {'-'*56}")
        for cls, m in report.items():
            if isinstance(m, dict) and "precision" in m:
                print(f"  {cls:<22} {m['precision']:>10.4f} {m['recall']:>8.4f} {m['f1-score']:>8.4f} {m['support']:>6}")
        print()
        print("  Top 10 feature importances:")
        for fi in results["feature_importances"][:10]:
            bar = "█" * int(fi["importance"] * 300)
            print(f"  {fi['feature']:<36} {fi['importance']:.5f}  {bar}")


if __name__ == "__main__":
    main()
