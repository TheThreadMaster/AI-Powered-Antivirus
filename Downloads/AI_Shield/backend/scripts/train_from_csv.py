import argparse
import csv
import json
import math
import pickle
from pathlib import Path

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


REGISTRY = {
    "size_log": True,
    "entropy": True,
    "ratio_non_ascii": True,
    "printable_ratio": True,
    "pe": True,
    "elf": True,
    "pdf": True,
    "zip": True,
    "script": True,
    "image": True,
    "suspicious_hits": True,
}


def detect_label_column(headers):
    lows = [h.lower() for h in headers]
    for cand in ["label", "y", "class", "target", "is_malicious", "malicious", "phishing"]:
        if cand in lows:
            return headers[lows.index(cand)]
    return None


def parse_row(row, feature_cols):
    vec = []
    for c in feature_cols:
        v = row.get(c, "")
        try:
            vec.append(float(v))
        except Exception:
            vec.append(0.0)
    return vec


def load_csv(path: Path):
    with open(path, newline="", encoding="utf-8", errors="ignore") as f:
        r = csv.DictReader(f)
        headers = r.fieldnames or []
        rows = list(r)
    return headers, rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--out_dir", default=str(Path(__file__).resolve().parents[1] / "app" / "services"))
    ap.add_argument("--limit", type=int, default=50000)
    args = ap.parse_args()
    csv_path = Path(args.csv)
    out_dir = Path(args.out_dir)
    headers, rows = load_csv(csv_path)
    headers_l = [h for h in headers if h]
    reg_keys = set(REGISTRY.keys())
    feat_cols = [h for h in headers_l if h.lower() in reg_keys]
    if not feat_cols:
        print("No matching feature columns found")
        return
    label_col = detect_label_column(headers_l)
    X = []
    for i, row in enumerate(rows):
        if i >= args.limit:
            break
        X.append(parse_row(row, feat_cols))
    if not X:
        print("No rows parsed")
        return
    contam = 0.1
    if label_col:
        mals = 0
        total = 0
        for i, row in enumerate(rows[: args.limit]):
            v = str(row.get(label_col, "")).strip().lower()
            if v in {"1", "true", "yes", "malicious", "malware", "phishing", "bad"}:
                mals += 1
            total += 1
        if total > 0:
            contam = max(0.01, min(0.5, mals / total))
    scaler = StandardScaler()
    scaler.fit(X)
    model = IsolationForest(n_estimators=200, contamination=contam, random_state=42)
    model.fit(scaler.transform(X))
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / "model.pkl", "wb") as f:
        pickle.dump(model, f)
    with open(out_dir / "scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)
    with open(out_dir / "feature_names.json", "w", encoding="utf-8") as f:
        json.dump(feat_cols, f)
    print("Saved", out_dir / "model.pkl", out_dir / "scaler.pkl", out_dir / "feature_names.json")


if __name__ == "__main__":
    main()

