import os
import sys
import argparse
import math
import pickle
import json
from pathlib import Path

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    e = 0.0
    n = len(data)
    for c in counts:
        if c:
            p = c / n
            e -= p * math.log2(p)
    return e


def extract_features(path: Path, data: bytes) -> list[float]:
    name = path.name
    size = path.stat().st_size if path.exists() else 0
    ext = path.suffix.lower()
    head = data[:16] if data else b""
    txt = (data[:256 * 1024] or b"").decode(errors="ignore")

    pe = 1.0 if head.startswith(b"MZ") else 0.0
    elf = 1.0 if head.startswith(b"\x7FELF") else 0.0
    pdf = 1.0 if head.startswith(b"%PDF") else 0.0
    zipm = 1.0 if head.startswith(b"PK\x03\x04") else 0.0

    script = 1.0 if ext in {".ps1", ".psm1", ".bat", ".cmd", ".js", ".vbs"} else 0.0
    image = 1.0 if ext in {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".webp", ".svg"} else 0.0

    ent = entropy(data or b"")
    size_log = math.log10(size + 1)

    non_ascii = sum(1 for c in (data or b"") if c >= 128)
    ratio_non_ascii = (non_ascii / max(1, len(data or b"")))
    printable = sum(1 for ch in txt if 32 <= ord(ch) <= 126)
    printable_ratio = printable / max(1, len(txt))

    suspicious_hits = 0.0
    for s in [
        "CreateRemoteThread",
        "VirtualAlloc",
        "RegSetValue",
        "RegCreateKey",
        "WinExec",
        "ShellExecute",
        "powershell",
        "-EncodedCommand",
        "FromBase64String",
        "cmd.exe",
        "wget ",
        "curl ",
        "http://",
        "https://",
        "AutoIt",
    ]:
        if s in txt:
            suspicious_hits += 1.0

    return [
        size_log,
        ent,
        ratio_non_ascii,
        printable_ratio,
        pe,
        elf,
        pdf,
        zipm,
        script,
        image,
        suspicious_hits,
    ]


def collect_files(root: Path, limit: int = 500) -> list[Path]:
    files = []
    for p in root.rglob('*'):
        try:
            if p.is_file():
                files.append(p)
                if len(files) >= limit:
                    break
        except Exception:
            continue
    return files


def main():
    ap = argparse.ArgumentParser(description="Train IsolationForest on extracted file features")
    ap.add_argument("--data-dir", default=str(Path.cwd()), help="Directory to sample files from")
    ap.add_argument("--limit", type=int, default=800, help="Max files to sample")
    ap.add_argument("--out", default=str(Path(__file__).resolve().parents[1] / "app" / "services" / "model.pkl"), help="Output model path")
    args = ap.parse_args()

    root = Path(args.data_dir)
    paths = collect_files(root, limit=args.limit)
    X = []
    for p in paths:
        try:
            with open(p, 'rb') as fh:
                data = fh.read(512 * 1024)
        except Exception:
            data = b""
        X.append(extract_features(p, data))

    if not X:
        print("No files found for training", file=sys.stderr)
        sys.exit(1)

    scaler = StandardScaler()
    scaler.fit(X)
    model = IsolationForest(n_estimators=200, contamination=0.1, random_state=42)
    model.fit(scaler.transform(X))

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, 'wb') as f:
        pickle.dump(model, f)
    with open(out_path.parent / 'scaler.pkl', 'wb') as f:
        pickle.dump(scaler, f)
    with open(out_path.parent / 'feature_names.json', 'w', encoding='utf-8') as f:
        json.dump([
            'size_log','entropy','ratio_non_ascii','printable_ratio','pe','elf','pdf','zip','script','image','suspicious_hits'
        ], f)
    print(f"Model saved to {out_path}")


if __name__ == "__main__":
    main()
