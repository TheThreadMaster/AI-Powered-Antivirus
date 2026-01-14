#!/usr/bin/env python3
"""
AI Shield - ML Model Training Script
Trains an Isolation Forest model for anomaly detection using benign and malicious file samples.

Usage:
    python train_ml_model.py --benign-dir <path> --malicious-dir <path> [--output-dir <path>]

Requirements:
    - sklearn
    - numpy
    - pandas (optional, for data analysis)
"""

import os
import sys
import argparse
import pickle
import json
import math
from pathlib import Path
from typing import List, Dict, Any
import mimetypes

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split
except ImportError as e:
    print(f"Error: Required library not installed: {e}")
    print("Please install: pip install scikit-learn numpy")
    sys.exit(1)

# Feature extraction functions (must match anomaly.py)
def _entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    length = len(data)
    for c in counts:
        if c:
            p = c / length
            entropy -= p * math.log2(p)
    return entropy

def extract_features(file_path: str, suspicious_strings: List[str]) -> List[float]:
    """Extract features from a file (must match anomaly.py logic)."""
    p = Path(file_path)
    ext = p.suffix.lower()
    mime = mimetypes.guess_type(p.name)[0] or "application/octet-stream"
    
    size = 0
    try:
        size = p.stat().st_size
    except Exception:
        size = 0
    
    # Read file sample
    body_slice = b""
    header = b""
    try:
        with open(p, "rb") as f:
            header = f.read(32)
            body_slice = f.read(256 * 1024)  # 256KB sample
    except Exception:
        pass
    
    # Extract text for string analysis
    try:
        txt = body_slice.decode(errors="ignore")
    except Exception:
        txt = ""
    
    # Feature extraction (must match anomaly.py)
    pe = 1.0 if header.startswith(b"MZ") else 0.0
    elf = 1.0 if header.startswith(b"\x7FELF") else 0.0
    pdf = 1.0 if header.startswith(b"%PDF") else 0.0
    zipm = 1.0 if header.startswith(b"PK\x03\x04") else 0.0
    script = 1.0 if ext in {".ps1", ".psm1", ".bat", ".cmd", ".js", ".vbs"} else 0.0
    image = 1.0 if (ext in {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".webp", ".svg"} or 
                    mime.startswith("image/")) else 0.0
    
    ent_all = _entropy(body_slice)
    size_log = math.log10(size + 1)
    non_ascii = sum(1 for c in (body_slice or b"") if c >= 128)
    ratio_non_ascii = (non_ascii / max(1, len(body_slice or b"")))
    printable = sum(1 for ch in txt if 32 <= ord(ch) <= 126)
    printable_ratio = printable / max(1, len(txt))
    suspicious_hits = sum(1 for s in suspicious_strings if s in txt)
    
    return [
        size_log,
        ent_all,
        ratio_non_ascii,
        printable_ratio,
        pe,
        elf,
        pdf,
        zipm,
        script,
        image,
        float(suspicious_hits),
    ]

# Suspicious strings (must match anomaly.py)
SUSPICIOUS_STRINGS = [
    "CreateRemoteThread", "VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
    "ReadProcessMemory", "NtCreateThreadEx", "RegSetValue", "RegCreateKey",
    "RegSetValueEx", "RegDeleteKey", "WinExec", "ShellExecute", "ShellExecuteEx",
    "CreateProcess", "SystemParametersInfo", "SetWindowsHookEx", "GetProcAddress",
    "LoadLibrary", "GetModuleHandle", "powershell", "-EncodedCommand", "-Encoded",
    "FromBase64String", "Invoke-Expression", "IEX", "DownloadString", "Invoke-WebRequest",
    "cmd.exe", "/c ", "/C ", "schtasks", "bitsadmin", "wget ", "curl ",
    "WebClient", "DownloadFile", "socket", "connect", "bind", "eval(", "unescape(",
    "String.fromCharCode", "atob(", "btoa(", "charCodeAt", "AutoIt",
    "Scripting.FileSystemObject", "WScript.Shell", "ActiveXObject",
    "HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE", "RunOnce", "RunServices",
    "Startup", "TaskScheduler", "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "OutputDebugString", "FindWindow", "GetTickCount", "GetClipboardData",
    "GetAsyncKeyState", "keylog", "screenshot",
]

FEATURE_NAMES = [
    "size_log", "entropy", "ratio_non_ascii", "printable_ratio",
    "pe", "elf", "pdf", "zip", "script", "image", "suspicious_hits"
]

def collect_files(directory: str, label: str) -> List[Dict[str, Any]]:
    """Collect files from directory and extract features."""
    files = []
    directory_path = Path(directory)
    
    if not directory_path.exists():
        print(f"Warning: Directory {directory} does not exist")
        return files
    
    print(f"Collecting {label} files from {directory}...")
    count = 0
    for file_path in directory_path.rglob("*"):
        if file_path.is_file():
            try:
                # Skip very large files
                if file_path.stat().st_size > 100 * 1024 * 1024:  # >100MB
                    continue
                features = extract_features(str(file_path), SUSPICIOUS_STRINGS)
                files.append({
                    "path": str(file_path),
                    "features": features,
                    "label": label
                })
                count += 1
                if count % 100 == 0:
                    print(f"  Processed {count} files...")
            except Exception as e:
                print(f"  Error processing {file_path}: {e}")
                continue
    
    print(f"Collected {len(files)} {label} files")
    return files

def train_model(benign_files: List[Dict], malicious_files: List[Dict], 
                output_dir: str, contamination: float = 0.1):
    """Train Isolation Forest model."""
    print("\nTraining model...")
    
    # Combine all files
    all_files = benign_files + malicious_files
    if len(all_files) < 100:
        print(f"Warning: Only {len(all_files)} files available. Need at least 100 for good training.")
        print("Consider adding more training samples.")
    
    # Extract features and labels
    X = np.array([f["features"] for f in all_files])
    y = np.array([1 if f["label"] == "malicious" else 0 for f in all_files])
    
    print(f"Training set: {len(benign_files)} benign, {len(malicious_files)} malicious")
    print(f"Total samples: {len(all_files)}")
    print(f"Feature dimensions: {X.shape[1]}")
    
    # Split data (80/20)
    if len(all_files) > 20:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y if len(set(y)) > 1 else None
        )
    else:
        X_train, X_test, y_train, y_test = X, X, y, y
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Train Isolation Forest
    # contamination: expected proportion of anomalies (malicious files)
    model = IsolationForest(
        contamination=contamination,
        random_state=42,
        n_estimators=100,
        max_samples='auto',
        n_jobs=-1
    )
    
    print("Fitting model...")
    model.fit(X_train_scaled)
    
    # Evaluate
    train_pred = model.predict(X_train_scaled)
    test_pred = model.predict(X_test_scaled)
    
    # Isolation Forest returns -1 for anomalies, 1 for normal
    # Convert: -1 (anomaly) -> 1 (malicious), 1 (normal) -> 0 (benign)
    train_pred_binary = (train_pred == -1).astype(int)
    test_pred_binary = (test_pred == -1).astype(int)
    
    train_accuracy = np.mean(train_pred_binary == y_train)
    test_accuracy = np.mean(test_pred_binary == y_test)
    
    print(f"\nTraining Results:")
    print(f"  Train Accuracy: {train_accuracy:.4f}")
    print(f"  Test Accuracy: {test_accuracy:.4f}")
    
    # Save model and scaler
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    model_path = output_path / "model.pkl"
    scaler_path = output_path / "scaler.pkl"
    feature_names_path = output_path / "feature_names.json"
    
    print(f"\nSaving model to {model_path}...")
    with open(model_path, "wb") as f:
        pickle.dump(model, f)
    
    print(f"Saving scaler to {scaler_path}...")
    with open(scaler_path, "wb") as f:
        pickle.dump(scaler, f)
    
    print(f"Saving feature names to {feature_names_path}...")
    with open(feature_names_path, "w") as f:
        json.dump(FEATURE_NAMES, f, indent=2)
    
    print("\nTraining complete!")
    print(f"Model files saved to: {output_dir}")
    return model, scaler

def main():
    parser = argparse.ArgumentParser(description="Train AI Shield ML model")
    parser.add_argument("--benign-dir", type=str, required=True,
                       help="Directory containing benign file samples")
    parser.add_argument("--malicious-dir", type=str, required=True,
                       help="Directory containing malicious file samples")
    parser.add_argument("--output-dir", type=str, default="backend/models",
                       help="Output directory for model files (default: backend/models)")
    parser.add_argument("--contamination", type=float, default=0.1,
                       help="Expected proportion of anomalies (default: 0.1)")
    
    args = parser.parse_args()
    
    # Collect files
    benign_files = collect_files(args.benign_dir, "benign")
    malicious_files = collect_files(args.malicious_dir, "malicious")
    
    if len(benign_files) == 0 and len(malicious_files) == 0:
        print("Error: No files found in either directory")
        sys.exit(1)
    
    if len(benign_files) < 50:
        print(f"Warning: Only {len(benign_files)} benign files. Recommend at least 50+ for good training.")
    
    if len(malicious_files) < 10:
        print(f"Warning: Only {len(malicious_files)} malicious files. Recommend at least 10+ for good training.")
    
    # Train model
    train_model(benign_files, malicious_files, args.output_dir, args.contamination)

if __name__ == "__main__":
    main()

