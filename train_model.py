import os
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, confusion_matrix,
                             classification_report, f1_score)
from sklearn.model_selection import cross_val_predict

FEATURE_COLUMNS = [
    "outbound_variance",
    "inbound_variance",
    "pkt_count",
    "byte_count",
    "avg_pkt_size",
    "duration"
]

DATASET = [
    # ── TRUE C2 BEACONING ────────────────────────────────────────────────────
    [0.000001, 0.000002, 120, 7200,   60.0,  300.0, 1],
    [0.000005, 0.000003, 110, 6600,   60.0,  280.0, 1],
    [0.000010, 0.000008, 130, 8450,   65.0,  310.0, 1],
    [0.000100, 0.000050, 100, 4000,   40.0,  360.0, 1],
    [0.000200, 0.000100,  95, 3800,   40.0,  340.0, 1],
    [0.000050, 0.000030, 105, 4200,   40.0,  370.0, 1],
    [0.001000, 0.000500,  80, 3200,   40.0,   60.0, 1],
    [0.000800, 0.000400,  85, 3400,   40.0,   55.0, 1],
    [0.000020, 0.000010, 200, 6000,   30.0,  600.0, 1],
    [0.000030, 0.000015, 180, 5400,   30.0,  540.0, 1],
    [0.004000, 0.002000,  90, 5400,   60.0,  270.0, 1],
    [0.006000, 0.003000,  88, 5280,   60.0,  264.0, 1],
    [0.010000, 0.005000,  85, 5100,   60.0,  255.0, 1],
    [0.012000, 0.008000,  92, 5520,   60.0,  276.0, 1],
    [0.000500, 99.00000, 150, 90000, 600.0,  300.0, 1],
    [0.000800, 99.00000, 140, 84000, 600.0,  280.0, 1],
    # ── BENIGN TRAFFIC ───────────────────────────────────────────────────────
    [5.500000,  8.200000, 200, 280000, 1400.0,  45.0, 0],
    [9.230000,  6.100000, 180, 252000, 1400.0,  30.0, 0],
    [3.400000, 11.500000, 220, 308000, 1400.0,  60.0, 0],
    [7.800000,  4.300000, 160, 224000, 1400.0,  25.0, 0],
    [12.45000, 15.30000,  500, 700000, 1400.0, 120.0, 0],
    [10.20000, 18.60000,  480, 672000, 1400.0, 110.0, 0],
    [14.70000, 12.40000,  520, 728000, 1400.0, 130.0, 0],
    [1.800000,  2.900000, 400, 560000, 1400.0,  20.0, 0],
    [2.100000,  3.400000, 380, 532000, 1400.0,  18.0, 0],
    [0.050000,  0.080000,  10,    600,   60.0,   2.0, 0],
    [0.030000,  0.060000,   8,    480,   60.0,   1.5, 0],
    [4.120000,  5.700000,  60, 120000, 2000.0,  60.0, 0],
    [6.300000,  7.200000,  55, 110000, 2000.0,  55.0, 0],
    [99.00000, 99.00000,   30, 600000, 20000.0, 900.0, 0],
    [99.00000, 99.00000,   25, 500000, 20000.0, 800.0, 0],
    [0.020000,  0.015000,  40,   2400,   60.0,  60.0, 0],
    [0.010000,  0.008000,   4,    288,   72.0,   1.0, 0],
]


def execute_standalone_training():
    model_dir = "models"
    model_pkl = os.path.join(model_dir, "c2_random_forest.pkl")
    csv_path  = os.path.join(model_dir, "c2_training_dataset.csv")

    os.makedirs(model_dir, exist_ok=True)

    if os.path.exists(model_pkl):
        os.remove(model_pkl)
        print("[*] Stale model removed.")

    cols = FEATURE_COLUMNS + ["label"]
    df   = pd.DataFrame(DATASET, columns=cols)
    df.to_csv(csv_path, index=False)
    print(f"[+] Training dataset saved to: {csv_path}  ({len(df)} samples)")

    X = df[FEATURE_COLUMNS].values
    y = df["label"].values

    print("[*] Training Random Forest...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=8,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42
    )
    model.fit(X, y)

    with open(model_pkl, "wb") as fh:
        pickle.dump(model, fh)
    print(f"[+] Model saved to: {model_pkl}")

    # ── EVALUATION ────────────────────────────────────────────────────────────
    # Cross-val predictions — more honest than training accuracy
    # Uses leave-one-out style so each sample is predicted on unseen data
    cv_preds = cross_val_predict(model, X, y, cv=5)

    train_preds  = model.predict(X)
    train_acc    = accuracy_score(y, train_preds) * 100
    cv_acc       = accuracy_score(y, cv_preds) * 100

    cm           = confusion_matrix(y, cv_preds)
    tn, fp, fn, tp = cm.ravel()

    fp_rate = (fp / (fp + tn) * 100) if (fp + tn) > 0 else 0
    fn_rate = (fn / (fn + tp) * 100) if (fn + tp) > 0 else 0

    print("\n" + "=" * 55)
    print("  MODEL EVALUATION REPORT")
    print("=" * 55)
    print(f"  Training Accuracy (on training data) : {train_acc:.1f}%")
    print(f"  Cross-Val Accuracy (honest estimate) : {cv_acc:.1f}%")
    print("=" * 55)
    print("  CONFUSION MATRIX (Cross-Validation)")
    print("=" * 55)
    print(f"                  Predicted")
    print(f"                  Benign    C2")
    print(f"  Actual Benign     {tn:>3}      {fp:>3}   ← False Positives")
    print(f"  Actual C2         {fn:>3}      {tp:>3}   ← True Positives")
    print("=" * 55)
    print(f"  True Positives  (C2 correctly caught)  : {tp}")
    print(f"  True Negatives  (Benign correctly ok'd) : {tn}")
    print(f"  False Positives (Benign flagged as C2)  : {fp}  ({fp_rate:.1f}%)")
    print(f"  False Negatives (C2 missed entirely)    : {fn}  ({fn_rate:.1f}%)")
    print("=" * 55)
    print(classification_report(y, cv_preds,
                                 target_names=["Benign", "C2"],
                                 digits=3))
    print("=" * 55)
    print("  FEATURE IMPORTANCES")
    print("=" * 55)
    for fname, imp in zip(FEATURE_COLUMNS, model.feature_importances_):
        bar = "█" * int(imp * 40)
        print(f"  {fname:22s}: {imp:.4f}  {bar}")
    print("=" * 55)


if __name__ == "__main__":
    execute_standalone_training()