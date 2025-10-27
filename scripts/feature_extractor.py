# Feature extraction logic here
"""
Phase 2: Feature Normalization & Mapping
- Reads raw packets CSV
- Cleans and normalizes values
- Creates ML/detection-ready feature dataset
"""

import pandas as pd
import os

RAW_PATH = os.path.join(os.path.dirname(__file__), "../data/raw_packets/captured_packets.csv")
OUT_PATH = os.path.join(os.path.dirname(__file__), "../data/processed/processed_features.csv")

def normalize_tcp_flags(flag_value):
    if pd.isna(flag_value):
        return 0
    return 1 if "S" in str(flag_value) else 0  # SYN = connection attempt

def normalize_arp_op(op):
    return int(op) if pd.notna(op) else 0  # 1=request, 2=reply

def main():
    print("[Phase 2] Loading raw CSV...")
    df = pd.read_csv(RAW_PATH)

    print("[Phase 2] Normalizing features...")

    df["tcp_syn"] = df["tcp_flags"].apply(normalize_tcp_flags)
    df["arp_op"] = df["arp_op"].apply(normalize_arp_op)

    df["ip_proto"] = df["ip_proto"].fillna(0).astype(int)
    df["udp_dport"] = df["udp_dport"].fillna(0).astype(int)
    df["tcp_dport"] = df["tcp_dport"].fillna(0).astype(int)

    df = df.fillna("None")

    print("[Phase 2] Saving processed CSV...")
    df.to_csv(OUT_PATH, index=False)

    print(f"[✅ Phase 2 Complete] Processed file saved at {OUT_PATH}")

if __name__ == "__main__":
    main()
