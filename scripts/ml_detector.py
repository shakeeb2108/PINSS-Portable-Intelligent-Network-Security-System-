# ML-based detection (optional)
"""
Phase 7: AI-Based Anomaly Detection using Isolation Forest
"""

import os
import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

PROCESSED_PATH = os.path.join(os.path.dirname(__file__), "../data/processed/processed_features.csv")
MODEL_PATH = os.path.join(os.path.dirname(__file__), "../data/models/isolation_forest.pkl")

# Features used for training
FEATURE_COLUMNS = ["ip_proto", "tcp_syn", "tcp_sport", "tcp_dport", "udp_sport", "udp_dport", "arp_op"]

def train_model():
    print("🚀 Loading processed features...")
    df = pd.read_csv(PROCESSED_PATH)
    
    print("✅ Selecting numeric ML features...")
    df_ml = df[FEATURE_COLUMNS].fillna(0)
    
    print("📊 Training Isolation Forest model...")
    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    model.fit(df_ml)
    
    print(f"💾 Saving model to {MODEL_PATH} ...")
    joblib.dump(model, MODEL_PATH)
    print("✅ Model training complete!")

def load_model():
    return joblib.load(MODEL_PATH)

def predict_anomaly(sample_df):
    """Returns True if anomaly detected."""
    model = load_model()
    pred = model.predict(sample_df[FEATURE_COLUMNS])
    return (pred[0] == -1)  # -1 means anomaly

if __name__ == "__main__":
    train_model()
