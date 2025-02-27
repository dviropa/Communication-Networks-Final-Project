import scapy.all as scapy
import numpy as np
import pandas as pd
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import StandardScaler
import joblib
import os



MODEL_FILE = "knn_model.pkl"
SCALER_FILE = "scaler.pkl"
TRAINING_CSV = "knn.csv"

# פונקציה לחילוץ תכונות מקובץ PCAP
def extract_features(pcap_file):
    packets = scapy.rdpcap(pcap_file)
    total_packets = len(packets)
    total_bytes = sum(len(pkt) for pkt in packets)
    avg_packet_size = total_bytes / total_packets if total_packets > 0 else 0

    timestamps = [float(pkt.time) for pkt in packets if hasattr(pkt, 'time')]
    inter_arrival_times = np.diff(timestamps).astype(float) if len(timestamps) > 1 else [0.0]
    avg_inter_arrival = float(np.mean(inter_arrival_times)) if len(inter_arrival_times) > 0 else 0.0
    return [total_packets, total_bytes, avg_packet_size, avg_inter_arrival]
def __load_csv( filename):
    try:
        _=pd.read_csv(filename)
        return _
    except (FileNotFoundError, pd.errors.EmptyDataError):
        return pd.DataFrame()


def train_model():
    df = __load_csv(TRAINING_CSV)

    if df.empty:
        print("Error: No training data available.")
        return

    X, y = df.drop(columns=["label"]), df["label"]

    # Check for NaN values
    if X.isnull().values.any():
        print("Warning: NaN values detected in training data. Filling missing values with median.")
        X = X.fillna(X.median())  # Replace NaN with median values

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    knn = KNeighborsClassifier(n_neighbors=3)
    knn.fit(X_scaled, y)

    joblib.dump(knn, MODEL_FILE)
    joblib.dump(scaler, SCALER_FILE)
    print("Model trained and saved.")

def predict_traffic(pcap_file):
    knn, scaler = joblib.load(MODEL_FILE), joblib.load(SCALER_FILE)

    features = extract_features(pcap_file)
    feature_names = ["total_packets", "total_bytes", "avg_packet_size", "avg_inter_arrival"]
    features_df = pd.DataFrame([features], columns=feature_names)

    prediction = knn.predict(scaler.transform(features_df))
    print(f"Predicted Traffic Type: {prediction[0]}")


# ריצה ראשונית
if __name__ == "__main__":
    train_model()
    predict_traffic("Spotify.pcap")
