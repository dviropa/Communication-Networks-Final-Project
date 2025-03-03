import scapy.all as scapy
import numpy as np
import pandas as pd
import os

CSV = "knn.csv"
LABEL_MAPPING = {
    "youtube": "YouTube",
    "spotify": "Spotify",
    "zoom": "Zoom"
}
def extract_features(pcap_file):
    packets = scapy.rdpcap(pcap_file)
    total_packets = len(packets)
    total_bytes = sum(len(pkt) for pkt in packets)
    avg_packet_size = total_bytes / total_packets if total_packets > 0 else 0

    timestamps = [float(pkt.time) for pkt in packets if hasattr(pkt, 'time')]
    inter_arrival_times = np.diff(timestamps).astype(float) if len(timestamps) > 1 else [0.0]
    avg_inter_arrival = float(np.mean(inter_arrival_times)) if len(inter_arrival_times) > 0 else 0.0
    return [total_packets, total_bytes, avg_packet_size, avg_inter_arrival]

def determine_label(filename):
    filename = filename.lower()
    for key, label in LABEL_MAPPING.items():
        if key in filename:
            return label
    return "General"

def add_pcap_to_csv(pcap_file):
    features = extract_features(pcap_file)
    if features is None:
        print(f"failed to add {pcap_file} due to an error.")
        return

    label = determine_label(os.path.basename(pcap_file))


    new_data = pd.DataFrame([features + [label]], columns=["total_packets", "total_bytes", "avg_packet_size", "avg_inter_arrival", "label"])


    try:
        df = pd.read_csv(CSV)
    except (FileNotFoundError, pd.errors.EmptyDataError):
        df = pd.DataFrame(columns=["total_packets", "total_bytes", "avg_packet_size", "avg_inter_arrival", "label"])


    df = pd.concat([df, new_data], ignore_index=True)


    df.to_csv(CSV, index=False)
    print(f"Added {pcap_file} to {CSV}")
if __name__ == "__main__":
    add_pcap_to_csv("Spotify.pcap")