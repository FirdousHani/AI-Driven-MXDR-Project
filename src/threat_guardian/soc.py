import psutil
import time
import os
import socket
import pickle
import numpy as np
from collections import defaultdict
from datetime import datetime
from sklearn.svm import OneClassSVM

# ================= SECURITY CHECK =================
if os.geteuid() != 0:
    print("⚠️  Run with sudo")
    exit(1)

# ================= CONFIG =================
CHECK_INTERVAL = 2
MODEL_PATH = "model.pkl"
BASELINE_SAMPLES = 50  # Samples required before training

hostname = socket.gethostname()

# ================= ML STATE =================
zero_day_detector = None
model_trained = False
baseline_data = []

ip_activity = defaultdict(lambda: {
    "connections": 0,
    "ports": set()
})

# ================= INITIALIZE MODEL =================
def init_ml_model():
    global zero_day_detector, model_trained

    if os.path.exists(MODEL_PATH):
        with open(MODEL_PATH, "rb") as f:
            zero_day_detector = pickle.load(f)
        model_trained = True
        print("✅ Loaded trained model")
    else:
        zero_day_detector = OneClassSVM(kernel="rbf", nu=0.05, gamma="scale")
        print("⚠️  Unsupervised anomaly detector (Learning baseline...)")

# ================= FEATURE EXTRACTION =================
def extract_features(ip):
    activity = ip_activity[ip]

    features = np.array([
        len(activity["ports"]),                        # Unique ports
        activity["connections"],                       # Total connections
        activity["connections"] / max(len(activity["ports"]), 1),  # Ratio
        len([p for p in activity["ports"] if p < 1024]),           # Privileged ports
        len([p for p in activity["ports"] if p >= 1024]),          # High ports
        time.localtime().tm_hour,                     # Hour of day
        activity["connections"] % 10                  # Burst pattern
    ])

    return features.reshape(1, -1)

# ================= ANOMALY DETECTION =================
def detect_anomaly(ip):
    global model_trained, baseline_data

    features = extract_features(ip)

    # ---------- Phase 1: Collect Baseline ----------
    if not model_trained:
        baseline_data.append(features[0])

        if len(baseline_data) >= BASELINE_SAMPLES:
            zero_day_detector.fit(np.array(baseline_data))
            model_trained = True

            # Save trained model
            with open(MODEL_PATH, "wb") as f:
                pickle.dump(zero_day_detector, f)

            print("\n✅ Baseline learned. AI detector ACTIVE.\n")

        return False, 0.0

    # ---------- Phase 2: Detect ----------
    prediction = zero_day_detector.predict(features)[0]

    if prediction == -1:
        score = abs(zero_day_detector.decision_function(features)[0])
        return True, float(score)

    return False, 0.0

# ================= ALERT FORMAT =================
def print_alert(ip, score):
    now = datetime.now()

    print("\n" + "=" * 60)
    print("🚨 AI SECURITY ALERT")
    print("=" * 60)

    print(f"Timestamp:   {now.strftime('%b %d %H:%M:%S')}")
    print(f"Hostname:    {hostname}")
    print(f"Process:     network-monitor[{os.getpid()}]")
    print(f"Event Type:  ANOMALY_DETECTED")
    print(f"Message:     Suspicious network behavior detected")
    print(f"IP Address:  {ip}")
    print(f"Username:    N/A")
    print(f"Anomaly Score: {score:.4f}")

    print("=" * 60)

# ================= LIVE MONITOR =================
def monitor_network():
    connections = psutil.net_connections(kind="inet")

    for conn in connections:
        if conn.raddr:
            ip = conn.raddr.ip
            port = conn.raddr.port

            ip_activity[ip]["connections"] += 1
            ip_activity[ip]["ports"].add(port)

            # Check every 5 connections
            if ip_activity[ip]["connections"] % 5 == 0:
                is_anomaly, score = detect_anomaly(ip)
                if is_anomaly:
                    print_alert(ip, score)

# ================= MAIN =================
if __name__ == "__main__":

    print("\n🚀 PROJECT 3: AI Anomaly Detection IDS")
    print("• Learns normal behavior automatically")
    print("• Flags abnormal activity → ALERT")
    print("• Zero-shot detection (no signatures)")
    print("• Real-time monitoring\n")

    init_ml_model()

    try:
        while True:
            monitor_network()
            time.sleep(CHECK_INTERVAL)
    except KeyboardInterrupt:
        print("\n🛑 Stopped")
