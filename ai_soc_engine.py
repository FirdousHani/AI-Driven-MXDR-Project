import psutil
import time
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import socket
import getpass
import platform
from datetime import datetime
from collections import defaultdict, deque
import threading
import sys

class BehavioralSOC:
    def __init__(self):
        self.entry_count = 1
        self.hostname = platform.node()
        self.username = getpass.getuser()
        self.engine_name = "BehavioralSOC"
        self.is_training = True
        self.training_data = []
        self.scaler = StandardScaler()
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.ip_features = defaultdict(lambda: {
            'conn_count': deque(maxlen=50),
            'port_diversity': deque(maxlen=50),
            'conn_rate': deque(maxlen=50),
            'unique_ports': set()
        })
        self.last_features = {}
        self.training_start = time.time()
        self.alert_lock = threading.Lock()
        
    def is_external_ip(self, ip):
        """Ignore localhost and private IPs"""
        try:
            if ip == '127.0.0.1' or ip == '::1':
                return False
            socket.inet_aton(ip)
            # Check private ranges
            octets = ip.split('.')
            if len(octets) == 4:
                if octets[0] in ['10', '172', '192'] or (octets[0] == '169' and octets[1] == '254'):
                    return False
            return True
        except:
            return False
    
    def extract_features(self, ip):
        """Extract behavioral features for ML"""
        features = self.ip_features[ip]
        
        # Connection count (current window)
        conn_count = len(features['conn_count'])
        
        # Port diversity (unique ports / total connections)
        unique_ports = len(features['unique_ports'])
        port_diversity = unique_ports / max(conn_count, 1)
        
        # Connection rate (connections per second)
        if len(features['conn_rate']) > 0:
            conn_rate = np.mean(features['conn_rate'])
        else:
            conn_rate = 0
        
        # Time since first connection (session age)
        session_age = time.time() - self.training_start
        
        return [conn_count, port_diversity, conn_rate, session_age]
    
    def update_features(self, ip):
        """Update behavioral features for IP"""
        timestamp = time.time()
        features = self.ip_features[ip]
        
        # Update connection count
        features['conn_count'].append(1)
        
        # Update connection rate (connections per second)
        features['conn_rate'].append(1.0 / max(timestamp - list(features['conn_count'])[-1] if len(features['conn_count']) > 1 else 1, 0.1))
        
    def collect_network_data(self):
        """Collect live network connections"""
        connections = psutil.net_connections(kind='inet')
        active_ips = defaultdict(set)

        for conn in connections:
            # Make sure remote address exists
            if conn.raddr:
                remote_ip = conn.raddr[0]
                remote_port = conn.raddr[1]

                if self.is_external_ip(remote_ip):
                    active_ips[remote_ip].add(remote_port)
                    self.update_features(remote_ip)

        # Update port diversity
        for ip, ports in active_ips.items():
            self.ip_features[ip]['unique_ports'] = ports

        return list(active_ips.keys())
    
    def train_baseline(self):
        """Train ML baseline from normal behavior"""
        print("Training baseline... (60-120s)")
        while self.is_training:
            ips = self.collect_network_data()
            for ip in ips:
                features = self.extract_features(ip)
                self.training_data.append(features)
            
            if len(self.training_data) >= 100:  # Sufficient training data
                self.training_data = np.array(self.training_data)
                self.scaler.fit(self.training_data)
                self.isolation_forest.fit(self.scaler.transform(self.training_data))
                self.is_training = False
                print("Baseline trained. Monitoring active.")
                return
            
            time.sleep(1)
    
    def detect_anomalies(self):
        """Real-time anomaly detection"""
        while True:
            try:
                ips = self.collect_network_data()
                now = time.time()
                
                for ip in ips:
                    features = np.array([self.extract_features(ip)]).reshape(1, -1)
                    scaled_features = self.scaler.transform(features)
                    anomaly_score = self.isolation_forest.decision_function(scaled_features)[0]
                    is_anomaly = self.isolation_forest.predict(scaled_features)[0] == -1
                    
                    if is_anomaly and anomaly_score < self.last_features.get(ip, 0):
                        # Calculate deviation score
                        deviation_score = -anomaly_score  # Negative anomaly scores are more anomalous
                        
                        self.alert(ip, deviation_score)
                        self.last_features[ip] = anomaly_score
                
                time.sleep(2)  # Check every 2 seconds
                
            except Exception:
                time.sleep(1)
    
    def alert(self, ip, deviation_score):
        """Generate SOC alert"""
        with self.alert_lock:
            timestamp = datetime.now().strftime("%b %d %H:%M:%S")
            
            print(f"\n[Entry {self.entry_count}]")
            print(f"Timestamp:   {timestamp}")
            print(f"Hostname:    {self.hostname}")
            print(f"Process:     {self.engine_name}")
            print(f"Event Type:  BEHAVIORAL_ANOMALY")
            print(f"Message:     IP {ip} exhibits anomalous connection patterns (deviation: {deviation_score:.3f})")
            print(f"IP Address:  {ip}")
            print(f"Username:    {self.username}")
            print("------------------------------------------------------------")
            
            self.entry_count += 1

def main():
    soc = BehavioralSOC()
    
    # Train baseline in main thread
    training_thread = threading.Thread(target=soc.train_baseline, daemon=True)
    training_thread.start()
    
    # Start detection after training
    while soc.is_training:
        time.sleep(1)
    
    # Real-time monitoring
    detection_thread = threading.Thread(target=soc.detect_anomalies, daemon=True)
    detection_thread.start()
    
    try:
        # Keep main thread alive
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        print("\nSOC monitoring stopped.")
        sys.exit(0)

if __name__ == "__main__":
    main()
