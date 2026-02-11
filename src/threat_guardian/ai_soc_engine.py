import psutil
import time
import re
import os
import socket
from collections import defaultdict
from datetime import datetime

# ================= CONFIG =================

AUTH_LOG = "/var/log/auth.log"
APACHE_LOG = "/var/log/apache2/access.log"

CHECK_INTERVAL = 2
WINDOW = 15
COOLDOWN = 30

SCAN_PORT_THRESHOLD = 15
BRUTE_FORCE_THRESHOLD = 5
WEB_404_THRESHOLD = 20

hostname = socket.gethostname()

# ================= STATE =================

ip_activity = defaultdict(lambda: {
    "ports": set(),
    "connections": 0,
    "failed_logins": 0,
    "web_404": 0,
    "score": 0,
    "last_alert": 0
})

auth_position = 0
apache_position = 0

# ================= UTIL =================

def normalize_ip(ip):
    if ip.startswith("::ffff:"):
        return ip.replace("::ffff:", "")
    return ip

def get_threat_level(score):
    if score >= 15:
        return "CRITICAL"
    elif score >= 10:
        return "HIGH"
    elif score >= 5:
        return "MEDIUM"
    else:
        return "LOW"

def print_event(process, event_type, message,
                ip="N/A", username="N/A"):

    score = ip_activity[ip]["score"] if ip != "N/A" else 0
    level = get_threat_level(score)

    print("\n==============================")
    print("Timestamp   :", datetime.now())
    print("Hostname    :", hostname)
    print("Process     :", process)
    print("Event Type  :", event_type)
    print("IP Address  :", ip)
    print("Username    :", username)
    print("Threat Level:", level)
    print("Threat Score:", score)
    print("Message     :", message)
    print("==============================\n")

# ================= NETWORK MONITOR =================

def monitor_network():

    connections = psutil.net_connections(kind='inet')
    current_time = time.time()

    for conn in connections:
        if conn.raddr:
            ip = normalize_ip(conn.raddr.ip)
            port = conn.raddr.port

            ip_activity[ip]["ports"].add(port)
            ip_activity[ip]["connections"] += 1

            if (len(ip_activity[ip]["ports"]) > SCAN_PORT_THRESHOLD and
                current_time - ip_activity[ip]["last_alert"] > COOLDOWN):

                ip_activity[ip]["score"] += 5

                print_event(
                    process="Network Monitor",
                    event_type="PORT_SCAN_DETECTED",
                    message=f"Multiple ports accessed: {len(ip_activity[ip]['ports'])}",
                    ip=ip
                )

                ip_activity[ip]["last_alert"] = current_time
                ip_activity[ip]["ports"].clear()

# ================= AUTH MONITOR =================

def monitor_auth():

    global auth_position

    if not os.path.exists(AUTH_LOG):
        return

    with open(AUTH_LOG, "r") as f:
        f.seek(auth_position)
        lines = f.readlines()
        auth_position = f.tell()

    for line in lines:

        if "Failed password" in line:
            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            user_match = re.search(r'for (\w+)', line)

            if ip_match:
                ip = ip_match.group(1)
                user = user_match.group(1) if user_match else "unknown"

                ip_activity[ip]["failed_logins"] += 1

                if ip_activity[ip]["failed_logins"] >= BRUTE_FORCE_THRESHOLD:

                    ip_activity[ip]["score"] += 7

                    print_event(
                        process="sshd",
                        event_type="BRUTE_FORCE_ATTACK",
                        message="Multiple failed SSH login attempts",
                        ip=ip,
                        username=user
                    )

                    ip_activity[ip]["failed_logins"] = 0

        if "Accepted password" in line:
            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            user_match = re.search(r'for (\w+)', line)

            if ip_match:
                ip = ip_match.group(1)
                user = user_match.group(1) if user_match else "unknown"

                if ip_activity[ip]["score"] >= 7:

                    ip_activity[ip]["score"] += 10

                    print_event(
                        process="sshd",
                        event_type="COMPROMISE_CONFIRMED",
                        message="Successful login after brute force",
                        ip=ip,
                        username=user
                    )

        if "session opened for user root" in line:

            print_event(
                process="sudo/sshd",
                event_type="PRIVILEGE_ESCALATION",
                message="Root session opened",
                ip="N/A"
            )

# ================= APACHE MONITOR =================

def monitor_apache():

    global apache_position

    if not os.path.exists(APACHE_LOG):
        return

    with open(APACHE_LOG, "r") as f:
        f.seek(apache_position)
        lines = f.readlines()
        apache_position = f.tell()

    for line in lines:

        ip_match = re.search(r'^(\d+\.\d+\.\d+\.\d+)', line)
        if not ip_match:
            continue

        ip = ip_match.group(1)

        # Nikto detection
        if "Nikto" in line:
            ip_activity[ip]["score"] += 8

            print_event(
                process="apache2",
                event_type="WEB_VULN_SCAN",
                message="Nikto scan detected",
                ip=ip
            )

        # SQL Injection
        if any(k in line.lower() for k in
               ["union select", "' or 1=1", "information_schema"]):

            ip_activity[ip]["score"] += 8

            print_event(
                process="apache2",
                event_type="SQL_INJECTION_ATTEMPT",
                message="Possible SQL injection attempt",
                ip=ip
            )

        # XSS
        if "<script>" in line.lower():
            ip_activity[ip]["score"] += 5

            print_event(
                process="apache2",
                event_type="XSS_ATTEMPT",
                message="Possible cross-site scripting attempt",
                ip=ip
            )

        # Directory brute force
        if " 404 " in line:
            ip_activity[ip]["web_404"] += 1

            if ip_activity[ip]["web_404"] >= WEB_404_THRESHOLD:
                ip_activity[ip]["score"] += 5

                print_event(
                    process="apache2",
                    event_type="DIRECTORY_BRUTEFORCE",
                    message="Multiple 404 errors – scanning suspected",
                    ip=ip
                )

                ip_activity[ip]["web_404"] = 0

# ================= WINDOW RESET =================

def reset_window():
    for ip in ip_activity:
        ip_activity[ip]["ports"].clear()
        ip_activity[ip]["connections"] = 0

# ================= MAIN LOOP =================

print("\n🚀 MXDR AI Engine Started...\n")

window_start = time.time()

while True:

    monitor_network()
    monitor_auth()
    monitor_apache()

    if time.time() - window_start > WINDOW:
        reset_window()
        window_start = time.time()

    time.sleep(CHECK_INTERVAL)
