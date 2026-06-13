import time
import socket
import requests
import smtplib
import os
from email.mime.text import MIMEText
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# CONFIGURATION
CHECK_INTERVAL = 5  # Seconds
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
# (Ideally load these from .env, but for demo we can mock the alert or ask user to set env)
ALERT_EMAIL_FROM = os.getenv("SENDER_EMAIL", "admin@evm.system") 
ALERT_EMAIL_TO = os.getenv("SENDER_EMAIL", "admin@evm.system")
ALERT_PASSWORD = os.getenv("SENDER_PASSWORD", "")

# SERVICES TO MONITOR
SERVICES = [
    {"name": "Web Server (HTTPS)", "type": "https", "target": "https://localhost:5000", "critical": True},
    {"name": "Log Server (UDP)",   "type": "udp",   "ip": "127.0.0.1", "port": 5140, "critical": False},
    {"name": "MQTT Broker (TCP)",  "type": "tcp",   "ip": "127.0.0.1", "port": 1883, "critical": True}
]

def check_https(url):
    try:
        # We verify=False because of self-signed certs
        resp = requests.get(url, verify=False, timeout=3)
        return resp.status_code == 200
    except:
        return False

def check_tcp(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        sock.close()
        return True
    except:
        return False

def check_udp_log_server(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        start = time.time()
        sock.sendto(b'PING', (ip, port))
        data, _ = sock.recvfrom(1024)
        sock.close()
        return data == b'PONG'
    except:
        return False

def send_alert(service_name):
    if not ALERT_PASSWORD:
        print(f"   [!] ALERT: {service_name} is DOWN! (Email skipped: No credentials)")
        return

    try:
        msg = MIMEText(f"CRITICAL ALERT: The {service_name} is invalid or unreachable as of {datetime.now()}. Check immediately.")
        msg['Subject'] = f"DOWN Alert: {service_name}"
        msg['From'] = ALERT_EMAIL_FROM
        msg['To'] = ALERT_EMAIL_TO

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(ALERT_EMAIL_FROM, ALERT_PASSWORD)
            server.send_message(msg)
        print(f"   [!] ALERT EMAIL SENT for {service_name}")
    except Exception as e:
        print(f"   [!] Failed to send email alert: {e}")

def run_monitor():
    print("="*60)
    print("NETWORK HEALTH MONITOR (HEARTBEAT)")
    print("Checking services every 5 seconds...")
    print("="*60)

    # Disable requests warning for cleaner output
    requests.packages.urllib3.disable_warnings()

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"--- Health Check at {datetime.now().strftime('%H:%M:%S')} ---")
        
        all_ok = True
        
        for service in SERVICES:
            is_up = False
            if service["type"] == "https":
                is_up = check_https(service["target"])
            elif service["type"] == "tcp":
                is_up = check_tcp(service["ip"], service["port"])
            elif service["type"] == "udp":
                is_up = check_udp_log_server(service["ip"], service["port"])
            
            status = "💚 UP" if is_up else "🔴 DOWN"
            print(f"{status.ljust(8)} {service['name']}")
            
            if not is_up:
                all_ok = False
                send_alert(service['name'])
        
        print("-" * 40)
        if all_ok:
            print("System Status: HEALTHY")
        else:
            print("System Status: CRITICAL ISSUES DETECTED")
            
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    run_monitor()
