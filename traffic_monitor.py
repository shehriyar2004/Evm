
import subprocess
import os
import time
import threading
import sys

# Configuration
INTERFACE = 'Adapter for loopback traffic capture' 
CAPTURE_FILE = "election_traffic.pcap"
TSHARK_PATH = os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 'Wireshark', 'tshark.exe')

if not os.path.exists(TSHARK_PATH):
    # Try x86
    TSHARK_PATH = os.path.join(os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)'), 'Wireshark', 'tshark.exe')

class TrafficAnalyzer:
    def __init__(self):
        self.process = None
        self.capture_file = os.path.abspath(CAPTURE_FILE)

    def start_capture(self):
        """Start capturing traffic to a pcap file."""
        if self.process:
            self.stop_capture()

        # Remove previous capture file if exists
        if os.path.exists(self.capture_file):
            try:
                os.remove(self.capture_file)
            except Exception as e:
                print(f"Error removing old pcap: {e}")

        cmd = [
            TSHARK_PATH,
            '-i', INTERFACE,
            '-f', 'port 5000 or port 1883 or port 587 or port 8883', # Filter relevant ports
            '-w', self.capture_file,
            '-q'  # Quiet mode
        ]
        
        try:
            # excessive buffering or waiting might be an issue, but writing to file should be fast
            self.process = subprocess.Popen(cmd)
            print(f"Started TShark capture to {self.capture_file} (PID: {self.process.pid})")
            return True
        except Exception as e:
            print(f"Failed to start TShark: {e}")
            return False

    def stop_capture(self):
        """Stop the running TShark process."""
        if self.process:
            print("Stopping TShark capture...")
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.process = None
            # Wait a moment for file handle release
            time.sleep(1)

    def generate_report(self):
        """Analyze the captured pcap file and generate a text report."""
        if not os.path.exists(self.capture_file):
            return "No capture file found. capture might not have run."

        report = []
        report.append("="*60)
        report.append("       NETWORK TRAFFIC ANALYSIS REPORT")
        report.append(f"       Generated: {time.ctime()}")
        report.append("="*60)
        
        # 1. IO Statistics (Traffic Volume)
        try:
            cmd = [TSHARK_PATH, '-r', self.capture_file, '-q', '-z', 'io,stat,0']
            res = subprocess.run(cmd, capture_output=True, text=True)
            report.append("\n[1] TRAFFIC VOLUME SUMMARY")
            report.append(res.stdout.strip())
        except Exception as e:
            report.append(f"\n[Error running basic stats]: {e}")

        # 2. Expert Info (Anomalies, Malformed, Warnings)
        try:
            cmd = [TSHARK_PATH, '-r', self.capture_file, '-q', '-z', 'expert']
            res = subprocess.run(cmd, capture_output=True, text=True)
            report.append("\n[2] EXPERT INFORMATION (ANOMALIES/WARNINGS)")
            report.append(res.stdout.strip())
        except Exception:
            pass

        # 3. Security Analysis (Custom Filters)
        report.append("\n[3] SECURITY & ANOMALY DETECTION")
        
        anomalies = []
        
        # Helper to run count
        def count_filter(name, filter_str):
            # -Y filter -T fields -e frame.number | wc -l
            # Using -z io,stat,0 is faster for counting but lets specific text search?
            # actually -Y with wc is easier logic in python or just check if output is empty
            c = [TSHARK_PATH, '-r', self.capture_file, '-Y', filter_str, '-T', 'fields', '-e', 'frame.number']
            r = subprocess.run(c, capture_output=True, text=True)
            count = len(r.stdout.strip().split('\n')) if r.stdout.strip() else 0
            return count

        # A. TCP Retransmissions (Network Issues/Congestion/DoS)
        retrans = count_filter("Retransmissions", "tcp.analysis.retransmission")
        if retrans > 0:
            anomalies.append(f"[!] TCP Retransmissions detected: {retrans} packets. (Possible Congestion/Packet Loss)")
        else:
            report.append("[-] No significant retransmissions.")

        # B. Duplicate ACKs
        dup_ack = count_filter("Duplicate ACKs", "tcp.analysis.duplicate_ack")
        if dup_ack > 0:
            anomalies.append(f"[!] Duplicate ACKs detected: {dup_ack} packets. (Possible Packet Loss)")
        
        # C. SYN Flooding Check (High volume of SYN without ACK)
        # Simplified check: Just count SYNs. Real analysis requires state tracking.
        syn_count = count_filter("SYNs", "tcp.flags.syn==1 and tcp.flags.ack==0")
        if syn_count > 1000:
             anomalies.append(f"[!] High potential for SYN Flooding: {syn_count} SYN packets detected.")

        # D. ARP Spoofing (Duplicate IP usage)
        # tshark expert usually catches 'arp.duplicate-address-detected'
        arp_dup = count_filter("ARP Duplicates", "arp.duplicate-address-detected")
        if arp_dup > 0:
            anomalies.append(f"[CRITICAL] ARP Spoofing / IP Conflict detected: {arp_dup} events.")

        # E. HTTP Error Codes (4xx/5xx) - Application anomalies
        http_err = count_filter("HTTP Errors", "http.response.code >= 400")
        if http_err > 0:
            anomalies.append(f"[!] HTTP Errors (4xx/5xx) detected: {http_err} responses.")

        if anomalies:
            for a in anomalies:
                report.append(a)
        else:
            report.append("[-] No major specific anomalies detected by custom filters.")

        report.append("\n" + "="*60)
        return "\n".join(report)

    def generate_layman_report(self):
        """Analyze the captured pcap file and generate a simple layman-understandable text report."""
        if not os.path.exists(self.capture_file):
            return "Security Report Unavailable: No traffic data was captured."

        report = []
        
        # Helper to run count
        def count_filter(filter_str):
            c = [TSHARK_PATH, '-r', self.capture_file, '-Y', filter_str, '-T', 'fields', '-e', 'frame.number']
            r = subprocess.run(c, capture_output=True, text=True)
            count = len(r.stdout.strip().split('\n')) if r.stdout.strip() else 0
            return count

        # Metric Collection
        retrans = count_filter("tcp.analysis.retransmission")
        dup_ack = count_filter("tcp.analysis.duplicate_ack")
        syn_count = count_filter("tcp.flags.syn==1 and tcp.flags.ack==0")
        arp_dup = count_filter("arp.duplicate-address-detected")
        http_err = count_filter("http.response.code >= 400")

        # Extended Metrics
        total_packets_cmd = [TSHARK_PATH, '-r', self.capture_file, '-q', '-z', 'io,stat,0']
        total_res = subprocess.run(total_packets_cmd, capture_output=True, text=True)
        # Try to parse total packets from io,stat output roughly or just use frame count
        total_packets = count_filter("frame")

        # Delays / High Latency (Time delta > 0.2s)
        high_latency = count_filter("frame.time_delta_displayed > 0.2")
        
        # Handshake Failures (Reset packets)
        rst_count = count_filter("tcp.flags.reset==1")
        
        # Malformed Packets
        malformed = count_filter("_ws.expert.severity == \"Error\"")
        
        # Protocol counts
        tls_count = count_filter("tls")
        http_count = count_filter("http")
        mqtt_count = count_filter("mqtt")
        
        # Misconfigurations (Plaintext passwords or HTTP usage)
        # Note: We filter for port 5000/HTTP usually, but checking for non-TLS auth would be complex.
        # Simple check: Ratio of HTTP vs TLS
        
        # --- BUILD REPORT ---
        report.append("🔍 WIRESHARK TRAFFIC ANALYSIS REPORT")
        report.append("===================================")
        report.append(f"TOTAL PACKETS ANALYZED: {total_packets}")
        report.append("")
        
        # 1. TRAFFIC OVERVIEW
        report.append("[1] TRAFFIC OVERVIEW")
        report.append(f"   • Protocols: HTTP ({http_count}), TLS ({tls_count}), MQTT ({mqtt_count})")
        report.append(f"   • General Behavior: {' predominantly Encrypted' if tls_count > http_count else ' Mixed/Unencrypted'}")
        report.append("")
        
        # 2. ANOMALY DETECTION
        report.append("[2] ANOMALY DETECTION")
        
        # Packet Loss / Retransmission
        if retrans > 0 or dup_ack > 0:
             report.append(f"   ⚠ PACKET LOSS DETECTED")
             report.append(f"     - Retransmissions: {retrans}")
             report.append(f"     - Duplicate ACKs:  {dup_ack}")
             report.append("     (Indicates network congestion or connectivity issues)")
        else:
             report.append("   ✅ No Packet Loss or Retransmissions detected.")

        # Delays
        if high_latency > 0:
            report.append(f"   ⚠ HIGH LATENCY: {high_latency} packets took >200ms")
        else:
            report.append("   ✅ Latency: Minimal (All packets <200ms)")
            
        # Handshake / Malformed
        if rst_count > 0 or malformed > 0:
            report.append(f"   ⚠ CONNECTION ERRORS")
            if rst_count > 0: report.append(f"     - Reset Connections: {rst_count} (Handshake failures)")
            if malformed > 0: report.append(f"     - Malformed Packets: {malformed}")
        else:
            report.append("   ✅ Handshakes: Stable (No resets or malformed packets)")
            
        report.append("")

        # 3. SECURITY EVALUATION
        report.append("[3] SECURITY EVALUATION")
        if arp_dup > 0:
            report.append("   ⛔ CRITICAL: ARP SPOOFING DETECTED")
            report.append(f"     - {arp_dup} conflicting ARP packets found.")
        elif syn_count > 1000:
            report.append("   ⛔ CRITICAL: DoS/FLOODING ATTACK DETECTED")
            report.append(f"     - SYN Flood: {syn_count} malicious connection attempts.")
        elif syn_count > 100:
             report.append("   ⚠ SUSPICIOUS ACTIVITY: Port Scanning or High Traffic")
             report.append(f"     - {syn_count} rapid connection attempts.")
        else:
             report.append("   ✅ No Security Threats Detected")
             report.append("     - No Flooding, Spoofing, or Scanning signatures found.")

        # 4. MISCONFIGURATIONS
        report.append("")
        report.append("[4] CONFIGURATION AUDIT")
        if http_count > 0 and tls_count == 0:
            report.append("   ⚠ WARNING: Unencrypted HTTP Traffic Detected")
            report.append("     - Recommendation: Enforce HTTPS/TLS for all connections.")
        elif http_err > 0:
             report.append(f"   ⚠ SERVER MISCONFIGURATION: {http_err} HTTP Errors (4xx/5xx)")
        else:
             report.append("   ✅ Configurations appear nominal.")

        return "\n".join(report)

# Global Instance
traffic_analyzer = TrafficAnalyzer()
