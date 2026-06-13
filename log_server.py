import socket
import datetime
import os

# Configuration
LOG_IP = "127.0.0.1"
LOG_PORT = 5140  # non-privileged port (standard syslog is 514)
BUFFER_SIZE = 1024
LOG_FILE = "network_audit.log"

def start_syslog_server():
    print("=" * 60)
    print("CENTRALIZED SYSLOG SERVER (UDP)")
    print("Network Security Project - Log Aggregator")
    print("=" * 60)
    
    # Create UDP Socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        sock.bind((LOG_IP, LOG_PORT))
        print(f"✓ Listening for logs on UDP {LOG_IP}:{LOG_PORT}")
        print(f"✓ Saving logs to: {os.path.abspath(LOG_FILE)}")
        print("------------------------------------------------------------")
        
        while True:
            # Receive UDP packet
            data, addr = sock.recvfrom(BUFFER_SIZE)
            message = data.decode('utf-8')
            
            # Health Check Responder
            if message == 'PING':
                sock.sendto(b'PONG', addr)
                continue
                
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"[{timestamp}] FROM {addr}: {message}"
            
            # Print to console
            print(log_entry)
            
            # Write to file
            with open(LOG_FILE, "a") as f:
                f.write(log_entry + "\n")
                
    except KeyboardInterrupt:
        print("\nStopping Syslog Server...")
    except Exception as e:
        print(f"\nError: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    start_syslog_server()
