
import requests
import threading
import time
import sys

# Configuration
TARGET_URL = "http://localhost:5000/"  # Monitor checks port 5000
REQUEST_COUNT = 1500  # Enough to trigger >1000 threshold
CONCURRENT_THREADS = 50

print("="*60)
print("       DDoS SIMULATION / LOAD TESTER")
print("="*60)
print(f"Target: {TARGET_URL}")
print(f"Goal:   {REQUEST_COUNT} requests")
print("="*60)

def send_request(counter):
    try:
        # We just hit the root endpoint or any lightweight endpoint
        r = requests.get(TARGET_URL, timeout=2)
        status = r.status_code
        if status == 429:
            print(f"[{counter}] Blocked (429) - Server Rate Limiter Active!", end='\r')
        else:
            print(f"[{counter}] Sent ({status})", end='\r')
    except Exception as e:
        print(f"[{counter}] Connection Error: {e}", end='\r')

def attack():
    threads = []
    start_time = time.time()
    
    print("\n[+] Starting packet flood...")
    
    for i in range(REQUEST_COUNT):
        t = threading.Thread(target=send_request, args=(i+1,))
        threads.append(t)
        t.start()
        
        # Limit concurrency slightly to avoid crashing the test script itself
        if len(threads) >= CONCURRENT_THREADS:
            for t in threads:
                t.join()
            threads = []
            
    # Join remaining
    for t in threads:
        t.join()
        
    duration = time.time() - start_time
    print(f"\n\n[✓] Test Completed in {duration:.2f} seconds.")
    print(f"    Rate: {REQUEST_COUNT / duration:.2f} req/s")
    print("\nNow CHECK THE ELECTION REPORT (End Election) to see 'SUSPICIOUS PACKETS' count.")

if __name__ == "__main__":
    confirm = input("Are you sure you want to simulate high traffic? (y/n): ")
    if confirm.lower() == 'y':
        attack()
    else:
        print("Aborted.")
