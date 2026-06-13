import webbrowser
import time
import sys

# Configuration
SERVER_URL = "https://localhost:5000/portal"

def open_portal():
    print("=" * 60)
    print("LAUNCHING VOTER PORTAL")
    print("Secure E-Voting System")
    print("=" * 60)
    
    print("\n[INFO] Opening your default web browser...")
    print(f"[INFO] Connecting to: {SERVER_URL}")
    
    # Wait a moment to simulate connection check
    time.sleep(1)
    
    try:
        webbrowser.open(SERVER_URL)
        print("\n✓ Portal launched successfully!")
        print("   If the browser did not open, please visit:")
        print(f"   {SERVER_URL}")
    except Exception as e:
        print(f"\n[ERROR] Failed to open browser: {e}")

    print("\n(Press any key to exit launcher...)")
    try:
        input() 
    except:
        pass

if __name__ == "__main__":
    open_portal()
