# admin_client.py
import requests
import urllib3

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SERVER = "https://localhost:5000"
VERIFY_SSL = False

def get_password():
    return input("Admin password: ")

def manage_candidates():
    """Manage election candidates"""
    pwd = get_password()
    
    while True:
        print("\n--- CANDIDATE MANAGEMENT ---")
        print("1. Add Candidate")
        print("2. Remove Candidate")
        print("3. List Candidates")
        print("4. Back to Main Menu")
        
        choice = input("Select: ")
        
        if choice == '1':
            name = input("Candidate name: ")
            party = input("Party: ")
            try:
                r = requests.post(f"{SERVER}/admin/add_candidate", 
                                 json={"admin_password": pwd, "name": name, "party": party}, 
                                 verify=VERIFY_SSL)
                print(f"Response: {r.json().get('message', r.text)}")
            except Exception as e:
                print(f"Error: {e}")
                
        elif choice == '2':
            # Show list first
            try:
                r_list = requests.post(f"{SERVER}/admin/list_candidates", 
                                 json={"admin_password": pwd}, 
                                 verify=VERIFY_SSL)
                data_list = r_list.json()
                if data_list.get('ok') and data_list.get('candidates'):
                    print("\n📋 Current Candidates:")
                    for c in data_list['candidates']:
                        print(f"   - {c['name']} ({c['party']})")
                else:
                    print("   (No candidates found)")
            except:
                pass

            name = input("\nEnter candidate name to REMOVE: ")
            try:
                r = requests.post(f"{SERVER}/admin/remove_candidate", 
                                 json={"admin_password": pwd, "name": name}, 
                                 verify=VERIFY_SSL)
                print(f"Response: {r.json().get('message', r.text)}")
            except Exception as e:
                print(f"Error: {e}")
        
        elif choice == '3':
            try:
                r = requests.post(f"{SERVER}/admin/list_candidates", 
                                 json={"admin_password": pwd}, 
                                 verify=VERIFY_SSL)
                data = r.json()
                if data.get('ok'):
                    cands = data.get('candidates', [])
                    if cands:
                        print("\n📋 Candidates Configuration:")
                        print(f"   {'ID':<5} {'Name':<20} {'Party'}")
                        print("   " + "-"*40)
                        for c in cands:
                            print(f"   {c['id']:<5} {c['name']:<20} {c['party']}")
                    else:
                        print("   No candidates found.")
                else:
                    print(f"Error: {data.get('error')}")
            except Exception as e:
                print(f"Error: {e}")
        
        elif choice == '4':
            break
        else:
            print("Invalid option")

def manage_domains():
    """Manage allowed email domains"""
    pwd = get_password()
    
    while True:
        print("\n--- DOMAIN MANAGEMENT ---")
        print("1. Add Domain")
        print("2. Remove Domain")
        print("3. List All Domains")
        print("4. Back to Main Menu")
        
        choice = input("Select: ")
        
        if choice == '1':
            print("\nExamples: nu.edu.pk, gmail.com, yahoo.com")
            domain = input("Enter domain to ADD (without @): ").strip()
            if domain.startswith('@'):
                domain = domain[1:]
            
            try:
                r = requests.post(f"{SERVER}/admin/add_domain", 
                                 json={"admin_password": pwd, "domain": domain}, 
                                 verify=VERIFY_SSL, timeout=10)
                data = r.json()
                if r.status_code == 200:
                    print(f"✅ {data.get('message')}")
                    print(f"   Current domains: {', '.join(['@' + d for d in data.get('domains', [])])}")
                else:
                    print(f"❌ {data.get('error', r.text)}")
            except Exception as e:
                print(f"Error: {e}")
                
        elif choice == '2':
            # List domains first
            try:
                r_list = requests.post(f"{SERVER}/admin/list_domains", 
                                 json={"admin_password": pwd}, 
                                 verify=VERIFY_SSL, timeout=5)
                data_list = r_list.json()
                if data_list.get('ok') and data_list.get('domains'):
                    print("\n📋 Current Allowed Domains:")
                    for d in data_list['domains']:
                        print(f"   - @{d}")
                else:
                    print("   (No domains configured)")
            except:
                pass

            domain = input("\nEnter domain to REMOVE (without @): ").strip()
            if domain.startswith('@'):
                domain = domain[1:]
            
            try:
                r = requests.post(f"{SERVER}/admin/remove_domain", 
                                 json={"admin_password": pwd, "domain": domain}, 
                                 verify=VERIFY_SSL, timeout=10)
                data = r.json()
                if r.status_code == 200:
                    print(f"✅ {data.get('message')}")
                    remaining = data.get('domains', [])
                    if remaining:
                        print(f"   Remaining domains: {', '.join(['@' + d for d in remaining])}")
                    else:
                        print("   No domains remaining.")
                else:
                    print(f"❌ {data.get('error', r.text)}")
            except Exception as e:
                print(f"Error: {e}")
                
        elif choice == '3':
            try:
                r = requests.post(f"{SERVER}/admin/list_domains", 
                                 json={"admin_password": pwd}, 
                                 verify=VERIFY_SSL, timeout=10)
                data = r.json()
                if r.status_code == 200:
                    domains = data.get('domains', [])
                    if domains:
                        print("\n📋 Allowed Domains:")
                        for i, d in enumerate(domains, 1):
                            print(f"   {i}. @{d}")
                    else:
                        print("\n⚠️  No domains configured.")
                else:
                    print(f"Error: {data.get('error', r.text)}")
            except Exception as e:
                print(f"Error: {e}")
                
        elif choice == '4':
            break
        else:
            print("Invalid option")

def start_election():
    print("\n--- START/INITIALIZE ELECTION ---")
    pwd = get_password()
    
    print("\nOptions:")
    print("  1. Start NEW election (reset voters and votes)")
    print("  2. Resume existing election (keep votes)")
    choice = input("Select (1 or 2): ")
    
    reset_votes = (choice == '1')
    
    if reset_votes:
        print("\n⚠️  WARNING: This will:")
        print("   - Delete ALL registered voters")
        print("   - Delete ALL votes")
        print("\n💡 TIP: Configure allowed domains via 'Manage Email Domains' option BEFORE starting.")
        confirm = input("\nContinue? (yes/no): ")
        if confirm.lower() != 'yes':
            print("Aborted.")
            return
    
    try:
        payload = {"admin_password": pwd, "reset_votes": reset_votes}
            
        r = requests.post(f"{SERVER}/admin/start_election", 
                         json=payload, 
                         verify=VERIFY_SSL,
                         timeout=10)
        if r.status_code == 200:
            print(f"✅ {r.json().get('message', r.text)}")
        else:
            try:
                print(f"Error ({r.status_code}): {r.json().get('error', r.text)}")
            except:
                print(f"Error ({r.status_code}): {r.text[:200]}")
    except requests.exceptions.ConnectionError:
        print("Error: Cannot connect to server. Is server.py running?")
    except Exception as e:
        print(f"Error: {e}")

def end_election():
    print("\n--- END ELECTION & BROADCAST RESULTS ---")
    pwd = get_password()
    confirm = input("Are you sure you want to END the election and broadcast results? (yes/no): ")
    if confirm.lower() != 'yes':
        print("Aborted.")
        return
        
    try:
        r = requests.post(f"{SERVER}/admin/end_election", 
                         json={"admin_password": pwd}, 
                         verify=VERIFY_SSL)
        data = r.json()
        print(f"Response: {data.get('message', r.text)}")
        
        if 'report' in data:
            print("\n" + data['report'])
    except Exception as e:
        print(f"Error: {e}")

def view_status():
    print("\n--- ELECTION STATUS ---")
    pwd = get_password()
    
    try:
        r = requests.post(f"{SERVER}/admin/get_status", 
                         json={"admin_password": pwd}, 
                         verify=VERIFY_SSL)
        data = r.json()
        if data.get('ok'):
            print(f"\n  Election Status:    {'ENDED' if data['election_ended'] else 'ONGOING'}")
            domains = data.get('allowed_domains', [])
            if domains:
                print(f"  Allowed Domains:    {', '.join(['@' + d for d in domains])}")
            else:
                print(f"  Allowed Domains:    (none configured)")
            print(f"  Registered Voters:  {data['registered_voters']}")
            print(f"  Votes Cast:         {data['votes_cast']}")
        else:
            print(f"Error: {data.get('error')}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    print("=" * 50)
    print("       E-VOTING SYSTEM - ADMIN PANEL")
    print("=" * 50)
    print(f"Server: {SERVER}")
    
    while True:
        print("\n=== ADMIN MENU ===")
        print("1. Manage Email Domains (Add/Remove)")
        print("2. Manage Candidates (Add/Remove/List)")
        print("3. Start/Initialize Election")
        print("4. End Election & Broadcast Results")
        print("5. View Election Status")
        print("6. Exit")
        
        choice = input("\nSelect option: ")
        
        if choice == '1':
            manage_domains()
        elif choice == '2':
            manage_candidates()
        elif choice == '3':
            start_election()
        elif choice == '4':
            end_election()
        elif choice == '5':
            view_status()
        elif choice == '6':
            print("Goodbye!")
            break
        else:
            print("Invalid option. Please try again.")
