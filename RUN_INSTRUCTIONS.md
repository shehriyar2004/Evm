# 🚀 E-Voting System - Complete Run Instructions

This document provides a step-by-step guide to running the full E-Voting System, including all advanced networking, security, and monitoring features.

## 📋 Prerequisites
- Python 3.8+
- Wireshark/Npcap (for Traffic Monitor)
- Mosquitto MQTT Broker (Embedded/Installed)

---

## 🛠️ Step 1: Install Dependencies
Open a terminal in the `evm_project2` folder and run:
```powershell
pip install -r requirements.txt
```

---

## 🖥️ Step 2: Start the System Components
You will need **6 separate terminal windows** to run the full system simulation.

### 1. 📡 Run MQTT Broker (Messaging Infrastructure)
This handles real-time vote updates securely over TLS.
*Open Terminal 1:*
```powershell
cd evm_project2
./start_broker.ps1
```
*Leave this running.*

### 2. 📝 Run Syslog Server (Centralized Logging)
Collects audit logs (UDP) from the main server.
*Open Terminal 2:*
```powershell
cd evm_project2
python log_server.py
```

### 3. 🗳️ Run Main Server (Backend Core)
The heart of the application. Handles voting logic, DB, and RSA encryption.
*Open Terminal 3:*
```powershell
cd evm_project2
python server.py
```
*Note: If asked, enter allowed email domains (e.g., `gmail.com`).*

### 4. 💾 Run Backup Node (Data Redundancy)
Simulates a distributed node that replicates the database and votes.
*Open Terminal 4:*
```powershell
cd evm_project2
python backup_node.py
```

### 5. 🏥 Run Health Monitor (System Watchdog)
Periodically checks if the Server, Broker, and Logger are alive. Sends email alerts if DOWN.
*Open Terminal 5:*
```powershell
cd evm_project2
python health_monitor.py
```



---

## 👤 Step 3: User Interaction

### 🌐 Voter Interface
Open your browser and go to:
**[http://localhost:5000](http://localhost:5000)**
- **Register**: Sign up with a valid email (domain must match what you configured).
- **Vote**: Cast your vote securely.
- **Verify**: Check your vote integrity using the Receipt Hash.

### 👮 Admin Interface
Manage the election (Add candidates, End Election).
*Use a new terminal:*
```powershell
cd evm_project2
python admin_client.py
```
- **Login**: (Default password in `config.py` is `adminpass` or check your `.env` file).
- **End Election**: Broadcasting results via MQTT and clearing the database.

---

## ✨ Key Features Showcase

| Feature | Description | File(s) |
| :--- | :--- | :--- |
| **🛡️ DoS Protection** | Rate-limiting logic blocks IPs sending too many requests. | `server.py` |
| **🔐 RSA Security** | Votes are digitally signed. Signatures stored in `votes_ledger`. | `server.py` (RSA functions) |
| **📡 Real-time Updates** | Live vote counts pushed to clients via MQTT over TLS. | `server.py`, `dashboard.html` |
| **📝 Central Logging** | Audit logs sent to Syslog Server via UDP. | `log_server.py`, `server.py` |
| **💾 Data Redundancy** | Backup node replicates data in real-time. | `backup_node.py` |
| **🏥 Health Check** | Watchdog service monitors system uptime. | `health_monitor.py` |
| **📧 OTP Auth** | Two-factor authentication via Email/OTP. | `email_service.py` |
