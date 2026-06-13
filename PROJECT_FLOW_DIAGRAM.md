# Project Flow Diagrams

## 1. Sequence Diagram (Step-by-Step Flow)

This diagram shows the detailed step-by-step interaction between all system components, including the security monitoring by Wireshark/TShark.

```mermaid
sequenceDiagram
    autonumber
    actor Admin
    actor Voter
    participant Browser as Web Browser
    participant Server as Flask Server
    participant DB as Database
    participant Email as Email Service
    participant MQTT as MQTT Broker
    participant TShark as Wireshark/TShark Monitor

    %% Phase 1: Setup & Monitoring
    Note over Admin, TShark: Phase 1: Election Setup & Monitoring Start
    
    Admin->>Server: Start Election (POST /start_election)
    Server->>DB: Reset/Initialize Data
    Server->>TShark: Start Network Capture (Popen tshark.exe)
    TShark-->>Server: [Background Process Started]
    Note right of TShark: Continuously capturing packets (Port 5000, 1883)

    %% Phase 2: Voter Registration
    Note over Voter, DB: Phase 2: Voter Registration
    
    Voter->>Browser: Opens Registration Page
    Browser->>Server: Register (CNIC, Email, Password)
    Server->>DB: Check if already registered
    Server->>Email: Validate Email Domain
    Server->>DB: Create Voter Record
    Server-->>Browser: Registration Successful

    %% Phase 3: Voting Process
    Note over Voter, DB: Phase 3: Voting Process
    
    Voter->>Browser: Request OTP
    Browser->>Server: POST /request_otp
    Server->>Email: Generate & Send OTP
    Email-->>Voter: Email with OTP Code
    
    Voter->>Browser: Enters OTP
    Browser->>Server: POST /verify_otp
    Server->>DB: Verify OTP & Check Expiry
    Server-->>Browser: Return Voting Token
    
    Voter->>Browser: Selects Candidate & Submits Vote
    Browser->>Server: POST /vote (Token + Candidate ID)
    Server->>DB: Validate Token & Check Double Voting
    Server->>DB: Update Candidate Vote Count
    Server->>DB: Append Vote to Ledger (Blockchain-like Hash)
    
    %% Real-time Update
    Server->>MQTT: Publish "Vote Cast" Event
    MQTT-->>Browser: Update Live Dashboard (Total Votes Only)
    
    Server-->>Browser: Vote Success Receipt

    %% Phase 4: Security Monitoring (Concurrent)
    Note over TShark, Server: Continuous Security Monitoring
    
    loop Every Packet
        TShark->>TShark: Capture & Analyze Traffic
        Note right of TShark: Detecting: ARP Spoofing,<br/>SYN Floods, Retransmissions
    end

    %% Phase 5: Election Conclusion
    Note over Admin, Browser: Phase 5: Election Conclusion
    
    Admin->>Server: End Election (POST /end_election)
    Server->>DB: Update Status to 'Ended'
    Server->>TShark: Stop Capture
    TShark->>TShark: Generate Traffic Analysis Report
    Server->>DB: Save Security Report
    
    Server->>MQTT: Broadcast FINAL Results
    MQTT-->>Browser: Show Winner & Detailed Results
    
    Admin->>Server: Get Status/Report
    Server-->>Admin: Return Election Stats + TShark Security Report
```

## 2. System Architecture (Component View)

```mermaid
graph TD
    %% Actors
    User((Voter))
    Admin((Administrator))

    %% Components
    subgraph "Client Side"
        Browser[Web Browser]
        AdminCLI[Admin Client]
    end

    subgraph "Server Side"
        FlaskServer[Flask Server]
        DB[(SQLite DB)]
        MQTT[MQTT Broker]
    end

    subgraph "Security Layer"
        TShark[Wireshark/TShark]
        RateLimiter{Rate Limiter}
    end

    %% Connections
    User -->|1. Registers/Votes| Browser
    Browser -->|2. HTTP Request| FlaskServer
    FlaskServer -->|3. Check Limit| RateLimiter
    FlaskServer -->|4. Store Data| DB
    FlaskServer -->|5. Publish Update| MQTT
    MQTT -->|6. Push to Client| Browser
    
    Admin -->|Manage| AdminCLI
    AdminCLI -->|API Calls| FlaskServer

    %% Wireshark Connection
    FlaskServer -.->|Network Traffic| Net(Network Interface)
    TShark -->|Sniffs| Net
    TShark -->|Generates Report| FlaskServer
```
