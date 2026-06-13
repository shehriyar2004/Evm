# E-Voting System with Email OTP Verification
## Computer Network Semester Project

This is a secure electronic voting system that implements various network concepts including:
- **SMTP Protocol** for email communication
- **TLS/SSL** for secure connections
- **MQTT Protocol** for real-time vote updates
- **WebSockets** for live dashboard updates
- **Domain-based Email Validation** for access control

---

## Network Concepts Implemented

### 1. SMTP (Simple Mail Transfer Protocol)
- **Location**: `email_service.py`
- **Purpose**: Sends OTP tokens via email using SMTP protocol
- **Features**:
  - STARTTLS for secure email transmission
  - EHLO handshake with SMTP server
  - Authentication with email credentials
  - HTML and plain text email formatting

### 2. Domain-Based Email Validation
- **Location**: `email_service.py` - `validate_email_domain()`
- **Purpose**: Restricts OTP delivery to specific email domains
- **Implementation**: Only emails from the configured domain (e.g., @university.edu) can receive OTPs
- **Network Concept**: Demonstrates access control at the application layer

### 3. TLS/SSL Encryption
- **SMTP TLS**: Encrypts email communication using STARTTLS
- **HTTPS**: Server can run with SSL certificates for encrypted web traffic
- **Location**: Certificate configuration in `server.py` startup

### 4. MQTT (Message Queuing Telemetry Transport)
- **Purpose**: Real-time voting updates
- **Broker**: localhost:1883
- **Topic**: `voting/updates`

### 5. WebSockets
- **Purpose**: Live dashboard updates using Socket.IO
- **Implementation**: Real-time vote count updates to connected clients

---

## Email OTP Verification Flow

```
1. User Registration
   ├─> User provides: CNIC, Name, Email, Password
   ├─> System validates email domain
   └─> Account created if domain matches allowed domain

2. Request OTP
   ├─> User requests OTP with CNIC
   ├─> System generates 6-digit OTP
   ├─> OTP sent via SMTP to registered email
   └─> OTP valid for 5 minutes

3. Verify OTP
   ├─> User enters received OTP code
   ├─> System validates OTP and expiry
   └─> Issues voting token upon success

4. Cast Vote
   ├─> User submits vote with token
   ├─> Token consumed (one-time use)
   └─> Vote recorded in blockchain-style ledger
```

---

## Setup Instructions

### 1. Install Dependencies

```powershell
pip install -r requirements.txt.txt
```

### 2. Configure Email Settings

**For Gmail Users:**
1. Enable 2-Factor Authentication on your Google account
2. Generate an App Password:
   - Go to: https://myaccount.google.com/apppasswords
   - Create app password for "Mail"
   - Copy the 16-character password

**Create .env file** (optional):
```bash
cp .env.example .env
```

Edit `.env` with your settings:
```
SENDER_EMAIL=your-email@gmail.com
SENDER_PASSWORD=your-16-char-app-password
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
ALLOWED_EMAIL_DOMAIN=university.edu
```

### 3. Initialize Database

```powershell
python init_db.py
```

### 4. Start the Server

```powershell
python server.py
```

You will be prompted to enter:
- **Allowed email domain** (e.g., `university.edu`)
- **SMTP configuration** (if not set in .env)

### 5. Access the System

- **Web Interface**: http://localhost:5000
- **API Endpoints**: See API Documentation below

---

## API Endpoints

### Registration
**POST** `/register`

```json
{
  "cnic": "12345-1234567-1",
  "name": "John Doe",
  "email": "john@university.edu",
  "password": "securepass123"
}
```

**Response:**
```json
{
  "ok": true,
  "message": "Registered successfully",
  "email": "john@university.edu"
}
```

### Request OTP
**POST** `/request_otp`

```json
{
  "cnic": "12345-1234567-1"
}
```

**Response:**
```json
{
  "ok": true,
  "message": "OTP sent to john@university.edu",
  "email": "john@university.edu",
  "expiry_seconds": 300
}
```

**Network Activity:**
- SMTP connection established to mail server
- TLS negotiation via STARTTLS
- Email delivered with OTP code

### Verify OTP
**POST** `/verify_otp`

```json
{
  "cnic": "12345-1234567-1",
  "otp": "123456"
}
```

**Response:**
```json
{
  "ok": true,
  "message": "OTP verified successfully",
  "voting_token": "abc123def456...",
  "cnic": "12345-1234567-1"
}
```

### Cast Vote
**POST** `/vote`

```json
{
  "token": "abc123def456...",
  "candidate_id": 1
}
```

**Response:**
```json
{
  "ok": true,
  "message": "Vote recorded"
}
```

**Network Activity:**
- Vote published to MQTT broker
- WebSocket broadcast to all connected clients
- Real-time dashboard updates

### Get Results
**GET** `/results`

**Response:**
```json
{
  "ok": true,
  "results": [
    {"id": 1, "name": "Imran Khan", "party": "Party A", "votes": 150},
    {"id": 2, "name": "Nawaz Sharif", "party": "Party B", "votes": 120},
    {"id": 3, "name": "Bilawal Bhutto", "party": "Party C", "votes": 98}
  ]
}
```

---

## Database Schema

### voters
- `cnic` (PRIMARY KEY): Voter ID
- `name`: Voter name
- `email`: Email address (domain validated)
- `password_hash`: Bcrypt hashed password
- `totp_secret`: TOTP secret (for future 2FA)
- `has_voted`: Boolean flag

### tokens
- `token` (PRIMARY KEY): Unique token
- `cnic`: Associated voter
- `otp`: 6-digit OTP code
- `used`: Boolean flag
- `expiry`: Unix timestamp

### candidates
- `id` (PRIMARY KEY): Candidate ID
- `name`: Candidate name
- `party`: Political party
- `votes`: Vote count

### votes_ledger
- `id` (PRIMARY KEY): Sequential ID
- `vote_hash`: SHA256 hash of vote
- `prev_hash`: Previous vote hash (blockchain-style)
- `candidate_id`: Voted candidate
- `timestamp`: ISO timestamp

---

## Network Protocols Used

| Protocol | Port | Purpose | Implementation |
|----------|------|---------|----------------|
| HTTP/HTTPS | 5000 | Web API & Dashboard | Flask |
| SMTP | 587 | Email OTP delivery | smtplib + TLS |
| MQTT | 1883 | Real-time vote updates | paho-mqtt |
| WebSocket | 5000 | Live dashboard | Socket.IO |

---

## Security Features

1. **Domain Validation**: Only whitelisted email domains can register
2. **Password Hashing**: Bcrypt with salt
3. **OTP Expiry**: 5-minute validity window
4. **One-Time Tokens**: Tokens consumed after single use
5. **TLS Encryption**: SMTP STARTTLS for email security
6. **Vote Integrity**: Blockchain-style hash chain in ledger

---

## Testing the Email Feature

### Test Registration with Domain Validation

```bash
# Valid domain - should succeed
curl -X POST http://localhost:5000/register \
  -H "Content-Type: application/json" \
  -d '{"cnic":"11111-1111111-1","name":"Alice","email":"alice@university.edu","password":"pass123"}'

# Invalid domain - should fail
curl -X POST http://localhost:5000/register \
  -H "Content-Type: application/json" \
  -d '{"cnic":"22222-2222222-2","name":"Bob","email":"bob@gmail.com","password":"pass123"}'
```

### Test OTP Flow

```bash
# 1. Request OTP
curl -X POST http://localhost:5000/request_otp \
  -H "Content-Type: application/json" \
  -d '{"cnic":"11111-1111111-1"}'

# 2. Check email for OTP code

# 3. Verify OTP (replace 123456 with actual OTP)
curl -X POST http://localhost:5000/verify_otp \
  -H "Content-Type: application/json" \
  -d '{"cnic":"11111-1111111-1","otp":"123456"}'

# 4. Vote with token
curl -X POST http://localhost:5000/vote \
  -H "Content-Type: application/json" \
  -d '{"token":"<token-from-step-3>","candidate_id":1}'
```

---

## Troubleshooting

### Email Not Sending

1. **Check SMTP credentials**: Verify email/password in .env or startup prompt
2. **Gmail App Password**: Regular Gmail password won't work - use App Password
3. **Firewall**: Ensure port 587 is not blocked
4. **SMTP Server**: Verify server address (smtp.gmail.com for Gmail)

### Domain Validation Failing

- Ensure domain is entered without @ symbol (e.g., `university.edu` not `@university.edu`)
- Domain matching is case-insensitive
- Email must exactly match: `user@allowed-domain.com`

### Database Errors

```powershell
# Reset database
Remove-Item voting.db -ErrorAction SilentlyContinue
python init_db.py
```

---

## Project Structure

```
evm_project/
├── server.py              # Main Flask application
├── email_service.py       # SMTP email service with domain validation
├── config.py              # Configuration management
├── init_db.py             # Database initialization
├── admin_client.py        # Admin interface
├── requirements.txt.txt   # Python dependencies
├── .env.example           # Environment variables template
├── templates/
│   ├── client.py          # Client application
│   └── dashboard.html     # Web dashboard
├── certs/                 # SSL/TLS certificates
└── rsa_keys/              # RSA key pairs

```

---

## Network Concepts Summary

This project demonstrates:

1. **Application Layer Protocols**:
   - HTTP/HTTPS for RESTful API
   - SMTP for email delivery
   - WebSocket for bidirectional communication

2. **Transport Layer**:
   - TCP connections for reliable data transfer
   - Port management (5000, 587, 1883)

3. **Security**:
   - TLS/SSL encryption
   - Application-level authentication
   - Domain-based access control

4. **Messaging Patterns**:
   - Request-Response (HTTP API)
   - Publish-Subscribe (MQTT)
   - Push (WebSocket)

---

## Contributors

Network Security Semester Project

## License

Educational Project - For Academic Use Only
