import os
import sqlite3
import json
import bcrypt
import time
import secrets
import hashlib
import base64
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_socketio import SocketIO, emit
import paho.mqtt.client as mqtt
import pyotp
import threading
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from email_service import EmailService
from config import Config
from traffic_monitor import traffic_analyzer

# Initialize configuration
config = Config()

# Global email service instance (will be initialized after domain input)
email_service = None

# RSA keys for vote signing
private_key = None
public_key = None

DB_FILE = config.DB_FILE
MQTT_BROKER = config.MQTT_BROKER
MQTT_PORT = config.MQTT_PORT
MQTT_TOPIC = config.MQTT_TOPIC
JWT_SECRET = config.JWT_SECRET
TOKEN_TTL_SECONDS = config.TOKEN_TTL_SECONDS

# Flask app and SocketIO
app = Flask(__name__, static_folder="static", template_folder="templates")
app.config['SECRET_KEY'] = config.SECRET_KEY
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ==========================================
# 🛡️ SECURITY FEATURE: DoS/DDoS PROTECTION
# ==========================================
from collections import defaultdict, deque

class RateLimiter:
    def __init__(self, limit=50, window=60):
        self.limit = limit  # Max requests
        self.window = window  # Time window in seconds
        self.requests = defaultdict(lambda: deque())

    def is_allowed(self, ip):
        now = time.time()
        timestamps = self.requests[ip]
        
        # Remove old timestamps
        while timestamps and timestamps[0] < now - self.window:
            timestamps.popleft()
            
        if len(timestamps) >= self.limit:
            return False
            
        timestamps.append(now)
        return True

# Initialize Rate Limiter (Limit: 20 requests per minute per IP)
# Initialize Rate Limiter (Limit: 100 requests per minute per IP to avoid blocking during testing)
# Initialize Rate Limiter (Limit: 30 requests per minute per IP)
limiter = RateLimiter(limit=30, window=60)

@app.before_request
def check_rate_limit():
    # whitelist static files and socket.io
    if request.path.startswith('/static') or 'socket.io' in request.path:
        return
        
    client_ip = request.remote_addr
    if not limiter.is_allowed(client_ip):
        print(f"⚠ BLOCKED IP {client_ip} - Rate Limit Exceeded")
        return jsonify({
            "ok": False,
            "error": "Too Many Requests (DoS Protection Enabled). Please try again later."
        }), 429
# ==========================================


# MQTT client used to publish vote updates
mqtt_client = mqtt.Client()
mqtt_connected = False

def mqtt_connect():
    global mqtt_connected
    def on_connect(client, userdata, flags, rc):
        global mqtt_connected
        print("MQTT connected with result code", rc)
        mqtt_connected = True
    mqtt_client.on_connect = on_connect
    
    try:
        # Check if TLS certificates exist
        if os.path.exists(config.SSL_CERT_PATH) and os.path.exists(config.SSL_KEY_PATH):
            try:
                mqtt_client.tls_set(
                    ca_certs=config.SSL_CERT_PATH,
                    certfile=config.SSL_CERT_PATH,
                    keyfile=config.SSL_KEY_PATH
                )
                print("✓ MQTT TLS encryption enabled")
                # Use secure port 8883 if TLS is enabled
                mqtt_client.connect(MQTT_BROKER, 8883, 60)
            except Exception as e:
                print(f"⚠ MQTT TLS setup failed: {e}")
                print("  Falling back to unencrypted connection on port 1883")
                mqtt_client.connect(MQTT_BROKER, MQTT_PORT, 60)
        else:
            print("⚠ MQTT TLS certificates not found, using unencrypted connection")
            mqtt_client.connect(MQTT_BROKER, MQTT_PORT, 60)
        
        mqtt_client.loop_start()
        mqtt_connected = True
    except Exception as e:
        print(f"⚠ MQTT connection failed: {e}")
        print("   Server will run without real-time MQTT updates.")
        mqtt_connected = False

# DB helper with a simple lock
db_lock = threading.Lock()
def get_db_conn():
    try:
        conn = sqlite3.connect(DB_FILE, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        print(f"DATABASE ERROR: {e}")
        return None

def get_election_state():
    """Returns 'NOT_STARTED', 'ONGOING', or 'ENDED'"""
    with db_lock:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT value FROM settings WHERE key = 'election_initialized'")
        row_init = cur.fetchone()
        initialized = row_init and row_init['value'] == 'true'
        
        cur.execute("SELECT value FROM settings WHERE key = 'election_ended'")
        row_ended = cur.fetchone()
        ended = row_ended and row_ended['value'] == 'true'
        conn.close()
    
    if not initialized:
        return "NOT_STARTED"
    if ended:
        return "ENDED"
    return "ONGOING"

def get_election_status():
    """Legacy: Check if election has ended (returns True if ended)"""
    return get_election_state() == "ENDED"

def set_election_status(ended: bool):
    with db_lock:
        conn = get_db_conn()
        cur = conn.cursor()
        val = 'true' if ended else 'false'
        cur.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('election_ended', ?)", (val,))
        conn.commit()
        conn.close()

# ==========================================
# 📡 UDP SYSLOG CLIENT IMPLEMENTATION
# ==========================================
import socket
SYSLOG_IP = "127.0.0.1"
SYSLOG_PORT = 5140

def send_syslog(message, level="INFO"):
    """
    Send audit log to remote UDP Syslog Server.
    Demonstrates UDP protocol (Fire-and-forget).
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        log_msg = f"[{level}] {message}"
        sock.sendto(log_msg.encode(), (SYSLOG_IP, SYSLOG_PORT))
        sock.close()
    except Exception as e:
        print(f"⚠ Failed to send syslog: {e}")
# ==========================================

# Utility functions
def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def check_password(password: str, pw_hash: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), pw_hash)

# RSA cryptography functions
def load_rsa_keys():
    """Load RSA private and public keys from files"""
    global private_key, public_key
    
    try:
        # Load private key
        with open(config.RSA_PRIVATE_KEY_PATH, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        
        # Load public key
        with open(config.RSA_PUBLIC_KEY_PATH, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        
        print("✓ RSA keys loaded successfully")
        return True
    except Exception as e:
        print(f"⚠ Warning: Could not load RSA keys: {e}")
        return False

def sign_vote_data(data: str) -> str:
    """
    Sign vote data with RSA private key for integrity verification.
    Returns base64-encoded signature.
    """
    if not private_key:
        return ""
    
    try:
        signature = private_key.sign(
            data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')
    except Exception as e:
        print(f"Error signing data: {e}")
        return ""

def verify_vote_signature(data: str, signature_b64: str) -> bool:
    """
    Verify RSA signature of vote data.
    Returns True if signature is valid, False otherwise.
    """
    if not public_key or not signature_b64:
        return False
    
    try:
        signature = base64.b64decode(signature_b64)
        public_key.verify(
            signature,
            data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def create_one_time_token(cnic, otp=None):
    """
    Create a one-time token for voting.
    If OTP is provided, store it for later verification.
    """
    token = secrets.token_urlsafe(32)
    expiry = int(time.time()) + TOKEN_TTL_SECONDS
    
    with db_lock:
        conn = get_db_conn()
        cur = conn.cursor()
        # Store token with optional OTP
        if otp:
            cur.execute("INSERT INTO tokens (token, cnic, otp, used, expiry) VALUES (?, ?, ?, 0, ?)",
                        (token, cnic, otp, expiry))
        else:
            cur.execute("INSERT INTO tokens (token, cnic, used, expiry) VALUES (?, ?, 0, ?)",
                        (token, cnic, expiry))
        conn.commit()
        conn.close()
    
    return token, expiry

def validate_and_consume_token(token):
    with db_lock:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT cnic, used, expiry FROM tokens WHERE token = ?", (token,))
        row = cur.fetchone()
        if not row:
            conn.close()
            return False, "Invalid token"
        if row["used"]:
            conn.close()
            return False, "Token already used"
        if int(time.time()) > row["expiry"]:
            conn.close()
            return False, "Token expired"
        # mark as used
        cur.execute("UPDATE tokens SET used = 1 WHERE token = ?", (token,))
        conn.commit()
        conn.close()
    return True, row["cnic"]

def record_vote_and_broadcast(cnic, candidate_id):
    # atomic update
    with db_lock:
        conn = get_db_conn()
        cur = conn.cursor()
        
        # check has voted
        cur.execute("SELECT has_voted FROM voters WHERE cnic = ?", (cnic,))
        row = cur.fetchone()
        if not row:
            conn.close()
            return False, "Voter not found"
        if row["has_voted"]:
            conn.close()
            return False, "Already voted"
        
        # Validate candidate exists
        cur.execute("SELECT id FROM candidates WHERE id = ?", (candidate_id,))
        if not cur.fetchone():
            conn.close()
            return False, f"Invalid candidate ID: {candidate_id}"

        # update candidate votes
        cur.execute("UPDATE candidates SET votes = votes + 1 WHERE id = ?", (candidate_id,))
        # mark voter as voted
        cur.execute("UPDATE voters SET has_voted = 1 WHERE cnic = ?", (cnic,))

        # compute ledger hash: prev_hash + candidate_id + timestamp
        cur.execute("SELECT vote_hash FROM votes_ledger ORDER BY id DESC LIMIT 1")
        last = cur.fetchone()
        prev_hash = last["vote_hash"] if last else ""
        ts = datetime.now(timezone.utc).isoformat()
        payload = f"{prev_hash}|{candidate_id}|{ts}"
        vote_hash = hashlib.sha256(payload.encode()).hexdigest()
        
        # Sign the vote with RSA private key for integrity
        vote_signature = sign_vote_data(payload)
        
        # Store vote with signature in ledger
        cur.execute("INSERT INTO votes_ledger (vote_hash, prev_hash, candidate_id, timestamp, signature) VALUES (?, ?, ?, ?, ?)",
                    (vote_hash, prev_hash, candidate_id, ts, vote_signature))
        vote_id = cur.lastrowid  # Get the ID of the inserted vote
        conn.commit()
        
        # AUDIT LOG (UDP)
        send_syslog(f"VOTE_CAST: Candidate={candidate_id}, VoteHash={vote_hash}...", level="AUDIT")

        # Build results snapshot
        cur.execute("SELECT id, name, party, votes FROM candidates")
        rows = cur.fetchall()
        results = [{"id": r["id"], "name": r["name"], "party": r["party"], "votes": r["votes"]} for r in rows]
        conn.close()

    # Determine if we should broadcast FULL results or just a "vote cast" notification
    election_ended = get_election_status()
    
    if election_ended:
        # If election ended (which shouldn't happen here usually if we block voting), broadcast full
        payload_json = json.dumps({"type": "update", "results": results, "timestamp": ts, "election_ended": True})
        mqtt_client.publish(MQTT_TOPIC, payload_json)
        socketio.emit('vote_update', payload_json)
    else:
        # SECRECY: During election, do NOT broadcast candidate vote counts.
        # Just broadcast that a vote happened so dashboard can maybe show "Total Votes" or "Live Activity"
        # but NOT who is winning.
        total_votes = sum(c['votes'] for c in results)
        masked_payload = json.dumps({
            "type": "vote_cast", 
            "total_votes": total_votes,
            "timestamp": ts,
            "election_ended": False
        })
        mqtt_client.publish(MQTT_TOPIC, masked_payload)
        socketio.emit('vote_update', masked_payload)
    
    # Return vote receipt information
    return True, {
        "message": "Vote recorded",
        "vote_id": vote_id,
        "vote_hash": vote_hash,
        "timestamp": ts
    }

# Flask routes
@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/portal')
def portal_home():
    return render_template('portal.html')

@app.route('/portal/register')
def portal_register():
    domains = email_service.allowed_domains if email_service else []
    return render_template('register.html', domains=domains)

@app.route('/portal/vote')
def portal_vote():
    return render_template('vote.html')

@app.route('/portal/verify')
def portal_verify():
    return render_template('verify.html')

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    cnic = data.get("cnic")
    name = data.get("name")
    email = data.get("email")
    password = data.get("password")
    
    if not all([cnic, name, email, password]):
        return jsonify({"ok": False, "error": "Missing fields"}), 400
    
    # Validate email domain
    if email_service:
        is_valid, error_msg = email_service.validate_email_domain(email)
        if not is_valid:
            return jsonify({"ok": False, "error": error_msg}), 400
    
    with db_lock:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT cnic FROM voters WHERE cnic = ?", (cnic,))
        if cur.fetchone():
            conn.close()
            return jsonify({"ok": False, "error": "CNIC already registered"}), 400
        
        # Check if email already registered
        cur.execute("SELECT email FROM voters WHERE email = ?", (email,))
        if cur.fetchone():
            conn.close()
            return jsonify({"ok": False, "error": "Email already registered"}), 400
        
        password_hash = hash_password(password)
        # Optional: create a TOTP secret for user (if using app-based OTP)
        totp_secret = pyotp.random_base32()
        cur.execute("INSERT INTO voters (cnic, name, email, password_hash, totp_secret, has_voted) VALUES (?, ?, ?, ?, ?, 0)",
                    (cnic, name, email, password_hash, totp_secret))
        conn.commit()
        conn.close()
    
    return jsonify({"ok": True, "message": "Registered successfully", "email": email})

@app.after_request
def log_request(response):
    if request.path == '/login' and response.status_code == 200:
        send_syslog(f"USER_LOGIN: IP={request.remote_addr}", level="AUTH")
    elif request.path == '/register' and response.status_code == 200:
        send_syslog(f"NEW_REGISTRATION: IP={request.remote_addr}", level="AUTH")
    return response

@app.route('/request_otp', methods=['POST'])
def request_otp():
    """
    Request OTP token via email.
    Demonstrates email communication and domain validation.
    """
    data = request.json
    cnic = data.get("cnic")
    
    if not cnic:
        return jsonify({"ok": False, "error": "Missing cnic"}), 400
    
    # Check if email service is initialized
    if not email_service:
        return jsonify({"ok": False, "error": "Email service not configured"}), 500
    
    # Fetch voter information
    with db_lock:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT cnic, email, name, has_voted FROM voters WHERE cnic = ?", (cnic,))
        voter = cur.fetchone()
        conn.close()
    
    if not voter:
        return jsonify({"ok": False, "error": "CNIC not registered"}), 400

    if voter["has_voted"]:
        return jsonify({"ok": False, "error": "User has already voted"}), 400
    
    if not voter["email"]:
        return jsonify({"ok": False, "error": "No email associated with this CNIC"}), 400
    
    # Generate OTP
    otp = email_service.generate_otp(6)
    
    # Create one-time token in database (store OTP for verification)
    token, expiry = create_one_time_token(cnic, otp)
    
    # Send OTP via email in a separate thread to avoid blocking
    def send_async_email(email, otp_code, user_cnic):
        try:
            print(f"Sending OTP to {email}...")
            email_service.send_otp_email(email, otp_code, user_cnic)
            print("OTP sent successfully (Async).")
        except Exception as e:
            print(f"Failed to send async OTP: {e}")

    threading.Thread(target=send_async_email, args=(voter["email"], otp, cnic)).start()
    
    return jsonify({
        "ok": True, 
        "message": f"OTP is being sent to {voter['email']}", 
        "email": voter["email"],
        "expiry_seconds": TOKEN_TTL_SECONDS
    })

@app.route('/verify_token', methods=['POST'])
def verify_token():
    """Legacy token verification endpoint"""
    data = request.json
    token = data.get("token")
    ok, res = validate_and_consume_token(token)
    if not ok:
        return jsonify({"ok": False, "error": res}), 400
    # res is cnic
    return jsonify({"ok": True, "cnic": res})

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    """
    Verify OTP code and issue voting token.
    This demonstrates the OTP verification flow.
    """
    data = request.json
    cnic = data.get("cnic")
    otp = data.get("otp")
    
    if not (cnic and otp):
        return jsonify({"ok": False, "error": "Missing cnic or OTP"}), 400
    
    with db_lock:
        conn = get_db_conn()
        cur = conn.cursor()
        
        # Find the most recent unused token for this CNIC with matching OTP
        cur.execute("""
            SELECT token, otp, used, expiry 
            FROM tokens 
            WHERE cnic = ? AND otp = ? AND used = 0 
            ORDER BY expiry DESC 
            LIMIT 1
        """, (cnic, otp))
        
        row = cur.fetchone()
        conn.close()
    
    if not row:
        return jsonify({"ok": False, "error": "Invalid OTP or OTP already used"}), 400
    
    # Check expiry
    if int(time.time()) > row["expiry"]:
        return jsonify({"ok": False, "error": "OTP expired. Please request a new one"}), 400
    
    # OTP is valid - return the token for voting
    voting_token = row["token"]
    
    return jsonify({
        "ok": True, 
        "message": "OTP verified successfully",
        "voting_token": voting_token,
        "cnic": cnic
    })

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    cnic = data.get("cnic")
    password = data.get("password")
    if not (cnic and password):
        return jsonify({"ok": False, "error": "Missing fields"}), 400
    with db_lock:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT password_hash, has_voted FROM voters WHERE cnic = ?", (cnic,))
        row = cur.fetchone()
        conn.close()
    if not row:
        return jsonify({"ok": False, "error": "CNIC not registered"}), 400
    pw_hash = row["password_hash"]
    if not check_password(password, pw_hash):
        return jsonify({"ok": False, "error": "Invalid credentials"}), 401
    return jsonify({"ok": True, "has_voted": bool(row["has_voted"])})

@app.route('/candidates', methods=['GET'])
def candidates():
    with db_lock:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT id, name, party, votes FROM candidates")
        rows = cur.fetchall()
        conn.close()
    return jsonify({"ok": True, "candidates": [dict(r) for r in rows]})

@app.route('/vote', methods=['POST'])
def vote():
    data = request.json
    token = data.get("token")  # the one-time token obtained via request_otp/verify_token flow
    candidate_id = data.get("candidate_id")
    if not (token and candidate_id):
        return jsonify({"ok": False, "error": "Missing token or candidate"}), 400
    
    state = get_election_state()
    if state == "NOT_STARTED":
        return jsonify({"ok": False, "error": "Election has not started yet."}), 403
    if state == "ENDED":
        return jsonify({"ok": False, "error": "Election has ended. Voting is closed."}), 403

    valid, result = validate_and_consume_token(token)
    if not valid:
        return jsonify({"ok": False, "error": result}), 400
    cnic = result
    ok, receipt = record_vote_and_broadcast(cnic, candidate_id)
    if not ok:
        return jsonify({"ok": False, "error": receipt}), 400
    
    # Return vote receipt with verification information
    return jsonify({
        "ok": True,
        "message": receipt["message"],
        "receipt": {
            "vote_id": receipt["vote_id"],
            "vote_hash": receipt["vote_hash"],
            "timestamp": receipt["timestamp"]
        }
    })

@app.route('/results', methods=['GET'])
def results():
    state = get_election_state()
    
    if state == "NOT_STARTED":
        return jsonify({
            "ok": True, 
            "results": [], 
            "message": "Welcome to the E-Voting System. Waiting for Administrator to start the election.",
            "election_status": "NOT_STARTED",
            "election_ended": False
        })

    if state == "ONGOING":
        # Hide results if election is ongoing
        return jsonify({
            "ok": True, 
            "results": [], 
            "message": "Election in progress. Results are hidden until broadcasted by Admin.",
            "election_status": "ONGOING",
            "election_ended": False
        })

    with db_lock:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT id, name, party, votes FROM candidates")
        rows = cur.fetchall()
        
        # Fetch the security report
        cur.execute("SELECT value FROM settings WHERE key = 'last_election_report'")
        row = cur.fetchone()
        report = row['value'] if row else "No report available."
        
        conn.close()
    return jsonify({"ok": True, "results": [dict(r) for r in rows], "election_ended": True, "report": report})

@app.route('/verify_vote', methods=['POST'])
def verify_vote():
    """
    Verify the RSA signature of a vote in the ledger.
    Demonstrates cryptographic verification of vote integrity.
    """
    data = request.json
    vote_id = data.get("vote_id")
    
    if not vote_id:
        return jsonify({"ok": False, "error": "Missing vote_id"}), 400
    
    with db_lock:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT vote_hash, prev_hash, candidate_id, timestamp, signature FROM votes_ledger WHERE id = ?", (vote_id,))
        vote = cur.fetchone()
        conn.close()
    
    if not vote:
        return jsonify({"ok": False, "error": "Vote not found"}), 404
    
    # Reconstruct the payload that was signed
    payload = f"{vote['prev_hash']}|{vote['candidate_id']}|{vote['timestamp']}"
    signature = vote['signature']
    
    # Verify signature
    is_valid = verify_vote_signature(payload, signature)
    
    return jsonify({
        "ok": True,
        "vote_id": vote_id,
        "vote_hash": vote['vote_hash'],
        "candidate_id": vote['candidate_id'],
        "timestamp": vote['timestamp'],
        "signature_valid": is_valid,
        "message": "Signature is valid - vote integrity confirmed" if is_valid else "Signature invalid - vote may be tampered"
    })

@app.route('/public_key', methods=['GET'])
def get_public_key():
    """
    Return the RSA public key for vote verification.
    Anyone can use this to verify vote signatures.
    """
    if not public_key:
        return jsonify({"ok": False, "error": "Public key not available"}), 500
    
    try:
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return jsonify({
            "ok": True,
            "public_key": pem.decode('utf-8'),
            "format": "PEM"
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# Admin endpoints (simple password-based admin)
ADMIN_PASSWORD = config.ADMIN_PASSWORD

@app.route('/admin/add_candidate', methods=['POST'])
def admin_add_candidate():
    data = request.json
    pwd = data.get("admin_password")
    name = data.get("name")
    party = data.get("party")
    if pwd != ADMIN_PASSWORD:
        return jsonify({"ok": False, "error": "Unauthorized"}), 403
    with db_lock:
        conn = get_db_conn()
        cur = conn.cursor()
        
        # Check if candidate exists
        cur.execute("SELECT id FROM candidates WHERE name = ?", (name,))
        existing = cur.fetchone()
        
        if existing:
            # Update existing candidate's party
            cur.execute("UPDATE candidates SET party = ? WHERE id = ?", (party, existing['id']))
        else:
            # Insert new candidate
            cur.execute("INSERT INTO candidates (name, party) VALUES (?, ?)", (name, party))
            
        conn.commit()
        conn.close()
    # log
    with db_lock:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("INSERT INTO admin_logs (action, actor, timestamp) VALUES (?, ?, ?)",
                    (f"add_candidate:{name}", "admin", datetime.now(timezone.utc).isoformat()))
        conn.commit()
        conn.close()
    return jsonify({"ok": True, "message": f"Candidate {name} added/updated"})

@app.route('/admin/remove_candidate', methods=['POST'])
def admin_remove_candidate():
    data = request.json
    pwd = data.get("admin_password")
    name = data.get("name")
    
    if pwd != ADMIN_PASSWORD:
        return jsonify({"ok": False, "error": "Unauthorized"}), 403
        
    with db_lock:
        conn = get_db_conn()
        cur = conn.cursor()
        
        cur.execute("SELECT id FROM candidates WHERE name = ?", (name,))
        existing = cur.fetchone()
        
        if existing:
            cur.execute("DELETE FROM candidates WHERE id = ?", (existing['id'],))
            conn.commit()
            msg = f"Candidate {name} removed"
            ok = True
        else:
            msg = f"Candidate {name} not found"
            ok = False
            
        conn.close()
        
    return jsonify({"ok": ok, "message": msg})

@app.route('/admin/list_candidates', methods=['POST'])
def admin_list_candidates():
    data = request.json
    pwd = data.get("admin_password")
    
    if pwd != ADMIN_PASSWORD:
        return jsonify({"ok": False, "error": "Unauthorized"}), 403
        
    with db_lock:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT id, name, party FROM candidates")
        rows = cur.fetchall()
        conn.close()
        
    return jsonify({"ok": True, "candidates": [dict(r) for r in rows]})

@app.route('/admin/end_election', methods=['POST'])
def admin_end_election():
    global email_service
    data = request.json
    pwd = data.get("admin_password")
    
    if pwd != ADMIN_PASSWORD:
        return jsonify({"ok": False, "error": "Unauthorized"}), 403
    
    # Check if there's an election to end
    if get_election_status():
        return jsonify({"ok": False, "error": "No active election to end."}), 400
        
    # Set status to ended
    set_election_status(True)
    
    # Get results before cleanup
    with db_lock:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT id, name, party, votes FROM candidates")
        rows = cur.fetchall()
        conn.close()
    
    results = [dict(r) for r in rows]
    ts = datetime.now(timezone.utc).isoformat()
    payload = json.dumps({"type": "ELECTION_ENDED", "results": results, "timestamp": ts, "election_ended": True})
    
    # Broadcast final results
    mqtt_client.publish(MQTT_TOPIC, payload)
    socketio.emit('vote_update', payload)
    
    # Cleanup for next election: clear voters, votes, tokens, and domains
    with db_lock:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("DELETE FROM voters")
        cur.execute("DELETE FROM votes_ledger")
        cur.execute("DELETE FROM tokens")
        cur.execute("UPDATE candidates SET votes = 0")
        cur.execute("DELETE FROM settings WHERE key = 'allowed_domains'")
        conn.commit()
        conn.close()
    
    # Clear in-memory domains
    if email_service:
        email_service.set_allowed_domains([])
    
    # Stop traffic capture and generate report
    traffic_analyzer.stop_capture()
    technical_report = traffic_analyzer.generate_report()
    layman_report = traffic_analyzer.generate_layman_report()
    
    # Save layman report to database so it persists for web clients
    try:
        with db_lock:
            conn = get_db_conn()
            cur = conn.cursor()
            cur.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('last_election_report', ?)", (layman_report,))
            conn.commit()
            conn.close()
    except Exception as e:
        print(f"Failed to save report: {e}")
        
    # Include report in broadcast
    payload_dict = json.loads(payload)
    payload_dict["report"] = layman_report
    payload_new = json.dumps(payload_dict)
    
    mqtt_client.publish(MQTT_TOPIC, payload_new)
    socketio.emit('vote_update', payload_new)
    
    return jsonify({
        "ok": True, 
        "message": "Election ended. Results broadcasted. System reset for next election.",
        "report": technical_report, # Admin still gets technical report
        "layman_report": layman_report
    })

@app.route('/admin/add_domain', methods=['POST'])
def admin_add_domain():
    """Add an allowed email domain for voter registration"""
    data = request.json
    pwd = data.get("admin_password")
    domain = data.get("domain", "").strip().lower()
    
    if pwd != ADMIN_PASSWORD:
        return jsonify({"ok": False, "error": "Unauthorized"}), 403
    
    if not domain:
        return jsonify({"ok": False, "error": "Domain is required"}), 400
    
    # Remove @ if provided
    if domain.startswith('@'):
        domain = domain[1:]
    
    with db_lock:
        conn = get_db_conn()
        cur = conn.cursor()
        
        # Get current domains
        cur.execute("SELECT value FROM settings WHERE key = 'allowed_domains'")
        row = cur.fetchone()
        current_domains = row['value'].split(',') if row and row['value'] else []
        
        # Add new domain if not already present
        if domain not in current_domains:
            current_domains.append(domain)
            cur.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('allowed_domains', ?)", 
                       (','.join(current_domains),))
            conn.commit()
            conn.close()
            
            # Sync email_service instance
            if email_service:
                email_service.set_allowed_domains(current_domains)
                
            return jsonify({"ok": True, "message": f"Domain @{domain} added", "domains": current_domains})
        else:
            conn.close()
            return jsonify({"ok": False, "error": f"Domain @{domain} already exists"}), 400

@app.route('/admin/remove_domain', methods=['POST'])
def admin_remove_domain():
    """Remove an allowed email domain"""
    data = request.json
    pwd = data.get("admin_password")
    domain = data.get("domain", "").strip().lower()
    
    if pwd != ADMIN_PASSWORD:
        return jsonify({"ok": False, "error": "Unauthorized"}), 403
    
    if not domain:
        return jsonify({"ok": False, "error": "Domain is required"}), 400
    
    if domain.startswith('@'):
        domain = domain[1:]
    
    with db_lock:
        conn = get_db_conn()
        cur = conn.cursor()
        
        # Get current domains
        cur.execute("SELECT value FROM settings WHERE key = 'allowed_domains'")
        row = cur.fetchone()
        current_domains = row['value'].split(',') if row and row['value'] else []
        
        if domain in current_domains:
            current_domains.remove(domain)
            cur.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('allowed_domains', ?)", 
                       (','.join(current_domains),))
            conn.commit()
            conn.close()
            
            # Sync email_service instance
            if email_service:
                email_service.set_allowed_domains(current_domains)
                
            return jsonify({"ok": True, "message": f"Domain @{domain} removed", "domains": current_domains})
        else:
            conn.close()
            return jsonify({"ok": False, "error": f"Domain @{domain} not found"}), 404

@app.route('/admin/list_domains', methods=['POST'])
def admin_list_domains():
    """List all allowed email domains"""
    data = request.json
    pwd = data.get("admin_password")
    
    if pwd != ADMIN_PASSWORD:
        return jsonify({"ok": False, "error": "Unauthorized"}), 403
    
    with db_lock:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT value FROM settings WHERE key = 'allowed_domains'")
        row = cur.fetchone()
        conn.close()
    
    domains = row['value'].split(',') if row and row['value'] else []
    return jsonify({"ok": True, "domains": domains})

@app.route('/admin/start_election', methods=['POST'])
def admin_start_election():
    """Start/Reset the election - clears votes, resets domain, and election status"""
    global email_service
    data = request.json
    pwd = data.get("admin_password")
    reset_votes = data.get("reset_votes", False)
    new_domain = data.get("domain", "")
    
    if pwd != ADMIN_PASSWORD:
        return jsonify({"ok": False, "error": "Unauthorized"}), 403
    
    # Check if an election is currently running
    current_status = get_election_status()
    if reset_votes and not current_status:
        # Election is ongoing (not ended) - cannot start new one
        return jsonify({
            "ok": False, 
            "error": "An election is currently in progress. You must END the current election before starting a new one."
        }), 400
    
    # Set election status to initialized and ongoing
    set_election_status(False)
    with db_lock:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('election_initialized', 'true')")
        conn.commit()
        conn.close()
    
    if reset_votes:
        # Reset votes but keep domains (they are managed separately)
        with db_lock:
            conn = get_db_conn()
            cur = conn.cursor()
            
            # Reset all vote counts and voter status
            cur.execute("UPDATE candidates SET votes = 0")
            cur.execute("DELETE FROM voters")  # Clear all registered voters for new election
            cur.execute("DELETE FROM votes_ledger")
            cur.execute("DELETE FROM tokens")
            conn.commit()
            
            # Get current domains to sync with email service
            cur.execute("SELECT value FROM settings WHERE key = 'allowed_domains'")
            row = cur.fetchone()
            domains = row['value'].split(',') if row and row['value'] else []
            conn.close()
        
        # Sync email service with current domains
        if email_service and domains:
            email_service.set_allowed_domains(domains)
        
        # Start network traffic capture
        traffic_analyzer.start_capture()
        
        return jsonify({
            "ok": True, 
            "message": f"New election started. All voter data has been reset. Configured domains: {', '.join(['@' + d for d in domains]) if domains else 'None (add domains in Domain Management)'}"
        })
    
    # Resume election - sync domains from database
    with db_lock:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT value FROM settings WHERE key = 'allowed_domains'")
        row = cur.fetchone()
        domains = row['value'].split(',') if row and row['value'] else []
        conn.close()
    
    # Sync email service with domains from database
    if email_service and domains:
        email_service.set_allowed_domains(domains)
    
    # Start network traffic capture
    traffic_analyzer.start_capture()

    return jsonify({
        "ok": True, 
        "message": f"Election resumed. Voting is now open. Active domains: {', '.join(['@' + d for d in domains]) if domains else 'None'}"
    })

@app.route('/admin/get_status', methods=['POST'])
def admin_get_status():
    """Get current election status and settings"""
    data = request.json
    pwd = data.get("admin_password")
    
    if pwd != ADMIN_PASSWORD:
        return jsonify({"ok": False, "error": "Unauthorized"}), 403
    
    election_ended = get_election_status()
    
    # Get allowed domains from DB
    with db_lock:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT value FROM settings WHERE key = 'allowed_domains'")
        row = cur.fetchone()
        domains = row['value'].split(',') if row and row['value'] else []
        
        cur.execute("SELECT COUNT(*) as count FROM voters WHERE has_voted = 1")
        voted_count = cur.fetchone()['count']
        
        cur.execute("SELECT COUNT(*) as count FROM voters")
        total_voters = cur.fetchone()['count']
        
        conn.close()
    
    state = get_election_state()
    
    # Get allowed domains from DB
    with db_lock:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT value FROM settings WHERE key = 'allowed_domains'")
        row = cur.fetchone()
        domains = row['value'].split(',') if row and row['value'] else []
        
        cur.execute("SELECT COUNT(*) as count FROM voters WHERE has_voted = 1")
        voted_count = cur.fetchone()['count']
        
        cur.execute("SELECT COUNT(*) as count FROM voters")
        total_voters = cur.fetchone()['count']
        
        conn.close()
    
    return jsonify({
        "ok": True,
        "election_status": state,
        "election_ended": (state == "ENDED"),
        "allowed_domains": domains,
        "votes_cast": voted_count,
        "registered_voters": total_voters
    })

# SocketIO event for simple testing
@socketio.on('connect')
def on_connect():
    print("Socket client connected")
    # Optionally send initial results
    state = get_election_state()
    
    if state == "ENDED":
        with db_lock:
            conn = get_db_conn()
            cur = conn.cursor()
            cur.execute("SELECT id, name, party, votes FROM candidates")
            rows = cur.fetchall()
            conn.close()
        emit('vote_update', json.dumps({"type": "initial", "results": [dict(r) for r in rows], "election_ended": True, "election_status": "ENDED"}))
    elif state == "NOT_STARTED":
        emit('vote_update', json.dumps({"type": "initial", "results": [], "election_ended": False, "election_status": "NOT_STARTED", "message": "Waiting for Administrator to start the election."}))
    else:
        # ONGOING
        emit('vote_update', json.dumps({"type": "initial", "results": [], "election_ended": False, "election_status": "ONGOING", "message": "Election in progress. Results hidden"}))

# MQTT subscribe -> socket bridge (if you want server to also listen MQTT)
def start_mqtt_listener():
    # if you want to subscribe incoming updates (e.g., other sources), implement here.
    pass

if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("┌" + "─" * 68 + "┐")
    print("│" + "  E-VOTING SYSTEM - NETWORK SECURITY PROJECT  ".center(68) + "│")
    print("│" + "  Secure · Transparent · Verifiable  ".center(68) + "│")
    print("└" + "─" * 68 + "┘")
    print("=" * 70)
    
    # Load RSA keys for vote signing
    print("\n📋 LOADING RSA KEYS FOR DIGITAL SIGNATURES")
    print("─" * 70)
    if load_rsa_keys():
        print("   ✓ Private key loaded (for signing votes)")
        print("   ✓ Public key loaded (for verification)")
    else:
        print("   ⚠ RSA keys not found - digital signatures disabled")
    
    # Email domain configuration - use .env if available, otherwise prompt
    print("\n📧 EMAIL DOMAIN CONFIGURATION")
    print("─" * 70)
    if config.ALLOWED_EMAIL_DOMAIN:
        allowed_domain = config.ALLOWED_EMAIL_DOMAIN
        print(f"   ✓ Using domain from .env: @{allowed_domain}")
    else:
        allowed_domain = input("   Enter allowed email domain (e.g., university.edu): ").strip()
        if not allowed_domain:
            print("   ✗ ERROR: Domain cannot be empty!")
            exit(1)
        config.ALLOWED_EMAIL_DOMAIN = allowed_domain
    print(f"   ✓ Allowed domain set to: @{allowed_domain}")
    
    # Email SMTP configuration - use .env if available
    print("\n📨 SMTP SERVER CONFIGURATION")
    print("─" * 70)
    if config.SENDER_EMAIL and config.SENDER_PASSWORD:
        print(f"   ✓ Using SMTP configuration from .env")
    else:
        print("   Note: For Gmail, use an App Password (not regular password)")
        print("         SMTP Server: smtp.gmail.com, Port: 587")
        print()
        
        sender_email = input("   Sender email (or Enter to use .env): ").strip()
        if sender_email:
            config.SENDER_EMAIL = sender_email
        
        sender_password = input("   Sender password (or Enter to use .env): ").strip()
        if sender_password:
            config.SENDER_PASSWORD = sender_password
        
        smtp_server = input(f"   SMTP server (default: {config.SMTP_SERVER}): ").strip()
        if smtp_server:
            config.SMTP_SERVER = smtp_server
        
        smtp_port = input(f"   SMTP port (default: {config.SMTP_PORT}): ").strip()
        if smtp_port:
            config.SMTP_PORT = int(smtp_port)
    
    # Validate email configuration
    is_valid, msg = config.validate_email_config()
    if not is_valid:
        print(f"\n   ✗ ERROR: {msg}")
        print("   Please set SENDER_EMAIL and SENDER_PASSWORD in .env or above.")
        exit(1)
    
    # Initialize email service
    email_service = EmailService(
        smtp_server=config.SMTP_SERVER,
        smtp_port=config.SMTP_PORT,
        sender_email=config.SENDER_EMAIL,
        sender_password=config.SENDER_PASSWORD,
        allowed_domain=config.ALLOWED_EMAIL_DOMAIN
    )
    
    # Load domains from database (restore from previous session)
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT value FROM settings WHERE key = 'allowed_domains'")
        row = cur.fetchone()
        saved_domains = row['value'].split(',') if row and row['value'] else []
        conn.close()
        
        if saved_domains:
            email_service.set_allowed_domains(saved_domains)
            print(f"   ✓ Restored {len(saved_domains)} domain(s) from database: {', '.join(['@' + d for d in saved_domains])}")
        else:
            print("   ⚠ No domains configured. Add domains via Admin Panel.")
    except Exception as e:
        print(f"   ⚠ Could not load domains from database: {e}")
    
    # Test SMTP connection
    print("\n🔌 TESTING SMTP CONNECTION")
    print("─" * 70)
    success, test_msg = email_service.test_connection()
    if success:
        print(f"   ✓ {test_msg}")
    else:
        print(f"   ✗ {test_msg}")
        print("   ⚠ WARNING: Email service may not work properly!")
        print("   Continuing anyway...")
    
    print("\n" + "=" * 70)
    print("✓ SERVER CONFIGURATION COMPLETE")
    print("=" * 70)
    print(f"  📧 Email Domains:    {', '.join(['@' + d for d in email_service.allowed_domains]) if email_service.allowed_domains else '(none - configure via Admin)'}")
    print(f"  📨 SMTP Server:      {config.SMTP_SERVER}:{config.SMTP_PORT}")
    print(f"  📤 Sender:           {config.SENDER_EMAIL}")
    print(f"  💾 Database:         {config.DB_FILE}")
    print(f"  🔐 RSA Signatures:   {'Enabled' if private_key else 'Disabled'}")
    print("=" * 70)
    
    # Start MQTT client loop
    print("\n🔄 STARTING MQTT BROKER CONNECTION")
    print("─" * 70)
    mqtt_connect()

    # Resume traffic capture if election is ongoing
    if get_election_state() == "ONGOING":
        print("   ✓ Election is ongoing")
        traffic_analyzer.start_capture()
    else:
        print(f"   ℹ Election Status: {get_election_state()}")
    
    # Check for SSL certificates
    ssl_cert = None
    if os.path.exists(config.SSL_CERT_PATH) and os.path.exists(config.SSL_KEY_PATH):
        ssl_cert = (config.SSL_CERT_PATH, config.SSL_KEY_PATH)
    
    print("\n🚀 STARTING FLASK SERVER")
    
    # Auto-open browser
    import webbrowser
    webbrowser.open("https://localhost:5000")
    print("=" * 70)
    if ssl_cert:
        print("   ✓ HTTPS enabled on https://localhost:5000")
        print("   🔒 TLS/SSL certificates loaded")
        print("=" * 70)
        socketio.run(app, host='0.0.0.0', port=5000, ssl_context=ssl_cert, allow_unsafe_werkzeug=True)
    else:
        print("   ⚠ HTTP mode on http://localhost:5000")
        print("   ℹ To enable HTTPS, place certificates at:")
        print(f"      - {config.SSL_CERT_PATH}")
        print(f"      - {config.SSL_KEY_PATH}")
        print("=" * 70)
        socketio.run(app, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
