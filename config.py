# config.py
"""
Configuration file for the E-Voting system.
Stores email settings and allowed domain configuration.
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()


class Config:
    """Application configuration class"""
    
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY', 'default-secret-key-change-in-production')
    
    
    # Database (Absolute path)
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    DB_FILE = os.path.join(BASE_DIR, "voting.db")
    
    # MQTT Broker settings
    MQTT_BROKER = os.environ.get('MQTT_BROKER', 'localhost')
    MQTT_PORT = int(os.environ.get('MQTT_PORT', '1883'))
    MQTT_TOPIC = "voting/updates"
    
    # JWT settings
    JWT_SECRET = os.environ.get('JWT_SECRET', 'CHANGE_THIS_SECRET')
    TOKEN_TTL_SECONDS = 300  # 5 minutes for OTP validity
    
    # Email/SMTP settings (configured from environment variables)
    SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
    SENDER_EMAIL = os.environ.get('SENDER_EMAIL', '')
    SENDER_PASSWORD = os.environ.get('SENDER_PASSWORD', '')
    
    # Allowed email domain (will be set at runtime)
    ALLOWED_EMAIL_DOMAIN = os.environ.get('ALLOWED_EMAIL_DOMAIN', '')
    
    # Admin password
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "adminpass")
    
    # SSL/TLS certificates
    SSL_CERT_PATH = os.path.join(BASE_DIR, 'tls_certs', 'server.crt')
    SSL_KEY_PATH = os.path.join(BASE_DIR, 'tls_certs', 'server.key')

    # RSA Keys
    RSA_PRIVATE_KEY_PATH = os.path.join(BASE_DIR, 'rsa_keys', 'private.pem')
    RSA_PUBLIC_KEY_PATH = os.path.join(BASE_DIR, 'rsa_keys', 'public.pem')
    
    @classmethod
    def validate_email_config(cls):
        """Validate that email configuration is complete"""
        if not cls.SENDER_EMAIL:
            return False, "SENDER_EMAIL not configured"
        if not cls.SENDER_PASSWORD:
            return False, "SENDER_PASSWORD not configured"
        if not cls.ALLOWED_EMAIL_DOMAIN:
            return False, "ALLOWED_EMAIL_DOMAIN not configured"
        return True, "Email configuration valid"
