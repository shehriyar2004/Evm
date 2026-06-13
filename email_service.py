# email_service.py
"""
Email service module for sending OTP tokens via email.
Implements SMTP email sending with domain validation.
"""

import smtplib
import secrets
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Tuple, Optional


class EmailService:
    """
    Service for sending OTP emails with domain validation.
    Demonstrates SMTP protocol usage for the network concepts project.
    """
    
    def __init__(self, smtp_server: str, smtp_port: int, sender_email: str, 
                 sender_password: str, allowed_domain: str):
        """
        Initialize email service with SMTP configuration.
        
        Args:
            smtp_server: SMTP server hostname (e.g., smtp.gmail.com)
            smtp_port: SMTP server port (587 for TLS, 465 for SSL)
            sender_email: Email address used to send OTPs
            sender_password: Password/app password for sender email
            allowed_domain: Domain that is allowed to receive OTPs (e.g., @university.edu)
        """
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.sender_email = sender_email
        self.sender_password = sender_password
        self.allowed_domains = []  # Will be set dynamically
        
        # Set initial domain if provided
        if allowed_domain:
            self.set_allowed_domains([allowed_domain])
    
    def set_allowed_domains(self, domains: list):
        """Set the list of allowed domains"""
        self.allowed_domains = []
        for d in domains:
            d = d.lower().strip()
            if d and not d.startswith('@'):
                d = '@' + d
            if d:
                self.allowed_domains.append(d)
    
    def validate_email_domain(self, email: str) -> Tuple[bool, str]:
        """
        Validate that email belongs to one of the allowed domains.
        
        Args:
            email: Email address to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not email or '@' not in email:
            return False, "Invalid email format"
        
        if not self.allowed_domains:
            return False, "No allowed domains configured. Contact administrator."
        
        email_lower = email.lower().strip()
        domain = '@' + email_lower.split('@')[1]
        
        if domain not in self.allowed_domains:
            domains_str = ', '.join(self.allowed_domains)
            return False, f"Only emails from these domains are allowed: {domains_str}"
        
        return True, ""
    
    def generate_otp(self, length: int = 6) -> str:
        """
        Generate a random numeric OTP.
        
        Args:
            length: Length of OTP (default 6 digits)
            
        Returns:
            OTP string
        """
        # Generate random number and convert to string with leading zeros
        otp_number = secrets.randbelow(10 ** length)
        return str(otp_number).zfill(length)
    
    def send_otp_email(self, recipient_email: str, otp: str, cnic: str) -> Tuple[bool, str]:
        """
        Send OTP via email using SMTP protocol.
        
        Args:
            recipient_email: Recipient's email address
            otp: OTP token to send
            cnic: Voter's CNIC (for reference)
            
        Returns:
            Tuple of (success, message)
        """
        # Validate domain first
        is_valid, error_msg = self.validate_email_domain(recipient_email)
        if not is_valid:
            return False, error_msg
        
        try:
            # Create email message
            message = MIMEMultipart("alternative")
            message["Subject"] = "Your Voting OTP Token"
            message["From"] = self.sender_email
            message["To"] = recipient_email
            
            # Create email body (both plain text and HTML)
            text_content = f"""
E-Voting System - OTP Verification

Dear Voter (CNIC: {cnic}),

Your One-Time Password (OTP) for voting is: {otp}

This OTP is valid for 5 minutes.

IMPORTANT: Do not share this OTP with anyone.

If you did not request this OTP, please ignore this email.

---
Secure E-Voting System
Network Security Project
"""
            
            html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background-color: #4CAF50; color: white; padding: 20px; text-align: center; }}
        .content {{ background-color: #f9f9f9; padding: 30px; border: 1px solid #ddd; }}
        .otp-box {{ background-color: #fff; border: 2px solid #4CAF50; padding: 20px; 
                    text-align: center; font-size: 32px; font-weight: bold; 
                    letter-spacing: 5px; margin: 20px 0; }}
        .warning {{ color: #d32f2f; font-weight: bold; margin-top: 20px; }}
        .footer {{ text-align: center; margin-top: 20px; font-size: 12px; color: #666; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>E-Voting System</h1>
            <p>OTP Verification</p>
        </div>
        <div class="content">
            <p>Dear Voter (CNIC: <strong>{cnic}</strong>),</p>
            <p>Your One-Time Password (OTP) for voting is:</p>
            <div class="otp-box">{otp}</div>
            <p>This OTP is valid for <strong>5 minutes</strong>.</p>
            <p class="warning">⚠️ IMPORTANT: Do not share this OTP with anyone.</p>
            <p>If you did not request this OTP, please ignore this email.</p>
        </div>
        <div class="footer">
            <p>Secure E-Voting System | Network Security Project</p>
        </div>
    </div>
</body>
</html>
"""
            
            # Attach both versions
            part1 = MIMEText(text_content, "plain")
            part2 = MIMEText(html_content, "html")
            message.attach(part1)
            message.attach(part2)
            
            # Connect to SMTP server and send email
            # Using STARTTLS for secure connection (demonstrating TLS protocol)
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.ehlo()  # Identify ourselves to SMTP server
                server.starttls()  # Upgrade connection to TLS
                server.ehlo()  # Re-identify as encrypted connection
                server.login(self.sender_email, self.sender_password)
                server.send_message(message)
            
            return True, f"OTP sent successfully to {recipient_email}"
            
        except smtplib.SMTPAuthenticationError:
            return False, "Email authentication failed. Check email credentials."
        except smtplib.SMTPException as e:
            return False, f"SMTP error occurred: {str(e)}"
        except Exception as e:
            return False, f"Failed to send email: {str(e)}"
    
    def test_connection(self) -> Tuple[bool, str]:
        """
        Test SMTP connection without sending email.
        
        Returns:
            Tuple of (success, message)
        """
        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=10) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(self.sender_email, self.sender_password)
            return True, "SMTP connection successful"
        except Exception as e:
            return False, f"SMTP connection failed: {str(e)}"
