Security Assessment of Threat Alert System  
Information Security Course - Penetration Testing  
Hashim Abdulla  
Date: April 10, 2025  
## Introduction  
This paper presents the findings of a comprehensive security assessment conducted on a Python-based threat alert system designed for ShopSmart's cybersecurity infrastructure. The assessment evaluated the code's security posture, identified vulnerabilities, and provides recommendations for remediation.
Target System Description
The target system is a Python script implementing an automated alert mechanism for high-risk cybersecurity threats. The system uses two notification channels:
Email alerts via SMTP
Webhook notifications to an API endpoint
When threats with a risk score exceeding 20 are detected, the system automatically dispatches notifications through both channels to enable rapid response to security incidents.
Assessment Methodology
The assessment followed a structured approach based on OWASP guidelines:
Static code analysis
Configuration review
Security control assessment
Vulnerability identification and validation
Risk analysis
Code Under Assessment
python
import smtplib
import os
from email.mime.text import MIMEText
import requests

def send_email_alert(threat, risk_score):
    msg = MIMEText(f"High-Risk Threat Detected: {threat} with Risk Score {risk_score}")
    msg["Subject"] = "Critical Cybersecurity Alert"
    msg["From"] = os.getenv("ALERT_EMAIL_FROM", "alerts@shopsmart.com")
    msg["To"] = os.getenv("ALERT_EMAIL_TO", "admin@shopsmart.com")
    
    with smtplib.SMTP(os.getenv("SMTP_SERVER", "smtp.shopsmart.com"), 587) as server:
        server.starttls()
        server.login(os.getenv("SMTP_USER"), os.getenv("SMTP_PASS"))
        server.sendmail(msg["From"], msg["To"], msg.as_string())

def send_webhook_alert(threat, risk_score):
    webhook_url = os.getenv("https://api.shopsmart.com/security/alerts")
    if webhook_url:
        payload = {"threat": threat, "risk_score": risk_score}
        requests.post(webhook_url, json=payload)

def check_and_alert(threat, risk_score):
    if risk_score > 20:
        send_email_alert(threat, risk_score)
        send_webhook_alert(threat, risk_score)
Identified Vulnerabilities
1. Missing Input Validation (High Severity)
Description: The send_email_alert() and send_webhook_alert() functions do not validate the threat and risk_score parameters. This could lead to injection attacks if an attacker can control these values.
Evidence:
python
msg = MIMEText(f"High-Risk Threat Detected: {threat} with Risk Score {risk_score}")
python
payload = {"threat": threat, "risk_score": risk_score}
Risk: An attacker might inject malicious content into threat names or manipulate risk scores, potentially leading to email header injection or webhook data manipulation.
Recommendation: Implement input validation to ensure threat is a string with reasonable length limits and risk_score is a numeric value within expected ranges.
2. Hardcoded Authentication Credentials Pattern (Critical Severity)
Description: The code uses environment variables for SMTP authentication but does not implement fallback security if these variables are not set.
Evidence:
python
server.login(os.getenv("SMTP_USER"), os.getenv("SMTP_PASS"))
Risk: If environment variables are not properly set, the application might throw an exception or, depending on the environment configuration, could potentially proceed with default or null credentials.
Recommendation: Implement proper error handling to validate that credentials are present before attempting authentication, and log appropriate warnings if credentials are missing.
3. Webhook URL Configuration Issue (High Severity)
Description: The webhook URL is hardcoded as a string inside the os.getenv() function rather than as the variable name to look up.
Evidence:
python
webhook_url = os.getenv("https://api.shopsmart.com/security/alerts")
Risk: This will always return None unless there's an environment variable literally named "https://api.shopsmart.com/security/alerts", resulting in alert delivery failure.
Recommendation: Correct the environment variable reference to use a proper variable name:
python
webhook_url = os.getenv("WEBHOOK_URL", "https://api.shopsmart.com/security/alerts")
4. Missing Error Handling (Medium Severity)
Description: The code lacks error handling for network failures, authentication issues, or API errors when sending alerts.
Evidence: No try/except blocks are present in either the email or webhook sending functions.
Risk: If the SMTP server is unavailable or the webhook endpoint returns an error, the application may crash or silently fail without logging the issue or attempting retries.
Recommendation: Implement comprehensive error handling with appropriate logging and fallback mechanisms.
5. No TLS Certificate Verification Control (Medium Severity)
Description: The requests library will verify TLS certificates by default, but there's no explicit handling for certificate validation failures which may be important for security incidents.
Evidence:
python
requests.post(webhook_url, json=payload)
Risk: Depending on how the code evolves, future modifications might disable certificate verification to work around issues, creating vulnerability to MITM attacks.
Recommendation: Explicitly set and document the verify=True parameter in the requests call and implement proper error handling for certificate validation failures.
6. Insufficient Logging (Medium Severity)
Description: The code does not implement any logging mechanism to record alert successes, failures, or security events.
Evidence: No logging statements are present in the code.
Risk: In case of alert delivery failure, there would be no record for incident response teams to diagnose the issue. Additionally, successful alerts are not logged for audit purposes.
Recommendation: Implement a structured logging system that records alert triggers, delivery attempts, successes, and failures.
7. No Rate Limiting (Low Severity)
Description: The alert system does not implement rate limiting, which could lead to alert fatigue or email/API flooding during incident response.
Evidence: The check_and_alert() function has no mechanism to prevent repeated alerts for the same or similar threats in rapid succession.
Risk: During an active attack or incident, the system might generate a flood of alerts, potentially overwhelming responders or exceeding email sending limits.
Recommendation: Implement rate limiting and alert deduplication to prevent alert storms during major incidents.
8. Plain Text Email Content (Low Severity)
Description: Alert emails are sent as plain text with minimal information about the threat.
Evidence:
python
msg = MIMEText(f"High-Risk Threat Detected: {threat} with Risk Score {risk_score}")
Risk: Plain text emails provide limited context and lack the structure to help responders quickly assess threat severity and required actions.
Recommendation: Consider using HTML formatted emails with proper structure, additional context, and direct links to threat management consoles.
Exploitation Proof of Concept
Webhook URL Configuration Bypass
The function send_webhook_alert will never work as implemented because:
python
webhook_url = os.getenv("https://api.shopsmart.com/security/alerts")
This attempts to retrieve an environment variable named literally "https://api.shopsmart.com/security/alerts" rather than looking up a variable that would contain this URL.
Since this will return None, the condition if webhook_url: will fail and no webhook alert will ever be sent.
Proof of concept:
python
import os
# Demonstrate that the current code gets None for webhook_url
webhook_url = os.getenv("https://api.shopsmart.com/security/alerts")
print(f"Current implementation result: {webhook_url}")  # Will print None

# Correct implementation would be:
os.environ["WEBHOOK_URL"] = "https://api.shopsmart.com/security/alerts"
webhook_url = os.getenv("WEBHOOK_URL")
print(f"Correct implementation: {webhook_url}")  # Will print the URL
Email Injection Attack
If the threat parameter can be controlled by an attacker, they could potentially inject email headers:
python
malicious_threat = "Normal Threat\nBcc: victim@example.com"
send_email_alert(malicious_threat, 25)
This could cause the email to be blind carbon copied to unintended recipients, though modern email libraries like email.mime typically provide protection against header injection.
Risk Assessment Matrix
Vulnerability
Severity
Impact
Likelihood
Risk Score
Missing Input Validation
High
High
Medium
8
Hardcoded Auth Pattern
Critical
High
Medium
9
Webhook URL Config Issue
High
High
High
9
Missing Error Handling
Medium
Medium
High
6
TLS Verification Control
Medium
High
Low
5
Insufficient Logging
Medium
Medium
High
6
No Rate Limiting
Low
Medium
Medium
4
Plain Text Email
Low
Low
Medium
3

Recommendations
Immediate Actions
Fix Webhook URL Configuration:
python
webhook_url = os.getenv("WEBHOOK_URL", "https://api.shopsmart.com/security/alerts")
Add Input Validation:
python
def send_email_alert(threat, risk_score):
    # Validate inputs
    if not isinstance(threat, str) or len(threat) > 200:
        raise ValueError("Threat must be a string under 200 characters")
    if not isinstance(risk_score, (int, float)) or risk_score < 0 or risk_score > 100:
        raise ValueError("Risk score must be a number between 0 and 100")
        
    # Proceed with sending email
    # ...
Implement Error Handling:
python
def send_email_alert(threat, risk_score):
    # Validation code...
    
    try:
        msg = MIMEText(f"High-Risk Threat Detected: {threat} with Risk Score {risk_score}")
        # ... email configuration ...
        
        with smtplib.SMTP(os.getenv("SMTP_SERVER", "smtp.shopsmart.com"), 587) as server:
            server.starttls()
            try:
                smtp_user = os.getenv("SMTP_USER")
                smtp_pass = os.getenv("SMTP_PASS")
                if not smtp_user or not smtp_pass:
                    raise ValueError("SMTP credentials not configured")
                server.login(smtp_user, smtp_pass)
                server.sendmail(msg["From"], msg["To"], msg.as_string())
            except smtplib.SMTPAuthenticationError:
                logging.error("SMTP authentication failed")
                # Implement fallback notification
            except Exception as e:
                logging.error(f"Email alert failed: {str(e)}")
                # Implement fallback notification
    except Exception as e:
        logging.error(f"Failed to prepare email alert: {str(e)}")
Short-Term Actions
Implement Comprehensive Logging:
python
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("alert_system.log"),
        logging.StreamHandler()
    ]
)

def send_email_alert(threat, risk_score):
    logging.info(f"Sending email alert for threat: {threat} with score: {risk_score}")
    # ... existing code with error handling
    logging.info("Email alert sent successfully")
Add Rate Limiting:
python
from datetime import datetime, timedelta

alert_history = {}  # In production, use a persistent store like Redis

def check_and_alert(threat, risk_score):
    if risk_score > 20:
        # Check if we've alerted on this threat recently
        now = datetime.now()
        if threat in alert_history and (now - alert_history[threat]) < timedelta(hours=1):
            logging.info(f"Suppressing duplicate alert for {threat} - last alerted at {alert_history[threat]}")
            return
            
        send_email_alert(threat, risk_score)
        send_webhook_alert(threat, risk_score)
        alert_history[threat] = now
Enhance Email Content:
python
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def send_email_alert(threat, risk_score):
    # Create multi-part email
    msg = MIMEMultipart('alternative')
    msg["Subject"] = f"CRITICAL SECURITY ALERT: {threat}"
    # ... other headers ...
    
    # Plain text version
    text_content = f"""
    CRITICAL SECURITY ALERT
    
    Threat: {threat}
    Risk Score: {risk_score}/100
    Detected: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    
    Please access the security console immediately: https://security.shopsmart.com
    """
    
    # HTML version
    html_content = f"""
    <html>
    <head>
        <style>
            .alert {{ background-color: #f8d7da; padding: 15px; border-radius: 5px; }}
            .score {{ font-size: 24px; font-weight: bold; color: {'#ff0000' if risk_score > 50 else '#ff9900'}; }}
        </style>
    </head>
    <body>
        <div class="alert">
            <h2>⚠️ CRITICAL SECURITY ALERT</h2>
            <p><strong>Threat:</strong> {threat}</p>
            <p><strong>Risk Score:</strong> <span class="score">{risk_score}/100</span></p>
            <p><strong>Detected:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><a href="https://security.shopsmart.com">Access Security Console</a></p>
        </div>
    </body>
    </html>
    """
    
    # Attach both versions
    msg.attach(MIMEText(text_content, 'plain'))
    msg.attach(MIMEText(html_content, 'html'))
    
    # Continue with sending...
Long-Term Actions
Implement Circuit Breaker Pattern - To prevent cascading failures if alert systems are unavailable.
Set Up Monitoring - Monitor the alert system itself to ensure it's functioning properly.
Add Two-Way Communication - Allow recipients to acknowledge alerts and update status.
Implement Tiered Alerting - Different notification methods based on severity and time of day.
Conclusion
The security assessment of ShopSmart's threat alert system identified several vulnerabilities that could potentially impact the reliability and security of alert notifications. The most critical issues include a configuration error in the webhook URL retrieval, lack of input validation, and insufficient error handling. These vulnerabilities could lead to alert delivery failure or potential security weaknesses in the notification system.
By implementing the recommended immediate and short-term actions, the security posture of the alert system would be significantly improved. The long-term recommendations would further enhance the resilience and effectiveness of the system.

