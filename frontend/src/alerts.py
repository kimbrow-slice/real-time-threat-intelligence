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
