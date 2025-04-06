import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import requests
from db.db import get_connection
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# SendGrid Environment Variables
SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY')
SENDGRID_EMAIL = os.getenv('SENDGRID_EMAIL')
SENDGRID_RECIPIENT = os.getenv('SENDGRID_RECIPIENT')
WEBHOOK_URL = os.getenv('WEBHOOK_URL')

# Function to send email alert using SendGrid
def send_email_alert(threat, risk_score, alert_description):
    try:

        # Create the email message
        message = Mail(
            from_email=SENDGRID_EMAIL,
            to_emails=SENDGRID_RECIPIENT,
            subject=f"High-Risk Threat Detected: {threat}",
            html_content=f"<strong>Risk Score: {risk_score}</strong><br><p>{alert_description}</p>"
        )

        # Send the email using SendGrid API
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        
    except Exception as e:
        print(f"Error while sending email: {str(e)}")


# Function to send a webhook alert
def send_webhook_alert(threat, risk_score, alert_description):
    payload = {
        "content": f"High-Risk Threat Detected: {threat}\nRisk Score: {risk_score}\nDescription: {alert_description}"
    }
    try:
        response = requests.post(WEBHOOK_URL, json=payload)
        if response.status_code == 200:
            print(f"Webhook sent successfully for {threat}")
        else:
            print(f"Failed to send webhook for {threat}, Status Code: {response.status_code}")
            print(f"Response Body: {response.text}")
    except Exception as e:
        print(f"Error sending webhook alert for {threat}: {e}")

        
# Function to trigger alerts
def trigger_alerts(threat, risk_score, alert_description):
    print(f"Triggering email alert for: {threat}, Risk Score: {risk_score}")
    send_email_alert(threat, risk_score, alert_description)
    send_webhook_alert(threat, risk_score, alert_description)


