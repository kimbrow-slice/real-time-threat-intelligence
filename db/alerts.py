import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import requests
from db.db import get_connection
from dotenv import load_dotenv
import datetime

# Load environment variables
load_dotenv()

# SendGrid Environment Variables
SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY')
SENDGRID_EMAIL = os.getenv('SENDGRID_EMAIL')
SENDGRID_RECIPIENT = os.getenv('SENDGRID_RECIPIENT')
WEBHOOK_URL = os.getenv('WEBHOOK_URL')

# Function to calculate the time-weighted risk score
def calculate_risk(likelihood, impact, last_seen):
    days_since_last_seen = (datetime.datetime.now() - last_seen).days
    decay_factor = max(0.1, 1 - (0.05 * days_since_last_seen))  # Decay factor reduces over time
    return (likelihood * impact) * decay_factor

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


# Function to trigger alerts with risk score calculation
def trigger_alerts(threat_name, likelihood, impact, alert_description, last_seen):
    # Calculate the risk score using the time-weighted formula
    risk_score = calculate_risk(likelihood, impact, last_seen)
    print(f"Triggering email alert for: {threat_name}, Risk Score: {risk_score}")
    
    # Insert alert into the database
    insert_alert(threat_name, risk_score, "Alert", alert_description)
    
    # Send email and webhook alerts
    send_email_alert(threat_name, risk_score, alert_description)
    send_webhook_alert(threat_name, risk_score, alert_description)
    
# Function to insert an alert into the database
def insert_alert(threat_name, risk_score, alert_type, alert_description):
    conn = get_connection()
    if not conn:
        print("Failed to connect to the database to insert alert.")
        return

    try:
        with conn.cursor() as cur:
            insert_query = """
                INSERT INTO alerts (threat_name, risk_score, alert_type, alert_description)
                VALUES (%s, %s, %s, %s)
            """
            cur.execute(insert_query, (threat_name, risk_score, alert_type, alert_description))
            conn.commit()
            print(f"Alert for {threat_name} inserted successfully.")
    except Exception as e:
        print(f"Error inserting alert: {e}")
    finally:
        conn.close()
