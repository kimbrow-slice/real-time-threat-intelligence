import os
import sys
import time
import json
import datetime
import requests
from dateutil.parser import isoparse
from dotenv import load_dotenv
import psycopg2, os

def get_connection():
    return psycopg2.connect(
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        host=os.getenv("DB_HOST")
    )

## Load environment variables
load_dotenv()

## Hugging Face Environment Variables
HUGGING_FACE_KEY = os.getenv('HUGGING_FACE_KEY')
HUGGING_FACE_URL = os.getenv('HUGGING_FACE_URL')

## Pathing for root directory
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, "..", ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from api.routes import calculate_risk, get_risk_label

from db.db import get_connection
from db.alerts import trigger_alerts


## Same impact mapping for Hugging Face
impact_mapping = {
    "Critical Risk": 5,
    "High Risk": 4,
    "Moderate Risk": 3,
    "Low Risk": 2,
    "No Risk": 1
}

## Log the defensive actions inside of the logs table
def log_defensive_action(action_type, details):

    conn = None
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO logs (user_id, action_type, details) VALUES (%s, %s, %s)",
                (4, action_type, details)
            )
        conn.commit()
    except Exception as e:
        print("Error logging defensive action:", e)
    finally:
        if conn:
            conn.close()

## Hugging Face providing risk classificaiton
def classify_ip_threat(ip):

    headers = {
        "Authorization": f"Bearer {os.getenv('HUGGING_FACE_KEY')}",
        "Content-Type": "application/json"
    }
    payload = {
        "inputs": f"IP {ip} is showing suspicious scanning activity.",
        "parameters": {
            "candidate_labels": ["Critical Risk", "High Risk", "Moderate Risk", "Low Risk", "No Risk"]
        }
    }
    
    response = requests.post(os.getenv("HUGGING_FACE_URL"), headers=headers, json=payload)
    if response.status_code == 503:
        print("HF API is unavailable for IP classification")
        return {"risk_score": 0, "risk_label": "Unavailable"}
    
    result = response.json()
    if isinstance(result, dict) and "scores" in result and "labels" in result:
        top_label = result["labels"][0]
        likelihood = result["scores"][0]
        impact = impact_mapping.get(top_label, 1)
        
        ## Use current time (UTC) as last_seen and normalize to local/ native time.
        last_seen = datetime.datetime.now(datetime.timezone.utc)
        last_seen = last_seen.replace(tzinfo=None)
        
        risk_score = calculate_risk(likelihood, impact, last_seen)
        risk_label = get_risk_label(risk_score)
        print("get_connection:", get_connection)
        print("trigger_alerts:", trigger_alerts)

        return {"risk_score": risk_score, "risk_label": risk_label}
    else:
        return {"risk_score": 0, "risk_label": "Malformed Response"}

## Function to block the IP address, currently only configured for Windows
def block_ip(ip):

    ## For Windows:
    command = f'netsh advfirewall firewall add rule name="Block IP {ip}" dir=in interface=any action=block remoteip={ip}'
    try:
        result = os.system(command)
        if result == 0:
            log_defensive_action("IP_BLOCK", f"Successfully blocked IP: {ip}")
            ## Trigger an alert using trigger_alerts, here with sample likelihood and impact values.
            trigger_alerts("Auto-Block IP", 5, 5, f"Automatically blocked malicious IP: {ip}", datetime.datetime.now())

        else:
            log_defensive_action("IP_BLOCK_FAILED", f"Failed to block IP: {ip} (Exit Code: {result})")

    except Exception as e:
        log_defensive_action("IP_BLOCK_EXCEPTION", f"Exception while blocking IP {ip}: {e}")

## Proces the IP address through Hugging Face
def process_ip(ip):

    classification = classify_ip_threat(ip)
    print(f"Classification for IP {ip}: {classification}")

    if classification["risk_score"] >= 2.0:
        block_ip(ip)
    else:
        log_defensive_action("IP_NOT_BLOCKED", f"IP {ip} classified as {classification['risk_label']} with score {classification['risk_score']}")

def monitor_threat_feed(feed_path):

    seen_ips = set()
    print("Starting threat feed monitoring using file:", feed_path)
    log_defensive_action("THREAT_FEED_START", f"Monitoring threat feed: {feed_path}")
    while True:
        try:
            with open(feed_path, "r") as file:
                data = json.load(file)
                malicious_ips = data.get("malicious_ips", [])
                for ip in malicious_ips:
                    if ip not in seen_ips:
                        log_defensive_action("THREAT_FEED_ALERT", f"New malicious IP detected: {ip}")

                        process_ip(ip)
                        seen_ips.add(ip)
        except Exception as e:

            log_defensive_action("THREAT_FEED_ERROR", f"Error reading threat feed: {e}")
        time.sleep(30)  ## Poll every 30 seconds.

def main():

    if len(sys.argv) > 1:
        ip = sys.argv[1]

        log_defensive_action("DIRECT_IP_PROCESS", f"Processing IP via direct invocation: {ip}")
        process_ip(ip)
    else:
        feed_path = os.getenv("THREAT_FEED_PATH", "threat_feed.json")
        monitor_threat_feed(feed_path)

if __name__ == "__main__":
    main()
