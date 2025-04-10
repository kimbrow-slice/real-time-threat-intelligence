from flask import Flask, request, jsonify
import requests
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from flask_cors import CORS
from dotenv import load_dotenv
from db.db import insert_alert
from db.alerts import trigger_alerts 
import bcrypt
import json
import datetime
from dateutil.parser import isoparse 
from risk_calculator import calculate_risk
from dateutil import parser

import logging



from db.db import get_connection

load_dotenv()

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

# API Keys
VIRUSTOTAL_API_KEY = os.getenv("REACT_APP_VIRUSTOTAL_API_KEY")
VIRUSTOTAL_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses"
SHODAN_API = os.getenv("SHODAN_API")
HUGGING_FACE_KEY = os.getenv("HUGGING_FACE_KEY")
HUGGING_FACE_URL = os.getenv("HUGGING_FACE_URL")

# SendGrid Environment Variables
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
SENDGRID_EMAIL = os.getenv("SENDGRID_EMAIL")
SENDGRID_RECIPIENT = os.getenv("SENDGRID_RECIPIENT")
WEBHOOK_URL = os.getenv("WEBHOOK_URL")

########################################
#         Logging Helper Function      #
########################################

def log_user_action(user_id, action_type, details=None):
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO logs (user_id, action_type, details)
                VALUES (%s, %s, %s)
            """, (user_id, action_type, details))
        conn.commit()
    except Exception as e:
        print("Logging error:", e)
        print("Logging error:", e)
    finally:
        if conn:
            conn.close()

########################################
#            User Management           #
########################################

@app.route("/register", methods=["POST"])
def register_user():
    data = request.get_json()
    username = data.get("username")
    raw_password = data.get("password")

    if not username or not raw_password:
        return jsonify({"error": "Username and password required"}), 400

    hashed_pw = bcrypt.hashpw(raw_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO users (username, password_hash)
                VALUES (%s, %s)
            """, (username, hashed_pw))
            conn.commit()
        return jsonify({"message": "User registered successfully"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    finally:
        if conn:
            conn.close()

@app.route("/login", methods=["POST"])
def login_user():
    data = request.get_json()
    username = data.get("username")
    raw_password = data.get("password")

    if not username or not raw_password:
        return jsonify({"error": "Username and password required"}), 400

    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute("SELECT id, password_hash FROM users WHERE username = %s", (username,))
            row = cur.fetchone()

        if not row:
            return jsonify({"error": "Invalid credentials"}), 401

        user_id, stored_hash = row
        if bcrypt.checkpw(raw_password.encode("utf-8"), stored_hash.encode("utf-8")):
            print(f"[+] User '{username}' logged in.")
            log_user_action(user_id, "login", f"User '{username}' logged in.")
            return jsonify({"message": "Login successful", "user_id": user_id, "redirect": "/dashboard"}), 200
        else:
            return jsonify({"error": "Invalid credentials"}), 401

    except Exception as e:
        print("Login error:", str(e))
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()

########################################
#             VirusTotal               #
########################################

@app.route("/scan_ip", methods=["GET"])
def scan_ip():
    ip_address = request.args.get("ip")
    user_id = request.args.get("user_id")

    if not ip_address:
        return jsonify({"error": "No IP provided"}), 400

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(f"{VIRUSTOTAL_IP_URL}/{ip_address}", headers=headers)

    if response.status_code == 200:
        if user_id:
            log_user_action(user_id, "scan_ip", f"VirusTotal scan on IP: {ip_address}")
        return response.json()
    else:
        return jsonify({"error": "VirusTotal API request failed", "details": response.text}), response.status_code
########################################
#               Shodan IP              #
########################################
@app.route("/get_shodan_data", methods=["GET"])
def get_shodan_data():
    ip_address = request.args.get("ip")
    user_id = request.args.get("user_id")

    if not ip_address:
        return jsonify({"error": "No IP provided"}), 400

    shodan_url = f"https://api.shodan.io/shodan/host/{ip_address}?key={SHODAN_API}"
    response = requests.get(shodan_url)

    if response.status_code == 200:
        data = response.json()

        try:
            conn = get_connection()
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO ip_scans (ip_address, scan_data)
                    VALUES (%s, %s)
                """, (ip_address, json.dumps(data)))
                conn.commit()
        except Exception as e:
            print("Error saving Shodan scan to DB:", e)
            print("Error saving Shodan scan to DB:", e)
        finally:
            if conn:
                conn.close()

        if user_id:
            log_user_action(user_id, "get_shodan_data", f"Shodan scan on IP: {ip_address}")

        return jsonify(data)
    else:
        return jsonify({"error": "Shodan API request failed", "details": response.text}), response.status_code


########################################
#     Shodan Search API                #
########################################
@app.route("/get_shodan_search_data", methods=["GET"])
def get_shodan_search_data():
    query = request.args.get("query")
    user_id = request.args.get("user_id")

    if not query:
        return jsonify({"error": "No query parameter provided"}), 400

    search_url = f"https://api.shodan.io/shodan/host/search?key={SHODAN_API}&query={query}"
    response = requests.get(search_url)

    if response.status_code == 200:
        data = response.json()

        if user_id:
            log_user_action(user_id, "get_shodan_search_data", f"Shodan search for query: {query}")

        return jsonify(data)
    else:
        return jsonify({"error": "Shodan Search API request failed", "details": response.text}), response.status_code


@app.route("/get_shodan_dns_resolve_data", methods=["GET"])
def get_shodan_dns_resolve_data():
    hostnames = request.args.get("hostnames")
    user_id = request.args.get("user_id")

    if not hostnames:
        return jsonify({"error": "No hostnames provided"}), 400

    dns_resolve_url = f"https://api.shodan.io/dns/resolve?key={SHODAN_API}&hostnames={hostnames}"
    response = requests.get(dns_resolve_url)

    if response.status_code == 200:
        data = response.json()

        if user_id:
            log_user_action(user_id, "get_shodan_dns_resolve_data", f"Shodan DNS resolve for hostnames: {hostnames}")

        return jsonify(data)
    else:
        return jsonify({"error": "Shodan DNS Resolve API request failed", "details": response.text}), response.status_code

    

########################################
#     Scan Programs Dependencies       #
########################################
@app.route("/scan_dependencies", methods=["POST"])
def scan_dependencies():
    data = request.get_json()
    packages = data.get("packages", [])  

    if not packages:
        return jsonify({"error": "No packages provided"}), 400

    all_vulns = []

    for pkg in packages:
        try:
            osv_response = requests.post("https://api.osv.dev/v1/query", json={
                "package": {
                    "name": pkg["name"],
                    "ecosystem": pkg.get("ecosystem", "npm")
                }
            })

            if osv_response.ok:
                osv_data = osv_response.json().get("vulns", [])
                for vuln in osv_data:
                    all_vulns.append({
                        "package": pkg["name"],
                        "version": pkg["version"],
                        "ecosystem": pkg["ecosystem"],
                        "source": pkg.get("source", "manual"),
                        "osv_id": vuln.get("id"),
                        "aliases": vuln.get("aliases", []),
                        "summary": vuln.get("summary"),
                        "severity": vuln.get("severity", "unknown")
                    })
            else:
                print(f"OSV API returned error for {pkg['name']}: {osv_response.text}")

        except Exception as e:
            print(f"OSV lookup failed for {pkg['name']}: {str(e)}")

    return jsonify({
        "results": all_vulns
    })

########################################
#              Scan EPSS               #
########################################
@app.route("/scan_epss", methods=["POST"])
def scan_epss():
    data = request.get_json()
    advisories = data.get("advisories", [])  

    if not advisories:
        return jsonify({"error": "No advisories provided"}), 400

    # Step 1: Filter advisories with a valid CVE
    cve_ids = {entry["cve"] for entry in advisories if entry.get("cve", "").startswith("CVE-")}

    if not cve_ids:
        return jsonify({"message": "No valid CVEs found", "results": []}), 200

    # Step 2: Query EPSS
    epss_response = requests.get("https://api.first.org/data/v1/epss", params={
        "cve": ",".join(cve_ids)
    })

    epss_data = epss_response.json().get("data", []) if epss_response.ok else []

    # Step 3: Match CVEs and enrich
    enriched = []
    for advisory in advisories:
        epss_match = next((e for e in epss_data if e["cve"] == advisory["cve"]), None)
        enriched.append({
            **advisory,
            "epss": float(epss_match["epss"]) if epss_match else None,
            "percentile": float(epss_match["percentile"]) if epss_match else None,
            "date": epss_match.get("date") if epss_match else None
        })

    return jsonify({
        "results": enriched
    })

########################################
#       Hugging Face Enrichment        #
########################################

def get_risk_label(score):
        if score >= 4.0:
            return "Critical Risk"
        elif score >= 3.0:
            return "High Risk"
        elif score >= 2.0:
            return "Moderate Risk"
        elif score >= 1.0:
            return "Low Risk"
        else:
            return "No Risk"
        

@app.route("/enrich_risks", methods=["POST"])
def enrich_risks():
    advisories = request.get_json().get("advisories", [])
    headers = {
        "Authorization": f"Bearer {os.getenv('HUGGING_FACE_KEY')}",
        "Content-Type": "application/json"
    }

    impact_mapping = {
        "Critical Risk": 5,
        "High Risk": 4,
        "Moderate Risk": 3,
        "Low Risk": 2,
        "No Risk": 1
    }
    

    enriched = []

    for advisory in advisories:
        try:
            # Ensure we are passing candidate_labels to Hugging Face API
            payload = {
                "inputs": f"{advisory['cve']} may impact {advisory['package']} {advisory['version']}: {advisory['summary']}",
                "parameters": {
                    "candidate_labels": ["Critical Risk", "High Risk", "Moderate Risk", "Low Risk", "No Risk"]
                }
            }

            # Send request to Hugging Face API
            response = requests.post(os.getenv("HUGGING_FACE_URL"), headers=headers, json=payload)

            if response.status_code == 503:
                print("HF API is unavailable")
                enriched.append({**advisory, "risk_score": 0, "risk_label": "Unavailable"})
                continue
            
            result = response.json()

            if isinstance(result, dict) and "scores" in result and "labels" in result:
                top_label = result["labels"][0]
                likelihood = result["scores"][0]
                impact = impact_mapping.get(top_label, 1)

                # Retrieve last_seen and default to a timezone-aware current time
                last_seen = advisory.get("last_seen", datetime.datetime.now(datetime.timezone.utc))

                # If last_seen is provided as a string, parse it
                if isinstance(last_seen, str):
                    try:
                        last_seen = isoparse(last_seen)
                    except Exception as e:
                        print("Error converting last_seen with isoparse:", e)
                        last_seen = datetime.datetime.now(datetime.timezone.utc)

                if hasattr(last_seen, "tzinfo") and last_seen.tzinfo is not None:
                    last_seen = last_seen.replace(tzinfo=None)

                risk_score = calculate_risk(likelihood, impact, last_seen)
                risk_label = get_risk_label(risk_score)

                enriched.append({
                    **advisory,
                    "risk_score": risk_score,
                    "risk_label": risk_label
                })

                # Insert alert into the database
                insert_alert(advisory['threat_name'], risk_score, risk_label, advisory['summary'])
            else:
                enriched.append({**advisory, "risk_score": 0, "risk_label": "Malformed Response"})


        except Exception as e:
            print("HF API error:", str(e))
            enriched.append({**advisory, "risk_score": 0, "risk_label": "Error"})

    return jsonify({"results": enriched})

########################################
#            Real Time Alerts          #
########################################
@app.route("/process_threat", methods=["POST"])
def process_threat():
    data = request.json
    
    threat_name = data.get("threat_name")
    alert_description = data.get("alert_description", "")
    last_seen_str = data.get("last_seen")
    likelihood = data.get("likelihood")
    impact = data.get("impact")


    # Parse the last_seen timestamp into a datetime object
    last_seen = datetime.strptime(last_seen_str, "%Y-%m-%dT%H:%M:%SZ")

    # Calculate the actual risk score using the time-weighted function
    calculated_risk_score = calculate_risk(likelihood, impact, last_seen)
    
    # Insert only the calculated risk score into the database
    insert_alert(threat_name, calculated_risk_score, "Alert", alert_description)

    # Trigger the email and webhook alerts
    trigger_alerts(threat_name, likelihood, impact, alert_description, last_seen)

    return jsonify({"message": "High risk alert triggered!"}), 200

def fetch_alerts_from_db():
    try:
        conn = get_connection()  
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, threat_name, risk_score, alert_type, alert_description, created_at
                FROM alerts
                ORDER BY created_at DESC
            """)
            alerts = cur.fetchall()  # Fetch all rows

            if not alerts:
                return []  # Return empty list if no alerts found


            return [
                {
                    "id": alert[0],
                    "threat_name": alert[1],
                    "risk_score": alert[2],
                    "alert_type": alert[3],
                    "alert_description": alert[4],
                    "created_at": alert[5].isoformat()  
                }
                for alert in alerts
            ]
    
    except Exception as e:
        print(f"Error fetching alerts: {str(e)}")
        return []  # Return empty list in case of any error
    
    finally:
        if conn:
            conn.close()


@app.route("/get_alerts", methods=["GET"])
def get_alerts():
    try:
        alerts = fetch_alerts_from_db()  # Function to fetch alerts from DB
        if not alerts:
            return jsonify({"message": "No alerts found."}), 404  # Return a 404 if no alerts are found

        return jsonify(alerts), 200  
    except Exception as e:
        print(f"Error fetching alerts: {str(e)}")
        return jsonify({"error": "Error fetching alerts"}), 500  # Return error as JSON with a 500 status



    
########################################
#              Run Server              #
########################################

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)