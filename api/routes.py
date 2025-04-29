from flask import Flask, request, jsonify, session, abort
from functools import wraps
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
import secrets
import re
import ipaddress
from dateutil.parser import isoparse 
from risk_calculator import calculate_risk, get_risk_label
from flask_talisman import Talisman
from dateutil import parser
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import cross_origin
import hashlib

from db.db import get_connection

# API Keys
VIRUSTOTAL_API_KEY = os.getenv("REACT_APP_VIRUSTOTAL_API_KEY")
VIRUSTOTAL_IP=os.getenv("VIRUSTOTAL_IP")
SHODAN_API = os.getenv("SHODAN_API")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
SHODAN_API_SEARCH_URL = os.getenv("SHODAN_API_SEARCH_URL")
SHODAN_API_RESOLVE_DNS_URL = os.getenv("SHODAN_API_RESOLVE_DNS_URL")
SHODAN_API_IP_URL = os.getenv("SHODAN_API_IP_URL")
SHODAN_API_HTTPHEADERS_URL = os.getenv("SHODAN_API_HTTPHEADERS_URL")


HUGGING_FACE_KEY = os.getenv("HUGGING_FACE_KEY")
HUGGING_FACE_URL = os.getenv("HUGGING_FACE_URL")
REACT_APP_API_URL= os.getenv("REACT_APP_API_URL")
frontend_origin = os.getenv("REACT_APP_ORIGIN", "http://localhost:3000")


# SendGrid Environment Variables
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
SENDGRID_EMAIL = os.getenv("SENDGRID_EMAIL")
SENDGRID_RECIPIENT = os.getenv("SENDGRID_RECIPIENT")
WEBHOOK_URL = os.getenv("WEBHOOK_URL")

load_dotenv()


app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
CORS(app, supports_credentials=True, origins=[os.getenv("REACT_APP_ORIGIN")])
Talisman(app, 
         force_https=False, 
         strict_transport_security=True,
         strict_transport_security_preload=True,
         strict_transport_security_max_age=63072000,
         content_security_policy={
             'default-src': "'self'",
             'script-src': "'self'",
             'style-src': "'self'",
             'img-src': "'self'",
             'object-src': "'none'",
         })

limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)



########################################
#         Logging Helper Function      #
########################################

def validate_csrf():
    client_token = request.headers.get("X-CSRF-Token")
    server_token = session.get("csrf_token")

    if not client_token:
        abort(403, description="CSRF token missing from request headers")

    if not server_token or client_token != server_token:
        abort(403, description="CSRF validation failed")

def csrf_protect(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        validate_csrf()
        return f(*args, **kwargs)
    return decorated_function

def is_valid_username(username):
    return re.match(r"^[A-Za-z0-9_]{3,20}$", username)

def is_strong_password(password):
    return (
        len(password) >= 8 and
        re.search(r"[A-Z]", password) and
        re.search(r"\d", password)
    )

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def log_user_action(user_id, action_type, details=None):
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO logs (user_id, action_type, details, client_ip)
                VALUES (%s, %s, %s, %s)
            """, (
                user_id,
                action_type,
                details,
                request.remote_addr
            ))
        conn.commit()
    except Exception as e:
        print("Logging error:", e)
    finally:
        if conn:
            conn.close()

@app.before_request

def enforce_internal_api_key():
    protected_endpoints = ["scan_ip", "get_shodan_data"]
    if request.endpoint in protected_endpoints:
        api_key = request.headers.get("X-Internal-API-Key")
        if api_key != os.getenv("INTERNAL_API_KEY"):
            print(403)
            

@app.after_request
def secure_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

@app.after_request
def remove_server_header(response):
    response.headers["Server"] = "Secure"
    response.headers["X-Powered-By"] = "Hidden"
    return response


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

    if not is_valid_username(username) or not is_strong_password(raw_password):
        return jsonify({"error": "Invalid username or weak password"}), 400

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

def get_username_or_empty():
    try:
        data = request.get_json(force=True, silent=True)
        return data.get("username", "")
    except:
        return "unknown"

@limiter.limit("10/hour", key_func=get_username_or_empty)

@limiter.limit("5 per minute", key_func=get_remote_address)


@app.route("/login", methods=["POST"])
def login_user():
    
    data = request.get_json()
    username = data.get("username")
    raw_password = data.get("password")

    if not username or not raw_password:
        return jsonify({"error": "Username and password required"}), 400

    conn = get_connection()
    if conn is None:
        return jsonify({"error": "Failed to connect to database"}), 500

    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, password_hash FROM users WHERE username = %s", (username,))
            row = cur.fetchone()

        if not row:
            return jsonify({"error": "Invalid credentials"}), 401

        user_id, stored_hash = row
        hashed_input = hashlib.sha256(raw_password.encode("utf-8")).hexdigest()

        if bcrypt.checkpw(hashed_input.encode("utf-8"), stored_hash.encode("utf-8")):  

            log_user_action(user_id, "login", f"User '{username}' logged in.")

            # CSRF token generation
            csrf_token = secrets.token_hex(128)
            session["csrf_token"] = csrf_token  # Store in session

            return jsonify({
                "message": "Login successful",
                "user_id": user_id,
                "redirect": "/dashboard",
                "csrf_token": csrf_token  # Send to frontend
            }), 200
        else:
            return jsonify({"error": "Invalid credentials"}), 401

    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500
    finally:
        conn.close()

@app.route("/logout", methods=["POST"])
@csrf_protect
def logout_user():
    response = jsonify({"message": "Logged out"})
    response.set_cookie("session", "", expires=0)
    return response

########################################
#             VirusTotal               #
########################################

from flask import request, jsonify
import requests

@app.route("/scan_ip", methods=["GET"])
def scan_ip():
    ip_address = request.args.get("ip")
    user_id = request.args.get("user_id")

    if not ip_address or not is_valid_ip(ip_address):
        return jsonify({"error": "Invalid or missing IP"}), 400

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Accept": "application/json"
    }

    try:
        response = requests.get(
            f"{VIRUSTOTAL_IP}/{ip_address}",
            headers=headers,
            timeout=10  # Set a 10-second timeout to avoid long blocking calls
        )

        response.raise_for_status()

        if user_id:
            log_user_action(user_id, "scan_ip", f"VirusTotal scan on IP: {ip_address}")
        
        return jsonify(response.json())

    except requests.exceptions.Timeout:
        return jsonify({"error": "VirusTotal scan timed out"}), 504

    except requests.exceptions.HTTPError as http_err:
        return jsonify({"error": "VirusTotal returned an error", "details": str(http_err)}), response.status_code

    except Exception as e:
        return jsonify({"error": "Unexpected server error", "details": str(e)}), 500


########################################
#               Shodan IP              #
########################################
@app.route("/get_shodan_data", methods=["GET"])
def get_shodan_data():
    ip_address = request.args.get("ip")
    user_id = request.args.get("user_id")

    if not ip_address or not is_valid_ip(ip_address):
        return jsonify({"error": "Invalid or missing IP"}), 400

    shodan_url = SHODAN_API_IP_URL.replace("{ip}", ip_address)
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
        finally:
            if conn:
                conn.close()

        if user_id:
            log_user_action(user_id, "get_shodan_data", f"Shodan scan on IP: {ip_address}")
        return jsonify(data)
    else:
        return jsonify({"error": "Shodan API request failed", "details": response.text}), response.status_code


########################################
#          Shodan Search API           #
########################################
@app.route("/get_shodan_search_data", methods=["POST"])
@cross_origin(origins="http://localhost:3000", supports_credentials=True)
def get_shodan_search_data():
    data = request.get_json()
    query = data.get("query")
    user_id = data.get("user_id")

    if not query:
        return jsonify({"error": "Missing search query"}), 400

    shodan_url = f"https://api.shodan.io/shodan/host/search?key={SHODAN_API}&query={query}&facets=ip"

    try:
        response = requests.get(shodan_url)
        if response.status_code != 200:
            return jsonify({"error": "Shodan Search API request failed", "details": response.text}), response.status_code

        raw_data = response.json()

        # Create a structured output
        results = []
        for match in raw_data.get("matches", []):
            results.append({
                "ip": match.get("ip_str"),
                "port": match.get("port"),
                "hostnames": match.get("hostnames", []),
                "org": match.get("org"),
                "isp": match.get("isp"),
                "location": {
                    "city": match.get("location", {}).get("city"),
                    "region": match.get("location", {}).get("region_name"),
                    "country": match.get("location", {}).get("country_name")
                },
                "product": match.get("product"),
                "banner": match.get("version"),
                "http_title": match.get("http", {}).get("title")
            })

        # Log if applicable
        if user_id:
            log_user_action(user_id, "get_shodan_search_data", f"Shodan search: {query}")

        return jsonify({"results": results})

    except Exception as e:
        print("Shodan search error:", str(e))
        return jsonify({"error": "Unexpected error occurred", "details": str(e)}), 500

########################################
#     Shodan DNS Resolve API           #
########################################
@app.route("/get_shodan_dns_resolve_data", methods=["GET"])
def get_shodan_dns_resolve_data():
    hostnames = request.args.get("hostnames")
    user_id = request.args.get("user_id")

    if not hostnames:
        return jsonify({"error": "No hostnames provided"}), 400

    dns_resolve_url = SHODAN_API_RESOLVE_DNS_URL.replace("{hostnames}", hostnames)
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
@cross_origin(origin="http://localhost:3000", supports_credentials=True)
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
@cross_origin(origin="http://localhost:3000", supports_credentials=True)
def scan_epss():
    try:
        advisories = request.get_json() or []

        if not isinstance(advisories, list):
            return jsonify({"error": "Invalid input. Expected a list of advisories."}), 400

        # Filter advisories with a valid CVE
        cve_ids = {entry["cve"] for entry in advisories if entry.get("cve", "").startswith("CVE-")}

        if not cve_ids:
            return jsonify({"message": "No valid CVEs found", "results": []}), 200

        # Query EPSS
        try:
            epss_response = requests.get("https://api.first.org/data/v1/epss", params={
                "cve": ",".join(cve_ids)
            }, timeout=10)

            epss_response.raise_for_status()
            epss_data = epss_response.json().get("data", [])
        except Exception as e:
            return jsonify({"error": "Failed to fetch EPSS data", "details": str(e)}), 502

        # Match CVEs and enrich
        enriched = []
        for advisory in advisories:
            epss_match = next((e for e in epss_data if e["cve"] == advisory["cve"]), None)
            enriched.append({
                **advisory,
                "epss": float(epss_match["epss"]) if epss_match else None,
                "percentile": float(epss_match["percentile"]) if epss_match else None,
                "date": epss_match.get("date") if epss_match else None
            })

        return jsonify({ "results": enriched })

    except Exception as e:
        return jsonify({"error": "Unexpected server error", "details": str(e)}), 500

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
            # Build prompt
            payload = {
                "inputs": f"{advisory['cve']} may impact {advisory['package']} {advisory['version']}: {advisory['summary']}",
                "parameters": {
                    "candidate_labels": ["Critical Risk", "High Risk", "Moderate Risk", "Low Risk", "No Risk"]
                }
            }

            # Request risk classification from Hugging Face
            response = requests.post(os.getenv("HUGGING_FACE_URL"), headers=headers, json=payload)

            if response.status_code == 503:
                enriched.append({**advisory, "risk_score": 0, "risk_label": "Unavailable"})
                continue

            result = response.json()

            if isinstance(result, dict) and "scores" in result and "labels" in result:
                top_label = result["labels"][0]
                likelihood = result["scores"][0]
                impact = impact_mapping.get(top_label, 1)

                last_seen = advisory.get("last_seen", datetime.datetime.now(datetime.timezone.utc))
                if isinstance(last_seen, str):
                    try:
                        last_seen = isoparse(last_seen)
                    except Exception:
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

                insert_alert(advisory['threat_name'], risk_score, risk_label, advisory['summary'])
            else:
                enriched.append({**advisory, "risk_score": 0, "risk_label": "Malformed Response"})

        except Exception as e:
            percentile = advisory.get("percentile") if isinstance(advisory, dict) else None
            try:
                if percentile is not None:
                    risk_score = round(float(percentile) * 4, 2)
                    risk_label = get_risk_label(risk_score)
                    enriched.append({
                        **advisory,
                        "risk_score": risk_score,
                        "risk_label": risk_label
                    })
                else:
                    enriched.append({
                        **advisory,
                        "risk_score": 0,
                        "risk_label": "Error"
                    })
            except Exception as fallback_error:
                enriched.append({
                    **advisory,
                    "risk_score": 0,
                    "risk_label": "Error"
                })


    return jsonify({"results": enriched})

@app.route("/predict_behavior", methods=["POST"])
def predict_behavior():
    data = request.get_json()
    threat_description = data.get("threat_description", "")

    if not threat_description:
        return jsonify({"error": "Missing threat_description"}), 400

    prediction = predict_threat_behavior(threat_description)
    return jsonify({"prediction": prediction})


def predict_threat_behavior(threat_description):
    # Format the prompt into a question-like statement
    prompt = (
        f"Analyze the following security threat and predict possible next attack vectors:\n"
        f"{threat_description}"
    )

    headers = {
        "Authorization": f"Bearer {os.getenv('HUGGING_FACE_KEY')}",
        "Content-Type": "application/json"
    }

    payload = {
        "inputs": prompt
    }

    try:
        response = requests.post(os.getenv("HUGGING_FACE_URL"), headers=headers, json=payload)

        if response.status_code != 200:
            return f"Hugging Face API error: {response.status_code}"

        result = response.json()

        # Handle both classification and text-generation responses
        if isinstance(result, dict) and "generated_text" in result:
            return result["generated_text"]
        elif isinstance(result, list) and "generated_text" in result[0]:
            return result[0]["generated_text"]
        else:
            return "Unexpected response format from Hugging Face."
    except Exception as e:
        return f"Error contacting Hugging Face API: {str(e)}"


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
        return jsonify({"error": "Error fetching alerts"}), 500  # Return error as JSON with a 500 status



    
########################################
#              Run Server              #
########################################

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)




