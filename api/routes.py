from flask import Flask, request, jsonify
import requests
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from flask_cors import CORS
from dotenv import load_dotenv
import bcrypt
import json

from db.db import get_connection

load_dotenv()

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

# API Keys
VIRUSTOTAL_API_KEY = os.getenv("REACT_APP_VIRUSTOTAL_API_KEY")
VIRUSTOTAL_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses"
SHODAN_API = os.getenv("SHODAN_API")

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
        print("[!] Logging error:", e)
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
        print("[!] Login error:", str(e))
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()

########################################
#         VirusTotal + Shodan          #
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
        finally:
            if conn:
                conn.close()

        if user_id:
            log_user_action(user_id, "get_shodan_data", f"Shodan scan on IP: {ip_address}")

        return jsonify(data)
    else:
        return jsonify({"error": "Shodan API request failed", "details": response.text}), response.status_code

########################################
#              Run Server              #
########################################

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
