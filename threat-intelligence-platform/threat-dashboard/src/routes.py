from flask import Flask, request, jsonify
import requests
import os
from flask_cors import CORS
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

# Load credentials from .env file
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
VIRUSTOTAL_API_KEY = os.getenv("REACT_APP_VIRUSTOTAL_API_KEY")  # VirusTotal API Key
VIRUSTOTAL_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses"  # VirusTotal IP Lookup API

# Login Route
@app.route("/login", methods=["POST"])
def login():
    print("Received login request")  # Debugging output

    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON request"}), 400

    username = data.get("username")
    password = data.get("password")

    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        return jsonify({"message": "Login successful", "redirect": "/dashboard"}), 200
    else:
        return jsonify({"error": "Invalid credentials"}), 401


# Scan an IP Route
@app.route("/scan_ip", methods=["GET"])
def scan_ip():
    ip_address = request.args.get("ip")
    
    if not ip_address:
        return jsonify({"error": "No IP address provided"}), 400
    
    print(f"Scanning IP: {ip_address}")  # Debugging output
    
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY  # Attach API Key in headers
    }

    # Make a request to VirusTotal API
    response = requests.get(f"{VIRUSTOTAL_IP_URL}/{ip_address}", headers=headers)

    # Return VirusTotal response to React
    if response.status_code == 200:
        return response.json()
    else:
        return jsonify({
            "error": "VirusTotal API request failed",
            "status": response.status_code,
            "details": response.text
        }), response.status_code


# Run Flask App
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)