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
SHODAN_API = os.getenv("SHODAN_API")
SHODAN_API_IP_URL = os.getenv("SHODAN_API_IP_URL")

# Login Route
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        return jsonify({"message": "Login successful", "redirect": "/dashboard"}), 200
    else:
        return jsonify({"error": "Invalid credentials"}), 401

@app.route("/scan_ip", methods=["GET"])
def scan_ip():
    ip_address = request.args.get("ip")
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(f"{VIRUSTOTAL_IP_URL}/{ip_address}", headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        return jsonify({"error": "VirusTotal API request failed"}), response.status_code

@app.route("/get_shodan_data", methods=["GET"])
def get_shodan_data():
    ip_address = request.args.get("ip")
    shodan_api_key = os.getenv("SHODAN_API")
    shodan_url = f"https://api.shodan.io/shodan/host/{ip_address}?key={shodan_api_key}"

    response = requests.get(shodan_url)

    if response.status_code == 200:
        return jsonify(response.json())
    else:
        return jsonify({"error": "Shodan API request failed", "details": response.text}), response.status_code


# Run Flask App
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)