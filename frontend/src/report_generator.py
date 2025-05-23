import os
import csv
from fpdf import FPDF
from db.db import get_connection

class ThreatReport(FPDF):
    def header(self):
        self.set_font("Arial", "B", 16)
        self.cell(200, 10, "Threat Intelligence Report", ln=True, align="C")
        self.ln(10)

    def add_threat(self, threat_name, risk_score, alert_type, alert_description):
        self.set_font("Arial", "B", 12)
        self.cell(0, 10, f"Threat: {threat_name}", ln=True)
        self.set_font("Arial", "", 12)
        self.cell(0, 10, f"Risk Score: {risk_score}", ln=True)
        self.cell(0, 10, f"Alert Type: {alert_type}", ln=True)
        self.multi_cell(0, 10, f"Description: {alert_description}")
        self.ln(5)

def fetch_alerts():
    conn = get_connection()
    if conn is None:
        return []
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT risk_score, alert_type, threat_name, alert_description
                FROM alerts
            """)
            return cur.fetchall()
    except Exception as e:
        print("Error fetching alerts:", e)
        return []
    finally:
        conn.close()

def generate_pdf_report(alerts, output_path="threat_report.pdf"):
    pdf = ThreatReport()
    pdf.add_page()
    for alert in alerts:
        risk_score, alert_type, threat_name, alert_description = alert
        pdf.add_threat(threat_name, risk_score, alert_type, alert_description)
    pdf.output(output_path)
    print(f"PDF report generated at {output_path}")

def generate_csv_report(alerts, output_path="threat_report.csv"):
    try:
        with open(output_path, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(["Risk Score", "Alert Type", "Threat Name", "Alert Description"])
            for alert in alerts:
                writer.writerow(alert)
        print(f"CSV report generated at {output_path}")
    except Exception as e:
        print("Error generating CSV report:", e)

if __name__ == "__main__":
    alerts = fetch_alerts()
    if alerts:
        generate_pdf_report(alerts)
        generate_csv_report(alerts)
    else:
        print("No alerts found to generate reports.")



""" DEAD VERS: 
# report_generator.py

from flask import Flask, send_file
from fpdf import FPDF
import os
import requests
from db.db import get_connection

app = Flask(__name__)

class ThreatReport(FPDF):
    def header(self):
        self.set_font("Arial", "B", 16)
        self.cell(200, 10, "Threat Intelligence Report", ln=True, align="C")
        self.ln(10)

    def add_threat(self, threat_name, alert_type, risk_score, alert_description, enriched_label):
        self.set_font("Arial", "B", 12)
        self.cell(0, 10, f"Threat Name: {threat_name}", ln=True)
        self.set_font("Arial", "", 12)
        self.cell(0, 10, f"Alert Type: {alert_type}", ln=True)
        self.cell(0, 10, f"Risk Score: {risk_score}", ln=True)
        self.multi_cell(0, 10, f"Description: {alert_description}")
        self.cell(0, 10, f"Enriched Risk Label: {enriched_label}", ln=True)
        self.ln(5)

@app.route("/generate_report", methods=["GET"])
def generate_report():
    # Setup Hugging Face headers
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

    # Query the database
    conn = get_connection()
    if conn is None:
        return "Database connection failed", 500

    try:
        cur = conn.cursor()
        cur.execute("SELECT risk_score, alert_type, threat_name, alert_description FROM alerts")
        rows = cur.fetchall()
        cur.close()
        conn.close()
    except Exception as e:
        return f"Error querying database: {e}", 500

    enriched_rows = []

    for row in rows:
        risk_score, alert_type, threat_name, alert_description = row
        description_text = (
            f"Threat {threat_name} of type {alert_type} has a risk score of {risk_score}. "
            f"Description: {alert_description}"
        )

        payload = {
            "inputs": description_text,
            "parameters": {
                "candidate_labels": list(impact_mapping.keys())
            }
        }

        try:
            response = requests.post(os.getenv("HUGGING_FACE_URL"), headers=headers, json=payload)
            if response.status_code == 503:
                enriched_label = "Unavailable"
            else:
                result = response.json()
                enriched_label = result.get("labels", ["Unknown"])[0]
        except Exception:
            enriched_label = "Error"

        enriched_rows.append((threat_name, alert_type, risk_score, alert_description, enriched_label))

    # Generate the PDF
    pdf = ThreatReport()
    pdf.add_page()

    for r in enriched_rows:
        pdf.add_threat(*r)

    output_path = "threat_intel_report.pdf"
    pdf.output(output_path)
    return send_file(output_path, as_attachment=True)



# ---------- Idea for having hybrid enrich_risks & report_generator, if that's any useful

""""""
@app.route("/generate_enriched_report", methods=["POST"])
def generate_enriched_report():
    advisories = request.get_json().get("advisories", [])

    headers = {
        "Authorization": f"Bearer {os.getenv('HUGGING_FACE_KEY')}",
        "Content-Type": "application/json"
    }

    enriched = []
    for advisory in advisories:
        payload = {
            "inputs": f"{advisory['cve']} may impact {advisory['package']} {advisory['version']}: {advisory['summary']}",
            "parameters": {
                "candidate_labels": ["Critical Risk", "High Risk", "Moderate Risk", "Low Risk", "No Risk"]
            }
        }
        response = requests.post(os.getenv("HUGGING_FACE_URL"), headers=headers, json=payload)

        if response.status_code == 503:
            enriched.append({**advisory, "risk_score": 0, "risk_label": "Unavailable"})
        else:
            result = response.json()
            enriched.append({
                **advisory,
                "risk_score": result["scores"][0] * 5,  # scale to 0-5, assuming sorted
                "risk_label": result["labels"][0]
            })

    # Now generate the PDF with enriched data
    pdf = ThreatReport()
    pdf.add_page()

    for threat in enriched:
        pdf.add_threat(
            risk_score=threat["risk_score"],
            alert_type=threat["risk_label"],
            threat_name=threat["cve"],
            alert_description=threat["summary"]
        )

    output_path = "enriched_threat_report.pdf"
    pdf.output(output_path)

    return send_file(output_path, as_attachment=True) 



"""