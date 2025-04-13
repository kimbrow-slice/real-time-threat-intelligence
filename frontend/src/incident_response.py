import json
from db.db import get_connection
from datetime import datetime

class IncidentResponse:
    
    """ Load incident response playbooks from a JSON file."""
    def __init__(self, playbooks_path="playbooks.json"):
        self.playbooks = self.load_playbooks(playbooks_path)
      
    """ Read playbooks from a JSON file. Returns an empty dictionary if not found. """
    def load_playbooks(self, path):
        try:
            with open(path, "r") as file:
                return json.load(file)
        except FileNotFoundError:
            return {}
          
    """ Return a predefined mitigation strategy for a given threat. """
    def map_threat_to_mitigation(self, threat):
        mitigation_strategies = {
            "Unauthorized Access": "1. Look for possible entry points. 2. Address/Patch the vulnerability. 3. Alert employees to remain alert.",
            "SQL Injection": "1. Block the attacking IP. 2. Patch the vulnerability. 3. Conduct forensic analysis.",
            "Data Breach": "1. Determine the scale of the breach. 2. Patch the vulnerability. 3. Alert everyone affected in accordance to the law.",
            "Phishing Attack": "1. Notify affected users. 2. Change compromised credentials. 3. Update phishing filters.",
            "Malicious File Execution": "1. Track and block the user who uploaded the file. 2. Contain and remedy the malware. 3. Scan every future file uploaded."
        }
        return mitigation_strategies.get(threat, "No predefined mitigation strategy available.")
      



    def log_incident_response(incident, response_plan):
        conn = None
        try:
            conn = get_connection()
            with conn.cursor() as cur:
                # Insert into incident_response
                cur.execute("""
                    INSERT INTO incident_response (incident, date, response_plan)
                    VALUES (%s, %s, %s)
                    RETURNING id;
                """, (incident, datetime.today().date(), response_plan))

                response_id = cur.fetchone()[0]

                # Insert into incident_logs
                cur.execute("""
                    INSERT INTO incident_logs (incident_response_id)
                    VALUES (%s, %s);
                """, (response_id))

            conn.commit()

        except Exception as e:
            print("Incident logging error:", e)

        finally:
            if conn:
                conn.close()



    """ Create a response plan with threat details, severity, and mitigation."""
    def generate_response_plan(self, threat, severity):
        timestamp = datetime.utcnow().isoformat()
        mitigation = self.map_threat_to_mitigation(threat)
        playbook = self.playbooks.get(threat, "No specific playbook available.")
        
        return {
            "timestamp": timestamp,
            "threat": threat,
            "severity": severity,
            "mitigation": mitigation,
            "playbook": playbook
        }
    """Generate and print the response plan for a detected threat."""
    def handle_incident(self, threat, severity):
        response = self.generate_response_plan(threat, severity)
        print(json.dumps(response, indent=4))
        log_incident_response(threat, response)
        return response
    
    

if __name__ == "__main__":
    # Simulate a high severity malware detection incident
    incident_handler = IncidentResponse()
    incident_handler.handle_incident("malware_detected", "high")
    
