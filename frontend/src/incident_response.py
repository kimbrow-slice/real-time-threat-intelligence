import json
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
            "malware_detected": "Isolate the affected system and run a full malware scan.",
            "unauthorized_access": "Revoke unauthorized credentials and enforce MFA.",
            "data_breach": "Initiate breach containment, notify stakeholders, and conduct forensic analysis.",
            "DDoS_attack": "Activate rate limiting and engage ISP for traffic filtering.",
        }
        return mitigation_strategies.get(threat, "No predefined mitigation strategy available.")
      
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
        return response

if __name__ == "__main__":
    # Simulate a high severity malware detection incident
    incident_handler = IncidentResponse()
    incident_handler.handle_incident("malware_detected", "high")


