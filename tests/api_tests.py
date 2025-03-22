import pytest
from api.shodan_integration import fetch_shodan_data
from api.virustotal_integration import fetch_virustotal_data

# Test function for Shodan API integration
def test_shodan_api():
    data = fetch_shodan_data("8.8.8.8")
    assert isinstance(data, dict)  # Ensure response is a dictionary
    assert "ports" in data  # Check if 'ports' key exists in response
    assert isinstance(data["ports"], list)  # Ensure 'ports' value is a list

# Test function for VirusTotal API integration
def test_virustotal_api():
    data = fetch_virustotal_data("example.com")
    assert isinstance(data, dict)  # Ensure response is a dictionary
    assert "malicious" in data  # Check if 'malicious' key exists in response
    assert isinstance(data["malicious"], int)  # Ensure 'malicious' value is an integer

# Run tests if script is executed directly
if __name__ == "__main__":
    pytest.main()
