import redis
import requests
import json

# Setup Redis cache
cache = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

# Function to fetch data from the API
def fetch_from_osint(ip):
    """ Get threat data for an IP from VirusTotal. """
    url = f"https://api.virustotal.com/v3/ip_addresses/{ip}"
    headers = {"x-apikey": "your_api_key_here"}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    return None

# Function to get threat data with caching temporarily 
def get_threat_data(ip):
    """ Checking the cache first, then fetching from the API if required. """
    cached_data = cache.get(ip)
    if cached_data:
        return json.loads(cached_data)
    
    data = fetch_from_osint(ip)
    if data:
        cache.setex(ip, 3600, json.dumps(data))  # Cache for 1 hour
    return data

if __name__ == "__main__":
    # Testing with a sample IP
    test_ip = "8.8.8.8"
    result = get_threat_data(test_ip)
    print(json.dumps(result, indent=4))
