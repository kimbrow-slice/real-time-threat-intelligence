Identify three OSINT APIs to integrate into the system:
Shodan, VirusTotal, SecurityTrails



Research API authentication and request methods & Write scripts to fetch real-time threat data:

Shodan Connection via Python:
This tool can be accessed using Python. We initialize a Shodan object to serve as the API by passing in the API key to a class constructor from Shodan’s python library. In the background, the class validates the key and returns the authenticated interface object. To make a request from Shodan’s services, we need to call corresponding functions from our authenticated API object.

FIRST:
$ pip install shodan

SECOND:
from shodan import Shodan

shodan_api = Shodan('LTYBNbsb567RnxzdbYeGDWJrYZJKqCAT')

# Lookup an IP
ipinfo = shodan_api.host('8.8.8.8')
print(ipinfo)

// ============================================ \\

VirusTotal Connection via Python:
This tool can be accessed using Python. We initialize a vt (VirusTotal) API connection object by passing the API key into an object constructor. This is done in one step here, pretty much the same as it was done in Shodan’s case. Similarly, an API call is made by declaring the endpoint and passing in the information you want to send to the endpoint. It will return an object that contains the results from the scan, and the results can be accessed by checking the fields on the object. 


NOTE – LIMITED TO: 
Request rate
4 lookups / min
Daily quota
500 lookups / day


FIRST:
$ git clone git://github.com/VirusTotal/vt-py.git
$ cd vt-py
$ sudo python3 setup.py install

SECOND:
import vt

#creating the client (vt_api)
vt_api = vt.Client("57413ddb6a6cc0657942fd811421c76d67cc3bee905626823ee31123c2d68f89")

# ex: checking the safety of a URL:
url_id = vt.url_id("http://www.virustotal.com")
url_results = vt_api.get_object("/urls/{}", url_id)

# checking how often a url is checked
url_results.times_submitted

# checking url analysis details 
url_results.last_analysis_stats

 

// ============================================ \\

SecurityTrails JSON data connected with python. Note that it is read-only.
Unlike Shodan which parses the JSON for us and returns it in one block or VirusTotal which returns an object containing all the information, we have to manually parse the JSON return values ourselves. In this one, all data being transmitted and received is in the form of JSON, so we need to format the API key into it when we pass along each request.

FIRST:
$ pip install requests

SECOND:
import requests as securitytrails_api

# Set up your API key
api_key = erAnjLGmQKcwwS3cv0pp0zg9utUZqBFx

# The base URL for SecurityTrails API; the endpoint:
base_url = "https://api.securitytrails.com/v1/domain/"
#/v1/domain/{domain}: Get information about a specific domain.

# Other sample endpoints
#/v1/ips/lookup/{ip}: Get information about a specific IP address.
#/v1/ips/ptr/{ip}: Reverse lookup for PTR records.


# The domain you want to query
domain = "google.com"

# Set up headers with your API key
headers = {
	"APIKEY": api_key
}

# Make a GET request to the API endpoint
response = securitytrails_api.get(f"{base_url}{domain}", headers=headers)

# Check if the request was successful
if response.status_code == 200:
	# Parse the JSON response
	data = response.json()
	print(data)  # Display the information
else:
	print(f"Error: {response.status_code}, {response.text}")
