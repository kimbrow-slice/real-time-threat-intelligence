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

