
import psycopg2
import time



def retrieve_shodan():

    import requests

    API_KEY = "LTYBNbsb567RnxzdbYeGDWJrYZJKqCAT"
    IP = "8.8.8.8"

    try:
        URL = f"https://api.shodan.io/shodan/host/{IP}?key={API_KEY}"
        response = requests.get(URL).json()
        # Connect to PostgreSQL and store the threat data
    except:
        print("BAD CONNECTION TO SHODAN: " + e)
        return

    try: 
        conn = psycopg2.connect("dbname=threat_intel user=admin password=Root1234")
    except Exception as e:
        print("BAD CONNECTION TO POSTGRES: " + e)
        return

# The 12 threats:
#       Compromises to intellectual property
#       Deviations in quality of service from service providers
#       Espionage or trespass 
#       Forces of nature
#       Human error or failure 
#       Information extortion 
#       Sabotage or vandalism 
#    8  Software attacks 
#       Technical hardware failures or errors 
#       Technical software failures or errors 
#       Technological obsolescence 
#       Theft

# initialize the threats


    cursor = conn.cursor()

    # First insert the vulnerability into db.
    cursor.execute("""INSERT INTO vulnerabilities (vulnerability_name, vulnerability_desc, severity_level)
        VALUES (%s, %s, %s)
        ON CONFLICT (vulnerability_name) DO NOTHING
        RETURNING id;""", 
        (response.get('ports'), "Exposed ports detected", 6))
                                                        #  ^ HARD CODED THREAT VALUE? IS THIS FINE?


    # this grabs the most recent thing done to the db, and then grabs the first column of it.
    # i.e. this grabs the vuln_id so we can input it in the next query.
    vulnerability_id = cursor.fetchone()[0]


    # Insert the TVA risk rating
    cursor.execute("""INSERT INTO risk_ratings (asset_id, threat_id, vulnerability_id, risk_score, risk_description)
        VALUES (%s, %s, %s, %s, %s);""", 
        (1, 8, vulnerability_id, 7, "Open ports are bad; allows traffic in."))
        #^  ^  hardcoded values  ^    ^
        
    # Commit the transaction
    conn.commit()   
    cursor.close()
    conn.close()



def retrieve_HIBP():
    
    import requests

    email_to_check = "placeholder@placeholder.com"
    api_key = "PLACEHOLDER_API_KEY"

    # URL for the API connection
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email_to_check}"

    # Set info for the API request
    headers = {
        "User-Agent": "Python script",  # required by HIBP
        "hibp-api-key": api_key  
    }

    # Make the GET request
    response = requests.get(url, headers=headers)

    # If API connection/response is not successful:
    if response.status_code != 200:
        print(f"BAD CONNECTION TO HAVE I BEEN PWNED: {response.status_code}")
        return
    elif response.status_code == 404:
        print(f"{email_to_check} has not been found in any breaches.")
        return

    #else: 
    # populate with returned breaches
    breaches = response.json()

    # if email is not found in breach, return
    if not breaches:
        print(f"{email_to_check} has not been found in any breaches.")
        return
        
    
    # for every breach that was returned
    for breach in breaches:

        # Try connecting to the db
        try: 
            conn = psycopg2.connect("dbname=threat_intel user=admin password=Root1234")
        except Exception as e:
            print("BAD CONNECTION TO POSTGRES: " + e)
            return
        
        cursor = conn.cursor()

        # Insert the vulnerability into db.
        cursor.execute("""INSERT INTO vulnerabilities (vulnerability_name, vulnerability_desc, severity_level)
            VALUES (%s, %s, %s)
            ON CONFLICT (vulnerability_name) DO NOTHING
            RETURNING id;""", 
            (breach.BreachDate + " " + breach.Title, "Email address was breached.", 4))
                                                                                 #  ^ HARD CODED THREAT VALUE? IS THIS FINE?


        # this grabs the most recent thing done to the db, and then grabs the first column of it.
        # i.e. this grabs the vuln_id so we can input it in the next query.
        vulnerability_id = cursor.fetchone()[0]


        # Insert the TVA risk rating
        cursor.execute("""INSERT INTO risk_ratings (asset_id, threat_id, vulnerability_id, risk_score, risk_description)
            VALUES (%s, %s, %s, %s, %s);""", 
            (1, 8, vulnerability_id, 4, "Emails were breached, created opportunities for phishing and spam."))
            #^  ^  hardcoded values  ^    ^
            
    # Commit the transaction to the db
    conn.commit()   
    cursor.close()
    conn.close()
        




def retrieve_security_trails():
    import requests as securitytrails_api

    # Set up your API key
    api_key = "erAnjLGmQKcwwS3cv0pp0zg9utUZqBFx"

    # The base URL for SecurityTrails API; the endpoint:
    base_url = "https://api.securitytrails.com/v1/domain/"
    #/v1/domain/{domain}: Get information about a specific domain.

    # Other sample endpoints
    #/v1/ips/lookup/{ip}: Get information about a specific IP address.
    #/v1/ips/ptr/{ip}: Reverse lookup for PTR records.


    # The domain you want to query
    domain = "placeholder.com"

    # Set up headers with your API key
    headers = {
        "APIKEY": api_key
    }

    # Make a GET request to the API endpoint
    response = securitytrails_api.get(f"{base_url}{domain}", headers=headers)

    # If API connection/response is not successful:
    if response.status_code != 200:
        print(f"BAD CONNECTION TO HAVE I BEN PWNED: {response.status_code}")
        return


    # Populate with the JSON response
    data = response.json()
    
    
    # Try connecting to the db
    try: 
        conn = psycopg2.connect("dbname=threat_intel user=admin password=Root1234")
    except Exception as e:
        print("BAD CONNECTION TO POSTGRES: " + e)
        return
    
    cursor = conn.cursor()

    # Insert the vulnerability into db.
    cursor.execute("""INSERT INTO vulnerabilities (vulnerability_name, vulnerability_desc, severity_level)
        VALUES (%s, %s, %s)
        ON CONFLICT (vulnerability_name) DO NOTHING
        RETURNING id;""", 
        (data.name, data.description, 5))
                                   #  ^ HARD CODED THREAT VALUE? IS THIS FINE?


    # this grabs the most recent thing done to the db, and then grabs the first column of it.
    # i.e. this grabs the vuln_id so we can input it in the next query.
    vulnerability_id = cursor.fetchone()[0]


    # Insert the TVA risk rating
    cursor.execute("""INSERT INTO risk_ratings (asset_id, threat_id, vulnerability_id, risk_score, risk_description)
        VALUES (%s, %s, %s, %s, %s);""", 
        (1, 8, vulnerability_id, 5, data.description))
        #^  ^  hardcoded values  ^    ^
            
    # Commit the transaction to the db
    conn.commit()   
    cursor.close()
    conn.close()



while True:
    retrieve_shodan()
    retrieve_HIBP()
    retrieve_security_trails()

    time.sleep(10000)