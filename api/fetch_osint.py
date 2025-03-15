import requests
import psycopg2
import time

def retrieve_shodan():

    API_KEY = "your_shodan_api_key"
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



def retrieve_():
    print()


while True:
    retrieve_shodan()
    time.sleep(30)