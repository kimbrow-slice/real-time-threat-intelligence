import schedule
import time
from fetch_osint import retrieve_shodan, retrieve_HIBP, retrieve_security_trails

def run_osint_updates():
    retrieve_shodan()
    retrieve_security_trails()
    retrieve_HIBP()

# Schedule API calls every 6 hours
schedule.every(6).hours.do(run_osint_updates)
while True:
    schedule.run_pending()
    time.sleep(1)