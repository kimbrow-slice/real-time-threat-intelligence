from shodan import Shodan

shodan_api = Shodan('LTYBNbsb567RnxzdbYeGDWJrYZJKqCAT')

# Lookup an IP
ipinfo = shodan_api.host('8.8.8.8')
print(ipinfo)
