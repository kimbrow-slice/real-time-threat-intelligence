## Group 2 OSINT Research Report

Summary of tools:

Shodan: Scans everything connected to the internet. Lists All known information about the device, like open ports, IP Address, and services running.

Have I Been Pwned: Scans data breaches to see if your personal information has been leaked.

VirusTotal: Scans and detects files and URLs for being malicious or harmful.

SecurityTrails: Used in scanning web services and websites. Unlike Shodan or Censys, this seems more focused on websites and web services than just any device connected to the internet. Its focus is mostly on website and domain information, like certificates, DNS records, domain ownership, and more. This can help identify security issues like outdated certificates, open and exposed ports, and more.

theHarvester: Used both for information gathering and penetration testing. This one is more individual focused, in that it would harvest as much data it can  on a particular given target. It can be used both on corporations/businesses, as well as individual people.

IntelOwl: Bundles many other OSINT tools together--thus it has many of the same features of the other tools. For example, it scans files and URLs from VirusTotal, scans the internet from Shodan, and more. It is built for the purposes of scaling well and maintaining speed.

The Recon-ng Framework: framework to provide "web-based reconnaissance". Reconnaissance in this context means gathering information from public websites and online sources to learn about its weaknesses and/or other useful data. Recon-ng in particular is very modular and prides itself on being easy to implement even for those without a lot of programming knowledge. Interfaced with in Python, and hosted from a GitHub repository.

Maltego Platform: Advertises itself on being an "all-in-one investigation platform", good for everyone from novices to professional investigators. Like Microsoft office or Adobe cloud products, it Maltego seems to have a suit of 4 products that each do different things. Monitor monitors data in real-time, Evidence tracks potential threats, Graph visually and organically connects and consolidates data for easy parsing, and Search is an OSINT tool that searches data breaches, the dark web, identity databases, social media, and more.

Censys: Integrated using Python, it scans the internet to see the devices connected to it and can act as a lookup database, where you can search for specific devices or vulnerabilities. It is extremely robust and seems it can tell a staggering amount of information about the devices it sees, and the searches can even be made via the website instead of code if desired.

Hunter.io: Provides services for searching for email addresses (company's, professional's, or private). Seems to be aimed to create and gather information about business or professional contacts.

ANY.RUN: realtime malware detection and analysis. Ability to upload files or links for analysis, and receive a report on how malicious it is. It monitors network traffic and for threats, for example malicious connections and strange HTTP/DNS requests. It is also useful for sandboxing, allowing the experimentation and tampering with potentially harmful things in a safe environment. It has a good UI.

OSINT Industries: Seems useful for stalking individuals across the internet. Tracking their social media, online associations, aliases, and other forms of their online presence.



- Selected OSINT tools:
The most useful for our purposes are: Shodan, VirusTotal, theHarvester.

- How they can be integrated into the web app:
Perhaps VirusTotal could be used in a way where the webapp users can select any files or links accessible via the webapp and send them to VirusTotal for processing.
Shodan can be used to test what is outward facing in our webapp and thHarvester could be used for automatic penetration testing so that we can learn what vulnerabilities we have.

- API access methods:
Shodan and theHarvester are accessible through Python.
VirusTotal is accessed through VT4Splunk, an app that uses Python.


