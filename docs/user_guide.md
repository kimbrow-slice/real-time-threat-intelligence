
# Real-Time Threat Intelligence Platform – User Guide

## Welcome

Welcome to the Real-Time Threat Intelligence Platform. This platform enables you to submit and review indicators of compromise (IOCs) such as IP addresses or domains and receive enriched threat analysis in real time. This guide will walk you through the features and usage of the platform to ensure you get the most value from it.

This guide is intended for security analysts, IT personnel, and users authorized to monitor and respond to cybersecurity threats within the organization.

## Getting Started

### Accessing the Platform

The platform is web-based and can be accessed using any modern browser. Supported browsers include:

- Google Chrome
- Mozilla Firefox
- Microsoft Edge

Ensure JavaScript is enabled and your browser is up to date.

### Logging In or Registering

1. Navigate to the login screen.
2. If you have an account, enter your credentials and click **Login**.
3. If you are a new user, click **Register** and complete the sign-up form with your name, email, and a secure password.
4. Upon registration, you will be redirected to the dashboard.

## Using the Platform

### Dashboard Overview

After logging in, the dashboard provides a snapshot of:

- Recent threat scans
- Active alerts
- Summary charts (threat severity breakdowns)

You can initiate new scans or view detailed reports from this interface.

### Submitting a Threat Indicator

1. Click **Submit Scan** or **New Scan** on the dashboard.
2. Enter one or more indicators in the input box. Supported types include:
   - IP addresses (e.g., 8.8.8.8)
   - Domain names (e.g., google.com)
3. Click **Scan** to begin the analysis.
4. The platform will call multiple intelligence sources to process the indicator.

### Viewing Scan Results

Once complete, scan results will appear in the dashboard. Each entry includes:

- Indicator scanned
- Timestamp
- Risk level (Low, Moderate, High, Critical)
- Quick summary of findings

Click any result to expand and view:

- VirusTotal detection counts and related files
- Shodan-exposed ports and service banners
- Natural language classification from machine learning models

## Understanding Scan Feedback

Each scan uses multiple threat feeds:

- **VirusTotal**: Shows reputation, number of engines flagging the indicator, and known associated malware.
- **Shodan**: Provides open port data, known services, and security exposures for IP addresses.
- **Hugging Face (ML Model)**: Adds classification tags like phishing, ransomware, or high-risk, based on context.

These layers help you triage and prioritize threats effectively.

## Real-Time Alerts

The system displays live alerts in the right-hand panel of the dashboard when new high-risk indicators are found.

You may also receive alerts through:

- **Email** via SendGrid
- **Discord** if your organization has configured webhook notifications

Alert contents typically include the indicator, threat level, and a link to view more details.

## Security Tips

To maintain platform integrity and ensure meaningful results:

- Only submit relevant and authorized indicators.
- Do not scan internal-only IPs unless approved.
- Use strong, unique passwords and keep your account credentials secure.
- Report any suspicious results or false positives to your IT/security team.

## FAQ

**Q: What types of indicators can I scan?**  
A: Currently, the platform supports IP addresses and domain names. Support for hashes and URLs may be added in the future.

**Q: How long do scans take?**  
A: Most scans return within 10–30 seconds depending on external API response times.

**Q: I received no results. Is that normal?**  
A: Yes, sometimes indicators have no known threats associated. The system will still log the scan for audit purposes.

**Q: Can I export results?**  
A: Not at this time. For now, you can take screenshots or copy results as needed.

**Q: How are results stored?**  
A: All scan data is stored in a PostgreSQL database and tied to your user account.

