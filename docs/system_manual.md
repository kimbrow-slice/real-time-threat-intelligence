# Real-Time Threat Intelligence Dashboard – System Guide

## 1. Introduction

The Real-Time Threat Intelligence Dashboard is a full-stack application that provides real-time threat analysis using external APIs. It supports secure user authentication, displays enriched threat alerts on a user-friendly dashboard, and logs all user activity. The system is built with:
- A **Flask Backend** for API endpoints and business logic.
- A **React Frontend** for a dynamic user interface.
- A **PostgreSQL Database** for storing scan results, user actions, and logs.
- External integrations with **VirusTotal**, **Shodan**, **Hugging Face** for enrichment and machine learning analysis, **Discord** for alert notifications, and **Sendgrid** for SMTP alerting.

---

## 2. System Architecture Overview

- **Frontend (React):**
  - Manages secure login, registration, and dynamic display of threat alerts.
  - Periodically fetches updated alert data from the backend.

- **Backend (Flask):**
  - Processes user scan requests and manages API interactions.
  - Calls external services like VirusTotal, Shodan, and Hugging Face to enrich threat data.
  - Logs user activity and scan results to the PostgreSQL database.
  - Sends alerts via Discord webhooks and SMTP (using Sendgrid).

- **Database (PostgreSQL):**
  - Stores detailed records such as scan data, user information, and logs.
  
- **External API Integrations:**
  - **VirusTotal:** Scans IP addresses, URLs, and file hashes to detect threats.
  - **Shodan:** Retrieves network information and vulnerability details.
  - **Hugging Face API:** Provides enrichment and machine learning analysis for threat data.
  - **Discord Webhook:** Delivers instant alerts and notifications to a Discord channel.
  - **Firewall Configuration:** Utilizes dynamic firewall rules based on threat analysis.

---

## 3. Backend Overview

- **API Endpoints & Business Logic:**
  - Receives scan requests and performs threat analysis by calling external APIs.
  - Logs each scan and user activity to the PostgreSQL database.
  
- **Security:**
  - Implements secure user authentication using hashed passwords (bcrypt).

---

## 4. Frontend Overview

- **User Interface:**
  - Provides screens for user registration and secure login.
  - Displays a real-time dashboard with enriched threat alerts.
  
- **Data Communication:**
  - Fetches threat data via HTTP requests to the Flask backend.
  - Updates the UI dynamically as new data becomes available.

---

## 5. API Integration

- **VirusTotal:**  
  Used to analyze IP addresses, URLs, and file hashes to determine threat levels.

- **Shodan:**  
  Retrieves comprehensive network information and vulnerability details.

- **Hugging Face API:**  
  Employed for enrichment and machine learning analysis to provide deeper insights into threat data.

- **Discord Webhook:**  
  Configured to send alerts and notifications directly to a Discord channel for rapid team awareness.

- **Firewall Configuration:**  
  Applies dynamic firewall rules based on the threat intelligence analysis to help secure systems.

- **Sendgrid (SMTP Alerting):**  
  Sends email alerts to team members, ensuring prompt notification of critical events.

---

## 6. Database Overview

- **Data Storage:**
  - **User Data:** Contains secure login and registration details.
  - **Scan Results:** Records detailed information from each scan, including results from external API calls.
  - **Logs:** A dedicated `logs` table stores all user activities for auditing and analysis.

---

## 7. Deployment and Setup

### Environment Variables

#### Database
```
DB_USER=your_postgres_username
DB_NAME=your_database_name
DB_PASSWORD_ENC=your_encrypted_password
FERNET_KEY=your_fernet_key
DB_HOST=localhost
DB_PORT=your_port_number
```

#### API Keys and Integrations
```
VIRUSTOTAL_IP=your_virus_total_ip_url
VIRUSTOTAL_API_KEY=your_virustotal_key
SHODAN_API=your_shodan_key
HUGGING_FACE_KEY=your_huggingface_key
SHODAN_API_BASE_URL=your_shodan_base_url
SHODAN_API_SEARCH_URL=your_shodan_search_url
SHODAN_API_RESOLVE_DNS_URL=your_shodan_resolve_url
SHODAN_API_HTTPHEADERS_URL=your_shodan_httpheaders_url
SHODAN_API_IP_URL=your_shodan_ip_url
DISCORD_WEBHOOK_URL=your_discord_webhook_url
FIREWALL_CONFIG=your_firewall_rules_config
```

#### Localhost API
```
REACT_APP_SHODAN_API_URL=internal_route_url/
REACT_APP_API_URL=internal_route_url/
REACT_APP_VIRUSTOTAL_API_URL=internal_route_url/
REACT_APP_VIRUSTOTAL_API_KEY=internal_route_url/
REACT-APP_ALERTS=internal_route_url/
```

#### SMTP Alerting
```
SENDGRID_API_KEY=your_sendgrid_key
SENDGRID_EMAIL=your_sendgrid_sender_email
SENDGRID_RECIPIENT=your_sendgrid_receipient
WEBHOOK_URL=your_webhook_url
```

### Database Setup

Make sure PostgreSQL is installed and running.

#### Enter PostgreSQL shell
```
psql -U your_postgres_username
```

#### Inside psql
```
CREATE DATABASE threat_intel;
```

#### Then run schema
```
\i path/to/db/schema.sql
```

### Install Dependencies

#### Backend
```
cd api
pip install -r requirements.txt
```

#### Frontend
```
cd ../frontend
npm install
```

### Running the Application

- **Start the Backend Server:**  
  Navigate to the backend directory and start the Flask server.
  
- **Start the Frontend Server:**  
  In the frontend directory, run the development server (e.g., `npm run dev`).  
  The frontend will be available at [http://localhost:3000](http://localhost:3000) and the backend API at [http://localhost:5000](http://localhost:5000).

---

## 8. Summary

The Real-Time Threat Intelligence Dashboard integrates multiple external services to provide enriched, real-time threat analysis. Key system features include:
- Secure user management with robust authentication.
- Comprehensive threat analysis using VirusTotal, Shodan, and Hugging Face for ML enrichment.
- Dynamic alert notifications via Discord and Sendgrid SMTP.
- Reliable data storage and comprehensive logging in PostgreSQL.

This clear separation of concerns across the frontend, backend, and database layers ensures scalability, maintainability, and rapid deployment—making it an effective tool for real-time threat intelligence.

---

## Contributors
- [kimbrow-slice](https://github.com/kimbrow-slice)
- [mohamede2022](https://github.com/mohamede2022)
- [kkkfc5](https://github.com/kkkfc5)
- [HashAbdulla](https://github.com/HashAbdulla)
- [MadisonAlex14](https://github.com/MadisonAlex14)
