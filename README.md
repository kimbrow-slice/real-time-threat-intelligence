# Real-Time Threat Intelligence Dashboard

This project is a full-stack application that provides real-time threat analysis using VirusTotal and Shodan APIs. It includes secure user authentication, data storage with PostgreSQL, and logging of all user activity.

---

## Table of Contents

- [Features](#features)
- [How to Start](#how-to-start)
  - [1. Clone the Repository](#1-clone-the-repository)
  - [2. Set Up Environment Variables](#2-set-up-environment-variables)
  - [3. Set Up the Database](#3-set-up-the-database)
  - [4. Install Dependencies](#4-install-dependencies)
  - [5. Run the App in Development Mode](#5-run-the-app-in-development-mode)
- [Contributors](#contributors)

---

## Features

- IP lookup via **VirusTotal** and **Shodan**
- Frontend built with React
- Backend API built with Flask
- Secure login and registration using hashed passwords (bcrypt)
- Scan results stored in a **PostgreSQL** database
- Logs all user activity in a dedicated `logs` table
- Simple, user-friendly threat intelligence dashboard

---

## How to Start

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/real-time-threat-intelligence.git
cd real-time-threat-intelligence
```

### 2. Set Up Environment Variables
Create a ```.env``` file inside the /api directory with the following:

#### Database
```
DB_HOST=localhost
DB_PORT=5432
DB_USER=your_postgres_username
DB_NAME=threat_intel
DB_PASSWORD_ENC=your_encrypted_password
FERNET_KEY=your_fernet_key
SECRET_KEY=your_flask_secret_key
```

#### API Keys
```
VIRUSTOTAL_IP=your_virus_total_ip_url
VIRUSTOTAL_API_KEY=your_virustotal_key
SHODAN_API=your_shodan_key
HUGGING_FACE_KEY=your_huggingface_key
```

#### Shodan Endpoint
```
SHODAN_API_BASE_URL=your_shodan_base_url
SHODAN_API_SEARCH_URL=your_shodan_search_url
SHODAN_API_RESOLVE_DNS_URL=your_shodan_resolve_url
SHODAN_API_HTTPHEADERS_URL=your_shodan_httpheaders_url
SHODAN_API_IP_URL=your_shodan_ip_url
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
SENDGRID_API_KEY=your_sendgrid_api_key
SENDGRID_EMAIL=alerts@example.com
SENDGRID_RECIPIENT=admin@example.com
WEBHOOK_URL=https://your-webhook-url
```

### 3. Set Up the Database
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

### 4. Install Dependencies
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

### 5. Run the App in Development Mode
From the ```frontend/``` directory:
```
npm run dev
```
This will run:
React frontend on: http://localhost:3000
Flask backend API on: http://localhost:5000

---

## Final Presentation Download
👉[Download](docs/final_presentation.pptx)




# Contributors
- [kimbrow-slice](https://github.com/kimbrow-slice)
- [mohamede2022](https://github.com/mohamede2022)
- [kkkfc5](https://github.com/kkkfc5)
- [HashAbdulla](https://github.com/HashAbdulla)
- [MadisonAlex14](https://github.com/MadisonAlex14)

