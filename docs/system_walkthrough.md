## System Walkthrough
[Jeff - Main Developer](https://github.com/kimbrow-slice)

My contributions centered on integrating real-time threat intelligence, building secure authentication, system logging, user session meanagement, and designing the interactive user interface.

I developed much of both the **frontend** (`dashboard.js`, `register.js`, `registerform.jsx`, `login_page.js`) and **backend** (`routes.py`, `alerts.py`, `risk_calculator.py`, `db.py`) 
core components that control the platform. The dashboard enables users to monitor live security analytics, generated through `risk_calculator.py` by aggregating scan results and querying external 
threat intelligence sources including **VirusTotal**, **Shodan**, the **OSV** and **EPSS APIs**. The OSV and EPSS APIs contain CVE datasets that are further enriched using **Hugging Face** models, 
which assign severity labels, contextual threat scores, and probabilities of exploitation in the next 30 days. This enables focused risk prioritization and vendor aware security remediation planning.

For authentication, I implemented secure user login and registration workflows with full **session management**, **bcrypt-hashed password storage**, 
and **Cross-Site Request Forgery (CSRF)** protections. API requests from the frontend (`api.js`) are routed securely to the backend using tokenized sessions and sanitized inputs. 
The `db.py` file maintains user data and threat logs using a **PostgreSQL** database. To protect against **SQL injection**, all database interactions are executed using **parameterized SQL queries** via prepared 
statements in `db.py` and `routes.py`. This helps ensures that user input is never directly interpolated into query strings, eliminating a common vector for database compromise.

I've included my vulnerability assessment results from tools such as **WireShark**, **Nmap** (`nmap_scan.txt`) and **OWASP ZAP** (`ZAP-Report.html`), which provided me the ability to close crucial
gaps within the systems architecture. Additionally, I created `security_validation.md` to document the layered security controls and validate compliance our recommended threat mitigations.


