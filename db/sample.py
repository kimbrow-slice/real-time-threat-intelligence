from cryptography.fernet import Fernet
import psycopg2
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

# Decrypt the encrypted password
fernet = Fernet(os.getenv("FERNET_KEY").encode())
DB_PASSWORD = fernet.decrypt(os.getenv("DB_PASSWORD_ENC").encode()).decode()

# Establish database connection
conn = psycopg2.connect(
    host=os.getenv("DB_HOST"),
    port=os.getenv("DB_PORT"),
    dbname=os.getenv("DB_NAME"),
    user=os.getenv("DB_USER"),
    password=DB_PASSWORD
)
cursor = conn.cursor()

# Sample insert statements
commands = [
    # Hardware
    "INSERT INTO assets (name, category, description) VALUES ('Firewall Appliance', 'Hardware', 'Cisco ASA firewall for network security');",
    "INSERT INTO hardware (id, hardware_type, manufacturer, model) VALUES (currval(pg_get_serial_sequence('assets','id')), 'Firewall', 'Cisco', 'ASA 5508-X');",

    # Software
    "INSERT INTO assets (name, category, description) VALUES ('Customer Management System', 'Software', 'Handles customer interactions and support.');",
    "INSERT INTO software (id, software_version, vendor) VALUES (currval(pg_get_serial_sequence('assets','id')), 'v3.2.1', 'Salesforce');",

    # Data
    "INSERT INTO assets (name, category, description) VALUES ('Customer Payment Records', 'Data', 'Sensitive financial transaction logs.');",
    "INSERT INTO data (id, data_classification) VALUES (currval(pg_get_serial_sequence('assets','id')), 'Confidential');",

    # People
    "INSERT INTO assets (name, category, description) VALUES ('John Doe - IT Security Engineer', 'People', 'Responsible for monitoring security events.');",
    "INSERT INTO people (id, role) VALUES (currval(pg_get_serial_sequence('assets','id')), 'IT Staff');",

    # Processes
    "INSERT INTO assets (name, category, description) VALUES ('Database Backup Process', 'Process', 'Automated daily database backups.');",
    "INSERT INTO processes (id, process_type, frequency) VALUES (currval(pg_get_serial_sequence('assets','id')), 'Backup', 'Daily');"
]

# Execute commands
try:
    for command in commands:
        cursor.execute(command)
    conn.commit()
    print("Sample data inserted successfully.")
except Exception as e:
    conn.rollback()
    print("Error inserting data:", str(e))
finally:
    cursor.close()
    conn.close()
