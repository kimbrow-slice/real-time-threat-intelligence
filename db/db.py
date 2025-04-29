import os
import psycopg2
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Decrypt DB password
FERNET_KEY = os.getenv("FERNET_KEY")
ENCRYPTED_PW = os.getenv("DB_PASSWORD_ENC")

fernet = Fernet(FERNET_KEY.encode())
DB_PASSWORD = fernet.decrypt(ENCRYPTED_PW.encode()).decode()

# Connect to PostgreSQL
def get_connection():
    try:
        conn = psycopg2.connect(
            host=os.getenv("DB_HOST"),
            port=os.getenv("DB_PORT"),
            dbname=os.getenv("DB_NAME"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD_ENC")        
            )
        return conn
    except Exception as e:
        print("Failed to connect to database:", e)
        return None

# Insert an alert into the alerts table
def insert_alert(threat_name, risk_score, alert_type, alert_description):
    conn = get_connection()
    if not conn:
        print("Failed to connect to the database to insert alert.")
        return

    try:
        with conn.cursor() as cur:
            insert_query = """
                INSERT INTO alerts (threat_name, risk_score, alert_type, alert_description)
                VALUES (%s, %s, %s, %s)
            """
            cur.execute(insert_query, (threat_name, risk_score, alert_type, alert_description))
            conn.commit()
            print(f"Alert for {threat_name} inserted successfully.")
    except Exception as e:
        print(f"Error inserting alert: {e}")
    finally:
        conn.close()

# Initialize the schema (only needs to run once)
def initialize_schema(schema_file="schema.sql"):
    conn = get_connection()
    if not conn:
        print("Failed to connect to DB for schema initialization.")
        return

    try:
        with conn.cursor() as cur, open(schema_file, "r") as f:
            cur.execute(f.read())
        conn.commit()
        print("Schema initialized successfully.")
    except Exception as e:
        print("Error applying schema:", e)
    finally:
        conn.close()

# Test connection and schema initialization
if __name__ == "__main__":
    conn = get_connection()
    if conn:
        print("Connected to the database!")
        conn.close()

        # Initialize schema only if necessary
        initialize_schema()  
    else:
        print("Connection failed.")
