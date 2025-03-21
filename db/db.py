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
            password=DB_PASSWORD

        )
        print("DB_USER:", os.getenv("DB_USER"))
        print("DB_PASSWORD (decrypted):", DB_PASSWORD)

        return conn
    except Exception as e:
        print("Failed to connect to database:", e)
        return None
if __name__ == "__main__":
    conn = get_connection()
    if conn:
        print("Connected to the database!")
        conn.close()
    else:
        print("Connection failed.")


