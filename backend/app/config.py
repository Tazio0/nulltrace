import os
from dotenv import load_dotenv


load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")
INGESTION_INTERVAL = os.getenv("INGESTION_INTERVAL")
try :
    int(INGESTION_INTERVAL)
    INGESTION_INTERVAL = int(INGESTION_INTERVAL)
except (ValueError, TypeError):
    INGESTION_INTERVAL = 1