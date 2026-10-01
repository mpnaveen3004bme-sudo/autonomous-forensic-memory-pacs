import sqlite3
import hashlib
import json
from datetime import datetime


# ==========================================
# 1. Create Forensic Memory Database
# ==========================================

def initialize_database():

    connection = sqlite3.connect("forensic_memory.db")
    cursor = connection.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS evidence (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        source TEXT,
        event_type TEXT,
        username TEXT,
        ip_address TEXT,
        description TEXT,
        event_hash TEXT,
        previous_hash TEXT
    )
    """)

    connection.commit()
    connection.close()

    print("Forensic Memory database initialized.")


# ==========================================
# 2. Generate SHA-256 Hash
# ==========================================

def calculate_hash(event_data, previous_hash=""):

    data = json.dumps(event_data, sort_keys=True) + previous_hash

    return hashlib.sha256(
        data.encode("utf-8")
    ).hexdigest()


# ==========================================
# 3. Store Evidence
# ==========================================

def store_event(event):

    connection = sqlite3.connect("forensic_memory.db")
    cursor = connection.cursor()

    # Get the hash of the previous event
    cursor.execute(
        "SELECT event_hash FROM evidence ORDER BY id DESC LIMIT 1"
    )

    result = cursor.fetchone()

    if result:
        previous_hash = result[0]
    else:
        previous_hash = "GENESIS"

    # Create event data
    event_data = {
        "timestamp": event["timestamp"],
        "source": event["source"],
        "event_type": event["event_type"],
        "username": event["username"],
        "ip_address": event["ip_address"],
        "description": event["description"]
    }

    # Generate SHA-256 hash
    event_hash = calculate_hash(
        event_data,
        previous_hash
    )

    # Store event
    cursor.execute("""
    INSERT INTO evidence
    (
        timestamp,
        source,
        event_type,
        username,
        ip_address,
        description,
        event_hash,
        previous_hash
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event["timestamp"],
        event["source"],
        event["event_type"],
        event["username"],
        event["ip_address"],
        event["description"],
        event_hash,
        previous_hash
    ))

    connection.commit()
    connection.close()

    return event_hash


# ==========================================
# 4. Read All Evidence
# ==========================================

def get_all_events():

    connection = sqlite3.connect("forensic_memory.db")

    cursor = connection.cursor()

    cursor.execute("""
    SELECT *
    FROM evidence
    ORDER BY id
    """)

    events = cursor.fetchall()

    connection.close()

    return events


# ==========================================
# 5. Verify Evidence Integrity
# ==========================================

def verify_integrity():

    connection = sqlite3.connect("forensic_memory.db")

    cursor = connection.cursor()

    cursor.execute("""
    SELECT
        id,
        timestamp,
        source,
        event_type,
        username,
        ip_address,
        description,
        event_hash,
        previous_hash
    FROM evidence
    ORDER BY id
    """)

    events = cursor.fetchall()

    connection.close()

    previous_hash = "GENESIS"

    for event in events:

        event_id = event[0]

        event_data = {
            "timestamp": event[1],
            "source": event[2],
            "event_type": event[3],
            "username": event[4],
            "ip_address": event[5],
            "description": event[6]
        }

        stored_hash = event[7]
        stored_previous_hash = event[8]
        if stored_previous_hash != previous_hash:
            print(
                f"WARNING: Evidence {event_id} has an invalid previous hash!"
            )
            return False

        calculated_hash = calculate_hash(
            event_data,
            previous_hash
        )

        if stored_hash != calculated_hash:
            print(
                f"WARNING: Evidence {event_id} has been modified!"
            )
            return False

        previous_hash = stored_hash

    print("Evidence integrity verified successfully.")
    return True


# ==========================================
# 6. Start Database
# ==========================================

if __name__ == "__main__":

    initialize_database()

    print("Autonomous Forensic Memory is ready.")

    print("\nChecking forensic evidence integrity...")

    verify_integrity()
    from datetime import datetime, timedelta


def generate_incident_events():

    start_time = datetime.now().replace(microsecond=0)

    events = [

        {
            "timestamp": str(start_time),
            "source": "Authentication",
            "event_type": "LOGIN_FAILED",
            "username": "radiologist",
            "ip_address": "192.168.1.50",
            "description": "Failed PACS login attempt"
        },

        {
            "timestamp": str(start_time + timedelta(seconds=20)),
            "source": "Authentication",
            "event_type": "LOGIN_FAILED",
            "username": "radiologist",
            "ip_address": "192.168.1.50",
            "description": "Repeated failed PACS login attempt"
        },

        {
            "timestamp": str(start_time + timedelta(seconds=40)),
            "source": "Authentication",
            "event_type": "LOGIN_FAILED",
            "username": "radiologist",
            "ip_address": "192.168.1.50",
            "description": "Third failed PACS login attempt"
        },

        {
            "timestamp": str(start_time + timedelta(seconds=60)),
            "source": "Authentication",
            "event_type": "LOGIN_SUCCESS",
            "username": "radiologist",
            "ip_address": "192.168.1.50",
            "description": "Successful privileged PACS login"
        },

        {
            "timestamp": str(start_time + timedelta(seconds=90)),
            "source": "DICOM",
            "event_type": "DICOM_ACCESS",
            "username": "radiologist",
            "ip_address": "192.168.1.50",
            "description": "Unusual DICOM image access detected"
        },

        {
            "timestamp": str(start_time + timedelta(seconds=120)),
            "source": "DICOM",
            "event_type": "DICOM_MODIFICATION",
            "username": "radiologist",
            "ip_address": "192.168.1.50",
            "description": "DICOM metadata modification detected"
        },

        {
            "timestamp": str(start_time + timedelta(seconds=150)),
            "source": "Database",
            "event_type": "DATABASE_CHANGE",
            "username": "radiologist",
            "ip_address": "192.168.1.50",
            "description": "Unexpected PACS database modification"
        },

        {
            "timestamp": str(start_time + timedelta(seconds=180)),
            "source": "Network",
            "event_type": "NETWORK_ANOMALY",
            "username": "radiologist",
            "ip_address": "192.168.1.50",
            "description": "Unusual network activity detected"
        }
    ]

    return events


if __name__ == "__main__":

    events = generate_incident_events()

    print("Simulated PACS incident generated.")
    print("-----------------------------------")

    for event in events:
        print(
            event["timestamp"],
            "|",
            event["source"],
            "|",
            event["event_type"]
        )