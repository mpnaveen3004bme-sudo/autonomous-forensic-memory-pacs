from datetime import datetime, timedelta
from forensic_memory import initialize_database, store_event


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

    # Initialize forensic database
    initialize_database()

    # Generate simulated PACS events
    events = generate_incident_events()

    print("Simulated PACS incident generated.")
    print("-----------------------------------")

    # Store every event in forensic memory
    for event in events:

        event_hash = store_event(event)

        print(
            event["timestamp"],
            "|",
            event["source"],
            "|",
            event["event_type"]
        )

        print("Hash:", event_hash)
        print()
        
    print("All events stored in Forensic Memory.")

    for event in events:
        print(
            event["timestamp"],
            "|",
            event["source"],
            "|",
            event["event_type"]
        )
        