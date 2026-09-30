import sqlite3


# ==========================================
# STEP 15: Suspicious Incident Detection
# ==========================================

def detect_incident():

    connection = sqlite3.connect("forensic_memory.db")
    cursor = connection.cursor()

    cursor.execute("""
        SELECT timestamp, source, event_type, username,
               ip_address, description
        FROM evidence
        ORDER BY id
    """)

    events = cursor.fetchall()

    connection.close()

    # Count failed login attempts
    failed_logins = 0

    privileged_login = False
    dicom_activity = False
    database_change = False
    network_anomaly = False

    for event in events:

        event_type = event[2]

        if event_type == "LOGIN_FAILED":
            failed_logins += 1

        elif event_type == "LOGIN_SUCCESS":
            privileged_login = True

        elif event_type in ["DICOM_ACCESS", "DICOM_MODIFICATION"]:
            dicom_activity = True

        elif event_type == "DATABASE_CHANGE":
            database_change = True

        elif event_type == "NETWORK_ANOMALY":
            network_anomaly = True

    # ======================================
    # Incident Detection Rule
    # ======================================

    if (
        failed_logins >= 3
        and privileged_login
        and dicom_activity
        and database_change
        and network_anomaly
    ):

        print("\n🚨 SUSPICIOUS INCIDENT DETECTED")
        print("--------------------------------")
        print("Reason:")
        print("• Multiple failed login attempts")
        print("• Successful privileged login")
        print("• Unusual DICOM activity")
        print("• PACS database modification")
        print("• Network anomaly detected")

        return True

    else:

        print("\nNo suspicious incident detected.")

        return False


# ==========================================
# Run Detection
# ==========================================

if __name__ == "__main__":

    print("Analyzing forensic evidence...")
    print("--------------------------------")

    detect_incident()