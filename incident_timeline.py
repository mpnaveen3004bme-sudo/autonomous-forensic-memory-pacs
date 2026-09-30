import sqlite3


# ==========================================
# STEP 16: Incident Timeline Reconstruction
# ==========================================

def generate_timeline():

    connection = sqlite3.connect("forensic_memory.db")
    cursor = connection.cursor()

    cursor.execute("""
        SELECT timestamp,
               source,
               event_type,
               username,
               ip_address,
               description
        FROM evidence
        ORDER BY timestamp ASC
    """)

    events = cursor.fetchall()

    connection.close()

    print("\n")
    print("=" * 75)
    print("        AUTONOMOUS FORENSIC MEMORY")
    print("        INCIDENT TIMELINE")
    print("=" * 75)

    for number, event in enumerate(events, start=1):

        timestamp = event[0]
        source = event[1]
        event_type = event[2]
        username = event[3]
        ip_address = event[4]
        description = event[5]

        print(f"\nEvent {number}")
        print("-" * 75)
        print("Time        :", timestamp)
        print("Source      :", source)
        print("Event       :", event_type)
        print("User        :", username)
        print("IP Address  :", ip_address)
        print("Description :", description)

    print("\n")
    print("=" * 75)
    print("        END OF INCIDENT TIMELINE")
    print("=" * 75)


# ==========================================
# Run Timeline
# ==========================================

if __name__ == "__main__":

    print("Reconstructing incident timeline...")

    generate_timeline()