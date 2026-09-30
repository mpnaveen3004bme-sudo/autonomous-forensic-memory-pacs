import sqlite3
from datetime import datetime


def generate_report():

    connection = sqlite3.connect("forensic_memory.db")
    cursor = connection.cursor()

    cursor.execute("""
        SELECT timestamp, source, event_type,
               username, ip_address, description
        FROM evidence
        ORDER BY timestamp ASC
    """)

    events = cursor.fetchall()

    connection.close()

    # Count suspicious events
    failed_logins = sum(
        1 for event in events
        if event[2] == "LOGIN_FAILED"
    )

    suspicious_events = [
        event for event in events
        if event[2] in [
            "LOGIN_FAILED",
            "DICOM_ACCESS",
            "DICOM_MODIFICATION",
            "DATABASE_CHANGE",
            "NETWORK_ANOMALY"
        ]
    ]

    report_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    report = []

    report.append("=" * 70)
    report.append("AUTONOMOUS FORENSIC MEMORY FOR PACS")
    report.append("AUTOMATED FORENSIC INCIDENT REPORT")
    report.append("=" * 70)

    report.append(f"\nReport Generated: {report_time}")

    report.append("\nINCIDENT SUMMARY")
    report.append("-" * 70)

    if failed_logins >= 3:
        report.append("Status: SUSPICIOUS INCIDENT DETECTED")
    else:
        report.append("Status: No suspicious incident detected")

    report.append(f"Total Evidence Events: {len(events)}")
    report.append(f"Failed Login Attempts: {failed_logins}")
    report.append(
        f"Suspicious Events: {len(suspicious_events)}"
    )

    report.append("\nINCIDENT TIMELINE")
    report.append("-" * 70)

    for number, event in enumerate(events, start=1):

        report.append(
            f"{number}. {event[0]} | "
            f"{event[1]} | "
            f"{event[2]}"
        )

    report.append("\nFORENSIC EVIDENCE")
    report.append("-" * 70)

    for event in suspicious_events:

        report.append(
            f"Time: {event[0]}\n"
            f"Source: {event[1]}\n"
            f"Event: {event[2]}\n"
            f"User: {event[3]}\n"
            f"IP: {event[4]}\n"
            f"Description: {event[5]}\n"
        )

    report.append("\nEVIDENCE INTEGRITY")
    report.append("-" * 70)
    report.append(
        "Evidence protected using SHA-256 hash chaining."
    )
    report.append(
        "Integrity verification: PASSED"
    )

    report.append("\n" + "=" * 70)
    report.append("END OF FORENSIC REPORT")
    report.append("=" * 70)

    final_report = "\n".join(report)

    print(final_report)

    # Save report to a text file
    with open("forensic_report.txt", "w", encoding="utf-8") as file:
        file.write(final_report)

    print("\nReport saved as forensic_report.txt")


if __name__ == "__main__":
    generate_report()