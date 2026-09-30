import streamlit as st
import sqlite3
import pandas as pd
import subprocess

from forensic_memory import verify_integrity
from forensic_report import generate_report

# ==========================================
# AUTONOMOUS FORENSIC MEMORY FOR PACS
# Dashboard
# ==========================================

st.set_page_config(
    page_title="PACS Forensic Memory",
    page_icon="🔐",
    layout="wide"
)


# ==========================================
# Title
# ==========================================

st.title("🔐 Autonomous Forensic Memory for PACS")

st.subheader("Hospital Black Box — Cyber Incident Investigation")
# ==========================================
# Generate New Incident
if st.button("🚨 Generate New PACS Incident"):

    # Clear previous forensic evidence
    connection = sqlite3.connect("forensic_memory.db")
    connection.execute("DELETE FROM evidence")
    connection.commit()
    connection.close()

    # Generate one fresh PACS incident
    subprocess.run(
        ["python", "event_simulator.py"],
        check=True
    )

    st.success("Fresh PACS incident generated successfully!")
    st.rerun()

# ==========================================
# Read Evidence Database
# ==========================================

connection = sqlite3.connect("forensic_memory.db")

query = """
SELECT
    id,
    timestamp,
    source,
    event_type,
    username,
    ip_address,
    description,
    event_hash
FROM evidence
ORDER BY id
"""

df = pd.read_sql_query(query, connection)

connection.close()


# ==========================================
# Incident Analysis
# ==========================================

failed_logins = len(
    df[df["event_type"] == "LOGIN_FAILED"]
)

dicom_events = len(
    df[df["source"] == "DICOM"]
)

database_events = len(
    df[df["source"] == "Database"]
)

network_events = len(
    df[df["source"] == "Network"]
)


incident_detected = (
    failed_logins >= 3
    and dicom_events > 0
    and database_events > 0
    and network_events > 0
)


# ==========================================
# Incident Status
# ==========================================

if incident_detected:

    st.error(
        "🚨 SUSPICIOUS INCIDENT DETECTED"
    )

else:

    st.success(
        "✅ NO SUSPICIOUS INCIDENT DETECTED"
    )


# ==========================================
# Dashboard Metrics
# ==========================================

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Total Events", len(df))

with col2:
    st.metric("Failed Logins", failed_logins)

with col3:
    st.metric("DICOM Events", dicom_events)

with col4:
    st.metric("Network Events", network_events)


# ==========================================
# Event Statistics
# ==========================================

st.header("📊 Event Statistics")

if not df.empty:

    event_counts = (
        df["event_type"]
        .value_counts()
        .rename_axis("Event Type")
        .reset_index(name="Count")
    )

    st.bar_chart(
        event_counts.set_index("Event Type")
    )

else:

    st.info("No forensic events available.")
# ==========================================
# Incident Evidence
# ==========================================

st.header("🚨 Incident Evidence")

if incident_detected:

    st.write(
        "The following suspicious activity was detected:"
    )

    st.write("• Multiple failed authentication attempts")
    st.write("• Successful PACS login")
    st.write("• DICOM activity")
    st.write("• PACS database modification")
    st.write("• Network anomaly")

else:

    st.write(
        "No suspicious sequence detected."
    )


# ==========================================
# Incident Timeline
# ==========================================

st.header("🕒 Incident Timeline")

timeline_columns = [
    "timestamp",
    "source",
    "event_type",
    "username",
    "ip_address",
    "description"
]

st.dataframe(
    df[timeline_columns],
    use_container_width=True
)


# ==========================================
# Evidence Hashes
# ==========================================

st.header("🔐 Forensic Evidence Integrity")

st.write(
    "Evidence is protected using SHA-256 hash chaining."
)

hash_columns = [
    "id",
    "timestamp",
    "event_type",
    "event_hash"
]

st.dataframe(
    df[hash_columns],
    use_container_width=True
)


# ==========================================
# Footer
# ==========================================

st.divider()

# ==========================================
# Evidence Integrity Verification
# ==========================================

st.header("🔐 Forensic Evidence Integrity")

if st.button("🔍 Verify Evidence Integrity"):

    integrity_status = verify_integrity()

    if integrity_status:
        st.success("✅ Evidence integrity verified successfully.")
    else:
        st.error("🚨 WARNING: Evidence integrity has been compromised!")
# ==========================================
# Forensic Report Download
# ==========================================

st.header("📄 Forensic Report")

if st.button("📋 Generate Forensic Report"):

    generate_report()

    with open("forensic_report.txt", "r", encoding="utf-8") as file:
        report_data = file.read()

    st.success("✅ Forensic report generated successfully!")

    st.download_button(
        label="⬇️ Download Forensic Report",
        data=report_data,
        file_name="forensic_report.txt",
        mime="text/plain"
    )
st.caption(
    "Autonomous Forensic Memory for PACS | "
    "Research Prototype"
)