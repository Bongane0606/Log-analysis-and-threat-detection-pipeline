"""Streamlit dashboard for the SSH log analysis and threat detection pipeline.
Run with: streamlit run dashboard.py
"""
import sqlite3

import pandas as pd
import streamlit as st

st.set_page_config(page_title="SSH Threat Detection", layout="wide")

DB_PATH = "events.db"


@st.cache_data(ttl=5)
def load_data():
    con = sqlite3.connect(DB_PATH)
    try:
        events = pd.read_sql("SELECT * FROM ssh_events ORDER BY ts", con)
    except pd.io.sql.DatabaseError:
        events = pd.DataFrame()
    try:
        alerts = pd.read_sql("SELECT * FROM alerts ORDER BY ts", con)
    except pd.io.sql.DatabaseError:
        alerts = pd.DataFrame()
    con.close()
    if not events.empty:
        events["ts"] = pd.to_datetime(events["ts"])
    if not alerts.empty:
        alerts["ts"] = pd.to_datetime(alerts["ts"])
    return events, alerts


st.title("SSH Threat Detection Dashboard")

events, alerts = load_data()

if events.empty:
    st.warning(
        "No data found. Run `python3 parse_ssh.py auth.log` and "
        "`python3 detect_ssh.py` first, then refresh this page."
    )
    st.stop()

# --- Top metrics ---
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total SSH events", len(events))
col2.metric("Failed logins", (events["status"] == "failed").sum())
col3.metric("Successful logins", (events["status"] == "success").sum())
col4.metric("Alerts raised", len(alerts))

st.divider()

# --- Alerts table ---
st.subheader("Alerts")
if alerts.empty:
    st.info("No alerts raised yet.")
else:
    st.dataframe(
        alerts[["ts", "ip", "rule", "severity", "detail"]],
        use_container_width=True,
        hide_index=True,
    )

st.divider()

col_left, col_right = st.columns(2)

# --- Events over time ---
with col_left:
    st.subheader("Events over time")
    by_minute = (
        events.set_index("ts")
        .groupby([pd.Grouper(freq="1min"), "status"])
        .size()
        .unstack(fill_value=0)
    )
    st.line_chart(by_minute)

# --- Top offending IPs ---
with col_right:
    st.subheader("Top IPs by failed attempts")
    failed = events[events["status"].isin(["failed", "invalid_user"])]
    top_ips = failed["ip"].value_counts().head(10)
    st.bar_chart(top_ips)

st.divider()

# --- Raw events table ---
st.subheader("Raw events")
st.dataframe(
    events[["ts", "host", "user", "ip", "status", "invalid_user"]].sort_values(
        "ts", ascending=False
    ),
    use_container_width=True,
    hide_index=True,
)