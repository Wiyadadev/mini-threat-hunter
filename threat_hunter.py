import streamlit as st
import pandas as pd
from pathlib import Path

REPORT_FILE = Path("hunt_report.csv")

st.set_page_config(
    page_title="Mini Threat Hunter",
    page_icon="🔎",
    layout="wide"
)

st.title("🔎 Mini Threat Hunter Dashboard")
st.caption("Sysmon Threat Hunting Findings")

if not REPORT_FILE.exists():
    st.error("hunt_report.csv not found. Run threat_hunter.py first.")
    st.stop()

df = pd.read_csv(REPORT_FILE)

# Sort highest threat first
df = df.sort_values(
    by=["score", "severity"],
    ascending=[False, True]
)

total = len(df)
high = len(df[df["severity"] == "HIGH"])
medium = len(df[df["severity"] == "MEDIUM"])
info = len(df[df["severity"] == "INFO"])

c1, c2, c3, c4 = st.columns(4)

c1.metric("Total Findings", total)
c2.metric("HIGH", high)
c3.metric("MEDIUM", medium)
c4.metric("INFO", info)

st.divider()

st.subheader("🚨 Top Threats")

top_threats = df.sort_values(
    by="score",
    ascending=False
).head(10)

st.dataframe(
    top_threats,
    use_container_width=True,
    hide_index=True
)

st.subheader("Severity Distribution")
st.bar_chart(df["severity"].value_counts())

st.subheader("Threat Score Distribution")
st.bar_chart(df["score"].value_counts().sort_index())

st.subheader("Event ID Distribution")
st.bar_chart(df["event_id"].value_counts())

st.subheader("Hunt Findings")

severity_filter = st.multiselect(
    "Severity",
    ["HIGH", "MEDIUM", "INFO"],
    default=["HIGH", "MEDIUM", "INFO"]
)

min_score = st.slider(
    "Minimum Threat Score",
    min_value=0,
    max_value=int(df["score"].max()) if not df.empty else 10,
    value=0
)

filtered = df[
    (df["severity"].isin(severity_filter))
    & (df["score"] >= min_score)
]

st.dataframe(
    filtered,
    use_container_width=True,
    hide_index=True
)

st.subheader("🔎 Investigation Queue")

queue = df[
    df["severity"].isin(["HIGH", "MEDIUM"])
].sort_values(
    by="score",
    ascending=False
)

if queue.empty:
    st.success("No findings currently require investigation.")
else:
    st.dataframe(
        queue,
        use_container_width=True,
        hide_index=True
    )