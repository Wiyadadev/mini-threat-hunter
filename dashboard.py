import streamlit as st
import pandas as pd
import altair as alt
from pathlib import Path

REPORT_FILE = Path("hunt_report.csv")

st.set_page_config(
    page_title="Mini Threat Hunter",
    page_icon="🔎",
    layout="wide"
)

# -----------------------------
# THEME
# -----------------------------

st.markdown("""
<style>
.stApp {
    background-color: #0B0F14;
    color: #E6EDF3;
}

h1, h2, h3 {
    color: #00E5A8;
}

[data-testid="stMetric"] {
    background-color: #111820;
    border: 1px solid #26313C;
    padding: 14px;
    border-radius: 12px;
}

[data-testid="stDataFrame"] {
    border: 1px solid #26313C;
    border-radius: 10px;
}
</style>
""", unsafe_allow_html=True)

st.title("🔎 Mini Threat Hunter Dashboard")
st.caption("Sysmon Threat Hunting Findings")

# -----------------------------
# LOAD DATA
# -----------------------------

if not REPORT_FILE.exists():
    st.error("hunt_report.csv not found. Run threat_hunter.py first.")
    st.stop()

df = pd.read_csv(REPORT_FILE)

required_columns = {
    "time",
    "event_id",
    "severity",
    "score",
    "image",
    "detail",
    "findings"
}

missing = required_columns - set(df.columns)

if missing:
    st.error(f"Missing CSV columns: {sorted(missing)}")
    st.write("Current columns:", list(df.columns))
    st.stop()

if df.empty:
    st.warning("hunt_report.csv contains no findings.")
    st.stop()

df["score"] = pd.to_numeric(
    df["score"],
    errors="coerce"
).fillna(0)

df = df.sort_values(
    by="score",
    ascending=False
)

# -----------------------------
# SUMMARY
# -----------------------------

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

# -----------------------------
# TOP THREATS
# -----------------------------

st.subheader("🚨 Top Threats")

st.dataframe(
    df.head(10),
    width="stretch",
    hide_index=True
)

# -----------------------------
# SEVERITY CHART
# -----------------------------

st.subheader("Severity Distribution")

severity_data = (
    df["severity"]
    .value_counts()
    .rename_axis("severity")
    .reset_index(name="count")
)

severity_chart = alt.Chart(severity_data).mark_bar(
    cornerRadiusTopLeft=6,
    cornerRadiusTopRight=6
).encode(
    x=alt.X(
        "severity:N",
        sort=["HIGH", "MEDIUM", "INFO"],
        title="Severity"
    ),
    y=alt.Y(
        "count:Q",
        title="Findings"
    ),
    color=alt.Color(
        "severity:N",
        scale=alt.Scale(
            domain=["HIGH", "MEDIUM", "INFO"],
            range=["#FF4B4B", "#FFA726", "#00C853"]
        ),
        legend=None
    ),
    tooltip=["severity", "count"]
)

st.altair_chart(
    severity_chart,
    width="stretch"
)

# -----------------------------
# THREAT SCORE CHART
# -----------------------------

st.subheader("Threat Score Distribution")

score_data = (
    df["score"]
    .value_counts()
    .sort_index()
    .rename_axis("score")
    .reset_index(name="count")
)

score_chart = alt.Chart(score_data).mark_bar(
    color="#00E5A8",
    cornerRadiusTopLeft=6,
    cornerRadiusTopRight=6
).encode(
    x=alt.X(
        "score:O",
        title="Threat Score"
    ),
    y=alt.Y(
        "count:Q",
        title="Findings"
    ),
    tooltip=["score", "count"]
)

st.altair_chart(
    score_chart,
    width="stretch"
)

# -----------------------------
# EVENT ID CHART
# -----------------------------

st.subheader("Event ID Distribution")

event_data = (
    df["event_id"]
    .value_counts()
    .sort_index()
    .rename_axis("event_id")
    .reset_index(name="count")
)

event_chart = alt.Chart(event_data).mark_bar(
    color="#42A5F5",
    cornerRadiusTopLeft=6,
    cornerRadiusTopRight=6
).encode(
    x=alt.X(
        "event_id:O",
        title="Sysmon Event ID"
    ),
    y=alt.Y(
        "count:Q",
        title="Findings"
    ),
    tooltip=["event_id", "count"]
)

st.altair_chart(
    event_chart,
    width="stretch"
)

# -----------------------------
# FILTERS
# -----------------------------

st.subheader("🔎 Hunt Findings")

severity_filter = st.multiselect(
    "Severity",
    ["HIGH", "MEDIUM", "INFO"],
    default=["HIGH", "MEDIUM", "INFO"]
)

max_score = max(
    1,
    int(df["score"].max())
)

min_score = st.slider(
    "Minimum Threat Score",
    min_value=0,
    max_value=max_score,
    value=0
)

filtered = df[
    (df["severity"].isin(severity_filter))
    & (df["score"] >= min_score)
]

st.dataframe(
    filtered,
    width="stretch",
    hide_index=True
)

# -----------------------------
# INVESTIGATION QUEUE
# -----------------------------

st.subheader("🛡️ Investigation Queue")

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
        width="stretch",
        hide_index=True
    )