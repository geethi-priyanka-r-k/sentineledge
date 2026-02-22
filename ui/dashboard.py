import streamlit as st
import pandas as pd
import time
import os
from datetime import datetime

import plotly.graph_objects as go

# -----------------------------
# Page + Theme (LIGHT + BLACK TEXT)
# -----------------------------
st.set_page_config(page_title="SentinelEdge AI", layout="wide")

st.markdown("""
<style>
/* App background */
.stApp { background: #f6f7fb; }

/* Force text to black */
html, body, [class*="css"]  { color: #111 !important; }
h1, h2, h3, h4, h5, h6, p, div, span, label, small { color: #111 !important; }

/* Cards */
.card {
    background: #ffffff;
    border: 1px solid rgba(0,0,0,0.08);
    border-radius: 16px;
    padding: 14px 16px;
    margin-bottom: 10px;
    box-shadow: 0 6px 18px rgba(17, 17, 17, 0.05);
}

/* Small label */
.mini {
    font-size: 12px;
    opacity: 0.75;
}

/* Badge */
.badge {
    display: inline-block;
    padding: 4px 10px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 700;
    border: 1px solid rgba(0,0,0,0.12);
}
.badge-low  { background: rgba(46, 204, 113, 0.15); color: #0b4d2a !important; }
.badge-med  { background: rgba(241, 196, 15, 0.18); color: #5a4b00 !important; }
.badge-high { background: rgba(230, 126, 34, 0.18); color: #5a2f00 !important; }
.badge-crit { background: rgba(231, 76, 60, 0.18); color: #5a0000 !important; }

/* Sidebar */
section[data-testid="stSidebar"] {
    background: #ffffff;
    border-right: 1px solid rgba(0,0,0,0.08);
}

/* Make dataframe header nicer */
div[data-testid="stDataFrame"] {
    border-radius: 12px;
    overflow: hidden;
    border: 1px solid rgba(0,0,0,0.08);
}
</style>
""", unsafe_allow_html=True)

# -----------------------------
# Paths
# -----------------------------
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
log_path = os.path.join(base_dir, "data", "predictions_log.csv")

# -----------------------------
# Helpers
# -----------------------------
def load_df():
    if os.path.exists(log_path):
        try:
            return pd.read_csv(log_path)
        except Exception:
            return None
    return None

def severity_badge(sev: str) -> str:
    if sev == "Critical":
        return '<span class="badge badge-crit">🔴 Critical</span>'
    if sev == "High":
        return '<span class="badge badge-high">🟠 High</span>'
    if sev == "Medium":
        return '<span class="badge badge-med">🟡 Medium</span>'
    return '<span class="badge badge-low">🟢 Low</span>'

def safe_mean(series, default=0.0):
    try:
        return float(series.mean())
    except Exception:
        return float(default)

def gauge(avg_risk: float):
    # Light theme gauge
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=float(avg_risk),
        number={"font": {"size": 42, "color": "#111"}},
        title={"text": "Threat Activity Level (avg last 50 events)", "font": {"color": "#111"}},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": "#111"},
            "bar": {"color": "rgba(231,76,60,0.9)"},
            "steps": [
                {"range": [0, 40], "color": "rgba(46,204,113,0.18)"},
                {"range": [40, 70], "color": "rgba(241,196,15,0.18)"},
                {"range": [70, 100], "color": "rgba(231,76,60,0.18)"},
            ],
            "threshold": {
                "line": {"color": "rgba(0,0,0,0.55)", "width": 3},
                "thickness": 0.75,
                "value": float(avg_risk)
            }
        }
    ))
    fig.update_layout(
        height=260,
        margin=dict(l=10, r=10, t=60, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#111"),
    )
    return fig

# -----------------------------
# Header
# -----------------------------
st.markdown("## 🛡 SentinelEdge AI")
st.markdown("<div class='mini'>Real-time Edge-Based AI Threat Detection for Smart Campuses & SMEs</div>", unsafe_allow_html=True)

# -----------------------------
# Sidebar Controls
# -----------------------------
st.sidebar.markdown("### Controls")
auto_refresh = st.sidebar.toggle("Auto Refresh", value=True)
refresh_sec = st.sidebar.slider("Refresh interval (sec)", 1, 10, 2)
min_severity = st.sidebar.selectbox("Alert filter", ["Medium+", "High+", "Critical only"], index=1)
max_rows = st.sidebar.slider("Recent events rows", 10, 100, 25)

st.sidebar.markdown("---")
st.sidebar.markdown("### Alert Sound")
sound_on = st.sidebar.toggle("Play siren on Critical", value=True)

st.sidebar.markdown("---")
st.sidebar.markdown("### Demo Tips")
st.sidebar.write("1) Keep **uvicorn** running")
st.sidebar.write("2) Run **streamer** to generate logs")
st.sidebar.write("3) Show **Edge vs Cloud** tab")

placeholder = st.empty()

# -----------------------------
# Main loop
# -----------------------------
while True:
    df = load_df()

    with placeholder.container():
        now = datetime.now().strftime("%d %b %Y, %I:%M:%S %p")

        if df is None or df.empty:
            st.markdown(
                f"<div class='card'><span class='badge badge-med'>🟡 Waiting</span> "
                f"<span class='mini'>No predictions_log.csv found yet. Start the streamer.</span>"
                f"<div class='mini' style='margin-top:6px;'>Last checked: {now}</div></div>",
                unsafe_allow_html=True
            )
            st.stop()

        required_cols = {"predicted_attack", "risk_score", "severity"}
        if not required_cols.issubset(set(df.columns)):
            st.error("predictions_log.csv is missing required columns. Restart streamer with the latest code.")
            st.stop()

        total = len(df)
        crit = int((df["severity"] == "Critical").sum())
        high = int((df["severity"] == "High").sum())
        med = int((df["severity"] == "Medium").sum())
        low = int((df["severity"] == "Low").sum())

        avg_edge = safe_mean(df["edge_latency_ms"]) if "edge_latency_ms" in df.columns else safe_mean(df.get("latency_ms", pd.Series([0])))
        avg_cloud = safe_mean(df["cloud_latency_ms"]) if "cloud_latency_ms" in df.columns else None

        # -----------------------------
        # Blinking Critical Banner + Siren
        # -----------------------------
        if crit > 0:
            st.markdown("""
            <style>
              @keyframes pulseRed {
                0%   { box-shadow: 0 0 0px rgba(231,76,60,0.15); }
                50%  { box-shadow: 0 0 22px rgba(231,76,60,0.55); }
                100% { box-shadow: 0 0 0px rgba(231,76,60,0.15); }
              }
              .critical-banner {
                background: rgba(231,76,60,0.12);
                border: 1px solid rgba(231,76,60,0.45);
                border-radius: 16px;
                padding: 14px 16px;
                margin: 10px 0 12px 0;
                animation: pulseRed 1.2s infinite;
              }
              .critical-title {
                font-size: 16px;
                font-weight: 900;
                color: #7a0000 !important;
              }
              .critical-sub {
                font-size: 12px;
                opacity: 0.9;
                margin-top: 4px;
                color: #111 !important;
              }
            </style>
            """, unsafe_allow_html=True)

            crit_df = df[df["severity"] == "Critical"].tail(3)
            top_attacks = ", ".join(crit_df["predicted_attack"].astype(str).tolist()) if not crit_df.empty else "Multiple attack signals"

            st.markdown(f"""
            <div class="critical-banner">
              <div class="critical-title">🚨 CRITICAL ALERTS ACTIVE: {crit}</div>
              <div class="critical-sub">Top recent critical signals: <b>{top_attacks}</b> — Immediate response recommended.</div>
            </div>
            """, unsafe_allow_html=True)

            if sound_on:
                st.markdown("""
                <audio autoplay>
                  <source src="data:audio/wav;base64,UklGRiQAAABXQVZFZm10IBAAAAABAAEAgD4AAAB9AAACABAAZGF0YQAAAAA=" type="audio/wav">
                </audio>
                """, unsafe_allow_html=True)

        # Live status card
        st.markdown(
            f"<div class='card'>"
            f"<span class='badge badge-low'>🟢 LIVE</span> "
            f"<span class='mini'>Streaming + Inference Active</span>"
            f"<div class='mini' style='margin-top:6px;'>Last updated: {now}</div>"
            f"</div>",
            unsafe_allow_html=True
        )

        # KPI row
        k1, k2, k3, k4, k5 = st.columns(5)
        k1.metric("Total Events", f"{total}")
        k2.metric("Critical", f"{crit}")
        k3.metric("High", f"{high}")
        k4.metric("Medium", f"{med}")
        if avg_cloud is None:
            k5.metric("Avg EDGE Latency (ms)", f"{avg_edge:.2f}")
        else:
            k5.metric("Avg EDGE Latency (ms)", f"{avg_edge:.2f}", delta=f"Cloud ~{avg_cloud:.2f} ms")

        # Tabs
        tab1, tab2, tab3, tab4 = st.tabs(["📌 Overview", "🚨 Alerts", "⚡ Edge vs Cloud", "🔎 Explore"])

        # -----------------------------
        # Tab 1: Overview
        # -----------------------------
        with tab1:
            left, right = st.columns([2, 1])

            with right:
                avg_risk = float(df["risk_score"].tail(50).mean())

                # IMPORTANT: unique key to avoid duplicate element id on refresh
                st.plotly_chart(
                    gauge(avg_risk),
                    use_container_width=True,
                    key=f"gauge_{int(time.time())}"
                )

                st.markdown("<div class='card'><div class='mini'>Severity Split</div>", unsafe_allow_html=True)
                st.write(f"🔴 Critical: **{crit}**")
                st.write(f"🟠 High: **{high}**")
                st.write(f"🟡 Medium: **{med}**")
                st.write(f"🟢 Low: **{low}**")
                st.markdown("</div>", unsafe_allow_html=True)

            with left:
                st.markdown("### 📈 Risk Score Timeline")
                st.line_chart(df["risk_score"].tail(300))

                st.markdown("### 📊 Attack Type Distribution")
                st.bar_chart(df["predicted_attack"].value_counts())

                st.markdown("### 🧾 Recent Events")
                st.dataframe(df.tail(max_rows), use_container_width=True)

        # -----------------------------
        # Tab 2: Alerts
        # -----------------------------
        with tab2:
            st.markdown("### 🚨 Alerts Feed")

            if min_severity == "Critical only":
                filt = df[df["severity"] == "Critical"]
            elif min_severity == "High+":
                filt = df[df["severity"].isin(["High", "Critical"])]
            else:
                filt = df[df["severity"].isin(["Medium", "High", "Critical"])]

            filt = filt.tail(50).copy()
            if filt.empty:
                st.success("No alerts in the selected severity filter window.")
            else:
                filt["severity"] = filt["severity"].apply(severity_badge)

                show_cols = ["predicted_attack", "risk_score", "severity"]
                if "edge_latency_ms" in df.columns:
                    show_cols.append("edge_latency_ms")
                if "cloud_latency_ms" in df.columns:
                    show_cols.append("cloud_latency_ms")

                filt = filt.sort_values("risk_score", ascending=False)

                st.markdown("<div class='card'><div class='mini'>Top incidents (sorted by risk score)</div></div>", unsafe_allow_html=True)
                st.dataframe(filt[show_cols], use_container_width=True)

        # -----------------------------
        # Tab 3: Edge vs Cloud
        # -----------------------------
        with tab3:
            st.markdown("### ⚡ Edge vs Cloud Latency Benchmark")

            if "edge_latency_ms" in df.columns and "cloud_latency_ms" in df.columns:
                st.markdown("<div class='card'><div class='mini'>Edge keeps telemetry local (privacy) and reduces response time.</div></div>", unsafe_allow_html=True)
                latency_df = df[["edge_latency_ms", "cloud_latency_ms"]].tail(300)
                st.line_chart(latency_df)

                c1, c2, c3 = st.columns(3)
                c1.metric("EDGE p50 (ms)", f"{latency_df['edge_latency_ms'].median():.2f}")
                c2.metric("CLOUD p50 (ms)", f"{latency_df['cloud_latency_ms'].median():.2f}")
                c3.metric("Avg Gain (ms)", f"{(latency_df['cloud_latency_ms'].mean() - latency_df['edge_latency_ms'].mean()):.2f}")
            else:
                st.warning("Edge vs Cloud columns not found. Restart streamer using the Edge+Cloud version.")

        # -----------------------------
        # Tab 4: Explore
        # -----------------------------
        with tab4:
            st.markdown("### 🔎 Explore Data")
            st.write("Use this to quickly inspect model outputs and debug.")
            st.dataframe(df.tail(200), use_container_width=True)

    if not auto_refresh:
        break
    time.sleep(refresh_sec)