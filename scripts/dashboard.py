import re
from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st

st.set_page_config(
    page_title="SOC-in-a-Box Dashboard",
    page_icon="🔐",
    layout="wide"
)

# ---------- CSS ----------
st.markdown("""
<style>
[data-testid="stAppViewContainer"] {
    background: linear-gradient(135deg, #07111f 0%, #0b1628 100%);
}
[data-testid="stSidebar"] {
    background-color: #08111f;
}
.metric-card {
    background: #101c2f;
    border: 1px solid #263b59;
    border-radius: 16px;
    padding: 22px;
    box-shadow: 0 0 18px rgba(0,0,0,0.25);
}
.metric-label {
    color: #a9b7c9;
    font-size: 14px;
}
.metric-value {
    color: white;
    font-size: 42px;
    font-weight: 700;
}
.card-title {
    color: white;
    font-size: 20px;
    font-weight: 700;
}
.status-good {
    background: #0f3b25;
    border: 1px solid #1f8f4d;
    color: #64f29a;
    padding: 16px;
    border-radius: 14px;
}
</style>
""", unsafe_allow_html=True)

# ---------- Load Reports ----------
try:
    with open("reports/final_report.md", "r", encoding="utf-8") as f:
        final_report = f.read()
except FileNotFoundError:
    final_report = ""

try:
    with open("reports/zap_report.html", "r", encoding="utf-8") as f:
        zap_report = f.read()
except FileNotFoundError:
    zap_report = ""

# ---------- Parse Data ----------
high = final_report.count("[HIGH]")
medium = final_report.count("[MEDIUM]")
low = final_report.count("[LOW]")

zap_warnings = len(re.findall(r"WARN-NEW", zap_report))
zap_failures = len(re.findall(r"FAIL-NEW", zap_report))
zap_pass = len(re.findall(r"PASS:", zap_report))

findings = re.findall(
    r"## \[(HIGH|MEDIUM|LOW)\] Port (\d+)\/(\w+) \((.*?)\)\n\*\*Risk:\*\* (.*?)\n\*\*Fix:\*\* (.*?)\n",
    final_report
)

findings_df = pd.DataFrame(
    findings,
    columns=["Severity", "Port", "Protocol", "Service", "Risk", "Fix"]
)

zap_warning_names = re.findall(r"WARN-NEW:\s(.*?)\s\[\d+\]", zap_report)

# ---------- Sidebar ----------
st.sidebar.title("🔐 SOC-in-a-Box")
st.sidebar.caption("Security Dashboard")

st.sidebar.markdown("---")
st.sidebar.write("### Navigation")
st.sidebar.write("📊 Overview")
st.sidebar.write("🌐 Network Findings")
st.sidebar.write("🕷️ Web Vulnerabilities")
st.sidebar.write("📄 Reports")

st.sidebar.markdown("---")
st.sidebar.write("### Scan Information")
st.sidebar.write(f"**Last Scan:** {datetime.now().strftime('%Y-%m-%d %H:%M')}")
st.sidebar.write("**Tools:** Nmap + OWASP ZAP")
st.sidebar.write("**Status:** ✅ Completed")

# ---------- Header ----------
st.title("🔐 SOC-in-a-Box Security Dashboard")
st.caption("Unified security overview of Nmap network findings and OWASP ZAP web scan results")

# ---------- Metrics ----------
st.subheader("Executive Summary")

c1, c2, c3, c4 = st.columns(4)

with c1:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">High Risk</div>
        <div class="metric-value">{high}</div>
    </div>
    """, unsafe_allow_html=True)

with c2:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">Medium Risk</div>
        <div class="metric-value">{medium}</div>
    </div>
    """, unsafe_allow_html=True)

with c3:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">Low Risk</div>
        <div class="metric-value">{low}</div>
    </div>
    """, unsafe_allow_html=True)

with c4:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">ZAP Warnings</div>
        <div class="metric-value">{zap_warnings}</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("---")

# ---------- Charts ----------
left, right = st.columns(2)

risk_df = pd.DataFrame({
    "Severity": ["High", "Medium", "Low"],
    "Count": [high, medium, low]
})

with left:
    st.markdown('<div class="card-title">Risk Distribution</div>', unsafe_allow_html=True)
    fig = px.pie(
        risk_df,
        names="Severity",
        values="Count",
        hole=0.55
    )
    fig.update_layout(
        height=350,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="white",
        margin=dict(t=20, b=20, l=20, r=20)
    )
    st.plotly_chart(fig, use_container_width=True)

zap_df = pd.DataFrame({
    "Result": ["Pass", "Warnings", "Failures"],
    "Count": [zap_pass, zap_warnings, zap_failures]
})

with right:
    st.markdown('<div class="card-title">ZAP Scan Summary</div>', unsafe_allow_html=True)
    fig2 = px.bar(
        zap_df,
        x="Result",
        y="Count",
        text="Count"
    )
    fig2.update_layout(
        height=350,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="white",
        margin=dict(t=20, b=20, l=20, r=20)
    )
    st.plotly_chart(fig2, use_container_width=True)

# ---------- Tables ----------
st.markdown("---")

left2, right2 = st.columns(2)

with left2:
    st.subheader("Top Network Findings")
    if not findings_df.empty:
        st.dataframe(
            findings_df[["Port", "Protocol", "Service", "Severity", "Risk"]],
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No Nmap findings available.")

with right2:
    st.subheader("Recent ZAP Alerts")
    if zap_warning_names:
        zap_alerts = pd.DataFrame({"Alert": zap_warning_names})
        st.dataframe(zap_alerts, use_container_width=True, hide_index=True)
    else:
        st.success("No ZAP alerts found.")

# ---------- Status ----------
st.markdown("---")

if high == 0 and zap_failures == 0:
    st.markdown("""
    <div class="status-good">
        <b>System Status:</b> No critical issues detected. Continue monitoring and improving security posture.
    </div>
    """, unsafe_allow_html=True)
else:
    st.warning("High-risk findings detected. Review the network findings table.")

# ---------- Details ----------
with st.expander("View Full Combined Report"):
    if final_report:
        st.markdown(final_report)
    else:
        st.warning("final_report.md not found.")

with st.expander("ZAP Report Location"):
    st.code("reports/zap_report.html")
    