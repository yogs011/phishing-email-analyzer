"""
SOC Tier-1 Email Security & Phishing Investigation Platform
Author: Yogesh Birla (github.com/yogs011)
Framework: Streamlit Web UI for Interactive Security Operations
"""

import streamlit as st
import tempfile
import os
import json
from analyzer import EmailThreatAnalyzer

# Page configuration
st.set_page_config(
    page_title="SOC Email Threat Analyzer | Yogesh Birla",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for SOC Cyber Dashboard Theme
st.markdown("""
<style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 700;
        color: #1E3A8A;
        margin-bottom: 0px;
    }
    .sub-header {
        font-size: 1.05rem;
        color: #4B5563;
        margin-bottom: 25px;
    }
    .metric-card {
        background-color: #F3F4F6;
        padding: 15px;
        border-radius: 8px;
        border-left: 5px solid #2563EB;
    }
    .author-badge {
        background-color: #E0E7FF;
        color: #3730A3;
        padding: 4px 10px;
        border-radius: 12px;
        font-weight: 600;
        font-size: 0.85rem;
    }
</style>
""", unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=70)
    st.title("SOC Analyst Desk")
    st.markdown("**Author:** Yogesh Birla  \n**Specialization:** Security Operations (SOC)")
    st.divider()

    st.subheader("⚙️ Settings & Threat Intel")
    vt_key = st.text_input("VirusTotal API Key (Optional)", type="password", help="Enter VT API v3 key to enrich hash reputation.")
    
    st.divider()
    st.markdown("""
    ### 📌 Investigation Checklist:
    - [x] Check Sender domain alignment
    - [x] Validate SPF, DKIM, and DMARC
    - [x] Defang embedded URLs
    - [x] Hash attachments (MD5 / SHA256)
    - [x] Correlate with MITRE ATT&CK T1566
    """)

# Main Header
col_title, col_badge = st.columns([4, 1])
with col_title:
    st.markdown('<p class="main-header">🛡️ Automated Email Threat & Phishing Investigation Tool</p>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">Tier-1 Incident Response utility for rapid header inspection, spoofing detection, and IoC extraction.</p>', unsafe_allow_html=True)
with col_badge:
    st.markdown('<br><span class="author-badge">Lead Dev: Yogesh Birla</span>', unsafe_allow_html=True)

# File uploader and sample selection
sample_option = st.radio("Choose Input Mode:", ["Upload your own .eml file", "Load Sample Malicious Phishing Artifact", "Load Sample Clean Newsletter"], horizontal=True)

eml_to_analyze = None
uploaded_file = None

if sample_option == "Upload your own .eml file":
    uploaded_file = st.file_uploader("Drop a suspicious .eml artifact here:", type=["eml"])
    if uploaded_file is not None:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp:
            tmp.write(uploaded_file.getvalue())
            eml_to_analyze = tmp.name
elif sample_option == "Load Sample Malicious Phishing Artifact":
    sample_path = os.path.join(os.path.dirname(__file__), "samples", "sample_malicious_phish.eml")
    if os.path.exists(sample_path):
        eml_to_analyze = sample_path
    else:
        st.warning("Sample file not found locally. Please upload an .eml file.")
elif sample_option == "Load Sample Clean Newsletter":
    sample_path = os.path.join(os.path.dirname(__file__), "samples", "sample_benign_newsletter.eml")
    if os.path.exists(sample_path):
        eml_to_analyze = sample_path
    else:
        st.warning("Sample file not found locally. Please upload an .eml file.")

# Run Analysis
if eml_to_analyze:
    with st.spinner("Parsing RFC 5322 headers and extracting threat indicators..."):
        analyzer = EmailThreatAnalyzer(eml_to_analyze, vt_key)
        results = analyzer.run_all()

    st.success("Triage Analysis Completed!")

    # Summary Row: Verdict & Score
    v_col1, v_col2, v_col3 = st.columns([1.5, 1.5, 3])
    with v_col1:
        st.metric("Risk Score", f"{results['risk_score']} / 100")
    with v_col2:
        verdict = results['verdict']
        if "MALICIOUS" in verdict:
            st.error(f"🚨 {verdict}")
        elif "SUSPICIOUS" in verdict:
            st.warning(f"⚠️ {verdict}")
        else:
            st.success(f"✅ {verdict}")
    with v_col3:
        if results['risk_factors']:
            st.markdown("**Identified Risk Signals:**")
            for rf in results['risk_factors']:
                st.markdown(f"- ⚠️ *{rf}*")
        else:
            st.markdown("✅ *No critical authentication failures or suspicious indicators found.*")

    st.divider()

    # Tabs for detailed forensic inspection
    tab_headers, tab_auth, tab_urls, tab_attachments, tab_export = st.tabs([
        "📩 Headers & Routing",
        "🔐 SPF / DKIM / DMARC",
        "🔗 Defanged URLs & IoCs",
        "📎 File Attachments",
        "📋 Export SOC Report"
    ])

    with tab_headers:
        st.subheader("Critical Email Headers")
        h = results["headers"]
        h_col1, h_col2 = st.columns(2)
        with h_col1:
            st.write(f"**From:** `{h.get('From')}`")
            st.write(f"**To:** `{h.get('To')}`")
            st.write(f"**Subject:** `{h.get('Subject')}`")
            st.write(f"**Date:** `{h.get('Date')}`")
        with h_col2:
            st.write(f"**Return-Path:** `{h.get('Return-Path')}`")
            st.write(f"**Reply-To:** `{h.get('Reply-To')}`")
            st.write(f"**Message-ID:** `{h.get('Message-ID')}`")

        with st.expander("View Received Hop Headers (Server Routing Trajectory)"):
            received_headers = h.get("Received", [])
            if received_headers:
                for idx, hop in enumerate(received_headers):
                    st.code(f"Hop #{idx + 1}:\n{hop}", language="text")
            else:
                st.info("No Received hops found.")

    with tab_auth:
        st.subheader("Sender Domain Authentication Verification")
        auth = results["auth"]
        a1, a2, a3 = st.columns(3)
        with a1:
            st.metric("SPF Check", auth["SPF"])
        with a2:
            st.metric("DKIM Signature", auth["DKIM"])
        with a3:
            st.metric("DMARC Alignment", auth["DMARC"])

        st.caption(f"**Raw Authentication-Results:** {auth['Raw']}")

    with tab_urls:
        st.subheader("Embedded Hyperlinks (Defanged)")
        st.info("💡 Hyperlinks are defanged automatically (`hxxps[://]`) so analysts can safely document and inspect without accidental execution.")
        urls = results["urls"]
        if urls:
            for idx, item in enumerate(urls):
                badge = "⚠️ Direct IP" if item["is_ip_based"] else "🌐 Domain"
                st.markdown(f"**#{idx+1} [{badge}]**")
                st.code(item["defanged"], language="text")
        else:
            st.write("No external hyperlinks identified in email content.")

    with tab_attachments:
        st.subheader("Attachment Fingerprints & Hashes")
        attachments = results["attachments"]
        if attachments:
            for att in attachments:
                box_color = "red" if att["is_dangerous"] else "green"
                with st.container():
                    st.markdown(f"#### 📄 `{att['filename']}` ({att['size_kb']} KB)")
                    st.write(f"**SHA-256:** `{att['sha256']}`")
                    st.write(f"**MD5:** `{att['md5']}`")
                    if att["is_dangerous"]:
                        st.error("🚨 High-risk executable or script extension. Escalate to Malware Analysis / Sandbox detonation.")
                    else:
                        st.success("Clean standard extension.")
        else:
            st.write("No attachments detected.")

    with tab_export:
        st.subheader("Download Incident Report")
        report_data = {
            "analyst": "Yogesh Birla",
            "verdict": results["verdict"],
            "risk_score": results["risk_score"],
            "headers": results["headers"],
            "auth": results["auth"],
            "urls": results["urls"],
            "attachments": results["attachments"],
            "risk_factors": results["risk_factors"]
        }
        json_report = json.dumps(report_data, indent=2)
        st.download_button(
            label="📥 Download JSON Triage Report",
            data=json_report,
            file_name="soc_triage_report.json",
            mime="application/json"
        )
else:
    st.info("👈 Upload an .eml artifact or choose one of the sample scenarios above to begin inspection.")

st.divider()
st.caption("Developed by **Yogesh Birla** | Built for Security Operations Center (SOC) Tier-1 Workflows.")
