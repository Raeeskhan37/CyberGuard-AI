import os
import sys
import json
import tempfile
import zipfile
import shutil
from datetime import datetime, timezone
import streamlit as st
from dotenv import load_dotenv

# Load local environment variables if available
load_dotenv()

# Import internal modules
from scanner import scan_python_code, audit_requirements_file
from agents import run_crewai_analysis
from report import generate_json_report, generate_pdf_report

# Configure Streamlit page layout and metadata
st.set_page_config(
    page_title="CyberGuard AI — Cybersecurity Assistant",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS styling for a polished, professional look
st.markdown("""
<style>
    .main-header {
        font-size: 2.2rem;
        color: #0f172a;
        font-weight: 800;
        margin-bottom: 0px;
    }
    .sub-header {
        font-size: 1.1rem;
        color: #475569;
        margin-bottom: 20px;
    }
    .card {
        padding: 20px;
        border-radius: 10px;
        background-color: #f8fafc;
        border: 1px solid #e2e8f0;
        margin-bottom: 15px;
    }
    .metric-card {
        background-color: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 15px;
        text-align: center;
    }
    .badge-high { background-color: #fee2e2; color: #991b1b; padding: 3px 8px; border-radius: 4px; font-weight: bold; }
    .badge-medium { background-color: #fef3c7; color: #92400e; padding: 3px 8px; border-radius: 4px; font-weight: bold; }
    .badge-low { background-color: #e0f2fe; color: #0369a1; padding: 3px 8px; border-radius: 4px; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

if "scan_results" not in st.session_state:
    st.session_state["scan_results"] = None
if "audit_results" not in st.session_state:
    st.session_state["audit_results"] = None
if "ai_analysis" not in st.session_state:
    st.session_state["ai_analysis"] = None
if "scan_timestamp" not in st.session_state:
    st.session_state["scan_timestamp"] = None
if "active_tab" not in st.session_state:
    st.session_state["active_tab"] = "scanner"

def main():
    # Sidebar Configuration & Settings
    st.sidebar.image("https://placehold.co/120x120/0f172a/ffffff?text=CG", width=80)
    st.sidebar.title("CyberGuard AI")
    st.sidebar.markdown("**AI-Powered Cybersecurity Assistant**")
    st.sidebar.markdown("---")
    
    # API Key Configuration (Securely loaded from Streamlit Secrets or environment)
    env_groq_key = st.secrets.get("GROQ_API_KEY", os.getenv("GROQ_API_KEY", ""))
    env_groq_model = st.secrets.get("GROQ_MODEL", os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"))
    
    # Use the secret directly without exposing an input box or eye icon to users
    groq_api_key = env_groq_key
    
    if groq_api_key:
        st.sidebar.success("🔒 AI Engine Active (Key Secured)")
    else:
        st.sidebar.warning("⚠️ Running in Static Mode (No AI Key configured)")
        
    groq_model = st.sidebar.selectbox(
        "Groq Model",
        ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "openai/gpt-oss-120b"],
        index=0,
        help="Select verified Groq model for agent orchestration."
    )
    
    st.sidebar.markdown("---")
    st.sidebar.markdown("### ℹ️ About")
    st.sidebar.markdown(
        "CyberGuard AI combines deterministic static security code analysis (**Bandit**), "
        "dependency auditing (**pip-audit**), and a 3-agent **CrewAI** workflow powered by **Groq**."
    )
    st.sidebar.markdown("**Developed by Raees Khan**")
    
    # Main Header & Overview
    st.markdown('<p class="main-header">🛡️ CyberGuard AI</p>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">Intelligent Python Code Security & Dependency Vulnerability Analyzer</p>', unsafe_allow_html=True)
    
    # Privacy & Authorized Use Warning
    st.markdown("""
    > **⚠️ Security & Privacy Notice:** Uploaded code and requirements files are processed securely in temporary local storage 
    > and cleaned up immediately after analysis. If AI analysis is enabled, sanitized summaries and findings are submitted 
    > to the configured Groq model. Do not upload classified source code or production secrets.
    """)

    # Tabs for Workflow Navigation
    tab1, tab2, tab3, tab4 = st.tabs(["📁 1. Scan & Audit", "🔍 2. Findings & Triage", "🤖 3. AI Analysis & Remediation", "📊 4. Export Reports"])
    
    with tab1:
        st.markdown("### Upload Target Files for Security Inspection")
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### Python Source Inspection")
            uploaded_py = st.file_uploader("Upload Python file (.py)", type=["py"])
            uploaded_zip = st.file_uploader("Or upload ZIP archive (.zip)", type=["zip"])
            
        with col2:
            st.markdown("#### Dependency Vulnerability Audit")
            uploaded_reqs = st.file_uploader("Upload requirements.txt", type=["txt"])
            
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("🚀 Run Comprehensive Security Scan", type="primary", use_container_width=True):
            if not uploaded_py and not uploaded_zip and not uploaded_reqs:
                st.warning("Please upload at least one Python file, ZIP archive, or requirements.txt file to begin scanning.")
            else:
                with st.spinner("Running deterministic security scanners and audits..."):
                    temp_dir = tempfile.mkdtemp()
                    try:
                        scan_findings = []
                        audit_findings = []
                        
                        # Handle Python File Upload
                        if uploaded_py:
                            py_path = os.path.join(temp_dir, uploaded_py.name)
                            with open(py_path, "wb") as f:
                                f.write(uploaded_py.getbuffer())
                            scan_findings.extend(scan_python_code(py_path))
                            
                        # Handle ZIP Archive Upload
                        if uploaded_zip:
                            zip_path = os.path.join(temp_dir, uploaded_zip.name)
                            with open(zip_path, "wb") as f:
                                f.write(uploaded_zip.getbuffer())
                            
                            extract_dir = os.path.join(temp_dir, "extracted_zip")
                            os.makedirs(extract_dir, exist_ok=True)
                            
                            try:
                                with zipfile.ZipFile(zip_path, 'r') as zf:
                                    # Security checks: limit entry count and total size
                                    if len(zf.infolist()) > 200:
                                        raise ValueError("ZIP archive contains too many files (limit: 200).")
                                    
                                    total_size = sum(info.file_size for info in zf.infolist())
                                    if total_size > 50 * 1024 * 1024:
                                        raise ValueError("Decompressed ZIP size exceeds 50MB limit.")
                                        
                                    for info in zf.infolist():
                                        # Prevent path traversal
                                        filename = info.filename
                                        if filename.startswith('/') or '..' in filename:
                                            continue
                                        zf.extract(info, extract_dir)
                                        
                                # Scan all extracted .py files
                                for root, dirs, files in os.walk(extract_dir):
                                    for file in files:
                                        if file.endswith('.py'):
                                            scan_findings.extend(scan_python_code(os.path.join(root, file)))
                            except Exception as e:
                                st.error(f"Error processing ZIP archive: {e}")
                                
                        # Handle Requirements Audit
                        if uploaded_reqs:
                            req_path = os.path.join(temp_dir, "requirements.txt")
                            with open(req_path, "wb") as f:
                                f.write(uploaded_reqs.getbuffer())
                            audit_findings = audit_requirements_file(req_path)
                            
                        st.session_state["scan_results"] = scan_findings
                        st.session_state["audit_results"] = audit_findings
                        st.session_state["scan_timestamp"] = datetime.now(timezone.utc).isoformat()
                        st.session_state["ai_analysis"] = None # Reset previous AI analysis on new scan
                        
                        st.success("Security scan completed successfully! Switch to Tab 2 & 3 to view results.")
                    
                    finally:
                        shutil.rmtree(temp_dir, ignore_errors=True)

    with tab2:
        st.markdown("### Scanner Findings & Risk Assessment")
        scan_results = st.session_state.get("scan_results")
        audit_results = st.session_state.get("audit_results")
        
        if scan_results is None and audit_results is None:
            st.info("No scan results available yet. Please upload files and run a scan from Tab 1.")
        else:
            # Metrics Overview
            total_bandit = len(scan_results) if scan_results else 0
            high_count = sum(1 for f in scan_results if f.get("severity") == "HIGH") if scan_results else 0
            med_count = sum(1 for f in scan_results if f.get("severity") == "MEDIUM") if scan_results else 0
            low_count = sum(1 for f in scan_results if f.get("severity") == "LOW") if scan_results else 0
            vuln_deps = len(audit_results.get("vulnerabilities", [])) if audit_results else 0
            
            m1, m2, m3, m4, m5 = st.columns(5)
            m1.metric("Total Code Findings", total_bandit)
            m2.metric("High Severity", high_count)
            m3.metric("Medium Severity", med_count)
            m4.metric("Low Severity", low_count)
            m5.metric("Vulnerable Dependencies", vuln_deps)
            
            st.markdown("---")
            st.markdown("#### 🔍 Static Code Analysis (Bandit)")
            if scan_results:
                for idx, finding in enumerate(scan_results):
                    sev = finding.get("severity", "LOW")
                    badge_class = f"badge-{sev.lower()}" if sev in ["HIGH", "MEDIUM", "LOW"] else "badge-low"
                    with st.expander(f"[{sev}] {finding.get('test_name', 'Finding')} - {finding.get('filename', 'file.py')}:L{finding.get('line_number', 0)}"):
                        st.markdown(f"**Severity:** <span class='{badge_class}'>{sev}</span> | **Confidence:** {finding.get('confidence', 'N/A')}", unsafe_allow_html=True)
                        st.markdown(f"**Description:** {finding.get('issue_text', 'No description available.')}")
                        st.code(finding.get('code_snippet', '# No snippet available'), language="python")
            else:
                st.success("No code vulnerabilities detected by Bandit.")
                
            st.markdown("---")
            st.markdown("#### 📦 Dependency Vulnerability Audit (pip-audit)")
            if audit_results and audit_results.get("vulnerabilities"):
                for vuln in audit_results["vulnerabilities"]:
                    st.warning(f"**Package:** {vuln.get('name')} ({vuln.get('version')}) — **Vuln ID:** {vuln.get('id')} — **Fixed in:** {vuln.get('fixed_version', 'Unknown')}")
            elif audit_results and audit_results.get("status") == "success":
                st.success("No known dependency vulnerabilities detected in requirements.txt.")
            else:
                st.info("No requirements.txt audit performed in this session.")

    with tab3:
        st.markdown("### AI Agent Orchestration (CrewAI + Groq)")
        scan_results = st.session_state.get("scan_results")
        audit_results = st.session_state.get("audit_results")
        
        if not scan_results and not audit_results:
            st.info("Please run a security scan in Tab 1 before running AI agent analysis.")
        elif not groq_api_key:
            st.warning("⚠️ Groq API key is missing. Please enter your Groq API key in the sidebar to enable AI agent analysis. Scanners and reports remain fully operational without AI.")
            if st.button("Run Offline Non-AI Risk Summary"):
                st.session_state["ai_analysis"] = {
                    "executive_summary": "Offline Assessment: Scanners completed successfully without AI agent augmentation.",
                    "triage_notes": "Findings grouped and prioritized via deterministic rules.",
                    "analyst_notes": "Standard static analysis findings recorded.",
                    "remediation_advice": "Review high and medium severity items manually and apply secure coding practices."
                }
                st.success("Offline risk assessment generated successfully!")
        else:
            if st.button("🤖 Run 3-Agent CrewAI Analysis", type="primary"):
                with st.spinner("Orchestrating Security Triage, Cybersecurity Analyst, and Remediation Advisor agents..."):
                    try:
                        analysis_output = run_crewai_analysis(
                            scan_results=scan_results,
                            audit_results=audit_results,
                            api_key=groq_api_key,
                            model_name=groq_model
                        )
                        st.session_state["ai_analysis"] = analysis_output
                        st.success("CrewAI analysis completed successfully!")
                    except Exception as e:
                        st.error(f"AI Agent execution error: {e}")
                        st.info("Falling back to structured fallback summary.")
                        st.session_state["ai_analysis"] = {
                            "executive_summary": f"Analysis encountered provider error: {str(e)}. Review raw scanner results.",
                            "triage_notes": "Triage fallback active.",
                            "analyst_notes": "Analyst fallback active.",
                            "remediation_advice": "Apply standard security patches."
                        }
            
            ai_data = st.session_state.get("ai_analysis")
            if ai_data:
                st.markdown("#### 📋 Executive Summary")
                st.info(ai_data.get("executive_summary", "No summary available."))
                
                col_a, col_b = st.columns(2)
                with col_a:
                    st.markdown("#### 🔬 Triage & Analyst Breakdown")
                    st.write(ai_data.get("triage_notes", "No triage notes."))
                    st.write(ai_data.get("analyst_notes", "No analyst notes."))
                with col_b:
                    st.markdown("#### 🛠️ Remediation Guidance")
                    st.write(ai_data.get("remediation_advice", "No remediation advice."))

    with tab4:
        st.markdown("### Export Security Reports")
        scan_results = st.session_state.get("scan_results")
        audit_results = st.session_state.get("audit_results")
        ai_analysis = st.session_state.get("ai_analysis")
        
        if not scan_results and not audit_results:
            st.info("No scan data available to export. Run a scan first.")
        else:
            col_x, col_y = st.columns(2)
            
            with col_x:
                st.markdown("#### 📄 JSON Report Export")
                json_data = generate_json_report(scan_results, audit_results, ai_analysis)
                st.download_button(
                    label="Download Full JSON Report",
                    data=json_data,
                    file_name=f"cyberguard_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json",
                    use_container_width=True
                )
                
            with col_y:
                st.markdown("#### 📑 PDF Report Export (ReportLab)")
                if st.button("Generate PDF Report", use_container_width=True):
                    try:
                        pdf_buffer = generate_pdf_report(scan_results, audit_results, ai_analysis)
                        st.download_button(
                            label="Download PDF Report",
                            data=pdf_buffer,
                            file_name=f"cyberguard_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.pdf",
                            mime="application/pdf",
                            use_container_width=True
                        )
                        st.success("PDF report generated successfully!")
                    except Exception as e:
                        st.error(f"PDF generation failed: {e}")

if __name__ == "__main__":
    main()
