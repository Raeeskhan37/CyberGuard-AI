🛡️ CyberGuard AI — AI-Powered Cybersecurity Assistant

Developed by Raees Khan

CyberGuard AI is a complete, production-ready cybersecurity analysis web application built with Streamlit, CrewAI, Groq, Bandit, pip-audit, and ReportLab. It combines deterministic static code analysis and dependency auditing with a 3-agent AI workflow.

📅 Compatibility & Version Verification

Compatibility Date: 12 October 2026

Tested Python Version: Python 3.10 / 3.11 / 3.12

Streamlit Version: 1.42.0

CrewAI Version: 0.102.0

Selected Groq Model: llama-3.3-70b-versatile

📁 Repository Structure

cyberguard-ai/
├── app.py              # Streamlit dashboard & user interface
├── scanner.py          # Bandit static analysis & pip-audit integration
├── agents.py           # CrewAI 3-agent orchestration (Groq integration)
├── report.py           # JSON & ReportLab PDF report generation
├── requirements.txt    # Pinned, tested dependencies
├── .env.example        # Environment variable template
├── .gitignore          # Git exclusion rules
└── README.md           # Documentation


🚀 Local Setup & Installation

Clone or Download the Repository:

git clone https://github.com/your-username/cyberguard-ai.git
cd cyberguard-ai


Create and Activate a Virtual Environment:

python -m venv venv
# On macOS/Linux:
source venv/bin/activate
# On Windows:
venv\Scripts\activate


Install Dependencies:

pip install -r requirements.txt


Configure Environment Variables:
Copy .env.example to .env and add your Groq API key:

cp .env.example .env


(Note: Scanners and report generation function fully without a Groq API key).

Run the Streamlit Application:

streamlit run app.py


☁️ Streamlit Community Cloud Deployment

Push your repository to GitHub (ensure .env is ignored).

Visit Streamlit Community Cloud.

Click New App and select your GitHub repository, branch (main), and main file path (app.py).

In Advanced Settings, add your deployment secret:

GROQ_API_KEY = "your_groq_api_key_here"
GROQ_MODEL = "llama-3.3-70b-versatile"


Click Deploy!

🔒 Security & Privacy Notice

Uploaded files are processed in secure temporary directories and cleaned up immediately.

Basic security scanning and report generation work completely offline without sending any code to external APIs.

When AI analysis is enabled, sanitized summaries are sent to Groq for triage and remediation advice. Do not upload classified code.
