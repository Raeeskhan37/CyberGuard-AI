import os
from crewai import Agent, Task, Crew, Process
from crewai.llm import LLM

def run_crewai_analysis(scan_results: list, audit_results: dict, api_key: str, model_name: str) -> dict:
    """
    Executes the 3-agent CrewAI sequential workflow using Groq:
    1. Security Triage Agent
    2. Cybersecurity Analyst Agent
    3. Remediation Advisor Agent
…    result_text = str(result)

    # Parse or structure output into dictionary format for the app
    return {
        "executive_summary": result_text[:800] if len(result_text) > 800 else result_text,
        "triage_notes": "Completed by Security Triage Agent. Findings organized by severity.",
        "analyst_notes": "Completed by Cybersecurity Analyst. Impact and evidence reviewed.",
        "remediation_advice": result_text
    }
