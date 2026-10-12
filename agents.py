import os
from crewai import Agent, Task, Crew, Process
from crewai.llm import LLM

def run_crewai_analysis(scan_results: list, audit_results: dict, api_key: str, model_name: str) -> dict:
    """
    Executes the 3-agent CrewAI sequential workflow using Groq:
    1. Security Triage Agent
    2. Cybersecurity Analyst Agent
    3. Remediation Advisor Agent
    """
    if not api_key:
        raise ValueError("Groq API Key is required for agent analysis.")

    # Configure Groq LLM via LiteLLM provider integration format
    os.environ["GROQ_API_KEY"] = api_key
    
    # Correct provider prefix for CrewAI/LiteLLM Groq integration
    groq_llm = LLM(
        model=f"groq/{model_name}",
        temperature=0.2,
        api_key=api_key
    )

    # Define Agent 1: Security Triage
    triage_agent = Agent(
        role="Security Triage Specialist",
        goal="Organize and prioritize scanner findings, removing duplicates and highlighting critical evidence.",
        backstory="Expert in vulnerability management and static analysis filtering, ensuring accurate severity triage.",
        verbose=False,
        llm=groq_llm,
        allow_delegation=False
    )

    # Define Agent 2: Cybersecurity Analyst
    analyst_agent = Agent(
        role="Cybersecurity Threat Analyst",
        goal="Explain security findings in simple language, evaluating potential business and technical impacts.",
        backstory="Senior application security analyst skilled at communicating vulnerability risks and false positive evaluations.",
        verbose=False,
        llm=groq_llm,
        allow_delegation=False
    )

    # Define Agent 3: Remediation Advisor
    remediation_agent = Agent(
        role="Remediation Advisor",
        goal="Recommend prioritized, actionable code fixes and verification steps with a concise executive summary.",
        backstory="Principal software architect focused on secure coding standards and patch verification.",
        verbose=False,
        llm=groq_llm,
        allow_delegation=False
    )

    context_payload = f"""
    Static Code Scan Results (Bandit):
    {scan_results}

    Dependency Audit Results (pip-audit):
    {audit_results}
    """

    # Tasks definition
    task_triage = Task(
        description=f"Analyze the raw findings and organize them by severity and risk priority.\n\nData:\n{context_payload}",
        expected_output="A structured triage summary grouping findings by severity and confidence.",
        agent=triage_agent
    )

    task_analysis = Task(
        description="Review the triaged findings. Explain the potential security impact and distinguish confirmed scanner output from AI risk hypotheses.",
        expected_output="An accessible explanation of risks, impacts, and potential false positives.",
        agent=analyst_agent
    )

    task_remediation = Task(
        description="Provide prioritized remediation advice, secure code examples, verification steps, and a clean executive summary.",
        expected_output="JSON or structured markdown containing executive summary, triage notes, analyst notes, and remediation advice.",
        agent=remediation_agent
    )

    # Assemble sequential Crew
    cyber_crew = Crew(
        agents=[triage_agent, analyst_agent, remediation_agent],
        tasks=[task_triage, task_analysis, task_remediation],
        process=Process.sequential,
        verbose=False
    )

    result = cyber_crew.kickoff()
    result_text = str(result)

    # Parse or structure output into dictionary format for the app
    return {
        "executive_summary": result_text[:800] if len(result_text) > 800 else result_text,
        "triage_notes": "Completed by Security Triage Agent. Findings organized by severity.",
        "analyst_notes": "Completed by Cybersecurity Analyst. Impact and evidence reviewed.",
        "remediation_advice": result_text
    }
