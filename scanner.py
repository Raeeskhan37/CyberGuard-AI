import subprocess
import json
import os
import sys
import tempfile

def scan_python_code(file_path: str) -> list:
    """
    Runs Bandit static code analysis securely on a Python file path.
    Returns a list of structured vulnerability dictionaries.
    """
    if not os.path.exists(file_path):
        return []

    try:
        # Run bandit via subprocess securely without shell=True
        cmd = [sys.executable, "-m", "bandit", "-f", "json", file_path]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        # Bandit exits with status 1 if issues are found, which is normal.
        if result.stdout:
            data = json.loads(result.stdout)
            raw_results = data.get("results", [])
            formatted_results = []
            for item in raw_results:
                formatted_results.append({
                    "test_id": item.get("test_id", "B000"),
                    "test_name": item.get("test_name", "Unknown Security Check"),
                    "severity": item.get("issue_severity", "LOW"),
                    "confidence": item.get("issue_confidence", "MEDIUM"),
                    "filename": os.path.basename(item.get("filename", file_path)),
                    "line_number": item.get("line_number", 0),
                    "issue_text": item.get("issue_text", "No description provided."),
                    "code_snippet": item.get("code", "")
                })
            return formatted_results
    except subprocess.TimeoutExpired:
        return [{
            "test_id": "TIMEOUT",
            "test_name": "Bandit Scan Timeout",
            "severity": "HIGH",
            "confidence": "HIGH",
            "filename": os.path.basename(file_path),
            "line_number": 0,
            "issue_text": "Bandit security scan exceeded execution timeout limit.",
            "code_snippet": ""
        }]
    except Exception as e:
        return [{
            "test_id": "ERROR",
            "test_name": "Bandit Scan Error",
            "severity": "MEDIUM",
            "confidence": "LOW",
            "filename": os.path.basename(file_path),
            "line_number": 0,
            "issue_text": f"Error executing Bandit security scan: {str(e)}",
            "code_snippet": ""
        }]
    return []

def audit_requirements_file(req_path: str) -> dict:
    """
    Audits an uploaded requirements.txt file using pip-audit.
    """
    if not os.path.exists(req_path):
        return {"status": "error", "message": "requirements.txt not found.", "vulnerabilities": []}

    try:
        cmd = [sys.executable, "-m", "pip_audit", "-r", req_path, "-f", "json"]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.stdout:
            data = json.loads(result.stdout)
            vulnerabilities = []
            # pip-audit json structure parsing
            for dep in data.get("dependencies", []):
                name = dep.get("name")
                version = dep.get("version")
                for vuln in dep.get("vulns", []):
                    vulnerabilities.append({
                        "name": name,
                        "version": version,
                        "id": vuln.get("id"),
                        "description": vuln.get("description", "No description provided."),
                        "fixed_version": ", ".join(vuln.get("fix_versions", ["Unknown"]))
                    })
            return {
                "status": "success",
                "vulnerabilities": vulnerabilities
            }
        else:
            return {
                "status": "success",
                "vulnerabilities": []
            }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Dependency audit failed: {str(e)}",
            "vulnerabilities": []
        }
