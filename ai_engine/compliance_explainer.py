import sys
from pathlib import Path
from typing import Dict, List

sys.path.append(str(Path(__file__).resolve().parent.parent))


#Example: simple LLM function placeholder
# In production, replace with OpenAI call or other LLM
def generate_explanation(finding:Dict) -> str: 
    explanation = (
    f"Policy '{finding['policy_name']}' is flagged as HIGH risk because it "
    f"violates the principle of Least Privilege.\n\n"
    f"Compliance Impact:\n"
    f"- NIST Controls: {', '.join(finding['compliance_impact']['NIST'])}\n"
    f"- CIS Controls: {', '.join(finding['compliance_impact']['CIS'])}\n"
    f"- HIPAA Safeguards: {', '.join(finding['compliance_impact']['HIPAA'])}\n\n"
    f"Issue:\n"
    f"{finding['issue']}\n\n"
    f"Suggested Remediation:\n"
    f"- Restrict IAM actions to only what is needed\n"
    f"- Limit resources to specific ARNs instead of '*'\n\n"
    f"Audit Note:\n"
    f"This finding should be documented in security review and remediated per policy."
    )
    return explanation
    
def explain_findings(findings: List[Dict]) -> List[str]:
    return [generate_explanation(f) for f in findings]
    
 if __name__ == "__main__":
     from analyzer.iam_checker import analyze_policies
     
     results = analyze_policies("data/iam_policies.json")
     
     if not results:
        print("No high-risk IAM findings detected.")
     else:
        explanations = explain_findings(results)
        for idx, exp in enumerate(explanations,1):
            print(f"\n--- Finding {idx} ---\n")
            print(exp)
