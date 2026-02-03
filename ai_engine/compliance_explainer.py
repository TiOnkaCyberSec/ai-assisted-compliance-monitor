from typing import Dict, List

#Example: simple LLM function placeholder
# In production, replace with OpenAI call or other LLM
def generate_explanation(finding:Dict) -> str: 
   """
   Generates plain-language compliance explanation from a single finding.
   """
  explanation = f"""
  Policy '{finding['policy_name']}' is flagged as HIGH risk because it violates the principle of Least Privilege

  Compliance Impact:
  - NIST Controls: {', '.join(finding['compliance_impact']['NIST'])}
  - CIS Controls: {', '.join(finding['compliance_impact']['CIS'])}
  - HIPAA Safeguards: {', '.join(finding['compliance_impact']['HIPAA'])}

  Issue: {finding['issue']}

  Suggested Remediation:
  - Restrict IAM actions to only what is needed.
  - Limit resources to specific ARNs instead of '*'.

  Audit Note:
  This finding should be documented in security review and remediated per policy.
  """
  return explanation.strip()


def explain_findings(findings: List[DICT]) -> List[str]:
    return [generate_explanation(f) for f in findings]
if __name__ == "__main__":
    from analyzer.iam_checker import analyze_policies

     results = analyze_policies("data/iam_policies.json")

     if not results:
       print("No high-risk IAM findings detected.")
else:
    explanations = explain_findings(results)
    for idx, exp in enumerate(explanations,1):
         print(f"\n--- Finding {idx} ---\n"
          print(exp)
