import json
from pathlib import Path

HIGH_RISK_ACTIONS = ["*"]
HIGH_RISK_RESOURCES = ["*"]

COMPLIANCE_MAPPING = {
    "NIST": ["AC-2"],
    "CIS": ["6.3"],
    "HIPAA": ["164.308(a)(4)"]
}
def load_policies(file_path):
    path = Path(file_path)
    with path.open("r") as f:
        return json.load(f)["policies"]

def analyze_policy(policy):
    findings = []
    wildcard_action = any(action in HIGH_RISK_ACTIONS for action in policy["actions"])
    wildcard_resource = any(resource in HIGH_RISK_RESOURCES for resource in policy["resources"])
    if wildcard_action and wildcard_resource:
        findings.append({
            "policy_name": policy["policy_name"],
            "risk_level": "HIGH",
            "issue": "Overly permissive IAM policy detected (wildcard actions and resources).",
            "principle_violated": "Least Privilege",
            "compliance_impact": COMPLIANCE_MAPPING
           })
            return findings

def analyze_polices(file_path):
    all_findings = []
    policies = load_policies(file_path)
    for policy in policies:
        all_findings.extend(analyze_policy(policy))
        return all_findings
        if __name__ == "__main__":
            results = analyze_policies("data/iam_policies.json")
            if not results:
                print("No high-risk IAM findings detected.")
            else:
                for finding in results:
                    print("\nIAM COMPLIANCE FINDING")
                    for key, value in finding.items():
                        print(f"{key}: {value}")
