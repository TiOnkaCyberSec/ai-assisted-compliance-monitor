def build_findings(parsed_statements):
  """
  Convert parsed IAM policy statements into compliance findings.
  Returns a list of SOC/GRC-ready findings.
  """
  findings = []

  for stmt in parsed_statements:
    # HIGH RISK: Full wildcard + no MFA
    if stmt["has_wildcard_action"] and stmt["has_wildcard_resource"] and not stmt["mfa_required"]:
      findings.append({
        "risk_level": "HIGH",
        "title": "Overly permissive IAM policy without MFA",
        "description": (
            "IAM policy allows unrestricted actions and resources"
            "without enforcing multi-factor authentication."
        ),
        "frameworks": {
            "NIST": ["AC-2"],
            "CIS": ["6.3"],
            "HIPAA": ["164.308(a)(4)"]
        },
        "recommended_remediation": [
            "Restrict IAM actions to only required services",
            "Limit resources to specific ARNs",
            "Require MFA for privileged IAM access"
        ]
      })
      # MEDIUM RISK: Partial wildcards
    elif stmt["has_partial_wildcard_action"]:
      findings.append({
        "risk_level": "MEDIUM",
        "title": "IAM policy uses partial wildcard actions",
        "description": (
            "IAM policy uses service-level wildcard  actions "
            "which may grant broader access than intended."
        ),
        "frameworks": {
          "NIST": ["AC-3"],
          "CIS": ["6.1"]
        },
        "recommended_remidation": [
          "Replace wildcard actions with specific API calls",
          "Review permissions for least privilege alignment"
        ]
      })
      return findings
