# AI-Assisted Compliance Monitor

## Overview
This project demonstrates how AI can be responsibly leveraged to support continuous coompliance monitoring in regulated environments.

The Tool evaluates security configurations and logs, maps findings to established compliance frameworks (NIST, CIS, HIPAA), and uses AI to assist with risk explanation and audit-ready reporting, without replacing human judgment.

## Objectives
- Detect compliance drift in security controls
- Detect overly permissive IAM policies that violate least privilege principles
- Map technical findings to regulatory requirements
- Map IAM findings to NIST, CIS, and HIPAA access control requirements
- Demonstrate secure, ethical AI usage in cybersecurity
- Support audit preparation and executive reporting

## One-Command Demo
This repository includes a working example that anlyzes an overly permissive IAM policy and produces SOC/GRC-ready compliance findings mapped to major regulatory frameworks.

### Requirements
- Python 3.10+
- No cloud credentials required
  
### Run the Demo
python -c "from ai_engine.policy_parser import parse_policy; from ai_engine.compliance_finder import build_findings; print(build_findings(parse_policy('policies/admin_policy.json')))"

### Sample Output
[{
  'risk_level': 'HIGH',
  'title': 'Overly permissive IAM policy without MFA',
  'description': 'IAM policy allows unrestricted actions and resources without enforcing multi-factor authentication.',
  'frameworks': {
    'NIST': ['AC-2'],
    'CIS': ['6.3'],
    'HIPAA': ['164.308(a)(4)']
  },
  'recommended_remediation': [
    'Restrict IAM actions to only required services',
    'Limit resources to specific ARNs',
    'Require MFA for privileged IAM access'
    ]
  }]
  

## Disclaimer
This project is for educational and demonstration purposes. AI outputs are assistive and require human validation before use in production or audits.
