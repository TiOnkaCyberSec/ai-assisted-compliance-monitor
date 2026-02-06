import json
import re

def parse_policy(file_path):
  """
  Load and normalize an IAM policy file.
  Returns a list of parsed policy statements with hardening checks:
  - Full wildcard actions/resources
  - Partial wildcard actions
  - Missing MFA conditions
  """
  with open(file_path, "r") as f:
    policy = json.load(f)

  statements = policy.get("Statement" , [])
  if isinstance(statements, dict):
    statements = [statements]
  
  parsed_statements = []

  for stmt in statements:
    actions = stmt.get("Action" , [])
    resources = stmt.get("Resource", [])
    
    if isinstance(actions, str):
      actions = [actions]
    if isinstance(resources, str):
      resources = [resources]

    # Hardening checks
    has_wildcard_action = "*" in actions
    has_partial_wildcard_action = any(re.search(r":.*\*$", a) for a in actions)
    has_wildcard_resource = "*" in resources

    # Check for MFA conditions
    conditions = stmt.get("Condition", {})
    mfa_required = "aws:MultiFactorAuthPresent" in json.dumps(conditions)

    parsed_statements.append({
     "effect": stmt.get("Effect"),
     "actions": actions,
     "resources": resources,
     "conditions": conditions,
     "has_wildcard_action": has_wildcard_action,
     "has_partial_wildcard_action": has_partial_wildcard_action,
     "has_wildcard_resource": has_wildcard_resource,
     "mfa_required": mfa_required
  })

  return parsed_statements
