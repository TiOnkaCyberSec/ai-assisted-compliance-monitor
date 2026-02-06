import json

def parse_policy(file_path):
  """
  Load and normalize an IAM policy file.
  Returns a list of parsed policy statements.
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

    parsed_statements.append({
     "effect": stmt.get("Effect"),
     "actions": actions,
     "resources": resources,
     "conditions": stmt.get("Condition", {}),
     "has_wildcard_action": "*" in actions,
     "has_wildcard_resource": "*" in resources
  })

  return parsed_statements
