import ast

credential_keywords = [
    "password", "passwd", "secret", "api_key", "token", "apikey", "accesskey", "auth", "credentials"
]

def check_for_credentials(string):
    lower_string = string.lower()
    return any(kw in lower_string for kw in credential_keywords)

def hardcoded_credentials_usage(tree, issues):
    """
    Walks through the AST and checks for hardcoded credentials.
    """
    for node in ast.walk(tree):
        # Check for hardcoded credentials in assignments
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id.lower() in ["password", "secret", "apikey"] for target in node.targets):
            issues.append({
                "line": node.lineno,
                "severity": "HIGH",
                "content": "CWE-798 : Potential hardcoded credential detected.",
                "url": "https://cwe.mitre.org/data/definitions/798.html"
            })

        # Check for hardcoded credentials in function calls (simplified check)
        elif isinstance(node, ast.Call) and any(isinstance(arg, ast.Str) and "password" in arg.s.lower() for arg in node.args):
            issues.append({
                "line": node.lineno,
                "severity": "HIGH",
                "content": "CWE-798 : Potential hardcoded credential detected in function call.",
                "url": "https://cwe.mitre.org/data/definitions/798.html"
            })

        # Check for hardcoded credentials in return statements (simplified check)
        elif isinstance(node, ast.Return) and isinstance(node.value, ast.Str) and "password" in node.value.s.lower():
            issues.append({
                "line": node.lineno,
                "severity": "HIGH",
                "content": "CWE-798 : Potential hardcoded credential detected in return statement.",
                "url": "https://cwe.mitre.org/data/definitions/798.html"
            })



def CWE_798(tree):
    """
    Main CWE-798 vulnerability detection function.
    """
    issues = []

    hardcoded_credentials_usage(tree, issues)
    return issues