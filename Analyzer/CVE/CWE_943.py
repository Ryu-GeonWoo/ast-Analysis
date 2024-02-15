import ast

def _check_nosql_injection(node):
    """
    Check if a node represents a potential NoSQL injection vulnerability.
    """
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and 
        node.func.attr.lower in ['find', 'find_one', 'aggregate', 'update', 'remove']):
        for arg in node.args:
            if (isinstance(arg, ast.Call) and arg.func.id == 'json.loads' ) or isinstance(arg.func, ast.Dict) :
                return {
                    "line": node.lineno,
                    "severity": "High",
                    "content": "Potential NoSQL injection detected",
                    "url": "https://cwe.mitre.org/data/definitions/943.html"
                }
    return None
def nosql_injection_usage(tree, issues):
    """
    Walks through the AST and checks for potential NoSQL injection vulnerabilities.
    """
    for node in ast.walk(tree):
        issue = _check_nosql_injection(node)
        if issue:
            issues.append(issue)

def CWE_943(tree):
    """
    Main CWE-943 vulnerability detection function.
    """
    issues = []

    nosql_injection_usage(tree, issues)
    return issues