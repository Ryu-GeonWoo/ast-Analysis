import ast

def _check_flask_debug_mode(node):
    """
    Check if a node represents a Flask 'run' call with the debug mode enabled.
    """
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and 
        node.func.attr == 'run'):
        for keyword in node.keywords:
            if (keyword.arg == 'debug' and isinstance(keyword.value, ast.NameConstant) and 
                keyword.value.value):
                return True
    return False

def flask_debug_mode_usage(tree, issues):
    """
    Walks through the AST and checks for Flask applications running in debug mode.
    """
    for node in ast.walk(tree):
        if _check_flask_debug_mode(node):
            issues.append({
                "line": node.lineno,
                "severity": "High",
                "content": "Potential CWE-215 Flask Debug vulnerability",
                "url": "https://cwe.mitre.org/data/definitions/215.html"
            })

def CWE_215(tree):
    """
    Main CWE-215 vulnerability detection function.
    """
    issues = []

    flask_debug_mode_usage(tree, issues)
    return issues