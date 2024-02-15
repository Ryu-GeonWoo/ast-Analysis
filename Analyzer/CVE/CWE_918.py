import ast

def _is_user_input_in_url(node):
    """
    Heuristically determine if a node might contain a URL constructed using user input.
    """
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        # Simple check for concatenation in URL
        return True
    elif isinstance(node, ast.JoinedStr):
        # Check for formatted strings
        return any(isinstance(value, ast.FormattedValue) for value in node.values)

    return False


def ssrf_detector(tree, issues):
    """
    Walks through the AST and checks for potential SSRF vulnerabilities.
    """
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and 
            node.func.attr in ['get', 'post', 'put', 'delete', 'request']):
            if node.args and _is_user_input_in_url(node.args[0]):
                issues.append({
                    "line": node.lineno,
                    "severity": "High",
                    "content": "Potential SSRF vulnerability detected.",
                    "url": "https://cwe.mitre.org/data/definitions/918.html"
                })

def CWE_918(tree):
    """
    Main CWE-918 vulnerability detection function.
    """
    issues = []

    ssrf_detector(tree, issues)
    return issues