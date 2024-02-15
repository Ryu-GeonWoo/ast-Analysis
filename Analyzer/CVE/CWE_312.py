import ast

def _is_potentially_sensitive(node):
    """
    Heuristically determine if a node might contain sensitive data.
    """
    if isinstance(node, ast.Attribute) and node.attr in ['environ', 'getenv']:
        return True
    if isinstance(node, ast.JoinedStr):
        for value in node.values:
            if isinstance(value, ast.FormattedValue) and _is_potentially_sensitive(value.value):
                return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_potentially_sensitive(node.left) or _is_potentially_sensitive(node.right)
    return False

def _check_cleartext_logging(node):
    """
    Check if a node represents a logging call with potentially sensitive data.
    """
    if (isinstance(node, ast.Call) and 
        ((isinstance(node.func, ast.Attribute) and node.func.attr in ['info', 'error', 'debug', 'warning', 'critical']) or
         (isinstance(node.func, ast.Name) and node.func.id == 'print'))):
        for arg in node.args:
            if _is_potentially_sensitive(arg):
                return True
    return False

def cleartext_logging_usage(tree, issues):
    """
    Walks through the AST and checks for cleartext logging of sensitive data.
    """
    for node in ast.walk(tree):
        if _check_cleartext_logging(node):
            issues.append({
                "line": node.lineno,
                "severity": "High",
                "content": "Potential cleartext logging of sensitive data",
                "url": "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"
            })

def CWE_312(tree):
    """
    Main CWE-312 vulnerability detection function.
    """
    issues = []

    cleartext_logging_usage(tree, issues)
    return issues