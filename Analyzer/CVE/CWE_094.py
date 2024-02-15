import ast

def _check_code_injection(node):
    """
    Check if a node represents a code execution call with potentially vulnerable arguments.
    """
    code_execution_functions = ['exec', 'eval']
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and 
        node.func.id in code_execution_functions):
        if len(node.args) > 0 and (isinstance(node.args[0], ast.BinOp) or isinstance(node.args[0], ast.JoinedStr)):
            return True
    return False

def code_injection_usage(tree, issues):
    """
    Walks through the AST and checks for code injection vulnerabilities.
    """
    for node in ast.walk(tree):
        if _check_code_injection(node):
            issues.append({
                "line": node.lineno,
                "severity": "High",
                "content": "Potential CWE-094-CodeInjection vulnerability",
                "url": "https://cwe.mitre.org/data/definitions/094.html"
                
            })

def CWE_094(tree):
    """
    Main CWE-094 vulnerability detection function.
    """
    issues = []

    code_injection_usage(tree, issues)
    return issues