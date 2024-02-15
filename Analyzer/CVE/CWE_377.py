import ast

def _check_insecure_temp_file(node):
    """
    Check if a node represents an insecure temporary file creation function.
    """
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute):
            # For method calls like module.function()
            module_name = node.func.value.id if isinstance(node.func.value, ast.Name) else None
            function_name = node.func.attr
            if (module_name, function_name) in [('tempfile', 'mktemp'), ('os', 'tmpnam'), ('os', 'tempnam')]:
                return {
                    "line": node.lineno,
                    "severity": "High",
                    "content": "Insecure temporary file creation detected",
                    "url": "https://cwe.mitre.org/data/definitions/377.html"
                }
        elif isinstance(node.func, ast.Name):
            # For direct function calls like function()
            if node.func.id in ['mktemp', 'tmpnam', 'tempnam']:
                return {
                    "line": node.lineno,
                    "severity": "High",
                    "content": "Insecure temporary file creation detected",
                    "url": "https://cwe.mitre.org/data/definitions/377.html"
                }
    return None

def nsecure_temp_files_usage(tree, issues):
    """
    Walks through the AST and checks for insecure temporary file creation.
    """
    for node in ast.walk(tree):
        issue = _check_insecure_temp_file(node)
        if issue:
            issues.append(issue)

def CWE_377(tree):
    """
    Main CWE-377 vulnerability detection function.
    """
    issues = []

    nsecure_temp_files_usage(tree, issues)
    return issues


