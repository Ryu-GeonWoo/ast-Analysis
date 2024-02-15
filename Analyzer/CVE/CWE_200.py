import ast

def _check_bind_to_all_interfaces(node):
    """
    Check if a node represents a socket binding to all interfaces.
    """
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'bind':
        for arg in node.args:
            if isinstance(arg, ast.Tuple) and len(arg.elts) == 2:
                ip = arg.elts[0]
                if ((isinstance(ip, ast.Str) and ip.s in ['0.0.0.0', '']) or 
                    (isinstance(ip, ast.Constant) and ip.value in ['0.0.0.0', ''])):
                    return True
    return False

def bind_to_all_interfaces_usage(tree, issues):
    """
    Walks through the AST and checks for socket bindings to all interfaces.
    """
    for node in ast.walk(tree):
        if _check_bind_to_all_interfaces(node):
            issues.append({
                "line": node.lineno,
                "severity": "High",
                "content": "CVE-2018-1281-BindToAllInterfaces vulnerability",
                "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1281"
            })

def CWE_200(tree):
    """
    Main CVE-2018-1281 vulnerability detection function.
    """
    issues = []

    bind_to_all_interfaces_usage(tree, issues)
    
    return issues