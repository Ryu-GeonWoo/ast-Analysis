# # CWE-209

import ast

# class StackTraceExposureVisitor(ast.NodeVisitor):
#     """
#     AST visitor to detect instances of potential CWE-209-StackTraceExposure vulnerabilities,
#     particularly where stack traces or exception details are exposed to the user.
#     """

#     def visit_Return(self, node):
#         """
#         Visit a return statement and check if it contains stack trace exposure.
#         """
#         # Check if the return statement includes a call to traceback.format_exc()
#         if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute):
#             if node.value.func.attr == 'format_exc' and isinstance(node.value.func.value, ast.Name) and node.value.func.value.id == 'traceback':
#                 print(
#                     f"Potential vulnerability found: Stack trace exposure at line {node.lineno}")

#         # Continue walking through the AST

def _check_stack_trace_exposure(node):
    """
    Check if a node represents a potential StackTraceExposure vulnerability.
    """
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and 
        node.func.attr in ['format_exc', 'format_exception']):
        if isinstance(node.func.value, ast.Name) and node.func.value.id == 'traceback':
            return {
                "line": node.lineno,
                "severity": "High",
                "content": "Potential StackTraceExposure vulnerability detected.",
                "url": "https://cwe.mitre.org/data/definitions/209.html"
            }
    return None

def stack_trace_exposure_usage(tree, issues):
    """
    Walks through the AST and checks for potential StackTraceExposure vulnerabilities.
    """
    for node in ast.walk(tree):
        issue = _check_stack_trace_exposure(node)
        if issue:
            issues.append(issue)

def CWE_209(tree):
    """
    Main CWE-209 vulnerability detection function.
    """
    issues = []

    stack_trace_exposure_usage(tree, issues)
   
    return issues