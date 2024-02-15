# # CWE-601

import ast

# class UrlRedirectVisitor(ast.NodeVisitor):
#     """
#     AST visitor to detect instances of potential CWE-601-UrlRedirect vulnerabilities,
#     where user inputs are used directly in URL redirection without validation.
#     """

#     def visit_Call(self, node):
#         """
#         Visit a call node and check if it's a URL redirection call with potentially vulnerable arguments.
#         """
#         # Check for calls to 'redirect' function
#         if isinstance(node.func, ast.Name) and node.func.id == 'redirect':
#             # Check if the first argument is a direct user input from request
#             if len(node.args) > 0 and isinstance(node.args[0], ast.Call):
#                 arg_func = node.args[0].func
#                 if isinstance(arg_func, ast.Attribute) and arg_func.attr == 'get':
#                     if isinstance(arg_func.value, ast.Attribute) and arg_func.value.attr == 'args':
#                         if isinstance(arg_func.value.value, ast.Name) and arg_func.value.value.id == 'request':
#                             print(
#                                 f"Potential vulnerability found: URL Redirection at line {node.lineno}")

#         # Continue walking through the AST
#         self.generic_visit(node)

def _url_redirect_checker(node):
    """
    Check if a node represents a potential UrlRedirect vulnerability.
    """
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'redirect':
        if len(node.args) > 0 and isinstance(node.args[0], ast.Call):
            arg_func = node.args[0].func
            if isinstance(arg_func, ast.Attribute) and arg_func.attr == 'get':
                if isinstance(arg_func.value, ast.Attribute) and arg_func.value.attr == 'args':
                    if isinstance(arg_func.value.value, ast.Name) and arg_func.value.value.id == 'request':
                        return {
                            "line": node.lineno,
                            "severity": "High",
                            "content": "Potential UrlRedirect vulnerability detected.",
                            "url": "https://cwe.mitre.org/data/definitions/601.html"
                        }
    return None

def _url_redirect_usage(tree, issues):
    """
    Walks through the AST and checks for potential UrlRedirect vulnerabilities.
    """
    for node in ast.walk(tree):
        issue = _url_redirect_checker(node)
        if issue:
            issues.append(issue)

def CWE_601(tree):
    """
    Main CWE-601 vulnerability detection function.
    """
    issues = []

    _url_redirect_usage(tree, issues)
    return issues