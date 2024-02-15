# CWE-285

import ast

# 원본

# class PamAuthorizationVisitor(ast.NodeVisitor):
#     """
#     AST visitor to detect instances of potential CWE-285-PamAuthorization vulnerabilities,
#     where PAM is used for authentication without subsequent account management checks.
#     """

#     def visit_FunctionDef(self, node):
#         """
#         Visit a function definition and check if it contains PAM authentication without account management.
#         """
#         pam_authenticate_call = False
#         pam_acct_mgmt_call = False

#         # Traverse the body of the function to look for pam_authenticate and pam_acct_mgmt calls
#         for subnode in ast.walk(node):
#             if isinstance(subnode, ast.Call) and isinstance(subnode.func, ast.Attribute):
#                 # Check if the function called is pam_authenticate
#                 if subnode.func.attr == 'pam_authenticate':
#                     pam_authenticate_call = True
#                 # Check if the function called is pam_acct_mgmt
#                 elif subnode.func.attr == 'pam_acct_mgmt':
#                     pam_acct_mgmt_call = True

#         # Report a potential vulnerability if pam_authenticate is used without pam_acct_mgmt
#         if pam_authenticate_call and not pam_acct_mgmt_call:
#             print(
#                 f"Potential vulnerability found: PAM authorization bypass in function '{node.name}' at line {node.lineno}")

#         # Continue walking through the AST
#         self.generic_visit(node)

        
def check_pam_authorization(node):
    """
    Check if a node represents a potential CWE-285-PamAuthorization vulnerability,
    where PAM is used for authentication without subsequent account management checks.
    """
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        # Check if the function called is pam_authenticate
        if node.func.attr == 'pam_authenticate' and not node.func.attr == 'pam_acct_mgmt':
            return {
                "line": node.lineno,
                "severity": "High",
                "content": "Potential Pam Authorization detected",
                "url": "https://cwe.mitre.org/data/definitions/285.html"
            }
    return None

def pam_authorization_usage(tree, issues):
    """
    Walks through the AST and checks for potential CWE-285-PamAuthorization vulnerabilities.
    """
    for node in ast.walk(tree):
        issue = check_pam_authorization(node)
        if issue:
            issues.append(issue)

def CWE_285(tree):
    """
    Main CWE-285 vulnerability detection function.
    """
    issues = []

    pam_authorization_usage(tree, issues)
    return issues