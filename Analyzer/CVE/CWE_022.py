#   CWE ID :

#   CWE-022 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

#   Vulnerability Details : CVE-2007-4559

#       Python » Python Versions from including (>=) 3.9.0 and before (<) 3.9.17
#       Python » Python Versions before (<) 3.6.16
#       Python » Python Versions from including (>=) 3.10.0 and before (<) 3.10.12
#       Python » Python Versions from including (>=) 3.11.0 and before (<) 3.11.4
#       Python » Python Versions from including (>=) 3.7.0 and before (<) 3.8.17
#
#       The product uses external input to construct a pathname 
#       that is intended to identify a file or directory that is located underneath a restricted parent directory, 
#       but the product does not properly neutralize special elements within the pathname 
#       that can cause the pathname to resolve to a location that is outside of the restricted directory.

    # Common Vulnerabilities and Exposures assigned an identifier CVE-2007-4559
    # to the following vulnerability:

    # Directory traversal vulnerability in the (1) extract and (2) extractall
    # functions in the tarfile module in Python allows user-assisted remote attackers
    # to overwrite arbitrary files via a .. (dot dot) sequence in filenames in a TAR
    # archive, a related issue to CVE-2001-1267.

    # References:

    # Issue and additional attack vectors were discussed in following thread on
    # python-dev mailinglist:

    # http://mail.python.org/pipermail/python-dev/2007-August/074290.html

    # Upstream bug tracking possible fixes for the issue:

    # http://bugs.python.org/issue1044041

import ast
import sys

def check_tarfile_import(node):
    if isinstance(node, ast.Import):
        for alias in node.names:
            if alias.name == 'tarfile':
                return True
    elif isinstance(node, ast.ImportFrom):
        if node.module == 'tarfile':
            for alias in node.names:
                if alias.name in ['extract', 'extractall']:
                    return True
    return False

def check_tarfile_method_call(node):
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr in ['extract', 'extractall']:
            return True
    return False

def detect_tarfile_issues(tree):
    issues = []

    for node in ast.walk(tree):
        if check_tarfile_import(node):
            issues.append({
                "line": node.lineno,
                "severity": "High",
                "content": "Unsafe tarfile module import detected",
                "url": "https://cwe.mitre.org/data/definitions/22.html"
            })
        elif check_tarfile_method_call(node):
            issues.append({
                "line": node.lineno,
                "severity": "High",
                "content": "Potentially unsafe tarfile extract/extractall call detected",
                "url": "https://cwe.mitre.org/data/definitions/22.html"
            })

    return issues


def CWE_022(tree):
    return detect_tarfile_issues(tree)