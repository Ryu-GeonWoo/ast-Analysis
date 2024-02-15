import ast

# Configuration for identifying weak hash functions and bad SSL/TLS protocol versions
WEAK_HASHES = ("md4", "md5", "sha", "sha1")
WEAK_CRYPT_HASHES = ("METHOD_CRYPT", "METHOD_MD5", "METHOD_BLOWFISH")
BAD_PROTOCOL_VERSIONS = [
    "PROTOCOL_SSLv2",
    "SSLv2_METHOD",
    "SSLv23_METHOD",
    "PROTOCOL_SSLv3",
    "PROTOCOL_TLSv1",
    "SSLv3_METHOD",
    "TLSv1_METHOD",
    "PROTOCOL_TLSv1_1",
    "TLSv1_1_METHOD",
]

def is_bad_ssl_version(version):
    return version in BAD_PROTOCOL_VERSIONS

def detect_weak_hash_usage(tree, issues):
    """
    Walks through the AST and checks for weak hash usage.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            module_name = node.func.value.id if isinstance(node.func.value, ast.Name) else None
            func_name = node.func.attr

            # Check for weak hash usage in the 'hashlib' module
            if module_name == "hashlib" and func_name in WEAK_HASHES:
                issues.append({
                    "line": node.lineno,
                    "severity": "HIGH",
                    "content": "Use of weak hash function detected.",
                    "url": "https://cwe.mitre.org/data/definitions/327.html"
                })

            # Check for weak hash usage in the 'crypt' module
            elif module_name == "crypt" and func_name in WEAK_CRYPT_HASHES:
                issues.append({
                    "line": node.lineno,
                    "severity": "MEDIUM",
                    "content": "Use of insecure crypt hash function detected.",
                    "url": "https://cwe.mitre.org/data/definitions/327.html"
                })

            # Additional checks can be implemented for specific use-cases


def CWE_327(tree):
    """
    Main CWE-327 vulnerability detection function.
    """
    issues = []

    detect_weak_hash_usage(tree, issues)
    return issues