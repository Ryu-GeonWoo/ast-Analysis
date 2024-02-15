import ast


def _filter_bad_tags(node):
    regex_functions = ['sub', 'match', 'search', 'findall', 'finditer', 'fullmatch']
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr in regex_functions:
            if len(node.args) > 0 and isinstance(node.args[0], (ast.Str, ast.Constant)):
                pattern = node.args[0].s if isinstance(node.args[0], ast.Str) else node.args[0].value
                if isinstance(pattern, str) and ('<script' in pattern.lower() or '<style' in pattern.lower()):
                    return True
    return False


def _bad_tag_usage(tree, issues):
    for node in ast.walk(tree):
        if _filter_bad_tags(node):
            issues.append({
                "line": node.lineno,
                "severity": "High",
                "content" : "CWE-116",
                "url" : "https://cwe.mitre.org/data/definitions/116.html"
            })


def CWE_116(tree):
    issues = []

    _bad_tag_usage(tree, issues)
    return issues

