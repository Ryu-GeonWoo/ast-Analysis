import ast

def detect_xxe_vulnerability(node, issues):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        # lxml 라이브러리 사용 검사
        if node.func.attr in ['XMLParser', 'parse', 'make_parser']:
            for keyword in node.keywords:
                if keyword.arg in ['load_dtd', 'resolve_entities']:
                    if isinstance(keyword.value, (ast.NameConstant, ast.Constant)) and \
                       keyword.value.value is True:
                        issues.append({
                            "line": node.lineno,
                            "severity": "High",
                            "content": "Potential XXE vulnerability detected in lxml library usage.",
                            "url": "https://cwe.mitre.org/data/definitions/643.html"
                        })
        # xml.etree.ElementTree 모듈 사용 검사
        elif (node.func.attr in ['fromstring', 'parse'] and
              isinstance(node.func.value, ast.Name) and
              node.func.value.id in ['ET', 'ElementTree']):
            issues.append({
                "line": node.lineno,
                "severity": "High",
                "content": "Potential XXE vulnerability detected in xml.etree.ElementTree usage.",
                "url": "https://cwe.mitre.org/data/definitions/643.html"
            })

def check_for_xxe(tree, issues):
    for node in ast.walk(tree):
        detect_xxe_vulnerability(node, issues)

def CWE_643(tree):
    issues = []
    check_for_xxe(tree, issues)
    return issues