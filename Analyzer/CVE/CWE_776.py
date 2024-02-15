import ast

def detect_xml_bomb_vulnerability(node, issues):
    # XML 파싱 함수 호출 탐지
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr.lower() in {'fromstring', 'parse', 'xml', 'xmlparser'}:
            # xml.etree.ElementTree 또는 유사한 라이브러리 사용 확인
            if isinstance(node.func.value, ast.Name) and node.func.value.id.lower() in {'et', 'elementtree', 'xml', 'etree'}:
                # 안전한 파싱 설정이 있는지 확인
                if not has_safe_parsing_config(node):
                    issues.append({
                        "line": node.lineno,
                        "severity": "High",
                        "content": "Potential XML Bomb vulnerability detected.",
                        "url": "https://cwe.mitre.org/data/definitions/776.html"
                    })

def has_safe_parsing_config(node):
    # XML 파싱 호출이 엔티티 확장을 제한하는 설정을 포함하는지 확인
    for keyword in node.keywords:
        if keyword.arg.lower() in {'entity_expansion_limit', 'resolve_entities', 'no_network'}:
            # 안전한 설정이 있는 경우
            if (isinstance(keyword.value, ast.Num) and keyword.value.n > 0) or \
               (isinstance(keyword.value, (ast.NameConstant, ast.Constant)) and not keyword.value.value):
                return True
    return False

def check_for_xml_bomb(tree, issues):
    for node in ast.walk(tree):
        detect_xml_bomb_vulnerability(node, issues)

def CWE_776(tree):
    issues = []
    check_for_xml_bomb(tree, issues)
    return issues