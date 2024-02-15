import ast

def detect_except_pass_continue(tree, issues):
    # AST 트리를 순회하며 ExceptHandler 노드를 찾음
    for node in ast.walk(tree):
        # ExceptHandler 노드이고, 내부 코드가 모두 Pass 또는 Continue인 경우를 탐지
        if isinstance(node, ast.ExceptHandler) and all(isinstance(inner_node, (ast.Pass, ast.Continue)) for inner_node in node.body):
            issues.append({
                "line": node.lineno,
                "severity": "LOW",
                "content": "CWE-703",
                "url": "https://cwe.mitre.org/data/definitions/703.html"
            })

def CWE_703(tree):
    issues = []
    # Except 블록 내에서 Pass 또는 Continue를 탐지하는 함수 호출
    detect_except_pass_continue(tree, issues)
    return issues