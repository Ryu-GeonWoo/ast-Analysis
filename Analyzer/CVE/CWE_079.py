import ast

class ImprovedXSSDetector(ast.NodeVisitor):
    def __init__(self):
        self.issues = []
        self.in_request_context = False

    def visit_Call(self, node):
        # Flask의 request.args.get 메서드 사용 탐지
        if self.is_flask_request_get(node):
            self.in_request_context = True
            self.generic_visit(node)

        # Django의 request.GET.get 또는 request.POST.get 메서드 사용 탐지
        elif self.is_django_request_get_post(node):
            self.in_request_context = True
            self.generic_visit(node)

        # 응답 생성 시 입력값을 검증하지 않는 경우 탐지
        elif self.in_request_context and isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in ['make_response', 'HttpResponse']:
                # escape 함수 사용 여부 확인
                is_escaped = self.is_response_escaped(node)
                if not is_escaped:
                    self.issues.append({
                        "line": node.lineno,
                        "severity": "High",
                        "content": "Potential Reflected XSS vulnerability detected in response.",
                        "url": "https://cwe.mitre.org/data/definitions/79.html"
                    })
            self.in_request_context = False
        self.generic_visit(node)

    def is_flask_request_get(self, node):
        return (isinstance(node.func, ast.Attribute) and 
                node.func.attr == 'get' and
                isinstance(node.func.value, ast.Attribute) and 
                node.func.value.attr == 'args' and
                isinstance(node.func.value.value, ast.Name) and 
                node.func.value.value.id == 'request')

    def is_django_request_get_post(self, node):
        return (isinstance(node.func, ast.Attribute) and 
                node.func.attr in ['get', 'post'] and
                isinstance(node.func.value, ast.Attribute) and 
                node.func.value.attr == 'GET' and
                isinstance(node.func.value.value, ast.Name) and 
                node.func.value.value.id == 'request')

    def is_response_escaped(self, node):
        return any(isinstance(arg, ast.Call) and 
                   isinstance(arg.func, ast.Name) and 
                   arg.func.id == 'escape' for arg in node.args)

def CWE_079(tree):
    detector = ImprovedXSSDetector()
    detector.visit(tree)
    return detector.issues