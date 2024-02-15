# 작업중인 코드
# 한동혁이 진행중, 아직 풀 버젼 아님
# 주석처리된 코드는 원본, 아래 코드는 수정본.

# import ast

# class PillowVulnerabilityDetector(ast.NodeVisitor):
#     def __init__(self):
#         self.issues = []

#     def visit_Call(self, node):
#         if isinstance(node.func, ast.Attribute) and node.func.attr == "truetype":
#             self.check_for_vulnerable_usage(node)
#         self.generic_visit(node)

#     def check_for_vulnerable_usage(self, node):
#         text_arg, font_arg = None, None
#         for arg in node.args:
#             if self.is_long_text_arg(arg):
#                 text_arg = arg
#             elif self.is_large_font_size_arg(arg):
#                 font_arg = arg
        
#         if text_arg and font_arg:
#             # 긴 텍스트와 큰 폰트 크기가 함께 사용되는 경우 탐지
#             self.issues.append({
#                 "line": node.lineno,
#                 "message": "Potential CVE-2023-44271 vulnerability detected with large text and font size.",
#                 "severity": "High",
#             })

#         # 이미지 크기에 대한 추가적인 확인 로직
#         if self.is_large_image_size(node):
#             self.issues.append({
#                 "line": node.lineno,
#                 "message": "Potential CVE-2023-44271 vulnerability detected with large image size.",
#                 "severity": "High",
#             })

#     @staticmethod
#     def is_long_text_arg(arg):
#         # arg가 긴 텍스트인지 확인
#         threshold = 100
#         if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
#             return len(arg.value) > threshold
#         return False

#     @staticmethod
#     def is_large_font_size_arg(arg):
#         # arg가 큰 폰트 크기인지 확인
#         font_size_threshold = 50
#         if isinstance(arg, ast.Constant) and isinstance(arg.value, (int, float)):
#             return arg.value > font_size_threshold
#         return False
    
#     def is_large_image_size(self, node):
#         # 이미지 크기가 큰지 확인하는 로직
#         # 이 부분은 실제 취약점의 세부 사항에 따라 다를 수 있습니다.
#         # 예시 로직: node.args에서 이미지 크기 인자를 분석
#         image_size_threshold = 10000  # 예시 임계값
#         for arg in node.args:
#             if isinstance(arg, ast.Tuple) and len(arg.elts) == 2:
#                 width, height = arg.elts
#                 if (isinstance(width, ast.Num) and width.n > image_size_threshold) or (isinstance(height, ast.Num) and height.n > image_size_threshold):
#                     return True
#         return False

# def find_imageFont_vulnerabilities(code):
#     tree = ast.parse(code)
#     detector = PillowVulnerabilityDetector()
#     detector.visit(tree)
#     return detector.issues

import ast

def _check_pilow_DoS(node):
    """
    Check if a node represents a potential DoS vulnerability.
    """
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and 
        node.func.attr in ['truetype', 'open']):
        for arg in node.args:
            if (isinstance(arg, ast.Constant) and isinstance(arg.value, str) and len(arg.value) > 100):
                return {
                    "line": node.lineno,
                    "severity": "High",
                    "content": "Potential DoS vulnerability detected",
                    "url": "https://cwe.mitre.org/data/definitions/400.html"
                }
    return None

def _check_pilow_DoS_usage(tree, issues):
    """
    Walks through the AST and checks for potential DoS vulnerabilities.
    """
    for node in ast.walk(tree):
        issue = _check_pilow_DoS(node)
        if issue:
            issues.append(issue)


def detect_request_without_timeout(tree, issues):
    # HTTP 메서드 저장
    http_verbs = {"get", "options", "head", "post", "put", "patch", "delete"}

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            # 함수 호출이 requests 모듈의 메소드 중 하나인지 확인
            if (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "requests"
                and node.func.attr in http_verbs
            ):
                # 타임아웃 지정되지 않은 경우 확인
                if not any(
                    keyword.arg == "timeout" for keyword in node.keywords
                ):
                    issues.append({
                        "line": node.lineno,
                        "severity": "Medium",                  
                        "content": "Timeout not detected",
                        "url" : "https://cwe.mitre.org/data/definitions/400.html"
                    })   
                # 타임아웃이 None인 경우 확인
                elif any(
                    keyword.arg == "timeout" and (
                        keyword.value is None or  # 타임아웃 값이 None
                        (isinstance(keyword.value, ast.NameConstant) and keyword.value.value is None)  # 타임아웃 값이 NoneConstant이면서 그 값이 None
                    )
                    for keyword in node.keywords
                ):
                    issues.append({
                        "line": node.lineno,
                        "severity": "Medium",
                        "content": "Timeout value is None",
                        "url" : "https://cwe.mitre.org/data/definitions/400.html"
                    })



def CWE_400(tree):
    """
    Main CWE-400 vulnerability detection function.
    """
    issues = []

    _check_pilow_DoS_usage(tree, issues)
    detect_request_without_timeout(tree, issues)
    return issues

