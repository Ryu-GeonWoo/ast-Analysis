import ast

def _check_yaml_load(node):
    if isinstance(node, ast.Call):  # 노드가 함수 호출 구조인지 확인
        if (
            hasattr(node.func, "value")
            and isinstance(node.func.value, ast.Name)
            and hasattr(node.func.value, "id")
            and node.func.value.id == "yaml"
            and hasattr(node.func, "attr")
            and node.func.attr == "load"  # yaml.load인지 확인
            and hasattr(node, "keywords")  # 키워드 인수가 있는지 확인
            and not any(
                arg.arg == "Loader" and hasattr(arg.value, "id") and arg.value.id == "SafeLoader"
                for arg in node.keywords
            )
        ):
            return True
    return False

def find_yaml_load_usage(tree, issues): #AST 순회하며 찾기
    for node in ast.walk(tree):
        if _check_yaml_load(node):
            issues.append(
                {
                    "line": node.lineno, #라인 넘버
                    "severity": "Medium", #문제 심각도
                    "content" : "CVE-2014-2525",
                    "url":"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-2525"
                  
                }
            )

def _is_user_input_function(call_node):
    if isinstance(call_node.func, ast.Attribute) or isinstance(call_node.func, ast.Name):
        function_name = call_node.func.attr if isinstance(call_node.func, ast.Attribute) else call_node.func.id

        # 사용자 입력 소스로 간주되는 함수 및 메소드 목록
        user_input_sources = {
            'input',  # 기본 input 함수
            'get',  # 예: request.get() 또는 다른 메소드
            'read',  # 파일 읽기
            'getenv'  # 환경 변수 접근
            # 여기에 다른 사용자 입력 함수나 메소드를 추가할 수 있습니다.
        }

        if function_name in user_input_sources:
            return True
    return False

def _check_user_input_misuse(node, user_input_sources):
    # 사용자 입력이 적절한 검증 없이 사용되는 경우 탐지
    if isinstance(node, ast.Call):
        for arg in node.args + node.keywords:
            if isinstance(arg, (ast.Name, ast.Attribute)) and getattr(arg, 'id', None) in user_input_sources:
                return True
    return False

def detect_user_input_validation_issues(tree, issues):
    user_input_sources = set()

    for node in ast.walk(tree):
        # 사용자 입력이 변수에 할당되는 경우 추적
        if isinstance(node, ast.Assign):
            if isinstance(node.value, ast.Call) and _is_user_input_function(node.value):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        user_input_sources.add(target.id)

        # 사용자 입력이 검증 없이 사용되는 경우 탐지
        if _check_user_input_misuse(node, user_input_sources):
            issues.append({
                "line": node.lineno, 
                "severity": "High",  
                "content": "Potential misuse of user input without validation", 
                "url": "https://cwe.mitre.org/data/definitions/20.html"
            })

def CWE_020(tree):
    issues = []

    find_yaml_load_usage(tree, issues)
    detect_user_input_validation_issues(tree, issues)
    return issues