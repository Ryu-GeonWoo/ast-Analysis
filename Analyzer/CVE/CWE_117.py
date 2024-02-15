import ast

def extract_variables_from_logging(tree):
    # 로깅 메서드 목록 정의
    logging_methods = ["info", "debug", "warning", "error"]

    # 사용된 변수를 저장할 집합 초기화
    used_variables = set()

    # AST 트리를 순회하며 로깅 메서드 호출에서 사용된 변수 추출
    for node in ast.walk(tree):
        # 표현식(expr)이고 함수 호출(Call)인 경우
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            # 함수 호출이 속성(Attribute)인 경우 (ex. app.logger.info())
            if isinstance(node.value.func, ast.Attribute):
                # Flask의 로거인지 확인 (app.logger)
                if (
                    isinstance(node.value.func.value, ast.Attribute)
                    and isinstance(node.value.func.value.value, ast.Name)
                    and node.value.func.value.value.id == "app"
                    and node.value.func.value.attr == "logger"
                    and node.value.func.attr in logging_methods
                ):
                    # 로깅 메시지에 사용된 변수 추출
                    for arg in node.value.args:
                        if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                            for operand in [arg.left, arg.right]:
                                if isinstance(operand, ast.Name):
                                    used_variables.add((operand.id, node.lineno))
                # logging 모듈의 로깅 메서드인지 확인
                elif (
                    isinstance(node.value.func.value, ast.Name)
                    and node.value.func.value.id == "logging"
                    and node.value.func.attr in logging_methods
                ):
                    # 로깅 메시지에 사용된 변수 추출
                    for arg in node.value.args:
                        if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                            for operand in [arg.left, arg.right]:
                                if isinstance(operand, ast.Name):
                                    used_variables.add((operand.id, node.lineno))
                # logger 모듈의 로깅 메서드인지 확인
                elif (
                    isinstance(node.value.func.value, ast.Name)
                    and node.value.func.value.id == "logger"
                    and node.value.func.attr in logging_methods
                ):
                    # 로깅 메시지에 사용된 변수 추출
                    for arg in node.value.args:
                        if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                            for operand in [arg.left, arg.right]:
                                if isinstance(operand, ast.Name):
                                    used_variables.add((operand.id, node.lineno))       
            # 함수 호출이 이항 연산(BinOp)인 경우 (ex. logger.info("Value: " + variable))
            elif isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.Add):
                # 이항 연산자가 '+'이면 변수 사용으로 간주
                for operand in [node.value.left, node.value.right]:
                    if isinstance(operand, ast.Name):
                        used_variables.add((operand.id, node.lineno))

    # 사용된 변수를 라인 번호에 따라 정렬하여 반환
    return sorted(used_variables, key=lambda x: x[1])

def check_user_input_usage(tree, issues):
    # 사용자 입력 함수와 Flask 관련 변수 정의
    user_input_functions = {"input", "getpass", "askstring", "prompt", "getText"}
    user_input_flask = {"args", "from", "json", "cookies", "headers"}
    
    # 사용자 입력 변수를 저장할 집합 초기화
    user_input_variables = set()

    # AST 트리를 순회하며 대입문 찾기
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            # 대입문에서 대입 대상 확인
            for target in node.targets:
                if isinstance(target, ast.Name):
                    # 변수가 함수 호출 결과로 초기화되었는지 확인
                    if (
                        isinstance(node.value, ast.Call)
                        and hasattr(node.value.func, 'id')
                        and node.value.func.id in user_input_functions
                    ):
                        # 사용자 입력 함수의 결과로 초기화된 변수 정보 저장
                        user_input_variables.add((target.id, node.lineno))
                    # 변수가 Flask request 모듈의 get 함수 호출 결과로 초기화되었는지 확인
                    elif (
                        isinstance(node.value, ast.Call)
                        and isinstance(node.value.func, ast.Attribute)
                        and isinstance(node.value.func.value, ast.Attribute)
                        and isinstance(node.value.func.value.value, ast.Name)
                        and node.value.func.value.value.id == "request"
                        and node.value.func.value.attr in user_input_flask
                        and node.value.func.attr == "get"
                    ):
                        # Flask request 모듈의 get 함수의 결과로 초기화된 변수 정보 저장
                        user_input_variables.add((target.id, node.lineno))

    # 로깅에서 사용된 변수 정보 추출
    used_variables = extract_variables_from_logging(tree)

    # 사용자 입력 변수 중 로깅 문장에서 사용된 변수가 있는지 확인
    for var, line_number in user_input_variables:
        for used_var, used_line_number in used_variables:
            # 중복된 이슈가 없으면 이슈 추가
            if var == used_var and not any(issue['line'] == used_line_number for issue in issues):
                issues.append({
                    "line": used_line_number,
                    "severity": "High",
                    "content": "Potential Log Injection detected",
                    "url": "https://cwe.mitre.org/data/definitions/117.html"
                })

def CWE_117(tree):
    # 감지된 이슈를 저장할 리스트 초기화
    issues = []
    
    # 사용자 입력과 로깅 문제를 체크하는 함수 호출
    check_user_input_usage(tree, issues)
    
    # 정렬된 이슈 리스트 반환
    return issues
