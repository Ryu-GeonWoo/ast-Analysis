import ast

# 다른 두 사람이 같은 취약점 코드 작성함.
# 기록을 위해 남겨둠.

# CWE-078 (오윤석)

# import ast
# import sys


# class UnsafeShellCommandConstructionVisitor(ast.NodeVisitor):
#     """
#     AST visitor to detect instances of potential CWE-078-UnsafeShellCommandConstruction vulnerabilities,
#     where user inputs are directly used or concatenated with shell commands.
#     """

#     def visit_Call(self, node):
#         """
#         Visit a call node and check if it's a shell command execution call with potentially vulnerable arguments.
#         """
#         # Functions of interest for shell command execution (like os.system, subprocess.call)
#         shell_command_functions = ['system', 'call',
#                                    'Popen', 'run', 'check_output', 'check_call']

#         # Check if it's a call to a shell command execution function
#         if isinstance(node.func, ast.Attribute) and node.func.attr in shell_command_functions:
#             # Check if any of the arguments are potentially user controlled
#             for arg in node.args:
#                 if isinstance(arg, ast.Name) or isinstance(arg, ast.BinOp):
#                     print(
#                         f"Potential vulnerability found: Unsafe shell command construction at line {node.lineno}")

#         # Continue walking through the AST
#         self.generic_visit(node)import ast


# 와일드카드 문자열 삽입 취약점 검사 (wildcard injection)
# https://owasp.org/www-community/vulnerabilities/OS_Command_Injection
# https://cwe.mitre.org/data/definitions/78.html


config = {
    "shell": ["chown", "chmod", "tar", "rsync"]
}

def is_vulnerable_call(node):
    return (
        isinstance(node, ast.Call)
        and (
            (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os"
                and node.func.attr in config["shell"]
            )
            or (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "subprocess"
                and node.func.attr in config["shell"]
                and (
                    any(kw.arg == "shell" and kw.value.value is True for kw in node.keywords)
                    or node.check_call_arg_value("shell", "True")
                )
            )
        )
    )

def has_wildcard_argument(node):
    if node.args:
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and "*" in arg.value:
                return True
            elif isinstance(arg, ast.List):
                for elt in arg.elts:
                    if (
                        isinstance(elt, ast.Constant)
                        and isinstance(elt.value, str)
                        and "*" in elt.value
                    ):
                        return True
    return False

def find_wildcard_injection_issues(tree, issues):

    for node in ast.walk(tree):
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            if is_vulnerable_call(node.value) and has_wildcard_argument(node.value):
                issues.append({
                    "line": node.lineno,
                    "severity": "HIGH",
                    "content" : "CWE-78",
                    "url" : "https://cwe.mitre.org/data/definitions/78.html"
                })


# Shell=True 취약점 검사 (shell injection) (김동연)

def has_shell(node):
    # 함수 호출에 "shell" 키워드가 있는지 확인
    keywords = node.keywords
    result = False
    if any(keyword.arg == "shell" for keyword in keywords):
        # "shell" 키워드가 있다면 해당 값에 따라 결과를 설정
        for key in keywords:
            if key.arg == "shell":
                val = key.value
                # 값의 타입에 따라 결과를 설정
                if isinstance(val, ast.Num):
                    result = bool(val.n)
                elif isinstance(val, ast.List):
                    result = bool(val.elts)
                elif isinstance(val, ast.Dict):
                    result = bool(val.keys)
                elif isinstance(val, ast.Name) and val.id in ["False", "None"]:
                    result = False
                elif isinstance(val, ast.NameConstant):
                    result = val.value
                else:
                    result = True
    return result

def _evaluate_shell_call(node):
    # 첫 번째 인수가 문자열이면 "LOW", 아니면 "HIGH" 반환
		# LOW인 이유 : 문자열 포맷팅, 변수 삽입 없이 직접 주어진 경우로 간주되어 상대적으로 안전
		# HIGH인 이유 : 다른 변수나 외부 입력을 통해 동적으로 생성되었을 가능성이 있어 취약성이 높다고 판단 
    no_formatting = isinstance(node.args[0], ast.Str)
    if no_formatting:
        return "LOW"
    else:
        return "HIGH"

def find_shell_issues(tree, issues):

    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and hasattr(node.func, "value")
            and hasattr(node.func.value, "id")
            and node.func.value.id == "subprocess"
            and hasattr(node.func, "attr")
            and node.func.attr in ["Popen", "call", "check_call", "check_output", "run"]
        ):
            # subprocess 모듈을 사용한 함수 호출이 있을 경우
            if has_shell(node):
                if len(node.args) > 0:
                    sev = _evaluate_shell_call(node)
                    if sev == "LOW":
                        # shell=True가 있지만 안전해 보일 때
                        issues.append(
                            {
                                "line": node.lineno,
                                "severity": "LOW",
                                "content": "CWE-78",
                                "url" : "https://cwe.mitre.org/data/definitions/78.html"
                            }
                        )
                    else:
                        # shell=True이고 보안 문제가 있을 때
                        issues.append(
                            {
                                "line": node.lineno,
                                "severity": "HIGH",
                                "content": "CWE-78",
                                "url" : "https://cwe.mitre.org/data/definitions/78.html"
                            }
                        )
        elif (# os 모듈을 사용한 os.system 함수 호출이 있을 경우
            isinstance(node, ast.Call)
            and hasattr(node.func, "value")
            and hasattr(node.func.value, "id")
            and node.func.value.id == "os"
            and hasattr(node.func, "attr")
            and node.func.attr == "system"
        ):
            
            if has_shell(node):
                issues.append(
                    {
                        "line": node.lineno,
                        "severity": "HIGH",
                        "content": "CWE-78",
                        "url" : "https://cwe.mitre.org/data/definitions/78.html"
                    }
                )
        elif (  # system 함수 호출
            isinstance(node, ast.Call)
            and hasattr(node.func, "id")
            and node.func.id == "system"
            and isinstance(node.func.ctx, ast.Load)
        ):
          
            if has_shell(node):
                issues.append(
                    {
                        "line": node.lineno,
                        "severity": "HIGH",
                        "content": "CWE-78",
                        "url" : "https://cwe.mitre.org/data/definitions/78.html"
                    }
                )
        elif ( #commands
            isinstance(node, ast.Call)
            and hasattr(node.func, "value")
            and hasattr(node.func.value, "id")
            and node.func.value.id == "commands"
            and hasattr(node.func, "attr")
            and node.func.attr in ["getoutput", "getstatusoutput"]
        ):

            if has_shell(node):
                issues.append(
                    {
                        "line": node.lineno,
                        "severity": "HIGH",
                        "content": "CWE-78",
                        "url" : "https://cwe.mitre.org/data/definitions/78.html"
                    }
                )

def _check_command_injection(node):
    """
    Check if a node represents a potentially vulnerable command execution call.
    """
    command_execution_functions = ['call', 'Popen', 'run', 'check_output', 'check_call']
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and 
        node.func.attr in command_execution_functions):
        for arg in node.args:
            if isinstance(arg, (ast.Name, ast.BinOp)):
                return True
    return False

def command_injection_usage(tree, issues):
    """
    Walks through the AST and checks for command injection vulnerabilities.
    """
    for node in ast.walk(tree):
        if _check_command_injection(node):
            issues.append({
                "line": node.lineno,
                "severity": "High",
                "content": "Potential command injection vulnerability detected.",
                "url": "https://owasp.org/www-project-top-ten/2017/A1_2017-Injection"
            })


def CWE_078(tree):
    issues = []

    find_wildcard_injection_issues(tree, issues)
    find_shell_issues(tree, issues)
    command_injection_usage(tree, issues)
    return issues