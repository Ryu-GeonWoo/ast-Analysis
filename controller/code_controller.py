import ast
import os

from controller.check_list import *

# 코드 취약점 분석
def check_security_issues(code_path):
    check_list = CHECK_FUNCTIONS
    all_issues = {}

    try:
        with open(code_path, "r", encoding= "utf-8") as file:
            python_code = file.read()
            tree = ast.parse(python_code)
            
            # cwe 패턴 분석 실시
            for check_function in check_list:
                globals()[check_function.__name__] = check_function

                try:
                    issues = check_function(tree)
                    if issues:
                        for issue in issues:
                            # 고유한 키 생성
                            issue_key = f"{check_function.__name__}_{issue['content']}_{issue['severity']}"

                            if issue_key not in all_issues:
                                all_issues[issue_key] = {
                                    'line': set(),
                                    'severity': issue['severity'],
                                    'content': issue['content'],
                                    'url': issue['url']
                                }
                            # 라인 번호 추가
                            all_issues[issue_key]['line'].add(issue['line'])

                except Exception as e:
                    # 예외 발생 시 해당 함수명과 예외 메시지 출력
                    print({'error': f'An error occurred in {check_function.__name__}: {e}'})

        # 결과 데이터 생성
        result_data = {
            'code_path': code_path,
            'code_name': os.path.basename(code_path),
            'issues': []
        }

        for issue_key, data in all_issues.items():
            function_name, _, _ = issue_key.rsplit('_', 2)
            result_data['issues'].append({
                'function_name': function_name.replace('_', ' ').title(),
                'line': ', '.join(map(str, sorted(data['line']))),
                'severity': data['severity'],
                'content': data['content'],
                'url': data['url']
            })

        return result_data

    except FileNotFoundError:
        print({'error': f'File not found: {code_path}'})
    
    except Exception as e:
        print({'error': f'An error occurred: {e} \ncode : {code_path}'})