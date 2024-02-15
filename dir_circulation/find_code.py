import os
import json
from controller.code_controller import check_security_issues
from dir_circulation.error_check import log_error

# 파이썬 파일을 읽어들일 때 에러 발생시 로깅하는 함수
# 예를들어 아래 경로의 파일처럼 .py로 끝나지만 파일이 화살표 폴더 형태로 저장되어 있을 경우 에러 발생
# https://github.com/streamlit/streamlit/tree/develop/e2e_flaky/scripts
# 또는 파이썬으로 실행할 수 없는 UTF8이 아닌 다른 형태의 인코딩 형식의 .py 파일인 경우 에러 처리


def analyze_python_file(file_path):
    try:
        # python code 분석 하기]
        return check_security_issues(file_path)
    except Exception as e:
        log_error(file_path, e)  # 오류 로깅
        print(f"Error processing file {file_path}: {e}")
        return None


def find_python_code(name, base_path='clone_repo' ):
    name = name
    repo_files = {}
    repo_issue = {}
    # JSON 파일 위함
    result_data = {
        'repo_path': base_path,  # repo 경로
        'code': []             # code 별 이슈
    }

    # base_path 내의 모든 파일에 대하여 순회
    for root, dirs, files in os.walk(base_path):
        python_files = []

        # 현재 디렉토리 내의 모든 파일에 대하여 순회
        for file in files:
            # 파이썬 파일인 경우 해당 파일에 대해 코드 분석 함수 호출
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                issue = analyze_python_file(file_path)
                if issue is not None:
                    # 상대 경로로 변경
                    python_files.append(os.path.relpath(file_path, base_path))
                    # 파일 이름을 key로 사용하지 않고 상대 경로를 사용
                    repo_issue[os.path.relpath(file_path, base_path)] = issue

        # 현재 디렉토리에 대한 파이썬 파일 경로를 json 로그로 저장
        if python_files:
            repo_name = os.path.relpath(root, base_path)
            repo_files[repo_name] = python_files

    # 코드에 대한 이슈 정보를 result_data에 추가
    result_data['code'] = repo_issue

    # 전체적으로 순회한 레포지토리 - 파이썬 파일 경로 json 데이터로 저장
    json_data = json.dumps(repo_files, indent=4)

    # JSON 데이터를 circle_log.json 파일로 저장
    with open(f'./path/{name}.json', 'w') as json_file:
        json_file.write(json_data)

    return remove_empty_issues(result_data)

# issue가 없는 결과 삭제
def remove_empty_issues(data):
    result_data = {
        "repo_path": data["repo_path"],
        "code": {}
    }

    for file_path, file_data in data["code"].items():
        if file_data["issues"]:
            result_data["code"][file_path] = file_data

    return result_data
