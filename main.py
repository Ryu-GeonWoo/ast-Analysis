import sys
import json
from jinja2 import Template  # Jinja2를 사용하기 위해 필요한 라이브러리. 설치 필요: pip install Jinja2

from CLI.ASTParser import *
from Repository.clone import *
from controller.code_controller import *
from dir_circulation.find_code import *

# 분석 타입 체크 및 실행
def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <Type> \ntype = url, dir, code")
        sys.exit(1)

    type = str(sys.argv[1]).lower()

    if type == 'url':
        if len(sys.argv) < 3:
            print("Usage: python main.py url <git_url>")
            sys.exit(1)
        git_url = sys.argv[2]
        print(git_url)
        url(git_url)

    elif type == 'dir':
        if len(sys.argv) < 3:
            print("Usage: python main.py dir <Repo_Dir>")
            sys.exit(1)
        dir_path = sys.argv[2]
        dir(dir_path)

    elif type == 'code':
        if len(sys.argv) < 3:
            print("Usage: python main.py code <Python file to analyze>")
            sys.exit(1)
        code_path = sys.argv[2]
        code(code_path)

    elif type == 'list':
        if len(sys.argv) < 3:
            print("Usage: python main.py list <list.txt>")
            sys.exit(1)
        list = sys.argv[2]
        print(list)
        try:
            with open(list, 'r') as file:
                url_list = file.readlines()

            for analyze_url in url_list:
                analyze_url = analyze_url.strip()  # 개행 문자 및 공백 제거
                if analyze_url:
                    url(analyze_url)

        except FileNotFoundError:
            print(f"Error: File '{list}' not found.")
        except Exception as e:
            print(f"Unexpected error: {e}")

    else:
        sys.exit(1)
    
# url을 입력받아 클론후 분석
def url(url):
    repo_path, repo_name = repository_clone(url)
    dir(repo_path, repo_name)
    delete_repo(repo_path)

# repo dir을 입력 받아 분석
def dir(path, name="repo_issue"):
    print("dir :", path)
    issue_result = find_python_code(name, path)
    # JSON 데이터를 circle_log.json 파일로 저장
    save_issue(issue_result, name)
    save_issue_as_html(issue_result, name)

# code path를 입력 받아서 특정 취약점 분석 
def code(code_path):
    issue_result = check_security_issues(code_path)
    # JSON 데이터를 circle_log.json 파일로 저장
    save_issue(issue_result, code_path)

# JSON 데이터를 circle_log.json 파일로 저장
def save_issue(result_data, file_name):
    with open("./result/json/"+file_name+".json", 'w') as json_file:
        json.dump(result_data, json_file, indent=4)

# JSON 데이터를 HTML 파일로 저장
def save_issue_as_html(result_data, file_name):
    # 'template.html'이라는 이름의 HTML 템플릿 파일이 있다고 가정
    with open('Template/template.html', 'r', encoding='utf-8') as template_file:
        template_content = template_file.read()

    # Jinja2를 사용하여 HTML 템플릿을 결과 데이터로 렌더링
    template = Template(template_content)
    rendered_html = template.render(issue_result=result_data)

    # 렌더링된 HTML을 파일로 저장
    with open("./result/html/" + file_name + ".html", 'w', encoding='utf-8') as html_file:
        html_file.write(rendered_html)

if __name__ == "__main__":
    main()