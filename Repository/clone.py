# Repository clone
import os
import shutil
import subprocess
from urllib.parse import urlparse


def repository_clone(url):
    try:
        repo_name = extract_repo_name(url)
        # 클론 저장 위치 설정
        result_path = f'clone_repo/{repo_name}'
        
        # 디렉토리가 이미 존재하면 삭제
        if os.path.exists(result_path):
            shutil.rmtree(result_path)

        # 디렉토리가 존재하지 않으면 생성
        if not os.path.exists(result_path):
            os.makedirs(result_path)

        repo_url = url
        subprocess.run(['git', 'clone', repo_url, result_path], check=True)
        print("Repository cloned successfully.")
        return result_path, repo_name
    except subprocess.CalledProcessError as e:
        print(f"Error during repository clone: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")


def extract_repo_name(url):
    # Git URL에서 경로(path) 부분을 추출
    path = urlparse(url).path

    # 경로에서 마지막 부분을 추출 (일반적으로 리포지토리의 이름)
    repo_name = os.path.basename(path)

    # ".git" 확장자가 있다면 제거
    if repo_name.endswith('.git'):
        repo_name = repo_name[:-4]

    return repo_name


def delete_repo(directory_path):
    try:
        shutil.rmtree(directory_path)
        print(f"Directory '{directory_path}' and its contents have been successfully deleted.")
    except Exception as e:
        print(f"Error deleting directory '{directory_path}': {e}")
