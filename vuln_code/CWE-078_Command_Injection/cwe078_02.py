import subprocess

def execute_command(user_input):
    # 사용자 입력을 그대로 명령어에 삽입 (취약점이 있는 코드)
    result = subprocess.check_output("echo " + user_input, shell=True)
    return result

# 사용자 입력을 받아 명령어 실행
user_input = input("Enter a value: ")
output = execute_command(user_input)
print("Output:", output.decode())

