from flask import Flask, request, make_response, escape

app = Flask(__name__)

@app.route('/unsafe')
def unsafe():
    first_name = request.args.get('name', '')
    return make_response("Your name is " + first_name)


from django.http import HttpResponse
from django.shortcuts import render

def vulnerable_view(request):
    # 사용자 입력을 검증하지 않고 직접 사용
    user_input = request.GET.get('input', '')

    # 이 입력값을 응답에 그대로 포함 (XSS 취약점)
    response = HttpResponse(f"<html><body><h1>Your Input:</h1><p>{user_input}</p></body></html>")

    return response