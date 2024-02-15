import ast
import json


def __init__(self):
        self.var_counter = 1
        self.var_map = {}  # 변수 이름 맵
        self.var_usage = {}  # 변수 사용 추적
        self.builtins = set(dir(__builtins__))  # 내장 함수 및 상수 목록

def visit_FunctionDef(self, node):
        # 함수 매개변수도 치환 대상에서 제외
        self.var_map = {arg.arg: arg.arg for arg in node.args.args}
        self.generic_visit(node)
        return node

# 변수 할당 추적
def visit_Assign(self, node):
        self.generic_visit(node)
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = self.var_map.get(target.id, target.id)
                self.var_usage[var_name] = self.var_usage.get(var_name, []) + ['assigned']
        return node
    
def visit_Call(self, node):
        # 함수 호출에서 함수 이름은 치환하지 않음
        if isinstance(node.func, ast.Name):
            if node.func.id in self.builtins:
                # 내장 함수 호출은 노드 이름을 그대로 유지
                return node
        self.generic_visit(node)
        return node

def visit_If(self, node):
    self.generic_visit(node)
    return node

def visit_While(self, node):
    self.generic_visit(node)
    return node

def visit_For(self, node):
    self.generic_visit(node)
    return node