import ast
import astor
import builtins

class RenameVariables(ast.NodeTransformer):
    def __init__(self):
        self.var_counter = 1
        self.var_map = {}
        self.builtins = set(dir(builtins))  # 내장 함수 및 상수 목록

    def visit_FunctionDef(self, node):
        # 함수 정의 내부에서의 변수 이름을 지역적으로 치환
        old_var_map = self.var_map.copy()
        self.generic_visit(node)
        self.var_map = old_var_map
        return node

    def visit_Assign(self, node):
        # 변수 할당 시 변수 이름 치환
        self.generic_visit(node)
        for target in node.targets:
            if isinstance(target, ast.Name):
                if target.id not in self.builtins and target.id not in self.var_map:
                    new_name = f"V{self.var_counter}_{target.id}"
                    self.var_map[target.id] = new_name
                    self.var_counter += 1
                target.id = self.var_map.get(target.id, target.id)
        return node

    def visit_Name(self, node):
        # 변수 사용 시 이름 치환
        if isinstance(node.ctx, (ast.Store, ast.Load)) and node.id not in self.builtins:
            if node.id not in self.var_map:
                new_name = f"V{self.var_counter}_{node.id}"
                self.var_map[node.id] = new_name
                self.var_counter += 1
            node.id = self.var_map[node.id]
        return node

    def visit_Call(self, node):
        # 함수 호출 시 인자들에 대한 방문 (함수 이름은 치환하지 않음)
        for arg in node.args:
            self.visit(arg)
        return node

def rename_variables_in_file(input_file_path, output_file_path):
    with open(input_file_path, 'r') as file:
        code = file.read()

    tree = ast.parse(code)
    RenameVariables().visit(tree)
    new_code = astor.to_source(tree)

    with open(output_file_path, 'w') as file:
        file.write(new_code)
