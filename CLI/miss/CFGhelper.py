import ast
import networkx as nx
import json

class CFGCreator:
    def __init__(self):
        self.graph = nx.DiGraph()
        self.last_node = None
        self.counter = 0

    def add_node(self, node, label=None):
        name = f"node{self.counter}"
        label = label or (str(node) if not isinstance(node, ast.AST) else node.__class__.__name__)
        self.graph.add_node(name, label=label)
        if self.last_node is not None:
            self.graph.add_edge(self.last_node, name)
        self.last_node = name
        self.counter += 1
        return name

    def visit(self, node):
        """ Visit a node. """
        if isinstance(node, ast.AST):
            method = 'visit_' + node.__class__.__name__
            visitor = getattr(self, method, self.generic_visit)
            return visitor(node)
        elif isinstance(node, list):
            for item in node:
                self.visit(item)

    def generic_visit(self, node):
        """ Called if no explicit visitor function exists for a node. """
        node_name = node.__class__.__name__
        self.add_node(node_name)

        for field, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    self.visit(item)
            elif isinstance(value, ast.AST):
                self.visit(value)

    # Define specific visit methods for different AST node types as needed
    # Example:
    # def visit_If(self, node):
    #     ...

    def save_cfg_to_json(self, output_json_path):
        """ Save the CFG to a JSON file. """
        graph_data = {
            "nodes": [],
            "edges": []
        }
        for node, data in self.graph.nodes(data=True):
            graph_data["nodes"].append({"id": node, "label": data.get("label", "")})
        for u, v in self.graph.edges():
            graph_data["edges"].append({"from": u, "to": v})

        with open(output_json_path, 'w') as file:
            json.dump(graph_data, file, indent=4)

            json.dump(graph_data, file, indent=4)

# def __init__(self):
#     self.graph = nx.DiGraph()
#     self.last_node = None
#     self.counter = 0

# def add_node(self, node, label=None):
#     name = f"node{self.counter}"
#     self.graph.add_node(name, label=label or node)
#     if self.last_node is not None:
#         self.graph.add_edge(self.last_node, name)
#     self.last_node = name
#     self.counter += 1
#     return name

# def visit(self, node):
#     if isinstance(node, ast.AST):
#         return visit(node)
#     elif isinstance(node, list):
#         for item in node:
#             self.visit(item)

# def generic_visit(self, node):
#     node_name = type(node).__name__
#     self.add_node(node_name)
#     generic_visit(node)

# # "If" 구문을 방문하는 메소드를 오버라이드
# def visit_If(self, node):
#     # "If" 조건에 대한 노드 생성
#     condition_node = self.add_node('IfCondition', label=f'if {astor.to_source(node.test).strip()}')
#     # "If" 본문을 방문하기 전에 마지막 노드를 기억
#     last_node_before_if = self.last_node
#     # "If" 구문의 본문 방문
#     for body_item in node.body:
#         self.visit(body_item)
#     # 본문을 방문한 후, 본문의 마지막 노드를 조건 노드에 다시 연결
#     self.graph.add_edge(self.last_node, condition_node)
#     # "else" 부분 처리
#     if node.orelse:
#         # "else"를 방문하기 전에 마지막 노드를 조건 노드로 재설정
#         self.last_node = last_node_before_if
#         else_node = self.add_node('Else', label='else')
#         self.graph.add_edge(condition_node, else_node)
#         for else_item in node.orelse:
#             self.visit(else_item)
#         # "else"의 마지막 노드를 조건 노드에 연결
#         self.graph.add_edge(self.last_node, condition_node)
#     # 마지막 노드를 조건 노드로 재설정
#     self.last_node = condition_node
# def visit_While(self, node):
#     # "While" 조건에 대한 노드 생성
#     condition_node = self.add_node('WhileCondition', label=f'while {astor.to_source(node.test).strip()}')
#     # "While" 본문을 방문하기 전에 마지막 노드를 기억
#     last_node_before_while = self.last_node
#     # "While" 구문의 본문 방문
#     for body_item in node.body:
#         self.visit(body_item)
#     # 본문을 방문한 후, 본문의 마지막 노드를 조건 노드에 다시 연결
#     self.graph.add_edge(self.last_node, condition_node)
#     # 마지막 노드를 조건 노드로 재설정
#     self.last_node = condition_node

# def visit_For(self, node):
#     # "For" 반복에 대한 노드 생성
#     for_node = self.add_node('ForLoop', label=f'for {astor.to_source(node.target).strip()} in {astor.to_source(node.iter).strip()}')
#     # "For" 본문을 방문하기 전에 마지막 노드를 기억
#     last_node_before_for = self.last_node
#     # "For" 구문의 본문 방문
#     for body_item in node.body:
#         self.visit(body_item)
#     # 본문을 방문한 후, 본문의 마지막 노드를 "For" 노드에 다시 연결
#     self.graph.add_edge(self.last_node, for_node)
#     # 마지막 노드를 "For" 노드로 재설정
#     self.last_node = for_node

# def visit_Assign(self, node):
#     # 변수 할당 추적
#     self.generic_visit(node)

#     # 할당 연산 노드 추가
#     assign_node = self.add_node('Assign', label=f'Assign to {astor.to_source(node.targets[0]).strip()}')
#     self.graph.add_edge(self.last_node, assign_node)
#     self.last_node = assign_node

#     # 할당되는 값에 대한 처리 (예: 연산, 함수 호출 등)
#     value_node = self.add_node('Value', label=f'Value: {astor.to_source(node.value).strip()}')
#     self.graph.add_edge(assign_node, value_node)
#     self.last_node = value_node

# def visit_Name(self, node):
#     # 변수 사용 추적
#     if isinstance(node.ctx, ast.Load):
#         # 변수 사용 위치 추가
#         use_node = self.add_node('VarUse', label=f'Use {node.id}')
#         self.graph.add_edge(self.last_node, use_node)
#         self.last_node = use_node
#     # 기타 컨텍스트 처리
#     self.generic_visit(node)

# def visit_FunctionDef(self, node):
#     # 함수 정의 노드 추가
#     func_node = self.add_node('FunctionDef', label=f'Function {node.name}')
#     self.graph.add_edge(self.last_node, func_node)
#     self.last_node = func_node

#     # 매개변수 처리
#     for arg in node.args.args:
#         arg_node = self.add_node('Param', label=f'Param {arg.arg}')
#         self.graph.add_edge(func_node, arg_node)

#     # 함수 본문 처리
#     for item in node.body:
#         self.visit(item)

# def visit_Return(self, node):
#     # Return 문 노드 추가
#     return_node = self.add_node('Return', label='Return')
#     self.graph.add_edge(self.last_node, return_node)
#     self.last_node = return_node

#     # Return 값 처리
#     if node.value:
#         return_value_node = self.add_node('ReturnValue', label=f'Return {astor.to_source(node.value).strip()}')
#         self.graph.add_edge(return_node, return_value_node)
#         self.last_node = return_value_node



# def save_cfg_to_json(self, output_json_path):
#     graph_data = {
#         "nodes": [],
#         "edges": []
#     }
#     for node, data in self.graph.nodes(data=True):
#         graph_data["nodes"].append({"id": node, "label": data.get("label", "")})
#     for u, v in self.graph.edges():
#         graph_data["edges"].append({"from": u, "to": v})

#     with open(output_json_path, 'w') as file:
#         json.dump(graph_data, file, indent=4)
        
# 사용 예시
input_path = './example/test_if.py'
output_code_path = './results/test_if_result/test_if_result.py'
output_json_path = './results/test_if_result/test_if_result.json'
output_image_path = './results/test_if_result/if_variable_usage.png'
output_graph_path = './results/test_if_result/test_if_graph.json'