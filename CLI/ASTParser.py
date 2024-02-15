import ast
import json
import sys

# ast tree create
def ast_python_file(filename):
    """ Parse a Python file into an AST using ast. """
    with open(filename, 'r') as file:
        code = file.read()
    return ast.parse(code)

# ast dictionary transfer
def ast_to_dict(node):
    """ Recursively convert an ast node into a dictionary. """
    if isinstance(node, ast.AST):
        result = {'_nodetype': type(node).__name__}
        # Convert node fields
        for field in node._fields:
            value = getattr(node, field, None)
            result[field] = ast_to_dict(value)
        # Include line number and column offset if available
        if hasattr(node, 'lineno'):
            result['lineno'] = node.lineno
        if hasattr(node, 'col_offset'):
            result['col_offset'] = node.col_offset
        return result
    elif isinstance(node, list):
        return [ast_to_dict(child) for child in node]
    else:
        return node

# ast to json
def to_json(node):
    """ Convert ast node to JSON string. """
    return json.dumps(ast_to_dict(node), indent=4)

# Main execution
if __name__ == "__main__":
    if len(sys.argv) > 1:
        ast_tree = ast_python_file(sys.argv[1])
        json_output = to_json(ast_tree)
        
        output_filename = 'ASToutput.json'
        
        with open(output_filename, 'w') as file:
            file.write(json_output)
        print(f"AST JSON saved to {output_filename}")
    else:
        print("Please provide a Python filename as an argument.")
