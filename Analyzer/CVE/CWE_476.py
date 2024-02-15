import ast

def check_null_deref(node, filename):
    """
    Check if an 'if' statement tests whether a variable (filename) is None.
    """
    if isinstance(node.test, ast.Compare):
        if (hasattr(node.test, 'left') and 
            isinstance(node.test.left, ast.Name) and 
            node.test.left.id == filename and 
            hasattr(node.test, 'comparators')):
            for comparator in node.test.comparators:
                if isinstance(comparator, ast.Constant) and comparator.value is None:
                    return True
    return False

def find_get_stmt_usage(tree, issues):
    """
    Find statements of the form filename = request.POST.get('filename') 
    and check for null dereference.
    """
    for node in ast.walk(tree):
        not_none_list = ['user_input', 'filepath', 'filename', 'fname', 'fpath', 'path', 'token', 'session_token', 'auth_token', 'access_token']
        if (isinstance(node, ast.Assign) and len(node.targets) == 1 and
            isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute) and hasattr(node.value.func, 'attr') and 
            node.value.func.attr == 'get') and node.targets[0] in not_none_list:
            filename = node.targets[0].id
            result = False
            for if_node in ast.walk(tree):
                if result:
                    break
                if isinstance(if_node, ast.If):
                    result = check_null_deref(if_node, filename)
            if not result:
                issues.append({
                    "line": node.lineno,
                    "severity": "Low",
                    "content": "Potential null dereference detected.",
                    "url": "https://owasp.org/www-project-top-ten/2017/A1_2017-Injection"
                })

def find_get_eviron_stmt_usage(tree, issues):
    """
    Find statements of the form path = os.environ.get('API_KEY')
    and check for null dereference.
    """
    for node in ast.walk(tree):
        if (isinstance(node, ast.Assign) and len(node.targets) == 1 and
            isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute) and hasattr(node.value.func, 'attr') and
            isinstance(node.value.func, ast.Attribute) and \
       isinstance(node.value.func.value, ast.Attribute) and \
       isinstance(node.value.func.value.value, ast.Name) and \
       node.value.func.value.value.id == 'os' and \
       node.value.func.value.attr == 'environ' and \
       node.value.func.attr == 'get'):
            filename = node.targets[0].id
            result = False
            for if_node in ast.walk(tree):
                if result:
                    break
                if isinstance(if_node, ast.If):
                    result = check_null_deref(if_node, filename)
            if not result:
                issues.append({
                    "line": node.lineno,
                    "severity": "Low",
                    "content": "Potential null dereference detected.",
                    "url": "https://owasp.org/www-project-top-ten/2017/A1_2017-Injection"
                })


def CWE_476(tree):
    """
    Main CWE-476 vulnerability detection function.
    """
    issues = []

    find_get_stmt_usage(tree, issues)
    find_get_eviron_stmt_usage(tree, issues)
    return issues