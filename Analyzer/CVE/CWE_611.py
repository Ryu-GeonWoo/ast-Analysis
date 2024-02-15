import ast

def CWE_611(tree):
    """
    Main CWE-611 vulnerability detection function.
    """
    issues = []

    xmlparser_usage(tree, issues)
    return issues
    

def xmlparser_usage(tree, issues):
    for node in ast.walk(tree):
        # XMLParser 사용 여부 체크
        if (isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute)
            and isinstance(node.value.func.value, ast.Attribute)
            and isinstance(node.value.func.value.value, ast.Name)
            and node.value.func.value.value.id == 'lxml'
            and node.value.func.value.attr == 'etree'
            and node.value.func.attr == 'XMLParser'
        ):
            resolve_entities_present = False
            for keyword in node.value.keywords:
                if (isinstance(keyword, ast.keyword)
                    and keyword.arg == 'resolve_entities'
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is False
                ): 
                    resolve_entities_present = True
                    break
            
            # If resolve_entities=False is not present, add to issues
            if not resolve_entities_present:
                issues.append({
                    "line": node.lineno,
                    "severity": "High",
                    "content": "Potential vulnerability found at line " + str(node.lineno),
                    "url": "https://cwe.mitre.org/data/definitions/611.html",
                })
            
