import ast
import json

def default(self, obj):
        if isinstance(obj, ast.AST):
            fields = {'_type': obj.__class__.__name__}
            fields.update({k: self.default(v) for k, v in ast.iter_fields(obj)})
            return fields
        elif isinstance(obj, list):
            return [self.default(item) for item in obj]
        return obj
    
    