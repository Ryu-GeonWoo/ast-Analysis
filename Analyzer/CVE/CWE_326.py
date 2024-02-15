# CWE-326: Inadequate Encryption Strength
# https://cwe.mitre.org/data/definitions/326.html
import ast

def _classify_key_size(config, key_type, key_size, lineno):
    if isinstance(key_size, str):
        return None

    key_sizes = {
        "DSA": [
            (config["weak_key_size_dsa_high"], "High"),
            (config["weak_key_size_dsa_medium"], "Medium"),
        ],
        "RSA": [
            (config["weak_key_size_rsa_high"], "High"),
            (config["weak_key_size_rsa_medium"], "Medium"),
        ],
        "EC": [
            (config["weak_key_size_ec_high"], "HIGH"),
            (config["weak_key_size_ec_medium"], "Medium"),
        ],
    }

    for size, severity in key_sizes[key_type]:
        if key_size < size:
            return {
                "line":lineno,
                "severity": severity,
                "content": f"{key_type} key sizes below {size} bits are considered breakable.",
                "url": "https://cwe.mitre.org/data/definitions/326.html"
            }
    return None

def check_weak_crypto_key(node, config):
    func_key_type1 = { #cyptography_io
        "cryptography.hazmat.primitives.asymmetric.dsa.generate_private_key": "DSA",
        "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key": "RSA",
        "cryptography.hazmat.primitives.asymmetric.ec.generate_private_key": "EC",
        "dsa.generate_private_key": "DSA",
        "rsa.generate_private_key": "RSA",
        "ec.generate_private_key": "EC",
    }
    
    func_key_type2 = { #pycrypto
        "Crypto.PublicKey.DSA.generate": "DSA",
        "Crypto.PublicKey.RSA.generate": "RSA",
        "Cryptodome.PublicKey.DSA.generate": "DSA",
        "Cryptodome.PublicKey.RSA.generate": "RSA",
        "DSA.generate": "DSA",
        "RSA.generate": "RSA",
    }
    
    curve_key_sizes = {
        "SECT571K1": 571, "SECT571R1": 570, "SECP521R1": 521,
        "BrainpoolP512R1": 512, "SECT409K1": 409, "SECT409R1": 409,
        "BrainpoolP384R1": 384, "SECP384R1": 384, "SECT283K1": 283,
        "SECT283R1": 283, "BrainpoolP256R1": 256, "SECP256K1": 256,
        "SECP256R1": 256, "SECT233K1": 233, "SECT233R1": 233,
        "SECP224R1": 224, "SECP192R1": 192, "SECT163K1": 163,
        "SECT163R2": 163,
    }

    key_size_arg = None  

    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        # 'node.func.id' 대신 'node.func.attr'을 사용하도록 수정
        func_name = f"{node.func.value.id}.{node.func.attr}" if isinstance(node.func.value, ast.Name) else node.func.attr
        key_type1 = func_key_type1.get(func_name)
        key_type2 = func_key_type2.get(func_name) 
        
        if key_type1:
            # EC
            if key_type1 == "EC":
                curve_name_arg = node.args[0] if node.args else None  
                if curve_name_arg and isinstance(curve_name_arg, ast.Call):
                    curve_func_name = f"{curve_name_arg.func.attr}"
                    key_size = curve_key_sizes.get(curve_func_name, None)
                    if key_size:
                        return _classify_key_size(config, key_type1, key_size, node.lineno)

            # DSA or RSA 
            elif key_type1 in ["DSA", "RSA"]:
                for kw in node.keywords:
                    if kw.arg == 'key_size':
                        key_size_arg = kw.value
                if key_size_arg is None and node.args:
                    key_size_arg = node.args[0]

                if key_size_arg and isinstance(key_size_arg, ast.Constant) and isinstance(key_size_arg.value, int):
                    return _classify_key_size(config, key_type1, key_size_arg.value, node.lineno)
                
        # pycrypto or Cryptodome
        if key_type2:
            if key_type2 in ["DSA", "RSA"]:
                key_size_arg = node.args[0] if node.args else None
                if key_size_arg and isinstance(key_size_arg, ast.Constant) and isinstance(key_size_arg.value, int):
                    return _classify_key_size(config, key_type2, key_size_arg.value, node.lineno)

    return None


def WeakCryptographicKeyChecker(tree, issues):
    config = {
        "weak_key_size_dsa_high": 1024,
        "weak_key_size_dsa_medium": 2048,
        "weak_key_size_rsa_high": 1024,
        "weak_key_size_rsa_medium": 2048,
        "weak_key_size_ec_high": 160,
        "weak_key_size_ec_medium": 224,
    }
    
    for node in ast.walk(tree):
        issue = check_weak_crypto_key(node, config)
        if issue:
            issues.append(issue)
            

def CWE_326(tree):
    issues = []

    WeakCryptographicKeyChecker(tree, issues)
    return issues