# An issue was discovered in Python 3.11 through 3.11.4. If a path containing '\0' bytes is passed to os.path.normpath(), the path will be truncated unexpectedly at the first '\0' byte. There are plausible cases in which an application would have rejected a filename for security reasons in Python 3.10.x or earlier, but that filename is no longer rejected in Python 3.11.x.
# CWE-426 Untrusted Search Path
# The product searches for critical resources using an externally-supplied search path that can point to resources that are not under the product's direct control.
# Assigned by: nvd@nist.gov (Primary)

# Looks like posix._path_normpath has slightly different behaviour to the python implementation of normpath defined in posixpath, as such os.path.normpath behaves differently on Python 3.11 (where posix._path_normpath is used if it exists) vs 3.10 on posix systems:

# Python 3.10:

# >>> import os.path
# >>> os.path.normpath('hello\x00world')
# 'hello\x00world'
# >>> os.path.normpath('\x00hello')
# '\x00hello'
# Python 3.11:

# >>> import os.path
# >>> os.path.normpath('hello\x00world')
# 'hello'
# >>> os.path.normpath('\x00hello')
# '.'
# Obviously filepaths shouldn't have nulls in them, but the above means invalid input to a program could result in the wrong files or directories being used, rather than an error about embedded nulls once the filepaths are actually used for a system call. And I'm guessing the inconsistency between Python3.10 and 3.11, or between the Python and C implementations of normpath was not intended in any case.

import ast  

def _check_os_path_normpath(node, issues):
    """
    Heuristically determine if a node might contain a Pathname to a Restricted Directory.
    """
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ['normpath']:
        # Simple check for concatenation in URL
        return True
    elif isinstance(node, ast.JoinedStr):
        # Check for formatted strings
        return any(isinstance(value, ast.FormattedValue) for value in node.values)

    return False
  
def CWE_426(tree):
    issues = []

    _check_os_path_normpath(tree, issues)
    return issues