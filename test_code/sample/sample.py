#패턴 탐지용 테스트 코드임 eval, insecureSSLTLS, requestTimeOut, HardcodedPassword 에 대한 취약 코드임

import ssl
from pyOpenSSL import SSL

import os

print(eval("1+1"))
print(eval("os.getcwd()"))
print(eval("os.chmod('%s', 0777)" % 'test.txt'))


# A user-defined method named "eval" should not get flagged.
class Test(object):
    def eval(self):
        print("hi")
    def foo(self):
        self.eval()

Test().eval()
exec("do evil")



ssl.wrap_socket(ssl_version=ssl.PROTOCOL_SSLv2)
SSL.Context(method=SSL.SSLv2_METHOD)
SSL.Context(method=SSL.SSLv23_METHOD)

herp_derp(ssl_version=ssl.PROTOCOL_SSLv2)
herp_derp(method=SSL.SSLv2_METHOD)
herp_derp(method=SSL.SSLv23_METHOD)

# strict tests
ssl.wrap_socket(ssl_version=ssl.PROTOCOL_SSLv3)
ssl.wrap_socket(ssl_version=ssl.PROTOCOL_TLSv1)
SSL.Context(method=SSL.SSLv3_METHOD)
SSL.Context(method=SSL.TLSv1_METHOD)

herp_derp(ssl_version=ssl.PROTOCOL_SSLv3)
herp_derp(ssl_version=ssl.PROTOCOL_TLSv1)
herp_derp(method=SSL.SSLv3_METHOD)
herp_derp(method=SSL.TLSv1_METHOD)

ssl.wrap_socket(ssl_version=ssl.PROTOCOL_TLSv1_1)
SSL.Context(method=SSL.TLSv1_1_METHOD)

herp_derp(ssl_version=ssl.PROTOCOL_TLSv1_1)
herp_derp(method=SSL.TLSv1_1_METHOD)


ssl.wrap_socket()

def open_ssl_socket(version=ssl.PROTOCOL_SSLv2):
    pass

def open_ssl_socket(version=SSL.SSLv2_METHOD):
    pass

def open_ssl_socket(version=SSL.SSLv23_METHOD):
    pass

def open_ssl_socket(version=SSL.TLSv1_1_METHOD):
    pass

# this one will pass ok
def open_ssl_socket(version=SSL.TLSv1_2_METHOD):
    pass
    
    
 # Possible hardcoded password: 'class_password'
# Severity: Low   Confidence: Medium
class SomeClass:
    password = "class_password"

# Possible hardcoded password: 'Admin'
# Severity: Low   Confidence: Medium
def someFunction(user, password="Admin"):
    print("Hi " + user)

def someFunction2(password):
    # Possible hardcoded password: 'root'
    # Severity: Low   Confidence: Medium
    if password == "root":
        print("OK, logged in")

def noMatch(password):
    # Possible hardcoded password: ''
    # Severity: Low   Confidence: Medium
    if password == '':
        print("No password!")

def NoMatch2(password):
    # Possible hardcoded password: 'ajklawejrkl42348swfgkg'
    # Severity: Low   Confidence: Medium
    if password == "ajklawejrkl42348swfgkg":
        print("Nice password!")

def noMatchObject():
    obj = SomeClass()
    # Possible hardcoded password: 'this cool password'
    # Severity: Low   Confidence: Medium
    if obj.password == "this cool password":
        print(obj.password)

# Possible hardcoded password: 'blerg'
# Severity: Low   Confidence: Medium
def doLogin(password="blerg"):
    pass

def NoMatch3(a, b):
    pass

# Possible hardcoded password: 'blerg'
# Severity: Low   Confidence: Medium
doLogin(password="blerg")

# Possible hardcoded password: 'blerg'
# Severity: Low   Confidence: Medium
password = "blerg"

# Possible hardcoded password: 'blerg'
# Severity: Low   Confidence: Medium
d["password"] = "blerg"

# Possible hardcoded password: 'secret'
# Severity: Low   Confidence: Medium
EMAIL_PASSWORD = "secret"

# Possible hardcoded password: 'emails_secret'
# Severity: Low   Confidence: Medium
email_pwd = 'emails_secret'

# Possible hardcoded password: 'd6s$f9g!j8mg7hw?n&2'
# Severity: Low   Confidence: Medium
my_secret_password_for_email = 'd6s$f9g!j8mg7hw?n&2'

# Possible hardcoded password: '1234'
# Severity: Low   Confidence: Medium
passphrase='1234'


import requests
import not_requests

requests.get('https://gmail.com')
requests.get('https://gmail.com', timeout=None)
requests.get('https://gmail.com', timeout=5)
requests.post('https://gmail.com')
requests.post('https://gmail.com', timeout=None)
requests.post('https://gmail.com', timeout=5)
requests.put('https://gmail.com')
requests.put('https://gmail.com', timeout=None)
requests.put('https://gmail.com', timeout=5)
requests.delete('https://gmail.com')
requests.delete('https://gmail.com', timeout=None)
requests.delete('https://gmail.com', timeout=5)
requests.patch('https://gmail.com')
requests.patch('https://gmail.com', timeout=None)
requests.patch('https://gmail.com', timeout=5)
requests.options('https://gmail.com')
requests.options('https://gmail.com', timeout=None)
requests.options('https://gmail.com', timeout=5)
requests.head('https://gmail.com')
requests.head('https://gmail.com', timeout=None)
requests.head('https://gmail.com', timeout=5)

# Okay
not_requests.get('https://gmail.com')