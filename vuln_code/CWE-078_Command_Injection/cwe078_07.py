import os
from os import popen
import os as o
from os import popen as pos
import stat

os.system('/bin/echo hi')

keyfile = 'foo'

os.chmod('/etc/passwd', 0o227)
os.chmod('/etc/passwd', 0o7)
os.chmod('/etc/passwd', 0o664)
os.chmod('/etc/passwd', 0o777)
os.chmod('/etc/passwd', 0o770)
os.chmod('/etc/passwd', 0o776)
os.chmod('/etc/passwd', 0o760)
os.chmod('~/.bashrc', 511)
os.chmod('/etc/hosts', 0o777)
os.chmod('/tmp/oh_hai', 0x1ff)
os.chmod('/etc/passwd', stat.S_IRWXU)
os.chmod(keyfile, 0o777)
os.chmod('~/hidden_exec', stat.S_IXGRP)
os.chmod('~/hidden_exec', stat.S_IXOTH)
os.execl(path, arg0, arg1)
os.execle(path, arg0, arg1, env)
os.execlp(file, arg0, arg1)
os.execlpe(file, arg0, arg1, env)
os.execv(path, args)
os.execve(path, args, env)
os.execvp(file, args)
os.execvpe(file, args, env)
os.popen('/bin/uname -av')
popen('/bin/uname -av')
o.popen('/bin/uname -av')
pos('/bin/uname -av')
os.popen2('/bin/uname -av')
os.popen3('/bin/uname -av')
os.popen4('/bin/uname -av')

os.popen4('/bin/uname -av; rm -rf /')
os.popen4(some_var)