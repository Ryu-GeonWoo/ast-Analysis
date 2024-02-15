import subprocess
from django.shotcuts import render

def execute_command(request):
    date = request.POST.get('data','')

    cmd_str = "cmd /c backuplog.bat" + date
    subprocess.run(cmd_str, shell=True)
    return render(request,'/success.html')
