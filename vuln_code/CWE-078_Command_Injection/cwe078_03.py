import os
from django.shrotcuts import render

def execute_command(request):
    app_name_string = request.POST.get('app_name','');

    os.system(app_name_string)
    return render(request,'/success.html')
