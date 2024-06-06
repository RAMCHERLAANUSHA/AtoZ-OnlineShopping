from django.shortcuts import render
from django.shortcuts import redirect
from django.contrib.auth.models import User as Admin
from django.contrib.auth.hashers import check_password
from django.urls import reverse

# Create your views here.

def validate_mobile_number(value):
    value = str(value)
    if not value.isdigit() or len(value) != 10:
        return False
    return True

def validate_password(password):
    if len(password) < 8:
        return False

    if not any(char.isupper() for char in password):
        return False

    if not any(char.islower() for char in password):
        return False

    if not any(char.isdigit() for char in password):
        return False

    special_characters = "!@#$%^&*()_+[]{}|;:,.<>?/~`"
    if not any(char in special_characters for char in password):
        return False
    
    return True

def adminLogin(request):
    context = {}
    context["comment"] = ''
    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")
        try:
            a1 = Admin.objects.get(email=email)
            if check_password(password,a1.password):
                return redirect('/adminList/')
            else:
                context["comment"] = "Incorrect password.."
                return render(request,'AdminLogin.html', context)
        except:
            context["comment"] = "Admin not found.."
            return render(request,'AdminLogin.html', context)
    return render(request,'AdminLogin.html')
