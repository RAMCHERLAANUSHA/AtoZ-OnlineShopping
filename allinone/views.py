from django.shortcuts import render
from django.shortcuts import redirect
from django.contrib.auth.models import User as Admin
from django.contrib.auth.hashers import check_password
from django.core.mail import send_mail
from .models import *
from .forms import *
from django.contrib.auth.hashers import make_password
from django.http import JsonResponse


# =================================================HomeView=============================================================

def homeView(request):
    return render(request, 'HomePage.html')

# ================================================Validations===========================================================

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

# ===============================================Forgot Password(OTP)===================================================

def send_otp_email(email):
    otp_code = generate_otp()  

    otp_instance = OTP.objects.create(email=email, otp=otp_code)

    subject = 'Your A to Z Shopping verification code'
    message = f"""
    Hi {email},

    We received a request to access your A to Z Shopping Account {email} through your email address. Your verification code is:

    {otp_code}

    If you did not request this code, it is possible that someone else is trying to access the Account {email}. Do not forward or give this code to anyone.

    Sincerely yours,

    A to Z Online Shopping team
    """
    from_email = 'A to Z Online Shopping team'
    to_email = [email]
    send_mail(subject, message, from_email, to_email, fail_silently=False)

def password_reset_request(request):
    if request.method == 'POST':
        form = EmailForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data.get('email')
            
            user_emails = list(User.objects.values_list('email', flat=True))
            admin_emails = list(Admin.objects.values_list('email', flat=True))
            seller_emails = list(Seller.objects.values_list('email', flat=True))
            
            all_emails = user_emails + admin_emails + seller_emails
            user_type = None

            if email in user_emails:
                user_type = 'user'
            elif email in admin_emails:
                user_type = 'admin'
            elif email in seller_emails:
                user_type = 'seller'
            
            if user_type:
                send_otp_email(email)
                request.session['email'] = email
                request.session['user_type'] = user_type
                return redirect('validate_otp')
            else:
                comment = "No user found with this email address."
        else:
            comment = "Invalid form data. Please check your input."
    else:
        form = EmailForm()
        comment = ''
    
    context = {
        'form': form,
        'comment': comment,
    }
    return render(request, 'ForgotPassword.html', context)

def validate_otp(request):
    context = {}
    context["comment"] = ''
    if request.method == 'POST':
        form = OTPForm(request.POST)
        if form.is_valid():
            otp_entered = form.cleaned_data.get('otp')
            email = request.session.get('email')
                        
            if not email:
                context['comment'] = 'Email not found in session. Please request OTP again.'
                form = OTPForm()
                context['form'] = form
                return render(request, 'ValidateOtp.html', context)
            
            try:
                otp_record = OTP.objects.get(email=email, otp=otp_entered)
                
                if otp_record.is_valid():
                    request.session['otp_valid'] = True
                    return redirect('password_reset_complete')
                else:
                    context['comment'] = 'Invalid or expired OTP. Please try again.'
            except OTP.DoesNotExist:
                context['comment'] = 'Invalid OTP. Please enter a valid OTP.'
    else:
        form = OTPForm()
    
    context['form'] = form
    return render(request, 'ValidateOtp.html', context)

def password_reset_complete(request):
    context = {}
    context["comment"] = ''
    user_type = request.session.get('user_type')
    email = request.session.get('email')
    
    if not user_type or not email:
        context['comment'] = 'Session expired or invalid. Please request password reset again.'
        return redirect('password_reset_request')
    
    if request.method == 'POST':
        form = PasswordResetForm(request.POST)
        context["form"] = form
        
        if form.is_valid():
            new_password = form.cleaned_data.get('new_password')
            confirm_password = form.cleaned_data.get('confirm_password')

            if new_password != confirm_password:
                context["comment"] = 'Passwords do not match.'
            else:
                try:
                    if user_type == 'admin':
                        user = Admin.objects.get(email=email)
                    elif user_type == 'seller':
                        user = Seller.objects.get(email=email)
                    else:
                        user = User.objects.get(email=email)

                    if user_type == 'admin':
                        user.set_password(new_password)
                    else:
                        user.password = make_password(new_password)
                    user.save()
                    context["success"] = True
                    context["user_type"] = user_type
                    return render(request, 'ResetCompletion.html', context)
                
                except (Admin.DoesNotExist, Seller.DoesNotExist, User.DoesNotExist):
                    context["comment"] = 'User not found.'
        
        else:
            context["comment"] = 'Form is not valid.'
    
    else:
        form = PasswordResetForm()
        context["form"] = form

    return render(request, 'ResetCompletion.html', context)

# ==============================================Admin-Login============================================================

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

# =================================================Admin-List==========================================================

def admin_list(request):
    items = Item.objects.exclude(itemaccess__isnull=False)
    if request.method == 'POST':
        item_id = request.POST.get('item_id')
        action = request.POST.get('action')
        
        try:
            item = Item.objects.get(id=item_id)
        except Item.DoesNotExist:
            item = None
        
        if item and action:
            if action == 'access':
                access_status = True
                comment = 'Access granted'
            elif action == 'deny':
                access_status = False
                comment = 'Access denied'
            item_access, created = ItemAccess.objects.update_or_create(
                item_id=item,
                defaults={'access': access_status, 'comment': comment}
            )
            items = items.exclude(id=item.id)
            
            return JsonResponse({'message': f'Item {action}ed successfully.'}, status=200)
        
    context = {
        'items': items,
        'form': ItemAccessForm(),
    }
    return render(request, 'AdminProducts.html', context)

def add_category(request):
    context = {}
    if request.method == 'POST':
        form = AdminCategoryForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            context['comment'] = 'Category added successfully.'
        else:
            context['comment'] = 'Category already exists.'
    categories = AdminCategory.objects.all()
    context['form'] = AdminCategoryForm
    context['categories'] = categories
    return render(request, 'AddCategory.html', context)

def category_delete(request, category_id):
    category = AdminCategory.objects.get(id=category_id)
    category.delete()
    return redirect('add_category')

def message_list(request):
    messages = Message.objects.all()
    context = {
        'messages': messages,
    }
    return render(request, 'MessageList.html', context)

#===========================================Seller-SignIn-SignUp-Update=================================================

def seller_signup(request):
    context = {}
    context['form'] = SellerForm()
    context['data'] = ''
    if request.method == 'POST':
        if not  validate_mobile_number(request.POST.get("phoneNumber")) and not validate_password(request.POST.get("password")):
            context['data'] = "Please enter a 10-digit mobile number and Password should contain 8 characters and at least one special character,one uppercase letter,one lowercase letter and one digit."
            return render(request,'SellerSignup.html',context)
        elif not validate_password(request.POST.get("password")):
            context['data'] = "Password should contain 8 characters and at least one special character,one uppercase letter,one lowercase letter and one digit."
            return render(request,'SellerSignup.html',context)
        elif not  validate_mobile_number(request.POST.get("phoneNumber")):
            context['data'] = "Please enter a 10 digit mobile number"
            return render(request,'SellerSignup.html',context)
        form = SellerForm(request.POST,request.FILES)
        if form.is_valid():
            form.save()
            context['data']=f"{request.POST.get('name')} registered succefully"
            return render(request,'SellerSignup.html',context)
        else:
            context['data'] = "Something wrong in given data"
            return render(request,'SellerSignup.html',context)
    return render(request,'SellerSignup.html',context)

def seller_signin(request):
    context = {}
    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")
        try:
            seller = Seller.objects.get(email=email)
            if password == seller.password:
                return redirect('/seller_itemform/{0}'.format(seller.id))
            else:
                context["comment"] = "Incorrect password."
        except Seller.DoesNotExist:
            context["comment"] = "Seller not found."
    return render(request, 'SellerSignin.html', context)

def seller_update(request,id):
    context = {}
    seller = Seller.objects.get(id=id)
    context['form'] = SellerForm(request.POST or None, instance=seller)
    context['data'] = ''
    context['btval'] = 'Update'
    if request.method == 'POST':
        if not  validate_mobile_number(request.POST.get("phoneNumber")) and not validate_password(request.POST.get("password")):
            context['data'] = "Please enter a 10-digit mobile number and Password should contain 8 characters and at least one special character,one uppercase letter,one lowercase letter and one digit."
            return render(request,'SellerSignup.html',context)
        elif not validate_password(request.POST.get("password")):
            context['data'] = "Password should contain 8 characters and at least one special character,one uppercase letter,one lowercase letter and one digit."
            return render(request,'SellerSignup.html',context)
        elif not  validate_mobile_number(request.POST.get("phoneNumber")):
            context['data'] = "Please enter a 10 digit mobile number"
            return render(request,'SellerSignup.html',context)
        form = SellerForm(request.POST,request.FILES,instance=seller)
        if form.is_valid():
            form.save()
            context['data']= "details updated successfully"
            return redirect('/seller_itemform/{0}'.format(seller.id))
        else:
            context['data'] = "Something wrong in given data"
            return render(request,'SellerSignup.html',context)
    return render(request,'SellerSignup.html',context)

# ==========================================Seller-List=================================================================

def seller_itemform(request,id):
    context = {}
    seller = Seller.objects.get(id=id)
    if request.method == 'POST':
        form = ItemForm(request.POST, request.FILES)
        if form.is_valid():
           item = form.save(commit=False)
           item.seller = seller
           item.save()  
           context['comment'] = 'Item added successfully.'
        #    return redirect('seller_itemform', id=id)
        else:
            context['comment'] = 'Something went wrong.'
            # return redirect('seller_itemform', id=id)
    else:
        form = ItemForm()

    context['form'] = form
    context['seller'] = seller
    return render(request, 'AddItem.html', context)

def seller_products(request,id):
    context = {}
    seller = Seller.objects.get(id=id)
    items = Item.objects.all()
    context['seller'] = seller
    context['items'] = items
    return render(request, 'SellerProducts.html', context)

def seller_product_delete(request, item_id):
    item = Item.objects.get(id=item_id)
    seller_id = item.seller.id
    item.delete()
    return redirect('/seller_products/' + str(seller_id))

def seller_messages(request,id):
    context = {}
    seller = Seller.objects.get(id=id)
    messages = ItemAccess.objects.all()
    if request.method == 'POST':
        form = MessageForm(request.POST)
        if form.is_valid():
            item = form.save(commit=False)
            item.seller = seller
            item.save() 
            context['comment']='Message Sent Successfully'
        else:
            context['comment']='Something went Wrong'
    context['seller'] = seller
    context['messages'] = messages
    context['form'] = MessageForm
    return render(request, 'SellerMessages.html', context)

def seller_orders(request, seller_id):
    seller = Seller.objects.get(id=seller_id)
    orders = Order.objects.filter(item__seller=seller)
    context = {
        'seller': seller,
        'orders': orders,
    }
    return render(request, 'SellerOrders.html', context)

# ====================================User-SignIn-SignUp-Update=========================================================

def user_signup(request):
    context = {}
    context['form'] = UserForm()
    context['data'] = ''
    if request.method == 'POST':
        if not  validate_mobile_number(request.POST.get("phoneNumber")) and not validate_password(request.POST.get("password")):
            context['data'] = "Please enter a 10-digit mobile number and Password should contain 8 characters and at least one special character,one uppercase letter,one lowercase letter and one digit."
            return render(request,'UserSignup.html',context)
        elif not validate_password(request.POST.get("password")):
            context['data'] = "Password should contain 8 characters and at least one special character,one uppercase letter,one lowercase letter and one digit."
            return render(request,'UserSignup.html',context)
        elif not  validate_mobile_number(request.POST.get("phoneNumber")):
            context['data'] = "Please enter a 10 digit mobile number"
            return render(request,'UserSignup.html',context)
        form = UserForm(request.POST,request.FILES)
        if form.is_valid():
            form.save()
            context['data']=f"{request.POST.get('name')} registered succefully"
            return render(request,'UserSignup.html',context)
        else:
            context['data'] = "Something wrong in given data"
            return render(request,'UserSignup.html',context)
    return render(request,'UserSignup.html',context)

def user_signin(request):
    context = {}
    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")
        try:
            user = User.objects.get(email=email)
            if password == user.password:
                return redirect('/user_dashboard/{0}'.format(user.id))
            else:
                context["comment"] = "Incorrect password."
        except User.DoesNotExist:
            context["comment"] = "User not found."
    return render(request, 'UserSignin.html', context)

def user_update(request,id):
    context = {}
    user = User.objects.get(id=id)
    context['form'] = UserForm(request.POST or None, instance=user)
    context['data'] = ''
    context['btval'] = 'Update'
    if request.method == 'POST':
        if not  validate_mobile_number(request.POST.get("phoneNumber")) and not validate_password(request.POST.get("password")):
            context['data'] = "Please enter a 10-digit mobile number and Password should contain 8 characters and at least one special character,one uppercase letter,one lowercase letter and one digit."
            return render(request,'UserSignup.html',context)
        elif not validate_password(request.POST.get("password")):
            context['data'] = "Password should contain 8 characters and at least one special character,one uppercase letter,one lowercase letter and one digit."
            return render(request,'UserSignup.html',context)
        elif not  validate_mobile_number(request.POST.get("phoneNumber")):
            context['data'] = "Please enter a 10 digit mobile number"
            return render(request,'UserSignup.html',context)
        form = SellerForm(request.POST,request.FILES,instance=user)
        if form.is_valid():
            form.save()
            context['data']= "details updated successfully"
            return redirect('/user_dashboard/{0}'.format(user.id))
        else:
            context['data'] = "Something wrong in given data"
            return render(request,'UserSignup.html',context)
    return render(request,'UserSignup.html',context)

# ==============================================User-List===============================================================

def user_dashboard(request,id):
    context = {}
    user = User.objects.get(id=id)
    accessed_items = Item.objects.filter(itemaccess__access=True)
    categories = AdminCategory.objects.all()
    context['categories'] = categories
    context['user'] = user
    context['items'] = accessed_items
    return render(request, 'UserDashboard.html', context)

def user_item(request,id,item_id):
    context={}
    items = Item.objects.get(id=item_id)
    user = User.objects.get(id=id)
    if request.method == 'POST':
        form = OrderForm(request.POST)
        if form.is_valid():
            order = form.save(commit=False)
            order.item = items
            order.user = user
            order.save()
    else:
        form = OrderForm()   
    context['item'] = items
    context['user'] = user
    context['form'] = form
    return render(request, 'UserItem.html', context)

def user_orders(request,id):
    context = {}
    user =  User.objects.get(id=id)
    orders = Order.objects.filter(user=user)
    context['user'] = user
    context['orders'] = orders
    return render(request, 'UserOrders.html', context)

def delete_orders(request,order_id):
    order = Order.objects.get(id=order_id)
    user_id = order.user.id
    order.delete()
    return redirect('/user_orders/' + str(user_id))

def category_wise_products(request, id, category_id):
    context = {}
    user = User.objects.get(id=id)
    category = AdminCategory.objects.get(id=category_id)
    accessed_items = Item.objects.filter(itemaccess__access=True, category=category)
    categories = AdminCategory.objects.all()
    context['user'] = user
    context['category'] = category
    context['items'] = accessed_items
    context['categories'] = categories
    return render(request, "CategoryWiseProducts.html", context)