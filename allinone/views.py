from django.shortcuts import render
from django.shortcuts import redirect
from django.contrib.auth.models import User as Admin
from django.contrib.auth.hashers import check_password
from django.core.mail import send_mail
from .models import *
from .forms import *
from django.contrib.auth.hashers import make_password
from django.http import JsonResponse
from django.db.models import Q


# =================================================HomeView=============================================================

def homeView(request):

    """
    Render the home page view.

    This view function renders a template named 'HomePage.html' to display the
    home page of the web application.

    Args:
    - request: HttpRequest object representing the request made to the server.

    Returns:
    - HttpResponse object: Renders the 'HomePage.html' template with optional context data
    """

    return render(request, 'HomePage.html')

# ================================================Validations===========================================================

def validate_mobile_number(value):

    """
    Validate that the input is a 10-digit mobile number.
    """

    value = str(value)
    if not value.isdigit() or len(value) != 10:
        return False
    return True

def validate_password(password):

    """
    Validate the input password.
    """

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

    """
    This function sends an OTP (One-Time Password) email to the provided email address.

    Parameters:

    email (str): The email address to which the OTP will be sent.
    Functionality:

    Generates a random OTP code using the generate_otp() function.
    Creates an OTP instance in the database with the email and OTP code.
    Constructs an email message containing the OTP code and sends it to the provided email address using Django's send_mail() function.
    """

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

    """
    This function handles the initial request for password reset.

    HTTP Method: POST

    Form Required: EmailForm

    Functionality:

    Validates the form data to extract the user's email address.
    Identifies the user type (user, admin, seller) based on the email address found in the respective user models (User, Admin, Seller).
    Sends an OTP email to the user's email address using send_otp_email(email).
    Stores the email and user type in the session.
    Redirects to validate_otp view to validate the OTP entered by the user.
    """

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

    """
    This function validates the OTP entered by the user.

    HTTP Method: POST

    Form Required: OTPForm

    Functionality:

    Validates the form data to extract the OTP entered by the user.
    Retrieves the stored email from the session.
    Checks if the entered OTP matches the OTP stored in the database for the user's email.
    If valid, sets a session variable (otp_valid = True) and redirects to password_reset_complete.
    If invalid or expired, displays appropriate error messages.
    """

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

    """
    This function completes the password reset process.

    HTTP Method: POST

    Form Required: PasswordResetForm

    Functionality:

    Retrieves the user type and email from the session.
    Validates the form data to get the new password and confirm password.
    Updates the user's password in the respective user model (User, Admin, Seller).
    Displays success message upon successful password reset.
    Handles errors such as password mismatch or user not found.
    """

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

    """
    This function manages the login process for admin users.

    HTTP Method: GET, POST

    Parameters:

    request (HttpRequest): The HTTP request object containing data submitted by the user.
    Functionality:
    Handles both GET and POST requests:
    GET Request:
    Renders the AdminLogin.html template to display the admin login form.
    POST Request:
    Retrieves the email and password from the POST data submitted by the user.

    If the admin user is found:
    Compares the hashed password stored in the database with the provided password using Django's check_password() function.
    If the passwords match, redirects the admin user to /adminList/.
    If the passwords do not match, sets an error message "Incorrect password.." and renders the AdminLogin.html template again.
    If the admin user is not found, sets an error message "Admin not found.." and renders the AdminLogin.html template again.

    """

    context = {}
    context["comment"] = ''
    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")
        try:
            a1 = Admin.objects.get(email=email)
            if check_password(password,a1.password):
                return redirect('/admin_list/')
            else:
                context["comment"] = "Incorrect password.."
                return render(request,'AdminLogin.html', context)
        except:
            context["comment"] = "Admin not found.."
            return render(request,'AdminLogin.html', context)
    return render(request,'AdminLogin.html')

# =================================================Admin-List==========================================================

def admin_list(request):

    """
    This function manages the list of items for admin.

    HTTP Method: GET, POST

    Parameters:

    request (HttpRequest): The HTTP request object containing data submitted by the user.
    Functionality:

    Retrieves items from the Item model excluding those with related ItemAccess instances.
    Handles POST requests to grant or deny access to specific items based on user action.
    Retrieves item_id and action from POST data.
    Updates the ItemAccess model accordingly:
    Grants access (action == 'access').
    Denies access (action == 'deny').
    Updates the items list to exclude processed items.
    Returns a JSON response indicating the success of the action.
    Renders the AdminProducts.html template with a list of items and a form for managing item access.
    """

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

    """
    This function handles the addition of categories by admin.

    HTTP Method: GET, POST

    Parameters:

    request (HttpRequest): The HTTP request object containing data submitted by the user.
    Functionality:

    Manages form submission for adding categories.
    Handles POST requests:
    Validates and saves the form data using AdminCategoryForm.
    Displays success or error messages based on form validation.
    Retrieves all existing categories from the AdminCategory model.
    Renders the AddCategory.html template with a form for adding categories and a list of existing categories.
    """

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
    
    """
    This function handles the deletion of categories by admin.

    HTTP Method: GET

    Parameters:

    request (HttpRequest): The HTTP request object containing data submitted by the user.
    category_id (int): The ID of the category to delete.
    Functionality:

    Retrieves the category to delete based on category_id from the AdminCategory model.
    Deletes the category from the database.
    Redirects the user back to the add_category view.
    """

    category = AdminCategory.objects.get(id=category_id)
    category.delete()
    return redirect('add_category')

def message_list(request):
    
    """
    This function retrieves and displays a list of messages.

    HTTP Method: GET

    Parameters:

    request (HttpRequest): The HTTP request object containing data submitted by the Seller.
    Functionality:

    Retrieves all messages from the Message model.
    Renders the MessageList.html template with the retrieved list of messages.

    """

    messages = Message.objects.all()
    context = {
        'messages': messages,
    }
    return render(request, 'MessageList.html', context)

#===========================================Seller-SignIn-SignUp-Update=================================================

def seller_signup(request):
    
    """
    This function handles the signup process for sellers.

    HTTP Method: GET, POST

    Parameters:

    request (HttpRequest): The HTTP request object containing data submitted by the Seller.
    Functionality:

    Renders the SellerSignup.html template with a blank SellerForm instance SellerForm().
    Handles form submission for seller signup:
    Validates the mobile number and password format using validate_mobile_number() and validate_password() functions.
    Displays appropriate error messages if validation fails.
    Saves the form data to create a new Seller instance if the form is valid.
    Redirects to the signup page with success or error messages based on form validation.
    """

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
    
    """
    This function handles the signin process for sellers.

    HTTP Method: GET, POST

    Parameters:

    request (HttpRequest): The HTTP request object containing data submitted by the seller.
    Functionality:

    Handles form submission for seller signin:
    Retrieves email and password from the POST request.
    Attempts to retrieve a Seller instance matching the provided email.
    Compares the provided password with the stored password for authentication.
    Redirects to the seller's item form page (/seller_itemform/{seller.id}) upon successful authentication.
    Displays an error message if the email or password is incorrect.
    """

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
    
    """
    This function handles the update process for seller details.

    HTTP Method: GET, POST

    Parameters:

    request (HttpRequest): The HTTP request object containing data submitted by the seller.
    id (int): The ID of the seller to update.
    Functionality:

    Retrieves the Seller instance to update based on the provided id.
    Renders the SellerSignup.html template with a populated SellerForm instance.
    Handles form submission for seller details update:
    Validates the mobile number and password format using validate_mobile_number() and validate_password() functions.
    Displays appropriate error messages if validation fails.
    Saves the form data to update the existing Seller instance if the form is valid.
    Redirects to the seller's item form page upon successful update.
    Displays an error message if the form data is invalid.
    """

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
    
    """
    This function handles the addition of items by a seller.

    HTTP Method: GET, POST

    Parameters:

    request (HttpRequest): The HTTP request object containing data submitted by the seller.
    id (int): The ID of the seller who is adding the item.
    Functionality:

    Retrieves the Seller instance based on the provided id.
    Renders the AddItem.html template with an empty ItemForm instance.
    Handles form submission for adding an item:
    Validates and saves the form data using ItemForm.
    Associates the item with the seller before saving.
    Displays a success message if the form is valid and the item is saved successfully.
    Displays an error message if there are validation errors or if something goes wrong during form submission.
    """

    context = {}
    seller = Seller.objects.get(id=id)
    if request.method == 'POST':
        form = ItemForm(request.POST, request.FILES)
        if form.is_valid():
           item = form.save(commit=False)
           item.seller = seller
           item.save()  
           context['comment'] = 'Item added successfully.'
        else:
            context['comment'] = 'Something went wrong.'
    else:
        form = ItemForm()

    context['form'] = form
    context['seller'] = seller
    return render(request, 'AddItem.html', context)

def seller_products(request,id):
    
    """
    This function displays the list of products associated with a seller.

    HTTP Method: GET

    Parameters:

    request (HttpRequest): The HTTP request object containing data submitted by the seller.
    id (int): The ID of the seller whose products are being displayed.
    Functionality:

    Retrieves the Seller instance based on the provided id.
    Retrieves all Item instances from the database.
    Renders the SellerProducts.html template with the seller and items context.
    """

    context = {}
    seller = Seller.objects.get(id=id)
    items = Item.objects.all()
    context['seller'] = seller
    context['items'] = items
    return render(request, 'SellerProducts.html', context)

def seller_product_delete(request, item_id):
    
    """
    This function handles the deletion of a product associated with a seller.

    HTTP Method: GET

    Parameters:

    request (HttpRequest): The HTTP request object containing data submitted by the seller.
    item_id (int): The ID of the item to be deleted.
    Functionality:

    Retrieves the Item instance based on the provided item_id.
    Retrieves the ID of the seller associated with the item.
    Deletes the item from the database.
    Redirects to the seller's products page after successful deletion.
    """

    item = Item.objects.get(id=item_id)
    seller_id = item.seller.id
    item.delete()
    return redirect('/seller_products/' + str(seller_id))

def seller_messages(request,id):
    
    """
    This function handles messages related to seller items.

    HTTP Method: GET, POST

    Parameters:

    request (HttpRequest): The HTTP request object containing data submitted by the seller
    id (int): The ID of the seller whose messages are being managed.
    Functionality:

    Retrieves the Seller instance based on the provided id.
    Retrieves all ItemAccess instances related to the seller.
    Handles form submission for sending messages:
    Validates and saves the form data using MessageForm.
    Associates the message with the seller before saving.
    Displays a success message if the form is valid and the message is saved successfully.
    Displays an error message if there are validation errors or if something goes wrong during form submission.
    """

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
    
    """
    This function displays orders related to seller items.

    HTTP Method: GET

    Parameters:

    request (HttpRequest): The HTTP request object containing data submitted by the seller.
    seller_id (int): The ID of the seller whose orders are being displayed.
    Functionality:

    Retrieves the Seller instance based on the provided seller_id.
    Retrieves all Order instances where the item is associated with the seller.
    Renders the SellerOrders.html template with the seller and orders context.
    """

    seller = Seller.objects.get(id=seller_id)
    orders = Order.objects.filter(item__seller=seller)
    context = {
        'seller': seller,
        'orders': orders,
    }
    return render(request, 'SellerOrders.html', context)

# ====================================User-SignIn-SignUp-Update=========================================================

def user_signup(request):
    
    """
    This function handles user registration.

    HTTP Method: GET, POST

    Parameters:

    request (HttpRequest): The HTTP request object containing data submitted by the user.
    Functionality:

    Renders the UserSignup.html template with an empty UserForm instance.
    Validates user input:
    Checks if the phone number is a 10-digit number.
    Checks if the password meets complexity requirements.
    Saves the user data if the form is valid and redirects to the signup page with a success message.
    Displays error messages if there are validation errors or if something goes wrong during form submission.
    """

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
    
    """
    This function handles user authentication.

    HTTP Method: GET, POST

    Parameters:

    request (HttpRequest): The HTTP request object containing data submitted by the user.
    Functionality:

    Validates user credentials.
    Redirects to the user dashboard if authentication is successful.
    Displays error messages if the email is not found or if the password is incorrect.
    """

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
    
    """
    This function handles user profile update.

    HTTP Method: GET, POST

    Parameters:

    request (HttpRequest): The HTTP request object containing data submitted by the user.
    id (int): The ID of the user whose profile is being updated.
    Functionality:

    Retrieves the User instance based on the provided id.
    Renders the UserSignup.html template with a populated UserForm instance.
    Validates user input:
    Checks if the phone number is a 10-digit number.
    Checks if the password meets complexity requirements.
    Saves the updated user data if the form is valid and redirects to the user dashboard with a success message.
    Displays error messages if there are validation errors or if something goes wrong during form submission.
    """

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

def user_dashboard(request, id):
    
    """
    This function renders the user dashboard page, displaying accessed items based on user queries or category filters.

    HTTP Method: GET

    Parameters:

    request (HttpRequest): The HTTP request object.
    id (int): The ID of the user whose dashboard is being accessed.
    Functionality:

    Retrieves the User instance based on the provided id.
    Optionally filters items based on user queries (q) or displays all items if no query is provided.
    Retrieves all admin categories for filtering.
    Renders the UserDashboard.html template with user details, accessed items, and admin categories.
    """

    user = User.objects.get(id=id)
    query = request.GET.get('q')
    categories = AdminCategory.objects.all()
    if not query:
        categories = AdminCategory.objects.all()
    else:
        categories = []
    if query:
        accessed_items = Item.objects.filter(
            Q(name__icontains=query) | Q(category__category__icontains=query),
            itemaccess__access=True
        )
    else:
        accessed_items = Item.objects.filter(itemaccess__access=True)

    context = {
        'user': user,
        'items': accessed_items,
        'categories': categories,
    }

    return render(request, 'UserDashboard.html', context)

def user_item(request,id,item_id):
    
    """
    This function displays details about a specific item for a user and allows them to place an order.

    HTTP Method: GET, POST

    Parameters:

    request (HttpRequest): The HTTP request object.
    id (int): The ID of the user viewing the item.
    item_id (int): The ID of the item being viewed.
    Functionality:

    Retrieves the User instance and the specific Item instance based on provided IDs.
    Handles POST requests to create a new order for the item if the form is valid.
    Renders the UserItem.html template with details of the item, user, and order form.
    """

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
    
    """
    This function displays a list of orders placed by a user.

    HTTP Method: GET

    Parameters:

    request (HttpRequest): The HTTP request object.
    id (int): The ID of the user whose orders are being displayed.
    Functionality:

    Retrieves the User instance based on the provided id.
    Retrieves all orders associated with the user.
    Renders the UserOrders.html template with user details and their orders.
    """

    context = {}
    user =  User.objects.get(id=id)
    orders = Order.objects.filter(user=user)
    context['user'] = user
    context['orders'] = orders
    return render(request, 'UserOrders.html', context)

def delete_orders(request,order_id):
    
    """
    This function deletes a specific order based on the provided order_id.

    HTTP Method: GET

    Parameters:

    request (HttpRequest): The HTTP request object.
    order_id (int): The ID of the order to be deleted.
    Functionality:

    Retrieves the Order instance based on the provided order_id.
    Deletes the order from the database.
    Redirects to the user's orders page after deletion.
    """

    order = Order.objects.get(id=order_id)
    user_id = order.user.id
    order.delete()
    return redirect('/user_orders/' + str(user_id))

def category_wise_products(request, id, category_id):
    
    """
    This function displays products within a specific category that have been accessed by users.

    HTTP Method: GET

    Parameters:

    request (HttpRequest): The HTTP request object.
    id (int): The ID of the user viewing the products.
    category_id (int): The ID of the category whose products are being viewed.
    Functionality:

    Retrieves the User instance and the specific AdminCategory instance based on provided IDs.
    Retrieves items that belong to the specified category and have been accessed.
    Retrieves all admin categories for filtering.
    Renders the CategoryWiseProducts.html template with user details, category details, accessed items, and admin categories.
    """

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

def add_to_cart(request, id, item_id):
    
    """
    This function adds an item to the user's cart.

    HTTP Method: GET

    Parameters:

    request (HttpRequest): The HTTP request object.
    id (int): The ID of the user adding the item to the cart.
    item_id (int): The ID of the item being added to the cart.
    Functionality:

    Retrieves the User instance and the specific Item instance based on provided IDs.
    Checks if the item already exists in the user's cart. If it does, increases its quantity; otherwise, creates a new cart item.
    Redirects to the user_item view after adding the item to the cart.
    """

    user = User.objects.get(id=id)
    item = Item.objects.get(id=item_id)
    existing_cart_item = Cart.objects.filter(user=user, item=item).first()

    if existing_cart_item:
        existing_cart_item.quantity += 1
        existing_cart_item.save()
    else:
        new_cart_item = Cart(user=user, item=item)
        new_cart_item.save()
    return redirect('user_item', id=user.id, item_id=item.id)

def view_cart(request, id):
    
    """
    This function displays the contents of the user's cart.

    HTTP Method: GET

    Parameters:

    request (HttpRequest): The HTTP request object.
    id (int): The ID of the user viewing their cart.
    Functionality:

    Retrieves the User instance and all cart items associated with the user.
    Renders the CartList.html template with user details and cart items.
    """

    user = User.objects.get(id=id)
    user_cart_items = Cart.objects.filter(user_id=id)
    context = {
        'items': user_cart_items,
        'user' : user
    }
    return render(request, 'CartList.html', context)

def cart_item_delete(request,cart_id):
    
    """
    This function deletes a specific cart item based on the provided cart_id.

    HTTP Method: GET

    Parameters:

    request (HttpRequest): The HTTP request object.
    cart_id (int): The ID of the cart item to be deleted.
    Functionality:

    Retrieves the Cart instance based on the provided cart_id.
    Deletes the cart item from the database.
    Redirects to the user's cart view after deletion.

    """

    cart = Cart.objects.get(id=cart_id)
    user_id = cart.user.id
    cart.delete()
    return redirect('/view_cart/' + str(user_id))
