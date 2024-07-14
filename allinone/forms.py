from django import forms
from .models import *
from django.forms import TextInput,EmailInput,NumberInput,ImageField

class AdminCategoryForm(forms.ModelForm):
    class Meta:
        model = AdminCategory
        fields = "__all__"

class SellerForm(forms.ModelForm):
    gender = forms.ChoiceField(choices=(
            ("Select",'Select'),
            ("Male","Male"),
            ("Female","Female"),
            ("Other","Other"),
    ))
    class Meta:
        model = Seller
        fields = "__all__"

class UserForm(forms.ModelForm):
    gender = forms.ChoiceField(choices=(
            ("Select",'Select'),
            ("Male","Male"),
            ("Female","Female"),
            ("Other","Other"),
    ))
    class Meta:
        model = User
        fields = "__all__"

class ItemForm(forms.ModelForm):
    class Meta:
        model = Item
        fields = ['name','description', 'photo', 'cost', 'category']
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['category'].queryset = AdminCategory.objects.all()
        self.fields['category'].label_from_instance = lambda obj: f"{obj.category}"
        self.fields['name'].queryset = Seller.objects.all()
        self.fields['name'].label_from_instance = lambda obj: f"{obj.name}"

class MessageForm(forms.ModelForm):
    class Meta:
        model = Message
        fields = ['message']

class OrderForm(forms.ModelForm):
    class Meta:
        model = Order
        fields = ['quantity'] 
        widgets = {
            'quantity': forms.Select(choices=[(i, str(i)) for i in range(1, 11)])
        }

class EmailForm(forms.Form):
    email = forms.EmailField()

class OTPForm(forms.Form):
    otp = forms.CharField(max_length=6)

class PasswordResetForm(forms.Form):
    new_password = forms.CharField(widget=forms.PasswordInput)
    confirm_password = forms.CharField(widget=forms.PasswordInput)

class ItemAccessForm(forms.ModelForm):
    class Meta:
        model = ItemAccess
        fields = ['comment']




