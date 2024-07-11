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

class ReviewForm(forms.ModelForm):
    class Meta:
        model = Review
        fields = "__all__"
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['item'].queryset = Item.objects.all()
        self.fields['item'].label_from_instance = lambda obj: f"{obj.item}"
        self.fields['user'].queryset = User.objects.all()
        self.fields['user'].label_from_instance = lambda obj: f"{obj.user}"

class MessageForm(forms.ModelForm):
    class Meta:
        model = Message
        fields = ['message']
    # def __init__(self, *args, **kwargs):
    #     super().__init__(*args, **kwargs)
    #     self.fields['seller'].queryset = Seller.objects.all()
    #     self.fields['seller'].label_from_instance = lambda obj: f"{obj.name}"

class OrderForm(forms.ModelForm):
    class Meta:
        model = Order
        fields = "__all__"
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['item'].queryset = Item.objects.all()
        self.fields['item'].label_from_instance = lambda obj: f"{obj.item}"
        self.fields['user'].queryset = User.objects.all()
        self.fields['user'].label_from_instance = lambda obj: f"{obj.user}"

class WishlistForm(forms.ModelForm):
    class Meta:
        model = Wishlist
        fields = "__all__"
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['item'].queryset = Item.objects.all()
        self.fields['item'].label_from_instance = lambda obj: f"{obj.item}"
        self.fields['user'].queryset = User.objects.all()
        self.fields['user'].label_from_instance = lambda obj: f"{obj.user}"

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




