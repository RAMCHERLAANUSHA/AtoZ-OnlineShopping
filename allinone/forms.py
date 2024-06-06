from django import forms
from models import *

class AdminCategoryForm(forms.ModelForm):
    class Meta:
        model = AdminCategory
        fields = "__all__"

class SellerForm(forms.ModelForm):
    class Meta:
        model = Seller
        fields = "__all__"

class UserForm(forms.ModelForm):
    class Meta:
        model = User
        fields = "__all__"

class ItemForm(forms.ModelForm):
    class Meta:
        model = Item
        fields = "__all__"
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['category'].queryset = AdminCategory.objects.all()
        self.fields['category'].label_from_instance = lambda obj: f"{obj.category}"
        self.fields['seller'].queryset = Seller.objects.all()
        self.fields['seller'].label_from_instance = lambda obj: f"{obj.seller}"

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
        fields = "__all__"
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['seller'].queryset = Seller.objects.all()
        self.fields['seller'].label_from_instance = lambda obj: f"{obj.seller}"

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

