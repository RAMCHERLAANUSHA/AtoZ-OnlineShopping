from django.db import models
import random
import string
from django.contrib.auth.models import User as Admin
from django.utils import timezone
from datetime import timedelta
# Create your models here.

class AdminCategory(models.Model):
    category = models.CharField(max_length=50, unique=True)
    image = models.ImageField(upload_to='images/',default='images/p1.jpg')

class Seller(models.Model):
    name = models.CharField(max_length=60)
    email = models.EmailField(unique=True)
    gender = models.CharField(max_length=6)
    phoneNumber = models.BigIntegerField()
    address = models.CharField(max_length=120)
    username = models.CharField(max_length=30,unique=True)
    password = models.CharField(max_length=100)
    image = models.ImageField(upload_to='images/',default='images/p1.png')

class User(models.Model):
    name = models.CharField(max_length=60)
    email = models.EmailField(unique=True)
    gender = models.CharField(max_length=6)
    phoneNumber = models.BigIntegerField()
    address = models.CharField(max_length=120)
    username = models.CharField(max_length=30,unique=True)
    password = models.CharField(max_length=100)
    image = models.ImageField(upload_to='images/',default='images/p1.png')

class Item(models.Model):
    name = models.CharField(max_length=255)
    description = models.CharField(max_length=120)
    photo = models.ImageField(upload_to='images/')
    cost = models.DecimalField(max_digits=10, decimal_places=2)
    category = models.ForeignKey(AdminCategory, on_delete=models.CASCADE)
    seller = models.ForeignKey(Seller, on_delete=models.CASCADE)

class Message(models.Model):
    seller = models.ForeignKey(Seller, on_delete=models.CASCADE)
    message = models.CharField(max_length=900)

class Order(models.Model):
    item = models.ForeignKey(Item, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField()
    order_date = models.DateTimeField(auto_now_add=True)

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

class OTP(models.Model):
    email = models.EmailField(null=True)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"OTP: {self.otp} for Email: {self.email}"
    
    def is_valid(self):
        expiration_time = self.created_at + timedelta(minutes=10)  # Set OTP expiration time
        return timezone.now() <= expiration_time

class ItemAccess(models.Model):  
    item_id = models.OneToOneField(Item,on_delete=models.CASCADE)
    access = models.BooleanField()
    comment = models.CharField(max_length=100,default='Item denied')

class Cart(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    item = models.ForeignKey(Item, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(default=1)

    def __str__(self):
        return f"{self.quantity} x {self.item.name} in {self.user.username}'s cart"
