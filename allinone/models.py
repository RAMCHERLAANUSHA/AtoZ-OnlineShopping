from django.db import models
import random
import string
from django.contrib.auth.models import User as Admin

# Create your models here.

class AdminCategory(models.Model):
    category = models.CharField(max_length=50)

class Seller(models.Model):
    s_name = models.CharField(max_length=60)
    email = models.EmailField(unique=True)
    gender = models.CharField(max_length=6)
    phoneNumber = models.BigIntegerField()
    Address = models.TextField(max_length=120)
    username = models.CharField(max_length=30,unique=True)
    password = models.CharField(max_length=100)
    image = models.ImageField(upload_to='images',default='images/p1.png')

class User(models.Model):
    u_name = models.CharField(max_length=60)
    email = models.EmailField(unique=True)
    gender = models.CharField(max_length=6)
    phoneNumber = models.BigIntegerField()
    Address = models.TextField(max_length=120)
    username = models.CharField(max_length=30,unique=True)
    password = models.CharField(max_length=100)
    image = models.ImageField(upload_to='images',default='images/p1.png')

class Item(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField()
    photo = models.ImageField(upload_to='item_photos/')
    cost = models.DecimalField(max_digits=10, decimal_places=2)
    category = models.ForeignKey(AdminCategory, on_delete=models.CASCADE)
    seller = models.ForeignKey(Seller, on_delete=models.CASCADE)

    def average_rating(self):
        reviews = self.review_set.all()
        if reviews:
            return sum(review.rating for review in reviews) / reviews.count()
        return 0

class Review(models.Model):
    item = models.ForeignKey(Item, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    rating = models.IntegerField(choices=[(i, str(i)) for i in range(1, 6)])
    comment = models.TextField()

class Message(models.Model):
    seller = models.ForeignKey(Seller, on_delete=models.CASCADE)
    message = models.TextField()

class Order(models.Model):
    item = models.ForeignKey(Item, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField()
    order_date = models.DateTimeField(auto_now_add=True)

class Wishlist(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    item = models.ForeignKey(Item, on_delete=models.CASCADE)

    class Meta:
        unique_together = ('user', 'item')

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

class OTP(models.Model):
    Admin = models.ForeignKey(Admin, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6, default=generate_otp)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_valid(self):
        # OTP is valid for 5 minutes
        return (timezone.now() - self.created_at).seconds < 300
