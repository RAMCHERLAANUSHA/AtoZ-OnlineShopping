"""
URL configuration for AtoZ project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from allinone import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),

    path('homepage/',views.homeView, name='homepage'),

    path('password-reset/', views.password_reset_request, name='password_reset_request'),
    path('validate-otp/', views.validate_otp, name='validate_otp'),
    path('reset-password/', views.password_reset_complete, name='password_reset_complete'),

    path('adminlogin/',views.adminLogin, name='adminLogin'),

    path('adminList/', views.admin_list, name = 'admin_list'),
    path('add_category/', views.add_category, name='add_category'),
    path('messages/', views.message_list, name='message_list'),
    path('delete_category/<int:category_id>/',views.category_delete, name='delete_category'),

    path('seller_signup/',views.seller_signup, name='seller_signup'),
    path('seller_signin/',views.seller_signin, name='seller_signin'),
    path('seller_update/<int:id>/',views.seller_update, name='seller_update'),

    path('seller_itemform/<int:id>/',views.seller_itemform, name='seller_itemform'),
    path('seller_products/<int:id>/',views.seller_products, name='seller_products'),
    path('seller_messages/<int:id>/',views.seller_messages, name='seller_messages'),

    path('user_signup/',views.user_signup, name='user_signup'),
    path('user_signin/',views.user_signin, name='user_signin'),
    path('user_update/<int:id>/',views.user_update, name='user_update'),

    path('user_dashboard/<int:id>/',views.user_dashboard, name='user_dashboard'),


]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)