# Shopping
This repository contains the codebase for an e-commerce platform with a three-sided application structure: Admin, Seller, and User. The platform allows sellers to list items, users to browse and purchase items, and admins to manage categories and oversee the platform operations.
## Prerequisites
* Python (version 3.x recommended)
* Django
# Setup Instructions
## Create a Virtual Environment:
* python -m venv myenv 
* Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
* myenv\scripts\activate
## Install Dependencies:
* pip install django
* pip install djangorestframework
## Set up a new project
django-admin startproject AtoZ
cd VendorHub
django-admin startapp allinone
## Database migration
* python manage.py makemigrations
* python manage.py migrate
## Superuser creation
* python manage.py createsuperuser
## Running the server
* python manage.py runserver
## Access Django Admin:
* Open the Django admin at http://127.0.0.1:8000/adminlogin/ and log in using the superuser credentials. this is to access the database as a admin user.
## how to run a api endpoint:
* first we need to make sure that we migrated the models to database
* then we need to start the server using "python manage.py runserver" command.
