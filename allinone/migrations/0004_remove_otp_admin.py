# Generated by Django 5.0.4 on 2024-06-07 10:10

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('allinone', '0003_otp'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='otp',
            name='Admin',
        ),
    ]
