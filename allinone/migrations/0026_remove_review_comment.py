# Generated by Django 5.0.4 on 2024-07-13 07:15

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('allinone', '0025_alter_review_comment'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='review',
            name='comment',
        ),
    ]
