# Generated by Django 5.0.4 on 2024-07-10 16:12

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('allinone', '0020_alter_message_message'),
    ]

    operations = [
        migrations.AlterField(
            model_name='itemaccess',
            name='comment',
            field=models.CharField(default='Item denied', max_length=100),
        ),
    ]
