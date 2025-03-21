# Generated by Django 5.0.4 on 2024-07-14 02:37

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('allinone', '0029_delete_wishlist'),
    ]

    operations = [
        migrations.CreateModel(
            name='Cart',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('quantity', models.PositiveIntegerField(default=1)),
                ('item', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='allinone.item')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='allinone.user')),
            ],
        ),
    ]
