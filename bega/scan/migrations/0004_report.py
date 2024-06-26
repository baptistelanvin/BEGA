# Generated by Django 5.0.3 on 2024-06-05 15:08

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scan', '0003_alter_scan_user'),
    ]

    operations = [
        migrations.CreateModel(
            name='Report',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=300)),
                ('date', models.DateField(auto_now=True)),
                ('data', models.JSONField()),
                ('scan', models.ForeignKey(on_delete=django.db.models.deletion.RESTRICT, to='scan.scan')),
            ],
        ),
    ]
