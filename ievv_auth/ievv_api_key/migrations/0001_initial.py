# Generated by Django 3.0.2 on 2020-01-14 12:29

import django.contrib.postgres.fields.jsonb
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='ScopedAPIKey',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('prefix', models.CharField(editable=False, max_length=8, unique=True)),
                ('hashed_key', models.CharField(editable=False, max_length=100)),
                ('name', models.CharField(blank=True, default=None, help_text='Free text for the api key', max_length=255, null=True, verbose_name='Name')),
                ('revoked', models.BooleanField(default=False, help_text='If the api key has been revoked, once revoked it cannot be undone', verbose_name='Revoked')),
                ('created', models.DateTimeField(auto_now_add=True, help_text='When the api key was created', verbose_name='Created datetime')),
                ('expiration_datetime', models.DateTimeField(editable=False, help_text='The datetime when the token expires', verbose_name='Expires')),
                ('authentication_log', django.contrib.postgres.fields.jsonb.JSONField(blank=True, default=list)),
                ('jwt_backend_name', models.CharField(blank=True, default=None, max_length=255, null=True)),
                ('base_jwt_payload', django.contrib.postgres.fields.jsonb.JSONField(blank=True, default=dict)),
            ],
            options={
                'verbose_name': 'Scoped api key',
                'verbose_name_plural': 'Scoped api keys',
            },
        ),
    ]
