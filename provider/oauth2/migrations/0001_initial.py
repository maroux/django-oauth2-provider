# -*- coding: utf-8 -*-
# Generated by Django 1.9.7 on 2016-06-30 20:44
from __future__ import unicode_literals

from django.conf import settings
import django.core.validators
from django.db import migrations, models
import django.db.models.deletion
import provider.oauth2.models
import provider.utils


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='AccessToken',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('token', models.CharField(db_index=True, default=provider.utils.long_token, max_length=255)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('expires', models.DateTimeField()),
                ('scope', provider.oauth2.models.ScopeField(choices=[(1, b'scope:public'), (2, b'scope:user:profile'), (4, b'scope:user:follow'), (8, b'scope:location'), (16, b'scope:current_location'), (32, b'scope:vehicle:events'), (64, b'scope:vehicle:profile'), (128, b'scope:vehicle:vin'), (256, b'scope:trip'), (512, b'scope:behavior'), (1024, b'scope:adapter:basic'), (2048, b'scope:crash_alert'), (4096, b'scope:patron'), (1073741824, b'scope:automatic')], default=0)),
                ('type', models.IntegerField(default=0)),
                ('is_deleted', models.BooleanField(default=False)),
            ],
        ),
        migrations.CreateModel(
            name='Client',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(blank=True, max_length=255)),
                ('url', models.URLField(help_text=b"Your application's URL.")),
                ('redirect_uri', models.CharField(help_text=b"Your application's callback URL", max_length=1028, validators=[django.core.validators.RegexValidator(regex=b'^\\S*//\\S*$')])),
                ('webhook_uri', models.CharField(blank=True, help_text=b"Your application's webhook URL", max_length=1028, null=True, validators=[django.core.validators.RegexValidator(regex=b'^\\S*//\\S*$')])),
                ('logo', models.ImageField(blank=True, help_text=b'40x40 pixel logo of your application', null=True, upload_to=provider.oauth2.models.client_logo_image_path)),
                ('status', models.PositiveSmallIntegerField(choices=[(0, b'INTERNAL'), (1, b'TEST'), (2, b'LIVE'), (3, b'DISABLED')], default=1, max_length=2)),
                ('last_updated_date', models.DateTimeField(auto_now=True)),
                ('created_date', models.DateTimeField(auto_now_add=True)),
                ('client_id', models.CharField(default=provider.utils.short_token, max_length=255)),
                ('client_secret', models.CharField(default=provider.utils.long_token, max_length=255)),
                ('client_type', models.IntegerField(choices=[(0, b'Confidential (Web applications)'), (1, b'Public (Native and JS applications)')], default=0)),
                ('scope', provider.oauth2.models.ScopeField(choices=[(1, b'scope:public'), (2, b'scope:user:profile'), (4, b'scope:user:follow'), (8, b'scope:location'), (16, b'scope:current_location'), (32, b'scope:vehicle:events'), (64, b'scope:vehicle:profile'), (128, b'scope:vehicle:vin'), (256, b'scope:trip'), (512, b'scope:behavior'), (1024, b'scope:adapter:basic'), (2048, b'scope:crash_alert'), (4096, b'scope:patron'), (1073741824, b'scope:automatic')], default=0)),
                ('event_delivery_preference', models.PositiveSmallIntegerField(choices=[(0, b'NONE'), (1, b'WEBHOOK'), (2, b'WEBSOCKET'), (3, b'WEBHOOK_FIXED_IP'), (4, b'BOTH - ONLY FOR FLEET. DO NOT USE')], default=0, max_length=2)),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='oauth2_client', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Grant',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('code', models.CharField(default=provider.utils.long_token, max_length=255)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('expires', models.DateTimeField(default=provider.utils.get_code_expiry)),
                ('redirect_uri', models.CharField(blank=True, max_length=255)),
                ('scope', provider.oauth2.models.ScopeField(choices=[(1, b'scope:public'), (2, b'scope:user:profile'), (4, b'scope:user:follow'), (8, b'scope:location'), (16, b'scope:current_location'), (32, b'scope:vehicle:events'), (64, b'scope:vehicle:profile'), (128, b'scope:vehicle:vin'), (256, b'scope:trip'), (512, b'scope:behavior'), (1024, b'scope:adapter:basic'), (2048, b'scope:crash_alert'), (4096, b'scope:patron'), (1073741824, b'scope:automatic')], default=0)),
                ('client', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='oauth2.Client')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='RefreshToken',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('token', models.CharField(default=provider.utils.long_token, max_length=255)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('expired', models.BooleanField(default=False)),
                ('access_token', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='refresh_token', to='oauth2.AccessToken')),
                ('client', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='oauth2.Client')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.AddField(
            model_name='accesstoken',
            name='client',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='oauth2.Client'),
        ),
        migrations.AddField(
            model_name='accesstoken',
            name='user',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
    ]
