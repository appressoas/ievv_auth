import json

from django.contrib import admin, messages
from django import forms
from django.utils.html import format_html

from ievv_auth.ievv_api_key.models import ScopedAPIKey, ScopedApiKeyAuthenticationLog
from ievv_auth.ievv_jwt.backends.backend_registry import JWTBackendRegistry


class ScopedAPIKeyForm(forms.ModelForm):
    jwt_backend_name = forms.ChoiceField(
        choices=[]
    )

    def __init__(self, *args, **kwargs):
        super(ScopedAPIKeyForm, self).__init__(*args, **kwargs)
        self.fields['jwt_backend_name'].choices = JWTBackendRegistry.get_instance().get_backend_choices()

    class Meta:
        model = ScopedAPIKey
        fields = [
            'name',
            'revoked',
            'jwt_backend_name',
            'base_jwt_payload'
        ]


@admin.register(ScopedAPIKey)
class ScopedAPIKeyAdmin(admin.ModelAdmin):
    form = ScopedAPIKeyForm

    list_display = [
        'name',
        'prefix',
        'revoked',
        'jwt_backend_name'
    ]

    readonly_fields = [
        'prefix',
        'hashed_key',
        'created',
        'expiration_datetime',
    ]
    fields = [
        'prefix',
        'name',
        'revoked',
        'created',
        'expiration_datetime',
        'jwt_backend_name',
        'base_jwt_payload'
    ]

    search_fields = [
        'name',
        'prefix'
    ]

    def save_model(self, request, obj, form, change):
        if change:
            obj.save()
        else:
            api_key, instance = ScopedAPIKey.objects.create_key(
                name=obj.name,
                jwt_backend_name=obj.jwt_backend_name,
                base_jwt_payload=obj.base_jwt_payload
            )
            messages.add_message(request, messages.SUCCESS, f'Api key created: {api_key}')


@admin.register(ScopedApiKeyAuthenticationLog)
class ScopedApiKeyAuthenticationLogAdmin(admin.ModelAdmin):

    list_display = [
        'api_key',
        'created',
    ]

    readonly_fields = [
        'api_key',
        'created',
        'get_log_data_pretty',
    ]
    fields = [
        'api_key',
        'created',
        'get_log_data_pretty',
    ]

    search_fields = [
        'api_key__name',
    ]

    def get_log_data_pretty(self, obj):
        return format_html('<pre>{}</pre>', json.dumps(obj.log_data or {}, indent=2, sort_keys=True))

    get_log_data_pretty.short_description = 'Log data pretty'
