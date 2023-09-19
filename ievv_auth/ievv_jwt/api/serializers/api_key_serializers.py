from ipware import get_client_ip
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed

from django.apps import apps
from ievv_auth.ievv_jwt.backends.backend_registry import JWTBackendRegistry
from ievv_auth.ievv_jwt.exceptions import JWTBackendError


class ApiKeyObtainJWTSerializer(serializers.Serializer):
    api_key = serializers.CharField()

    def validate(self, attrs):
        request = self.context.get("request")
        client_ip, is_routable = get_client_ip(request)
        ScopedAPIKey = apps.get_model(app_label='ievv_api_key', model_name='ScopedAPIKey')
        is_valid, instance = ScopedAPIKey.objects.is_valid_with_logging(
            api_key=attrs['api_key'],
            extra={
                'ip': client_ip
            }
        )
        if not is_valid or not instance:
            raise AuthenticationFailed('Api key has expired or is invalid')
        jwt_backend_class = JWTBackendRegistry.get_instance().get_backend(instance.jwt_backend_name)
        if not jwt_backend_class:
            raise AuthenticationFailed('Unknown jwt backend could not authenticate')
        backend = jwt_backend_class()
        backend.set_context(api_key_instance=instance)
        return backend.make_authenticate_success_response()
