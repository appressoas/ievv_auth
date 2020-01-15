from ipware import get_client_ip
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed

from ievv_auth.ievv_api_key.models import ScopedAPIKey
from ievv_auth.ievv_jwt.backends.backend_registry import JWTBackendRegistry
from ievv_auth.ievv_jwt.exceptions import JWTBackendError


class ApiKeyObtainJWTSerializer(serializers.Serializer):
    api_key = serializers.CharField()

    def validate(self, attrs):
        request = self.context.get("request")
        client_ip, is_routable = get_client_ip(request)
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
        return backend.make_authenticate_success_response(
            base_payload={
                **instance.base_jwt_payload,
                'api_key_id': instance.id
            }
        )
