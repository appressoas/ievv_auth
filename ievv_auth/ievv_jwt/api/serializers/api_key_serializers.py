from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed

from ievv_auth.ievv_api_key.models import ScopedAPIKey
from ievv_auth.ievv_jwt.backends.backend_registry import JWTBackendRegistry
from ievv_auth.ievv_jwt.exceptions import JWTBackendError


class ApiKeyObtainJWTSerializer(serializers.Serializer):
    api_key = serializers.CharField()

    def validate(self, attrs):
        is_valid, instance = ScopedAPIKey.objects.is_valid_with_logging(api_key=attrs['api_key'])
        if not is_valid:
            raise AuthenticationFailed('Api key has expired or is invalid')
        jwt_backend_class = JWTBackendRegistry.get_instance().get_backend(instance.jwt_backend_name)
        if not jwt_backend_class:
            raise AuthenticationFailed('Unknown jwt backend could not authenticate')
        try:
            backend = jwt_backend_class(api_key_id=instance.id)
        except JWTBackendError:
            raise AuthenticationFailed('Api key is invalid')
        return backend.make_authenticate_success_response()
