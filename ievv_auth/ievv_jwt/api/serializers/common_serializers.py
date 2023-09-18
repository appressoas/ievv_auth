from ipware import get_client_ip
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed

from ievv_auth.ievv_jwt.backends.backend_registry import JWTBackendRegistry, get_backend_from_raw_jwt
from ievv_auth.ievv_jwt.exceptions import JWTBackendError


class RefreshTokenSerializer(serializers.Serializer):
    refresh = serializers.CharField(required=True)

    def validate(self, attrs):
        request = self.context.get("request")
        refresh_token = attrs['refresh']
        backend = get_backend_from_raw_jwt(raw_jwt=refresh_token)
        try:
            backend_instance = backend.make_instance_from_raw_jwt(raw_jwt=refresh_token, use_context=True)
        except JWTBackendError:
            raise AuthenticationFailed('Token invalid, blacklisted or expired')
        try:
            return backend_instance.refresh(token=refresh_token)
        except JWTBackendError as e:
            raise AuthenticationFailed('Token invalid, blacklisted or expired')
