import typing as t

from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.models import update_last_login

from ievv_auth.ievv_jwt.backends.backend_registry import JWTBackendRegistry
from ievv_auth.ievv_jwt.exceptions import JWTBackendError

User = get_user_model()
username_field = User.USERNAME_FIELD


class PasswordField(serializers.CharField):
    def __init__(self, **kwargs) -> None:
        kwargs.setdefault("style", {})
        kwargs["style"]["input_type"] = "password"
        kwargs["write_only"] = True
        super().__init__(**kwargs)


class UserAuthObtainJWTSerializer(serializers.Serializer):
    jwt_backend_name = 'default'

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.fields[username_field] = serializers.CharField(write_only=True, required=True)
        self.fields['password'] = PasswordField(required=True)

    def validate(self, attrs):
        authenticate_kwargs = {
            username_field: attrs[username_field],
            'password': attrs['password'],
            'request': self.context.get("request")
        }
        user_instance = authenticate(**authenticate_kwargs)
        if user_instance is None or not user_instance.is_active:
            raise AuthenticationFailed()
        jwt_backend_class = JWTBackendRegistry.get_instance().get_backend(self.jwt_backend_name)
        if not jwt_backend_class:
            raise AuthenticationFailed('Unknown jwt backend could not authenticate')
        backend = jwt_backend_class()
        if backend.update_last_login:
            update_last_login(None, user_instance)
        backend.set_context(user_instance=user_instance)
        return backend.make_authenticate_success_response()


def get_user_auth_obtain_jwt_serializer(backend_name='user-auth') -> t.Type[UserAuthObtainJWTSerializer]:
    class _UserAuthObtainJWTSerializer(UserAuthObtainJWTSerializer):
        jwt_backend_name = backend_name
    return _UserAuthObtainJWTSerializer
