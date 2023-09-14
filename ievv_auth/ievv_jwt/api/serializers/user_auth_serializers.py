import typing as t

from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import get_user_model, authenticate

from ievv_auth.ievv_jwt.backends.backend_registry import JWTBackendRegistry
from ievv_auth.ievv_jwt.exceptions import JWTBackendError


class PasswordField(serializers.CharField):
    def __init__(self, **kwargs) -> None:
        kwargs.setdefault("style", {})
        kwargs["style"]["input_type"] = "password"
        kwargs["write_only"] = True
        super().__init__(**kwargs)


class UserAuthObtainJWTSerializer(serializers.Serializer):
    username_field = get_user_model().USERNAME_FIELD
    jwt_backend_name = 'default'

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.fields[self.username_field] = serializers.CharField(write_only=True)
        self.fields['password'] = PasswordField()

    def validators(self, attrs):
        authenticate_kwargs = {
            self.username_field: attrs[self.username_field],
            'password': attrs['password'],
            'request': self.context.get("request")
        }
        user_instance = authenticate(**authenticate_kwargs)
        if user_instance is not None and user_instance.is_active:
            raise AuthenticationFailed()
        jwt_backend_class = JWTBackendRegistry.get_instance().get_backend(self.jwt_backend_name)
        if not jwt_backend_class:
            raise AuthenticationFailed('Unknown jwt backend could not authenticate')
        backend = jwt_backend_class()
        backend.set_context(user_instance=user_instance)
        return backend.make_authenticate_success_response()


def get_user_auth_obtain_jwt_serializer(backend_name='default') -> t.Type[UserAuthObtainJWTSerializer]:
    class _UserAuthObtainJWTSerializer(UserAuthObtainJWTSerializer):
        jwt_backend_name = backend_name
    return _UserAuthObtainJWTSerializer
