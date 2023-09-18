import jwt

from django.contrib.auth import get_user_model

from ievv_auth.ievv_jwt.backends.base_backend import AbstractBackend
from ievv_auth.ievv_jwt.exceptions import JWTBackendError

UserModel = get_user_model()


class UserAuthBackend(AbstractBackend):
    user_instance: UserModel = None

    @classmethod
    def get_backend_name(cls):
        return 'user-auth'

    def set_context(self, user_instance: UserModel = None, *args, **kwargs):
        self.user_instance = user_instance

    def make_access_token_payload(self) -> dict:
        if self.user_instance is None:
            raise JWTBackendError('Missing context "user_instance"')
        return {
            'user_id': self.user_instance.id
        }

    def make_refresh_token_payload(self) -> dict:
        if self.user_instance is None:
            raise JWTBackendError('Missing context "user_instance"')
        return {
            'user_id': self.user_instance.id
        }

    @classmethod
    def make_instance_from_raw_jwt(cls, raw_jwt, use_context=False, *args, **kwargs):
        instance = cls()
        if use_context:
            payload = instance.decode(raw_jwt)
            if 'user_id' not in payload:
                raise JWTBackendError('JWT payload missing key "user_id"')
            try:
                user_instance = UserModel.objects.get(id=payload['user_id'])
                instance.set_context(user_instance=user_instance)
            except UserModel.DoesNotExists:
                raise JWTBackendError(f'No user with id "{payload["user_id"]}" found')
        return instance
