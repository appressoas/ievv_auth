import typing as t

from django.contrib.auth import get_user_model
from django.apps import apps

from ievv_auth.ievv_jwt.backends.base_backend import AbstractBackend
from ievv_auth.ievv_jwt.exceptions import JWTBackendError

UserModel = get_user_model()


if t.TYPE_CHECKING:
    from ievv_auth.ievv_jwt_blacklist.models import UserBlacklistedToken, UserIssuedToken


class UserAuthBackend(AbstractBackend):
    user_instance: UserModel = None

    @classmethod
    def get_backend_name(cls):
        return 'user-auth'

    def set_context(self, user_instance: UserModel = None, *args, **kwargs):
        self.user_instance = user_instance

    @property
    def issued_token_model(self) -> t.Type['UserIssuedToken']:
        return apps.get_model(app_label='ievv_jwt_blacklist', model_name='UserIssuedToken')

    @property
    def blacklisted_token_model(self) -> t.Type['UserBlacklistedToken']:
        return apps.get_model(app_label='ievv_jwt_blacklist', model_name='UserBlacklistedToken')

    def create_issued_token(self, token, payload, issued_at, expires_at, jti) -> 'UserBlacklistedToken':
        return self.issued_token_model.objects.create(
            issued_at=issued_at,
            expires_at=expires_at,
            token=token,
            jti=jti,
            token_payload=payload,
            user=self.user_instance
        )

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
                if not user_instance.is_active:
                    raise JWTBackendError('Inactive User')
                instance.set_context(user_instance=user_instance)
            except UserModel.DoesNotExist:
                raise JWTBackendError(f'No user with id "{payload["user_id"]}" found')
        return instance
