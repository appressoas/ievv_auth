import typing as t
import jwt

from ievv_auth.ievv_jwt.backends.base_backend import AbstractBackend
from ievv_auth.ievv_jwt.exceptions import JWTBackendError
from django.apps import apps

#: if typechecking
if t.TYPE_CHECKING:
    from ievv_auth.ievv_api_key.models import ScopedAPIKey


class ApiKeyBackend(AbstractBackend):
    api_key_instance = None

    @classmethod
    def get_backend_name(cls):
        return 'api-key'

    def set_context(self, api_key_instance: 'ScopedAPIKey', *args, **kwargs):
        self.api_key_instance = api_key_instance

    def make_access_token_payload(self) -> dict:
        if self.api_key_instance is None:
            raise JWTBackendError('Missing context "api_key_instance"')
        return {
            **self.api_key_instance.base_jwt_payload,
            'api_key_id': self.api_key_instance.id
        }

    def make_refresh_token_payload(self) -> dict:
        if self.api_key_instance is None:
            raise JWTBackendError('Missing context "api_key_instance"')
        return {
            'api_key_id': self.api_key_instance.id
        }

    @classmethod
    def make_instance_from_raw_jwt(cls, raw_jwt, use_context=False, *args, **kwargs):
        instance = cls()
        if use_context:
            payload = instance.decode(raw_jwt)
            ScopedAPIKey = apps.get_model(app_label='ievv_auth.ievv_api_key', model_name='ScopedAPIKey')
            if 'api_key_id' not in payload:
                raise JWTBackendError('JWT payload missing key "api_key_id"')
            try:
                api_key_instance = ScopedAPIKey.objects.get(id=payload['api_key_id'])
                instance.set_context(api_key_instance=api_key_instance)
            except ScopedAPIKey.DoesNotExist:
                raise JWTBackendError(f'No ScopedAPIKey with id "{payload["api_key_id"]}" found')
        return instance
