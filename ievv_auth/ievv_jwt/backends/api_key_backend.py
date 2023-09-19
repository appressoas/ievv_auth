import typing as t

from ievv_auth.ievv_jwt.backends.base_backend import AbstractBackend
from ievv_auth.ievv_jwt.exceptions import JWTBackendError
from django.conf import settings
from django.apps import apps

#: if typechecking
if t.TYPE_CHECKING:
    from ievv_auth.ievv_api_key.models import ScopedAPIKey
    from ievv_auth.ievv_jwt_blacklist.models import ScopedApiKeyIssuedToken, ScopedApiKeyBlacklistedToken


class ApiKeyBackend(AbstractBackend):
    api_key_instance = None

    @classmethod
    def get_backend_name(cls):
        return 'api-key'

    def set_context(self, api_key_instance: 'ScopedAPIKey', *args, **kwargs):
        self.api_key_instance = api_key_instance

    @property
    def blacklist_app(self):
        return 'ievv_auth.ievv_jwt_api_key_blacklist'

    @property
    def issued_token_model(self) -> t.Type['ScopedApiKeyIssuedToken']:
        return apps.get_model(app_label='ievv_jwt_api_key_blacklist', model_name='ScopedApiKeyIssuedToken')

    @property
    def blacklisted_token_model(self) -> t.Type['ScopedApiKeyBlacklistedToken']:
        return apps.get_model(app_label='ievv_jwt_api_key_blacklist', model_name='ScopedApiKeyBlacklistedToken')

    def create_issued_token(self, token, payload, issued_at, expires_at, jti) -> 'ScopedApiKeyIssuedToken':
        return self.issued_token_model.objects.create(
            issued_at=issued_at,
            expires_at=expires_at,
            token=token,
            token_payload=payload,
            jti=jti,
            scoped_api_key=self.api_key_instance
        )

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
            if 'ievv_auth.ievv_api_key' not in settings.INSTALLED_APPS:
                raise JWTBackendError(
                    'Could not instantiate ApiKeyBackend as "ievv_auth.ievv_api_key" is not in installed apps'
                )
            ScopedAPIKey = apps.get_model(app_label='ievv_api_key', model_name='ScopedAPIKey')
            if 'api_key_id' not in payload:
                raise JWTBackendError('JWT payload missing key "api_key_id"')
            try:
                api_key_instance = ScopedAPIKey.objects.get(id=payload['api_key_id'])
                if api_key_instance.has_expired or api_key_instance.revoked:
                    raise JWTBackendError('API Key has expired or is revoked')
                instance.set_context(api_key_instance=api_key_instance)
            except ScopedAPIKey.DoesNotExist:
                raise JWTBackendError(f'No ScopedAPIKey with id "{payload["api_key_id"]}" found')
        return instance
