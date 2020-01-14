import jwt

from ievv_auth.ievv_api_key.models import ScopedAPIKey
from ievv_auth.ievv_jwt.backends.base_backend import AbstractBackend
from ievv_auth.ievv_jwt.exceptions import JWTBackendError


class ApiKeyBackend(AbstractBackend):

    @classmethod
    def get_backend_name(cls):
        return 'api-key'

    def __init__(self, api_key_id, *args, **kwargs):
        super(ApiKeyBackend, self).__init__(*args, **kwargs)
        try:
            self.api_key_instance = ScopedAPIKey.objects.get(id=api_key_id)
        except ScopedAPIKey.DoesNotExist:
            raise JWTBackendError('API key is not valid')

    def make_payload(self):
        payload = super(ApiKeyBackend, self).make_payload()
        api_key_scope_payload = self.api_key_instance.base_jwt_payload
        api_key_scope_payload['api_key_id'] = self.api_key_instance.id
        api_key_scope_payload.update(**payload)
        return api_key_scope_payload

    @classmethod
    def make_instance_from_raw_jwt(cls, raw_jwt):
        payload = jwt.decode(jwt=raw_jwt, verify=False)
        return cls(api_key_id=payload['api_key_id'])

    def make_authenticate_success_response(self, *args, **kwargs):
        return {
            'access': self.encode()
        }
