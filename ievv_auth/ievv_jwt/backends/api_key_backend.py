import jwt

from ievv_auth.ievv_api_key.models import ScopedAPIKey
from ievv_auth.ievv_jwt.backends.base_backend import AbstractBackend
from ievv_auth.ievv_jwt.exceptions import JWTBackendError


class ApiKeyBackend(AbstractBackend):

    @classmethod
    def get_backend_name(cls):
        return 'api-key'

    def make_authenticate_success_response(self, base_payload, *args, **kwargs):
        return {
            'access': self.encode(base_payload=base_payload)
        }
