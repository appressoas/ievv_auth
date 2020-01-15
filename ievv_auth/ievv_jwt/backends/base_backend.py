from uuid import uuid4

import jwt
from django.utils import timezone
from django.utils.functional import cached_property
from jwt import InvalidTokenError

from ievv_auth.ievv_jwt.exceptions import JWTBackendError
from ievv_auth.ievv_jwt.utils.load_settings import load_settings

ALLOWED_ALGORITHMS = [
    'HS256',
    'HS384',
    'HS512',
    'RS256',
    'RS384',
    'RS512',
]


class AbstractBackend:

    @classmethod
    def get_backend_name(cls):
        raise NotImplementedError('Please implement get_backend_name')

    @cached_property
    def settings(self):
        return load_settings(self.__class__.get_backend_name())

    @property
    def algorithm(self):
        algorithm = self.settings['ALGORITHM']
        if algorithm not in ALLOWED_ALGORITHMS:
            raise JWTBackendError(f'{self.algorithm} is not one of the allowed algorithms')
        return algorithm

    @property
    def signing_key(self):
        return self.settings['SIGNING_KEY']

    @property
    def audience(self):
        return self.settings.get('AUDIENCE', None)

    @property
    def issuer(self):
        return self.settings.get('ISSUER', None)

    @property
    def subject(self):
        return self.settings.get('SUBJECT', None)

    @property
    def verifying_key(self):
        if self.algorithm.startswith('HS'):
            return self.signing_key
        if not self.settings['VERIFYING_KEY']:
            raise JWTBackendError(f'Verifying key cannot be None when algorithm is {self.algorithm}')
        return self.settings['VERIFYING_KEY']

    @property
    def access_token_expiration(self):
        return timezone.now() + self.settings['ACCESS_TOKEN_LIFETIME']

    @property
    def jti(self):
        return uuid4().hex

    def make_payload(self, base_payload=None):
        if not base_payload:
            payload = {}
        else:
            payload = base_payload
        if self.audience:
            payload['aud'] = self.audience

        if self.issuer:
            payload['iss'] = self.issuer

        if self.subject:
            payload['sub'] = self.subject

        payload['exp'] = self.access_token_expiration
        payload['iat'] = timezone.now()
        payload[self.settings['JTI_CLAIM']] = self.jti
        payload['jwt_backend_name'] = self.__class__.get_backend_name()
        return payload

    def encode(self, base_payload=None):
        token = jwt.encode(
            self.make_payload(base_payload=base_payload),
            self.signing_key,
            algorithm=self.algorithm
        )
        return token.decode('utf-8')

    def decode(self, token, verify=True):
        try:
            return jwt.decode(token, self.verifying_key, algorithms=[self.algorithm], verify=verify,
                              audience=self.audience, issuer=self.issuer,
                              options={'verify_aud': self.audience is not None})
        except InvalidTokenError:
            raise JWTBackendError('Token is invalid or expired')

    def make_authenticate_success_response(self, *args, **kwargs):
        return {}

    @classmethod
    def make_instance_from_raw_jwt(cls, raw_jwt):
        return cls()


class BaseBackend(AbstractBackend):
    @classmethod
    def get_backend_name(cls):
        return 'default'
