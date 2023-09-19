import typing as t
import json

from uuid import uuid4
import logging
import jwt
from django.utils import timezone
from django.utils.functional import cached_property
from django.conf import settings
from jwt import InvalidTokenError, ExpiredSignatureError

from ievv_auth.ievv_jwt.exceptions import JWTBackendError
from ievv_auth.ievv_jwt.utils import load_settings, DateTimeEncoder
logger = logging.Logger(__name__)

ALLOWED_ALGORITHMS = [
    'HS256',
    'HS384',
    'HS512',
    'RS256',
    'RS384',
    'RS512',
]

if t.TYPE_CHECKING:
    from ievv_auth.ievv_jwt_blacklist.models import AbstractBlacklistedToken, AbstractIssuedToken


class AbstractBackend:
    @classmethod
    def get_backend_name(cls):
        raise NotImplementedError('Please implement get_backend_name')

    @cached_property
    def settings(self):
        return load_settings(self.__class__.get_backend_name())

    @property
    def blacklist_app(self):
        return 'ievv_auth.ievv_jwt_blacklist'

    @property
    def use_blacklist(self):
        return self.settings['USE_BLACKLIST']

    @property
    def blacklist_after_rotation(self):
        return self.settings['BLACKLIST_AFTER_ROTATION']

    @property
    def algorithm(self):
        algorithm = self.settings['ALGORITHM']
        if algorithm not in ALLOWED_ALGORITHMS:
            raise JWTBackendError(f'{self.algorithm} is not one of the allowed algorithms')
        return algorithm

    @property
    def update_last_login(self):
        return self.settings['UPDATE_LAST_LOGIN']

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
    def refresh_token_expiration(self):
        if not self.settings['REFRESH_TOKEN_LIFETIME']:
            return None
        return timezone.now() + self.settings['REFRESH_TOKEN_LIFETIME']

    @property
    def jti(self):
        return uuid4().hex

    def set_context(self, *args, **kwargs):
        """
        Should be overridden to set additional context
        """
        pass

    @property
    def issued_token_model(self) -> t.Type['AbstractIssuedToken']:
        raise NotImplementedError('Should implement property issued_token_model')

    @property
    def blacklisted_token_model(self) -> t.Type['AbstractBlacklistedToken']:
        raise NotImplementedError('Should implement property blacklisted_token_model')

    def create_issued_token(self, token, payload, issued_at, expires_at, jti) -> 'AbstractIssuedToken':
        raise NotImplementedError('Should implement create_issued_token')

    def __make_access_token_payload(self, base_payload: dict | None = None) -> dict:
        payload = self.make_access_token_payload()
        if base_payload is not None:
            payload.update(base_payload)
        if self.audience:
            payload['aud'] = self.audience

        if self.issuer:
            payload['iss'] = self.issuer

        if self.subject:
            payload['sub'] = self.subject

        payload['exp'] = self.access_token_expiration
        payload['iat'] = timezone.now()
        payload[self.settings['TOKEN_TYPE_CLAIM']] = 'access'
        payload[self.settings['JTI_CLAIM']] = self.jti
        payload['jwt_backend_name'] = self.__class__.get_backend_name()
        return payload

    def __make_refresh_token_payload(self, base_payload: dict | None = None) -> dict:
        payload = self.make_refresh_token_payload()
        if base_payload is not None:
            payload.update(base_payload)
        if self.audience:
            payload['aud'] = self.audience

        if self.issuer:
            payload['iss'] = self.issuer

        if self.subject:
            payload['sub'] = self.subject

        payload['exp'] = self.refresh_token_expiration
        payload['iat'] = timezone.now()
        payload[self.settings['TOKEN_TYPE_CLAIM']] = 'refresh'
        payload[self.settings['JTI_CLAIM']] = self.jti
        payload['jwt_backend_name'] = self.__class__.get_backend_name()
        return payload

    def encode_access_token(self, base_payload=None) -> str:
        token = jwt.encode(
            self.__make_access_token_payload(base_payload=base_payload),
            self.signing_key,
            algorithm=self.algorithm
        )
        return token

    def encode_refresh_token(self, base_payload=None) -> str:
        payload = self.__make_refresh_token_payload(base_payload=base_payload)
        token = jwt.encode(
            payload,
            self.signing_key,
            algorithm=self.algorithm
        )
        if self.blacklist_app not in settings.INSTALLED_APPS and \
                self.use_blacklist:
            logger.warning(
                f'USE_BLACKLIST is: {self.use_blacklist} '
                f'while ievv_auth.ievv_jwt_blacklist is not in INSTALLED_APPS'
            )
            return token

        if self.blacklist_app in settings.INSTALLED_APPS and self.use_blacklist:
            self.create_issued_token(
                token=token,
                payload=json.dumps(payload, cls=DateTimeEncoder),
                issued_at=payload['iat'],
                expires_at=payload['exp'],
                jti=payload[self.settings['JTI_CLAIM']]
            )
        return token

    def decode(self, token, verify=True):
        try:
            return jwt.decode(token, self.verifying_key, algorithms=[self.algorithm], verify=verify,
                              audience=self.audience, issuer=self.issuer,
                              options={'verify_aud': self.audience is not None})
        except InvalidTokenError:
            raise JWTBackendError('Token is invalid or expired')

    def refresh(self, token):
        payload = self.decode(token, verify=True)
        jti = payload[self.settings['JTI_CLAIM']]
        if payload[self.settings['TOKEN_TYPE_CLAIM']] != 'refresh':
            raise JWTBackendError('Token is not a refresh token')
        if self.blacklist_app not in settings.INSTALLED_APPS and \
                self.use_blacklist:
            logger.warning(
                f'USE_BLACKLIST is: {self.use_blacklist} '
                f'while ievv_auth.ievv_jwt_blacklist is not in INSTALLED_APPS'
            )
            return self.make_authenticate_success_response()
        if self.use_blacklist and \
                self.blacklisted_token_model.objects.filter(token__jti=jti).exists():
            raise JWTBackendError('Token is not valid')
        if self.use_blacklist and self.blacklist_after_rotation:
            issued_token = self.issued_token_model.objects.filter(jti=jti).first()
            if issued_token is not None:
                issued_token.blacklist_token()
        return self.make_authenticate_success_response()

    def make_access_token_payload(self) -> dict:
        return {}

    def make_refresh_token_payload(self) -> dict:
        return {}

    def make_authenticate_success_response(self, *args, **kwargs) -> dict:
        response = {
            'access': self.encode_access_token()
        }
        if self.refresh_token_expiration is not None:
            response['refresh'] = self.encode_refresh_token()
        return response

    @classmethod
    def make_instance_from_raw_jwt(cls, raw_jwt, use_context=False, *args, **kwargs) -> 'AbstractBackend':
        """
        Makes instance from raw jwt.
        Args:
            raw_jwt:
            use_context: if true the extra context should be set see::`AbstractBackend.set_context`

        Returns:
            instance of AbstractBackend

        """
        return cls()


class BaseBackend(AbstractBackend):
    @classmethod
    def get_backend_name(cls):
        return 'default'

    @property
    def use_blacklist(self):
        return False

    @property
    def blacklist_after_rotation(self):
        return False
