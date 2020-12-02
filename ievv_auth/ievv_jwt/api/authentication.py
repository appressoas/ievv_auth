from rest_framework import HTTP_HEADER_ENCODING, authentication
from rest_framework.exceptions import AuthenticationFailed
from django.utils.translation import gettext_lazy

from ievv_auth.ievv_jwt.backends.backend_registry import get_backend_from_raw_jwt
from ievv_auth.ievv_jwt.exceptions import JWTBackendError
from ievv_auth.ievv_jwt.utils.load_settings import load_global_settings

ievv_jwt_global_settings = load_global_settings()
AUTH_HEADER_TYPES = ievv_jwt_global_settings['AUTH_HEADER_TYPES']

AUTH_HEADER_TYPE_BYTES = set(
    h.encode(HTTP_HEADER_ENCODING)
    for h in AUTH_HEADER_TYPES
)


class JWTAuthentication(authentication.BaseAuthentication):
    www_authenticate_realm = 'api'

    def authenticate(self, request):
        header = self.get_header(request)
        if header is None:
            return None

        raw_token = self.get_raw_token(header)
        if raw_token is None:
            return None

        backend_class = get_backend_from_raw_jwt(raw_token)
        if backend_class:
            backend = backend_class.make_instance_from_raw_jwt(raw_token)
            try:
                payload = backend.decode(token=raw_token, verify=True)
                return None, payload
            except JWTBackendError:
                raise AuthenticationFailed('Token verification failed, token is invalid or has expired')
        raise AuthenticationFailed('No matching backend found for token')

    def get_header(self, request):
        """
        Extracts the header containing the JSON web token from the given
        request.
        """
        header = request.META.get('HTTP_AUTHORIZATION')

        if isinstance(header, str):
            # Work around django test client oddness
            header = header.encode(HTTP_HEADER_ENCODING)

        return header

    def authenticate_header(self, request):

        return '{0} realm="{1}"'.format(
            AUTH_HEADER_TYPES[0],
            self.www_authenticate_realm,
        )

    def get_raw_token(self, header):
        """
        Extracts an unvalidated JSON web token from the given "Authorization"
        header value.
        """
        parts = header.split()

        if len(parts) == 0:
            # Empty AUTHORIZATION header sent
            return None

        if parts[0] not in AUTH_HEADER_TYPE_BYTES:
            # Assume the header does not contain a JSON web token
            return None

        if len(parts) != 2:
            raise AuthenticationFailed(
                gettext_lazy('Authorization header must contain two space-delimited values'),
                code='bad_authorization_header',
            )

        return parts[1]
