from django.conf import settings
from django.utils import timezone


DEFAULT_SETTINGS = {
    'ACCESS_TOKEN_LIFETIME': timezone.timedelta(minutes=2),             # Access token lifetime
    'REFRESH_TOKEN_LIFETIME': timezone.timedelta(days=1),               # Refresh token lifetime if None refresh token is not issued
    'USE_BLACKLIST': True,                                              # Use the blacklist app, Default backend does not support blacklist
    'BLACKLIST_AFTER_ROTATION': True,                                   # Blacklist token after rotation, Default backend does not support blacklist

    'ALGORITHM': 'HS256',                                               # Algorithm
    'SIGNING_KEY': settings.SECRET_KEY,                                 # Signing key
    'VERIFYING_KEY': None,                                              # Verifying key used when using private/public key algorithms such as RSA
    'AUDIENCE': None,                                                   # Not mandatory Audience could be s resource server url or a list of urls where the token is intended for
    'ISSUER': None,                                                     # Not mandatory issuer could be a url, domain, organization or person.

    'TOKEN_TYPE_CLAIM': 'token_type',                                   # Token type payload name
    'UPDATE_LAST_LOGIN': True,                                          # Only used by user auth

    'JTI_CLAIM': 'jti',

    'SLIDING_TOKEN_REFRESH_EXP_CLAIM': 'refresh_exp',
    'SLIDING_TOKEN_LIFETIME': timezone.timedelta(minutes=5),
    'SLIDING_TOKEN_REFRESH_LIFETIME': timezone.timedelta(days=1),
}

GLOBAL_SETTINGS = {
    'AUTH_HEADER_TYPES': ('Bearer',)
}
