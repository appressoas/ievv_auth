from django.conf import settings
from django.utils import timezone


DEFAULT_SETTINGS = {
    'ACCESS_TOKEN_LIFETIME': timezone.timedelta(minutes=2),
    'REFRESH_TOKEN_LIFETIME': timezone.timedelta(days=1),
    'BLACKLIST_AFTER_ROTATION': True,

    'ALGORITHM': 'HS256',
    'SIGNING_KEY': settings.SECRET_KEY,
    'VERIFYING_KEY': None,
    'AUDIENCE': None,
    'ISSUER': None,

    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
    'TOKEN_TYPE_CLAIM': 'token_type',

    'JTI_CLAIM': 'jti',

    'SLIDING_TOKEN_REFRESH_EXP_CLAIM': 'refresh_exp',
    'SLIDING_TOKEN_LIFETIME': timezone.timedelta(minutes=5),
    'SLIDING_TOKEN_REFRESH_LIFETIME': timezone.timedelta(days=1),
}

GLOBAL_SETTINGS = {
    'AUTH_HEADER_TYPES': ('Bearer',)
}
