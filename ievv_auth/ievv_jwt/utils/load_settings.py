from django.conf import settings

from ievv_auth.ievv_jwt.settings import DEFAULT_SETTINGS, GLOBAL_SETTINGS
from ievv_auth.ievv_jwt.utils.deep_merge import deep_merge


def load_settings(backend_type='default'):
    ievv_jwt_settings = getattr(settings, 'IEVV_JWT', None)
    if ievv_jwt_settings:
        default_settings = ievv_jwt_settings.get('default', DEFAULT_SETTINGS)
        backend_settings = ievv_jwt_settings.get(backend_type, default_settings)
        merged_settings = deep_merge(default_settings, backend_settings)
        return deep_merge(DEFAULT_SETTINGS, merged_settings)
    return DEFAULT_SETTINGS


def load_global_settings():
    ievv_jwt_settings = getattr(settings, 'IEVV_JWT', None)
    if ievv_jwt_settings:
        global_settings = ievv_jwt_settings.get('global', GLOBAL_SETTINGS)
        return deep_merge(GLOBAL_SETTINGS, global_settings)
    return GLOBAL_SETTINGS
