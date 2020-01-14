from ievv_auth.project.default.settings import *

from django_dbdev.backends.postgres import DBSETTINGS


DATABASES = {
    'default': DBSETTINGS
}
DATABASES['default']['PORT'] = 27253

INSTALLED_APPS += [
    'django_dbdev'
]
