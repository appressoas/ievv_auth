from ievv_auth.project.default.settings import *


DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": "dbdev.sqlite3",
    }
}
DATABASES['default']['PORT'] = 27253
