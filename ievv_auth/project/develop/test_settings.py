from ievv_auth.project.develop.common_settings import *

# Disable migrations when running tests
class DisableMigrations(object):

    def __contains__(self, item):
        return True

    def __getitem__(self, item):
        import django
        if django.VERSION[0:3] > (1, 11, 0):
            return None
        return 'notmigrations'

MIGRATION_MODULES = DisableMigrations()
