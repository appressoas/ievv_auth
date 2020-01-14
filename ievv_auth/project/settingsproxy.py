import json
import os

"""
A simple Django settings module proxy that lets us configure Django
using the DJANGOENV environment variable.

Example (running tests)::

    $ DJANGOENV=test python manage.py test

Defaults to the ``develop`` enviroment, so developers can use ``python
manage.py`` without anything extra during development.
"""

DJANGOENV = os.environ.get('DJANGOENV', 'develop')


def _load_develop_environment_from_file():
    if os.path.exists('develop-environment.json'):
        environment_dict = json.loads(open('develop-environment.json', 'r').read())
        for key, value in environment_dict.items():
            if key.upper() == key:
                os.environ[key] = value

if DJANGOENV == 'develop':  # Used for local development
    _load_develop_environment_from_file()
    from ievv_auth.project.develop.develop_settings import *
elif DJANGOENV == 'test':  # Used when running the Django tests locally
    _load_develop_environment_from_file()
    from ievv_auth.project.develop.test_settings import *
# elif DJANGOENV == 'production':  # Used in production
#     from ievv_auth.project.production.settings import *
else:
    raise ValueError('Invalid value for the DJANGOENV environment variable: {}'.format(DJANGOENV))
