from django.test import TestCase
from ievv_auth.ievv_jwt.settings import DEFAULT_SETTINGS
from ievv_auth.ievv_jwt.utils.load_settings import load_settings


class TestLoadSettings(TestCase):
    def test_load_settings_sanity(self):
        settings = load_settings(backend_type='default')
        self.assertDictEqual(
            settings,
            DEFAULT_SETTINGS
        )

    def test_load_settings_with_default_settings_override(self):
        with self.settings(IEVV_JWT={
            'default': {
                'ISSUER': 'ievv issuer',
            }
        }):
            settings = load_settings(backend_type='default')
            settings2 = DEFAULT_SETTINGS
            settings2['ISSUER'] = 'ievv issuer'
            self.assertDictEqual(
                settings,
                settings2
            )

    def test_load_default_settings_with_non_existing_jwt_backend_type(self):
        settings = load_settings(backend_type='non-existing-backend')
        self.assertDictEqual(
            settings,
            DEFAULT_SETTINGS
        )

    def test_load_existing_backend_type_settings(self):
        with self.settings(IEVV_JWT={
            'test_backend': {
                'ISSUER': 'test issuer',
                'AUDIENCE': 'test audience'
            }
        }):
            settings = load_settings(backend_type='test_backend')
            settings2 = DEFAULT_SETTINGS
            settings2['ISSUER'] = 'test issuer'
            settings2['AUDIENCE'] = 'test audience'
            self.assertDictEqual(
                settings,
                DEFAULT_SETTINGS
            )

    def test_load_existing_backend_type_settings_with_default_settings_override(self):
        with self.settings(IEVV_JWT={
            'default': {
                'ISSUER': 'ievv issuer'
            },
            'test_backend': {
                'AUDIENCE': 'test audience'
            }
        }):
            settings = load_settings(backend_type='test_backend')
            settings2 = DEFAULT_SETTINGS
            settings2['ISSUER'] = 'ievv issuer'
            settings2['AUDIENCE'] = 'test audience'
            self.assertDictEqual(
                settings,
                DEFAULT_SETTINGS
            )
