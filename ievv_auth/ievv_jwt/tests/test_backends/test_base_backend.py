import base64
import json
from calendar import timegm
from unittest import mock
from unittest.mock import PropertyMock

import jwt as py_jwt
from django.test import TestCase, override_settings
from django.utils import timezone

from ievv_auth.ievv_jwt.backends.base_backend import BaseBackend
from ievv_auth.ievv_jwt.exceptions import JWTBackendError


class TestBaseBackend(TestCase):

    def test_access_token_encode_base_backend(self):
        backend = BaseBackend()
        jwt = backend.encode_access_token()
        decoded = backend.decode(jwt)
        self.assertIn('exp', decoded)
        self.assertIn('iat', decoded)
        self.assertIn('jti', decoded)
        self.assertEqual(decoded[backend.settings['TOKEN_TYPE_CLAIM']], 'access')

    def test_refresh_token_encode_base_backend(self):
        backend = BaseBackend()
        jwt = backend.encode_refresh_token()
        decoded = backend.decode(jwt)
        self.assertIn('exp', decoded)
        self.assertIn('iat', decoded)
        self.assertIn('jti', decoded)
        self.assertEqual(decoded[backend.settings['TOKEN_TYPE_CLAIM']], 'refresh')

    def test_access_verify_intercepted_payload_extend_expiration(self):
        backend = BaseBackend()
        jwt = backend.encode_access_token()
        [header, _, secret] = jwt.split('.')
        decoded = backend.decode(jwt)
        decoded['exp'] = timegm((timezone.now() + timezone.timedelta(weeks=200)).utctimetuple())
        payload = base64.urlsafe_b64encode(
            json.dumps(
                decoded,
                separators=(',', ':')
            ).encode('utf-8')
        ).decode('utf-8')
        new_jwt = f'{header}.{payload}.{secret}'
        with self.assertRaisesMessage(JWTBackendError, 'Token is invalid or expired'):
            backend.decode(new_jwt, verify=True)

    def test_refresh_verify_intercepted_payload_extend_expiration(self):
        backend = BaseBackend()
        jwt = backend.encode_refresh_token()
        [header, _, secret] = jwt.split('.')
        decoded = backend.decode(jwt)
        decoded['exp'] = timegm((timezone.now() + timezone.timedelta(weeks=200)).utctimetuple())
        payload = base64.urlsafe_b64encode(
            json.dumps(
                decoded,
                separators=(',', ':')
            ).encode('utf-8')
        ).decode('utf-8')
        new_jwt = f'{header}.{payload}.{secret}'
        with self.assertRaisesMessage(JWTBackendError, 'Token is invalid or expired'):
            backend.decode(new_jwt, verify=True)

    def test_access_verify_intercepted_payload_added_additional_scope(self):
        backend = BaseBackend()
        jwt = backend.encode_access_token()
        [header, _, secret] = jwt.split('.')
        decoded = backend.decode(jwt)
        decoded['scope'] = 'admin'
        payload = base64.urlsafe_b64encode(
            json.dumps(
                decoded,
                separators=(',', ':')
            ).encode('utf-8')
        ).decode('utf-8')
        new_jwt = f'{header}.{payload}.{secret}'
        with self.assertRaisesMessage(JWTBackendError, 'Token is invalid or expired'):
            backend.decode(new_jwt, verify=True)

    def test_refresh_verify_intercepted_payload_added_additional_scope(self):
        backend = BaseBackend()
        jwt = backend.encode_refresh_token()
        [header, _, secret] = jwt.split('.')
        decoded = backend.decode(jwt)
        decoded['scope'] = 'admin'
        payload = base64.urlsafe_b64encode(
            json.dumps(
                decoded,
                separators=(',', ':')
            ).encode('utf-8')
        ).decode('utf-8')
        new_jwt = f'{header}.{payload}.{secret}'
        with self.assertRaisesMessage(JWTBackendError, 'Token is invalid or expired'):
            backend.decode(new_jwt, verify=True)

    def test_access_sign_jwt_with_another_secret(self):
        backend = BaseBackend()
        jwt = backend.encode_access_token()
        decoded = backend.decode(jwt)
        new_jwt = py_jwt.encode(payload=decoded, key='asdxxxxxxxxxxxxxxxxxxxxxxxxxxx')
        with self.assertRaisesMessage(JWTBackendError, 'Token is invalid or expired'):
            backend.decode(new_jwt, verify=True)

    def test_refresh_sign_jwt_with_another_secret(self):
        backend = BaseBackend()
        jwt = backend.encode_refresh_token()
        decoded = backend.decode(jwt)
        new_jwt = py_jwt.encode(payload=decoded, key='asdxxxxxxxxxxxxxxxxxxxxxxxxxxx')
        with self.assertRaisesMessage(JWTBackendError, 'Token is invalid or expired'):
            backend.decode(new_jwt, verify=True)

    def test_access_token_has_expired(self):
        with self.settings(IEVV_JWT={
            'default': {
                'ACCESS_TOKEN_LIFETIME': timezone.timedelta(minutes=0),
            }
        }):
            with mock.patch(
                    'ievv_auth.ievv_jwt.backends.base_backend.BaseBackend.access_token_expiration',
                    new_callable=PropertyMock,
                    return_value=timezone.now() - timezone.timedelta(days=1)):
                backend = BaseBackend()
                jwt = backend.encode_access_token()
                with self.assertRaisesMessage(JWTBackendError, 'Token is invalid or expired'):
                    backend.decode(jwt, verify=True)

    def test_refresh_token_has_expired(self):
        with self.settings(IEVV_JWT={
            'default': {
                'REFRESH_TOKEN_LIFETIME': timezone.timedelta(minutes=0)
            }
        }):
            with mock.patch(
                    'ievv_auth.ievv_jwt.backends.base_backend.BaseBackend.refresh_token_expiration',
                    new_callable=PropertyMock,
                    return_value=timezone.now() - timezone.timedelta(days=1)):
                backend = BaseBackend()
                jwt = backend.encode_refresh_token()
                with self.assertRaisesMessage(JWTBackendError, 'Token is invalid or expired'):
                    backend.decode(jwt, verify=True)
