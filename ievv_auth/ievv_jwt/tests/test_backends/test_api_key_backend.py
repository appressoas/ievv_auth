import base64
import json
from calendar import timegm
from unittest import mock
from unittest.mock import PropertyMock

import jwt as py_jwt
from django.test import TestCase
from django.utils import timezone
from model_bakery import baker

from ievv_auth.ievv_jwt.backends.api_key_backend import ApiKeyBackend
from ievv_auth.ievv_jwt.exceptions import JWTBackendError


class TestApiKeyBackend(TestCase):

    def test_access_sanity(self):
        api_key = baker.make(
            'ievv_api_key.ScopedApiKey',
            base_jwt_payload={
                'scope': ['read', 'write']
            }
        )
        backend = ApiKeyBackend()
        backend.set_context(api_key_instance=api_key)
        jwt = backend.encode_access_token(base_payload={
            **api_key.base_jwt_payload
        })
        decoded = backend.decode(jwt)
        self.assertIn('exp', decoded)
        self.assertIn('iat', decoded)
        self.assertIn('jti', decoded)
        self.assertEqual(decoded['api_key_id'], api_key.id)
        self.assertEqual(decoded[backend.settings['TOKEN_TYPE_CLAIM']], 'access')
        self.assertEqual(decoded['scope'], ['read', 'write'])

    def test_refresh_sanity(self):
        api_key = baker.make(
            'ievv_api_key.ScopedApiKey',
            base_jwt_payload={
                'scope': ['read', 'write']
            }
        )
        backend = ApiKeyBackend()
        backend.set_context(api_key_instance=api_key)
        jwt = backend.encode_refresh_token(base_payload={
            **api_key.base_jwt_payload
        })
        decoded = backend.decode(jwt)
        self.assertIn('exp', decoded)
        self.assertIn('iat', decoded)
        self.assertIn('jti', decoded)
        self.assertEqual(decoded['api_key_id'], api_key.id)
        self.assertEqual(decoded[backend.settings['TOKEN_TYPE_CLAIM']], 'refresh')
        self.assertEqual(decoded['scope'], ['read', 'write'])

    def test_access_fields_which_is_not_overridable_is_not_changed(self):
        api_key = baker.make(
            'ievv_api_key.ScopedApiKey',
            base_jwt_payload={
                'exp': 123,
                'iat': 123,
                'jti': 123
            }
        )
        backend = ApiKeyBackend()
        backend.set_context(api_key_instance=api_key)
        jwt = backend.encode_access_token(base_payload={
            **api_key.base_jwt_payload
        })
        decoded = backend.decode(jwt)
        self.assertIn('exp', decoded)
        self.assertNotEqual(decoded['exp'], 123)
        self.assertIn('iat', decoded)
        self.assertNotEqual(decoded['iat'], 123)
        self.assertIn('jti', decoded)
        self.assertNotEqual(decoded['jti'], 123)
        self.assertEqual(decoded['api_key_id'], api_key.id)

    def test_refresh_fields_which_is_not_overridable_is_not_changed(self):
        api_key = baker.make(
            'ievv_api_key.ScopedApiKey',
            base_jwt_payload={
                'exp': 123,
                'iat': 123,
                'jti': 123
            }
        )
        backend = ApiKeyBackend()
        backend.set_context(api_key_instance=api_key)
        jwt = backend.encode_refresh_token(base_payload={
            **api_key.base_jwt_payload
        })
        decoded = backend.decode(jwt)
        self.assertIn('exp', decoded)
        self.assertNotEqual(decoded['exp'], 123)
        self.assertIn('iat', decoded)
        self.assertNotEqual(decoded['iat'], 123)
        self.assertIn('jti', decoded)
        self.assertNotEqual(decoded['jti'], 123)
        self.assertEqual(decoded['api_key_id'], api_key.id)

    def test_access_verify_intercepted_payload_extend_expiration(self):
        api_key = baker.make(
            'ievv_api_key.ScopedApiKey',
            base_jwt_payload={
                'scope': ['read', 'write']
            }
        )
        backend = ApiKeyBackend()
        backend.set_context(api_key_instance=api_key)
        jwt = backend.encode_access_token(base_payload={
            **api_key.base_jwt_payload
        })
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

    def test_refresh_intercepted_payload_extend_expiration(self):
        api_key = baker.make(
            'ievv_api_key.ScopedApiKey',
            base_jwt_payload={
                'scope': ['read', 'write']
            }
        )
        backend = ApiKeyBackend()
        backend.set_context(api_key_instance=api_key)
        jwt = backend.encode_refresh_token(base_payload={
            **api_key.base_jwt_payload
        })
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
        api_key = baker.make(
            'ievv_api_key.ScopedApiKey',
            base_jwt_payload={
                'scope': ['read', 'write']
            }
        )
        backend = ApiKeyBackend()
        backend.set_context(api_key_instance=api_key)
        jwt = backend.encode_access_token(base_payload={
            **api_key.base_jwt_payload
        })
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
        api_key = baker.make(
            'ievv_api_key.ScopedApiKey',
            base_jwt_payload={
                'scope': ['read', 'write']
            }
        )
        backend = ApiKeyBackend()
        backend.set_context(api_key_instance=api_key)
        jwt = backend.encode_refresh_token(base_payload={
            **api_key.base_jwt_payload
        })
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

    def test_sign_access_jwt_with_another_secret(self):
        api_key = baker.make(
            'ievv_api_key.ScopedApiKey',
            base_jwt_payload={
                'scope': ['read', 'write']
            }
        )
        backend = ApiKeyBackend()
        backend.set_context(api_key_instance=api_key)
        jwt = backend.encode_access_token(base_payload={
            **api_key.base_jwt_payload
        })
        decoded = backend.decode(jwt)
        new_jwt = py_jwt.encode(payload=decoded, key='asdxxxxxxxxxxxxxxxxxxxxxxxxxxx')
        with self.assertRaisesMessage(JWTBackendError, 'Token is invalid or expired'):
            backend.decode(new_jwt, verify=True)

    def test_sign_refresh_jwt_with_another_secret(self):
        api_key = baker.make(
            'ievv_api_key.ScopedApiKey',
            base_jwt_payload={
                'scope': ['read', 'write']
            }
        )
        backend = ApiKeyBackend()
        backend.set_context(api_key_instance=api_key)
        jwt = backend.encode_refresh_token(base_payload={
            **api_key.base_jwt_payload
        })
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
                    'ievv_auth.ievv_jwt.backends.api_key_backend.ApiKeyBackend.access_token_expiration',
                    new_callable=PropertyMock,
                    return_value=timezone.now() - timezone.timedelta(days=1)):
                api_key = baker.make(
                    'ievv_api_key.ScopedApiKey',
                    base_jwt_payload={
                        'scope': ['read', 'write']
                    }
                )
                backend = ApiKeyBackend()
                backend.set_context(api_key_instance=api_key)
                jwt = backend.encode_access_token(base_payload={
                    **api_key.base_jwt_payload
                })
                with self.assertRaisesMessage(JWTBackendError, 'Token is invalid or expired'):
                    backend.decode(jwt, verify=True)

    def test_refresh_token_has_expired(self):
        with self.settings(IEVV_JWT={
            'default': {
                'REFRESH_TOKEN_LIFETIME': timezone.timedelta(minutes=0),
            }
        }):
            with mock.patch(
                    'ievv_auth.ievv_jwt.backends.api_key_backend.ApiKeyBackend.refresh_token_expiration',
                    new_callable=PropertyMock,
                    return_value=timezone.now() - timezone.timedelta(days=1)):
                api_key = baker.make(
                    'ievv_api_key.ScopedApiKey',
                    base_jwt_payload={
                        'scope': ['read', 'write']
                    }
                )
                backend = ApiKeyBackend()
                backend.set_context(api_key_instance=api_key)
                jwt = backend.encode_refresh_token(base_payload={
                    **api_key.base_jwt_payload
                })
                with self.assertRaisesMessage(JWTBackendError, 'Token is invalid or expired'):
                    backend.decode(jwt, verify=True)

    def test_make_instance_from_raw_jwt(self):
        api_key = baker.make(
            'ievv_api_key.ScopedApiKey',
            base_jwt_payload={
                'scope': ['read', 'write']
            }
        )
        backend = ApiKeyBackend()
        backend.set_context(api_key_instance=api_key)
        jwt = backend.encode_access_token(base_payload={
            **api_key.base_jwt_payload
        })
        backend_instance = ApiKeyBackend.make_instance_from_raw_jwt(raw_jwt=jwt)
        self.assertIsInstance(backend_instance, ApiKeyBackend)

    def test_make_authenticate_success_access_token_only_response(self):
        with self.settings(IEVV_JWT={
            'default': {
                'REFRESH_TOKEN_LIFETIME': None,
            }
        }):
            with mock.patch(
                'ievv_auth.ievv_jwt.backends.api_key_backend.ApiKeyBackend.encode_access_token',
                return_value='test'
            ):
                api_key = baker.make(
                    'ievv_api_key.ScopedApiKey',
                    base_jwt_payload={
                        'scope': ['read', 'write']
                    }
                )
                backend = ApiKeyBackend()
                backend.set_context(api_key_instance=api_key)
                self.assertDictEqual(
                    backend.make_authenticate_success_response(
                        base_payload={
                            **api_key.base_jwt_payload
                        }),
                    {'access': 'test'}
                )

    def test_make_authenticate_success_access_refresh_response(self):
        with self.settings(IEVV_JWT={
            'default': {
                'REFRESH_TOKEN_LIFETIME': timezone.timedelta(days=1),
            }
        }):
            with mock.patch(
                'ievv_auth.ievv_jwt.backends.api_key_backend.ApiKeyBackend.encode_access_token',
                return_value='access token'
            ):
                with mock.patch(
                        'ievv_auth.ievv_jwt.backends.api_key_backend.ApiKeyBackend.encode_refresh_token',
                        return_value='refresh token'
                ):
                    api_key = baker.make(
                        'ievv_api_key.ScopedApiKey',
                        base_jwt_payload={
                            'scope': ['read', 'write']
                        }
                    )
                    backend = ApiKeyBackend()
                    backend.set_context(api_key_instance=api_key)
                    self.assertDictEqual(
                        backend.make_authenticate_success_response(
                            base_payload={
                                **api_key.base_jwt_payload
                            }),
                        {'access': 'access token', 'refresh': 'refresh token'}
                    )
