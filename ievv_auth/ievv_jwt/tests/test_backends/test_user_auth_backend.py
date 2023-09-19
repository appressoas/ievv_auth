import base64
import json
from calendar import timegm
from unittest import mock
from unittest.mock import PropertyMock

import jwt as py_jwt
from django.test import TestCase
from django.utils import timezone
from model_bakery import baker
from django.conf import settings

from ievv_auth.ievv_jwt.backends.user_auth_backend import UserAuthBackend
from ievv_auth.ievv_jwt.exceptions import JWTBackendError


class TestUserAuthBackend(TestCase):

    def test_access_token_sanity(self):
        user = baker.make(settings.AUTH_USER_MODEL)
        backend = UserAuthBackend()
        backend.set_context(user_instance=user)
        jwt = backend.encode_access_token(base_payload={
            'scope': ['read', 'write']
        })
        decoded = backend.decode(jwt)
        self.assertIn('exp', decoded)
        self.assertIn('iat', decoded)
        self.assertIn('jti', decoded)
        self.assertEqual(decoded['user_id'], user.id)
        self.assertEqual(decoded['scope'], ['read', 'write'])
        self.assertEqual(decoded[backend.settings['TOKEN_TYPE_CLAIM']], 'access')

    def test_refresh_token_sanity(self):
        user = baker.make(settings.AUTH_USER_MODEL)
        backend = UserAuthBackend()
        backend.set_context(user_instance=user)
        jwt = backend.encode_refresh_token(base_payload={
            'scope': ['read', 'write']
        })
        decoded = backend.decode(jwt)
        self.assertIn('exp', decoded)
        self.assertIn('iat', decoded)
        self.assertIn('jti', decoded)
        self.assertEqual(decoded['user_id'], user.id)
        self.assertEqual(decoded['scope'], ['read', 'write'])
        self.assertEqual(decoded[backend.settings['TOKEN_TYPE_CLAIM']], 'refresh')

    def test_access_fields_which_is_not_overridable_is_not_changed(self):
        user = baker.make(settings.AUTH_USER_MODEL)
        backend = UserAuthBackend()
        backend.set_context(user_instance=user)
        jwt = backend.encode_access_token(base_payload={
            'exp': 123,
            'iat': 123,
            'jti': 123,
        })
        decoded = backend.decode(jwt)
        self.assertIn('exp', decoded)
        self.assertNotEqual(decoded['exp'], 123)
        self.assertIn('iat', decoded)
        self.assertNotEqual(decoded['iat'], 123)
        self.assertIn('jti', decoded)
        self.assertNotEqual(decoded['jti'], 123)
        self.assertEqual(decoded['user_id'], user.id)

    def test_refresh_fields_which_is_not_overridable_is_not_changed(self):
        user = baker.make(settings.AUTH_USER_MODEL)
        backend = UserAuthBackend()
        backend.set_context(user_instance=user)
        jwt = backend.encode_refresh_token(base_payload={
            'exp': 123,
            'iat': 123,
            'jti': 123,
        })
        decoded = backend.decode(jwt)
        self.assertIn('exp', decoded)
        self.assertNotEqual(decoded['exp'], 123)
        self.assertIn('iat', decoded)
        self.assertNotEqual(decoded['iat'], 123)
        self.assertIn('jti', decoded)
        self.assertNotEqual(decoded['jti'], 123)
        self.assertEqual(decoded['user_id'], user.id)

    def test_access_verify_intercepted_payload_extend_expiration(self):
        user = baker.make(settings.AUTH_USER_MODEL)
        backend = UserAuthBackend()
        backend.set_context(user_instance=user)
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

    def test_refresh_intercepted_payload_extend_expiration(self):
        user = baker.make(settings.AUTH_USER_MODEL)
        backend = UserAuthBackend()
        backend.set_context(user_instance=user)
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
        user = baker.make(settings.AUTH_USER_MODEL)
        backend = UserAuthBackend()
        backend.set_context(user_instance=user)
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
        user = baker.make(settings.AUTH_USER_MODEL)
        backend = UserAuthBackend()
        backend.set_context(user_instance=user)
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

    def test_sign_access_jwt_with_another_secret(self):
        user = baker.make(settings.AUTH_USER_MODEL)
        backend = UserAuthBackend()
        backend.set_context(user_instance=user)
        jwt = backend.encode_access_token()
        decoded = backend.decode(jwt)
        new_jwt = py_jwt.encode(payload=decoded, key='asdxxxxxxxxxxxxxxxxxxxxxxxxxxx')
        with self.assertRaisesMessage(JWTBackendError, 'Token is invalid or expired'):
            backend.decode(new_jwt, verify=True)

    def test_sign_refresh_jwt_with_another_secret(self):
        user = baker.make(settings.AUTH_USER_MODEL)
        backend = UserAuthBackend()
        backend.set_context(user_instance=user)
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
                    'ievv_auth.ievv_jwt.backends.user_auth_backend.UserAuthBackend.access_token_expiration',
                    new_callable=PropertyMock,
                    return_value=timezone.now() - timezone.timedelta(days=1)):
                user = baker.make(settings.AUTH_USER_MODEL)
                backend = UserAuthBackend()
                backend.set_context(user_instance=user)
                jwt = backend.encode_access_token()
                with self.assertRaisesMessage(JWTBackendError, 'Token is invalid or expired'):
                    backend.decode(jwt, verify=True)

    def test_refresh_token_has_expired(self):
        with self.settings(IEVV_JWT={
            'default': {
                'REFRESH_TOKEN_LIFETIME': timezone.timedelta(minutes=0),
            }
        }):
            with mock.patch(
                    'ievv_auth.ievv_jwt.backends.user_auth_backend.UserAuthBackend.refresh_token_expiration',
                    new_callable=PropertyMock,
                    return_value=timezone.now() - timezone.timedelta(days=1)):
                user = baker.make(settings.AUTH_USER_MODEL)
                backend = UserAuthBackend()
                backend.set_context(user_instance=user)
                jwt = backend.encode_refresh_token()
                with self.assertRaisesMessage(JWTBackendError, 'Token is invalid or expired'):
                    backend.decode(jwt, verify=True)

    def test_make_instance_from_raw_jwt(self):
        user = baker.make(settings.AUTH_USER_MODEL)
        backend = UserAuthBackend()
        backend.set_context(user_instance=user)
        jwt = backend.encode_access_token()
        backend_instance = UserAuthBackend.make_instance_from_raw_jwt(raw_jwt=jwt)
        self.assertIsInstance(backend_instance, UserAuthBackend)

    def test_make_authenticate_success_access_token_only_response(self):
        with self.settings(IEVV_JWT={
            'default': {
                'REFRESH_TOKEN_LIFETIME': None,
            }
        }):
            with mock.patch(
                'ievv_auth.ievv_jwt.backends.user_auth_backend.UserAuthBackend.encode_access_token',
                return_value='test'
            ):
                user = baker.make(settings.AUTH_USER_MODEL)
                backend = UserAuthBackend()
                backend.set_context(user_instance=user)
                self.assertDictEqual(
                    backend.make_authenticate_success_response(),
                    {'access': 'test'}
                )

    def test_make_authenticate_success_access_refresh_response(self):
        with self.settings(IEVV_JWT={
            'default': {
                'REFRESH_TOKEN_LIFETIME': timezone.timedelta(days=1),
            }
        }):
            with mock.patch(
                'ievv_auth.ievv_jwt.backends.user_auth_backend.UserAuthBackend.encode_access_token',
                return_value='access token'
            ):
                with mock.patch(
                        'ievv_auth.ievv_jwt.backends.user_auth_backend.UserAuthBackend.encode_refresh_token',
                        return_value='refresh token'
                ):
                    user = baker.make(settings.AUTH_USER_MODEL)
                    backend = UserAuthBackend()
                    backend.set_context(user_instance=user)
                    self.assertDictEqual(
                        backend.make_authenticate_success_response(),
                        {'access': 'access token', 'refresh': 'refresh token'}
                    )

    def test_refresh_token_wrong_token_type(self):
        with self.settings(IEVV_JWT={
            'default': {
                'REFRESH_TOKEN_LIFETIME': timezone.timedelta(days=1),
                'USE_BLACKLIST': True,
                'BLACKLIST_AFTER_ROTATION': True
            }
        }, INSTALLED_APPS=settings.INSTALLED_APPS_USER_BLACKLIST):
            user = baker.make(settings.AUTH_USER_MODEL)
            backend = UserAuthBackend()
            backend.set_context(user_instance=user)
            token_pair = backend.make_authenticate_success_response()
            with self.assertRaisesMessage(JWTBackendError, 'Token is not a refresh token'):
                new_token_pair = backend.refresh(token=token_pair['access'])

    def test_make_authenticate_blacklist_not_installed_in_apps(self):
        with self.settings(IEVV_JWT={
            'default': {
                'REFRESH_TOKEN_LIFETIME': timezone.timedelta(days=1),
            }
        }, INSTALLED_APPS=settings.INSTALLED_APPS_IEVV_JWT):
            user = baker.make(settings.AUTH_USER_MODEL)
            backend = UserAuthBackend()
            backend.set_context(user_instance=user)
            token_pair = backend.make_authenticate_success_response()
            self.assertIn('access', token_pair)
            self.assertIn('refresh', token_pair)
            with self.settings(INSTALLED_APPS=settings.INSTALLED_APPS_USER_BLACKLIST):
                self.assertEqual(backend.issued_token_model.objects.all().count(), 0)

    def test_make_authenticate_blacklist_in_installed_apps_but_not_enabled(self):
        with self.settings(IEVV_JWT={
            'default': {
                'REFRESH_TOKEN_LIFETIME': timezone.timedelta(days=1),
                'USE_BLACKLIST': False
            }
        }, INSTALLED_APPS=settings.INSTALLED_APPS_USER_BLACKLIST):
            user = baker.make(settings.AUTH_USER_MODEL)
            backend = UserAuthBackend()
            backend.set_context(user_instance=user)
            token_pair = backend.make_authenticate_success_response()
            self.assertIn('access', token_pair)
            self.assertIn('refresh', token_pair)
            self.assertEqual(backend.issued_token_model.objects.all().count(), 0)

    def test_make_authenticate_blacklist_in_use(self):
        with self.settings(IEVV_JWT={
            'default': {
                'REFRESH_TOKEN_LIFETIME': timezone.timedelta(days=1),
                'USE_BLACKLIST': True
            }
        }, INSTALLED_APPS=settings.INSTALLED_APPS_USER_BLACKLIST):
            user = baker.make(settings.AUTH_USER_MODEL)
            backend = UserAuthBackend()
            backend.set_context(user_instance=user)
            token_pair = backend.make_authenticate_success_response()
            self.assertIn('access', token_pair)
            self.assertIn('refresh', token_pair)
            refresh_jti = backend.decode(token_pair['refresh'])[backend.settings['JTI_CLAIM']]
            IssuedTokenModel = backend.issued_token_model
            self.assertEqual(IssuedTokenModel.objects.filter(jti=refresh_jti).count(), 1)

    def test_refresh_toke_blacklist_not_in_installed_apps(self):
        with self.settings(IEVV_JWT={
            'default': {
                'REFRESH_TOKEN_LIFETIME': timezone.timedelta(days=1),
                'USE_BLACKLIST': True
            }
        }, INSTALLED_APPS=settings.INSTALLED_APPS_API_KEY):
            user = baker.make(settings.AUTH_USER_MODEL)
            backend = UserAuthBackend()
            backend.set_context(user_instance=user)
            token_pair = backend.make_authenticate_success_response()
            new_token_pair = backend.refresh(token=token_pair['refresh'])
            self.assertIn('access', new_token_pair)
            self.assertIn('refresh', new_token_pair)
            with self.settings(INSTALLED_APPS=settings.INSTALLED_APPS_USER_BLACKLIST):
                self.assertEqual(backend.issued_token_model.objects.all().count(), 0)
                self.assertEqual(backend.blacklisted_token_model.objects.all().count(), 0)
            self.assertNotEqual(token_pair['access'], new_token_pair['access'])
            self.assertNotEqual(token_pair['refresh'], new_token_pair['refresh'])

    def test_refresh_token_blacklist_is_in_installed_apps_but_blacklist_is_disabled(self):
        with self.settings(IEVV_JWT={
            'default': {
                'REFRESH_TOKEN_LIFETIME': timezone.timedelta(days=1),
                'USE_BLACKLIST': False
            }
        }, INSTALLED_APPS=settings.INSTALLED_APPS_USER_BLACKLIST):
            user = baker.make(settings.AUTH_USER_MODEL)
            backend = UserAuthBackend()
            backend.set_context(user_instance=user)
            token_pair = backend.make_authenticate_success_response()
            new_token_pair = backend.refresh(token=token_pair['refresh'])
            self.assertIn('access', new_token_pair)
            self.assertIn('refresh', new_token_pair)
            with self.settings(INSTALLED_APPS=settings.INSTALLED_APPS_USER_BLACKLIST):
                self.assertEqual(backend.issued_token_model.objects.all().count(), 0)
                self.assertEqual(backend.blacklisted_token_model.objects.all().count(), 0)
            self.assertNotEqual(token_pair['access'], new_token_pair['access'])
            self.assertNotEqual(token_pair['refresh'], new_token_pair['refresh'])

    def test_refresh_token_is_blacklisted(self):
        with self.settings(IEVV_JWT={
            'default': {
                'REFRESH_TOKEN_LIFETIME': timezone.timedelta(days=1),
                'USE_BLACKLIST': True
            }
        }, INSTALLED_APPS=settings.INSTALLED_APPS_USER_BLACKLIST):
            user = baker.make(settings.AUTH_USER_MODEL)
            backend = UserAuthBackend()
            backend.set_context(user_instance=user)
            token_pair = backend.make_authenticate_success_response()
            refresh_jti = backend.decode(token_pair['refresh'])[backend.settings['JTI_CLAIM']]
            IssuedTokenModel = backend.issued_token_model
            BlacklistedTokenModel = backend.blacklisted_token_model
            IssuedTokenModel.objects.get(jti=refresh_jti).blacklist_token()
            self.assertEqual(BlacklistedTokenModel.objects.filter(token__jti=refresh_jti).count(), 1)
            with self.assertRaisesMessage(JWTBackendError, 'Token is not valid'):
                new_token_pair = backend.refresh(token=token_pair['refresh'])

    def test_refresh_token_blacklist_on_rotation(self):
        with self.settings(IEVV_JWT={
            'default': {
                'REFRESH_TOKEN_LIFETIME': timezone.timedelta(days=1),
                'USE_BLACKLIST': True,
                'BLACKLIST_AFTER_ROTATION': True
            }
        }, INSTALLED_APPS=settings.INSTALLED_APPS_USER_BLACKLIST):
            user = baker.make(settings.AUTH_USER_MODEL)
            backend = UserAuthBackend()
            backend.set_context(user_instance=user)
            token_pair = backend.make_authenticate_success_response()
            refresh_jti = backend.decode(token_pair['refresh'])[backend.settings['JTI_CLAIM']]
            IssuedTokenModel = backend.issued_token_model
            BlacklistedTokenModel = backend.blacklisted_token_model
            new_token_pair = backend.refresh(token=token_pair['refresh'])
            self.assertEqual(BlacklistedTokenModel.objects.filter(token__jti=refresh_jti).count(), 1)

    def test_refresh_token_blacklist_on_rotation_try_to_use_old(self):
        with self.settings(IEVV_JWT={
            'default': {
                'REFRESH_TOKEN_LIFETIME': timezone.timedelta(days=1),
                'USE_BLACKLIST': True,
                'BLACKLIST_AFTER_ROTATION': True
            }
        }, INSTALLED_APPS=settings.INSTALLED_APPS_USER_BLACKLIST):
            user = baker.make(settings.AUTH_USER_MODEL)
            backend = UserAuthBackend()
            backend.set_context(user_instance=user)
            token_pair = backend.make_authenticate_success_response()
            refresh_jti = backend.decode(token_pair['refresh'])[backend.settings['JTI_CLAIM']]
            IssuedTokenModel = backend.issued_token_model
            BlacklistedTokenModel = backend.blacklisted_token_model
            new_token_pair = backend.refresh(token=token_pair['refresh'])
            self.assertEqual(BlacklistedTokenModel.objects.filter(token__jti=refresh_jti).count(), 1)
            with self.assertRaisesMessage(JWTBackendError, 'Token is not valid'):
                new_token_pair = backend.refresh(token=token_pair['refresh'])

    def test_refresh_request_token_has_expired(self):
        with self.settings(IEVV_JWT={
            'default': {
                'REFRESH_TOKEN_LIFETIME': timezone.timedelta(days=1),
                'USE_BLACKLIST': True
            }
        }, INSTALLED_APPS=settings.INSTALLED_APPS_USER_BLACKLIST):
            with mock.patch(
                    'ievv_auth.ievv_jwt.backends.user_auth_backend.UserAuthBackend.refresh_token_expiration',
                    new_callable=PropertyMock,
                    return_value=timezone.now() - timezone.timedelta(days=1)):
                user = baker.make(settings.AUTH_USER_MODEL)
                backend = UserAuthBackend()
                backend.set_context(user_instance=user)
                token_pair = backend.make_authenticate_success_response()
                refresh_jti = py_jwt.decode(
                    jwt=token_pair['refresh'],
                    verify=False,
                    options={'verify_signature': False}
                )[backend.settings['JTI_CLAIM']]
                IssuedTokenModel = backend.issued_token_model
                with self.assertRaisesMessage(JWTBackendError, 'Token is invalid or expired'):
                    backend.refresh(token=token_pair['refresh'])
