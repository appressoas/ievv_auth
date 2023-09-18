from unittest import mock
from unittest.mock import PropertyMock

from django import test
from django.utils import timezone
from django.conf import settings

from model_bakery import baker

from ievv_auth.ievv_api_key.models import ScopedAPIKey
from ievv_auth.ievv_jwt.api.views import RefreshJWTAccessTokenView
from ievv_auth.ievv_jwt.backends.api_key_backend import ApiKeyBackend
from ievv_auth.ievv_jwt.backends.user_auth_backend import UserAuthBackend
from ievv_auth.ievv_jwt.tests.test_api import api_test_mixin


class TestRefreshJWTAccessTokenView(test.TestCase, api_test_mixin.ApiTestMixin):
    apiview_class = RefreshJWTAccessTokenView

    def test_user_auth_refresh_access_token_user_auth(self):
        with self.settings(IEVV_JWT={
            'default': {
                'REFRESH_TOKEN_LIFETIME': timezone.timedelta(days=1),
                'USE_BLACKLIST': True,
                'BLACKLIST_AFTER_ROTATION': True
            }
        }):
            user = baker.make(settings.AUTH_USER_MODEL)
            backend = UserAuthBackend()
            backend.set_context(user_instance=user)
            token_pair = backend.make_authenticate_success_response()
            response = self.make_post_request(data={
                'refresh': token_pair['refresh']
            })
            self.assertEqual(response.status_code, 200)
            backend.decode(response.data['refresh'], verify=True)
            backend.decode(response.data['access'], verify=True)
            self.assertNotEqual(response.data['refresh'], token_pair['refresh'])
            self.assertNotEqual(response.data['access'], token_pair['access'])

    def test_user_auth_refresh_access_token_not_active_user(self):
        with self.settings(IEVV_JWT={
            'default': {
                'REFRESH_TOKEN_LIFETIME': timezone.timedelta(days=1),
                'USE_BLACKLIST': True,
                'BLACKLIST_AFTER_ROTATION': True
            }
        }):
            user = baker.make(settings.AUTH_USER_MODEL, is_active=False)
            backend = UserAuthBackend()
            backend.set_context(user_instance=user)
            token_pair = backend.make_authenticate_success_response()
            response = self.make_post_request(data={
                'refresh': token_pair['refresh']
            })
            self.assertEqual(response.status_code, 401)

    def test_user_auth_refresh_access_token_has_expired(self):
        with self.settings(IEVV_JWT={
            'default': {
                'REFRESH_TOKEN_LIFETIME': timezone.timedelta(days=1),
                'USE_BLACKLIST': True,
                'BLACKLIST_AFTER_ROTATION': True
            }
        }):
            user = baker.make(settings.AUTH_USER_MODEL)
            backend = UserAuthBackend()
            backend.set_context(user_instance=user)
            with mock.patch(
                    'ievv_auth.ievv_jwt.backends.user_auth_backend.UserAuthBackend.refresh_token_expiration',
                    new_callable=PropertyMock,
                    return_value=timezone.now() - timezone.timedelta(days=1)):
                token_pair = backend.make_authenticate_success_response()
            response = self.make_post_request(data={
                'refresh': token_pair['refresh']
            })
            self.assertEqual(response.status_code, 401)

    def test_user_auth_refresh_access_token_blacklisted(self):
        with self.settings(IEVV_JWT={
            'default': {
                'REFRESH_TOKEN_LIFETIME': timezone.timedelta(days=1),
                'USE_BLACKLIST': True,
                'BLACKLIST_AFTER_ROTATION': True
            }
        }):
            user = baker.make(settings.AUTH_USER_MODEL)
            backend = UserAuthBackend()
            backend.set_context(user_instance=user)
            token_pair = backend.make_authenticate_success_response()
            refresh_jti = backend.decode(token_pair['refresh'])[backend.settings['JTI_CLAIM']]
            IssuedTokenModel = backend.issued_token_model
            BlacklistedTokenModel = backend.blacklisted_token_model
            IssuedTokenModel.objects.get(jti=refresh_jti).blacklist_token()
            response = self.make_post_request(data={
                'refresh': token_pair['refresh']
            })
            self.assertEqual(response.status_code, 401)

    def test_user_auth_double_refresh(self):
        with self.settings(IEVV_JWT={
            'default': {
                'REFRESH_TOKEN_LIFETIME': timezone.timedelta(days=1),
                'USE_BLACKLIST': True,
                'BLACKLIST_AFTER_ROTATION': True
            }
        }):
            user = baker.make(settings.AUTH_USER_MODEL)
            backend = UserAuthBackend()
            backend.set_context(user_instance=user)
            token_pair = backend.make_authenticate_success_response()
            response = self.make_post_request(data={
                'refresh': token_pair['refresh']
            })
            self.assertEqual(response.status_code, 200)
            response = self.make_post_request(data={
                'refresh': token_pair['refresh']
            })
            self.assertEqual(response.status_code, 401)

    def test_api_key_refresh_access_token_api_key(self):
        with self.settings(IEVV_JWT={
            'default': {
                'REFRESH_TOKEN_LIFETIME': timezone.timedelta(days=1),
                'USE_BLACKLIST': True,
                'BLACKLIST_AFTER_ROTATION': True
            }
        }):
            api_key = baker.make(
                'ievv_api_key.ScopedApiKey',
                base_jwt_payload={
                    'scope': ['read', 'write']
                },
                expiration_datetime=timezone.now() + timezone.timedelta(days=1)
            )
            backend = ApiKeyBackend()
            backend.set_context(api_key_instance=api_key)
            token_pair = backend.make_authenticate_success_response()
            response = self.make_post_request(data={
                'refresh': token_pair['refresh']
            })
            self.assertEqual(response.status_code, 200)
            backend.decode(response.data['refresh'], verify=True)
            backend.decode(response.data['access'], verify=True)
            self.assertNotEqual(response.data['refresh'], token_pair['refresh'])
            self.assertNotEqual(response.data['access'], token_pair['access'])

    def test_api_key_refresh_access_token_api_key_expired(self):
        with self.settings(IEVV_JWT={
            'default': {
                'REFRESH_TOKEN_LIFETIME': timezone.timedelta(days=1),
                'USE_BLACKLIST': True,
                'BLACKLIST_AFTER_ROTATION': True
            }
        }):
            api_key = baker.make(
                'ievv_api_key.ScopedApiKey',
                base_jwt_payload={
                    'scope': ['read', 'write']
                },
                expiration_datetime=timezone.now() - timezone.timedelta(days=1)
            )
            backend = ApiKeyBackend()
            backend.set_context(api_key_instance=api_key)
            token_pair = backend.make_authenticate_success_response()
            response = self.make_post_request(data={
                'refresh': token_pair['refresh']
            })
            self.assertEqual(response.status_code, 401)

    def test_api_key_refresh_access_token_api_key_revoked(self):
        with self.settings(IEVV_JWT={
            'default': {
                'REFRESH_TOKEN_LIFETIME': timezone.timedelta(days=1),
                'USE_BLACKLIST': True,
                'BLACKLIST_AFTER_ROTATION': True
            }
        }):
            api_key = baker.make(
                'ievv_api_key.ScopedApiKey',
                base_jwt_payload={
                    'scope': ['read', 'write']
                },
                expiration_datetime=timezone.now() + timezone.timedelta(days=1),
                revoked=True
            )
            backend = ApiKeyBackend()
            backend.set_context(api_key_instance=api_key)
            token_pair = backend.make_authenticate_success_response()
            response = self.make_post_request(data={
                'refresh': token_pair['refresh']
            })
            self.assertEqual(response.status_code, 401)

    def test_api_key_refresh_access_token_has_expired(self):
        with self.settings(IEVV_JWT={
            'default': {
                'REFRESH_TOKEN_LIFETIME': timezone.timedelta(days=1),
                'USE_BLACKLIST': True,
                'BLACKLIST_AFTER_ROTATION': True
            }
        }):
            api_key = baker.make(
                'ievv_api_key.ScopedApiKey',
                base_jwt_payload={
                    'scope': ['read', 'write']
                },
                expiration_datetime=timezone.now() + timezone.timedelta(days=1)
            )
            backend = ApiKeyBackend()
            backend.set_context(api_key_instance=api_key)
            with mock.patch(
                    'ievv_auth.ievv_jwt.backends.api_key_backend.ApiKeyBackend.refresh_token_expiration',
                    new_callable=PropertyMock,
                    return_value=timezone.now() - timezone.timedelta(days=1)):
                token_pair = backend.make_authenticate_success_response()
            response = self.make_post_request(data={
                'refresh': token_pair['refresh']
            })
            self.assertEqual(response.status_code, 401)

    def test_api_key_refresh_access_token_blacklisted(self):
        with self.settings(IEVV_JWT={
            'default': {
                'REFRESH_TOKEN_LIFETIME': timezone.timedelta(days=1),
                'USE_BLACKLIST': True,
                'BLACKLIST_AFTER_ROTATION': True
            }
        }):
            api_key = baker.make(
                'ievv_api_key.ScopedApiKey',
                base_jwt_payload={
                    'scope': ['read', 'write']
                },
                expiration_datetime=timezone.now() + timezone.timedelta(days=1)
            )
            backend = ApiKeyBackend()
            backend.set_context(api_key_instance=api_key)
            token_pair = backend.make_authenticate_success_response()
            refresh_jti = backend.decode(token_pair['refresh'])[backend.settings['JTI_CLAIM']]
            IssuedTokenModel = backend.issued_token_model
            BlacklistedTokenModel = backend.blacklisted_token_model
            IssuedTokenModel.objects.get(jti=refresh_jti).blacklist_token()
            response = self.make_post_request(data={
                'refresh': token_pair['refresh']
            })
            self.assertEqual(response.status_code, 401)

    def test_api_key_double_refresh(self):
        with self.settings(IEVV_JWT={
            'default': {
                'REFRESH_TOKEN_LIFETIME': timezone.timedelta(days=1),
                'USE_BLACKLIST': True,
                'BLACKLIST_AFTER_ROTATION': True
            }
        }):
            api_key = baker.make(
                'ievv_api_key.ScopedApiKey',
                base_jwt_payload={
                    'scope': ['read', 'write']
                },
                expiration_datetime=timezone.now() + timezone.timedelta(days=1)
            )
            backend = ApiKeyBackend()
            backend.set_context(api_key_instance=api_key)
            token_pair = backend.make_authenticate_success_response()
            response = self.make_post_request(data={
                'refresh': token_pair['refresh']
            })
            self.assertEqual(response.status_code, 200)
            response = self.make_post_request(data={
                'refresh': token_pair['refresh']
            })
            self.assertEqual(response.status_code, 401)
