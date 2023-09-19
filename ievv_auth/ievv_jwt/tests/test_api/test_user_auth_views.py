from django import test
from django.utils import timezone
from model_bakery import baker

from ievv_auth.ievv_api_key.models import ScopedAPIKey
from ievv_auth.ievv_jwt.api.views import get_user_auth_obtain_jwt_access_token_view
from ievv_auth.ievv_jwt.tests.test_api import api_test_mixin
from django.conf import settings

from django.contrib.auth import get_user_model
User = get_user_model()
username_field = User.USERNAME_FIELD


class TestUserAuthObtainJWTAccessTokenView(test.TestCase, api_test_mixin.ApiTestMixin):
    apiview_class = get_user_auth_obtain_jwt_access_token_view()

    def setUp(self):
        from ievv_auth.ievv_jwt.backends.backend_registry import JWTBackendRegistry
        from ievv_auth.ievv_jwt.backends.user_auth_backend import UserAuthBackend
        registry = JWTBackendRegistry.get_instance()
        registry.set_backend(UserAuthBackend)

    def test_no_credentials(self):
        response = self.make_post_request()
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data.get(username_field)[0], 'This field is required.')
        self.assertEqual(response.data.get('password')[0], 'This field is required.')

    def test_no_user(self):
        response = self.make_post_request(data={
            username_field: 'cool@example.com',
            'password': '123'
        })
        self.assertEqual(response.status_code, 401)

    def test_incorrect_credentials_for_user(self):
        user_kwargs = {
            username_field: 'cool@example.com'
        }
        user = baker.make(settings.AUTH_USER_MODEL, **user_kwargs)
        user.set_password('abcd1234')
        user.save()
        response = self.make_post_request(data={
            username_field: 'cool@example.com',
            'password': '123'
        })
        self.assertEqual(response.status_code, 401)

    def test_user_inactive(self):
        user_kwargs = {
            username_field: 'cool@example.com',
            'is_active': False
        }
        user = baker.prepare(settings.AUTH_USER_MODEL, **user_kwargs)
        user.set_password('abcd1234')
        user.save()
        response = self.make_post_request(data={
            username_field: 'cool@example.com',
            'password': 'abcd1234'
        })
        self.assertEqual(response.status_code, 401)

    def test_get_access_and_refresh_token(self):
        user_kwargs = {
            username_field: 'cool@example.com',
            'is_active': True
        }
        user = baker.prepare(settings.AUTH_USER_MODEL, **user_kwargs)
        user.set_password('abcd1234')
        user.save()
        response = self.make_post_request(data={
            username_field: 'cool@example.com',
            'password': 'abcd1234'
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    def test_get_access_token_only(self):
        with self.settings(IEVV_JWT={
            'default': {
                'REFRESH_TOKEN_LIFETIME': None,
            }
        }):
            user_kwargs = {
                username_field: 'cool@example.com',
                'is_active': True
            }
            user = baker.prepare(settings.AUTH_USER_MODEL, **user_kwargs)
            user.set_password('abcd1234')
            user.save()
            response = self.make_post_request(data={
                username_field: 'cool@example.com',
                'password': 'abcd1234'
            })
            self.assertEqual(response.status_code, 200)
            self.assertIn('access', response.data)
