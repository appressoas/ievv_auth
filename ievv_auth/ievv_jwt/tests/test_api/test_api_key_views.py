from django import test
from django.utils import timezone

from ievv_auth.ievv_api_key.models import ScopedAPIKey
from ievv_auth.ievv_jwt.api.views import APIKeyObtainJWTAccessTokenView
from ievv_auth.ievv_jwt.backends.api_key_backend import ApiKeyBackend
from ievv_auth.ievv_jwt.tests.test_api import api_test_mixin


class TestAPIKeyObtainJWTAccessTokenView(test.TestCase, api_test_mixin.ApiTestMixin):
    apiview_class = APIKeyObtainJWTAccessTokenView

    def setUp(self):
        from ievv_auth.ievv_jwt.backends.backend_registry import JWTBackendRegistry
        from ievv_auth.ievv_jwt.backends.api_key_backend import ApiKeyBackend
        registry = JWTBackendRegistry.get_instance()
        registry.set_backend(ApiKeyBackend)

    def test_no_api_key(self):
        response = self.make_post_request()
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data.get('api_key')[0], 'This field is required.')

    def test_wrong_api_key(self):
        response = self.make_post_request(data={'api_key': '12ret'})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data.get('detail'), 'Api key has expired or is invalid')

    def test_unknown_backend_key(self):
        api_key, instance = ScopedAPIKey.objects.create_key(
            name='test',
            jwt_backend_name='crazy',
        )
        response = self.make_post_request(data={'api_key': api_key})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data.get('detail'), 'Unknown jwt backend could not authenticate')

    def test_api_key_revoked(self):
        api_key, instance = ScopedAPIKey.objects.create_key(
            name='test',
            jwt_backend_name='crazy',
        )
        instance.revoked = True
        instance.save()
        response = self.make_post_request(data={'api_key': api_key})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data.get('detail'), 'Api key has expired or is invalid')

    def test_api_key_expired(self):
        api_key, instance = ScopedAPIKey.objects.create_key(
            name='test',
            jwt_backend_name='crazy',
        )
        instance.expiration_datetime = timezone.now()
        instance.save()
        response = self.make_post_request(data={'api_key': api_key})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data.get('detail'), 'Api key has expired or is invalid')

    def test_api_key_ok_api_key_backend(self):
        api_key, instance = ScopedAPIKey.objects.create_key(
            name='test',
            jwt_backend_name='api-key',
            base_jwt_payload={
                'scope': 'cool'
            }
        )
        response = self.make_post_request(data={'api_key': api_key})
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(response.data.get('access'))
        payload = ApiKeyBackend().decode(token=response.data.get('access'), verify=True)
        self.assertEqual(payload['scope'], 'cool')
        self.assertEqual(payload['api_key_id'], instance.id)
        self.assertEqual(payload['jwt_backend_name'], 'api-key')
