from unittest.mock import patch

from django import test
from django.core.exceptions import ValidationError
from django.utils import timezone

from ievv_auth.ievv_api_key.models import ScopedAPIKey, ScopedApiKeyAuthenticationLog


class TestScopedApiKey(test.TestCase):

    def test_valid_api_key(self):
        api_key, instance = ScopedAPIKey.objects.create_key()
        is_valid, instance = ScopedAPIKey.objects.is_valid(api_key=api_key)
        self.assertTrue(is_valid)

    def test_api_key_revoked(self):
        api_key, instance = ScopedAPIKey.objects.create_key()
        instance.revoked = True
        instance.save()
        is_valid, instance = ScopedAPIKey.objects.is_valid(api_key=api_key)
        self.assertFalse(is_valid)

    def test_api_key_expired(self):
        with patch.object(ScopedAPIKey.objects, 'make_expiration_datetime', return_value=timezone.now() - timezone.timedelta(days=1)):
            api_key, instance = ScopedAPIKey.objects.create_key()
            is_valid, instance = ScopedAPIKey.objects.is_valid(api_key=api_key)
            self.assertFalse(is_valid)

    def test_api_key_is_valid_api_key_does_not_exists(self):
        is_valid, instance = ScopedAPIKey.objects.is_valid(api_key='XXXXXXXX.YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY')
        self.assertFalse(is_valid)

    def test_valid_api_key_with_logging(self):
        api_key, instance = ScopedAPIKey.objects.create_key()
        is_valid, instance = ScopedAPIKey.objects.is_valid_with_logging(api_key=api_key)
        self.assertTrue(is_valid)
        instance.refresh_from_db()
        self.assertEqual(ScopedApiKeyAuthenticationLog.objects.count(), 1)
        log = ScopedApiKeyAuthenticationLog.objects.first()
        self.assertEqual(log.api_key.id, instance.id)
        self.assertEqual(log.log_data.get('message'), 'Authentication successful')

    def test_api_key_revoked_with_logging(self):
        api_key, instance = ScopedAPIKey.objects.create_key()
        instance.revoked = True
        instance.save()
        is_valid, instance = ScopedAPIKey.objects.is_valid_with_logging(api_key=api_key)
        self.assertFalse(is_valid)
        self.assertEqual(ScopedApiKeyAuthenticationLog.objects.count(), 1)
        log = ScopedApiKeyAuthenticationLog.objects.first()
        self.assertEqual(log.api_key.id, instance.id)
        self.assertEqual(log.log_data.get('message'), 'Authentication failed, key has been revoked')

    def test_api_key_expired_with_logging(self):
        with patch.object(ScopedAPIKey.objects, 'make_expiration_datetime',
                          return_value=timezone.now() - timezone.timedelta(days=1)):
            api_key, instance = ScopedAPIKey.objects.create_key()
            is_valid, instance = ScopedAPIKey.objects.is_valid_with_logging(api_key=api_key)
            self.assertFalse(is_valid)
            self.assertEqual(ScopedApiKeyAuthenticationLog.objects.count(), 1)
            log = ScopedApiKeyAuthenticationLog.objects.first()
            self.assertEqual(log.api_key.id, instance.id)
            self.assertEqual(log.log_data.get('message'), 'Authentication failed, key has expired')

    def test_should_not_be_able_to_set_revoked_to_false_after_being_true(self):
        api_key, instance = ScopedAPIKey.objects.create_key()
        instance.revoked = True
        instance.save()
        [prefix, _] = api_key.split('.')
        instance = ScopedAPIKey.objects.get(prefix=prefix)
        with self.assertRaisesMessage(ValidationError, 'Cannot set revoked to False once revoked'):
            instance.revoked = False
            instance.full_clean()
