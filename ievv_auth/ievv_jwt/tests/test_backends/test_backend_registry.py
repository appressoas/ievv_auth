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
from ievv_auth.ievv_jwt.backends.backend_registry import JWTBackendRegistry, get_backend_from_raw_jwt
from ievv_auth.ievv_jwt.exceptions import JWTBackendError


class TestJWTBackendRegistry(TestCase):

    def setUp(self):
        registry = JWTBackendRegistry.get_instance()
        registry.set_backend(ApiKeyBackend)

    def test_sanity(self):
        registry = JWTBackendRegistry.get_instance()
        backend_class = registry.get_backend('api-key')
        self.assertEqual(backend_class, ApiKeyBackend)

    def test_unknown_backend(self):
        registry = JWTBackendRegistry.get_instance()
        backend_class = registry.get_backend('unknown')
        self.assertIsNone(backend_class)

    def test_get_backend_from_raw_jwt(self):
        api_key = baker.make(
            'ievv_api_key.ScopedApiKey',
            base_jwt_payload={
                'scope': ['read', 'write']
            }
        )
        backend = ApiKeyBackend()
        jwt = backend.encode()
        backend_class = get_backend_from_raw_jwt(raw_jwt=jwt)
        self.assertEqual(backend_class, ApiKeyBackend)

    def test_get_backend_from_raw_jwt_unknown_backend(self):
        backend_class = get_backend_from_raw_jwt(raw_jwt='eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhcGlfa2V5X2lkIjo2LCJleHAiOjE1NzkwODI2MjEsImlhdCI6MTU3OTA4MDgyMSwianRpIjoiZTRkMTVkZTQwZjg1NDk1Mjg2MGNkYTI3N2Y0NDIwYWIiLCJqd3RfYmFja2VuZF9uYW1lIjoidW5rbm93biJ9.9PM35De6yg_IaTvdLgBzo2F5xG9ywioIthTOK637iO4')
        self.assertIsNone(backend_class)
