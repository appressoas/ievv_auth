from django.apps import AppConfig


class IevvJwtConfig(AppConfig):
    name = 'ievv_auth.ievv_jwt'

    def ready(self):
        from ievv_auth.ievv_jwt.backends.backend_registry import JWTBackendRegistry
        from ievv_auth.ievv_jwt.backends.api_key_backend import ApiKeyBackend
        registry = JWTBackendRegistry.get_instance()
        registry.set_backend(ApiKeyBackend)
