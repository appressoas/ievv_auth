# ievv_jwt

> Managing jwt tokens


## Custom backend
How to create a custom jwt backend

```python 
from ievv_auth.ievv_jwt.backends.base_backend import AbstractBackend

class CustomJWTBackend(AbstractBackend):

    def make_payload(self):
        payload = super(ApiKeyBackend, self).make_payload()
        payload['some-key'] = 'Some value'
        return payload
    
    def make_authenticate_success_response(self, *args, **kwargs):
        return {
            'access': self.encode()
        }
```

in `apps.py`

```python
from django.apps import AppConfig


class IevvJwtConfig(AppConfig):
    name = 'my_project.my_app'

    def ready(self):
        from ievv_auth.ievv_jwt.backends.backend_registry import JWTBackendRegistry
        from my_project.my_app.jwt_backends import CustomJWTBackend 
        registry = JWTBackendRegistry.get_instance()
        registry.set_backend(CustomJWTBackend)
```
