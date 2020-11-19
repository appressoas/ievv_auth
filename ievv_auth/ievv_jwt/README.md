# ievv_jwt

> Managing Json Web Tokens


## Custom backend
If we want to customize json web tokens, with custom payload or with custom settings we can create a custom JWT backend

```python 
from ievv_auth.ievv_jwt.backends.base_backend import AbstractBackend

class CustomJWTBackend(AbstractBackend):
    @classmethod
    def get_backend_name(cls):
        return 'my-jwt-backend'

    def make_payload(self):
        #: You can also override this function to make custom payload for JWT
        payload = super(ApiKeyBackend, self).make_payload()
        payload['some-key'] = 'Some value'
        return payload
    
    def make_authenticate_success_response(self, *args, **kwargs):
        #: This function should be called when authentication is successful
        #: Here you can return access tokens and refresh token if its needed.
        return {
            'access': self.encode()
        }
```

Register the backend in the registry in `apps.py`

```python
from django.apps import AppConfig


class MyAppConfig(AppConfig):
    name = 'my_project.my_app'

    def ready(self):
        from ievv_auth.ievv_jwt.backends.backend_registry import JWTBackendRegistry
        from my_project.my_app.jwt_backends import CustomJWTBackend 
        registry = JWTBackendRegistry.get_instance()
        registry.set_backend(CustomJWTBackend)
```

## API example
Since JWT is stateless we can do permission handling based on the jwt payload since we will always verify that the jwt is signed by our secret.
When using the permission class `JWTAuthentication` the JWT payload will be available on `request.auth` 

```python
from rest_framework import permissions
from ievv_auth.ievv_jwt.api.authentication import JWTAuthentication
from rest_framework.views import APIView


class CustomPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.auth is not None and request.auth.get('scope', None) == 'some-signed-value'


class MyApiView(APIView):
    permission_classes = (CustomPermission, )
    authentication_classes = (JWTAuthentication, )
    ...
```

## Authenticate with api key
Simply add the api authentication view in urls.py
```python
from ievv_auth.ievv_jwt.api.views import APIKeyObtainJWTAccessTokenView
from django.urls import path

urlpatterns = [
    path('api-key-auth', APIKeyObtainJWTAccessTokenView.as_view(), name='api-key-auth')
]
```
