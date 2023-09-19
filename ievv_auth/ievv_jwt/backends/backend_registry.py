import typing as t

import jwt
from ievv_opensource.utils.singleton import Singleton

if t.TYPE_CHECKING:
    from .base_backend import AbstractBackend


class JWTBackendRegistry(Singleton):

    def __init__(self):
        super(JWTBackendRegistry, self).__init__()
        self._backend_map = {}

    def set_backend(self, backend: t.Type['AbstractBackend']):
        self._backend_map[backend.get_backend_name()] = backend

    def get_backend(self, backend_name) -> t.Type['AbstractBackend']:
        return self._backend_map.get(backend_name, None)

    def get_backend_choices(self):
        choices = []
        for key in self._backend_map:
            choices.append((key, key))
        return choices


def get_backend_from_raw_jwt(raw_jwt) -> t.Type['AbstractBackend']:
    """
    Gets the backend from raw_jwt,
    this step does not verify the jwt, it should happen later,
    the only purpose is to get the backend class
    Args:
        raw_jwt: raw jwt string

    Returns:
        instance of AbstractBackend
    """
    payload = jwt.decode(jwt=raw_jwt, verify=False, options={'verify_signature': False})
    return JWTBackendRegistry.get_instance().get_backend(payload['jwt_backend_name'])
