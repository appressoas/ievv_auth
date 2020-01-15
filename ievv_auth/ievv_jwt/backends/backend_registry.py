import jwt
from ievv_opensource.utils.singleton import Singleton


class JWTBackendRegistry(Singleton):

    def __init__(self):
        super(JWTBackendRegistry, self).__init__()
        self._backend_map = {}

    def set_backend(self, backend):
        self._backend_map[backend.get_backend_name()] = backend

    def get_backend(self, backend_name):
        return self._backend_map.get(backend_name, None)

    def get_backend_choices(self):
        choices = []
        for key in self._backend_map:
            choices.append((key, key))
        return choices


def get_backend_from_raw_jwt(raw_jwt):
    payload = jwt.decode(jwt=raw_jwt, verify=False)
    return JWTBackendRegistry.get_instance().get_backend(payload['jwt_backend_name'])
