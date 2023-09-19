import typing as t

from ievv_auth.ievv_jwt.api.serializers import get_user_auth_obtain_jwt_serializer
from ievv_auth.ievv_jwt.api.views.base_view import JWTBaseView


def get_user_auth_obtain_jwt_access_token_view(backend_name='user-auth') -> t.Type[JWTBaseView]:
    class UserAuthObtainJWTAccessTokenView(JWTBaseView):
        serializer_class = get_user_auth_obtain_jwt_serializer(backend_name=backend_name)
    return UserAuthObtainJWTAccessTokenView
