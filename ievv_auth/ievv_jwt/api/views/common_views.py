from ievv_auth.ievv_jwt.api.serializers import RefreshTokenSerializer
from ievv_auth.ievv_jwt.api.views.base_view import JWTBaseView


class RefreshJWTAccessTokenView(JWTBaseView):
    serializer_class = RefreshTokenSerializer
