from ievv_auth.ievv_jwt.api.serializers.api_key_serializers import ApiKeyObtainJWTSerializer
from ievv_auth.ievv_jwt.api.views.base_view import JWTBaseView


class APIKeyObtainJWTAccessTokenView(JWTBaseView):

    serializer_class = ApiKeyObtainJWTSerializer
