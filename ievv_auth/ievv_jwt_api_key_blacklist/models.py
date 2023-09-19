from django.db import models

from ievv_auth.ievv_jwt_blacklist.models import AbstractIssuedToken, AbstractBlacklistedToken


class ScopedApiKeyIssuedToken(AbstractIssuedToken):
    scoped_api_key = models.ForeignKey(
        'ievv_api_key.ScopedAPIKey',
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )

    def blacklist_token(self) -> 'ScopedApiKeyBlacklistedToken':
        return ScopedApiKeyBlacklistedToken.objects.create(token=self)


class ScopedApiKeyBlacklistedToken(AbstractBlacklistedToken):
    token = models.OneToOneField(ScopedApiKeyIssuedToken, on_delete=models.SET_NULL, null=True, blank=True)

