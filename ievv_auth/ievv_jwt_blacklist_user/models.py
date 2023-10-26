from django.db import models
from django.conf import settings

from ievv_auth.ievv_jwt_blacklist_core.models import AbstractIssuedToken, AbstractBlacklistedToken


class UserIssuedToken(AbstractIssuedToken):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )

    def blacklist_token(self) -> 'UserBlacklistedToken':
        return UserBlacklistedToken.objects.create(token=self)


class UserBlacklistedToken(AbstractBlacklistedToken):
    token = models.OneToOneField(UserIssuedToken, on_delete=models.SET_NULL, null=True, blank=True)
