from django.db import models
from django.conf import settings


class AbstractIssuedToken(models.Model):

    #: JTI Claim
    jti = models.CharField(
        unique=True,
        max_length=255,
        editable=False
    )

    #: JWT token
    token = models.TextField(null=False, blank=False, editable=False)

    #: JWT token payload
    token_payload = models.JSONField(null=False, blank=False, editable=False)

    #: Token issued at
    issued_at = models.DateTimeField(null=False, blank=False, editable=False)

    #: Token expires at
    expires_at = models.DateTimeField(null=False, blank=False, editable=False)

    class Meta:
        abstract = True

    def blacklist_token(self) -> 'AbstractBlacklistedToken':
        raise NotImplementedError('Implement blacklist_token method')


class AbstractBlacklistedToken(models.Model):
    blacklisted_at = models.DateTimeField(auto_now_add=True)


class UserIssuedToken(AbstractIssuedToken):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )

    def blacklist_token(self) -> 'UserBlacklistedToken':
        return UserBlacklistedToken.objects.create(token=self)


class ScopedApiKeyIssuedToken(AbstractIssuedToken):
    scoped_api_key = models.ForeignKey(
        'ievv_api_key.ScopedAPIKey',
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )

    class Meta:
        #: is abstract when
        abstract = 'ievv_auth.ievv_api_key' not in settings.INSTALLED_APPS

    def blacklist_token(self) -> 'ScopedApiKeyBlacklistedToken':
        return ScopedApiKeyBlacklistedToken.objects.create(token=self)


class UserBlacklistedToken(AbstractBlacklistedToken):
    token = models.OneToOneField(UserIssuedToken, on_delete=models.SET_NULL, null=True, blank=True)


class ScopedApiKeyBlacklistedToken(AbstractBlacklistedToken):
    token = models.OneToOneField(ScopedApiKeyIssuedToken, on_delete=models.SET_NULL, null=True, blank=True)

    class Meta:
        #: is abstract when
        abstract = 'ievv_auth.ievv_api_key' not in settings.INSTALLED_APPS
