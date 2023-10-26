from django.db import models


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

    class Meta:
        abstract = True
