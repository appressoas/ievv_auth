import re
from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.db import models
from django.utils.translation import gettext_lazy
from django.contrib.auth.hashers import check_password, make_password
from django.utils.crypto import get_random_string


class BaseAPIKeyManager(models.Manager):

    def make_prefix(self):
        """
        Generates a unique api key prefix

        Returns:
            String: generated prefix for api key
        """
        while True:
            prefix = get_random_string(length=8)
            if not self.filter(prefix=prefix).exists():
                break
        return prefix

    def make_secret_key(self):
        """
        Generates a unique api key secret

        Returns:
             String: generated secret for api key
        """
        return get_random_string(length=getattr(settings, 'IEVV_API_KEY_SECRET_KEY_LENGTH', 32))

    def hash_secret_key(self, secret_key):
        """
        Hash secret key

        Args:
            secret_key: The secret key which will be hashed

        Returns:
             String: Hashed secret key
        """
        return make_password(secret_key)

    def make_expiration_datetime(self):
        """
        makes expiration datetime for the api key

        Returns:
             Datetime: Expiration datetime
        """
        return timezone.now() + timezone.timedelta(days=getattr(settings, 'IEVV_API_KEY_EXPIRATION_DAYS', 180))

    def generate_api_key(self):
        """
        Generate api key

        Returns:
            String: api_key (prefix).(secret)
            String: The api key prefix
            String: hashed_key the hashed secret
        """
        prefix = self.make_prefix()
        secret_key = self.make_secret_key()
        hashed_key = self.hash_secret_key(secret_key=secret_key)
        api_key = '{}.{}'.format(prefix, secret_key)
        return api_key, prefix, hashed_key

    def create_key(self, **kwargs):
        api_key, prefix, hashed_key = self.generate_api_key()
        instance = self.model(
            prefix=prefix,
            hashed_key=hashed_key,
            expiration_datetime=self.make_expiration_datetime(),
            **kwargs
        )
        instance.full_clean()
        instance.save()
        return api_key, instance

    def _is_valid(self, api_key):
        #: Validate format for the api key
        if len(api_key.split('.')) != 2:
            return None, False, None

        [prefix, secret] = api_key.split('.')
        try:
            instance = self.get(prefix=prefix)
        except self.model.DoesNotExist:
            return None, False, None
        valid = True
        message = 'Authentication successful'
        if not instance.verify(secret_key=secret):
            valid = False
            message = 'Authentication failed, secret key is not valid'
        if instance.revoked:
            valid = False
            message = 'Authentication failed, key has been revoked'
        if instance.has_expired:
            valid = False
            message = 'Authentication failed, key has expired'
        return instance, valid, message

    def is_valid(self, api_key):
        """
        Simply checks whether the api key is valid
        Returns True if the API Key is valid, False otherwise.

        It will check:
            - if api key prefix exists
            - if the api key has expired
            - if the hashed secret matches the one on database

        Args:
            api_key: The api key

        Returns:
            Boolean: If the api_key is valid
            Object: api key instance
        """
        instance, valid, _ = self._is_valid(api_key=api_key)
        return valid, instance

    def is_valid_with_logging(self, api_key, extra=None):
        """
        Returns True if the API Key is valid, False otherwise.
        Some logging is appended for the authentication try

        It will check:
            - if api key prefix exists
            - if the api key has expired
            - if the hashed secret matches the one on database

        Args:
            api_key: The api key
            extra (optional): optional dict for logging entry

        Returns:
            Boolean: If the api_key is valid
            Object: api key instance
        """
        if not extra:
            extra = {}
        instance, valid, message = self._is_valid(api_key=api_key)

        if instance:
            extra.update({'message': message})
            instance.log_authentication_attempt(extra)
        return valid, instance


class AbstractAPIKey(models.Model):
    objects = BaseAPIKeyManager()

    #: api key prefix (prefix).(secret)
    prefix = models.CharField(
        max_length=8,
        unique=True,
        editable=False
    )

    #: hashed key
    hashed_key = models.CharField(
        max_length=100,
        editable=False,
    )

    #: free text field
    name = models.CharField(
        max_length=255,
        blank=True,
        default=None,
        null=True,
        verbose_name=gettext_lazy('Name'),
        help_text=gettext_lazy('Free text for the api key')
    )

    #: If the api key has been revoked
    revoked = models.BooleanField(
        default=False,
        verbose_name=gettext_lazy('Revoked'),
        help_text=gettext_lazy('If the api key has been revoked, once revoked it cannot be undone')
    )

    #: created datetime
    created = models.DateTimeField(
        auto_now_add=True,
        editable=False,
        verbose_name=gettext_lazy('Created datetime'),
        help_text=gettext_lazy('When the api key was created')
    )

    #: datetime when the key expires
    expiration_datetime = models.DateTimeField(
        blank=False,
        null=False,
        verbose_name=gettext_lazy('Expires'),
        help_text=gettext_lazy('The datetime when the token expires'),
        editable=False
    )

    def __init__(self, *args, **kwargs):
        super(AbstractAPIKey, self).__init__(*args, **kwargs)
        self._initial_revoked = self.revoked

    class Meta:
        abstract = True
        verbose_name = gettext_lazy('API key')
        verbose_name_plural = gettext_lazy('API keys')

    def log_authentication_attempt(self, log_data):
        raise NotImplementedError('Please implement logging_model_class')

    @property
    def has_expired(self):
        return self.expiration_datetime < timezone.now()

    def verify(self, secret_key):
        return check_password(secret_key, self.hashed_key)

    def _validate_revoked(self):
        if self._initial_revoked and not self.revoked:
            raise ValidationError(
                gettext_lazy('Cannot set revoked to False once revoked')
            )

    def clean(self):
        self._validate_revoked()


class ScopedAPIKey(AbstractAPIKey):

    #: Backend type
    jwt_backend_name = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        default=None,
    )

    #: Should contain the payload of the jwt issued after authentication
    base_jwt_payload = models.JSONField(
        default=dict,
        null=False,
        blank=True
    )

    class Meta:
        verbose_name = gettext_lazy('Scoped api key')
        verbose_name_plural = gettext_lazy('Scoped api keys')

    def log_authentication_attempt(self, log_data):
        ScopedApiKeyAuthenticationLog.objects.create(api_key=self, log_data=log_data)

    def __str__(self):
        return f'{self.name} - id<{self.id}>'


class AbstractAuthenticationLog(models.Model):
    #: Log data contains authentication attempt message and auxiliary data
    log_data = models.JSONField(null=True, blank=False, default=dict)

    #: created datetime
    created = models.DateTimeField(auto_now_add=True)

    class Meta:
        abstract = True


class ScopedApiKeyAuthenticationLog(AbstractAuthenticationLog):
    #: The instance of ScopedAPIKey this log belongs to.
    api_key = models.ForeignKey(to=ScopedAPIKey, on_delete=models.CASCADE)
