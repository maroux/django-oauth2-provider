"""
Default model implementations. Custom database or OAuth backends need to
implement these models with fields and and methods to be compatible with the
views in :attr:`provider.views`.
"""

import os
from django.db import models
from django.conf import settings
from django.core.validators import RegexValidator
from .. import constants
from ..constants import CLIENT_TYPES
from ..utils import now, short_token, long_token, get_code_expiry
from ..utils import get_token_expiry, serialize_instance, deserialize_instance
from .managers import AccessTokenManager
from .. import scope

try:
    from django.utils import timezone
except ImportError:
    timezone = None

AUTH_USER_MODEL = getattr(settings, 'AUTH_USER_MODEL', 'auth.User')

class ClientStatus:
    INTERNAL = 0
    TEST = 1
    LIVE = 2
    DISABLED = 3

    CHOICES = (
        (INTERNAL, 'INTERNAL'),
        (TEST, 'TEST'),
        (LIVE, 'LIVE'),
        (DISABLED, 'DISABLED'),
    )

class EventDeliveryPreference:
    NONE = 0
    WEBHOOK = 1
    WEBSOCKET = 2
    WEBHOOK_FIXED_IP = 3
    BOTH = 4

    CHOICES = (
        (NONE, 'NONE'),
        (WEBHOOK, 'WEBHOOK'),
        (WEBSOCKET, 'WEBSOCKET'),
        (WEBHOOK_FIXED_IP, 'WEBHOOK_FIXED_IP'),
        (BOTH, 'BOTH - ONLY FOR FLEET. DO NOT USE'),
    )

class ScopeField(models.IntegerField):
    initial = {}

    def __init__(self, *args, **kwargs):
        kwargs['choices'] = scope.SCOPE_CHOICES
        super(ScopeField, self).__init__(*args, **kwargs)

    def formfield(self, **kwargs):
        from .forms import ScopeChoiceField
        defaults = {'choices_form_class': ScopeChoiceField}
        defaults.update(kwargs)
        return super(ScopeField, self).formfield(**defaults)

    def validate(self, value, model_instance):
        # all the bits in value must be present in list of all scopes
        return value == (value & scope.to_int(*scope.SCOPE_NAME_DICT.values()))

    def __unicode__(self):
        return u'scope'

    def __str__(self):
        return 'scope'

def client_logo_image_path(instance, filename):
    filename_split = os.path.splitext(filename)
    ext = filename_split[1]
    if not ext:
        ext = '.png'
    return '/'.join([constants.LOGO_FOLDER, instance.client_id, 'icon' + ext])

class Client(models.Model):
    """
    Default client implementation.

    Expected fields:

    * :attr:`user`
    * :attr:`name`
    * :attr:`url`
    * :attr:`redirect_url`
    * :attr:`client_id`
    * :attr:`client_secret`
    * :attr:`client_type`

    Clients are outlined in the :rfc:`2` and its subsections.
    """

    user = models.ForeignKey(AUTH_USER_MODEL, related_name='oauth2_client',
        blank=True, null=True)
    name = models.CharField(max_length=255, blank=True)
    url = models.URLField(help_text="Your application's URL.")
    redirect_uri = models.CharField(max_length=1028, help_text="Your application's callback URL", validators=[RegexValidator(regex=r'^\S*//\S*$')])
    webhook_uri = models.CharField(max_length=1028, help_text="Your application's webhook URL", null=True, blank=True, validators=[RegexValidator(regex=r'^\S*//\S*$')])
    logo = models.ImageField(upload_to=client_logo_image_path,
                             null=True, blank=True,
                             storage=constants.IMAGE_STORAGE,
                             help_text="40x40 pixel logo of your application")
    status = models.PositiveSmallIntegerField(max_length=2, choices=ClientStatus.CHOICES, default=1)
    last_updated_date = models.DateTimeField(auto_now=True)
    created_date = models.DateTimeField(auto_now_add=True)
    client_id = models.CharField(max_length=255, default=short_token)
    client_secret = models.CharField(max_length=255, default=long_token)
    client_type = models.IntegerField(choices=CLIENT_TYPES, default=constants.CONFIDENTIAL)
    scope = ScopeField(default=0)
    event_delivery_preference = models.PositiveSmallIntegerField(max_length=2, choices=EventDeliveryPreference.CHOICES, default=0)

    def __unicode__(self):
        return self.redirect_uri

    def __str__(self):
        return self.redirect_uri

    def get_default_token_expiry(self):
        public = (self.client_type == 1)
        return get_token_expiry(public)

    def serialize(self):
        return dict(user=serialize_instance(self.user),
                    name=self.name,
                    url=self.url,
                    redirect_uri=self.redirect_uri,
                    client_id=self.client_id,
                    client_secret=self.client_secret,
                    client_type=self.client_type)

    @classmethod
    def deserialize(cls, data):
        if not data:
            return None

        kwargs = {}

        # extract values that we care about
        for field in cls._meta.fields:
            name = field.name
            val = data.get(field.name, None)

            # handle relations
            if val and field.rel:
                val = deserialize_instance(field.rel.to, val)

            kwargs[name] = val

        return cls(**kwargs)


class Grant(models.Model):
    """
    Default grant implementation. A grant is a code that can be swapped for an
    access token. Grants have a limited lifetime as defined by
    :attr:`provider.constants.EXPIRE_CODE_DELTA` and outlined in
    :rfc:`4.1.2`

    Expected fields:

    * :attr:`user`
    * :attr:`client` - :class:`Client`
    * :attr:`code`
    * :attr:`expires` - :attr:`datetime.datetime`
    * :attr:`redirect_uri`
    * :attr:`scope`
    """
    user = models.ForeignKey(AUTH_USER_MODEL)
    client = models.ForeignKey(Client)
    code = models.CharField(max_length=255, default=long_token)
    created_at = models.DateTimeField(auto_now_add=True)
    expires = models.DateTimeField(default=get_code_expiry)
    redirect_uri = models.CharField(max_length=255, blank=True)
    scope = ScopeField(default=0)

    def __unicode__(self):
        return self.code

class AccessToken(models.Model):
    """
    Default access token implementation. An access token is a time limited
    token to access a user's resources.

    Access tokens are outlined :rfc:`5`.

    Expected fields:

    * :attr:`user`
    * :attr:`token`
    * :attr:`client` - :class:`Client`
    * :attr:`expires` - :attr:`datetime.datetime`
    * :attr:`scope`

    Expected methods:

    * :meth:`get_expire_delta` - returns an integer representing seconds to
        expiry
    """
    user = models.ForeignKey(AUTH_USER_MODEL, null=True)
    token = models.CharField(max_length=255, default=long_token, db_index=True)
    client = models.ForeignKey(Client)
    created_at = models.DateTimeField(auto_now_add=True)
    expires = models.DateTimeField()
    scope = ScopeField(default=0)
    type = models.IntegerField(default=0)
    is_deleted = models.BooleanField(default=False)

    objects = AccessTokenManager()

    def __unicode__(self):
        return self.token

    def save(self, *args, **kwargs):
        if not self.expires:
            self.expires = self.client.get_default_token_expiry()
        super(AccessToken, self).save(*args, **kwargs)

    def get_expire_delta(self, reference=None):
        """
        Return the number of seconds until this token expires.
        """
        if reference is None:
            reference = now()
        expiration = self.expires

        if timezone:
            if timezone.is_aware(reference) and timezone.is_naive(expiration):
                # MySQL doesn't support timezone for datetime fields
                # so we assume that the date was stored in the UTC timezone
                expiration = timezone.make_aware(expiration, timezone.utc)
            elif timezone.is_naive(reference) and timezone.is_aware(expiration):
                reference = timezone.make_aware(reference, timezone.utc)

        timedelta = expiration - reference
        return timedelta.days*86400 + timedelta.seconds


class RefreshToken(models.Model):
    """
    Default refresh token implementation. A refresh token can be swapped for a
    new access token when said token expires.

    Expected fields:

    * :attr:`user`
    * :attr:`token`
    * :attr:`access_token` - :class:`AccessToken`
    * :attr:`client` - :class:`Client`
    * :attr:`expired` - ``boolean``
    """
    user = models.ForeignKey(AUTH_USER_MODEL)
    token = models.CharField(max_length=255, default=long_token)
    access_token = models.OneToOneField(AccessToken,
            related_name='refresh_token')
    client = models.ForeignKey(Client)
    created_at = models.DateTimeField(auto_now_add=True)
    expired = models.BooleanField(default=False)

    def __unicode__(self):
        return self.token

"""
Fix for south being unable to introspect custom fields
https://github.com/pinax/django-user-accounts/issues/61
Commenting out because projects like admin which depend on
this have moved to Django 1.7 and above and use django migrations
instead of south.

from south.modelsinspector import add_introspection_rules
add_introspection_rules([], ["^provider\.oauth2\.models\.ScopeField"])
"""
