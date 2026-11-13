"""The interface's own records. Operator accounts and MFA state belong to allauth."""
from django.db import models


class SignIn(models.Model):
    """A Companion sign-in or failed attempt, recorded from allauth's signals (companion_web.signins).

    A rejected password keeps the name tried only when it is an account's (otherwise the
    name is empty), never the password, and the browser is a short label rather than the
    full user agent. Entries are kept for 90 days.
    """
    at = models.DateTimeField()
    succeeded = models.BooleanField()
    username = models.CharField(max_length=150)
    # The Cloudflare-validated client address Nginx forwards; empty only if none was forwarded.
    ip = models.CharField(max_length=45, blank=True)
    country = models.CharField(max_length=2, blank=True)
    browser = models.CharField(max_length=80)
    # A sign-in completed with an authenticator or recovery code, or an attempt rejected at that step.
    two_factor = models.BooleanField(default=False)
    # 'ip' or 'country' when a sign-in came from a source unseen in the previous 90 days.
    new_source = models.CharField(max_length=7, blank=True)
    # For the failed attempt that completed a burst: the failures counted in its window.
    burst = models.PositiveIntegerField(default=0)

    class Meta:
        indexes = [models.Index(fields=['succeeded', 'at'], name='signin_outcome_time')]
