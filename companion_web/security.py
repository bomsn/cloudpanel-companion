"""No implicit trust in WordPress administrators or CloudPanel sessions."""
from allauth.account.adapter import DefaultAccountAdapter
from django.shortcuts import render
from django.urls import reverse


class OperatorAccountAdapter(DefaultAccountAdapter):
    def is_open_for_signup(self, request):
        return False


def is_operator(user):
    return user.is_authenticated and user.is_active and user.is_staff


def operator_context(request):
    """Templates show the operations shell only to accounts this boundary admits."""
    return {'operator': is_operator(request.user)}


class OperatorBoundary:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Two-factor authentication is optional, as in CloudPanel. Allauth
        # completes the code step before authenticating an operator who
        # enrolled an authenticator, so no further check is needed here.
        # A signed-in non-operator may still sign out from the denial page.
        if request.user.is_authenticated and not is_operator(request.user) and request.path != reverse('account_logout'):
            response = render(request, 'not_operator.html', status=403)
        else:
            response = self.get_response(request)
        response['Cache-Control'] = 'private, no-store'
        response['X-Robots-Tag'] = 'noindex, nofollow, noarchive'
        response['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        # Operations use local static assets and no third-party embeds. Keep a
        # content-injection bug from loading remote code or submitting secrets.
        response['Content-Security-Policy'] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
        )
        return response
