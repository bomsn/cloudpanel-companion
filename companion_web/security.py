"""No implicit trust in WordPress administrators or CloudPanel sessions."""
from allauth.account.adapter import DefaultAccountAdapter
from allauth.mfa.utils import is_mfa_enabled
from django.http import HttpResponseForbidden
from django.shortcuts import redirect


class OperatorAccountAdapter(DefaultAccountAdapter):
    def is_open_for_signup(self, request):
        return False


class OperatorBoundary:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = None
        if request.user.is_authenticated:
            if not request.user.is_active or not request.user.is_staff:
                response = HttpResponseForbidden('This account is not an operator.')
            # Allauth completes the MFA login flow before authenticating users
            # with enrolled factors. New operators must enrol before seeing any
            # site or operational data; account pages remain available to do so.
            elif not request.path.startswith('/accounts/') and not is_mfa_enabled(request.user):
                response = redirect('mfa_index')
        if response is None:
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
