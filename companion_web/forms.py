"""Account forms worded like the rest of the interface."""
from allauth.account import forms


class ChangePasswordForm(forms.ChangePasswordForm):
    """Allauth's change-password form with sentence-case labels.

    Allauth also copies each label into the field's placeholder, so both are set.
    """
    LABELS = {'oldpassword': 'Current password', 'password1': 'New password', 'password2': 'New password again'}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for name, label in self.LABELS.items():
            self.fields[name].label = label
            self.fields[name].widget.attrs['placeholder'] = label
