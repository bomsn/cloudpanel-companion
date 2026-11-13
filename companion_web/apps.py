from django.apps import AppConfig


class CompanionWebConfig(AppConfig):
    name = 'companion_web'
    default_auto_field = 'django.db.models.BigAutoField'

    def ready(self):
        # Connects the receivers that record Companion sign-ins and failed attempts.
        from . import signins  # noqa: F401
