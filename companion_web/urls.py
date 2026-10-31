from django.urls import include, path
from .views import dashboard, monitoring, staging, staging_change, staging_external, staging_external_change, staging_inbox, releases, release_change, comparison_status, comparison_detail, comparison_start, staging_job_status

urlpatterns = [path('', dashboard, name='dashboard'), path('monitoring/', monitoring, name='monitoring'), path('staging/', staging, name='staging'),
               path('staging/change/', staging_change, name='staging_change'),
               path('staging/status/', staging_job_status, name='staging_job_status'),
               path('staging/external/', staging_external, name='staging_external'),
               path('staging/external/change/', staging_external_change, name='staging_external_change'),
               path('staging/releases/', releases, name='releases'),
               path('staging/releases/change/', release_change, name='release_change'),
               path('staging/releases/check/', comparison_start, name='comparison_start'),
               path('staging/releases/status/', comparison_status, name='comparison_status'),
               path('staging/releases/files/', comparison_detail, name='comparison_detail'),
               path('staging/inbox/', staging_inbox, name='staging_inbox'), path('accounts/', include('allauth.urls'))]
