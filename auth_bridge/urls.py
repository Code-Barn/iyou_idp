from django.urls import path
from .views import ChallengeView, verify_signature, LoginPageView
from .admin_views import custom_admin_login, custom_admin_verify, custom_admin_dashboard

app_name = 'auth_bridge'

urlpatterns = [
    # verify/ first to rule out any routing shadow
    path('verify/', verify_signature, name='verify_signature'),
    path('challenge/', ChallengeView.as_view(), name='challenge'),
    path('login/', LoginPageView.as_view(), name='login'),

    path('admin/did-login/', custom_admin_login, name='admin_did_login'),
    path('admin/did-verify/', custom_admin_verify, name='admin_did_verify'),
    path('admin/did-dashboard/', custom_admin_dashboard, name='admin_did_dashboard'),
]
