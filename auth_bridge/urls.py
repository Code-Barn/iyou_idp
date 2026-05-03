"""
URL patterns for auth_bridge application.
"""
from django.urls import path
from .views import ChallengeView, VerifySignatureView, LoginPageView
from .admin_views import custom_admin_login, custom_admin_verify, custom_admin_dashboard

urlpatterns = [
    path('challenge/', ChallengeView.as_view(), name='auth_challenge'),
    path('verify/', VerifySignatureView.as_view(), name='auth_verify'),
    path('login/', LoginPageView.as_view(), name='auth_login'),
    
    # Custom admin authentication URLs
    path('admin/did-login/', custom_admin_login, name='admin_did_login'),
    path('admin/did-verify/', custom_admin_verify, name='admin_did_verify'),
    path('admin/did-dashboard/', custom_admin_dashboard, name='admin_did_dashboard'),
]
