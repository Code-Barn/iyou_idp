"""
URL patterns for auth_bridge application.
"""
from django.urls import path
from .views import ChallengeView, VerifySignatureView

urlpatterns = [
    path('challenge/', ChallengeView.as_view(), name='auth_challenge'),
    path('verify/', VerifySignatureView.as_view(), name='auth_verify'),
]
