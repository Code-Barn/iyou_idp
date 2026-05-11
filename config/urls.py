from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    # auth/ must come before openid/ to avoid any routing conflict
    path('auth/', include('auth_bridge.urls')),
    path('openid/', include('oidc_provider.urls', namespace='oidc_provider')),
    path('oauth/', include('oauth2_provider.urls', namespace='oauth2_provider')),
]
