"""
"""
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView

from futureApp.serializers import CustomTokenObtainPairView
from futureApp.views import (
    UserViewSet,
    UserInfoView,
    ChangePasswordView,
    PasswordResetRequestView,
    PasswordResetConfirmView,
)
from futureProject import settings

# Create router and register viewSets
router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include(router.urls)),
    # JWT Authentication
    path('api/gettoken/', CustomTokenObtainPairView.as_view(), name='gettoken'),
    path('api/refresh_token/', TokenRefreshView.as_view(), name='refresh_token'),
    path('api/verify_token/', TokenVerifyView.as_view(), name='verify_token'),
    path('api/userinfo/', UserInfoView.as_view(), name='userinfo'),
    path('api/userinfo/change-password/', ChangePasswordView.as_view(), name="change-password"),
    path('api/password-reset/request/', PasswordResetRequestView.as_view(), name="password-reset-request"),
    path('api/password-reset/confirm/', PasswordResetConfirmView.as_view(), name="password-reset-confirm"),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
