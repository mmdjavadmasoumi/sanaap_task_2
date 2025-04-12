from django.urls import path
from .views import (
    RegisterAPIView,
    OTPVerifyAPIView,
    LoginAPIView,
)
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)

urlpatterns = [
    path('register/', RegisterAPIView.as_view(), name='register'),
    path('verify-otp/', OTPVerifyAPIView.as_view(), name='verify-otp'),
    path('login/', LoginAPIView.as_view(), name='login'),  # سفارشی: شامل تولید JWT
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),  # تمدید توکن
]