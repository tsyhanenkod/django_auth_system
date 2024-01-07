from django.urls import path
from .views import RegisterUserView, VerifyUserEmail, LoginUserView, PasswordResetConfirmView, PassowrdResetRequestView, SetNewPasswordView, LogoutUserView

urlpatterns = [
    path('register/', RegisterUserView.as_view(), name='register'),
    path('verify-email/', VerifyUserEmail.as_view(), name='verify'),
    path('login/', LoginUserView.as_view(), name='login'),
    path('password-reset/', PassowrdResetRequestView.as_view(), name='password-reset'),
    path('password-reset-confirm/<uidb64>/<token>/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    path('set-new-password/', SetNewPasswordView.as_view(), name='set-new-password'),  
    path('logout/', LogoutUserView.as_view(), name='logout'),  
]
