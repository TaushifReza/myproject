from django.urls import path

from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("api/user/", views.UserAPI.as_view()),
    # path("api/login/", views.UserLoginApiView.as_view()),
    path("api/login/", views.LoginAPI.as_view()),
    path("api/service/", views.ServicesAPI.as_view()),
    # Email verification activate url
    path("activate/<uidb64>/<token>/", views.activate, name="activate"),
    path("api/change_password/", views.ChangePasswordAPI.as_view()),
    path("api/forgot_password_otp_send/", views.ForgotPasswrdOtpSendAPI.as_view()),
    path(
        "api/forgot_password_otp_validare_change_password/",
        views.ForgotPasswordOtpValidateChangePasswordAPI.as_view(),
    ),
]
