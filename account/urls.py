from django.urls import path, include
from rest_framework.routers import DefaultRouter


from . import views

router = DefaultRouter()
# router.register("profile", views.UserProfileViewSet)
# router.register("user", views.UserAPI.as_view(), basename="user")

urlpatterns = [
    path("", views.home, name="home"),
    path("register_user/", views.register_user, name="register_user"),
    path("login/", views.login, name="login"),
    path("logout/", views.logout, name="logout"),
    path("user_profile/", views.user_profile, name="user_profile"),
    path("api/", include(router.urls)),
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
