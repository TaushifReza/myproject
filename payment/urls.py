from django.urls import path

from payment import views

urlpatterns = [
    path("stripe_test/", views.StripePaymentTestView.as_view(), name="stripe_test"),
]
