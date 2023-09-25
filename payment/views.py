from django.conf import settings
from django.http import HttpResponse
from django.shortcuts import redirect
from django.urls import reverse

from rest_framework.views import APIView
from rest_framework.response import Response

# Create your views here.


import stripe

# This is your test secret API key.
stripe.api_key = settings.STRIPE_SECRET_KEY


class StripePaymentTestView(APIView):
    def post(self, request):
        try:
            checkout_session = stripe.checkout.Session.create(
                line_items=[
                    {
                        # Provide the exact Price ID (for example, pr_1234) of the product you want to sell
                        "price": "price_1NsjS4IcB7Zsil8MHUmB1KJC",
                        "quantity": 1,
                    },
                ],
                # payment_method_types=["card"],
                mode="payment",
                success_url="http://localhost:8000/?success=true&session_id={CHECKOUT_SESSION_ID}",
                cancel_url="http://localhost:8000/?cancel=true&session_id={CHECKOUT_SESSION_ID}",
            )
        except Exception as e:
            return Response({"message": str(e)})
        return redirect(checkout_session.url)
