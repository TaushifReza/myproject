from rest_framework.throttling import SimpleRateThrottle


class CustomUserRateThrottle(SimpleRateThrottle):
    rate = "5/minute"

    def allow_request(self, request, view):
        if request.user.is_authenticated:
            self.key = f"user_throttle_{request.user.id}"
            print(request.user.id)
            return super().allow_request(request, view)
        return True

    def get_cache_key(self, request, view):
        if request.user.is_authenticated:
            return f"user_throttle_{request.user.id}"
        else:
            return None
