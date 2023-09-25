from rest_framework.permissions import BasePermission
from rest_framework import permissions


class IsSuperUser(BasePermission):
    """
    Custom permission to allow superusers full access,
    but not allow others to access.
    """

    def has_permission(self, request, view):
        # Check if a token is provided in the request
        if not request.auth:
            # Token is not provided
            return False

        # Check if the user associated with the token is a superuser (admin)
        return request.user and request.user.is_superadmin
