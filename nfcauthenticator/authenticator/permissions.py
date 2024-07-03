from authenticator.models import EstiamUser
from rest_framework import permissions


def user_authentication_rule(user: EstiamUser) -> bool:
    return user is not None and user.is_confirmed


class IsConfirmedUser(permissions.BasePermission):
    message = "User is not confirmed."

    def has_permission(self, request, view):
        user = request.user
        return user_authentication_rule(user)
