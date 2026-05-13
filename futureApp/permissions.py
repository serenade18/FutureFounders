
from rest_framework.permissions import BasePermission, SAFE_METHODS


# =============================================================================
# Custom Permissions
# =============================================================================

class IsAdminRole(BasePermission):
    """Allow access only to object owner or admin users."""

    def has_object_permission(self, request, view, obj):
        if request.user.is_staff:
            return True
        if hasattr(obj, 'user'):
            return obj.user == request.user
        return obj == request.user


