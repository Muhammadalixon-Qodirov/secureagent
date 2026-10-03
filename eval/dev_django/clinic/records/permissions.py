from rest_framework import permissions


class IsInvoiceOwner(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.owner_id == request.user.id
