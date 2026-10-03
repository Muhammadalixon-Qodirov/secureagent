from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.core.exceptions import PermissionDenied
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.views import View
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Article, Attachment, Ticket


def can_see_ticket(user, ticket):
    return user.is_staff or ticket.requester_id == user.id


class TicketView(LoginRequiredMixin, View):
    def get(self, request, ticket_id):
        ticket = get_object_or_404(Ticket, id=ticket_id)
        if not can_see_ticket(request.user, ticket):
            raise PermissionDenied
        return JsonResponse({"subject": ticket.subject})


class TicketCloseView(LoginRequiredMixin, View):
    def post(self, request, ticket_id):
        ticket = get_object_or_404(Ticket, id=ticket_id)
        ticket.status = "closed"
        ticket.save()
        return JsonResponse({"ok": True})


class StaffTicketListView(UserPassesTestMixin, View):
    def test_func(self):
        return self.request.user.is_staff

    def get(self, request):
        return JsonResponse({"tickets": list(Ticket.objects.values("id", "subject"))})


class AttachmentAPI(APIView):
    def get(self, request, pk):
        att = Attachment.objects.get(pk=pk)
        return Response({"path": att.path})


class MyTicketsAPI(APIView):
    def get(self, request):
        return Response({"tickets": list(request.user.tickets.values("id", "subject"))})


@api_view(["GET"])
@permission_classes([AllowAny])
def article(request, pk):
    art = get_object_or_404(Article, pk=pk)
    return Response({"title": art.title, "body": art.body})


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def reassign(request, ticket_id):
    ticket = Ticket.objects.get(pk=ticket_id)
    ticket.requester_id = request.data["user_id"]
    ticket.save()
    return Response({"ok": True})


@api_view(["DELETE"])
def delete_ticket(request, ticket_id):
    if not request.user.is_staff:
        raise PermissionDenied
    Ticket.objects.filter(pk=ticket_id).delete()
    return Response(status=204)
