from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden, JsonResponse
from django.shortcuts import get_object_or_404
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated

from .models import Appointment, Clinic, Invoice, Note
from .permissions import IsInvoiceOwner


def note_for_user(user, pk):
    note = get_object_or_404(Note, pk=pk)
    if note.appointment.patient_id != user.id:
        raise PermissionError("not yours")
    return note


def login_view(request):
    return JsonResponse({"ok": True})


def clinics(request):
    return JsonResponse({"clinics": list(Clinic.objects.values("name", "city"))})


@login_required
def appointment_detail(request, pk):
    appt = get_object_or_404(Appointment, pk=pk)
    return JsonResponse({"reason": appt.reason})


@login_required
def my_appointment(request, pk):
    appt = get_object_or_404(Appointment, pk=pk, patient=request.user)
    return JsonResponse({"reason": appt.reason})


@login_required
def cancel_appointment(request, appointment_id):
    appt = Appointment.objects.get(id=appointment_id)
    if appt.patient != request.user:
        return HttpResponseForbidden()
    appt.delete()
    return JsonResponse({"ok": True})


@login_required
def note_detail(request, pk):
    note = note_for_user(request.user, pk)
    return JsonResponse({"body": note.body})


@login_required
def edit_note(request, note_id):
    note = Note.objects.get(pk=note_id)
    note.body = request.POST["body"]
    note.save()
    return JsonResponse({"ok": True})


def purge_invoices(request):
    Invoice.objects.filter(paid=True).delete()
    return JsonResponse({"ok": True})


class InvoiceViewSet(viewsets.ModelViewSet):
    queryset = Invoice.objects.all()
    permission_classes = [IsAuthenticated]


class MyInvoiceViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Invoice.objects.filter(owner=self.request.user)


class GuardedInvoiceViewSet(viewsets.ModelViewSet):
    queryset = Invoice.objects.all()
    permission_classes = [IsAuthenticated, IsInvoiceOwner]
