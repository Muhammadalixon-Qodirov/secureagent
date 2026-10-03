from django.urls import include, path
from rest_framework.routers import DefaultRouter

from records import views

router = DefaultRouter()
router.register("invoices", views.InvoiceViewSet, basename="invoice")
router.register("my-invoices", views.MyInvoiceViewSet, basename="my-invoice")
router.register("guarded-invoices", views.GuardedInvoiceViewSet, basename="guarded-invoice")

urlpatterns = [
    path("login/", views.login_view),
    path("clinics/", views.clinics),
    path("appointments/<int:pk>/", views.appointment_detail),
    path("appointments/<int:pk>/mine/", views.my_appointment),
    path("appointments/<int:appointment_id>/cancel/", views.cancel_appointment),
    path("notes/<int:pk>/", views.note_detail),
    path("notes/<int:note_id>/edit/", views.edit_note),
    path("invoices/purge/", views.purge_invoices),
    path("api/", include(router.urls)),
]
