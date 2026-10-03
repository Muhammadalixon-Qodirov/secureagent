from django.urls import path

from tickets import views

urlpatterns = [
    path("tickets/<int:ticket_id>/", views.TicketView.as_view()),
    path("tickets/<int:ticket_id>/close/", views.TicketCloseView.as_view()),
    path("staff/tickets/", views.StaffTicketListView.as_view()),
    path("attachments/<int:pk>/", views.AttachmentAPI.as_view()),
    path("me/tickets/", views.MyTicketsAPI.as_view()),
    path("articles/<int:pk>/", views.article),
    path("tickets/<int:ticket_id>/reassign/", views.reassign),
    path("tickets/<int:ticket_id>/delete/", views.delete_ticket),
]
