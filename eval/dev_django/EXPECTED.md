# Synthetic Django dev app (v4 development only)

Written by hand for developing `secagent/authz_django.py` without touching the
RealVuln Django test set. Expected authorization candidates in `clinic/records/views.py`:

| View | Expected | Why |
|---|---|---|
| `appointment_detail` | candidate | owned object by pk, login only |
| `edit_note` | candidate | owned (via Appointment) object changed by id, login only |
| `InvoiceViewSet` | candidate | `queryset = Invoice.objects.all()`, authenticated only |
| `purge_invoices` | candidate (missing authentication) | deletes rows, no auth, siblings authenticate |
| `my_appointment` | safe | lookup scoped with `patient=request.user` |
| `cancel_appointment` | safe | `appt.patient != request.user` |
| `note_detail` | safe | helper `note_for_user` compares the owner |
| `MyInvoiceViewSet` | safe | `get_queryset` filters by `request.user` |
| `GuardedInvoiceViewSet` | safe | permission class compares `obj.owner_id` with the user |
| `login_view`, `clinics` | safe | public by design |
| `note_for_user` | not a view | not referenced from urls.py |

Second app, `desk/tickets/views.py` (class-based views, DRF `APIView`, `@api_view`,
a custom user model, project-wide `IsAuthenticated` default):

| View | Expected | Why |
|---|---|---|
| `TicketCloseView` | candidate | owned object changed by id, login only; sibling `TicketView` checks |
| `AttachmentAPI` | candidate | owned (via Ticket) object by pk, authenticated by the project default only |
| `reassign` | candidate | owned object by id, and the new owner id comes from request data |
| `TicketView` | safe | helper `can_see_ticket` compares the requester |
| `MyTicketsAPI` | safe | `request.user.tickets` |
| `StaffTicketListView`, `delete_ticket` | safe | role-gated, no sibling scoping expected of staff |
| `article` | safe | `AllowAny`, public content |
