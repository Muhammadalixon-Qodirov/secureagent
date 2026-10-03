from django.conf import settings
from django.db import models


class Appointment(models.Model):
    patient = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    starts_at = models.DateTimeField()
    reason = models.CharField(max_length=200)


class Invoice(models.Model):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    amount_cents = models.IntegerField()
    paid = models.BooleanField(default=False)


class Note(models.Model):
    appointment = models.ForeignKey("records.Appointment", on_delete=models.CASCADE)
    body = models.TextField()


class Clinic(models.Model):
    name = models.CharField(max_length=100)
    city = models.CharField(max_length=100)
