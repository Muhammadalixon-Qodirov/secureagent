from django.contrib.auth.models import AbstractUser
from django.db import models


class Agent(AbstractUser):
    team = models.CharField(max_length=50)


class Ticket(models.Model):
    requester = models.ForeignKey(Agent, on_delete=models.CASCADE, related_name="tickets")
    subject = models.CharField(max_length=200)
    status = models.CharField(max_length=20)


class Attachment(models.Model):
    ticket = models.ForeignKey(Ticket, on_delete=models.CASCADE)
    path = models.CharField(max_length=300)


class Article(models.Model):
    title = models.CharField(max_length=200)
    body = models.TextField()
