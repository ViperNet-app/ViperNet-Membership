from django.conf import settings
from django.db import models

class Vault(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    revision = models.PositiveIntegerField(default=0)
    ciphertext = models.TextField(default='')

class Revision(models.Model):
    vault = models.ForeignKey(Vault, on_delete=models.CASCADE, related_name='versions')
    number = models.PositiveIntegerField()
    ciphertext = models.TextField()
    created = models.DateTimeField(auto_now_add=True)
    class Meta:
        constraints = [models.UniqueConstraint(fields=['vault', 'number'], name='unique_revision')]

class Device(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    name = models.CharField(max_length=80)
    token_hash = models.CharField(max_length=64, unique=True)
    created = models.DateTimeField(auto_now_add=True)
    expires = models.DateTimeField()
    revoked = models.BooleanField(default=False)
    last_seen = models.DateTimeField(null=True)

class Grant(models.Model):
    code_hash = models.CharField(max_length=64, unique=True)
    user_code = models.CharField(max_length=16, unique=True)
    challenge = models.CharField(max_length=64)
    name = models.CharField(max_length=80)
    expires = models.DateTimeField()
    user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.CASCADE)
    consumed = models.BooleanField(default=False)
    denied = models.BooleanField(default=False)

class MailAction(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    digest = models.CharField(max_length=64, unique=True)
    purpose = models.CharField(max_length=12)
    expires = models.DateTimeField()

class RateBucket(models.Model):
    key = models.CharField(max_length=64, primary_key=True)
    count = models.PositiveIntegerField(default=0)
    expires = models.DateTimeField()
