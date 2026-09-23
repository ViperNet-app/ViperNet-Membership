from django.core.management.base import BaseCommand
from django.utils import timezone
from members.models import Grant, MailAction, RateBucket


class Command(BaseCommand):
    help = 'Remove expired temporary authorization and rate-limit records.'

    def handle(self, *args, **options):
        for model in (Grant, MailAction, RateBucket):
            model.objects.filter(expires__lt=timezone.now()).delete()
        self.stdout.write('Expired temporary records removed.')
