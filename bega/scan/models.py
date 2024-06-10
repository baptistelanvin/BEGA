from django.db import models
from authentication.models import User

class Scan(models.Model):
    domain_name=models.fields.CharField(max_length=100)
    tapirus = models.fields.BooleanField(default=False)
    goat = models.fields.BooleanField(default=False)
    owl = models.fields.BooleanField(default=False)
    kangaroo = models.fields.BooleanField(default=False)
    badger = models.fields.BooleanField(default=False)
    limit = models.fields.IntegerField()
    dkim=models.fields.CharField(max_length=100)

    user = models.ForeignKey(User, null=False, on_delete=models.CASCADE)

    def __str__(self):
        return f'{self.domain_name}'

class Report(models.Model):
    name = models.CharField(max_length=300)
    date = models.DateField(auto_now=True)
    data = models.JSONField()
    scan = models.ForeignKey(Scan, null=False, on_delete=models.RESTRICT)
    user = models.ForeignKey(User, null=False, on_delete=models.CASCADE)
    def __str__(self):
        return f'{self.name}'