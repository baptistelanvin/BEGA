from django.contrib.auth.models import AbstractUser
from django.db import models

class User(AbstractUser):
    USERNAME_FIELD = 'email'
    email = models.EmailField(('email address'), unique=True) # changes email to unique and blank to false
    ADMINISTRATOR = 'ADMINISTRATOR'
    CUSTOMER = 'CUSTOMER'

    ROLE_CHOICES = (
        (ADMINISTRATOR, 'ADMINISTRATOR'),
        (CUSTOMER, 'CUSTOMER'),
    )
    profile_photo = models.ImageField(verbose_name='Photo de profil')
    role = models.CharField(max_length=30, choices=ROLE_CHOICES, verbose_name='Rôle')
    domain_names = []
    REQUIRED_FIELDS = []

