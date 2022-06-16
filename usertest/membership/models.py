from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.models import User
from .manager import UserManeger
from django.utils import timezone
from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver
from rest_framework.authtoken.models import Token
from rest_framework_simplejwt.tokens import RefreshToken
from django.dispatch import receiver

class User(AbstractUser):
    email = models.EmailField(unique=True)
    is_verified = models.BooleanField(default=False)
    is_registered = models.BooleanField(default=False, editable=False)
    otp = models.CharField(max_length=6 , null=True , blank=True)
    generated_date = models.DateTimeField(default=timezone.now, editable=False)

    REQUIRED_FIELDS = ['email',]
     
    objects: UserManeger()

    def name(self):
        return self.first_name + '' + self.last_name
 
    def save(self, *args, **kwargs):
        if not self.username:
            self.username = 'user_' + str(self.email[0:7])
        if not self.password:
            self.password = 1234
        # prevent staff members access_token hijacking through registration API
        if self.is_staff or self.is_superuser:
            self.is_verified = True
            self.is_registered = True
        super(User, self).save(*args, **kwargs)
     
    def __str__(self) :
          template = '{0.email} {0.is_registered} {0.is_verified}'
          return template.format(self)

