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

AUTH_PROVIDERS = {'google':'google' , 'email':'email'}

class User(AbstractUser):
    email = models.EmailField(unique=True)
    is_verified = models.BooleanField(default=False)
    is_registered = models.BooleanField(default=False, editable=False)
    otp = models.CharField(max_length=6 , null=True , blank=True)
    generated_date = models.DateTimeField(default=timezone.now, editable=False)
    auth_provider=models.CharField(max_length=225,blank=False,null=False,default=AUTH_PROVIDERS.get('email'))


    REQUIRED_FIELDS = ['email',]
     
    objects: UserManeger()

    def name(self):
        return self.first_name + '' + self.last_name
 
    def save(self, *args, **kwargs):
        #This section automatically creates a username for the user
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
    
    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }
 