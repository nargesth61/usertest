from django.contrib.auth import authenticate 
from membership.models import User
import os
import random
from rest_framework.exceptions import AuthenticationFailed
import random
from django.utils import timezone
from django.contrib.auth.backends import ModelBackend


def generate_username(name):
        random_username = 'user'+'_'+name+ str(random.randint(0, 100))
        return str(random_username)

class EmailAuthBackend(ModelBackend):
    def authenticate(self, request, email=None, password=None, **kwargs):
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            User().set_password(password)
        else:
            if user.check_password(password) and self.user_can_authenticate(user):
                return user

    def user_can_authenticate(self, user):
        is_registered = getattr(user, 'is_registered', False)
        return super(EmailAuthBackend, self).user_can_authenticate(user) and is_registered


def register_social_user(provider, user_id, email, name):
    filtered_user_by_email = User.objects.filter(email=email)
    
    if filtered_user_by_email.exists():

        if provider == filtered_user_by_email[0].auth_provider:
            registered_user = authenticate(
                email=email, password=os.environ.get('SOCIAL_SECRET'))
            
            return {
                'username': registered_user.username,
                'email': registered_user.email,
                'tokens': registered_user.tokens()}
    else:
        user = {
            'username': generate_username(name), 'email': email,
            'password': os.environ.get('SOCIAL_SECRET')}
        user = User.objects.create_user(**user)
        user.is_verified = True
        
        user.auth_provider = provider
        user.save()

        new_user = authenticate(
            email=email, password=os.environ.get('SOCIAL_SECRET'))
        return {
            'email': new_user.email,
            'username': new_user.username,
            'tokens': new_user.tokens()
        }
    