from django.contrib.auth import authenticate
from membership.models import User
import os
import random
from rest_framework.exceptions import AuthenticationFailed
import random

def generate_username():
        random_username = 'username' + str(random.randint(0, 1000))
        return str(random_username)

def Social_register (provider,user_id,email):
    email_user =User.objects.filter(email=email)
    
    if email_user.exists():
       
        if provider == email_user[0].auth_provider:
            register_user = authenticate(email = email , password=os.environ.get('SOCIAL_SECRET'))

            return {
                'email': register_user.email,
                'tokens': register_user.tokens()}
        else:
            raise AuthenticationFailed(
                detail='Please continue your login using ' + email_user[0].auth_provider)
    
    else:
        
        user = { 
            'username': generate_username(),
            'email':email,
            }
        user = User.objects.create_user(**user)
        user.is_verified = True
        user.auth_provider = provider
        user.save()
        new_user = authenticate(
            email=email, password=os.environ.get('SOCIAL_SECRET'))
        return {
            'email': user.email,
            'username': user.username,
            'tokens': user.tokens()
        }